/*
 * Implementation of "ethtool --show-mse <dev>"
 *
 * Background:
 * - Kernel MSE GET is defined in Documentation/netlink/specs/ethtool.yaml
 *   and implemented in net/ethtool/mse.c.
 * - Capabilities describe scale and timing for MSE readings:
 *     max-average-mse / max-peak-mse : scale
 *     refresh-rate-ps                : nominal update interval (picoseconds)
 *     num-symbols                    : symbols per sample window
 *   These two timing fields are mandatory in the kernel reply; limits are
 *   present only when the corresponding metrics are supported.
 * - Metrics originate from OPEN Alliance PHY diagnostics (100/1000BASE-T1),
 *   but scaling, windows, and refresh reate are vendor-specific; the
 *   capability block reports the implementation details provided by the PHY
 *   driver.
 * - Snapshots carry per-channel values (A-D, WORST, LINK) chosen by the
 *   kernel in priority order (per-channel first, else WORST, else LINK).
 */

#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "parser.h"

enum mse_attr_kind {
	MSE_ATTR_HEADER,
	MSE_ATTR_CAPS,
	MSE_ATTR_SNAPSHOT,
	MSE_ATTR_UNKNOWN,
};

struct mse_field_desc {
	uint16_t attr;
	const char *json_key;
	const char *plain_fmt;
	bool required;
};

static const struct mse_field_desc mse_cap_fields[] = {
	{
		.attr = ETHTOOL_A_MSE_CAPABILITIES_REFRESH_RATE_PS,
		.json_key = "refresh-rate-ps",
		.plain_fmt = "\tRefresh Rate: %" PRIu64 " ps\n",
		.required = true,
	},
	{
		.attr = ETHTOOL_A_MSE_CAPABILITIES_NUM_SYMBOLS,
		.json_key = "symbols-per-sample",
		.plain_fmt = "\tSymbols per Sample: %" PRIu64 "\n",
		.required = true,
	},
	{
		.attr = ETHTOOL_A_MSE_CAPABILITIES_MAX_AVERAGE_MSE,
		.json_key = "max-average-mse",
		.plain_fmt = "\tMax Average MSE: %" PRIu64 "\n",
		.required = false,
	},
	{
		.attr = ETHTOOL_A_MSE_CAPABILITIES_MAX_PEAK_MSE,
		.json_key = "max-peak-mse",
		.plain_fmt = "\tMax Peak MSE: %" PRIu64 "\n",
		.required = false,
	},
};

static const struct mse_field_desc mse_snapshot_fields[] = {
	{
		.attr = ETHTOOL_A_MSE_SNAPSHOT_AVERAGE_MSE,
		.json_key = "average-mse",
		.plain_fmt = "\tAverage MSE: %" PRIu64 "\n",
		.required = false,
	},
	{
		.attr = ETHTOOL_A_MSE_SNAPSHOT_PEAK_MSE,
		.json_key = "peak-mse",
		.plain_fmt = "\tPeak MSE: %" PRIu64 "\n",
		.required = false,
	},
	{
		.attr = ETHTOOL_A_MSE_SNAPSHOT_WORST_PEAK_MSE,
		.json_key = "worst-peak-mse",
		.plain_fmt = "\tWorst-Peak MSE: %" PRIu64 "\n",
		.required = false,
	},
};

static enum mse_attr_kind mse_classify_attr(uint16_t at)
{
	switch (at) {
	case ETHTOOL_A_MSE_HEADER:
		return MSE_ATTR_HEADER;
	case ETHTOOL_A_MSE_CAPABILITIES:
		return MSE_ATTR_CAPS;
	case ETHTOOL_A_MSE_CHANNEL_A:
	case ETHTOOL_A_MSE_CHANNEL_B:
	case ETHTOOL_A_MSE_CHANNEL_C:
	case ETHTOOL_A_MSE_CHANNEL_D:
	case ETHTOOL_A_MSE_WORST_CHANNEL:
	case ETHTOOL_A_MSE_LINK:
		return MSE_ATTR_SNAPSHOT;
	default:
		return MSE_ATTR_UNKNOWN;
	}
}

/* Validate presence (if required) and width of integer attrs, then fetch the
 * value. The kernel uses nla_put_uint(), which may encode values in
 * 8/16/32/64-bit payloads; rely on attr_get_uint() for size handling.
 * @present reports whether the attribute was found.
 *
 * Return: 0 on success, -EINVAL/-EMSGSIZE on malformed attributes.
 */
static int mse_validate_get_u64_attr(const struct nlattr *attr, const char *name,
				     bool required, u64 *val, bool *present)
{
	if (present)
		*present = false;
	if (!attr) {
		if (required)
			fprintf(stderr, "warning: missing %s attribute in MSE reply; skipping\n",
				name);
		if (val)
			*val = 0;
		return 0;
	}

	*val = attr_get_uint(attr);
	if (*val == UINT64_MAX) {
		fprintf(stderr, "invalid %s attribute size in MSE reply\n", name);
		return -EMSGSIZE;
	}
	if (present)
		*present = true;

	return 0;
}

static int mse_print_fields(const struct nlattr **tb,
			    const struct mse_field_desc *fields, size_t n,
			    bool *has_value)
{
	const struct mse_field_desc *f;
	bool present;
	u64 val;
	int ret;

	for (f = fields; f < fields + n; f++) {
		ret = mse_validate_get_u64_attr(tb[f->attr], f->json_key,
						f->required, &val, &present);
		if (ret < 0)
			return ret;
		if (present) {
			print_u64(PRINT_ANY, f->json_key, f->plain_fmt, val);
			if (has_value)
				*has_value = true;
		}
	}

	return 0;
}

static const char *mse_get_channel_name(uint16_t channel)
{
	switch (channel) {
	case ETHTOOL_A_MSE_CHANNEL_A:
		return "a";
	case ETHTOOL_A_MSE_CHANNEL_B:
		return "b";
	case ETHTOOL_A_MSE_CHANNEL_C:
		return "c";
	case ETHTOOL_A_MSE_CHANNEL_D:
		return "d";
	case ETHTOOL_A_MSE_WORST_CHANNEL:
		return "worst";
	case ETHTOOL_A_MSE_LINK:
		return "link";
	default:
		return "unknown";
	}
}

static int mse_dump_capabilities(const struct nlattr *cap_attr)
{
	const struct nlattr *tb[ETHTOOL_A_MSE_CAPABILITIES_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	bool has_value = false;
	int ret;

	ret = mnl_attr_parse_nested(cap_attr, attr_cb, &tb_info);
	if (ret != MNL_CB_OK) {
		fprintf(stderr, "malformed netlink message (capabilities)\n");
		return -EINVAL;
	}

	open_json_object("mse-capabilities");
	if (!is_json_context())
		printf("MSE Capabilities:\n");

	/* Kernel sends max-average/peak only if corresponding PHY_MSE_CAP_* bits
	 * are set; refresh-rate-ps and num-symbols are always present.
	 */
	ret = mse_print_fields(tb, mse_cap_fields, ARRAY_SIZE(mse_cap_fields),
			       &has_value);

	if (!has_value)
		fprintf(stderr, "warning: kernel returned empty MSE capability block\n");

	close_json_object();

	return ret;
}

static int mse_dump_snapshot(const struct nlattr *snapshot_attr,
			     uint16_t channel)
{
	const struct nlattr *tb[ETHTOOL_A_MSE_SNAPSHOT_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	const char *channel_name;
	bool has_value = false;
	int ret;

	ret = mnl_attr_parse_nested(snapshot_attr, attr_cb, &tb_info);
	if (ret != MNL_CB_OK) {
		fprintf(stderr, "malformed netlink message (snapshot)\n");
		return -EINVAL;
	}

	channel_name = mse_get_channel_name(channel);
	print_string(PRINT_ANY, "channel", "\nMSE Snapshot (Channel: %s):\n",
		     channel_name);

	ret = mse_print_fields(tb, mse_snapshot_fields,
			       ARRAY_SIZE(mse_snapshot_fields), &has_value);
	if (ret < 0)
		return ret;

	if (!has_value)
		fprintf(stderr, "warning: kernel returned empty MSE snapshot for channel %s\n",
			channel_name);

	return 0;
}

static int mse_process_snapshot_attr(const struct nlattr *attr)
{
	uint16_t channel = mnl_attr_get_type(attr);
	int ret;

	open_json_object(NULL);

	ret = mse_dump_snapshot(attr, channel);

	close_json_object();

	return ret;
}

static int mse_dump_snapshots(const struct nlmsghdr *nlhdr)
{
	bool snapshots_started = false;
	unsigned int unknown_cnt = 0;
	const struct nlattr *attr;
	int ret = 0;

	/*
	 * If the kernel provides no per-channel snapshot nests, still emit an
	 * empty "mse-snapshots" array in JSON mode. This keeps the JSON schema
	 * stable for consumers (always an array, possibly empty).
	 */
	if (is_json_context())
		open_json_array("mse-snapshots", NULL);

	/* Kernel already picks per-channel over WORST over LINK; we just dump
	 * whatever nests are present.
	 */
	mnl_attr_for_each(attr, nlhdr, GENL_HDRLEN) {
		uint16_t at = mnl_attr_get_type(attr);

		switch (mse_classify_attr(at)) {
		case MSE_ATTR_SNAPSHOT:
			ret = mse_process_snapshot_attr(attr);
			if (ret < 0)
				goto out;

			snapshots_started = true;

			break;
		case MSE_ATTR_UNKNOWN:
			unknown_cnt++;
			break;
		case MSE_ATTR_HEADER:
		case MSE_ATTR_CAPS:
		default:
			break;
		}
	}

	if (!snapshots_started)
		fprintf(stderr, "warning: no MSE snapshot data available from kernel\n");

	if (unknown_cnt)
		fprintf(stderr, "warning: %u unknown MSE attribute(s) ignored\n",
			unknown_cnt);
out:
	if (is_json_context())
		close_json_array(NULL);

	return ret;
}

int mse_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_MSE_MAX + 1] = {};
	struct nl_context *nlctx = data;
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret != MNL_CB_OK)
		return -EINVAL;

	nlctx->devname = get_dev_name(tb[ETHTOOL_A_MSE_HEADER]);
	if (!dev_ok(nlctx))
		return 0;

	open_json_object(NULL);
	print_string(PRINT_ANY, "ifname", "MSE diagnostics for %s:\n",
		     nlctx->devname);

	if (tb[ETHTOOL_A_MSE_CAPABILITIES]) {
		ret = mse_dump_capabilities(tb[ETHTOOL_A_MSE_CAPABILITIES]);
		if (ret < 0)
			goto out;
	} else {
		fprintf(stderr, "warning: missing MSE capabilities; continuing with snapshots\n");
	}

	ret = mse_dump_snapshots(nlhdr);

	print_nl();
out:
	close_json_object();

	return ret;
}

int nl_gmse(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_msg_buff *msgbuff;
	struct nl_socket *nlsk;
	int ret;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_MSE_GET, true))
		return -EOPNOTSUPP;

	nlctx->cmd = "--show-mse";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	nlctx->devname = ctx->devname;
	nlsk = nlctx->ethnl_socket;
	msgbuff = &nlsk->msgbuff;

	ret = msg_init(nlctx, msgbuff, ETHTOOL_MSG_MSE_GET,
		       NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return ret;
	ret = ethnla_fill_header_phy(msgbuff, ETHTOOL_A_MSE_HEADER,
				     ctx->devname, ctx->phy_index, 0);
	if (ret < 0)
		return ret;

	new_json_obj(ctx->json);
	ret = nlsock_sendmsg(nlsk, NULL);
	if (ret < 0)
		goto out;
	ret = nlsock_process_reply(nlsk, mse_reply_cb, nlctx);

out:
	delete_json_obj();
	return ret;
}
