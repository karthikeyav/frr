// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Unreachability Information SAFI
 * Copyright (C) 2025 Nvidia Corporation
 *                    Karthikeya Venkat Muppalla
 *
 * Wire format per draft-tantsura-idr-unreachability-safi:
 *
 * NLRI Format (Section 3.2-3.3):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Prefix Length |           Prefix (variable)                   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  Reporter TLV (variable)                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Reporter TLV Format (Section 3.4):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type=1    |            Length             |               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               |
 * |              Reporter Identifier (4 octets)                   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              Reporter AS Number (4 octets)                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Sub-TLVs (variable)                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Sub-TLV Format (Section 3.5):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Sub-Type    |         Sub-Length            |               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               |
 * |                   Sub-Value (variable)                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Implementation notes:
 * - Multiple NLRIs can be packed in single UPDATE message
 * - Current implementation: 1 Reporter TLV per NLRI (no aggregation)
 * - Unknown Sub-TLV types are silently ignored (forward compatibility)
 */

#include <zebra.h>

#include "prefix.h"
#include "log.h"
#include "stream.h"
#include "memory.h"
#include "command.h"
#include "json.h"
#include "frrevent.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_unreach.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_updgrp.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_UNREACH_INFO, "BGP Unreachability Information");

/* Helper function to convert reason code to string */
const char *bgp_unreach_reason_str(uint16_t code)
{
	static const char *const reason_names[] = {
		"Unspecified",	      /* 0 */
		"Policy-Blocked",     /* 1 */
		"Security-Filtered",  /* 2 */
		"RPKI-Invalid",	      /* 3 */
		"No-Export-Policy",   /* 4 */
		"Martian-Address",    /* 5 */
		"Bogon-Prefix",	      /* 6 */
		"Route-Dampening",    /* 7 */
		"Local-Admin-Action", /* 8 */
		"Local-Link-Down"     /* 9 */
	};

	if (code <= 9)
		return reason_names[code];
	else if (code >= 64536)
		return "Private-Use";
	else
		return "Reserved";
}

/* Helper function to convert reason string to code
 * Returns 0 on success, -1 if the string is not recognized
 */
int bgp_unreach_reason_str2code(const char *str, uint16_t *code)
{
	if (strmatch(str, "unspecified"))
		*code = BGP_UNREACH_REASON_UNSPECIFIED;
	else if (strmatch(str, "policy-blocked"))
		*code = BGP_UNREACH_REASON_POLICY_BLOCKED;
	else if (strmatch(str, "security-filtered"))
		*code = BGP_UNREACH_REASON_SECURITY_FILTERED;
	else if (strmatch(str, "rpki-invalid"))
		*code = BGP_UNREACH_REASON_RPKI_INVALID;
	else if (strmatch(str, "no-export-policy"))
		*code = BGP_UNREACH_REASON_NO_EXPORT_POLICY;
	else if (strmatch(str, "martian-address"))
		*code = BGP_UNREACH_REASON_MARTIAN_ADDRESS;
	else if (strmatch(str, "bogon-prefix"))
		*code = BGP_UNREACH_REASON_BOGON_PREFIX;
	else if (strmatch(str, "route-dampening"))
		*code = BGP_UNREACH_REASON_ROUTE_DAMPENING;
	else if (strmatch(str, "local-admin-action"))
		*code = BGP_UNREACH_REASON_LOCAL_ADMIN_ACTION;
	else if (strmatch(str, "local-link-down"))
		*code = BGP_UNREACH_REASON_LOCAL_LINK_DOWN;
	else
		return -1;

	return 0;
}

int bgp_unreach_tlv_encode(struct stream *s, struct bgp_unreach_nlri *unreach)
{
	/* Calculate Reporter TLV total length:
	 * - Reporter ID (4 bytes) + Reporter AS (4 bytes) = 8 bytes fixed
	 * - Sub-TLV Type 1 (Reason): 3 + 2 = 5 bytes (if present)
	 * - Sub-TLV Type 2 (Timestamp): 3 + 8 = 11 bytes (if present)
	 */
	uint16_t reporter_tlv_len = BGP_UNREACH_REPORTER_FIXED_LEN;

	if (unreach->has_reason_code)
		reporter_tlv_len += BGP_UNREACH_SUBTLV_HEADER_LEN + BGP_UNREACH_REASON_CODE_LEN;

	if (unreach->has_timestamp)
		reporter_tlv_len += BGP_UNREACH_SUBTLV_HEADER_LEN + BGP_UNREACH_TIMESTAMP_LEN;

	/* Encode Reporter TLV header */
	stream_putc(s, BGP_UNREACH_TLV_TYPE_REPORTER);
	stream_putw(s, reporter_tlv_len);

	/* Reporter Identifier (4 bytes) - mandatory */
	stream_put(s, &unreach->reporter, BGP_UNREACH_REPORTER_ID_LEN);

	/* Reporter AS Number (4 bytes) - mandatory */
	stream_putl(s, unreach->reporter_as);

	/* Sub-TLV Type 1: Reason Code (optional) */
	if (unreach->has_reason_code) {
		stream_putc(s, BGP_UNREACH_SUBTLV_TYPE_REASON_CODE);
		stream_putw(s, BGP_UNREACH_REASON_CODE_LEN);
		stream_putw(s, unreach->reason_code);
	}

	/* Sub-TLV Type 2: Timestamp (optional) */
	if (unreach->has_timestamp) {
		uint64_t ts = htobe64(unreach->timestamp);

		stream_putc(s, BGP_UNREACH_SUBTLV_TYPE_TIMESTAMP);
		stream_putw(s, BGP_UNREACH_TIMESTAMP_LEN);
		stream_put(s, &ts, BGP_UNREACH_TIMESTAMP_LEN);
	}

	return 0;
}

/* Parse unreachability NLRI
 *
 * Parses one or more UNREACH NLRIs from UPDATE message.
 * Wire format documented at top of file.
 */
struct bgp_unreach_info *bgp_unreach_info_new(struct prefix *prefix)
{
	struct bgp_unreach_info *info;

	info = XCALLOC(MTYPE_BGP_UNREACH_INFO, sizeof(struct bgp_unreach_info));
	prefix_copy(&info->prefix, prefix);
	info->received_time = monotime(NULL);

	return info;
}

/* Free unreachability info */
void bgp_unreach_info_free(struct bgp_unreach_info *info)
{
	XFREE(MTYPE_BGP_UNREACH_INFO, info);
}

/* Add unreachability information to RIB */
int bgp_unreach_info_add(struct bgp *bgp, afi_t afi, struct bgp_unreach_nlri *nlri,
			 struct attr *attr)
{
	struct bgp_dest *dest;
	struct bgp_path_info *bpi;
	struct bgp_path_info *new;
	struct attr attr_new;
	struct attr *attr_interned;

	if (!bgp || !nlri)
		return -1;

	/* Get/create destination node */
	dest = bgp_node_get(bgp->rib[afi][SAFI_UNREACH], &nlri->prefix);

	/* Check for existing path */
	for (bpi = bgp_dest_get_bgp_path_info(dest); bpi; bpi = bpi->next) {
		if (bpi->peer == bgp->peer_self)
			break;
	}

	/* Create new path or update existing */
	if (!bpi) {
		/* Initialize attributes (no TLV data in attr) */
		if (attr) {
			attr_new = *attr;
		} else {
			/* Set default attributes for locally originated route */
			bgp_attr_default_set(&attr_new, bgp, BGP_ORIGIN_IGP);
		}

		/* Set nexthop length to 0 for SAFI_UNREACH (no nexthop, like Flowspec) */
		attr_new.mp_nexthop_len = 0;

		/* Intern the attributes */
		attr_interned = bgp_attr_intern(&attr_new);

		new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, 0, bgp->peer_self, attr_interned,
				dest);

		if (!new->extra)
			new->extra = bgp_path_info_extra_get(new);

		new->extra->unreach = XCALLOC(MTYPE_BGP_ROUTE_EXTRA_UNREACH,
					      sizeof(struct bgp_path_info_extra_unreach));

		new->extra->unreach->timestamp = nlri->timestamp;
		new->extra->unreach->has_timestamp = nlri->has_timestamp;
		new->extra->unreach->reason_code = nlri->reason_code;
		new->extra->unreach->has_reason_code = nlri->has_reason_code;
		new->extra->unreach->reporter = nlri->reporter;
		new->extra->unreach->has_reporter = nlri->has_reporter;
		new->extra->unreach->reporter_as = nlri->reporter_as;
		new->extra->unreach->has_reporter_as = nlri->has_reporter_as;

		bgp_path_info_set_flag(dest, new, BGP_PATH_VALID);
		bgp_path_info_add(dest, new);
		bgp_process(bgp, dest, new, afi, SAFI_UNREACH);
	} else {
		/* Update existing path with new TLV data */
		if (!bpi->extra)
			bpi->extra = bgp_path_info_extra_get(bpi);

		if (!bpi->extra->unreach)
			bpi->extra->unreach = XCALLOC(MTYPE_BGP_ROUTE_EXTRA_UNREACH,
						      sizeof(struct bgp_path_info_extra_unreach));

		if (bgp_debug_update(NULL, &nlri->prefix, NULL, 0)) {
			zlog_debug("UNREACH UPDATE %pFX: old reason=%u new reason=%u",
				   &nlri->prefix,
				   bpi->extra->unreach->reason_code,
				   nlri->reason_code);
		}

		bpi->extra->unreach->timestamp = nlri->timestamp;
		bpi->extra->unreach->has_timestamp = nlri->has_timestamp;
		bpi->extra->unreach->reason_code = nlri->reason_code;
		bpi->extra->unreach->has_reason_code = nlri->has_reason_code;
		bpi->extra->unreach->reporter = nlri->reporter;
		bpi->extra->unreach->has_reporter = nlri->has_reporter;
		bpi->extra->unreach->reporter_as = nlri->reporter_as;
		bpi->extra->unreach->has_reporter_as = nlri->has_reporter_as;

		bpi->uptime = monotime(NULL);
		bgp_path_info_set_flag(dest, bpi, BGP_PATH_ATTR_CHANGED);
		bgp_process(bgp, dest, bpi, afi, SAFI_UNREACH);
	}

	bgp_dest_unlock_node(dest);

	return 0;
}

/* Delete unreachability information */
void bgp_unreach_info_delete(struct bgp *bgp, afi_t afi, struct prefix *prefix)
{
	struct bgp_dest *dest;
	struct bgp_path_info *bpi;

	if (!bgp || !prefix)
		return;

	dest = bgp_node_lookup(bgp->rib[afi][SAFI_UNREACH], prefix);
	if (!dest)
		return;

	for (bpi = bgp_dest_get_bgp_path_info(dest); bpi; bpi = bpi->next) {
		if (bpi->peer == bgp->peer_self) {
			bgp_rib_remove(dest, bpi, bgp->peer_self, afi, SAFI_UNREACH);
			break;
		}
	}

	bgp_dest_unlock_node(dest);
}

/* Encode unreachability NLRI for transmission */
void bgp_unreach_nlri_encode(struct stream *s, struct bgp_unreach_nlri *unreach,
			     bool addpath_capable, uint32_t addpath_id)
{
	/* AddPath ID if needed */
	if (addpath_capable)
		stream_putl(s, addpath_id);

	/* Prefix length */
	stream_putc(s, unreach->prefix.prefixlen);

	/* Prefix */
	int psize = PSIZE(unreach->prefix.prefixlen);

	if (psize > 0)
		stream_put(s, &unreach->prefix.u.prefix, psize);

	/* TLVs */
	bgp_unreach_tlv_encode(s, unreach);
}

/* Show unreachability information */
