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
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_trace.h"

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

/* Parse TLVs from unreachability NLRI
 *
 * Extracts Reporter ID, Reporter AS, and Sub-TLVs (Reason Code, Timestamp).
 * Wire format documented at top of file.
 *
 * Parameters:
 *   data - Pointer to start of ONE Reporter TLV (Type + Length + payload)
 *   len  - Length of THIS Reporter TLV only (caller pre-calculated)
 *   unreach - Output structure to store parsed fields
 *
 * Returns:
 *   0 on success
 *   -1 on parse error
 */
int bgp_unreach_tlv_parse(uint8_t *data, uint16_t len, struct bgp_unreach_nlri *unreach)
{
	uint8_t *pnt = data;
	uint8_t *end = data + len;

	/* Initialize */
	memset(&unreach->reporter, 0, sizeof(unreach->reporter));
	unreach->reporter_as = 0;
	unreach->reason_code = 0;
	unreach->timestamp = 0;
	unreach->has_reason_code = false;
	unreach->has_timestamp = false;
	unreach->has_reporter = false;
	unreach->has_reporter_as = false;

	/* Validate minimum length for Reporter TLV */
	if (len < BGP_UNREACH_REPORTER_TLV_MIN_LEN) {
		zlog_err("Unreachability NLRI too short: %u bytes (min %u)", len,
			 BGP_UNREACH_REPORTER_TLV_MIN_LEN);
		return -1;
	}

	/* Parse Reporter TLV (Type 1 - mandatory container) */
	if (pnt + BGP_UNREACH_TLV_HEADER_LEN > end) {
		zlog_err("Truncated Reporter TLV header");
		return -1;
	}

	uint8_t tlv_type = *pnt++;
	uint16_t tlv_len;

	tlv_len = ((uint16_t)*pnt++ << 8);
	tlv_len |= *pnt++;

	/* Validate Reporter TLV Type */
	if (tlv_type != BGP_UNREACH_TLV_TYPE_REPORTER) {
		zlog_err("Invalid TLV type: expected %u (Reporter), got %u",
			 BGP_UNREACH_TLV_TYPE_REPORTER, tlv_type);
		return -1;
	}

	/* Validate Reporter TLV length */
	if (tlv_len < BGP_UNREACH_REPORTER_FIXED_LEN) {
		zlog_err("Reporter TLV too short: %u bytes (min %u)", tlv_len,
			 BGP_UNREACH_REPORTER_FIXED_LEN);
		return -1;
	}

	if (pnt + tlv_len > end) {
		zlog_err("Reporter TLV length overflow: %u bytes", tlv_len);
		return -1;
	}

	uint8_t *reporter_end = pnt + tlv_len;

	/* Extract Reporter Identifier (4 bytes) - mandatory */
	if (pnt + BGP_UNREACH_REPORTER_ID_LEN > reporter_end) {
		zlog_err("Truncated Reporter Identifier");
		return -1;
	}
	memcpy(&unreach->reporter, pnt, BGP_UNREACH_REPORTER_ID_LEN);
	unreach->has_reporter = true;
	pnt += BGP_UNREACH_REPORTER_ID_LEN;

	/* Extract Reporter AS Number (4 bytes) - mandatory */
	if (pnt + BGP_UNREACH_REPORTER_AS_LEN > reporter_end) {
		zlog_err("Truncated Reporter AS Number");
		return -1;
	}
	unreach->reporter_as = ((uint32_t)*pnt++ << 24);
	unreach->reporter_as |= ((uint32_t)*pnt++ << 16);
	unreach->reporter_as |= ((uint32_t)*pnt++ << 8);
	unreach->reporter_as |= *pnt++;
	unreach->has_reporter_as = true;

	/* Parse Sub-TLVs */
	while (pnt < reporter_end) {
		if (pnt + BGP_UNREACH_SUBTLV_HEADER_LEN > reporter_end) {
			zlog_err("Truncated Sub-TLV header");
			return -1;
		}

		uint8_t sub_type = *pnt++;
		uint16_t sub_len;

		sub_len = ((uint16_t)*pnt++ << 8);
		sub_len |= *pnt++;

		if (pnt + sub_len > reporter_end) {
			zlog_err("Sub-TLV length overflow: type=%u len=%u", sub_type, sub_len);
			return -1;
		}

		/* Reject zero-length Sub-TLVs (invalid, no data) */
		if (sub_len == 0) {
			zlog_err("Zero-length Sub-TLV type %u", sub_type);
			return -1;
		}

		switch (sub_type) {
		case BGP_UNREACH_SUBTLV_TYPE_REASON_CODE:
			if (sub_len != BGP_UNREACH_REASON_CODE_LEN) {
				zlog_err("Invalid Reason Code Sub-TLV length: %u (expected %u)",
					 sub_len, BGP_UNREACH_REASON_CODE_LEN);
				return -1;
			}
			unreach->reason_code = ((uint16_t)*pnt << 8);
			unreach->reason_code |= *(pnt + 1);
			unreach->has_reason_code = true;
			break;

		case BGP_UNREACH_SUBTLV_TYPE_TIMESTAMP:
			if (sub_len != BGP_UNREACH_TIMESTAMP_LEN) {
				zlog_err("Invalid Timestamp Sub-TLV length: %u (expected %u)",
					 sub_len, BGP_UNREACH_TIMESTAMP_LEN);
				return -1;
			}
			unreach->timestamp = ((uint64_t)*pnt << 56);
			unreach->timestamp |= ((uint64_t)*(pnt + 1) << 48);
			unreach->timestamp |= ((uint64_t)*(pnt + 2) << 40);
			unreach->timestamp |= ((uint64_t)*(pnt + 3) << 32);
			unreach->timestamp |= ((uint64_t)*(pnt + 4) << 24);
			unreach->timestamp |= ((uint64_t)*(pnt + 5) << 16);
			unreach->timestamp |= ((uint64_t)*(pnt + 6) << 8);
			unreach->timestamp |= *(pnt + 7);
			unreach->has_timestamp = true;
			break;

		default:
			break;
		}

		pnt += sub_len;
	}

	return 0;
}

/* Encode Reporter TLV into stream
 *
 * Encodes Reporter ID, Reporter AS, and Sub-TLVs (Reason Code, Timestamp).
 * Wire format documented at top of file.
 */
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
int bgp_nlri_parse_unreach(struct peer *peer, struct attr *attr, struct bgp_nlri *packet,
			   bool withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	struct prefix p;
	int psize = 0;
	uint8_t prefixlen;
	afi_t afi;
	safi_t safi;
	uint32_t addpath_id;
	bool addpath_capable;
	struct bgp_unreach_nlri unreach;

	/* Start processing the NLRI */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;

	addpath_capable = bgp_addpath_encode_rx(peer, afi, safi);

	while (pnt < lim) {
		/* Clear structures */
		memset(&p, 0, sizeof(p));
		memset(&unreach, 0, sizeof(unreach));

		/* Get AddPath ID if applicable */
		if (addpath_capable) {
			if (pnt + BGP_ADDPATH_ID_LEN > lim)
				return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

			memcpy(&addpath_id, pnt, BGP_ADDPATH_ID_LEN);
			addpath_id = ntohl(addpath_id);
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/* Fetch prefix length */
		if (pnt >= lim) {
			zlog_err("%s: Premature end of unreachability NLRI", peer->host);
			return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
		}

		prefixlen = *pnt++;
		p.family = afi2family(afi);
		p.prefixlen = prefixlen;

		/* Prefix length check */
		if (prefixlen > prefix_blen(&p) * 8) {
			zlog_err("%s: Invalid prefix length %d for AFI %u", peer->host, prefixlen,
				 afi);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
		}

		/* Calculate size of prefix in bytes */
		psize = PSIZE(prefixlen);

		/* Check packet size */
		if (pnt + psize > lim) {
			zlog_err("%s: Prefix length %d overflows packet", peer->host, prefixlen);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		/* Copy prefix and advance pointer */
		if (psize > 0)
			memcpy(&p.u.prefix, pnt, psize);
		pnt += psize;

		/* Parse TLVs for this NLRI.
		 * Each NLRI has: [prefix][Reporter TLV(s)]
		 * Withdrawals do NOT include TLVs - only parse for updates.
		 */
		if (!withdraw && pnt < lim) {
			uint16_t remaining_in_packet = lim - pnt;

			/* Read Reporter TLV header to determine its length */
			if (remaining_in_packet < BGP_UNREACH_TLV_HEADER_LEN) {
				zlog_err("%s: Insufficient Reporter TLV data for %pFX", peer->host,
					 &p);
				return BGP_NLRI_PARSE_ERROR;
			}

			/* Read Reporter TLV Length field (2 bytes, network byte order) */
			uint16_t reporter_tlv_len = ((uint16_t)pnt[BGP_UNREACH_TLV_LEN_OFFSET]
						     << 8) |
						    pnt[BGP_UNREACH_TLV_LEN_OFFSET + 1];

			/* Validate Reporter TLV length is within valid range */
			if (reporter_tlv_len < BGP_UNREACH_REPORTER_FIXED_LEN) {
				zlog_err("%s: Reporter TLV length %u too short (min %u) for %pFX",
					 peer->host, reporter_tlv_len,
					 BGP_UNREACH_REPORTER_FIXED_LEN, &p);
				return BGP_NLRI_PARSE_ERROR;
			}

			uint16_t reporter_tlv_total = BGP_UNREACH_TLV_HEADER_LEN + reporter_tlv_len;

			/* Validate Reporter TLV doesn't overflow remaining packet */
			if (reporter_tlv_total > remaining_in_packet) {
				zlog_err("%s: Reporter TLV length %u exceeds remaining packet %u for %pFX",
					 peer->host, reporter_tlv_total, remaining_in_packet, &p);
				return BGP_NLRI_PARSE_ERROR;
			}

			/* Parse Reporter TLV (extracts Reporter ID, AS, Sub-TLVs) */
			if (bgp_unreach_tlv_parse(pnt, reporter_tlv_total, &unreach) < 0) {
				zlog_err("%s: Failed to parse Reporter TLV for %pFX", peer->host,
					 &p);
				return BGP_NLRI_PARSE_ERROR;
			}

			/* Advance pointer past THIS NLRI's Reporter
			 * TLV to next NLRI.
			 *
			 * We expect 1 Reporter TLV per NLRI. If sender
			 * includes multiple Reporter TLVs without
			 * capability negotiation, they will be
			 * misinterpreted as next NLRI, causing parse
			 * error and UPDATE rejection.
			 */
			pnt += reporter_tlv_total;
		}

		/* Store prefix in unreach structure */
		prefix_copy(&unreach.prefix, &p);

		/* Store TLV data in attr for bgp_update() to access.
		 * This follows the same pattern as EVPN (see bgp_route.c:5418-5421).
		 */
		if (attr && !withdraw) {
			/* Allocate and attach TLV data to attributes */
			struct bgp_unreach_nlri *unreach_copy =
				XCALLOC(MTYPE_TMP, sizeof(struct bgp_unreach_nlri));
			*unreach_copy = unreach;
			attr->unreach_nlri = unreach_copy;
		}

		if (withdraw) {
			bgp_withdraw(peer, &p, addpath_id, afi, safi,
				     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				     NULL, NULL, 0);
		} else if (attr) {
			bgp_update(peer, &p, addpath_id, attr, afi, safi,
				   ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				   NULL, NULL, 0, 0, NULL);
		} else {
			if (BGP_DEBUG(update, UPDATE_IN))
				zlog_debug("%s: Missing attributes for unreachability update %pFX, skipping",
					   peer->host, &p);
		}

		/* Free temporary TLV data */
		if (attr && attr->unreach_nlri) {
			XFREE(MTYPE_TMP, attr->unreach_nlri);
			attr->unreach_nlri = NULL;
		}

		if (BGP_DEBUG(update, UPDATE_IN))
			zlog_debug("%s: Processed unreachability info for %pFX via bgp_update()",
				   peer->host, &p);
	}

	return 0;
}

/* Create new unreachability info */
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
			bgp_attr_default_set(&attr_new, bgp, BGP_ORIGIN_INCOMPLETE);
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
void bgp_unreach_info_delete(struct bgp *bgp, afi_t afi, const struct prefix *prefix)
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

/*
 * Populate a JSON path object with detailed fields for one
 * unreachability path (TLVs, peer, origin, flags, communities, aspath).
 */
static void bgp_unreach_path_detail_json(json_object *json_path,
					 struct bgp_path_info *pi)
{
	struct bgp_path_info_extra_unreach *ud =
		(pi->extra) ? pi->extra->unreach : NULL;

	if (ud && ud->has_reporter) {
		char reporter[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &ud->reporter,
			  reporter, sizeof(reporter));
		json_object_string_add(json_path, "reporter", reporter);
	}
	if (ud && ud->has_reporter_as)
		json_object_int_add(json_path, "reporterAs",
				    ud->reporter_as);

	if (ud && ud->has_reason_code) {
		const char *reason_str =
			bgp_unreach_reason_str(ud->reason_code);

		json_object_string_add(json_path, "reason", reason_str);
	}

	if (ud && ud->has_timestamp) {
		time_t ts = (time_t)ud->timestamp;
		char timebuf[64];
		json_object *json_ts = json_object_new_object();

		json_object_int_add(json_ts, "epoch", ts);
		json_object_string_add(json_ts, "string",
				       ctime_r(&ts, timebuf));
		json_object_object_add(json_path, "timestamp", json_ts);
	}

	if (pi->peer) {
		json_object_string_addf(json_path, "peer", "%pSU",
					&pi->peer->connection->su);
		if (pi->peer->hostname)
			json_object_string_add(json_path, "peerHostname",
					       pi->peer->hostname);
	}

	if (pi->attr)
		json_object_string_add(json_path, "origin",
				       bgp_origin_long_str[pi->attr->origin]);

	json_object_boolean_add(json_path, "valid",
				CHECK_FLAG(pi->flags, BGP_PATH_VALID));
	json_object_boolean_add(json_path, "best",
				CHECK_FLAG(pi->flags, BGP_PATH_SELECTED));
	json_object_boolean_add(json_path, "stale",
				CHECK_FLAG(pi->flags, BGP_PATH_STALE));
	json_object_boolean_add(json_path, "multipath",
				CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH));

	if (pi->peer && pi->peer->sort == BGP_PEER_IBGP)
		json_object_string_add(json_path, "pathFrom", "internal");
	else if (pi->peer && pi->peer->sort == BGP_PEER_EBGP)
		json_object_string_add(json_path, "pathFrom", "external");

	{
		time_t tbuf = time(NULL) - (monotime(NULL) - pi->uptime);
		char timebuf[64];
		json_object *json_last_update = json_object_new_object();

		json_object_int_add(json_last_update, "epoch", tbuf);
		json_object_string_add(json_last_update, "string",
				       ctime_r(&tbuf, timebuf));
		json_object_object_add(json_path, "lastUpdate",
				       json_last_update);
	}

	if (pi->attr &&
	    (pi->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES))) {
		struct community *comm = bgp_attr_get_community(pi->attr);

		if (comm) {
			if (!comm->json)
				community_str(comm, true, true);
			json_object_lock(comm->json);
			json_object_object_add(json_path, "community",
					       comm->json);
		}
	}

	if (pi->attr && bgp_attr_get_ecommunity(pi->attr)) {
		struct ecommunity *ecomm =
			bgp_attr_get_ecommunity(pi->attr);
		json_object *json_ecomm = json_object_new_object();

		json_object_string_add(json_ecomm, "string", ecomm->str);
		json_object_object_add(json_path, "extendedCommunity",
				       json_ecomm);
	}

	if (pi->attr && pi->attr->aspath) {
		json_object *json_aspath = json_object_new_object();

		json_object_string_add(json_aspath, "string",
				       aspath_print(pi->attr->aspath));
		json_object_int_add(json_aspath, "length",
				    aspath_count_hops(pi->attr->aspath));
		json_object_object_add(json_path, "aspath", json_aspath);
	}
}

/*
 * Populate a JSON path object with summary fields for one
 * unreachability path (metric, locPrf, weight, reason, reporter,
 * origin, flags, pathFrom, lastUpdate, ecommunity, from).
 */
static void bgp_unreach_path_summary_json(json_object *json_path,
					   struct bgp_path_info *pi,
					   struct bgp_path_info_extra_unreach *ud)
{
	if (pi->attr)
		json_object_int_add(json_path, "metric", pi->attr->med);

	if (pi->attr &&
	    (pi->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
		json_object_int_add(json_path, "locPrf",
				    pi->attr->local_pref);

	if (pi->attr)
		json_object_int_add(json_path, "weight",
				    pi->attr->weight);

	if (ud && ud->has_reason_code) {
		const char *reason_str =
			bgp_unreach_reason_str(ud->reason_code);

		json_object_string_add(json_path, "reason", reason_str);
	}

	if (ud) {
		char reporter_ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &ud->reporter,
			  reporter_ip, sizeof(reporter_ip));
		json_object_string_add(json_path, "reporter",
				       reporter_ip);
		json_object_int_add(json_path, "reporterAs",
				    ud->reporter_as);
	}

	if (pi->attr && pi->attr->aspath)
		json_object_string_add(json_path, "path",
				       pi->attr->aspath->str);

	if (pi->attr)
		json_object_string_add(json_path, "origin",
				       bgp_origin_long_str[pi->attr->origin]);

	json_object_boolean_add(json_path, "valid",
				CHECK_FLAG(pi->flags, BGP_PATH_VALID));
	json_object_boolean_add(json_path, "best",
				CHECK_FLAG(pi->flags, BGP_PATH_SELECTED));
	json_object_boolean_add(json_path, "stale",
				CHECK_FLAG(pi->flags, BGP_PATH_STALE));
	json_object_boolean_add(json_path, "multipath",
				CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH));

	if (pi->peer && pi->peer->sort == BGP_PEER_IBGP)
		json_object_string_add(json_path, "pathFrom", "internal");
	else if (pi->peer && pi->peer->sort == BGP_PEER_EBGP)
		json_object_string_add(json_path, "pathFrom", "external");

	{
		time_t tbuf = time(NULL) - (monotime(NULL) - pi->uptime);
		char timebuf[64];
		json_object *json_last_update = json_object_new_object();

		json_object_int_add(json_last_update, "epoch", tbuf);
		json_object_string_add(json_last_update, "string",
				       ctime_r(&tbuf, timebuf));
		json_object_object_add(json_path, "lastUpdate",
				       json_last_update);
	}

	if (pi->attr && bgp_attr_get_ecommunity(pi->attr)) {
		json_object *json_ecomm = json_object_new_object();

		json_object_string_add(json_ecomm, "string",
				       bgp_attr_get_ecommunity(pi->attr)->str);
		json_object_object_add(json_path, "extendedCommunity",
				       json_ecomm);
	}

	if (pi->peer) {
		json_object *json_from = json_object_new_object();

		if (pi->peer->hostname)
			json_object_string_add(json_from, "hostname",
					       pi->peer->hostname);
		if (pi->peer->conf_if)
			json_object_string_add(json_from, "interface",
					       pi->peer->conf_if);
		else
			json_object_string_addf(json_from, "peerId",
						"%pSU",
						&pi->peer->connection->su);
		json_object_string_addf(json_from, "routerId", "%pI4",
					&pi->peer->remote_id);
		json_object_object_add(json_path, "from", json_from);
	}
}

/*
 * Print one VTY summary line for an unreachability path
 * (status codes, prefix, metric, locPrf, weight, reason, reporter,
 * aspath, origin).
 */
static void bgp_unreach_path_summary_vty(
	struct vty *vty, struct bgp_path_info *pi,
	struct bgp_path_info_extra_unreach *unreach_data,
	afi_t afi, const char *prefix_display)
{
	char reporter_str[32] = "-";
	char aspath_str[256] = "";
	const char *reason_str = "";
	char origin_str[2] = "";

	if (unreach_data) {
		char reporter_ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &unreach_data->reporter,
			  reporter_ip, sizeof(reporter_ip));
		snprintf(reporter_str, sizeof(reporter_str),
			 "%s/%u", reporter_ip,
			 unreach_data->reporter_as);

		if (unreach_data->has_reason_code)
			reason_str = bgp_unreach_reason_str(
				unreach_data->reason_code);
	}

	if (pi->attr && pi->attr->aspath) {
		const char *aspath_tmp = aspath_print(pi->attr->aspath);

		if (aspath_tmp)
			snprintf(aspath_str, sizeof(aspath_str),
				 "%s", aspath_tmp);
	}

	if (pi->attr)
		snprintf(origin_str, sizeof(origin_str), "%s",
			 bgp_origin_str[pi->attr->origin]);

	/* Status codes */
	vty_out(vty, " ");

	if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
		vty_out(vty, "R");
	else if (CHECK_FLAG(pi->flags, BGP_PATH_STALE))
		vty_out(vty, "S");
	else if (bgp_path_suppressed(pi))
		vty_out(vty, "s");
	else if (CHECK_FLAG(pi->flags, BGP_PATH_VALID) &&
		 !CHECK_FLAG(pi->flags, BGP_PATH_HISTORY))
		vty_out(vty, "*");
	else
		vty_out(vty, " ");

	if (CHECK_FLAG(pi->flags, BGP_PATH_HISTORY))
		vty_out(vty, "h");
	else if (CHECK_FLAG(pi->flags, BGP_PATH_UNSORTED))
		vty_out(vty, "u");
	else if (CHECK_FLAG(pi->flags, BGP_PATH_DAMPED))
		vty_out(vty, "d");
	else if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
		vty_out(vty, ">");
	else if (CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH))
		vty_out(vty, "=");
	else
		vty_out(vty, " ");

	if (pi->peer && (pi->peer->as) &&
	    (pi->peer->as == pi->peer->local_as))
		vty_out(vty, "i");
	else
		vty_out(vty, " ");

	if (afi == AFI_IP) {
		if (pi->attr &&
		    (pi->attr->flag &
		     ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
			vty_out(vty,
				" %-18s %7u %7u %7u %-19s %-17s %s %s\n",
				prefix_display, pi->attr->med,
				pi->attr->local_pref,
				pi->attr->weight, reason_str,
				reporter_str, aspath_str,
				origin_str);
		else
			vty_out(vty,
				" %-18s %7u        %7u %-19s %-17s %s %s\n",
				prefix_display,
				pi->attr ? pi->attr->med : 0,
				pi->attr ? pi->attr->weight : 0,
				reason_str, reporter_str,
				aspath_str, origin_str);
	} else {
		if (pi->attr &&
		    (pi->attr->flag &
		     ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
			vty_out(vty,
				" %-48s %7u %7u %7u %-19s %-17s %s %s\n",
				prefix_display, pi->attr->med,
				pi->attr->local_pref,
				pi->attr->weight, reason_str,
				reporter_str, aspath_str,
				origin_str);
		else
			vty_out(vty,
				" %-48s %7u        %7u %-19s %-17s %s %s\n",
				prefix_display,
				pi->attr ? pi->attr->med : 0,
				pi->attr ? pi->attr->weight : 0,
				reason_str, reporter_str,
				aspath_str, origin_str);
	}
}

/*
 * Build an "advertisedTo" JSON object for a destination.
 * Returns NULL if no peers advertise this route.
 */
static json_object *bgp_unreach_advertised_to_json(struct bgp *bgp,
						   struct bgp_dest *dest)
{
	json_object *json_adv_to = NULL;
	struct peer *peer;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (bgp_adj_out_lookup(peer, dest, 0)) {
			json_object *json_peer;

			if (!json_adv_to)
				json_adv_to = json_object_new_object();
			json_peer = json_object_new_object();

			if (peer->hostname)
				json_object_string_add(json_peer, "hostname",
						       peer->hostname);
			if (peer->conf_if)
				json_object_object_add(json_adv_to,
						       peer->conf_if,
						       json_peer);
			else {
				char peer_str[SU_ADDRSTRLEN];

				sockunion2str(&peer->connection->su,
					      peer_str, sizeof(peer_str));
				json_object_object_add(json_adv_to,
						       peer_str, json_peer);
			}
		}
	}

	return json_adv_to;
}

/* Show unreachability information */
void bgp_unreach_show(struct vty *vty, struct bgp *bgp, afi_t afi, struct prefix *prefix,
		      bool use_json, bool detail)
{
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	json_object *json = NULL;
	json_object *json_paths = NULL;
	int count = 0;

	if (!bgp) {
		if (use_json)
			vty_out(vty, "{}\n");
		return;
	}

	table = bgp->rib[afi][SAFI_UNREACH];
	if (!table) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "No unreachability information\n");
		return;
	}

	if (use_json)
		json = json_object_new_object();

	/* Show specific prefix or all */
	if (prefix) {
		dest = bgp_node_lookup(table, prefix);
		if (!dest) {
			if (use_json)
				vty_json(vty, json);
			else
				vty_out(vty, "%% Network not in table\n");
			return;
		}

		if (use_json)
			json_paths = json_object_new_array();
		else {
			/* Print header once before looping through paths */
			route_vty_out_detail_header(vty, bgp, dest, prefix,
						    NULL, afi, SAFI_UNREACH,
						    NULL, false, false);
		}

		int multi_path_count = 0;

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			count++;
			if (CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH))
				multi_path_count++;

			if (use_json) {
				json_object *json_path = json_object_new_object();

				bgp_unreach_path_detail_json(json_path, pi);
				json_object_array_add(json_paths, json_path);
			} else {
				/* Use standard BGP route detail display for single prefix */
				route_vty_out_detail(vty, bgp, dest, prefix,
						     pi, afi, SAFI_UNREACH,
						     RPKI_NOT_BEING_USED,
						     NULL, NULL, 0);
			}
		}

		if (use_json) {
			json_object_object_add(json, "paths", json_paths);
			json_object_int_add(json, "pathCount", count);
			json_object_int_add(json, "multiPathCount", multi_path_count);

			json_object *json_adv_to =
				bgp_unreach_advertised_to_json(bgp, dest);

			if (json_adv_to)
				json_object_object_add(json, "advertisedTo",
						       json_adv_to);

			vty_json(vty, json);
		}

		bgp_dest_unlock_node(dest);
	} else {
		/* Show all unreachability information */

		/* If detail flag, use detailed output per route */
		if (detail) {
			int prefix_count = 0;

			if (use_json)
				json = json_object_new_object();

			for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
				const struct prefix *p = bgp_dest_get_prefix(dest);
				bool has_paths = false;

				if (use_json) {
					json_paths = json_object_new_array();
					char prefix_str[PREFIX2STR_BUFFER];

					prefix2str(p, prefix_str, sizeof(prefix_str));

					for (pi = bgp_dest_get_bgp_path_info(dest); pi;
					     pi = pi->next) {
						json_object *json_path =
							json_object_new_object();

						bgp_unreach_path_detail_json(
							json_path, pi);
						json_object_array_add(json_paths,
								      json_path);
						count++;
						has_paths = true;
					}

					json_object_object_add(json, prefix_str, json_paths);
				} else {
					/* VTY detail output */
					for (pi = bgp_dest_get_bgp_path_info(dest); pi;
					     pi = pi->next) {
						route_vty_out_detail_header(
							vty, bgp, dest, p,
							NULL, afi,
							SAFI_UNREACH, NULL,
							false, false);
						route_vty_out_detail(
							vty, bgp, dest,
							p, pi, afi,
							SAFI_UNREACH,
							RPKI_NOT_BEING_USED,
							NULL, NULL, 0);
						count++;
						has_paths = true;
					}
				}

				if (has_paths)
					prefix_count++;
			}

			if (use_json) {
				vty_json(vty, json);
			} else {
				vty_out(vty,
					"\nDisplayed %d routes and %d total paths\n",
					prefix_count, count);
			}
			return;
		}

		/* Summary view */
		if (!use_json) {
			/* Print table header with status code legends (same as ipv4 unicast) */
			vty_out(vty,
				"BGP table version is %" PRIu64 ", local router ID is %pI4, vrf id %u\n",
				table->version, &bgp->router_id,
				bgp->vrf_id);
			vty_out(vty, "Default local pref %u, local AS %u\n",
				bgp->default_local_pref, bgp->as);
			vty_out(vty, BGP_UNREACH_SHOW_SCODE_HEADER);
			vty_out(vty, BGP_SHOW_OCODE_HEADER);
			vty_out(vty, BGP_SHOW_RPKI_HEADER);

			/* SAFI_UNREACH specific information */
			vty_out(vty,
				"Note: Unreachability routes are informational only and not installed in RIB/FIB\n");
			vty_out(vty, "Reason: Unreachability reason code\n");
			vty_out(vty, "Reporter: BGP router ID of the original reporter\n\n");

			/* Column header - use macros to match standard BGP style */
			if (afi == AFI_IP)
				vty_out(vty, BGP_UNREACH_SHOW_HEADER);
			else
				vty_out(vty, BGP_UNREACH_SHOW_HEADER_WIDE);
		}

		int prefix_count = 0; /* Count unique prefixes */

		for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
			const struct prefix *p = bgp_dest_get_prefix(dest);
			char buf[PREFIX2STR_BUFFER];
			bool first_path = true;
			int prefix_path_count = 0;
			int multi_path_count = 0;
			json_object *json_route_for_prefix = NULL;
			bool has_paths = false;

			for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
				struct bgp_path_info_extra_unreach *unreach_data = NULL;

				if (pi->extra && pi->extra->unreach)
					unreach_data = pi->extra->unreach;

				count++; /* Count total paths/entries */
				prefix_path_count++;
				has_paths = true;

				/* Count multipath routes */
				if (CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH))
					multi_path_count++;

				if (use_json) {
					json_object *json_route = NULL;
					json_object *json_path = NULL;

					json_paths = NULL;
					char prefix_str[PREFIX2STR_BUFFER];

					/* Get or create route object for this prefix */
					prefix2str(p, prefix_str, sizeof(prefix_str));
					if (!json_object_object_get_ex(
						    json, prefix_str,
						    &json_route)) {
						json_route =
							json_object_new_object();
						json_object_string_add(
							json_route, "prefix",
							prefix_str);
						json_paths =
							json_object_new_array();
						json_object_object_add(
							json_route, "paths",
							json_paths);
						json_object_object_add(
							json, prefix_str,
							json_route);
					} else {
						json_object_object_get_ex(
							json_route, "paths",
							&json_paths);
					}

					json_path = json_object_new_object();
					bgp_unreach_path_summary_json(
						json_path, pi, unreach_data);
					json_object_array_add(json_paths, json_path);

					/* Save reference for adding counts after loop */
					json_route_for_prefix = json_route;
				} else {
					const char *prefix_display =
						first_path
							? prefix2str(p, buf,
								     sizeof(buf))
							: "";

					bgp_unreach_path_summary_vty(
						vty, pi, unreach_data,
						afi, prefix_display);
					first_path = false;
				}
			}

			/* Add route-level fields */
			if (use_json && json_route_for_prefix) {
				json_object_int_add(json_route_for_prefix, "pathCount",
						    prefix_path_count);
				json_object_int_add(json_route_for_prefix, "multiPathCount",
						    multi_path_count);

				/* Add flags object */
				json_object *json_flags = json_object_new_object();
				struct bgp_path_info *pi_check;
				bool has_bestpath = false;

				for (pi_check = bgp_dest_get_bgp_path_info(dest); pi_check;
				     pi_check = pi_check->next) {
					if (CHECK_FLAG(pi_check->flags, BGP_PATH_SELECTED)) {
						has_bestpath = true;
						break;
					}
				}
				json_object_string_add(json_flags, "bestPathExists",
						       has_bestpath ? "true" : "false");
				json_object_object_add(json_route_for_prefix, "flags", json_flags);

				json_object *json_adv_to =
					bgp_unreach_advertised_to_json(bgp,
								       dest);

				if (json_adv_to)
					json_object_object_add(
						json_route_for_prefix,
						"advertisedTo", json_adv_to);
			}

			if (has_paths)
				prefix_count++;
		}

		if (use_json) {
			/* Add numPrefixes (consistent with unicast) */
			json_object_int_add(json, "numPrefixes", prefix_count);
			vty_json(vty, json);
		} else {
			if (count == 0)
				vty_out(vty, "No unreachability information\n");
			else
				vty_out(vty,
					"\nDisplayed %d routes and %d total paths\n",
					prefix_count, count);
		}
	}
}
