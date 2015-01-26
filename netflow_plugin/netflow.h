/*	$Id$	*/

/*
 * Copyright (c) 2004,2005 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* NetFlow packet definitions */

#ifndef _NETFLOW_H
#define _NETFLOW_H

/* A record in a NetFlow v.9 template record */
struct peer_nf9_record {
        u_int type;
        u_int len;
};


/* A NetFlow v.9 template record */
struct peer_nf9_template {
        u_int16_t template_id;
        u_int num_records;
        u_int total_len;
        std::vector <struct peer_nf9_record> records;
};


// TODO: clean up!!! 
#if defined(__GNUC__)
# ifndef __dead
#  define __dead                __attribute__((__noreturn__))
# endif
# ifndef __packed
#  define __packed              __attribute__((__packed__))
# endif
#endif

/*
 * These are Cisco Netflow(tm) packet formats
 * Based on:
 * http://www.cisco.com/univercd/cc/td/doc/product/rtrmgmt/nfc/nfc_3_0/nfc_ug/nfcform.htm
 */

/* Common header fields */
struct NF_HEADER_COMMON {
	u_int16_t version, flows;
} __packed;

/* Netflow v.1 */
struct NF1_HEADER {
	struct NF_HEADER_COMMON c;
	u_int32_t uptime_ms, time_sec, time_nanosec;
} __packed;
struct NF1_FLOW {
	u_int32_t src_ip, dest_ip, nexthop_ip;
	u_int16_t if_index_in, if_index_out;
	u_int32_t flow_packets, flow_octets;
	u_int32_t flow_start, flow_finish;
	u_int16_t src_port, dest_port;
	u_int16_t pad1;
	u_int8_t protocol, tos, tcp_flags;
	u_int8_t pad2, pad3, pad4;
	u_int32_t reserved1;
#if 0
 	u_int8_t reserved2; /* XXX: no longer used */
#endif
} __packed;

/* Maximum of 30 flows per packet */
#define NF1_MAXFLOWS		24
#define NF1_PACKET_SIZE(nflows)	(sizeof(struct NF1_HEADER) + \
				((nflows) * sizeof(struct NF1_FLOW)))
#define NF1_MAXPACKET_SIZE	(NF1_PACKET_SIZE(NF1_MAXFLOWS))

/* Netflow v.5 */
struct NF5_HEADER {
	struct NF_HEADER_COMMON c;
	u_int32_t uptime_ms, time_sec, time_nanosec, flow_sequence;
	u_int8_t engine_type, engine_id, reserved1, reserved2;
} __packed;
struct NF5_FLOW {
	u_int32_t src_ip, dest_ip, nexthop_ip;
	u_int16_t if_index_in, if_index_out;
	u_int32_t flow_packets, flow_octets;
	u_int32_t flow_start, flow_finish;
	u_int16_t src_port, dest_port;
	u_int8_t pad1;
	u_int8_t tcp_flags, protocol, tos;
	u_int16_t src_as, dest_as;
	u_int8_t src_mask, dst_mask;
	u_int16_t pad2;
} __packed;
/* Maximum of 24 flows per packet */
#define NF5_MAXFLOWS		30
#define NF5_PACKET_SIZE(nflows)	(sizeof(struct NF5_HEADER) + \
				((nflows) * sizeof(struct NF5_FLOW)))
#define NF5_MAXPACKET_SIZE	(NF5_PACKET_SIZE(NF5_MAXFLOWS))

/* Netflow v.7 */
struct NF7_HEADER {
	struct NF_HEADER_COMMON c;
	u_int32_t uptime_ms, time_sec, time_nanosec, flow_sequence;
	u_int32_t reserved1;
} __packed;
struct NF7_FLOW {
	u_int32_t src_ip, dest_ip, nexthop_ip;
	u_int16_t if_index_in, if_index_out;
	u_int32_t flow_packets, flow_octets;
	u_int32_t flow_start, flow_finish;
	u_int16_t src_port, dest_port;
	u_int8_t flags1;
	u_int8_t tcp_flags, protocol, tos;
	u_int16_t src_as, dest_as;
	u_int8_t src_mask, dst_mask;
	u_int16_t flags2;
	u_int32_t router_sc;
} __packed;
/* Maximum of 24 flows per packet */
#define NF7_MAXFLOWS		30
#define NF7_PACKET_SIZE(nflows)	(sizeof(struct NF7_HEADER) + \
				((nflows) * sizeof(struct NF7_FLOW)))
#define NF7_MAXPACKET_SIZE	(NF7_PACKET_SIZE(NF7_MAXFLOWS))

/* Netflow v.9 */
struct NF9_HEADER {
	struct NF_HEADER_COMMON c;
	u_int32_t uptime_ms, time_sec;
	u_int32_t package_sequence, source_id;
} __packed;
struct NF9_FLOWSET_HEADER_COMMON {
	u_int16_t flowset_id, length;
} __packed;
struct NF9_TEMPLATE_FLOWSET_HEADER {
	u_int16_t template_id, count;
} __packed;
struct NF9_TEMPLATE_FLOWSET_RECORD {
	u_int16_t type, length;
} __packed;
struct NF9_DATA_FLOWSET_HEADER {
	struct NF9_FLOWSET_HEADER_COMMON c;
} __packed;
#define NF9_TEMPLATE_FLOWSET_ID		0
#define NF9_OPTIONS_FLOWSET_ID		1
#define NF9_MIN_RECORD_FLOWSET_ID	256

/* Flowset record types the we care about */
#define NF9_IN_BYTES			1
#define NF9_IN_PACKETS			2
/* ... */
#define NF9_IN_PROTOCOL			4
#define NF9_SRC_TOS			5
#define NF9_TCP_FLAGS			6
#define NF9_L4_SRC_PORT			7
#define NF9_IPV4_SRC_ADDR		8
#define NF9_SRC_MASK			9
#define NF9_INPUT_SNMP			10
#define NF9_L4_DST_PORT			11
#define NF9_IPV4_DST_ADDR		12
#define NF9_DST_MASK			13
#define NF9_OUTPUT_SNMP			14
#define NF9_IPV4_NEXT_HOP		15
#define NF9_SRC_AS			16
#define NF9_DST_AS			17
/* ... */
#define NF9_LAST_SWITCHED		21
#define NF9_FIRST_SWITCHED		22
/* ... */
#define NF9_IPV6_SRC_ADDR		27
#define NF9_IPV6_DST_ADDR		28
#define NF9_IPV6_SRC_MASK		29
#define NF9_IPV6_DST_MASK		30
/* ... */
#define NF9_ENGINE_TYPE			38
#define NF9_ENGINE_ID			39
/* ... */
#define NF9_IPV6_NEXT_HOP		62

/* Netflow v.10 */
struct NF10_HEADER {
	struct NF_HEADER_COMMON c;
	u_int32_t time_sec;
	u_int32_t package_sequence, source_id;
} __packed;
struct NF10_FLOWSET_HEADER_COMMON {
	u_int16_t flowset_id, length;
} __packed;
struct NF10_TEMPLATE_FLOWSET_HEADER {
	u_int16_t template_id, count;
} __packed;
struct NF10_TEMPLATE_FLOWSET_RECORD {
	u_int16_t type, length;
} __packed;
struct NF10_DATA_FLOWSET_HEADER {
	struct NF10_FLOWSET_HEADER_COMMON c;
} __packed;
#define NF10_TEMPLATE_FLOWSET_ID	2
#define NF10_OPTIONS_FLOWSET_ID		3
#define NF10_MIN_RECORD_FLOWSET_ID	256

#define	NF10_ENTERPRISE			(1<<15)

/* Flowset record types the we care about */
#define NF10_IN_BYTES			1
#define NF10_IN_PACKETS			2
/* ... */
#define NF10_IN_PROTOCOL		4
#define NF10_SRC_TOS			5
#define NF10_TCP_FLAGS			6
#define NF10_L4_SRC_PORT		7
#define NF10_IPV4_SRC_ADDR		8
#define NF10_SRC_MASK			9
#define NF10_INPUT_SNMP			10
#define NF10_L4_DST_PORT		11
#define NF10_IPV4_DST_ADDR		12
#define NF10_DST_MASK			13
#define NF10_OUTPUT_SNMP		14
#define NF10_IPV4_NEXT_HOP		15
#define NF10_SRC_AS			16
#define NF10_DST_AS			17
/* ... */
#define NF10_LAST_SWITCHED		21
#define NF10_FIRST_SWITCHED		22
/* ... */
#define NF10_IPV6_SRC_ADDR		27
#define NF10_IPV6_DST_ADDR		28
#define NF10_IPV6_SRC_MASK		29
#define NF10_IPV6_DST_MASK		30
/* ... */
#define NF10_ENGINE_TYPE		38
#define NF10_ENGINE_ID			39
/* ... */
#define NF10_IPV6_NEXT_HOP		62

#endif /* _NETFLOW_H */

