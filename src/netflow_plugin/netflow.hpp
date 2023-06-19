// ISC license header

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

// Netflow packet definitions

#pragma once

#include "../fast_endianless.hpp"
#include <boost/serialization/nvp.hpp>
#include <map>
#include <sstream>
#include <vector>

enum class netflow_protocol_version_t { netflow_v5, netflow_v9, ipfix };

// According to spec it should be 4 bytes:
// http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
#define FLOW_SAMPLER_RANDOM_INTERVAL_LENGTH 4

// But in real world I saw this one for Cisco ASR1000
#define FLOW_SAMPLER_RANDOM_INTERVAL_LENGTH_ASR1000 2

/*
 * These are Cisco Netflow(tm) packet formats
 * Based on:
 * http://www.cisco.com/univercd/cc/td/doc/product/rtrmgmt/nfc/nfc_3_0/nfc_ug/nfcform.htm
 */

/* Common header fields */
class __attribute__((__packed__)) netflow_header_common_t {
    public:
    uint16_t version = 0;
    uint16_t flows   = 0;
};

/* Netflow v5 */
class __attribute__((__packed__)) netflow5_header_t {
    public:
    netflow_header_common_t header;
    uint32_t uptime_ms     = 0;
    uint32_t time_sec      = 0;
    uint32_t time_nanosec  = 0;
    uint32_t flow_sequence = 0;
    uint8_t engine_type    = 0;
    uint8_t engine_id      = 0;

    // "First two bits hold the sampling mode; remaining 14 bits hold value of
    // sampling interval"
    // according to https://www.plixer.com/support/netflow_v5.html
    // http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html
    uint16_t sampling_rate = 0;
};

// We are using this class for decoding messages from the wire
// Please do not add new fields here
class __attribute__((__packed__)) netflow5_flow_t {
    public:
    // Source IP
    uint32_t src_ip = 0;

    // Destination IP
    uint32_t dest_ip = 0;

    // IPv4 next hop
    uint32_t nexthop_ip = 0;

    // Input interface
    uint16_t if_index_in = 0;

    // Output interface
    uint16_t if_index_out = 0;

    // Number of packets in flow
    uint32_t flow_packets = 0;

    // Number of bytes / octets in flow
    uint32_t flow_octets = 0;

    // Flow start time in milliseconds
    uint32_t flow_start = 0;

    // Flow end time in milliseconds
    uint32_t flow_finish = 0;

    // Source port
    uint16_t src_port = 0;

    // Destination port
    uint16_t dest_port = 0;

    // Padding
    uint8_t pad1 = 0;

    // TCP flags
    uint8_t tcp_flags = 0;

    // Protocol number
    uint8_t protocol = 0;

    // Type of service
    uint8_t tos = 0;

    // Source ASN
    uint16_t src_as = 0;

    // Destination ASN
    uint16_t dest_as = 0;

    // Source mask length
    uint8_t src_mask = 0;

    // Destination mask length
    uint8_t dst_mask = 0;

    // Padding
    uint16_t pad2 = 0;
};

static_assert(sizeof(netflow5_flow_t) == 48, "Bad size for netflow5_flow_t");

#define NETFLOW5_MAXFLOWS 30
#define NETFLOW5_PACKET_SIZE(nflows) (sizeof(netflow5_header_t) + ((nflows) * sizeof(netflow5_flow_t)))


/* Netflow v9 */

class __attribute__((__packed__)) netflow9_header_common_t {
    public:
    uint16_t version        = 0;
    uint16_t flowset_number = 0;
};


class __attribute__((__packed__)) netflow9_header_t {
    public:
    netflow9_header_common_t header;
    uint32_t uptime_ms        = 0;
    uint32_t time_sec         = 0;
    uint32_t package_sequence = 0;
    uint32_t source_id        = 0;
};

class __attribute__((__packed__)) netflow9_flowset_header_common_t {
    public:
    uint16_t flowset_id = 0;
    uint16_t length     = 0;
};

class __attribute__((__packed__)) netflow9_template_flowset_header_t {
    public:
    uint16_t template_id  = 0;
    uint16_t fields_count = 0;
};

class __attribute__((__packed__)) netflow9_template_flowset_record_t {
    public:
    uint16_t type   = 0;
    uint16_t length = 0;
};

class __attribute__((__packed__)) netflow9_data_flowset_header_t {
    public:
    netflow9_flowset_header_common_t header;
};

#define NETFLOW9_TEMPLATE_FLOWSET_ID 0
#define NETFLOW9_OPTIONS_FLOWSET_ID 1
#define NETFLOW9_MIN_RECORD_FLOWSET_ID 256

/* Flowset record types the we care about */
#define NETFLOW9_IN_BYTES 1
#define NETFLOW9_IN_PACKETS 2
#define NETFLOW9_IN_PROTOCOL 4
#define NETFLOW9_SRC_TOS 5
#define NETFLOW9_TCP_FLAGS 6
#define NETFLOW9_L4_SRC_PORT 7
#define NETFLOW9_IPV4_SRC_ADDR 8
#define NETFLOW9_SRC_MASK 9
#define NETFLOW9_INPUT_SNMP 10
#define NETFLOW9_L4_DST_PORT 11
#define NETFLOW9_IPV4_DST_ADDR 12
#define NETFLOW9_DST_MASK 13
#define NETFLOW9_OUTPUT_SNMP 14
#define NETFLOW9_IPV4_NEXT_HOP 15
#define NETFLOW9_SRC_AS 16
#define NETFLOW9_DST_AS 17
#define NETFLOW9_BGP_NEXT_HOP_IPV4_ADDRESS 18
#define NETFLOW9_LAST_SWITCHED 21
#define NETFLOW9_FIRST_SWITCHED 22
#define NETFLOW9_IPV6_SRC_ADDR 27
#define NETFLOW9_IPV6_DST_ADDR 28
#define NETFLOW9_IPV6_SRC_MASK 29
#define NETFLOW9_IPV6_DST_MASK 30
// Juniper MX things,
// http://www.juniper.net/techpubs/en_US/junos/topics/task/configuration/flow-aggregation-template-id-configuring-version9-ipfix.html
#define NETFLOW9_SAMPLING_INTERVAL 34
#define NETFLOW9_ACTIVE_TIMEOUT 36
#define NETFLOW9_INACTIVE_TIMEOUT 37
#define NETFLOW9_ENGINE_TYPE 38
#define NETFLOW9_ENGINE_ID 39

// ASR 1000 and ASR 9000 use it
// It can be used for data and options template and length may by different in each case
#define NETFLOW9_FLOW_SAMPLER_ID 48

// 1 byte
#define NETFLOW9_FLOW_SAMPLER_MODE 49

// 4 byte
#define NETFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL 50

#define NETFLOW9_SOURCE_MAC_ADDRESS 56

#define NETFLOW9_IPV6_NEXT_HOP 62

#define NETFLOW9_DESTINATION_MAC_ADDRESS 80

#define NETFLOW9_INTERFACE_DESCRIPTION 83

// Any length
#define NETFLOW9_SAMPLER_NAME 84

#define NETFLOW9_FORWARDING_STATUS 89
#define NETFLOW9_LAYER2_PACKET_SECTION_DATA 104

#define NETFLOW9_FLOW_ID 148

// Cisco calls them "timestamp absolute first" and "timestamp absolute last"
#define NETFLOW9_START_MILLISECONDS 152
#define NETFLOW9_END_MILLISECONDS 153

// These fields have alternative naming initiator and responder and I find such naming just ridiculous and very tricky to understand
// This Cisco ASA guide uses more clear way to name them as source and destination: https://www.cisco.com/c/en/us/td/docs/security/asa/special/netflow/asa_netflow.html
#define NETFLOW9_BYTES_FROM_SOURCE_TO_DESTINATION 231
#define NETFLOW9_BYTES_FROM_DESTINATION_TO_SOURCE 232

#define NETFLOW9_PACKETS_FROM_SOURCE_TO_DESTINATION 298
#define NETFLOW9_PACKETS_FROM_DESTINATION_TO_SOURCE 299

#define NETFLOW9_DATALINK_FRAME_SIZE 312
#define NETFLOW9_SELECTOR_TOTAL_PACKETS_OBSERVED 318
#define NETFLOW9_SELECTOR_TOTAL_PACKETS_SELECTED 319

// IPFIX

class __attribute__((__packed__)) ipfix_header_common_t {
    public:
    uint16_t version = 0;
    //  Total length of the IPFIX Message, measured in octets, including Message Header and Set(s).
    uint16_t length = 0;
};

class __attribute__((__packed__)) ipfix_header_t {
    public:
    ipfix_header_common_t header;
    uint32_t time_sec         = 0;
    uint32_t package_sequence = 0;
    uint32_t source_id        = 0;
};

class __attribute__((__packed__)) ipfix_flowset_header_common_t {
    public:
    uint16_t flowset_id = 0;
    uint16_t length     = 0;
};

class __attribute__((__packed__)) ipfix_template_flowset_header_t {
    public:
    uint16_t template_id  = 0;
    uint16_t record_count = 0;
};

class __attribute__((__packed__)) ipfix_template_flowset_record_t {
    public:
    uint16_t type   = 0;
    uint16_t length = 0;
};

class __attribute__((__packed__)) ipfix_data_flowset_header_t {
    public:
    ipfix_flowset_header_common_t header;
};


// Documentation about these fields can be found here: https://www.iana.org/assignments/ipfix/ipfix.xhtml
#define IPFIX_TEMPLATE_FLOWSET_ID 2
#define IPFIX_OPTIONS_FLOWSET_ID 3
#define IPFIX_MIN_RECORD_FLOWSET_ID 256

#define IPFIX_ENTERPRISE (1 << 15)

// Record types the we care about
#define IPFIX_IN_BYTES 1
#define IPFIX_IN_PACKETS 2

#define IPFIX_IN_PROTOCOL 4
#define IPFIX_SRC_TOS 5
#define IPFIX_TCP_FLAGS 6
#define IPFIX_L4_SRC_PORT 7
#define IPFIX_IPV4_SRC_ADDR 8
#define IPFIX_SRC_MASK 9
#define IPFIX_INPUT_SNMP 10
#define IPFIX_L4_DST_PORT 11
#define IPFIX_IPV4_DST_ADDR 12
#define IPFIX_DST_MASK 13
#define IPFIX_OUTPUT_SNMP 14
#define IPFIX_IPV4_NEXT_HOP 15
#define IPFIX_SRC_AS 16
#define IPFIX_DST_AS 17

#define IPFIX_BGP_NEXT_HOP_IPV4_ADDRESS 18

#define IPFIX_LAST_SWITCHED 21
#define IPFIX_FIRST_SWITCHED 22

#define IPFIX_IPV6_SRC_ADDR 27
#define IPFIX_IPV6_DST_ADDR 28
#define IPFIX_IPV6_SRC_MASK 29
#define IPFIX_IPV6_DST_MASK 30

// RFC claims that this field is deprecated in favour of IPFIX_SAMPLING_PACKET_INTERVAL but many vendors use it, we need to support it too
#define IPFIX_SAMPLING_INTERVAL 34

#define IPFIX_ACTIVE_TIMEOUT 36
#define IPFIX_INACTIVE_TIMEOUT 37

#define IPFIX_ENGINE_TYPE 38
#define IPFIX_ENGINE_ID 39

#define IPFIX_FLOW_DIRECTION 61
#define IPFIX_IPV6_NEXT_HOP 62

#define IPFIX_FORWARDING_STATUS 89

#define IPFIX_FLOW_END_REASON 136

// We use 8 byte encoding for "dateTimeMilliseconds" https://tools.ietf.org/html/rfc7011#page-35
#define IPFIX_FLOW_START_MILLISECONDS 152
#define IPFIX_FLOW_END_MILLISECONDS 153

#define IPFIX_SAMPLING_PACKET_INTERVAL 305

#define IPFIX_SAMPLING_PACKET_SPACE 306

#define IPFIX_DATALINK_FRAME_SIZE 312
#define IPFIX_DATALINK_FRAME_SECTION 315
#define IPFIX_SELECTOR_TOTAL_PACKETS_OBSERVED 318
#define IPFIX_SELECTOR_TOTAL_PACKETS_SELECTED 319

// IPFIX options structures
class __attribute__((__packed__)) ipfix_options_header_common_t {
    public:
    uint16_t flowset_id = 0;
    uint16_t length     = 0;
};

class __attribute__((__packed__)) ipfix_options_header_t {
    public:
    uint16_t template_id       = 0;
    uint16_t field_count       = 0;
    uint16_t scope_field_count = 0;
};

// Docs about format http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
class __attribute__((__packed__)) netflow9_options_header_common_t {
    public:
    uint16_t flowset_id = 0;
    uint16_t length     = 0;
};


class __attribute__((__packed__)) netflow9_options_header_t {
    public:
    uint16_t template_id         = 0;
    uint16_t option_scope_length = 0;
    uint16_t option_length       = 0;

    std::string print() {
        std::stringstream buffer;

        buffer << "template_id: " << fast_ntoh(template_id) << " "
               << "option_scope_length: " << fast_ntoh(option_scope_length) << " "
               << "option_length: " << fast_ntoh(option_length);

        return buffer.str();
    }
};

// https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
// I think we can use same format for IPFIX: https://datatracker.ietf.org/doc/html/rfc7270#section-4.12
class __attribute__((__packed__)) netflow9_forwarding_status_t {
    public:
    uint8_t reason_code : 6, status : 2;
};

// This class carries mapping between interface ID and human friendly interface name
class interface_id_to_name_t {
    public:
    uint32_t interface_id = 0;
    std::string interface_description{};
};
