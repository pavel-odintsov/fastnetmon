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

#pragma once

#include "../fast_endianless.hpp"
#include <boost/serialization/nvp.hpp>
#include <map>
#include <sstream>
#include <vector>

enum class netflow9_template_type { Unknown, Data, Options };

/* A record in a NetFlow v9 template record */
class peer_nf9_record_t {
    public:
    uint32_t record_type = 0;
    uint32_t record_length  = 0;

    peer_nf9_record_t(uint32_t record_type, uint32_t record_length) {
        this->record_type = record_type;
        this->record_length  = record_length;
    }

    // We created custom constructor but I still want to have default with no arguments
    peer_nf9_record_t() = default;

    // For boost serialize
    template <typename Archive> void serialize(Archive& ar, const unsigned int version) {
        ar& BOOST_SERIALIZATION_NVP(record_type);
        ar& BOOST_SERIALIZATION_NVP(record_length);
    }
};

bool operator==(const peer_nf9_record_t& lhs, const peer_nf9_record_t& rhs);
bool operator!=(const peer_nf9_record_t& lhs, const peer_nf9_record_t& rhs);

/* NetFlow v9 template record */
/* It's used for wire data decoding. Feel free to add any new fields */
class peer_nf9_template {
    public:
    uint16_t template_id = 0;
    uint32_t num_records = 0;
    uint32_t total_len   = 0;

    // Only for options templates
    uint32_t option_scope_length = 0;
    netflow9_template_type type  = netflow9_template_type::Unknown;
    std::vector<peer_nf9_record_t> records;

    // For boost serialize
    template <typename Archive> void serialize(Archive& ar, const unsigned int version) {
        ar& BOOST_SERIALIZATION_NVP(template_id);
        ar& BOOST_SERIALIZATION_NVP(num_records);
        ar& BOOST_SERIALIZATION_NVP(total_len);
        ar& BOOST_SERIALIZATION_NVP(option_scope_length);
        ar& BOOST_SERIALIZATION_NVP(type);
        ar& BOOST_SERIALIZATION_NVP(records);
    }
};

std::string print_peer_nf9_template(const peer_nf9_template& field_template);
bool operator==(const peer_nf9_template& lhs, const peer_nf9_template& rhs);
bool operator!=(const peer_nf9_template& lhs, const peer_nf9_template& rhs);

// New ASR 1000 Netflow 9 sampling template
// 1 byte
#define FLOW_SAMPLER_ID 48

// 1 byte
#define FLOW_SAMPLER_MODE 49

// Any length
#define SAMPLER_NAME 84

// 4 byte
#define FLOW_SAMPLER_RANDOM_INTERVAL 50

// Juniper MX things,
// http://www.juniper.net/techpubs/en_US/junos/topics/task/configuration/flow-aggregation-template-id-configuring-version9-ipfix.html
#define NETFLOW9_SAMPLING_INTERVAL 34

#define NETFLOW9_ACTIVE_TIMEOUT 36
#define NETFLOW9_INACTIVE_TIMEOUT 37

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
class __attribute__((__packed__)) nf_header_common_t {
    public:
    uint16_t version, flows;
};

/* Netflow v5 */
class __attribute__((__packed__)) nf5_header_t {
    public:
    nf_header_common_t c;
    uint32_t uptime_ms;
    uint32_t time_sec;
    uint32_t time_nanosec;
    uint32_t flow_sequence;
    uint8_t engine_type;
    uint8_t engine_id;
    
    // "First two bits hold the sampling mode; remaining 14 bits hold value of
    // sampling interval"
    // accoring to https://www.plixer.com/support/netflow_v5.html
    // http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html
    uint16_t sampling_rate;
};

// We are using this class for decoding messages from the wire
// Please do not add new fields here
class __attribute__((__packed__)) nf5_flow_t {
    public:
    uint32_t src_ip     = 0;
    uint32_t dest_ip    = 0;
    uint32_t nexthop_ip = 0;

    uint16_t if_index_in  = 0;
    uint16_t if_index_out = 0;

    uint32_t flow_packets = 0;
    uint32_t flow_octets  = 0;

    uint32_t flow_start  = 0;
    uint32_t flow_finish = 0;

    uint16_t src_port  = 0;
    uint16_t dest_port = 0;

    uint8_t pad1 = 0;

    uint8_t tcp_flags = 0;
    uint8_t protocol  = 0;
    uint8_t tos       = 0;

    // Autonomous system number
    uint16_t src_as  = 0;
    uint16_t dest_as = 0;

    uint8_t src_mask = 0;
    uint8_t dst_mask = 0;

    uint16_t pad2 = 0;
};

static_assert(sizeof(nf5_flow_t) == 48, "Bad size for nf5_flow_t");

#define NF5_MAXFLOWS 30
#define NF5_PACKET_SIZE(nflows) (sizeof(nf5_header_t) + ((nflows) * sizeof(nf5_flow_t)))


/* Netflow v9 */
class __attribute__((__packed__)) nf9_header_t {
    public:
    nf_header_common_t c;
    uint32_t uptime_ms;
    uint32_t time_sec;
    uint32_t package_sequence, source_id;
};

class __attribute__((__packed__)) nf9_flowset_header_common_t {
    public:
    uint16_t flowset_id, length;
};

class __attribute__((__packed__)) nf9_template_flowset_header_t {
    public:
    uint16_t template_id, count;
};

class __attribute__((__packed__)) nf9_template_flowset_record_t {
    public:
    uint16_t type, length;
};

class __attribute__((__packed__)) nf9_data_flowset_header_t {
    public:
    class nf9_flowset_header_common_t c;
};

#define NF9_TEMPLATE_FLOWSET_ID 0
#define NF9_OPTIONS_FLOWSET_ID 1
#define NF9_MIN_RECORD_FLOWSET_ID 256

/* Flowset record types the we care about */
#define NF9_IN_BYTES 1
#define NF9_IN_PACKETS 2
/* ... */
#define NF9_IN_PROTOCOL 4
#define NF9_SRC_TOS 5
#define NF9_TCP_FLAGS 6
#define NF9_L4_SRC_PORT 7
#define NF9_IPV4_SRC_ADDR 8
#define NF9_SRC_MASK 9
#define NF9_INPUT_SNMP 10
#define NF9_L4_DST_PORT 11
#define NF9_IPV4_DST_ADDR 12
#define NF9_DST_MASK 13
#define NF9_OUTPUT_SNMP 14
#define NF9_IPV4_NEXT_HOP 15
#define NF9_SRC_AS 16
#define NF9_DST_AS 17
/* ... */
#define NF9_LAST_SWITCHED 21
#define NF9_FIRST_SWITCHED 22
/* ... */
#define NF9_IPV6_SRC_ADDR 27
#define NF9_IPV6_DST_ADDR 28
#define NF9_IPV6_SRC_MASK 29
#define NF9_IPV6_DST_MASK 30

#define NF9_SAMPLING_INTERVAL 34

/* ... */
#define NF9_ENGINE_TYPE 38
#define NF9_ENGINE_ID 39
/* ... */
#define NF9_IPV6_NEXT_HOP 62

#define NF9_FORWARDING_STATUS 89

#define NF9_LAYER2_PACKET_SECTION_DATA 104

#define NF9_DATALINK_FRAME_SIZE 312
#define NF9_SELECTOR_TOTAL_PACKETS_OBSERVED 318
#define NF9_SELECTOR_TOTAL_PACKETS_SELECTED 319


/* Netflow v10 */
class __attribute__((__packed__)) nf10_header_t {
    public:
    nf_header_common_t c;
    uint32_t time_sec = 0;
    uint32_t package_sequence = 0;
    uint32_t source_id = 0;
};

class __attribute__((__packed__)) nf10_flowset_header_common_t {
    public:
    uint16_t flowset_id = 0;
    uint16_t length = 0;
};

class __attribute__((__packed__)) nf10_template_flowset_header_t {
    public:
    uint16_t template_id = 0;
    uint16_t count = 0;
};

class __attribute__((__packed__)) nf10_template_flowset_record_t {
    public:
    uint16_t type, length;
};

class __attribute__((__packed__)) nf10_data_flowset_header_t {
    public:
    nf10_flowset_header_common_t c;
};

#define NF10_TEMPLATE_FLOWSET_ID 2
#define NF10_OPTIONS_FLOWSET_ID 3
#define NF10_MIN_RECORD_FLOWSET_ID 256

#define NF10_ENTERPRISE (1 << 15)

/* Flowset record types the we care about */
#define NF10_IN_BYTES 1
#define NF10_IN_PACKETS 2
/* ... */
#define NF10_IN_PROTOCOL 4
#define NF10_SRC_TOS 5
#define NF10_TCP_FLAGS 6
#define NF10_L4_SRC_PORT 7
#define NF10_IPV4_SRC_ADDR 8
#define NF10_SRC_MASK 9
#define NF10_INPUT_SNMP 10
#define NF10_L4_DST_PORT 11
#define NF10_IPV4_DST_ADDR 12
#define NF10_DST_MASK 13
#define NF10_OUTPUT_SNMP 14
#define NF10_IPV4_NEXT_HOP 15
#define NF10_SRC_AS 16
#define NF10_DST_AS 17
/* ... */
#define NF10_LAST_SWITCHED 21
#define NF10_FIRST_SWITCHED 22
/* ... */
#define NF10_IPV6_SRC_ADDR 27
#define NF10_IPV6_DST_ADDR 28
#define NF10_IPV6_SRC_MASK 29
#define NF10_IPV6_DST_MASK 30
/* ... */
// RFC claims that this field is deprecated in favour of NF10_SAMPLING_PACKET_INTERVAL but many vendors use it, we need to support it too
#define NF10_SAMPLING_INTERVAL 34
/* ... */
#define NF10_ENGINE_TYPE 38
#define NF10_ENGINE_ID 39
/* ... */
#define NF10_IPV6_NEXT_HOP 62

#define NF10_FLOW_END_REASON 136

// We use 8 byte encoding for "dateTimeMilliseconds" https://tools.ietf.org/html/rfc7011#page-35
#define NF10_FLOW_START_MILLISECONDS 152
#define NF10_FLOW_END_MILLISECONDS 153

#define NF10_SAMPLING_PACKET_INTERVAL 305

// IPFIX options structures
class __attribute__((__packed__)) ipfix_options_header_common_t {
    public:
    uint16_t flowset_id = 0;
    uint16_t length = 0;
};

class __attribute__((__packed__)) ipfix_options_header_t {
    public:
    uint16_t template_id = 0;
    uint16_t field_count = 0;
    uint16_t scope_field_count = 0;
};

// Docs about format http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
class __attribute__((__packed__)) nf9_options_header_common_t {
    public:
    uint16_t flowset_id = 0;
    uint16_t length = 0;
};


class __attribute__((__packed__)) nf9_options_header_t {
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

typedef std::map<uint32_t, peer_nf9_template> template_storage_t;
typedef std::map<std::string, template_storage_t> global_template_storage_t;

std::string get_netflow9_template_type_as_string(netflow9_template_type type);
