// Netflow v9

#include "../fast_endianless.hpp"

#define NETFLOW9_TEMPLATE_FLOWSET_ID 0
#define NETFLOW9_OPTIONS_FLOWSET_ID 1
#define NETFLOW9_MIN_RECORD_FLOWSET_ID 256

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

// Legacy field. Recommended replacement is NETFLOW9_DATALINK_FRAME_SIZE
// Cisco Catalyst 4500 uses this field with field NETFLOW9_LAYER2_PACKET_SECTION_DATA to deliver Netflow v9 lite
#define NETFLOW9_LAYER2_PACKET_SECTION_SIZE 103

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
