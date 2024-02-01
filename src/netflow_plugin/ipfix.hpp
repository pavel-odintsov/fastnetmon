// IPFIX

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

#define IPFIX_FRAGMENT_IDENTIFICATION 54

#define IPFIX_SOURCE_MAC_ADDRESS 56

#define IPFIX_FLOW_DIRECTION 61
#define IPFIX_IPV6_NEXT_HOP 62

#define IPFIX_DESTINATION_MAC_ADDRESS 80

#define IPFIX_FORWARDING_STATUS 89

#define IPFIX_FLOW_END_REASON 136

// We use 8 byte encoding for "dateTimeMilliseconds" https://tools.ietf.org/html/rfc7011#page-35
#define IPFIX_FLOW_START_MILLISECONDS 152
#define IPFIX_FLOW_END_MILLISECONDS 153

// We use 8 byte encoding: https://datatracker.ietf.org/doc/html/rfc7011#section-6.1.10
#define IPFIX_FLOW_START_NANOSECONDS 156
#define IPFIX_FLOW_END_NANOSECONDS 157

#define IPFIX_SAMPLING_SELECTOR_ALGORITHM 304

#define IPFIX_SAMPLING_PACKET_INTERVAL 305

#define IPFIX_SAMPLING_PACKET_SPACE 306

#define IPFIX_DATALINK_FRAME_SIZE 312
#define IPFIX_DATALINK_FRAME_SECTION 315
#define IPFIX_SELECTOR_TOTAL_PACKETS_OBSERVED 318
#define IPFIX_SELECTOR_TOTAL_PACKETS_SELECTED 319

// Sampler types https://www.iana.org/assignments/psamp-parameters/psamp-parameters.xhtml
#define IPFIX_SAMPLER_TYPE_SYSTEMATIC_COUNT_BASED_SAMPLING 1

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
