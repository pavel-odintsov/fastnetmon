// IPFIX

#include "../fast_endianless.hpp"

// Documentation about these fields can be found here: https://www.iana.org/assignments/ipfix/ipfix.xhtml
#define IPFIX_TEMPLATE_SET_ID 2
#define IPFIX_OPTIONS_SET_ID 3
#define IPFIX_MIN_RECORD_SET_ID 256

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

// Juniper SRX uses this field to encode number of octets
#define IPFIX_TOTAL_BYTES 85

// Juniper SRX uses this field to encode number of packets
#define IPFIX_TOTAL_PACKETS 86

#define IPFIX_FORWARDING_STATUS 89

#define IPFIX_FLOW_END_REASON 136

// We use 8 byte encoding for "dateTimeMilliseconds" https://tools.ietf.org/html/rfc7011#page-35
#define IPFIX_FLOW_START_MILLISECONDS 152
#define IPFIX_FLOW_END_MILLISECONDS 153

// We use 8 byte encoding: https://datatracker.ietf.org/doc/html/rfc7011#section-6.1.10
#define IPFIX_FLOW_START_NANOSECONDS 156
#define IPFIX_FLOW_END_NANOSECONDS 157

// UDP ports
#define IPFIX_UDP_SOURCE_PORT 180
#define IPFIX_UDP_DESTINATION_PORT 181

// TCP ports
#define IPFIX_TCP_SOURCE_PORT 182
#define IPFIX_TCP_DESTINATION_PORT 183

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

static_assert(sizeof(ipfix_header_common_t) == 4, "Bad size for ipfix_header_common_t");

// Described here https://datatracker.ietf.org/doc/html/rfc7011#section-3.1
class __attribute__((__packed__)) ipfix_header_t {
    public:
    uint32_t get_package_sequence_host_byte_order() const {
        return fast_ntoh(package_sequence);
    }

    uint32_t get_source_id_host_byte_order() const {
        return fast_ntoh(source_id);
    }

    uint32_t get_time_sec_host_byte_order() const {
        return fast_ntoh(time_sec);
    }

    uint16_t get_length_host_byte_order() const {
        return fast_ntoh(header.length);
    }

    private:
    ipfix_header_common_t header;
    uint32_t time_sec         = 0;
    uint32_t package_sequence = 0;
    uint32_t source_id        = 0;
};

static_assert(sizeof(ipfix_header_t) == 16, "Bad size for ipfix_header_t");

// Set header
// Described here https://datatracker.ietf.org/doc/html/rfc7011#section-3.3.2
class __attribute__((__packed__)) ipfix_set_header_common_t {
    public:
    uint16_t get_set_id_host_byte_order() const {
        return fast_ntoh(set_id);
    }

    uint16_t get_length_host_byte_order() const {
        return fast_ntoh(length);
    }

    private:
    uint16_t set_id = 0;
    uint16_t length = 0;
};

static_assert(sizeof(ipfix_set_header_common_t) == 4, "Bad size for ipfix_set_header_common_t");

// Template record header https://datatracker.ietf.org/doc/html/rfc7011#section-3.4.1
class __attribute__((__packed__)) ipfix_template_record_header_t {
    public:
    uint16_t get_template_id_host_byte_order() const {
        return fast_ntoh(template_id);
    }

    uint16_t get_field_count_host_byte_order() const {
        return fast_ntoh(field_count);
    }

    private:
    uint16_t template_id = 0;
    uint16_t field_count = 0;
};

static_assert(sizeof(ipfix_template_record_header_t) == 4, "Bad size for ipfix_template_record_header_t");

// Field specifier https://datatracker.ietf.org/doc/html/rfc7011#page-17
class __attribute__((__packed__)) ipfix_field_specifier_t {
    public:
    uint16_t get_type_host_byte_order() const {
        return fast_ntoh(type);
    }

    uint16_t get_length_host_byte_order() const {
        return fast_ntoh(length);
    }

    private:
    uint16_t type   = 0;
    uint16_t length = 0;
};

static_assert(sizeof(ipfix_field_specifier_t) == 4, "Bad size for ipfix_field_specifier_t");

// Options template record header
// https://datatracker.ietf.org/doc/html/rfc7011#page-24
class __attribute__((__packed__)) ipfix_options_template_record_header_t {
    public:
    uint16_t get_template_id_host_byte_order() const {
        return fast_ntoh(template_id);
    }

    uint16_t get_field_count_host_byte_order() const {
        return fast_ntoh(field_count);
    }

    uint16_t get_scope_field_count_host_byte_order() const {
        return fast_ntoh(scope_field_count);
    }

    private:
    uint16_t template_id       = 0;
    uint16_t field_count       = 0;
    uint16_t scope_field_count = 0;
};

static_assert(sizeof(ipfix_options_template_record_header_t) == 6, "Bad size for ipfix_options_header_t");

// It's new RFC 4 byte long format which was introduced by IPFIX update https://datatracker.ietf.org/doc/draft-ietf-opsawg-ipfix-fixes/12/
class __attribute__((__packed__)) ipfix_forwarding_status_4_bytes_t {
    public:
    // These fields carry no informatin and we have them here only to access reason_code and status
    uint8_t first_empty  = 0;
    uint8_t second_empty = 0;
    uint8_t thrid_empty  = 0;

    // That's only
    uint8_t reason_code : 6, status : 2;
};

// It's not wire friendly class, feel free to add any fields
class variable_length_encoding_info_t {
public:
    // Length encoding type: one or two byte
    variable_length_encoding_t variable_field_length_encoding = variable_length_encoding_t::unknown;

    // Store variable field length
    uint16_t variable_field_length = 0;

    // Full length of variable length field (length header + payload)
    uint32_t record_full_length = 0;
};

static_assert(sizeof(ipfix_forwarding_status_4_bytes_t) == 4, "Bad size for ipfix_forwarding_status_4_bytes_t");
