#pragma once

#include <bitset>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>

#include "iana_ethertypes.h"
#include "iana_ip_protocols.h"

/*
 * TODO:
 * Add strict type check for ntohl/ntohs and ntonl/htons
 *
*/

#include <arpa/inet.h> // ntohs, ntohl

// This function could copy X bytes from src to dst.
// Where X - size of dst object (referenced by pointer)
template <typename dst_type, typename src_type> inline void* smart_memcpy(dst_type* dst, const src_type* src) {
    return memcpy(dst, src, sizeof(dst_type));
}

namespace network_data_stuctures {
/* We are using this structure as pretty interface for IPv4 address bytes in
 * host byte order (little
 * endian) */
struct __attribute__((__packed__)) ipv4_octets_form_little_endian_t {
    uint8_t fourth;
    uint8_t third;
    uint8_t second;
    uint8_t first;
};

// Convert IP as integer to string representation
inline std::string convert_ip_as_little_endian_to_string(uint32_t ip) {
    /*
        Actually we could use inet_ntoa but it's implementation uses not very
       convenient data
       structures (struct in_addr)
        Also it has multi thread issues (because it's using common buffer) and it
       solved by thread
       local storage.
        Which could produce performance issues too (chec http://www.agner.org)

        Here you could
       https://github.com/bminor/glibc/blob/0a1f1e78fbdfaf2c01e9c2368023b2533e7136cf/inet/inet_ntoa.c#L31
        And has known performance issues: https://github.com/h2o/qrintf
        I decided to implement it manually
    */

    const size_t max_ip_as_string_size = 16; // Maximum string length as integer
    char buffer[max_ip_as_string_size];

    ipv4_octets_form_little_endian_t* ipv4_octets = (ipv4_octets_form_little_endian_t*)&ip;

    snprintf(buffer, max_ip_as_string_size, "%d.%d.%d.%d", ipv4_octets->first, ipv4_octets->second, ipv4_octets->third,
             ipv4_octets->fourth);

    return std::string(buffer);
}

// Here we are using very cryptic form of pointer to fixed size array
inline std::string convert_mac_to_string(uint8_t (&mac_as_array)[6]) {
    std::stringstream buffer;

    for (int i = 0; i < 6; i++) {
        buffer << std::hex << std::setfill('0') << std::setw(2) << int(mac_as_array[i]);

        if (i != 5) {
            buffer << ":";
        }
    }

    return buffer.str();
}

// TODO: it's not finished yet
class __attribute__((__packed__)) mpls_label_t {
    public:
    uint32_t label : 20, qos : 3, bottom_of_stack : 1, ttl : 8;

    std::string print() {
        std::stringstream buffer;

        buffer << "label: " << uint32_t(label) << " "
               << "qos: " << uint32_t(qos) << " "
               << "bottom of stack: " << uint32_t(bottom_of_stack) << " "
               << "ttl: " << uint32_t(ttl);

        return buffer.str();
    }
};

static_assert(sizeof(mpls_label_t) == 4, "Bad size for mpls_label_t");

// We are storing vlan meta data and next ethertype in same packet
// It's not standard approach! Be careful!
class __attribute__((__packed__)) ethernet_vlan_header_t {
    public:
    union {
        __extension__ struct { uint16_t vlan_id : 12, cfi : 1, priority : 3; };
        uint16_t vlan_metadata_as_integer;
    };

    uint16_t ethertype;

    void convert() {
        ethertype                = ntohs(ethertype);
        vlan_metadata_as_integer = ntohs(vlan_metadata_as_integer);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "priority: " << uint32_t(priority) << " "
               << "cfi: " << uint32_t(cfi) << " "
               << "vlan_id: " << uint32_t(vlan_id) << " "
               << "ethertype: " << ethertype;

        return buffer.str();
    }
};

static_assert(sizeof(ethernet_vlan_header_t) == 4, "Bad size for ethernet_vlan_header_t");

class __attribute__((__packed__)) ethernet_header_t {
    public:
    uint8_t destination_mac[6];
    uint8_t source_mac[6];
    uint16_t ethertype;

    void convert() {
        ethertype = ntohs(ethertype);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "ethertype: 0x" << std::setfill('0') << std::setw(4) << std::hex << ethertype << " "
               << "source mac: " << convert_mac_to_string(source_mac) << " "
               << "destination mac: " << convert_mac_to_string(destination_mac);

        return buffer.str();
    }
};

static_assert(sizeof(ethernet_header_t) == 14, "Bad size for ethernet_header_t");

// Please be careful!
// This structure will work only for IPv4 (4 byte address) + ethernet (6 byte
// address)
class __attribute__((__packed__)) arp_header_t {
    public:
    uint16_t hardware_type;
    uint16_t protocol_type;

    uint8_t hardware_address_length;
    uint8_t protocol_address_length;

    uint16_t operation;
    uint8_t sender_hardware_address[6];
    uint32_t sender_protocol_address;
    uint8_t target_hardware_address[6];
    uint32_t target_protocol_address;

    void convert() {
        // 16 bit
        hardware_type = ntohs(hardware_type);
        protocol_type = ntohs(protocol_type);
        operation     = ntohs(operation);

        // 32 bit
        sender_protocol_address = ntohl(sender_protocol_address);
        target_protocol_address = ntohl(target_protocol_address);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "hardware_type: " << uint32_t(hardware_type) << " "
               << "protocol_type: " << uint32_t(protocol_type) << " "
               << "hardware_address_length: " << uint32_t(hardware_address_length) << " "
               << "protocol_address_length: " << uint32_t(protocol_address_length) << " "
               << "operation: " << uint32_t(operation) << " "
               << "sender_hardware_address: " << convert_mac_to_string(sender_hardware_address) << " "
               << "sender_protocol_address: " << convert_ip_as_little_endian_to_string(sender_protocol_address) << " "
               << "target_hardware_address: " << convert_mac_to_string(target_hardware_address) << " "
               << "target_protocol_address: " << convert_ip_as_little_endian_to_string(target_protocol_address);

        return buffer.str();
    }
};

class __attribute__((__packed__)) icmp_header_t {
    public:
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest_of_header;

    void convert() {
        checksum = htons(checksum);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "type: " << uint32_t(type) << " "
               << "code: " << uint32_t(code) << " "
               << "checksum: " << uint32_t(checksum);

        return buffer.str();
    }
};

class __attribute__((__packed__)) udp_header_t {
    public:
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;

    void convert() {
        source_port      = ntohs(source_port);
        destination_port = ntohs(destination_port);
        length           = ntohs(length);
        checksum         = ntohs(checksum);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "source_port: " << source_port << " "
               << "destination_port: " << destination_port << " "
               << "length: " << length << " "
               << "cheksum: " << checksum;

        return buffer.str();
    }
};

static_assert(sizeof(udp_header_t) == 8, "Bad size for udp_header_t");

// It's tcp packet flags represented as bitfield for user friendly access to this flags
class __attribute__((__packed__)) tcp_flags_as_uint16_t {
    public:
    uint16_t fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1, ns : 1, reserved : 3, data_offset : 4;

    std::string print() {
        std::stringstream buffer;

        buffer << "data_offset: " << uint32_t(data_offset) << " "
               << "reserved: " << uint32_t(reserved) << " "
               << "ns: " << uint32_t(ns) << " "
               << "cwr: " << uint32_t(cwr) << " "
               << "ece: " << uint32_t(ece) << " "
               << "urg: " << uint32_t(urg) << " "
               << "ack: " << uint32_t(ack) << " "
               << "psh: " << uint32_t(psh) << " "
               << "rst: " << uint32_t(rst) << " "
               << "syn: " << uint32_t(syn) << " "
               << "fin: " << uint32_t(fin);

        return buffer.str();
    }
};

// It's another version of previous code suitable for nice casting from 32 bit
class __attribute__((__packed__)) tcp_flags_as_uint32_t {
    public:
    tcp_flags_as_uint16_t data;
    uint16_t not_used1;
    uint8_t not_used2;
    std::string print() {
        return data.print();
    }
};

class __attribute__((__packed__)) tcp_header_t {
    public:
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t ack_number;
    union {
        __extension__ struct __attribute__((__packed__)) {
            // uint16_t data_offset : 4, reserved : 3, ns : 1, cwr : 1, ece : 1, urg :
            // 1, ack : 1,
            // psh : 1, rst : 1, syn : 1, fin : 1;
            uint16_t fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1, ns : 1, reserved : 3, data_offset : 4;
        };

        uint16_t data_offset_and_flags_as_integer;
    };
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent;

    void convert() {
        // 16 bit data
        source_port      = ntohs(source_port);
        destination_port = ntohs(destination_port);
        window_size      = ntohs(window_size);
        checksum         = ntohs(checksum);
        urgent           = ntohs(urgent);

        data_offset_and_flags_as_integer = ntohs(data_offset_and_flags_as_integer);

        // 32 bit data
        sequence_number = ntohl(sequence_number);
        ack_number      = ntohl(ack_number);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "source_port: " << source_port << " "
               << "destination_port: " << destination_port << " "
               << "sequence_number: " << sequence_number << " "
               << "ack_number: " << ack_number << " "
               << "data_offset: " << uint32_t(data_offset) << " "
               << "reserved: " << uint32_t(reserved) << " "
               << "ns: " << uint32_t(ns) << " "
               << "cwr: " << uint32_t(cwr) << " "
               << "ece: " << uint32_t(ece) << " "
               << "urg: " << uint32_t(urg) << " "
               << "ack: " << uint32_t(ack) << " "
               << "psh: " << uint32_t(psh) << " "
               << "rst: " << uint32_t(rst) << " "
               << "syn: " << uint32_t(syn) << " "
               << "fin: " << uint32_t(fin) << " "
               << "window_size: " << window_size << " "
               << "checksum: " << checksum << " "
               << "urgent: " << urgent;

        return buffer.str();
    }
};

static_assert(sizeof(tcp_header_t) == 20, "Bad size for tcp_header_t");

typedef uint8_t ipv6_address[16];

// Custom type for pretty printing
typedef uint16_t ipv6_address_16bit_blocks[8];

inline std::string convert_ipv6_in_big_endian_to_string(uint8_t (&v6_address)[16]) {
    std::stringstream buffer;

    uint16_t* pretty_print = (uint16_t*)v6_address;

    for (int i = 0; i < 8; i++) {
        buffer << std::hex << ntohs(pretty_print[i]);

        if (i != 7) {
            buffer << ":";
        }
    }

    return buffer.str();
}

/*
    For full IPv6 support we should implement following option types:
   https://tools.ietf.org/html/rfc2460#page-7

       Hop-by-Hop Options - IpProtocolNumberHOPOPT
       Routing (Type 0) - IpProtocolNumberIPV6_ROUTE
       Fragment - IpProtocolNumberIPV6_FRAG
       Destination Options - IpProtocolNumberIPV6_OPTS
       Authentication - IpProtocolNumberAH
       Encapsulating Security Payload - IpProtocolNumberESP
*/

/* IPv6 fragmentation header option */
class __attribute__((__packed__)) ipv6_extention_header_fragment_t {
    public:
    uint8_t next_header;
    uint8_t reserved1;
    union {
        __extension__ struct {
            // uint16_t fragment_offset : 13, reserved2 : 2, more_fragments : 1;
            uint16_t more_fragments : 1, reserved2 : 2, fragment_offset : 13;
        };
        uint16_t fragmentation_and_flags_as_integer;
    };

    uint32_t identification;

    void convert() {
        fragmentation_and_flags_as_integer = ntohs(fragmentation_and_flags_as_integer);
        identification                     = ntohl(identification);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "next_header: " << uint32_t(next_header) << " "
               << "reserved1: " << uint32_t(reserved1) << " "
               << "fragment_offset: " << uint32_t(fragment_offset) << " "
               << "reserverd2: " << uint32_t(reserved2) << " "
               << "more_fragments: " << uint32_t(more_fragments) << " "
               << "identification: " << identification;

        return buffer.str();
    }
};

static_assert(sizeof(ipv6_extention_header_fragment_t) == 8, "Bad size for ipv6_extention_header_fragment_t");

class __attribute__((__packed__)) ipv6_header_t {
    public:
    union {
        __extension__ struct { uint32_t flow_label : 20, traffic_class : 8, version : 4; };

        uint32_t version_and_traffic_class_as_integer;
    };
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    ipv6_address source_address;
    ipv6_address destination_address;

    void convert() {
        payload_length                       = ntohs(payload_length);
        version_and_traffic_class_as_integer = ntohl(version_and_traffic_class_as_integer);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "version: " << uint32_t(version) << " "
               << "traffic_class: " << uint32_t(traffic_class) << " "
               << "flow_label: " << uint32_t(flow_label) << " "
               << "payload_length: " << uint32_t(payload_length) << " "
               << "next_header: " << uint32_t(next_header) << " "
               << "hop_limit: " << uint32_t(hop_limit) << " "
               << "source_address: " << convert_ipv6_in_big_endian_to_string(source_address) << " "
               << "destination_address: " << convert_ipv6_in_big_endian_to_string(destination_address);

        return buffer.str();
    }
};

static_assert(sizeof(ipv6_header_t) == 40, "Bad size for ipv6_header_t");

// It's class for fragmentation flag representation. It's pretty useful in some cases
class __attribute__((__packed__)) ipv4_header_fragmentation_flags_t {
    public:
    union {
        // We should store bitfields in nested struct. Othervise each of bitfields
        // will use same
        // storage as each other!
        // We are using GCC extension here. It's working perfectly for clang and gcc
        // but could
        // produce warning in pedantic mode
        __extension__ struct {
            uint16_t fragment_offset : 13, more_fragments_flag : 1, dont_fragment_flag : 1, reserved_flag : 1;
        };

        uint16_t fragmentation_details_as_integer;
    };

    std::string print() {

        std::stringstream buffer;
        buffer << "fragment_offset: " << uint32_t(fragment_offset) << " "
               << "reserved_flag: " << uint32_t(reserved_flag) << " "
               << "dont_fragment_flag: " << uint32_t(dont_fragment_flag) << " "
               << "more_fragments_flag: " << uint32_t(more_fragments_flag);

        return buffer.str();
    }
};

// It's another version of previous code suitable for nice casting from 32 bit
class __attribute__((__packed__)) ipv4_header_fragmentation_flags_as_32bit_t {
    public:
    ipv4_header_fragmentation_flags_t data;
    uint16_t not_used1;

    std::string print() {
        return data.print();
    }
};

class __attribute__((__packed__)) ipv4_header_t {
    public:
    uint8_t ihl : 4, version : 4;
    uint8_t ecn : 2, dscp : 6;

    // This is the combined length of the header and the data
    uint16_t total_length;
    uint16_t identification;

    union {
        // We should store bitfields in nested struct. Othervise each of bitfields
        // will use same
        // storage as each other!
        // We are using GCC extension here. It's working perfectly for clang and gcc
        // but could
        // produce warning in pedantic mode
        __extension__ struct {
            uint16_t fragment_offset : 13, more_fragments_flag : 1, dont_fragment_flag : 1, reserved_flag : 1;
        };

        uint16_t fragmentation_details_as_integer;
    };

    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t source_ip;
    uint32_t destination_ip;

    ipv4_header_t()
    : version(0), ihl(0), ecn(0), dscp(0), total_length(0), identification(0), ttl(0), protocol(0), checksum(0),
      source_ip(0), destination_ip(0), fragmentation_details_as_integer(0) {
    }

    // Should be called AFTER convert() call
    bool is_fragmented() {
        if (this->more_fragments_flag != 0) {
            return true;
        }

        if (this->fragment_offset != 0) {
            return true;
        }

        return false;
    }

    void convert() {
        // Convert all 2 or 4 byte values to little endian from network format (big
        // endian)

        // 4 byte integers
        source_ip      = ntohl(source_ip);
        destination_ip = ntohl(destination_ip);

        fragmentation_details_as_integer = ntohs(fragmentation_details_as_integer);

        // 2 byte integers
        identification = ntohs(identification);
        total_length   = ntohs(total_length);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "version: " << uint32_t(version) << " "
               << "ihl: " << uint32_t(ihl) << " "
               << "dscp: " << uint32_t(dscp) << " "
               << "ecn: " << uint32_t(ecn) << " "
               << "length: " << uint32_t(total_length) << " "
               << "identification: " << uint32_t(identification) << " "
               << "fragment_offset: " << uint32_t(fragment_offset) << " "
               << "reserved_flag: " << uint32_t(reserved_flag) << " "
               << "dont_fragment_flag: " << uint32_t(dont_fragment_flag) << " "
               << "more_fragments_flag: " << uint32_t(more_fragments_flag) << " "
               << "ttl: " << uint32_t(ttl) << " "
               << "protocol: " << uint32_t(protocol) << " "
               << "cheksum: " << uint32_t(checksum) << " "
               << "source_ip: " << convert_ip_as_little_endian_to_string(source_ip) << " "
               << "destination_ip: " << convert_ip_as_little_endian_to_string(destination_ip);

        return buffer.str();
    }
};

static_assert(sizeof(ipv4_header_t) == 20, "Bad size for ipv4_header_t");

enum class parser_code_t { memory_violation, not_ipv4, success };

std::string parser_code_to_string(parser_code_t code);
} // namespace network_data_stuctures
