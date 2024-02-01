#pragma once

#include <bitset>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>

#include "fast_endianless.hpp"

#include "iana_ethertypes.hpp"
#include "iana_ip_protocols.hpp"

//
// If you have an idea to add unions to "improve" this code please stop and think.
//
// More details about issue https://en.cppreference.com/w/cpp/language/union
//
// "It is undefined behavior to read from the member of the union that wasn't most recently written. Many compilers implement,
// as a non-standard language extension, the ability to read inactive members of a union."
//
// Few more additional details: https://stackoverflow.com/questions/53074726/c-union-struct-bitfield-implementation-and-portability/53074781#53074781
//

// This function could copy X bytes from src to dst.
// Where X - size of dst object (referenced by pointer)
template <typename dst_type, typename src_type> inline void* smart_memcpy(dst_type* dst, const src_type* src) {
    return memcpy(dst, src, sizeof(dst_type));
}

namespace network_data_stuctures {

// We are using this structure as pretty interface for IPv4 address bytes in host byte order (little  endian)
class __attribute__((__packed__)) ipv4_octets_form_little_endian_t {
    public:
    uint8_t fourth = 0;
    uint8_t third  = 0;
    uint8_t second = 0;
    uint8_t first  = 0;
};

static_assert(sizeof(ipv4_octets_form_little_endian_t) == 4, "Bad size for ipv4_octets_form_little_endian_t");


class __attribute__((__packed__)) ipv4_octets_form_big_endian_t {
    public:
    uint8_t first  = 0;
    uint8_t second = 0;
    uint8_t third  = 0;
    uint8_t fourth = 0;
};

static_assert(sizeof(ipv4_octets_form_big_endian_t) == 4, "Bad size for ipv4_octets_form_big_endian_t");


// Convert IP as integer in little endian to string representation
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

// Convert IP as integer in big endian to string representation
inline std::string convert_ip_as_big_endian_to_string(uint32_t ip) {
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

    ipv4_octets_form_big_endian_t* ipv4_octets = (ipv4_octets_form_big_endian_t*)&ip;

    snprintf(buffer, max_ip_as_string_size, "%d.%d.%d.%d", ipv4_octets->first, ipv4_octets->second, ipv4_octets->third,
             ipv4_octets->fourth);

    return std::string(buffer);
}

// Here we are using very cryptic form of pointer to fixed size array
inline std::string convert_mac_to_string(const uint8_t (&mac_as_array)[6]) {
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
    uint32_t label : 20 = 0, qos : 3 = 0, bottom_of_stack : 1 = 0, ttl : 8 = 0;

    std::string print() const {
        std::stringstream buffer;

        buffer << "label: " << uint32_t(label) << " "
               << "qos: " << uint32_t(qos) << " "
               << "bottom of stack: " << uint32_t(bottom_of_stack) << " "
               << "ttl: " << uint32_t(ttl);

        return buffer.str();
    }
};

static_assert(sizeof(mpls_label_t) == 4, "Bad size for mpls_label_t");

// In this class we keep vlan id, priority and cfi
class __attribute__((__packed__)) ethernet_vlan_metadata_t {
    public:
    uint16_t vlan_id : 12, cfi : 1, priority : 3;
};

static_assert(sizeof(ethernet_vlan_metadata_t) == 2, "Bad size for ethernet_vlan_metadata_t");

// We are storing VLAN meta data and next ethertype in same packet
// It's not standard approach so be careful
class __attribute__((__packed__)) ethernet_vlan_header_t {
    // We must not access these fields directly as it requires explicit byte order conversion
    private:
    uint16_t vlan_metadata_as_integer = 0;
    uint16_t ethertype                = 0;

    // We can access data in packet only using special methods which can do all required format conversions
    public:
    // Returns ethertype in host byte order
    uint16_t get_ethertype_host_byte_order() const {
        return fast_ntoh(ethertype);
    }

    // Returns VLAN id in host byte order. You must call convert before calling it
    uint16_t get_vlan_id_host_byte_order() const {
        // Copy whole structure and convert to host byte order
        uint16_t vlan_metadata_little_endian = fast_ntoh(vlan_metadata_as_integer);

        // Apply mask to retrieve vlan id field
        // TODO: I'm not 100% sure that it will work correct if cfi or priority are non zero or vlan id is relatively large number
        const ethernet_vlan_metadata_t* vlan_metadata = (ethernet_vlan_metadata_t*)&vlan_metadata_little_endian;

        return vlan_metadata->vlan_id;
    }

    // Returns CFI flag. You must call convert before calling it
    // TODO: We never tested this logic
    bool get_cfi_flag() const {
        // Copy whole structure and convert to host byte order
        uint16_t vlan_metadata_little_endian = fast_ntoh(vlan_metadata_as_integer);

        const ethernet_vlan_metadata_t* vlan_metadata = (ethernet_vlan_metadata_t*)&vlan_metadata_little_endian;

        return vlan_metadata->cfi;
    }

    // Return priority in host byte order. You must call convert before calling it
    // TODO: We never tested this logic
    uint8_t get_priority() const {
        // Copy whole structure and convert to host byte order
        uint16_t vlan_metadata_little_endian = fast_ntoh(vlan_metadata_as_integer);

        const ethernet_vlan_metadata_t* vlan_metadata = (ethernet_vlan_metadata_t*)&vlan_metadata_little_endian;

        return vlan_metadata->priority;
    }

    std::string print() const {
        std::stringstream buffer;

        // We use cast to avoid printing it as char
        buffer << "priority: " << uint32_t(get_priority()) << " ";

        buffer << "cfi: " << std::boolalpha << get_cfi_flag() << " "
               << "vlan_id: " << get_vlan_id_host_byte_order() << " ";

        buffer << "ethertype: 0x" << std::setfill('0') << std::setw(4) << std::hex << get_ethertype_host_byte_order();

        return buffer.str();
    }
};

static_assert(sizeof(ethernet_vlan_header_t) == 4, "Bad size for ethernet_vlan_header_t");

class __attribute__((__packed__)) ethernet_header_t {
    public:
    uint8_t destination_mac[6];
    uint8_t source_mac[6];

    private:
    // We must not access this field directly as it requires explicit byte order conversion
    uint16_t ethertype = 0;

    public:
    // Returns ethertype in host byte order
    uint16_t get_ethertype_host_byte_order() const {
        return fast_ntoh(ethertype);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "ethertype: 0x" << std::setfill('0') << std::setw(4) << std::hex << get_ethertype_host_byte_order();

        buffer << " "
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
    // These fields must not be accessed directly as we need to convert them to host byte order
    private:
    uint16_t hardware_type = 0;
    uint16_t protocol_type = 0;

    uint8_t hardware_address_length = 0;
    uint8_t protocol_address_length = 0;

    uint16_t operation = 0;

    uint8_t sender_hardware_address[6];
    uint32_t sender_protocol_address = 0;

    uint8_t target_hardware_address[6];
    uint32_t target_protocol_address = 0;

    public:
    uint8_t get_hardware_address_length() const {
        return hardware_address_length;
    }

    uint8_t get_protocol_address_length() const {
        return protocol_address_length;
    }

    uint16_t get_hardware_type_host_byte_order() const {
        return fast_ntoh(hardware_type);
    }

    uint16_t get_protocol_type_host_byte_order() const {
        return fast_ntoh(protocol_type);
    }

    uint16_t get_operation_host_byte_order() const {
        return fast_ntoh(operation);
    }

    // Return it as is
    uint32_t get_sender_protocol_address_network_byte_order() const {
        return sender_protocol_address;
    }

    // Return it as is
    uint32_t get_target_protocol_address_network_byte_order() const {
        return target_protocol_address;
    }

    std::string print() const {
        std::stringstream buffer;

        buffer << "hardware_type: " << get_hardware_type_host_byte_order() << " "
               << "protocol_type: " << get_protocol_type_host_byte_order() << " "
               << "hardware_address_length: " << uint32_t(get_hardware_address_length()) << " "
               << "protocol_address_length: " << uint32_t(get_protocol_address_length()) << " "
               << "operation: " << get_operation_host_byte_order() << " "
               << "sender_hardware_address: " << convert_mac_to_string(sender_hardware_address) << " "
               << "sender_protocol_address: "
               << convert_ip_as_big_endian_to_string(get_sender_protocol_address_network_byte_order()) << " "
               << "target_hardware_address: " << convert_mac_to_string(target_hardware_address) << " "
               << "target_protocol_address: "
               << convert_ip_as_big_endian_to_string(get_target_protocol_address_network_byte_order());

        return buffer.str();
    }
};

static_assert(sizeof(arp_header_t) == 28, "Bad size for arp_header_t");

class __attribute__((__packed__)) icmp_header_t {
    // We must not access these fields directly as they may need conversion
    private:
    uint8_t type            = 0;
    uint8_t code            = 0;
    uint16_t checksum       = 0;
    uint32_t rest_of_header = 0;

    public:
    uint8_t get_type() const {
        return type;
    }

    uint8_t get_code() const {
        return code;
    }

    uint16_t get_checksum() const {
        return fast_ntoh(checksum);
    }

    std::string print() const {
        std::stringstream buffer;

        buffer << "type: " << uint32_t(get_type()) << " "
               << "code: " << uint32_t(get_code()) << " "
               << "checksum: " << uint32_t(get_checksum());

        return buffer.str();
    }
};

class __attribute__((__packed__)) udp_header_t {
    // We must not access these fields directly as they may need conversion
    private:
    uint16_t source_port      = 0;
    uint16_t destination_port = 0;
    uint16_t length           = 0;
    uint16_t checksum         = 0;

    public:
    uint16_t get_source_port_host_byte_order() const {
        return fast_ntoh(source_port);
    }

    uint16_t get_destination_port_host_byte_order() const {
        return fast_ntoh(destination_port);
    }

    uint16_t get_length_host_byte_order() const {
        return fast_ntoh(length);
    }

    uint16_t get_checksum_host_byte_order() const {
        return fast_ntoh(checksum);
    }

    std::string print() const {
        std::stringstream buffer;

        buffer << "source_port: " << get_source_port_host_byte_order() << " "
               << "destination_port: " << get_destination_port_host_byte_order() << " "
               << "length: " << get_length_host_byte_order() << " "
               << "checksum: " << get_checksum_host_byte_order();

        return buffer.str();
    }
};

static_assert(sizeof(udp_header_t) == 8, "Bad size for udp_header_t");

// https://datatracker.ietf.org/doc/html/rfc2784
class __attribute__((__packed__)) gre_header_t {
    // We must not access these fields directly as they may need conversion
    private:
    // TODO: we have no pcaps where these fields are no zeros and we did not test this case
    // For some reasons PVS thinks that we did not initialised all members. I think they're not that great with bitfields
    uint16_t checksum : 1 = 0, reserved : 12 = 0, version : 3 = 0; //-V730
    uint16_t protocol_type = 0;

    public:
    uint16_t get_protocol_type_host_byte_order() const {
        return fast_ntoh(protocol_type);
    }

    uint16_t get_reserved() const {
        return reserved;
    }

    uint16_t get_checksum() const {
        return checksum;
    }

    uint16_t get_version() const {
        return version;
    }

    std::string print() const {
        std::stringstream buffer;

        buffer << "checksum: " << get_checksum() << " "
               << "reserved: " << get_reserved() << " "
               << "version: " << get_version() << " "
               << "protocol_type: " << get_protocol_type_host_byte_order();

        return buffer.str();
    }
};

static_assert(sizeof(gre_header_t) == 4, "Bad size for gre_header_t");

// It's tcp packet flags represented as bitfield for user friendly access to this flags
class __attribute__((__packed__)) tcp_flags_as_uint16_t {
    public:
    uint16_t fin : 1 = 0, syn : 1 = 0, rst : 1 = 0, psh : 1 = 0, ack : 1 = 0, urg : 1 = 0, ece : 1 = 0, cwr : 1 = 0,
                   ns : 1 = 0, reserved : 3 = 0, data_offset : 4 = 0;

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

class __attribute__((__packed__)) tcp_flags_t {
    public:
    uint16_t fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1, ns : 1, reserved : 3, data_offset : 4;
};

static_assert(sizeof(tcp_flags_t) == 2, "Bad size for tcp_flags_t");

// It's cropped TCP header and we use it only in cases when data was cropped (sFlow, inline monitoring services or cropped mirror)
class __attribute__((__packed__)) cropped_tcp_header_only_ports_t {
    // These fields must not be accessed directly as they need decoding
    private:
    uint16_t source_port      = 0;
    uint16_t destination_port = 0;

    public:
    uint16_t get_source_port_host_byte_order() const {
        return fast_ntoh(source_port);
    }

    uint16_t get_destination_port_host_byte_order() const {
        return fast_ntoh(destination_port);
    }
};

static_assert(sizeof(cropped_tcp_header_only_ports_t) == 4, "Bad size for cropped_tcp_header_only_ports_t");

class __attribute__((__packed__)) tcp_header_t {
    // These fields must not be accessed directly as they need decoding
    private:
    uint16_t source_port      = 0;
    uint16_t destination_port = 0;
    uint32_t sequence_number  = 0;
    uint32_t ack_number       = 0;

    // Flags here encoded as tcp_flags_t
    uint16_t data_offset_and_flags_as_integer = 0;

    private:
    uint16_t window_size = 0;
    uint16_t checksum    = 0;
    uint16_t urgent      = 0;

    public:
    uint16_t get_source_port_host_byte_order() const {
        return fast_ntoh(source_port);
    }

    uint16_t get_destination_port_host_byte_order() const {
        return fast_ntoh(destination_port);
    }

    uint32_t get_sequence_number_host_byte_order() const {
        return fast_ntoh(sequence_number);
    }

    uint32_t get_ack_number_host_byte_order() const {
        return fast_ntoh(ack_number);
    }

    uint16_t get_window_size_host_byte_order() const {
        return fast_ntoh(window_size);
    }

    uint16_t get_checksum_host_byte_order() const {
        return fast_ntoh(checksum);
    }

    uint16_t get_urgent_host_byte_order() const {
        return fast_ntoh(urgent);
    }

    uint16_t get_data_offset_and_flags_host_byte_order() const {
        return fast_ntoh(data_offset_and_flags_as_integer);
    }

    void set_data_offset(uint8_t data_offset) {
        uint16_t data_offset_and_flags_as_integer_litle_endian = fast_ntoh(data_offset_and_flags_as_integer);

        tcp_flags_t* tcp_flags = (tcp_flags_t*)&data_offset_and_flags_as_integer_litle_endian;

        tcp_flags->data_offset = data_offset;

        // Re-encode into network byte order again
        data_offset_and_flags_as_integer = fast_hton(data_offset_and_flags_as_integer_litle_endian);
    }

    bool get_fin() const {
        uint16_t data_offset_and_flags_as_integer_litle_endian = fast_ntoh(data_offset_and_flags_as_integer);

        tcp_flags_t* tcp_flags = (tcp_flags_t*)&data_offset_and_flags_as_integer_litle_endian;

        return tcp_flags->fin == 1;
    }

    bool get_syn() const {
        uint16_t data_offset_and_flags_as_integer_litle_endian = fast_ntoh(data_offset_and_flags_as_integer);

        tcp_flags_t* tcp_flags = (tcp_flags_t*)&data_offset_and_flags_as_integer_litle_endian;

        return tcp_flags->syn == 1;
    }

    bool get_rst() const {
        uint16_t data_offset_and_flags_as_integer_litle_endian = fast_ntoh(data_offset_and_flags_as_integer);

        tcp_flags_t* tcp_flags = (tcp_flags_t*)&data_offset_and_flags_as_integer_litle_endian;

        return tcp_flags->rst == 1;
    }

    bool get_psh() const {
        uint16_t data_offset_and_flags_as_integer_litle_endian = fast_ntoh(data_offset_and_flags_as_integer);

        tcp_flags_t* tcp_flags = (tcp_flags_t*)&data_offset_and_flags_as_integer_litle_endian;

        return tcp_flags->psh == 1;
    }

    bool get_ack() const {
        uint16_t data_offset_and_flags_as_integer_litle_endian = fast_ntoh(data_offset_and_flags_as_integer);

        tcp_flags_t* tcp_flags = (tcp_flags_t*)&data_offset_and_flags_as_integer_litle_endian;

        return tcp_flags->ack == 1;
    }

    bool get_urg() const {
        uint16_t data_offset_and_flags_as_integer_litle_endian = fast_ntoh(data_offset_and_flags_as_integer);

        tcp_flags_t* tcp_flags = (tcp_flags_t*)&data_offset_and_flags_as_integer_litle_endian;

        return tcp_flags->urg == 1;
    }

    bool get_ece() const {
        uint16_t data_offset_and_flags_as_integer_litle_endian = fast_ntoh(data_offset_and_flags_as_integer);

        tcp_flags_t* tcp_flags = (tcp_flags_t*)&data_offset_and_flags_as_integer_litle_endian;

        return tcp_flags->ece == 1;
    }

    bool get_cwr() const {
        uint16_t data_offset_and_flags_as_integer_litle_endian = fast_ntoh(data_offset_and_flags_as_integer);

        tcp_flags_t* tcp_flags = (tcp_flags_t*)&data_offset_and_flags_as_integer_litle_endian;

        return tcp_flags->cwr == 1;
    }

    bool get_ns() const {
        uint16_t data_offset_and_flags_as_integer_litle_endian = fast_ntoh(data_offset_and_flags_as_integer);

        tcp_flags_t* tcp_flags = (tcp_flags_t*)&data_offset_and_flags_as_integer_litle_endian;

        return tcp_flags->ns == 1;
    }

    uint8_t get_reserved() const {
        uint16_t data_offset_and_flags_as_integer_litle_endian = fast_ntoh(data_offset_and_flags_as_integer);

        tcp_flags_t* tcp_flags = (tcp_flags_t*)&data_offset_and_flags_as_integer_litle_endian;

        return tcp_flags->reserved;
    }

    uint8_t get_data_offset() const {
        uint16_t data_offset_and_flags_as_integer_litle_endian = fast_ntoh(data_offset_and_flags_as_integer);

        tcp_flags_t* tcp_flags = (tcp_flags_t*)&data_offset_and_flags_as_integer_litle_endian;

        return tcp_flags->data_offset;
    }

    std::string print() const {
        std::stringstream buffer;

        buffer << "source_port: " << get_source_port_host_byte_order() << " "
               << "destination_port: " << get_destination_port_host_byte_order() << " "
               << "sequence_number: " << get_sequence_number_host_byte_order() << " "
               << "ack_number: " << get_ack_number_host_byte_order() << " "
               << "data_offset: " << uint32_t(get_data_offset()) << " "
               << "reserved: " << uint32_t(get_reserved()) << " "
               << "ns: " << get_ns() << " "
               << "cwr: " << get_cwr() << " "
               << "ece: " << get_ece() << " "
               << "urg: " << get_urg() << " "
               << "ack: " << get_ack() << " "
               << "psh: " << get_psh() << " "
               << "rst: " << get_rst() << " "
               << "syn: " << get_syn() << " "
               << "fin: " << get_fin() << " "
               << "window_size: " << get_window_size_host_byte_order() << " "
               << "checksum: " << get_checksum_host_byte_order() << " "
               << "urgent: " << get_urgent_host_byte_order();

        return buffer.str();
    }
};

static_assert(sizeof(tcp_header_t) == 20, "Bad size for tcp_header_t");

typedef uint8_t ipv6_address[16];

// Custom type for pretty printing
typedef uint16_t ipv6_address_16bit_blocks[8];

inline std::string convert_ipv6_in_byte_array_to_string(const uint8_t (&v6_address)[16]) {
    std::stringstream buffer;

    uint16_t* pretty_print = (uint16_t*)v6_address;

    for (int i = 0; i < 8; i++) {
        buffer << std::hex << fast_ntoh(pretty_print[i]);

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

class __attribute__((__packed__)) ipv6_fragment_header_flags {
    public:
    // fragment_offset is a number of 8byte chunk
    uint16_t more_fragments : 1, reserved2 : 2, fragment_offset : 13;
};

static_assert(sizeof(ipv6_fragment_header_flags) == 2, "Bad size for ipv6_header_flags_t");

// IPv6 fragmentation header option
class __attribute__((__packed__)) ipv6_extension_header_fragment_t {
    private:
    uint8_t next_header = 0;
    uint8_t reserved1   = 0;

    // Multiple flags in format ipv6_fragment_header_flags
    uint16_t fragmentation_and_flags_as_integer = 0;

    // We must not access these fields directly as they need proper decoding
    private:
    uint32_t identification = 0;

    public:
    uint16_t get_more_fragments() const {
        uint16_t flags_little_endian = fast_ntoh(fragmentation_and_flags_as_integer);

        ipv6_fragment_header_flags* flags = (ipv6_fragment_header_flags*)&flags_little_endian;

        return flags->more_fragments;
    }

    uint16_t get_reserved2() const {
        uint16_t flags_little_endian = fast_ntoh(fragmentation_and_flags_as_integer);

        ipv6_fragment_header_flags* flags = (ipv6_fragment_header_flags*)&flags_little_endian;

        return flags->reserved2;
    }

    uint16_t get_fragment_offset_8byte_chunks() const {
        uint16_t flags_little_endian = fast_ntoh(fragmentation_and_flags_as_integer);

        ipv6_fragment_header_flags* flags = (ipv6_fragment_header_flags*)&flags_little_endian;

        return flags->fragment_offset;
    }

    uint16_t get_fragment_offset_bytes() const {
        uint16_t flags_little_endian = fast_ntoh(fragmentation_and_flags_as_integer);

        ipv6_fragment_header_flags* flags = (ipv6_fragment_header_flags*)&flags_little_endian;

        return flags->fragment_offset * 8;
    }

    uint8_t get_next_header() const {
        return next_header;
    }

    uint8_t get_reserved1() const {
        return reserved1;
    }

    uint32_t get_identification_host_byte_order() const {
        return fast_ntoh(identification);
    }

    std::string print() const {
        std::stringstream buffer;

        buffer << "next_header: " << uint32_t(get_next_header()) << " "
               << "reserved1: " << uint32_t(get_reserved1()) << " "
               << "fragment_offset_bytes: " << uint32_t(get_fragment_offset_bytes()) << " "
               << "reserverd2: " << uint32_t(get_reserved2()) << " "
               << "more_fragments: " << uint32_t(get_more_fragments()) << " "
               << "identification: " << get_identification_host_byte_order();

        return buffer.str();
    }
};

static_assert(sizeof(ipv6_extension_header_fragment_t) == 8, "Bad size for ipv6_extension_header_fragment_t");

class __attribute__((__packed__)) ipv6_header_flags_t {
    public:
    uint32_t flow_label : 20, traffic_class : 8, version : 4;
};

static_assert(sizeof(ipv6_header_flags_t) == 4, "Bad size for ipv6_header_flags_t");

class __attribute__((__packed__)) ipv6_header_t {
    // We must not access these fields directly as they need decoding
    private:
    // Multiple flags carried in ipv6_header_flags_t
    uint32_t version_and_traffic_class_as_integer = 0;

    uint16_t payload_length = 0;
    uint8_t next_header     = 0;
    uint8_t hop_limit       = 0;

    public:
    ipv6_address source_address{};
    ipv6_address destination_address{};

    uint32_t get_flow_label() const {
        uint32_t version_and_traffic_class_little_endian = fast_ntoh(version_and_traffic_class_as_integer);

        ipv6_header_flags_t* header_flags = (ipv6_header_flags_t*)&version_and_traffic_class_little_endian;

        return header_flags->flow_label;
    }

    uint32_t get_traffic_class() const {
        uint32_t version_and_traffic_class_little_endian = fast_ntoh(version_and_traffic_class_as_integer);

        ipv6_header_flags_t* header_flags = (ipv6_header_flags_t*)&version_and_traffic_class_little_endian;

        return header_flags->traffic_class;
    }

    uint32_t get_version() const {
        uint32_t version_and_traffic_class_little_endian = fast_ntoh(version_and_traffic_class_as_integer);

        ipv6_header_flags_t* header_flags = (ipv6_header_flags_t*)&version_and_traffic_class_little_endian;

        return header_flags->version;
    }

    uint16_t get_payload_length() const {
        return fast_ntoh(payload_length);
    }

    uint8_t get_next_header() const {
        return next_header;
    }

    uint8_t get_hop_limit() const {
        return hop_limit;
    }

    std::string print() const {
        std::stringstream buffer;

        buffer << "version: " << get_version() << " "
               << "traffic_class: " << get_traffic_class() << " "
               << "flow_label: " << get_flow_label() << " "
               << "payload_length: " << get_payload_length() << " "
               << "next_header: " << uint32_t(get_next_header()) << " "
               << "hop_limit: " << uint32_t(get_hop_limit()) << " "
               << "source_address: " << convert_ipv6_in_byte_array_to_string(source_address) << " "
               << "destination_address: " << convert_ipv6_in_byte_array_to_string(destination_address);

        return buffer.str();
    }
};

static_assert(sizeof(ipv6_header_t) == 40, "Bad size for ipv6_header_t");

// It's class for fragmentation flag representation. It's pretty useful in some cases
class __attribute__((__packed__)) ipv4_header_fragmentation_flags_t {
    public:
    // The offset value is the number of 8 byte blocks of data
    uint16_t fragment_offset : 13, more_fragments_flag : 1, dont_fragment_flag : 1, reserved_flag : 1;

    std::string print() {

        std::stringstream buffer;
        buffer << "fragment_offset: " << uint32_t(fragment_offset) << " "
               << "reserved_flag: " << uint32_t(reserved_flag) << " "
               << "dont_fragment_flag: " << uint32_t(dont_fragment_flag) << " "
               << "more_fragments_flag: " << uint32_t(more_fragments_flag);

        return buffer.str();
    }
};

static_assert(sizeof(ipv4_header_fragmentation_flags_t) == 2, "Bad size for ipv4_header_fragmentation_flags_t");

class __attribute__((__packed__)) ipv4_header_t {
    // We must not access these fields directly as they need conversion
    private:
    uint8_t ihl : 4 = 0, version : 4 = 0;
    uint8_t ecn : 2 = 0, dscp : 6 = 0;

    // This is the combined length of the header and the data
    uint16_t total_length   = 0;
    uint16_t identification = 0;

    // There we have plenty of fragmentation specific fields encoded in ipv4_header_fragmentation_flags_t
    uint16_t fragmentation_details_as_integer = 0;

    uint8_t ttl      = 0;
    uint8_t protocol = 0;

    uint16_t checksum = 0;

    uint32_t source_ip      = 0;
    uint32_t destination_ip = 0;

    public:
    ipv4_header_t()
    : ihl(0), version(0), ecn(0), dscp(0), total_length(0), identification(0), fragmentation_details_as_integer(0),
      ttl(0), protocol(0), checksum(0), source_ip(0), destination_ip(0) {
    }

    uint16_t get_checksum_host_byte_order() const {
        return fast_ntoh(checksum);
    }

    uint16_t get_total_length_host_byte_order() const {
        return fast_ntoh(total_length);
    }

    bool is_fragmented() const {
        if (this->get_more_fragments_flag()) {
            return true;
        }

        if (this->get_fragment_offset_bytes() != 0) {
            return true;
        }

        return false;
    }

    uint8_t get_ihl() const {
        return ihl;
    }

    uint8_t get_version() const {
        return version;
    }

    uint8_t get_ecn() const {
        return ecn;
    }

    uint8_t get_dscp() const {
        return dscp;
    }

    uint16_t get_fragmentation_details_host_byte_order() {
        return fast_ntoh(fragmentation_details_as_integer);
    }

    // Returns fragment offset in number of 8 byte chunks
    uint16_t get_fragment_offset_8byte_chunks() const {
        uint16_t fragmenation_details_little_endian = fast_ntoh(fragmentation_details_as_integer);

        ipv4_header_fragmentation_flags_t* fragmentation_flags = (ipv4_header_fragmentation_flags_t*)&fragmenation_details_little_endian;

        return fragmentation_flags->fragment_offset;
    }

    // Returns offset in bytes
    uint16_t get_fragment_offset_bytes() const {
        uint16_t fragmenation_details_little_endian = fast_ntoh(fragmentation_details_as_integer);

        ipv4_header_fragmentation_flags_t* fragmentation_flags = (ipv4_header_fragmentation_flags_t*)&fragmenation_details_little_endian;

        // The offset value is the number of 8 byte blocks of data
        return fragmentation_flags->fragment_offset * 8;
    }

    bool get_more_fragments_flag() const {
        uint16_t fragmenation_details_little_endian = fast_ntoh(fragmentation_details_as_integer);

        ipv4_header_fragmentation_flags_t* fragmentation_flags = (ipv4_header_fragmentation_flags_t*)&fragmenation_details_little_endian;

        return fragmentation_flags->more_fragments_flag == 1;
    }

    bool get_dont_fragment_flag() const {
        uint16_t fragmenation_details_little_endian = fast_ntoh(fragmentation_details_as_integer);

        ipv4_header_fragmentation_flags_t* fragmentation_flags = (ipv4_header_fragmentation_flags_t*)&fragmenation_details_little_endian;

        return fragmentation_flags->dont_fragment_flag == 1;
    }

    uint16_t get_reserved_flag() const {
        uint16_t fragmenation_details_little_endian = fast_ntoh(fragmentation_details_as_integer);

        ipv4_header_fragmentation_flags_t* fragmentation_flags = (ipv4_header_fragmentation_flags_t*)&fragmenation_details_little_endian;

        return fragmentation_flags->reserved_flag;
    }

    // Clears reserved flag
    void clear_reserved_flag() {
        uint16_t fragmenation_details_little_endian = fast_ntoh(fragmentation_details_as_integer);

        ipv4_header_fragmentation_flags_t* fragmentation_flags = (ipv4_header_fragmentation_flags_t*)&fragmenation_details_little_endian;

        fragmentation_flags->reserved_flag = 0;

        // Re-encode back to network byte order
        fragmentation_details_as_integer = fast_hton(fragmenation_details_little_endian);
    }

    // Clears dont_fragment_flag flag
    void clear_dont_fragment_flag() {
        uint16_t fragmenation_details_little_endian = fast_ntoh(fragmentation_details_as_integer);

        ipv4_header_fragmentation_flags_t* fragmentation_flags = (ipv4_header_fragmentation_flags_t*)&fragmenation_details_little_endian;

        fragmentation_flags->dont_fragment_flag = 0;

        // Re-encode back to network byte order
        fragmentation_details_as_integer = fast_hton(fragmenation_details_little_endian);
    }

    // Value is a number of 8 byte blocks
    void set_fragment_offset_8byte_chunks(uint16_t value) {
        uint16_t fragmenation_details_little_endian = fast_ntoh(fragmentation_details_as_integer);

        ipv4_header_fragmentation_flags_t* fragmentation_flags = (ipv4_header_fragmentation_flags_t*)&fragmenation_details_little_endian;

        fragmentation_flags->fragment_offset = value;

        // Re-encode back to network byte order
        fragmentation_details_as_integer = fast_hton(fragmenation_details_little_endian);
    }

    uint32_t get_source_ip_network_byte_order() const {
        return source_ip;
    }

    uint32_t get_destination_ip_network_byte_order() const {
        return destination_ip;
    }

    uint32_t get_source_ip_host_byte_order() const {
        return fast_ntoh(source_ip);
    }

    uint32_t get_destination_ip_host_byte_order() const {
        return fast_ntoh(destination_ip);
    }

    uint16_t get_identification_host_byte_order() const {
        return fast_ntoh(identification);
    }

    uint8_t get_ttl() const {
        return ttl;
    }

    uint8_t get_protocol() const {
        return protocol;
    }

    std::string print() const {
        std::stringstream buffer;

        buffer << "version: " << uint32_t(get_version()) << " "
               << "ihl: " << uint32_t(get_ihl()) << " "
               << "dscp: " << uint32_t(get_dscp()) << " "
               << "ecn: " << uint32_t(get_ecn()) << " "
               << "length: " << get_total_length_host_byte_order() << " "
               << "identification: " << get_identification_host_byte_order() << " "
               << "fragment_offset_bytes: " << this->get_fragment_offset_bytes() << " "
               << "reserved_flag: " << uint32_t(get_reserved_flag()) << " "
               << "dont_fragment_flag: " << uint32_t(get_dont_fragment_flag()) << " "
               << "more_fragments_flag: " << uint32_t(get_more_fragments_flag()) << " "
               << "ttl: " << uint32_t(get_ttl()) << " "
               << "protocol: " << uint32_t(get_protocol()) << " "
               << "checksum: " << get_checksum_host_byte_order() << " "
               << "source_ip: " << convert_ip_as_little_endian_to_string(get_source_ip_host_byte_order()) << " "
               << "destination_ip: " << convert_ip_as_little_endian_to_string(get_destination_ip_host_byte_order());

        return buffer.str();
    }
};

static_assert(sizeof(ipv4_header_t) == 20, "Bad size for ipv4_header_t");

enum class parser_code_t {
    memory_violation,
    not_ipv4,
    success,
    broken_gre,
    no_ipv6_support,
    no_ipv6_options_support,
    unknown_ethertype,
    arp,
    too_many_nested_vlans,
};

std::string parser_code_to_string(parser_code_t code);
} // namespace network_data_stuctures
