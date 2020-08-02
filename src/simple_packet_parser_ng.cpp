#include "simple_packet_parser_ng.h"
#include "all_logcpp_libraries.h"
#include "network_data_structures.hpp"

#include <cstring>

using namespace network_data_stuctures;

// Our own native function to convert wire packet into simple_packet_t
// TODO: development is going here, we still need to add number of options here
// It based on code from parse_ipv4_or_ipv6_packet_up_to_l3
parser_code_t parse_raw_packet_to_simple_packet_full_ng(uint8_t* pointer,
                                                        int length_before_sampling,
                                                        int captured_length,
                                                        simple_packet_t& packet,
                                                        bool use_packet_length_from_wire) {
    // We are using pointer copy because we are changing it
    uint8_t* local_pointer = pointer;

    // It's very nice for doing checks
    uint8_t* end_pointer = pointer + captured_length;

    // Return error if it shorter then ethernet headers
    if (local_pointer + sizeof(ethernet_header_t) > end_pointer) {
        return parser_code_t::memory_violation;
    }

    ethernet_header_t* ethernet_header = (ethernet_header_t*)local_pointer;
    ethernet_header->convert();

    local_pointer += sizeof(ethernet_header_t);

    // Here we store IPv4 or IPv6 l4 protocol numbers
    uint8_t protocol = 0;

    if (ethernet_header->ethertype == IanaEthertypeVLAN) {
        // Return error if it shorter then vlan header
        if (local_pointer + sizeof(ethernet_vlan_header_t) > end_pointer) {
            return parser_code_t::memory_violation;
        }

        ethernet_vlan_header_t* ethernet_vlan_header = (ethernet_vlan_header_t*)local_pointer;
        ethernet_vlan_header->convert();

        packet.vlan = ethernet_vlan_header->vlan_id;

        local_pointer += sizeof(ethernet_vlan_header_t);

        // Change ethernet ethertype to vlan's ethertype
        ethernet_header->ethertype = ethernet_vlan_header->ethertype;
    }

    if (ethernet_header->ethertype == IanaEthertypeIPv4) {
        // Return error if pointer is shorter then IP header
        if (local_pointer + sizeof(ipv4_header_t) > end_pointer) {
            return parser_code_t::memory_violation;
        }

        ipv4_header_t* ipv4_header = (ipv4_header_t*)local_pointer;

        // Populate IP specific options in packet structure before making any conversions, use network representation of
        // addresses
        packet.src_ip = ipv4_header->source_ip;
        packet.dst_ip = ipv4_header->destination_ip;

        packet.ip_protocol_version = 4;

        // Convert all integers in IP header to little endian
        ipv4_header->convert();

        packet.ttl              = ipv4_header->ttl;
        packet.ip_length        = ipv4_header->total_length;
        packet.ip_dont_fragment = ipv4_header->dont_fragment_flag;

        packet.ip_fragmented = ipv4_header->is_fragmented();

        // We keep these variables to maintain backward compatibility with parse_raw_packet_to_simple_packet_full()
        packet.packet_payload_length      = length_before_sampling;
        packet.packet_payload_full_length = length_before_sampling;

        // Pointer to payload
        packet.packet_payload_pointer = (void*)pointer;

        protocol        = ipv4_header->protocol;
        packet.protocol = protocol;

        if (use_packet_length_from_wire) {
            packet.length = length_before_sampling;
        } else {
            packet.length = ipv4_header->total_length;
        }

        // Ignore all IP options and shift pointer to L3 payload
        local_pointer += 4 * ipv4_header->ihl;
    } else {
        // TODO: we do not support IPv6 yet
        return parser_code_t::not_ipv4;
    }

    if (protocol == IpProtocolNumberTCP) {
        if (local_pointer + sizeof(tcp_header_t) > end_pointer) {
            return parser_code_t::memory_violation;
        }

        tcp_header_t* tcp_header = (tcp_header_t*)local_pointer;
        tcp_header->convert();

        packet.source_port      = tcp_header->source_port;
        packet.destination_port = tcp_header->destination_port;

        // TODO: rework this code to use structs with bit fields
        packet.flags = tcp_header->fin * 0x01 + tcp_header->syn * 0x02 + tcp_header->rst * 0x04 +
                       tcp_header->psh * 0x08 + tcp_header->ack * 0x10 + tcp_header->urg * 0x20;

    } else if (protocol == IpProtocolNumberUDP) {
        if (local_pointer + sizeof(udp_header_t) > end_pointer) {
            return parser_code_t::memory_violation;
        }

        udp_header_t* udp_header = (udp_header_t*)local_pointer;
        udp_header->convert();

        packet.source_port      = udp_header->source_port;
        packet.destination_port = udp_header->destination_port;
    } else {
        // We're not interested in other protocol types
        return parser_code_t::not_ipv4;
    }

    return parser_code_t::success;
}

