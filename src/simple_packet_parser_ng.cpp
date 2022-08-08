#include "simple_packet_parser_ng.hpp"
#include "all_logcpp_libraries.hpp"
#include "network_data_structures.hpp"

#include <cstring>

using namespace network_data_stuctures;

// By default, we do not touch MPLS
// TODO: it's not working code yet
bool decode_mpls = false;

// Our own native function to convert wire packet into simple_packet_t
// TODO: development is going here, we still need to add number of options here
parser_code_t parse_raw_packet_to_simple_packet_full_ng(uint8_t* pointer,
                                                        int length_before_sampling,
                                                        int captured_length,
                                                        simple_packet_t& packet,
                                                        bool unpack_gre,
                                                        bool read_packet_length_from_ip_header) {
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

    if (decode_mpls) {
        if (ethernet_header->ethertype == IanaEthertypeMPLS_unicast) {
        REPEAT_MPLS_STRIP:
            if (local_pointer + sizeof(mpls_label_t) > end_pointer) {
                return parser_code_t::memory_violation;
            }

            mpls_label_t* mpls_label_header = (mpls_label_t*)local_pointer;

            std::cout << "MPLS header: " << mpls_label_header->print() << std::endl;

            // Strip this MPLS label
            local_pointer += sizeof(mpls_label_t);

            // If it's not bottom of stack, repeat operation
            if (mpls_label_header->bottom_of_stack == 0) {
                goto REPEAT_MPLS_STRIP;
            }
        }
    }

    // Here we store IPv4 or IPv6 l4 protocol numbers
    uint8_t protocol = 0;

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
        
        // We need this specific field for Flow Spec mitigation mode
        packet.ip_length        = ipv4_header->total_length;
        
        packet.ip_dont_fragment = ipv4_header->dont_fragment_flag;

        packet.ip_fragmented = ipv4_header->is_fragmented();

        packet.ip_more_fragments = ipv4_header->more_fragments_flag;

        // We keep these variables to maintain backward compatibility with parse_raw_packet_to_simple_packet_full()
        packet.packet_payload_length      = length_before_sampling;
        packet.packet_payload_full_length = length_before_sampling;

        // Pointer to payload
        packet.packet_payload_pointer = (void*)pointer;

        protocol        = ipv4_header->protocol;
        packet.protocol = protocol;

        if (read_packet_length_from_ip_header) {
            packet.length = ipv4_header->total_length;
        } else {
            packet.length = length_before_sampling;
        }

        // Ignore all IP options and shift pointer to L3 payload
        local_pointer += 4 * ipv4_header->ihl;
    } else if (ethernet_header->ethertype == IanaEthertypeIPv6) {
        // Return error if pointer is shorter then IP header
        if (local_pointer + sizeof(ipv6_header_t) > end_pointer) {
            return parser_code_t::memory_violation;
        }

        ipv6_header_t* ipv6_header = (ipv6_header_t*)local_pointer;
        
        // Convert all integers in IP header to little endian
        ipv6_header->convert();

        memcpy(&packet.src_ipv6, ipv6_header->source_address, sizeof(packet.src_ipv6));
        memcpy(&packet.dst_ipv6, ipv6_header->destination_address, sizeof(packet.dst_ipv6));

        packet.ip_protocol_version = 6;

        packet.ttl              = ipv6_header->hop_limit;

        // We need this specific field for Flow Spec mitigation mode
        packet.ip_length        = ipv6_header->payload_length;

        // We keep these variables to maintain backward compatibility with parse_raw_packet_to_simple_packet_full()
        packet.packet_payload_length      = length_before_sampling;
        packet.packet_payload_full_length = length_before_sampling;

        // Pointer to payload
        packet.packet_payload_pointer = (void*)pointer;

        protocol        = ipv6_header->next_header;
        packet.protocol = protocol;

        if (read_packet_length_from_ip_header) {
            packet.length = ipv6_header->payload_length;
        } else {
            packet.length = length_before_sampling;
        }

        // Just skip our simple IPv6 header and then code below will try to decode specific protocol
        local_pointer += sizeof(ipv6_header_t);

        // According to https://datatracker.ietf.org/doc/html/rfc8200#page-8
        // these 6 options are mandatory for complete IPv6 implementations
        //
        //    IpProtocolNumberHOPOPT           = 0
        //    IpProtocolNumberIPV6_ROUTE       = 43
        //    IpProtocolNumberIPV6_FRAG        = 44
        //    IpProtocolNumberESP              = 50
        //    IpProtocolNumberAH               = 51
        //    IpProtocolNumberIPV6_OPTS        = 60
        //
        // https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
        //
        // We do not support all IPv6 options in current version of parser
        // Some options are extremely rare in The Wild Internet: https://stats.labs.apnic.net/cgi-bin/v6frag_worldmap?w=7&d=f
        if (protocol == IpProtocolNumberHOPOPT || protocol == IpProtocolNumberIPV6_ROUTE || protocol == IpProtocolNumberIPV6_FRAG ||
            protocol == IpProtocolNumberIPV6_OPTS || protocol == IpProtocolNumberAH || protocol == IpProtocolNumberESP) {

            // We decided to parse only fragmentation header option as only this field may be found in the Wild
            if (protocol == IpProtocolNumberIPV6_FRAG) {
                ipv6_extension_header_fragment_t* ipv6_extension_header_fragment = (ipv6_extension_header_fragment_t*)local_pointer;

                ipv6_extension_header_fragment->convert();

                // If we received this header then we assume that packet was fragmented
                packet.ip_fragmented = true;

                packet.ip_more_fragments = ipv6_extension_header_fragment->more_fragments;

                // We stop processing here as I believe that it's enough to know that this traffic was fragmented 
                // We do not parse nested protocol in this case at all
                // If we observe first fragment of UDP datagram we may see header but for consequent packets we cannot do it
                // I think that's it's safer to avoid parsing such traffic deeper until we collect packet examples for all cases
                return parser_code_t::success;
            }

            return parser_code_t::no_ipv6_options_support;
        }
    } else if (ethernet_header->ethertype == IanaEthertypeARP) {
        // it's not parser error of course but we need to have visibility about this case
        return parser_code_t::arp;
    } else {
        return parser_code_t::unknown_ethertype;
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
    } else if (protocol == IpProtocolNumberGRE) {
        if (!unpack_gre) {
            // We do not decode it automatically but we can report source and destination IPs for it to FNM processing
            return parser_code_t::success;
        }

        if (local_pointer + sizeof(gre_packet_t) > end_pointer) {
            return parser_code_t::memory_violation;
        }

        gre_packet_t* gre_header = (gre_packet_t*)local_pointer;
        gre_header->convert();

        // Current version of parser does not handle these special codes and we just fail parsing process
        // These flags may extend length of GRE header and current logic is not ready to decode any of them
        if (gre_header->checksum != 0 || gre_header->reserved != 0 || gre_header->version != 0) {
            return parser_code_t::broken_gre;
        }

        // We will try parsing IPv4 only for now
        if (gre_header->protocol_type == IanaEthertypeIPv4) {
            local_pointer += sizeof(gre_packet_t);

            // This function will override all fields in original packet structure by new fields
            bool read_length_from_ip_header = true;

            // We need to calculate how much data we have after all parsed fields until end of packet to pass it to function below
            int remaining_packet_length = end_pointer - local_pointer;

            parser_code_t nested_packet_parse_result =
                parse_raw_ipv4_packet_to_simple_packet_full_ng(local_pointer, remaining_packet_length,
                                                               remaining_packet_length, packet, read_length_from_ip_header);

            return nested_packet_parse_result;
        } else if (gre_header->protocol_type == IanaEthertypeERSPAN) {
            local_pointer += sizeof(gre_packet_t);

            // We need to calculate how much data we have after all parsed fields until end of packet to pass it to function below
            int remaining_packet_length = end_pointer - local_pointer;

            bool read_length_from_ip_header_erspan = true;

            // We do not decode it second time
            bool decode_nested_gre = false;

            // We need to call same function because we have normal wire format encoded data with ethernet header here
            parser_code_t nested_packet_parse_result =
                parse_raw_packet_to_simple_packet_full_ng(local_pointer, remaining_packet_length, remaining_packet_length,
                                                          packet, decode_nested_gre, read_length_from_ip_header_erspan);

            return nested_packet_parse_result;
        } else {
            return parser_code_t::broken_gre;
        }
    } else {
        // That's fine, it's not some known protocol but we can export basic information retrieved from IP packet
        return parser_code_t::success;
    }

    return parser_code_t::success;
}

// Our own native function to convert IPv4 packet into simple_packet_t
parser_code_t parse_raw_ipv4_packet_to_simple_packet_full_ng(uint8_t* pointer,
                                                             int length_before_sampling,
                                                             int captured_length,
                                                             simple_packet_t& packet,
                                                             bool read_packet_length_from_ip_header) {
    // We are using pointer copy because we are changing it
    uint8_t* local_pointer = pointer;

    // It's very nice for doing checks
    uint8_t* end_pointer = pointer + captured_length;


    // Here we store IPv4 or IPv6 l4 protocol numbers
    uint8_t protocol = 0;


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

    if (read_packet_length_from_ip_header) {
        packet.length = ipv4_header->total_length;
    } else {
        packet.length = length_before_sampling;
    }

    // Ignore all IP options and shift pointer to L3 payload
    local_pointer += 4 * ipv4_header->ihl;

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
        // That's fine, it's not some known protocol but we can export basic information retrieved from IP packet
        return parser_code_t::success;
    }

    return parser_code_t::success;
}
