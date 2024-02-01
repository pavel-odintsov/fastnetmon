#include "simple_packet_parser_ng.hpp"
#include "all_logcpp_libraries.hpp"
#include "network_data_structures.hpp"

#include "fast_library.hpp"

#include <algorithm>
#include <cstring>
#include <iterator>

using namespace network_data_stuctures;

// By default, we do not touch MPLS
// TODO: it's not working code yet
bool decode_mpls = false;

// We can strip only 3 nested vlans
const uint32_t maximum_vlans_to_strip = 3;

// Our own native function to convert wire packet into simple_packet_t
parser_code_t parse_raw_packet_to_simple_packet_full_ng(const uint8_t* pointer,
                                                        int length_before_sampling,
                                                        int captured_length,
                                                        simple_packet_t& packet,
                                                        bool unpack_gre,
                                                        bool read_packet_length_from_ip_header) {
    // We are using pointer copy because we are changing it
    const uint8_t* local_pointer = pointer;

    // It's very nice for doing checks
    const uint8_t* end_pointer = pointer + captured_length;

    // Return error if it shorter then ethernet headers
    if (local_pointer + sizeof(ethernet_header_t) > end_pointer) {
        return parser_code_t::memory_violation;
    }

    const ethernet_header_t* ethernet_header = (const ethernet_header_t*)local_pointer;

    // Copy Ethernet MAC addresses to packet structure using native C++ approach to avoid touching memory with memcpy
    std::copy(std::begin(ethernet_header->source_mac), std::end(ethernet_header->source_mac), std::begin(packet.source_mac));

    std::copy(std::begin(ethernet_header->destination_mac), std::end(ethernet_header->destination_mac),
              std::begin(packet.destination_mac));

    local_pointer += sizeof(ethernet_header_t);

    // Copy ethertype as we may need to change it below
    uint16_t ethertype = ethernet_header->get_ethertype_host_byte_order();

    uint32_t number_of_stripped_vlans = 0;

    // This loop will not start if ethertype is not VLAN
    while (ethertype == IanaEthertypeVLAN) { 
        // Return error if it's shorter than vlan header
        if (local_pointer + sizeof(ethernet_vlan_header_t) > end_pointer) {
            return parser_code_t::memory_violation;
        }

        const ethernet_vlan_header_t* ethernet_vlan_header = (const ethernet_vlan_header_t*)local_pointer;

        // We've agreed that this field keeps only outermost vlan
        if (number_of_stripped_vlans == 0) {
            packet.vlan = ethernet_vlan_header->get_vlan_id_host_byte_order();
        }
    
        local_pointer += sizeof(ethernet_vlan_header_t);

        number_of_stripped_vlans++;

        // We need to limit it to avoid possibility of attack which uses too many vlans tags to overload our parser
        if (number_of_stripped_vlans > maximum_vlans_to_strip) {
            return parser_code_t::too_many_nested_vlans;
        }

        // Change ethertype to vlan's ethertype
        ethertype = ethernet_vlan_header->get_ethertype_host_byte_order();
    }

    if (decode_mpls) {
        if (ethertype == IanaEthertypeMPLS_unicast) {
        REPEAT_MPLS_STRIP:
            if (local_pointer + sizeof(mpls_label_t) > end_pointer) {
                return parser_code_t::memory_violation;
            }

            const mpls_label_t* mpls_label_header = (const mpls_label_t*)local_pointer;

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

    if (ethertype == IanaEthertypeIPv4) {
        // Return error if pointer is shorter then IP header
        if (local_pointer + sizeof(ipv4_header_t) > end_pointer) {
            return parser_code_t::memory_violation;
        }

        const ipv4_header_t* ipv4_header = (const ipv4_header_t*)local_pointer;

        // Use network representation of addresses
        packet.src_ip = ipv4_header->get_source_ip_network_byte_order();
        packet.dst_ip = ipv4_header->get_destination_ip_network_byte_order();

        packet.ip_protocol_version = 4;

        packet.ttl = ipv4_header->get_ttl();

        // We need this specific field for Flow Spec mitigation mode
        packet.ip_length = ipv4_header->get_total_length_host_byte_order();

        packet.ip_dont_fragment = ipv4_header->get_dont_fragment_flag();

        packet.ip_fragmented = ipv4_header->is_fragmented();

        packet.ip_more_fragments = ipv4_header->get_more_fragments_flag();

        // We must use special function to recover value in a format useable for our consumption
        // We must not read this field directly
        packet.ip_fragment_offset = ipv4_header->get_fragment_offset_bytes();

        // We keep these variables to maintain backward compatibility with parse_raw_packet_to_simple_packet_full()
        packet.captured_payload_length = length_before_sampling;
        packet.payload_full_length     = length_before_sampling;

        // Pointer to payload
        packet.payload_pointer = (void*)pointer;

        protocol        = ipv4_header->get_protocol();
        packet.protocol = protocol;

        if (read_packet_length_from_ip_header) {
            packet.length = ipv4_header->get_total_length_host_byte_order();
        } else {
            packet.length = length_before_sampling;
        }

        // We need to handle fragmented traffic. In case of IPv4 fragmentation only first packet carries UDP / TCP / other headers
        // and consequent packets simply lack of this information and we know only protocol for them.
        // We can consequent packets by non zero fragment_offset
        if (ipv4_header->get_fragment_offset_bytes() != 0) {
            // The best we can do it so stop processing here and report success
            return parser_code_t::success;
        }

        // Ignore all IP options and shift pointer to L3 payload
        local_pointer += 4 * ipv4_header->get_ihl();
    } else if (ethertype == IanaEthertypeIPv6) {
        // Return error if pointer is shorter then IP header
        if (local_pointer + sizeof(ipv6_header_t) > end_pointer) {
            return parser_code_t::memory_violation;
        }

        const ipv6_header_t* ipv6_header = (const ipv6_header_t*)local_pointer;

        // TODO: we may use std::copy for it to avoid touching memory with memcpy
        memcpy(&packet.src_ipv6, ipv6_header->source_address, sizeof(packet.src_ipv6));
        memcpy(&packet.dst_ipv6, ipv6_header->destination_address, sizeof(packet.dst_ipv6));

        packet.ip_protocol_version = 6;

        packet.ttl = ipv6_header->get_hop_limit();

        // We need this specific field for Flow Spec mitigation mode
        packet.ip_length = ipv6_header->get_payload_length();

        // We keep these variables to maintain backward compatibility with parse_raw_packet_to_simple_packet_full()
        packet.captured_payload_length = length_before_sampling;
        packet.payload_full_length     = length_before_sampling;

        // Pointer to payload
        packet.payload_pointer = (void*)pointer;

        protocol        = ipv6_header->get_next_header();
        packet.protocol = protocol;

        if (read_packet_length_from_ip_header) {
            packet.length = ipv6_header->get_payload_length();
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
                const ipv6_extension_header_fragment_t* ipv6_extension_header_fragment = (const ipv6_extension_header_fragment_t*)local_pointer;

                // If we received this header then we assume that packet was fragmented
                packet.ip_fragmented = true;

                packet.ip_more_fragments = ipv6_extension_header_fragment->get_more_fragments();

                packet.ip_fragment_offset = ipv6_extension_header_fragment->get_fragment_offset_bytes();

                // We stop processing here as I believe that it's enough to know that this traffic was fragmented
                // We do not parse nested protocol in this case at all
                // If we observe first fragment of UDP datagram we may see header but for consequent packets we cannot do it
                // I think that's it's safer to avoid parsing such traffic deeper until we collect packet examples for all cases
                return parser_code_t::success;
            }

            return parser_code_t::no_ipv6_options_support;
        }
    } else if (ethertype == IanaEthertypeARP) {
        // it's not parser error of course but we need to have visibility about this case
        return parser_code_t::arp;
    } else {
        return parser_code_t::unknown_ethertype;
    }

    if (protocol == IpProtocolNumberTCP) {
        if (local_pointer + sizeof(tcp_header_t) > end_pointer) {
            // We observed that Huawei routers may send only first 52 bytes of header in sFlow mode
            // and it's not enough to accommodate whole TCP header which has length of 20 bytes and we can observe only
            // first 14 bytes and it happened in case of vlan presence

            // To offer better experience we will try retrieving only ports from TCP header as they're located in the beginning of packet
            if (local_pointer + sizeof(cropped_tcp_header_only_ports_t) > end_pointer) {
                // Sadly we cannot even retrieve port numbers and we have to discard this packet
                // Idea of reporting this packet as TCP protocol without ports information is not reasonable
                return parser_code_t::memory_violation;
            }

            // Use short TCP header which has only access to source and destination ports
            const cropped_tcp_header_only_ports_t* tcp_header = (const cropped_tcp_header_only_ports_t*)local_pointer;

            packet.source_port      = tcp_header->get_source_port_host_byte_order();
            packet.destination_port = tcp_header->get_destination_port_host_byte_order();

            return parser_code_t::success;
        }

        const tcp_header_t* tcp_header = (const tcp_header_t*)local_pointer;

        packet.source_port      = tcp_header->get_source_port_host_byte_order();
        packet.destination_port = tcp_header->get_destination_port_host_byte_order();

        // TODO: rework this code to use structs with bit fields
        packet.flags = tcp_header->get_fin() * 0x01 + tcp_header->get_syn() * 0x02 + tcp_header->get_rst() * 0x04 +
                       tcp_header->get_psh() * 0x08 + tcp_header->get_ack() * 0x10 + tcp_header->get_urg() * 0x20;

    } else if (protocol == IpProtocolNumberUDP) {
        if (local_pointer + sizeof(udp_header_t) > end_pointer) {
            return parser_code_t::memory_violation;
        }

        const udp_header_t* udp_header = (const udp_header_t*)local_pointer;

        packet.source_port      = udp_header->get_source_port_host_byte_order();
        packet.destination_port = udp_header->get_destination_port_host_byte_order();
    } else if (protocol == IpProtocolNumberGRE) {
        if (!unpack_gre) {
            // We do not decode it automatically but we can report source and destination IPs for it to FNM processing
            return parser_code_t::success;
        }

        if (local_pointer + sizeof(gre_header_t) > end_pointer) {
            return parser_code_t::memory_violation;
        }

        const gre_header_t* gre_header = (const gre_header_t*)local_pointer;

        // Current version of parser does not handle these special codes and we just fail parsing process
        // These flags may extend length of GRE header and current logic is not ready to decode any of them
        if (gre_header->get_checksum() != 0 || gre_header->get_reserved() != 0 || gre_header->get_version() != 0) {
            return parser_code_t::broken_gre;
        }

        uint16_t gre_nested_protocol = gre_header->get_protocol_type_host_byte_order();

        // We will try parsing IPv4 only for now
        if (gre_nested_protocol == IanaEthertypeIPv4) {
            local_pointer += sizeof(gre_header_t);

            // This function will override all fields in original packet structure by new fields
            bool read_length_from_ip_header = true;

            // We need to calculate how much data we have after all parsed fields until end of packet to pass it to function below
            int remaining_packet_length = end_pointer - local_pointer;

            parser_code_t nested_packet_parse_result =
                parse_raw_ipv4_packet_to_simple_packet_full_ng(local_pointer, remaining_packet_length,
                                                               remaining_packet_length, packet, read_length_from_ip_header);

            return nested_packet_parse_result;
        } else if (gre_nested_protocol == IanaEthertypeERSPAN) {
            local_pointer += sizeof(gre_header_t);

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
parser_code_t parse_raw_ipv4_packet_to_simple_packet_full_ng(const uint8_t* pointer,
                                                             int length_before_sampling,
                                                             int captured_length,
                                                             simple_packet_t& packet,
                                                             bool read_packet_length_from_ip_header) {
    // We are using pointer copy because we are changing it
    const uint8_t* local_pointer = pointer;

    // It's very nice for doing checks
    const uint8_t* end_pointer = pointer + captured_length;


    // Here we store IPv4 or IPv6 l4 protocol numbers
    uint8_t protocol = 0;


    // Return error if pointer is shorter then IP header
    if (local_pointer + sizeof(ipv4_header_t) > end_pointer) {
        return parser_code_t::memory_violation;
    }

    ipv4_header_t* ipv4_header = (ipv4_header_t*)local_pointer;

    // Use network representation of addresses
    packet.src_ip = ipv4_header->get_source_ip_network_byte_order();
    packet.dst_ip = ipv4_header->get_destination_ip_network_byte_order();

    packet.ip_protocol_version = 4;

    packet.ttl              = ipv4_header->get_ttl();
    packet.ip_length        = ipv4_header->get_total_length_host_byte_order();
    packet.ip_dont_fragment = ipv4_header->get_dont_fragment_flag();

    packet.ip_fragmented = ipv4_header->is_fragmented();

    // We keep these variables to maintain backward compatibility with parse_raw_packet_to_simple_packet_full()
    packet.captured_payload_length = length_before_sampling;
    packet.payload_full_length     = length_before_sampling;

    // Pointer to payload
    packet.payload_pointer = (void*)pointer;

    protocol        = ipv4_header->get_protocol();
    packet.protocol = protocol;

    if (read_packet_length_from_ip_header) {
        packet.length = ipv4_header->get_total_length_host_byte_order();
    } else {
        packet.length = length_before_sampling;
    }

    // Ignore all IP options and shift pointer to L3 payload
    local_pointer += 4 * ipv4_header->get_ihl();

    if (protocol == IpProtocolNumberTCP) {
        if (local_pointer + sizeof(tcp_header_t) > end_pointer) {
            return parser_code_t::memory_violation;
        }

        tcp_header_t* tcp_header = (tcp_header_t*)local_pointer;

        packet.source_port      = tcp_header->get_source_port_host_byte_order();
        packet.destination_port = tcp_header->get_destination_port_host_byte_order();

        // TODO: rework this code to use structs with bit fields
        packet.flags = tcp_header->get_fin() * 0x01 + tcp_header->get_syn() * 0x02 + tcp_header->get_rst() * 0x04 +
                       tcp_header->get_psh() * 0x08 + tcp_header->get_ack() * 0x10 + tcp_header->get_urg() * 0x20;

    } else if (protocol == IpProtocolNumberUDP) {
        if (local_pointer + sizeof(udp_header_t) > end_pointer) {
            return parser_code_t::memory_violation;
        }

        udp_header_t* udp_header = (udp_header_t*)local_pointer;

        packet.source_port      = udp_header->get_source_port_host_byte_order();
        packet.destination_port = udp_header->get_destination_port_host_byte_order();
    } else {
        // That's fine, it's not some known protocol but we can export basic information retrieved from IP packet
        return parser_code_t::success;
    }

    return parser_code_t::success;
}
