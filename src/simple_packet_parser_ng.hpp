#pragma once

#include "fastnetmon_simple_packet.hpp"
#include "network_data_structures.hpp"

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
    too_many_mpls_tags,
    mpls,
    unknown_traffic_in_mpls,
    broken_pppoe,
    pppoe_ipv6,
    malformed_ip_header_length,
    // It must be kept here as last element
    maximum_parser_code_value
};

std::string parser_code_to_string(parser_code_t code);


// This class is used to alter parser behaviour
class parser_options_t {
    public:
    // Enables logic to unpack GRE
    bool unpack_gre = false;

    bool read_packet_length_from_ip_header = false;

    // Enables logic to unpack GTPv1
    bool unpack_gtp_v1 = false;

    // Enables MPLS stripping logic
    bool parse_mpls = false;

    // Enabled logic to unpack PPPoE session packets
    bool unpack_ppp = false;
};

parser_code_t parse_raw_packet_to_simple_packet_full(const uint8_t* pointer,
                                                                                int length_before_sampling,
                                                                                int captured_length,
                                                                                simple_packet_t& packet,
                                                                                const parser_options_t& parser_options);


parser_code_t parse_raw_ipv4_packet_to_simple_packet_full(const uint8_t* pointer,
                                                                                     int length_before_sampling,
                                                                                     int captured_length,
                                                                                     simple_packet_t& packet,
                                                                                     const parser_options_t& parser_options);

parser_code_t parse_raw_ipv6_packet_to_simple_packet_full(const uint8_t* pointer,
                                                             int length_before_sampling,
                                                             int captured_length,
                                                             simple_packet_t& packet,
                                                             const parser_options_t& parser_options);
