#pragma once

#include "fastnetmon_simple_packet.hpp"
#include "network_data_structures.hpp"

// This class is used to alter parser behaviour
class parser_options_t {
    public:
    // Enables logic to unpack GRE
    bool unpack_gre = false;

    bool read_packet_length_from_ip_header = false;

    // Enables logic to unpack GTPv1
    bool unpack_gtp_v1 = false;
};

network_data_stuctures::parser_code_t parse_raw_packet_to_simple_packet_full_ng(const uint8_t* pointer,
                                                                                int length_before_sampling,
                                                                                int captured_length,
                                                                                simple_packet_t& packet,
                                                                                const parser_options_t& parser_options);


network_data_stuctures::parser_code_t parse_raw_ipv4_packet_to_simple_packet_full_ng(const uint8_t* pointer,
                                                                                     int length_before_sampling,
                                                                                     int captured_length,
                                                                                     simple_packet_t& packet,
                                                                                     const parser_options_t& parser_options);
