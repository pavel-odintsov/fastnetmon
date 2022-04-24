#include "fastnetmon_simple_packet.h"
#include "network_data_structures.hpp"

network_data_stuctures::parser_code_t parse_raw_packet_to_simple_packet_full_ng(uint8_t* pointer,
                                                                                int length_before_sampling,
                                                                                int captured_length,
                                                                                simple_packet_t& packet,
                                                                                bool use_packet_length_from_wire);

parser_code_t parse_raw_ipv4_packet_to_simple_packet_full_ng(uint8_t* pointer,
                                                             int length_before_sampling,
                                                             int captured_length,
                                                             simple_packet_t& packet,
                                                             bool read_packet_length_from_ip_header);
