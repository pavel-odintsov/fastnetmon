#pragma once

#include "../fastnetmon_types.hpp"

bool process_netflow_packet_v5(const uint8_t* packet,
                               uint32_t packet_length,
                               const std::string& client_addres_in_string_format,
                               uint32_t client_ipv4_address);

std::vector<system_counter_t> get_netflow_v5_stats();

