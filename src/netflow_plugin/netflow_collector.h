#pragma once
/* netflow plugin header */

#include "../fastnetmon_types.h"

// For testing
bool process_netflow_packet(uint8_t* packet, uint32_t len, std::string& client_addres_in_string_format, uint32_t client_ipv4_address);
void start_netflow_collection(process_packet_pointer func_ptr);
std::vector<system_counter_t> get_netflow_stats();
