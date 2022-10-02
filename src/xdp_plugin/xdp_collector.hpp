#pragma once

#include "../fastnetmon_types.hpp"

void start_xdp_collection(process_packet_pointer func_ptr);
std::vector<system_counter_t> get_xdp_stats();
