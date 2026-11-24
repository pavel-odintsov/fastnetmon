#pragma once

#include "../fastnetmon_types.hpp"

void start_afpacket_collection(process_packet_pointer func_ptr);
void start_af_packet_capture_for_interface(std::string capture_interface, int interface_number, unsigned int num_cpus);
std::vector<system_counter_t> get_af_packet_stats();
