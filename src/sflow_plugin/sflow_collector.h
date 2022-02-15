#pragma once

#include "../fastnetmon_types.h"
#include <stdint.h>

void start_sflow_collection(process_packet_pointer func_ptr);
void init_sflow_module();
void deinit_sflow_module();

// New code for v5 only
void parse_sflow_v5_packet(uint8_t* payload_ptr, unsigned int payload_length, uint32_t client_ipv4_address);
