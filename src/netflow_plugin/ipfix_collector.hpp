#pragma once

std::vector<system_counter_t> get_ipfix_sampling_rates();
std::vector<system_counter_t> get_ipfix_stats();

bool process_ipfix_packet(const uint8_t* packet,
                          uint32_t udp_packet_length,
                          const std::string& client_addres_in_string_format,
                          uint32_t client_ipv4_address);

void load_ipfix_template_cache();
void load_ipfix_sampling_cache();

