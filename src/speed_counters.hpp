#pragma once

#include "fastnetmon_types.hpp"

void increment_incoming_counters(subnet_counter_t& current_element,
                                 const simple_packet_t& current_packet,
                                 uint64_t sampled_number_of_packets,
                                 uint64_t sampled_number_of_bytes);

void build_speed_counters_from_packet_counters(subnet_counter_t& new_speed_element, const subnet_counter_t& data_counter, double speed_calc_period);
void increment_outgoing_counters(subnet_counter_t& current_element,
                                 const simple_packet_t& current_packet,
                                 uint64_t sampled_number_of_packets,
                                 uint64_t sampled_number_of_bytes);
void build_average_speed_counters_from_speed_counters(subnet_counter_t& current_average_speed_element,
                                                      const subnet_counter_t& new_speed_element,
                                                      double exp_value);
