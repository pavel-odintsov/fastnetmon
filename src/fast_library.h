#ifndef _FAST_LIBRARY_H
#define _FAST_LIBRARY_H

#include "fastnetmon_types.h"

#include <stdint.h>
#include <sys/types.h>
#include <string>
#include <iostream>
#include <vector>
#include <utility>
#include <sstream>

#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/regex.hpp>

// Boost libs
#include <boost/algorithm/string.hpp>

std::string get_protocol_name_by_number(unsigned int proto_number);
uint64_t convert_speed_to_mbps(uint64_t speed_in_bps);
std::vector<std::string> exec(std::string cmd);
uint32_t convert_ip_as_string_to_uint(std::string ip);
std::string convert_ip_as_uint_to_string(uint32_t ip_as_integer);
std::string convert_int_to_string(int value);
std::string print_simple_packet(simple_packet packet);
std::string convert_timeval_to_date(struct timeval tv);
int extract_bit_value(uint8_t num, int bit);
std::string print_tcp_flags(uint8_t flag_value);
uint64_t MurmurHash64A ( const void * key, int len, uint64_t seed );
std::string print_tcp_flags(uint8_t flag_value);
int timeval_subtract (struct timeval * result, struct timeval * x,  struct timeval * y);
bool folder_exists(std::string path);
bool is_cidr_subnet(const char* subnet);
bool file_exists(std::string path);
uint32_t convert_cidr_to_binary_netmask(unsigned int cidr);
std::string get_printable_protocol_name(unsigned int protocol);
std::string get_net_address_from_network_as_string(std::string network_cidr_format);
std::string print_time_t_in_fastnetmon_format(time_t current_time);
unsigned int get_cidr_mask_from_network_as_string(std::string network_cidr_format);
void copy_networks_from_string_form_to_binary(std::vector<std::string> networks_list_as_string, std::vector<subnet>& our_networks);
int convert_string_to_integer(std::string line);

// Byte order type safe converters
uint16_t fast_ntoh(uint16_t value);
uint32_t fast_ntoh(uint32_t value);
uint64_t fast_ntoh (uint64_t value);

uint16_t fast_hton(uint16_t value);
uint32_t fast_hton(uint32_t value);
uint64_t fast_hton(uint64_t value);

#endif
