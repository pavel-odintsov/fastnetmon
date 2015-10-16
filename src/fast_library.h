#ifndef FAST_LIBRARY_H
#define FAST_LIBRARY_H

#include "fastnetmon_types.h"

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <map>
#include <vector>
#include <utility>
#include <sstream>

#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/regex.hpp>

#include <json-c/json.h>

// Boost libs
#include <boost/algorithm/string.hpp>

#include "libpatricia/patricia.h"

#ifdef ENABLE_LUA_HOOKS
#include <luajit-2.0/lua.hpp>
#endif

#define TCP_FIN_FLAG_SHIFT 1
#define TCP_SYN_FLAG_SHIFT 2
#define TCP_RST_FLAG_SHIFT 3
#define TCP_PSH_FLAG_SHIFT 4
#define TCP_ACK_FLAG_SHIFT 5
#define TCP_URG_FLAG_SHIFT 6

typedef std::map<std::string, uint64_t> graphite_data_t;
typedef std::vector<std::string> interfaces_list_t;
typedef std::vector<std::string> ip_addresses_list_t;

ip_addresses_list_t get_local_ip_v4_addresses_list();
ip_addresses_list_t get_ip_list_for_interface(std::string interface);
interfaces_list_t get_interfaces_list();

bool store_data_to_graphite(unsigned short int graphite_port, std::string graphite_host, graphite_data_t graphite_data);
std::string get_protocol_name_by_number(unsigned int proto_number);
uint64_t convert_speed_to_mbps(uint64_t speed_in_bps);
std::vector<std::string> exec(std::string cmd);
uint32_t convert_ip_as_string_to_uint(std::string ip);
std::string convert_ip_as_uint_to_string(uint32_t ip_as_integer);
std::string convert_int_to_string(int value);
std::string print_ipv6_address(struct in6_addr& ipv6_address);
std::string print_simple_packet(simple_packet packet);
std::string convert_timeval_to_date(struct timeval tv);

int extract_bit_value(uint8_t num, int bit);
int extract_bit_value(uint16_t num, int bit);

int clear_bit_value(uint8_t& num, int bit);
int clear_bit_value(uint16_t& num, int bit);

int set_bit_value(uint8_t& num, int bit);
int set_bit_value(uint16_t& num, int bit);

std::string print_tcp_flags(uint8_t flag_value);
uint64_t MurmurHash64A(const void* key, int len, uint64_t seed);
std::string print_tcp_flags(uint8_t flag_value);
int timeval_subtract(struct timeval* result, struct timeval* x, struct timeval* y);
bool folder_exists(std::string path);
bool is_cidr_subnet(const char* subnet);
bool is_v4_host(std::string host);
bool file_exists(std::string path);
uint32_t convert_cidr_to_binary_netmask(unsigned int cidr);
std::string get_printable_protocol_name(unsigned int protocol);
std::string get_net_address_from_network_as_string(std::string network_cidr_format);
std::string print_time_t_in_fastnetmon_format(time_t current_time);
unsigned int get_cidr_mask_from_network_as_string(std::string network_cidr_format);
void copy_networks_from_string_form_to_binary(std::vector<std::string> networks_list_as_string,
                                              std::vector<subnet_t>& our_networks);
int convert_string_to_integer(std::string line);

// Byte order type safe converters
uint16_t fast_ntoh(uint16_t value);
uint32_t fast_ntoh(uint32_t value);
uint64_t fast_ntoh(uint64_t value);

uint16_t fast_hton(uint16_t value);
uint32_t fast_hton(uint32_t value);
uint64_t fast_hton(uint64_t value);

bool print_pid_to_file(pid_t pid, std::string pid_path);
bool read_pid_from_file(pid_t& pid, std::string pid_path);

direction get_packet_direction(patricia_tree_t* lookup_tree, uint32_t src_ip, uint32_t dst_ip, unsigned long& subnet, unsigned int& subnet_cidr_mask);

direction get_packet_direction_ipv6(patricia_tree_t* lookup_tree, struct in6_addr src_ipv6, struct in6_addr dst_ipv6);

std::string convert_prefix_to_string_representation(prefix_t* prefix);
std::string find_subnet_by_ip_in_string_format(patricia_tree_t* patricia_tree, std::string ip);
std::string convert_subnet_to_string(subnet_t my_subnet);
std::string get_direction_name(direction direction_value);
subnet_t convert_subnet_from_string_to_binary(std::string subnet_cidr);
std::vector <std::string> split_strings_to_vector_by_comma(std::string raw_string);
subnet_t convert_subnet_from_string_to_binary_with_cidr_format(std::string subnet_cidr);

inline uint64_t read_tsc_cpu_register();
uint64_t get_tsc_freq_with_sleep();

#ifdef __linux__
bool manage_interface_promisc_mode(std::string interface_name, bool switch_on);
#endif

#ifdef ENABLE_LUA_HOOKS
lua_State* init_lua_jit(std::string lua_hooks_path);
bool call_lua_function(std::string function_name, lua_State* lua_state_param, std::string client_addres_in_string_format, void* ptr);
#endif

std::string serialize_attack_description(attack_details& current_attack);
attack_type_t detect_attack_type(attack_details& current_attack);
std::string get_printable_attack_name(attack_type_t attack);
std::string serialize_network_load_to_text(map_element& network_speed_meter, bool average);
json_object* serialize_attack_description_to_json(attack_details& current_attack);
json_object* serialize_network_load_to_json(map_element& network_speed_meter);
std::string serialize_statistic_counters_about_attack(attack_details& current_attack);

std::string dns_lookup(std::string domain_name);
bool store_data_to_stats_server(unsigned short int graphite_port, std::string graphite_host, std::string buffer_as_string);

#endif
