#pragma once

#include "fastnetmon_types.h"

#include <iostream>
#include <map>
#include <sstream>
#include <stdint.h>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include <boost/regex.hpp>
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>

#include <json-c/json.h>

// Boost libs
#include <boost/algorithm/string.hpp>

#include "libpatricia/patricia.h"

#include "fast_endianless.hpp"

#include "fastnetmon_networks.hpp"

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
std::string print_ipv6_address(const struct in6_addr& ipv6_address);
std::string print_simple_packet(simple_packet_t packet);
std::string convert_timeval_to_date(struct timeval tv);
bool convert_hex_as_string_to_uint(std::string hex, uint32_t& value);

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
bool is_cidr_subnet(std::string subnet);
bool is_v4_host(std::string host);
bool file_exists(std::string path);
uint32_t convert_cidr_to_binary_netmask(unsigned int cidr);
std::string get_printable_protocol_name(unsigned int protocol);
std::string get_net_address_from_network_as_string(std::string network_cidr_format);
std::string print_time_t_in_fastnetmon_format(time_t current_time);
unsigned int get_cidr_mask_from_network_as_string(std::string network_cidr_format);
void copy_networks_from_string_form_to_binary(std::vector<std::string> networks_list_as_string,
                                              std::vector<subnet_cidr_mask_t>& our_networks);
int convert_string_to_integer(std::string line);

bool print_pid_to_file(pid_t pid, std::string pid_path);
bool read_pid_from_file(pid_t& pid, std::string pid_path);

direction_t get_packet_direction(patricia_tree_t* lookup_tree,
                               uint32_t src_ip,
                               uint32_t dst_ip,
                               subnet_cidr_mask_t& subnet);

direction_t get_packet_direction_ipv6(patricia_tree_t* lookup_tree, struct in6_addr src_ipv6, struct in6_addr dst_ipv6, subnet_ipv6_cidr_mask_t& subnet);

std::string convert_prefix_to_string_representation(prefix_t* prefix);
std::string find_subnet_by_ip_in_string_format(patricia_tree_t* patricia_tree, std::string ip);
std::string convert_subnet_to_string(subnet_cidr_mask_t my_subnet);
std::string get_direction_name(direction_t direction_value);
subnet_cidr_mask_t convert_subnet_from_string_to_binary(std::string subnet_cidr);
std::vector<std::string> split_strings_to_vector_by_comma(std::string raw_string);
subnet_cidr_mask_t convert_subnet_from_string_to_binary_with_cidr_format(std::string subnet_cidr);

#ifdef __linux__
bool manage_interface_promisc_mode(std::string interface_name, bool switch_on);
#endif

bool ip_belongs_to_patricia_tree_ipv6(patricia_tree_t* patricia_tree, struct in6_addr client_ipv6_address);
std::string serialize_attack_description(attack_details_t& current_attack);
attack_type_t detect_attack_type(attack_details_t& current_attack);
std::string get_printable_attack_name(attack_type_t attack);
std::string serialize_network_load_to_text(map_element_t& network_speed_meter, bool average);
json_object* serialize_attack_description_to_json(attack_details_t& current_attack);
json_object* serialize_network_load_to_json(map_element_t& network_speed_meter);
std::string serialize_statistic_counters_about_attack(attack_details_t& current_attack);

std::string dns_lookup(std::string domain_name);
bool store_data_to_stats_server(unsigned short int graphite_port, std::string graphite_host, std::string buffer_as_string);
bool get_interface_number_by_device_name(int socket_fd, std::string interface_name, int& interface_number);

bool set_boost_process_name(boost::thread* thread, std::string process_name);
 std::string convert_subnet_to_string(subnet_cidr_mask_t my_subnet);

 std::string print_ipv6_cidr_subnet(subnet_ipv6_cidr_mask_t subnet);
 std::string convert_any_ip_to_string(subnet_ipv6_cidr_mask_t subnet);
bool convert_string_to_positive_integer_safe(std::string line, int& value);
bool read_ipv6_host_from_string(std::string ipv6_host_as_string, in6_addr& result);
bool validate_ipv6_or_ipv4_host(const std::string host);
uint64_t get_current_unix_time_in_nanoseconds();

bool write_data_to_influxdb(std::string database,
                            std::string host,
                            std::string port,
                            bool enable_auth,
                            std::string influx_user,
                            std::string influx_password,
                            std::string query);

std::string join_by_comma_and_equal(std::map<std::string, std::string>& data);
