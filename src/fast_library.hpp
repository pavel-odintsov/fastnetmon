#pragma once

#include "fastnetmon_types.hpp"

#include <iostream>
#include <map>
#include <sstream>
#include <string>

#include <utility>
#include <vector>

#include <boost/thread.hpp>
#include "nlohmann/json.hpp"

#include "libpatricia/patricia.hpp"

#include "fastnetmon_networks.hpp"

#include "attack_details.hpp"

#include <boost/circular_buffer.hpp>

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
ip_addresses_list_t get_ip_list_for_interface(const std::string& interface_name);
interfaces_list_t get_interfaces_list();

bool store_data_to_graphite(unsigned short int graphite_port, std::string graphite_host, graphite_data_t graphite_data);
std::string get_protocol_name_by_number(unsigned int proto_number);
uint64_t convert_speed_to_mbps(uint64_t speed_in_bps);
bool exec(const std::string& cmd, std::vector<std::string>& output_list, std::string& error_text);
std::string convert_ip_as_uint_to_string(uint32_t ip_as_integer);
std::string convert_int_to_string(int value);
std::string print_ipv6_address(const struct in6_addr& ipv6_address);
std::string print_simple_packet(simple_packet_t packet);
std::string convert_timeval_to_date(const timeval& tv);
bool convert_hex_as_string_to_uint(std::string hex, uint32_t& value);

int extract_bit_value(uint8_t num, int bit);
int extract_bit_value(uint16_t num, int bit);

int clear_bit_value(uint8_t& num, int bit);
int clear_bit_value(uint16_t& num, int bit);

int set_bit_value(uint8_t& num, int bit);
int set_bit_value(uint16_t& num, int bit);

std::string print_tcp_flags(uint8_t flag_value);
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
int convert_string_to_integer(std::string line);

bool print_pid_to_file(pid_t pid, std::string pid_path);
bool read_pid_from_file(pid_t& pid, std::string pid_path);

direction_t get_packet_direction(patricia_tree_t* lookup_tree, uint32_t src_ip, uint32_t dst_ip, subnet_cidr_mask_t& subnet);

direction_t
get_packet_direction_ipv6(patricia_tree_t* lookup_tree, struct in6_addr src_ipv6, struct in6_addr dst_ipv6, subnet_ipv6_cidr_mask_t& subnet);

std::string convert_prefix_to_string_representation(prefix_t* prefix);
std::string convert_subnet_to_string(subnet_cidr_mask_t my_subnet);
std::string get_direction_name(direction_t direction_value);
std::vector<std::string> split_strings_to_vector_by_comma(std::string raw_string);
bool convert_subnet_from_string_to_binary_with_cidr_format_safe(const std::string& subnet_cidr, subnet_cidr_mask_t& subnet_cidr_mask);

#ifdef __linux__
bool manage_interface_promisc_mode(std::string interface_name, bool switch_on);
bool get_interface_number_by_device_name(int socket_fd, std::string interface_name, int& interface_number);
#endif

bool ip_belongs_to_patricia_tree_ipv6(patricia_tree_t* patricia_tree, struct in6_addr client_ipv6_address);
std::string serialize_attack_description(const attack_details_t& current_attack);
attack_type_t detect_attack_type(const attack_details_t& current_attack);
std::string get_printable_attack_name(attack_type_t attack);
std::string serialize_network_load_to_text(subnet_counter_t& network_speed_meter, bool average);

std::string dns_lookup(std::string domain_name);
bool store_data_to_stats_server(unsigned short int graphite_port, std::string graphite_host, std::string buffer_as_string);

bool set_boost_process_name(boost::thread* thread, const std::string& process_name);
std::string convert_subnet_to_string(subnet_cidr_mask_t my_subnet);

std::string print_ipv6_cidr_subnet(subnet_ipv6_cidr_mask_t subnet);
std::string convert_any_ip_to_string(const subnet_ipv6_cidr_mask_t& subnet);
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

std::string join_by_comma_and_equal(const std::map<std::string, std::string>& data);
bool parse_meminfo_into_map(std::map<std::string, uint64_t>& parsed_meminfo);
bool read_uint64_from_string(const std::string& line, uint64_t& value);
bool read_integer_from_file(const std::string& file_path, int& value);
bool read_file_to_string(const std::string& file_path, std::string& file_content);
bool convert_string_to_any_integer_safe(const std::string& line, int& value);
void exec_no_error_check(const std::string& cmd);
bool parse_os_release_into_map(std::map<std::string, std::string>& parsed_os_release);
unsigned int get_logical_cpus_number();
std::string get_virtualisation_method();
bool get_cpu_flags(std::vector<std::string>& flags);
bool get_linux_distro_name(std::string& distro_name);
bool get_linux_distro_version(std::string& distro_name);
bool get_kernel_version(std::string& kernel_version);
bool execute_web_request(const std::string& address_param,
                         const std::string& request_type,
                         const std::string& post_data,
                         uint32_t& response_code,
                         std::string& response_body,
                         const std::map<std::string, std::string>& headers,
                         std::string& error_text);
unsigned int get_total_memory();
std::string get_cpu_model();
bool execute_web_request_secure(std::string address,
                                std::string request_type,
                                std::string post_data,
                                uint32_t& response_code,
                                std::string& response_body,
                                std::map<std::string, std::string>& headers,
                                std::string& error_text);
std::string forwarding_status_to_string(forwarding_status_t status);
std::string country_static_string_to_dynamic_string(const boost::beast::static_string<2>& country_code);
bool serialize_simple_packet_to_json(const simple_packet_t& packet, nlohmann::json& json_packet);
bool convert_ip_as_string_to_uint_safe(const std::string& ip, uint32_t& ip_as_integer);
forwarding_status_t forwarding_status_from_integer(uint8_t forwarding_status_as_integer);
bool is_zero_ipv6_address(const in6_addr& ipv6_address);
std::string convert_ipv4_subnet_to_string(const subnet_cidr_mask_t& subnet);

// Represent IPv6 subnet in string form
std::string convert_ipv6_subnet_to_string(const subnet_ipv6_cidr_mask_t& subnet);
std::string convert_any_ip_to_string(uint32_t client_ip);
bool lookup_ip_in_integer_form_inpatricia_and_return_subnet_if_found(patricia_tree_t* patricia_tree,
                                                                     uint32_t client_ip,
                                                                     subnet_cidr_mask_t& subnet);
bool ip_belongs_to_patricia_tree(patricia_tree_t* patricia_tree, uint32_t client_ip);

// Overloaded function which works with any IP protocol version, we use it for templated applications
std::string convert_any_subnet_to_string(const subnet_ipv6_cidr_mask_t& subnet);
std::string convert_any_subnet_to_string(const subnet_cidr_mask_t& subnet);
std::string print_binary_string_as_hex_with_leading_0x(const uint8_t* data_ptr, uint32_t data_length);
bool read_ipv6_subnet_from_string(subnet_ipv6_cidr_mask_t& ipv6_address, const std::string& ipv6_subnet_as_string);
bool subnet_belongs_to_patricia_tree(patricia_tree_t* patricia_tree, const subnet_cidr_mask_t& subnet);
// Prepares textual dump of simple packets buffer
void print_simple_packet_buffer_to_string(const boost::circular_buffer<simple_packet_t>& simple_packets_buffer, std::string& output);
