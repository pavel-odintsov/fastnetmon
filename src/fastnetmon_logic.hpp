#include "fastnetmon_types.h"
#include "bgp_flow_spec.h"

#ifdef ENABLE_DPI
#include "fast_dpi.h"
#endif

#ifdef REDIS
#include <hiredis/hiredis.h>
#endif

typedef std::map<std::string, uint32_t> active_flow_spec_announces_t;

void build_speed_counters_from_packet_counters(map_element& new_speed_element,
                                                      map_element* vector_itr,
                                                      double speed_calc_period) ;
                                                  
void build_average_speed_counters_from_speed_counters(map_element* current_average_speed_element,
         map_element& new_speed_element,
         double exp_value,
         double exp_power);

std::string get_amplification_attack_type(amplification_attack_type_t attack_type);
std::string generate_flow_spec_for_amplification_attack(amplification_attack_type_t amplification_attack_type,
                                                        std::string destination_ip);

bool we_should_ban_this_ip(map_element* average_speed_element, ban_settings_t current_ban_settings);

bool exceed_mbps_speed(uint64_t in_counter, uint64_t out_counter, unsigned int threshold_mbps);
bool exceed_flow_speed(uint64_t in_counter, uint64_t out_counter, unsigned int threshold);
bool exceed_pps_speed(uint64_t in_counter, uint64_t out_counter, unsigned int threshold);
ban_settings_t read_ban_settings(configuration_map_t configuration_map, std::string host_group_name);
logging_configuration_t read_logging_settings(configuration_map_t configuration_map);
void print_attack_details_to_file(std::string details, std::string client_ip_as_string, attack_details current_attack);
std::string print_ban_thresholds(ban_settings_t current_ban_settings);
std::string print_subnet_load();
std::string print_flow_tracking_for_ip(conntrack_main_struct& conntrack_element, std::string client_ip);
std::string print_flow_tracking_for_specified_protocol(contrack_map_type& protocol_map,
                                                       std::string client_ip,
                                                       direction_t flow_direction);

void convert_integer_to_conntrack_hash_struct(packed_session* packed_connection_data,
                                              packed_conntrack_hash* unpacked_data);

void cleanup_ban_list();
void call_unban_handlers(uint32_t client_ip, attack_details& current_attack);
std::string print_ddos_attack_details();

std::string get_attack_description(uint32_t client_ip, attack_details& current_attack) ;

std::string get_attack_description_in_json(uint32_t client_ip, attack_details& current_attack) ;

std::string generate_simple_packets_dump(std::vector<simple_packet_t>& ban_list_details) ;

void send_attack_details(uint32_t client_ip, attack_details current_attack_details);

#ifdef ENABLE_DPI
// Parse raw binary stand-alone packet with nDPI
ndpi_protocol dpi_parse_packet(char* buffer,
                               uint32_t len,
                               uint32_t snap_len,
                               struct ndpi_id_struct* src,
                               struct ndpi_id_struct* dst,
                               struct ndpi_flow_struct* flow,
                               std::string& parsed_packet_as_string);
void init_current_instance_of_ndpi();
#endif

void zeroify_ndpi_flow(struct ndpi_flow_struct* flow);
void launch_bgp_flow_spec_rule(amplification_attack_type_t attack_type, std::string client_ip_as_string);
void produce_dpi_dump_for_pcap_dump(std::string pcap_file_path, std::stringstream& ss, std::string client_ip_as_string);
void call_attack_details_handlers(uint32_t client_ip, attack_details& current_attack, std::string attack_fingerprint);
uint64_t convert_conntrack_hash_struct_to_integer(packed_conntrack_hash* struct_value);
bool process_flow_tracking_table(conntrack_main_struct& conntrack_element, std::string client_ip);
bool exec_with_stdin_params(std::string cmd, std::string params);
ban_settings_t get_ban_settings_for_this_subnet(subnet_t subnet, std::string& host_group_name);
void exabgp_ban_manage(std::string action, std::string ip_as_string, attack_details current_attack);
void exabgp_prefix_ban_manage(std::string action,
                              std::string prefix_as_string_with_mask,
                              std::string exabgp_next_hop,
                              std::string exabgp_community);
bool exabgp_flow_spec_ban_manage(std::string action, std::string flow_spec_rule_as_text);

#ifdef REDIS
void store_data_in_redis(std::string key_name, std::string attack_details);
redisContext* redis_init_connection();
#endif
