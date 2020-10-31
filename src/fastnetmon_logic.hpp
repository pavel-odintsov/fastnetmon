#include "fastnetmon_types.h"

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
