#include "bgp_protocol.hpp"
#include "fastnetmon_types.hpp"

#ifdef REDIS
#include <hiredis/hiredis.h>
#endif

#include "all_logcpp_libraries.hpp"
#include "packet_bucket.hpp"

#include "fastnetmon.grpc.pb.h"
#include <grpc++/grpc++.h>

std::string get_amplification_attack_type(amplification_attack_type_t attack_type);
std::string generate_flow_spec_for_amplification_attack(amplification_attack_type_t amplification_attack_type, std::string destination_ip);

bool we_should_ban_this_entity(const subnet_counter_t& average_speed_element,
                               const ban_settings_t& current_ban_settings,
                               attack_detection_threshold_type_t& attack_detection_source,
                               attack_detection_direction_type_t& attack_detection_direction);

bool exceed_mbps_speed(uint64_t in_counter, uint64_t out_counter, unsigned int threshold_mbps);
bool exceed_flow_speed(uint64_t in_counter, uint64_t out_counter, unsigned int threshold);
bool exceed_pps_speed(uint64_t in_counter, uint64_t out_counter, unsigned int threshold);
ban_settings_t read_ban_settings(configuration_map_t configuration_map, std::string host_group_name);
logging_configuration_t read_logging_settings(configuration_map_t configuration_map);
void print_attack_details_to_file(const std::string& details, const std::string& client_ip_as_string, const attack_details_t& current_attack);
std::string print_ban_thresholds(ban_settings_t current_ban_settings);
std::string print_subnet_ipv4_load();
std::string print_flow_tracking_for_ip(conntrack_main_struct_t& conntrack_element, std::string client_ip);
std::string print_flow_tracking_for_specified_protocol(contrack_map_type& protocol_map, std::string client_ip, direction_t flow_direction);

void convert_integer_to_conntrack_hash_struct(const uint64_t& packed_connection_data, packed_conntrack_hash_t& unpacked_data);

void cleanup_ban_list();

std::string print_ddos_attack_details();

std::string get_attack_description(uint32_t client_ip, const attack_details_t& current_attack);

std::string get_attack_description_in_json(uint32_t client_ip, const attack_details_t& current_attack);

std::string generate_simple_packets_dump(std::vector<simple_packet_t>& ban_list_details);

void send_attack_details(uint32_t client_ip, attack_details_t current_attack_details);

void call_attack_details_handlers(uint32_t client_ip, attack_details_t& current_attack, std::string attack_fingerprint);
uint64_t convert_conntrack_hash_struct_to_integer(packed_conntrack_hash_t* struct_value);
bool process_flow_tracking_table(conntrack_main_struct_t& conntrack_element, std::string client_ip);
bool exec_with_stdin_params(std::string cmd, std::string params);
ban_settings_t get_ban_settings_for_this_subnet(const subnet_cidr_mask_t& subnet, std::string& host_group_name);
void exabgp_prefix_ban_manage(std::string action, std::string prefix_as_string_with_mask, std::string exabgp_next_hop, std::string exabgp_community);

#ifdef REDIS
void store_data_in_redis(std::string key_name, std::string attack_details);
redisContext* redis_init_connection();
#endif

void execute_ip_ban(uint32_t client_ip, subnet_counter_t average_speed_element, std::string flow_attack_details, subnet_cidr_mask_t customer_subnet);

void call_blackhole_actions_per_host(attack_action_t attack_action,
                                     uint32_t client_ip,
                                     const subnet_ipv6_cidr_mask_t& client_ipv6,
                                     bool ipv6,
                                     const attack_details_t& current_attack,
                                     attack_detection_source_t attack_detection_source,
                                     const std::string& flow_attack_details,
                                     const boost::circular_buffer<simple_packet_t>& simple_packets_buffer,
                                     const boost::circular_buffer<fixed_size_packet_storage_t>& raw_packets_buffer);

#ifdef MONGO
void store_data_in_mongo(std::string key_name, std::string attack_details_json);
#endif

std::string print_channel_speed_ipv6(std::string traffic_type, direction_t packet_direction);
std::string print_channel_speed(std::string traffic_type, direction_t packet_direction);
void traffic_draw_ipv4_program();
void recalculate_speed();
std::string draw_table_ipv4(const attack_detection_direction_type_t& sort_direction,
                            const attack_detection_threshold_type_t& sorter_type);
std::string draw_table_ipv6(attack_detection_direction_type_t sort_direction, attack_detection_threshold_type_t sorter_type);
std::string draw_table_ipv4_hash(attack_detection_direction_type_t sort_direction, attack_detection_threshold_type_t sorter_type);
void print_screen_contents_into_file(std::string screen_data_stats_param, std::string file_path);
void zeroify_all_flow_counters();
void process_packet(simple_packet_t& current_packet);
void system_counters_speed_thread_handler();

void increment_outgoing_flow_counters(
                                      uint32_t client_ip,
                                      const simple_packet_t& packet,
                                      uint64_t sampled_number_of_packets,
                                      uint64_t sampled_number_of_bytes);

void increment_incoming_flow_counters(
                                      uint32_t client_ip,
                                      const simple_packet_t& packet,
                                      uint64_t sampled_number_of_packets,
                                      uint64_t sampled_number_of_bytes);

void traffic_draw_ipv6_program();
void check_traffic_buckets();
void process_filled_buckets_ipv6();
template <typename TemplatedKeyType>
bool should_remove_orphaned_bucket(const std::pair<TemplatedKeyType, packet_bucket_t>& pair);
void inaccurate_time_generator();
void collect_stats();
void start_prometheus_web_server();
std::string get_human_readable_attack_detection_direction(attack_detection_direction_type_t attack_detection_direction);

// API declaration
using fastmitigation::BanListReply;
using fastmitigation::BanListRequest;
using fastmitigation::Fastnetmon;
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

class FastnetmonApiServiceImpl final : public Fastnetmon::Service {
    Status GetBanlist(::grpc::ServerContext* context,
                      const ::fastmitigation::BanListRequest* request,
                      ::grpc::ServerWriter<::fastmitigation::BanListReply>* writer) override;

    Status ExecuteBan(ServerContext* context, const fastmitigation::ExecuteBanRequest* request, fastmitigation::ExecuteBanReply* reply) override;
    Status ExecuteUnBan(ServerContext* context,
                        const fastmitigation::ExecuteBanRequest* request,
                        fastmitigation::ExecuteBanReply* reply) override;
};
