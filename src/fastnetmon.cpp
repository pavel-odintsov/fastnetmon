/* Author: pavel.odintsov@gmail.com */
/* License: GPLv2 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <new> 
#include <signal.h>
#include <time.h>
#include <math.h>

#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include "libpatricia/patricia.h"
#include "fastnetmon_types.h"
#include "fastnetmon_packet_parser.h"
#include "fast_library.h"
#include "packet_storage.h"
#include "bgp_flow_spec.h"

// Here we store variables which differs for different paltforms
#include "fast_platform.h"

#ifdef ENABLE_DPI
#include "fast_dpi.h"
#endif

#ifdef FASTNETMON_API
#include <grpc++/grpc++.h>
#include "fastnetmon.grpc.pb.h"
#endif

// Plugins
#include "sflow_plugin/sflow_collector.h"
#include "netflow_plugin/netflow_collector.h"
#include "pcap_plugin/pcap_collector.h"

#ifdef NETMAP_PLUGIN
#include "netmap_plugin/netmap_collector.h"
#endif

#ifdef PF_RING
#include "pfring_plugin/pfring_collector.h"
#endif

#ifdef SNABB_SWITCH
#include "snabbswitch_plugin/snabbswitch_collector.h"
#endif

#ifdef FASTNETMON_ENABLE_AFPACKET
#include "afpacket_plugin/afpacket_collector.h"
#endif

#ifdef PF_RING
#include "actions/pfring_hardware_filter_action.h"
#endif

#ifdef ENABLE_GOBGP
#include "actions/gobgp_action.h"
#endif

// Yes, maybe it's not an good idea but with this we can guarantee working code in example plugin
#include "example_plugin/example_collector.h"

#include <algorithm>
#include <iostream>
#include <map>
#include <fstream>

#include <vector>
#include <utility>
#include <sstream>

#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/regex.hpp>

#include <boost/program_options.hpp>

// log4cpp logging facility
#include "log4cpp/RemoteSyslogAppender.hh"
#include "log4cpp/SyslogAppender.hh"
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"


// Boost libs
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>

#ifdef GEOIP
#include "GeoIP.h"
#endif

#ifdef REDIS
#include <hiredis/hiredis.h>
#endif

#ifdef MONGO
#include <bson.h>
#include <mongoc.h>
#endif

// #define IPV6_HASH_COUNTERS

#ifdef IPV6_HASH_COUNTERS
#include "concurrentqueue.h"
#endif

#ifdef FASTNETMON_API
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using fastmitigation::BanListRequest;
using fastmitigation::BanListReply;
using fastmitigation::Fastnetmon;

std::unique_ptr<Server> api_server;
bool enable_api = false;
#endif

time_t last_call_of_traffic_recalculation;

std::string cli_stats_file_path = "/tmp/fastnetmon.dat";

unsigned int stats_thread_sleep_time = 3600;
unsigned int stats_thread_initial_call_delay = 30;

unsigned int recalculate_speed_timeout = 1;

// Send or not any details about attack for ban script call over stdin
bool notify_script_pass_details = true;

bool pfring_hardware_filters_enabled = false;

bool notify_script_enabled = true; 

// We could collect attack dumps in pcap format
bool collect_attack_pcap_dumps = false;

// We could process this dumps with DPI
bool process_pcap_attack_dumps_with_dpi = false;

bool unban_only_if_attack_finished = true;

logging_configuration_t logging_configuration;

// Variable with all data from main screen
std::string screen_data_stats = "";

// Global map with parsed config file
typedef std::map<std::string, std::string> configuration_map_t;
configuration_map_t configuration_map;

// Every X seconds we will run ban list cleaner thread
// If customer uses ban_time smaller than this value we will use ban_time/2 as unban_iteration_sleep_time
int unban_iteration_sleep_time = 60;

bool unban_enabled = true;

#ifdef ENABLE_DPI
struct ndpi_detection_module_struct* my_ndpi_struct = NULL;

u_int32_t ndpi_size_flow_struct = 0;
u_int32_t ndpi_size_id_struct = 0;
#endif

#ifdef ENABLE_GOBGP
bool gobgp_enabled = false;
#endif

#ifdef MONGO
std::string mongodb_host = "localhost";
unsigned int mongodb_port = 27017;
bool mongodb_enabled = false;

std::string mongodb_database_name = "fastnetmon";
#endif

/* Configuration block, we must move it to configuration file  */
#ifdef REDIS
unsigned int redis_port = 6379;
std::string redis_host = "127.0.0.1";

// redis key prefix
std::string redis_prefix = "";

// because it's additional and very specific feature we should disable it by default
bool redis_enabled = false;
#endif

bool monitor_local_ip_addresses = true;

// This flag could enable print of ban actions and thresholds on the client's screen 
bool print_configuration_params_on_the_screen = false;

// Trigger for enable or disable traffic counting for whole subnets
bool enable_subnet_counters = false;

// We will announce whole subnet instead single IP with BGP if this flag enabled
bool exabgp_announce_whole_subnet = false;

// We will announce only /32 host
bool exabgp_announce_host = false;

// With this flag we will announce more specfic then whole block Flow Spec announces
bool exabgp_flow_spec_announces = false;

ban_settings_t global_ban_settings;

void init_global_ban_settings() {
    // ban Configuration params
    global_ban_settings.enable_ban_for_pps = false;
    global_ban_settings.enable_ban_for_bandwidth = false;
    global_ban_settings.enable_ban_for_flows_per_second = false;

    // We must ban IP if it exceeed this limit in PPS
    global_ban_settings.ban_threshold_pps = 20000;

    // We must ban IP of it exceed this limit for number of flows in any direction
    global_ban_settings.ban_threshold_flows = 3500;

    // We must ban client if it exceed 1GBps
    global_ban_settings.ban_threshold_mbps = 1000;

    // Disable per protocol thresholds too
    global_ban_settings.enable_ban_for_tcp_pps = false;
    global_ban_settings.enable_ban_for_tcp_bandwidth = false;

    global_ban_settings.enable_ban_for_udp_pps = false;
    global_ban_settings.enable_ban_for_udp_bandwidth = false;

    global_ban_settings.enable_ban_for_icmp_pps = false;
    global_ban_settings.enable_ban_for_icmp_bandwidth = false;

    // Ban enable/disable flag
    global_ban_settings.enable_ban = true;
}

bool enable_conection_tracking = true;

bool enable_snabbswitch_collection = false;
bool enable_afpacket_collection = false;
bool enable_data_collection_from_mirror = true;
bool enable_netmap_collection = false;
bool enable_sflow_collection = false;
bool enable_netflow_collection = false;
bool enable_pcap_collection = false;

// Time consumed by reaclculation for all IPs
struct timeval speed_calculation_time;

// Time consumed by drawing stats for all IPs
struct timeval drawing_thread_execution_time;

// Global thread group for packet capture threads
boost::thread_group packet_capture_plugin_thread_group;

// Global thread group for service processes (speed recalculation,
// screen updater and ban list cleaner)
boost::thread_group service_thread_group;

// Total number of hosts in our networks
// We need this as global variable because it's very important value for configuring data structures
unsigned int total_number_of_hosts_in_our_networks = 0;

#ifdef GEOIP
GeoIP* geo_ip = NULL;
#endif

// IPv4 lookup trees
patricia_tree_t* lookup_tree_ipv4, *whitelist_tree_ipv4;

// IPv6 lookup trees
patricia_tree_t* lookup_tree_ipv6, *whitelist_tree_ipv6;

bool DEBUG = 0;

// flag about dumping all packets to log
bool DEBUG_DUMP_ALL_PACKETS = false;

// dump "other" packets
bool DEBUG_DUMP_OTHER_PACKETS = false;

// Period for update screen for console version of tool
unsigned int check_period = 3;

// Standard ban time in seconds for all attacks but you can tune this value
int global_ban_time = 1800;

// We calc average pps/bps for this time
double average_calculation_amount = 15;

// We calc average pps/bps for subnets with this time, we use longer value for calculation average network traffic
double average_calculation_amount_for_subnets = 30;

// Show average or absolute value of speed
bool print_average_traffic_counts = true;

// Key used for sorting clients in output.  Allowed sort params: packets/bytes/flows
std::string sort_parameter = "packets";

// Number of lines in program output
unsigned int max_ips_in_list = 7;

// Number of lines for sending ben attack details to email
unsigned int ban_details_records_count = 500;

// We haven't option for configure it with configuration file
unsigned int number_of_packets_for_pcap_attack_dump = 500;

// log file
log4cpp::Category& logger = log4cpp::Category::getRoot();

// We storae all active BGP Flow Spec announces here
typedef std::map<std::string, uint32_t> active_flow_spec_announces_t;
active_flow_spec_announces_t active_flow_spec_announces;

/* Configuration block ends */

// We count total number of incoming/outgoing/internal and other traffic type packets/bytes
// And initilize by 0 all fields
total_counter_element total_counters[4];
total_counter_element total_speed_counters[4];
total_counter_element total_speed_average_counters[4];

// Total amount of non parsed packets
uint64_t total_unparsed_packets = 0;
uint64_t total_unparsed_packets_speed = 0;

// Total amount of IPv6 packets
uint64_t total_ipv6_packets = 0;

// IPv6 traffic which belongs to our own networks
uint64_t our_ipv6_packets = 0;

uint64_t incoming_total_flows_speed = 0;
uint64_t outgoing_total_flows_speed = 0;

map_of_vector_counters SubnetVectorMap;

// Here we store taffic per subnet
map_for_subnet_counters PerSubnetCountersMap;

// Here we store traffic speed per subnet
map_for_subnet_counters PerSubnetSpeedMap;

// Here we store average speed per subnet
map_for_subnet_counters PerSubnetAverageSpeedMap;

// Flow tracking structures
map_of_vector_counters_for_flow SubnetVectorMapFlow;

/* End of our data structs */
boost::mutex ban_list_details_mutex;
boost::mutex ban_list_mutex;
boost::mutex flow_counter;

// map for flows
std::map<uint64_t, int> FlowCounter;

// Struct for string speed per IP
map_of_vector_counters SubnetVectorMapSpeed; 

// Struct for storing average speed per IP for specified interval
map_of_vector_counters SubnetVectorMapSpeedAverage;

#ifdef GEOIP
map_for_counters GeoIpCounter;
#endif

// In ddos info we store attack power and direction
std::map<uint32_t, banlist_item> ban_list;
std::map<uint32_t, std::vector<simple_packet> > ban_list_details;

host_group_map_t host_groups;

// Here we store assignment from subnet to certain host group for fast lookup
subnet_to_host_group_map_t subnet_to_host_groups;

host_group_ban_settings_map_t host_group_ban_settings_map;

std::vector<subnet_t> our_networks;
std::vector<subnet_t> whitelist_networks;

// ExaBGP support flag
bool exabgp_enabled = false;
std::string exabgp_community = "";

// We could use separate communities for subnet and host announces
std::string exabgp_community_subnet = "";
std::string exabgp_community_host = "";


std::string exabgp_command_pipe = "/var/run/exabgp.cmd";
std::string exabgp_next_hop = "";

// Graphite monitoring
bool graphite_enabled = false;
std::string graphite_host = "127.0.0.1";
unsigned short int graphite_port = 2003;

// Default graphite namespace
std::string graphite_prefix = "fastnetmon";

bool process_incoming_traffic = true;
bool process_outgoing_traffic = true;

// Prototypes
#ifdef ENABLE_DPI
void init_current_instance_of_ndpi();
#endif

inline void build_average_speed_counters_from_speed_counters( map_element* current_average_speed_element, map_element& new_speed_element, double exp_value, double exp_power);
inline void build_speed_counters_from_packet_counters(map_element& new_speed_element, map_element* vector_itr, double speed_calc_period);
void execute_ip_ban(uint32_t client_ip, map_element average_speed_element, std::string flow_attack_details, subnet_t customer_subnet);
std::string get_attack_description_in_json(uint32_t client_ip, attack_details& current_attack);
logging_configuration_t read_logging_settings(configuration_map_t configuration_map);
std::string get_amplification_attack_type(amplification_attack_type_t attack_type);
std::string generate_flow_spec_for_amplification_attack(amplification_attack_type_t amplification_attack_type, std::string destination_ip);
bool exabgp_flow_spec_ban_manage(std::string action, std::string flow_spec_rule_as_text);
void call_attack_details_handlers(uint32_t client_ip, attack_details& current_attack, std::string attack_fingerprint);
void call_ban_handlers(uint32_t client_ip, attack_details& current_attack, std::string flow_attack_details);
void call_unban_handlers(uint32_t client_ip, attack_details& current_attack);
ban_settings_t read_ban_settings(configuration_map_t configuration_map, std::string host_group_name = "");
void exabgp_prefix_ban_manage(std::string action, std::string prefix_as_string_with_mask, std::string exabgp_next_hop,
    std::string exabgp_community);
std::string print_subnet_load();
bool we_should_ban_this_ip(map_element* current_average_speed_element, ban_settings_t current_ban_settings);
unsigned int get_max_used_protocol(uint64_t tcp, uint64_t udp, uint64_t icmp);
void print_attack_details_to_file(std::string details, std::string client_ip_as_string, attack_details current_attack);
std::string print_ban_thresholds(ban_settings_t current_ban_settings);
bool load_configuration_file();
std::string print_flow_tracking_for_ip(conntrack_main_struct& conntrack_element, std::string client_ip);
void convert_integer_to_conntrack_hash_struct(packed_session* packed_connection_data,
                                              packed_conntrack_hash* unpacked_data);
uint64_t convert_conntrack_hash_struct_to_integer(packed_conntrack_hash* struct_value);
void cleanup_ban_list();
std::string get_attack_description(uint32_t client_ip, attack_details& current_attack);
void send_attack_details(uint32_t client_ip, attack_details current_attack_details);
void free_up_all_resources();
std::string print_ddos_attack_details();
void recalculate_speed();
std::string print_channel_speed(std::string traffic_type, direction packet_direction);
void process_packet(simple_packet& current_packet);
void traffic_draw_program();
void interruption_signal_handler(int signal_number);

#ifdef FASTNETMON_API
void silent_logging_function(gpr_log_func_args *args) {
    // We do not want any logging here
}

// Logic and data behind the server's behavior.
class FastnetmonApiServiceImpl final : public Fastnetmon::Service {
    Status GetBanlist(::grpc::ServerContext* context, const ::fastmitigation::BanListRequest* request, ::grpc::ServerWriter< ::fastmitigation::BanListReply>* writer) override {
        logger << log4cpp::Priority::INFO << "API we asked for banlist";

        for (std::map<uint32_t, banlist_item>::iterator itr = ban_list.begin(); itr != ban_list.end(); ++itr) {
            std::string client_ip_as_string = convert_ip_as_uint_to_string(itr->first);

            BanListReply reply;
            reply.set_ip_address( client_ip_as_string + "/32" );
            writer->Write(reply);
        }       

        return Status::OK;
    }

    Status ExecuteBan(ServerContext* context, const fastmitigation::ExecuteBanRequest* request, fastmitigation::ExecuteBanReply* reply) override {
        logger << log4cpp::Priority::INFO << "API we asked for ban for IP: " << request->ip_address();

        if (!is_v4_host(request->ip_address())) {
            logger << log4cpp::Priority::ERROR << "IP bad format";
            return Status::CANCELLED;
        }    

        uint32_t client_ip = convert_ip_as_string_to_uint(request->ip_address());

        struct attack_details current_attack;
        ban_list_mutex.lock();
        ban_list[client_ip] = current_attack;
        ban_list_mutex.unlock();

        ban_list_details_mutex.lock();
        ban_list_details[client_ip] = std::vector<simple_packet>();
        ban_list_details_mutex.unlock();

        logger << log4cpp::Priority::INFO << "API call ban handlers manually";

        std::string flow_attack_details = "manually triggered attack";
        call_ban_handlers(client_ip, current_attack, flow_attack_details);

        return Status::OK;
    }

    Status ExecuteUnBan(ServerContext* context, const fastmitigation::ExecuteBanRequest* request, fastmitigation::ExecuteBanReply* reply) override {
        logger << log4cpp::Priority::INFO << "API: We asked for unban for IP: " << request->ip_address();

        if (!is_v4_host(request->ip_address())) {
            logger << log4cpp::Priority::ERROR << "IP bad format";
            return Status::CANCELLED;
        }

        uint32_t banned_ip = convert_ip_as_string_to_uint(request->ip_address());

        if (ban_list.count(banned_ip) == 0) {
            logger << log4cpp::Priority::ERROR << "API: Could not find IP in ban list";
            return Status::CANCELLED;
        }

        banlist_item ban_details = ban_list[banned_ip];

        logger << log4cpp::Priority::INFO << "API: call unban handlers";
        call_unban_handlers(banned_ip, ban_details);

        logger << log4cpp::Priority::INFO << "API: remove IP from ban list";

        ban_list_mutex.lock();
        ban_list.erase(banned_ip);
        ban_list_mutex.unlock();

        return Status::OK;
    }
};

// We could not define this variable in top of the file because we should define class before
FastnetmonApiServiceImpl api_service;

std::unique_ptr<Server> StartupApiServer() {
    std::string server_address("127.0.0.1:50052");
    ServerBuilder builder;
    // Listen on the given address without any authentication mechanism.
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    // Register "service" as the instance through which we'll communicate with
    // clients. In this case it corresponds to an *synchronous* service.
    builder.RegisterService(&api_service);

    // Finally assemble the server.
    std::unique_ptr<Server> current_api_server(builder.BuildAndStart());
    logger << log4cpp::Priority::INFO << "API server listening on " << server_address;     

    return current_api_server;
}

void RunApiServer() {
    api_server = StartupApiServer();

    // Wait for the server to shutdown. Note that some other thread must be
    // responsible for shutting down the server for this call to ever return.
    api_server->Wait();
    logger << log4cpp::Priority::INFO << "API server got shutdown signal";
}
#endif


/* Class for custom comparison fields by different fields */
template <typename T>
class TrafficComparatorClass {
    private:
    sort_type sort_field;
    direction sort_direction;

    public:
    TrafficComparatorClass(direction sort_direction, sort_type sort_field) {
        this->sort_field = sort_field;
        this->sort_direction = sort_direction;
    }

    bool operator()(T a, T b) {
        if (sort_field == FLOWS) {
            if (sort_direction == INCOMING) {
                return a.second.in_flows > b.second.in_flows;
            } else if (sort_direction == OUTGOING) {
                return a.second.out_flows > b.second.out_flows;
            } else {
                return false;
            }
        } else if (sort_field == PACKETS) {
            if (sort_direction == INCOMING) {
                return a.second.in_packets > b.second.in_packets;
            } else if (sort_direction == OUTGOING) {
                return a.second.out_packets > b.second.out_packets;
            } else {
                return false;
            }
        } else if (sort_field == BYTES) {
            if (sort_direction == INCOMING) {
                return a.second.in_bytes > b.second.in_bytes;
            } else if (sort_direction == OUTGOING) {
                return a.second.out_bytes > b.second.out_bytes;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
};

void sigpipe_handler_for_popen(int signo) {
    logger << log4cpp::Priority::ERROR << "Sorry but we experienced error with popen. "
           << "Please check your scripts. They should receive data on stdin! Optionally you could disable passing any details with configuration param: notify_script_pass_details = no";

    // Well, we do not need exit here because we have another options to notifying about atatck
    // exit(1);
}

// exec command and pass data to it stdin
bool exec_with_stdin_params(std::string cmd, std::string params) {
    FILE* pipe = popen(cmd.c_str(), "w");
    if (!pipe) {
        logger << log4cpp::Priority::ERROR << "Can't execute program " << cmd
               << " error code: " << errno << " error text: " << strerror(errno);
        return false;
    }

    int fputs_ret = fputs(params.c_str(), pipe);

    if (fputs_ret) {
        pclose(pipe);
        return true;
    } else {
        logger << log4cpp::Priority::ERROR << "Can't pass data to stdin of program " << cmd;
        pclose(pipe);
        return false;
    }
}

#ifdef GEOIP
bool geoip_init() {
    // load GeoIP ASN database to memory
    geo_ip = GeoIP_open("/root/fastnetmon/GeoIPASNum.dat", GEOIP_MEMORY_CACHE);

    if (geo_ip == NULL) {
        return false;
    } else {
        return true;
    }
}
#endif

#ifdef REDIS
redisContext* redis_init_connection() {
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    redisContext* redis_context = redisConnectWithTimeout(redis_host.c_str(), redis_port, timeout);
    if (redis_context->err) {
        logger << log4cpp::Priority::ERROR << "Redis connection error:" << redis_context->errstr;
        return NULL;
    }

    // We should check connection with ping because redis do not check connection
    redisReply* reply = (redisReply*)redisCommand(redis_context, "PING");
    if (reply) {
        freeReplyObject(reply);
    } else {
        return NULL;
    }

    return redis_context;
}
#endif

#ifdef MONGO
void store_data_in_mongo(std::string key_name, std::string attack_details_json) {
    mongoc_client_t *client;
    mongoc_collection_t *collection;
    mongoc_cursor_t *cursor;
    bson_error_t error;
    bson_oid_t oid;
    bson_t *doc;

    mongoc_init ();

    std::string collection_name = "attacks"; 
    std::string connection_string = "mongodb://" + mongodb_host + ":" + convert_int_to_string(mongodb_port) + "/"; 

    client = mongoc_client_new (connection_string.c_str());

    if (!client) {
        logger << log4cpp::Priority::ERROR << "Can't connect to MongoDB database";
        return;
    }
    
    bson_error_t bson_from_json_error;
    bson_t* bson_data = bson_new_from_json((const uint8_t *)attack_details_json.c_str(), attack_details_json.size(), &bson_from_json_error);
    if (!bson_data) {
        logger << log4cpp::Priority::ERROR << "Could not convert JSON to BSON";
        return;
    }    

    // logger << log4cpp::Priority::INFO << bson_as_json(bson_data, NULL);

    collection = mongoc_client_get_collection (client, mongodb_database_name.c_str(), collection_name.c_str());

    doc = bson_new ();
    bson_oid_init (&oid, NULL);
    BSON_APPEND_OID (doc, "_id", &oid);
    bson_append_document(doc,  key_name.c_str(), key_name.size(), bson_data);

    // logger << log4cpp::Priority::INFO << bson_as_json(doc, NULL);

    if (!mongoc_collection_insert (collection, MONGOC_INSERT_NONE, doc, NULL, &error)) {
        logger << log4cpp::Priority::ERROR << "Could not store data to MongoDB: " << error.message;
    }

    // TODO: destroy bson_data too!

    bson_destroy (doc);
    mongoc_collection_destroy (collection);
    mongoc_client_destroy (client);

}
#endif

#ifdef REDIS
void store_data_in_redis(std::string key_name, std::string attack_details) {
    redisReply* reply = NULL;
    redisContext* redis_context = redis_init_connection();

    if (!redis_context) {
        logger << log4cpp::Priority::ERROR << "Could not initiate connection to Redis";
        return;
    }

    reply = (redisReply*)redisCommand(redis_context, "SET %s %s", key_name.c_str(), attack_details.c_str());

    // If we store data correctly ...
    if (!reply) {
        logger << log4cpp::Priority::ERROR << "Can't increment traffic in redis error_code: " << redis_context->err
            << " error_string: " << redis_context->errstr;

        // Handle redis server restart corectly
        if (redis_context->err == 1 or redis_context->err == 3) {
            // Connection refused
            logger << log4cpp::Priority::ERROR << "Unfortunately we can't store data in Redis because server reject connection";
        }
    } else {
        freeReplyObject(reply);
    }

    redisFree(redis_context);
}
#endif

std::string draw_table(direction data_direction, bool do_redis_update, sort_type sort_item) {
    std::vector<pair_of_map_elements> vector_for_sort;

    std::stringstream output_buffer;

    // Preallocate memory for sort vector
    // We use total networks size for this vector
    vector_for_sort.reserve(total_number_of_hosts_in_our_networks);

    // Switch to Average speed there!!!
    map_of_vector_counters* current_speed_map = NULL;

    if (print_average_traffic_counts) {
        current_speed_map = &SubnetVectorMapSpeedAverage;
    } else {
        current_speed_map = &SubnetVectorMapSpeed;
    }

    map_element zero_map_element;
    memset(&zero_map_element, 0, sizeof(zero_map_element));

    unsigned int count_of_zero_speed_packets = 0;
    for (map_of_vector_counters::iterator itr = current_speed_map->begin(); itr != current_speed_map->end(); ++itr) {
        for (vector_of_counters::iterator vector_itr = itr->second.begin(); vector_itr != itr->second.end(); ++vector_itr) {
            int current_index = vector_itr - itr->second.begin();

            // convert to host order for math operations
            uint32_t subnet_ip = ntohl(itr->first.first);
            uint32_t client_ip_in_host_bytes_order = subnet_ip + current_index;

            // covnert to our standard network byte order
            uint32_t client_ip = htonl(client_ip_in_host_bytes_order);
            
            // Do not add zero speed packets to sort list
            if (memcmp((void*)&zero_map_element, &*vector_itr, sizeof(map_element)) != 0) {
                vector_for_sort.push_back(std::make_pair(client_ip, *vector_itr));
            } else {
                count_of_zero_speed_packets++;
            }
        }
    }
   
    // Sort only first X elements in this vector
    unsigned int shift_for_sort = max_ips_in_list;

    if (data_direction == INCOMING or data_direction == OUTGOING) {
        // Because in another case we will got segmentation fault
        unsigned int vector_size = vector_for_sort.size();

        if (vector_size < shift_for_sort) {
            shift_for_sort = vector_size;
        }

        std::partial_sort(vector_for_sort.begin(), vector_for_sort.begin() + shift_for_sort, vector_for_sort.end(),
                  TrafficComparatorClass<pair_of_map_elements>(data_direction, sort_item));
    } else {
        logger << log4cpp::Priority::ERROR << "Unexpected bahaviour on sort function";
        return "Internal error";
    }

    unsigned int element_number = 0;
    
    // In this loop we print only top X talkers in our subnet to screen buffer
    for (std::vector<pair_of_map_elements>::iterator ii = vector_for_sort.begin(); ii != vector_for_sort.end(); ++ii) {
        // Print first max_ips_in_list elements in list, we will show top X "huge" channel loaders
        if (element_number >= max_ips_in_list) {
            break;
        } 

        uint32_t client_ip = (*ii).first;
        std::string client_ip_as_string = convert_ip_as_uint_to_string((*ii).first);

        uint64_t pps = 0;
        uint64_t bps = 0;
        uint64_t flows = 0;

        uint64_t pps_average = 0;
        uint64_t bps_average = 0;
        uint64_t flows_average = 0;

        // Here we could have average or instantaneous speed
        map_element* current_speed_element = &ii->second;

        // Create polymorphic pps, byte and flow counters
        if (data_direction == INCOMING) {
            pps = current_speed_element->in_packets;
            bps = current_speed_element->in_bytes;
            flows = current_speed_element->in_flows;
        } else if (data_direction == OUTGOING) {
            pps = current_speed_element->out_packets;
            bps = current_speed_element->out_bytes;
            flows = current_speed_element->out_flows;
        }

        uint64_t mbps = convert_speed_to_mbps(bps);
        uint64_t mbps_average = convert_speed_to_mbps(bps_average);

        std::string is_banned = ban_list.count(client_ip) > 0 ? " *banned* " : "";

        // We use setw for alignment
        output_buffer << client_ip_as_string << "\t\t";

        output_buffer << std::setw(6) << pps << " pps ";
        output_buffer << std::setw(6) << mbps << " mbps ";
        output_buffer << std::setw(6) << flows << " flows ";
        
        output_buffer << is_banned << std::endl;

        element_number++;
    }

    graphite_data_t graphite_data;

    // TODO: add graphite operations time to the config file
    if (graphite_enabled) {
        for (std::vector<pair_of_map_elements>::iterator ii = vector_for_sort.begin(); ii != vector_for_sort.end(); ++ii) {
            uint32_t client_ip = (*ii).first;
            std::string client_ip_as_string = convert_ip_as_uint_to_string((*ii).first);

            uint64_t pps = 0;
            uint64_t bps = 0;
            uint64_t flows = 0;

            // Here we could have average or instantaneous speed
            map_element* current_speed_element = &ii->second;

            // Create polymorphic pps, byte and flow counters
            if (data_direction == INCOMING) {
                pps = current_speed_element->in_packets;
                bps = current_speed_element->in_bytes;
                flows = current_speed_element->in_flows;
            } else if (data_direction == OUTGOING) {
                pps = current_speed_element->out_packets;
                bps = current_speed_element->out_bytes;
                flows = current_speed_element->out_flows;
            }

            std::string direction_as_string;

            if (data_direction == INCOMING) {
                direction_as_string = "incoming";
            } else if (data_direction == OUTGOING) {
                direction_as_string = "outgoing";
            }

            std::string ip_as_string_with_dash_delimiters = client_ip_as_string;
            // Replace dots by dashes
            std::replace(ip_as_string_with_dash_delimiters.begin(),
                ip_as_string_with_dash_delimiters.end(), '.', '_');

            std::string graphite_current_prefix = graphite_prefix + ".hosts." + ip_as_string_with_dash_delimiters + "." + direction_as_string;

            if (print_average_traffic_counts) {
                graphite_current_prefix = graphite_current_prefix + ".average";
            }

            // We do not store zero data to Graphite
            if (pps != 0) {
                graphite_data[ graphite_current_prefix + ".pps"   ] = pps;
            }

            if (bps != 0) {
                graphite_data[ graphite_current_prefix + ".bps"  ]  = bps * 8;
            }
    
            if (flows != 0) {
                graphite_data[ graphite_current_prefix + ".flows" ] = flows;
            }
        }
    }

    // TODO: we should switch to piclke format instead text
    // TODO: we should check packet size for Graphite
    // logger << log4cpp::Priority::INFO << "We will write " << graphite_data.size() << " records to Graphite"; 

    if (graphite_enabled) {
        bool graphite_put_result = store_data_to_graphite(graphite_port, graphite_host, graphite_data);

        if (!graphite_put_result) {
            logger << log4cpp::Priority::ERROR << "Can't store data to Graphite";
        }
    }

    return output_buffer.str();
}

// TODO: move to lirbary
// read whole file to vector
std::vector<std::string> read_file_to_vector(std::string file_name) {
    std::vector<std::string> data;
    std::string line;

    std::ifstream reading_file;

    reading_file.open(file_name.c_str(), std::ifstream::in);
    if (reading_file.is_open()) {
        while (getline(reading_file, line)) {
            boost::algorithm::trim(line);
            data.push_back(line);
        }
    } else {
        logger << log4cpp::Priority::ERROR << "Can't open file: " << file_name;
    }

    return data;
}

void parse_hostgroups(std::string name, std::string value) {
    // We are creating new host group of subnets
    if (name != "hostgroup") {
        return;
    }

    std::vector<std::string> splitted_new_host_group;
    // We have new host groups in form:
    // hostgroup = new_host_group_name:11.22.33.44/32,....
    split(splitted_new_host_group, value, boost::is_any_of(":"), boost::token_compress_on);

    if (splitted_new_host_group.size() != 2) {
        logger << log4cpp::Priority::ERROR << "We can't parse new host group";
        return;
    }

    boost::algorithm::trim(splitted_new_host_group[0]);
    boost::algorithm::trim(splitted_new_host_group[1]);

    std::string host_group_name = splitted_new_host_group[0];

    if (host_groups.count(host_group_name) > 0) {
        logger << log4cpp::Priority::WARN << "We already have this host group (" << host_group_name << "). Please check!"; 
        return;
    }

    // Split networks
    std::vector<std::string> hostgroup_subnets = split_strings_to_vector_by_comma(splitted_new_host_group[1]);
    for (std::vector<std::string>::iterator itr = hostgroup_subnets.begin(); itr != hostgroup_subnets.end(); ++itr) {
        subnet_t subnet = convert_subnet_from_string_to_binary_with_cidr_format(*itr);
       
        host_groups[ host_group_name ].push_back( subnet ); 
        
        logger << log4cpp::Priority::WARN << "We add subnet " << convert_subnet_to_string( subnet )
            << " to host group " << host_group_name;

        // And add to subnet to host group lookup hash
        if (subnet_to_host_groups.count(subnet) > 0) {
            // Huston, we have problem! Subnet to host group mapping should map single subnet to single group! 
            logger << log4cpp::Priority::WARN << "Seems you have specified single subnet " << *itr
                << " to multiple host groups, please fix it, it's prohibited";
        } else {
            subnet_to_host_groups[ subnet ] = host_group_name;
        } 
    }

    logger << log4cpp::Priority::INFO << "We have created host group " << host_group_name << " with "
        << host_groups[ host_group_name ].size() << " subnets";
}

// Load configuration
bool load_configuration_file() {
    std::ifstream config_file(global_config_path.c_str());
    std::string line;

    if (!config_file.is_open()) {
        logger << log4cpp::Priority::ERROR << "Can't open config file";
        return false;
    }

    while (getline(config_file, line)) {
        std::vector<std::string> parsed_config;
        boost::algorithm::trim(line);

        if (line.find("#") == 0 or line.empty()) {
            // Ignore comments line
            continue;
        }

        boost::split(parsed_config, line, boost::is_any_of("="), boost::token_compress_on);

        if (parsed_config.size() == 2) {
            boost::algorithm::trim(parsed_config[0]);
            boost::algorithm::trim(parsed_config[1]);
            
            configuration_map[parsed_config[0]] = parsed_config[1];
            
            // Well, we parse host groups here
            parse_hostgroups(parsed_config[0], parsed_config[1]);
        } else {
            logger << log4cpp::Priority::ERROR << "Can't parse config line: '" << line << "'";
        }
    }

    if (configuration_map.count("enable_connection_tracking")) {
        if (configuration_map["enable_connection_tracking"] == "on") {
            enable_conection_tracking = true;
        } else {
            enable_conection_tracking = false;
        }
    }

    if (configuration_map.count("ban_time") != 0) {
        global_ban_time = convert_string_to_integer(configuration_map["ban_time"]);

        // Completely disable unban option
        if (global_ban_time == 0) {
            unban_enabled = false;
        }
    }

    if (configuration_map.count("pid_path") != 0) {
        pid_path = configuration_map["pid_path"];
    }

    if (configuration_map.count("cli_stats_file_path") != 0) {
        cli_stats_file_path = configuration_map["cli_stats_file_path"];
    }

    if (configuration_map.count("unban_only_if_attack_finished") != 0) {
        if (configuration_map["unban_only_if_attack_finished"] == "on") {
            unban_only_if_attack_finished = true;
        } else { 
            unban_only_if_attack_finished = false;
        }
    }

    if(configuration_map.count("graphite_prefix") != 0) {
        graphite_prefix = configuration_map["graphite_prefix"];
    }

    if (configuration_map.count("average_calculation_time") != 0) {
        average_calculation_amount =
        convert_string_to_integer(configuration_map["average_calculation_time"]);
    }

    if (configuration_map.count("average_calculation_time_for_subnets") != 0) {
        average_calculation_amount_for_subnets =
        convert_string_to_integer(configuration_map["average_calculation_time_for_subnets"]);
    }

    if (configuration_map.count("monitor_local_ip_addresses") != 0) {
        monitor_local_ip_addresses = configuration_map["monitor_local_ip_addresses"] == "on" ? true : false;
    }

#ifdef FASTNETMON_API
    if (configuration_map.count("enable_api") != 0) {
        enable_api = configuration_map["enable_api"] == "on";
    }
#endif

#ifdef ENABLE_GOBGP
    // GoBGP configuration
    if (configuration_map.count("gobgp") != 0) {
        gobgp_enabled = configuration_map["gobgp"] == "on";
    }
#endif

    // ExaBGP configuration

    if (configuration_map.count("exabgp") != 0) {
        if (configuration_map["exabgp"] == "on") {
            exabgp_enabled = true;
        } else {
            exabgp_enabled = false;
        }
    }

    if (exabgp_enabled) {
        // TODO: add community format validation
        if (configuration_map.count("exabgp_community")) {
            exabgp_community = configuration_map["exabgp_community"];
        }

        if (configuration_map.count("exabgp_community_subnet")) {
            exabgp_community_subnet = configuration_map["exabgp_community_subnet"];
        } else {
            exabgp_community_subnet = exabgp_community;
        }
        
        if (configuration_map.count("exabgp_community_host")) {
            exabgp_community_host = configuration_map["exabgp_community_host"];
        } else {
            exabgp_community_host = exabgp_community;
        }

        if (exabgp_enabled && exabgp_announce_whole_subnet && exabgp_community_subnet.empty()) {
            logger << log4cpp::Priority::ERROR
                << "You enabled exabgp for subnet but not specified community, we disable exabgp support";

            exabgp_enabled = false;
        }

        if (exabgp_enabled && exabgp_announce_host && exabgp_community_host.empty()) {
            logger << log4cpp::Priority::ERROR
                << "You enabled exabgp for host but not specified community, we disable exabgp support";

            exabgp_enabled = false;
        } 
    }

    if (exabgp_enabled) {
        exabgp_command_pipe = configuration_map["exabgp_command_pipe"];

        if (exabgp_command_pipe.empty()) {
            logger << log4cpp::Priority::ERROR << "You enabled exabgp but not specified "
                                                  "exabgp_command_pipe, so we disable exabgp "
                                                  "support";

            exabgp_enabled = false;
        }
    }

    if (exabgp_enabled) {
        exabgp_next_hop = configuration_map["exabgp_next_hop"];

        if (exabgp_next_hop.empty()) {
            logger
            << log4cpp::Priority::ERROR
            << "You enabled exabgp but not specified exabgp_next_hop, so we disable exabgp support";

            exabgp_enabled = false;
        }

        if (configuration_map.count("exabgp_flow_spec_announces") != 0) {
            exabgp_flow_spec_announces = configuration_map["exabgp_flow_spec_announces"] == "on";
        }

        if (exabgp_enabled) {
            logger << log4cpp::Priority::INFO << "ExaBGP support initialized correctly";
        }
    }

    if (configuration_map.count("sflow") != 0) {
        if (configuration_map["sflow"] == "on") {
            enable_sflow_collection = true;
        } else {
            enable_sflow_collection = false;
        }
    }

    if (configuration_map.count("pfring_hardware_filters_enabled") != 0) {
        pfring_hardware_filters_enabled = configuration_map["pfring_hardware_filters_enabled"] == "on";
    }

    if (configuration_map.count("netflow") != 0) {
        if (configuration_map["netflow"] == "on") {
            enable_netflow_collection = true;
        } else {
            enable_netflow_collection = false;
        }
    }

    if (configuration_map.count("exabgp_announce_whole_subnet") != 0) {
        exabgp_announce_whole_subnet = configuration_map["exabgp_announce_whole_subnet"] == "on" ? true : false;
    }

    if (configuration_map.count("exabgp_announce_host") != 0) {
        exabgp_announce_host = configuration_map["exabgp_announce_host"] == "on" ? true : false;
    }

    if (configuration_map.count("enable_subnet_counters") != 0) {
        enable_subnet_counters = configuration_map["enable_subnet_counters"] == "on" ? true : false;
    }

    // Graphite
    if (configuration_map.count("graphite") != 0) {
        graphite_enabled = configuration_map["graphite"] == "on" ? true : false;
    }

    if (configuration_map.count("graphite_host") != 0) {
        graphite_host = configuration_map["graphite_host"];
    }

    if (configuration_map.count("graphite_port") != 0) {
        graphite_port = convert_string_to_integer(configuration_map["graphite_port"]);
    }

    if (configuration_map.count("graphite_number_of_ips") != 0) {
        logger << log4cpp::Priority::ERROR << "Sorry, you have used deprecated function graphite_number_of_ips";  
    }

    if (configuration_map.count("process_incoming_traffic") != 0) {
        process_incoming_traffic = configuration_map["process_incoming_traffic"] == "on" ? true : false;
    }

    if (configuration_map.count("process_outgoing_traffic") != 0) {
        process_outgoing_traffic = configuration_map["process_outgoing_traffic"] == "on" ? true : false;
    }

    if (configuration_map.count("mirror") != 0) {
        if (configuration_map["mirror"] == "on") {
            enable_data_collection_from_mirror = true;
        } else {
            enable_data_collection_from_mirror = false;
        }
    }

    if (configuration_map.count("mirror_netmap") != 0) {
        if (configuration_map["mirror_netmap"] == "on") {
            enable_netmap_collection = true;
        } else {
            enable_netmap_collection = false;
        }
    }

    if (configuration_map.count("mirror_snabbswitch") != 0) {
        enable_snabbswitch_collection = configuration_map["mirror_snabbswitch"] == "on";
    } 

    if (configuration_map.count("mirror_afpacket") != 0) {
        enable_afpacket_collection = configuration_map["mirror_afpacket"] == "on";
    }

    if (enable_netmap_collection && enable_data_collection_from_mirror) {
        logger << log4cpp::Priority::ERROR << "You have enabled pfring and netmap data collection "
                                              "from mirror which strictly prohibited, please "
                                              "select one";
        exit(1);
    }

    if (configuration_map.count("pcap") != 0) {
        if (configuration_map["pcap"] == "on") {
            enable_pcap_collection = true;
        } else {
            enable_pcap_collection = false;
        }
    }

    // Read global ban configuration
    global_ban_settings = read_ban_settings(configuration_map, "");

    logging_configuration = read_logging_settings(configuration_map);

    // logger << log4cpp::Priority::INFO << "We read global ban settings: " << print_ban_thresholds(global_ban_settings);

    // Read host group ban settings
    for (host_group_map_t::iterator hostgroup_itr = host_groups.begin(); hostgroup_itr != host_groups.end(); ++hostgroup_itr) {
        std::string host_group_name = hostgroup_itr->first;

        logger << log4cpp::Priority::INFO << "We will read ban settings for " << host_group_name;

        host_group_ban_settings_map[ host_group_name ] =  read_ban_settings(configuration_map, host_group_name);

        //logger << log4cpp::Priority::INFO << "We read " << host_group_name << " ban settings "
        //    << print_ban_thresholds(host_group_ban_settings_map[ host_group_name ]);
    }

    if (configuration_map.count("white_list_path") != 0) {
        white_list_path = configuration_map["white_list_path"];
    }

    if (configuration_map.count("networks_list_path") != 0) {
        networks_list_path = configuration_map["networks_list_path"];
    }

#ifdef REDIS
    if (configuration_map.count("redis_port") != 0) {
        redis_port = convert_string_to_integer(configuration_map["redis_port"]);
    }

    if (configuration_map.count("redis_host") != 0) {
        redis_host = configuration_map["redis_host"];
    }

    if (configuration_map.count("redis_prefix") != 0) {
        redis_prefix = configuration_map["redis_prefix"];
    }

    if (configuration_map.count("redis_enabled") != 0) {
        // We use yes and on because it's stupid typo :(
        if (configuration_map["redis_enabled"] == "on" or configuration_map["redis_enabled"] == "yes") {
            redis_enabled = true;
        } else {
            redis_enabled = false;
        }
    }
#endif

#ifdef MONGO
    if (configuration_map.count("mongodb_enabled") != 0) {
        if (configuration_map["mongodb_enabled"] == "on") {
            mongodb_enabled = true;
        }
    }

    if (configuration_map.count("mongodb_host") != 0) {
        mongodb_host = configuration_map["mongodb_host"];
    }

    if (configuration_map.count("mongodb_port") != 0) {
        mongodb_port = convert_string_to_integer(configuration_map["mongodb_port"]);
    }

    if (configuration_map.count("mongodb_database_name") != 0) {
        mongodb_database_name = configuration_map["mongodb_database_name"];
    }
#endif

    if (configuration_map.count("ban_details_records_count") != 0) {
        ban_details_records_count =
        convert_string_to_integer(configuration_map["ban_details_records_count"]);
    }

    if (configuration_map.count("check_period") != 0) {
        check_period = convert_string_to_integer(configuration_map["check_period"]);
    }

    if (configuration_map.count("sort_parameter") != 0) {
        sort_parameter = configuration_map["sort_parameter"];
    }

    if (configuration_map.count("max_ips_in_list") != 0) {
        max_ips_in_list = convert_string_to_integer(configuration_map["max_ips_in_list"]);
    }

    if (configuration_map.count("notify_script_path") != 0) {
        notify_script_path = configuration_map["notify_script_path"];
    }

    if (configuration_map.count("notify_script_pass_details") != 0) {
        notify_script_pass_details = configuration_map["notify_script_pass_details"] == "on" ? true : false;
    }

    if (file_exists(notify_script_path)) {
        notify_script_enabled = true;
    } else {
        logger << log4cpp::Priority::ERROR << "We can't find notify script " << notify_script_path;
        notify_script_enabled = false;
    }

    if (configuration_map.count("collect_attack_pcap_dumps") != 0) {
        collect_attack_pcap_dumps = configuration_map["collect_attack_pcap_dumps"] == "on" ? true : false;
    }

    if (configuration_map.count("process_pcap_attack_dumps_with_dpi") != 0) {
        if (collect_attack_pcap_dumps) {
            process_pcap_attack_dumps_with_dpi = configuration_map["process_pcap_attack_dumps_with_dpi"] == "on" ? true : false;
        }
    } 

    return true;
}

/* Enable core dumps for simplify debug tasks */
void enable_core_dumps() {
    struct rlimit rlim;

    int result = getrlimit(RLIMIT_CORE, &rlim);

    if (result) {
        logger << log4cpp::Priority::ERROR << "Can't get current rlimit for RLIMIT_CORE";
        return;
    } else {
        rlim.rlim_cur = rlim.rlim_max;
        setrlimit(RLIMIT_CORE, &rlim);
    }
}

void subnet_vectors_allocator(prefix_t* prefix, void* data) {
    // Network byte order
    uint32_t subnet_as_integer = prefix->add.sin.s_addr;

    u_short bitlen = prefix->bitlen;
    double base = 2;
    int network_size_in_ips = pow(base, 32 - bitlen);
    // logger<< log4cpp::Priority::INFO<<"Subnet: "<<prefix->add.sin.s_addr<<" network size:
    // "<<network_size_in_ips;
    logger << log4cpp::Priority::INFO << "I will allocate " << network_size_in_ips
           << " records for subnet " << subnet_as_integer << " cidr mask: " << bitlen;

    subnet_t current_subnet = std::make_pair(subnet_as_integer, bitlen);

    map_element zero_map_element;
    memset(&zero_map_element, 0, sizeof(zero_map_element));

    // Initilize our counters with fill constructor
    try {
        SubnetVectorMap[current_subnet]             = vector_of_counters(network_size_in_ips, zero_map_element);
        SubnetVectorMapSpeed[current_subnet]        = vector_of_counters(network_size_in_ips, zero_map_element);
        SubnetVectorMapSpeedAverage[current_subnet] = vector_of_counters(network_size_in_ips, zero_map_element);
    } catch (std::bad_alloc& ba) {
        logger << log4cpp::Priority::ERROR << "Can't allocate memory for counters";
        exit(1);
    }

    // Initilize map element
    SubnetVectorMapFlow[current_subnet] = vector_of_flow_counters(network_size_in_ips);

    // On creating it initilizes by zeros
    conntrack_main_struct zero_conntrack_main_struct;
    std::fill(SubnetVectorMapFlow[current_subnet].begin(),
              SubnetVectorMapFlow[current_subnet].end(), zero_conntrack_main_struct);

    PerSubnetCountersMap[current_subnet] = zero_map_element;
    PerSubnetSpeedMap[current_subnet] = zero_map_element;
}

void zeroify_all_counters() {
    map_element zero_map_element;
    memset(&zero_map_element, 0, sizeof(zero_map_element));

    for (map_of_vector_counters::iterator itr = SubnetVectorMap.begin(); itr != SubnetVectorMap.end(); ++itr) {
        // logger<< log4cpp::Priority::INFO<<"Zeroify "<<itr->first;
        std::fill(itr->second.begin(), itr->second.end(), zero_map_element);
    }
}

void zeroify_all_flow_counters() {
    // On creating it initilizes by zeros
    conntrack_main_struct zero_conntrack_main_struct;

    // Iterate over map
    for (map_of_vector_counters_for_flow::iterator itr = SubnetVectorMapFlow.begin();
         itr != SubnetVectorMapFlow.end(); ++itr) {
        // Iterate over vector
        for (vector_of_flow_counters::iterator vector_iterator = itr->second.begin();
             vector_iterator != itr->second.end(); ++vector_iterator) {
            // TODO: rewrite this monkey code
            vector_iterator->in_tcp.clear();
            vector_iterator->in_udp.clear();
            vector_iterator->in_icmp.clear();
            vector_iterator->in_other.clear();

            vector_iterator->out_tcp.clear();
            vector_iterator->out_udp.clear();
            vector_iterator->out_icmp.clear();
            vector_iterator->out_other.clear();
        }
    }
}

bool load_our_networks_list() {
    if (file_exists(white_list_path)) {
        std::vector<std::string> network_list_from_config = read_file_to_vector(white_list_path);

        for (std::vector<std::string>::iterator ii = network_list_from_config.begin();
             ii != network_list_from_config.end(); ++ii) {
            if (ii->length() > 0 && is_cidr_subnet(ii->c_str())) {
                make_and_lookup(whitelist_tree_ipv4, const_cast<char*>(ii->c_str()));
            } else {
                logger << log4cpp::Priority::ERROR << "Can't parse line from whitelist: " << *ii;
            }
        }

        logger << log4cpp::Priority::INFO << "We loaded " << network_list_from_config.size()
               << " networks from whitelist file";
    }

    std::vector<std::string> networks_list_ipv4_as_string;
    std::vector<std::string> networks_list_ipv6_as_string;

    // We can bould "our subnets" automatically here
    if (file_exists("/proc/vz/version")) {
        logger << log4cpp::Priority::INFO << "We found OpenVZ";
        // Add /32 CIDR mask for every IP here
        std::vector<std::string> openvz_ips = read_file_to_vector("/proc/vz/veip");
        for (std::vector<std::string>::iterator ii = openvz_ips.begin(); ii != openvz_ips.end(); ++ii) {
            // skip header
            if (strstr(ii->c_str(), "Version") != NULL) {
                continue;
            }

            /*
                Example data for this lines: 
                2a03:f480:1:17:0:0:0:19          0
                            185.4.72.40          0
            */

            if (strstr(ii->c_str(), ":") == NULL) {
                // IPv4

                std::vector<std::string> subnet_as_string;
                split(subnet_as_string, *ii, boost::is_any_of(" "), boost::token_compress_on);

                std::string openvz_subnet = subnet_as_string[1] + "/32";
                networks_list_ipv4_as_string.push_back(openvz_subnet);
            } else {
                // IPv6

                std::vector<std::string> subnet_as_string;
                split(subnet_as_string, *ii, boost::is_any_of(" "), boost::token_compress_on);

                std::string openvz_subnet = subnet_as_string[1] + "/128";
                networks_list_ipv6_as_string.push_back(openvz_subnet);
            }
        }

        logger << log4cpp::Priority::INFO << "We loaded " << networks_list_ipv4_as_string.size()
               << " IPv4 networks from /proc/vz/veip";

        logger << log4cpp::Priority::INFO << "We loaded " << networks_list_ipv6_as_string.size()
                << " IPv6 networks from /proc/vz/veip";
    }

    if (monitor_local_ip_addresses && file_exists("/sbin/ip")) {
        logger << log4cpp::Priority::INFO
               << "We are working on Linux and could use ip tool for detecting local IP's";

        ip_addresses_list_t ip_list = get_local_ip_v4_addresses_list();

        logger << log4cpp::Priority::INFO << "We found " << ip_list.size()
               << " local IP addresses and will monitor they";

        for (ip_addresses_list_t::iterator iter = ip_list.begin(); iter != ip_list.end(); ++iter) {
            // TODO: add IPv6 here
            networks_list_ipv4_as_string.push_back(*iter + "/32");
        }
    }

    if (file_exists(networks_list_path)) {
        std::vector<std::string> network_list_from_config = read_file_to_vector(networks_list_path);

        for (std::vector<std::string>::iterator line_itr = network_list_from_config.begin(); line_itr != network_list_from_config.end(); ++line_itr) {

            if (line_itr->length() == 0) { 
                // Skip blank lines in subnet list file silently
                continue;
            }    

            if (strstr(line_itr->c_str(), ":") == NULL) {
                networks_list_ipv4_as_string.push_back(*line_itr);
            } else {
                networks_list_ipv6_as_string.push_back(*line_itr);
            }
        } 

        logger << log4cpp::Priority::INFO << "We loaded " << network_list_from_config.size()
               << " networks from networks file";
    }

    // Some consistency checks
    assert(convert_ip_as_string_to_uint("255.255.255.0") == convert_cidr_to_binary_netmask(24));
    assert(convert_ip_as_string_to_uint("255.255.255.255") == convert_cidr_to_binary_netmask(32));

    logger << log4cpp::Priority::INFO << "Totally we have " << networks_list_ipv4_as_string.size() << " IPv4 subnets";
    logger << log4cpp::Priority::INFO << "Totally we have " << networks_list_ipv6_as_string.size() << " IPv6 subnets";

    for (std::vector<std::string>::iterator ii = networks_list_ipv4_as_string.begin();
         ii != networks_list_ipv4_as_string.end(); ++ii) {
        
        if (!is_cidr_subnet(ii->c_str())) {
            logger << log4cpp::Priority::ERROR << "Can't parse line from subnet list: '" << *ii << "'";
            continue;
        }

        std::string network_address_in_cidr_form = *ii;

        unsigned int cidr_mask = get_cidr_mask_from_network_as_string(network_address_in_cidr_form);
        std::string network_address = get_net_address_from_network_as_string(network_address_in_cidr_form);

        double base = 2;
        total_number_of_hosts_in_our_networks += pow(base, 32 - cidr_mask);

        // Make sure it's "subnet address" and not an host address
        uint32_t subnet_address_as_uint = convert_ip_as_string_to_uint(network_address);
        uint32_t subnet_address_netmask_binary = convert_cidr_to_binary_netmask(cidr_mask);
        uint32_t generated_subnet_address = subnet_address_as_uint & subnet_address_netmask_binary;

        if (subnet_address_as_uint != generated_subnet_address) {
            std::string new_network_address_as_string =
            convert_ip_as_uint_to_string(generated_subnet_address) + "/" + convert_int_to_string(cidr_mask);

            logger << log4cpp::Priority::WARN << "We will use " << new_network_address_as_string << " instead of "
                   << network_address_in_cidr_form << " because it's host address";

            network_address_in_cidr_form = new_network_address_as_string;
        }

        make_and_lookup(lookup_tree_ipv4, const_cast<char*>(network_address_in_cidr_form.c_str()));
    }

    for (std::vector<std::string>::iterator ii = networks_list_ipv6_as_string.begin();
         ii != networks_list_ipv6_as_string.end(); ++ii) {
            
        // TODO: add IPv6 subnet format validation
        make_and_lookup_ipv6(lookup_tree_ipv6, (char*)ii->c_str()); 
    }

    logger << log4cpp::Priority::INFO
           << "Total number of monitored hosts (total size of all networks): " << total_number_of_hosts_in_our_networks;

    // 3 - speed counter, average speed counter and data counter
    uint64_t memory_requirements = 3 * sizeof(map_element) * total_number_of_hosts_in_our_networks / 1024 / 1024;

    logger << log4cpp::Priority::INFO
        << "We need " << memory_requirements << " MB of memory for storing counters for your networks";

    /* Preallocate data structures */
    patricia_process(lookup_tree_ipv4, (void_fn_t)subnet_vectors_allocator);

    logger << log4cpp::Priority::INFO << "We start total zerofication of counters";
    zeroify_all_counters();
    logger << log4cpp::Priority::INFO << "We finished zerofication";

    logger << log4cpp::Priority::INFO << "We loaded " << networks_list_ipv4_as_string.size()
           << " IPv4 subnets to our in-memory list of networks";
    
    return true;
}

#ifdef IPV6_HASH_COUNTERS

moodycamel::ConcurrentQueue<simple_packet> multi_process_queue_for_ipv6_counters;

void ipv6_traffic_processor() {
    simple_packet packets_from_queue[32];

    while (true) {
        std::size_t count = 0;

        while ((count = multi_process_queue_for_ipv6_counters.try_dequeue_bulk(packets_from_queue, 32)) != 0) {
            for (std::size_t i = 0; i != count; ++i) {
#ifdef USE_NEW_ATOMIC_BUILTINS
                __atomic_add_fetch(&total_ipv6_packets, 1, __ATOMIC_RELAXED);
#else
                __sync_fetch_and_add(&total_ipv6_packets, 1);
#endif

                direction packet_direction = packets_from_queue[i].packet_direction;

                uint64_t sampled_number_of_packets = packets_from_queue[i].number_of_packets * packets_from_queue[i].sample_ratio;
                uint64_t sampled_number_of_bytes = packets_from_queue[i].length * packets_from_queue[i].sample_ratio;

#ifdef USE_NEW_ATOMIC_BUILTINS
                __atomic_add_fetch(&total_counters[packet_direction].packets, sampled_number_of_packets, __ATOMIC_RELAXED);
                __atomic_add_fetch(&total_counters[packet_direction].bytes,   sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
                __sync_fetch_and_add(&total_counters[packet_direction].packets, sampled_number_of_packets);
                __sync_fetch_and_add(&total_counters[packet_direction].bytes,   sampled_number_of_bytes);
#endif

                if (packet_direction != OTHER) {
#ifdef USE_NEW_ATOMIC_BUILTINS
                    __atomic_add_fetch(&our_ipv6_packets, 1, __ATOMIC_RELAXED);
#else
                    __sync_fetch_and_add(&our_ipv6_packets, 1);
#endif
                }       
            }
        }
    }
}

#endif

/* Process simple unified packet */
void process_packet(simple_packet& current_packet) {
    // Packets dump is very useful for bug hunting
    if (DEBUG_DUMP_ALL_PACKETS) {
        logger << log4cpp::Priority::INFO << "Dump: " << print_simple_packet(current_packet);
    }

    if (current_packet.ip_protocol_version == 6) {
#ifdef IPV6_HASH_COUNTERS
        current_packet.packet_direction = get_packet_direction_ipv6(lookup_tree_ipv6, current_packet.src_ipv6, current_packet.dst_ipv6);

        // TODO: move to bulk operations here!
        multi_process_queue_for_ipv6_counters.enqueue(current_packet);
#else


#ifdef USE_NEW_ATOMIC_BUILTINS
        __atomic_add_fetch(&total_ipv6_packets, 1, __ATOMIC_RELAXED);
#else       
        __sync_fetch_and_add(&total_ipv6_packets, 1);
#endif

#endif

        return;
    }

    // We do not process IPv6 at all on this mement
    if (current_packet.ip_protocol_version != 4) {
        return;
    }

    // Subnet for found IPs
    unsigned long subnet = 0;
    unsigned int subnet_cidr_mask = 0;

    direction packet_direction = get_packet_direction(lookup_tree_ipv4, current_packet.src_ip, current_packet.dst_ip, subnet, subnet_cidr_mask);

    // It's useful in case when we can't find what packets do not processed correctly
    if (DEBUG_DUMP_OTHER_PACKETS && packet_direction == OTHER) {
        logger << log4cpp::Priority::INFO << "Dump other: " << print_simple_packet(current_packet);
    }    

    // Skip processing of specific traffic direction
    if ((packet_direction == INCOMING && !process_incoming_traffic) or
        (packet_direction == OUTGOING && !process_outgoing_traffic)) {
        return;
    }

    subnet_t current_subnet = std::make_pair(subnet, subnet_cidr_mask); 

    uint32_t subnet_in_host_byte_order = 0;
    // We operate in host bytes order and need to convert subnet
    if (subnet != 0) {
        subnet_in_host_byte_order = ntohl(current_subnet.first);
    }

    // Try to find map key for this subnet
    map_of_vector_counters::iterator itr;

    // Iterator for subnet counter
    subnet_counter_t* subnet_counter = NULL;

    if (packet_direction == OUTGOING or packet_direction == INCOMING) {
        // Find element in map of vectors
        itr = SubnetVectorMap.find(current_subnet);

        if (itr == SubnetVectorMap.end()) {
            logger << log4cpp::Priority::ERROR << "Can't find vector address in subnet map";
            return;
        }

        if (enable_subnet_counters) {
            map_for_subnet_counters::iterator subnet_iterator;

            // Find element in map of subnet counters
            subnet_iterator = PerSubnetCountersMap.find(current_subnet);

            if (subnet_iterator == PerSubnetCountersMap.end()) {
                logger << log4cpp::Priority::ERROR << "Can't find counter structure for subnet";
                return;
            }

            subnet_counter = &subnet_iterator->second;
        }
    }

    map_of_vector_counters_for_flow::iterator itr_flow;

    if (enable_conection_tracking) {
        if (packet_direction == OUTGOING or packet_direction == INCOMING) {
            itr_flow = SubnetVectorMapFlow.find(current_subnet);

            if (itr_flow == SubnetVectorMapFlow.end()) {
                logger << log4cpp::Priority::ERROR
                       << "Can't find vector address in subnet flow map";
                return;
            }
        }
    }

    /* Because we support mirroring, sflow and netflow we should support different cases:
        - One packet passed for processing (mirror)
        - Multiple packets ("flows") passed for processing (netflow)
        - One sampled packed passed for processing (netflow)
        - Another combinations of this three options
    */

    uint64_t sampled_number_of_packets = current_packet.number_of_packets * current_packet.sample_ratio;
    uint64_t sampled_number_of_bytes = current_packet.length * current_packet.sample_ratio;

#ifdef USE_NEW_ATOMIC_BUILTINS
    __atomic_add_fetch(&total_counters[packet_direction].packets, sampled_number_of_packets, __ATOMIC_RELAXED);
    __atomic_add_fetch(&total_counters[packet_direction].bytes,   sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
    __sync_fetch_and_add(&total_counters[packet_direction].packets, sampled_number_of_packets); 
    __sync_fetch_and_add(&total_counters[packet_direction].bytes,   sampled_number_of_bytes);
#endif

    // Incerementi main and per protocol packet counters
    if (packet_direction == OUTGOING) {
        int64_t shift_in_vector = (int64_t)ntohl(current_packet.src_ip) - (int64_t)subnet_in_host_byte_order;

        if (shift_in_vector < 0 or shift_in_vector >= itr->second.size()) {
            logger << log4cpp::Priority::ERROR << "We tried to access to element with index " << shift_in_vector
                   << " which located outside allocated vector with size " << itr->second.size();

            logger << log4cpp::Priority::ERROR
                   << "We expect issues with this packet in OUTGOING direction: "
                   << print_simple_packet(current_packet);

            return;
        }

        map_element* current_element = &itr->second[shift_in_vector];

        // Main packet/bytes counter
#ifdef USE_NEW_ATOMIC_BUILTINS
        __atomic_add_fetch(&current_element->out_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
        __atomic_add_fetch(&current_element->out_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
        __sync_fetch_and_add(&current_element->out_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element->out_bytes, sampled_number_of_bytes);
#endif

        // Fragmented IP packets
        if (current_packet.ip_fragmented) {
#ifdef USE_NEW_ATOMIC_BUILTINS
            __atomic_add_fetch(&current_element->fragmented_out_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
            __atomic_add_fetch(&current_element->fragmented_out_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
            __sync_fetch_and_add(&current_element->fragmented_out_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->fragmented_out_bytes, sampled_number_of_bytes);
#endif
        }

        // TODO: add another counters
        if (enable_subnet_counters) {
#ifdef USE_NEW_ATOMIC_BUILTINS
            __atomic_add_fetch(&subnet_counter->out_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
            __atomic_add_fetch(&subnet_counter->out_bytes,   sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
            __sync_fetch_and_add(&subnet_counter->out_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&subnet_counter->out_bytes,   sampled_number_of_bytes);
#endif
        }

        conntrack_main_struct* current_element_flow = NULL;
        if (enable_conection_tracking) {
            current_element_flow = &itr_flow->second[shift_in_vector];
        }

        // Collect data when ban client
        if (!ban_list_details.empty() && ban_list_details.count(current_packet.src_ip) > 0 &&
            ban_list_details[current_packet.src_ip].size() < ban_details_records_count) {

            ban_list_details_mutex.lock();

            if (collect_attack_pcap_dumps) {
                // this code SHOULD NOT be called without mutex!
                if (current_packet.packet_payload_length > 0 && current_packet.packet_payload_pointer != NULL) {
                    ban_list[current_packet.src_ip].pcap_attack_dump.write_packet(current_packet.packet_payload_pointer,
                        current_packet.packet_payload_length);
                }
            }

            ban_list_details[current_packet.src_ip].push_back(current_packet);
            ban_list_details_mutex.unlock();
        }

        uint64_t connection_tracking_hash = 0;

        if (enable_conection_tracking) {
            packed_conntrack_hash flow_tracking_structure;
            flow_tracking_structure.opposite_ip = current_packet.dst_ip;
            flow_tracking_structure.src_port = current_packet.source_port;
            flow_tracking_structure.dst_port = current_packet.destination_port;

            // convert this struct to 64 bit integer
            connection_tracking_hash = convert_conntrack_hash_struct_to_integer(&flow_tracking_structure);
        }

        if (current_packet.protocol == IPPROTO_TCP) {
#ifdef USE_NEW_ATOMIC_BUILTINS
            __atomic_add_fetch(&current_element->tcp_out_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
            __atomic_add_fetch(&current_element->tcp_out_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
            __sync_fetch_and_add(&current_element->tcp_out_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->tcp_out_bytes, sampled_number_of_bytes);
#endif

            if (extract_bit_value(current_packet.flags, TCP_SYN_FLAG_SHIFT)) {
#ifdef USE_NEW_ATOMIC_BUILTINS
                __atomic_add_fetch(&current_element->tcp_syn_out_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
                __atomic_add_fetch(&current_element->tcp_syn_out_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
                __sync_fetch_and_add(&current_element->tcp_syn_out_packets, sampled_number_of_packets);
                __sync_fetch_and_add(&current_element->tcp_syn_out_bytes, sampled_number_of_bytes);
#endif
            }

            if (enable_conection_tracking) {
                flow_counter.lock();
                conntrack_key_struct* conntrack_key_struct_ptr =
                &current_element_flow->out_tcp[connection_tracking_hash];

                conntrack_key_struct_ptr->packets += sampled_number_of_packets;
                conntrack_key_struct_ptr->bytes += sampled_number_of_bytes;

                flow_counter.unlock();
            }
        } else if (current_packet.protocol == IPPROTO_UDP) {
#ifdef USE_NEW_ATOMIC_BUILTINS
            __atomic_add_fetch(&current_element->udp_out_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
            __atomic_add_fetch(&current_element->udp_out_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
            __sync_fetch_and_add(&current_element->udp_out_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->udp_out_bytes, sampled_number_of_bytes);
#endif

            if (enable_conection_tracking) {
                flow_counter.lock();
                conntrack_key_struct* conntrack_key_struct_ptr =
                &current_element_flow->out_udp[connection_tracking_hash];

                conntrack_key_struct_ptr->packets += sampled_number_of_packets;
                conntrack_key_struct_ptr->bytes += sampled_number_of_bytes;

                flow_counter.unlock();
            }
        } else if (current_packet.protocol == IPPROTO_ICMP) {
#ifdef USE_NEW_ATOMIC_BUILTINS
            __atomic_add_fetch(&current_element->icmp_out_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
            __atomic_add_fetch(&current_element->icmp_out_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
            __sync_fetch_and_add(&current_element->icmp_out_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->icmp_out_bytes, sampled_number_of_bytes);
#endif
            // no flow tracking for icmp
        } else {
        }

    } else if (packet_direction == INCOMING) {
        int64_t shift_in_vector = (int64_t)ntohl(current_packet.dst_ip) - (int64_t)subnet_in_host_byte_order;

        if (shift_in_vector < 0 or shift_in_vector >= itr->second.size()) {
            logger << log4cpp::Priority::ERROR << "We tried to access to element with index " << shift_in_vector
                   << " which located outside allocated vector with size " << itr->second.size();

            logger << log4cpp::Priority::ERROR
                   << "We expect issues with this packet in INCOMING direction: "
                   << print_simple_packet(current_packet);

            return;
        }

        map_element* current_element = &itr->second[shift_in_vector];

        // Main packet/bytes counter
#ifdef USE_NEW_ATOMIC_BUILTINS
        __atomic_add_fetch(&current_element->in_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
        __atomic_add_fetch(&current_element->in_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
        __sync_fetch_and_add(&current_element->in_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element->in_bytes, sampled_number_of_bytes);
#endif

        if (enable_subnet_counters) {
#ifdef USE_NEW_ATOMIC_BUILTINS
            __atomic_add_fetch(&subnet_counter->in_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
            __atomic_add_fetch(&subnet_counter->in_bytes,   sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
            __sync_fetch_and_add(&subnet_counter->in_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&subnet_counter->in_bytes,   sampled_number_of_bytes);
#endif
        }

        // Count fragmented IP packets
        if (current_packet.ip_fragmented) {
#ifdef USE_NEW_ATOMIC_BUILTINS
            __atomic_add_fetch(&current_element->fragmented_in_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
            __atomic_add_fetch(&current_element->fragmented_in_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
            __sync_fetch_and_add(&current_element->fragmented_in_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->fragmented_in_bytes, sampled_number_of_bytes);
#endif
        }

        conntrack_main_struct* current_element_flow = NULL;

        if (enable_conection_tracking) {
            current_element_flow = &itr_flow->second[shift_in_vector];
        }

        uint64_t connection_tracking_hash = 0;
        if (enable_conection_tracking) {
            packed_conntrack_hash flow_tracking_structure;
            flow_tracking_structure.opposite_ip = current_packet.src_ip;
            flow_tracking_structure.src_port = current_packet.source_port;
            flow_tracking_structure.dst_port = current_packet.destination_port;

            // convert this struct to 64 bit integer
            connection_tracking_hash = convert_conntrack_hash_struct_to_integer(&flow_tracking_structure);
        }

        // Collect attack details
        if (!ban_list_details.empty() && ban_list_details.count(current_packet.dst_ip) > 0 &&
            ban_list_details[current_packet.dst_ip].size() < ban_details_records_count) {

            ban_list_details_mutex.lock();

            if (collect_attack_pcap_dumps) {
                // this code SHOULD NOT be called without mutex!
                if (current_packet.packet_payload_length > 0 && current_packet.packet_payload_pointer != NULL) {
                    ban_list[current_packet.dst_ip].pcap_attack_dump.write_packet(current_packet.packet_payload_pointer,
                        current_packet.packet_payload_length);
                }    
            }    

            ban_list_details[current_packet.dst_ip].push_back(current_packet);
            ban_list_details_mutex.unlock();
        }

        if (current_packet.protocol == IPPROTO_TCP) {
#ifdef USE_NEW_ATOMIC_BUILTINS
            __atomic_add_fetch(&current_element->tcp_in_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
            __atomic_add_fetch(&current_element->tcp_in_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
            __sync_fetch_and_add(&current_element->tcp_in_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->tcp_in_bytes, sampled_number_of_bytes);
#endif

            if (extract_bit_value(current_packet.flags, TCP_SYN_FLAG_SHIFT)) {
#ifdef USE_NEW_ATOMIC_BUILTINS
                __atomic_add_fetch(&current_element->tcp_syn_in_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
                __atomic_add_fetch(&current_element->tcp_syn_in_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
                __sync_fetch_and_add(&current_element->tcp_syn_in_packets, sampled_number_of_packets);
                __sync_fetch_and_add(&current_element->tcp_syn_in_bytes, sampled_number_of_bytes);
#endif
            }

            if (enable_conection_tracking) {
                flow_counter.lock();
                conntrack_key_struct* conntrack_key_struct_ptr =
                &current_element_flow->in_tcp[connection_tracking_hash];

                conntrack_key_struct_ptr->packets += sampled_number_of_packets;
                conntrack_key_struct_ptr->bytes += sampled_number_of_bytes;

                flow_counter.unlock();
            }
        } else if (current_packet.protocol == IPPROTO_UDP) {
#ifdef USE_NEW_ATOMIC_BUILTINS
            __atomic_add_fetch(&current_element->udp_in_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
            __atomic_add_fetch(&current_element->udp_in_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
            __sync_fetch_and_add(&current_element->udp_in_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->udp_in_bytes, sampled_number_of_bytes);
#endif

            if (enable_conection_tracking) {
                flow_counter.lock();
                conntrack_key_struct* conntrack_key_struct_ptr =
                &current_element_flow->in_udp[connection_tracking_hash];

                conntrack_key_struct_ptr->packets += sampled_number_of_packets;
                conntrack_key_struct_ptr->bytes += sampled_number_of_bytes;
                flow_counter.unlock();
            }
        } else if (current_packet.protocol == IPPROTO_ICMP) {
#ifdef USE_NEW_ATOMIC_BUILTINS
            __atomic_add_fetch(&current_element->icmp_in_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
            __atomic_add_fetch(&current_element->icmp_in_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
            __sync_fetch_and_add(&current_element->icmp_in_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->icmp_in_bytes, sampled_number_of_bytes);
#endif
            // no flow tracking for icmp
        } else {
            // TBD
        }

    } else if (packet_direction == INTERNAL) {
    }
}

#ifdef GEOIP
unsigned int get_asn_for_ip(uint32_t ip) {
    char* asn_raw = GeoIP_org_by_name(geo_ip, convert_ip_as_uint_to_string(remote_ip).c_str());
    uint32_t asn_number = 0;

    if (asn_raw == NULL) {
        asn_number = 0;
    } else {
        // split string: AS1299 TeliaSonera International Carrier
        std::vector<std::string> asn_as_string;
        split(asn_as_string, asn_raw, boost::is_any_of(" "), boost::token_compress_on);

        // free up original string
        free(asn_raw);

        // extract raw number
        asn_number = convert_string_to_integer(asn_as_string[0].substr(2));
    }

    return asn_number;
}
#endif

// It's vizualization thread :)
void screen_draw_thread() {
    // we need wait one second for calculating speed by recalculate_speed

    //#include <sys/prctl.h>
    // prctl(PR_SET_NAME , "fastnetmon calc thread", 0, 0, 0);

    // Sleep for a half second for shift against calculatiuon thread
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));

    while (true) {
        // Available only from boost 1.54: boost::this_thread::sleep_for(
        // boost::chrono::seconds(check_period) );
        boost::this_thread::sleep(boost::posix_time::seconds(check_period));
        traffic_draw_program();
    }
}

void recalculate_speed_thread_handler() {
    while (true) {
        // recalculate data every one second
        // Available only from boost 1.54: boost::this_thread::sleep_for( boost::chrono::seconds(1)
        // );
        boost::this_thread::sleep(boost::posix_time::seconds(recalculate_speed_timeout));
        recalculate_speed();
    }
}

// Get ban settings for this subnet or return global ban settings
ban_settings_t get_ban_settings_for_this_subnet(subnet_t subnet, std::string& host_group_name) {
    // Try to find host group for this subnet
    subnet_to_host_group_map_t::iterator host_group_itr = subnet_to_host_groups.find( subnet );

    if (host_group_itr == subnet_to_host_groups.end()) {
        // We haven't host groups for all subnets, it's OK
        // logger << log4cpp::Priority::INFO << "We haven't custom host groups for this network. We will use global ban settings";
        host_group_name = "global";
        return global_ban_settings;
    }
  
    host_group_name = host_group_itr->second;
 
    // We found host group for this subnet
    host_group_ban_settings_map_t::iterator hostgroup_settings_itr = 
        host_group_ban_settings_map.find(host_group_itr->second);

    if (hostgroup_settings_itr == host_group_ban_settings_map.end()) {
        logger << log4cpp::Priority::ERROR << "We can't find ban settings for host group " << host_group_itr->second;
        return global_ban_settings;
    }
            
    // We found ban settings for this host group and use they instead global
    return hostgroup_settings_itr->second;
}

/* Calculate speed for all connnections */
void recalculate_speed() {
    // logger<< log4cpp::Priority::INFO<<"We run recalculate_speed";

    struct timeval start_calc_time;
    gettimeofday(&start_calc_time, NULL);

    double speed_calc_period = recalculate_speed_timeout;
    time_t start_time;
    time(&start_time);

    // If we got 1+ seconds lag we should use new "delta" or skip this step
    double time_difference = difftime(start_time, last_call_of_traffic_recalculation);

    if (time_difference < 1) {
        // It could occur on program start
        logger << log4cpp::Priority::INFO
               << "We skip one iteration of speed_calc because it runs so early!";
        return;
    } else if (int(time_difference) == int(speed_calc_period)) {
        // All fine, we run on time
    } else {
        logger << log4cpp::Priority::INFO
               << "Time from last run of speed_recalc is soooo big, we got ugly lags: " << time_difference;
        speed_calc_period = time_difference;
    }

    map_element zero_map_element;
    memset(&zero_map_element, 0, sizeof(zero_map_element));

    uint64_t incoming_total_flows = 0;
    uint64_t outgoing_total_flows = 0;

    if (enable_subnet_counters) {
        for (map_for_subnet_counters::iterator itr = PerSubnetSpeedMap.begin(); itr != PerSubnetSpeedMap.end(); ++itr) {
            subnet_t current_subnet = itr->first;

            map_for_subnet_counters::iterator iter_subnet = PerSubnetCountersMap.find(current_subnet);

            if (iter_subnet == PerSubnetCountersMap.end()) {
                logger << log4cpp::Priority::INFO<<"Can't find traffic counters for subnet";
                break;
            }

            subnet_counter_t* subnet_traffic = &iter_subnet->second; 

            subnet_counter_t new_speed_element;

            new_speed_element.in_packets = uint64_t((double)subnet_traffic->in_packets / speed_calc_period);
            new_speed_element.in_bytes   = uint64_t((double)subnet_traffic->in_bytes   / speed_calc_period); 

            new_speed_element.out_packets = uint64_t((double)subnet_traffic->out_packets / speed_calc_period);
            new_speed_element.out_bytes   = uint64_t((double)subnet_traffic->out_bytes   / speed_calc_period);   

            /* Moving average recalculation for subnets */
            /* http://en.wikipedia.org/wiki/Moving_average#Application_to_measuring_computer_performance */
            double exp_power_subnet = -speed_calc_period / average_calculation_amount_for_subnets;
            double exp_value_subnet = exp(exp_power_subnet);

            map_element* current_average_speed_element = &PerSubnetAverageSpeedMap[current_subnet];

            current_average_speed_element->in_bytes = uint64_t(new_speed_element.in_bytes +
                exp_value_subnet * ((double)current_average_speed_element->in_bytes - (double)new_speed_element.in_bytes));

            current_average_speed_element->out_bytes = uint64_t(new_speed_element.out_bytes +
                exp_value_subnet * ((double)current_average_speed_element->out_bytes - (double)new_speed_element.out_bytes));

            current_average_speed_element->in_packets = uint64_t(new_speed_element.in_packets +
                exp_value_subnet * ((double)current_average_speed_element->in_packets - (double)new_speed_element.in_packets));
 
            current_average_speed_element->out_packets = uint64_t(new_speed_element.out_packets +
                exp_value_subnet * ((double)current_average_speed_element->out_packets - (double)new_speed_element.out_packets));

            // Update speed calculation structure
            PerSubnetSpeedMap[current_subnet] = new_speed_element;
            *subnet_traffic = zero_map_element;

            //logger << log4cpp::Priority::INFO<<convert_subnet_to_string(current_subnet)
            //    << "in pps: " << new_speed_element.in_packets << " out pps: " << new_speed_element.out_packets;
        }
    }

    for (map_of_vector_counters::iterator itr = SubnetVectorMap.begin(); itr != SubnetVectorMap.end(); ++itr) {
        for (vector_of_counters::iterator vector_itr = itr->second.begin();
             vector_itr != itr->second.end(); ++vector_itr) {
            int current_index = vector_itr - itr->second.begin();

            // New element
            map_element new_speed_element;

            // convert to host order for math operations
            uint32_t subnet_ip = ntohl(itr->first.first);
            uint32_t client_ip_in_host_bytes_order = subnet_ip + current_index;

            // covnert to our standard network byte order
            uint32_t client_ip = htonl(client_ip_in_host_bytes_order);

            // Calculate speed for IP or whole subnet
            build_speed_counters_from_packet_counters(new_speed_element, & *vector_itr, speed_calc_period);

            conntrack_main_struct* flow_counter_ptr = &SubnetVectorMapFlow[itr->first][current_index];

            if (enable_conection_tracking) {
                // todo: optimize this operations!
                // it's really bad and SLOW CODE
                uint64_t total_out_flows =
                    (uint64_t)flow_counter_ptr->out_tcp.size() + (uint64_t)flow_counter_ptr->out_udp.size() +
                    (uint64_t)flow_counter_ptr->out_icmp.size() + (uint64_t)flow_counter_ptr->out_other.size();

                uint64_t total_in_flows =
                    (uint64_t)flow_counter_ptr->in_tcp.size() + (uint64_t)flow_counter_ptr->in_udp.size() +
                    (uint64_t)flow_counter_ptr->in_icmp.size() + (uint64_t)flow_counter_ptr->in_other.size();

                new_speed_element.out_flows = uint64_t((double)total_out_flows / speed_calc_period);
                new_speed_element.in_flows = uint64_t((double)total_in_flows / speed_calc_period);

                // Increment global counter
                outgoing_total_flows += new_speed_element.out_flows;
                incoming_total_flows += new_speed_element.in_flows;
            } else {
                new_speed_element.out_flows = 0;
                new_speed_element.in_flows = 0;
            }

            /* Moving average recalculation */
            // http://en.wikipedia.org/wiki/Moving_average#Application_to_measuring_computer_performance
            // double speed_calc_period = 1;
            double exp_power = -speed_calc_period / average_calculation_amount;
            double exp_value = exp(exp_power);

            map_element* current_average_speed_element = &SubnetVectorMapSpeedAverage[itr->first][current_index];

            // Calculate average speed from per-second speed
            build_average_speed_counters_from_speed_counters(current_average_speed_element, new_speed_element, exp_value, exp_power);

            if (enable_conection_tracking) {
                current_average_speed_element->out_flows = uint64_t(
                    new_speed_element.out_flows +
                    exp_value * ((double)current_average_speed_element->out_flows - (double)new_speed_element.out_flows));

                current_average_speed_element->in_flows = uint64_t(
                    new_speed_element.in_flows +
                    exp_value * ((double)current_average_speed_element->in_flows - (double)new_speed_element.in_flows));
            }

            /* Moving average recalculation end */
            std::string host_group_name;
            ban_settings_t current_ban_settings = get_ban_settings_for_this_subnet(itr->first, host_group_name);

            if (we_should_ban_this_ip(current_average_speed_element, current_ban_settings)) {
                logger << log4cpp::Priority::DEBUG << "We have found host group for this host as: " << host_group_name;  

                std::string flow_attack_details = "";

                if (enable_conection_tracking) {
                    flow_attack_details =
                    print_flow_tracking_for_ip(*flow_counter_ptr, convert_ip_as_uint_to_string(client_ip));
                }

                // TODO: we should pass type of ddos ban source (pps, flowd, bandwidth)!
                execute_ip_ban(client_ip, *current_average_speed_element, flow_attack_details, itr->first);
            }

            SubnetVectorMapSpeed[itr->first][current_index] = new_speed_element;

            *vector_itr = zero_map_element;
        }
    }

    // Calculate global flow speed
    incoming_total_flows_speed = uint64_t((double)incoming_total_flows / (double)speed_calc_period);
    outgoing_total_flows_speed = uint64_t((double)outgoing_total_flows / (double)speed_calc_period);

    if (enable_conection_tracking) {
        // Clean Flow Counter
        flow_counter.lock();
        zeroify_all_flow_counters();
        flow_counter.unlock();
    }

    total_unparsed_packets_speed = uint64_t((double)total_unparsed_packets / (double)speed_calc_period);
    total_unparsed_packets = 0;

    for (unsigned int index = 0; index < 4; index++) {
        total_speed_counters[index].bytes =
        uint64_t((double)total_counters[index].bytes / (double)speed_calc_period);

        total_speed_counters[index].packets =
        uint64_t((double)total_counters[index].packets / (double)speed_calc_period);

        double exp_power = -speed_calc_period / average_calculation_amount;
        double exp_value = exp(exp_power);

        total_speed_average_counters[index].bytes = uint64_t(total_speed_counters[index].bytes + exp_value * 
            ((double) total_speed_average_counters[index].bytes - (double) total_speed_counters[index].bytes));

        total_speed_average_counters[index].packets = uint64_t(total_speed_counters[index].packets + exp_value *  
            ((double) total_speed_average_counters[index].packets - (double) total_speed_counters[index].packets));  

        // nullify data counters after speed calculation
        total_counters[index].bytes = 0;
        total_counters[index].packets = 0;
    }

    // Set time of previous startup
    time(&last_call_of_traffic_recalculation);

    struct timeval finish_calc_time;
    gettimeofday(&finish_calc_time, NULL);

    timeval_subtract(&speed_calculation_time, &finish_calc_time, &start_calc_time);
}

void print_screen_contents_into_file(std::string screen_data_stats_param) {
    std::ofstream screen_data_file;
    screen_data_file.open(cli_stats_file_path.c_str(), std::ios::trunc);

    if (screen_data_file.is_open()) {
        screen_data_file << screen_data_stats_param;
        screen_data_file.close();
    } else {
        logger << log4cpp::Priority::ERROR << "Can't print program screen into file";
    }
}

void traffic_draw_program() {
    std::stringstream output_buffer;

    // logger<<log4cpp::Priority::INFO<<"Draw table call";

    struct timeval start_calc_time;
    gettimeofday(&start_calc_time, NULL);

    sort_type sorter;
    if (sort_parameter == "packets") {
        sorter = PACKETS;
    } else if (sort_parameter == "bytes") {
        sorter = BYTES;
    } else if (sort_parameter == "flows") {
        sorter = FLOWS;
    } else {
        logger << log4cpp::Priority::INFO << "Unexpected sorter type: " << sort_parameter;
        sorter = PACKETS;
    }

    output_buffer << "FastNetMon " << fastnetmon_version
                  << " Pavel Odintsov: fastnetmon.com"
                  << "\n"
                  << "IPs ordered by: " << sort_parameter << "\n";

    output_buffer << print_channel_speed("Incoming traffic", INCOMING) << std::endl;

    if (process_incoming_traffic) {
        output_buffer << draw_table(INCOMING, true, sorter);
        output_buffer << std::endl;
    }

    output_buffer << print_channel_speed("Outgoing traffic", OUTGOING) << std::endl;

    if (process_outgoing_traffic) {
        output_buffer << draw_table(OUTGOING, false, sorter);
        output_buffer << std::endl;
    }

    output_buffer << print_channel_speed("Internal traffic", INTERNAL) << std::endl;

    output_buffer << std::endl;

    output_buffer << print_channel_speed("Other traffic", OTHER) << std::endl;

    output_buffer << std::endl;

    // Application statistics
    output_buffer << "Screen updated in:\t\t" << drawing_thread_execution_time.tv_sec << " sec "
                  << drawing_thread_execution_time.tv_usec << " microseconds\n";

    output_buffer << "Traffic calculated in:\t\t" << speed_calculation_time.tv_sec << " sec "
                  << speed_calculation_time.tv_usec << " microseconds\n";

    if (speed_calculation_time.tv_sec > 0) {
        output_buffer << "ALERT! Toolkit working incorrectly! We should calculate speed in ~1 second\n";
    }

#ifdef IPV6_HASH_COUNTERS
    output_buffer << "Total amount of IPv6 packets: " << total_ipv6_packets << "\n";
#endif

    output_buffer << "Total amount of IPv6 packets related to our own network: " << our_ipv6_packets << "\n";
    output_buffer << "Not processed packets: " << total_unparsed_packets_speed << " pps\n";

    // Print backend stats
    if (enable_pcap_collection) {
        output_buffer << get_pcap_stats() << "\n";
    }  

#ifdef PF_RING
    if (enable_data_collection_from_mirror) {
        output_buffer << get_pf_ring_stats();
    }
#endif

    // Print thresholds
    if (print_configuration_params_on_the_screen) {
        output_buffer << "\n" << print_ban_thresholds(global_ban_settings);
    }

    if (!ban_list.empty()) {
        output_buffer << std::endl << "Ban list:" << std::endl;
        output_buffer << print_ddos_attack_details();
    }

    if (enable_subnet_counters) {
        output_buffer << std::endl << "Subnet load:" << std::endl;
        output_buffer << print_subnet_load() << "\n";
    }

    screen_data_stats = output_buffer.str();

    // Print screen contents into file
    print_screen_contents_into_file(screen_data_stats);

    struct timeval end_calc_time;
    gettimeofday(&end_calc_time, NULL);

    timeval_subtract(&drawing_thread_execution_time, &end_calc_time, &start_calc_time);
}

// pretty print channel speed in pps and MBit
std::string print_channel_speed(std::string traffic_type, direction packet_direction) {
    uint64_t speed_in_pps = total_speed_average_counters[packet_direction].packets;
    uint64_t speed_in_bps = total_speed_average_counters[packet_direction].bytes;

    unsigned int number_of_tabs = 1;
    // We need this for correct alignment of blocks
    if (traffic_type == "Other traffic") {
        number_of_tabs = 2;
    }

    std::stringstream stream;
    stream << traffic_type;

    for (unsigned int i = 0; i < number_of_tabs; i++) {
        stream << "\t";
    }

    uint64_t speed_in_mbps = convert_speed_to_mbps(speed_in_bps);

    stream << std::setw(6) << speed_in_pps << " pps " << std::setw(6) << speed_in_mbps << " mbps";

    if (traffic_type == "Incoming traffic" or traffic_type == "Outgoing traffic") {
        if (packet_direction == INCOMING) {
            stream << " " << std::setw(6) << incoming_total_flows_speed << " flows";
        } else if (packet_direction == OUTGOING) {
            stream << " " << std::setw(6) << outgoing_total_flows_speed << " flows";
        }

        if (graphite_enabled) {
            graphite_data_t graphite_data;

            std::string direction_as_string;

            if (packet_direction == INCOMING) {
                direction_as_string = "incoming";

                graphite_data[graphite_prefix + ".total." + direction_as_string + ".flows"] = incoming_total_flows_speed;
            } else if (packet_direction == OUTGOING) {
                direction_as_string = "outgoing";

                graphite_data[graphite_prefix + ".total." + direction_as_string + ".flows"] = outgoing_total_flows_speed;
            }

            graphite_data[graphite_prefix + ".total." + direction_as_string + ".pps"] = speed_in_pps;
            graphite_data[graphite_prefix + ".total." + direction_as_string + ".bps"] = speed_in_bps * 8;

            bool graphite_put_result = store_data_to_graphite(graphite_port, graphite_host, graphite_data);

            if (!graphite_put_result) {
                logger << log4cpp::Priority::ERROR << "Can't store data to Graphite";
            }
        }
    }

    return stream.str();
}

bool file_is_appendable(std::string path) {
    std::ofstream check_appendable_file;

    check_appendable_file.open(path.c_str(), std::ios::app);

    if (check_appendable_file.is_open()) {
        // all fine, just close file
        check_appendable_file.close();
    
        return true;
    } else {
        return false;
    }
}

void init_logging() {
    // So log4cpp will never notify you if it could not write to log file due to permissions issues
    // We will check it manually

    if (!file_is_appendable(log_file_path)) {
        std::cerr << "Can't open log file " << log_file_path << " for writing! Please check file and folder permissions" << std::endl;
        exit(EXIT_FAILURE);
    }

    log4cpp::PatternLayout* layout = new log4cpp::PatternLayout();
    layout->setConversionPattern("%d [%p] %m%n");

    log4cpp::Appender* appender = new log4cpp::FileAppender("default", log_file_path);
    appender->setLayout(layout);

    logger.setPriority(log4cpp::Priority::INFO);
    logger.addAppender(appender);

    logger << log4cpp::Priority::INFO << "Logger initialized!";
}

void reconfigure_logging() {
    log4cpp::PatternLayout* layout = new log4cpp::PatternLayout();
    layout->setConversionPattern("[%p] %m%n");

    if (logging_configuration.local_syslog_logging) {
        log4cpp::Appender* local_syslog_appender = new log4cpp::SyslogAppender("fastnetmon", "fastnetmon", LOG_USER);
	local_syslog_appender->setLayout(layout);
        logger.addAppender(local_syslog_appender);

        logger << log4cpp::Priority::INFO << "We start local syslog logging corectly";
    }   
     
    if (logging_configuration.remote_syslog_logging) {
        log4cpp::Appender* remote_syslog_appender = new log4cpp::RemoteSyslogAppender(
            "fastnetmon", "fastnetmon", logging_configuration.remote_syslog_server, LOG_USER, logging_configuration.remote_syslog_port); 

	remote_syslog_appender->setLayout(layout);
        logger.addAppender(remote_syslog_appender);
        
        logger << log4cpp::Priority::INFO << "We start remote syslog logging corectly";
    }
}

// Call fork function
int do_fork() {
    int status = 0;

    switch (fork()) {
    case 0:
        // It's child
        break;
    case -1:
        /* fork failed */
        status = -1;
        break;
    default:
        // We should close master process with _exit(0)
        // We should not call exit() because it will destroy all global variables for program
        _exit(0);
    }

    return status;
}


void redirect_fds() {
    // Close stdin, stdout and stderr
    close(0);
    close(1);
    close(2);

    if (open("/dev/null", O_RDWR) != 0) {
        // We can't notify anybody now
        exit(1);
    }

    // Create copy of zero decriptor for 1 and 2 fd's
    // We do not need return codes here but we need do it for suppressing complaints from compiler
    int first_dup_result  = dup(0);
    int second_dup_result = dup(0);
}

int main(int argc, char** argv) {
    bool daemonize = false;

    namespace po = boost::program_options;

    try {
        po::options_description desc("Allowed options");
        desc.add_options()
            ("help", "produce help message")
            ("version", "show version")
            ("daemonize", "detach from the terminal")
            ("configuration_file", po::value<std::string>(), "set path to custom configuration file")
            ("log_file", po::value<std::string>(), "set path to custom log file")
        ;

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);    

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            exit(EXIT_SUCCESS);
        }

        if (vm.count("version")) {
            std::cout << "Version: " << fastnetmon_version << std::endl;
            exit(EXIT_SUCCESS);
        }

        if (vm.count("daemonize")) {
            daemonize = true;
        }
   
        if (vm.count("configuration_file")) {
            global_config_path = vm["configuration_file"].as<std::string>();
            std::cout << "We will use custom path to configuration file: " << global_config_path << std::endl;
        } 
        
        if (vm.count("log_file")) {
            log_file_path = vm["log_file"].as<std::string>();
            std::cout << "We will use custom path to log file: " << log_file_path << std::endl;
        }
    } catch (po::error& e) {
        std::cerr << "ERROR: " << e.what() << std::endl << std::endl; 
        exit(EXIT_FAILURE);
    }

    // We use ideas from here https://github.com/bmc/daemonize/blob/master/daemon.c

    if (daemonize) {
        int status = 0;

        printf("We will run in daemonized mode\n");

        if ((status = do_fork()) < 0) {
            // fork failed
            status = -1;
        } else if (setsid() < 0) {
            // Create new session
            status = -1;
        } else if ((status = do_fork()) < 0) {
            status = -1;
        } else {
            // Clear inherited umask
            umask(0);

            // Chdir to root
            int chdir_result = chdir("/");

            // close all descriptors because we are daemon!
            redirect_fds();
        }
    }

    // enable core dumps
    enable_core_dumps();

    init_logging();

#ifdef FASTNETMON_API
    gpr_set_log_function(silent_logging_function);
#endif

    // Set default ban configuration
    init_global_ban_settings();

    // We should read configurartion file _after_ logging initialization
    bool load_config_result = load_configuration_file();

    if (!load_config_result) {
        std::cerr << "Can't open config file " << global_config_path << " please create it!" << std::endl;
        exit(1);
    } 

    if (file_exists(pid_path)) {
        pid_t pid_from_file = 0;

        if (read_pid_from_file(pid_from_file, pid_path)) {
            // We could read pid
            if (pid_from_file > 0) {
                // We use signal zero for check process existence
                int kill_result = kill(pid_from_file, 0);

                if (kill_result == 0) {
                    logger << log4cpp::Priority::ERROR
                           << "FastNetMon is already running with pid: " << pid_from_file;
                    exit(1);
                } else {
                    // Yes, we have pid with pid but it's zero
                }
            } else {
                // pid from file is broken, we assume tool is not running
            }
        } else {
            // We can't open file, let's assume it's broken and tool is not running
        }
    } else {
        // no pid file
    }

    // If we not failed in check steps we could run toolkit
    bool print_pid_to_file_result = print_pid_to_file(getpid(), pid_path);

    if (!print_pid_to_file_result) {
        logger << log4cpp::Priority::ERROR << "Could not create pid file, please check permissions: " << pid_path; 
        exit(EXIT_FAILURE);
    }

#ifdef ENABLE_DPI
    init_current_instance_of_ndpi();
#endif

    lookup_tree_ipv4 = New_Patricia(32);
    whitelist_tree_ipv4 = New_Patricia(32);

    lookup_tree_ipv6 = New_Patricia(128);
    whitelist_tree_ipv6 = New_Patricia(128);

    // nullify total counters
    for (int index = 0; index < 4; index++) {
        total_counters[index].bytes = 0;
        total_counters[index].packets = 0;

        total_speed_counters[index].bytes = 0;
        total_speed_counters[index].packets = 0;

        total_speed_average_counters[index].bytes = 0;
        total_speed_average_counters[index].packets = 0; 
    }

    /* Create folder for attack details */
    if (!folder_exists(attack_details_folder)) {
        int mkdir_result = mkdir(attack_details_folder.c_str(), S_IRWXU);

        if (mkdir_result != 0) {
            logger << log4cpp::Priority::ERROR << "Can't create folder for attack details: " << attack_details_folder;
            exit(1);
        }
    }

    if (getenv("DUMP_ALL_PACKETS") != NULL) {
        DEBUG_DUMP_ALL_PACKETS = true;
    }

    if (getenv("DUMP_OTHER_PACKETS") != NULL) {
        DEBUG_DUMP_OTHER_PACKETS = true;
    }

    if (sizeof(packed_conntrack_hash) != sizeof(uint64_t) or sizeof(packed_conntrack_hash) != 8) {
        logger << log4cpp::Priority::INFO << "Assertion about size of packed_conntrack_hash, it's "
               << sizeof(packed_conntrack_hash) << " instead 8";
        exit(1);
    }

    logger << log4cpp::Priority::INFO << "Read configuration file";

    // Reconfigure logging. We will enable specific logging methods here
    reconfigure_logging();

    load_our_networks_list();

    // Setup CTRL+C handler
    if (signal(SIGINT, interruption_signal_handler) == SIG_ERR) {
        logger << log4cpp::Priority::ERROR << "Can't setup SIGINT handler";
        exit(1);
    }

    /* Without this SIGPIPE error could shutdown toolkit on call of exec_with_stdin_params */
    if (signal(SIGPIPE, sigpipe_handler_for_popen) == SIG_ERR) {
        logger << log4cpp::Priority::ERROR << "Can't setup SIGPIPE handler";
        exit(1);
    }

#ifdef GEOIP
    // Init GeoIP
    if (!geoip_init()) {
        logger << log4cpp::Priority::ERROR << "Can't load geoip tables";
        exit(1);
    }
#endif
    // Init previous run date
    time(&last_call_of_traffic_recalculation);

    // We call init for each action
#ifdef ENABLE_GOBGP
    if (gobgp_enabled) {
        gobgp_action_init();
    } 
#endif

#ifdef IPV6_HASH_COUNTERS
    service_thread_group.add_thread(new boost::thread(ipv6_traffic_processor));
#endif

#ifdef FASTNETMON_API
    if (enable_api) {
        service_thread_group.add_thread(new boost::thread(RunApiServer));
    }
#endif

    // Run screen draw thread
    service_thread_group.add_thread(new boost::thread(screen_draw_thread));
    
    // start thread for recalculating speed in realtime
    service_thread_group.add_thread(new boost::thread(recalculate_speed_thread_handler));

    // Run banlist cleaner thread
    if (unban_enabled) {
        service_thread_group.add_thread(new boost::thread(cleanup_ban_list));
    }

#ifdef PF_RING
    if (enable_data_collection_from_mirror) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_pfring_collection, process_packet));
    }
#endif

#ifdef NETMAP_PLUGIN
    // netmap processing
    if (enable_netmap_collection) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_netmap_collection, process_packet));
    }
#endif

#ifdef SNABB_SWITCH 
    if (enable_snabbswitch_collection) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_snabbswitch_collection, process_packet));
    }
#endif

#ifdef FASTNETMON_ENABLE_AFPACKET
    if (enable_afpacket_collection) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_afpacket_collection, process_packet));
    }
#endif

    if (enable_sflow_collection) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_sflow_collection, process_packet));
    }

    if (enable_netflow_collection) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_netflow_collection, process_packet));
    }

    if (enable_pcap_collection) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_pcap_collection, process_packet));
    }

    // Wait for all threads in capture thread group
    packet_capture_plugin_thread_group.join_all();

    // Wait for all service threads
    service_thread_group.join_all();

    free_up_all_resources();

    return 0;
}

void free_up_all_resources() {
#ifdef GEOIP
    // Free up geoip handle
    GeoIP_delete(geo_ip);
#endif

    Destroy_Patricia(lookup_tree_ipv4, (void_fn_t)0);
    Destroy_Patricia(whitelist_tree_ipv4, (void_fn_t)0);

    Destroy_Patricia(lookup_tree_ipv6, (void_fn_t)0);
    Destroy_Patricia(whitelist_tree_ipv6, (void_fn_t)0);
}

// For correct program shutdown by CTRL+C
void interruption_signal_handler(int signal_number) {
     
    logger << log4cpp::Priority::INFO << "SIGNAL captured, prepare toolkit shutdown";

#ifdef FASTNETMON_API
    logger << log4cpp::Priority::INFO << "Send shutdown command to API server";
    api_server->Shutdown();
#endif

    logger << log4cpp::Priority::INFO << "Interrupt service threads";   
    service_thread_group.interrupt_all();

    logger << log4cpp::Priority::INFO << "Wait while they finished";
    service_thread_group.join_all();

    logger << log4cpp::Priority::INFO << "Interrupt packet capture treads";
    packet_capture_plugin_thread_group.interrupt_all(); 
    
    logger << log4cpp::Priority::INFO << "Wait while they finished";
    packet_capture_plugin_thread_group.join_all();
  
    logger << log4cpp::Priority::INFO << "Shutdown main process"; 

    // TODO: we should REMOVE this exit command and wait for correct toolkit shutdown
    exit(1);
}

unsigned int detect_attack_protocol(map_element& speed_element, direction attack_direction) {
    if (attack_direction == INCOMING) {
        return get_max_used_protocol(speed_element.tcp_in_packets, speed_element.udp_in_packets,
                                     speed_element.icmp_in_packets);
    } else {
        // OUTGOING
        return get_max_used_protocol(speed_element.tcp_out_packets, speed_element.udp_out_packets,
                                     speed_element.icmp_out_packets);
    }
}

#define my_max_on_defines(a, b) (a > b ? a : b)
unsigned int get_max_used_protocol(uint64_t tcp, uint64_t udp, uint64_t icmp) {
    unsigned int max = my_max_on_defines(my_max_on_defines(udp, tcp), icmp);

    if (max == tcp) {
        return IPPROTO_TCP;
    } else if (max == udp) {
        return IPPROTO_UDP;
    } else if (max == icmp) {
        return IPPROTO_ICMP;
    }

    return 0;
}

void exabgp_ban_manage(std::string action, std::string ip_as_string, attack_details current_attack) {
    // We will announce whole subent here
    if (exabgp_announce_whole_subnet) {
        std::string subnet_as_string_with_mask = convert_subnet_to_string(current_attack.customer_network);

        exabgp_prefix_ban_manage(action, subnet_as_string_with_mask, exabgp_next_hop, exabgp_community_subnet);
    }

    // And we could announce single host here (/32)
    if (exabgp_announce_host) {
        std::string ip_as_string_with_mask = ip_as_string + "/32";

        exabgp_prefix_ban_manage(action, ip_as_string_with_mask, exabgp_next_hop, exabgp_community_host);
    }
}

// Low level ExaBGP ban management
void exabgp_prefix_ban_manage(std::string action, std::string prefix_as_string_with_mask,
    std::string exabgp_next_hop, std::string exabgp_community) {

    /* Buffer for BGP message */
    char bgp_message[256];    

    if (action == "ban") {
        sprintf(bgp_message, "announce route %s next-hop %s %s\n",
            prefix_as_string_with_mask.c_str(), exabgp_next_hop.c_str(), exabgp_community.c_str());
    } else {
        sprintf(bgp_message, "withdraw route %s next-hop %s\n", prefix_as_string_with_mask.c_str(), exabgp_next_hop.c_str());
    }    

    logger << log4cpp::Priority::INFO << "ExaBGP announce message: " << bgp_message;
 
    int exabgp_pipe = open(exabgp_command_pipe.c_str(), O_WRONLY);

    if (exabgp_pipe <= 0) {
        logger << log4cpp::Priority::ERROR << "Can't open ExaBGP pipe " << exabgp_command_pipe
               << " Ban is not executed";
        return;
    }

    int wrote_bytes = write(exabgp_pipe, bgp_message, strlen(bgp_message));

    if (wrote_bytes != strlen(bgp_message)) {
        logger << log4cpp::Priority::ERROR << "Can't write message to ExaBGP pipe";
    }

    close(exabgp_pipe);
}

bool exabgp_flow_spec_ban_manage(std::string action, std::string flow_spec_rule_as_text) {
    std::string announce_action;

    if (action == "ban") {
        announce_action = "announce";
    } else {
        announce_action = "withdraw";
    }

    // Trailing \n is very important!
    std::string bgp_message = announce_action + " " + flow_spec_rule_as_text + "\n"; 

    int exabgp_pipe = open(exabgp_command_pipe.c_str(), O_WRONLY);

    if (exabgp_pipe <= 0) {
        logger << log4cpp::Priority::ERROR << "Can't open ExaBGP pipe for flow spec announce " << exabgp_command_pipe;
        return false;
    }

    int wrote_bytes = write(exabgp_pipe, bgp_message.c_str(), bgp_message.size());

    if (wrote_bytes != bgp_message.size()) {
        logger << log4cpp::Priority::ERROR << "Can't write message to ExaBGP pipe";
        return false;
    }

    close(exabgp_pipe);
    return true;
}

void execute_ip_ban(uint32_t client_ip, map_element average_speed_element, std::string flow_attack_details, subnet_t customer_subnet) {
    struct attack_details current_attack;
    uint64_t pps = 0;

    uint64_t in_pps = average_speed_element.in_packets;
    uint64_t out_pps = average_speed_element.out_packets;
    uint64_t in_bps = average_speed_element.in_bytes;
    uint64_t out_bps = average_speed_element.out_bytes;
    uint64_t in_flows = average_speed_element.in_flows;
    uint64_t out_flows = average_speed_element.out_flows;

    direction data_direction;

    if (!global_ban_settings.enable_ban) {
        logger << log4cpp::Priority::INFO << "We do not ban: " << convert_ip_as_uint_to_string(client_ip)
               << " because ban disabled completely";
        return;
    }

    // Detect attack direction with simple heuristic
    if (abs(int((int)in_pps - (int)out_pps)) < 1000) {
        // If difference between pps speed is so small we should do additional investigation using
        // bandwidth speed
        if (in_bps > out_bps) {
            data_direction = INCOMING;
            pps = in_pps;
        } else {
            data_direction = OUTGOING;
            pps = out_pps;
        }
    } else {
        if (in_pps > out_pps) {
            data_direction = INCOMING;
            pps = in_pps;
        } else {
            data_direction = OUTGOING;
            pps = out_pps;
        }
    }

    current_attack.attack_protocol = detect_attack_protocol(average_speed_element, data_direction);

    if (ban_list.count(client_ip) > 0) {
        if (ban_list[client_ip].attack_direction != data_direction) {
            logger << log4cpp::Priority::INFO
                   << "We expected very strange situation: attack direction for "
                   << convert_ip_as_uint_to_string(client_ip) << " was changed";

            return;
        }

        // update attack power
        if (pps > ban_list[client_ip].max_attack_power) {
            ban_list[client_ip].max_attack_power = pps;
        }

        return;
    }

    prefix_t prefix_for_check_adreess;
    prefix_for_check_adreess.add.sin.s_addr = client_ip;
    prefix_for_check_adreess.family = AF_INET;
    prefix_for_check_adreess.bitlen = 32;

    bool in_white_list = (patricia_search_best2(whitelist_tree_ipv4, &prefix_for_check_adreess, 1) != NULL);

    if (in_white_list) {
        return;
    }

    std::string data_direction_as_string = get_direction_name(data_direction);

    logger << log4cpp::Priority::INFO << "We run execute_ip_ban code with following params "
        << " in_pps: "  << in_pps
        << " out_pps: " << out_pps
        << " in_bps: "  << in_bps
        << " out_bps: " << out_bps
        << " and we decide it's " << data_direction_as_string << " attack";

    std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
    std::string pps_as_string = convert_int_to_string(pps);

    // Store information about subnet
    current_attack.customer_network = customer_subnet;

    // Store ban time
    time(&current_attack.ban_timestamp);
    // set ban time in seconds
    current_attack.ban_time = global_ban_time;
    current_attack.unban_enabled = unban_enabled;

    // Pass main information about attack
    current_attack.attack_direction = data_direction;
    current_attack.attack_power = pps;
    current_attack.max_attack_power = pps;

    current_attack.in_packets = in_pps;
    current_attack.out_packets = out_pps;

    current_attack.in_bytes = in_bps;
    current_attack.out_bytes = out_bps;

    // pass flow information
    current_attack.in_flows = in_flows;
    current_attack.out_flows = out_flows;

    current_attack.fragmented_in_packets = average_speed_element.fragmented_in_packets;
    current_attack.tcp_in_packets = average_speed_element.tcp_in_packets;
    current_attack.tcp_syn_in_packets = average_speed_element.tcp_syn_in_packets;
    current_attack.udp_in_packets = average_speed_element.udp_in_packets;
    current_attack.icmp_in_packets = average_speed_element.icmp_in_packets;

    current_attack.fragmented_out_packets = average_speed_element.fragmented_out_packets;
    current_attack.tcp_out_packets = average_speed_element.tcp_out_packets;
    current_attack.tcp_syn_out_packets = average_speed_element.tcp_syn_out_packets;
    current_attack.udp_out_packets = average_speed_element.udp_out_packets;
    current_attack.icmp_out_packets = average_speed_element.icmp_out_packets;

    current_attack.fragmented_out_bytes = average_speed_element.fragmented_out_bytes;
    current_attack.tcp_out_bytes = average_speed_element.tcp_out_bytes;
    current_attack.tcp_syn_out_bytes = average_speed_element.tcp_syn_out_bytes;
    current_attack.udp_out_bytes = average_speed_element.udp_out_bytes;
    current_attack.icmp_out_bytes = average_speed_element.icmp_out_bytes;

    current_attack.fragmented_in_bytes = average_speed_element.fragmented_in_bytes;
    current_attack.tcp_in_bytes = average_speed_element.tcp_in_bytes;
    current_attack.tcp_syn_in_bytes = average_speed_element.tcp_syn_in_bytes;
    current_attack.udp_in_bytes = average_speed_element.udp_in_bytes;
    current_attack.icmp_in_bytes = average_speed_element.icmp_in_bytes;

    current_attack.average_in_packets = average_speed_element.in_packets;
    current_attack.average_in_bytes = average_speed_element.in_bytes;
    current_attack.average_in_flows = average_speed_element.in_flows;

    current_attack.average_out_packets = average_speed_element.out_packets;
    current_attack.average_out_bytes = average_speed_element.out_bytes;
    current_attack.average_out_flows = average_speed_element.out_flows;

    if (collect_attack_pcap_dumps) {
        bool buffer_allocation_result = current_attack.pcap_attack_dump.allocate_buffer( number_of_packets_for_pcap_attack_dump );

        if (!buffer_allocation_result) {
            logger << log4cpp::Priority::ERROR << "Can't allocate buffer for attack, switch off this option completely ";
            collect_attack_pcap_dumps = false; 
        }
        
    }

    ban_list_mutex.lock();
    ban_list[client_ip] = current_attack;
    ban_list_mutex.unlock();

    ban_list_details_mutex.lock();
    ban_list_details[client_ip] = std::vector<simple_packet>();
    ban_list_details_mutex.unlock();

    logger << log4cpp::Priority::INFO << "Attack with direction: " << data_direction_as_string
           << " IP: " << client_ip_as_string << " Power: " << pps_as_string;

    call_ban_handlers(client_ip, ban_list[client_ip], flow_attack_details);
}

void call_ban_handlers(uint32_t client_ip, attack_details& current_attack, std::string flow_attack_details) { 
    std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
    std::string pps_as_string = convert_int_to_string(current_attack.attack_power);
    std::string data_direction_as_string = get_direction_name(current_attack.attack_direction);

    bool store_attack_details_to_file = true;
    
    std::string basic_attack_information = get_attack_description(client_ip, current_attack);
    
    std::string basic_attack_information_in_json = get_attack_description_in_json(client_ip, current_attack);

    std::string full_attack_description = basic_attack_information + flow_attack_details;

    if (store_attack_details_to_file) {
        print_attack_details_to_file(full_attack_description, client_ip_as_string, current_attack);
    }

    if (pfring_hardware_filters_enabled) {
#ifdef PF_RING
        logger << log4cpp::Priority::INFO
            << "We will block traffic to/from this IP with hardware filters";
        pfring_hardware_filter_action_block(client_ip_as_string);
#else
        logger << log4cpp::Priority::ERROR << "You haven't compiled PF_RING hardware filters support";
#endif
    }

    if (notify_script_enabled) {
        std::string script_call_params = notify_script_path + " " + client_ip_as_string + " " +
                                         data_direction_as_string + " " + pps_as_string +
                                         " " + "ban";
        logger << log4cpp::Priority::INFO << "Call script for ban client: " << client_ip_as_string;

        // We should execute external script in separate thread because any lag in this code will be
        // very distructive

        if (notify_script_pass_details) {
            // We will pass attack details over stdin
            boost::thread exec_thread(exec_with_stdin_params, script_call_params, full_attack_description);
            exec_thread.detach();
        } else {
            // Do not pass anything to script
            boost::thread exec_thread(exec, script_call_params);
            exec_thread.detach();
        }

        logger << log4cpp::Priority::INFO << "Script for ban client is finished: " << client_ip_as_string;
    }

    if (exabgp_enabled) {
        logger << log4cpp::Priority::INFO << "Call ExaBGP for ban client started: " << client_ip_as_string;

        boost::thread exabgp_thread(exabgp_ban_manage, "ban", client_ip_as_string, current_attack);
        exabgp_thread.detach();

        logger << log4cpp::Priority::INFO << "Call to ExaBGP for ban client is finished: " << client_ip_as_string;
    }

#ifdef ENABLE_GOBGP
    if (gobgp_enabled) {
        logger << log4cpp::Priority::INFO << "Call GoBGP for ban client started: " << client_ip_as_string;

        boost::thread gobgp_thread(gobgp_ban_manage, "ban", client_ip_as_string, current_attack);
        gobgp_thread.detach();

        logger << log4cpp::Priority::INFO << "Call to GoBGP for ban client is finished: " << client_ip_as_string;
    }
#endif

#ifdef REDIS
    if (redis_enabled) {
        std::string redis_key_name = client_ip_as_string + "_information";

        if (!redis_prefix.empty()) {
            redis_key_name = redis_prefix + "_" + client_ip_as_string + "_information";
        }

        logger << log4cpp::Priority::INFO << "Start data save in Redis in key: " << redis_key_name;
        boost::thread redis_store_thread(store_data_in_redis, redis_key_name, basic_attack_information_in_json);
        redis_store_thread.detach();
        logger << log4cpp::Priority::INFO << "Finish data save in Redis in key: " << redis_key_name;

        // If we have flow dump put in redis too
        if (!flow_attack_details.empty()) {
            std::string redis_key_name = client_ip_as_string + "_flow_dump";

            if (!redis_prefix.empty()) {
                redis_key_name = redis_prefix + "_" + client_ip_as_string + "_flow_dump";
            }

            logger << log4cpp::Priority::INFO << "Start data save in redis in key: " << redis_key_name;
            boost::thread redis_store_thread(store_data_in_redis, redis_key_name, flow_attack_details);
            redis_store_thread.detach();
            logger << log4cpp::Priority::INFO << "Finish data save in redis in key: " << redis_key_name;
        }
    }
#endif

#ifdef MONGO
    if (mongodb_enabled) {
        std::string mongo_key_name = client_ip_as_string + "_information_" +
            print_time_t_in_fastnetmon_format(current_attack.ban_timestamp);

        // We could not use dot in key names: http://docs.mongodb.org/manual/core/document/#dot-notation
        std::replace(mongo_key_name.begin(), mongo_key_name.end(), '.', '_');

        logger << log4cpp::Priority::INFO << "Start data save in Mongo in key: " << mongo_key_name;
        boost::thread  mongo_store_thread(store_data_in_mongo, mongo_key_name, basic_attack_information_in_json);
        mongo_store_thread.detach();
        logger << log4cpp::Priority::INFO << "Finish data save in Mongo in key: " << mongo_key_name;
    }
#endif
}


/* Thread for cleaning up ban list */
void cleanup_ban_list() {
    // If we use very small ban time we should call ban_cleanup thread more often
    if (unban_iteration_sleep_time > global_ban_time) {
        unban_iteration_sleep_time = int(global_ban_time / 2);

        logger << log4cpp::Priority::INFO << "You are using enough small ban time " << global_ban_time
            << " we need reduce unban_iteration_sleep_time twices to " << unban_iteration_sleep_time << " seconds";
    }

    logger << log4cpp::Priority::INFO << "Run banlist cleanup thread, we will awake every " << unban_iteration_sleep_time << " seconds";

    while (true) {
        boost::this_thread::sleep(boost::posix_time::seconds(unban_iteration_sleep_time));

        time_t current_time;
        time(&current_time);

        std::vector<uint32_t> ban_list_items_for_erase;

        for (std::map<uint32_t, banlist_item>::iterator itr = ban_list.begin(); itr != ban_list.end(); ++itr) {
            uint32_t client_ip = itr->first;

            // This IP should be banned permanentely and we skip any processing
            if (!itr->second.unban_enabled) {
                continue;
            }

            double time_difference = difftime(current_time, itr->second.ban_timestamp);
            int ban_time = itr->second.ban_time;

            // Yes, we reached end of ban time for this customer
            bool we_could_unban_this_ip = time_difference > ban_time; 

            // We haven't reached time for unban yet
            if (!we_could_unban_this_ip) {
                continue;
            }

            // Check about ongoing attack
            if (unban_only_if_attack_finished) {
                std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
                uint32_t subnet_in_host_byte_order = ntohl(itr->second.customer_network.first); 
                int64_t shift_in_vector = (int64_t)ntohl(client_ip) - (int64_t)subnet_in_host_byte_order;
    
                // Try to find average speed element 
                map_of_vector_counters::iterator itr_average_speed =
                    SubnetVectorMapSpeedAverage.find(itr->second.customer_network); 

                if (itr_average_speed == SubnetVectorMapSpeedAverage.end()) {
                    logger << log4cpp::Priority::ERROR << "Can't find vector address in subnet map for unban function";
                    continue;
                }

                if (shift_in_vector < 0 or shift_in_vector >= itr_average_speed->second.size()) {
                    logger << log4cpp::Priority::ERROR << "We tried to access to element with index " << shift_in_vector
                        << " which located outside allocated vector with size " << itr_average_speed->second.size();

                    continue;
                }

                map_element* average_speed_element = &itr_average_speed->second[shift_in_vector];  

                // We get ban settings from host subnet
                std::string host_group_name;
                ban_settings_t current_ban_settings = get_ban_settings_for_this_subnet(itr->second.customer_network, host_group_name);

                if (we_should_ban_this_ip(average_speed_element, current_ban_settings)) {
                    logger << log4cpp::Priority::ERROR << "Attack to IP " << client_ip_as_string
                        << " still going! We should not unblock this host";

                    // Well, we still saw attack, skip to next iteration
                    continue;
                }
            } 

            // Add this IP to remove list
            // We will remove keyas really after this loop
            ban_list_items_for_erase.push_back(itr->first);

            // Call all hooks for unban
            call_unban_handlers(itr->first, itr->second);
        }

        // Remove all unbanned hosts from the ban list
        for (std::vector<uint32_t>::iterator itr = ban_list_items_for_erase.begin(); itr != ban_list_items_for_erase.end(); ++itr) {
            ban_list_mutex.lock();
            ban_list.erase(*itr);
            ban_list_mutex.unlock(); 
        }
    }
}

void call_unban_handlers(uint32_t client_ip, attack_details& current_attack) {
    std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);

    logger << log4cpp::Priority::INFO << "We will unban banned IP: " << client_ip_as_string
        << " because it ban time " << current_attack.ban_time << " seconds is ended";

    if (notify_script_enabled) {
        std::string data_direction_as_string = get_direction_name(current_attack.attack_direction); 
        std::string pps_as_string = convert_int_to_string(current_attack.attack_power);

        std::string script_call_params = notify_script_path + " " + client_ip_as_string +
            " " + data_direction_as_string + " " +  pps_as_string + " unban";

        logger << log4cpp::Priority::INFO << "Call script for unban client: " << client_ip_as_string;

        // We should execute external script in separate thread because any lag in this
        // code will be very distructive
        boost::thread exec_thread(exec, script_call_params);
        exec_thread.detach();

        logger << log4cpp::Priority::INFO << "Script for unban client is finished: " << client_ip_as_string;
    }   

    if (exabgp_enabled) {
        logger << log4cpp::Priority::INFO
               << "Call ExaBGP for unban client started: " << client_ip_as_string;

        boost::thread exabgp_thread(exabgp_ban_manage, "unban", client_ip_as_string, current_attack);
        exabgp_thread.detach();

        logger << log4cpp::Priority::INFO << "Call to ExaBGP for unban client is finished: " << client_ip_as_string;
    }

#ifdef ENABLE_GOBGP
    if (gobgp_enabled) {
        logger << log4cpp::Priority::INFO << "Call GoBGP for unban client started: " << client_ip_as_string;

        boost::thread gobgp_thread(gobgp_ban_manage, "unban", client_ip_as_string, current_attack);
        gobgp_thread.detach();
        
        logger << log4cpp::Priority::INFO << "Call to GoBGP for unban client is finished: " << client_ip_as_string;
    }
#endif 
}

std::string print_ddos_attack_details() {
    std::stringstream output_buffer;

    for (std::map<uint32_t, banlist_item>::iterator ii = ban_list.begin(); ii != ban_list.end(); ++ii) {
        uint32_t client_ip = (*ii).first;

        std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
        std::string max_pps_as_string = convert_int_to_string(((*ii).second).max_attack_power);
        std::string attack_direction = get_direction_name(((*ii).second).attack_direction);

        output_buffer << client_ip_as_string << "/" << max_pps_as_string << " pps "
                      << attack_direction << " at "
                      << print_time_t_in_fastnetmon_format(ii->second.ban_timestamp) << std::endl;

        send_attack_details(client_ip, (*ii).second);
    }


    return output_buffer.str();
}

std::string get_attack_description(uint32_t client_ip, attack_details& current_attack) {
    std::stringstream attack_description;

    attack_description << "IP: " << convert_ip_as_uint_to_string(client_ip) << "\n";
    attack_description << serialize_attack_description(current_attack) << "\n";

    if (enable_subnet_counters) {
        // Got subnet tracking structure
        // TODO: we suppose case "no key exists" is not possible
        map_element network_speed_meter = PerSubnetSpeedMap[ current_attack.customer_network ];
        map_element average_network_speed_meter = PerSubnetAverageSpeedMap[ current_attack.customer_network ];

        attack_description <<"Network: " << convert_subnet_to_string(current_attack.customer_network) << "\n";

        attack_description << serialize_network_load_to_text(network_speed_meter, false);
        attack_description << serialize_network_load_to_text(average_network_speed_meter, true);
    }

    attack_description << serialize_statistic_counters_about_attack(current_attack);
    
    return attack_description.str();
}

std::string get_attack_description_in_json(uint32_t client_ip, attack_details& current_attack) {
    json_object* jobj = json_object_new_object();

    json_object_object_add(jobj, "ip", json_object_new_string(convert_ip_as_uint_to_string(client_ip).c_str()));
    json_object_object_add(jobj, "attack_details", serialize_attack_description_to_json(current_attack) ); 

    if (enable_subnet_counters) {
        map_element network_speed_meter = PerSubnetSpeedMap[ current_attack.customer_network ];
        map_element average_network_speed_meter = PerSubnetAverageSpeedMap[ current_attack.customer_network ];

        json_object_object_add(jobj, "network_load", serialize_network_load_to_json(network_speed_meter));
        json_object_object_add(jobj, "network_average_load", serialize_network_load_to_json(average_network_speed_meter));
    }

    // So we haven't statistic_counters here but from my point of view they are useless

    std::string json_as_text = json_object_to_json_string(jobj);

    // Free memory
    json_object_put(jobj);

    return json_as_text;
}

std::string generate_simple_packets_dump(std::vector<simple_packet>& ban_list_details) {
    std::stringstream attack_details;

    std::map<unsigned int, unsigned int> protocol_counter;
    for (std::vector<simple_packet>::iterator iii = ban_list_details.begin(); iii != ban_list_details.end(); ++iii) {
            attack_details << print_simple_packet(*iii);

        protocol_counter[iii->protocol]++;
    }    

    std::map<unsigned int, unsigned int>::iterator max_proto =
    std::max_element(protocol_counter.begin(), protocol_counter.end(), protocol_counter.value_comp());
    /*
    attack_details
        << "\n" 
        << "We got more packets (" << max_proto->second << " from " << ban_details_records_count
        << ") for protocol: " << get_protocol_name_by_number(max_proto->first) << "\n";
    */

    return attack_details.str();
}

void send_attack_details(uint32_t client_ip, attack_details current_attack_details) {
    std::string pps_as_string = convert_int_to_string(current_attack_details.attack_power);
    std::string attack_direction = get_direction_name(current_attack_details.attack_direction);
    std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);

    // Very strange code but it work in 95% cases
    if (ban_list_details.count(client_ip) > 0 && ban_list_details[client_ip].size() >= ban_details_records_count) {
        std::stringstream attack_details;

        attack_details << get_attack_description(client_ip, current_attack_details) << "\n\n";
        attack_details << generate_simple_packets_dump(ban_list_details[client_ip]);
        
        logger << log4cpp::Priority::INFO << "Attack with direction: " << attack_direction
               << " IP: " << client_ip_as_string << " Power: " << pps_as_string
               << " traffic samples collected";

        call_attack_details_handlers(client_ip, current_attack_details, attack_details.str()); 

        // TODO: here we have definitely RACE CONDITION!!! FIX IT

        // Remove key and prevent collection new data about this attack
        ban_list_details_mutex.lock();
        ban_list_details.erase(client_ip);
        ban_list_details_mutex.unlock();
    }    
}

#ifdef ENABLE_DPI
// Parse raw binary stand-alone packet with nDPI
ndpi_protocol dpi_parse_packet(char* buffer, uint32_t len, uint32_t snap_len, struct ndpi_id_struct *src, struct ndpi_id_struct *dst, struct ndpi_flow_struct *flow, std::string& parsed_packet_as_string) {
    struct pfring_pkthdr packet_header;
    memset(&packet_header, 0, sizeof(packet_header));
    packet_header.len = len;
    packet_header.caplen = snap_len;

    fastnetmon_parse_pkt((u_char*)buffer, &packet_header, 4, 1, 0);

    uint32_t current_tickt = 0;
    uint8_t* iph = (uint8_t*)(&buffer[packet_header.extended_hdr.parsed_pkt.offset.l3_offset]);
    unsigned int ipsize = packet_header.len; 

    ndpi_protocol detected_protocol = ndpi_detection_process_packet(my_ndpi_struct, flow, iph, ipsize, current_tickt, src, dst);

    // So bad approach :( 
    char print_buffer[512];
    fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)buffer, &packet_header);

    parsed_packet_as_string = std::string(print_buffer);
 
    return detected_protocol;
}
#endif

#ifdef ENABLE_DPI
void init_current_instance_of_ndpi() {
    my_ndpi_struct = init_ndpi();

    if (my_ndpi_struct == NULL) {
        logger << log4cpp::Priority::ERROR << "Can't load nDPI, disable it!";
        process_pcap_attack_dumps_with_dpi = false;

        return;
    }

    // Load sizes of main parsing structures
    ndpi_size_id_struct   = ndpi_detection_get_sizeof_ndpi_id_struct();
    ndpi_size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct(); 
}

// Zeroify nDPI structure without memory leaks
void zeroify_ndpi_flow(struct ndpi_flow_struct* flow) {
    if (flow->http.url) {
        ndpi_free(flow->http.url);
    }

    if (flow->http.content_type) {
        ndpi_free(flow->http.content_type);
    }

    memset(flow, 0, ndpi_size_flow_struct);
}

// Run flow spec mitigation rule
void launch_bgp_flow_spec_rule(amplification_attack_type_t attack_type, std::string client_ip_as_string) {
    logger << log4cpp::Priority::INFO << "We detected this attack as: " << get_amplification_attack_type(attack_type);

    std::string flow_spec_rule_text = generate_flow_spec_for_amplification_attack(attack_type, client_ip_as_string);

    logger << log4cpp::Priority::INFO << "We have generated BGP Flow Spec rule for this attack: " << flow_spec_rule_text;

    if (exabgp_flow_spec_announces) {
        active_flow_spec_announces_t::iterator itr = active_flow_spec_announces.find(flow_spec_rule_text);

        if (itr == active_flow_spec_announces.end()) {
            // We havent this flow spec rule active yet

            logger << log4cpp::Priority::INFO << "We will publish flow spec announce about this attack";
            bool exabgp_publish_result = exabgp_flow_spec_ban_manage("ban", flow_spec_rule_text);

            if (exabgp_publish_result) {
                active_flow_spec_announces[ flow_spec_rule_text ] = 1;
            }
        } else {
            // We have already blocked this attack
            logger << log4cpp::Priority::INFO << "The same rule was already sent to ExaBGP formerly";
        }
    } else {
          logger << log4cpp::Priority::INFO << "exabgp_flow_spec_announces disabled. We will not talk to ExaBGP";
    }
}

// Not so pretty copy and paste from pcap_reader()
// TODO: rewrite to memory parser
void produce_dpi_dump_for_pcap_dump(std::string pcap_file_path, std::stringstream& ss, std::string client_ip_as_string) {
    int filedesc = open(pcap_file_path.c_str(), O_RDONLY);

    if (filedesc <= 0) {
        logger << log4cpp::Priority::ERROR << "Can't open file for DPI";
        return;
    }

    struct fastnetmon_pcap_file_header pcap_header;
    ssize_t file_header_readed_bytes = read(filedesc, &pcap_header, sizeof(struct fastnetmon_pcap_file_header));

    if (file_header_readed_bytes != sizeof(struct fastnetmon_pcap_file_header)) {
        logger << log4cpp::Priority::ERROR << "Can't read pcap file header";
        return;
    }   

    // http://www.tcpdump.org/manpages/pcap-savefile.5.html
    if (pcap_header.magic == 0xa1b2c3d4 or pcap_header.magic == 0xd4c3b2a1) {
        // printf("Magic readed correctly\n");
    } else {
        logger << log4cpp::Priority::ERROR << "Magic in file header broken";
        return;
    }   

    // Buffer for packets
    char packet_buffer[pcap_header.snaplen];

    unsigned int total_packets_number = 0;

    uint64_t dns_amplification_packets = 0;
    uint64_t ntp_amplification_packets = 0;
    uint64_t ssdp_amplification_packets = 0;
    uint64_t snmp_amplification_packets = 0;


    struct ndpi_id_struct *src = (struct ndpi_id_struct*)malloc(ndpi_size_id_struct);
    memset(src, 0, ndpi_size_id_struct);

    struct ndpi_id_struct* dst = (struct ndpi_id_struct*)malloc(ndpi_size_id_struct);
    memset(dst, 0, ndpi_size_id_struct);

    struct ndpi_flow_struct* flow = (struct ndpi_flow_struct*)malloc(ndpi_size_flow_struct); 
    memset(flow, 0, ndpi_size_flow_struct);

    while (1) {
        struct fastnetmon_pcap_pkthdr pcap_packet_header;
        ssize_t packet_header_readed_bytes =
        read(filedesc, &pcap_packet_header, sizeof(struct fastnetmon_pcap_pkthdr));

        if (packet_header_readed_bytes != sizeof(struct fastnetmon_pcap_pkthdr)) {
            if (packet_header_readed_bytes != 0) {
                logger << log4cpp::Priority::INFO << "All packet read ? (" << packet_header_readed_bytes << ", " << errno << ")";
            }
            // We haven't any packets
            break;
        }

        if (pcap_packet_header.incl_len > pcap_header.snaplen) {
            logger << log4cpp::Priority::ERROR << "Please enlarge packet buffer for DPI";
            return;
        }

        ssize_t packet_payload_readed_bytes = read(filedesc, packet_buffer, pcap_packet_header.incl_len);

        if (pcap_packet_header.incl_len != packet_payload_readed_bytes) {
            logger << log4cpp::Priority::ERROR << "I read packet header but can't read packet payload";
            return;
        }

        // The flow must be reset to zero state - in other case the DPI will not detect all packets properly.
        // To use flow properly there must be much more complicated code (with flow buffer for each flow probably)
        // following code is copied from ndpi_free_flow() just to be sure there will be no memory leaks due to memset()
        zeroify_ndpi_flow(flow);

        std::string parsed_packet_as_string;

        ndpi_protocol detected_protocol = dpi_parse_packet(packet_buffer, pcap_packet_header.orig_len, pcap_packet_header.incl_len, src, dst, flow, parsed_packet_as_string);

#if NDPI_MAJOR >= 2
        u_int16_t app_protocol = detected_protocol.app_protocol;
#else
        u_int16_t app_protocol = detected_protocol.protocol;
#endif
        char* protocol_name = ndpi_get_proto_name(my_ndpi_struct, app_protocol);
        char* master_protocol_name = ndpi_get_proto_name(my_ndpi_struct, detected_protocol.master_protocol); 

        if (app_protocol == NDPI_PROTOCOL_DNS) {
            // It's answer for ANY request with so much
            if (flow->protos.dns.query_type == 255 && flow->protos.dns.num_queries < flow->protos.dns.num_answers) {
                dns_amplification_packets++;
            }

        } else if (app_protocol == NDPI_PROTOCOL_NTP) {
            // Detect packets with type MON_GETLIST_1
            if (flow->protos.ntp.version == 2 && flow->protos.ntp.request_code == 42) {
                ntp_amplification_packets++;
            }
        } else if (app_protocol == NDPI_PROTOCOL_SSDP) {
            // So, this protocol completely unexpected in WAN networks
            ssdp_amplification_packets++;
        } else if (app_protocol == NDPI_PROTOCOL_SNMP) {
            // TODO: we need detailed tests for SNMP!
            snmp_amplification_packets++;
        }

        ss << parsed_packet_as_string << " protocol: " << protocol_name << " master_protocol: " << master_protocol_name << "\n";

        total_packets_number++;
    }

    // Free up all memory
    ndpi_free_flow(flow);
    free(dst);
    free(src);
    
    close(filedesc);

    logger << log4cpp::Priority::INFO 
           << "DPI pkt stats: total:"  << total_packets_number
                           << " DNS:"  << dns_amplification_packets
                           << " NTP:"  << ntp_amplification_packets
                           << " SSDP:" << ssdp_amplification_packets
                           << " SNMP:" << snmp_amplification_packets;
                                       
    amplification_attack_type_t attack_type;

    // Attack type in unknown by default
    attack_type = AMPLIFICATION_ATTACK_UNKNOWN;

    // Detect amplification attack type
    if ( (double)dns_amplification_packets / (double)total_packets_number > 0.2) {
        launch_bgp_flow_spec_rule(AMPLIFICATION_ATTACK_DNS, client_ip_as_string);
    } else if ( (double)ntp_amplification_packets / (double)total_packets_number > 0.2) {
        launch_bgp_flow_spec_rule(AMPLIFICATION_ATTACK_NTP, client_ip_as_string);
    } else if ( (double)ssdp_amplification_packets / (double)total_packets_number > 0.2) {
        launch_bgp_flow_spec_rule(AMPLIFICATION_ATTACK_SSDP, client_ip_as_string);
    } else if ( (double)snmp_amplification_packets / (double)total_packets_number > 0.2) {
        launch_bgp_flow_spec_rule(AMPLIFICATION_ATTACK_SNMP, client_ip_as_string);
    } else {
        /*TODO 
            - full IP ban should be announced here !        
            - and maybe some protocol/port based statistics could be used to filter new/unknown attacks...
        */

        logger << log4cpp::Priority::ERROR << "We can't detect attack type with DPI. It's not so critical, only for your information";
    }
}

#endif

void call_attack_details_handlers(uint32_t client_ip, attack_details& current_attack, std::string attack_fingerprint) { 
    std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
    std::string attack_direction = get_direction_name(current_attack.attack_direction);
    std::string pps_as_string = convert_int_to_string(current_attack.attack_power);

    // We place this variables here because we need this paths from DPI parser code
    std::string ban_timestamp_as_string = print_time_t_in_fastnetmon_format(current_attack.ban_timestamp);
    std::string attack_pcap_dump_path = attack_details_folder + "/" + client_ip_as_string + "_" + ban_timestamp_as_string + ".pcap"; 

    if (collect_attack_pcap_dumps) {
        int pcap_fump_filedesc = open(attack_pcap_dump_path.c_str(), O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);
        if (pcap_fump_filedesc <= 0) {
            logger << log4cpp::Priority::ERROR << "Can't open file for storing pcap dump: " << attack_pcap_dump_path;
        } else {
            ssize_t wrote_bytes = write(pcap_fump_filedesc,
                (void*)current_attack.pcap_attack_dump.get_buffer_pointer(),
                current_attack.pcap_attack_dump.get_used_memory());
            
            if (wrote_bytes != current_attack.pcap_attack_dump.get_used_memory()) {
                 logger << log4cpp::Priority::ERROR << "Can't wrote all attack details to the disk correctly"; 
            }

            close (pcap_fump_filedesc);   
 
            // Freeup memory
            current_attack.pcap_attack_dump.deallocate_buffer();
        }
    }

#ifdef ENABLE_DPI
    // Yes, will be fine to read packets from the memory but we haven't this code yet
    // Thus we could read from file with not good performance because it's simpler
    if (collect_attack_pcap_dumps && process_pcap_attack_dumps_with_dpi) {
        std::stringstream string_buffer_for_dpi_data;

        string_buffer_for_dpi_data << "\n\nDPI\n\n";

        produce_dpi_dump_for_pcap_dump(attack_pcap_dump_path, string_buffer_for_dpi_data, client_ip_as_string);

        attack_fingerprint = attack_fingerprint + string_buffer_for_dpi_data.str();
    }
#endif

    print_attack_details_to_file(attack_fingerprint, client_ip_as_string, current_attack);

    // Pass attack details to script
    if (notify_script_enabled) {
            logger << log4cpp::Priority::INFO
                   << "Call script for notify about attack details for: " << client_ip_as_string;

            std::string script_params = notify_script_path + " " + client_ip_as_string + " " +
                                        attack_direction + " " + pps_as_string + " attack_details";

            // We should execute external script in separate thread because any lag in this code
            // will be very distructive
            boost::thread exec_with_params_thread(exec_with_stdin_params, script_params, attack_fingerprint);
            exec_with_params_thread.detach();

            logger << log4cpp::Priority::INFO
                   << "Script for notify about attack details is finished: " << client_ip_as_string;
        }

#ifdef REDIS
        if (redis_enabled) {
            std::string redis_key_name = client_ip_as_string + "_packets_dump";

            if (!redis_prefix.empty()) {
                redis_key_name = redis_prefix + "_" + client_ip_as_string + "_packets_dump";
            }

            logger << log4cpp::Priority::INFO << "Start data save in redis for key: " << redis_key_name;
            boost::thread redis_store_thread(store_data_in_redis, redis_key_name, attack_fingerprint);
            redis_store_thread.detach();
            logger << log4cpp::Priority::INFO << "Finish data save in redis for key: " << redis_key_name;
        }
#endif
}

uint64_t convert_conntrack_hash_struct_to_integer(packed_conntrack_hash* struct_value) {
    uint64_t unpacked_data = 0;
    memcpy(&unpacked_data, struct_value, sizeof(uint64_t));
    return unpacked_data;
}

void convert_integer_to_conntrack_hash_struct(packed_session* packed_connection_data,
                                              packed_conntrack_hash* unpacked_data) {
    memcpy(unpacked_data, packed_connection_data, sizeof(uint64_t));
}

std::string print_flow_tracking_for_specified_protocol(contrack_map_type& protocol_map,
                                                       std::string client_ip,
                                                       direction flow_direction) {
    std::stringstream buffer;
    // We shoud iterate over all fields

    int printed_records = 0;
    for (contrack_map_type::iterator itr = protocol_map.begin(); itr != protocol_map.end(); ++itr) {
        // We should limit number of records in flow dump because syn flood attacks produce
        // thounsands of lines
        if (printed_records > ban_details_records_count) {
            buffer << "Flows have cropped due to very long list.\n";
            break;
        }

        uint64_t packed_connection_data = itr->first;
        packed_conntrack_hash unpacked_key_struct;
        convert_integer_to_conntrack_hash_struct(&packed_connection_data, &unpacked_key_struct);

        std::string opposite_ip_as_string = convert_ip_as_uint_to_string(unpacked_key_struct.opposite_ip);
        if (flow_direction == INCOMING) {
            buffer << client_ip << ":" << unpacked_key_struct.dst_port << " < "
                   << opposite_ip_as_string << ":" << unpacked_key_struct.src_port << " ";
        } else if (flow_direction == OUTGOING) {
            buffer << client_ip << ":" << unpacked_key_struct.src_port << " > "
                   << opposite_ip_as_string << ":" << unpacked_key_struct.dst_port << " ";
        }

        buffer << itr->second.bytes << " bytes " << itr->second.packets << " packets";
        buffer << "\n";

        printed_records++;
    }

    return buffer.str();
}

/*
    Attack types:
        - syn flood: one local port, multiple remote hosts (and maybe multiple remote ports) and
   small packet size
*/

/* Iterate over all flow tracking table */
bool process_flow_tracking_table(conntrack_main_struct& conntrack_element, std::string client_ip) {
    std::map<uint32_t, unsigned int> uniq_remote_hosts_which_generate_requests_to_us;
    std::map<unsigned int, unsigned int> uniq_local_ports_which_target_of_connectiuons_from_inside;

    /* Process incoming TCP connections */
    for (contrack_map_type::iterator itr = conntrack_element.in_tcp.begin();
         itr != conntrack_element.in_tcp.end(); ++itr) {
        uint64_t packed_connection_data = itr->first;
        packed_conntrack_hash unpacked_key_struct;
        convert_integer_to_conntrack_hash_struct(&packed_connection_data, &unpacked_key_struct);

        uniq_remote_hosts_which_generate_requests_to_us[unpacked_key_struct.opposite_ip]++;
        uniq_local_ports_which_target_of_connectiuons_from_inside[unpacked_key_struct.dst_port]++;

        // we can calc average packet size
        // string opposite_ip_as_string =
        // convert_ip_as_uint_to_string(unpacked_key_struct.opposite_ip);
        // unpacked_key_struct.src_port
        // unpacked_key_struct.dst_port
        // itr->second.packets
        // itr->second.bytes
    }

    return true;
}

std::string print_flow_tracking_for_ip(conntrack_main_struct& conntrack_element, std::string client_ip) {
    std::stringstream buffer;

    std::string in_tcp =
    print_flow_tracking_for_specified_protocol(conntrack_element.in_tcp, client_ip, INCOMING);
    std::string in_udp =
    print_flow_tracking_for_specified_protocol(conntrack_element.in_udp, client_ip, INCOMING);

    unsigned long long total_number_of_incoming_tcp_flows = conntrack_element.in_tcp.size();
    unsigned long long total_number_of_incoming_udp_flows = conntrack_element.in_udp.size();

    unsigned long long total_number_of_outgoing_tcp_flows = conntrack_element.out_tcp.size();
    unsigned long long total_number_of_outgoing_udp_flows = conntrack_element.out_udp.size();

    bool we_have_incoming_flows = in_tcp.length() > 0 or in_udp.length() > 0;
    if (we_have_incoming_flows) {
        buffer << "Incoming\n\n";

        if (in_tcp.length() > 0) {
            buffer << "TCP flows: " << total_number_of_incoming_tcp_flows << "\n";
            buffer << in_tcp << "\n";
        }

        if (in_udp.length() > 0) {
            buffer << "UDP flows: " << total_number_of_incoming_udp_flows << "\n";
            buffer << in_udp << "\n";
        }
    }

    std::string out_tcp =
    print_flow_tracking_for_specified_protocol(conntrack_element.out_tcp, client_ip, OUTGOING);
    std::string out_udp =
    print_flow_tracking_for_specified_protocol(conntrack_element.out_udp, client_ip, OUTGOING);

    bool we_have_outgoing_flows = out_tcp.length() > 0 or out_udp.length() > 0;

    // print delimiter if we have flows in both directions
    if (we_have_incoming_flows && we_have_outgoing_flows) {
        buffer << "\n";
    }

    if (we_have_outgoing_flows) {
        buffer << "Outgoing\n\n";

        if (out_tcp.length() > 0) {
            buffer << "TCP flows: " << total_number_of_outgoing_tcp_flows << "\n";
            buffer << out_tcp << "\n";
        }

        if (out_udp.length() > 0) {
            buffer << "UDP flows: " << total_number_of_outgoing_udp_flows << "\n";
            buffer << out_udp << "\n";
        }
    }

    return buffer.str();
}

std::string print_subnet_load() {
    std::stringstream buffer;

    sort_type sorter;
    if (sort_parameter == "packets") {
        sorter = PACKETS;
    } else if (sort_parameter == "bytes") {
        sorter = BYTES;
    } else if (sort_parameter == "flows") {
        sorter = FLOWS;
    } else {
        logger << log4cpp::Priority::INFO << "Unexpected sorter type: " << sort_parameter;
        sorter = PACKETS;
    }  

    std::vector<pair_of_map_for_subnet_counters_elements_t> vector_for_sort;
    vector_for_sort.reserve(PerSubnetSpeedMap.size());

    for (map_for_subnet_counters::iterator itr = PerSubnetSpeedMap.begin(); itr != PerSubnetSpeedMap.end(); ++itr) {
        vector_for_sort.push_back(std::make_pair(itr->first, itr->second));
    }

    std::sort(vector_for_sort.begin(), vector_for_sort.end(),
        TrafficComparatorClass<pair_of_map_for_subnet_counters_elements_t>(INCOMING, sorter));

    graphite_data_t graphite_data;

    for (std::vector<pair_of_map_for_subnet_counters_elements_t>::iterator itr = vector_for_sort.begin(); itr != vector_for_sort.end(); ++itr) {
        map_element* speed = &itr->second; 
        std::string subnet_as_string = convert_subnet_to_string(itr->first);

        buffer
            << std::setw(18)
            << std::left
            << subnet_as_string;
           
        if (graphite_enabled) {
            std::string subnet_as_string_as_dash_delimiters = subnet_as_string;

            // Replace dots by dashes
            std::replace(subnet_as_string_as_dash_delimiters.begin(),
                subnet_as_string_as_dash_delimiters.end(), '.', '_');

            // Replace / by dashes too
            std::replace(subnet_as_string_as_dash_delimiters.begin(),
                subnet_as_string_as_dash_delimiters.end(), '/', '_');

            graphite_data[ graphite_prefix + ".networks." + subnet_as_string_as_dash_delimiters + ".incoming.pps" ] = speed->in_packets;
            graphite_data[ graphite_prefix + ".networks." + subnet_as_string_as_dash_delimiters + ".outgoing.pps" ] = speed->out_packets; 

            graphite_data[ graphite_prefix + ".networks." + subnet_as_string_as_dash_delimiters + ".incoming.bps" ] = speed->in_bytes * 8; 
            graphite_data[ graphite_prefix + ".networks." + subnet_as_string_as_dash_delimiters + ".outgoing.bps" ] = speed->out_bytes * 8;
        }
    
        buffer
            << " "
            << "pps in: "   << std::setw(8) << speed->in_packets
            << " out: "     << std::setw(8) << speed->out_packets
            << " mbps in: " << std::setw(5) << convert_speed_to_mbps(speed->in_bytes)
            << " out: "     << std::setw(5) << convert_speed_to_mbps(speed->out_bytes)
            << "\n";
    }

    if (graphite_enabled) {
        bool graphite_put_result = store_data_to_graphite(graphite_port, graphite_host, graphite_data);
        
        if (!graphite_put_result) {
            logger << log4cpp::Priority::ERROR << "Can't store network load data to Graphite";
        }
    }

    return buffer.str();
}

std::string print_ban_thresholds(ban_settings_t current_ban_settings) {
    std::stringstream output_buffer;

    output_buffer << "Configuration params:\n";
    if (current_ban_settings.enable_ban) {
        output_buffer << "We call ban script: yes\n";
    } else {
        output_buffer << "We call ban script: no\n";
    }

    output_buffer << "Packets per second: ";
    if (current_ban_settings.enable_ban_for_pps) {
        output_buffer << current_ban_settings.ban_threshold_pps;
    } else {
        output_buffer << "disabled";
    }

    output_buffer << "\n";

    output_buffer << "Mbps per second: ";
    if (current_ban_settings.enable_ban_for_bandwidth) {
        output_buffer << current_ban_settings.ban_threshold_mbps;
    } else {
        output_buffer << "disabled";
    }

    output_buffer << "\n";

    output_buffer << "Flows per second: ";
    if (current_ban_settings.enable_ban_for_flows_per_second) {
        output_buffer << current_ban_settings.ban_threshold_flows;
    } else {
        output_buffer << "disabled";
    }

    output_buffer << "\n";
    return output_buffer.str();
}

void print_attack_details_to_file(std::string details, std::string client_ip_as_string, attack_details current_attack) {
    std::ofstream my_attack_details_file;

    std::string ban_timestamp_as_string = print_time_t_in_fastnetmon_format(current_attack.ban_timestamp);
    std::string attack_dump_path = attack_details_folder + "/" + client_ip_as_string + "_" + ban_timestamp_as_string + ".txt";

    my_attack_details_file.open(attack_dump_path.c_str(), std::ios::app);

    if (my_attack_details_file.is_open()) {
        my_attack_details_file << details << "\n\n";
        my_attack_details_file.close();
    } else {
        logger << log4cpp::Priority::ERROR << "Can't print attack details to file";
    }
}

logging_configuration_t read_logging_settings(configuration_map_t configuration_map) {
    logging_configuration_t logging_configuration_temp;

    if (configuration_map.count("logging:local_syslog_logging") != 0) {
        logging_configuration_temp.local_syslog_logging = configuration_map["logging:local_syslog_logging"] == "on";
    }

    if (configuration_map.count("logging:remote_syslog_logging") != 0) { 
        logging_configuration_temp.remote_syslog_logging = configuration_map["logging:remote_syslog_logging"] == "on";
    } 

    if (configuration_map.count("logging:remote_syslog_server") != 0) {
        logging_configuration_temp.remote_syslog_server = configuration_map["logging:remote_syslog_server"];
    }

    if (configuration_map.count("logging:remote_syslog_port") != 0) {
        logging_configuration_temp.remote_syslog_port = convert_string_to_integer(configuration_map["logging:remote_syslog_port"]);
    }

    if (logging_configuration_temp.remote_syslog_logging) {
        if (logging_configuration_temp.remote_syslog_port > 0 && !logging_configuration_temp.remote_syslog_server.empty()) {
            logger << log4cpp::Priority::INFO << "We have configured remote syslog logging corectly";
        } else {
            logger << log4cpp::Priority::ERROR << "You have enabled remote logging but haven't specified port or host";
            logging_configuration_temp.remote_syslog_logging = false;
        }
    }

    if (logging_configuration_temp.local_syslog_logging) {
        logger << log4cpp::Priority::INFO << "We have configured local syslog logging corectly";
    }

    return logging_configuration_temp;
}

ban_settings_t read_ban_settings(configuration_map_t configuration_map, std::string host_group_name) {
    ban_settings_t ban_settings;

    std::string prefix = "";
    if (host_group_name != "") {
        prefix = host_group_name + "_";
    } 

    if (configuration_map.count(prefix + "enable_ban") != 0) {
        ban_settings.enable_ban = configuration_map[prefix + "enable_ban"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_pps") != 0) {
        ban_settings.enable_ban_for_pps = configuration_map[prefix + "ban_for_pps"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_bandwidth") != 0) {
        ban_settings.enable_ban_for_bandwidth = configuration_map[prefix + "ban_for_bandwidth"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_flows") != 0) { 
        ban_settings.enable_ban_for_flows_per_second = configuration_map[prefix + "ban_for_flows"] == "on";
    }    

    // Per protocol bandwidth triggers
    if (configuration_map.count(prefix + "ban_for_tcp_bandwidth") != 0) {
        ban_settings.enable_ban_for_tcp_bandwidth = configuration_map[prefix + "ban_for_tcp_bandwidth"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_udp_bandwidth") != 0) { 
        ban_settings.enable_ban_for_udp_bandwidth = configuration_map[prefix + "ban_for_udp_bandwidth"] == "on";
    }   

    if (configuration_map.count(prefix + "ban_for_icmp_bandwidth") != 0) { 
        ban_settings.enable_ban_for_icmp_bandwidth = configuration_map[prefix + "ban_for_icmp_bandwidth"] == "on";
    }   

    // Per protocol pps ban triggers
    if (configuration_map.count(prefix + "ban_for_tcp_pps") != 0) { 
        ban_settings.enable_ban_for_tcp_pps = configuration_map[prefix + "ban_for_tcp_pps"] == "on";
    }    

    if (configuration_map.count(prefix + "ban_for_udp_pps") != 0) {
        ban_settings.enable_ban_for_udp_pps = configuration_map[prefix + "ban_for_udp_pps"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_icmp_pps") != 0) {
        ban_settings.enable_ban_for_icmp_pps = configuration_map[prefix + "ban_for_icmp_pps"] == "on";
    }

    // Pps per protocol thresholds
    if (configuration_map.count(prefix + "threshold_tcp_pps") != 0) {
        ban_settings.ban_threshold_tcp_pps = convert_string_to_integer(configuration_map[prefix + "threshold_tcp_pps"]);
    }

    if (configuration_map.count(prefix + "threshold_udp_pps") != 0) { 
        ban_settings.ban_threshold_udp_pps = convert_string_to_integer(configuration_map[prefix + "threshold_udp_pps"]);
    } 
    
    if (configuration_map.count(prefix + "threshold_icmp_pps") != 0) { 
        ban_settings.ban_threshold_icmp_pps = convert_string_to_integer(configuration_map[prefix + "threshold_icmp_pps"]);
    }

    // Bandwidth per protocol thresholds 
    if (configuration_map.count(prefix + "threshold_tcp_mbps") != 0) { 
        ban_settings.ban_threshold_tcp_mbps = convert_string_to_integer(configuration_map[prefix + "threshold_tcp_mbps"]);
    }    

    if (configuration_map.count(prefix + "threshold_udp_mbps") != 0) {
        ban_settings.ban_threshold_udp_mbps = convert_string_to_integer(configuration_map[prefix + "threshold_udp_mbps"]);
    }
    
    if (configuration_map.count(prefix + "threshold_icmp_mbps") != 0) {
        ban_settings.ban_threshold_icmp_mbps = convert_string_to_integer(configuration_map[prefix + "threshold_icmp_mbps"]);
    }   
 
    if (configuration_map.count(prefix + "threshold_pps") != 0) {
        ban_settings.ban_threshold_pps = convert_string_to_integer(configuration_map[prefix + "threshold_pps"]);
    }

    if (configuration_map.count(prefix + "threshold_mbps") != 0) {
        ban_settings.ban_threshold_mbps = convert_string_to_integer(configuration_map[prefix + "threshold_mbps"]);
    }

    if (configuration_map.count(prefix + "threshold_flows") != 0) {
        ban_settings.ban_threshold_flows = convert_string_to_integer(configuration_map[prefix + "threshold_flows"]);
    }

    return ban_settings;
}



bool exceed_pps_speed(uint64_t in_counter, uint64_t out_counter, unsigned int threshold) {
    if (in_counter > threshold or out_counter > threshold) {
        return true;
    } else {
        return false;
    }
}

bool exceed_flow_speed(uint64_t in_counter, uint64_t out_counter, unsigned int threshold) {
    if (in_counter > threshold or out_counter > threshold) {
        return true;
    } else {
        return false;
    }  
}

bool exceed_mbps_speed(uint64_t in_counter, uint64_t out_counter, unsigned int threshold_mbps) {
    if (convert_speed_to_mbps(in_counter) > threshold_mbps or convert_speed_to_mbps(out_counter) > threshold_mbps) {
        return true;
    } else {
        return false;
    }
}

// Return true when we should ban this IP
bool we_should_ban_this_ip(map_element* average_speed_element, ban_settings_t current_ban_settings) {
    // we detect overspeed by packets
    bool attack_detected_by_pps = false;
    bool attack_detected_by_bandwidth = false;
    bool attack_detected_by_flow = false;
    if (current_ban_settings.enable_ban_for_pps &&
        exceed_pps_speed(average_speed_element->in_packets, average_speed_element->out_packets, current_ban_settings.ban_threshold_pps)) {
        logger << log4cpp::Priority::DEBUG  << "We detected this attack by pps limit";
        return true;
    }

    if (current_ban_settings.enable_ban_for_bandwidth &&
        exceed_mbps_speed(average_speed_element->in_bytes, average_speed_element->out_bytes, current_ban_settings.ban_threshold_mbps)) { 
        logger << log4cpp::Priority::DEBUG  << "We detected this attack by mbps limit";
        return true;
    }

    if (current_ban_settings.enable_ban_for_flows_per_second &&
        exceed_flow_speed(average_speed_element->in_flows, average_speed_element->out_flows, current_ban_settings.ban_threshold_flows)) {
        logger << log4cpp::Priority::DEBUG  << "We detected this attack by flow limit"; 
        return true;
    }

    // We could try per protocol thresholds here

    // Per protocol pps thresholds
    if (current_ban_settings.enable_ban_for_tcp_pps && 
        exceed_pps_speed(average_speed_element->tcp_in_packets, average_speed_element->tcp_out_packets, current_ban_settings.ban_threshold_tcp_pps)) {
        logger << log4cpp::Priority::DEBUG  << "We detected this attack by tcp pps limit";
        return true;
    }

    if (current_ban_settings.enable_ban_for_udp_pps && 
        exceed_pps_speed(average_speed_element->udp_in_packets, average_speed_element->udp_out_packets, current_ban_settings.ban_threshold_udp_pps)) {
        logger << log4cpp::Priority::DEBUG  << "We detected this attack by udp pps limit";
        return true;
    } 

    if (current_ban_settings.enable_ban_for_icmp_pps && 
        exceed_pps_speed(average_speed_element->icmp_in_packets, average_speed_element->icmp_out_packets, current_ban_settings.ban_threshold_icmp_pps)) {
        logger << log4cpp::Priority::DEBUG  << "We detected this attack by icmp pps limit";
        return true;
    }     

    // Per protocol bandwidth thresholds
    if (current_ban_settings.enable_ban_for_tcp_bandwidth &&
        exceed_mbps_speed(average_speed_element->tcp_in_bytes, average_speed_element->tcp_out_bytes, current_ban_settings.ban_threshold_tcp_mbps)) {
        logger << log4cpp::Priority::DEBUG  << "We detected this attack by tcp mbps limit";
        return true;
    }

    if (current_ban_settings.enable_ban_for_udp_bandwidth &&
        exceed_mbps_speed(average_speed_element->udp_in_bytes, average_speed_element->udp_out_bytes, current_ban_settings.ban_threshold_udp_mbps)) {
        logger << log4cpp::Priority::DEBUG  << "We detected this attack by udp mbps limit";
        return true;
    }  

    if (current_ban_settings.enable_ban_for_icmp_bandwidth &&
        exceed_mbps_speed(average_speed_element->icmp_in_bytes, average_speed_element->icmp_out_bytes, current_ban_settings.ban_threshold_icmp_mbps)) {
        logger << log4cpp::Priority::DEBUG  << "We detected this attack by icmp mbps limit";
        return true;
    }  

    return false;
}

std::string generate_flow_spec_for_amplification_attack(amplification_attack_type_t amplification_attack_type, std::string destination_ip) {
    exabgp_flow_spec_rule_t exabgp_rule;

    bgp_flow_spec_action_t my_action;

    // We drop all traffic by default
    my_action.set_type(FLOW_SPEC_ACTION_DISCARD);

    // Assign action to the rule
    exabgp_rule.set_action( my_action ); 

    // TODO: rewrite!
    exabgp_rule.set_destination_subnet( convert_subnet_from_string_to_binary_with_cidr_format( destination_ip + "/32") );
    
    // We use only UDP here
    exabgp_rule.add_protocol(FLOW_SPEC_PROTOCOL_UDP);
    
    if (amplification_attack_type == AMPLIFICATION_ATTACK_DNS) {
        exabgp_rule.add_source_port(53);
    } else if (amplification_attack_type == AMPLIFICATION_ATTACK_NTP) {
        exabgp_rule.add_source_port(123);
    } else if (amplification_attack_type == AMPLIFICATION_ATTACK_SSDP) {
        exabgp_rule.add_source_port(1900);
    } else if (amplification_attack_type == AMPLIFICATION_ATTACK_SNMP) {
        exabgp_rule.add_source_port(161);
    } else if (amplification_attack_type == AMPLIFICATION_ATTACK_CHARGEN) {
        exabgp_rule.add_source_port(19);
    } 

    return exabgp_rule.serialize_single_line_exabgp_v4_configuration();
}

std::string get_amplification_attack_type(amplification_attack_type_t attack_type) {
    if (attack_type == AMPLIFICATION_ATTACK_UNKNOWN) {
        return "unknown";
    } else if (attack_type == AMPLIFICATION_ATTACK_DNS) {
        return "dns_amplification";
    } else if (attack_type == AMPLIFICATION_ATTACK_NTP) {
        return "ntp_amplification";
    } else if (attack_type == AMPLIFICATION_ATTACK_SSDP) {
        return "ssdp_amplification";
    } else if (attack_type == AMPLIFICATION_ATTACK_SNMP) {
        return "snmp_amplification";
    } else if (attack_type == AMPLIFICATION_ATTACK_CHARGEN) {
        return "chargen_amplification";
    } else {
        return "unexpected";
    }
}

// We calculate speed from packet counters here
inline void build_speed_counters_from_packet_counters(map_element& new_speed_element, map_element* vector_itr, double speed_calc_period) {
    // calculate_speed(new_speed_element speed_element, vector_itr* );
    new_speed_element.in_packets = uint64_t((double)vector_itr->in_packets / speed_calc_period);
    new_speed_element.out_packets = uint64_t((double)vector_itr->out_packets / speed_calc_period);

    new_speed_element.in_bytes = uint64_t((double)vector_itr->in_bytes / speed_calc_period);
    new_speed_element.out_bytes = uint64_t((double)vector_itr->out_bytes / speed_calc_period);

    // Fragmented
    new_speed_element.fragmented_in_packets =
    uint64_t((double)vector_itr->fragmented_in_packets / speed_calc_period);
    new_speed_element.fragmented_out_packets =
    uint64_t((double)vector_itr->fragmented_out_packets / speed_calc_period);

    new_speed_element.fragmented_in_bytes =
    uint64_t((double)vector_itr->fragmented_in_bytes / speed_calc_period);
    new_speed_element.fragmented_out_bytes =
    uint64_t((double)vector_itr->fragmented_out_bytes / speed_calc_period);

    // By protocol counters

    // TCP
    new_speed_element.tcp_in_packets = uint64_t((double)vector_itr->tcp_in_packets / speed_calc_period);
    new_speed_element.tcp_out_packets =
    uint64_t((double)vector_itr->tcp_out_packets / speed_calc_period);

    new_speed_element.tcp_in_bytes = uint64_t((double)vector_itr->tcp_in_bytes / speed_calc_period);
    new_speed_element.tcp_out_bytes = uint64_t((double)vector_itr->tcp_out_bytes / speed_calc_period);

    // TCP syn
    new_speed_element.tcp_syn_in_packets =
    uint64_t((double)vector_itr->tcp_syn_in_packets / speed_calc_period);
    new_speed_element.tcp_syn_out_packets =
    uint64_t((double)vector_itr->tcp_syn_out_packets / speed_calc_period);

    new_speed_element.tcp_syn_in_bytes =
    uint64_t((double)vector_itr->tcp_syn_in_bytes / speed_calc_period);
    new_speed_element.tcp_syn_out_bytes =
    uint64_t((double)vector_itr->tcp_syn_out_bytes / speed_calc_period);

    // UDP
    new_speed_element.udp_in_packets = uint64_t((double)vector_itr->udp_in_packets / speed_calc_period);
    new_speed_element.udp_out_packets =
    uint64_t((double)vector_itr->udp_out_packets / speed_calc_period);

    new_speed_element.udp_in_bytes = uint64_t((double)vector_itr->udp_in_bytes / speed_calc_period);
    new_speed_element.udp_out_bytes = uint64_t((double)vector_itr->udp_out_bytes / speed_calc_period);

    // ICMP
    new_speed_element.icmp_in_packets =
    uint64_t((double)vector_itr->icmp_in_packets / speed_calc_period);
    new_speed_element.icmp_out_packets =
    uint64_t((double)vector_itr->icmp_out_packets / speed_calc_period);

    new_speed_element.icmp_in_bytes = uint64_t((double)vector_itr->icmp_in_bytes / speed_calc_period);
    new_speed_element.icmp_out_bytes = uint64_t((double)vector_itr->icmp_out_bytes / speed_calc_period);
}

inline void build_average_speed_counters_from_speed_counters(
    map_element* current_average_speed_element,
    map_element& new_speed_element, 
    double exp_value,
    double exp_power) {

    // Global bytes counters
    current_average_speed_element->in_bytes = uint64_t(
        new_speed_element.in_bytes +
        exp_value * ((double)current_average_speed_element->in_bytes - (double)new_speed_element.in_bytes));
     
    current_average_speed_element->out_bytes = uint64_t(
        new_speed_element.out_bytes +
        exp_value * ((double)current_average_speed_element->out_bytes - (double)new_speed_element.out_bytes));

    // Global packet counters
    current_average_speed_element->in_packets = uint64_t(
        new_speed_element.in_packets +
        exp_value * ((double)current_average_speed_element->in_packets - (double)new_speed_element.in_packets));

    current_average_speed_element->out_packets = uint64_t(
        new_speed_element.out_packets +
        exp_value * ((double)current_average_speed_element->out_packets - (double)new_speed_element.out_packets));

    // Per packet type packet counters for in traffic
   current_average_speed_element->fragmented_in_packets = uint64_t(
        new_speed_element.fragmented_in_packets +
        exp_value * ((double)current_average_speed_element->fragmented_in_packets - (double)new_speed_element.fragmented_in_packets));

    current_average_speed_element->tcp_in_packets = uint64_t(
        new_speed_element.tcp_in_packets +
        exp_value * ((double)current_average_speed_element->tcp_in_packets - (double)new_speed_element.tcp_in_packets));

    current_average_speed_element->tcp_syn_in_packets = uint64_t(
        new_speed_element.tcp_syn_in_packets +
        exp_value * ((double)current_average_speed_element->tcp_syn_in_packets - (double)new_speed_element.tcp_syn_in_packets));

    current_average_speed_element->udp_in_packets = uint64_t(
        new_speed_element.udp_in_packets +
        exp_value * ((double)current_average_speed_element->udp_in_packets - (double)new_speed_element.udp_in_packets));

    current_average_speed_element->icmp_in_packets = uint64_t(
        new_speed_element.icmp_in_packets +
        exp_value * ((double)current_average_speed_element->icmp_in_packets - (double)new_speed_element.icmp_in_packets));

    // Per packet type packets counters for out
    current_average_speed_element->fragmented_out_packets = uint64_t(
        new_speed_element.fragmented_out_packets +
        exp_value * ((double)current_average_speed_element->fragmented_out_packets - (double)new_speed_element.fragmented_out_packets));

    current_average_speed_element->tcp_out_packets = uint64_t(
        new_speed_element.tcp_out_packets +
        exp_value * ((double)current_average_speed_element->tcp_out_packets - (double)new_speed_element.tcp_out_packets));

    current_average_speed_element->tcp_syn_out_packets = uint64_t(
        new_speed_element.tcp_syn_out_packets +
        exp_value * ((double)current_average_speed_element->tcp_syn_out_packets - (double)new_speed_element.tcp_syn_out_packets));

    current_average_speed_element->udp_out_packets = uint64_t(
        new_speed_element.udp_out_packets +
        exp_value * ((double)current_average_speed_element->udp_out_packets - (double)new_speed_element.udp_out_packets));

    current_average_speed_element->icmp_out_packets = uint64_t(
        new_speed_element.icmp_out_packets +
        exp_value * ((double)current_average_speed_element->icmp_out_packets - (double)new_speed_element.icmp_out_packets));

    // Per packet type bytes counter for out
    current_average_speed_element->fragmented_out_bytes = uint64_t(
        new_speed_element.fragmented_out_bytes +
        exp_value * ((double)current_average_speed_element->fragmented_out_bytes - (double)new_speed_element.fragmented_out_bytes));

    current_average_speed_element->tcp_out_bytes = uint64_t(
        new_speed_element.tcp_out_bytes +
        exp_value * ((double)current_average_speed_element->tcp_out_bytes - (double)new_speed_element.tcp_out_bytes));

    current_average_speed_element->tcp_syn_out_bytes = uint64_t(
        new_speed_element.tcp_syn_out_bytes +
        exp_value * ((double)current_average_speed_element->tcp_syn_out_bytes - (double)new_speed_element.tcp_syn_out_bytes));

    current_average_speed_element->udp_out_bytes = uint64_t(
        new_speed_element.udp_out_bytes +
        exp_value * ((double)current_average_speed_element->udp_out_bytes - (double)new_speed_element.udp_out_bytes));

    current_average_speed_element->icmp_out_bytes = uint64_t(
        new_speed_element.icmp_out_bytes +
        exp_value * ((double)current_average_speed_element->icmp_out_bytes - (double)new_speed_element.icmp_out_bytes));

    // Per packet type bytes counter for in
    current_average_speed_element->fragmented_in_bytes = uint64_t(
        new_speed_element.fragmented_in_bytes +
        exp_value * ((double)current_average_speed_element->fragmented_in_bytes - (double)new_speed_element.fragmented_in_bytes));

    current_average_speed_element->tcp_in_bytes = uint64_t(
        new_speed_element.tcp_in_bytes +
        exp_value * ((double)current_average_speed_element->tcp_in_bytes - (double)new_speed_element.tcp_in_bytes));

    current_average_speed_element->tcp_syn_in_bytes = uint64_t(
        new_speed_element.tcp_syn_in_bytes +
        exp_value * ((double)current_average_speed_element->tcp_syn_in_bytes - (double)new_speed_element.tcp_syn_in_bytes));

    current_average_speed_element->udp_in_bytes = uint64_t(
        new_speed_element.udp_in_bytes +
        exp_value * ((double)current_average_speed_element->udp_in_bytes - (double)new_speed_element.udp_in_bytes));

    current_average_speed_element->icmp_in_bytes = uint64_t(
        new_speed_element.icmp_in_bytes +
        exp_value * ((double)current_average_speed_element->icmp_in_bytes - (double)new_speed_element.icmp_in_bytes));
}

