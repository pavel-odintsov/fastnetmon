/* Author: pavel.odintsov@gmail.com */
/* License: GPLv2 */

#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <string.h>
#include <unistd.h>
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
#include <netdb.h>

#include "libpatricia/patricia.h"
#include "fastnetmon_types.h"

// Plugins
#include "sflow_plugin/sflow_collector.h"
#include "netflow_plugin/netflow_collector.h"
#include "pcap_plugin/pcap_collector.h"

// Our structires
// #include "fast_priority_queue.h"

#ifdef PF_RING
#include "pfring_plugin/pfring_collector.h"
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

// log4cpp logging facility
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

#ifdef GEOIP
#include "GeoIP.h"
#endif

#ifdef REDIS
#include <hiredis/hiredis.h>
#endif

std::string global_config_path = "/etc/fastnetmon.conf";

boost::regex regular_expression_cidr_pattern("^\\d+\\.\\d+\\.\\d+\\.\\d+\\/\\d+$");

time_t last_call_of_traffic_recalculation;

// Variable with all data from main screen
std::string screen_data_stats = "";

// Global map with parsed config file
std::map<std::string, std::string> configuration_map;

/* Configuration block, we must move it to configuration file  */
#ifdef REDIS
unsigned int redis_port = 6379;
std::string redis_host = "127.0.0.1";
// because it's additional and very specific feature we should disable it by default
bool redis_enabled = false;
#endif

bool enable_ban_for_pps = false;
bool enable_ban_for_bandwidth = false;
bool enable_ban_for_flows_per_second = false;
 
bool enable_conection_tracking = true;

bool enable_data_collection_from_mirror = true;
bool enable_sflow_collection = false;
bool enable_netflow_collection = false;
bool enable_pcap_collection = false;

// Time consumed by reaclculation for all IPs
struct timeval speed_calculation_time;

// Time consumed by drawing stats for all IPs
struct timeval drawing_thread_execution_time;

// Total number of hosts in our networks
// We need this as global variable because it's very important value for configuring data structures
unsigned int total_number_of_hosts_in_our_networks = 0;

#ifdef GEOIP
GeoIP * geo_ip = NULL;
#endif

patricia_tree_t *lookup_tree, *whitelist_tree;

bool DEBUG = 0;

// flag about dumping all packets to log
bool DEBUG_DUMP_ALL_PACKETS = false;

// Period for update screen for console version of tool
unsigned int check_period = 3;

// Standard ban time in seconds for all attacks but you can tune this value
int standard_ban_time = 1800; 

// We calc average pps/bps for this time
double average_calculation_amount = 15;

// Show average or absolute value of speed 
bool print_average_traffic_counts = true;

// Key used for sorting clients in output.  Allowed sort params: packets/bytes
std::string sort_parameter = "packets";

// Path to notify script 
std::string notify_script_path = "/usr/local/bin/notify_about_attack.sh";

// Number of lines in programm output
unsigned int max_ips_in_list = 7;

// We must ban IP if it exceeed this limit in PPS
unsigned int ban_threshold_pps = 20000;

// We must ban IP of it exceed this limit for number of flows in any direction
unsigned int ban_threshold_flows = 3500;

// We must ban client if it exceed 1GBps
unsigned int ban_threshold_mbps = 1000;

// Number of lines for sending ben attack details to email
unsigned int ban_details_records_count = 500;


// log file
log4cpp::Category& logger = log4cpp::Category::getRoot();
std::string log_file_path = "/var/log/fastnetmon.log";
std::string attack_details_folder = "/var/log/fastnetmon_attacks";

/* Configuration block ends */

/* Our data structs */

// Enum with availible sort by field
enum sort_type { PACKETS, BYTES, FLOWS };

enum direction {
    INCOMING = 0,
    OUTGOING,
    INTERNAL,
    OTHER
};

typedef struct {
    uint64_t bytes;
    uint64_t packets;
    uint64_t flows;
} total_counter_element;

// We count total number of incoming/outgoing/internal and other traffic type packets/bytes
// And initilize by 0 all fields
total_counter_element total_counters[4];
total_counter_element total_speed_counters[4];

// Total amount of non parsed packets
uint64_t total_unparsed_packets = 0;

uint64_t incoming_total_flows_speed = 0;
uint64_t outgoing_total_flows_speed = 0;

typedef std::pair<uint32_t, uint32_t> subnet;

// main data structure for storing traffic and speed data for all our IPs
class map_element {
public:
    map_element() : in_bytes(0), out_bytes(0), in_packets(0), out_packets(0), tcp_in_packets(0), tcp_out_packets(0), tcp_in_bytes(0), tcp_out_bytes(0),
        udp_in_packets(0), udp_out_packets(0), udp_in_bytes(0), udp_out_bytes(0), in_flows(0), out_flows(0),
        icmp_in_packets(0), icmp_out_packets(0), icmp_in_bytes(0), icmp_out_bytes(0)
     {}
    uint64_t in_bytes;
    uint64_t out_bytes;
    uint64_t in_packets;
    uint64_t out_packets;
    
    // Additional data for correct attack protocol detection
    uint64_t tcp_in_packets;
    uint64_t tcp_out_packets;
    uint64_t tcp_in_bytes;
    uint64_t tcp_out_bytes;

    uint64_t udp_in_packets;
    uint64_t udp_out_packets;
    uint64_t udp_in_bytes;
    uint64_t udp_out_bytes;

    uint64_t icmp_in_packets;
    uint64_t icmp_out_packets;
    uint64_t icmp_in_bytes;
    uint64_t icmp_out_bytes;

    uint64_t in_flows;
    uint64_t out_flows;
};

// structure with attack details
class attack_details : public map_element {
    public:
    attack_details() :
        attack_protocol(0), attack_power(0), max_attack_power(0), average_in_bytes(0), average_out_bytes(0), average_in_packets(0), average_out_packets(0), average_in_flows(0), average_out_flows(0) {
    }    
    direction attack_direction;
    // first attackpower detected
    uint64_t attack_power;
    // max attack power
    uint64_t max_attack_power;
    unsigned int attack_protocol;

    // Average counters
    uint64_t average_in_bytes;
    uint64_t average_out_bytes;
    uint64_t average_in_packets;
    uint64_t average_out_packets;
    uint64_t average_in_flows;
    uint64_t average_out_flows;

    // time when we but this user
    time_t   ban_timestamp;
    int      ban_time; // seconds of the ban
};

typedef attack_details banlist_item;


// struct for save per direction and per protocol details for flow
typedef struct {
    uint64_t bytes;
    uint64_t packets;
    // will be used for Garbage Collection
    time_t   last_update_time;
} conntrack_key_struct;

typedef uint64_t packed_session;
// Main mega structure for storing conntracks
// We should use class instead struct for correct std::map allocation
typedef std::map<packed_session, conntrack_key_struct> contrack_map_type;

class conntrack_main_struct {
public:
    contrack_map_type in_tcp;
    contrack_map_type in_udp;
    contrack_map_type in_icmp;
    contrack_map_type in_other;

    contrack_map_type out_tcp;
    contrack_map_type out_udp;
    contrack_map_type out_icmp;
    contrack_map_type out_other;
};

typedef std::map <uint32_t, map_element> map_for_counters;
typedef std::vector<map_element> vector_of_counters;

typedef std::map <unsigned long int, vector_of_counters> map_of_vector_counters;

map_of_vector_counters SubnetVectorMap;

// Flow tracking structures
typedef std::vector<conntrack_main_struct> vector_of_flow_counters;
typedef std::map <unsigned long int, vector_of_flow_counters> map_of_vector_counters_for_flow;
map_of_vector_counters_for_flow SubnetVectorMapFlow;

class packed_conntrack_hash {
public:
    packed_conntrack_hash() : opposite_ip(0), src_port(0), dst_port(0) { } 
    // src or dst IP 
    uint32_t opposite_ip;
    uint16_t src_port;
    uint16_t dst_port;
};


// data structure for storing data in Vector
typedef std::pair<uint32_t, map_element> pair_of_map_elements;

/* End of our data structs */

boost::mutex data_counters_mutex;
boost::mutex speed_counters_mutex;
boost::mutex total_counters_mutex;

boost::mutex ban_list_details_mutex;

boost::mutex ban_list_mutex;
boost::mutex flow_counter;

#ifdef REDIS
redisContext *redis_context = NULL;
#endif

// map for flows
std::map<uint64_t, int> FlowCounter;

// Struct for string speed per IP
map_for_counters SpeedCounter;

// Struct for storing average speed per IP for specified interval 
map_for_counters SpeedCounterAverage;

#ifdef GEOIP
map_for_counters GeoIpCounter;
#endif

// In ddos info we store attack power and direction
std::map<uint32_t, banlist_item> ban_list;
std::map<uint32_t, std::vector<simple_packet> > ban_list_details;

std::vector<subnet> our_networks;
std::vector<subnet> whitelist_networks;

// Ban enable/disable flag
bool we_do_real_ban = true;

bool process_incoming_traffic = true;
bool process_outgoing_traffic = true;

// Prototypes
#ifdef HWFILTER_LOCKING
void block_all_traffic_with_82599_hardware_filtering(std::string client_ip_as_string);
#endif

std::string get_net_address_from_network_as_string(std::string network_cidr_format);
unsigned int get_max_used_protocol(uint64_t tcp, uint64_t udp, uint64_t icmp);
std::string get_printable_protocol_name(unsigned int protocol);
void print_attack_details_to_file(std::string details, std::string client_ip_as_string,  attack_details current_attack);
bool folder_exists(std::string path);
std::string print_time_t_in_fastnetmon_format(time_t current_time);
std::string print_ban_thresholds();
bool load_configuration_file();
std::string print_flow_tracking_for_ip(conntrack_main_struct& conntrack_element, std::string client_ip);
void convert_integer_to_conntrack_hash_struct(packed_session* packed_connection_data, packed_conntrack_hash* unpacked_data);
uint64_t convert_conntrack_hash_struct_to_integer(packed_conntrack_hash* struct_value);
int timeval_subtract (struct timeval * result, struct timeval * x,  struct timeval * y);
bool is_cidr_subnet(const char* subnet);
uint64_t MurmurHash64A (const void * key, int len, uint64_t seed);
void cleanup_ban_list();
std::string print_tcp_flags(uint8_t flag_value);
int extract_bit_value(uint8_t num, int bit);
std::string get_attack_description(uint32_t client_ip, attack_details& current_attack);
uint64_t convert_speed_to_mbps(uint64_t speed_in_bps);
void send_attack_details(uint32_t client_ip, attack_details current_attack_details);
std::string convert_timeval_to_date(struct timeval tv);
void free_up_all_resources();
unsigned int get_cidr_mask_from_network_as_string(std::string network_cidr_format);
std::string print_ddos_attack_details();
void execute_ip_ban(uint32_t client_ip, map_element new_speed_element, uint64_t in_pps, uint64_t out_pps, uint64_t in_bps, uint64_t out_bps, uint64_t in_flows, uint64_t out_flows, std::string flow_attack_details);
direction get_packet_direction(uint32_t src_ip, uint32_t dst_ip, unsigned long& subnet);
void recalculate_speed();
std::string print_channel_speed(std::string traffic_type, direction packet_direction);
void process_packet(simple_packet& current_packet);
void copy_networks_from_string_form_to_binary(std::vector<std::string> networks_list_as_string, std::vector<subnet>& our_networks);

bool file_exists(std::string path);
void traffic_draw_programm();
void ulog_main_loop();
void signal_handler(int signal_number);
uint32_t convert_cidr_to_binary_netmask(unsigned int cidr);

/* Class for custom comparison fields by different fields */
class TrafficComparatorClass {
    private:
        sort_type sort_field;
        direction sort_direction;
    public:    
        TrafficComparatorClass(direction sort_direction, sort_type sort_field) {
            this->sort_field = sort_field;
            this->sort_direction = sort_direction;
        }

        bool operator()(pair_of_map_elements a, pair_of_map_elements b) {
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

std::string get_direction_name(direction direction_value) {
    std::string direction_name; 

    switch (direction_value) {
        case INCOMING: direction_name = "incoming"; break;
        case OUTGOING: direction_name = "outgoing"; break;
        case INTERNAL: direction_name = "internal"; break;
        case OTHER:    direction_name = "other";    break;
        default:       direction_name = "unknown";  break;
    }   

    return direction_name;
}

uint32_t convert_ip_as_string_to_uint(std::string ip) {
    struct in_addr ip_addr;
    inet_aton(ip.c_str(), &ip_addr);

    // in network byte order
    return ip_addr.s_addr;
}

std::string convert_ip_as_uint_to_string(uint32_t ip_as_integer) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ip_as_integer;
    return (std::string)inet_ntoa(ip_addr);
}

// convert integer to string
std::string convert_int_to_string(int value) {
    std::stringstream out;
    out << value;

    return out.str();
}

// convert string to integer
int convert_string_to_integer(std::string line) {
    return atoi(line.c_str());
}

// exec command in shell
std::vector<std::string> exec(std::string cmd) {
    std::vector<std::string> output_list;

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return output_list;

    char buffer[256];
    std::string result = "";
    while(!feof(pipe)) {
        if(fgets(buffer, 256, pipe) != NULL) {
            size_t newbuflen = strlen(buffer);
            
            // remove newline at the end
            if (buffer[newbuflen - 1] == '\n') {
                buffer[newbuflen - 1] = '\0';
            }

            output_list.push_back(buffer);
        }
    }

    pclose(pipe);
    return output_list;
}

// exec command and pass data to it stdin
bool exec_with_stdin_params(std::string cmd, std::string params) {
    FILE* pipe = popen(cmd.c_str(), "w");
    if (!pipe) {
        logger<<log4cpp::Priority::ERROR<<"Can't execute programm "<<cmd<<" error code: "<<errno<<" error text: "<<strerror(errno);
        return false;
    }

    if (fputs(params.c_str(), pipe)) {
        fclose(pipe);
        return true;
    } else {
        logger<<log4cpp::Priority::ERROR<<"Can't pass data to stdin of programm "<<cmd;
        fclose(pipe);
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
bool redis_init_connection() {
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    redis_context = redisConnectWithTimeout(redis_host.c_str(), redis_port, timeout);
    if (redis_context->err) {
        logger<<log4cpp::Priority::INFO<<"Connection error:"<<redis_context->errstr;
        return false;
    }

    // We should check connection with ping because redis do not check connection
    redisReply* reply = (redisReply*)redisCommand(redis_context, "PING");
    if (reply) {
        freeReplyObject(reply);
    } else {
        return false;
    }

    return true;
}

void update_traffic_in_redis(uint32_t ip, unsigned int traffic_bytes, direction my_direction) {
    std::string ip_as_string = convert_ip_as_uint_to_string(ip);
    redisReply *reply;

    if (!redis_context) {
        logger<< log4cpp::Priority::INFO<<"Please initialize Redis handle";
        return;
    }

    std::string key_name = ip_as_string + "_" + get_direction_name(my_direction);
    reply = (redisReply *)redisCommand(redis_context, "INCRBY %s %s", key_name.c_str(), convert_int_to_string(traffic_bytes).c_str());

    // If we store data correctly ...
    if (!reply) {
        logger.error("Can't increment traffic in redis error_code: %d error_string: %s", redis_context->err, redis_context->errstr);
   
        // Handle redis server restart corectly
        if (redis_context->err == 1 or redis_context->err == 3) {
            // Connection refused            
            redis_init_connection();
        }
    } else {
        freeReplyObject(reply); 
    }
}
#endif

std::string draw_table(map_for_counters& my_map_packets, direction data_direction, bool do_redis_update, sort_type sort_item) {
    std::vector<pair_of_map_elements> vector_for_sort;

    std::stringstream output_buffer;

    // Preallocate memory for sort vector
    vector_for_sort.reserve(my_map_packets.size());

    for( map_for_counters::iterator ii = my_map_packets.begin(); ii != my_map_packets.end(); ++ii) {
        // store all elements into vector for sorting
        vector_for_sort.push_back( std::make_pair((*ii).first, (*ii).second) );
    } 
 
    if (data_direction == INCOMING or data_direction == OUTGOING) {
        std::sort( vector_for_sort.begin(), vector_for_sort.end(), TrafficComparatorClass(data_direction, sort_item));
    } else {
        logger<< log4cpp::Priority::ERROR<<"Unexpected bahaviour on sort function";
        return "Internal error";
    }

    unsigned int element_number = 0;
    // TODO: fix this code because iteraton over over millions of IPs is very CPU intensive
    for( std::vector<pair_of_map_elements>::iterator ii=vector_for_sort.begin(); ii!=vector_for_sort.end(); ++ii) {
        uint32_t client_ip = (*ii).first;
        std::string client_ip_as_string = convert_ip_as_uint_to_string((*ii).first);

        uint64_t pps = 0; 
        uint64_t bps = 0;
        uint64_t flows = 0;

        uint64_t pps_average = 0;
        uint64_t bps_average = 0;
        uint64_t flows_average = 0;  

        // TODO: replace map by vector iteration 
        map_element* current_average_speed_element = &SpeedCounterAverage[client_ip];
        map_element* current_speed_element         = &SpeedCounter[client_ip];
 
        // Create polymorphic pps, byte and flow counters
        if (data_direction == INCOMING) {
            pps   = current_speed_element->in_packets;
            bps   = current_speed_element->in_bytes;
            flows = current_speed_element->in_flows;
       
            pps_average   = current_average_speed_element->in_packets;
            bps_average   = current_average_speed_element->in_bytes;
            flows_average = current_average_speed_element->in_flows;
        } else if (data_direction == OUTGOING) {
            pps   = current_speed_element->out_packets;
            bps   = current_speed_element->out_bytes;
            flows = current_speed_element->out_flows;
    
            pps_average = current_average_speed_element->out_packets;
            bps_average = current_average_speed_element->out_bytes;
            flows_average = current_average_speed_element->out_flows;
        }    

        uint64_t mbps = convert_speed_to_mbps(bps);
        uint64_t mbps_average = convert_speed_to_mbps(bps_average);

        // Print first max_ips_in_list elements in list, we will show top 20 "huge" channel loaders
        if (element_number < max_ips_in_list) {
            std::string is_banned = ban_list.count(client_ip) > 0 ? " *banned* " : "";
            // We use setw for alignment
            output_buffer<<client_ip_as_string << "\t\t";

            if (print_average_traffic_counts) {
                output_buffer<<std::setw(6)<<pps_average   << " pps ";
                output_buffer<<std::setw(6)<<mbps_average  << " mbps ";
                output_buffer<<std::setw(6)<<flows_average << " flows ";
            } else {
                output_buffer<<std::setw(6)<< pps   <<" pps ";
                output_buffer<<std::setw(6)<< mbps  <<" mbps ";
                output_buffer<<std::setw(6)<< flows <<" flows ";
            }

            output_buffer<< is_banned << std::endl;
        }  
   
#ifdef REDIS 
        if (redis_enabled && do_redis_update) {
            update_traffic_in_redis( (*ii).first, (*ii).second.in_packets, INCOMING);
            update_traffic_in_redis( (*ii).first, (*ii).second.out_packets, OUTGOING);
        }
#endif
        
        element_number++;
    }

    return output_buffer.str(); 
}

// check file existence
bool file_exists(std::string path) {
    FILE* check_file = fopen(path.c_str(), "r");
    if (check_file) {
        fclose(check_file);
        return true;
    } else {
        return false;
    }
}

// read whole file to vector
std::vector<std::string> read_file_to_vector(std::string file_name) {
    std::vector<std::string> data;
    std::string line;

    std::ifstream reading_file;

    reading_file.open(file_name.c_str(), std::ifstream::in);
    if (reading_file.is_open()) {
        while ( getline(reading_file, line) ) {
            data.push_back(line); 
        }
    } else {
        logger<< log4cpp::Priority::ERROR <<"Can't open file: "<<file_name;
    }

    return data;
}

// Load configuration
bool load_configuration_file() {
    std::ifstream config_file (global_config_path.c_str());
    std::string line;

    if (!config_file.is_open()) {
        logger<< log4cpp::Priority::ERROR<<"Can't open config file";
        return false;
    }

    while ( getline(config_file, line) ) {
        std::vector<std::string> parsed_config; 
        boost::split( parsed_config, line, boost::is_any_of(" ="), boost::token_compress_on );

        if (parsed_config.size() == 2) {
            configuration_map[ parsed_config[0] ] = parsed_config[1];
        } else {
            logger<< log4cpp::Priority::ERROR<<"Can't parse config line: '"<<line<<"'";
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
        standard_ban_time = convert_string_to_integer(configuration_map["ban_time"]);
    }

    if (configuration_map.count("average_calculation_time") != 0) {
        average_calculation_amount = convert_string_to_integer(configuration_map["average_calculation_time"]);
    }

    if (configuration_map.count("threshold_pps") != 0) {
        ban_threshold_pps = convert_string_to_integer( configuration_map[ "threshold_pps" ] );
    }

    if (configuration_map.count("threshold_mbps") != 0) {
        ban_threshold_mbps = convert_string_to_integer(  configuration_map[ "threshold_mbps" ] );
    }

    if (configuration_map.count("threshold_flows") != 0) {
        ban_threshold_flows = convert_string_to_integer(  configuration_map[ "threshold_flows" ] );
    }

    if (configuration_map.count("enable_ban") != 0) {
        if (configuration_map["enable_ban"] == "on") {
            we_do_real_ban = true;
        } else {
            we_do_real_ban = false;
        }
    }

    if (configuration_map.count("sflow") != 0) {
        if (configuration_map[ "sflow" ] == "on") {
            enable_sflow_collection = true;
        } else {
            enable_sflow_collection = false;
        }
    }

    if (configuration_map.count("netflow") != 0) {
        if (configuration_map[ "netflow" ] == "on") {
            enable_netflow_collection = true;
        } else {
            enable_netflow_collection = false;
        }
    }

    if (configuration_map.count("process_incoming_traffic") != 0) {
        process_incoming_traffic = configuration_map[ "process_incoming_traffic" ] == "on" ? true : false;
    }

    if (configuration_map.count("process_outgoing_traffic") != 0) {
        process_outgoing_traffic = configuration_map[ "process_outgoing_traffic" ] == "on" ? true : false;
    }

    if (configuration_map.count("mirror") != 0) { 
        if (configuration_map["mirror"] == "on") {
            enable_data_collection_from_mirror = true;
        } else {
            enable_data_collection_from_mirror = false;
        }
    }

    if (configuration_map.count("pcap") != 0) {
        if (configuration_map["pcap"] == "on") {
            enable_pcap_collection = true;
        } else {
            enable_pcap_collection = false;
        }
    }

    if (configuration_map.count("ban_for_pps") != 0) {
        if (configuration_map["ban_for_pps"] == "on") {
            enable_ban_for_pps = true;
        } else {
            enable_ban_for_pps = false;
        }
    }

    if (configuration_map.count("ban_for_bandwidth") != 0) { 
        if (configuration_map["ban_for_bandwidth"] == "on") {
            enable_ban_for_bandwidth = true;
        } else {
            enable_ban_for_bandwidth = false;
        }    
    }    

    if (configuration_map.count("ban_for_flows") != 0) { 
        if (configuration_map["ban_for_flows"] == "on") {
            enable_ban_for_flows_per_second = true;
        } else {
            enable_ban_for_flows_per_second = false;
        }    
    }    

#ifdef REDIS
    if (configuration_map.count("redis_port") != 0) { 
        redis_port = convert_string_to_integer(configuration_map[ "redis_port" ] );
    }

    if (configuration_map.count("redis_host") != 0) {
        redis_host = configuration_map[ "redis_host" ];
    }

    if (configuration_map.count("redis_enabled") != 0) {
        if (configuration_map[ "redis_enabled" ] == "yes") {
            redis_enabled = true;
        } else {
            redis_enabled = false;
        } 
    }
#endif

    if (configuration_map.count("ban_details_records_count") != 0 ) {
        ban_details_records_count = convert_string_to_integer( configuration_map[ "ban_details_records_count" ]);
    }

    if (configuration_map.count("check_period") != 0) {
        check_period = convert_string_to_integer( configuration_map[ "check_period" ]);
    }

    if (configuration_map.count("sort_parameter") != 0) {
        sort_parameter = configuration_map[ "sort_parameter" ];
    }

    if (configuration_map.count("max_ips_in_list") != 0) {
        max_ips_in_list = convert_string_to_integer( configuration_map[ "max_ips_in_list" ]);
    }

    if (configuration_map.count("notify_script_path") != 0 ) {
        notify_script_path = configuration_map[ "notify_script_path" ];
    }

    return true;
}

/* Enable core dumps for simplify debug tasks */
void enable_core_dumps() {
    struct rlimit rlim;

    int result = getrlimit(RLIMIT_CORE, &rlim);

    if (result) {
        logger<< log4cpp::Priority::ERROR<<"Can't get current rlimit for RLIMIT_CORE";
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
    int network_size_in_ips = pow(base, 32-bitlen);
    //logger<< log4cpp::Priority::INFO<<"Subnet: "<<prefix->add.sin.s_addr<<" network size: "<<network_size_in_ips;
    logger<< log4cpp::Priority::INFO<<"I will allocate "<<network_size_in_ips<<" records for subnet "<<subnet_as_integer<<" cidr mask: "<<bitlen;

    // Initialize map element
    SubnetVectorMap[subnet_as_integer] = vector_of_counters(network_size_in_ips);

    // Zeroify all vector elements
    map_element zero_map_element;
    memset(&zero_map_element, 0, sizeof(zero_map_element));
    std::fill(SubnetVectorMap[subnet_as_integer].begin(), SubnetVectorMap[subnet_as_integer].end(), zero_map_element);

    // Initilize map element
    SubnetVectorMapFlow[subnet_as_integer] = vector_of_flow_counters(network_size_in_ips); 

    // On creating it initilizes by zeros
    conntrack_main_struct zero_conntrack_main_struct;
    std::fill(SubnetVectorMapFlow[subnet_as_integer].begin(), SubnetVectorMapFlow[subnet_as_integer].end(), zero_conntrack_main_struct);
}

void zeroify_all_counters() {
    map_element zero_map_element;
    memset(&zero_map_element, 0, sizeof(zero_map_element));

    for (map_of_vector_counters::iterator itr = SubnetVectorMap.begin(); itr != SubnetVectorMap.end(); itr++) {
        //logger<< log4cpp::Priority::INFO<<"Zeroify "<<itr->first;
        std::fill(itr->second.begin(), itr->second.end(), zero_map_element); 
    }
}

void zeroify_all_flow_counters() {
    // On creating it initilizes by zeros
    conntrack_main_struct zero_conntrack_main_struct;

    // Iterate over map
    for (map_of_vector_counters_for_flow::iterator itr = SubnetVectorMapFlow.begin(); itr != SubnetVectorMapFlow.end(); itr++) {
        // Iterate over vector
        for (vector_of_flow_counters::iterator vector_iterator = itr->second.begin(); vector_iterator != itr->second.end(); vector_iterator++) {
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
    if (file_exists("/etc/networks_whitelist")) {
        std::vector<std::string> network_list_from_config = read_file_to_vector("/etc/networks_whitelist");

        for( std::vector<std::string>::iterator ii=network_list_from_config.begin(); ii!=network_list_from_config.end(); ++ii) {
            if (ii->length() > 0 && is_cidr_subnet(ii->c_str())) {
                make_and_lookup(whitelist_tree, const_cast<char*>(ii->c_str()));
            } else {
                logger<<log4cpp::Priority::ERROR<<"Can't parse line from whitelist: "<<*ii;
            }
        }

        logger<<log4cpp::Priority::INFO<<"We loaded "<<network_list_from_config.size()<< " networks from whitelist file";
    }
 
    std::vector<std::string> networks_list_as_string;
    // We can bould "our subnets" automatically here 
    if (file_exists("/proc/vz/version")) {
        logger<< log4cpp::Priority::INFO<<"We found OpenVZ";
        // Add /32 CIDR mask for every IP here
        std::vector<std::string> openvz_ips = read_file_to_vector("/proc/vz/veip");
        for( std::vector<std::string>::iterator ii=openvz_ips.begin(); ii!=openvz_ips.end(); ++ii) {
            // skip IPv6 addresses
            if (strstr(ii->c_str(), ":") != NULL) {
                continue;
            }

            // skip header
            if (strstr(ii->c_str(), "Version") != NULL) {
                continue;
            }

            std::vector<std::string> subnet_as_string; 
            split( subnet_as_string, *ii, boost::is_any_of(" "), boost::token_compress_on );
 
            std::string openvz_subnet = subnet_as_string[1] + "/32";
            networks_list_as_string.push_back(openvz_subnet);
        }

        logger<<log4cpp::Priority::INFO<<"We loaded "<<networks_list_as_string.size()<< " networks from /proc/vz/version";
    } 

    if (file_exists("/etc/networks_list")) { 
        std::vector<std::string> network_list_from_config = read_file_to_vector("/etc/networks_list");
        networks_list_as_string.insert(networks_list_as_string.end(), network_list_from_config.begin(), network_list_from_config.end());

        logger<<log4cpp::Priority::INFO<<"We loaded "<<network_list_from_config.size()<< " networks from networks file";
    }

    // Some consistency checks
    assert( convert_ip_as_string_to_uint("255.255.255.0")   == convert_cidr_to_binary_netmask(24) );
    assert( convert_ip_as_string_to_uint("255.255.255.255") == convert_cidr_to_binary_netmask(32) );

    for ( std::vector<std::string>::iterator ii=networks_list_as_string.begin(); ii!=networks_list_as_string.end(); ++ii) {
        if (ii->length() == 0) {
            // Skip blank lines in subnet list file silently
            continue;
        }

        if (!is_cidr_subnet(ii->c_str())) { 
            logger<<log4cpp::Priority::ERROR<<"Can't parse line from subnet list: '"<<*ii<<"'";
            continue;
        }
       
        std::string network_address_in_cidr_form = *ii;
  
        unsigned int cidr_mask = get_cidr_mask_from_network_as_string(network_address_in_cidr_form);
        std::string network_address = get_net_address_from_network_as_string(network_address_in_cidr_form);

        double base = 2;
        total_number_of_hosts_in_our_networks += pow(base, 32-cidr_mask);

        // Make sure it's "subnet address" and not an host address
        uint32_t subnet_address_as_uint = convert_ip_as_string_to_uint(network_address);            
        uint32_t subnet_address_netmask_binary = convert_cidr_to_binary_netmask(cidr_mask); 
        uint32_t generated_subnet_address = subnet_address_as_uint & subnet_address_netmask_binary;

        if (subnet_address_as_uint != generated_subnet_address) {
            std::string new_network_address_as_string
                = convert_ip_as_uint_to_string(generated_subnet_address) + "/" + convert_int_to_string(cidr_mask); 

            logger<<log4cpp::Priority::WARN<<"We will use "<<new_network_address_as_string
                <<" instead of "<<network_address_in_cidr_form<<" because it's host address";
    
            network_address_in_cidr_form = new_network_address_as_string;
        }

        make_and_lookup(lookup_tree, const_cast<char*>(network_address_in_cidr_form.c_str()));
    }    

    /* Preallocate data structures */

    patricia_process (lookup_tree, (void_fn_t)subnet_vectors_allocator);

    logger<<log4cpp::Priority::INFO<<"We start total zerofication of counters";
    zeroify_all_counters();
    logger<<log4cpp::Priority::INFO<<"We finished zerofication";

    logger<<log4cpp::Priority::INFO<<"We loaded "<<networks_list_as_string.size()<<" subnets to our in-memory list of networks";
    logger<<log4cpp::Priority::INFO<<"Total number of monitored hosts (total size of all networks): "
        <<total_number_of_hosts_in_our_networks;

    return true;
}

// extract 24 from 192.168.1.1/24
unsigned int get_cidr_mask_from_network_as_string(std::string network_cidr_format) {
    std::vector<std::string> subnet_as_string; 
    split( subnet_as_string, network_cidr_format, boost::is_any_of("/"), boost::token_compress_on );

    if (subnet_as_string.size() != 2) {
        return 0;
    }

    return convert_string_to_integer(subnet_as_string[1]);
}

// extract 192.168.1.1 from 192.168.1.1/24
std::string get_net_address_from_network_as_string(std::string network_cidr_format) {
    std::vector<std::string> subnet_as_string;
    split( subnet_as_string, network_cidr_format, boost::is_any_of("/"), boost::token_compress_on );

    if (subnet_as_string.size() != 2) {
        return 0;
    }

    return subnet_as_string[0];
}

void copy_networks_from_string_form_to_binary(std::vector<std::string> networks_list_as_string, std::vector<subnet>& our_networks ) {
    for( std::vector<std::string>::iterator ii=networks_list_as_string.begin(); ii!=networks_list_as_string.end(); ++ii) {
        std::vector<std::string> subnet_as_string; 
        split( subnet_as_string, *ii, boost::is_any_of("/"), boost::token_compress_on );
        unsigned int cidr = convert_string_to_integer(subnet_as_string[1]);

        uint32_t subnet_as_int  = convert_ip_as_string_to_uint(subnet_as_string[0]);
        uint32_t netmask_as_int = convert_cidr_to_binary_netmask(cidr);

        subnet current_subnet = std::make_pair(subnet_as_int, netmask_as_int);

        our_networks.push_back(current_subnet);
    }  
} 

uint32_t convert_cidr_to_binary_netmask(unsigned int cidr) {
    uint32_t binary_netmask = 0xFFFFFFFF; 
    binary_netmask = binary_netmask << ( 32 - cidr );
    // htonl from host byte order to network
    // ntohl from network byte order to host

    // We need network byte order at output 
    return htonl(binary_netmask);
}

std::string get_printable_protocol_name(unsigned int protocol) {
    std::string proto_name;

    switch (protocol) {
        case IPPROTO_TCP:
            proto_name = "tcp";
            break;
        case IPPROTO_UDP:
            proto_name = "udp";
            break;
        case IPPROTO_ICMP:
            proto_name = "icmp";
            break;
        default:
            proto_name = "unknown";
            break;
    } 

    return proto_name;
}

std::string print_simple_packet(simple_packet packet) {
    std::stringstream buffer;

    buffer<<convert_timeval_to_date(packet.ts)<<" ";

    buffer
        <<convert_ip_as_uint_to_string(packet.src_ip)<<":"<<packet.source_port
        <<" > "
        <<convert_ip_as_uint_to_string(packet.dst_ip)<<":"<<packet.destination_port
        <<" protocol: "<<get_printable_protocol_name(packet.protocol);
   
    // Print flags only for TCP 
    if (packet.protocol == IPPROTO_TCP) { 
        buffer<<" flags: "<<print_tcp_flags(packet.flags);
    }

    buffer<<" ";
    buffer<<"packets: "     <<packet.number_of_packets  <<" ";
    buffer<<"size: "        <<packet.length             <<" bytes ";
    buffer<<"sample ratio: "<<packet.sample_ratio       <<" ";

    buffer<<" \n";
    
    return buffer.str();
}

/* Process simple unified packet */
void process_packet(simple_packet& current_packet) { 
    // Packets dump is very useful for bug hunting
    if (DEBUG_DUMP_ALL_PACKETS) {
        logger<< log4cpp::Priority::INFO<<"Dump: "<<print_simple_packet(current_packet);
    }

    // Subnet for found IPs
    unsigned long subnet = 0;
    direction packet_direction = get_packet_direction(current_packet.src_ip, current_packet.dst_ip, subnet);

    // Skip processing of specific traffic direction
    if ( (packet_direction == INCOMING && !process_incoming_traffic) or (packet_direction == OUTGOING && !process_outgoing_traffic) ) {
        return;
    }

    uint32_t subnet_in_host_byte_order = 0;
    // We operate in host bytes order and need to convert subnet
    if (subnet != 0) {
        subnet_in_host_byte_order = ntohl(subnet);
    }

    // Try to find map key for this subnet
    map_of_vector_counters::iterator itr;

    if (packet_direction == OUTGOING or packet_direction == INCOMING) {
        itr = SubnetVectorMap.find(subnet);

        if (itr == SubnetVectorMap.end()) {
            logger<< log4cpp::Priority::ERROR<<"Can't find vector address in subnet map";
            return; 
        }
    }

    map_of_vector_counters_for_flow::iterator itr_flow;

    if (enable_conection_tracking) {
        if (packet_direction == OUTGOING or packet_direction == INCOMING) {
            itr_flow = SubnetVectorMapFlow.find(subnet);

            if (itr_flow == SubnetVectorMapFlow.end()) {
                logger<< log4cpp::Priority::ERROR<<"Can't find vector address in subnet flow map";
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
     
    uint32_t sampled_number_of_packets = current_packet.number_of_packets * current_packet.sample_ratio;
    uint32_t sampled_number_of_bytes   = current_packet.length            * current_packet.sample_ratio;

    __sync_fetch_and_add(&total_counters[packet_direction].packets, sampled_number_of_packets);
    __sync_fetch_and_add(&total_counters[packet_direction].bytes,   sampled_number_of_bytes);
    
    // Incerementi main and per protocol packet counters
    if (packet_direction == OUTGOING) {
        int64_t shift_in_vector = (int64_t)ntohl(current_packet.src_ip) - (int64_t)subnet_in_host_byte_order;

        if (shift_in_vector < 0 or shift_in_vector >= itr->second.size()) {
            logger<< log4cpp::Priority::ERROR<<"We tried to access to element with index "<<shift_in_vector
                <<" which located outside allocated vector with size "<<itr->second.size();
            
            logger<< log4cpp::Priority::ERROR<<"We expect issues with this packet in OUTGOING direction: "<<print_simple_packet(current_packet);

            return;
        } 

        map_element* current_element = &itr->second[shift_in_vector];

        // Main packet/bytes counter
        __sync_fetch_and_add(&current_element->out_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element->out_bytes,   sampled_number_of_bytes);

        conntrack_main_struct* current_element_flow = NULL;
        if (enable_conection_tracking) {
            current_element_flow = &itr_flow->second[shift_in_vector]; 
        }

        // Collect data when ban client
        if  (ban_list_details.size() > 0 && ban_list_details.count(current_packet.src_ip) > 0 &&
            ban_list_details[current_packet.src_ip].size() < ban_details_records_count) {

            ban_list_details_mutex.lock();
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
            __sync_fetch_and_add(&current_element->tcp_out_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->tcp_out_bytes,   sampled_number_of_bytes);    

            if (enable_conection_tracking) {
                flow_counter.lock();
                conntrack_key_struct* conntrack_key_struct_ptr = &current_element_flow->out_tcp[connection_tracking_hash];
 
                conntrack_key_struct_ptr->packets += sampled_number_of_packets;
                conntrack_key_struct_ptr->bytes   += sampled_number_of_bytes;

                flow_counter.unlock();
            }
        } else if (current_packet.protocol == IPPROTO_UDP) {    
            __sync_fetch_and_add(&current_element->udp_out_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->udp_out_bytes,   sampled_number_of_bytes);

            if (enable_conection_tracking) {
                flow_counter.lock();
                conntrack_key_struct* conntrack_key_struct_ptr = &current_element_flow->out_udp[connection_tracking_hash];

                conntrack_key_struct_ptr->packets += sampled_number_of_packets;
                conntrack_key_struct_ptr->bytes   += sampled_number_of_bytes;
 
                flow_counter.unlock();
            }
        } else if (current_packet.protocol == IPPROTO_ICMP) {
            __sync_fetch_and_add(&current_element->icmp_out_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->icmp_out_bytes,   sampled_number_of_bytes);
            // no flow tracking for icmp
        } else {

        } 

    } else if (packet_direction == INCOMING) {
        int64_t shift_in_vector = (int64_t)ntohl(current_packet.dst_ip) - (int64_t)subnet_in_host_byte_order;

        if (shift_in_vector < 0 or shift_in_vector >= itr->second.size()) {
            logger<< log4cpp::Priority::ERROR<<"We tried to access to element with index "<<shift_in_vector
                <<" which located outside allocated vector with size "<<itr->second.size();

            logger<< log4cpp::Priority::INFO<<"We expect issues with this packet in INCOMING direction: "<<print_simple_packet(current_packet);

            return;
        }

        map_element* current_element = &itr->second[shift_in_vector];
   
        // Main packet/bytes counter 
        __sync_fetch_and_add(&current_element->in_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element->in_bytes,   sampled_number_of_bytes);

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
        if  (ban_list_details.size() > 0 && ban_list_details.count(current_packet.dst_ip) > 0 &&
            ban_list_details[current_packet.dst_ip].size() < ban_details_records_count) {

            ban_list_details_mutex.lock();
            ban_list_details[current_packet.dst_ip].push_back(current_packet);
            ban_list_details_mutex.unlock();
        }

        if (current_packet.protocol == IPPROTO_TCP) {
            __sync_fetch_and_add(&current_element->tcp_in_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->tcp_in_bytes,   sampled_number_of_bytes);

            if (enable_conection_tracking) {
                flow_counter.lock();
                conntrack_key_struct* conntrack_key_struct_ptr = &current_element_flow->in_tcp[connection_tracking_hash];

                conntrack_key_struct_ptr->packets += sampled_number_of_packets;
                conntrack_key_struct_ptr->bytes   += sampled_number_of_bytes;

                flow_counter.unlock();
            }
        } else if (current_packet.protocol == IPPROTO_UDP) {
            __sync_fetch_and_add(&current_element->udp_in_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->udp_in_bytes,   sampled_number_of_bytes);

            if (enable_conection_tracking) {
                flow_counter.lock();
                conntrack_key_struct* conntrack_key_struct_ptr = &current_element_flow->in_udp[connection_tracking_hash];

                conntrack_key_struct_ptr->packets += sampled_number_of_packets;
                conntrack_key_struct_ptr->bytes   += sampled_number_of_bytes;
                flow_counter.unlock();
            }
        } else if (current_packet.protocol == IPPROTO_ICMP) {
            __sync_fetch_and_add(&current_element->icmp_in_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->icmp_in_bytes,   sampled_number_of_bytes);

             // no flow tarcking for icmp
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
        split( asn_as_string, asn_raw, boost::is_any_of(" "), boost::token_compress_on );

        // free up original string
        free(asn_raw);

        // extract raw number
        asn_number = convert_string_to_integer(asn_as_string[0].substr(2)); 
    }
 
    return asn_number;
}
#endif 

// void* void* data
// It's not an calculation thread, it's vizualization thread :)
void calculation_thread() {
    // we need wait one second for calculating speed by recalculate_speed

    //#include <sys/prctl.h>
    //prctl(PR_SET_NAME , "fastnetmon calc thread", 0, 0, 0);

    // Sleep for a half second for shift against calculatiuon thread
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));

    while (1) {
        // Availible only from boost 1.54: boost::this_thread::sleep_for( boost::chrono::seconds(check_period) );
        boost::this_thread::sleep(boost::posix_time::seconds(check_period));
        traffic_draw_programm();
    }
}

void recalculate_speed_thread_handler() {
    while (1) {
        // recalculate data every one second
        // Availible only from boost 1.54: boost::this_thread::sleep_for( boost::chrono::seconds(1) );
        boost::this_thread::sleep(boost::posix_time::seconds(1));
        recalculate_speed();
    }
}

/* Calculate speed for all connnections */
void recalculate_speed() {
    //logger<< log4cpp::Priority::INFO<<"We run recalculate_speed";

    struct timeval start_calc_time;
    gettimeofday(&start_calc_time, NULL);

    double speed_calc_period = 1;
    time_t start_time;
    time(&start_time);

    // If we got 1+ seconds lag we should use new "delta" or skip this step
    double time_difference = difftime(start_time, last_call_of_traffic_recalculation);

    if (time_difference < 1) {
        // It could occur on programm start
        logger<< log4cpp::Priority::INFO<<"We skip one iteration of speed_calc because it runs so early!";        
        return;
    } else if (int(time_difference) == 1) {
        // All fine, we run on time
    } else {
        logger<< log4cpp::Priority::INFO<<"Time from last run of speed_recalc is soooo big, we got ugly lags: "<<time_difference;
        speed_calc_period = time_difference;
    }

    map_element zero_map_element;
    memset(&zero_map_element, 0, sizeof(zero_map_element));
   
    uint64_t incoming_total_flows = 0;
    uint64_t outgoing_total_flows = 0;
 
    for (map_of_vector_counters::iterator itr = SubnetVectorMap.begin(); itr != SubnetVectorMap.end(); ++itr) {
        for (vector_of_counters::iterator vector_itr = itr->second.begin(); vector_itr !=  itr->second.end(); ++vector_itr) {
            int current_index = vector_itr - itr->second.begin();
            
            // New element
            map_element new_speed_element;

            // convert to host order for math operations
            uint32_t subnet_ip = ntohl(itr->first);
            uint32_t client_ip_in_host_bytes_order = subnet_ip + current_index;

            // covnert to our standard network byte order
            uint32_t client_ip = htonl(client_ip_in_host_bytes_order); 
            
            new_speed_element.in_packets  = uint64_t((double)vector_itr->in_packets   / speed_calc_period);
            new_speed_element.out_packets = uint64_t((double)vector_itr->out_packets  / speed_calc_period);

            new_speed_element.in_bytes  = uint64_t((double)vector_itr->in_bytes  / speed_calc_period);
            new_speed_element.out_bytes = uint64_t((double)vector_itr->out_bytes / speed_calc_period);     

            // By protocol counters

            // TCP
            new_speed_element.tcp_in_packets  = uint64_t((double)vector_itr->tcp_in_packets   / speed_calc_period);
            new_speed_element.tcp_out_packets = uint64_t((double)vector_itr->tcp_out_packets  / speed_calc_period);

            new_speed_element.tcp_in_bytes  = uint64_t((double)vector_itr->tcp_in_bytes  / speed_calc_period);
            new_speed_element.tcp_out_bytes = uint64_t((double)vector_itr->tcp_out_bytes / speed_calc_period);    

            // UDP
            new_speed_element.udp_in_packets  = uint64_t((double)vector_itr->udp_in_packets   / speed_calc_period);
            new_speed_element.udp_out_packets = uint64_t((double)vector_itr->udp_out_packets  / speed_calc_period);

            new_speed_element.udp_in_bytes  = uint64_t((double)vector_itr->udp_in_bytes  / speed_calc_period);
            new_speed_element.udp_out_bytes = uint64_t((double)vector_itr->udp_out_bytes / speed_calc_period); 

            // ICMP
            new_speed_element.icmp_in_packets  = uint64_t((double)vector_itr->icmp_in_packets   / speed_calc_period);
            new_speed_element.icmp_out_packets = uint64_t((double)vector_itr->icmp_out_packets  / speed_calc_period);

            new_speed_element.icmp_in_bytes  = uint64_t((double)vector_itr->icmp_in_bytes  / speed_calc_period);
            new_speed_element.icmp_out_bytes = uint64_t((double)vector_itr->icmp_out_bytes / speed_calc_period);

            conntrack_main_struct* flow_counter_ptr = &SubnetVectorMapFlow[itr->first][current_index]; 

            // todo: optimize this operations!
            uint64_t total_out_flows =
                (uint64_t)flow_counter_ptr->out_tcp.size()  +
                (uint64_t)flow_counter_ptr->out_udp.size()  +
                (uint64_t)flow_counter_ptr->out_icmp.size() +
                (uint64_t)flow_counter_ptr->out_other.size();

            uint64_t total_in_flows =
                (uint64_t)flow_counter_ptr->in_tcp.size()  +
                (uint64_t)flow_counter_ptr->in_udp.size()  +
                (uint64_t)flow_counter_ptr->in_icmp.size() +
                (uint64_t)flow_counter_ptr->in_other.size();

            new_speed_element.out_flows = uint64_t((double)total_out_flows  / speed_calc_period);
            new_speed_element.in_flows  = uint64_t((double)total_in_flows   / speed_calc_period);

            // Increment global counter
            incoming_total_flows += new_speed_element.in_flows;
            outgoing_total_flows += new_speed_element.out_flows;

            /* Moving average recalculation */
            // http://en.wikipedia.org/wiki/Moving_average#Application_to_measuring_computer_performance 
            //double speed_calc_period = 1; 
            double exp_power = -speed_calc_period/average_calculation_amount;
            double exp_value = exp(exp_power);

            map_element* current_average_speed_element = &SpeedCounterAverage[client_ip]; 
 
            current_average_speed_element->in_bytes  = uint64_t(new_speed_element.in_bytes  + exp_value *
                ((double)current_average_speed_element->in_bytes - (double)new_speed_element.in_bytes));
            current_average_speed_element->out_bytes = uint64_t(new_speed_element.out_bytes + exp_value *
                ((double)current_average_speed_element->out_bytes - (double)new_speed_element.out_bytes)); 

            current_average_speed_element->in_packets  = uint64_t(new_speed_element.in_packets  + exp_value *
                ((double)current_average_speed_element->in_packets -  (double)new_speed_element.in_packets));
            current_average_speed_element->out_packets = uint64_t(new_speed_element.out_packets + exp_value *
                ((double)current_average_speed_element->out_packets - (double)new_speed_element.out_packets));

            current_average_speed_element->out_flows = uint64_t(new_speed_element.out_flows + exp_value *
                ((double)current_average_speed_element->out_flows -  (double)new_speed_element.out_flows));
            current_average_speed_element->in_flows = uint64_t(new_speed_element.in_flows + exp_value *
                ((double)current_average_speed_element->in_flows -  (double)new_speed_element.in_flows));

            uint64_t in_pps_average  = current_average_speed_element->in_packets;
            uint64_t out_pps_average = current_average_speed_element->out_packets;

            uint64_t in_bps_average  = current_average_speed_element->in_bytes;
            uint64_t out_bps_average = current_average_speed_element->out_bytes; 

            uint64_t in_flows_average  = current_average_speed_element->in_flows;
            uint64_t out_flows_average = current_average_speed_element->out_flows;

            /* Moving average recalculation end */

            // we detect overspeed by packets
            bool attack_detected_by_pps = false;
            bool attack_detected_by_bandwidth = false;
            bool attack_detected_by_flow = false;

            if (enable_ban_for_pps && (in_pps_average > ban_threshold_pps or out_pps_average > ban_threshold_pps)) {
                attack_detected_by_pps = true;
            }

            // we detect overspeed by bandwidth
            if (enable_ban_for_bandwidth && (convert_speed_to_mbps(in_bps_average) > ban_threshold_mbps or convert_speed_to_mbps(out_bps_average) > ban_threshold_mbps)) {
                attack_detected_by_bandwidth = true;
            }

            if (enable_ban_for_flows_per_second && (in_flows_average > ban_threshold_flows or out_flows_average > ban_threshold_flows)) {
                attack_detected_by_flow = true; 
            } 

            if (attack_detected_by_pps or attack_detected_by_bandwidth or attack_detected_by_flow) {
                std::string flow_attack_details = "";
                
                if (enable_conection_tracking) {
                    flow_attack_details = print_flow_tracking_for_ip(*flow_counter_ptr, convert_ip_as_uint_to_string(client_ip));
                }
        
                // TODO: we should pass type of ddos ban source (pps, flowd, bandwidth)!
                execute_ip_ban(client_ip, new_speed_element, in_pps_average, out_pps_average, in_bps_average, out_bps_average, in_flows_average, out_flows_average, flow_attack_details);
            }
    
            speed_counters_mutex.lock();
            //map_element* current_speed_element = &SpeedCounter[client_ip];
            //*current_speed_element = new_speed_element;
            SpeedCounter[client_ip] = new_speed_element;
            speed_counters_mutex.unlock();

            data_counters_mutex.lock();
            *vector_itr = zero_map_element;
            data_counters_mutex.unlock();
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

    for (unsigned int index = 0; index < 4; index++) {
        total_speed_counters[index].bytes   = uint64_t((double)total_counters[index].bytes   / (double)speed_calc_period);
        total_speed_counters[index].packets = uint64_t((double)total_counters[index].packets / (double)speed_calc_period);

        // nullify data counters after speed calculation
        //total_counters_mutex.lock();
        total_counters[index].bytes = 0; 
        total_counters[index].packets = 0; 
        //total_counters_mutex.unlock();
    }    

    // Set time of previous startup 
    time(&last_call_of_traffic_recalculation);

    struct timeval finish_calc_time;
    gettimeofday(&finish_calc_time, NULL);

    timeval_subtract(&speed_calculation_time, &finish_calc_time, &start_calc_time);
}

void print_screen_contents_into_file(std::string screen_data_stats_param) {
    std::ofstream screen_data_file;
    screen_data_file.open("/tmp/fastnetmon.dat", std::ios::trunc);

    if (screen_data_file.is_open()) {
        screen_data_file<<screen_data_stats_param;
        screen_data_file.close();
    } else {
        logger<<log4cpp::Priority::ERROR<<"Can't print programm screen into file";
    }
}

void traffic_draw_programm() {
    std::stringstream output_buffer;
   
    //logger<<log4cpp::Priority::INFO<<"Draw table call";
 
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
        logger<< log4cpp::Priority::INFO<<"Unexpected sorter type: "<<sort_parameter;
        sorter = PACKETS;
    }

    output_buffer<<"FastNetMon v1.0 FastVPS Eesti OU (c) VPS and dedicated: http://FastVPS.host"<<"\n"
        <<"IPs ordered by: "<<sort_parameter<<"\n";

    output_buffer<<print_channel_speed("Incoming traffic", INCOMING)<<std::endl;
    output_buffer<<draw_table(SpeedCounter, INCOMING, true, sorter);
    
    output_buffer<<std::endl; 
    
    output_buffer<<print_channel_speed("Outgoing traffic", OUTGOING)<<std::endl;
    output_buffer<<draw_table(SpeedCounter, OUTGOING, false, sorter);

    output_buffer<<std::endl;

    output_buffer<<print_channel_speed("Internal traffic", INTERNAL)<<std::endl;

    output_buffer<<std::endl;

    output_buffer<<print_channel_speed("Other traffic", OTHER)<<std::endl;

    output_buffer<<std::endl;

    if (enable_pcap_collection) {
        output_buffer<<get_pcap_stats()<<"\n";
    }

    // Application statistics
    output_buffer<<"Screen updated in:\t\t"<< drawing_thread_execution_time.tv_sec<<" sec "<<drawing_thread_execution_time.tv_usec<<" microseconds\n";
    output_buffer<<"Traffic calculated in:\t\t"<< speed_calculation_time.tv_sec<<" sec "<<speed_calculation_time.tv_usec<<" microseconds\n";
    output_buffer<<"Total amount of not processed packets: "<<total_unparsed_packets<<"\n";

#ifdef PF_RING 
    if (enable_data_collection_from_mirror) { 
        output_buffer<<get_pf_ring_stats();
    }
#endif

    // Print thresholds
    output_buffer<<"\n\n"<<print_ban_thresholds();

    if (!ban_list.empty()) {
        output_buffer<<std::endl<<"Ban list:"<<std::endl;  
        output_buffer<<print_ddos_attack_details();
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
    uint64_t speed_in_pps = total_speed_counters[packet_direction].packets;
    uint64_t speed_in_bps = total_speed_counters[packet_direction].bytes;

    unsigned int number_of_tabs = 1; 
    // We need this for correct alignment of blocks
    if (traffic_type == "Other traffic") {
        number_of_tabs = 2;
    }
 
    std::stringstream stream;
    stream<<traffic_type;

    for (unsigned int i = 0; i < number_of_tabs; i ++ ) {
        stream<<"\t";
    }

    uint64_t speed_in_mbps = convert_speed_to_mbps(speed_in_bps);

    stream<<std::setw(6)<<speed_in_pps<<" pps "<<std::setw(6)<<speed_in_mbps<<" mbps";

    if (traffic_type ==  "Incoming traffic" or traffic_type ==  "Outgoing traffic") {
        if (packet_direction == INCOMING) {
            stream<<" "<<std::setw(6)<<incoming_total_flows_speed<<" flows";
        } else if (packet_direction == OUTGOING) {
            stream<<" "<<std::setw(6)<<outgoing_total_flows_speed<<" flows";
        }
    }
 
    return stream.str();
}    

uint64_t convert_speed_to_mbps(uint64_t speed_in_bps) {
    return uint64_t((double)speed_in_bps / 1024 / 1024 * 8);
}

void init_logging() {
    log4cpp::PatternLayout* layout = new log4cpp::PatternLayout(); 
    layout->setConversionPattern ("%d [%p] %m%n"); 

    log4cpp::Appender *appender = new log4cpp::FileAppender("default", log_file_path);
    appender->setLayout(layout);

    logger.setPriority(log4cpp::Priority::INFO);
    logger.addAppender(appender);
    logger.info("Logger initialized!");
}

bool folder_exists(std::string path) {
    if (access(path.c_str(), 0) == 0) {
        struct stat status;
        stat(path.c_str(), &status);

        if (status.st_mode & S_IFDIR) {
            return true;
        }
    }

    return false;
}

int main(int argc,char **argv) {
    lookup_tree = New_Patricia(32);
    whitelist_tree = New_Patricia(32);

    // nullify total counters
    for (int index = 0; index < 4; index++) {
        total_counters[index].bytes = 0; 
        total_counters[index].packets = 0;

        total_speed_counters[index].bytes = 0;
        total_speed_counters[index].packets = 0; 
    } 

    // enable core dumps
    enable_core_dumps();

    init_logging();

    /* Create folder for attack details */
    if (!folder_exists(attack_details_folder)) {
        int mkdir_result = mkdir(attack_details_folder.c_str(), S_IRWXU);

        if (mkdir_result != 0) {
            logger<<log4cpp::Priority::ERROR<<"Can't create folder for attack details: "<<attack_details_folder;
            exit(1);
        }
    }

    if (getenv("DUMP_ALL_PACKETS") != NULL) {
        DEBUG_DUMP_ALL_PACKETS = true;
    }

    if (sizeof(packed_conntrack_hash) != sizeof(uint64_t) or sizeof(packed_conntrack_hash) != 8) {
        logger<< log4cpp::Priority::INFO<<"Assertion about size of packed_conntrack_hash, it's "<<sizeof(packed_conntrack_hash)<<" instead 8";
        exit(1);
    }
 
    logger<<log4cpp::Priority::INFO<<"Read configuration file";

    bool load_config_result = load_configuration_file();

    if (!load_config_result) {
        fprintf(stderr, "Can't open config file %s, please create it!\n", global_config_path.c_str());
        exit(1);
    }

    logger<< log4cpp::Priority::INFO<<"I need few seconds for collecting data, please wait. Thank you!";

    load_our_networks_list();

    // Setup CTRL+C handler
    signal(SIGINT, signal_handler);

#ifdef REDIS
    // Init redis connection
    if (redis_enabled) {
        if (!redis_init_connection()) {
            logger<< log4cpp::Priority::ERROR<<"Can't establish connection to the redis";
            exit(1);
        }
    }
#endif

#ifdef GEOIP
    // Init GeoIP
    if(!geoip_init()) {
        logger<< log4cpp::Priority::ERROR<<"Can't load geoip tables";
        exit(1);
    } 
#endif
    // Init previous run date
    time(&last_call_of_traffic_recalculation);

    // Run screen draw thread
    boost::thread calc_thread(calculation_thread);

    // start thread for recalculating speed in realtime
    boost::thread recalculate_speed_thread(recalculate_speed_thread_handler);

    // Run banlist cleaner thread 
    boost::thread cleanup_ban_list_thread(cleanup_ban_list);

#ifdef PF_RING
    // pf_ring processing
    boost::thread pfring_process_collector_thread;
    if (enable_data_collection_from_mirror) {
        pfring_process_collector_thread = boost::thread(start_pfring_collection, process_packet);   
    }
#endif

    boost::thread sflow_process_collector_thread; 
    if (enable_sflow_collection) {
        sflow_process_collector_thread = boost::thread(start_sflow_collection, process_packet);
    }

    boost::thread netflow_process_collector_thread;
    if (enable_netflow_collection) {
        netflow_process_collector_thread = boost::thread(start_netflow_collection, process_packet);
    }

    boost::thread pcap_process_collector_thread;
    if (enable_pcap_collection) {
        pcap_process_collector_thread = boost::thread(start_pcap_collection, process_packet);
    }

    if (enable_sflow_collection) {
        sflow_process_collector_thread.join();
    }

    if (enable_data_collection_from_mirror) {
#ifdef PF_RING
        pfring_process_collector_thread.join();
#endif
    }

    recalculate_speed_thread.join();
    calc_thread.join();

    free_up_all_resources();
 
    return 0;
}

void free_up_all_resources() {
#ifdef GEOIP
    // Free up geoip handle 
    GeoIP_delete(geo_ip);
#endif

    Destroy_Patricia(lookup_tree,    (void_fn_t)0);
    Destroy_Patricia(whitelist_tree, (void_fn_t)0);
}

// For correct programm shutdown by CTRL+C
void signal_handler(int signal_number) {

    if (enable_pcap_collection) {
        stop_pcap_collection();
    }

#ifdef PF_RING
    stop_pfring_collection();
#endif

#ifdef REDIS
    if (redis_enabled) {
        redisFree(redis_context);
    }
#endif
    exit(1); 
}

/* Get traffic type: check it belongs to our IPs */
direction get_packet_direction(uint32_t src_ip, uint32_t dst_ip, unsigned long& subnet) {
    direction packet_direction;

    bool our_ip_is_destination = false;
    bool our_ip_is_source = false;

    prefix_t prefix_for_check_adreess;
    prefix_for_check_adreess.family = AF_INET;
    prefix_for_check_adreess.bitlen = 32;

    patricia_node_t* found_patrica_node = NULL;
    prefix_for_check_adreess.add.sin.s_addr = dst_ip;

    unsigned long destination_subnet = 0;
    found_patrica_node = patricia_search_best2(lookup_tree, &prefix_for_check_adreess, 1);

    if (found_patrica_node) {
        our_ip_is_destination = true;
        destination_subnet = found_patrica_node->prefix->add.sin.s_addr;
    }    

    found_patrica_node = NULL;
    prefix_for_check_adreess.add.sin.s_addr = src_ip;

    unsigned long source_subnet = 0;
    found_patrica_node = patricia_search_best2(lookup_tree, &prefix_for_check_adreess, 1);

    if (found_patrica_node) { 
        our_ip_is_source = true;
        source_subnet = found_patrica_node->prefix->add.sin.s_addr;
    } 

    subnet = 0;
    if (our_ip_is_source && our_ip_is_destination) {
        packet_direction = INTERNAL;
    } else if (our_ip_is_source) {
        subnet = source_subnet;
        packet_direction = OUTGOING;
    } else if (our_ip_is_destination) {
        subnet = destination_subnet;
        packet_direction = INCOMING;
    } else {
        packet_direction = OTHER;
    }

    return packet_direction;
}

unsigned int detect_attack_protocol(map_element& speed_element, direction attack_direction) {
    if (attack_direction == INCOMING) {
        return get_max_used_protocol(speed_element.tcp_in_packets, speed_element.udp_in_packets, speed_element.icmp_in_packets);
    } else {
        // OUTGOING
        return get_max_used_protocol(speed_element.tcp_out_packets, speed_element.udp_out_packets, speed_element.icmp_out_packets);    
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

void execute_ip_ban(uint32_t client_ip, map_element speed_element, uint64_t in_pps, uint64_t out_pps, uint64_t in_bps, uint64_t out_bps, uint64_t in_flows, uint64_t out_flows, std::string flow_attack_details) {
    struct attack_details current_attack;
    uint64_t pps = 0;

    direction data_direction;

    if (!we_do_real_ban) {
        logger<<log4cpp::Priority::INFO<<"We do not ban: "<<convert_ip_as_uint_to_string(client_ip)<<" because ban disabled completely";
        return;
    }

    // Detect attack direction with simple heuristic 
    if (abs(int((int)in_pps - (int)out_pps)) < 1000) {
        // If difference between pps speed is so small we should do additional investigation using bandwidth speed 
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

    current_attack.attack_protocol = detect_attack_protocol(speed_element, data_direction);

    if (ban_list.count(client_ip) > 0) {
        if ( ban_list[client_ip].attack_direction != data_direction ) {
            logger<<log4cpp::Priority::INFO<<"We expected very strange situation: attack direction for "
                <<convert_ip_as_uint_to_string(client_ip)<<" was changed";

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

    bool in_white_list = (patricia_search_best2(whitelist_tree, &prefix_for_check_adreess, 1) != NULL);
    
    if (in_white_list) {
        return;
    }  

    std::string data_direction_as_string = get_direction_name(data_direction);

    logger.info("We run execute_ip_ban code with following params in_pps: %d out_pps: %d in_bps: %d out_bps: %d and we decide it's %s attack",
        in_pps, out_pps, in_bps, out_bps, data_direction_as_string.c_str());

    std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
    std::string pps_as_string = convert_int_to_string(pps);

    // Store ban time
    time(&current_attack.ban_timestamp); 
    // set ban time in seconds
    current_attack.ban_time = standard_ban_time;

    // Pass main information about attack
    current_attack.attack_direction = data_direction;
    current_attack.attack_power = pps;
    current_attack.max_attack_power = pps;

    current_attack.in_packets  = in_pps;
    current_attack.out_packets = out_pps;

    current_attack.in_bytes = in_bps;
    current_attack.out_bytes = out_bps;

    // pass flow information
    current_attack.in_flows = in_flows;
    current_attack.out_flows = out_flows;

    current_attack.tcp_in_packets  = speed_element.tcp_in_packets;
    current_attack.udp_in_packets  = speed_element.udp_in_packets;
    current_attack.icmp_in_packets = speed_element.icmp_in_packets;
    
    current_attack.tcp_out_packets = speed_element.tcp_out_packets;
    current_attack.udp_out_packets = speed_element.udp_out_packets;
    current_attack.icmp_out_packets = speed_element.icmp_out_packets;

    current_attack.tcp_out_bytes  = speed_element.tcp_out_bytes;
    current_attack.udp_out_bytes  = speed_element.udp_out_bytes;
    current_attack.icmp_out_bytes = speed_element.icmp_out_bytes;

    current_attack.tcp_in_bytes = speed_element.tcp_in_bytes;
    current_attack.udp_in_bytes = speed_element.udp_in_bytes;
    current_attack.icmp_in_bytes = speed_element.icmp_in_bytes;

    // Add average counters
    map_element* current_average_speed_element = &SpeedCounterAverage[client_ip];
   
    current_attack.average_in_packets = current_average_speed_element->in_packets;
    current_attack.average_in_bytes   = current_average_speed_element->in_bytes;
    current_attack.average_in_flows   = current_average_speed_element->in_flows;

    current_attack.average_out_packets = current_average_speed_element->out_packets;
    current_attack.average_out_bytes   = current_average_speed_element->out_bytes;
    current_attack.average_out_flows   = current_average_speed_element->out_flows;
    
    ban_list_mutex.lock();
    ban_list[client_ip] = current_attack;
    ban_list_mutex.unlock();

    ban_list_details_mutex.lock();
    ban_list_details[client_ip] = std::vector<simple_packet>();
    ban_list_details_mutex.unlock();                         

    logger<<log4cpp::Priority::INFO<<"Attack with direction: " << data_direction_as_string
        << " IP: " << client_ip_as_string << " Power: "<<pps_as_string;
    
#ifdef HWFILTER_LOCKING
    logger<<log4cpp::Priority::INFO<<"We will block traffic to/from this IP with hardware filters";
    block_all_traffic_with_82599_hardware_filtering(client_ip_as_string);
#endif

    std::string full_attack_description = get_attack_description(client_ip, current_attack) + flow_attack_details;
    print_attack_details_to_file(full_attack_description, client_ip_as_string, current_attack);

    if (file_exists(notify_script_path)) {
        std::string script_call_params = notify_script_path + " " + client_ip_as_string + " " + data_direction_as_string + " " + pps_as_string + " attack_details";
        logger<<log4cpp::Priority::INFO<<"Call script for ban client: "<<client_ip_as_string; 

        // We should execute external script in separate thread because any lag in this code will be very distructive 
        boost::thread exec_thread(exec_with_stdin_params, script_call_params, full_attack_description);
        exec_thread.detach();

        logger<<log4cpp::Priority::INFO<<"Script for ban client is finished: "<<client_ip_as_string;
    }    
}

#ifdef HWFILTER_LOCKING
void block_all_traffic_with_82599_hardware_filtering(std::string client_ip_as_string) {
    /* 6 - tcp, 17 - udp, 0 - other (non tcp and non udp) */
    std::vector<int> banned_protocols;
    banned_protocols.push_back(17);
    banned_protocols.push_back(6);
    banned_protocols.push_back(0); 
    
    int rule_number = 10;

    // Iterate over incoming and outgoing direction
    for (int rule_direction = 0; rule_direction < 2; rule_direction++) {
        for (std::vector<int>::iterator banned_protocol = banned_protocols.begin() ;
            banned_protocol != banned_protocols.end(); ++banned_protocol) {

            /* On 82599 NIC we can ban traffic using hardware filtering rules */
        
            // Difference between fie tuple and perfect filters:
            // http://www.ntop.org/products/pf_ring/hardware-packet-filtering/ 

            hw_filtering_rule rule;
            intel_82599_five_tuple_filter_hw_rule *ft_rule;

            ft_rule = &rule.rule_family.five_tuple_rule;

            memset(&rule, 0, sizeof(rule));
            rule.rule_family_type = intel_82599_five_tuple_rule;
            rule.rule_id = rule_number++;
            ft_rule->queue_id = -1; // drop traffic
            ft_rule->proto = *banned_protocol;

            std::string hw_filter_rule_direction = "";
            if (rule_direction == 0) {
                hw_filter_rule_direction = "outgoing";
                ft_rule->s_addr = ntohl(inet_addr(client_ip_as_string.c_str()));
            } else {
                hw_filter_rule_direction = "incoming";
                ft_rule->d_addr = ntohl(inet_addr(client_ip_as_string.c_str()));
            }

            if (pfring_add_hw_rule(pf_ring_descr, &rule) != 0) {
                logger<<log4cpp::Priority::ERROR<<"Can't add hardware filtering rule for protocol: "<<*banned_protocol<<" in direction: "<<hw_filter_rule_direction;
            }

            rule_number ++;
        }
    }
}
#endif
         
/* Thread for cleaning up ban list */
void cleanup_ban_list() {
    // Every X seconds we will run ban list cleaner thread
    int iteration_sleep_time = 600;

    logger<<log4cpp::Priority::INFO<<"Run banlist cleanup thread";

    while (true) {
        // Sleep for ten minutes
        boost::this_thread::sleep(boost::posix_time::seconds(iteration_sleep_time));

        time_t current_time;
        time(&current_time);

        std::map<uint32_t,banlist_item>::iterator itr = ban_list.begin();
        while (itr != ban_list.end()) {
            uint32_t client_ip = (*itr).first;

            double time_difference = difftime(current_time, ((*itr).second).ban_timestamp);
            int ban_time = ((*itr).second).ban_time;

            if (time_difference > ban_time) {
                // Cleanup all data related with this attack
                std::string data_direction_as_string = get_direction_name((*itr).second.attack_direction);
                std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
                std::string pps_as_string = convert_int_to_string((*itr).second.attack_power);

                logger<<log4cpp::Priority::INFO<<"We will unban banned IP: "<<client_ip_as_string<<
                    " because it ban time "<<ban_time<<" seconds is ended";

                ban_list_mutex.lock();
                std::map<uint32_t,banlist_item>::iterator itr_to_erase = itr;
                itr++;

                ban_list.erase(itr_to_erase);
                ban_list_mutex.unlock();

                if (file_exists(notify_script_path)) {
                    std::string script_call_params = notify_script_path + " " + client_ip_as_string + " " +
                        data_direction_as_string + " " + pps_as_string + " unban";
     
                    logger<<log4cpp::Priority::INFO<<"Call script for unban client: "<<client_ip_as_string; 

                    // We should execute external script in separate thread because any lag in this code will be very distructive 
                    boost::thread exec_thread(exec, script_call_params);
                    exec_thread.detach();

                    logger<<log4cpp::Priority::INFO<<"Script for unban client is finished: "<<client_ip_as_string;
                }
            } else {
               itr++; 
            } 
        }
    }
}

std::string print_time_t_in_fastnetmon_format(time_t current_time) {
    struct tm* timeinfo;
    char buffer[80];

    timeinfo = localtime (&current_time);

    strftime (buffer, sizeof(buffer), "%d_%m_%y_%H:%M:%S", timeinfo);

    return std::string(buffer);
}

std::string print_ddos_attack_details() {
    std::stringstream output_buffer;

    for( std::map<uint32_t,banlist_item>::iterator ii=ban_list.begin(); ii!=ban_list.end(); ++ii) {
        uint32_t client_ip = (*ii).first; 

        std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
        std::string pps_as_string = convert_int_to_string(((*ii).second).attack_power);
        std::string max_pps_as_string = convert_int_to_string(((*ii).second).max_attack_power);
        std::string attack_direction = get_direction_name(((*ii).second).attack_direction);

        output_buffer<<client_ip_as_string<<"/"<<max_pps_as_string<<" pps "<<attack_direction<<" at "<<print_time_t_in_fastnetmon_format(ii->second.ban_timestamp)<<std::endl;

        send_attack_details(client_ip, (*ii).second);
    }


    return output_buffer.str();
}

std::string get_attack_description(uint32_t client_ip, attack_details& current_attack) {
    std::stringstream attack_description;

    attack_description
        <<"IP: "<<convert_ip_as_uint_to_string(client_ip)<<"\n"
        <<"Initial attack power: "  <<current_attack.attack_power<<" packets per second\n"
        <<"Peak attack power: "     <<current_attack.max_attack_power<< " packets per second\n"
        <<"Attack direction: "      <<get_direction_name(current_attack.attack_direction)<<"\n"
        <<"Attack protocol: "       <<get_printable_protocol_name(current_attack.attack_protocol)<<"\n"

        <<"Total incoming traffic: "      <<convert_speed_to_mbps(current_attack.in_bytes)<<" mbps\n"
        <<"Total outgoing traffic: "      <<convert_speed_to_mbps(current_attack.out_bytes)<<" mbps\n"
        <<"Total incoming pps: "          <<current_attack.in_packets<<" packets per second\n"
        <<"Total outgoing pps: "          <<current_attack.out_packets<<" packets per second\n"
        <<"Total incoming flows: "        <<current_attack.in_flows<<" flows per second\n"
        <<"Total outgoing flows: "        <<current_attack.out_flows<<" flows per second\n";

    // Add average counters 
    attack_description
        <<"Average incoming traffic: " << convert_speed_to_mbps(current_attack.average_in_bytes)  <<" mbps\n"
        <<"Average outgoing traffic: " << convert_speed_to_mbps(current_attack.average_out_bytes) <<" mbps\n"
        <<"Average incoming pps: "     << current_attack.average_in_packets                       <<" packets per second\n"
        <<"Average outgoing pps: "     << current_attack.average_out_packets                      <<" packets per second\n"
        <<"Average incoming flows: "   << current_attack.average_in_flows                         <<" flows per second\n"
        <<"Average outgoing flows: "   << current_attack.average_out_flows                        <<" flows per second\n";

    attack_description
        <<"Incoming tcp traffic: "      <<convert_speed_to_mbps(current_attack.tcp_in_bytes)<<" mbps\n"
        <<"Outgoing tcp traffic: "      <<convert_speed_to_mbps(current_attack.tcp_out_bytes)<<" mbps\n"
        <<"Incoming tcp pps: "          <<current_attack.tcp_in_packets<<" packets per second\n"
        <<"Outgoing tcp pps: "          <<current_attack.tcp_out_packets<<" packets per second\n"
        <<"Incoming udp traffic: "      <<convert_speed_to_mbps(current_attack.udp_in_bytes)<<" mbps\n"
        <<"Outgoing udp traffic: "      <<convert_speed_to_mbps(current_attack.udp_out_bytes)<<" mbps\n"
        <<"Incoming udp pps: "          <<current_attack.udp_in_packets<<" packets per second\n"
        <<"Outgoing udp pps: "          <<current_attack.udp_out_packets<<" packets per second\n"
        <<"Incoming icmp traffic: "     <<convert_speed_to_mbps(current_attack.icmp_in_bytes)<<" mbps\n"
        <<"Outgoing icmp traffic: "     <<convert_speed_to_mbps(current_attack.icmp_out_bytes)<<" mbps\n"
        <<"Incoming icmp pps: "         <<current_attack.icmp_in_packets<<" packets per second\n"
        <<"Outgoing icmp pps: "         <<current_attack.icmp_out_packets<<" packets per second\n";
 
    return attack_description.str();
}    

std::string get_protocol_name_by_number(unsigned int proto_number) {
    struct protoent* proto_ent = getprotobynumber( proto_number );
    std::string proto_name = proto_ent->p_name;
    return proto_name;
}       

void send_attack_details(uint32_t client_ip, attack_details current_attack_details) {
    std::string pps_as_string = convert_int_to_string(current_attack_details.attack_power);
    std::string attack_direction = get_direction_name(current_attack_details.attack_direction);
    std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);

    // Very strange code but it work in 95% cases 
    if (ban_list_details.count( client_ip ) > 0 && ban_list_details[ client_ip ].size() == ban_details_records_count) {
        std::stringstream attack_details;

        attack_details<<get_attack_description(client_ip, current_attack_details)<<"\n\n";

        std::map<unsigned int, unsigned int> protocol_counter;
        for( std::vector<simple_packet>::iterator iii=ban_list_details[ client_ip ].begin(); iii!=ban_list_details[ client_ip ].end(); ++iii) {
            attack_details<<print_simple_packet( *iii );

            protocol_counter[ iii->protocol ]++;
        }

        std::map<unsigned int, unsigned int>::iterator max_proto = std::max_element(protocol_counter.begin(), protocol_counter.end(), protocol_counter.value_comp());
        attack_details<<"\n"<<"We got more packets ("
            <<max_proto->second
            <<" from "
            << ban_details_records_count
            <<") for protocol: "<< get_protocol_name_by_number(max_proto->first)<<"\n";
        
        logger<<log4cpp::Priority::INFO<<"Attack with direction: "<<attack_direction<<
            " IP: "<<client_ip_as_string<<" Power: "<<pps_as_string<<" traffic sample collected";

        print_attack_details_to_file(attack_details.str(), client_ip_as_string, current_attack_details);

        // Pass attack details to script
        if (file_exists(notify_script_path)) {
            logger<<log4cpp::Priority::INFO<<"Call script for notify about attack details for: "<<client_ip_as_string;

            std::string script_params = notify_script_path + " " + client_ip_as_string + " " + attack_direction  + " " + pps_as_string + " ban";

            // We should execute external script in separate thread because any lag in this code will be very distructive 
            boost::thread exec_with_params_thread(exec_with_stdin_params, script_params, attack_details.str());
            exec_with_params_thread.detach();

            logger<<log4cpp::Priority::INFO<<"Script for notify about attack details is finished: "<<client_ip_as_string;
        } 
        // Remove key and prevent collection new data about this attack
        ban_list_details.erase(client_ip);
    } 
}


std::string convert_timeval_to_date(struct timeval tv) {
    time_t nowtime = tv.tv_sec;
    struct tm *nowtm = localtime(&nowtime);
    
    char tmbuf[64];
    char buf[64];

    strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);

    snprintf(buf, sizeof(buf), "%s.%06ld", tmbuf, tv.tv_usec); 

    return std::string(buf);
}

// http://stackoverflow.com/questions/14528233/bit-masking-in-c-how-to-get-first-bit-of-a-byte
int extract_bit_value(uint8_t num, int bit) {
    if (bit > 0 && bit <= 8) {
        return ( (num >> (bit-1)) & 1 );
    } else {
        return 0;
    }
}

std::string print_tcp_flags(uint8_t flag_value) {
    if (flag_value == 0) {
        return "-";
    }

    // cod from pfring.h
    // (tcp->fin * TH_FIN_MULTIPLIER) + (tcp->syn * TH_SYN_MULTIPLIER) +
    // (tcp->rst * TH_RST_MULTIPLIER) + (tcp->psh * TH_PUSH_MULTIPLIER) +
    // (tcp->ack * TH_ACK_MULTIPLIER) + (tcp->urg * TH_URG_MULTIPLIER);

    /*
        // Required for decoding tcp flags
        #define TH_FIN_MULTIPLIER   0x01
        #define TH_SYN_MULTIPLIER   0x02
        #define TH_RST_MULTIPLIER   0x04
        #define TH_PUSH_MULTIPLIER  0x08
        #define TH_ACK_MULTIPLIER   0x10
        #define TH_URG_MULTIPLIER   0x20
    */

    std::vector<std::string> all_flags;

    if (extract_bit_value(flag_value, 1)) {
        all_flags.push_back("fin");
    }
    
    if (extract_bit_value(flag_value, 2)) {
        all_flags.push_back("syn");
    }   

    if (extract_bit_value(flag_value, 3)) {
        all_flags.push_back("rst");
    }   

    if (extract_bit_value(flag_value, 4)) {
        all_flags.push_back("psh");
    }   

    if (extract_bit_value(flag_value, 5)) {
        all_flags.push_back("ack");
    }    

    if (extract_bit_value(flag_value, 6)) {
        all_flags.push_back("urg");
    }   

    
    std::ostringstream flags_as_string;

    if (all_flags.empty()) {
        return "-";
    }

    // concatenate all vector elements with comma
    std::copy(all_flags.begin(), all_flags.end() - 1, std::ostream_iterator<std::string>(flags_as_string, ","));

    // add last element
    flags_as_string << all_flags.back();
    
    return flags_as_string.str();
}

#define BIG_CONSTANT(x) (x##LLU)

/*

    // calculate hash
    unsigned int seed = 11;
    uint64_t hash = MurmurHash64A(&current_packet, sizeof(current_packet), seed);

*/

// https://code.google.com/p/smhasher/source/browse/trunk/MurmurHash2.cpp
// 64-bit hash for 64-bit platforms
uint64_t MurmurHash64A ( const void * key, int len, uint64_t seed ) {
    const uint64_t m = BIG_CONSTANT(0xc6a4a7935bd1e995);
    const int r = 47;

    uint64_t h = seed ^ (len * m);

    const uint64_t * data = (const uint64_t *)key;
    const uint64_t * end = data + (len/8);

    while(data != end) {
        uint64_t k = *data++;

        k *= m; 
        k ^= k >> r; 
        k *= m; 
    
        h ^= k;
        h *= m; 
    }

    const unsigned char * data2 = (const unsigned char*)data;

    switch(len & 7) {
        case 7: h ^= uint64_t(data2[6]) << 48;
        case 6: h ^= uint64_t(data2[5]) << 40;
        case 5: h ^= uint64_t(data2[4]) << 32;
        case 4: h ^= uint64_t(data2[3]) << 24;
        case 3: h ^= uint64_t(data2[2]) << 16;
        case 2: h ^= uint64_t(data2[1]) << 8;
        case 1: h ^= uint64_t(data2[0]);
            h *= m;
    };
 
    h ^= h >> r;
    h *= m;
    h ^= h >> r;

    return h;
} 

bool is_cidr_subnet(const char* subnet) {
    boost::cmatch what;
    if (regex_match(subnet, what, regular_expression_cidr_pattern)) {
        return true;
    } else {
        return false;
    }
}


// http://www.gnu.org/software/libc/manual/html_node/Elapsed-Time.html
int timeval_subtract (struct timeval * result, struct timeval * x,  struct timeval * y) {
    /* Perform the carry for the later subtraction by updating y. */
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }

    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait. tv_usec is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}

uint64_t convert_conntrack_hash_struct_to_integer(packed_conntrack_hash* struct_value) {
    uint64_t unpacked_data = 0;
    memcpy(&unpacked_data, struct_value, sizeof(uint64_t));
    return unpacked_data;
}

void convert_integer_to_conntrack_hash_struct(packed_session* packed_connection_data, packed_conntrack_hash* unpacked_data) {
    memcpy(unpacked_data, packed_connection_data, sizeof(uint64_t)); 
}

std::string print_flow_tracking_for_specified_protocol(contrack_map_type& protocol_map, std::string client_ip, direction flow_direction) {
    std::stringstream buffer;
    // We shoud iterate over all fields

    int printed_records = 0;
    for (contrack_map_type::iterator itr = protocol_map.begin(); itr != protocol_map.end(); ++itr) {
        // We should limit number of records in flow dump because syn flood attacks produce thounsands of lines
        if (printed_records > ban_details_records_count) {
            buffer<<"Flows are cropped due very long list\n";
            break;
        }

        uint64_t packed_connection_data = itr->first;
        packed_conntrack_hash unpacked_key_struct;
        convert_integer_to_conntrack_hash_struct(&packed_connection_data, &unpacked_key_struct);
      
        std::string opposite_ip_as_string = convert_ip_as_uint_to_string(unpacked_key_struct.opposite_ip);  
        if (flow_direction == INCOMING) {
            buffer<<client_ip<<":"<<unpacked_key_struct.dst_port<<" < "<<opposite_ip_as_string<<":"<<unpacked_key_struct.src_port<<" "; 
        } else if (flow_direction == OUTGOING) {
            buffer<<client_ip<<":"<<unpacked_key_struct.src_port<<" > "<<opposite_ip_as_string<<":"<<unpacked_key_struct.dst_port<<" ";
        } 
        
        buffer<<itr->second.bytes<<" bytes "<<itr->second.packets<<" packets";
        buffer<<"\n";

        printed_records++;
    } 

    return buffer.str();
}

/*
    Attack types: 
        - syn flood: one local port, multiple remote hosts (and maybe multiple remote ports) and small packet size
*/

/* Iterate over all flow tracking table */
bool process_flow_tracking_table(conntrack_main_struct& conntrack_element, std::string client_ip) {
    std::map <uint32_t, unsigned int>     uniq_remote_hosts_which_generate_requests_to_us;
    std::map <unsigned int, unsigned int> uniq_local_ports_which_target_of_connectiuons_from_inside;

    /* Process incoming TCP connections */
    for (contrack_map_type::iterator itr = conntrack_element.in_tcp.begin(); itr != conntrack_element.in_tcp.end(); ++itr) {
        uint64_t packed_connection_data = itr->first;
        packed_conntrack_hash unpacked_key_struct;
        convert_integer_to_conntrack_hash_struct(&packed_connection_data, &unpacked_key_struct);
        
        uniq_remote_hosts_which_generate_requests_to_us[unpacked_key_struct.opposite_ip]++;
        uniq_local_ports_which_target_of_connectiuons_from_inside[unpacked_key_struct.dst_port]++;
       
        // we can calc average packet size 
        // string opposite_ip_as_string = convert_ip_as_uint_to_string(unpacked_key_struct.opposite_ip);
        // unpacked_key_struct.src_port
        // unpacked_key_struct.dst_port
        // itr->second.packets
        // itr->second.bytes
    } 

    return true;
}

std::string print_flow_tracking_for_ip(conntrack_main_struct& conntrack_element, std::string client_ip) {
    std::stringstream buffer;

    std::string in_tcp = print_flow_tracking_for_specified_protocol(conntrack_element.in_tcp, client_ip, INCOMING);
    std::string in_udp = print_flow_tracking_for_specified_protocol(conntrack_element.in_udp, client_ip, INCOMING);

    bool we_have_incoming_flows = in_tcp.length() > 0 or in_udp.length() > 0;
    if (we_have_incoming_flows) {
        buffer<<"Incoming\n\n";
        
        if (in_tcp.length() > 0) {
            buffer<<"TCP\n"<<in_tcp<<"\n";
        }

        if (in_udp.length() > 0) {
            buffer<<"UDP\n"<<in_udp<<"\n";
        }

    }

    std::string out_tcp = print_flow_tracking_for_specified_protocol(conntrack_element.out_tcp, client_ip, OUTGOING);
    std::string out_udp = print_flow_tracking_for_specified_protocol(conntrack_element.out_udp, client_ip, OUTGOING);

    bool we_have_outgoing_flows = out_tcp.length() > 0 or out_udp.length() > 0;

    // print delimiter if we have flows in both directions
    if (we_have_incoming_flows && we_have_outgoing_flows) {
        buffer<<"\n";
    }

    if (we_have_outgoing_flows) {
        buffer<<"Outgoing\n\n";

        if (out_tcp.length() > 0 ) {
            buffer<<"TCP\n"<<out_tcp<<"\n";
        }

        if (out_udp.length() > 0) {
            buffer<<"UDP\n"<<out_udp<<"\n";
        }
    }

    return buffer.str();
}

std::string print_ban_thresholds() {
    std::stringstream output_buffer;

    output_buffer<<"Configuration params:\n";
    if (we_do_real_ban) {
        output_buffer<<"We call ban script: yes\n";
    } else {
        output_buffer<<"We call ban script: no\n";
    }

    output_buffer<<"Packets per second: ";
    if (enable_ban_for_pps) {
        output_buffer<<ban_threshold_pps;
    } else {
        output_buffer<<"disabled";
    }

    output_buffer<<"\n";

    output_buffer<<"Mbps per second: ";
    if (enable_ban_for_bandwidth) {
        output_buffer<<ban_threshold_mbps;
    } else {
        output_buffer<<"disabled";
    }

    output_buffer<<"\n";

    output_buffer<<"Flows per second: ";
    if (enable_ban_for_flows_per_second) {
        output_buffer<<ban_threshold_flows;
    } else {
        output_buffer<<"disabled";
    }

    output_buffer<<"\n";
    return output_buffer.str();
}

void print_attack_details_to_file(std::string details, std::string client_ip_as_string,  attack_details current_attack) { 
    std::ofstream my_attack_details_file;

    std::string ban_timestamp_as_string = print_time_t_in_fastnetmon_format(current_attack.ban_timestamp); 
    std::string attack_dump_path = attack_details_folder + "/" + client_ip_as_string + "_" + ban_timestamp_as_string;

    my_attack_details_file.open(attack_dump_path.c_str(), std::ios::app);

    if (my_attack_details_file.is_open()) {
        my_attack_details_file << details << "\n\n"; 
        my_attack_details_file.close();
    } else {
        logger<<log4cpp::Priority::ERROR<<"Can't print attack details to file";
    }    
}


