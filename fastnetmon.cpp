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
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netdb.h>

#include "libpatricia/patricia.h"
#include "lru_cache/lru_cache.h"

#include <ncurses.h>

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

#ifdef PCAP
#include <pcap.h>
#endif

#ifdef REDIS
#include <hiredis/hiredis.h>
#endif

#ifdef PF_RING
#include "pfring.h"
#endif

using namespace std;

/* 802.1Q VLAN tags are 4 bytes long. */
#define VLAN_HDRLEN 4

/* Complete list of ethertypes: http://en.wikipedia.org/wiki/EtherType */
/* This is the decimal equivalent of the VLAN tag's ether frame type */
#define VLAN_ETHERTYPE 0x8100
#define IP_ETHERTYPE 0x0800
#define IP6_ETHERTYPE 0x86dd
#define ARP_ETHERTYPE 0x0806

// Interface name or interface list (delimitered by comma)
string work_on_interfaces = "";

boost::regex regular_expression_cidr_pattern("^\\d+\\.\\d+\\.\\d+\\.\\d+\\/\\d+$");

time_t last_call_of_traffic_recalculation;

/* Configuration block, we must move it to configuration file  */
#ifdef REDIS
unsigned int redis_port = 6379;
string redis_host = "127.0.0.1";
// because it's additional and very specific feature we should disable it by default
bool redis_enabled = false;
#endif

typedef LRUCache<uint32_t, bool> lpm_cache_t;

// Time consumed by reaclculation for all IPs
struct timeval calculation_thread_execution_time;

// Total number of hosts in our networks
// We need this as global variable because it's very important value for configuring data structures
unsigned int total_number_of_hosts_in_our_networks = 0;

// LPM cache
lpm_cache_t *lpm_cache = NULL;

#ifdef GEOIP
GeoIP * geo_ip = NULL;
#endif

patricia_tree_t *lookup_tree, *whitelist_tree;

bool DEBUG = 0;

// flag about dumping all packets to console
bool DEBUG_DUMP_ALL_PACKETS = false;

// Period for recounting pps/traffic
unsigned int check_period = 3;

// Standard ban time in seconds for all attacks but you can tune this value
int standard_ban_time = 1800; 

#ifdef PCAP
// Enlarge receive buffer for PCAP for minimize packet drops
unsigned int pcap_buffer_size_mbytes = 10;
#endif

// Key used for sorting clients in output.  Allowed sort params: packets/bytes
string sort_parameter = "packets";

// Path to notify script 
string notify_script_path = "/usr/local/bin/notify_about_attack.sh";

// Number of lines in programm output
unsigned int max_ips_in_list = 7;

// We must ban IP if it exceeed this limit in PPS
unsigned int ban_threshold_pps = 20000;

// We must ban client if it exceed 1GBps
unsigned int ban_threshold_mbps = 1000;

// Number of lines for sending ben attack details to email
unsigned int ban_details_records_count = 500;


// log file
log4cpp::Category& logger = log4cpp::Category::getRoot();
string log_file_path = "/var/log/fastnetmon.log";

/* Configuration block ends */

/* Our data structs */

// Enum with availible sort by field
enum sort_type { PACKETS, BYTES };

enum direction {
    INCOMING = 0,
    OUTGOING,
    INTERNAL,
    OTHER
};

typedef struct {
    unsigned int bytes;
    unsigned int packets;
} total_counter_element;

// We count total number of incoming/outgoing/internal and other traffic type packets/bytes
// And initilize by 0 all fields
total_counter_element total_counters[4];
total_counter_element total_speed_counters[4];

// simplified packet struct for lightweight save into memory
struct simple_packet {
    uint32_t     src_ip;
    uint32_t     dst_ip;
    uint16_t     source_port;
    uint16_t     destination_port;
    unsigned     int protocol;
    unsigned     int length;
    uint8_t      flags; /* tcp flags */
    struct       timeval ts;
};

// structure with atatck details
struct attack_details {
    direction attack_direction;
    // first attackpower detected
    unsigned int attack_power;
    // max attack power
    unsigned int max_attack_power;
    unsigned int in_bytes;
    unsigned int out_bytes;
    unsigned int in_packets;
    unsigned int out_packets;
    // time when we but this user
    time_t   ban_timestamp;
    int      ban_time; // seconds of the ban
};

typedef attack_details banlist_item;
typedef pair<uint32_t, uint32_t> subnet;

// main data structure for storing traffic data for all our IPs
typedef struct {
    unsigned  int in_bytes;
    unsigned  int out_bytes;
    unsigned  int in_packets;
    unsigned  int out_packets;
    
    // Additional data for correct attack protocol detection
    unsigned  int tcp_in_packets;
    unsigned  int tcp_out_packets;
    unsigned  int tcp_in_bytes;
    unsigned  int tcp_out_bytes;

    unsigned  int udp_in_packets;
    unsigned  int udp_out_packets;

    unsigned  int udp_in_bytes;
    unsigned  int udp_out_bytes;
} map_element;

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t src_ip;
    uint32_t dst_ip; 
} conntrack_key;

typedef std::map <uint32_t, map_element> map_for_counters;
typedef vector<map_element> vector_of_counters;
typedef std::map <unsigned long int, vector_of_counters> map_of_vector_counters;

map_of_vector_counters SubnetVectorMap;

// data structure for storing data in Vector
typedef pair<uint32_t, map_element> pair_of_map_elements;

/* End of our data structs */

boost::mutex data_counters_mutex;
boost::mutex speed_counters_mutex;
boost::mutex total_counters_mutex;
boost::mutex ban_list_mutex;
boost::mutex flow_counter;

#ifdef REDIS
redisContext *redis_context = NULL;
#endif

#ifdef PCAP
// pcap handler, we want it as global variable beacuse it used in singnal handler
pcap_t* descr = NULL;
#endif

#ifdef PF_RING
struct thread_stats {
    u_int64_t __padding_0[8];

    u_int64_t numPkts;
    u_int64_t numBytes;

    pfring *ring;
    pthread_t pd_thread;
    int core_affinity;

    volatile u_int64_t do_shutdown;

    u_int64_t __padding_1[3];
};

struct thread_stats *threads;

pfring* pf_ring_descr = NULL;
#endif

// main map for storing traffic data
// map_for_counters DataCounter;

// map for flows
map<uint64_t, int> FlowCounter;

// структура для сохранения мгновенных скоростей
map_for_counters SpeedCounter;

#ifdef GEOIP
map_for_counters GeoIpCounter;
#endif

// В информации о ддосе мы храним силу атаки и ее направление
map<uint32_t, banlist_item> ban_list;
map<uint32_t, vector<simple_packet> > ban_list_details;

// стандартно у нас смещение для типа DLT_EN10MB, Ethernet
unsigned int DATA_SHIFT_VALUE = 14;

// начальный размер unordered_map для хранения данных
unsigned int MAP_INITIAL_SIZE = 2048;

vector<subnet> our_networks;
vector<subnet> whitelist_networks;

/* 
 Тут кроется огромный баго-фич:
  В случае прослушивания any интерфейсов мы ловим фичу-баг, вместо эзернет хидера у нас тип 113, который LINUX SLL,
  а следовательно размер хидера не 14, а 16 байт! 
  Если мы сниффим один интерфейсе - у нас хидер эзернет, 14 байт, а если ANY, то хидер у нас 16 !!!

 packetptr += 14; // Ethernet
 packetptr += 16; // LINUX SLL, только в случае указания any интерфейса 

 Подробнее:
  https://github.com/the-tcpdump-group/libpcap/issues/324
  http://comments.gmane.org/gmane.network.tcpdump.devel/5043
  http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html 
  https://github.com/the-tcpdump-group/libpcap/issues/163

*/

// prototypes
int timeval_subtract (struct timeval * result, struct timeval * x,  struct timeval * y);
bool pf_ring_main_loop_multy_channel(const char* dev);
void* pf_ring_packet_consumer_thread(void* _id);
bool is_cidr_subnet(string subnet);
uint64_t MurmurHash64A (const void * key, int len, uint64_t seed);
void cleanup_ban_list();
string print_tcp_flags(uint8_t flag_value);
int extract_bit_value(uint8_t num, int bit);
string get_attack_description(uint32_t client_ip, attack_details& current_attack);
unsigned int convert_speed_to_mbps(unsigned int speed_in_bps);
void send_attack_details(uint32_t client_ip, attack_details current_attack_details);
string convert_timeval_to_date(struct timeval tv);
void free_up_all_resources();
void main_packet_process_task();
unsigned int get_cidr_mask_from_network_as_string(string network_cidr_format);
string send_ddos_attack_details();
void execute_ip_ban(uint32_t client_ip, unsigned int in_pps, unsigned int out_pps, unsigned int in_bps, unsigned int out_bps);
direction get_packet_direction(uint32_t src_ip, uint32_t dst_ip, unsigned long& subnet);
void recalculate_speed();
std::string print_channel_speed(string traffic_type, direction packet_direction);
void process_packet(simple_packet& current_packet);
void copy_networks_from_string_form_to_binary(vector<string> networks_list_as_string, vector<subnet>& our_networks);

bool file_exists(string path);
void calculation_programm();
void pcap_main_loop(const char* dev);
bool pf_ring_main_loop(const char* dev);
void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, const u_char *packetptr);
void ulog_main_loop();
void signal_handler(int signal_number);
uint32_t convert_cidr_to_binary_netmask(unsigned int cidr);

// Function for sorting Vector of pairs
bool compare_function_by_in_packets (pair_of_map_elements a, pair_of_map_elements b) {
    return a.second.in_packets > b.second.in_packets;
}

bool compare_function_by_out_packets (pair_of_map_elements a, pair_of_map_elements b) {
    return a.second.out_packets > b.second.out_packets;
}

bool compare_function_by_out_bytes (pair_of_map_elements a, pair_of_map_elements b) {
    return a.second.out_bytes > b.second.out_bytes;
}

bool compare_function_by_in_bytes(pair_of_map_elements a, pair_of_map_elements b) {
    return a.second.in_bytes > b.second.in_bytes;
}

string get_direction_name(direction direction_value) {
    string direction_name; 

    switch (direction_value) {
        case INCOMING: direction_name = "incoming"; break;
        case OUTGOING: direction_name = "outgoing"; break;
        case INTERNAL: direction_name = "internal"; break;
        case OTHER:    direction_name = "other";    break;
        default:       direction_name = "unknown";  break;
    }   

    return direction_name;
}

uint32_t convert_ip_as_string_to_uint(string ip) {
    struct in_addr ip_addr;
    inet_aton(ip.c_str(), &ip_addr);

    // in network byte order
    return ip_addr.s_addr;
}

string convert_ip_as_uint_to_string(uint32_t ip_as_integer) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ip_as_integer;
    return (string)inet_ntoa(ip_addr);
}

// convert integer to string
string convert_int_to_string(int value) {
    std::stringstream out;
    out << value;

    return out.str();
}

// convert string to integer
int convert_string_to_integer(string line) {
    return atoi(line.c_str());
}

// exec command in shell
vector<string> exec(string cmd) {
    vector<string> output_list;

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
bool exec_with_stdin_params(string cmd, string params) {
    FILE* pipe = popen(cmd.c_str(), "w");
    if (!pipe) return false;

    if (fputs(params.c_str(), pipe)) {
        fclose(pipe);
        return true;
    } else {
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

    // Нужно проверить соединение пингом, так как, по-моему, оно не првоеряет само подключение при коннекте
    redisReply* reply = (redisReply*)redisCommand(redis_context, "PING");
    if (reply) {
        freeReplyObject(reply);
    } else {
        return false;
    }

    return true;
}

void update_traffic_in_redis(uint32_t ip, unsigned int traffic_bytes, direction my_direction) {
    string ip_as_string = convert_ip_as_uint_to_string(ip);
    redisReply *reply;

    if (!redis_context) {
        logger<< log4cpp::Priority::INFO<<"Please initialize Redis handle";
        return;
    }

    string key_name = ip_as_string + "_" + get_direction_name(my_direction);
    reply = (redisReply *)redisCommand(redis_context, "INCRBY %s %s", key_name.c_str(), convert_int_to_string(traffic_bytes).c_str());

    // Только в случае, если мы обновили без ошибки
    if (!reply) {
        logger.info("Can't increment traffic in redis error_code: %d error_string: %s", redis_context->err, redis_context->errstr);
   
        // Такое может быть в случае перезапуска redis, нам надо попробовать решить это без падения программы 
        if (redis_context->err == 1 or redis_context->err == 3) {
            // Connection refused            
            redis_init_connection();
        }
    } else {
        freeReplyObject(reply); 
    }
}
#endif

string draw_table(map_for_counters& my_map_packets, direction data_direction, bool do_redis_update, sort_type sort_item) {
        std::vector<pair_of_map_elements> vector_for_sort;

        stringstream output_buffer;

        // Preallocate memory for sort vector
        vector_for_sort.reserve(my_map_packets.size());

        /* Вобщем-то весь код ниже зависит лишь от входных векторов и порядка сортировки данных */
        for( map_for_counters::iterator ii = my_map_packets.begin(); ii != my_map_packets.end(); ++ii) {
            // кладем все наши элементы в массив для последующей сортировки при отображении
            //pair_of_map_elements current_pair = make_pair((*ii).first, (*ii).second);
            vector_for_sort.push_back( make_pair((*ii).first, (*ii).second) );
        } 
  
        if (sort_item == PACKETS) {

            // используем разные сортировочные функции 
            if (data_direction == INCOMING) {
                std::sort( vector_for_sort.begin(), vector_for_sort.end(), compare_function_by_in_packets);
            } else if (data_direction == OUTGOING) {
                std::sort( vector_for_sort.begin(), vector_for_sort.end(), compare_function_by_out_packets);
            } else {
                // unexpected
            }

        } else if (sort_item == BYTES) {
            if (data_direction == INCOMING) {
                std::sort( vector_for_sort.begin(), vector_for_sort.end(), compare_function_by_in_bytes);
            } else if (data_direction == OUTGOING) {
                std::sort( vector_for_sort.begin(), vector_for_sort.end(), compare_function_by_out_bytes);
            }
        } else {
            logger<< log4cpp::Priority::INFO<<"Unexpected bahaviour on sort function";
        }

        unsigned int element_number = 0;
        for( vector<pair_of_map_elements>::iterator ii=vector_for_sort.begin(); ii!=vector_for_sort.end(); ++ii) {
            uint32_t client_ip = (*ii).first;
            string client_ip_as_string = convert_ip_as_uint_to_string((*ii).first);

            unsigned int pps = 0; 
            unsigned int bps = 0; 

            // делаем "полиморфную" полосу и ппс
            if (data_direction == INCOMING) {
                pps = SpeedCounter[client_ip].in_packets;
                bps = SpeedCounter[client_ip].in_bytes;
            } else if (data_direction == OUTGOING) {
                pps = SpeedCounter[client_ip].out_packets;
                bps = SpeedCounter[client_ip].out_bytes;
            }    

            double mbps = (double)bps/1024/1024*8;

            // Set one number after comma for double
            output_buffer<<fixed<<setprecision(1);

            // Выводим первые max_ips_in_list элементов в списке, при нашей сортировке, будут выданы топ 10 самых грузящих клиентов
            if (element_number < max_ips_in_list) {
                string is_banned = ban_list.count(client_ip) > 0 ? " *banned* " : "";
                output_buffer << client_ip_as_string << "\t\t" << pps << " pps " << mbps << " mbps" << is_banned << endl;
            }  
   
#ifdef REDIS 
            if (redis_enabled && do_redis_update) {
                //cout<<"Start updating traffic in redis"<<endl;
                update_traffic_in_redis( (*ii).first, (*ii).second.in_packets, INCOMING);
                update_traffic_in_redis( (*ii).first, (*ii).second.out_packets, OUTGOING);
            }
#endif
        
            element_number++;
        }

    return output_buffer.str(); 
}

// check file existence
bool file_exists(string path) {
    FILE* check_file = fopen(path.c_str(), "r");
    if (check_file) {
        fclose(check_file);
        return true;
    } else {
        return false;
    }
}

// read whole file to vector
vector<string> read_file_to_vector(string file_name) {
    vector<string> data;
    string line;

    ifstream reading_file;

    reading_file.open(file_name.c_str(), std::ifstream::in);
    if (reading_file.is_open()) {
        while ( getline(reading_file, line) ) {
            data.push_back(line); 
        }
    } else {
        logger<< log4cpp::Priority::INFO <<"Can't open file: "<<file_name;
    }

    return data;
}

// Load configuration
void load_configuration_file() {
    ifstream config_file ("/etc/fastnetmon.conf");
    string line;

    map<string, std::string> configuration_map;
    
    if (config_file.is_open()) {
        while ( getline(config_file, line) ) {
            vector<string> parsed_config; 
            split( parsed_config, line, boost::is_any_of(" ="), boost::token_compress_on );
            configuration_map[ parsed_config[0] ] = parsed_config[1];
        }

        if (configuration_map.count("threshold_pps") != 0) {
            ban_threshold_pps = convert_string_to_integer( configuration_map[ "threshold_pps" ] );
        }

        if (configuration_map.count("threshold_mbps") != 0) {
            ban_threshold_mbps = convert_string_to_integer(  configuration_map[ "threshold_mbps" ] );
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
            sort_parameter = convert_string_to_integer( configuration_map[ "check_period" ]);
        }

        if (configuration_map.count("sort_parameter") != 0) {
            sort_parameter = configuration_map[ "sort_parameter" ];
        }

        if (configuration_map.count("interfaces") != 0) {
            work_on_interfaces = configuration_map[ "interfaces" ]; 
        }

        if (configuration_map.count("max_ips_in_list") != 0) {
            max_ips_in_list = convert_string_to_integer( configuration_map[ "max_ips_in_list" ]);
        }

        if (configuration_map.count("notify_script_path") != 0 ) {
            notify_script_path = configuration_map[ "notify_script_path" ];
        }
    } else {
        logger<< log4cpp::Priority::INFO<<"Can't open config file";
    }
}

/* Enable core dumps for simplify debug tasks */
void enable_core_dumps() {
    struct rlimit rlim;

    int result = getrlimit(RLIMIT_CORE, &rlim);

    if (result) {
        logger<< log4cpp::Priority::INFO<<"Can't get current rlimit for RLIMIT_CORE";
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
    int network_size_in_ips = pow(2, 32-bitlen);
    //logger<< log4cpp::Priority::INFO<<"Subnet: "<<prefix->add.sin.s_addr<<" network size: "<<network_size_in_ips;
    logger<< log4cpp::Priority::INFO<<"I will allocate "<<network_size_in_ips<<" records for subnet "<<subnet_as_integer;

    // Initialize map element
    SubnetVectorMap[subnet_as_integer] = vector_of_counters(network_size_in_ips);

    // Zeroify all vector elements
    map_element zero_map_element;
    memset(&zero_map_element, 0, sizeof(zero_map_element));
    std::fill(SubnetVectorMap[subnet_as_integer].begin(), SubnetVectorMap[subnet_as_integer].end(), zero_map_element);
}

void zeroify_all_counters() {
    map_element zero_map_element;
    memset(&zero_map_element, 0, sizeof(zero_map_element));

    for (map_of_vector_counters::iterator itr = SubnetVectorMap.begin(); itr != SubnetVectorMap.end(); itr++) {
        logger<< log4cpp::Priority::INFO<<"Zeroify "<<itr->first;
        std::fill(itr->second.begin(), itr->second.end(), zero_map_element); 
    }
}

bool load_our_networks_list() {
    if (file_exists("/etc/networks_whitelist")) {
        vector<string> network_list_from_config = read_file_to_vector("/etc/networks_whitelist");

        for( vector<string>::iterator ii=network_list_from_config.begin(); ii!=network_list_from_config.end(); ++ii) {
            if (ii->length() > 0 && is_cidr_subnet(*ii)) {
                make_and_lookup(whitelist_tree, const_cast<char*>(ii->c_str()));
            } else {
                logger<<log4cpp::Priority::INFO<<"Can't parse line from whitelist: "<<*ii;
            }
        }

        logger<<log4cpp::Priority::INFO<<"We loaded "<<network_list_from_config.size()<< " networks from whitelist file";
    }
 
    vector<string> networks_list_as_string;
    // если мы на openvz ноде, то "свои" IP мы можем получить из спец-файла в /proc
    if (file_exists("/proc/vz/version")) {
        logger<< log4cpp::Priority::INFO<<"We found OpenVZ";
        // тут искусствено добавляем суффикс 32
        vector<string> openvz_ips = read_file_to_vector("/proc/vz/veip");
        for( vector<string>::iterator ii=openvz_ips.begin(); ii!=openvz_ips.end(); ++ii) {
            // skip IPv6 addresses
            if (strstr(ii->c_str(), ":") != NULL) {
                continue;
            }

            // skip header
            if (strstr(ii->c_str(), "Version") != NULL) {
                continue;
            }

            vector<string> subnet_as_string; 
            split( subnet_as_string, *ii, boost::is_any_of(" "), boost::token_compress_on );
 
            string openvz_subnet = subnet_as_string[1] + "/32";
            networks_list_as_string.push_back(openvz_subnet);
        }

        logger<<log4cpp::Priority::INFO<<"We loaded "<<networks_list_as_string.size()<< " networks from /proc/vz/version";
    } 

    if (file_exists("/etc/networks_list")) { 
        vector<string> network_list_from_config = read_file_to_vector("/etc/networks_list");
        networks_list_as_string.insert(networks_list_as_string.end(), network_list_from_config.begin(), network_list_from_config.end());

        logger<<log4cpp::Priority::INFO<<"We loaded "<<network_list_from_config.size()<< " networks from networks file";
    }

    // если это ложь, то в моих функциях косяк
    assert( convert_ip_as_string_to_uint("255.255.255.0")   == convert_cidr_to_binary_netmask(24) );
    assert( convert_ip_as_string_to_uint("255.255.255.255") == convert_cidr_to_binary_netmask(32) );

    for( vector<string>::iterator ii=networks_list_as_string.begin(); ii!=networks_list_as_string.end(); ++ii) { 
        unsigned int cidr_mask = get_cidr_mask_from_network_as_string(*ii);
        total_number_of_hosts_in_our_networks += pow(2, 32-cidr_mask);
       
        if (ii->length() > 0 && is_cidr_subnet(*ii)) { 
            make_and_lookup(lookup_tree, const_cast<char*>(ii->c_str()));
        } else {
            logger<<log4cpp::Priority::INFO<<"Can't parse line from subnet list: "<<*ii;
        }
    }    

    /* Preallocate data structures */

    patricia_process (lookup_tree, (void_fn_t)subnet_vectors_allocator);

    logger<<log4cpp::Priority::INFO<<"We start total zerofication of counters";
    zeroify_all_counters();
    logger<<log4cpp::Priority::INFO<<"We finished it";

    logger<<log4cpp::Priority::INFO<<"We loaded "<<networks_list_as_string.size()<<" subnets to our in-memory list of networks";
    logger<<log4cpp::Priority::INFO<<"Total number of monitored hosts (total size of all networks): "
        <<total_number_of_hosts_in_our_networks;

    return true;
}

// extract 24 from 192.168.1.1/24
unsigned int get_cidr_mask_from_network_as_string(string network_cidr_format) {
   vector<string> subnet_as_string; 
   split( subnet_as_string, network_cidr_format, boost::is_any_of("/"), boost::token_compress_on );

   return convert_string_to_integer(subnet_as_string[1]);
}

void copy_networks_from_string_form_to_binary(vector<string> networks_list_as_string, vector<subnet>& our_networks ) {
    for( vector<string>::iterator ii=networks_list_as_string.begin(); ii!=networks_list_as_string.end(); ++ii) {
        vector<string> subnet_as_string; 
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

    // поидее, на выходе тут нужен network byte order 
    return htonl(binary_netmask);
}

string print_simple_packet(struct simple_packet packet) {
    std::stringstream buffer;

    string proto_name;
    switch (packet.protocol) {
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
    
    buffer<<convert_timeval_to_date(packet.ts)<<" ";

    buffer
        <<convert_ip_as_uint_to_string(packet.src_ip)<<":"<<packet.source_port
        <<" > "
        <<convert_ip_as_uint_to_string(packet.dst_ip)<<":"<<packet.destination_port
        <<" protocol: "<<proto_name
        <<" flags: "<<print_tcp_flags(packet.flags)
        <<" size: "<<packet.length<<" bytes"<<"\n";
    // используется \n вместо endl, ибо иначе начинается хрень всякая при передаче данной строки команде на stdin

    return buffer.str();
}

// Обработчик для pf_ring, так как у него иной формат входных параметров
void parse_packet_pf_ring(const struct pfring_pkthdr *h, const u_char *p, const u_char *user_bytes) {
    // Описание всех полей: http://www.ntop.org/pfring_api/structpkt__parsing__info.html
    simple_packet packet;

    // In ZC (zc:eth0) mode you should manually add packet parsing here
    // Because it disabled by default: "parsing already disabled in zero-copy"
    // http://www.ntop.org/pfring_api/pfring_8h.html 
    // Parse up to L3, no timestamp, no hashing
    // pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)h, 3, 0, 0);

    /* We handle only IPv4 */
    if (h->extended_hdr.parsed_pkt.ip_version == 4) {
        /* PF_RING хранит данные в host byte order, а мы использум только network byte order */
        packet.src_ip = htonl( h->extended_hdr.parsed_pkt.ip_src.v4 ); 
        packet.dst_ip = htonl( h->extended_hdr.parsed_pkt.ip_dst.v4 );

        packet.source_port = h->extended_hdr.parsed_pkt.l4_src_port;
        packet.destination_port = h->extended_hdr.parsed_pkt.l4_dst_port;

        packet.length = h->len;
        packet.protocol = h->extended_hdr.parsed_pkt.l3_proto;
        packet.ts = h->ts;

        if (packet.protocol == IPPROTO_TCP) {
            packet.flags = h->extended_hdr.parsed_pkt.tcp.flags;
        } else {
            packet.flags = 0;
        } 

        process_packet(packet);
        //std::cout<<print_simple_packet(packet)<<std::endl;
        //printf("hash%d\n",h->extended_hdr.pkt_hash);
    } else {
        // Uncomment this line for deep inspection of all packets
        /*
        char buffer[512]; 
        pfring_print_parsed_pkt(buffer, 512, p, h);
        logger<<log4cpp::Priority::INFO<<buffer; 
        */
    }
}

// в случае прямого вызова скрипта колбэка - нужно конст, напрямую в хендлере - конст не нужно
void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, const u_char *packetptr) {
    struct ip* iphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;

    struct ether_header *eptr;    /* net/ethernet.h */
    eptr = (struct ether_header* )packetptr;

    // проверяем тип эзернет фрейма и его принадлежность к типу "фрейм с VLAN" 
    if ( ntohs(eptr->ether_type) ==  VLAN_ETHERTYPE ) {
        // это тегированный трафик, поэтому нужно отступить еще 4 байта, чтобы добраться до данных
        packetptr += DATA_SHIFT_VALUE + VLAN_HDRLEN;
    } else if (ntohs(eptr->ether_type) == IP_ETHERTYPE) {
        // Skip the datalink layer header and get the IP header fields.
        packetptr += DATA_SHIFT_VALUE;
    } else if (ntohs(eptr->ether_type) == IP6_ETHERTYPE or ntohs(eptr->ether_type) == ARP_ETHERTYPE) {
        // we know about it but does't not care now
    } else  {
        // printf("Packet with non standard ethertype found: 0x%x\n", ntohs(eptr->ether_type));
    }

    iphdr = (struct ip*)packetptr;

    // исходящий/входящий айпи это in_addr, http://man7.org/linux/man-pages/man7/ip.7.html
    uint32_t src_ip = iphdr->ip_src.s_addr;
    uint32_t dst_ip = iphdr->ip_dst.s_addr;

    // The ntohs() function converts the unsigned short integer netshort from network byte order to host byte order
    unsigned int packet_length = ntohs(iphdr->ip_len); 

    simple_packet current_packet;

    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp
    packetptr += 4*iphdr->ip_hl;
    switch (iphdr->ip_p) {
        case IPPROTO_TCP: 
            tcphdr = (struct tcphdr*)packetptr;
            current_packet.source_port = ntohs(tcphdr->source);
            current_packet.destination_port = ntohs(tcphdr->dest);
            break;
        case IPPROTO_UDP:
            udphdr = (struct udphdr*)packetptr;
            current_packet.source_port = ntohs(udphdr->source);
            current_packet.destination_port = ntohs(udphdr->dest);
            break;
        case IPPROTO_ICMP:
            // there are no port for ICMP
            current_packet.source_port = 0;
            current_packet.destination_port = 0;
            break;
    }

    current_packet.protocol = iphdr->ip_p;
    current_packet.src_ip = src_ip;
    current_packet.dst_ip = dst_ip;
    current_packet.length = packet_length;
    
    /* Передаем пакет в обработку */ 
    process_packet(current_packet);
}

uint32_t get_packet_hash(simple_packet& packet) {
/*
    packet.protocol
    packet.src_ip
    packet.dst_ip
    packet.lenght
    packet.source_port
    packet.destination_port
*/
    return 0;
}



/* Производим обработку уже переданного нам пакета в простом формате */
void process_packet(simple_packet& current_packet) { 
    // Packets dump is very useful for bug hunting
    if (DEBUG_DUMP_ALL_PACKETS) {
        logger<< log4cpp::Priority::INFO<<"Dump: "<<print_simple_packet(current_packet);
    }

    // Subnet for found IPs
    unsigned long subnet = 0;
    direction packet_direction = get_packet_direction(current_packet.src_ip, current_packet.dst_ip, subnet);

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
            logger<< log4cpp::Priority::INFO<<"Can't find vector address in subnet map";
            return; 
        }
    }

    total_counters_mutex.lock();
    total_counters[packet_direction].packets++;
    total_counters[packet_direction].bytes += current_packet.length;
    total_counters_mutex.unlock();

    if (packet_direction == INTERNAL) {
    
    } else if (packet_direction == OUTGOING) {
        uint32_t shift_in_vector = ntohl(current_packet.src_ip) - subnet_in_host_byte_order;
        #define current_element itr->second[shift_in_vector]

        // собираем данные для деталей при бане клиента
        if  (ban_list_details.count(current_packet.src_ip) > 0 &&
            ban_list_details[current_packet.src_ip].size() < ban_details_records_count) {

            ban_list_details[current_packet.src_ip].push_back(current_packet);
        }

        //data_counters_mutex.lock();
        if (current_packet.protocol == IPPROTO_TCP) {
            current_element.tcp_out_packets++;
            current_element.tcp_out_bytes += current_packet.length;

            //DataCounter[ current_packet.src_ip ].tcp_out_packets++;
            //DataCounter[ current_packet.src_ip ].tcp_out_bytes += current_packet.length;
        } else if (current_packet.protocol == IPPROTO_UDP) {
            current_element.udp_out_packets++;
            current_element.udp_out_bytes += current_packet.length;        
    
            //DataCounter[ current_packet.src_ip ].udp_out_packets++;
            //DataCounter[ current_packet.src_ip ].udp_out_bytes += current_packet.length; 
        } else {
            // TBD
        }

        current_element.out_packets++;
        current_element.out_bytes += current_packet.length; 

        //DataCounter[ current_packet.src_ip ].out_packets++; 
        //DataCounter[ current_packet.src_ip ].out_bytes += current_packet.length;

        //data_counters_mutex.unlock();

    } else if (packet_direction == INCOMING) {
        uint32_t shift_in_vector = ntohl(current_packet.dst_ip) - subnet_in_host_byte_order;
        #define current_element itr->second[shift_in_vector]

        // logger<< log4cpp::Priority::INFO<<"Shift is: "<<shift_in_vector;

        // собираемы данные для деталей при бане клиента
        if  (ban_list_details.count(current_packet.dst_ip) > 0 &&
            ban_list_details[current_packet.dst_ip].size() < ban_details_records_count) {

            ban_list_details[current_packet.dst_ip].push_back(current_packet);
        }

        //data_counters_mutex.lock();
    
        if (current_packet.protocol == IPPROTO_TCP) {
            current_element.tcp_in_packets++;
            current_element.tcp_in_bytes += current_packet.length;

            //DataCounter[ current_packet.dst_ip ].tcp_in_packets++;
            //DataCounter[ current_packet.dst_ip ].tcp_in_bytes += current_packet.length;
        } else if (current_packet.protocol == IPPROTO_UDP) {
            current_element.udp_in_packets++;
            current_element.udp_in_bytes += current_packet.length;

            //DataCounter[ current_packet.dst_ip ].udp_in_packets++;
            //DataCounter[ current_packet.dst_ip ].udp_in_bytes += current_packet.length; 
        } else {
            // TBD
        }

        current_element.in_packets ++;
        current_element.in_bytes += current_packet.length;

        //DataCounter[ current_packet.dst_ip ].in_packets ++;
        //DataCounter[ current_packet.dst_ip ].in_bytes += current_packet.length;
        //data_counters_mutex.unlock();
    } else {
        // Other traffic
    }

#ifdef ENABLE_CONNTRACKING
    // Connection трекинг нам интересен лишь для наших узлов
    if (packet_direction == INCOMING or packet_direction == OUTGOING) {
        // Зануляем поля, которые не являются постоянными для 5 tuple
        // TODO я правлю переменную переданную по ссылке, ТАК НЕЛЬЗЯ!!!
        current_packet.flags = 0;
        current_packet.ts.tv_sec = 0;
        current_packet.ts.tv_usec = 0;
        current_packet.length = 0;

        // calculate hash
        uint64_t hash = MurmurHash64A(&current_packet, sizeof(current_packet), 11);

        flow_counter.lock();
        FlowCounter[hash]++;
        flow_counter.unlock();
    }
#endif
}

#ifdef GEOIP
unsigned int get_asn_for_ip(uint32_t ip) { 
    char* asn_raw = GeoIP_org_by_name(geo_ip, convert_ip_as_uint_to_string(remote_ip).c_str());
    uint32_t asn_number = 0;
   
    if (asn_raw == NULL) {
        asn_number = 0; 
    } else {
        // split string: AS1299 TeliaSonera International Carrier
        vector<string> asn_as_string;
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
void calculation_thread() {
    // we need wait one second for calculating speed by recalculate_speed

    // #include <sys/prctl.h>
    //prctl(PR_SET_NAME , "fastnetmon calc thread", 0, 0, 0);

    while (1) {
        // Availible only from boost 1.54: boost::this_thread::sleep_for( boost::chrono::seconds(check_period) );
        boost::this_thread::sleep(boost::posix_time::seconds(check_period));
        calculation_programm();
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

/* Пересчитать мгновенную скорость для всех известных соединений  */
void recalculate_speed() {
    // TODO: WE SHOULD ZEROFY ALL ELEMETS IN TABLE SpeedCounter

    double speed_calc_period = 1;
    time_t current_time;
    time(&current_time);

    // В случае, если наш поток обсчета скорости завис на чем-то эдак на 1+ секунд, то мы должны либо пропустить шаг либо попробовать поделить его на новую разницу

    double time_difference = difftime(current_time, last_call_of_traffic_recalculation);

    if (time_difference < 1) {
        // It could occur on programm start
         logger<< log4cpp::Priority::INFO<<"We skip one iteration of speed_calc because it runs so early!";        
        return;
    } else if (int(time_difference) == 1) {
        // все отлично! Запуск произошел ровно через +- секунду после прошлого
    } else {
        logger<< log4cpp::Priority::INFO<<"Time from last run of speed_recalc is soooo big, we got ugly lags: "<<time_difference;
        speed_calc_period = time_difference;
    }

    //logger<< log4cpp::Priority::INFO<<"Difference: "<<time_difference;

    map_element zero_map_element;
    memset(&zero_map_element, 0, sizeof(zero_map_element));
    
    for (map_of_vector_counters::iterator itr = SubnetVectorMap.begin(); itr != SubnetVectorMap.end(); ++itr) {
        for (vector_of_counters::iterator vector_itr = itr->second.begin(); vector_itr !=  itr->second.end(); ++vector_itr) {
            if (vector_itr->in_packets == 0 and vector_itr->out_packets == 0) {
                continue;
            } 

            int current_index = vector_itr - itr->second.begin();

            // convert to host order for math operations
            uint32_t subnet_ip = ntohl(itr->first);
            uint32_t client_ip_in_host_bytes_order = subnet_ip + current_index;

            // covnert to our standard network byte order
            uint32_t client_ip = htonl(client_ip_in_host_bytes_order); 
            
            //logger<< log4cpp::Priority::INFO<<convert_ip_as_uint_to_string(client_ip);
            unsigned int in_pps  = int((double)vector_itr->in_packets   / (double)speed_calc_period);
            unsigned int out_pps = int((double)vector_itr->out_packets / (double)speed_calc_period);

            unsigned int in_bps  = int((double)vector_itr->in_bytes  / (double)speed_calc_period);
            unsigned int out_bps = int((double)vector_itr->out_bytes / (double)speed_calc_period);     

            // we detect overspeed by packets
            if (in_pps > ban_threshold_pps or out_pps > ban_threshold_pps) {
                execute_ip_ban(client_ip, in_pps, out_pps, in_bps, out_bps);
            }

            // we detect overspeed by bandwidth
            if (convert_speed_to_mbps(in_bps) > ban_threshold_mbps or convert_speed_to_mbps(out_bps) > ban_threshold_mbps) {
                /* TODO: it's stub for debug bandwidth overspeed */
                logger<<log4cpp::Priority::INFO<<"We detect bandwidth_overuse from ip: "<<convert_ip_as_uint_to_string(client_ip)
                    <<"incoming: "<<convert_speed_to_mbps(in_bps)<<" mbps outgoing: "<<convert_speed_to_mbps(out_bps)<<" mbps";
            }

            speed_counters_mutex.lock();
            // add speed values to speed struct
            SpeedCounter[client_ip].in_bytes    = in_bps;
            SpeedCounter[client_ip].out_bytes   = out_bps;

            SpeedCounter[client_ip].in_packets  = in_pps;
            SpeedCounter[client_ip].out_packets = out_pps;
            speed_counters_mutex.unlock();

            data_counters_mutex.lock();
            *vector_itr = zero_map_element;
            data_counters_mutex.unlock();
        } 
    }

    // Clean Flow Counter
    flow_counter.lock();
    FlowCounter.clear();
    flow_counter.unlock();

    total_counters_mutex.lock();
    
    for (unsigned int index = 0; index < 4; index++) {
        total_speed_counters[index].bytes   = int((double)total_counters[index].bytes   / (double)speed_calc_period);
        total_speed_counters[index].packets = int((double)total_counters[index].packets / (double)speed_calc_period);

        // nullify data counters after speed calculation
        total_counters[index].bytes = 0; 
        total_counters[index].packets = 0; 
    }    

    total_counters_mutex.unlock();

    // устанавливаем время прошлого запуска данного скрипта
    time(&last_call_of_traffic_recalculation);
}

void calculation_programm() {
    stringstream output_buffer;
    
    struct timeval start_calc_time;
    gettimeofday(&start_calc_time, NULL);

    // clean up screen
    clear();

    sort_type sorter;
    if (sort_parameter == "packets") {
        sorter = PACKETS;
    } else if (sort_parameter == "bytes") {
        sorter = BYTES;
    } else {
        logger<< log4cpp::Priority::INFO<<"Unexpected sorter type: "<<sort_parameter;
        sorter = PACKETS;
    }

    output_buffer<<"FastNetMon v1.0 FastVPS Eesti OU (c) VPS and dedicated: http://FastVPS.host"<<"\n"
        <<"IPs ordered by: "<<sort_parameter<<" (use keys 'b'/'p' for change) and use 'q' for quit"<<"\n"
        <<"Threshold is: "<<ban_threshold_pps<<" pps and "<<ban_threshold_mbps<<" mbps"
        //<<" number of active hosts: "<<DataCounter.size()
        <<" traffic recaculation time is: "<< calculation_thread_execution_time.tv_sec<<" sec "<<calculation_thread_execution_time.tv_usec<<" microseconds"
        <<" number of flows: "<<FlowCounter.size()
        <<" from total hosts: "<<total_number_of_hosts_in_our_networks<<endl<<endl;

    output_buffer<<print_channel_speed("Incoming Traffic", INCOMING)<<endl;
    output_buffer<<draw_table(SpeedCounter, INCOMING, true, sorter);
    
    output_buffer<<endl; 
    
    output_buffer<<print_channel_speed("Outgoing traffic", OUTGOING)<<endl;
    output_buffer<<draw_table(SpeedCounter, OUTGOING, false, sorter);

    output_buffer<<endl;

    output_buffer<<print_channel_speed("Internal traffic", INTERNAL)<<endl;

    output_buffer<<endl;

    output_buffer<<print_channel_speed("Other traffic", OTHER)<<endl;

    output_buffer<<endl;

#ifdef PCAP
    struct pcap_stat current_pcap_stats;
    if (pcap_stats(descr, &current_pcap_stats) == 0) {
        output_buffer<<"PCAP statistics"<<endl<<"Received packets: "<<current_pcap_stats.ps_recv<<endl
            <<"Dropped packets: "<<current_pcap_stats.ps_drop
            <<" ("<<int((double)current_pcap_stats.ps_drop/current_pcap_stats.ps_recv*100)<<"%)"<<endl
             <<"Dropped by driver or interface: "<<current_pcap_stats.ps_ifdrop<<endl;
    }
#endif

#ifdef PF_RING
        pfring_stat pfring_status_data;
        if(pfring_stats(pf_ring_descr, &pfring_status_data) >= 0) {
            char stats_buffer[256];
            sprintf(
                stats_buffer,
                "Packets received:\t%lu\n"
                "Packets dropped:\t%lu\n"
                "Packets dropped:\t%.1f %%\n",
                (long unsigned int) pfring_status_data.recv,
                (long unsigned int) pfring_status_data.drop,
                (double) pfring_status_data.drop/pfring_status_data.recv*100
            ); 
            output_buffer<<stats_buffer;
        } else {
            logger<< log4cpp::Priority::INFO<<"Can't get PF_RING stats";
        }
#endif 
 
        if (!ban_list.empty()) {
            output_buffer<<endl<<"Ban list:"<<endl;  
            output_buffer<<send_ddos_attack_details();
        }
 
        printw( (output_buffer.str()).c_str());
        // update screen
        refresh();
        // зануляем счетчик пакетов

    struct timeval end_calc_time;
    gettimeofday(&end_calc_time, NULL);

    timeval_subtract(&calculation_thread_execution_time, &end_calc_time, &start_calc_time);
}

// pretty print channel speed in pps and MBit
std::string print_channel_speed(string traffic_type, direction packet_direction) {

    unsigned int speed_in_pps = total_speed_counters[packet_direction].packets;
    unsigned int speed_in_bps = total_speed_counters[packet_direction].bytes;

    // Потому что к нам скорость приходит в чистом виде 
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

    unsigned int speed_in_mbps = convert_speed_to_mbps(speed_in_bps);

    stream<<speed_in_pps<<" pps "<< speed_in_mbps<<" mbps"; 
    return stream.str();
}    

unsigned int convert_speed_to_mbps(unsigned int speed_in_bps) {
    return int((double)speed_in_bps/1024/1024*8);
}

void init_logging() {
    log4cpp::PatternLayout* layout = new log4cpp::PatternLayout(); 
    layout->setConversionPattern ("%d [%p] %m%n"); 

    log4cpp::Appender *appender = new log4cpp::FileAppender("default", log_file_path);
    //appender->setLayout(new log4cpp::BasicLayout());
    appender->setLayout(layout);

    logger.setPriority(log4cpp::Priority::INFO);
    logger.addAppender(appender);
    logger.info("Logger initialized!");
}

int main(int argc,char **argv) {
    lpm_cache = new lpm_cache_t(16);

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

    if (getenv("DUMP_ALL_PACKETS") != NULL) {
        DEBUG_DUMP_ALL_PACKETS = true;
    }
 
#ifdef PCAP
    char errbuf[PCAP_ERRBUF_SIZE]; 
    struct pcap_pkthdr hdr;
#endif 

    logger<<log4cpp::Priority::INFO<<"Read configuration file";

    load_configuration_file();

    logger<< log4cpp::Priority::INFO<<"I need few seconds for collecting data, please wait. Thank you!";

    if (work_on_interfaces == "" && argc != 2) {
        fprintf(stdout, "Usage: %s \"eth0\" or \"eth0,eth1\" or specify interfaces param in config file\n", argv[0]);
        exit(1);
    }
 
    // If we found params on command line we sue it 
    if (argc >= 2 && strlen(argv[1]) > 0) {
        work_on_interfaces = argv[1];
    } 

    logger<< log4cpp::Priority::INFO<<"We selected interface:"<<work_on_interfaces;

    // загружаем наши сети и whitelist 
    load_our_networks_list();

    // устанавливаем обработчик CTRL+C
    signal(SIGINT, signal_handler);

    // иницилизируем соединение с Redis
#ifdef REDIS
    if (redis_enabled) {
        if (!redis_init_connection()) {
            logger<< log4cpp::Priority::INFO<<"Can't establish connection to the redis";
            exit(1);
        }
    }
#endif

    // иницилизируем GeoIP
#ifdef GEOIP
    if(!geoip_init()) {
        logger<< log4cpp::Priority::INFO<<"Can't load geoip tables";
        exit(1);
    } 
#endif

    // инициализируем псевдо дату последнего запуска
    time(&last_call_of_traffic_recalculation);

    // запускаем поток-обсчета данных
    boost::thread calc_thread(calculation_thread);

    // start thread for recalculating speed in realtime
    boost::thread recalculate_speed_thread(recalculate_speed_thread_handler);
    // запускаем поток, который занимается очисткой банлиста 
    boost::thread cleanup_ban_list_thread(cleanup_ban_list);

    boost::thread main_packet_process_thread(main_packet_process_task);

    // Init ncurses screen 
    initscr();

    // disable any character output 
    noecho();
    // hide cursor
    curs_set(0);

    while(1) { 
        int c = getch(); 

        switch(c) {
            case 'b':
                sort_parameter = "bytes";
                break;
            case 'p':
                sort_parameter = "packets";
                break;
            case 'q':
                signal_handler(0);
                break;
            default:
                break;
        }
    }

    // wait threads
    main_packet_process_thread.join();
    recalculate_speed_thread.join();
    calc_thread.join();

    free_up_all_resources();
 
    return 0;
}

// Main worker thread for packet handling
void main_packet_process_task() {
    const char* device_name = work_on_interfaces.c_str();

#ifdef PCAP
    pcap_main_loop(device_name);
#endif

#ifdef PF_RING
    bool pf_ring_init_result = pf_ring_main_loop(device_name);
    // Uncomment this line if you want multichannel PF_RING pooler
    // bool pf_ring_init_result = pf_ring_main_loop_multy_channel(device_name);
    if (!pf_ring_init_result) {
        // Internal error in PF_RING
        logger<< log4cpp::Priority::INFO<<"PF_RING initilization failed, exit from programm"; 
        exit(1);
    }
#endif

}
 
void free_up_all_resources() {
#ifdef GEOIP
    // Free up geoip handle 
    GeoIP_delete(geo_ip);
#endif

    Destroy_Patricia(lookup_tree,    (void_fn_t)0);
    Destroy_Patricia(whitelist_tree, (void_fn_t)0);
}

#ifdef PF_RING 
bool pf_ring_main_loop_multy_channel(const char* dev) {
    int MAX_NUM_THREADS = 64;
    // TODO: enable tuning for number of threads
    unsigned int num_threads = 8;

    if ((threads = (struct thread_stats*)calloc(MAX_NUM_THREADS, sizeof(struct thread_stats))) == NULL) {
        logger<< log4cpp::Priority::INFO<<"Can't allocate memory for threads structure";
        return false;
    }

    u_int32_t flags = 0;

    flags |= PF_RING_PROMISC; /* hardcode: promisc=1 */
    flags |= PF_RING_DNA_SYMMETRIC_RSS;  /* Note that symmetric RSS is ignored by non-DNA drivers */
    flags |= PF_RING_LONG_HEADER;

    packet_direction direction = rx_only_direction;

    pfring* ring[MAX_NUM_RX_CHANNELS];
    
    unsigned int snaplen = 128;
    int num_channels = pfring_open_multichannel(dev, snaplen, flags, ring);

    if (num_channels <= 0) {
        logger<< log4cpp::Priority::INFO<<"pfring_open_multichannel returned: "<<num_channels<<" and error:"<<strerror(errno);
        return false;
    }

    logger<< log4cpp::Priority::INFO<<"We open "<<num_channels<<" channels from pf_ring NIC";

    for (int i = 0; i < num_channels; i++) {
        // char buf[32];
  
        threads[i].ring = ring[i];
        // threads[i].core_affinity = threads_core_affinity[i];

        int rc = 0;

        if  ((rc = pfring_set_direction(threads[i].ring, direction)) != 0) {
            logger<< log4cpp::Priority::INFO<<"pfring_set_direction returned: "<<rc;
        }
   
        if ((rc = pfring_set_socket_mode(threads[i].ring, recv_only_mode)) != 0) {
            logger<< log4cpp::Priority::INFO<<"pfring_set_socket_mode returned: "<<rc;
        }

        int rehash_rss = 0;

        if (rehash_rss)
            pfring_enable_rss_rehash(threads[i].ring);
  
        int poll_duration = 0; 
        if (poll_duration > 0)
            pfring_set_poll_duration(threads[i].ring, poll_duration);

        pfring_enable_ring(threads[i].ring);

        unsigned long thread_id = i;
        pthread_create(&threads[i].pd_thread, NULL, pf_ring_packet_consumer_thread, (void*)thread_id);
    }

    for(int i = 0; i < num_channels; i++) {
        pthread_join(threads[i].pd_thread, NULL);
        pfring_close(threads[i].ring);
    }

    return true;
}

void* pf_ring_packet_consumer_thread(void* _id) {
    long thread_id = (long)_id;
    int wait_for_packet = 1;

    // TODO: fix it
    bool do_shutdown = false;

    while (!do_shutdown) {
        u_char *buffer = NULL;
        struct pfring_pkthdr hdr;

        if (pfring_recv(threads[thread_id].ring, &buffer, 0, &hdr, wait_for_packet) > 0) {
            // TODO: pass (u_char*)thread_id)
            parse_packet_pf_ring(&hdr, buffer, 0);
        } else {
            if (wait_for_packet == 0) {
                usleep(1); //sched_yield();
            }
        }
   }

   return(NULL);
}
#endif
 
#ifdef PF_RING 
bool pf_ring_main_loop(const char* dev) {
    // We could pool device in multiple threads
    unsigned int num_threads = 1;

    bool promisc = true;
    /* This flag manages packet parser for extended_hdr */
    bool use_extended_pkt_header = true;
    bool enable_hw_timestamp = false;
    bool dont_strip_timestamps = false; 

    u_int32_t flags = 0;
    if (num_threads > 1)         flags |= PF_RING_REENTRANT;
    if (use_extended_pkt_header) flags |= PF_RING_LONG_HEADER;
    if (promisc)                 flags |= PF_RING_PROMISC;
    if (enable_hw_timestamp)     flags |= PF_RING_HW_TIMESTAMP;
    if (!dont_strip_timestamps)  flags |= PF_RING_STRIP_HW_TIMESTAMP;
    flags |= PF_RING_DNA_SYMMETRIC_RSS;  /* Note that symmetric RSS is ignored by non-DNA drivers */ 

    // use default value from pfcount.c
    unsigned int snaplen = 128;

    pf_ring_descr = pfring_open(dev, snaplen, flags); 

    if (pf_ring_descr == NULL) {
        logger<< log4cpp::Priority::INFO<<"pfring_open error: "<<strerror(errno)
            << " (pf_ring not loaded or perhaps you use quick mode and have already a socket bound to: "<<dev<< ")";
        return false;
    }


    logger<< log4cpp::Priority::INFO<<"Successully binded to: "<<dev;
    logger<< log4cpp::Priority::INFO<<"Device RX channels number: "<< pfring_get_num_rx_channels(pf_ring_descr); 

    u_int32_t version;
    // задаемт имя приложения для его указания в переменной PCAP_PF_RING_APPNAME в статистике в /proc 
    int pfring_set_application_name_result =
        pfring_set_application_name(pf_ring_descr, (char*)"fastnetmon");

    if (pfring_set_application_name_result != 0) {
        logger<< log4cpp::Priority::INFO<<"Can't set programm name for PF_RING: pfring_set_application_name";
    }

    pfring_version(pf_ring_descr, &version);

    logger.info(
        "Using PF_RING v.%d.%d.%d",
       (version & 0xFFFF0000) >> 16, (version & 0x0000FF00) >> 8, version & 0x000000FF
    );
    
    int pfring_set_socket_mode_result =  pfring_set_socket_mode(pf_ring_descr, recv_only_mode);

    if (pfring_set_socket_mode_result != 0) {
        logger.info("pfring_set_socket_mode returned [rc=%d]\n", pfring_set_socket_mode_result);
    }  
 
    // enable ring
    if (pfring_enable_ring(pf_ring_descr) != 0) {
        logger<< log4cpp::Priority::INFO<<"Unable to enable ring :-(";
        pfring_close(pf_ring_descr);
        return false;
    }

    // Active wait wor packets. But I did not know what is mean..
    u_int8_t wait_for_packet = 1;

    pfring_loop(pf_ring_descr, parse_packet_pf_ring, (u_char*)NULL, wait_for_packet);

    return true;
}
#endif
 
#ifdef PCAP 
void pcap_main_loop(const char* dev) {
    char errbuf[PCAP_ERRBUF_SIZE];
    /* open device for reading in promiscuous mode */
    int promisc = 1;

    bpf_u_int32 maskp; /* subnet mask */
    bpf_u_int32 netp;  /* ip */ 

    logger<< log4cpp::Priority::INFO<<"Start listening on "<<dev;

    /* Get the network address and mask */
    pcap_lookupnet(dev, &netp, &maskp, errbuf);

    descr = pcap_create(dev, errbuf);

    if (descr == NULL) {
        logger<< log4cpp::Priority::INFO<<"pcap_create was failed with error: "<<errbuf;
        exit(0);
    }

    int set_buffer_size_res = pcap_set_buffer_size(descr, pcap_buffer_size_mbytes * 1024 * 1024);
    if (set_buffer_size_res != 0 ) { // выставляем буфер в 1 мегабайт
        if (set_buffer_size_res == PCAP_ERROR_ACTIVATED) {
            logger<< log4cpp::Priority::INFO<<"Can't set buffer size because pcap already activated\n";
            exit(1);
        } else {
            logger<< log4cpp::Priority::INFO<<"Can't set buffer size due to error: "<<set_buffer_size_res;
            exit(1);
        }   
    } 

    /*
    Вот через этот спец механизм можно собирать лишь хидеры!
    If you don't need the entire contents of the packet - for example, if you are only interested in the TCP headers of packets 
     you can set the "snapshot length" for the capture to an appropriate value.
    */
    /*
    if (pcap_set_snaplen(descr, 32 ) != 0 ) {
        logger<< log4cpp::Priority::INFO<<"Can't set snap len";
        exit(1);
    }
    */

    if (pcap_set_promisc(descr, promisc) != 0) {
        logger<< log4cpp::Priority::INFO<<"Can't activate promisc mode for interface: "<<dev;
        exit(1);
    }

    if (pcap_activate(descr) != 0) {
        logger<< log4cpp::Priority::INFO<<"Call pcap_activate was failed: "<<pcap_geterr(descr);
        exit(1);
    }

    // man pcap-linktype
    int link_layer_header_type = pcap_datalink(descr);

    if (link_layer_header_type == DLT_EN10MB) {
        DATA_SHIFT_VALUE = 14;
    } else if (link_layer_header_type == DLT_LINUX_SLL) {
        DATA_SHIFT_VALUE = 16;
    } else {
        logger<< log4cpp::Priority::INFO<<"We did not support link type:", link_layer_header_type;
        exit(0);
    }
   
    // пока деактивируем pcap, начинаем интегрировать ULOG
    pcap_loop(descr, -1, (pcap_handler)parse_packet, NULL);
}
#endif

// For correct programm shutdown by CTRL+C
void signal_handler(int signal_number) {

#ifdef PCAP
    // Stop PCAP loop
    pcap_breakloop(descr);
#endif

#ifdef PF_RING
    pfring_breakloop(pf_ring_descr);
#endif

#ifdef REDIS
    if (redis_enabled) {
        redisFree(redis_context);
    }
#endif
    /* End ncurses mode */
    endwin(); 
    exit(1); 
}

bool fast_patricia_lookup(patricia_tree_t *patricia_tree, prefix_t* prefix) {
    bool result = patricia_search_best(patricia_tree, prefix) != NULL;
    return result;
}

// DONT USE THIS VERSION!!! USE fast_patricia_lookup instead because this version os so slow!
bool cached_patricia_lookup(patricia_tree_t *patricia_tree, prefix_t* prefix, lpm_cache_t* lpm_cache) {
    bool* lpm_status;

    lpm_status = lpm_cache->fetch_ptr(prefix->add.sin.s_addr);

    if (lpm_status == NULL) {
         bool resolved_status = fast_patricia_lookup(patricia_tree, prefix);
         lpm_cache->insert(prefix->add.sin.s_addr, resolved_status);
        return resolved_status;
    } else {
        return lpm_status;
    }
}

/* Get traffic type: check it belongs to our IPs */
direction get_packet_direction(uint32_t src_ip, uint32_t dst_ip, unsigned long& subnet) {
    direction packet_direction;

    bool our_ip_is_destination = false;
    bool our_ip_is_source = false;

    prefix_t prefix_for_check_adreess;
    prefix_for_check_adreess.add.sin.s_addr = dst_ip;
    prefix_for_check_adreess.family = AF_INET;
    prefix_for_check_adreess.bitlen = 32;

    patricia_node_t* found_patrica_node = NULL;

    unsigned long destination_subnet = 0;
    //if (cached_patricia_lookup(lookup_tree, &prefix_for_check_adreess, lpm_cache)) {
    if (found_patrica_node = patricia_search_best(lookup_tree, &prefix_for_check_adreess)) {
        our_ip_is_destination = true;
        destination_subnet = found_patrica_node->prefix->add.sin.s_addr;
    }    

    prefix_for_check_adreess.add.sin.s_addr = src_ip;

    unsigned long source_subnet = 0;
    //if (cached_patricia_lookup(lookup_tree, &prefix_for_check_adreess, lpm_cache)) {
    if (found_patrica_node = patricia_search_best(lookup_tree, &prefix_for_check_adreess)) { 
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

void execute_ip_ban(uint32_t client_ip, unsigned int in_pps, unsigned int out_pps, unsigned int in_bps, unsigned int out_bps) {
    direction data_direction;
    unsigned int pps = 0;

    // Check attack direction
    if (in_pps > out_pps) {
        data_direction = INCOMING;
        pps = in_pps;
    } else {
        data_direction = OUTGOING;
        pps = out_pps;
    }

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

    bool in_white_list = (patricia_search_best(whitelist_tree, &prefix_for_check_adreess) != NULL);
    
    if (in_white_list) {
        return;
    }  

    string data_direction_as_string = get_direction_name(data_direction);

    logger.info("We run execute_ip_ban code with following params in_pps: %d out_pps: %d in_bps: %d out_bps: %d and we decide it's %s attack",
        in_pps, out_pps, in_bps, out_bps, data_direction_as_string.c_str());

    string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
    string pps_as_string = convert_int_to_string(pps);

    struct attack_details current_attack;

    // фиксируем время бана
    time(&current_attack.ban_timestamp); 
    // set ban time in seconds
    current_attack.ban_time = standard_ban_time;

    // передаем основную информацию об атаке
    current_attack.attack_direction = data_direction;
    current_attack.attack_power = pps;
    current_attack.max_attack_power = pps;

    // передаем вторичные параметры, чтобы иметь более точное представление об атаке
    current_attack.in_packets  = in_pps;
    current_attack.out_packets = out_pps;

    current_attack.in_bytes = in_bps;
    current_attack.out_bytes = out_bps;

    ban_list_mutex.lock();
    ban_list[client_ip] = current_attack;
    ban_list_mutex.unlock();

    ban_list_details[client_ip] = vector<simple_packet>();
                         
    logger<<log4cpp::Priority::INFO<<"Attack with direction: " << data_direction_as_string
        << " IP: " << client_ip_as_string << " Power: "<<pps_as_string;
    
#ifdef HWFILTER_LOCKING
    logger<<log4cpp::Priority::INFO<<"We will block traffic to/from this IP with hardware filters";

    /* 6 - tcp, 17 - udp, 0 - other (non tcp and non udp) */
    vector<int> banned_protocols;
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

            string hw_filter_rule_direction = "";
            if (rule_direction == 0) {
                hw_filter_rule_direction = "outgoing";
                ft_rule->s_addr = ntohl(inet_addr(client_ip_as_string.c_str()));
            } else {
                hw_filter_rule_direction = "incoming";
                ft_rule->d_addr = ntohl(inet_addr(client_ip_as_string.c_str()));
            }

            if (pfring_add_hw_rule(pf_ring_descr, &rule) != 0) {
                logger<<log4cpp::Priority::INFO<<"Can't add hardware filtering rule for protocol: "<<*banned_protocol<<" in direction: "<<hw_filter_rule_direction;
            }

            rule_number ++;
        }
    }

#endif
         
    if (file_exists(notify_script_path)) {
        string script_call_params = notify_script_path + " " + client_ip_as_string + " " +
            data_direction_as_string + " " + pps_as_string + " ban";
       
        logger<<log4cpp::Priority::INFO<<"Call script for ban client: "<<client_ip_as_string; 

        // We should execute external script in separate thread because any lag in this code will be very distructive 
        boost::thread exec_thread(exec, script_call_params);
        exec_thread.detach();

        logger<<log4cpp::Priority::INFO<<"Script for ban client is finished: "<<client_ip_as_string;
    }    
}

/* Thread for cleaning up ban list */
void cleanup_ban_list() {
    /* Время через которое просыпается поток чистки */
    int iteration_sleep_time = 600;

    logger<<log4cpp::Priority::INFO<<"Run banlist cleanup thread";

    while (true) {
        // Sleep for ten minutes
        boost::this_thread::sleep(boost::posix_time::seconds(iteration_sleep_time));

        time_t current_time;
        time(&current_time);

        logger<<log4cpp::Priority::INFO<<"Wake up banlist cleanup function";

        map<uint32_t,banlist_item>::iterator itr = ban_list.begin();
        while (itr != ban_list.end()) {
            uint32_t client_ip = (*itr).first;

            double time_difference = difftime(current_time, ((*itr).second).ban_timestamp);
            int ban_time = ((*itr).second).ban_time;

            if (time_difference > ban_time) {
                // Вычищаем все останки данного забаненого товарища
                string data_direction_as_string = get_direction_name((*itr).second.attack_direction);
                string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
                string pps_as_string = convert_int_to_string((*itr).second.attack_power);

                logger<<log4cpp::Priority::INFO<<"We will unban banned IP: "<<client_ip_as_string<<
                    " because it ban time "<<ban_time<<" seconds is ended";

                ban_list_mutex.lock();
                map<uint32_t,banlist_item>::iterator itr_to_erase = itr;
                itr++;

                ban_list.erase(itr_to_erase);
                ban_list_mutex.unlock();

                if (file_exists(notify_script_path)) {
                    string script_call_params = notify_script_path + " " + client_ip_as_string + " " +
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

string send_ddos_attack_details() {
    stringstream output_buffer;

    for( map<uint32_t,banlist_item>::iterator ii=ban_list.begin(); ii!=ban_list.end(); ++ii) {
        uint32_t client_ip = (*ii).first; 

        string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
        string pps_as_string = convert_int_to_string(((*ii).second).attack_power);
        string max_pps_as_string = convert_int_to_string(((*ii).second).max_attack_power);
        string attack_direction = get_direction_name(((*ii).second).attack_direction);

        output_buffer<<client_ip_as_string<<"/"<<max_pps_as_string<<" pps "<<attack_direction<<endl;

        send_attack_details(client_ip, (*ii).second);
    }


    return output_buffer.str();
}

string get_attack_description(uint32_t client_ip, attack_details& current_attack) {
    stringstream attack_description;

    attack_description
        <<"IP: "<<convert_ip_as_uint_to_string(client_ip)<<"\n"
        <<"Initial attack power: "<<current_attack.attack_power<<" packets per second\n"
        <<"Peak attack power: "<<current_attack.max_attack_power<< " packets per second\n"
        <<"Attack direction: "<<get_direction_name(current_attack.attack_direction)<<"\n"
        <<"Incoming traffic: "<<convert_speed_to_mbps(current_attack.in_bytes)<<" mbps\n"
        <<"Outgoing traffic: "<<convert_speed_to_mbps(current_attack.out_bytes)<<" mbps\n"
        <<"Incoming pps: "<<current_attack.in_packets<<" packets per second\n"
        <<"Outgoing pps: "<<current_attack.out_packets<<" packets per second\n"; 

        return attack_description.str();
}    

string get_protocol_name_by_number(unsigned int proto_number) {
    struct protoent* proto_ent = getprotobynumber( proto_number );
    string proto_name = proto_ent->p_name;
    return proto_name;
}       

void send_attack_details(uint32_t client_ip, attack_details current_attack_details) {
    string pps_as_string = convert_int_to_string(current_attack_details.attack_power);
    string attack_direction = get_direction_name(current_attack_details.attack_direction);
    string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);

    // странная проверка, но при мощной атаке набить ban_details_records_count пакетов - очень легко
    if (ban_list_details.count( client_ip ) > 0 && ban_list_details[ client_ip ].size() == ban_details_records_count) {
        stringstream attack_details;

        attack_details<<get_attack_description(client_ip, current_attack_details)<<"\n\n";

        std::map<unsigned int, unsigned int> protocol_counter;
        for( vector<simple_packet>::iterator iii=ban_list_details[ client_ip ].begin(); iii!=ban_list_details[ client_ip ].end(); ++iii) {
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
            " IP: "<<client_ip_as_string<<" Power: "<<pps_as_string;
        logger<<log4cpp::Priority::INFO<<attack_details.str();

        // отсылаем детали атаки (отпечаток пакетов) по почте
        if (file_exists(notify_script_path)) {
            logger<<log4cpp::Priority::INFO<<"Call script for notify about attack details for: "<<client_ip_as_string;

            string script_params = notify_script_path + " " + client_ip_as_string + " " + attack_direction  + " " + pps_as_string + " ban";

            // We should execute external script in separate thread because any lag in this code will be very distructive 
            boost::thread exec_with_params_thread(exec_with_stdin_params, script_params, attack_details.str());
            exec_with_params_thread.detach();

            logger<<log4cpp::Priority::INFO<<"Script for notify about attack details is finished: "<<client_ip_as_string;
        } 
        // удаляем ключ из деталей атаки, чтобы он не выводился снова и в него не собирался трафик
        ban_list_details.erase(client_ip);
    } 
}


string convert_timeval_to_date(struct timeval tv) {
    time_t nowtime = tv.tv_sec;
    struct tm *nowtm = localtime(&nowtime);
    
    char tmbuf[64];
    char buf[64];

    strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);

    snprintf(buf, sizeof(buf), "%s.%06ld", tmbuf, tv.tv_usec); 

    return string(buf);
}

// http://stackoverflow.com/questions/14528233/bit-masking-in-c-how-to-get-first-bit-of-a-byte
int extract_bit_value(uint8_t num, int bit) {
    if (bit > 0 && bit <= 8) {
        return ( (num >> (bit-1)) & 1 );
    } else {
        return 0;
    }
}

string print_tcp_flags(uint8_t flag_value) {
    if (flag_value == 0) {
        return "";
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

    vector<string> all_flags;

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

    
    ostringstream flags_as_string;

    if (all_flags.empty()) {
        return "-";
    }

    // concatenate all vector elements with comma
    std::copy(all_flags.begin(), all_flags.end() - 1, std::ostream_iterator<string>(flags_as_string, ","));

    // add last element
    flags_as_string << all_flags.back();
    
    return flags_as_string.str();
}

#define BIG_CONSTANT(x) (x##LLU)

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

bool is_cidr_subnet(string subnet) {
    boost::cmatch what;
    if (regex_match(subnet.c_str(), what, regular_expression_cidr_pattern)) {
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
