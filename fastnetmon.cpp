/* Author: pavel.odintsov@gmail.com */
/* License: GPLv2 */

#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

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

// C++ 11
#include <thread>
#include <chrono>
#include <mutex>

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
#include <boost/unordered_map.hpp>

// We use boost unordered map instead standard map because it faster:
// http://tinodidriksen.com/2009/07/09/cpp-map-speeds/
// standard map:         41% cpu in top
// boost::unordered_map: 25% cpu in top

// It's buggy, http://www.stableit.ru/2013/11/unorderedmap-c11-debian-wheezy.html
// #include <unordered_map>
// When we used unordered_map it will increase it perfomance
// DataCounter.reserve(MAP_INITIAL_SIZE);

#ifdef ULOG2
#include "libipulog.h"
#endif

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

time_t last_call_of_traffic_recalculation;

/* Configuration block, we must move it to configuration file  */
#ifdef REDIS
int redis_port = 6379;
string redis_host = "127.0.0.1";
// because it's additional and very specific feature we should disable it by default
bool redis_enabled = false;
#endif

typedef LRUCache<uint32_t, bool> lpm_cache_t;

// LPM cache
lpm_cache_t *lpm_cache = NULL;

#ifdef GEOIP
GeoIP * geo_ip = NULL;
#endif

patricia_tree_t *lookup_tree, *whitelist_tree;

#ifdef ULOG2
// netlink group number for listening for traffic
int ULOGD_NLGROUP_DEFAULT = 1;
/* Size of the socket receive memory.  Should be at least the same size as the 'nlbufsiz' module loadtime
   parameter of ipt_ULOG.o If you have _big_ in-kernel queues, you may have to increase this number.  (
 * --qthreshold 100 * 1500 bytes/packet = 150kB  */

int ULOGD_RMEM_DEFAULT = 131071;

/* Size of the receive buffer for the netlink socket.  Should be at least of RMEM_DEFAULT size.  */
int ULOGD_BUFSIZE_DEFAULT = 150000;
#endif

int DEBUG = 0;

// flag about dumping all packets to console
bool DEBUG_DUMP_ALL_PACKETS = false;

// Period for recounting pps/traffic
int check_period = 3;

#ifdef PCAP
// Enlarge receive buffer for PCAP for minimize packet drops
int pcap_buffer_size_mbytes = 10;
#endif

// Key used for sorting clients in output.  Allowed sort params: packets/bytes
string sort_parameter = "packets";

// Path to notify script 
string notify_script_path = "/usr/local/bin/notify_about_attack.sh";

// Number of lines in programm output
int max_ips_in_list = 7;

// We must ban IP if it exceeed this limit in PPS
int ban_threshold = 20000;

// Number of lines for sending ben attack details to email
int ban_details_records_count = 500;


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
    int bytes;
    int packets;
} total_counter_element;

// We count total number of incoming/outgoing/internal and other traffic type packets/bytes
// And initilize by 0 all fields
total_counter_element total_counters[4]{};

// simplified packet struct for lightweight save into memory
struct simple_packet {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t source_port;
    uint16_t destination_port;
    int      protocol;
    int      length;
    struct   timeval ts;
};

typedef pair<int, direction> banlist_item;
typedef pair<uint32_t, uint32_t> subnet;

// main data structure for storing traffic data for all our IPs
typedef struct {
    int in_bytes;
    int out_bytes;
    int in_packets;
    int out_packets;
} map_element;

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t src_ip;
    uint32_t dst_ip; 
} conntrack_key;

// TODO: please put back boost::unordered_map
// switched off because segfaults
typedef boost::unordered_map <uint32_t, map_element> map_for_counters;
// data structure for storing data in Vector
typedef pair<uint32_t, map_element> pair_of_map_elements;

/* End of our data structs */

std::mutex data_counters_mutex;
std::mutex speed_counters_mutex;
std::mutex total_counters_mutex;

#ifdef REDIS
redisContext *redis_context = NULL;
#endif

#ifdef ULOG2
// For counting number of communication errors via netlink
int netlink_error_counter = 0;
int netlink_packets_counter = 0;
#endif

#ifdef PCAP
// pcap handler, we want it as global variable beacuse it used in singnal handler
pcap_t* descr = NULL;
#endif

#ifdef PF_RING
pfring* pf_ring_descr = NULL;
#endif

// main map for storing traffic data
map_for_counters DataCounter;

// структура для сохранения мгновенных скоростей
map_for_counters SpeedCounter;

#ifdef GEOIP
map_for_counters GeoIpCounter;
#endif

// В информации о ддосе мы храним силу атаки и ее направление
map<uint32_t, banlist_item> ban_list;
map<uint32_t, vector<simple_packet> > ban_list_details;

// стандартно у нас смещение для типа DLT_EN10MB, Ethernet
int DATA_SHIFT_VALUE = 14;

// начальный размер unordered_map для хранения данных
int MAP_INITIAL_SIZE = 2048;

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
string send_ddos_attack_details();
void execute_ip_ban(uint32_t client_ip, int in_pps, int out_pps, int in_bps, int out_bps);
direction get_packet_direction(uint32_t src_ip, uint32_t dst_ip);
void recalculate_speed();
std::string print_channel_speed(string traffic_type, direction packet_direction, int check_period);
void process_packet(simple_packet& current_packet);
void copy_networks_from_string_form_to_binary(vector<string> networks_list_as_string, vector<subnet>& our_networks);

bool file_exists(string path);
void calculation_programm();
void pcap_main_loop(char* dev);
void pf_ring_main_loop(char* dev);
void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, const u_char *packetptr);
void ulog_main_loop();
void signal_handler(int signal_number);
uint32_t convert_cidr_to_binary_netmask(int cidr);

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

void update_traffic_in_redis(uint32_t ip, int traffic_bytes, direction my_direction) {
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
        for( auto ii = my_map_packets.begin(); ii != my_map_packets.end(); ++ii) {
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

        int element_number = 0;
        for( auto ii=vector_for_sort.begin(); ii!=vector_for_sort.end(); ++ii) {
            uint32_t client_ip = (*ii).first;
            string client_ip_as_string = convert_ip_as_uint_to_string((*ii).first);

            int pps = 0; 
            int bps = 0; 

            // делаем "полиморфную" полосу и ппс
            if (data_direction == INCOMING) {
                pps = SpeedCounter[client_ip].in_packets;
                bps = SpeedCounter[client_ip].in_bytes;
            } else if (data_direction == OUTGOING) {
                pps = SpeedCounter[client_ip].out_packets;
                bps = SpeedCounter[client_ip].out_bytes;
            }    

            int mbps = int((double)bps / 1024 / 1024 * 8);

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

    ifstream reading_file (file_name);
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
bool load_configuration_file() {
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
            ban_threshold = convert_string_to_integer( configuration_map[ "threshold_pps" ] );
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

bool load_our_networks_list() {
    if (file_exists("/etc/networks_whitelist")) {
        vector<string> network_list_from_config = read_file_to_vector("/etc/networks_whitelist");

        for( auto ii=network_list_from_config.begin(); ii!=network_list_from_config.end(); ++ii) { 
            make_and_lookup(whitelist_tree, const_cast<char*>(ii->c_str())); 
        }

        logger<<log4cpp::Priority::INFO<<"We loaded "<<network_list_from_config.size()<< " networks from whitelist file";
    }
 
    vector<string> networks_list_as_string;
    // если мы на openvz ноде, то "свои" IP мы можем получить из спец-файла в /proc
    if (file_exists("/proc/vz/version")) {
        logger<< log4cpp::Priority::INFO<<"We found OpenVZ";
        // тут искусствено добавляем суффикс 32
        vector<string> openvz_ips = read_file_to_vector("/proc/vz/veip");
        for( auto ii=openvz_ips.begin(); ii!=openvz_ips.end(); ++ii) {
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
    } 

    if (file_exists("/etc/networks_list")) { 
        vector<string> network_list_from_config = read_file_to_vector("/etc/networks_list");
        networks_list_as_string.insert(networks_list_as_string.end(), network_list_from_config.begin(), network_list_from_config.end());

        logger<<log4cpp::Priority::INFO<<"We loaded "<<network_list_from_config.size()<< " networks from networks file";
    }

    // если это ложь, то в моих функциях косяк
    assert( convert_ip_as_string_to_uint("255.255.255.0")   == convert_cidr_to_binary_netmask(24) );
    assert( convert_ip_as_string_to_uint("255.255.255.255") == convert_cidr_to_binary_netmask(32) );

    for( auto ii=networks_list_as_string.begin(); ii!=networks_list_as_string.end(); ++ii) { 
        make_and_lookup(lookup_tree, const_cast<char*>(ii->c_str())); 
    }    

    return true;
}

void copy_networks_from_string_form_to_binary(vector<string> networks_list_as_string, vector<subnet>& our_networks ) {
    for( auto ii=networks_list_as_string.begin(); ii!=networks_list_as_string.end(); ++ii) {
        vector<string> subnet_as_string; 
        split( subnet_as_string, *ii, boost::is_any_of("/"), boost::token_compress_on );
        int cidr = convert_string_to_integer(subnet_as_string[1]);

        uint32_t subnet_as_int  = convert_ip_as_string_to_uint(subnet_as_string[0]);
        uint32_t netmask_as_int = convert_cidr_to_binary_netmask(cidr);

        subnet current_subnet = std::make_pair(subnet_as_int, netmask_as_int);

        our_networks.push_back(current_subnet);
    }  
} 

uint32_t convert_cidr_to_binary_netmask(int cidr) {
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
     

    buffer
        <<convert_ip_as_uint_to_string(packet.src_ip)<<":"<<packet.source_port
        <<" > "
        <<convert_ip_as_uint_to_string(packet.dst_ip)<<":"<<packet.destination_port
        <<" protocol: "<<proto_name
        <<" size: "<<packet.length<<" bytes"<<"\n";
    // используется \n вместо endl, ибо иначе начинается хрень всякая при передаче данной строки команде на stdin

    return buffer.str();
}

// Обработчик для pf_ring, так как у него иной формат входных параметров
void parse_packet_pf_ring(const struct pfring_pkthdr *h, const u_char *p, const u_char *user_bytes) {
    // Описание всех полей: http://www.ntop.org/pfring_api/structpkt__parsing__info.html
    simple_packet packet;

    /* We handle only IPv4 */
    if (h->extended_hdr.parsed_pkt.ip_version == 4) {
        /* PF_RING хранит данные в host byte order, а мы использум только network byte order */
        packet.src_ip = htonl( h->extended_hdr.parsed_pkt.ip_src.v4 ); 
        packet.dst_ip = htonl( h->extended_hdr.parsed_pkt.ip_dst.v4 );

        packet.source_port = h->extended_hdr.parsed_pkt.l4_src_port;
        packet.destination_port = h->extended_hdr.parsed_pkt.l4_dst_port;

        packet.length = h->len;
        packet.protocol = h->extended_hdr.parsed_pkt.l3_proto;

        // We must put TS into to packet
        //logger<< log4cpp::Priority::INFO<<"sec: "<<h->ts.tv_sec<<" nanosec:"<<h->ts.tv_usec;
        packet.ts = h->ts;
 
        process_packet(packet);
        //std::cout<<print_simple_packet(packet)<<std::endl;
        //printf("hash%d\n",h->extended_hdr.pkt_hash);
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
    int packet_length = ntohs(iphdr->ip_len); 

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


/* Производим обработку уже переданного нам пакета в простом формате */
void process_packet(simple_packet& current_packet) { 
    // Packets dump is very useful for bug hunting
    if (DEBUG_DUMP_ALL_PACKETS) {
        logger<< log4cpp::Priority::INFO<<"Dump: "<<print_simple_packet(current_packet);
    }

    direction packet_direction = get_packet_direction(current_packet.src_ip, current_packet.dst_ip);

    total_counters_mutex.lock();
    total_counters[packet_direction].packets++;
    total_counters[packet_direction].bytes += current_packet.length;
    total_counters_mutex.unlock();

    if (packet_direction == INTERNAL) {
    
    } else if (packet_direction == OUTGOING) {
        // собираем данные для деталей при бане клиента
        if  (ban_list_details.count(current_packet.src_ip) > 0 &&
            ban_list_details[current_packet.src_ip].size() < ban_details_records_count) {

            ban_list_details[current_packet.src_ip].push_back(current_packet);
        }

        data_counters_mutex.lock();
        DataCounter[ current_packet.src_ip ].out_packets++; 
        DataCounter[ current_packet.src_ip ].out_bytes += current_packet.length;
        data_counters_mutex.unlock();
 
    } else if (packet_direction == INCOMING) {
        // собираемы данные для деталей при бане клиента
        if  (ban_list_details.count(current_packet.dst_ip) > 0 &&
            ban_list_details[current_packet.dst_ip].size() < ban_details_records_count) {

            ban_list_details[current_packet.dst_ip].push_back(current_packet);
        }

        data_counters_mutex.lock();
        DataCounter[ current_packet.dst_ip ].in_packets ++;
        DataCounter[ current_packet.dst_ip ].in_bytes += current_packet.length;
        data_counters_mutex.unlock();
    } else {
        // Other traffic
    }
}

#ifdef GEOIP
int get_asn_for_ip(uint32_t ip) { 
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

    while (1) {
        std::this_thread::sleep_for(std::chrono::seconds( check_period ));
        calculation_programm();
    }
}

void recalculate_speed_thread_handler() {
    while (1) {
        // recalculate data every one second
        std::this_thread::sleep_for(std::chrono::seconds( 1 ));
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

    // calculate speed for all our IPs
    for( auto ii = DataCounter.begin(); ii != DataCounter.end(); ++ii) {
        uint32_t client_ip = (*ii).first;
            
        int in_pps  = int((double)(*ii).second.in_packets   / (double)speed_calc_period);
        int out_pps = int((double)(*ii).second.out_packets / (double)speed_calc_period);

        int in_bps  = int((double)(*ii).second.in_bytes  / (double)speed_calc_period);
        int out_bps = int((double)(*ii).second.out_bytes / (double)speed_calc_period);     

        // we detect overspeed
        if (in_pps > ban_threshold or out_pps > ban_threshold) {
            execute_ip_ban(client_ip, in_pps, out_pps, in_bps, out_bps);
        }

        speed_counters_mutex.lock();
        // add speed values to speed struct
        SpeedCounter[client_ip].in_bytes    = in_bps;
        SpeedCounter[client_ip].out_bytes   = out_bps;

        SpeedCounter[client_ip].in_packets  = in_pps;
        SpeedCounter[client_ip].out_packets = out_pps;
        speed_counters_mutex.unlock();

        data_counters_mutex.lock();
        DataCounter[client_ip].in_bytes = 0;
        DataCounter[client_ip].out_bytes = 0;
        DataCounter[client_ip].in_packets = 0;
        DataCounter[client_ip].out_packets = 0;
        data_counters_mutex.unlock();
    }

    // устанавливаем время прошлого запуска данного скрипта
    time(&last_call_of_traffic_recalculation);
}

void calculation_programm() {
    stringstream output_buffer;

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

    output_buffer<<"FastNetMon v1.0 "<<"IPs ordered by: "<<sort_parameter<<" "<<"threshold is: "<<ban_threshold<<" number of our hosts: "<<DataCounter.size()<<endl<<endl;

    output_buffer<<print_channel_speed("Incoming Traffic", INCOMING, check_period)<<endl;
    output_buffer<<draw_table(SpeedCounter, INCOMING, true, sorter);
    
    output_buffer<<endl; 
    
    output_buffer<<print_channel_speed("Outgoing traffic", OUTGOING, check_period)<<endl;
    output_buffer<<draw_table(SpeedCounter, OUTGOING, false, sorter);

    output_buffer<<endl;

    output_buffer<<print_channel_speed("Internal traffic", INTERNAL, check_period)<<endl;

    output_buffer<<endl;

    output_buffer<<print_channel_speed("Other traffic", OTHER, check_period)<<endl;

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

#ifdef ULOG2
       output_buffer<<"ULOG buffer errors: "   << netlink_error_counter<<" ("<<int((double)netlink_error_counter/netlink_packets_counter)<<"%)"<<endl; 
       output_buffer<<"ULOG packets received: "<< netlink_packets_counter<<endl;
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

    total_counters_mutex.lock();

    for (int index = 0; index < 4; index++) {
        total_counters[index].bytes = 0;
        total_counters[index].packets = 0;
    }

    total_counters_mutex.unlock();
}

// pretty print channel speed in pps and MBit
std::string print_channel_speed(string traffic_type, direction packet_direction, int check_period) {

    int total_number_of_packets = total_counters[packet_direction].packets;
    int total_number_of_bytes   = total_counters[packet_direction].bytes;

    // Потому что к нам скорость приходит в чистом виде 
    int number_of_tabs = 1; 
    // We need this for correct alignment of blocks
    if (traffic_type == "Other traffic") {
        number_of_tabs = 2;
    }
 
    std::stringstream stream;
    stream<<traffic_type;

    for (int i = 0; i < number_of_tabs; i ++ ) {
        stream<<"\t";
    }

    int speed_in_pps    = int( (double)total_number_of_packets/(double)check_period );
    double speed_in_bps = (double)total_number_of_bytes/(double)check_period;
    int speed_in_mbps   = int(speed_in_bps/1024/1024*8);

    stream<<speed_in_pps<<" pps "<< speed_in_mbps<<" mbps"; 
    return stream.str();
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
    // listened device
    char* dev; 

    lpm_cache = new lpm_cache_t(16);

    lookup_tree = New_Patricia(32);
    whitelist_tree = New_Patricia(32);

    // enable core dumps
    enable_core_dumps();

    init_logging();

    /* Init ncurses screen */
    initscr();
   
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

#ifdef PF_RING
    
    if (work_on_interfaces == "" && argc != 2) {
        fprintf(stdout, "Usage: %s \"eth0\" or \"eth0,eth1\" or specify interfaces param in config file\n", argv[0]);
        exit(1);
    }
   
    if (work_on_interfaces != "") {
        dev = const_cast<char*>(work_on_interfaces.c_str());
    } else {
        dev = argv[1];
    }    

    logger<< log4cpp::Priority::INFO<<"We selected interface:"<<dev;

#endif
 
#ifdef PCAP 
    if (argc != 2) {
        fprintf(stdout, "Usage: %s \"eth0\" or \"any\"\n", argv[0]);

        logger<< log4cpp::Priority::INFO<< "We must automatically select interface";
        /* Now get a device */
        dev = pcap_lookupdev(errbuf);
        
        if(dev == NULL) {
            logger<< log4cpp::Priority::INFO<<"Can't lookup device for pcap:" << errbuf;
            exit (1);    
        }

        logger << log4cpp::Priority::INFO<< "Automatically selected device: " << dev;

    } else { 
        dev = argv[1];
    }
#endif

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

    // запускаем поток-обсчета данных
    thread calc_thread(calculation_thread);
    // start thread for recalculating speed in realtime
    thread recalculate_speed_thread(recalculate_speed_thread_handler);

    // инициализируем псевдо дату последнего запуска
    time(&last_call_of_traffic_recalculation);

#ifdef PCAP
    pcap_main_loop(dev);
#endif

#ifdef PF_RING
    pf_ring_main_loop(dev);
#endif

#ifdef ULOG2 
    thread ulog_thread(ulog_main_loop);
    ulog_thread.join();
#endif

    recalculate_speed_thread.join();
    calc_thread.join();
#ifdef GEOIP
    // Free up geoip handle 
    GeoIP_delete(geo_ip);
#endif

    Destroy_Patricia(lookup_tree,    (void_fn_t)0);
    Destroy_Patricia(whitelist_tree, (void_fn_t)0);
 
    return 0;
}
  
#ifdef PF_RING 
void pf_ring_main_loop(char* dev) {
    // We could pool device in multiple threads
    int num_threads = 1;

    int promisc = 1;
    /* This flag manages packet parser for extended_hdr */
    u_int8_t use_extended_pkt_header = 1;
    u_int8_t touch_payload = 0, enable_hw_timestamp = 0, dont_strip_timestamps = 0;    

    u_int32_t flags = 0;
    if (num_threads > 1)         flags |= PF_RING_REENTRANT;
    if (use_extended_pkt_header) flags |= PF_RING_LONG_HEADER;
    if (promisc)                 flags |= PF_RING_PROMISC;
    if (enable_hw_timestamp)     flags |= PF_RING_HW_TIMESTAMP;
    if (!dont_strip_timestamps)  flags |= PF_RING_STRIP_HW_TIMESTAMP;
    flags |= PF_RING_DNA_SYMMETRIC_RSS;  /* Note that symmetric RSS is ignored by non-DNA drivers */ 

    // use default value from pfcount.c
    int snaplen = 128;

    pf_ring_descr = pfring_open(dev, snaplen, flags); 

    if(pf_ring_descr == NULL) {
        logger<< log4cpp::Priority::INFO<<"pfring_open error: "<<strerror(errno)
            << " (pf_ring not loaded or perhaps you use quick mode and have already a socket bound to: "<<dev<< ")";
        exit(1);
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
    
    int rc;
    if((rc = pfring_set_socket_mode(pf_ring_descr, recv_only_mode)) != 0)
        logger.info("pfring_set_socket_mode returned [rc=%d]\n", rc);
   
    /*
    Этот код требуется, когда мы сами пишем какую-либо свою статистику в ядерный модуль PF_RING 
    char path[256] = { 0 };
    if (pfring_get_appl_stats_file_name(pf_ring_descr, path, sizeof(path)) != NULL) {
        logger.info("Dumping statistics on %s\n", path);
    }
    */

    // enable ring
    if (pfring_enable_ring(pf_ring_descr) != 0) {
        logger<< log4cpp::Priority::INFO<<"Unable to enable ring :-(";
        pfring_close(pf_ring_descr);
        exit(-1);
    }

    // Active wait wor packets. But I did not know what is mean..
    u_int8_t wait_for_packet = 1;
 
    pfring_loop(pf_ring_descr, parse_packet_pf_ring, (u_char*)NULL, wait_for_packet);
}
#endif
 
#ifdef PCAP 
void pcap_main_loop(char* dev) {
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

#ifdef ULOG2
void ulog_main_loop() {
    // В загрузке модуля есть параметры: modprobe ipt_ULOG nlbufsiz=131072
    // Увеличиваем размер буфера в ядре, так как стандартно он всего-то 3712    
    // Текущий размер буфера смотреть:  /sys/module/ipt_ULOG/parameters/nlbufsiz
    // В рантайме его указать нельзя, только при загрузке модуля ipt_ULOG

    struct ipulog_handle *libulog_h;
    unsigned char *libulog_buf;

    libulog_buf = (unsigned char*)malloc(ULOGD_BUFSIZE_DEFAULT);
    if (!libulog_buf) {
        logger<< log4cpp::Priority::INFO<<"Can't allocate buffer";
        exit(1);
    }

    libulog_h = ipulog_create_handle(ipulog_group2gmask(ULOGD_NLGROUP_DEFAULT), ULOGD_RMEM_DEFAULT);

    if (!libulog_h) {
        logger<< log4cpp::Priority::INFO<<"Can't create ipulog handle";
        exit(0);
    }
    
    int len;
    while ( len = ipulog_read(libulog_h, libulog_buf, ULOGD_BUFSIZE_DEFAULT) ) {
        if (len <= 0) {
            if (errno == EAGAIN) {
                break;
            }

            if (errno == 105) {
                // Наш уютный бажик: errno = '105' ('No buffer space available'
                netlink_error_counter++;
                continue;
            }

            // поймали ошибку - зафиксируем ее при расчетах
            logger.info("ipulog_read = '%d'! "
                "ipulog_errno = '%d' ('%s'), "
                "errno = '%d' ('%s')\n",
                len, ipulog_errno,
                ipulog_strerror(ipulog_errno),
                errno, strerror(errno));

            continue;
        } 

        // успешний прием пакета
        netlink_packets_counter++;

        ulog_packet_msg_t *upkt;
        while ((upkt = ipulog_get_packet(libulog_h, libulog_buf, len))) {
            // вот такой хитрый хак, так как данные начинаются без ethernet хидера и нам не нужно выполнять никакого смещения
            DATA_SHIFT_VALUE = 0;
            parse_packet(NULL, NULL, upkt->payload);
        }
    }

    free(libulog_buf);
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
    return patricia_search_best(patricia_tree, prefix) != NULL;
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
direction get_packet_direction(uint32_t src_ip, uint32_t dst_ip) {
    direction packet_direction;

    bool our_ip_is_destination = false;
    bool our_ip_is_source = false;

    prefix_t prefix_for_check_adreess;
    prefix_for_check_adreess.add.sin.s_addr = dst_ip;
    prefix_for_check_adreess.family = AF_INET;
    prefix_for_check_adreess.bitlen = 32;

    //if (cached_patricia_lookup(lookup_tree, &prefix_for_check_adreess, lpm_cache)) {
    if (fast_patricia_lookup(lookup_tree, &prefix_for_check_adreess)) {
        our_ip_is_destination = true;
    }    

    prefix_for_check_adreess.add.sin.s_addr = src_ip;

    //if (cached_patricia_lookup(lookup_tree, &prefix_for_check_adreess, lpm_cache)) {
    if (fast_patricia_lookup(lookup_tree, &prefix_for_check_adreess)) { 
        our_ip_is_source = true;
    }    

    if (our_ip_is_source && our_ip_is_destination) {
        packet_direction = INTERNAL;
    } else if (our_ip_is_source) {
        packet_direction = OUTGOING;
    } else if (our_ip_is_destination) {
        packet_direction = INCOMING;
    } else {
        packet_direction = OTHER;
    }

    return packet_direction;
}

void execute_ip_ban(uint32_t client_ip, int in_pps, int out_pps, int in_bps, int out_bps) {
    direction data_direction;
    int pps = 0;

    // Check attack direction
    if (in_pps > out_pps) {
        data_direction = INCOMING;
        pps = in_pps; 
    } else {
        data_direction = OUTGOING;
        pps = out_pps;
    }

    string data_direction_as_string = get_direction_name(data_direction);
    string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
    string pps_as_string = convert_int_to_string(pps);

    prefix_t prefix_for_check_adreess;
    prefix_for_check_adreess.add.sin.s_addr = client_ip;
    prefix_for_check_adreess.family = AF_INET;
    prefix_for_check_adreess.bitlen = 32;

    bool in_white_list = (patricia_search_best(whitelist_tree, &prefix_for_check_adreess) != NULL);
    
    if (in_white_list) {
        /*
        logger<<log4cpp::Priority::INFO<<"Attack with direction: " << data_direction_as_string
            << " IP: " << client_ip_as_string << " This IP is whitelisted, we IGNORE it and do not do anything" << " Power: "<<pps_as_string;
        */
        return;
    }    

    // если клиента еще нету в бан листе
    if (ban_list.count(client_ip) == 0) { 
        ban_list[client_ip] = make_pair(pps, data_direction);
        ban_list_details[client_ip] = vector<simple_packet>();
                         
        logger<<log4cpp::Priority::INFO<<"Attack with direction: " << data_direction_as_string
            << " IP: " << client_ip_as_string << " Power: "<<pps_as_string;
             
        if (file_exists(notify_script_path)) {
            string script_call_params = notify_script_path + " " + client_ip_as_string + " " +
                data_direction_as_string + " " + pps_as_string;
       
            logger<<log4cpp::Priority::INFO<<"Call script for ban client: "<<client_ip_as_string; 

            // We should execute external script in separate thread because 
            //std::thread exec_thread(exec, script_call_params);
            // detach thread explicitly from main thread
            // exec_thread.detach();
            exec(script_call_params);

            logger<<log4cpp::Priority::INFO<<"Script for ban client is finished: "<<client_ip_as_string;
        }    
    } else {
        // already banned
    }    
}

string send_ddos_attack_details() {
    stringstream output_buffer;

    for( auto ii=ban_list.begin(); ii!=ban_list.end(); ++ii) {
        string client_ip_as_string = convert_ip_as_uint_to_string((*ii).first);
        string pps_as_string = convert_int_to_string(((*ii).second).first);

        string attack_direction = get_direction_name(((*ii).second).second);

        output_buffer<<client_ip_as_string<<"/"<<pps_as_string<<" pps "<<attack_direction<<endl;

        // странная проверка, но при мощной атаке набить ban_details_records_count пакетов - очень легко
        if (ban_list_details.count( (*ii).first  ) > 0 && ban_list_details[ (*ii).first ].size() == ban_details_records_count) {
            stringstream attack_details;
            for( auto iii=ban_list_details[ (*ii).first ].begin(); iii!=ban_list_details[ (*ii).first ].end(); ++iii) {
                attack_details<<print_simple_packet( *iii );
            }

            logger<<log4cpp::Priority::INFO<<"Attack with direction: "<<attack_direction<<
                " IP: "<<client_ip_as_string<<" Power: "<<pps_as_string;
            logger<<log4cpp::Priority::INFO<<attack_details.str();

            // отсылаем детали атаки (отпечаток пакетов) по почте
            if (file_exists(notify_script_path)) {
                logger<<log4cpp::Priority::INFO<<"Call script for notify about attack details for: "<<client_ip_as_string;

                exec_with_stdin_params(notify_script_path + " " + client_ip_as_string + " " +
                    attack_direction  + " " + pps_as_string, attack_details.str() );

                logger<<log4cpp::Priority::INFO<<"Script for notify about attack details is finished: "<<client_ip_as_string;
            }
            // удаляем ключ из деталей атаки, чтобы он не выводился снова и в него не собирался трафик
            ban_list_details.erase((*ii).first);
        }
    }

    return output_buffer.str();
}
