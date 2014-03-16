/*
 TODO:
  1) Add network average load for 30 second/60 and 5 minutes
  2) Migrate params to configuration
  3) Migrate ban list to blacklist struct
  4) Enable work as standard linux user with CAP Admin
  5) Migrate belongs_to_network to prefix bitwise tree
  6) Please do not create big network's list, it will be result to slooww ip lookup
  7) http://hg.python.org/cpython/file/3fa1414ce505/Lib/heapq.py#l183 - поиск топ 10
  8) Try libsparsehash-dev
*/

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
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include <algorithm>
#include <iostream>
#include <map>

// so buggy, http://www.stableit.ru/2013/11/unorderedmap-c11-debian-wheezy.html
//#include <unordered_map>

#include <vector>
#include <utility>
#include <sstream>

// C++ 11
#include <thread>
#include <chrono>
#include <mutex>

// Boost lib for strings split
#include <boost/algorithm/string.hpp>

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

/* This is the decimal equivalent of the VLAN tag's ether frame type */
#define VLAN_ETHERTYPE 33024


/*
 Pcap docs:    
   http://www.linuxforu.com/2011/02/capturing-packets-c-program-libpcap/
   http://vichargrave.com/develop-a-packet-sniffer-with-libpcap/ парсер отсюда
*/

/* Configuration block, we must move it to configuration file  */
#ifdef REDIS
int redis_port = 6379;
string redis_host = "127.0.0.1";
#endif

#ifdef GEOIP
GeoIP * geo_ip = NULL;
#endif

#ifdef ULOG2
// netlink group number for listening for traffic
int ULOGD_NLGROUP_DEFAULT = 1;
/* Size of the socket receive memory.  Should be at least the same size as the 'nlbufsiz' module loadtime parameter of ipt_ULOG.o If you have _big_ in-kernel queues, you may have to increase this number.  (
 * --qthreshold 100 * 1500 bytes/packet = 150kB  */

int ULOGD_RMEM_DEFAULT = 131071;
/* Size of the receive buffer for the netlink socket.  Should be at least of RMEM_DEFAULT size.  */
int ULOGD_BUFSIZE_DEFAULT = 150000;
#endif

int DEBUG = 0;

// Period for recounting pps/traffic
int check_period = 3;

#ifdef PCAP
// Enlarge receive buffer for PCAP for minimize packet drops
int pcap_buffer_size_mbytes = 10;
#endif

// Key used for sorting clients in output.  Allowed sort params: packets/bytes
string sort_parameter = "packets";

// Number of lines in programm output
int max_ips_in_list = 7;

// We must ban IP if it exceeed this limit in PPS
int ban_threshold = 20000;

// Number of lines for sending ben attack details to email
int ban_details_records_count = 500;

/* Configuration block ends */

/* Our data structs */

// Enum with availible sort by field
enum sort_type { PACKETS, BYTES };

enum direction {INCOMING, OUTGOING, INTERNAL, OTHER};

// simplified packet struct for lightweight save into memory
struct simple_packet {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t source_port;
    uint16_t destination_port;
    int      protocol;
    int      length;
};


// Struct for Long Prefix Match Tree
typedef struct leaf {
    bool bit;
    bool end_of_path;
    struct leaf *right, *left;
} tree_leaf;

typedef pair<int, direction> banlist_item;
typedef pair<uint32_t, uint32_t> subnet;

// main data structure for storing traffic data for all our IPs
typedef struct {
    int in_bytes;
    int out_bytes;
    int in_packets;
    int out_packets;
} map_element;

typedef map <uint32_t, map_element> map_for_counters;
// data structure for storing data in Vector
typedef pair<uint32_t, map_element> pair_of_map_elements;

/// buffers for parser
char iphdrInfo[256], srcip_char[256], dstip_char[256];

/* End of our data structs */

std::mutex counters_mutex;

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

#ifdef GEOIP
map_for_counters GeoIpCounter;
#endif

int total_count_of_incoming_packets = 0;
int total_count_of_outgoing_packets = 0;
int total_count_of_other_packets = 0;
int total_count_of_internal_packets = 0;

int total_count_of_incoming_bytes = 0;
int total_count_of_outgoing_bytes = 0;
int total_count_of_other_bytes = 0;
int total_count_of_internal_bytes = 0;

// В информации о ддосе мы храним силу атаки и ее направление
map<uint32_t, banlist_item> ban_list;
map<uint32_t, vector<simple_packet> > ban_list_details;

time_t start_time;

// стандартно у нас смещение для типа DLT_EN10MB, Ethernet
int DATA_SHIFT_VALUE = 14;

// начальный размер unordered_map для хранения данных
int MAP_INITIAL_SIZE = 2048;

vector<subnet> our_networks;
vector<subnet> whitelist_networks;
//tree_leaf* our_networks;
//tree_leaf* whitelist_networks;

/* 
 Тут кроется огромный баго-фич:
  В случае прослушивания any интерфейсов мы ловим фичу-баг, вместо эзернет хидера у нас тип 113, который LINUX SLL, а следовательно размер хидера не 14, а 16 байт! 
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
void insert_prefix_bitwise_tree(tree_leaf* root, string subnet, int cidr_mask); 
//bool belongs_to_networks(tree_leaf* root, uint32_t ip);
bool belongs_to_networks(vector<subnet>& networks_list, uint32_t ip);

/*
Old on strings compare:
23.56      0.53     0.53 10000000     0.00     0.00  belongs_to_networks(std::vector<std::pair<unsigned int, unsigned int>, std::a     llocator<std::pair<unsigned int, unsigned int> > >&, unsigned int)

Fast lookup tree:
14.67      1.21     0.33 10000000     0.00     0.00  fast_ip_lookup(leaf*, unsigned int)
*/

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

string convert_ip_as_uint_to_string(uint32_t ip_as_string) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ip_as_string;
    return (string)inet_ntoa(ip_addr);
}

// convert integer to string
string convert_int_to_string(int value) {
    string pps_as_string;
    std::stringstream out;
    out << value;

    return out.str();
}

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
        printf("Connection error: %s\n", redis_context->errstr);
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
        printf("Please initialize Redis handle");
        return;
    }

    string key_name = ip_as_string + "_" + get_direction_name(my_direction);
    reply = (redisReply *)redisCommand(redis_context, "INCRBY %s %s", key_name.c_str(), convert_int_to_string(traffic_bytes).c_str());

    // Только в случае, если мы обновили без ошибки
    if (!reply) {
        printf("Can't increment traffic in redis error_code: %d error_string: %s", redis_context->err, redis_context->errstr);
   
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

// TODO: унифицировать с draw_table
void draw_asn_table(map_for_counters& my_map_packets, direction data_direction) {
    std::vector<pair_of_map_elements> vector_for_sort;

    for( map_for_counters::iterator ii=my_map_packets.begin(); ii!=my_map_packets.end(); ++ii) {
        vector_for_sort.push_back( make_pair((*ii).first, (*ii).second) );
    }

    // sort ONLY BY BYTES!!!

    // используем разные сортировочные функции 
    if (data_direction == INCOMING) {
        std::sort( vector_for_sort.begin(), vector_for_sort.end(), compare_function_by_in_bytes);
    } else if (data_direction == OUTGOING) {
        std::sort( vector_for_sort.begin(), vector_for_sort.end(), compare_function_by_out_bytes);
    } else {
        // unexpected
    }

    int element_number = 0;
    for( vector<pair_of_map_elements>::iterator ii=vector_for_sort.begin(); ii!=vector_for_sort.end(); ++ii) {
            uint32_t client_ip = (*ii).first;
            string asn_as_string = convert_int_to_string((*ii).first);

            int in_pps = (*ii).second.in_packets   / check_period;
            int out_pps = (*ii).second.out_packets / check_period;

            int in_bps  = (*ii).second.in_bytes  / check_period;
            int out_bps = (*ii).second.out_bytes / check_period;

            int pps = 0;
            int bps = 0;

            // делаем "полиморфную" полосу и ппс
            if (data_direction == INCOMING) {
                pps = in_pps;
                bps = in_bps;
            } else if (data_direction == OUTGOING) {
                pps = out_pps;
                bps = out_bps;
            }

            int mbps = int((double)bps / 1024 / 1024 * 8);

            // Выводим первые max_ips_in_list элементов в списке, при нашей сортировке, будут выданы топ 10 самых грузящих клиентов
            if (element_number < max_ips_in_list) {
                cout << asn_as_string << "\t\t" << pps << " pps " << mbps << " mbps" << endl;
            }

            element_number++;
    }
}

void draw_table(map_for_counters& my_map_packets, direction data_direction, bool do_redis_update, sort_type sort_item) {
        std::vector<pair_of_map_elements> vector_for_sort;

        /* Вобщем-то весь код ниже зависит лишь от входных векторов и порядка сортировки данных */
        for( map_for_counters::iterator ii=my_map_packets.begin(); ii!=my_map_packets.end(); ++ii) {
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
            assert("Unexpected bahaviour");
        }

        int element_number = 0;
        for( vector<pair_of_map_elements>::iterator ii=vector_for_sort.begin(); ii!=vector_for_sort.end(); ++ii) {
            uint32_t client_ip = (*ii).first;
            string client_ip_as_string = convert_ip_as_uint_to_string((*ii).first);

            int in_pps = (*ii).second.in_packets   / check_period;
            int out_pps = (*ii).second.out_packets / check_period;

            int in_bps  = (*ii).second.in_bytes  / check_period;
            int out_bps = (*ii).second.out_bytes / check_period; 

            int pps = 0;
            int bps = 0;

            // делаем "полиморфную" полосу и ппс
            if (data_direction == INCOMING) {
                pps = in_pps; 
                bps = in_bps;
            } else if (data_direction == OUTGOING) {
                pps = out_pps;
                bps = out_bps;
            }

            int mbps = int((double)bps / 1024 / 1024 * 8);

            if (pps > ban_threshold) {
                if (belongs_to_networks(whitelist_networks, client_ip)) {
                    // IP в белом списке 
                } else {
                    // если клиента еще нету в бан листе
                    if (ban_list.count(client_ip) == 0) {
                        string data_direction_as_string = get_direction_name(data_direction);
                        ban_list[client_ip] = make_pair(pps, data_direction);

                        ban_list_details[client_ip] = vector<simple_packet>();
               
                        string pps_as_string = convert_int_to_string(pps); 
                        exec("./notify_about_attack.sh " + client_ip_as_string + " " + data_direction_as_string + " " + pps_as_string);
                    }
                } 
            } 

            // Выводим первые max_ips_in_list элементов в списке, при нашей сортировке, будут выданы топ 10 самых грузящих клиентов
            if (element_number < max_ips_in_list) {
                string is_banned = ban_list.count(client_ip) > 0 ? " *banned* " : "";
                cout << client_ip_as_string << "\t\t" << pps << " pps " << mbps << " mbps" << is_banned << endl;
            }  
   
#ifdef REDIS 
            if (do_redis_update) {
                //cout<<"Start updating traffic in redis"<<endl;
                update_traffic_in_redis( (*ii).first, (*ii).second.in_packets, INCOMING);
                update_traffic_in_redis( (*ii).first, (*ii).second.out_packets, OUTGOING);
            }
#endif
        
            element_number++;
        } 
}

bool file_exists(string path) {
    FILE* check_file = fopen(path.c_str(), "r");
    if (check_file) {
        fclose(check_file);
        return true;
    } else {
        return false;
    }
}

bool load_our_networks_list() {
    // enable core dumps
    exec("ulimit -c unlimited");

    // вносим в белый список, IP из этой сети мы не баним
    //whitelist_networks = new tree_leaf;    
    //whitelist_networks->left = whitelist_networks->right = NULL;
    // whitelist_networks.end_of_path = false;

    //insert_prefix_bitwise_tree(whitelist_networks, "159.253.17.0", 24);
    
    subnet white_subnet = std::make_pair(convert_ip_as_string_to_uint("159.253.17.0"), convert_cidr_to_binary_netmask(24));
    whitelist_networks.push_back(white_subnet);
    
    // Whet we used unordered_map it will encrease it perfomance
    //DataCounter.reserve(MAP_INITIAL_SIZE);

    vector<string> networks_list_as_string;
    // если мы на openvz ноде, то "свои" IP мы можем получить из спец-файла в /proc
    string our_networks_netmask;

    if (file_exists("/proc/vz/version")) {
        cout<<"We found OpenVZ"<<endl;
        // тут искусствено добавляем суффикс 32
        networks_list_as_string = exec("cat /proc/vz/veip | awk '{print $1\"/32\"}' |grep -vi version |grep -v ':'");
    } 

    if (file_exists("/etc/networks_list")) { 
        vector<string> network_list_from_config = exec("cat /etc/networks_list");
        networks_list_as_string.insert(networks_list_as_string.end(), network_list_from_config.begin(), network_list_from_config.end());
    }

    // если это ложь, то в моих функциях косяк
    assert( convert_ip_as_string_to_uint("255.255.255.0")   == convert_cidr_to_binary_netmask(24) );
    assert( convert_ip_as_string_to_uint("255.255.255.255") == convert_cidr_to_binary_netmask(32) );

    //our_networks.push_back(current_subnet); 

    //our_networks = new tree_leaf;
    //our_networks->left = our_networks->right = NULL;

    for( vector<string>::iterator ii=networks_list_as_string.begin(); ii!=networks_list_as_string.end(); ++ii) {
        vector<string> subnet_as_string; 
        split( subnet_as_string, *ii, boost::is_any_of("/"), boost::token_compress_on );
        int cidr = atoi(subnet_as_string[1].c_str());

        uint32_t subnet_as_int  = convert_ip_as_string_to_uint(subnet_as_string[0]);
        uint32_t netmask_as_int = convert_cidr_to_binary_netmask(cidr);

        subnet current_subnet = std::make_pair(subnet_as_int, netmask_as_int);

        our_networks.push_back(current_subnet);
        //insert_prefix_bitwise_tree(our_networks, subnet_as_string[0], cidr);
    }
 
    return true;
}





uint32_t convert_cidr_to_binary_netmask(int cidr) {
    uint32_t binary_netmask = 0xFFFFFFFF; 
    binary_netmask = binary_netmask << ( 32 - cidr );
    // htonl from host byte order to network
    // ntohl from network byte order to host

    // поидее, на выходе тут нужен network byte order 
    return htonl(binary_netmask);
}

bool belongs_to_networks(vector<subnet>& networks_list, uint32_t ip) {
    for( vector<subnet>::iterator ii=networks_list.begin(); ii!=networks_list.end(); ++ii) {

        if ( (ip & (*ii).second) == ((*ii).first & (*ii).second) ) {
            return true; 
        }
    }

    return false;
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
    parse_packet(NULL, NULL, p);
}

// в случае прямого вызова скрипта колбэка - нужно конст, напрямую в хендлере - конст не нужно
void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, const u_char *packetptr) {
    struct ip* iphdr;
    struct icmphdr* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    unsigned short id, seq;

    struct ether_header *eptr;    /* net/ethernet.h */
    eptr = (struct ether_header* )packetptr;

    /*
    if (ntohs(eptr->ether_type) ==  VLAN_ETHERTYPE) {
        std::cout<<"TAGGED"<<endl;
    } else {
        std::cout<<"NOT TAGGED"<<endl;
    } 
    */
   
    // проверяем тип эзернет фрейма и его принадлежность к типу "фрейм с VLAN" 
    if ( ntohs(eptr->ether_type) ==  VLAN_ETHERTYPE ) {
        // это тегированный трафик, поэтому нужно отступить еще 4 байта, чтобы добраться до данных
        packetptr += DATA_SHIFT_VALUE + VLAN_HDRLEN;
    } else {
        // Skip the datalink layer header and get the IP header fields.
        packetptr += DATA_SHIFT_VALUE;
    }

    iphdr = (struct ip*)packetptr;

    // исходящий/входящий айпи это in_addr, http://man7.org/linux/man-pages/man7/ip.7.html
    strcpy(srcip_char, inet_ntoa(iphdr->ip_src));
    strcpy(dstip_char, inet_ntoa(iphdr->ip_dst));

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

    //cout<<"Dump: "<<print_simple_packet(current_packet);
    direction packet_direction;

    // try to cache succesful lookups
    bool our_ip_is_destination = DataCounter.count(dst_ip) > 0;
    bool our_ip_is_source      = DataCounter.count(src_ip) > 0;

    if (! our_ip_is_destination) {
        our_ip_is_destination = belongs_to_networks(our_networks, dst_ip);
    }

    if (!our_ip_is_source) {
        our_ip_is_source      = belongs_to_networks(our_networks, src_ip);
    }

    if (our_ip_is_source && our_ip_is_destination) {
        packet_direction = INTERNAL;

        counters_mutex.lock();
        total_count_of_internal_packets ++;
        total_count_of_internal_bytes += packet_length;
        counters_mutex.unlock();

    } else if (our_ip_is_source) {
        packet_direction = OUTGOING;

        counters_mutex.lock();
        total_count_of_outgoing_packets ++;
        total_count_of_outgoing_bytes += packet_length;
        counters_mutex.unlock();

        // собираем данные для деталей при бане клиента
        if  (ban_list_details.count(src_ip) > 0 && ban_list_details[src_ip].size() < ban_details_records_count) {
            ban_list_details[src_ip].push_back(current_packet);
        }

        counters_mutex.lock();
        DataCounter[ src_ip ].out_packets++; 
        DataCounter[ src_ip ].out_bytes += packet_length;
        counters_mutex.unlock();
 
    } else if (our_ip_is_destination) {
        packet_direction = INCOMING;
    
        counters_mutex.lock();
        total_count_of_incoming_packets++;
        total_count_of_incoming_bytes += packet_length;
        counters_mutex.unlock();

        // собираемы данные для деталей при бане клиента
        if  (ban_list_details.count(dst_ip) > 0 && ban_list_details[dst_ip].size() < ban_details_records_count) {
            ban_list_details[dst_ip].push_back(current_packet);
        }

        counters_mutex.lock();
        DataCounter[ dst_ip ].in_packets ++;
        DataCounter[ dst_ip ].in_bytes += packet_length;
        counters_mutex.unlock();
    } else {
        packet_direction = OTHER;

        counters_mutex.lock();
        total_count_of_other_packets ++;
        total_count_of_other_bytes += packet_length;
        counters_mutex.unlock();
    }

#ifdef GEOIP
    // Execute GeoIP lookup
    if (packet_direction == INCOMING or packet_direction == OUTGOING) {
        uint32_t remote_ip = packet_direction == INCOMING ? src_ip : dst_ip; 
        
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
            asn_number = atoi(asn_as_string[0].substr(2).c_str()); 
            // packet_length
        }

        // кладем данные по трафику ASN в хэш
        counters_mutex.lock();

#ifdef GEOIP
        if (packet_direction == INCOMING) {
            // Incoming
            GeoIpCounter[ asn_number ].out_packets++;
            GeoIpCounter[ asn_number ].out_bytes += packet_length;
        } else {
            // Outgoing
            GeoIpCounter[ asn_number ].in_packets++;
            GeoIpCounter[ asn_number ].in_bytes += packet_length;
        }
#endif

        counters_mutex.unlock();
    }
#endif

#ifdef THREADLESS
    calculation_programm();
#endif
}


// void* void* data
void calculation_thread() {
    while (1) {
        //sleep(check_period);
        std::this_thread::sleep_for(std::chrono::seconds( check_period ));
        calculation_programm();
    }
}

void calculation_programm() {
    time_t current_time;
    time(&current_time);

#ifdef THREADLESS 
    if ( difftime(current_time, start_time) >= check_period ) {
#endif
        // clean up screen
        system("clear");

        sort_type sorter;
        if (sort_parameter == "packets") {
            sorter = PACKETS;
        } else if (sort_parameter == "bytes") {
            sorter = BYTES;
        }

        cout<<"FastNetMon v1.0 "<<"all IPs ordered by: "<<sort_parameter<<endl<<endl;

        cout<<"Incoming Traffic"<<"\t"<<total_count_of_incoming_packets/check_period<<" pps "<<total_count_of_incoming_bytes/check_period/1024/1024*8<<" mbps"<<endl;
        draw_table(DataCounter, INCOMING, true, sorter);
    
        cout<<endl; 

        cout<<"Outgoing traffic"<<"\t"<<total_count_of_outgoing_packets/check_period<<" pps "<<total_count_of_outgoing_bytes/check_period/1024/1024*8<<" mbps"<<endl;
        draw_table(DataCounter, OUTGOING, false, sorter);

        cout<<endl;

        cout<<"Internal traffic"<<"\t"<<total_count_of_internal_packets/check_period<<" pps"<<endl;    

        cout<<endl;

        cout<<"Other traffic"<<"\t\t"<<total_count_of_other_packets/check_period<<" pps"<<endl;

        cout<<endl;

        // TODO: ВРЕМЕННО ДЕАКТИВИРОВАНО
#ifdef GEOIP
        if (false) {
            cout<<"Incoming channel: ASN traffic\n";
            draw_asn_table(GeoIpCounter, OUTGOING);
            cout<<endl;    

            cout<<"Outgoing channel: ASN traffic\n";
            draw_asn_table(GeoIpCounter, INCOMING);
            cout<<endl;
        }   
#endif 

#ifdef PCAP
        struct pcap_stat current_pcap_stats;
        if (pcap_stats(descr, &current_pcap_stats) == 0) {
            cout<<"PCAP statistics"<<endl<<"Received packets: "<<current_pcap_stats.ps_recv<<endl
                <<"Dropped packets: "<<current_pcap_stats.ps_drop
                <<" ("<<int((double)current_pcap_stats.ps_drop/current_pcap_stats.ps_recv*100)<<"%)"<<endl
                <<"Dropped by driver or interface: "<<current_pcap_stats.ps_ifdrop<<endl;
        }
#endif

#ifdef ULOG2
       cout<<"ULOG buffer errors: "   << netlink_error_counter<<" ("<<int((double)netlink_error_counter/netlink_packets_counter)<<"%)"<<endl; 
       cout<<"ULOG packets received: "<< netlink_packets_counter<<endl;
#endif

#ifdef PF_RING
        pfring_stat pfring_status_data;
        if(pfring_stats(pf_ring_descr, &pfring_status_data) >= 0) {
            printf(
                "Packets received:\t%lu\n"
                "Packets dropped:\t%lu\n"
                "Packets dropped:\t%.1f %%\n",
                (long unsigned int) pfring_status_data.recv,
                (long unsigned int) pfring_status_data.drop,
                (double) pfring_status_data.drop/pfring_status_data.recv*100
            ); 
        } else {
            cout<<"Can't get PF_RING stats"<<endl;
        }
#endif 
 
        if (ban_list.size() > 0) {
            cout<<endl<<"Ban list:"<<endl;  
 
            for( map<uint32_t,banlist_item>::iterator ii=ban_list.begin(); ii!=ban_list.end(); ++ii) {
                string client_ip_as_string = convert_ip_as_uint_to_string((*ii).first);
                string pps_as_string = convert_int_to_string(((*ii).second).first);

                string attack_direction = get_direction_name(((*ii).second).second);

                cout<<client_ip_as_string<<"/"<<pps_as_string<<" pps "<<attack_direction<<endl;

                // странная проверка, но при мощной атаке набить ban_details_records_count пакетов - очень легко
                if (ban_list_details.count( (*ii).first  ) > 0 && ban_list_details[ (*ii).first ].size() == ban_details_records_count) {
                    string attack_details;
                    for( vector<simple_packet>::iterator iii=ban_list_details[ (*ii).first ].begin(); iii!=ban_list_details[ (*ii).first ].end(); ++iii) {
                        attack_details += print_simple_packet( *iii );
                    }

                    // отсылаем детали атаки (отпечаток пакетов) по почте
                    exec_with_stdin_params("./notify_about_attack.sh " + client_ip_as_string + " " + attack_direction  + " " + pps_as_string, attack_details );
                    // удаляем ключ из деталей атаки, чтобы он не выводился снова и в него не собирался трафик
                    ban_list_details.erase((*ii).first); 
                }

            }
        }
        
        // переустанавливаем время запуска
        time(&start_time);
        // зануляем счетчик пакетов

        counters_mutex.lock();
        DataCounter.clear();

#ifdef GEOIP
        GeoIpCounter.clear();
#endif 

        total_count_of_incoming_bytes = 0;
        total_count_of_outgoing_bytes = 0;

        total_count_of_other_packets = 0;
        total_count_of_other_bytes   = 0;

        total_count_of_internal_packets = 0;
        total_count_of_internal_bytes = 0;
 
        total_count_of_incoming_packets = 0;
        total_count_of_outgoing_packets = 0;
        counters_mutex.unlock();
#ifdef THREADLESS
    }
#endif
}


int main(int argc,char **argv) {
    // listened device
    char *dev; 
    
#ifdef PCAP
    char errbuf[PCAP_ERRBUF_SIZE]; 
    const u_char *packet; 
    struct pcap_pkthdr hdr;
#endif 

    time(&start_time);
    printf("I need few seconds for collecting data, please wait. Thank you!\n");

#ifdef PF_RING
    
    if (argc != 2) {
        fprintf(stdout, "Usage: %s \"eth0\" or \"eth0,eth1\"\n", argv[0]);
        exit(1);
    }
    
    dev = argv[1];
    fprintf(stdout, "We selected %s\n", dev);

#endif
 
#ifdef PCAP 
    if (argc != 2) {
        fprintf(stdout, "Usage: %s \"eth0\" or \"any\"\n", argv[0]);

        cout<< "We must automatically select interface"<<endl;
        /* Now get a device */
        dev = pcap_lookupdev(errbuf);
        
        if(dev == NULL) {
            fprintf(stderr, "%s\n", errbuf);
            exit (1);    
        }

        printf("Automatically selected %s device\n", dev);

    } else { 
        dev = argv[1];
    }
#endif

    // иницилизируем соединение с Redis
#ifdef REDIS
    if (!redis_init_connection()) {
        printf("Can't establish connection to the redis\n");
        exit(1);
    }
#endif

    // иницилизируем GeoIP
#ifdef GEOIP
    if(!geoip_init()) {
        printf("Can't load geoip tables");
        exit(1);
    } 
#endif

    // загружаем наши сети и whitelist 
    load_our_networks_list();

    // устанавливаем обработчик CTRL+C
    signal(SIGINT, signal_handler);

#ifndef THREADLESS
    // запускаем поток-обсчета данных
    thread calc_thread(calculation_thread);
#endif

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

    calc_thread.join();
   
#ifdef GEOIP
    // Free up geoip handle 
    GeoIP_delete(geo_ip);
#endif
 
    return 0;
}
  
#ifdef PF_RING 
void pf_ring_main_loop(char* dev) {
    // We could pool device in multiple threads
    int num_threads = 1;

    int promisc = 1;
    u_int8_t use_extended_pkt_header = 0, touch_payload = 0, enable_hw_timestamp = 0, dont_strip_timestamps = 0;    

    u_int32_t flags = 0;
    if(num_threads > 1)         flags |= PF_RING_REENTRANT;
    if(use_extended_pkt_header) flags |= PF_RING_LONG_HEADER;
    if(promisc)                 flags |= PF_RING_PROMISC;
    if(enable_hw_timestamp)     flags |= PF_RING_HW_TIMESTAMP;
    if(!dont_strip_timestamps)  flags |= PF_RING_STRIP_HW_TIMESTAMP;
    flags |= PF_RING_DNA_SYMMETRIC_RSS;  /* Note that symmetric RSS is ignored by non-DNA drivers */ 

    // use default value from pfcount.c
    int snaplen = 128;
    pf_ring_descr = pfring_open(dev, snaplen, flags);

    if(pf_ring_descr == NULL) {
        fprintf(stderr, "pfring_open error [%s] (pf_ring not loaded or perhaps you use quick mode and have already a socket bound to %s ?)\n", strerror(errno), dev);
        exit(1);
    } else {
        fprintf(stdout, "Successully binded to: %s\n", dev);

        /*
        u_char mac_address[6] = { 0 };
        if(pfring_get_bound_device_address(pf_ring_descr, mac_address) != 0) {
            fprintf(stderr, "Unable to read the device address\n");
        } else {
            int ifindex = -1; 

            pfring_get_bound_device_ifindex(pf_ring_descr, &ifindex);
            printf("Capturing from %s [%s][ifIndex: %d]\n", dev, mac_address, ifindex);
        }
        */ 

        fprintf(stdout, "Device RX channels number: %d\n", pfring_get_num_rx_channels(pf_ring_descr));

        u_int32_t version;
        // задаемт имя приложения для его указания в переменной PCAP_PF_RING_APPNAME в статистике в /proc 
        pfring_set_application_name(pf_ring_descr, (char*)"fastnetmon");
        pfring_version(pf_ring_descr, &version);

        fprintf(stdout, "Using PF_RING v.%d.%d.%d\n",
           (version & 0xFFFF0000) >> 16, 
           (version & 0x0000FF00) >> 8,
           version & 0x000000FF);
    }
    
    int rc;
    if((rc = pfring_set_socket_mode(pf_ring_descr, recv_only_mode)) != 0)
        fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);

    char path[256] = { 0 };
    if(pfring_get_appl_stats_file_name(pf_ring_descr, path, sizeof(path)) != NULL)
        fprintf(stderr, "Dumping statistics on %s\n", path);

    // enable ring
    if (pfring_enable_ring(pf_ring_descr) != 0) {
        printf("Unable to enable ring :-(\n");
        pfring_close(pf_ring_descr);
        exit(-1);
    }

    // WTF?
    u_int8_t wait_for_packet = 1;
 
    pfring_loop(pf_ring_descr, parse_packet_pf_ring, (u_char*)NULL, wait_for_packet);
}
#endif
 
#ifdef PCAP 
void pcap_main_loop(char* dev) {
    char errbuf[PCAP_ERRBUF_SIZE];
    /* open device for reading in promiscuous mode */
    int promisc = 1;
    int pcap_read_timeout = -1;

    bpf_u_int32 maskp; /* subnet mask */
    bpf_u_int32 netp;  /* ip */ 

    cout<<"Start listening on "<<dev<<endl;

    /* Get the network address and mask */
    pcap_lookupnet(dev, &netp, &maskp, errbuf);

    descr = pcap_create(dev, errbuf);

    if (descr == NULL) {
        printf("pcap_create was failed with error: %s", errbuf);
        exit(0);
    }

    int set_buffer_size_res = pcap_set_buffer_size(descr, pcap_buffer_size_mbytes * 1024 * 1024);
    if (set_buffer_size_res != 0 ) { // выставляем буфер в 1 мегабайт
        if (set_buffer_size_res == PCAP_ERROR_ACTIVATED) {
            printf("Can't set buffer size because pcap already activated\n");
            exit(1);
        } else {
            printf("Can't set buffer size due to error %d\n", set_buffer_size_res);
            exit(1);
        }   
    } 

    /*
    Вот через этот спец механизм можно собирать лишь хидеры!
    If you don't need the entire contents of the packet - for example, if you are only interested in the TCP headers of packets - you can set the "snapshot length" for the capture to an appropriate value.
    */
    /*
    if (pcap_set_snaplen(descr, 32 ) != 0 ) {
        printf("Can't set snap len\n");
        exit(1);
    }
    */

    if (pcap_set_promisc(descr, promisc) != 0) {
        printf("Can't activate promisc mode for interface: %s\n", dev);
        exit(1);
    }

    if (pcap_activate(descr) != 0) {
        printf("Call pcap_activate was failed: %s\n", pcap_geterr(descr));
        exit(1);
    }

    // В общем-то можно фильтровать то, что нам падает от PCAP, но в моем случае это совершенно не требуется
    // тут было argv[1], но я убрал фильтрацию
    /* Now we'll compile the filter expression*/
    // struct bpf_program fp;        /* hold compiled program */
    //if(pcap_compile(descr, &fp, "", 0, netp) == -1) {
    //    fprintf(stderr, "Error calling pcap_compile\n");
    //    exit(1);

    //} 
 
    /* set the filter */
    //if(pcap_setfilter(descr, &fp) == -1) {
    //    fprintf(stderr, "Error setting filter\n");
    //    exit(1);
    //} 
 
    // man pcap-linktype
    int link_layer_header_type = pcap_datalink(descr);

    if (link_layer_header_type == DLT_EN10MB) {
        DATA_SHIFT_VALUE = 14;
    } else if (link_layer_header_type == DLT_LINUX_SLL) {
        DATA_SHIFT_VALUE = 16;
    } else {
        printf("We did not support link type %d\n", link_layer_header_type);
        exit(0);
    }
   
    // пока деактивируем pcap, начинаем интегрировать ULOG
    pcap_loop(descr, -1, (pcap_handler)parse_packet, NULL);

    /*  
    Альтернативный парсер, пока не совсем корректно работает, так как возвращает NULL
    const u_char* packetptr;
    struct pcap_pkthdr packethdr;
    while ( (packetptr = pcap_next(descr, &packethdr) ) != NULL) { 
        parse_packet(NULL, &packethdr, packetptr);
    } 
    */ 
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
        printf("Can't allocate buffer");
        exit(1);
    }

    libulog_h = ipulog_create_handle(ipulog_group2gmask(ULOGD_NLGROUP_DEFAULT), ULOGD_RMEM_DEFAULT);

    if (!libulog_h) {
        printf("Can't create ipulog handle");
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
            printf("ipulog_read = '%d'! "
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
    redisFree(redis_context);
#endif

    exit(1); 
}

void dump_ip_lookup_tree(tree_leaf* root) {

}
