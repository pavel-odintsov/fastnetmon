/*
 TODO:
  1) Добавить среднюю нагрузку за 30 секунд/минуту/5 минут, хз как ее сделать  -- не уверен, что это нужно 
  2) Подумать на тему выноса всех параметров в конфиг
  3) Подумать как бы сделать лимитер еще по суммарному трафику
  4) Вынести уведомления о ддосах/обсчет данных трафика в отдельный тред
  5) Не забыть сделать синхронизацию при очистке аккумуляторов 
  6) Перенести список бана в структуру черного списка
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
#include <vector>
#include <utility>
#include <sstream>

//#include <thread>

// #include <boost/thread.hpp> - выливается в падение компилятора
// for boost split
#include <boost/algorithm/string.hpp>

#ifdef ULOG2
#include "libipulog.h"
#endif

#ifdef PCAP
#include <pcap.h>
#endif

#ifdef REDIS
#include <hiredis/hiredis.h>
#endif

using namespace std;

/*
 Pcap docs:    
   http://www.linuxforu.com/2011/02/capturing-packets-c-program-libpcap/
   http://vichargrave.com/develop-a-packet-sniffer-with-libpcap/ парсер отсюда
*/

/* Блок конфигурации */
#ifdef REDIS
int redis_port = 6379;
string redis_host = "127.0.0.1";
#endif

#ifdef ULOG2
// номер netlink группы для прослушивания трафика
int ULOGD_NLGROUP_DEFAULT = 1;
/* Size of the socket receive memory.  Should be at least the same size as the 'nlbufsiz' module loadtime parameter of ipt_ULOG.o If you have _big_ in-kernel queues, you may have to increase this number.  (
 * --qthreshold 100 * 1500 bytes/packet = 150kB  */
int ULOGD_RMEM_DEFAULT = 131071;
/* Size of the receive buffer for the netlink socket.  Should be at least of RMEM_DEFAULT size.  */
int ULOGD_BUFSIZE_DEFAULT = 150000;
#endif

int DEBUG = 0;

// Период, через который мы пересчитываем pps/трафик
int check_period = 3;

// Увеличиваем буфер, чтобы минимизировать потери пакетов
int pcap_buffer_size_mbytes = 10;

// По какому критерию мы сортируем клиентов? Допустимые варианты: packets/bytes
string sort_parameter = "packets";

// сколько всего выводим IP адресов в списках?
int max_ips_in_list = 7;

// Баним IP, если он превысил данный порог
int ban_threshold = 20000;

// сколько строк мы высылаем в деталях атаки на почту
int ban_details_records_count = 500;

/* конец блока конфигурации */

/* Блок наших структур данных */

// поле, по которому мы сортируем данные 
enum sort_type { PACKETS, BYTES };

enum direction {INCOMING, OUTGOING, INTERNAL, OTHER};
// структура для "легкого" хранения статистики соединений в памяти 
struct simple_packet {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t source_port;
    uint16_t destination_port;
    int      protocol;
    int      length;
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

typedef map <uint32_t, map_element> map_for_counters;
// data structure for storing data in Vector
typedef pair<uint32_t, map_element> pair_of_map_elements;

/* конец объявления наших структур данных */

#ifdef REDIS
redisContext *redis_context = NULL;
#endif

#ifdef ULOG2
// для подсчета числа ошибок буфера при работе по netlink
int netlink_error_counter = 0;
int netlink_packets_counter = 0;
#endif

#ifdef PCAP
// делаем глобальной, так как нам нужно иметь к ней доступ из обработчика сигнала
pcap_t* descr = NULL;
#endif

// счетчик трафика наш
map_for_counters DataCounter;

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

vector<subnet> our_networks;
vector<subnet> whitelist_networks;

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
void calculation_programm();
void pcap_main_loop(char* dev);
void ulog_main_loop();
void signal_handler(int signal_number);
uint32_t convert_cidr_to_binary_netmask(int cidr);
bool belongs_to_networks(vector<subnet> networks_list, uint32_t ip);

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

void draw_table(map_for_counters& my_map_packets, direction data_direction, bool do_redis_update, sort_type sort_item) {
        std::vector<pair_of_map_elements> vector_for_sort;

        /* Вобщем-то весь код ниже зависит лишь от входных векторов и порядка сортировки данных */
        for( map_for_counters::iterator ii=my_map_packets.begin(); ii!=my_map_packets.end(); ++ii) {
            // кладем все наши элементы в массив для последующей сортировки при отображении
            pair_of_map_elements current_pair = make_pair((*ii).first, (*ii).second);
            vector_for_sort.push_back(current_pair);
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

        } else if (sort_item = BYTES) {
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
 
                    cout<<"!!!ALARM!!! WE MUST BAN THIS IP!!! ";
                    // add IP to BAN list

                    // если клиента еще нету в бан листе
                    if (ban_list.count(client_ip) == 0) {
                        string data_direction_as_string = get_direction_name(data_direction);

                        ban_list[client_ip].first = pps;
                        ban_list[client_ip].second = data_direction;

                        ban_list_details[client_ip] = vector<simple_packet>();
                        cout << "*BAN EXECUTED* ";
               
                        string pps_as_string = convert_int_to_string(pps); 
                        exec("./notify_about_attack.sh " + client_ip_as_string + " " + data_direction_as_string + " " + pps_as_string);
                    } else {
                        // Есдли вдруг атака стала мощнее, то обновим ее предельную мощность в памяти (на почте так и остается старая цифра)
                        // в итоге я решил, что это плохая идея, так как гугл тогда перестает схлопывать темы двух писем идущих подряд =)
                        //if (ban_list[client_ip].first < pps) {
                        //    ban_list[client_ip].first = pps;
                        //}

                        cout << "*BAN EXECUTED* ";
                        // already in ban list
                    }
                } 
            } 

            // Выводим первые max_ips_in_list элементов в списке, при нашей сортировке, будут выданы топ 10 самых грузящих клиентов
            if (element_number < max_ips_in_list) {
                cout << client_ip_as_string << "\t\t" << pps << " pps " << mbps << " mbps" << endl;
            }  
    
            if (do_redis_update) {
                //cout<<"Start updating traffic in redis"<<endl;
                update_traffic_in_redis( (*ii).first, (*ii).second.in_packets, INCOMING);
                update_traffic_in_redis( (*ii).first, (*ii).second.out_packets, OUTGOING);
            }
        
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
    // вносим в белый список, IP из этой сети мы не баним
    subnet white_subnet = std::make_pair(convert_ip_as_string_to_uint("159.253.17.0"), convert_cidr_to_binary_netmask(24));
    whitelist_networks.push_back(white_subnet);

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

    for( vector<string>::iterator ii=networks_list_as_string.begin(); ii!=networks_list_as_string.end(); ++ii) {
        vector<string> subnet_as_string; 
        split( subnet_as_string, *ii, boost::is_any_of("/"), boost::token_compress_on );
        int cidr = atoi(subnet_as_string[1].c_str());

        uint32_t subnet_as_int  = convert_ip_as_string_to_uint(subnet_as_string[0]);
        uint32_t netmask_as_int = convert_cidr_to_binary_netmask(cidr);

        subnet current_subnet = std::make_pair(subnet_as_int, netmask_as_int);

        our_networks.push_back(current_subnet);
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

bool belongs_to_networks(vector<subnet> networks_list, uint32_t ip) {
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

// в случае прямого вызова скрипта колбэка - нужно конст, напрямую в хендлере - конст не нужно
void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, const u_char *packetptr) {
    struct ip* iphdr;
    struct icmphdr* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char iphdrInfo[256], srcip_char[256], dstip_char[256];
    unsigned short id, seq;

    // Skip the datalink layer header and get the IP header fields.
    packetptr += DATA_SHIFT_VALUE;
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

    //count<<print_simple_packet(current_packet);

    direction packet_direction;

    if (belongs_to_networks(our_networks, src_ip) && belongs_to_networks(our_networks, dst_ip)) {
        packet_direction = INTERNAL;

        total_count_of_internal_packets ++;
        total_count_of_internal_bytes += packet_length;

    } else if (belongs_to_networks(our_networks, src_ip)) {
        packet_direction = OUTGOING;

        total_count_of_outgoing_packets ++;
        total_count_of_outgoing_bytes += packet_length;

        // собираем данные для деталей при бане клиента
        if  (ban_list_details.count(src_ip) > 0 && ban_list_details[src_ip].size() < ban_details_records_count) {
            ban_list_details[src_ip].push_back(current_packet);
        }

        DataCounter[ src_ip ].out_packets++; 
        DataCounter[ src_ip ].out_bytes += packet_length;
    } else if (belongs_to_networks(our_networks, dst_ip)) {
        packet_direction = INCOMING;
    
        total_count_of_incoming_packets++;
        total_count_of_incoming_bytes += packet_length;

        // собираемы данные для деталей при бане клиента
        if  (ban_list_details.count(dst_ip) > 0 && ban_list_details[dst_ip].size() < ban_details_records_count) {
            ban_list_details[dst_ip].push_back(current_packet);
        }

        DataCounter[ dst_ip ].in_packets ++;
        DataCounter[ dst_ip ].in_bytes += packet_length;
    } else {
        packet_direction = OTHER;
        total_count_of_other_packets ++;
        total_count_of_other_bytes += packet_length;
    }

    // вынести в отдельный триад
    calculation_programm();
}


void calculation_programm() {
    time_t current_time;
    time(&current_time);
   
    // вынести в поток!!! 
    if ( difftime(current_time, start_time) >= check_period ) {
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

                    // отсылаем детали атаки по почте, к сожалению, без направления атаки только
                    exec_with_stdin_params("./notify_about_attack.sh " + client_ip_as_string + " " + attack_direction  + " " + pps_as_string, attack_details );
                    // удаляем ключ из деталей атаки, чтобы он не выводился снова и в него не собирался трафик
                    ban_list_details.erase((*ii).first); 
                }

            }
        }
        
        // переустанавливаем время запуска
        time(&start_time);
        // зануляем счетчик пакетов
        DataCounter.clear();

        total_count_of_incoming_bytes = 0;
        total_count_of_outgoing_bytes = 0;

        total_count_of_other_packets = 0;
        total_count_of_other_bytes   = 0;

        total_count_of_internal_packets = 0;
        total_count_of_internal_bytes = 0;
 
        total_count_of_incoming_packets = 0;
        total_count_of_outgoing_packets = 0;
    }
}


int main(int argc,char **argv) {
    char *dev; 
    
#ifdef PCAP
    char errbuf[PCAP_ERRBUF_SIZE]; 
    const u_char *packet; 
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;    /* net/ethernet.h */
#endif 

    time(&start_time);
    printf("I need few seconds for collecting data, please wait. Thank you!\n");
 
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

    // загружаем наши сети и whitelist 
    load_our_networks_list();

    // устанавливаем обработчик CTRL+C
    signal(SIGINT, signal_handler);

    // запускаем поток-обсчета данных
    //thread calculation_thread(calculation_programm);

#ifdef PCAP
    pcap_main_loop(dev);
#endif

#ifdef ULOG2 
    ulog_main_loop();
#endif

    return 0;
}
   
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
 

// для корректной остановки программы по CTRL+C
void signal_handler(int signal_number) {

#ifdef PCAP
    // останавливаем PCAP цикл
    pcap_breakloop(descr);
#endif

#ifdef REDIS
    redisFree(redis_context);
#endif

    exit(1); 
}


