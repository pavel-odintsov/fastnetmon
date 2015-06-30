#include <sys/types.h>
#include <stdint.h>
#include "fast_library.h"
#include <arpa/inet.h>
#include <stdlib.h> // atoi
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/socket.h>
#include <fstream>
#include <iostream>

#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
// Source: https://gist.github.com/pavel-odintsov/d13684600423d1c5e64e
#define be64toh(x) OSSwapBigToHostInt64(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#endif

// For be64toh and htobe64
#if defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/endian.h>
#endif

boost::regex regular_expression_cidr_pattern("^\\d+\\.\\d+\\.\\d+\\.\\d+\\/\\d+$");

// convert string to integer
int convert_string_to_integer(std::string line) {
    return atoi(line.c_str());
}

// Type safe versions of ntohl, ntohs with type control
uint16_t fast_ntoh(uint16_t value) {
    return ntohs(value);
}

uint32_t fast_ntoh(uint32_t value) {
    return ntohl(value);
}

// network (big endian) byte order to host byte order
uint64_t fast_ntoh(uint64_t value) {
    return be64toh(value);
}

// Type safe version of htonl, htons
uint16_t fast_hton(uint16_t value) {
    return htons(value);
}

uint32_t fast_hton(uint32_t value) {
    return htonl(value);
}

uint64_t fast_hton(uint64_t value) {
    // host to big endian (network byte order)
    return htobe64(value);
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

void copy_networks_from_string_form_to_binary(std::vector<std::string> networks_list_as_string,
                                              std::vector<subnet_t>& our_networks) {
    for (std::vector<std::string>::iterator ii = networks_list_as_string.begin();
         ii != networks_list_as_string.end(); ++ii) {
        std::vector<std::string> subnet_as_string;
        split(subnet_as_string, *ii, boost::is_any_of("/"), boost::token_compress_on);
        unsigned int cidr = convert_string_to_integer(subnet_as_string[1]);

        uint32_t subnet_as_int = convert_ip_as_string_to_uint(subnet_as_string[0]);
        uint32_t netmask_as_int = convert_cidr_to_binary_netmask(cidr);

        subnet_t current_subnet = std::make_pair(subnet_as_int, netmask_as_int);

        our_networks.push_back(current_subnet);
    }
}

std::string convert_subnet_to_string(subnet_t my_subnet) {
    std::stringstream buffer;

    buffer<<convert_ip_as_uint_to_string(my_subnet.first)<<"/"<<my_subnet.second;

    return buffer.str();
}

// extract 24 from 192.168.1.1/24
unsigned int get_cidr_mask_from_network_as_string(std::string network_cidr_format) {
    std::vector<std::string> subnet_as_string;
    split(subnet_as_string, network_cidr_format, boost::is_any_of("/"), boost::token_compress_on);

    if (subnet_as_string.size() != 2) {
        return 0;
    }

    return convert_string_to_integer(subnet_as_string[1]);
}


std::string print_time_t_in_fastnetmon_format(time_t current_time) {
    struct tm* timeinfo;
    char buffer[80];

    timeinfo = localtime(&current_time);

    strftime(buffer, sizeof(buffer), "%d_%m_%y_%H:%M:%S", timeinfo);

    return std::string(buffer);
}

// extract 192.168.1.1 from 192.168.1.1/24
std::string get_net_address_from_network_as_string(std::string network_cidr_format) {
    std::vector<std::string> subnet_as_string;
    split(subnet_as_string, network_cidr_format, boost::is_any_of("/"), boost::token_compress_on);

    if (subnet_as_string.size() != 2) {
        return 0;
    }

    return subnet_as_string[0];
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

uint32_t convert_cidr_to_binary_netmask(unsigned int cidr) {
    uint32_t binary_netmask = 0xFFFFFFFF;
    binary_netmask = binary_netmask << (32 - cidr);
    // htonl from host byte order to network
    // ntohl from network byte order to host

    // We need network byte order at output
    return htonl(binary_netmask);
}


bool is_cidr_subnet(const char* subnet) {
    boost::cmatch what;
    if (regex_match(subnet, what, regular_expression_cidr_pattern)) {
        return true;
    } else {
        return false;
    }
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

#define BIG_CONSTANT(x) (x##LLU)

/*

    // calculate hash
    unsigned int seed = 11;
    uint64_t hash = MurmurHash64A(&current_packet, sizeof(current_packet), seed);

*/

// https://code.google.com/p/smhasher/source/browse/trunk/MurmurHash2.cpp
// 64-bit hash for 64-bit platforms
uint64_t MurmurHash64A(const void* key, int len, uint64_t seed) {
    const uint64_t m = BIG_CONSTANT(0xc6a4a7935bd1e995);
    const int r = 47;

    uint64_t h = seed ^ (len * m);

    const uint64_t* data = (const uint64_t*)key;
    const uint64_t* end = data + (len / 8);

    while (data != end) {
        uint64_t k = *data++;

        k *= m;
        k ^= k >> r;
        k *= m;

        h ^= k;
        h *= m;
    }

    const unsigned char* data2 = (const unsigned char*)data;

    switch (len & 7) {
    case 7:
        h ^= uint64_t(data2[6]) << 48;
    case 6:
        h ^= uint64_t(data2[5]) << 40;
    case 5:
        h ^= uint64_t(data2[4]) << 32;
    case 4:
        h ^= uint64_t(data2[3]) << 24;
    case 3:
        h ^= uint64_t(data2[2]) << 16;
    case 2:
        h ^= uint64_t(data2[1]) << 8;
    case 1:
        h ^= uint64_t(data2[0]);
        h *= m;
    };

    h ^= h >> r;
    h *= m;
    h ^= h >> r;

    return h;
}

// http://www.gnu.org/software/libc/manual/html_node/Elapsed-Time.html
int timeval_subtract(struct timeval* result, struct timeval* x, struct timeval* y) {
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

    if (extract_bit_value(flag_value, TCP_FIN_FLAG_SHIFT)) {
        all_flags.push_back("fin");
    }

    if (extract_bit_value(flag_value, TCP_SYN_FLAG_SHIFT)) {
        all_flags.push_back("syn");
    }

    if (extract_bit_value(flag_value, TCP_RST_FLAG_SHIFT)) {
        all_flags.push_back("rst");
    }

    if (extract_bit_value(flag_value, TCP_PSH_FLAG_SHIFT)) {
        all_flags.push_back("psh");
    }

    if (extract_bit_value(flag_value, TCP_ACK_FLAG_SHIFT)) {
        all_flags.push_back("ack");
    }

    if (extract_bit_value(flag_value, TCP_URG_FLAG_SHIFT)) {
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


// http://stackoverflow.com/questions/14528233/bit-masking-in-c-how-to-get-first-bit-of-a-byte
int extract_bit_value(uint8_t num, int bit) {
    if (bit > 0 && bit <= 8) {
        return ((num >> (bit - 1)) & 1);
    } else {
        return 0;
    }
}

// Overloaded version with 16 bit integer support
int extract_bit_value(uint16_t num, int bit) {
    if (bit > 0 && bit <= 16) {
        return ((num >> (bit - 1)) & 1);
    } else {
        return 0;
    }
}

int set_bit_value(uint8_t& num, int bit) {
    if (bit > 0 && bit <= 8) {
        num = num | 1 << (bit - 1);

        return 1; 
    } else {
        return 0;
    }   
}

int set_bit_value(uint16_t& num, int bit) {
    if (bit > 0 && bit <= 16) { 
        num = num | 1 << (bit - 1);

        return 1;
    } else {
        return 0;
    }
}

int clear_bit_value(uint8_t& num, int bit) {
    if (bit > 0 && bit <= 8) { 
        num = num & ~(1 << (bit - 1) );

        return 1;
    } else {
        return 0;
    }   
}

// http://stackoverflow.com/questions/47981/how-do-you-set-clear-and-toggle-a-single-bit-in-c-c
int clear_bit_value(uint16_t& num, int bit) {
    if (bit > 0 && bit <= 16) {
        num = num & ~(1 << (bit - 1) );

        return 1;
    } else {
        return 0;
    }   
}

std::string print_simple_packet(simple_packet packet) {
    std::stringstream buffer;

    if (packet.ts.tv_sec == 0) {
        // PF_RING and netmap do not generate timestamp for all packets because it's very CPU
        // intensive operation
        // But we want pretty attack report and fill it there
        gettimeofday(&packet.ts, NULL);
    }

    buffer << convert_timeval_to_date(packet.ts) << " ";

    std::string source_ip_as_string = "";
    std::string  destination_ip_as_string = "";

    if (packet.ip_protocol_version == 4) {
        source_ip_as_string = convert_ip_as_uint_to_string(packet.src_ip);
        destination_ip_as_string = convert_ip_as_uint_to_string(packet.dst_ip);
    } else if (packet.ip_protocol_version == 6) {
        source_ip_as_string = print_ipv6_address(packet.src_ipv6);
        destination_ip_as_string = print_ipv6_address(packet.dst_ipv6);
    } else {
        // WTF?
    }

    buffer << source_ip_as_string << ":" << packet.source_port << " > "
           << destination_ip_as_string << ":" << packet.destination_port
           << " protocol: " << get_printable_protocol_name(packet.protocol);

    // Print flags only for TCP
    if (packet.protocol == IPPROTO_TCP) {
        buffer << " flags: " << print_tcp_flags(packet.flags);
    }

    buffer << " frag: " << packet.ip_fragmented << " ";

    buffer << " ";
    buffer << "packets: " << packet.number_of_packets << " ";
    buffer << "size: " << packet.length << " bytes ";

    // We should cast it to integer because otherwise it will be interpreted as char
    buffer << "ttl: " << unsigned(packet.ttl) << " ";
    buffer << "sample ratio: " << packet.sample_ratio << " ";

    buffer << " \n";

    return buffer.str();
}

std::string convert_timeval_to_date(struct timeval tv) {
    time_t nowtime = tv.tv_sec;
    struct tm* nowtm = localtime(&nowtime);

    char tmbuf[64];
    char buf[64];

    strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);

    snprintf(buf, sizeof(buf), "%s.%06ld", tmbuf, tv.tv_usec);

    return std::string(buf);
}


uint64_t convert_speed_to_mbps(uint64_t speed_in_bps) {
    return uint64_t((double)speed_in_bps / 1024 / 1024 * 8);
}

std::string get_protocol_name_by_number(unsigned int proto_number) {
    struct protoent* proto_ent = getprotobynumber(proto_number);
    std::string proto_name = proto_ent->p_name;
    return proto_name;
}

// exec command in shell
std::vector<std::string> exec(std::string cmd) {
    std::vector<std::string> output_list;

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return output_list;

    char buffer[256];
    while (!feof(pipe)) {
        if (fgets(buffer, 256, pipe) != NULL) {
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

void print_pid_to_file(pid_t pid, std::string pid_path) {
    std::ofstream pid_file;

    pid_file.open(pid_path.c_str(), std::ios::trunc);
    if (pid_file.is_open()) {
        pid_file << pid << "\n";
        pid_file.close();
    }
}

bool read_pid_from_file(pid_t& pid, std::string pid_path) {
    std::fstream pid_file(pid_path.c_str(), std::ios_base::in);

    if (pid_file.is_open()) {
        pid_file >> pid;
        pid_file.close();

        return true;
    } else {
        return false;
    }
}

bool store_data_to_graphite(unsigned short int graphite_port, std::string graphite_host, graphite_data_t graphite_data) {
    int client_sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (client_sockfd < 0) {
        return false;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(graphite_port);

    int pton_result = inet_pton(AF_INET, graphite_host.c_str(), &serv_addr.sin_addr);

    if (pton_result <= 0) {
        return false;
    }

    int connect_result = connect(client_sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    if (connect_result < 0) {
        return false;
    }

    std::stringstream buffer;
    time_t current_time = time(NULL);
    for (graphite_data_t::iterator itr = graphite_data.begin(); itr != graphite_data.end(); ++itr) {
        buffer << itr->first << " " << itr->second << " " << current_time << "\n";
    }

    std::string buffer_as_string = buffer.str();

    int write_result = write(client_sockfd, buffer_as_string.c_str(), buffer_as_string.size());

    close(client_sockfd);

    if (write_result > 0) {
        return true;
    } else {
        return false;
    }
}


// Get list of all available interfaces on the server
interfaces_list_t get_interfaces_list() {
    interfaces_list_t interfaces_list;

    // Format: 1: eth0: < ....
    boost::regex interface_name_pattern("^\\d+:\\s+(\\w+):.*?$");

    std::vector<std::string> output_list = exec("ip -o link show");

    if (output_list.empty()) {
        return interfaces_list;
    }

    for (std::vector<std::string>::iterator iter = output_list.begin(); iter != output_list.end(); ++iter) {
        boost::match_results<std::string::const_iterator> regex_results;

        if (boost::regex_match(*iter, regex_results, interface_name_pattern)) {
            // std::cout<<"Interface: "<<regex_results[1]<<std::endl;
            interfaces_list.push_back(regex_results[1]);
        }
    }

    return interfaces_list;
}

// Get all IPs for interface: main IP and aliases
ip_addresses_list_t get_ip_list_for_interface(std::string interface) {
    ip_addresses_list_t ip_list;

    std::vector<std::string> output_list = exec("ip address show dev " + interface);

    if (output_list.empty()) {
        return ip_list;
    }

    boost::regex interface_alias_pattern("^\\s+inet\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+).*?$");
    // inet 188.40.35.142

    for (std::vector<std::string>::iterator iter = output_list.begin(); iter != output_list.end(); ++iter) {
        boost::match_results<std::string::const_iterator> regex_results;

        if (boost::regex_match(*iter, regex_results, interface_alias_pattern)) {
            ip_list.push_back(regex_results[1]);
            // std::cout<<"IP: "<<regex_results[1]<<std::endl;
        }
    }

    return ip_list;
}

ip_addresses_list_t get_local_ip_addresses_list() {
    ip_addresses_list_t ip_list;

    std::vector<std::string> list_of_ignored_interfaces;
    list_of_ignored_interfaces.push_back("lo");
    list_of_ignored_interfaces.push_back("venet0");

    interfaces_list_t interfaces_list = get_interfaces_list();

    if (interfaces_list.empty()) {
        return ip_list;
    }

    for (interfaces_list_t::iterator iter = interfaces_list.begin(); iter != interfaces_list.end(); ++iter) {
        std::vector<std::string>::iterator iter_exclude_list =
        std::find(list_of_ignored_interfaces.begin(), list_of_ignored_interfaces.end(), *iter);

        // Skip ignored interface
        if (iter_exclude_list != list_of_ignored_interfaces.end()) {
            continue;
        }

        // std::cout<<*iter<<std::endl;
        ip_addresses_list_t ip_list_on_interface = get_ip_list_for_interface(*iter);

        // Append list
        ip_list.insert(ip_list.end(), ip_list_on_interface.begin(), ip_list_on_interface.end());
    }

    return ip_list;
}

std::string convert_prefix_to_string_representation(prefix_t* prefix) {
    std::string address = convert_ip_as_uint_to_string(prefix->add.sin.s_addr);

    return address + "/" + convert_int_to_string(prefix->bitlen);
}

std::string find_subnet_by_ip_in_string_format(patricia_tree_t* patricia_tree, std::string ip) {
    patricia_node_t* found_patrica_node = NULL;

    // Convert IP to integer
    uint32_t client_ip = convert_ip_as_string_to_uint(ip);

    prefix_t prefix_for_check_adreess;
    prefix_for_check_adreess.add.sin.s_addr = client_ip;
    prefix_for_check_adreess.family = AF_INET;
    prefix_for_check_adreess.bitlen = 32;

    found_patrica_node = patricia_search_best2(patricia_tree, &prefix_for_check_adreess, 1);

    if (found_patrica_node != NULL) {
       return convert_prefix_to_string_representation(found_patrica_node->prefix);
    } else {
       return "";
    }
}

// It could not be on start or end of the line
boost::regex  ipv6_address_compression_algorithm("(0000:){2,}");

std::string print_ipv6_address(struct in6_addr& ipv6_address) {
    char buffer[128];

    // For short print
    uint8_t* b = ipv6_address.s6_addr;

    sprintf(buffer, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12],
        b[13], b[14], b[15]);

    std::string buffer_string(buffer);

    // Compress IPv6 address
    std::string result = boost::regex_replace(buffer_string, ipv6_address_compression_algorithm, ":", boost::format_first_only);

    return result;
}

/* Get traffic type: check it belongs to our IPs */
direction get_packet_direction(patricia_tree_t* lookup_tree, uint32_t src_ip, uint32_t dst_ip, unsigned long& subnet, unsigned int& subnet_cidr_mask) {
    direction packet_direction;

    bool our_ip_is_destination = false;
    bool our_ip_is_source = false;

    prefix_t prefix_for_check_adreess;
    prefix_for_check_adreess.family = AF_INET;
    prefix_for_check_adreess.bitlen = 32;

    patricia_node_t* found_patrica_node = NULL;
    prefix_for_check_adreess.add.sin.s_addr = dst_ip;

    unsigned long destination_subnet = 0;
    unsigned int  destination_subnet_cidr_mask = 0;
    found_patrica_node = patricia_search_best2(lookup_tree, &prefix_for_check_adreess, 1);

    if (found_patrica_node) {
        our_ip_is_destination = true;
        destination_subnet = found_patrica_node->prefix->add.sin.s_addr;
        destination_subnet_cidr_mask = found_patrica_node->prefix->bitlen;
    }

    found_patrica_node = NULL;
    prefix_for_check_adreess.add.sin.s_addr = src_ip;

    unsigned long source_subnet = 0;
    unsigned int source_subnet_cidr_mask = 0;
    found_patrica_node = patricia_search_best2(lookup_tree, &prefix_for_check_adreess, 1);

    if (found_patrica_node) {
        our_ip_is_source = true;
        source_subnet = found_patrica_node->prefix->add.sin.s_addr;
        source_subnet_cidr_mask = found_patrica_node->prefix->bitlen;
    }

    subnet = 0;
    if (our_ip_is_source && our_ip_is_destination) {
        packet_direction = INTERNAL;
    } else if (our_ip_is_source) {
        subnet = source_subnet;
        subnet_cidr_mask = source_subnet_cidr_mask;

        packet_direction = OUTGOING;
    } else if (our_ip_is_destination) {
        subnet = destination_subnet;
        subnet_cidr_mask = destination_subnet_cidr_mask;

        packet_direction = INCOMING;
    } else {
        packet_direction = OTHER;
    }

    return packet_direction;
}

std::string get_direction_name(direction direction_value) {
    std::string direction_name;

    switch (direction_value) {
    case INCOMING:
        direction_name = "incoming";
        break;
    case OUTGOING:
        direction_name = "outgoing";
        break;
    case INTERNAL:
        direction_name = "internal";
        break;
    case OTHER:
        direction_name = "other";
        break;
    default:
        direction_name = "unknown";
        break;
    }    

    return direction_name;
}

// We haven't this code for FreeBSD yet
#ifdef __linux__
bool manage_interface_promisc_mode(std::string interface_name, bool switch_on) {
    extern log4cpp::Category& logger;

    // We need really any socket for ioctl
    int fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (!fd) {
        logger << log4cpp::Priority::ERROR << "Can't create socket for promisc mode manager";
        return false;
    }

    struct ifreq ethreq;    
    memset(&ethreq, 0, sizeof(ethreq));
    strncpy(ethreq.ifr_name, interface_name.c_str(), IFNAMSIZ);

    int ioctl_res = ioctl(fd, SIOCGIFFLAGS, &ethreq);

    if (ioctl_res == -1) {
        logger << log4cpp::Priority::ERROR << "Can't get interface flags";
        return false;
    }
 
    bool promisc_enabled_on_device = ethreq.ifr_flags & IFF_PROMISC;

    if (switch_on) {
        if (promisc_enabled_on_device) {
            logger << log4cpp::Priority::INFO << "Interface " << interface_name << " in promisc mode already";
            return true;
        } else {
             logger << log4cpp::Priority::INFO << "Interface in non promisc mode now, switch it on";
             ethreq.ifr_flags |= IFF_PROMISC;
             
             int ioctl_res_set = ioctl(fd, SIOCSIFFLAGS, &ethreq);

             if (ioctl_res_set == -1) {
                 logger << log4cpp::Priority::ERROR << "Can't set interface flags";
                 return false;
             }

             return true;
        }
    } else { 
        if (!promisc_enabled_on_device) {
            logger << log4cpp::Priority::INFO << "Interface " << interface_name << " in normal mode already";
            return true;
        } else {
            logger << log4cpp::Priority::INFO << "Interface in  promisc mode now, switch it off";

            ethreq.ifr_flags &= ~IFF_PROMISC;
            int ioctl_res_set = ioctl(fd, SIOCSIFFLAGS, &ethreq);
 
            if (ioctl_res_set == -1) {
                logger << log4cpp::Priority::ERROR << "Can't set interface flags";
                return false;
            }

            return true;
        }
    }

}

#endif
