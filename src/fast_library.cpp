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

#include <boost/asio.hpp>

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
boost::regex regular_expression_host_pattern("^\\d+\\.\\d+\\.\\d+\\.\\d+$");

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

// BE AWARE! WE USE NON STANDARD SUBNET_T HERE! WE USE NON CIDR MASK HERE!
subnet_t convert_subnet_from_string_to_binary(std::string subnet_cidr) {
    std::vector<std::string> subnet_as_string;
    split(subnet_as_string, subnet_cidr, boost::is_any_of("/"), boost::token_compress_on);

    unsigned int cidr = convert_string_to_integer(subnet_as_string[1]);
    
    uint32_t subnet_as_int = convert_ip_as_string_to_uint(subnet_as_string[0]);

    uint32_t netmask_as_int = convert_cidr_to_binary_netmask(cidr);

    return std::make_pair(subnet_as_int, netmask_as_int);   
}

subnet_t convert_subnet_from_string_to_binary_with_cidr_format(std::string subnet_cidr) {
    std::vector<std::string> subnet_as_string;
    split(subnet_as_string, subnet_cidr, boost::is_any_of("/"), boost::token_compress_on);

    unsigned int cidr = convert_string_to_integer(subnet_as_string[1]);
        
    uint32_t subnet_as_int = convert_ip_as_string_to_uint(subnet_as_string[0]);

    return std::make_pair(subnet_as_int, cidr); 
}

void copy_networks_from_string_form_to_binary(std::vector<std::string> networks_list_as_string,
                                              std::vector<subnet_t>& our_networks) {
    for (std::vector<std::string>::iterator ii = networks_list_as_string.begin();
         ii != networks_list_as_string.end(); ++ii) {

        subnet_t current_subnet = convert_subnet_from_string_to_binary(*ii);
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

bool is_v4_host(std::string host) {
    boost::cmatch what;

    return regex_match(host.c_str(), what, regular_expression_host_pattern);
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

std::vector <std::string> split_strings_to_vector_by_comma(std::string raw_string) {
    std::vector<std::string> splitted_strings;
    boost::split(splitted_strings, raw_string, boost::is_any_of(","), boost::token_compress_on);
 
    return splitted_strings;
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

#if defined(__APPLE__)
    snprintf(buf, sizeof(buf), "%s.%06d", tmbuf, tv.tv_usec);
#else
    snprintf(buf, sizeof(buf), "%s.%06ld", tmbuf, tv.tv_usec);
#endif

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

bool print_pid_to_file(pid_t pid, std::string pid_path) {
    std::ofstream pid_file;

    pid_file.open(pid_path.c_str(), std::ios::trunc);
    if (pid_file.is_open()) {
        pid_file << pid << "\n";
        pid_file.close();

        return true;
    } else {
        return false;    
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
        close(client_sockfd);
        return false;
    }

    int connect_result = connect(client_sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    if (connect_result < 0) {
        close(client_sockfd);
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

ip_addresses_list_t get_local_ip_v4_addresses_list() {
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

direction get_packet_direction_ipv6(patricia_tree_t* lookup_tree, struct in6_addr src_ipv6, struct in6_addr dst_ipv6) {
    direction packet_direction;

    bool our_ip_is_destination = false;
    bool our_ip_is_source = false;

    prefix_t prefix_for_check_address;
    prefix_for_check_address.family = AF_INET6;
    prefix_for_check_address.bitlen = 128;

    patricia_node_t* found_patrica_node = NULL;
    prefix_for_check_address.add.sin6 = dst_ipv6; 

    found_patrica_node = patricia_search_best2(lookup_tree, &prefix_for_check_address, 1);

    if (found_patrica_node) {
        our_ip_is_destination = true;
    }

    found_patrica_node = NULL;
    prefix_for_check_address.add.sin6 = src_ipv6;

    if (found_patrica_node) {
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

#ifdef ENABLE_LUA_HOOKS
lua_State* init_lua_jit(std::string lua_hooks_path) {
    extern log4cpp::Category& logger;

    lua_State* lua_state = luaL_newstate();

    if (lua_state == NULL) {
        logger << log4cpp::Priority::ERROR << "Can't create LUA session";

        return NULL;
    }    

     // load libraries
    luaL_openlibs(lua_state);

    int lua_load_file_result = luaL_dofile(lua_state, lua_hooks_path.c_str());

    if (lua_load_file_result != 0) { 
        logger << log4cpp::Priority::ERROR << "LuaJIT can't load file correctly from path: " << lua_hooks_path
            << " disable LUA support";

        return NULL;
    }    

    return lua_state;
}

bool call_lua_function(std::string function_name, lua_State* lua_state_param, std::string client_addres_in_string_format, void* ptr) {
    extern log4cpp::Category& logger;
 
    /* Function name */
    lua_getfield(lua_state_param, LUA_GLOBALSINDEX, function_name.c_str());
    
    /* Function params */
    lua_pushstring(lua_state_param, client_addres_in_string_format.c_str());
    lua_pushlightuserdata(lua_state_param, ptr);
    
    // Call with 1 argumnents and 1 result
    lua_call(lua_state_param, 2, 1);
    
    if (lua_gettop(lua_state_param) == 1) { 
        bool result = lua_toboolean(lua_state_param, -1) == 1 ? true : false;

        // pop returned value
        lua_pop(lua_state_param, 1);

        return result;
    } else {
        logger << log4cpp::Priority::ERROR << "We got " << lua_gettop(lua_state_param) << " return values from the LUA, it's error, please check your LUA code";
        return false;
    }    

    return false;
}

#endif

inline uint64_t read_tsc_cpu_register() {
    union {
        uint64_t tsc_64;
            struct {
                uint32_t lo_32;
                uint32_t hi_32;
            };  
    } tsc;

    asm volatile("rdtsc" :
        "=a" (tsc.lo_32),
        "=d" (tsc.hi_32));
    return tsc.tsc_64;
}

uint64_t get_tsc_freq_with_sleep() {
    uint64_t start = read_tsc_cpu_register();
            
    sleep(1);

    return read_tsc_cpu_register() - start;
}

json_object* serialize_attack_description_to_json(attack_details& current_attack) {
    json_object* jobj = json_object_new_object();

    attack_type_t attack_type = detect_attack_type(current_attack);
    std::string printable_attack_type = get_printable_attack_name(attack_type);

    json_object_object_add(jobj, "attack_type", json_object_new_string(printable_attack_type.c_str()));
    json_object_object_add(jobj, "initial_attack_power", json_object_new_int(current_attack.attack_power));
    json_object_object_add(jobj, "peak_attack_power",    json_object_new_int(current_attack.max_attack_power));
    json_object_object_add(jobj, "attack_direction",     json_object_new_string(get_direction_name(current_attack.attack_direction).c_str()));
    json_object_object_add(jobj, "attack_protocol",      json_object_new_string(get_printable_protocol_name(current_attack.attack_protocol).c_str()));

    json_object_object_add(jobj, "total_incoming_traffic", json_object_new_int(current_attack.in_bytes));
    json_object_object_add(jobj, "total_outgoing_traffic", json_object_new_int(current_attack.out_bytes));
    json_object_object_add(jobj, "total_incoming_pps",     json_object_new_int(current_attack.in_packets));
    json_object_object_add(jobj, "total_outgoing_pps",     json_object_new_int(current_attack.out_packets));
    json_object_object_add(jobj, "total_incoming_flows",   json_object_new_int(current_attack.in_flows));
    json_object_object_add(jobj, "total_outgoing_flows",   json_object_new_int(current_attack.out_flows));

    json_object_object_add(jobj, "average_incoming_traffic", json_object_new_int(current_attack.average_in_bytes));
    json_object_object_add(jobj, "average_outgoing_traffic", json_object_new_int(current_attack.average_out_bytes));
    json_object_object_add(jobj, "average_incoming_pps",     json_object_new_int(current_attack.average_in_packets));
    json_object_object_add(jobj, "average_outgoing_pps",     json_object_new_int(current_attack.average_out_packets)); 
    json_object_object_add(jobj, "average_incoming_flows",   json_object_new_int(current_attack.average_in_flows));
    json_object_object_add(jobj, "average_outgoing_flows",   json_object_new_int(current_attack.average_out_flows));

    json_object_object_add(jobj, "incoming_ip_fragmented_traffic", json_object_new_int( current_attack.fragmented_in_bytes )); 
    json_object_object_add(jobj, "outgoing_ip_fragmented_traffic", json_object_new_int( current_attack.fragmented_out_bytes  ));
    json_object_object_add(jobj, "incoming_ip_fragmented_pps", json_object_new_int( current_attack.fragmented_in_packets ));
    json_object_object_add(jobj, "outgoing_ip_fragmented_pps", json_object_new_int( current_attack.fragmented_out_packets ));

    json_object_object_add(jobj, "incoming_tcp_traffic", json_object_new_int( current_attack.tcp_in_bytes ));
    json_object_object_add(jobj, "outgoing_tcp_traffic", json_object_new_int( current_attack.tcp_out_bytes ));
    json_object_object_add(jobj, "incoming_tcp_pps", json_object_new_int( current_attack.tcp_in_packets ));
    json_object_object_add(jobj, "outgoing_tcp_pps", json_object_new_int(current_attack.tcp_out_packets ));
    
    json_object_object_add(jobj, "incoming_syn_tcp_traffic", json_object_new_int( current_attack.tcp_syn_in_bytes ));
    json_object_object_add(jobj, "outgoing_syn_tcp_traffic", json_object_new_int( current_attack.tcp_syn_out_bytes ));
    json_object_object_add(jobj, "incoming_syn_tcp_pps", json_object_new_int( current_attack.tcp_syn_in_packets  ));
    json_object_object_add(jobj, "outgoing_syn_tcp_pps", json_object_new_int( current_attack.tcp_syn_out_packets ));

    json_object_object_add(jobj, "incoming_udp_traffic", json_object_new_int( current_attack.udp_in_bytes  ));
    json_object_object_add(jobj, "outgoing_udp_traffic", json_object_new_int( current_attack.udp_out_bytes ));
    json_object_object_add(jobj, "incoming_udp_pps", json_object_new_int( current_attack.udp_in_packets ));
    json_object_object_add(jobj, "outgoing_udp_pps", json_object_new_int( current_attack.udp_out_packets ));
 
    json_object_object_add(jobj, "incoming_icmp_traffic", json_object_new_int( current_attack.icmp_in_bytes   ));
    json_object_object_add(jobj, "outgoing_icmp_traffic", json_object_new_int( current_attack.icmp_out_bytes ));
    json_object_object_add(jobj, "incoming_icmp_pps", json_object_new_int( current_attack.icmp_in_packets ));
    json_object_object_add(jobj, "outgoing_icmp_pps", json_object_new_int( current_attack.icmp_out_packets ));

    return jobj;
}

std::string serialize_attack_description(attack_details& current_attack) {
    std::stringstream attack_description;

    attack_type_t attack_type = detect_attack_type(current_attack);
    std::string printable_attack_type = get_printable_attack_name(attack_type);

    attack_description
    << "Attack type: " << printable_attack_type << "\n"
    << "Initial attack power: " << current_attack.attack_power << " packets per second\n"
    << "Peak attack power: " << current_attack.max_attack_power << " packets per second\n"
    << "Attack direction: " << get_direction_name(current_attack.attack_direction) << "\n"
    << "Attack protocol: " << get_printable_protocol_name(current_attack.attack_protocol) << "\n";

    attack_description
    << "Total incoming traffic: " << convert_speed_to_mbps(current_attack.in_bytes) << " mbps\n"
    << "Total outgoing traffic: " << convert_speed_to_mbps(current_attack.out_bytes) << " mbps\n"
    << "Total incoming pps: " << current_attack.in_packets << " packets per second\n"
    << "Total outgoing pps: " << current_attack.out_packets << " packets per second\n"
    << "Total incoming flows: " << current_attack.in_flows << " flows per second\n"
    << "Total outgoing flows: " << current_attack.out_flows << " flows per second\n";


    // Add average counters
    attack_description
    << "Average incoming traffic: " << convert_speed_to_mbps(current_attack.average_in_bytes) << " mbps\n"
    << "Average outgoing traffic: " << convert_speed_to_mbps(current_attack.average_out_bytes) << " mbps\n"
    << "Average incoming pps: " << current_attack.average_in_packets << " packets per second\n"
    << "Average outgoing pps: " << current_attack.average_out_packets << " packets per second\n"
    << "Average incoming flows: " << current_attack.average_in_flows << " flows per second\n"
    << "Average outgoing flows: " << current_attack.average_out_flows << " flows per second\n";

    attack_description
    << "Incoming ip fragmented traffic: " << convert_speed_to_mbps(current_attack.fragmented_in_bytes) << " mbps\n"
    << "Outgoing ip fragmented traffic: " << convert_speed_to_mbps(current_attack.fragmented_out_bytes)
    << " mbps\n"
    << "Incoming ip fragmented pps: " << current_attack.fragmented_in_packets
    << " packets per second\n"
    << "Outgoing ip fragmented pps: " << current_attack.fragmented_out_packets
    << " packets per second\n"

    << "Incoming tcp traffic: " << convert_speed_to_mbps(current_attack.tcp_in_bytes) << " mbps\n"
    << "Outgoing tcp traffic: " << convert_speed_to_mbps(current_attack.tcp_out_bytes) << " mbps\n"
    << "Incoming tcp pps: " << current_attack.tcp_in_packets << " packets per second\n"
    << "Outgoing tcp pps: " << current_attack.tcp_out_packets << " packets per second\n"
    << "Incoming syn tcp traffic: " << convert_speed_to_mbps(current_attack.tcp_syn_in_bytes)
    << " mbps\n"
    << "Outgoing syn tcp traffic: " << convert_speed_to_mbps(current_attack.tcp_syn_out_bytes) << " mbps\n"
    << "Incoming syn tcp pps: " << current_attack.tcp_syn_in_packets << " packets per second\n"
    << "Outgoing syn tcp pps: " << current_attack.tcp_syn_out_packets << " packets per second\n"

    << "Incoming udp traffic: " << convert_speed_to_mbps(current_attack.udp_in_bytes) << " mbps\n"
    << "Outgoing udp traffic: " << convert_speed_to_mbps(current_attack.udp_out_bytes) << " mbps\n"
    << "Incoming udp pps: " << current_attack.udp_in_packets << " packets per second\n"
    << "Outgoing udp pps: " << current_attack.udp_out_packets << " packets per second\n"

    << "Incoming icmp traffic: " << convert_speed_to_mbps(current_attack.icmp_in_bytes) << " mbps\n"
    << "Outgoing icmp traffic: " << convert_speed_to_mbps(current_attack.icmp_out_bytes) << " mbps\n"
    << "Incoming icmp pps: " << current_attack.icmp_in_packets << " packets per second\n"
    << "Outgoing icmp pps: " << current_attack.icmp_out_packets << " packets per second\n";

    return attack_description.str();
}

attack_type_t detect_attack_type(attack_details& current_attack) {
    double threshold_value = 0.9; 

    if (current_attack.attack_direction == INCOMING) {
        if (current_attack.tcp_syn_in_packets > threshold_value * current_attack.in_packets) {
            return ATTACK_SYN_FLOOD;
        } else if (current_attack.icmp_in_packets > threshold_value * current_attack.in_packets) {
            return ATTACK_ICMP_FLOOD;
        } else if (current_attack.fragmented_in_packets > threshold_value * current_attack.in_packets) {
            return ATTACK_IP_FRAGMENTATION_FLOOD;
        } else if (current_attack.udp_in_packets > threshold_value * current_attack.in_packets) {
            return ATTACK_UDP_FLOOD;
        }    
    } else if (current_attack.attack_direction == OUTGOING) {
        if (current_attack.tcp_syn_out_packets > threshold_value * current_attack.out_packets) {
            return ATTACK_SYN_FLOOD;
        } else if (current_attack.icmp_out_packets > threshold_value * current_attack.out_packets) {
            return ATTACK_ICMP_FLOOD;
        } else if (current_attack.fragmented_out_packets > threshold_value * current_attack.out_packets) {
            return ATTACK_IP_FRAGMENTATION_FLOOD;
        } else if (current_attack.udp_out_packets > threshold_value * current_attack.out_packets) {
            return ATTACK_UDP_FLOOD;
        }    
    }    

    return ATTACK_UNKNOWN;
}

std::string get_printable_attack_name(attack_type_t attack) {
    if (attack == ATTACK_SYN_FLOOD) {
        return "syn_flood";
    } else if (attack == ATTACK_ICMP_FLOOD) {
        return "icmp_flood";
    } else if (attack == ATTACK_UDP_FLOOD) {
        return "udp_flood";
    } else if (attack == ATTACK_IP_FRAGMENTATION_FLOOD) {
        return "ip_fragmentation";
    } else if (attack == ATTACK_UNKNOWN) {
        return "unknown";
    } else {
        return "unknown";
    }    
}

std::string serialize_network_load_to_text(map_element& network_speed_meter, bool average) {
    std::stringstream buffer;

    std::string prefix = "Network";

    if (average) {
        prefix = "Average network";
    }    

    buffer 
        << prefix << " incoming traffic: "<< convert_speed_to_mbps(network_speed_meter.in_bytes) << " mbps\n"
        << prefix << " outgoing traffic: "<< convert_speed_to_mbps(network_speed_meter.out_bytes) << " mbps\n"
        << prefix << " incoming pps: "<< network_speed_meter.in_packets << " packets per second\n"
        << prefix << " outgoing pps: "<< network_speed_meter.out_packets << " packets per second\n"; 

    return buffer.str();
}

json_object* serialize_network_load_to_json(map_element& network_speed_meter) {
    json_object* jobj = json_object_new_object();

    json_object_object_add(jobj, "incoming traffic", json_object_new_int(network_speed_meter.in_bytes));
    json_object_object_add(jobj, "outgoing traffic", json_object_new_int(network_speed_meter.out_bytes));
    json_object_object_add(jobj, "incoming pps",     json_object_new_int(network_speed_meter.in_packets));
    json_object_object_add(jobj, "outgoing pps",     json_object_new_int(network_speed_meter.out_packets));

    return jobj;
}

std::string serialize_statistic_counters_about_attack(attack_details& current_attack) {
    std::stringstream attack_description;

    double average_packet_size_for_incoming_traffic = 0; 
    double average_packet_size_for_outgoing_traffic = 0; 

    if (current_attack.average_in_packets > 0) { 
        average_packet_size_for_incoming_traffic =
        (double)current_attack.average_in_bytes / (double)current_attack.average_in_packets;
    }    

    if (current_attack.average_out_packets > 0) { 
        average_packet_size_for_outgoing_traffic =
        (double)current_attack.average_out_bytes / (double)current_attack.average_out_packets;
    }    

    // We do not need very accurate size
    attack_description.precision(1);
    attack_description << "Average packet size for incoming traffic: " << std::fixed
                       << average_packet_size_for_incoming_traffic << " bytes \n"
                       << "Average packet size for outgoing traffic: " << std::fixed
                       << average_packet_size_for_outgoing_traffic << " bytes \n";

    return attack_description.str();
}

std::string dns_lookup(std::string domain_name) {
    try {
        boost::asio::io_service io_service;
        boost::asio::ip::tcp::resolver resolver(io_service);

        boost::asio::ip::tcp::resolver::query query(domain_name, "");

        for (boost::asio::ip::tcp::resolver::iterator i = resolver.resolve(query);
            i != boost::asio::ip::tcp::resolver::iterator();
            ++i)
        {   
            boost::asio::ip::tcp::endpoint end = *i; 
            return end.address().to_string();
        }   
    } catch (std::exception& e) {
        return ""; 
    }   

    return ""; 
}

bool store_data_to_stats_server(unsigned short int graphite_port, std::string graphite_host, std::string buffer_as_string) {
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
        close(client_sockfd);
        return false;
    }

    int connect_result = connect(client_sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    if (connect_result < 0) {
        close(client_sockfd);
        return false;
    }

    int write_result = write(client_sockfd, buffer_as_string.c_str(), buffer_as_string.size());

    close(client_sockfd);

    if (write_result > 0) {
        return true;
    } else {
        return false;
    }
}
