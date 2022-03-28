#include "fast_library.h"
#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h> // atoi
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "all_logcpp_libraries.h"

#include <boost/asio.hpp>

#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>


#include "simple_packet_capnp/simple_packet.capnp.h"
#include <capnp/message.h>
#include <capnp/serialize-packed.h>

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
subnet_cidr_mask_t convert_subnet_from_string_to_binary(std::string subnet_cidr) {
    std::vector<std::string> subnet_as_string;
    split(subnet_as_string, subnet_cidr, boost::is_any_of("/"), boost::token_compress_on);

    unsigned int cidr = convert_string_to_integer(subnet_as_string[1]);

    uint32_t subnet_as_int = convert_ip_as_string_to_uint(subnet_as_string[0]);

    uint32_t netmask_as_int = convert_cidr_to_binary_netmask(cidr);

    return subnet_cidr_mask_t(subnet_as_int, cidr);
}

// TODO: very bad code without result checks!!! Get rid all functions which are using it
// But this code is pretty handy in tests code
subnet_cidr_mask_t convert_subnet_from_string_to_binary_with_cidr_format(std::string subnet_cidr) {
    std::vector<std::string> subnet_as_string;
    split(subnet_as_string, subnet_cidr, boost::is_any_of("/"), boost::token_compress_on);

    // Return zero subnet in this case
    if (subnet_as_string.size() != 2) { 
        return subnet_cidr_mask_t();
    }    

    unsigned int cidr = convert_string_to_integer(subnet_as_string[1]);

    uint32_t subnet_as_int = convert_ip_as_string_to_uint(subnet_as_string[0]);

    return subnet_cidr_mask_t(subnet_as_int, cidr);
}

void copy_networks_from_string_form_to_binary(std::vector<std::string> networks_list_as_string,
                                              std::vector<subnet_cidr_mask_t>& our_networks) {
    for (std::vector<std::string>::iterator ii = networks_list_as_string.begin();
         ii != networks_list_as_string.end(); ++ii) {

        subnet_cidr_mask_t current_subnet = convert_subnet_from_string_to_binary(*ii);
        our_networks.push_back(current_subnet);
    }
}

std::string convert_subnet_to_string(subnet_cidr_mask_t my_subnet) {
    std::stringstream buffer;

    buffer << convert_ip_as_uint_to_string(my_subnet.subnet_address) << "/" << my_subnet.cidr_prefix_length;

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
    // We can do bit shift only for 0 .. 31 bits but we cannot do it in case of 32 bits
    // Shift for same number of bits as type has is undefined behaviour in C standard:
    // https://stackoverflow.com/questions/7401888/why-doesnt-left-bit-shift-for-32-bit-integers-work-as-expected-when-used
    // We will handle this case manually
    if (cidr == 0) { 
        return 0;
    }

    uint32_t binary_netmask = 0xFFFFFFFF;
    binary_netmask = binary_netmask << (32 - cidr);

    // We need network byte order at output
    return htonl(binary_netmask);
}


bool is_cidr_subnet(std::string subnet) {
    boost::cmatch what;

    return regex_match(subnet.c_str(), what, regular_expression_cidr_pattern);
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

std::vector<std::string> split_strings_to_vector_by_comma(std::string raw_string) {
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
        num = num & ~(1 << (bit - 1));

        return 1;
    } else {
        return 0;
    }
}

// http://stackoverflow.com/questions/47981/how-do-you-set-clear-and-toggle-a-single-bit-in-c-c
int clear_bit_value(uint16_t& num, int bit) {
    if (bit > 0 && bit <= 16) {
        num = num & ~(1 << (bit - 1));

        return 1;
    } else {
        return 0;
    }
}

std::string print_simple_packet(simple_packet_t packet) {
    std::stringstream buffer;

    if (packet.ts.tv_sec == 0) {
        // PF_RING and netmap do not generate timestamp for all packets because it's very CPU
        // intensive operation
        // But we want pretty attack report and fill it there
        gettimeofday(&packet.ts, NULL);
    }

    buffer << convert_timeval_to_date(packet.ts) << " ";

    std::string source_ip_as_string = "";
    std::string destination_ip_as_string = "";

    if (packet.ip_protocol_version == 4) {
        source_ip_as_string = convert_ip_as_uint_to_string(packet.src_ip);
        destination_ip_as_string = convert_ip_as_uint_to_string(packet.dst_ip);
    } else if (packet.ip_protocol_version == 6) {
        source_ip_as_string = print_ipv6_address(packet.src_ipv6);
        destination_ip_as_string = print_ipv6_address(packet.dst_ipv6);
    } else {
        // WTF?
    }

    buffer << source_ip_as_string << ":" << packet.source_port << " > " << destination_ip_as_string << ":"
           << packet.destination_port << " protocol: " << get_printable_protocol_name(packet.protocol);

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
    return uint64_t((double)speed_in_bps / 1000 / 1000 * 8);
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
    // Do not bother Graphite if we do not have any metrics here
    if (graphite_data.size() == 0) {
        return true;
    }

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
boost::regex ipv6_address_compression_algorithm("(0000:){2,}");

std::string print_ipv6_address(const in6_addr& ipv6_address) {
    char buffer[128];

    // For short print
    const uint8_t* b = ipv6_address.s6_addr;

    sprintf(buffer, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", b[0], b[1],
            b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);

    std::string buffer_string(buffer);

    // Compress IPv6 address
    std::string result =
    boost::regex_replace(buffer_string, ipv6_address_compression_algorithm, ":", boost::format_first_only);

    return result;
}

direction_t get_packet_direction_ipv6(patricia_tree_t* lookup_tree, struct in6_addr src_ipv6, struct in6_addr dst_ipv6, subnet_ipv6_cidr_mask_t& subnet) {
    direction_t packet_direction;

    bool our_ip_is_destination = false;
    bool our_ip_is_source      = false;

    prefix_t prefix_for_check_address;
    prefix_for_check_address.family = AF_INET6;
    prefix_for_check_address.bitlen = 128; 

    patricia_node_t* found_patrica_node = NULL;
    prefix_for_check_address.add.sin6   = dst_ipv6;

    found_patrica_node = patricia_search_best2(lookup_tree, &prefix_for_check_address, 1);

    subnet_ipv6_cidr_mask_t destination_subnet;
    if (found_patrica_node) {
        our_ip_is_destination = true;

        destination_subnet.subnet_address     = found_patrica_node->prefix->add.sin6;
        destination_subnet.cidr_prefix_length = found_patrica_node->prefix->bitlen;
    }    

    found_patrica_node                = NULL;
    prefix_for_check_address.add.sin6 = src_ipv6;

    subnet_ipv6_cidr_mask_t source_subnet;

    found_patrica_node = patricia_search_best2(lookup_tree, &prefix_for_check_address, 1);

    if (found_patrica_node) {
        our_ip_is_source = true;

        source_subnet.subnet_address     = found_patrica_node->prefix->add.sin6;
        source_subnet.cidr_prefix_length = found_patrica_node->prefix->bitlen;
    }    

    if (our_ip_is_source && our_ip_is_destination) {
        packet_direction = INTERNAL;
    } else if (our_ip_is_source) {
        subnet           = source_subnet;
        packet_direction = OUTGOING;
    } else if (our_ip_is_destination) {
        subnet           = destination_subnet;
        packet_direction = INCOMING;
    } else {
        packet_direction = OTHER;
    }

    return packet_direction;
}

/* Get traffic type: check it belongs to our IPs */
direction_t get_packet_direction(patricia_tree_t* lookup_tree, uint32_t src_ip, uint32_t dst_ip, subnet_cidr_mask_t& subnet) {
    direction_t packet_direction;

    bool our_ip_is_destination = false;
    bool our_ip_is_source      = false;

    prefix_t prefix_for_check_adreess;
    prefix_for_check_adreess.family = AF_INET;
    prefix_for_check_adreess.bitlen = 32;

    patricia_node_t* found_patrica_node     = NULL;
    prefix_for_check_adreess.add.sin.s_addr = dst_ip;

    subnet_cidr_mask_t destination_subnet;
    found_patrica_node = patricia_search_best2(lookup_tree, &prefix_for_check_adreess, 1);

    if (found_patrica_node) {
        our_ip_is_destination                 = true;
        destination_subnet.subnet_address     = found_patrica_node->prefix->add.sin.s_addr;
        destination_subnet.cidr_prefix_length = found_patrica_node->prefix->bitlen;
    }    

    found_patrica_node                      = NULL;
    prefix_for_check_adreess.add.sin.s_addr = src_ip;

    subnet_cidr_mask_t source_subnet;
    found_patrica_node = patricia_search_best2(lookup_tree, &prefix_for_check_adreess, 1);

    if (found_patrica_node) {
        our_ip_is_source                 = true;
        source_subnet.subnet_address     = found_patrica_node->prefix->add.sin.s_addr;
        source_subnet.cidr_prefix_length = found_patrica_node->prefix->bitlen;
    }    

    if (our_ip_is_source && our_ip_is_destination) {
        packet_direction = INTERNAL;
    } else if (our_ip_is_source) {
        subnet           = source_subnet;
        packet_direction = OUTGOING;
    } else if (our_ip_is_destination) {
        subnet           = destination_subnet;
        packet_direction = INCOMING;
    } else {
        packet_direction = OTHER;
    }    

    return packet_direction;
}


std::string get_direction_name(direction_t direction_value) {
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

json_object* serialize_attack_description_to_json(attack_details_t& current_attack) {
    json_object* jobj = json_object_new_object();

    attack_type_t attack_type = detect_attack_type(current_attack);
    std::string printable_attack_type = get_printable_attack_name(attack_type);

    json_object_object_add(jobj, "attack_type", json_object_new_string(printable_attack_type.c_str()));
    json_object_object_add(jobj, "initial_attack_power", json_object_new_int(current_attack.attack_power));
    json_object_object_add(jobj, "peak_attack_power", json_object_new_int(current_attack.max_attack_power));
    json_object_object_add(jobj, "attack_direction",
                           json_object_new_string(
                           get_direction_name(current_attack.attack_direction).c_str()));
    json_object_object_add(jobj, "attack_protocol",
                           json_object_new_string(
                           get_printable_protocol_name(current_attack.attack_protocol).c_str()));

    json_object_object_add(jobj, "total_incoming_traffic", json_object_new_int(current_attack.in_bytes));
    json_object_object_add(jobj, "total_outgoing_traffic", json_object_new_int(current_attack.out_bytes));
    json_object_object_add(jobj, "total_incoming_pps", json_object_new_int(current_attack.in_packets));
    json_object_object_add(jobj, "total_outgoing_pps", json_object_new_int(current_attack.out_packets));
    json_object_object_add(jobj, "total_incoming_flows", json_object_new_int(current_attack.in_flows));
    json_object_object_add(jobj, "total_outgoing_flows", json_object_new_int(current_attack.out_flows));

    json_object_object_add(jobj, "average_incoming_traffic", json_object_new_int(current_attack.average_in_bytes));
    json_object_object_add(jobj, "average_outgoing_traffic",
                           json_object_new_int(current_attack.average_out_bytes));
    json_object_object_add(jobj, "average_incoming_pps", json_object_new_int(current_attack.average_in_packets));
    json_object_object_add(jobj, "average_outgoing_pps", json_object_new_int(current_attack.average_out_packets));
    json_object_object_add(jobj, "average_incoming_flows", json_object_new_int(current_attack.average_in_flows));
    json_object_object_add(jobj, "average_outgoing_flows", json_object_new_int(current_attack.average_out_flows));

    json_object_object_add(jobj, "incoming_ip_fragmented_traffic",
                           json_object_new_int(current_attack.fragmented_in_bytes));
    json_object_object_add(jobj, "outgoing_ip_fragmented_traffic",
                           json_object_new_int(current_attack.fragmented_out_bytes));
    json_object_object_add(jobj, "incoming_ip_fragmented_pps",
                           json_object_new_int(current_attack.fragmented_in_packets));
    json_object_object_add(jobj, "outgoing_ip_fragmented_pps",
                           json_object_new_int(current_attack.fragmented_out_packets));

    json_object_object_add(jobj, "incoming_tcp_traffic", json_object_new_int(current_attack.tcp_in_bytes));
    json_object_object_add(jobj, "outgoing_tcp_traffic", json_object_new_int(current_attack.tcp_out_bytes));
    json_object_object_add(jobj, "incoming_tcp_pps", json_object_new_int(current_attack.tcp_in_packets));
    json_object_object_add(jobj, "outgoing_tcp_pps", json_object_new_int(current_attack.tcp_out_packets));

    json_object_object_add(jobj, "incoming_syn_tcp_traffic", json_object_new_int(current_attack.tcp_syn_in_bytes));
    json_object_object_add(jobj, "outgoing_syn_tcp_traffic",
                           json_object_new_int(current_attack.tcp_syn_out_bytes));
    json_object_object_add(jobj, "incoming_syn_tcp_pps", json_object_new_int(current_attack.tcp_syn_in_packets));
    json_object_object_add(jobj, "outgoing_syn_tcp_pps", json_object_new_int(current_attack.tcp_syn_out_packets));

    json_object_object_add(jobj, "incoming_udp_traffic", json_object_new_int(current_attack.udp_in_bytes));
    json_object_object_add(jobj, "outgoing_udp_traffic", json_object_new_int(current_attack.udp_out_bytes));
    json_object_object_add(jobj, "incoming_udp_pps", json_object_new_int(current_attack.udp_in_packets));
    json_object_object_add(jobj, "outgoing_udp_pps", json_object_new_int(current_attack.udp_out_packets));

    json_object_object_add(jobj, "incoming_icmp_traffic", json_object_new_int(current_attack.icmp_in_bytes));
    json_object_object_add(jobj, "outgoing_icmp_traffic", json_object_new_int(current_attack.icmp_out_bytes));
    json_object_object_add(jobj, "incoming_icmp_pps", json_object_new_int(current_attack.icmp_in_packets));
    json_object_object_add(jobj, "outgoing_icmp_pps", json_object_new_int(current_attack.icmp_out_packets));

    return jobj;
}

std::string serialize_attack_description(attack_details_t& current_attack) {
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
    << "Outgoing ip fragmented traffic: " << convert_speed_to_mbps(current_attack.fragmented_out_bytes) << " mbps\n"
    << "Incoming ip fragmented pps: " << current_attack.fragmented_in_packets << " packets per second\n"
    << "Outgoing ip fragmented pps: " << current_attack.fragmented_out_packets << " packets per second\n"

    << "Incoming tcp traffic: " << convert_speed_to_mbps(current_attack.tcp_in_bytes) << " mbps\n"
    << "Outgoing tcp traffic: " << convert_speed_to_mbps(current_attack.tcp_out_bytes) << " mbps\n"
    << "Incoming tcp pps: " << current_attack.tcp_in_packets << " packets per second\n"
    << "Outgoing tcp pps: " << current_attack.tcp_out_packets << " packets per second\n"
    << "Incoming syn tcp traffic: " << convert_speed_to_mbps(current_attack.tcp_syn_in_bytes) << " mbps\n"
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

attack_type_t detect_attack_type(attack_details_t& current_attack) {
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

std::string serialize_network_load_to_text(map_element_t& network_speed_meter, bool average) {
    std::stringstream buffer;

    std::string prefix = "Network";

    if (average) {
        prefix = "Average network";
    }

    buffer
    << prefix << " incoming traffic: " << convert_speed_to_mbps(network_speed_meter.in_bytes) << " mbps\n"
    << prefix << " outgoing traffic: " << convert_speed_to_mbps(network_speed_meter.out_bytes) << " mbps\n"
    << prefix << " incoming pps: " << network_speed_meter.in_packets << " packets per second\n"
    << prefix << " outgoing pps: " << network_speed_meter.out_packets << " packets per second\n";

    return buffer.str();
}

json_object* serialize_network_load_to_json(map_element_t& network_speed_meter) {
    json_object* jobj = json_object_new_object();

    json_object_object_add(jobj, "incoming traffic", json_object_new_int(network_speed_meter.in_bytes));
    json_object_object_add(jobj, "outgoing traffic", json_object_new_int(network_speed_meter.out_bytes));
    json_object_object_add(jobj, "incoming pps", json_object_new_int(network_speed_meter.in_packets));
    json_object_object_add(jobj, "outgoing pps", json_object_new_int(network_speed_meter.out_packets));

    return jobj;
}

std::string serialize_statistic_counters_about_attack(attack_details_t& current_attack) {
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
             i != boost::asio::ip::tcp::resolver::iterator(); ++i) {
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

bool convert_hex_as_string_to_uint(std::string hex, uint32_t& value) {
    std::stringstream ss;

    ss << std::hex << hex;
    ss >> value;

    return ss.fail();
}

// Get interface number by name
bool get_interface_number_by_device_name(int socket_fd, std::string interface_name, int& interface_number) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    if (interface_name.size() > IFNAMSIZ) {
        return false;
    }

    strncpy(ifr.ifr_name, interface_name.c_str(), sizeof(ifr.ifr_name));

/* Attempt to use SIOCGIFINDEX if present. */
#ifdef SIOCGIFINDEX
    if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) == -1) {
        return false;
    }

    interface_number = ifr.ifr_ifindex;
#else
    /* Fallback to if_nametoindex(3) otherwise. */
    interface_number = if_nametoindex(interface_name.c_str());
    if (interface_number == 0)
	    return false;
#endif /* SIOCGIFINDEX */
    return true;
}


bool set_boost_process_name(boost::thread* thread, std::string process_name) {
    extern log4cpp::Category& logger;

    if (process_name.size() > 15) {
        logger << log4cpp::Priority::ERROR << "Process name should not exceed 15 symbols " << process_name;
        return false;
    }

    // The buffer specified by name should be at least 16 characters in length.
    char new_process_name[16];
    strcpy(new_process_name, process_name.c_str());

    int result = pthread_setname_np(thread->native_handle(), new_process_name);

    if (result != 0) {
        logger << log4cpp::Priority::ERROR << "pthread_setname_np failed with code: " << result;
        logger << log4cpp::Priority::ERROR << "Failed to set process name for " << process_name;
    }

    return true;
}

bool read_simple_packet(uint8_t* buffer, size_t buffer_length, simple_packet_t& packet) {
    extern log4cpp::Category& logger;

    try {

        auto words = kj::heapArray<capnp::word>(buffer_length / sizeof(capnp::word));
        memcpy(words.begin(), buffer, words.asBytes().size());

        capnp::FlatArrayMessageReader reader(words);
        auto root = reader.getRoot<SimplePacketType>();

        packet.protocol            = root.getProtocol();
        packet.sample_ratio        = root.getSampleRatio();
        packet.src_ip              = root.getSrcIp();
        packet.dst_ip              = root.getDstIp();
        packet.ip_protocol_version = root.getIpProtocolVersion();
        packet.src_asn             = root.getSrcAsn();
        packet.dst_asn             = root.getDstAsn();
        packet.input_interface     = root.getInputInterface();
        packet.output_interface    = root.getOutputInterface();
        packet.agent_ip_address    = root.getAgentIpAddress();

        // Extract IPv6 addresses from packet
        if (packet.ip_protocol_version == 6) {
            if (root.hasSrcIpv6()) {
                ::capnp::Data::Reader reader_ipv6_data = root.getSrcIpv6();

                if (reader_ipv6_data.size() == 16) {
                    // Copy internal structure to C++ struct
                    // TODO: move this code to something more high level, please
                    memcpy((void*)&packet.src_ipv6, reader_ipv6_data.begin(), reader_ipv6_data.size());
                } else {
                    logger << log4cpp::Priority::ERROR << "broken size for IPv6 source address";
                }
            }

            if (root.hasDstIpv6()) {
                ::capnp::Data::Reader reader_ipv6_data = root.getDstIpv6();

                if (reader_ipv6_data.size() == 16) {
                    // Copy internal structure to C++ struct
                    // TODO: move this code to something more high level, please
                    memcpy((void*)&packet.dst_ipv6, reader_ipv6_data.begin(), reader_ipv6_data.size());
                } else {
                    logger << log4cpp::Priority::ERROR << "broken size for IPv6 destination address";
                }
            }

            // TODO: if we could not read src of dst IP addresses here we should drop this packet
        }

        packet.ttl                        = root.getTtl();
        packet.source_port                = root.getSourcePort();
        packet.destination_port           = root.getDestinationPort();
        packet.length                     = root.getLength();
        packet.number_of_packets          = root.getNumberOfPackets();
        packet.flags                      = root.getFlags();
        packet.ip_fragmented              = root.getIpFragmented();
        packet.ts.tv_sec                  = root.getTsSec();
        packet.ts.tv_usec                 = root.getTsMsec();
        packet.packet_payload_length      = root.getPacketPayloadLength();
        packet.packet_payload_full_length = root.getPacketPayloadFullLength();
        packet.packet_direction           = (direction_t)root.getPacketDirection();
        packet.source                     = (source_t)root.getSource();
    } catch (kj::Exception e) {
        logger << log4cpp::Priority::WARN
               << "Exception happened during attempt to parse tera flow packet: " << e.getDescription().cStr();
        return false;
    } catch (...) {
        logger << log4cpp::Priority::WARN << "Exception happened during attempt to parse tera flow packet";
        return false;
    }

    return true;
}

// Encode simple packet into special capnp structure for serialization
bool write_simple_packet(int fd, simple_packet_t& packet, bool populate_ipv6) {
    extern log4cpp::Category& logger;
    ::capnp::MallocMessageBuilder message;

    auto capnp_packet = message.initRoot<SimplePacketType>();

    capnp_packet.setProtocol(packet.protocol);
    capnp_packet.setSampleRatio(packet.sample_ratio);
    capnp_packet.setSrcIp(packet.src_ip);
    capnp_packet.setDstIp(packet.dst_ip);
    capnp_packet.setIpProtocolVersion(packet.ip_protocol_version);
    capnp_packet.setTtl(packet.ttl);
    capnp_packet.setSourcePort(packet.source_port);
    capnp_packet.setDestinationPort(packet.destination_port);
    capnp_packet.setLength(packet.length);
    capnp_packet.setNumberOfPackets(packet.number_of_packets);
    capnp_packet.setFlags(packet.flags);
    capnp_packet.setIpFragmented(packet.ip_fragmented);
    capnp_packet.setTsSec(packet.ts.tv_sec);
    capnp_packet.setTsMsec(packet.ts.tv_usec);
    capnp_packet.setPacketPayloadLength(packet.packet_payload_length);
    capnp_packet.setPacketPayloadFullLength(packet.packet_payload_full_length);
    capnp_packet.setPacketDirection(packet.packet_direction);
    capnp_packet.setSource(packet.source);
    capnp_packet.setSrcAsn(packet.src_asn);
    capnp_packet.setDstAsn(packet.dst_asn);
    capnp_packet.setInputInterface(packet.input_interface);
    capnp_packet.setOutputInterface(packet.output_interface);
    capnp_packet.setAgentIpAddress(packet.agent_ip_address);

    if (populate_ipv6 && packet.ip_protocol_version == 6) {
        kj::ArrayPtr<kj::byte> src_ipv6_as_kj_array((kj::byte*)&packet.src_ipv6, sizeof(packet.src_ipv6));
        capnp_packet.setSrcIpv6(capnp::Data::Reader(src_ipv6_as_kj_array));

        kj::ArrayPtr<kj::byte> dst_ipv6_as_kj_array((kj::byte*)&packet.dst_ipv6, sizeof(packet.dst_ipv6));
        capnp_packet.setDstIpv6(capnp::Data::Reader(dst_ipv6_as_kj_array));
    }

    // Capnp uses exceptions, let's wrap them out
    try {
        // For some unknown for me reasons this function sends incorrect (very short) data
        // writePackedMessageToFd(fd, message);

        // Instead I'm using less optimal (non zero copy) approach but it's working well
        kj::Array<capnp::word> words = messageToFlatArray(message);
        kj::ArrayPtr<kj::byte> bytes = words.asBytes();

        size_t write_result = write(fd, bytes.begin(), bytes.size());

        // If write returned error or we could not write whole packet notify caller about it
        if (write_result < 0 || write_result != bytes.size()) {
            // If we received error from it, let's provide details about it in DEBUG mode
            if (write_result == -1) {
                logger << log4cpp::Priority::DEBUG << "write in write_simple_packet returned error: " << errno;
            }

            return false;
        }
    } catch (...) {
        // logger << log4cpp::Priority::ERROR << "writeSimplePacket failed with error";
        return false;
    }

    return true;
}

// Represent IPv6 cidr subnet in string form
std::string print_ipv6_cidr_subnet(subnet_ipv6_cidr_mask_t subnet) {
    return print_ipv6_address(subnet.subnet_address) + "/" + std::to_string(subnet.cidr_prefix_length);
}

// Abstract function with overloads for templated classes where we use v4 and v4
std::string convert_any_ip_to_string(subnet_ipv6_cidr_mask_t subnet) {
    return print_ipv6_cidr_subnet(subnet);
}

// Return true if we have this IP in patricia tree
bool ip_belongs_to_patricia_tree_ipv6(patricia_tree_t* patricia_tree, struct in6_addr client_ipv6_address) {
    prefix_t prefix_for_check_address;

    prefix_for_check_address.family   = AF_INET6;
    prefix_for_check_address.bitlen   = 128;
    prefix_for_check_address.add.sin6 = client_ipv6_address;

    return patricia_search_best2(patricia_tree, &prefix_for_check_address, 1) != NULL;
}

// Safe way to convert string to positive integer.
// We accept only positive numbers here
bool convert_string_to_positive_integer_safe(std::string line, int& value) {
    int temp_value = 0;

    try {
        temp_value = std::stoi(line);
    } catch (...) {
        // Could not parse number correctly
        return false;
    }

    if (temp_value >= 0) {
        value = temp_value;
        return true;
    } else {
        // We do not expect negative values here
        return false;
    }

    return true;
}

// Read IPv6 host address from string representation
bool read_ipv6_host_from_string(std::string ipv6_host_as_string, in6_addr& result) {
    if (inet_pton(AF_INET6, ipv6_host_as_string.c_str(), &result) == 1) {
        return true;
    } else {
        return false;
    }
}

// Validates IPv4 or IPv6 address in host form:
// 127.0.0.1 or ::1
bool validate_ipv6_or_ipv4_host(const std::string host) {
    // Validate host address
    boost::system::error_code ec;

    // Try to build it from string representation
    auto parsed_ip_address = boost::asio::ip::address::from_string(host, ec);

    // If we failed to parse it
    if (ec) {
        return false;
    }

    return true;
}

// We expect something like: 122.33.11.22:8080/somepath here
// And return: 122.33.11.22, 8080 and "/somepath" as separate parts
bool split_full_url(std::string full_url, std::string& host, std::string& port, std::string& path) {
    auto delimiter_position = full_url.find("/");

    if (delimiter_position == std::string::npos) {
        host = full_url;
        path = "";
    } else {
        host = full_url.substr(0, delimiter_position);
        // Add all symbols until the end of line to the path
        path = full_url.substr(delimiter_position, std::string::npos);
    }

    auto port_delimiter_position = host.find(":");

    // Let's try to extract port if we have ":" delimiter in host
    if (port_delimiter_position != std::string::npos) {
        std::vector<std::string> splitted_host;

        split(splitted_host, host, boost::is_any_of(":"), boost::token_compress_on);

        if (splitted_host.size() != 2) {
            return false;
        }

        host = splitted_host[0];
        port = splitted_host[1];
    }

    return true;
}


// Encrypted version of execute_web_request
bool execute_web_request_secure(std::string address,
                                std::string request_type,
                                std::string post_data,
                                uint32_t& response_code,
                                std::string& response_body,
                                std::map<std::string, std::string>& headers) {

    extern log4cpp::Category& logger;

    std::string host;
    std::string path;
    std::string port = "443";

    if (address.find("https://") == std::string::npos) {
        logger << log4cpp::Priority::ERROR << "URL has not supported protocol prefix: " << address;
        logger << log4cpp::Priority::ERROR << "We have support only for https";

        return false;
    }

    // Remove URL prefix
    boost::replace_all(address, "https://", "");

    bool split_result = split_full_url(address, host, port, path);

    if (!split_result) {
        logger << log4cpp::Priority::ERROR << "Could not split URL into components";
        return false;
    }

    if (request_type != "post" && request_type != "get") {
        logger << log4cpp::Priority::ERROR << "execute_web_request has support only for post and get requests";
        return false;
    }

    // If customer uses address like: 11.22.33.44:8080 without any path we should add it manually to comply with http protocol
    if (path == "") {
        path = "/";
    }

    try {
        boost::system::error_code ec;

        boost::asio::io_context ioc;

        // The SSL context is required, and holds certificates
        boost::asio::ssl::context ctx{ boost::asio::ssl::context::sslv23_client };

        // Load default CA certificates
        ctx.set_default_verify_paths();

        boost::asio::ip::tcp::resolver r(ioc);

        boost::asio::ip::tcp::resolver resolver{ ioc };
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream{ ioc, ctx };

        // Set SNI Hostname
        if (!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str())) {
            boost::system::error_code ec{ static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category() };
            logger << log4cpp::Priority::ERROR << "Can't set SNI hostname: " << ec.message();
            return false;
        }

        auto end_point = r.resolve(boost::asio::ip::tcp::resolver::query{ host, port }, ec);

        if (ec) {
            logger << log4cpp::Priority::ERROR << "Could not resolve peer address in execute_web_request " << ec;
            return false;
        }

        logger << log4cpp::Priority::INFO << "Resolved domain to " << end_point.size() << " IP addresses";

        boost::asio::connect(stream.next_layer(), end_point.begin(), end_point.end(), ec);

        if (ec) {
            logger << log4cpp::Priority::ERROR << "Could not connect to peer in execute_web_request " << ec.message();
            return false;
        }

        stream.handshake(boost::asio::ssl::stream_base::client, ec);

        if (ec) {
            logger << log4cpp::Priority::ERROR << "SSL handshake failed " << ec.message();
            return false;
        }

        // logger << log4cpp::Priority::INFO << "SSL connection established";

        // Send HTTP request using beast
        boost::beast::http::request<boost::beast::http::string_body> req;

        if (request_type == "post") {
            req.method(boost::beast::http::verb::post);
        } else if (request_type == "get") {
            req.method(boost::beast::http::verb::get);
        }

        for (const auto& [k, v] : headers) {
            req.set(k, v);
        }

        req.target(path);
        req.version(11);

        // Pass data only for post request
        if (request_type == "post") {
            req.body() = post_data;
        }

        req.set(boost::beast::http::field::content_type, "application/x-www-form-urlencoded");

        // We must specify port explicitly if we use non standard one
        std::string full_host = host + ":" + std::to_string(stream.next_layer().remote_endpoint().port());
        // logger << log4cpp::Priority::INFO << "I will use " << full_host << " as host";
        req.set(boost::beast::http::field::host, full_host.c_str());

        // TBD: we also should add port number to host name if we use non standard one
        // + ":" + std::to_string(end_point.port()));
        req.set(boost::beast::http::field::user_agent, "FastNetMon");

        req.prepare_payload();
        boost::beast::http::write(stream, req, ec);

        if (ec) {
            logger << log4cpp::Priority::ERROR << "Could not write data to socket in execute_web_request: " << ec.message();
            return false;
        }

        // Receive and print HTTP response using beast
        // This buffer is used for reading and must be persisted
        boost::beast::flat_buffer b;

        boost::beast::http::response<boost::beast::http::string_body> resp;
        boost::beast::http::read(stream, b, resp, ec);

        if (ec) {
            logger << log4cpp::Priority::ERROR << "Could not read data inside execute_web_request: " << ec.message();
            return false;
        }

        response_code = resp.result_int();

        // Return response body to caller
        response_body = resp.body();

        // logger << log4cpp::Priority::INFO << "Response code: " << response_code;

        // Gracefully close the stream
        stream.shutdown(ec);
        if (ec == boost::asio::error::eof) {
            // Rationale:
            // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            ec.assign(0, ec.category());
        }

        if (ec) {
            logger << log4cpp::Priority::DEBUG << "Can't shutdown connection gracefully: " << ec.message();
            // But we should not return error to caller in this case because we pushed data properly
        }

        return true;
    } catch (std::exception& e) {
        logger << log4cpp::Priority::ERROR << "execute_web_request failed with error: " << e.what();
        return false;
    }

    return false;
}


bool execute_web_request(std::string address,
                         std::string request_type,
                         std::string post_data,
                         uint32_t& response_code,
                         std::string& response_body,
                         std::map<std::string, std::string>& headers,
                         std::string& error_text) {
    std::string host;
    std::string path;
    std::string port = "http";

    if (address.find("https://") != std::string::npos) {
        return execute_web_request_secure(address, request_type, post_data, response_code, response_body, headers);
    }

    if (address.find("http://") == std::string::npos) {
        error_text = "URL has not supported protocol prefix: " + address;
        return false;
    }

    // Remove URL prefix
    boost::replace_all(address, "http://", "");

    bool split_result = split_full_url(address, host, port, path);

    if (!split_result) {
        error_text = "Could not split URL into components";
        return false;
    }

    // If customer uses address like: 11.22.33.44:8080 without any path we should add it manually to comply with http protocol
    if (path == "") {
        path = "/";
    }

    if (request_type != "post" && request_type != "get") {
        error_text = "execute_web_request has support only for post and get requests. Requested: ";
        error_text += request_type;
        
        return false;
    }

    try {
        boost::system::error_code ec;

        // Normal boost::asio setup
        // std::string const host = "178.62.227.110";
        boost::asio::io_service ios;
        boost::asio::ip::tcp::resolver r(ios);
        boost::asio::ip::tcp::socket sock(ios);

        auto end_point = r.resolve(boost::asio::ip::tcp::resolver::query{ host, port }, ec);

        if (ec) {
            error_text = "Could not resolve peer address in execute_web_request " + ec.message();
            return false;
        }

        boost::asio::connect(sock, end_point, ec);

        if (ec) {
            error_text = "Could not connect to peer in execute_web_request " + ec.message();
            return false;
        }

        // Send HTTP request using beast
        boost::beast::http::request<boost::beast::http::string_body> req;

        if (request_type == "post") {
            req.method(boost::beast::http::verb::post);
        } else if (request_type == "get") {
            req.method(boost::beast::http::verb::get);
        }

        for (const auto& [k, v] : headers) {
            req.set(k, v);
        }

        req.target(path);
        req.version(11);

        // Pass data only for post request
        if (request_type == "post") {
            req.body() = post_data;
        }

        req.set(boost::beast::http::field::content_type, "application/x-www-form-urlencoded");
        req.set(boost::beast::http::field::host, host + ":" + std::to_string(sock.remote_endpoint().port()));
        req.set(boost::beast::http::field::user_agent, "FastNetMon");

        req.prepare_payload();
        boost::beast::http::write(sock, req, ec);

        if (ec) {
            error_text = "Could not write data to socket in execute_web_request: " + ec.message();
            return false;
        }

        // Receive and print HTTP response using beast
        // This buffer is used for reading and must be persisted
        boost::beast::flat_buffer b;

        boost::beast::http::response<boost::beast::http::string_body> resp;
        boost::beast::http::read(sock, b, resp, ec);

        if (ec) {
            error_text = "Could not read data inside execute_web_request: ";
            error_text += ec.message();
            return false;
        }

        response_code = resp.result_int();

        response_body = resp.body();

        using tcp = boost::asio::ip::tcp;
        // Gracefully close the socket
        sock.shutdown(tcp::socket::shutdown_both, ec);

        // We ignore ec error here from shutdown

        return true;
    } catch (std::exception& e) {
        error_text = "execute_web_request failed with error: ";
        error_text += e.what();
        return false;
    }

    return false;
}

// Write data to influxdb
bool write_data_to_influxdb(std::string database,
                            std::string host,
                            std::string port,
                            bool enable_auth,
                            std::string influx_user,
                            std::string influx_password,
                            std::string query) {
    uint32_t response_code = 0;

    std::string address = host + ":" + port;

    std::string influxdb_query_string = std::string("http://") + address + "/write?db=" + database;

    // Add auth credentials
    if (enable_auth) {
        influxdb_query_string += "&u=" + influx_user + "&p=" + influx_password;
    }

    // TODO: I have an idea to reduce number of active TIME_WAIT connections and we have function
    // execute_web_request_connection_close
    // But I suppose issues on InfluxDB side and raised ticket about it
    // https://github.com/influxdata/influxdb/issues/8525
    // And we could not switch to it yet

    // We do not need it here but function requires this option
    std::string response_body;

    std::map<std::string, std::string> headers;
    std::string error_text;
    bool result = execute_web_request(influxdb_query_string, "post", query, response_code, response_body, headers, error_text);

    if (!result) {
        return false;
    }

    if (response_code != 204) {
        return false;
    }

    return true;
}

uint64_t get_current_unix_time_in_nanoseconds() {
    auto unix_timestamp                 = std::chrono::seconds(std::time(NULL));
    uint64_t unix_timestamp_nanoseconds = std::chrono::milliseconds(unix_timestamp).count() * 1000 * 1000;
    return unix_timestamp_nanoseconds;
}

// Joins data to format a=b,d=f
std::string join_by_comma_and_equal(std::map<std::string, std::string>& data) {
    std::stringstream buffer;

    for (auto itr = data.begin(); itr != data.end(); ++itr) {
        buffer << itr->first << "=" << itr->second;

        // it's last element
        if (std::distance(itr, data.end()) == 1) {
            // Do not print comma
        } else {
            buffer << ",";
        }
    }

    return buffer.str();
}

