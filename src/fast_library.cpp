#include "fast_library.hpp"
#include <fstream>
#include <iostream>

// Windows does not use ioctl
#ifndef _WIN32
#include <sys/ioctl.h>
#endif

#ifndef _WIN32
// For uname function
#include <sys/utsname.h>
#endif

#include "all_logcpp_libraries.hpp"

#include <boost/asio.hpp>

#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

#ifdef ENABLE_CAPNP
#include "simple_packet_capnp/simple_packet.capnp.h"
#include <capnp/message.h>
#include <capnp/serialize-packed.h>
#endif

#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>

#include "iana_ip_protocols.hpp"

boost::regex regular_expression_cidr_pattern("^\\d+\\.\\d+\\.\\d+\\.\\d+\\/\\d+$");
boost::regex regular_expression_host_pattern("^\\d+\\.\\d+\\.\\d+\\.\\d+$");

// convert string to integer
int convert_string_to_integer(std::string line) {
    return atoi(line.c_str());
}

std::string convert_ip_as_uint_to_string(uint32_t ip_as_integer) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ip_as_integer;
    return (std::string)inet_ntoa(ip_addr);
}

std::string convert_ipv4_subnet_to_string(const subnet_cidr_mask_t& subnet) {
    std::stringstream buffer;

    buffer << convert_ip_as_uint_to_string(subnet.subnet_address) << "/" << subnet.cidr_prefix_length;

    return buffer.str();
}


// convert integer to string
std::string convert_int_to_string(int value) {
    std::stringstream out;
    out << value;

    return out.str();
}

// Converts IP address in cidr form 11.22.33.44/24 to our representation
bool convert_subnet_from_string_to_binary_with_cidr_format_safe(const std::string& subnet_cidr, subnet_cidr_mask_t& subnet_cidr_mask) {
    if (subnet_cidr.empty()) {
        return false;
    }

    // It's not a cidr mask
    if (!is_cidr_subnet(subnet_cidr)) {
        return false;
    }

    std::vector<std::string> subnet_as_string;

    split(subnet_as_string, subnet_cidr, boost::is_any_of("/"), boost::token_compress_on);

    if (subnet_as_string.size() != 2) {
        return false;
    }

    uint32_t subnet_as_int = 0;

    bool ip_to_integer_convresion_result = convert_ip_as_string_to_uint_safe(subnet_as_string[0], subnet_as_int);

    if (!ip_to_integer_convresion_result) {
        return false;
    }

    int cidr = 0;

    bool ip_conversion_result = convert_string_to_any_integer_safe(subnet_as_string[1], cidr);

    if (!ip_conversion_result) {
        return false;
    }

    subnet_cidr_mask = subnet_cidr_mask_t(subnet_as_int, cidr);

    return true;
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
        return std::string();
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
    binary_netmask          = binary_netmask << (32 - cidr);

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
    result->tv_sec  = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}

std::string print_tcp_flags(uint8_t flag_value) {
    if (flag_value == 0) {
        return "-";
    }

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

// Encodes simple packet with all fields as separate fields in json format
bool serialize_simple_packet_to_json(const simple_packet_t& packet, nlohmann::json& json_packet) {
    extern log4cpp::Category& logger;

    std::string protocol_version;
    std::string source_ip_as_string;
    std::string destination_ip_as_string;

    if (packet.ip_protocol_version == 4) {
        protocol_version = "ipv4";

        source_ip_as_string      = convert_ip_as_uint_to_string(packet.src_ip);
        destination_ip_as_string = convert_ip_as_uint_to_string(packet.dst_ip);
    } else if (packet.ip_protocol_version == 6) {
        protocol_version = "ipv6";

        source_ip_as_string      = print_ipv6_address(packet.src_ipv6);
        destination_ip_as_string = print_ipv6_address(packet.dst_ipv6);
    } else {
        protocol_version = "unknown";
    }

    try {
        // We use arrival_time as traffic telemetry protocols do not provide this time in a reliable manner
        json_packet["timestamp"] = packet.arrival_time;

        json_packet["ip_version"] = protocol_version;

        json_packet["source_ip"]      = source_ip_as_string;
        json_packet["destination_ip"] = destination_ip_as_string;

        json_packet["source_asn"]      = packet.src_asn;
        json_packet["destination_asn"] = packet.dst_asn;

        json_packet["source_country"]      = country_static_string_to_dynamic_string(packet.src_country);
        json_packet["destination_country"] = country_static_string_to_dynamic_string(packet.dst_country);

        json_packet["input_interface"]  = packet.input_interface;
        json_packet["output_interface"] = packet.output_interface;

        // Add ports for TCP and UDP
        if (packet.protocol == IPPROTO_TCP or packet.protocol == IPPROTO_UDP) {
            json_packet["source_port"]      = packet.source_port;
            json_packet["destination_port"] = packet.destination_port;
        }

        // Add agent information
        std::string agent_ip_as_string = convert_ip_as_uint_to_string(packet.agent_ip_address);
        json_packet["agent_address"]   = agent_ip_as_string;

        if (packet.protocol == IPPROTO_TCP) {
            std::string tcp_flags    = print_tcp_flags(packet.flags);
            json_packet["tcp_flags"] = tcp_flags;
        }

        // Add forwarding status
        std::string forwarding_status = forwarding_status_to_string(packet.forwarding_status);

        json_packet["forwarding_status"] = forwarding_status;

        json_packet["fragmentation"] = packet.ip_fragmented;

        json_packet["packets"]   = packet.number_of_packets;
        json_packet["length"]    = packet.length;
        json_packet["ip_length"] = packet.ip_length;

        json_packet["ttl"]          = packet.ttl;
        json_packet["sample_ratio"] = packet.sample_ratio;

        std::string protocol = get_printable_protocol_name(packet.protocol);

        json_packet["protocol"] = protocol;

    } catch (...) {
        logger << log4cpp::Priority::ERROR << "Exception was triggered in JSON logic in serialize_simple_packet_to_json";
        return false;
    }

    return true;
}

std::string print_simple_packet(simple_packet_t packet) {
    std::stringstream buffer;

    if (packet.ts.tv_sec == 0) {
        // Netmap does not generate timestamp for all packets because it's very CPU
        // intensive operation
        // But we want pretty attack report and fill it there
        gettimeofday(&packet.ts, NULL);
    }

    buffer << convert_timeval_to_date(packet.ts) << " ";

    std::string source_ip_as_string      = "";
    std::string destination_ip_as_string = "";

    if (packet.ip_protocol_version == 4) {
        source_ip_as_string      = convert_ip_as_uint_to_string(packet.src_ip);
        destination_ip_as_string = convert_ip_as_uint_to_string(packet.dst_ip);
    } else if (packet.ip_protocol_version == 6) {
        source_ip_as_string      = print_ipv6_address(packet.src_ipv6);
        destination_ip_as_string = print_ipv6_address(packet.dst_ipv6);
    } else {
        // WTF?
    }

    std::string protocol_name = get_ip_protocol_name_by_number_iana(packet.protocol);

    // We use lowercase format
    boost::algorithm::to_lower(protocol_name);

    buffer << source_ip_as_string << ":" << packet.source_port << " > " << destination_ip_as_string << ":"
           << packet.destination_port << " protocol: " << protocol_name;

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

std::string convert_timeval_to_date(const timeval& tv) {
    time_t nowtime = tv.tv_sec;
    tm* nowtm      = localtime(&nowtime);

    std::ostringstream ss;
    ss << std::put_time(nowtm, "%F %H:%M:%S");

    // Add microseconds
    // If value is short we will add leading zeros
    ss << "." << std::setfill('0') << std::setw(6) << tv.tv_usec;

    return ss.str();
}

uint64_t convert_speed_to_mbps(uint64_t speed_in_bps) {
    return uint64_t((double)speed_in_bps / 1000 / 1000 * 8);
}

std::string get_protocol_name_by_number(unsigned int proto_number) {
    struct protoent* proto_ent = getprotobynumber(proto_number);
    std::string proto_name     = proto_ent->p_name;
    return proto_name;
}

// Exec command in shell and capture output
bool exec(const std::string& cmd, std::vector<std::string>& output_list, std::string& error_text) {
    FILE* pipe = popen(cmd.c_str(), "r");

    if (!pipe) {
        // We need more details in case of failure
        error_text = "error code: " + std::to_string(errno) + " error text: " + strerror(errno);
        return false;
    }

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
    return true;
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
    serv_addr.sin_port   = htons(graphite_port);

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

    std::string error_text;
    std::vector<std::string> output_list;

    bool exec_result = exec("ip -o link show", output_list, error_text);

    if (!exec_result) {
        return interfaces_list;
    }

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
ip_addresses_list_t get_ip_list_for_interface(const std::string& interface_name) {
    ip_addresses_list_t ip_list;

    std::string error_text;
    std::vector<std::string> output_list;

    bool exec_result = exec("ip address show dev " + interface_name, output_list, error_text);

    if (!exec_result) {
        return ip_list;
    }

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

// It could not be on start or end of the line
boost::regex ipv6_address_compression_algorithm("(0000:){2,}");

// Returns true when all octets of IP address are set to zero
bool is_zero_ipv6_address(const in6_addr& ipv6_address) {
    const uint8_t* b = ipv6_address.s6_addr;

    if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
        b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0 && b[12] == 0 && b[13] == 0 && b[14] == 0 && b[15] == 0) {
        return true;
    }

    return false;
}


std::string print_ipv6_address(const in6_addr& ipv6_address) {
    char buffer[128];

    // For short print
    const uint8_t* b = ipv6_address.s6_addr;

    sprintf(buffer, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", b[0], b[1], b[2], b[3],
            b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);

    std::string buffer_string(buffer);

    // Compress IPv6 address
    std::string result = boost::regex_replace(buffer_string, ipv6_address_compression_algorithm, ":", boost::format_first_only);

    return result;
}

direction_t get_packet_direction_ipv6(patricia_tree_t* lookup_tree,
                                      struct in6_addr src_ipv6,
                                      struct in6_addr dst_ipv6,
                                      subnet_ipv6_cidr_mask_t& subnet) {
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

std::string serialize_attack_description(const attack_details_t& current_attack) {
    std::stringstream attack_description;

    attack_type_t attack_type         = detect_attack_type(current_attack);
    std::string printable_attack_type = get_printable_attack_name(attack_type);

    attack_description << "Attack type: " << printable_attack_type << "\n"
                       << "Initial attack power: " << current_attack.attack_power << " packets per second\n"
                       << "Peak attack power: " << current_attack.max_attack_power << " packets per second\n"
                       << "Attack direction: " << get_direction_name(current_attack.attack_direction) << "\n"
                       << "Attack protocol: " << get_printable_protocol_name(current_attack.attack_protocol) << "\n";

    attack_description
        << "Total incoming traffic: " << convert_speed_to_mbps(current_attack.traffic_counters.total.in_bytes) << " mbps\n"
        << "Total outgoing traffic: " << convert_speed_to_mbps(current_attack.traffic_counters.total.out_bytes) << " mbps\n"
        << "Total incoming pps: " << current_attack.traffic_counters.total.in_packets << " packets per second\n"
        << "Total outgoing pps: " << current_attack.traffic_counters.total.out_packets << " packets per second\n"
        << "Total incoming flows: " << current_attack.traffic_counters.in_flows << " flows per second\n"
        << "Total outgoing flows: " << current_attack.traffic_counters.out_flows << " flows per second\n";

    attack_description
        << "Incoming ip fragmented traffic: " << convert_speed_to_mbps(current_attack.traffic_counters.fragmented.in_bytes) << " mbps\n"
        << "Outgoing ip fragmented traffic: " << convert_speed_to_mbps(current_attack.traffic_counters.fragmented.out_bytes)
        << " mbps\n"
        << "Incoming ip fragmented pps: " << current_attack.traffic_counters.fragmented.in_packets << " packets per second\n"
        << "Outgoing ip fragmented pps: " << current_attack.traffic_counters.fragmented.out_packets << " packets per second\n"

        << "Incoming dropped traffic: " << convert_speed_to_mbps(current_attack.traffic_counters.dropped.in_bytes) << " mbps\n"
        << "Outgoing dropped traffic: " << convert_speed_to_mbps(current_attack.traffic_counters.dropped.out_bytes) << " mbps\n"
        << "Incoming dropped pps: " << current_attack.traffic_counters.dropped.in_packets << " packets per second\n"
        << "Outgoing dropped pps: " << current_attack.traffic_counters.dropped.out_packets << " packets per second\n"

        << "Incoming tcp traffic: " << convert_speed_to_mbps(current_attack.traffic_counters.tcp.in_bytes) << " mbps\n"
        << "Outgoing tcp traffic: " << convert_speed_to_mbps(current_attack.traffic_counters.tcp.out_bytes) << " mbps\n"
        << "Incoming tcp pps: " << current_attack.traffic_counters.tcp.in_packets << " packets per second\n"
        << "Outgoing tcp pps: " << current_attack.traffic_counters.tcp.out_packets << " packets per second\n"
        << "Incoming syn tcp traffic: " << convert_speed_to_mbps(current_attack.traffic_counters.tcp_syn.in_bytes) << " mbps\n"
        << "Outgoing syn tcp traffic: " << convert_speed_to_mbps(current_attack.traffic_counters.tcp_syn.out_bytes) << " mbps\n"
        << "Incoming syn tcp pps: " << current_attack.traffic_counters.tcp_syn.in_packets << " packets per second\n"
        << "Outgoing syn tcp pps: " << current_attack.traffic_counters.tcp_syn.out_packets << " packets per second\n"

        << "Incoming udp traffic: " << convert_speed_to_mbps(current_attack.traffic_counters.udp.in_bytes) << " mbps\n"
        << "Outgoing udp traffic: " << convert_speed_to_mbps(current_attack.traffic_counters.udp.out_bytes) << " mbps\n"
        << "Incoming udp pps: " << current_attack.traffic_counters.udp.in_packets << " packets per second\n"
        << "Outgoing udp pps: " << current_attack.traffic_counters.udp.out_packets << " packets per second\n"

        << "Incoming icmp traffic: " << convert_speed_to_mbps(current_attack.traffic_counters.icmp.in_bytes) << " mbps\n"
        << "Outgoing icmp traffic: " << convert_speed_to_mbps(current_attack.traffic_counters.icmp.out_bytes) << " mbps\n"
        << "Incoming icmp pps: " << current_attack.traffic_counters.icmp.in_packets << " packets per second\n"
        << "Outgoing icmp pps: " << current_attack.traffic_counters.icmp.out_packets << " packets per second\n";


    return attack_description.str();
}

attack_type_t detect_attack_type(const attack_details_t& current_attack) {
    double threshold_value = 0.9;

    if (current_attack.attack_direction == INCOMING) {
        if (current_attack.traffic_counters.tcp_syn.in_packets > threshold_value * current_attack.traffic_counters.total.in_packets) {
            return ATTACK_SYN_FLOOD;
        } else if (current_attack.traffic_counters.icmp.in_packets >
                   threshold_value * current_attack.traffic_counters.total.in_packets) {
            return ATTACK_ICMP_FLOOD;
        } else if (current_attack.traffic_counters.fragmented.in_packets >
                   threshold_value * current_attack.traffic_counters.total.in_packets) {
            return ATTACK_IP_FRAGMENTATION_FLOOD;
        } else if (current_attack.traffic_counters.udp.in_packets >
                   threshold_value * current_attack.traffic_counters.total.in_packets) {
            return ATTACK_UDP_FLOOD;
        }
    } else if (current_attack.attack_direction == OUTGOING) {
        if (current_attack.traffic_counters.tcp_syn.out_packets >
            threshold_value * current_attack.traffic_counters.total.out_packets) {
            return ATTACK_SYN_FLOOD;
        } else if (current_attack.traffic_counters.icmp.out_packets >
                   threshold_value * current_attack.traffic_counters.total.out_packets) {
            return ATTACK_ICMP_FLOOD;
        } else if (current_attack.traffic_counters.fragmented.out_packets >
                   threshold_value * current_attack.traffic_counters.total.out_packets) {
            return ATTACK_IP_FRAGMENTATION_FLOOD;
        } else if (current_attack.traffic_counters.udp.out_packets >
                   threshold_value * current_attack.traffic_counters.total.out_packets) {
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

std::string serialize_network_load_to_text(subnet_counter_t& network_speed_meter, bool average) {
    std::stringstream buffer;

    std::string prefix = "Network";

    if (average) {
        prefix = "Average network";
    }

    buffer << prefix << " incoming traffic: " << convert_speed_to_mbps(network_speed_meter.total.in_bytes) << " mbps\n"
           << prefix << " outgoing traffic: " << convert_speed_to_mbps(network_speed_meter.total.out_bytes) << " mbps\n"
           << prefix << " incoming pps: " << network_speed_meter.total.in_packets << " packets per second\n"
           << prefix << " outgoing pps: " << network_speed_meter.total.out_packets << " packets per second\n";

    return buffer.str();
}

std::string dns_lookup(std::string domain_name) {
    try {
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::resolver resolver(io_context);

        auto results = resolver.resolve(domain_name, "");

        for (const auto& entry : results) {
            return entry.endpoint().address().to_string();
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
    serv_addr.sin_port   = htons(graphite_port);

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


#ifdef __linux__
// We use this logic only from AF_PACKET and we clearly have no reasons to maintain cross platform portability for it
// Get interface number by name
bool get_interface_number_by_device_name(int socket_fd, std::string interface_name, int& interface_number) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    if (interface_name.size() > IFNAMSIZ) {
        return false;
    }

    strncpy(ifr.ifr_name, interface_name.c_str(), sizeof(ifr.ifr_name));

    if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) == -1) {
        return false;
    }

    interface_number = ifr.ifr_ifindex;
    return true;
}

#endif

#if defined(__APPLE__) || defined(_WIN32)
bool set_boost_process_name(boost::thread* thread, const std::string& process_name) {
    extern log4cpp::Category& logger;

    logger << log4cpp::Priority::ERROR << "We do not support custom thread names on this platform";
    return false;
}

#else

bool set_boost_process_name(boost::thread* thread, const std::string& process_name) {
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

#endif

#ifdef ENABLE_CAPNP


// Crafts capnp packet
void craft_capnp_for_simple_packet(const simple_packet_t& packet, SimplePacketType::Builder& capnp_packet) {
    capnp_packet.setProtocol(packet.protocol);
    capnp_packet.setSampleRatio(packet.sample_ratio);
    capnp_packet.setSrcIp(packet.src_ip);
    capnp_packet.setDstIp(packet.dst_ip);
    capnp_packet.setIpProtocolVersion(packet.ip_protocol_version);
    capnp_packet.setTtl(packet.ttl);
    capnp_packet.setSourcePort(packet.source_port);
    capnp_packet.setDestinationPort(packet.destination_port);
    capnp_packet.setLength(packet.length);
    capnp_packet.setIpLength(packet.ip_length);
    capnp_packet.setNumberOfPackets(packet.number_of_packets);
    capnp_packet.setFlags(packet.flags);
    capnp_packet.setIpFragmented(packet.ip_fragmented);
    capnp_packet.setTsSec(packet.ts.tv_sec);
    capnp_packet.setTsMsec(packet.ts.tv_usec);
    capnp_packet.setPacketPayloadLength(packet.captured_payload_length);
    capnp_packet.setPacketPayloadFullLength(packet.payload_full_length);
    capnp_packet.setPacketDirection(packet.packet_direction);
    capnp_packet.setSource(packet.source);
    capnp_packet.setSrcAsn(packet.src_asn);
    capnp_packet.setDstAsn(packet.dst_asn);
    capnp_packet.setInputInterface(packet.input_interface);
    capnp_packet.setOutputInterface(packet.output_interface);
    capnp_packet.setAgentIpAddress(packet.agent_ip_address);

    if (packet.ip_protocol_version == 6) {
        kj::ArrayPtr<kj::byte> src_ipv6_as_kj_array((kj::byte*)&packet.src_ipv6, sizeof(packet.src_ipv6));
        capnp_packet.setSrcIpv6(capnp::Data::Reader(src_ipv6_as_kj_array));

        kj::ArrayPtr<kj::byte> dst_ipv6_as_kj_array((kj::byte*)&packet.dst_ipv6, sizeof(packet.dst_ipv6));
        capnp_packet.setDstIpv6(capnp::Data::Reader(dst_ipv6_as_kj_array));
    }

    // Add MAC addresses
    kj::ArrayPtr<kj::byte> source_mac_as_kj_array((kj::byte*)&packet.source_mac, sizeof(packet.source_mac));
    capnp_packet.setSrcMac(capnp::Data::Reader(source_mac_as_kj_array));

    kj::ArrayPtr<kj::byte> destination_mac_as_kj_array((kj::byte*)&packet.destination_mac, sizeof(packet.destination_mac));
    capnp_packet.setDstMac(capnp::Data::Reader(destination_mac_as_kj_array));
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
        packet.captured_payload_length      = root.getPacketPayloadLength();
        packet.payload_full_length = root.getPacketPayloadFullLength();
        packet.packet_direction           = (direction_t)root.getPacketDirection();
        packet.source                     = (source_t)root.getSource();
    } catch (kj::Exception& e) {
        logger << log4cpp::Priority::WARN
               << "Exception happened during attempt to parse tera flow packet: " << e.getDescription().cStr();
        return false;
    } catch (...) {
        logger << log4cpp::Priority::WARN << "Exception happened during attempt to parse tera flow packet";
        return false;
    }

    return true;
}

bool write_simple_packet(int fd, bool write_message_length, const simple_packet_t& packet, int send_flags) {
    extern log4cpp::Category& logger;
    ::capnp::MallocMessageBuilder message;

    auto capnp_packet = message.initRoot<SimplePacketType>();

    // Craft Capnp message
    craft_capnp_for_simple_packet(packet, capnp_packet);

    kj::Array<capnp::word> words;

    // For some unknown reasons function writePackedMessageToFd sends incorrect, too short data and we use regular send for better flexibility

    try {
        words = messageToFlatArray(message);
    } catch (...) {
        logger << log4cpp::Priority::ERROR << "messageToFlatArray failed with error";
        return false;
    }

    kj::ArrayPtr<kj::byte> bytes = words.asBytes();

    size_t message_length = bytes.size();

    if (write_message_length) {
        // To avoid dependency on platform specific type size_t we use uint64_t instead
        // https://en.cppreference.com/w/c/types/size_t
        uint64_t portable_message_length = message_length;

        ssize_t message_length_write_result = send(fd, &portable_message_length, sizeof(portable_message_length), send_flags);

        // If write returned error then stop processing
        if (message_length_write_result < 0) {
            // If we received error from it, let's provide details about it in DEBUG mode
            if (message_length_write_result == -1) {
                logger << log4cpp::Priority::DEBUG << "write in write_simple_packet for message length returned error: " << errno
                       << " " << strerror(errno);
            }

            return false;
        }

        // we could not write whole packet notify caller about it
        if (message_length_write_result != sizeof(portable_message_length)) {
            logger << log4cpp::Priority::DEBUG << "write in write_simple_packet for message length did not write all data";
            return false;
        }
    }

    ssize_t write_result = send(fd, bytes.begin(), message_length, send_flags);

    // If write returned error then stop processing
    if (write_result < 0) {
        // If we received error from it, let's provide details about it in DEBUG mode
        if (write_result == -1) {
            logger << log4cpp::Priority::DEBUG << "write in write_simple_packet returned error: " << errno << " "
                   << strerror(errno);
        }

        return false;
    }

    // we could not write whole packet notify caller about it
    if (write_result != bytes.size()) {
        logger << log4cpp::Priority::DEBUG << "write in write_simple_packet did not write all data";
        return false;
    }

    return true;
}



// Encode simple packet into special capnp structure for serialization
bool write_simple_packet_to_tls_socket(SSL* tls_fd, const simple_packet_t& packet) {
    extern log4cpp::Category& logger;
    ::capnp::MallocMessageBuilder message;

    auto capnp_packet = message.initRoot<SimplePacketType>();

    // Craft Capnp message
    craft_capnp_for_simple_packet(packet, capnp_packet);

    kj::Array<capnp::word> words;

    // For some unknown reasons function writePackedMessageToFd sends incorrect, too short data and we use regular send for better flexibility

    try {
        words = messageToFlatArray(message);
    } catch (...) {
        logger << log4cpp::Priority::ERROR << "messageToFlatArray failed with error";
        return false;
    }

    kj::ArrayPtr<kj::byte> bytes = words.asBytes();

    size_t message_length = bytes.size();


    // To avoid dependency on platform specific type size_t we use uint64_t instead
    // https://en.cppreference.com/w/c/types/size_t
    uint64_t portable_message_length = message_length;

    // TODO: unfortunately, it can fire SIGPIPE signal and there are no documented way to stop it :(
    // It's clearly topic to raise with OpenSSL team
    // https://github.com/openssl/openssl/issues/16399
    int message_length_write_result = SSL_write(tls_fd, &portable_message_length, sizeof(portable_message_length));

    // If write returned error then stop processing
    if (message_length_write_result <= 0) {
        // unsigned long error_code = ERR_get_error();

        // We had some issue with this logging function as it cropped output this way:
        // "TLS write for header failed with error:"
        // logger << log4cpp::Priority::ERROR << "TLS write for header failed with error: " << ERR_reason_error_string(error_code) << " error code " << error_code;
        return false;
    }

    // we could not write whole packet notify caller about it
    if (message_length_write_result != sizeof(portable_message_length)) {
        logger << log4cpp::Priority::DEBUG << "write in write_simple_packet for message length did not write all data";
        return false;
    }

    // TODO: unfortunately, it can fire SIGPIPE signal and there are no documented way to stop it :(
    // It's clearly topic to raise with OpenSSL team
    // https://github.com/openssl/openssl/issues/16399
    int write_result = SSL_write(tls_fd, bytes.begin(), message_length);

    // If write returned error then stop processing
    if (write_result <= 0) {
        // unsigned long error_code = ERR_get_error();

        // logger << log4cpp::Priority::ERROR << "TLS write for message body failed with error: " << ERR_reason_error_string(error_code) << " error code " << error_code;
        return false;
    }

    // we could not write whole packet notify caller about it
    if (write_result != bytes.size()) {
        logger << log4cpp::Priority::DEBUG << "write in write_simple_packet did not write all data";
        return false;
    }

    return true;
}

#endif

// Represent IPv6 cidr subnet in string form
std::string print_ipv6_cidr_subnet(subnet_ipv6_cidr_mask_t subnet) {
    return print_ipv6_address(subnet.subnet_address) + "/" + std::to_string(subnet.cidr_prefix_length);
}

// Abstract function with overloads for templated classes where we use v4 and v4
std::string convert_any_ip_to_string(const subnet_ipv6_cidr_mask_t& subnet) {
    return convert_ipv6_subnet_to_string(subnet);
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
    boost::asio::ip::make_address(host, ec);

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
                                std::map<std::string, std::string>& headers,
                                std::string& error_text) {

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
        boost::asio::ssl::context ctx{ boost::asio::ssl::context::tls_client };

        // Load default CA certificates
        ctx.set_default_verify_paths();

        boost::asio::ip::tcp::resolver resolver{ ioc };
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream{ ioc, ctx };

        // Set SNI Hostname
        if (!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str())) {
            boost::system::error_code ec{ static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category() };
            logger << log4cpp::Priority::ERROR << "Can't set SNI hostname: " << ec.message();
            return false;
        }

        auto end_point = resolver.resolve(host, port, ec);

        if (ec) {
            logger << log4cpp::Priority::ERROR << "Could not resolve peer address in execute_web_request " << ec;
            return false;
        }

        logger << log4cpp::Priority::DEBUG << "Resolved host " << host << " to " << end_point.size() << " IP addresses";

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

        std::string content_type = "application/x-www-form-urlencoded";

        // We can override Content Type from headers
        auto header_itr = headers.find("Content-Type");

        if (header_itr != headers.end()) {
            content_type = header_itr->second;
        }

        req.set(boost::beast::http::field::content_type, content_type);

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

        logger << log4cpp::Priority::DEBUG << "Response code: " << response_code;

        logger << log4cpp::Priority::DEBUG << "Prepare to shutdown TLS";

        stream.shutdown(ec);
        if (ec == boost::asio::error::eof) {
            // Rationale:
            // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            ec.assign(0, ec.category());
        }

        logger << log4cpp::Priority::DEBUG << "Successfully closed TLS";

        return true;
    } catch (std::exception& e) {
        logger << log4cpp::Priority::ERROR << "execute_web_request failed with error: " << e.what();
        return false;
    } catch (...) {
        logger << log4cpp::Priority::ERROR << "execute_web_request failed with unknown error";
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
        return execute_web_request_secure(address, request_type, post_data, response_code, response_body, headers, error_text);
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
        boost::asio::io_context ios;
        boost::asio::ip::tcp::resolver r(ios);
        boost::asio::ip::tcp::socket sock(ios);

        auto end_point = r.resolve(host, port, ec);

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

        std::string content_type = "application/x-www-form-urlencoded";

        // We can override Content Type from headers
        auto header_itr = headers.find("Content-Type");

        if (header_itr != headers.end()) {
            content_type = header_itr->second;
        }

        req.set(boost::beast::http::field::content_type, content_type);

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
    } catch (...) {
        error_text = "execute_web_request failed with unknown error";
        return false;
    }

    return false;
}

// Write data to influxdb
bool write_data_to_influxdb(const std::string& database,
                            const std::string& host,
                            const std::string& port,
                            bool enable_auth,
                            const std::string& influx_user,
                            const std::string& influx_password,
                            const std::string& query,
			    std::string& error_text) {
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
    bool result = execute_web_request(influxdb_query_string, "post", query, response_code, response_body, headers, error_text);

    if (!result) {
        return false;
    }

    if (response_code != 204) {
	error_text = "Unexpected response code: " + std::to_string(response_code);
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
std::string join_by_comma_and_equal(const std::map<std::string, std::string>& data) {
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

// We will store option name as key and value will be memory size in bytes
bool parse_meminfo_into_map(std::map<std::string, uint64_t>& parsed_meminfo) {
    extern log4cpp::Category& logger;

    std::ifstream meminfo_file("/proc/meminfo");
    boost::regex memory_info_pattern("^(.*?):\\s+(\\d+).*$", boost::regex::icase);

    if (!meminfo_file.is_open()) {
        logger << log4cpp::Priority::ERROR << "Could not open meminfo file";
        return false;
    }

    std::string line;

    while (getline(meminfo_file, line)) {
        // MemTotal:         501912 kB
        boost::match_results<std::string::const_iterator> regex_results;

        if (boost::regex_match(line, regex_results, memory_info_pattern)) {
            uint64_t memory_value = 0;

            bool integer_parser_result = read_uint64_from_string(regex_results[2], memory_value);

            if (!integer_parser_result) {
                logger << log4cpp::Priority::ERROR << "Could not parse " << regex_results[2] << " as unsigned 64 bit integer";
                return false;
            }

            parsed_meminfo[regex_results[1]] = memory_value * 1024;
        }
    }


    return true;
}

// Reads uint64_t from string with all required safety checks
bool read_uint64_from_string(const std::string& line, uint64_t& value) {
    uint64_t temp_value = 0;

    try {
        // Read value to intermediate variable to avoid interference with argument of function in case of failure
        // NB! This function does not work very well when we have minus in input sequence as it will accept it
        // If the minus sign was part of the input sequence, the numeric value calculated from the sequence of digits
        // is negated as if by unary minus in the result type, which applies unsigned integer wraparound rules.
        temp_value = std::stoull(line);
    } catch (...) {
        return false;
    }

    value = temp_value;

    return true;
}

bool read_file_to_string(const std::string& file_path, std::string& file_content) {
    std::ifstream file_handler;

    file_handler.open(file_path, std::ios::in);

    if (file_handler.is_open()) {
        std::stringstream str_stream;

        str_stream << file_handler.rdbuf();
        file_handler.close();

        file_content = str_stream.str();
        return true;
    } else {
        return false;
    }
}

bool read_integer_from_file(const std::string& file_path, int& value) {
    std::string file_content_in_string;

    bool read_file_to_string_result = read_file_to_string(file_path, file_content_in_string);

    if (!read_file_to_string_result) {
        return false;
    }

    int scanned_value = 0;

    bool read_integer_from_file = convert_string_to_any_integer_safe(file_content_in_string, scanned_value);

    if (!read_integer_from_file) {
        return false;
    }

    value = scanned_value;
    return true;
}

// Safe way to convert string to any integer
bool convert_string_to_any_integer_safe(const std::string& line, int& value) {
    int temp_value = 0;

    try {
        temp_value = std::stoi(line);
    } catch (...) {
        // Could not parse number correctly
        return false;
    }

    value = temp_value;

    return true;
}

// This function is useful when we start it from thread and detach and so we are not interested in error text and we need to discard it
void exec_no_error_check(const std::string& cmd) {
    std::string error_text;
    std::vector<std::string> output_list;

    exec(cmd, output_list, error_text);
    return;
}

unsigned int get_logical_cpus_number() {
    extern log4cpp::Category& logger;

    std::ifstream cpuinfo_file("/proc/cpuinfo");
    boost::regex processor_pattern("^processor.*?$");

    if (!cpuinfo_file.is_open()) {
        logger << log4cpp::Priority::ERROR << "License: could not open cpuinfo";
        return 0;
    }

    std::string line;
    unsigned int logical_cpus_number = 0;

    while (getline(cpuinfo_file, line)) {
        boost::cmatch what;

        if (regex_match(line.c_str(), what, processor_pattern)) {
            logical_cpus_number++;
        }
    }

    return logical_cpus_number;
}

// Get server's total memory in megabytes
unsigned int get_total_memory() {
    extern log4cpp::Category& logger;

    std::ifstream meminfo_file("/proc/meminfo");
    boost::regex memory_info_pattern("^(.*?):\\s+(\\d+).*$", boost::regex::icase);

    if (!meminfo_file.is_open()) {
        logger << log4cpp::Priority::ERROR << "License: could not open meminfo file";
        return 0;
    }

    std::string line;

    while (getline(meminfo_file, line)) {
        // MemTotal:         501912 kB
        boost::match_results<std::string::const_iterator> regex_results;

        if (boost::regex_match(line, regex_results, memory_info_pattern)) {
            if (regex_results[1] == "MemTotal") {
                int memory_amount = 0;

                bool conversion_result = convert_string_to_any_integer_safe(regex_results[2], memory_amount);

                if (!conversion_result) {
                    logger << log4cpp::Priority::ERROR << "Could not parse integer value";
                    return 0;
                }

                return unsigned(memory_amount / 1024);
            }
        } else {
            logger << log4cpp::Priority::ERROR << "Could not parse line in /proc/meminfo: " << line;
            return 0;
        }
    }

    return 0;
}

// Return code name of Linux distro:
// ID=debian
// ID="centos"
// ID=ubuntu
bool get_linux_distro_name(std::string& distro_name) {
    std::map<std::string, std::string> parsed_file;

    if (!parse_os_release_into_map(parsed_file)) {
        return false;
    }

    auto itr = parsed_file.find("ID");

    if (itr == parsed_file.end()) {
        return false;
    }

    distro_name = itr->second;
    return true;
}


// Returns Linux distro version
// VERSION_ID="11"
// VERSION_ID="8"
// VERSION_ID="7"
// VERSION_ID="16.04"
bool get_linux_distro_version(std::string& distro_version) {
    std::map<std::string, std::string> parsed_file;

    if (!parse_os_release_into_map(parsed_file)) {
        return false;
    }

    auto itr = parsed_file.find("VERSION_ID");

    if (itr == parsed_file.end()) {
        return false;
    }

    distro_version = itr->second;
    return true;
}


// We will store option name as key and value will be value
bool parse_os_release_into_map(std::map<std::string, std::string>& parsed_os_release) {
    extern log4cpp::Category& logger;

    // Format: https://www.freedesktop.org/software/systemd/man/os-release.html
    std::ifstream os_release_file("/etc/os-release");

    // Split line like:
    // ID="centos"
    boost::regex os_release_pattern("^(.*?)=\"?(.*?)\"?$", boost::regex::icase);

    if (!os_release_file.is_open()) {
        logger << log4cpp::Priority::ERROR << "Could not open /etc/os-release file";
        return false;
    }

    std::string line;

    while (getline(os_release_file, line)) {
        // ID="centos"
        // VERSION_ID="7"

        boost::match_results<std::string::const_iterator> regex_results;

        if (boost::regex_match(line, regex_results, os_release_pattern)) {
            std::string value = regex_results[2];

            // We may have or may not have quotes for value, strip them
            boost::replace_all(value, "\"", "");

            parsed_os_release[regex_results[1]] = value;
        }
    }

    return true;
}

// Returns virtualisation method or "unknown"
// It may have dash in value like "vm-other" or "lxc-libvirt" but no other symbols are expected
std::string get_virtualisation_method() {
    std::string error_text;
    std::vector<std::string> output;

    bool exec_result = exec("systemd-detect-virt --vm", output, error_text);

    if (!exec_result) {
        return "unknown";
    }

    if (output.empty()) {
        return "unknown";
    }

    // Return first element
    return boost::algorithm::to_lower_copy(output[0]);
}

#ifdef _WIN32
bool get_kernel_version(std::string& kernel_version) {
    kernel_version = "windows";
    return true;
}
#else
// Get linux kernel version in form: 3.19.0-25-generic
bool get_kernel_version(std::string& kernel_version) {
    struct utsname current_utsname;

    int uname_result = uname(&current_utsname);

    if (uname_result != 0) {
        return false;
    }

    // Release field is a char array (char release[], http://man7.org/linux/man-pages/man2/uname.2.html) and we do not need NULL check here
    kernel_version = std::string(current_utsname.release);

    return true;
}
#endif

// Returns all CPU flags in vector
bool get_cpu_flags(std::vector<std::string>& flags) {
    extern log4cpp::Category& logger;

    std::ifstream cpuinfo_file("/proc/cpuinfo");
    boost::regex processor_flags_pattern("^flags\\s+:\\s(.*?)$");

    if (!cpuinfo_file.is_open()) {
        logger << log4cpp::Priority::ERROR << "Could not open cpuinfo";
        return false;
    }

    std::string line;
    while (getline(cpuinfo_file, line)) {
        boost::match_results<std::string::const_iterator> regex_results;

        if (boost::regex_match(line, regex_results, processor_flags_pattern)) {
            // Split all flags by space
            split(flags, regex_results[1], boost::is_any_of(" "), boost::token_compress_on);
            return true;
        }
    }

    logger << log4cpp::Priority::ERROR << "Cannot find any flags in cpuinfo";
    return false;
}

bool get_cpu_model(std::string& cpu_model) {
    extern log4cpp::Category& logger;

    std::ifstream cpuinfo_file("/proc/cpuinfo");

    if (!cpuinfo_file.is_open()) {
        logger << log4cpp::Priority::ERROR << "Could not open /proc/cpuinfo";
        return false;
    }

    boost::regex processor_model_pattern("^model name\\s+:\\s(.*?)$");
    std::string line;

    while (getline(cpuinfo_file, line)) {
        boost::match_results<std::string::const_iterator> regex_results;

        if (boost::regex_match(line, regex_results, processor_model_pattern)) {
            cpu_model = regex_results[1];
            return true;
        }
    }

    // For ARM CPUs we have another format
    // Even if we run in x86_64 mode we can have cpuinfo with such information on ARM64 based macOS platforms
    std::string implementer;
    std::string part;
    std::string revision;

    boost::regex implementer_pattern("^CPU implementer\\s+:\\s(.*?)$");
    boost::regex part_pattern("^CPU part\\s+:\\s(.*?)$");
    boost::regex revision_pattern("^CPU revision\\s+:\\s(.*?)$");

    // Reset to start of file
    cpuinfo_file.clear();
    cpuinfo_file.seekg(0, std::ios::beg);

    while (getline(cpuinfo_file, line)) {
        boost::match_results<std::string::const_iterator> regex_results_implementer;
        boost::match_results<std::string::const_iterator> regex_results_part;
        boost::match_results<std::string::const_iterator> regex_results_revision;

        if (boost::regex_match(line, regex_results_implementer, implementer_pattern)) {
            implementer = regex_results_implementer[1];
        }

        if (boost::regex_match(line, regex_results_part, part_pattern)) {
            part = regex_results_part[1];
        }

        if (boost::regex_match(line, regex_results_revision, revision_pattern)) {
            revision = regex_results_revision[1];
        }
    }

    // If we fould all of them, use these fields as model
    if (implementer.size() > 0 && part.size() > 0 && revision.size() > 0) {
        cpu_model = "implementer: " + implementer + " part: " + part + " revision: " + revision;
        return true;
    }

    // logger << log4cpp::Priority::ERROR << "implementer: " << implementer << " part: " << part << " revision: " << revision;

    return false;
}

// returns forwarding status as string
std::string forwarding_status_to_string(forwarding_status_t status) {
    if (status == forwarding_status_t::unknown) {
        return "unknown";
    } else if (status == forwarding_status_t::forwarded) {
        return "forwarded";
    } else if (status == forwarding_status_t::dropped) {
        return "dropped";
    } else if (status == forwarding_status_t::consumed) {
        return "consumed";
    } else {
        // It must not happen
        return "unknown";
    }
}

// Pretty strange function to implement country code conversion we use in fastnetmon_simple_packet
std::string country_static_string_to_dynamic_string(const boost::beast::static_string<2>& country_code) {
    std::string country_code_dynamic_string;

    if (country_code.size() == 2) {
        country_code_dynamic_string += country_code[0];
        country_code_dynamic_string += country_code[1];
    }

    return country_code_dynamic_string;
}

#ifdef _WIN32
// We have no inet_aton on Windows but we do have inet_pton https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-inet_pton
// Convert IP in string representation to uint32_t in big endian (network byte order)
// I think we can switch to using pton for Linux and other *nix too but we need to do careful testing including performance evaluation before
bool convert_ip_as_string_to_uint_safe(const std::string& ip, uint32_t& ip_as_integer) {
    struct in_addr ip_addr;

    // Both Windows and Linux return 1 in case of success
    if (inet_pton(AF_INET, ip.c_str(), &ip_addr) != 1) {
        return false;
    }

    // in network byte order
    ip_as_integer = ip_addr.s_addr;
    return true;
}
#else
// Convert IP in string representation to uint32_t in big endian (network byte order)
bool convert_ip_as_string_to_uint_safe(const std::string& ip, uint32_t& ip_as_integer) {
    struct in_addr ip_addr;

    // Please be careful! This function uses pretty strange approach for returned codes
    // inet_aton() returns nonzero if the address is valid, zero if not.
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
        return false;
    }

    // in network byte order
    ip_as_integer = ip_addr.s_addr;
    return true;
}
#endif

forwarding_status_t forwarding_status_from_integer(uint8_t forwarding_status_as_integer) {
    // Decode numbers into forwarding statuses
    // I think they're same for Netflow v9 https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
    // and IPFIX: https://datatracker.ietf.org/doc/html/rfc7270#section-4.12
    if (forwarding_status_as_integer == 0) {
        return forwarding_status_t::unknown;
    } else if (forwarding_status_as_integer == 1) {
        return forwarding_status_t::forwarded;
    } else if (forwarding_status_as_integer == 2) {
        return forwarding_status_t::dropped;
    } else if (forwarding_status_as_integer == 3) {
        return forwarding_status_t::consumed;
    } else {
        // It must not happen
        return forwarding_status_t::unknown;
    }
}

// Represent IPv6 subnet in string form
std::string convert_ipv6_subnet_to_string(const subnet_ipv6_cidr_mask_t& subnet) {
    return print_ipv6_address(subnet.subnet_address) + "/" + std::to_string(subnet.cidr_prefix_length);
}

std::string convert_any_ip_to_string(uint32_t client_ip) {
    return convert_ip_as_uint_to_string(client_ip);
}

// This code lookup IP in specified patricia tree and returns prefix which it
// belongs
bool lookup_ip_in_integer_form_inpatricia_and_return_subnet_if_found(patricia_tree_t* patricia_tree,
                                                                     uint32_t client_ip,
                                                                     subnet_cidr_mask_t& subnet) {
    if (patricia_tree == NULL) {
        return false;
    }

    prefix_t prefix_for_check_address;
    prefix_for_check_address.add.sin.s_addr = client_ip;
    prefix_for_check_address.family         = AF_INET;
    prefix_for_check_address.bitlen         = 32;

    patricia_node_t* found_patrica_node = patricia_search_best2(patricia_tree, &prefix_for_check_address, 1);

    if (found_patrica_node == NULL) {
        return false;
    }

    prefix_t* prefix = found_patrica_node->prefix;

    if (prefix == NULL) {
        return false;
    }

    subnet.subnet_address     = prefix->add.sin.s_addr;
    subnet.cidr_prefix_length = prefix->bitlen;

    return true;
}

// Return true if we have this IP in patricia tree
bool ip_belongs_to_patricia_tree(patricia_tree_t* patricia_tree, uint32_t client_ip) {
    prefix_t prefix_for_check_address;
    prefix_for_check_address.add.sin.s_addr = client_ip;
    prefix_for_check_address.family         = AF_INET;
    prefix_for_check_address.bitlen         = 32;

    return patricia_search_best2(patricia_tree, &prefix_for_check_address, 1) != NULL;
}

// Overloaded function which works with any IP protocol version, we use it for templated applications
std::string convert_any_subnet_to_string(const subnet_ipv6_cidr_mask_t& subnet) {
    return convert_ipv6_subnet_to_string(subnet);
}

std::string convert_any_subnet_to_string(const subnet_cidr_mask_t& subnet) {
    return convert_ipv4_subnet_to_string(subnet);
}

std::string print_binary_string_as_hex_with_leading_0x(const uint8_t* data_ptr, uint32_t data_length) {
    std::stringstream buffer;

    for (uint32_t i = 0; i < data_length; i++) {
        buffer << "0x" << std::setfill('0') << std::setw(2) << std::hex << uint32_t(data_ptr[i]) << " ";
    }

    return buffer.str();
}

bool read_ipv6_subnet_from_string(subnet_ipv6_cidr_mask_t& ipv6_address, const std::string& ipv6_subnet_as_string) {
    extern log4cpp::Category& logger;

    std::vector<std::string> subnet_as_string;

    split(subnet_as_string, ipv6_subnet_as_string, boost::is_any_of("/"), boost::token_compress_on);

    if (subnet_as_string.size() != 2) {
        return false;
    }

    int cidr = 0;

    bool conversion_result = convert_string_to_any_integer_safe(subnet_as_string[1], cidr);

    if (!conversion_result) {
        return false;
    }

    ipv6_address.cidr_prefix_length = cidr;

    bool parsed_ipv6 = read_ipv6_host_from_string(subnet_as_string[0], ipv6_address.subnet_address);

    if (!parsed_ipv6) {
        logger << log4cpp::Priority::ERROR << "Can't parse IPv6 address: " << ipv6_subnet_as_string;
        return false;
    }

    return true;
}

// Return true if we have this subnet in patricia tree
bool subnet_belongs_to_patricia_tree(patricia_tree_t* patricia_tree, const subnet_cidr_mask_t& subnet) {
    prefix_t prefix_for_check_adreess;
    prefix_for_check_adreess.add.sin.s_addr = subnet.subnet_address;
    prefix_for_check_adreess.family         = AF_INET;
    prefix_for_check_adreess.bitlen         = subnet.cidr_prefix_length;

    patricia_node_t* found_patrica_node = patricia_search_best2(patricia_tree, &prefix_for_check_adreess, 1);

    if (found_patrica_node != NULL) {
        return true;
    } else {
        return false;
    }
}

// Prepares textual dump of simple packets buffer
void print_simple_packet_buffer_to_string(const boost::circular_buffer<simple_packet_t>& simple_packets_buffer, std::string& output) {
    if (simple_packets_buffer.size() != 0) {
        std::stringstream ss;

        for (const simple_packet_t& packet : simple_packets_buffer) {
            ss << print_simple_packet(packet);
        }

        output = ss.str();
    }
}


// Write circular buffer with simple packets to json document
bool write_simple_packet_as_separate_fields_dump_to_json(const boost::circular_buffer<simple_packet_t>& simple_packets_buffer,
                                                         nlohmann::json& packet_array) {
    extern log4cpp::Category& logger;

    // Even if we have no data we need empty array here
    packet_array = nlohmann::json::array();

    try {

        if (simple_packets_buffer.size() == 0) {
            logger << log4cpp::Priority::INFO << "Packet buffer is blank";
            return true;
        }

        // Add all pack descriptions as strings array
        for (const simple_packet_t& packet : simple_packets_buffer) {
            nlohmann::json json_packet;

            if (!serialize_simple_packet_to_json(packet, json_packet)) {
                continue;
            }

            // Append to document as normal STL container
            packet_array.push_back(json_packet);
        }

    } catch (...) {
        logger << log4cpp::Priority::ERROR << "Cannot create packet list in JSON";
        return false;
    }

    return true;
}


