#include <sys/types.h>
#include <stdint.h>
#include "fast_library.h"
#include <arpa/inet.h>
#include <stdlib.h> // atoi
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>

#include <fstream>
#include <iostream>

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
uint64_t fast_ntoh (uint64_t value) {
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

// extract 24 from 192.168.1.1/24
unsigned int get_cidr_mask_from_network_as_string(std::string network_cidr_format) {
    std::vector<std::string> subnet_as_string;
    split( subnet_as_string, network_cidr_format, boost::is_any_of("/"), boost::token_compress_on );

    if (subnet_as_string.size() != 2) {
        return 0;
    }

    return convert_string_to_integer(subnet_as_string[1]);
}


std::string print_time_t_in_fastnetmon_format(time_t current_time) {
    struct tm* timeinfo;
    char buffer[80];

    timeinfo = localtime (&current_time);

    strftime (buffer, sizeof(buffer), "%d_%m_%y_%H:%M:%S", timeinfo);

    return std::string(buffer);
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
        case 0:
        	proto_name = "mixed";
        	break;
        default:
            proto_name = "unknown";
            break;
    }

    return proto_name;
}

uint32_t convert_cidr_to_binary_netmask(unsigned int cidr) {
    uint32_t binary_netmask = 0xFFFFFFFF;
    binary_netmask = binary_netmask << ( 32 - cidr );
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


// http://stackoverflow.com/questions/14528233/bit-masking-in-c-how-to-get-first-bit-of-a-byte
int extract_bit_value(uint8_t num, int bit) {
    if (bit > 0 && bit <= 8) {
        return ( (num >> (bit-1)) & 1 );
    } else {
        return 0;
    }
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

std::string convert_timeval_to_date(struct timeval tv) {
    time_t nowtime = tv.tv_sec;
    struct tm *nowtm = localtime(&nowtime);

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
    struct protoent* proto_ent = getprotobynumber( proto_number );
    std::string proto_name = proto_ent->p_name;
    return proto_name;
} 

// exec command in shell
std::vector<std::string> exec(std::string cmd) {
    std::vector<std::string> output_list;

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return output_list;

    char buffer[256];
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

void print_pid_to_file(pid_t pid, std::string pid_path) {
    std::ofstream pid_file;

    pid_file.open(pid_path.c_str(), std::ios::trunc);
    if (pid_file.is_open()) {
        pid_file<<pid<<"\n";
        pid_file.close();
    }
}

bool read_pid_from_file(pid_t& pid, std::string pid_path) {
    std::fstream pid_file(pid_path.c_str(), std::ios_base::in);

    if (pid_file.is_open()) {
        pid_file>>pid;
        pid_file.close();

        return true;
    } else {
        return false;
    }
}
