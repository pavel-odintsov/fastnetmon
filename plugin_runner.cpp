#include <inttypes.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <iterator>
#include <sstream>
#include <netinet/ip.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "fastnetmon_types.h"
#include "netflow_plugin/netflow_collector.h"
#include "sflow_plugin/sflow_collector.h"
#include "pcap_plugin/pcap_collector.h"

// log4cpp logging facility
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

using namespace std;

std::string log_file_path = "/tmp/fastnetmon_plugin_tester.log";
log4cpp::Category& logger = log4cpp::Category::getRoot();

// Global map with parsed config file
std::map<std::string, std::string> configuration_map;

void init_logging() {
    log4cpp::PatternLayout* layout = new log4cpp::PatternLayout(); 
    layout->setConversionPattern ("%d [%p] %m%n"); 

    log4cpp::Appender *appender = new log4cpp::FileAppender("default", log_file_path);
    appender->setLayout(layout);

    logger.setPriority(log4cpp::Priority::INFO);
    logger.addAppender(appender);
    logger.info("Logger initialized!");
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

string convert_timeval_to_date(struct timeval tv) {
    time_t nowtime = tv.tv_sec;
    struct tm *nowtm = localtime(&nowtime);
    
    char tmbuf[64];
    char buf[64];

    strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);

    snprintf(buf, sizeof(buf), "%s.%06ld", tmbuf, tv.tv_usec); 

    return string(buf);
}

string convert_ip_as_uint_to_string(uint32_t ip_as_integer) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ip_as_integer;
    return (string)inet_ntoa(ip_addr);
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

string print_simple_packet(simple_packet packet) {
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

    buffer<<" packets: "<<packet.number_of_packets<<" ";
    buffer<<"size: "   <<packet.length<<" bytes"<<" ";
    buffer<<"sample ratio: "<<packet.sample_ratio<<" ";
    buffer<<"\n";
    
    return buffer.str();
}

void process_packet(simple_packet& current_packet) { 
    std::cout<<print_simple_packet(current_packet);
}

int main(int argc, char *argv[]) {
    init_logging(); 
    
    if (argc < 2) {
        std::cout<<"Please specify sflow or netflow as param";
        return 1;
    }

    if (strstr(argv[1], "sflow") != NULL) {
        std::cout<<"Starting sflow"<<std::endl;
        start_sflow_collection(process_packet);
    } else if (strstr(argv[1], "netflow") != NULL) {
        std::cout<<"Starting netflow"<<std::endl;
        start_netflow_collection(process_packet);
    } else if (strstr(argv[1], "pcap") != NULL) {
        std::cout<<"Starting pcap"<<std::endl;
        start_pcap_collection(process_packet);
    } else {
        std::cout<<"Bad plugin name!";
    }
}


