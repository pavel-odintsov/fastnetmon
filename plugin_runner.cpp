#include <inttypes.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <sstream>
#include <netinet/ip.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "fastnetmon_types.h"
#include "netflow_plugin/netflow_collector.h"

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

string print_simple_packet(simple_packet packet) {
    std::stringstream buffer;

    buffer<<convert_timeval_to_date(packet.ts)<<" ";

    buffer
        <<convert_ip_as_uint_to_string(packet.src_ip)<<":"<<packet.source_port
        <<" > "
        <<convert_ip_as_uint_to_string(packet.dst_ip)<<":"<<packet.destination_port
        <<" protocol: "<<get_printable_protocol_name(packet.protocol);
   
    // Print flags only for TCP 
    //if (packet.protocol == IPPROTO_TCP) { 
    //    buffer<<" flags: "<<print_tcp_flags(packet.flags);
    //}

    buffer<<" size: "<<packet.length<<" bytes"<<"\n";
    
    return buffer.str();
}

void process_packet(simple_packet& current_packet) { 
    std::cout<<print_simple_packet(current_packet);
}

int main() {
    init_logging(); 
    
    start_netflow_collection(process_packet);
}


