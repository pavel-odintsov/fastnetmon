#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string>
#include <sstream>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../netflow_plugin/netflow_collector.h"
#include "../fastnetmon_packet_parser.h"
#include "../fastnetmon_types.h"

#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

// Fake config
std::map<std::string, std::string> configuration_map;

std::string log_file_path = "/tmp/fastnetmon_pcap_reader.log";
log4cpp::Category& logger = log4cpp::Category::getRoot();


/* It's prototype for moc testing of FastNetMon, it's very useful for netflow or direct packet parsers debug */

/* 
   pcap dump format:
    global header: struct pcap_file_header
    packet header: struct fastnetmon_pcap_pkthdr
*/

// We can't use pcap_pkthdr from upstream because it uses 16 bytes timeval instead of 8 byte and broke everything
struct fastnetmon_pcap_pkthdr {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};

void pcap_parse_packet(char* buffer, uint32_t len);

void init_logging() {
    log4cpp::PatternLayout* layout = new log4cpp::PatternLayout(); 
    layout->setConversionPattern ("%d [%p] %m%n"); 

    log4cpp::Appender *appender = new log4cpp::FileAppender("default", log_file_path);
    appender->setLayout(layout);

    logger.setPriority(log4cpp::Priority::INFO);
    logger.addAppender(appender);
    logger.info("Logger initialized!");
}

// Copy & Paste
int convert_string_to_integer(std::string line) {
    return atoi(line.c_str());
}

int pcap_reader(const char* pcap_file_path) {
    int filedesc = open(pcap_file_path, O_RDONLY);

    if (filedesc <= 0) {
        printf("Can't open dump file");
        return -1;
    } 

    struct pcap_file_header pcap_header;
    ssize_t file_header_readed_bytes = read(filedesc, &pcap_header, sizeof(struct pcap_file_header));

    if (file_header_readed_bytes != sizeof(struct pcap_file_header)) {
        printf("Can't read pcap file header");
    }

    // http://www.tcpdump.org/manpages/pcap-savefile.5.html
    if (pcap_header.magic == 0xa1b2c3d4 or pcap_header.magic == 0xd4c3b2a1) {
        // printf("Magic readed correctly\n");
    } else {
        printf("Magic in file header broken\n");
        return -2;
    }

    // Buffer for packets
    char packet_buffer[pcap_header.snaplen];

    unsigned int read_packets = 0; 
    while (1) {
        printf("Start packet %d processing\n", read_packets);
        struct fastnetmon_pcap_pkthdr pcap_packet_header;
        ssize_t packet_header_readed_bytes = read(filedesc, &pcap_packet_header, sizeof(struct fastnetmon_pcap_pkthdr));
      
        if (packet_header_readed_bytes != sizeof(struct fastnetmon_pcap_pkthdr)) {
            // We haven't any packets 
            break;
        }

        if (pcap_packet_header.incl_len > pcap_header.snaplen) {
            printf("Please enlarge packet buffer! We got packet with size: %d but our buffer is %d bytes\n",
                pcap_packet_header.incl_len, pcap_header.snaplen);
            return -4;
        }

        ssize_t packet_payload_readed_bytes = read(filedesc, packet_buffer, pcap_packet_header.incl_len);
 
        if (pcap_packet_header.incl_len != packet_payload_readed_bytes) {
            printf("I read packet header but can't read packet payload\n");
            return -3;
        }

        // printf("packet payload read\n");
        pcap_parse_packet(packet_buffer, pcap_packet_header.incl_len);

        printf("Process packet %d\n", read_packets);
        read_packets++;
    }

    printf("I correctly read %d packets from this dump\n", read_packets);

    return 0;
}



// Ugly copy & paste
std::string convert_ip_as_uint_to_string(uint32_t ip_as_integer) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ip_as_integer;
    return (std::string)inet_ntoa(ip_addr);
}

// Reduce function version
std::string print_simple_packet(simple_packet packet) {
    std::stringstream buffer;

    /// buffer<<convert_timeval_to_date(packet.ts)<<" ";

    buffer
        <<convert_ip_as_uint_to_string(packet.src_ip)<<":"<<packet.source_port
        <<" > "
        <<convert_ip_as_uint_to_string(packet.dst_ip)<<":"<<packet.destination_port;
        //<<" protocol: "<<get_printable_protocol_name(packet.protocol);
   
    // Print flags only for TCP 
    //if (packet.protocol == IPPROTO_TCP) { 
    //    buffer<<" flags: "<<print_tcp_flags(packet.flags);
    //}

    buffer<<" packets: "<<packet.number_of_packets<<" ";
    buffer<<"size: "   <<packet.length<<" bytes"<<" ";
    buffer<<"sample ratio: "<<packet.sample_ratio<<" ";
    buffer<<"\n";
    
    return buffer.str();
}

void my_fastnetmon_packet_handler(simple_packet& current_packet) {
    printf("handler colled\n");
    std::cout<<print_simple_packet(current_packet)<<std::endl;
}

extern process_packet_pointer netflow_process_func_ptr;

void pcap_parse_packet(char* buffer, uint32_t len) {
    struct pfring_pkthdr packet_header;
    memset(&packet_header, 0, sizeof(packet_header));
    packet_header.len = len;
    packet_header.caplen = len;

    netflow_process_func_ptr = my_fastnetmon_packet_handler;

    fastnetmon_parse_pkt((u_char*)buffer, &packet_header, 4, 1, 0); 
    
    //char print_buffer[512];
    //fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)buffer, &packet_header);
    //logger.info("%s", print_buffer);

    char* payload_ptr = packet_header.extended_hdr.parsed_pkt.offset.payload_offset + buffer;

    if (packet_header.len <= packet_header.extended_hdr.parsed_pkt.offset.payload_offset) {
        printf("Something goes wrong! Offset if bigger than total packet length");
        return;
    }
       
    unsigned int payload_length = packet_header.len - packet_header.extended_hdr.parsed_pkt.offset.payload_offset;
    process_netflow_packet((u_int8_t*)payload_ptr, payload_length); 
}

int main() {
    init_logging();
    //pcap_reader("/root/netflowexample2_netflow9_cisco_sampling_issue.pcap");
    pcap_reader("/root/flow_dump_ipfix_issue_with_fixed_to_2055.pcap");
    //pcap_reader("/root/ipfix_example_ipt_netflow_syn_flood.pcap");
    //pcap_reader("/Users/pavel-odintsov/Dropbox/ipfix_example_ipt_netflow_syn_flood.pcap");
}
