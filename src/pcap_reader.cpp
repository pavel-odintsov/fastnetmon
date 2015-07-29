#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string>
#include <sstream>

#include "fastnetmon_pcap_format.h"

#ifdef ENABLE_DPI
#include "fast_dpi.h"
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "netflow_plugin/netflow_collector.h"
#include "sflow_plugin/sflow_collector.h"

#include "sflow_plugin/sflow_data.h"
#include "sflow_plugin/sflow.h"

#include "fastnetmon_packet_parser.h"
#include "fastnetmon_types.h"
#include "fast_library.h"

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


/* It's prototype for moc testing of FastNetMon, it's very useful for netflow or direct packet
 * parsers debug */

void init_logging() {
    log4cpp::PatternLayout* layout = new log4cpp::PatternLayout();
    layout->setConversionPattern("%d [%p] %m%n");

    log4cpp::Appender* appender = new log4cpp::FileAppender("default", log_file_path);
    appender->setLayout(layout);

    logger.setPriority(log4cpp::Priority::INFO);
    logger.addAppender(appender);
    logger.info("Logger initialized!");
}

void pcap_parse_packet(const char* flow_type, char* buffer, uint32_t len);

void my_fastnetmon_packet_handler(simple_packet& current_packet) {
    std::cout << print_simple_packet(current_packet);
}

extern process_packet_pointer netflow_process_func_ptr;
extern process_packet_pointer sflow_process_func_ptr;

char* flow_type = NULL;

#ifdef ENABLE_DPI
struct ndpi_detection_module_struct* my_ndpi_struct = NULL;

u_int32_t ndpi_size_flow_struct = 0;
u_int32_t ndpi_size_id_struct = 0;
#endif

void pcap_parse_packet(char* buffer, uint32_t len) {
    struct pfring_pkthdr packet_header;
    memset(&packet_header, 0, sizeof(packet_header));
    packet_header.len = len;
    packet_header.caplen = len;

    fastnetmon_parse_pkt((u_char*)buffer, &packet_header, 4, 1, 0);

    // char print_buffer[512];
    // fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)buffer, &packet_header);
    // logger.info("%s", print_buffer);

    char* payload_ptr = packet_header.extended_hdr.parsed_pkt.offset.payload_offset + buffer;

    if (packet_header.len <= packet_header.extended_hdr.parsed_pkt.offset.payload_offset) {
        printf("Something goes wrong! Offset %u is bigger than total packet length %u\n",
            packet_header.extended_hdr.parsed_pkt.offset.payload_offset, packet_header.len);
        return;
    }

    unsigned int payload_length = packet_header.len - packet_header.extended_hdr.parsed_pkt.offset.payload_offset;

    if (strcmp(flow_type, "netflow") == 0) {
        netflow_process_func_ptr = my_fastnetmon_packet_handler;

        std::string fake_peer_ip = "10.0.1.2";
        process_netflow_packet((u_int8_t*)payload_ptr, payload_length, fake_peer_ip);
    } else if (strcmp(flow_type, "sflow") == 0) {
        sflow_process_func_ptr = my_fastnetmon_packet_handler;

        SFSample sample;
        memset(&sample, 0, sizeof(sample));

        sample.rawSample = (uint8_t*)payload_ptr;
        sample.rawSampleLen = payload_length;
        sample.sourceIP.type = SFLADDRESSTYPE_IP_V4;

        read_sflow_datagram(&sample);
    } else if (strcmp(flow_type, "raw") == 0) {
        // We do not need parsed data here
        struct pfring_pkthdr packet_header;
        memset(&packet_header, 0, sizeof(packet_header));

        packet_header.len = payload_length;
        packet_header.caplen = payload_length;

        fastnetmon_parse_pkt((u_char*)buffer, &packet_header, 4, 1, 0);

        char print_buffer[512];
        fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)buffer, &packet_header);
        printf("%s", print_buffer);
    } else if (strcmp(flow_type, "dpi") == 0) {
#ifdef ENABLE_DPI
        struct ndpi_id_struct *src = NULL;
        struct ndpi_id_struct *dst = NULL;
        struct ndpi_flow_struct *flow = NULL;

        src = (struct ndpi_id_struct*)malloc(ndpi_size_id_struct);
        memset(src, 0, ndpi_size_id_struct);

        dst = (struct ndpi_id_struct*)malloc(ndpi_size_id_struct);
        memset(dst, 0, ndpi_size_id_struct);

        flow = (struct ndpi_flow_struct *)malloc(ndpi_size_flow_struct); 
        memset(flow, 0, ndpi_size_flow_struct);

        uint32_t current_tickt = 0;
        uint8_t* iph = (uint8_t*)(&buffer[packet_header.extended_hdr.parsed_pkt.offset.l3_offset]);
        unsigned int ipsize = packet_header.len; 

        ndpi_protocol detected_protocol = ndpi_detection_process_packet(my_ndpi_struct, flow, iph, ipsize, current_tickt, src, dst);

        char* protocol_name = ndpi_get_proto_name(my_ndpi_struct, detected_protocol.protocol);
        char* master_protocol_name = ndpi_get_proto_name(my_ndpi_struct, detected_protocol.master_protocol); 

        printf("Protocol: %s master protocol: %s\n", protocol_name, master_protocol_name);

        if (detected_protocol.protocol == NDPI_PROTOCOL_DNS) {
            printf("It's DNS, we could check packet type. query_type: %d query_class: %d rsp_code: %d\n",
                flow->protos.dns.query_type,
                flow->protos.dns.query_class,
                flow->protos.dns.rsp_type
            );

            /*
                struct {
                    u_int8_t num_queries, num_answers, ret_code;
                    u_int8_t bad_packet // the received packet looks bad
                    u_int16_t query_type, query_class, rsp_type;
                } dns;
            */

            
        }

        ndpi_free_flow(flow);
        free(dst);
        free(src);
#endif  
    } else {
        printf("We do not support this flow type: %s\n", flow_type);
    }
}

int main(int argc, char** argv) {
    init_logging();

    if (argc != 3) {
        printf("Please provide flow type: sflow, netflow, raw or dpi and path to pcap dump\n");
        exit(1);
    }
    
    flow_type = argv[1];
    printf("We will process file: %s as %s dump\n", argv[2], argv[1]);

#ifdef ENABLE_DPI
    if (strcmp(flow_type, "dpi") == 0) {
        my_ndpi_struct = init_ndpi();

        if (my_ndpi_struct == NULL) {
            printf("Can't load nDPI\n");
            exit(0);
        }

        ndpi_size_id_struct   = ndpi_detection_get_sizeof_ndpi_id_struct();
        ndpi_size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();
    }
#endif
    

    pcap_reader(argv[2], pcap_parse_packet);
}
