/* netflow plugin body */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>

// log4cpp logging facility
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

// Get it from main programm
extern log4cpp::Category& logger;

#include "netflow_collector.h"
#include "netflow.h"

process_packet_pointer netflow_process_func_ptr = NULL;

void process_netflow_packet_v5(u_int len, u_int8_t *packet) {
    //logger<< log4cpp::Priority::INFO<<"We get v5 netflow packet!";
    
    struct NF5_HEADER* nf5_hdr = (struct NF5_HEADER*)packet;

    if (len < sizeof(*nf5_hdr)) {
        logger<< log4cpp::Priority::ERROR<<"Short netflow v5 packet "<<len;
        return;
    }

    u_int nflows = ntohs(nf5_hdr->c.flows);
    if (nflows == 0 || nflows > NF5_MAXFLOWS) {
        logger<< log4cpp::Priority::ERROR<<"Invalid number of flows in netflow "<<nflows;
        return;
    }
    
    for (u_int i = 0; i < nflows; i++) {
        size_t offset = NF5_PACKET_SIZE(i);
        struct NF5_FLOW* nf5_flow = (struct NF5_FLOW *)(packet + offset);

        // convert netflow to simple packet form
        simple_packet current_packet;
  
        current_packet.src_ip = nf5_flow->src_ip;
        current_packet.dst_ip = nf5_flow->dest_ip;
        current_packet.ts.tv_sec  = ntohl(nf5_hdr->time_sec);
        current_packet.ts.tv_usec = ntohl(nf5_hdr->time_nanosec);
        current_packet.flags = 0;

        current_packet.source_port = 0;
        current_packet.destination_port = 0;

        // TODO: we should pass data about "flow" structure of this data
    
        // htobe64 removed
        current_packet.length            = ntohl(nf5_flow->flow_octets);
        current_packet.number_of_packets = ntohl(nf5_flow->flow_packets);

        // netflow did not support sampling
        current_packet.sample_ratio = 1;

        switch (nf5_flow->protocol) {
            case 1: {
                //ICMP
                current_packet.protocol = IPPROTO_ICMP; 
            }
            break;

            case 6: { 
                // TCP
                current_packet.protocol = IPPROTO_TCP;

                current_packet.source_port      = nf5_flow->src_port;
                current_packet.destination_port = nf5_flow->dest_port;

                // TODO: flags can be in another format!
                current_packet.flags = nf5_flow->tcp_flags;
            }
            break;

            case 17: {
                // UDP
                current_packet.protocol = IPPROTO_UDP;

                current_packet.source_port      = nf5_flow->src_port;
                current_packet.destination_port = nf5_flow->dest_port;
            }
            break;
        }
   
        // Call processing function for every flow in packet
        netflow_process_func_ptr(current_packet);
    }
}

void process_netflow_packet(u_int len, u_int8_t *packet) {
    struct NF_HEADER_COMMON *hdr = (struct NF_HEADER_COMMON *)packet;

    switch (ntohs(hdr->version)) {
        case 5:
            process_netflow_packet_v5(len, packet);
            break;
        //case 9:
        //   process_netflow_v9(fp, conf, peer, peers, log_fd, log_socket);
        //    break;
        default:
            logger<< log4cpp::Priority::ERROR<<"We did not support this version of netflow "<<ntohs(hdr->version);
            break;    
    }
}

void start_netflow_collection(process_packet_pointer func_ptr) {
    logger<< log4cpp::Priority::INFO<<"netflow plugin started";
    netflow_process_func_ptr = func_ptr;

    unsigned int udp_buffer_size = 65536;
    char udp_buffer[udp_buffer_size];

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
   
    unsigned int netflow_port = 2055;
 
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(netflow_port);
    
    int bind_result = bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    if (bind_result) {
        logger<< log4cpp::Priority::ERROR<<"Can't listen port: "<<netflow_port;
        return;
    }

    struct sockaddr_in6 peer;
    memset(&peer, 0, sizeof(peer));

    for (;;) {
        struct sockaddr_in cliaddr;
        socklen_t address_len = sizeof(cliaddr);

        int received_bytes = recvfrom(sockfd, udp_buffer, udp_buffer_size, 0, (struct sockaddr *)&cliaddr, &address_len); 

        if (received_bytes > 0) {
            // printf("We receive %d\n", received_bytes);
            process_netflow_packet(received_bytes, (u_int8_t*)udp_buffer);
        } else {
            logger<< log4cpp::Priority::ERROR<<"netflow data receive failed";
        }
    }
}

