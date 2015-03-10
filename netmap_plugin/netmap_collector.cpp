// log4cpp logging facility
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

// For support uint32_t, uint16_t
#include <sys/types.h>

// For config map operations
#include <string>
#include <map>

#include <stdio.h>
#include <iostream>
#include <string>
#define NETMAP_WITH_LIBS

#include <net/netmap_user.h>
#include <boost/thread.hpp>

#include "../fastnetmon_packet_parser.h"

// For pooling operations
#include <poll.h>

// For support: IPPROTO_TCP, IPPROTO_ICMP, IPPROTO_UDP
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "netmap_collector.h"

/* prototypes */
void netmap_thread(struct nm_desc* netmap_descriptor, int netmap_thread);
void consume_pkt(u_char* buffer, int len);

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

// Global configuration map 
extern std::map<std::string, std::string> configuration_map;

std::string interface_for_listening = "";

// This variable name should be uniq for every plugin!
process_packet_pointer netmap_process_func_ptr = NULL;

int receive_packets(struct netmap_ring *ring) {
    u_int cur, rx, n;

    cur = ring->cur;
    n = nm_ring_space(ring);
    
    for (rx = 0; rx < n; rx++) {
        struct netmap_slot *slot = &ring->slot[cur];
        char *p = NETMAP_BUF(ring, slot->buf_idx);

        // process data
        consume_pkt((u_char*)p, slot->len);

        cur = nm_ring_next(ring, cur);
    }

    ring->head = ring->cur = cur;
    return (rx);
}

void consume_pkt(u_char* buffer, int len) {
    struct pfring_pkthdr packet_header;
    memset(&packet_header, 0, sizeof(packet_header));
    packet_header.len = len;
    packet_header.caplen = len;
   
    fastnetmon_parse_pkt((u_char*)buffer, &packet_header, 4, 1, 0);
    
    //char print_buffer[512];
    //fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)buffer, &packet_header);
    //logger.info("%s", print_buffer);
   
    // We should fill this structure for passing to FastNetMon
    simple_packet packet;
 
    /* We handle only IPv4 */
    if (packet_header.extended_hdr.parsed_pkt.ip_version == 4) {
        /* PF_RING stores data in host byte order but we use network byte order */
        packet.src_ip = htonl( packet_header.extended_hdr.parsed_pkt.ip_src.v4 ); 
        packet.dst_ip = htonl( packet_header.extended_hdr.parsed_pkt.ip_dst.v4 );

        packet.source_port      = packet_header.extended_hdr.parsed_pkt.l4_src_port;
        packet.destination_port = packet_header.extended_hdr.parsed_pkt.l4_dst_port;

        packet.length   = packet_header.len;
        packet.protocol = packet_header.extended_hdr.parsed_pkt.l3_proto;
        packet.ts       = packet_header.ts;

        // Copy flags from PF_RING header to our pseudo header
        if (packet.protocol == IPPROTO_TCP) {
            packet.flags = packet_header.extended_hdr.parsed_pkt.tcp.flags;
        } else {
            packet.flags = 0;
        }

        netmap_process_func_ptr(packet); 
    }
}

void receiver(void) {
    struct  nm_desc *netmap_descriptor;

    u_int num_cpus = sysconf( _SC_NPROCESSORS_ONLN );
    logger.info("We have %d cpus", num_cpus);

    struct nmreq base_nmd;
    bzero(&base_nmd, sizeof(base_nmd));

    // Magic from pkt-gen.c
    base_nmd.nr_tx_rings = base_nmd.nr_rx_rings = 0;
    base_nmd.nr_tx_slots = base_nmd.nr_rx_slots = 0;

    std::string interface = "netmap:" + interface_for_listening; 
    netmap_descriptor = nm_open(interface.c_str(), &base_nmd, 0, NULL);

    if (netmap_descriptor == NULL) {
        logger.error("Can't open netmap device %s", interface.c_str());
        exit(1);
        return;
    }

    logger.info("Mapped %dKB memory at %p", netmap_descriptor->req.nr_memsize>>10, netmap_descriptor->mem);
    logger.info("We have %d tx and %d rx rings", netmap_descriptor->req.nr_tx_rings, netmap_descriptor->req.nr_rx_rings);

    if (num_cpus > netmap_descriptor->req.nr_rx_rings) {
        num_cpus = netmap_descriptor->req.nr_rx_rings;

        logger.info("We have number of CPUs bigger than number of NIC RX queues. Set number of CPU's to number of threads");
    }

    /*
        protocol stack and may cause a reset of the card,
        which in turn may take some time for the PHY to
        reconfigure. We do the open here to have time to reset.
    */

    int wait_link = 2;
    logger.info("Wait %d seconds for NIC reset", wait_link);
    sleep(wait_link);
  
    boost::thread* boost_threads_array[num_cpus]; 
    for (int i = 0; i < num_cpus; i++) {
        struct nm_desc nmd = *netmap_descriptor;
        // This operation is VERY important!
        nmd.self = &nmd;

        uint64_t nmd_flags = 0;

        if (nmd.req.nr_flags != NR_REG_ALL_NIC) {
            logger.error("Ooops, main descriptor should be with NR_REG_ALL_NIC flag");
        }

        nmd.req.nr_flags = NR_REG_ONE_NIC;
        nmd.req.nr_ringid = i;

        /* Only touch one of the rings (rx is already ok) */
        nmd_flags |= NETMAP_NO_TX_POLL;

        struct nm_desc* new_nmd = nm_open(interface.c_str(), NULL, nmd_flags | NM_OPEN_IFNAME | NM_OPEN_NO_MMAP, &nmd);

        if (new_nmd == NULL) {
            logger.error("Can't open netmap descriptor for netmap per nardware queue thread");
            exit(1);
        }

        logger.info("My first ring is %d and last ring id is %d I'm thread %d", new_nmd->first_rx_ring, new_nmd->last_rx_ring, i);

        logger.info("Start new netmap thread %d", i);
        // Start thread and pass netmap descriptor to it 
        boost_threads_array[i] = new boost::thread(netmap_thread, new_nmd, i);
    }

    //printf("Wait for thread finish");
    // Wait all threads for completion
    for (int i = 0; i < num_cpus; i++) {
        boost_threads_array[i]->join();
    }
} 

void netmap_thread(struct nm_desc* netmap_descriptor, int thread_number) {
    struct  nm_pkthdr h;
    u_char* buf;
    struct  pollfd fds;
    fds.fd     = netmap_descriptor->fd;//NETMAP_FD(netmap_descriptor);
    fds.events = POLLIN;

    struct netmap_ring *rxring = NULL;
    struct netmap_if *nifp = netmap_descriptor->nifp;

    //printf("Reading from fd %d thread id: %d", netmap_descriptor->fd, thread_number);

    for (;;) {
        // We will wait 1000 microseconds for retry, for infinite timeout please use -1
        int poll_result = poll(&fds, 1, 1000);
       
        if (poll_result == 0) {
            // printf("poll return 0 return code");
            continue;
        }

        if (poll_result == -1) {
            logger.error("Netmap plugin: poll failed with return code -1");
        }
 
        for (int i = netmap_descriptor->first_rx_ring; i <= netmap_descriptor->last_rx_ring; i++) {
            //printf("Check ring %d from thread %d", i, thread_number);
            rxring = NETMAP_RXRING(nifp, i); 

            if (nm_ring_empty(rxring)) {
                continue;
            }

            int m = receive_packets(rxring);
        }
    }

    //nm_close(netmap_descriptor);
}

void start_netmap_collection(process_packet_pointer func_ptr) {
    logger<< log4cpp::Priority::INFO<<"Netmap plugin started";
    netmap_process_func_ptr = func_ptr;

    std::string netmap_plugin_config_param = "";

    if (configuration_map.count("interfaces") != 0) {
        interface_for_listening = configuration_map[ "interfaces" ];
    }

    logger<< log4cpp::Priority::INFO<<"netmap will sniff interface: "<<interface_for_listening;

    boost::thread netmap_plugin_main_thread(receiver);
    netmap_plugin_main_thread.join();
}
