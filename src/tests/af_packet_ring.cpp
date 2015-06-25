#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <unistd.h>

#include <boost/thread.hpp>
#include <sys/mman.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */

#include "../fastnetmon_packet_parser.h"

// 4194304 bytes
unsigned int blocksiz = 1 << 22; 
// 2048 bytes
unsigned int framesiz = 1 << 11; 
unsigned int blocknum = 64; 

struct block_desc {
    uint32_t version;
    uint32_t offset_to_priv;
    struct tpacket_hdr_v1 h1;
};

/*

Build it:
g++ ../fastnetmon_packet_parser.c -ofastnetmon_packet_parser.o -c
g++ af_packet.cpp fastnetmon_packet_parser.o -lboost_thread -lboost_system -lpthread 

*/

// Get interface number by name
int get_interface_number_by_device_name(int socket_fd, std::string interface_name) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    if (interface_name.size() > IFNAMSIZ) {
        return -1;
    }

    strncpy(ifr.ifr_name, interface_name.c_str(), sizeof(ifr.ifr_name));
    
    if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) == -1) {
        return -1;
    }

    return ifr.ifr_ifindex;
}

unsigned int af_packet_threads = 1;

uint64_t received_packets = 0;
uint64_t received_bytes = 0;

void speed_printer() {
    while (true) {
        uint64_t packets_before = received_packets;
        
        boost::this_thread::sleep(boost::posix_time::seconds(1));       
        
        uint64_t packets_after = received_packets;
        uint64_t pps = packets_after - packets_before;

        printf("We process: %llu pps\n", pps);
    }
}

void flush_block(struct block_desc *pbd) {
    pbd->h1.block_status = TP_STATUS_KERNEL;
}

void walk_block(struct block_desc *pbd, const int block_num) {
    int num_pkts = pbd->h1.num_pkts, i;
    unsigned long bytes = 0;
    struct tpacket3_hdr *ppd;

    ppd = (struct tpacket3_hdr *) ((uint8_t *) pbd +
                       pbd->h1.offset_to_first_pkt);
    for (i = 0; i < num_pkts; ++i) {
        bytes += ppd->tp_snaplen;

        // struct ethhdr *eth = (struct ethhdr *) ((uint8_t *) ppd + ppd->tp_mac);
        // Print packets

// #define PRINT_PACKETS
#ifdef PRINT_PACKETS
        struct pfring_pkthdr packet_header;
        memset(&packet_header, 0, sizeof(packet_header));
        packet_header.len = ppd->tp_snaplen;
        packet_header.caplen = ppd->tp_snaplen;

        u_int8_t timestamp = 0;
        u_int8_t add_hash = 0;

        u_char* data_pointer = (u_char*)((uint8_t *) ppd + ppd->tp_mac);

        fastnetmon_parse_pkt(data_pointer, &packet_header, 4, timestamp, add_hash);

        char print_buffer[512];
        fastnetmon_print_parsed_pkt(print_buffer, 512, data_pointer, &packet_header);
        printf("%s\n", print_buffer);
#endif
 
        ppd = (struct tpacket3_hdr *) ((uint8_t *) ppd +
                           ppd->tp_next_offset);
    }

    received_packets += num_pkts;
    received_bytes += bytes;
}

int setup_socket(std::string interface_name, int fanout_group_id) {
    // More details here: http://man7.org/linux/man-pages/man7/packet.7.html
    // We could use SOCK_RAW or SOCK_DGRAM for second argument
    // SOCK_RAW - raw packets pass from the kernel
    // SOCK_DGRAM - some amount of processing 
    // Third argument manage ether type of captured packets
    int packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
   
    if (packet_socket == -1) {
        printf("Can't create AF_PACKET socket\n");
        return -1;
    }

    // We whould use V3 bcause it could read/pool in per block basis instead per packet
    int version = TPACKET_V3;
    int setsockopt_packet_version = setsockopt(packet_socket, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));

    if (setsockopt_packet_version < 0) {
        printf("Can't set packet v3 version\n");
        return -1;
    }

    int interface_number = get_interface_number_by_device_name(packet_socket, interface_name);

    if (interface_number == -1) {
        printf("Can't get interface number by interface name\n");
        return -1;
    }
 
    // Switch to PROMISC mode
    struct packet_mreq sock_params;
    memset(&sock_params, 0, sizeof(sock_params));
    sock_params.mr_type = PACKET_MR_PROMISC;
    sock_params.mr_ifindex = interface_number;
    
    int set_promisc = setsockopt(packet_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *)&sock_params, sizeof(sock_params));

    if (set_promisc == -1) {
        printf("Can't enable promisc mode\n");
        return -1;
    }

    struct sockaddr_ll bind_address;
    memset(&bind_address, 0, sizeof(bind_address));

    bind_address.sll_family = AF_PACKET;
    bind_address.sll_protocol = htons(ETH_P_ALL);
    bind_address.sll_ifindex = interface_number;

    // We will follow http://yusufonlinux.blogspot.ru/2010/11/data-link-access-and-zero-copy.html
    // And this: https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt

    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));

    req.tp_block_size = blocksiz;
    req.tp_frame_size = framesiz;
    req.tp_block_nr = blocknum;
    req.tp_frame_nr = (blocksiz * blocknum) / framesiz;

    req.tp_retire_blk_tov = 60; // Timeout in msec
    req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    int setsockopt_rx_ring = setsockopt(packet_socket, SOL_PACKET , PACKET_RX_RING , (void*)&req , sizeof(req));
    
    if (setsockopt_rx_ring == -1) {
        printf("Can't enable RX_RING for AF_PACKET socket\n");
        return -1;
    }

    // We use per thread structures
    uint8_t* mapped_buffer = NULL;
    struct iovec* rd = NULL;

    mapped_buffer = (uint8_t*)mmap(NULL, req.tp_block_size * req.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, packet_socket, 0);

    if (mapped_buffer == MAP_FAILED) {
        printf("mmap failed!\n");
        return -1;
    }

    // Allocate iov structure for each block
    rd = (struct iovec*)malloc(req.tp_block_nr * sizeof(struct iovec));

    // Initilize iov structures
    for (int i = 0; i < req.tp_block_nr; ++i) {
        rd[i].iov_base = mapped_buffer + (i * req.tp_block_size);
        rd[i].iov_len = req.tp_block_size;
    }

    int bind_result = bind(packet_socket, (struct sockaddr *)&bind_address, sizeof(bind_address));

    if (bind_result == -1) {
        printf("Can't bind to AF_PACKET socket\n");
        return -1;
    }
 
   if (fanout_group_id) {
        // PACKET_FANOUT_LB - round robin
        // PACKET_FANOUT_CPU - send packets to CPU where packet arrived
        int fanout_type = PACKET_FANOUT_CPU; 

        int fanout_arg = (fanout_group_id | (fanout_type << 16));

        int setsockopt_fanout = setsockopt(packet_socket, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg));

        if (setsockopt_fanout < 0) {
            printf("Can't configure fanout\n");
            return -1;
        }
    }

    unsigned int current_block_num = 0;

    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));

    pfd.fd = packet_socket;
    pfd.events = POLLIN | POLLERR;
    pfd.revents = 0;
   
    while (true) {
        struct block_desc *pbd = (struct block_desc *) rd[current_block_num].iov_base;
 
        if ((pbd->h1.block_status & TP_STATUS_USER) == 0) {
            poll(&pfd, 1, -1);

            continue;
        }   

        walk_block(pbd, current_block_num);
        flush_block(pbd);
        current_block_num = (current_block_num + 1) % blocknum;
    }   

    return packet_socket;
}

void start_af_packet_capture(std::string interface_name, int fanout_group_id) {
    setup_socket(interface_name, fanout_group_id); 
}

void get_af_packet_stats() {
// getsockopt PACKET_STATISTICS
}

// Could get some speed up on NUMA servers
bool execute_strict_cpu_affinity = false;

bool use_multiple_fanout_processes = true;

int main() {
    int fanout_group_id = getpid() & 0xffff;

    boost::thread speed_printer_thread( speed_printer );

    if (use_multiple_fanout_processes) {
        boost::thread_group packet_receiver_thread_group;

        unsigned int num_cpus = 8;
        for (int cpu = 0; cpu < num_cpus; cpu++) {
            boost::thread::attributes thread_attrs;

            if (execute_strict_cpu_affinity) {
                cpu_set_t current_cpu_set;

                int cpu_to_bind = cpu % num_cpus;
                CPU_ZERO(&current_cpu_set);
                // We count cpus from zero
                CPU_SET(cpu_to_bind, &current_cpu_set);

                int set_affinity_result = pthread_attr_setaffinity_np(thread_attrs.native_handle(), sizeof(cpu_set_t), &current_cpu_set);
    
                if (set_affinity_result != 0) {
                    printf("Can't set CPU affinity for thread\n");
                } 
            }

            packet_receiver_thread_group.add_thread(
                new boost::thread(thread_attrs, boost::bind(start_af_packet_capture, "eth6", fanout_group_id))
            );
        }

        // Wait all processes for finish
        packet_receiver_thread_group.join_all();
    } else {    
        start_af_packet_capture("eth6", 0);
    }

    speed_printer_thread.join();
}
