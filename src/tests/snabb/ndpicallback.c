// compile with: gcc -shared -o capturecallback.so -fPIC capturecallback.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <vector>
#include <unordered_map>
#include <string>

#include "../../fastnetmon_types.h"
#include "../../fastnetmon_packet_parser.h"

#include "libndpi/ndpi_api.h"

// For correct compilation with g++
extern "C" {

void debug_printf(u_int32_t protocol, void *id_struct, ndpi_log_level_t log_level, const char *format, ...) {
    va_list va_ap;
    struct tm result;

    char buf[8192], out_buf[8192];
    char theDate[32];
    const char *extra_msg = "";
    time_t theTime = time(NULL);

    va_start (va_ap, format);

    /*
    if(log_level == NDPI_LOG_ERROR)
      extra_msg = "ERROR: ";
    else if(log_level == NDPI_LOG_TRACE)
      extra_msg = "TRACE: ";
    else 
      extra_msg = "DEBUG: ";
    */

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime_r(&theTime, &result) );
    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    snprintf(out_buf, sizeof(out_buf), "%s %s%s", theDate, extra_msg, buf);
    printf("%s", out_buf);
    fflush(stdout);

    va_end(va_ap);
}


struct ndpi_detection_module_struct* my_ndpi_struct = NULL;

bool init_ndpi() {
    u_int32_t detection_tick_resolution = 1000;
    
    my_ndpi_struct = ndpi_init_detection_module(detection_tick_resolution, malloc, free, debug_printf);

    if (my_ndpi_struct == NULL) {
        printf("Can't init nDPI");
        return false;     
    }

    NDPI_PROTOCOL_BITMASK all;
    // enable all protocols
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(my_ndpi_struct, &all);

    // allocate memory for id and flow tracking
    uint32_t size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
    uint32_t size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

    // Load custom protocols
    // ndpi_load_protocols_file(ndpi_thread_info[thread_id].ndpi_struct, _protoFilePath);

    printf("nDPI started correctly\n");
}

/* Called once before processing packets. */
void firehose_start(); /* optional */

/* Called once after processing packets. */
void firehose_stop();  /* optional */

/*
 * Process a packet received from a NIC.
 *
 * pciaddr: name of PCI device packet is received from
 * data:    packet payload (ethernet frame)
 * length:  payload length in bytes
 */
inline void firehose_packet(const char *pciaddr, char *data, int length);

/* Intel 82599 "Legacy" receive descriptor format.
 * See Intel 82599 data sheet section 7.1.5.
 * http://www.intel.com/content/dam/www/public/us/en/documents/datasheets/82599-10-gbe-controller-datasheet.pdf
 */
struct firehose_rdesc {
  uint64_t address;
  uint16_t length;
  uint16_t cksum;
  uint8_t status;
  uint8_t errors;
  uint16_t vlan;
} __attribute__((packed));

/* Traverse the hardware receive descriptor ring.
 * Process each packet that is ready.
 * Return the updated ring index.
 */
int firehose_callback_v1(const char *pciaddr,
                         char **packets,
                         struct firehose_rdesc *rxring,
                         int ring_size,
                         int index) {
  while (rxring[index].status & 1) {
    int next_index = (index + 1) & (ring_size-1);
    __builtin_prefetch(packets[next_index]);
    firehose_packet(pciaddr, packets[index], rxring[index].length);
    rxring[index].status = 0; /* reset descriptor for reuse */
    index = next_index;
  }
  return index;
}


uint64_t received_packets = 0;

void* speed_printer(void* ptr) {
    while (1) {
        uint64_t packets_before = received_packets;
    
        sleep(1);
    
        uint64_t packets_after = received_packets;
        uint64_t pps = packets_after - packets_before;
 
        printf("We process: %llu pps\n", (long long)pps);
    }   
}

// We will start speed printer
void firehose_start() {
    init_ndpi();

    pthread_t thread;
    pthread_create(&thread, NULL, speed_printer, NULL);

    pthread_detach(thread);
}

// https://code.google.com/p/smhasher/source/browse/trunk/MurmurHash2.cpp
// 64-bit hash for 64-bit platforms
#define BIG_CONSTANT(x) (x##LLU)
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

class conntrack_hash_struct_for_simple_packet_t {
    public:
        uint32_t src_ip;
        uint32_t dst_ip;
        
        uint16_t source_port;
        uint16_t destination_port;

        unsigned int protocol;
        bool operator==(const conntrack_hash_struct_for_simple_packet_t& rhs) {
            return memcmp(this, &rhs, sizeof(conntrack_hash_struct_for_simple_packet_t)) == 0; 
        }
};


// Copy and paste from netmap module 
inline bool parse_raw_packet_to_simple_packet(u_char* buffer, int len, simple_packet& packet) {
    struct pfring_pkthdr packet_header;

    memset(&packet_header, 0, sizeof(packet_header));
    packet_header.len = len;
    packet_header.caplen = len;

    // We do not calculate timestamps because timestamping is very CPU intensive operation:
    // https://github.com/ntop/PF_RING/issues/9
    u_int8_t timestamp = 0;
    u_int8_t add_hash = 0;
    fastnetmon_parse_pkt((u_char*)buffer, &packet_header, 4, timestamp, add_hash);

    // char print_buffer[512];
    // fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)buffer, &packet_header);
    // logger.info("%s", print_buffer);

    if (packet_header.extended_hdr.parsed_pkt.ip_version != 4 && packet_header.extended_hdr.parsed_pkt.ip_version != 6) {
        return false;
    }

    // We need this for deep packet inspection
    packet.packet_payload_length = len;
    packet.packet_payload_pointer = (void*)buffer;

    packet.ip_protocol_version = packet_header.extended_hdr.parsed_pkt.ip_version;

    if (packet.ip_protocol_version == 4) {
        // IPv4

        /* PF_RING stores data in host byte order but we use network byte order */
        packet.src_ip = htonl(packet_header.extended_hdr.parsed_pkt.ip_src.v4);
        packet.dst_ip = htonl(packet_header.extended_hdr.parsed_pkt.ip_dst.v4);
    } else {
        // IPv6
        memcpy(packet.src_ipv6.s6_addr, packet_header.extended_hdr.parsed_pkt.ip_src.v6.s6_addr, 16);
        memcpy(packet.dst_ipv6.s6_addr, packet_header.extended_hdr.parsed_pkt.ip_dst.v6.s6_addr, 16);
    }

    packet.source_port = packet_header.extended_hdr.parsed_pkt.l4_src_port;
    packet.destination_port = packet_header.extended_hdr.parsed_pkt.l4_dst_port;

    packet.length = packet_header.len;
    packet.protocol = packet_header.extended_hdr.parsed_pkt.l3_proto;
    packet.ts = packet_header.ts;

    packet.ip_fragmented = packet_header.extended_hdr.parsed_pkt.ip_fragmented;
    packet.ttl = packet_header.extended_hdr.parsed_pkt.ip_ttl;

    // Copy flags from PF_RING header to our pseudo header
    if (packet.protocol == IPPROTO_TCP) {
        packet.flags = packet_header.extended_hdr.parsed_pkt.tcp.flags;
    } else {
        packet.flags = 0;
    }

    return true;
} 

bool convert_simple_packet_toconntrack_hash_struct(simple_packet& packet, conntrack_hash_struct_for_simple_packet_t& conntrack_struct) {
    conntrack_struct.src_ip = packet.src_ip;
    conntrack_struct.dst_ip = packet.dst_ip;

    conntrack_struct.protocol = packet.protocol;

    conntrack_struct.source_port = packet.source_port;
    conntrack_struct.destination_port = packet.destination_port; 
}

typedef std::unordered_map<uint64_t, unsigned int> my_connection_tracking_storage_t;
my_connection_tracking_storage_t my_connection_tracking_storage;

void firehose_packet(const char *pciaddr, char *data, int length) {
    // Put packet to the cache
    simple_packet current_packet;

    parse_raw_packet_to_simple_packet((u_char*)data, length, current_packet); 
    
    conntrack_hash_struct_for_simple_packet_t conntrack_structure;
    convert_simple_packet_toconntrack_hash_struct(current_packet, conntrack_structure);

    unsigned int seed = 13;
    uint64_t conntrack_hash = MurmurHash64A(&conntrack_structure, sizeof(conntrack_structure), seed);
    
    // printf("Hash: %llu", conntrack_hash);
   
    my_connection_tracking_storage_t::iterator itr = my_connection_tracking_storage.find(conntrack_hash);

    if (itr == my_connection_tracking_storage.end()) {
        my_connection_tracking_storage[ conntrack_hash ] = 123;
        //printf("Initiate new connection\n");
    } else {
        //printf("Found this connection\n");
    }

    /*
    struct ndpi_id_struct *src, *dst;
    struct ndpi_flow_struct *flow;

    uint32_t current_tickt = 0 ;
   
    uint8_t* iph = (uint8_t*)(&data[packet_header.extended_hdr.parsed_pkt.offset.l3_offset]);
    unsigned int ipsize = packet_header.len; 
 
    ndpi_protocol detected_protocol = ndpi_detection_process_packet(my_ndpi_struct, flow, iph, ipsize, current_tickt, src, dst);

    if (detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN) {
        printf("Can't detect protocol");
        return;
    } 

    // printf("protocol: %s\n", ndpi_get_proto_name(my_ndpi_struct, flow->detected_protocol));
    */

    /* 
    char print_buffer[512];
    fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)data, &packet_header);
    printf("packet: %s\n", print_buffer);
    */

    __sync_fetch_and_add(&received_packets, 1);
    //printf("Got packet with %d bytes.\n", length);
}

}
