// compile with: gcc -shared -o capturecallback.so -fPIC capturecallback.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <functional>
#include <algorithm>
#include <vector>
#include <unordered_map>
#include <string>

#include <boost/functional/hash.hpp>

#include <hiredis/hiredis.h>

#include "../../fastnetmon_pcap_format.h"
#include "../../fastnetmon_types.h"
#include "../../fastnetmon_packet_parser.h"

#include "../../fast_dpi.h"

unsigned int redis_port = 6379;
std::string redis_host = "127.0.0.1";

u_int32_t size_flow_struct = 0;
u_int32_t size_id_struct = 0;

double last_timestamp = 0;
double system_tsc_resolution_hz = 0;

redisContext* redis_context = NULL;

#ifdef __cplusplus
extern "C" {

redisContext* redis_init_connection();

void store_data_in_redis(std::string key_name, std::string value) {
    redisReply* reply = NULL;
    
    //redisContext* redis_context = redis_init_connection();

    if (!redis_context) {
        printf("Could not initiate connection to Redis\n");
        return;
    }

    reply = (redisReply*)redisCommand(redis_context, "SET %s %s", key_name.c_str(), value.c_str());

    // If we store data correctly ...
    if (!reply) {
        std::cout << "Can't increment traffic in redis error_code: " << redis_context->err
            << " error_string: " << redis_context->errstr;

        // Handle redis server restart corectly
        if (redis_context->err == 1 or redis_context->err == 3) {
            // Connection refused
            printf("Unfortunately we can't store data in Redis because server reject connection\n");
        }
    } else {
        freeReplyObject(reply);
    }

    //redisFree(redis_context);
}

redisContext* redis_init_connection() {
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    redisContext* redis_context = redisConnectWithTimeout(redis_host.c_str(), redis_port, timeout);
    if (redis_context->err) {
        std::cout << "Connection error:" << redis_context->errstr;
        return NULL;
    }

    // We should check connection with ping because redis do not check connection
    redisReply* reply = (redisReply*)redisCommand(redis_context, "PING");
    if (reply) {
        freeReplyObject(reply);
    } else {
        return NULL;
    }

    return redis_context;
}
#endif

inline uint64_t rte_rdtsc(void) {
    union {
        uint64_t tsc_64;
            struct {
                uint32_t lo_32;
                uint32_t hi_32;
            };  
    } tsc;

    asm volatile("rdtsc" :
        "=a" (tsc.lo_32),
        "=d" (tsc.hi_32));
    return tsc.tsc_64;
}

void set_tsc_freq_fallback() {
    uint64_t start = rte_rdtsc();
    sleep(1);
    system_tsc_resolution_hz = (double)rte_rdtsc() - start;
}

#ifdef __cplusplus
}
#endif

class conntrack_hash_struct_for_simple_packet_t {
    public:
        uint32_t upper_ip;
        uint32_t lower_ip;
    
        uint16_t upper_port;
        uint16_t lower_port;

        unsigned int protocol;

        bool operator==(const conntrack_hash_struct_for_simple_packet_t& rhs) const {
            return memcmp(this, &rhs, sizeof(conntrack_hash_struct_for_simple_packet_t)) == 0;  
        }   
};

namespace std {
    template<>
    struct hash<conntrack_hash_struct_for_simple_packet_t> {
        size_t operator()(const conntrack_hash_struct_for_simple_packet_t& x) const {
            std::size_t seed = 0;
            boost::hash_combine(seed, x.upper_ip);
            boost::hash_combine(seed, x.lower_ip);
            boost::hash_combine(seed, x.upper_port);
            boost::hash_combine(seed, x.lower_port);
            boost::hash_combine(seed, x.protocol);
  
            return seed; 
        }
    };
}

class ndpi_tracking_flow_t {
    public:
        ndpi_tracking_flow_t() {
            src = (struct ndpi_id_struct*)malloc(size_id_struct);
            memset(src, 0, size_id_struct);

            dst = (struct ndpi_id_struct*)malloc(size_id_struct);
            memset(dst, 0, size_id_struct);

            flow = (struct ndpi_flow_struct *)malloc(size_flow_struct);
            memset(flow, 0, size_flow_struct);
        
            update_timestamp();    
        }

        void update_timestamp() {
            this->last_timestamp = (double)rte_rdtsc() / system_tsc_resolution_hz;
        }

        ~ndpi_tracking_flow_t() {
            // We need use custom function because standard free could not free all memory here
            ndpi_free_flow(flow);

            free(dst);
            free(src);

            flow = NULL;
            dst = NULL;
            src = NULL;
        }

        ndpi_protocol detected_protocol;
        struct ndpi_id_struct *src = NULL;
        struct ndpi_id_struct *dst = NULL;
    	struct ndpi_flow_struct *flow = NULL;     
        bool protocol_detected = false;
        double last_timestamp;
};

typedef std::unordered_map<conntrack_hash_struct_for_simple_packet_t, ndpi_tracking_flow_t> my_connection_tracking_storage_t;
my_connection_tracking_storage_t my_connection_tracking_storage;

typedef std::unordered_map<std::string, unsigned int> known_http_hosts_t;
known_http_hosts_t known_http_hosts;

// For correct compilation with g++
#ifdef __cplusplus
    extern "C" {
#endif

void pcap_parse_packet(char* buffer, uint32_t len);

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
uint64_t received_bytes = 0;

void* speed_printer(void* ptr) {
    while (1) {
        uint64_t packets_before = received_packets;
        uint64_t bytes_before = received_bytes;   
 
        sleep(1);
    
        uint64_t packets_after = received_packets;
        uint64_t bytes_after = received_bytes;

        uint64_t pps = packets_after - packets_before;
        uint64_t bps = bytes_after - bytes_before; 

        printf("We process: %llu pps %.2f Gbps\n", (long long)pps, (float)bps/1024/1024/1024 * 8);
        // std::cout << "Hash size: " << my_connection_tracking_storage.size() << std::endl;
        std::cout << "Uniq hosts: " << known_http_hosts.size() << std::endl;
    }   
}

// We will start speed printer
void firehose_start() {
    my_ndpi_struct = init_ndpi();

    // Connect to the Redis
    redis_context = redis_init_connection();

    if (!redis_context) {
        printf("Can't connect to the Redis\n");
    }

    // Tune timer
    set_tsc_freq_fallback();

    // Set call time
    last_timestamp = (double)rte_rdtsc() / system_tsc_resolution_hz;

    size_id_struct   = ndpi_detection_get_sizeof_ndpi_id_struct();
    size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

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
    conntrack_struct.protocol = packet.protocol;

    // Build hash for lookup this connection
    uint32_t ip_src = packet.src_ip; 
    uint32_t ip_dst = packet.dst_ip;

    uint16_t src_port = packet.source_port;
    uint16_t dst_port = packet.destination_port;

    // Build universal lookup structure which describes single connection
    if (ip_src < ip_dst) {
        conntrack_struct.lower_ip = ip_src;
        conntrack_struct.upper_ip = ip_dst;

        conntrack_struct.lower_port = src_port;
        conntrack_struct.upper_port = dst_port;
    } else {
        conntrack_struct.lower_ip = ip_dst;
        conntrack_struct.upper_ip = ip_src;

        conntrack_struct.lower_port = dst_port;
        conntrack_struct.upper_port = src_port;
    }

    return true;
}

unsigned int gc_call_timeout = 20;
unsigned int gc_clean_how_old_records = 20; 

void firehose_packet(const char *pciaddr, char *data, int length) {
    // Garbadge collection code
    double current_timestamp = (double)rte_rdtsc() / system_tsc_resolution_hz;

    if (current_timestamp - last_timestamp > gc_call_timeout) {
        std::vector<conntrack_hash_struct_for_simple_packet_t> keys_to_remove; 
    
        for (auto& itr : my_connection_tracking_storage) {
            // Remove all records who older than X seconds
            if (current_timestamp - itr.second.last_timestamp > gc_clean_how_old_records) {
                keys_to_remove.push_back(itr.first);
            }   
        }   

        //if (!keys_to_remove.empty()) {
        //    std::cout << "We will remove " << keys_to_remove.size() << " keys" << std::endl; 
        //}  

        for (auto key_to_remove : keys_to_remove)  {
            my_connection_tracking_storage.erase(key_to_remove);
        }

        last_timestamp = current_timestamp;
    }  
    // GC code ends
    
    __sync_fetch_and_add(&received_packets, 1);
    __sync_fetch_and_add(&received_bytes, length);
 
    struct pfring_pkthdr packet_header;

    memset(&packet_header, 0, sizeof(packet_header));
    packet_header.len = length;
    packet_header.caplen = length;

    // We do not calculate timestamps because timestamping is very CPU intensive operation:
    // https://github.com/ntop/PF_RING/issues/9
    u_int8_t timestamp = 0;
    u_int8_t add_hash = 0;
    fastnetmon_parse_pkt((u_char*)data, &packet_header, 4, timestamp, add_hash);

    simple_packet current_packet;
    parse_raw_packet_to_simple_packet((u_char*)data, length, current_packet); 
    
    conntrack_hash_struct_for_simple_packet_t conntrack_structure;
    convert_simple_packet_toconntrack_hash_struct(current_packet, conntrack_structure);



    ndpi_tracking_flow_t& dpi_tracking_structure = my_connection_tracking_storage[ conntrack_structure ];

    // Protocol already detected
    /*
    if (dpi_tracking_structure.protocol_detected && dpi_tracking_structure.detected_protocol.protocol == NDPI_PROTOCOL_IRC) {
        char print_buffer[512];
        fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)data, &packet_header);
        printf("packet: %s\n", print_buffer);

        for (unsigned int index = packet_header.extended_hdr.parsed_pkt.offset.payload_offset; index < packet_header.len; index++) {
            printf("%c", data[index]); 
        }   
    
        printf("\n");

        return;
    }
    */

    dpi_tracking_structure.update_timestamp();

    uint32_t current_tickt = 0 ;
    uint8_t* iph = (uint8_t*)(&data[packet_header.extended_hdr.parsed_pkt.offset.l3_offset]);

    // printf("vlan: %d\n", packet_header.extended_hdr.parsed_pkt.vlan_id);

    struct ndpi_iphdr* ndpi_ip_header = (struct ndpi_iphdr*)iph;

    unsigned int ipsize = packet_header.len; 
 
    ndpi_protocol detected_protocol = ndpi_detection_process_packet(my_ndpi_struct, dpi_tracking_structure.flow, iph, ipsize, current_tickt, dpi_tracking_structure.src, dpi_tracking_structure.dst);

    if (detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN && detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN) {
        // printf("Can't detect protocol\n");
    } else {
        dpi_tracking_structure.detected_protocol = detected_protocol;
        dpi_tracking_structure.protocol_detected = true;

        //printf("Master protocol: %d protocol: %d\n", detected_protocol.master_protocol, detected_protocol.protocol);
        char* protocol_name = ndpi_get_proto_name(my_ndpi_struct, detected_protocol.protocol);
        char* master_protocol_name = ndpi_get_proto_name(my_ndpi_struct, detected_protocol.master_protocol);        

        if (detected_protocol.protocol == NDPI_PROTOCOL_HTTP) {
            std::string host_name = std::string((const char*)dpi_tracking_structure.flow->host_server_name);

            //printf("server name: %s\n", dpi_tracking_structure.flow->host_server_name); 
           
            if (redis_context != NULL) { 
                known_http_hosts_t::iterator itr = known_http_hosts.find(host_name);

                if (itr == known_http_hosts.end()) {
                    // Not defined in internal cache
                    // Add in local cache:
                    known_http_hosts[ host_name ] = 1;
                
                    // Add to Redis
                    store_data_in_redis(host_name, "1");
                } else {
                    // Already stored
                }

            }
        }

        //printf("Protocol: %s master protocol: %s\n", protocol_name, master_protocol_name);

        bool its_bad_protocol = false;
        //if(ndpi_is_proto(detected_protocol, NDPI_PROTOCOL_TOR)) { 
        //    its_bad_protocol = true;
        //}
   
        if (detected_protocol.protocol == NDPI_PROTOCOL_IRC or detected_protocol.master_protocol == NDPI_PROTOCOL_IRC) { 
            its_bad_protocol = true;
        }

        if (its_bad_protocol) {
            printf("Bad protocol %s master protocol %s found\n", protocol_name, master_protocol_name);
            char print_buffer[512];
            fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)data, &packet_header);
            printf("packet: %s\n", print_buffer);

            for (unsigned int index = packet_header.extended_hdr.parsed_pkt.offset.payload_offset; index < packet_header.len; index++) {
                printf("%c", data[index]); 
            }
            
            printf("\n");
        }
    }
}

#ifdef __cplusplus
    }   
#endif

int main(int argc, char** argv) {
    my_ndpi_struct = init_ndpi();

    size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
    size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

    if (argc != 2) {
        printf("Please specify path to dump file\n");
        exit(-1);
    }

    const char* path = argv[1];

    //pcap_reader(path, pcap_parse_packet);
}

