// compile with: gcc -shared -o capturecallback.so -fPIC capturecallback.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

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

void firehose_packet(const char *pciaddr, char *data, int length) {
    // Put packet to the cache
    struct pfring_pkthdr packet_header;
    memset(&packet_header, 0, sizeof(packet_header));
    packet_header.len = length;
    packet_header.caplen = length;

    fastnetmon_parse_pkt((u_char*)data, &packet_header, 3, 0, 0);

    struct ndpi_id_struct *src, *dst;
    struct ndpi_flow_struct *flow;

    uint32_t current_tickt = 0 ;
   
    uint8_t* iph = (uint8_t*)(&data[packet_header.extended_hdr.parsed_pkt.offset.l3_offset]);
    unsigned int ipsize = packet_header.len; 
 
    ndpi_protocol detected_protocol = ndpi_detection_process_packet(my_ndpi_struct, flow, iph, ipsize, current_tickt, src, dst);

    if (detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN) {
        printf("Can't detect protocol");
    } 

    printf("protocol: %s\n", ndpi_get_proto_name(my_ndpi_struct, detected_protocol.protocol));

    /* 
    char print_buffer[512];
    fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)data, &packet_header);
    printf("packet: %s\n", print_buffer);
    */

    __sync_fetch_and_add(&received_packets, 1);
    //printf("Got packet with %d bytes.\n", length);
}

}
