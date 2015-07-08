// compile with: gcc -shared -o capturecallback.so -fPIC capturecallback.c
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include "../../fastnetmon_packet_parser.h"

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

void run_speed_printer() {
    pthread_t thread;
    pthread_create(&thread, NULL, speed_printer, NULL);

    pthread_detach(thread);
}

void process_packet(char *data, int length) {
    // Put packet to the cache
    struct pfring_pkthdr packet_header;
    memset(&packet_header, 0, sizeof(packet_header));
    packet_header.len = length;
    packet_header.caplen = length;

    fastnetmon_parse_pkt((u_char*)data, &packet_header, 3, 0, 0);

    /* 
    char print_buffer[512];
    fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)data, &packet_header);
    printf("packet: %s\n", print_buffer);
    */

    __sync_fetch_and_add(&received_packets, 1);
    //printf("Got packet with %d bytes.\n", length);
}

//
// DMA processing callback for Lua
//

// Legacy receive descriptor format.
// See 82599 data sheet section 7.1.5.
struct rdesc {
  uint64_t address;
  uint16_t length;
  uint16_t cksum;
  uint8_t status;
  uint8_t errors;
  uint16_t vlan;
} __attribute__((packed));

// Traverse the hardware receive descriptor ring.
// Process each packet that is ready.
// Return the updated ring indx.
int process_packets(char **packets,       // array of packet data buffers
                    struct rdesc *rxring, // hardware RX descriptor ring
                    int ring_size,        // size of ring
                    int index,
                    int max) {          // current index into ring
  while (max-- > 0 && (rxring[index].status & 1)) { // packet ready?
    process_packet(packets[index], rxring[index].length); // process packet
    rxring[index].status = 0;                     // reset descriptor
    index = (index + 1) & (ring_size-1);          // move on to next ring item
  }
  return index;
}

