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
 
        printf("We process: %llu pps\n", pps);
    }   
}

void run_speed_printer() {
    pthread_t thread;
    pthread_create(&thread, NULL, speed_printer, NULL);

    pthread_detach(thread);
}

void packet(char *data, int length) {
    // Put packet to the cache
    __builtin_prefetch(data);

    struct pfring_pkthdr packet_header;
    memset(&packet_header, 0, sizeof(packet_header));
    packet_header.len = length;
    packet_header.caplen = length;

    fastnetmon_parse_pkt((u_char*)data, &packet_header, 3, 0, 0);

    __sync_fetch_and_add(&received_packets, 1);
    //printf("Got packet with %d bytes.\n", length);
}
