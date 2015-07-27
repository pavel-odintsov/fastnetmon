// Author: Pavel.Odintsov@gmail.com
// License GPLv2

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>

#include <iostream>
#include <memory>
#include <thread>

#include <boost/thread/thread.hpp>
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/atomic.hpp>

#include "../../fastnetmon_pcap_format.h"

/*

Compile it:
g++ -O3 -fPIC -std=c++11  ../../fastnetmon_pcap_format.cpp  -c -o fastnetmon_pcap_format.o
g++ -O3 -shared -o capturetodisk.so -fPIC capturetodisk.cpp  fastnetmon_pcap_format.o -std=c++11 -lboost_system

Run it:
/usr/src/snabbswitch/src/snabb firehose --input 0000:02:00.0 --input 0000:02:00.1 /usr/src/fastnetmon/src/tests/snabb/capturetodisk.so

*/

class packet_buffer_t {
    public:
        unsigned char buffer[1600];
        unsigned int length;
};

typedef std::shared_ptr<packet_buffer_t> packet_buffer_shared_pointer_t;
typedef boost::lockfree::spsc_queue< packet_buffer_shared_pointer_t,  boost::lockfree::capacity<1048576> > my_spsc_queue_t;

FILE* pcap_file = NULL;
my_spsc_queue_t my_spsc_queue;

#ifdef __cplusplus
extern "C" {
#endif

/* Called once before processing packets. */
void firehose_start(); /* optional */

#ifdef __cplusplus
}
#endif

/* Called once after processing packets. */
void firehose_stop();  /* optional */

void firehose_stop() {
    // Close file and flush data
    fclose(pcap_file);
}

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

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

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

	float gbps_speed = (float)bps/1024/1024/1024 * 8;
 
        printf("We process: %llu pps %.2f Gbps. We will store %.2f megabytes per second\n", (long long)pps, gbps_speed, gbps_speed / 8 * 1024);
    }   
}

void* packets_consumer(void* ptr) {
    printf("Start consumer thread\n");
    packet_buffer_shared_pointer_t packet;

    while (true) {
        while (my_spsc_queue.pop(packet)) {
            struct timeval current_time;

            current_time.tv_sec  = 0;
            current_time.tv_usec = 0;

            // It's performance killer!
            bool we_do_timestamps = false; 

            if (we_do_timestamps) {
                gettimeofday(&current_time, NULL);
            }

            struct fastnetmon_pcap_pkthdr pcap_packet_header;
            
            pcap_packet_header.ts_sec  = current_time.tv_sec;
            pcap_packet_header.ts_usec = current_time.tv_usec;

            pcap_packet_header.incl_len = packet->length;
            pcap_packet_header.orig_len = packet->length;

            unsigned int written_structs = fwrite(&pcap_packet_header, sizeof(pcap_packet_header), 1, pcap_file);

            if (written_structs != 1) { 
                printf("Can't write pcap pcaket header\n");
            }

            unsigned int written_bytes = fwrite(packet->buffer, sizeof(char), packet->length, pcap_file);

            if (written_bytes != packet->length) {
                printf("Can't write data to file\n");
            }

            __sync_fetch_and_add(&received_packets, 1);
            __sync_fetch_and_add(&received_bytes, packet->length);
        }
    }
}

void sigproc(int sig) {
    firehose_stop();

    printf("We caught SINGINT and will finish application\n");
    exit(0);
}

#ifdef __cplusplus
extern "C" {
#endif

// We will start speed printer
void firehose_start() {
    signal(SIGINT,  sigproc); 

    pcap_file = fopen("/tmp/traffic_capture.pcap", "wb");

    if (pcap_file == NULL) {
        printf("Can't open file for capture\n");
        exit(-1);
    }

    struct fastnetmon_pcap_file_header pcap_header;
    fill_pcap_header(&pcap_header, 1600);
 
    unsigned int written_structures = fwrite(&pcap_header, sizeof(pcap_header), 1, pcap_file);

    if (written_structures != 1) {
        printf("Can't write pcap header\n");
    }
 
    pthread_t thread;
    pthread_create(&thread, NULL, speed_printer, NULL);

    pthread_t consumer_thread;
    pthread_create(&consumer_thread, NULL, packets_consumer, NULL);

    pthread_detach(thread);
    pthread_detach(consumer_thread);
}

#ifdef __cplusplus
}
#endif

void firehose_packet(const char *pciaddr, char *data, int length) {
    std::shared_ptr<packet_buffer_t> packet_pointer( new packet_buffer_t );
    packet_pointer->length = length;

    if (length < 1600) {
        memcpy(packet_pointer->buffer, data, length);
    } else {
        printf("So big packet: %d\n", length);
    }

    // Put pointer to the tube!
    while (!my_spsc_queue.push(packet_pointer)); 
}

