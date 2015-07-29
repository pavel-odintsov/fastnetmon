// compile with: gcc -shared -o capturecallback.so -fPIC capturecallback.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <algorithm>

#include "../../fastnetmon_packet_parser.h"

double system_tsc_resolution_hz = 0;

#ifdef __cplusplus
extern "C" {
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

// C++ rewrite of Python code: https://gist.github.com/pavel-odintsov/652904287ca0ca6816f6
class token_bucket_t {
    public:
        token_bucket_t() {
            this->tokens = 0;
            this->rate = 0;
            this->burst = 0;
            this->last_timestamp = 0;
        }

        int64_t get_rate() {
            return this->rate;
        }
   
        int64_t get_burst() {
            return this->burst;
        }
 
        int64_t get_tokens() {
            return this->tokens;
        }

        bool set_rate(int64_t rate, int64_t burst) {
            this->rate   = rate;

            this->tokens = burst;
            this->burst  = burst;

            // Start counter!
            this->last_timestamp = (double)rte_rdtsc() / system_tsc_resolution_hz;
        }

        int64_t consume(int64_t consumed_tokens) {
            double current_time = (double)rte_rdtsc() / system_tsc_resolution_hz;
            double interval = (current_time - this->last_timestamp);

            if (interval < 0) {
                printf("Your TSC is buggy, we have last %llu and current time: %llu\n", this->last_timestamp, current_time);
            }

            this->last_timestamp = current_time;

            this->tokens = std::max(
                (double)0, 
                std::min(
                    double(this->tokens + this->rate * interval), 
                    double(this->burst)
                ) 
            ) - 1;

            return this->tokens;
        }
    private:
        int64_t rate;
        int64_t tokens;
        int64_t burst;
        double last_timestamp;
};

token_bucket_t global_token_bucket_counter;

#ifdef __cplusplus
extern "C" {
#endif

/* Called once before processing packets. */
void firehose_start(); /* optional */

/* Called once after processing packets. */
void firehose_stop();  /* optional */

void firehose_stop() {

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
 
        printf("We process: %llu pps tokens %lld rate %lld burst %lld \n",
            (long long)pps,
            global_token_bucket_counter.get_tokens(),
            global_token_bucket_counter.get_rate(),
            global_token_bucket_counter.get_burst()
        );
    }   
}

void sigproc(int sig) {
    firehose_stop();

    printf("We caught SINGINT and will finish application\n");
    exit(0);
}


// We will start speed printer
void firehose_start() {
    signal(SIGINT,  sigproc); 

    set_tsc_freq_fallback();
    global_token_bucket_counter.set_rate(10000000, 15000000);

    //printf("tsq hz is: %f\n", system_tsc_resolution_hz);

    pthread_t thread;
    pthread_create(&thread, NULL, speed_printer, NULL);

    pthread_detach(thread);
}

void firehose_packet(const char *pciaddr, char *data, int length) {
    // Put packet to the cache

    /*
    struct pfring_pkthdr packet_header;
    memset(&packet_header, 0, sizeof(packet_header));
    packet_header.len = length;
    packet_header.caplen = length;

    fastnetmon_parse_pkt((u_char*)data, &packet_header, 3, 0, 0);
    */

    /* 
    char print_buffer[512];
    fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)data, &packet_header);
    printf("packet: %s\n", print_buffer);
    */

    int64_t consume_result = global_token_bucket_counter.consume(1);

    if (consume_result < 0) {
        printf("Overflow!\n");
    }

    __sync_fetch_and_add(&received_packets, 1);
    //printf("Got packet with %d bytes.\n", length);
}

#ifdef __cplusplus
}
#endif


