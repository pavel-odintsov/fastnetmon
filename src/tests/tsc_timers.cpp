#include <iostream>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>

/* The frequency of the RDTSC timer resolution */
static uint64_t eal_tsc_resolution_hz = 0;

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

uint64_t rte_get_tsc_hz(void) {
    return eal_tsc_resolution_hz;
}

void set_tsc_freq_fallback() {
    uint64_t start = rte_rdtsc();
    sleep(1);
    eal_tsc_resolution_hz = rte_rdtsc() - start;
}

int set_tsc_freq_from_clock(void) {
#ifdef CLOCK_MONOTONIC_RAW
#define NS_PER_SEC 1E9
    struct timespec sleeptime;

    sleeptime.tv_sec  = 1;
    sleeptime.tv_nsec = 5E8; /* 1/2 second */

    struct timespec t_start, t_end;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &t_start) == 0) {
        uint64_t ns, end, start;

        start = rte_rdtsc();

        nanosleep(&sleeptime,NULL);
        clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);
        end = rte_rdtsc();
        ns = ((t_end.tv_sec - t_start.tv_sec) * NS_PER_SEC);
        ns += (t_end.tv_nsec - t_start.tv_nsec);

        double secs = (double)ns/NS_PER_SEC;
        eal_tsc_resolution_hz = (uint64_t)((end - start)/secs);
        return 0;
    }   
#endif
    return -1; 
}

int main() {
    printf("Determine TSC freq with sleep\n");
    set_tsc_freq_fallback();         
    printf("TSC freq is %llu\n", eal_tsc_resolution_hz);

    printf("Determing TSC freq with CLOCK_MONOTONIC_RAW\n");
    set_tsc_freq_from_clock();
    printf("TSC freq is %llu\n", eal_tsc_resolution_hz);

    printf("Current TSC value %llu\n", rte_rdtsc());
}
