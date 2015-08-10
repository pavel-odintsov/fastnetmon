#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>

inline uint64_t read_tsc_cpu_register(void) {
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

uint64_t get_tsc_freq_with_sleep() {
    uint64_t start = read_tsc_cpu_register();
        
    sleep(1);

    return read_tsc_cpu_register() - start;
}

uint64_t get_tsc_freq_from_clock(void) {
//#ifdef CLOCK_MONOTONIC_RAW
#define NS_PER_SEC 1E9
    struct timespec sleeptime;

    sleeptime.tv_sec  = 1;
    sleeptime.tv_nsec = 5E8; /* 1/2 second */

    struct timespec t_start, t_end;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &t_start) == 0) {
        uint64_t ns, end, start;

        start = read_tsc_cpu_register();

        nanosleep(&sleeptime,NULL);
        clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);
        end = read_tsc_cpu_register();
        ns = ((t_end.tv_sec - t_start.tv_sec) * NS_PER_SEC);
        ns += (t_end.tv_nsec - t_start.tv_nsec);

        double secs = (double)ns/NS_PER_SEC;
        return (uint64_t)((end - start)/secs);
    }   
//#endif
}

int main() {
    /* The frequency of the RDTSC timer resolution */
    uint64_t fastnetmon_tsc_resolution_hz = 0;

    printf("Determine TSC freq with sleep\n");
    fastnetmon_tsc_resolution_hz = get_tsc_freq_with_sleep();
    printf("TSC freq is %llu\n", fastnetmon_tsc_resolution_hz);

    printf("Determing TSC freq with CLOCK_MONOTONIC_RAW\n");
    fastnetmon_tsc_resolution_hz = get_tsc_freq_from_clock();
    printf("TSC freq is %llu\n", fastnetmon_tsc_resolution_hz);

    printf("Current TSC value %llu\n", read_tsc_cpu_register());
}
