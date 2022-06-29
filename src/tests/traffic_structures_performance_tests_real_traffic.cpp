#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <math.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "fast_library.hpp"

#include "../fastnetmon_types.hpp"

#include <map>
#include <unordered_map>
#include <boost/unordered_map.hpp>

#ifdef __MACH__
// On MacOS X we haven't clock_gettime(CLOCK_REALTIME, &ts) and should use another code
// http://stackoverflow.com/questions/5167269/clock-gettime-alternative-in-mac-os-x

#include <mach/clock.h>
#include <mach/mach.h>

#define CLOCK_REALTIME 1111
clock_serv_t cclock;

// Create custom wrapper for Mac OS X
int clock_gettime(int clodk_type_do_not_used_really, struct timespec* ts) {
    mach_timespec_t mts;

    clock_get_time(cclock, &mts);

    ts->tv_sec  = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;

    return 0;
}
#endif

log4cpp::Category& logger = log4cpp::Category::getRoot();

// Runs tests for specific structure
template <typename T>
void run_tests(std::vector<uint32_t> our_ips, T& data_structure) {
    struct timespec start_time;
    clock_gettime(CLOCK_REALTIME, &start_time);

    unsigned long total_ops = 0;

    uint64_t number_of_reruns = 1000;

    total_ops = number_of_reruns * our_ips.size();

    for (int j = 0; j < number_of_reruns; j++) {
        for (const auto& ip: our_ips) {
            data_structure[ip].udp.in_bytes++;
        }
    }

    struct timespec finish_time;
    clock_gettime(CLOCK_REALTIME, &finish_time);

    unsigned long used_seconds     = finish_time.tv_sec - start_time.tv_sec;
    unsigned long used_nanoseconds = finish_time.tv_nsec - start_time.tv_nsec;

    unsigned long total_used_nanoseconds = used_seconds * 1000000000 + used_nanoseconds;

    float megaops_per_second = (float)total_ops / ((float)total_used_nanoseconds / (float)1000000000) / 1000000;

    std::cout << "Total time is " << used_seconds << " seconds total ops: " << total_ops << std::endl;
    std::cout << "Million of ops per second: " << megaops_per_second << std::endl;

#ifdef __MACH__
    mach_port_deallocate(mach_task_self(), cclock);
#endif
}


int main() {
#ifdef __MACH__
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
#endif

    std::string line;
    std::ifstream myfile("/home/odintsov/cable_isp_ip_addresses_non_unique.txt");

    if (!myfile.is_open()) {
        std::cerr << "Could not open file with IP list" << std::endl;
        return 1;
    }

    std::vector<uint32_t> our_ips;
    // We know file size and allocate that number of elements + some spare space
    our_ips.reserve(200000);

    while (getline(myfile, line)) {
        // It will be big endian internally
        uint32_t ip = 0;

        bool res = convert_ip_as_string_to_uint_safe(line, ip);

        if (!res) {
            std::cout << "Cannot parse IP " << line << std::endl;
            continue;
        }

        our_ips.push_back(ip);
    }


    std::cout << "Loaded " << our_ips.size() << " IPs into memory" << std::endl;

    {
        std::cout << "std::map" << std::endl;

        std::map<uint32_t, subnet_counter_t> std_map;
        run_tests<std::map<uint32_t, subnet_counter_t>>(our_ips, std_map);
        std_map.clear();
    }

    {
        std::cout << "std::unordered_map" << std::endl;

        std::unordered_map<uint32_t, subnet_counter_t> std_unordered;
        run_tests<std::unordered_map<uint32_t, subnet_counter_t>>(our_ips, std_unordered);
        std_unordered.clear();
    }

    {
        std::cout << "boost::unordered_map" << std::endl;

        boost::unordered_map<uint32_t, subnet_counter_t> boost_unordered;
        run_tests<boost::unordered_map<uint32_t, subnet_counter_t>>(our_ips, boost_unordered);
        boost_unordered.clear();
    }
}
