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

#include "../all_logcpp_libraries.hpp"

#include "../fast_library.hpp"

#include "../fast_endianless.hpp"

#include "../fastnetmon_types.hpp"

#include <boost/unordered/unordered_flat_map.hpp>
#include <boost/unordered_map.hpp>
#include <map>
#include <unordered_map>

#ifdef ABSEIL_TESTS
#include "absl/container/flat_hash_map.h"
#include "absl/container/node_hash_map.h"
#endif

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

// We use these structures to tests smaller value
class udp_t {
    public:
    uint64_t in_bytes = 0;
};

class subnet_counter_small_t {
    public:
    udp_t udp;
};


// Runs tests for specific structure
template <typename T> void run_tests(std::vector<uint32_t> our_ips, T& data_structure) {
    struct timespec start_time;
    clock_gettime(CLOCK_REALTIME, &start_time);

    unsigned long total_ops = 0;

    uint64_t number_of_reruns = 1000;

    total_ops = number_of_reruns * our_ips.size();

    for (int j = 0; j < number_of_reruns; j++) {
        for (const auto& ip : our_ips) {
            data_structure[ip].udp.in_bytes++;
        }
    }

    struct timespec finish_time;
    clock_gettime(CLOCK_REALTIME, &finish_time);

    unsigned long used_seconds     = finish_time.tv_sec - start_time.tv_sec;
    unsigned long used_nanoseconds = finish_time.tv_nsec - start_time.tv_nsec;

    unsigned long total_used_nanoseconds = used_seconds * 1000000000 + used_nanoseconds;

    float megaops_per_second = (float)total_ops / ((float)total_used_nanoseconds / (float)1000000000) / 1000000;

    std::cout << "Total lookup time is " << used_seconds << " seconds" << std::endl;
    std::cout << "Million of lookup ops per second: " << megaops_per_second << std::endl;

#ifdef __MACH__
    mach_port_deallocate(mach_task_self(), cclock);
#endif
}

// Runs tests for specific structure
template <typename T> void run_scan_tests(T& data_structure, uint64_t& accumulator) {
    struct timespec start_time;
    clock_gettime(CLOCK_REALTIME, &start_time);

    unsigned long total_ops = 0;

    uint64_t number_of_reruns = 1000;

    total_ops = number_of_reruns * data_structure.size();

    for (int j = 0; j < number_of_reruns; j++) {
        for (const auto& elem : data_structure) {
            accumulator += elem.second.udp.in_bytes;
        }
    }

    struct timespec finish_time;
    clock_gettime(CLOCK_REALTIME, &finish_time);

    unsigned long used_seconds     = finish_time.tv_sec - start_time.tv_sec;
    unsigned long used_nanoseconds = finish_time.tv_nsec - start_time.tv_nsec;

    unsigned long total_used_nanoseconds = used_seconds * 1000000000 + used_nanoseconds;

    float megaops_per_second = (float)total_ops / ((float)total_used_nanoseconds / (float)1000000000) / 1000000;

    std::cout << "Total scan time is " << used_seconds << " seconds" << std::endl;
    std::cout << "Million of full scan ops per second: " << megaops_per_second << std::endl;

#ifdef __MACH__
    mach_port_deallocate(mach_task_self(), cclock);
#endif
}

int main() {
#ifdef __MACH__
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
#endif

    std::string file_path = "/home/odintsov/cable_isp_ip_addresses_non_unique.txt";

    std::string line;
    std::ifstream myfile(file_path);

    if (!myfile.is_open()) {
        std::cerr << "Could not open file with IP list: " << file_path << std::endl;
        return 1;
    }

    std::vector<uint32_t> our_ips_big_endian;
    std::vector<uint32_t> our_ips_little_endian;

    // We know file size and allocate that number of elements + some spare space
    our_ips_big_endian.reserve(200000);
    our_ips_little_endian.reserve(200000);


    while (getline(myfile, line)) {
        // It will be big endian internally
        uint32_t ip = 0;

        bool res = convert_ip_as_string_to_uint_safe(line, ip);

        if (!res) {
            std::cout << "Cannot parse IP " << line << std::endl;
            continue;
        }

        our_ips_big_endian.push_back(ip);

        // Convert it to little endian
        our_ips_little_endian.push_back(fast_ntoh(ip));
    }


    std::cout << "Loaded " << our_ips_big_endian.size() << " IPs into memory" << std::endl;


    {
        uint64_t accumulator = 0;
        std::cout << std::endl << "std::map big endian " << std::endl;

        std::map<uint32_t, subnet_counter_t> std_map;
        run_tests(our_ips_big_endian, std_map);
        run_scan_tests(std_map, accumulator);
        std_map.clear();

        std::cout << "Accumulator value to guarantee no optimisation tricks from compiler: " << accumulator << std::endl;
    }


    {
        uint64_t accumulator = 0;
        std::cout << std::endl << "std::map little endian " << std::endl;

        std::map<uint32_t, subnet_counter_t> std_map;
        run_tests(our_ips_little_endian, std_map);
        run_scan_tests(std_map, accumulator);
        std_map.clear();

        std::cout << "Accumulator value to guarantee no optimisation tricks from compiler: " << accumulator << std::endl;
    }


    {
        uint64_t accumulator = 0;
        std::cout << std::endl << "std::unordered_map big endian" << std::endl;

        std::unordered_map<uint32_t, subnet_counter_t> std_unordered;
        run_tests(our_ips_big_endian, std_unordered);
        run_scan_tests(std_unordered, accumulator);
        std_unordered.clear();

        std::cout << "Bucket number: " << std_unordered.bucket_count() << std::endl;
        std::cout << "Accumulator value to guarantee no optimisation tricks from compiler: " << accumulator << std::endl;
    }

    {
        uint64_t accumulator = 0;
        std::cout << std::endl << "std::unordered_map little endian" << std::endl;

        std::unordered_map<uint32_t, subnet_counter_t> std_unordered;
        run_tests(our_ips_little_endian, std_unordered);
        run_scan_tests(std_unordered, accumulator);
        std_unordered.clear();

        std::cout << "Bucket number: " << std_unordered.bucket_count() << std::endl;
        std::cout << "Accumulator value to guarantee no optimisation tricks from compiler: " << accumulator << std::endl;
    }


    {
        uint64_t accumulator = 0;
        std::cout << std::endl << "boost::unordered_map big endian " << std::endl;

        boost::unordered_map<uint32_t, subnet_counter_t> boost_unordered;
        run_tests(our_ips_big_endian, boost_unordered);
        run_scan_tests(boost_unordered, accumulator);
        boost_unordered.clear();

        std::cout << "Bucket number: " << boost_unordered.bucket_count() << std::endl;
        std::cout << "Accumulator value to guarantee no optimisation tricks from compiler: " << accumulator << std::endl;
    }

    {
        uint64_t accumulator = 0;
        std::cout << std::endl << "boost::unordered_map little endian " << std::endl;

        boost::unordered_map<uint32_t, subnet_counter_t> boost_unordered;
        run_tests(our_ips_little_endian, boost_unordered);
        run_scan_tests(boost_unordered, accumulator);
        boost_unordered.clear();

        std::cout << "Bucket number: " << boost_unordered.bucket_count() << std::endl;
        std::cout << "Accumulator value to guarantee no optimisation tricks from compiler: " << accumulator << std::endl;
    }

    {
        uint64_t accumulator = 0;
        std::cout << std::endl << "boost::unordered_flat_map big endian " << std::endl;

        boost::unordered_flat_map<uint32_t, subnet_counter_t> boost_unordered;
        run_tests(our_ips_big_endian, boost_unordered);
        run_scan_tests(boost_unordered, accumulator);
        boost_unordered.clear();

        std::cout << "Bucket number: " << boost_unordered.bucket_count() << std::endl;
        std::cout << "Accumulator value to guarantee no optimisation tricks from compiler: " << accumulator << std::endl;
    }

    {
        uint64_t accumulator = 0;
        std::cout << std::endl << "boost::unordered_flat_map little endian " << std::endl;

        boost::unordered_flat_map<uint32_t, subnet_counter_t> boost_unordered;
        run_tests(our_ips_little_endian, boost_unordered);
        run_scan_tests(boost_unordered, accumulator);
        boost_unordered.clear();

        std::cout << "Bucket number: " << boost_unordered.bucket_count() << std::endl;
        std::cout << "Accumulator value to guarantee no optimisation tricks from compiler: " << accumulator << std::endl;
    }

#ifdef ABSEIL_TESTS
    {
        uint64_t accumulator = 0;
        std::cout << std::endl << "absl::flat_hash_map little endian " << std::endl;

        absl::flat_hash_map<uint32_t, subnet_counter_t> unordered;
        run_tests(our_ips_little_endian, unordered);
        run_scan_tests(unordered, accumulator);
        unordered.clear();

        std::cout << "Bucket number: " << unordered.bucket_count() << std::endl;
        std::cout << "Accumulator value to guarantee no optimisation tricks from compiler: " << accumulator << std::endl;
    }

    {
        uint64_t accumulator = 0;
        std::cout << std::endl << "absl::flat_hash_map big endian " << std::endl;

        absl::flat_hash_map<uint32_t, subnet_counter_t> unordered;
        run_tests(our_ips_big_endian, unordered);
        run_scan_tests(unordered, accumulator);
        unordered.clear();

        std::cout << "Bucket number: " << unordered.bucket_count() << std::endl;
        std::cout << "Accumulator value to guarantee no optimisation tricks from compiler: " << accumulator << std::endl;
    }

    {
        uint64_t accumulator = 0;
        std::cout << std::endl << "absl::node_hash_map little endian " << std::endl;

        absl::node_hash_map<uint32_t, subnet_counter_t> unordered;
        run_tests(our_ips_little_endian, unordered);
        run_scan_tests(unordered, accumulator);
        unordered.clear();

        std::cout << "Bucket number: " << unordered.bucket_count() << std::endl;
        std::cout << "Accumulator value to guarantee no optimisation tricks from compiler: " << accumulator << std::endl;
    }

    {
        uint64_t accumulator = 0;
        std::cout << std::endl << "node_hash_map big endian " << std::endl;

        absl::node_hash_map<uint32_t, subnet_counter_t> unordered;
        run_tests(our_ips_big_endian, unordered);
        run_scan_tests(unordered, accumulator);
        unordered.clear();

        std::cout << "Bucket number: " << unordered.bucket_count() << std::endl;
        std::cout << "Accumulator value to guarantee no optimisation tricks from compiler: " << accumulator << std::endl;
    }


#endif
}
