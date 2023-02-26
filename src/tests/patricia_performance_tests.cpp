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


#include "../nlohmann/json.hpp"

#include "../fast_library.hpp"
#include "../libpatricia/patricia.hpp"

#include "../all_logcpp_libraries.hpp"

using json = nlohmann::json;

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

int main() {
#ifdef __MACH__
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
#endif

    patricia_tree_t* lookup_tree;
    lookup_tree = New_Patricia(32);

    std::string line;
    std::ifstream myfile("/home/odintsov/isp_prefixes.txt");

    if (!myfile.is_open()) {
        std::cerr << "Could not open file with prefix list" << std::endl;
        return 1;
    }

    std::cout << "Start subnet load to patricia" << std::endl;
    while (getline(myfile, line)) {
        // std::cout << "Add subnet " << line << " to patricia tree" << std::endl;
        make_and_lookup(lookup_tree, (char*)line.c_str());
    }

    std::cout << "Finished subnet load to patricia" << std::endl;

    // Load example traffic
    std::ifstream example_traffic("/home/odintsov/isp_traffic.json");

    if (!example_traffic.is_open()) {
        std::cerr << "Could not open file with example traffic" << std::endl;
        return 1;
    }

    std::vector<std::pair<uint32_t, uint32_t>> fragmented_vector_of_packets;

    std::cout << "Start loading traffic into memory" << std::endl;

    while (getline(example_traffic, line)) {
        auto json_conf = json::parse(line, nullptr, false);

        if (json_conf.is_discarded()) {
            std::cerr << "Could not parse JSON: " << line << std::endl;
            return 1;
        }

        // We test only IPv4 for now
        if (json_conf["ip_version"].get<std::string>() != "ipv4") {
            continue;
        }

        uint32_t src_ip = 0;
        uint32_t dst_ip = 0;

        bool source_res = convert_ip_as_string_to_uint_safe(json_conf["source_ip"].get<std::string>(), src_ip);

        if (!source_res) {
            std::cout << "Cannot parse src ip" << std::endl;
            continue;
        }

        bool destionation_res = convert_ip_as_string_to_uint_safe(json_conf["destination_ip"].get<std::string>(), dst_ip);

        if (!destionation_res) {
            std::cout << "Cannot parse dst ip" << std::endl;
            continue;
        }

        // std::cout << json_conf["source_ip"].get<std::string>() << " " << json_conf["destination_ip"].get<std::string>() << std::endl;

        fragmented_vector_of_packets.push_back(std::make_pair(src_ip, dst_ip));
    }

    std::cout << "Loaded traffic into memory" << std::endl;

    std::cout << "Defragment memory for input packet set" << std::endl;

    // Copy traffic into single continious memory regiuon to avoid issues performance issues due to memory frragmentation
    std::vector<std::pair<uint32_t, uint32_t>> vector_of_packets;
    vector_of_packets.reserve(fragmented_vector_of_packets.size());

    for (const auto& pair : fragmented_vector_of_packets) {
        vector_of_packets.push_back(pair);
    }

    fragmented_vector_of_packets.clear();

    std::cout << "Defragmentation done" << std::endl;

    std::cout << "I have " << vector_of_packets.size() << " real packets for test" << std::endl;

    std::cout << "Start tests" << std::endl;

    // Process vector_of_packets

    prefix_t prefix_for_check_adreess;
    prefix_for_check_adreess.family = AF_INET;
    prefix_for_check_adreess.bitlen = 32;
    // prefix_for_check_adreess.add.sin.s_addr = 123123123;

    struct timespec start_time;
    clock_gettime(CLOCK_REALTIME, &start_time);

    unsigned long total_ops = 0;

    if (false) {
        int i_iter = 100;
        // Million operations
        int j_iter = 1000000;

        total_ops = i_iter * j_iter;

        uint64_t matches = 0;

        for (int j = 0; j < j_iter; j++) {
            for (int i = 0; i < i_iter; i++) {
                // Random Pseudo IP
                prefix_for_check_adreess.add.sin.s_addr = i * j;
                patricia_node_t* found_patrica_node = patricia_search_best2(lookup_tree, &prefix_for_check_adreess, 1);

                if (found_patrica_node != NULL) {
                    matches++;
                }
            }
        }
    }

    uint64_t number_of_reruns = 1000;

    // I do not multiple by two here becasue we assume that interation involves two lookups all the time
    total_ops = number_of_reruns * vector_of_packets.size();

    uint64_t match_source       = 0;
    uint64_t match_destionation = 0;

    for (int j = 0; j < number_of_reruns; j++) {
        for (const auto& pair : vector_of_packets) {
            prefix_for_check_adreess.add.sin.s_addr = pair.first;

            patricia_node_t* found_patrica_node = patricia_search_best2(lookup_tree, &prefix_for_check_adreess, 1);

            if (found_patrica_node != NULL) {
                match_source++;
            }

            // Repeat for another IP
            prefix_for_check_adreess.add.sin.s_addr = pair.second;

            found_patrica_node = patricia_search_best2(lookup_tree, &prefix_for_check_adreess, 1);

            if (found_patrica_node != NULL) {
                match_destionation++;
            }
        }
    }

    struct timespec finish_time;
    clock_gettime(CLOCK_REALTIME, &finish_time);

    std::cout << "match_source: " << match_source << " match_destionation: " << match_destionation << std::endl;

    unsigned long used_seconds     = finish_time.tv_sec - start_time.tv_sec;
    unsigned long used_nanoseconds = finish_time.tv_nsec - start_time.tv_nsec;

    unsigned long total_used_nanoseconds = used_seconds * 1000000000 + used_nanoseconds;

    float megaops_per_second = (float)total_ops / ((float)total_used_nanoseconds / (float)1000000000) / 1000000;

    std::cout << "Total time is " << used_seconds << " seconds total ops: " << total_ops << std::endl;
    std::cout << "Million of ops per second: " << megaops_per_second << std::endl;

    Destroy_Patricia(lookup_tree, [](void* ptr) {});

#ifdef __MACH__
    mach_port_deallocate(mach_task_self(), cclock);
#endif
}
