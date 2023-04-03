#include <fstream>
#include <iostream>
#include <thread>
#include <unordered_map>

#include <boost/archive/binary_iarchive.hpp>

#include "../abstract_subnet_counters.hpp"
#include "../fast_library.hpp"
#include "../fastnetmon_types.hpp"

#include "../fast_endianless.hpp"

#include "log4cpp/Appender.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

log4cpp::Category& logger = log4cpp::Category::getRoot();

abstract_subnet_counters_t<uint32_t, subnet_counter_t> ipv4_host_counters;
time_t current_inaccurate_time = 0;

// Try to copy source map into vector
template <typename T> void try_to_copy_to_vector(T& counter_map) {
    std::cout << "Evaluate time required to make full copy of structure into std::vector" << std::endl;

    std::vector<std::pair<uint32_t, subnet_counter_t>> counter_map_copy;
    counter_map_copy.reserve(counter_map.size());

    timeval start_time_val;
    gettimeofday(&start_time_val, NULL);

    ssize_t current_index = 0;

    // Try making copy of traffic counters and track time
    for (auto& itr : counter_map) {
        counter_map_copy[current_index++] = itr;
    }

    timeval finish_time_val;
    gettimeofday(&finish_time_val, NULL);

    timeval interval;
    timeval_subtract(&interval, &finish_time_val, &start_time_val);

    double used_time = (double)interval.tv_sec + (double)interval.tv_usec / 1000000;

    std::cout << "Copied traffic map in " << used_time << " seconds" << std::endl << std::endl;
    counter_map_copy.clear();
}

// Try to copy source map into vector
template <typename T> void try_to_copy_to_vector_initilised_elements(T& counter_map) {
    std::cout
        << "Evaluate time required to make full copy of structure into std::vector with all pre-initialised elements"
        << std::endl;

    // 3) Constructs the container with count copies of elements with value value.
    std::vector<std::pair<uint32_t, subnet_counter_t>> counter_map_copy(counter_map.size(), std::make_pair(0, subnet_counter_t{}));

    timeval start_time_val;
    gettimeofday(&start_time_val, NULL);

    ssize_t current_index = 0;

    // Try making copy of traffic counters and track time
    for (auto& itr : counter_map) {
        counter_map_copy[current_index++] = itr;
    }

    timeval finish_time_val;
    gettimeofday(&finish_time_val, NULL);

    timeval interval;
    timeval_subtract(&interval, &finish_time_val, &start_time_val);

    double used_time = (double)interval.tv_sec + (double)interval.tv_usec / 1000000;

    std::cout << "Copied traffic map in " << used_time << " seconds" << std::endl << std::endl;
    counter_map_copy.clear();
}

// Try to copy source map into array
// TODO: this test cannot free up memory, you must run it as last
template <typename T> void try_to_copy_to_array(T& counter_map) {
    std::cout << "Evaluate time required to make full copy of structure into std::array" << std::endl;

    // I've manually set size to bit our 14.6m element array
    std::array<std::pair<uint32_t, subnet_counter_t>, 20000000> counter_map_copy;

    timeval start_time_val;
    gettimeofday(&start_time_val, NULL);

    ssize_t current_index = 0;

    for (auto& itr : counter_map) {
        counter_map_copy[current_index++] = itr;
    }

    timeval finish_time_val;
    gettimeofday(&finish_time_val, NULL);

    timeval interval;
    timeval_subtract(&interval, &finish_time_val, &start_time_val);

    double used_time = (double)interval.tv_sec + (double)interval.tv_usec / 1000000;

    std::cout << "Copied traffic map in " << used_time << " seconds" << std::endl << std::endl;
}


// Try to copy source map into std::unordered_map
template <typename T> void try_to_copy_to_std_unordered_map(T& counter_map, bool reserve) {
    std::cout << "Evaluate time required to make full copy of structure into std::unordered_map";

    if (reserve) {
        std::cout << " with memory reserve in map";
    }

    std::cout << std::endl;

    std::unordered_map<uint32_t, subnet_counter_t> counter_map_copy;

    if (reserve) {
        counter_map_copy.reserve(counter_map.size());
    }

    timeval start_time_val;
    gettimeofday(&start_time_val, NULL);

    // Try making copy of traffic counters and track time
    for (const auto& itr : counter_map) {
        counter_map_copy[itr.first] = itr.second;
    }

    timeval finish_time_val;
    gettimeofday(&finish_time_val, NULL);

    timeval interval;
    timeval_subtract(&interval, &finish_time_val, &start_time_val);

    double used_time = (double)interval.tv_sec + (double)interval.tv_usec / 1000000;

    std::cout << "Copied traffic map in " << used_time << " seconds" << std::endl << std::endl;
    counter_map_copy.clear();
}

// Try to copy source map into std::unordered_map
template <typename T> void try_to_copy_to_std_unordered_map_pre_created_keys(T& counter_map) {
    std::cout << "Evaluate time required to make full copy of structure into std::unordered_map with pre-created keys "
                 "as in source structure";

    std::cout << std::endl;

    std::unordered_map<uint32_t, subnet_counter_t> counter_map_copy;

    // Create keys as in original structure
    for (const auto& itr : counter_map) {
        counter_map_copy[itr.first] = subnet_counter_t{};
    }

    timeval start_time_val;
    gettimeofday(&start_time_val, NULL);

    // Try making copy of traffic counters and track time
    for (const auto& itr : counter_map) {
        counter_map_copy[itr.first] = itr.second;
    }

    timeval finish_time_val;
    gettimeofday(&finish_time_val, NULL);

    timeval interval;
    timeval_subtract(&interval, &finish_time_val, &start_time_val);

    double used_time = (double)interval.tv_sec + (double)interval.tv_usec / 1000000;

    std::cout << "Copied traffic map in " << used_time << " seconds" << std::endl << std::endl;
    counter_map_copy.clear();
}

// Copies memory from std::vector to another std::vector using memory copy
template <typename T> void try_to_copy_vector_to_vector_memory_copy(T& counter_map_copy, const T& counter_map) {
    std::cout
        << "Evaluate time required to make full copy of std::vector into another std::vector using memory region copy"
        << std::endl;

    // We need to allocate as much memory as source std::vector to have enough memory to do copy
    counter_map_copy.reserve(counter_map.size());

    timeval start_time_val;
    gettimeofday(&start_time_val, NULL);

    std::size_t memory_region_size = counter_map.size() * sizeof(std::pair<uint32_t, subnet_counter_t>);

    // Do memory copy
    memcpy((void*)counter_map_copy.data(), (void*)counter_map.data(), memory_region_size);

    timeval finish_time_val;
    gettimeofday(&finish_time_val, NULL);

    timeval interval;
    timeval_subtract(&interval, &finish_time_val, &start_time_val);

    double used_time = (double)interval.tv_sec + (double)interval.tv_usec / 1000000;

    std::cout << "Copied " << memory_region_size / 1024 / 1024 << " Mbytes of memory from vector to vector in "
              << used_time << " seconds" << std::endl
              << std::endl;
}

template <typename T> void do_parallel_memory_copy(const T& counter_map) {
    // Create std::vectors from map
    std::array<std::vector<std::pair<uint32_t, subnet_counter_t>>, 4> source_vectors;

    for (auto& current_vector : source_vectors) {
        current_vector.reserve(counter_map.size());

        for (auto& itr : counter_map) {
            current_vector.push_back(itr);
        }
    }

    // Target vector to receive copy
    std::array<std::vector<std::pair<uint32_t, subnet_counter_t>>, 4> target_vectors;


    std::thread t1([&]() { try_to_copy_vector_to_vector_memory_copy(target_vectors[0], source_vectors[0]); });

    std::thread t2([&]() { try_to_copy_vector_to_vector_memory_copy(target_vectors[1], source_vectors[1]); });

    std::thread t3([&]() { try_to_copy_vector_to_vector_memory_copy(target_vectors[2], source_vectors[2]); });

    std::thread t4([&]() { try_to_copy_vector_to_vector_memory_copy(target_vectors[3], source_vectors[3]); });


    t1.join();
    t2.join();
    t3.join();
    t4.join();

    for (auto& current_vector : source_vectors) {
        current_vector.clear();
    }

    for (auto& current_vector : target_vectors) {
        current_vector.clear();
    }
}

int main() {
    std::cout << "Load structure from disk dump" << std::endl;

    time_t start_time = 0;
    time(&start_time);

    try {
        std::ifstream deserialize_stream("/home/odintsov/speed_counters_local_ipv4_hosts.dat");
        boost::archive::binary_iarchive input_archive(deserialize_stream);

        input_archive >> BOOST_SERIALIZATION_NVP(ipv4_host_counters);
        std::cout << "Loaded traffic counters from disk" << std::endl;
    } catch (boost::archive::archive_exception& e) {
        std::cout << "Internal error with loading traffic counters from disk: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cout << "Internal error with loading traffic counters from disk" << std::endl;
        ;
        return 1;
    }

    time_t finish_time = 0;
    time(&finish_time);

    std::cout << "Loaded traffic from disk in " << finish_time - start_time << " seconds" << std::endl;

    std::cout << "Map size " << ipv4_host_counters.counter_map.size() << std::endl;
    std::cout << "Map bucket count " << ipv4_host_counters.counter_map.bucket_count() << std::endl;

    std::cout << "Memory use by single counter map: "
              << ipv4_host_counters.counter_map.size() * (sizeof(subnet_counter_t) + sizeof(uint32_t)) / 1024 / 1024
              << " Mb" << std::endl;

    /*
    try_to_copy_to_vector(ipv4_host_counters.counter_map);

    try_to_copy_to_vector_initilised_elements(ipv4_host_counters.counter_map);

    try_to_copy_to_std_unordered_map(ipv4_host_counters.counter_map, false);

    try_to_copy_to_std_unordered_map(ipv4_host_counters.counter_map, true);

    try_to_copy_to_std_unordered_map_pre_created_keys(ipv4_host_counters.counter_map);

    // Well, key findings that it does not scale as we expected ;(
    do_parallel_memory_copy(ipv4_host_counters.counter_map);

    // This test cannot free up memory, we should run it as last
    try_to_copy_to_array(ipv4_host_counters.counter_map);
    */

    double speed_calc_period        = 1;
    double average_calculation_time = 60;

    std::cout << "Loaded" << std::endl;

    std::cout << "Sharding data" << std::endl;

    const int sharding_value = 32;

    std::array<abstract_subnet_counters_t<uint32_t, subnet_counter_t>, sharding_value> speed_counters;

    for (const auto& itr : ipv4_host_counters.counter_map) {
        // NB!!!! TODO: without ntoh conversion it will be 2 all the time and sharding will not work!!!
        int reminder = fast_ntoh(itr.first) % sharding_value;

        // std::cout << "value" << itr.first << "reminder: " << reminder << std::endl;
        speed_counters[reminder].counter_map[itr.first] = itr.second;
    }

    for (const auto& current_speed_counter : speed_counters) {
        std::cout << "Speed counter size: " << current_speed_counter.counter_map.size() << std::endl;
    }

    /*
     Lab server has: AMD Ryzen 5 3600 6-Core Processor
     PC: AMD Ryzen 7 5800X 8-Core Processor

     Lab server, 1 thread (old):
        Calculated speed in 3.70434 seconds
        Calculated speed in 3.73092 seconds
        Calculated speed in 3.72158 seconds

     Lab server, 2 threads:
        Calculated speed in 2.93566 seconds
        Calculated speed in 2.94285 seconds
        Calculated speed in 2.92184 seconds

     Lab server, 3 threads:
        Calculated speed in 2.17883 seconds
        Calculated speed in 2.13465 seconds
        Calculated speed in 2.09182 seconds

     Lab server, 4 threads:
        Calculated speed in 1.76031 seconds
        Calculated speed in 1.82056 seconds
        Calculated speed in 1.79133 seconds

      Lab server, 5 threads:
        Calculated speed in 1.47045 seconds
        Calculated speed in 1.47526 seconds
        Calculated speed in 1.41408 seconds

       Lab server, 6 threads (2.7 times better than single threaded!):
        Calculated speed in 1.35194 seconds
        Calculated speed in 1.37153 seconds
        Calculated speed in 1.34529 seconds

     PC, 1 thread (old):
        Calculated speed in 2.80088 seconds
        Calculated speed in 2.80217 seconds
        Calculated speed in 2.80967 seconds

     PC, 4 threads:
        Calculated speed in 1.37763 seconds
        Calculated speed in 1.38572 seconds
        Calculated speed in 1.37288 seconds

     PC, 6 threads:
        Calculated speed in 1.12384 seconds
        Calculated speed in 1.11926 seconds
        Calculated speed in 1.1167 seconds

     PC, 7 threads:
        Calculated speed in 1.02398 seconds
        Calculated speed in 1.0216 seconds
        Calculated speed in 1.01837 seconds

     PC, 8 threads (2.7 times better than single threaded!):
        Calculated speed in 1.03207 seconds
        Calculated speed in 1.01931 seconds
        Calculated speed in 1.0154 seconds

     GCE, c2-standard-16 (16 cores), Intel Cascade Lake, 1 thread (old):
        Calculated speed in 4.60883 seconds
        Calculated speed in 4.61683 seconds
        Calculated speed in 4.60568 seconds

     GCE, c2-standard-16 (16 cores), Intel Cascade Lake, 16 threads, (7.6 times better then single thread!):
        Calculated speed in 0.664504 seconds
        Calculated speed in 0.661836 seconds
        Calculated speed in 0.71273 seconds

    GCE, e2-highcpu-32 (32 cores), Intel Broadwell, 1 thread (old):
        Calculated speed in 5.68188 seconds
        Calculated speed in 5.70301 seconds
        Calculated speed in 5.69111 seconds


     GCE, e2-highcpu-32 (32 cores), Intel Broadwell, 16 threads (9.9 times better then single thread!):
        Calculated speed in 0.562593 seconds
        Calculated speed in 0.565208 seconds
        Calculated speed in 0.559615 seconds

     GCE, e2-highcpu-32 (32 cores), Intel Broadwell, 32 threads (13 times better then single thread!):
        Calculated speed in 0.425343 seconds
        Calculated speed in 0.425999 seconds
        Calculated speed in 0.434782 seconds

     */

    while (true) {
        timeval start_time_val;
        gettimeofday(&start_time_val, NULL);

        std::vector<std::thread> threads;

        for (auto& current_speed_counter : speed_counters) {
            threads.push_back(std::thread([&]() {
                current_speed_counter.recalculate_speed(speed_calc_period, average_calculation_time, nullptr);
            }));
        }

        // Wait threads to finish
        for (auto& current_thread : threads) {
            current_thread.join();
        }

        timeval finish_time_val;
        gettimeofday(&finish_time_val, NULL);

        timeval interval;
        timeval_subtract(&interval, &finish_time_val, &start_time_val);

        double used_time = (double)interval.tv_sec + (double)interval.tv_usec / 1000000;

        std::cout << "Calculated speed in " << used_time << " seconds" << std::endl << std::endl;
    }

    /*
    while (true) {
        timeval start_time_val;
        gettimeofday(&start_time_val, NULL);

        ipv4_host_counters.recalculate_speed(speed_calc_period, average_calculation_time, nullptr);

        timeval finish_time_val;
        gettimeofday(&finish_time_val, NULL);

        timeval interval;
        timeval_subtract(&interval, &finish_time_val, &start_time_val);

        double used_time = (double)interval.tv_sec + (double)interval.tv_usec / 1000000;

        std::cout << "Calculated speed in " << used_time  << " seconds" << std::endl << std::endl;
    }
    */

    return 0;
}
