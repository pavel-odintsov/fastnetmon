#include <functional>
#include <iomanip>
#include <iostream>
#include <locale.h>
#include <map>
#include <memory>
#include <stdint.h>
#include <sys/time.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <boost/thread.hpp>
#include <boost/unordered_map.hpp>

#include <boost/container/flat_map.hpp>

#include <boost/pool/pool_alloc.hpp>
#include <boost/pool/singleton_pool.hpp>

#include "../fastnetmon_types.hpp"

#ifdef TEST_TBB_LIBRARY

#ifndef __APPLE__
#include "tbb/concurrent_unordered_map.h"
#endif

#endif

#include <sys/ipc.h>
#include <sys/shm.h>

#include "../all_logcpp_libraries.hpp"

// #define ABSEIL

#ifdef ABSEIL
#include "absl/container/flat_hash_map.h"
#endif

// It's not enabled because it crashes: https://github.com/sparsehash/sparsehash/issues/166
//#define TEST_SPARSE_HASH

#ifdef TEST_SPARSE_HASH
#include <sparsehash/dense_hash_map>
#endif

#include "../fast_library.hpp"

log4cpp::Category& logger = log4cpp::Category::getRoot();


// No speed benefits
// std::map<uint32_t, subnet_counter_t, std::less<uint32_t>,
// boost::fast_pool_allocator<std::pair<const
// uint32_t, map_element>>
std::map<uint32_t, subnet_counter_t> DataCounter;

std::map<uint32_t, subnet_counter_t> DataCounterPrecreated;


std::mutex data_counter_mutex;

std::unordered_map<uint32_t, subnet_counter_t> DataCounterUnordered;

std::unordered_map<uint32_t, subnet_counter_t> DataCounterUnorderedPreallocated;

std::unordered_map<uint32_t, subnet_counter_t> DataCounterUnorderedPrecreated;


boost::unordered_map<uint32_t, subnet_counter_t> DataCounterBoostUnordered;

boost::unordered_map<uint32_t, subnet_counter_t> DataCounterBoostUnorderedPreallocated;

boost::unordered_map<uint32_t, subnet_counter_t> DataCounterBoostUnorderedPrecreated;

boost::container::flat_map<uint32_t, subnet_counter_t> DataCounterBoostFlatMap;

struct eqint {
    bool operator()(uint32_t a, uint32_t b) const {
        return a == b;
    }
};

#ifdef TEST_SPARSE_HASH
google::dense_hash_map<uint32_t, subnet_counter_t, std::hash<uint32_t>, eqint, google::libc_allocator_with_realloc<std::pair<const uint32_t, subnet_counter_t>>> DataCounterGoogleDensehashMapPreallocated;

google::dense_hash_map<uint32_t, subnet_counter_t, std::hash<uint32_t>, eqint, google::libc_allocator_with_realloc<std::pair<const uint32_t, subnet_counter_t>>> DataCounterGoogleDensehashMap;
#endif

#ifdef ABSEIL
absl::flat_hash_map<uint32_t, subnet_counter_t> DataCounterAbseilFlatHashMap;
#endif

#ifdef TEST_TBB_LIBRARY

#ifndef __APPLE__
tbb::concurrent_unordered_map<uint32_t, subnet_counter_t> DataCounterUnorderedConcurrent;
#endif

#endif


using namespace std;

int number_of_ips     = 10 * 1000 * 1000;
int number_of_retries = 1;

// #define enable_mutexes_in_test
unsigned int number_of_threads = 1;

// Preallocate vector
std::vector<subnet_counter_t> DataCounterVector(number_of_ips);
subnet_counter_t* data_counter_c_array_ptr = nullptr;

subnet_counter_t* data_counter_c_array_ptr_huge_tlb = nullptr;


key_t generate_ipc_key() {
    // 121 is unique project id
    key_t ipc_key = ftok(__FILE__, 121);
    if (ipc_key < 0) {
        std::cerr << "Failed to Generate IPC Key" << std::endl;
        return 0;
    }

    return ipc_key;
}

// 83 seconds
// without mutexes segmentation fault
void packet_collector_thread_std_map() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexes_in_test
            data_counter_mutex.lock();
#endif
            DataCounter[i].udp_in_bytes++;

#ifdef enable_mutexes_in_test
            data_counter_mutex.unlock();
#endif
        }
    }
}

void packet_collector_thread_std_map_precreated() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexes_in_test
            data_counter_mutex.lock();
#endif
            DataCounterPrecreated[i].udp_in_bytes++;

#ifdef enable_mutexes_in_test
            data_counter_mutex.unlock();
#endif
        }
    }
}

void packet_collector_thread_boost_unordered_map() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexes_in_test
            data_counter_mutex.lock();
#endif
            DataCounterBoostUnordered[i].udp_in_bytes++;
#ifdef enable_mutexes_in_test
            data_counter_mutex.unlock();
#endif
        }
    }
}

void packet_collector_thread_boost_unordered_map_preallocated() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexes_in_test
            data_counter_mutex.lock();
#endif
            DataCounterBoostUnorderedPreallocated[i].udp_in_bytes++;
#ifdef enable_mutexes_in_test
            data_counter_mutex.unlock();
#endif
        }
    }
}

void packet_collector_thread_boost_unordered_map_precreated() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexes_in_test
            data_counter_mutex.lock();
#endif
            DataCounterBoostUnorderedPrecreated[i].udp_in_bytes++;
#ifdef enable_mutexes_in_test
            data_counter_mutex.unlock();
#endif
        }
    }
}

void packet_collector_thread_unordered_map() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexes_in_test
            data_counter_mutex.lock();
#endif
            DataCounterUnordered[i].udp_in_bytes++;
#ifdef enable_mutexes_in_test
            data_counter_mutex.unlock();
#endif
        }
    }
}

#ifdef ABSEIL
void packet_collector_thread_abseil_flat_map() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexes_in_test
            data_counter_mutex.lock();
#endif
            DataCounterAbseilFlatHashMap[i].udp_in_bytes++;
#ifdef enable_mutexes_in_test
            data_counter_mutex.unlock();
#endif
        }
    }
}
#endif

#ifdef TEST_SPARSE_HASH
void packet_collector_thread_google_dense_hash_map_preallocated() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexes_in_test
            data_counter_mutex.lock();
#endif
            DataCounterGoogleDensehashMapPreallocated[i].udp_in_bytes++;
#ifdef enable_mutexes_in_test
            data_counter_mutex.unlock();
#endif
        }
    }
}
#endif

#ifdef TEST_SPARSE_HASH
void packet_collector_thread_google_dense_hash_map() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexes_in_test
            data_counter_mutex.lock();
#endif
            DataCounterGoogleDensehashMap[i].udp_in_bytes++;
#ifdef enable_mutexes_in_test
            data_counter_mutex.unlock();
#endif
        }
    }
}
#endif

void packet_collector_thread_unordered_map_preallocated() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexes_in_test
            data_counter_mutex.lock();
#endif
            DataCounterUnorderedPreallocated[i].udp_in_bytes++;
#ifdef enable_mutexes_in_test
            data_counter_mutex.unlock();
#endif
        }
    }
}

void packet_collector_thread_unordered_map_precreated() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexes_in_test
            data_counter_mutex.lock();
#endif
            DataCounterUnorderedPrecreated[i].udp_in_bytes++;
#ifdef enable_mutexes_in_test
            data_counter_mutex.unlock();
#endif
        }
    }
}


void packet_collector_thread_flat_map_preallocated() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexes_in_test
            data_counter_mutex.lock();
#endif
            DataCounterBoostFlatMap[i].udp_in_bytes++;
#ifdef enable_mutexes_in_test
            data_counter_mutex.unlock();
#endif
        }
    }
}

void packet_collector_thread_vector() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
            DataCounterVector[i].udp_in_bytes++;
        }
    }
}

void packet_collector_thread_c_array() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
            data_counter_c_array_ptr[i].udp_in_bytes++;
        }
    }
}

void packet_collector_thread_c_array_huge_tlb() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
            data_counter_c_array_ptr_huge_tlb[i].udp_in_bytes++;
        }
    }
}

// We just execute time read here
void packet_collector_time_calculaitons() {
    struct timespec current_time;

    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
            clock_gettime(CLOCK_REALTIME, &current_time);
        }
    }
}

// We just execute time read here
void packet_collector_time_calculaitons_monotonic() {
    struct timespec current_time;

    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
            clock_gettime(CLOCK_MONOTONIC, &current_time);
        }
    }
}

// We just execute time read here
void packet_collector_time_calculaitons_monotonic_coarse() {
    struct timespec current_time;

    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
            clock_gettime(CLOCK_MONOTONIC_COARSE, &current_time);
        }
    }
}

// We just execute time read here
void packet_collector_time_calculaitons_gettimeofday() {
    struct timeval current_time;

    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
            gettimeofday(&current_time, NULL);
        }
    }
}


#ifdef TEST_TBB_LIBRARY

#ifndef __APPLE__
void packet_collector_thread_unordered_concurrent_map() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
            DataCounterUnorderedConcurrent[i].udp_in_bytes++;
        }
    }
}
#endif

#endif

int run_tests(std::function<void()> tested_function) {
    timeval start_time;
    gettimeofday(&start_time, NULL);

    // std::cout << "Run "<< number_of_threads <<" threads" << endl;
    boost::thread* threads[number_of_threads];
    for (int i = 0; i < number_of_threads; i++) {
        threads[i] = new boost::thread(tested_function);
    }

    // std::cout << "All threads started" << endl;

    // std::cout << "Wait for finishing" << endl;
    for (int i = 0; i < number_of_threads; i++) {
        threads[i]->join();
    }

    // cout << "All threads finished" << endl;

    timeval finish_time;
    gettimeofday(&finish_time, NULL);

    double total_operations = number_of_ips * number_of_retries * number_of_threads;

    // We use ' for pretty print of long numbers
    // http://stackoverflow.com/questions/1499156/convert-astronomically-large-numbers-into-human-readable-form-in-c-c
    setlocale(LC_NUMERIC, "en_US.utf-8"); /* important */

    timeval interval;
    timeval_subtract(&interval, &finish_time, &start_time);

    // Build time with float part
    double used_time = (double)interval.tv_sec + (double)interval.tv_usec / 1000000;
    // printf("We spent %f seconds\n", used_time);

    double ops_per_second = total_operations / used_time;
    ;
    double mega_ops_per_second = ops_per_second / 1000 / 1000;

    printf("%'.1f mega ops per second\n", mega_ops_per_second);

    return 0;
}

void init_logging() {
    log4cpp::PatternLayout* console_layout = new log4cpp::PatternLayout();
    console_layout->setConversionPattern("%d [%p] %m%n");

    log4cpp::Appender* console_appender = new log4cpp::OstreamAppender("console", &std::cout);
    console_appender->setLayout(console_layout);

    logger.setPriority(log4cpp::Priority::DEBUG);
    logger.addAppender(console_appender);
}


int main(int argc, char* argv[]) {
    init_logging();

    bool test_monotonic_coarse                 = false;
    bool test_gettimeofday                     = false;
    bool test_std_map                          = false;
    bool test_tbb_concurrent_unordered_map     = false;
    
    bool test_boost_unordered_map              = false;
    bool test_boost_unordered_map_preallocated = false;
    bool test_boost_unordered_map_precreated   = false;

    bool test_boost_container_flat_map         = false;
    bool test_unordered_map_cpp11              = false;
    bool test_unordered_map_cpp11_preallocated = false;
    bool test_unordered_map_cpp11_precreated   = false;

    bool test_vector_preallocated              = false;
    bool test_std_map_precreated               = false;
    bool test_clock_gettime_realtime           = false;
    bool test_clock_gettime_monotonic          = false;
    bool test_c_array_preallocated             = false;
    bool test_c_array_huge_pages_preallocated  = false;

    if (argc > 1) {
        std::string first_argument = argv[1];

        if (first_argument == "test_std_map") {
            test_std_map = true;
        } else if (first_argument == "test_tbb_concurrent_unordered_map") {
            test_tbb_concurrent_unordered_map = true;
        } else if (first_argument == "test_boost_unordered_map") {
            test_boost_unordered_map = true;
        } else if (first_argument == "test_boost_unordered_map_preallocated") {
            test_boost_unordered_map_preallocated = true;
        } else if (first_argument == "test_boost_unordered_map_precreated") { 
            test_boost_unordered_map_precreated = true;
        } else if (first_argument == "test_boost_container_flat_map") {
            test_boost_container_flat_map = true;
        } else if (first_argument == "test_unordered_map_cpp11") {
            test_unordered_map_cpp11 = true;
        } else if (first_argument == "test_unordered_map_cpp11_preallocated") {
            test_unordered_map_cpp11_preallocated = true;
        } else if (first_argument == "test_vector_preallocated") {
            test_vector_preallocated = true;
        } else if (first_argument == "test_unordered_map_cpp11_precreated") {
            test_unordered_map_cpp11_precreated = true;
        } else if (first_argument == "test_std_map_precreated") {
            test_std_map_precreated = true;
        } else if (first_argument == "test_clock_gettime_realtime") {
            test_clock_gettime_realtime = true;
        } else if (first_argument == "test_clock_gettime_monotonic") {
            test_clock_gettime_monotonic = true;
        } else if (first_argument == "test_gettimeofday") {
            test_gettimeofday = true;
        } else if (first_argument == "test_c_array_preallocated") {
            test_c_array_preallocated = true;
        } else if (first_argument == "test_c_array_huge_pages_preallocated") {
            test_c_array_huge_pages_preallocated = true;
        } else if (first_argument == "test_monotonic_coarse") {
            test_monotonic_coarse = true;
        }
    } else {
        test_monotonic_coarse                 = true;
        test_clock_gettime_monotonic          = true;
        test_gettimeofday                     = true;
        test_clock_gettime_realtime           = true;
        test_std_map                          = true;
        test_std_map_precreated               = true;
        test_tbb_concurrent_unordered_map     = true;
        
        test_boost_unordered_map              = true;
        test_boost_unordered_map_preallocated = true;
        test_boost_unordered_map_precreated   = true;
        
        test_boost_container_flat_map         = true;
        
        test_unordered_map_cpp11              = true;
        test_unordered_map_cpp11_preallocated = true;
        test_unordered_map_cpp11_precreated   = true;

        test_vector_preallocated              = true;
        test_c_array_preallocated             = true;
        test_c_array_huge_pages_preallocated  = true;
    }

    std::cout << "Element size: " << sizeof(subnet_counter_t) << " bytes" << std::endl;
    std::cout << "Total structure size: " << sizeof(subnet_counter_t) * number_of_ips / 1024 / 1024 << " Mbytes" << std::endl;

    if (test_std_map) {
        std::cout << "std::map: ";
        run_tests(packet_collector_thread_std_map);
        DataCounter.clear();
    }

    if (test_std_map_precreated) {
        // Precreate all elements
        for (uint32_t i = 0; i < number_of_ips; i++) {
            subnet_counter_t current_map_element;

            DataCounterPrecreated.insert(std::make_pair(i, current_map_element));
        }

        std::cout << "std::map precreated: ";
        run_tests(packet_collector_thread_std_map_precreated);
        DataCounterPrecreated.clear();
    }


    if (test_tbb_concurrent_unordered_map) {
#ifdef TEST_TBB_LIBRARY

#ifndef __APPLE__
        std::cout << "tbb::concurrent_unordered_map: ";
        run_tests(packet_collector_thread_unordered_concurrent_map);
        DataCounterUnorderedConcurrent.clear();
#endif

#endif
    }

    if (test_boost_unordered_map) {
        std::cout << "boost::unordered_map: ";
        run_tests(packet_collector_thread_boost_unordered_map);
        DataCounterBoostUnordered.clear();
    }

    if (test_boost_unordered_map_preallocated) {
        std::cout << "boost::unordered_map with preallocated elements: ";
        DataCounterBoostUnorderedPreallocated.reserve(number_of_ips);
        run_tests(packet_collector_thread_boost_unordered_map_preallocated);
        DataCounterBoostUnorderedPreallocated.clear();
    }

    if (test_boost_unordered_map_precreated) {
        std::cout << "boost::unordered_map with precreated elements: ";

        for (uint32_t i = 0; i < number_of_ips; i++) {
            subnet_counter_t current_map_element;

            DataCounterBoostUnorderedPrecreated.insert(std::make_pair(i, current_map_element));
        }

        run_tests(packet_collector_thread_boost_unordered_map_precreated);
        DataCounterBoostUnorderedPrecreated.clear();
    }

    if (test_boost_container_flat_map) {
        // Boost flat_map
        DataCounterBoostFlatMap.reserve(number_of_ips);
        std::cout << "boost::container::flat_map with preallocated elements: ";
        run_tests(packet_collector_thread_flat_map_preallocated);
        DataCounterBoostFlatMap.clear();
    }

    if (test_unordered_map_cpp11) {
        std::cout << "std::unordered_map C++11: ";
        run_tests(packet_collector_thread_unordered_map);
        DataCounterUnordered.clear();
    }

    if (test_unordered_map_cpp11_preallocated) {
        // Preallocate hash buckets
        DataCounterUnorderedPreallocated.reserve(number_of_ips);
        std::cout << "std::unordered_map C++11 preallocated buckets: ";
        run_tests(packet_collector_thread_unordered_map_preallocated);

        /*
        std::cout << "Number of buckets: " << DataCounterUnorderedPreallocated.bucket_count() << std::endl;
        std::cout << "Number of IP's: " << DataCounterUnorderedPreallocated.size() << std::endl;
        std::cout << "Load factor: " << DataCounterUnorderedPreallocated.load_factor() << std::endl;
        */
        DataCounterUnorderedPreallocated.clear();
    }

    if (test_unordered_map_cpp11_precreated) {
        // Precreate all elements in hash
        for (uint32_t i = 0; i < number_of_ips; i++) {
            subnet_counter_t current_map_element;

            DataCounterUnorderedPrecreated.insert(std::make_pair(i, current_map_element));
        }

        std::cout << "std::unordered_map C++11 precreated elements: ";
        run_tests(packet_collector_thread_unordered_map_precreated);
        DataCounterUnorderedPrecreated.clear();
    }

#ifdef ABSEIL
    std::cout << "abesil::flat_hash_map: ";
    run_tests(packet_collector_thread_abseil_flat_map);
#endif

#ifdef TEST_SPARSE_HASH
    std::cout << "google:dense_hashmap without preallocation: ";
    DataCounterGoogleDensehashMap.set_empty_key(UINT32_MAX); // We will got assert without it!
    run_tests(packet_collector_thread_google_dense_hash_map);
    DataCounterGoogleDensehashMap.clear();
#endif

#ifdef TEST_SPARSE_HASH
    std::cout << "google:dense_hashmap preallocated buckets: ";
    // We use UINT32_MAX as "empty" here, not a good idea but OK for tests
    DataCounterGoogleDensehashMapPreallocated.set_empty_key(UINT32_MAX); // We will got assert without it!
    DataCounterGoogleDensehashMapPreallocated.resize(number_of_ips);
    run_tests(packet_collector_thread_google_dense_hash_map_preallocated);
    DataCounterGoogleDensehashMapPreallocated.clear();
#endif

    if (test_vector_preallocated) {
        std::cout << "std::vector preallocated: ";
        run_tests(packet_collector_thread_vector);
        DataCounterVector.clear();
    }

    if (test_c_array_preallocated) {
        data_counter_c_array_ptr = new subnet_counter_t[number_of_ips];
        std::cout << "C array preallocated: ";
        run_tests(packet_collector_thread_c_array);
        delete[] data_counter_c_array_ptr;
        data_counter_c_array_ptr = NULL;
    }

    if (test_c_array_huge_pages_preallocated) {
        // Here you could find awesome example for this option:
        // http://lxr.free-electrons.com/source/tools/testing/selftests/vm/hugepage-shm.c
        uint32_t required_number_of_bytes = sizeof(subnet_counter_t) * number_of_ips;

        std::map<std::string, uint64_t> meminfo_map;

        bool parse_meminfo = parse_meminfo_into_map(meminfo_map);

        if (!parse_meminfo) {
            std::cerr << "Could not parse meminfo" << std::endl;
            exit(-1);
        }

        uint64_t required_number_of_hugetlb_pages = ceil(required_number_of_bytes / meminfo_map["Hugepagesize"]);

        // std::cout << "We need least: " << required_number_of_hugetlb_pages << " of huge TLB pages" << std::endl;

        if (meminfo_map["HugePages_Free"] < required_number_of_hugetlb_pages) {
            // std::cerr << "We need " << required_number_of_hugetlb_pages << " hugetlb pages. But we have only: " <<
            // meminfo_map["HugePages_Free"] << std::endl;

            std::cerr << "Let's try to allocated required number of pages" << std::endl;
            std::string allocate_required_number_of_huge_pages =
                "echo " + std::to_string(required_number_of_hugetlb_pages) + "> /proc/sys/vm/nr_hugepages";

            exec(allocate_required_number_of_huge_pages);
        }


        // If huge tlb pages allocation failed
        uint64_t we_have_huge_tlb_memory = meminfo_map["Hugepagesize"] * meminfo_map["HugePages_Free"];

        if (we_have_huge_tlb_memory < required_number_of_bytes) {
            std::cerr << "We need least " << required_number_of_bytes
                      << " bytes but we have free only: " << we_have_huge_tlb_memory << std::endl;
            std::cerr << "Total number of huge pages is: " << meminfo_map["HugePages_Total"] << std::endl;
            exit(-1);
        }

        // Also we teed to tune kernel options about maximum shm memory segment size and overall shm memory size for
        // whole system becuase by default they are pretty low


        // std::cerr << "We need " << required_number_of_bytes << " bytes"<< std::endl;

        // TODO: please use print to handle for correct error handling because echo ignores all write errors
        std::string increase_shm_all_command = "echo " + std::to_string(required_number_of_bytes) + " > /proc/sys/kernel/shmall";
        std::string increase_shm_max_command = "echo " + std::to_string(required_number_of_bytes) + " > /proc/sys/kernel/shmmax";

        exec(increase_shm_all_command);
        exec(increase_shm_max_command);

        // Let's check new values right now!

        int shm_all_value        = 0;
        bool read_shm_all_result = read_integer_from_file("/proc/sys/kernel/shmall", shm_all_value);

        if (!read_shm_all_result) {
            std::cerr << "Could not read shm all from /proc" << std::endl;
            exit(1);
        }

        int shm_max_value        = 0;
        bool read_shm_max_result = read_integer_from_file("/proc/sys/kernel/shmmax", shm_max_value);

        if (!read_shm_max_result) {
            std::cerr << "Could not read shm max from /proc" << std::endl;
            exit(1);
        }

        if (shm_all_value < required_number_of_bytes) {
            std::cerr << "Could not set shm all to required value" << std::endl;
            exit(1);
        }

        if (shm_max_value < required_number_of_bytes) {
            std::cerr << "Could not set shm max to required value" << std::endl;
            exit(1);
        }

        /*
        In 3.8 or more recent we could use SHM_HUGE_2MB and SHM_HUGE_1GB flag options! But unfortunately on Ubuntu 14.04
        we haven't this
        */
        auto ipc_key = generate_ipc_key();

        if (ipc_key == 0) {
            std::cerr << "Failed to generate ipc key" << std::endl;
            exit(1);
        }

        // std::cout << "IPC key is: " << ipc_key << std::endl;

        int shmid = shmget(ipc_key, required_number_of_bytes, SHM_HUGETLB | IPC_CREAT | SHM_R | SHM_W);

        if (shmid == -1) {
            std::cerr << "shmget failed with code: " << errno << " error as text: " << strerror(errno) << std::endl;
            exit(-1);
        }

        // std::cerr << "Correctly allocated hugetlb" << std::endl;

        data_counter_c_array_ptr_huge_tlb = (subnet_counter_t*)shmat(shmid, 0, 0);

        if (data_counter_c_array_ptr_huge_tlb == (subnet_counter_t*)-1) {
            std::cerr << "Could not get address of  TLB shm memory" << std::endl;
            exit(2);
        }

        // We need to fill memory with allocated structures
        for (uint32_t i = 0; i < number_of_ips; i++) {
            subnet_counter_t new_blak_map_element;

            memcpy(&data_counter_c_array_ptr_huge_tlb[i], &new_blak_map_element, sizeof(new_blak_map_element));
        }

        std::cout << "C array preallocated with huge tlb: ";
        run_tests(packet_collector_thread_c_array_huge_tlb);

        // std::cerr << "Deallocate tlb" << std::endl;

        // That's very important! Without this option allocated huge tlb memory will be accounted in "HugePages_Rsvd" of
        // /proc/meminfo.
        // I'm not sure it's dangerous but will be fine to close all handles properly
        shmctl(shmid, IPC_RMID, NULL);
    }


    if (test_clock_gettime_monotonic) {
        std::cout << "clock_gettime CLOCK_MONOTONIC: ";
        run_tests(packet_collector_time_calculaitons_monotonic);
    }

    // According to https://fossies.org/dox/glibc-2.23/sysdeps_2unix_2clock__gettime_8c_source.html clock_gettime with
    // CLOCK_REALTIME is a just shortcut for gettimeofday
    if (test_clock_gettime_realtime) {
        std::cout << "clock_gettime CLOCK_REALTIME: ";
        run_tests(packet_collector_time_calculaitons);
    }

    if (test_gettimeofday) {
        std::cout << "gettimeofday: ";
        run_tests(packet_collector_time_calculaitons_gettimeofday);
    }

    if (test_monotonic_coarse) {
        std::cout << "clock_gettime CLOCK_MONOTONIC_COARSE: ";
        run_tests(packet_collector_time_calculaitons_monotonic_coarse);
    }
}
