#include <map>
#include <iostream>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>
#include <unordered_map>
#include <locale.h>
#include <vector>

#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/unordered_map.hpp>

#include "../fastnetmon_types.h"

// apt-get install -y libtbb-dev
// g++ traffic_structures_performance_tests.cpp -std=c++11 -lboost_system  -lboost_thread -ltbb -I/opt/local/include -L/opt/local/lib
// Mac OS:
// g++ traffic_structures_performance_tests.cpp -std=c++11 -lboost_system_mt -lboost_thread_mt -ltbb -I/opt/local/include -L/opt/local/lib -g -pg

#ifndef __APPLE__
#include "tbb/concurrent_unordered_map.h"
#endif

std::map<uint32_t, map_element> DataCounter;
boost::mutex data_counter_mutex;

std::unordered_map<uint32_t, map_element> DataCounterUnordered;
std::unordered_map<uint32_t, map_element> DataCounterUnorderedPreallocated;

boost::unordered_map<uint32_t, map_element> DataCounterBoostUnordered;

#ifndef __APPLE__
tbb::concurrent_unordered_map<uint32_t, map_element> DataCounterUnorderedConcurrent;
#endif

std::vector<map_element> DataCounterVector;

using namespace std;

int number_of_ips = 10 * 1000 * 1000;
int number_of_retries = 1;

// #define enable_mutexex_in_test
unsigned int number_of_threads = 1;

// 83 seconds
// without mutexes segmentation fault
void packet_collector_thread_std_map() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexex_in_test
            data_counter_mutex.lock();
#endif
            DataCounter[i].udp_in_bytes++;

#ifdef enable_mutexex_in_test
            data_counter_mutex.unlock();
#endif
        }
    }
}

void packet_collector_thread_boost_unordered_map() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexex_in_test
            data_counter_mutex.lock();
#endif
            DataCounterBoostUnordered[i].udp_in_bytes++;
#ifdef enable_mutexex_in_test
            data_counter_mutex.unlock();
#endif
        }   
    }   
}

void packet_collector_thread_unordered_map() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexex_in_test
            data_counter_mutex.lock();
#endif
            DataCounterUnordered[i].udp_in_bytes++;
#ifdef enable_mutexex_in_test
            data_counter_mutex.unlock();
#endif
        }
    }
}

void packet_collector_thread_unordered_map_preallocated() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
#ifdef enable_mutexex_in_test
            data_counter_mutex.lock();
#endif
            DataCounterUnordered[i].udp_in_bytes++;
#ifdef enable_mutexex_in_test
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


#ifndef __APPLE__
void packet_collector_thread_unordered_concurrent_map() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for (uint32_t i = 0; i < number_of_ips; i++) {
            DataCounterUnorderedConcurrent[i].udp_in_bytes++;
        }
    }
}
#endif

// http://www.gnu.org/software/libc/manual/html_node/Elapsed-Time.html
int timeval_subtract(struct timeval* result, struct timeval* x, struct timeval* y) {
    /* Perform the carry for the later subtraction by updating y. */
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }

    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait. tv_usec is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}


int run_tests(void (*tested_function)(void)) {
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

    //cout << "All threads finished" << endl;

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

    double ops_per_second = total_operations / used_time;;
    double mega_ops_per_second = ops_per_second / 1000 / 1000;

    printf("%'.1f mega ops per second\n", mega_ops_per_second);
}

int main() {
    std::cout << "Element size: " << sizeof(map_element) << std::endl;

    std::cout << "std::map: ";
    run_tests(packet_collector_thread_std_map);
    DataCounter.clear();

#ifndef __APPLE__
    std::cout << "tbb::concurrent_unordered_map: ";
    run_tests(packet_collector_thread_unordered_concurrent_map);
    DataCounterUnorderedConcurrent.clear();
#endif

    // Boost unordered map
    std::cout << "boost::unordered_map: ";
    run_tests(packet_collector_thread_boost_unordered_map);
    DataCounterBoostUnordered.clear();

    std::cout << "std::unordered_map C++11: ";
    run_tests(packet_collector_thread_unordered_map);
    DataCounterUnordered.clear();

    // Preallocate hash buckets
    DataCounterUnorderedPreallocated.reserve( number_of_ips );
    std::cout << "std::unordered_map C++11 preallocated: ";
    run_tests(packet_collector_thread_unordered_map_preallocated);
    DataCounterUnorderedPreallocated.clear();

    // Preallocate vector
    DataCounterVector.reserve( number_of_ips );
    std::cout << "std::vector preallocated: ";
    run_tests(packet_collector_thread_vector);
    DataCounterVector.clear();
}
