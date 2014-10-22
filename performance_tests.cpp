#include <map>
#include <iostream>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>
#include <unordered_map>

#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>

// apt-get install -y libtbb-dev 
#include "tbb/concurrent_unordered_map.h"

typedef struct {
    unsigned  int in_bytes;
    unsigned  int out_bytes;
    unsigned  int in_packets;
    unsigned  int out_packets;
    
    // Additional data for correct attack protocol detection
    unsigned  int tcp_in_packets;
    unsigned  int tcp_out_packets;
    unsigned  int tcp_in_bytes;
    unsigned  int tcp_out_bytes;

    unsigned  int udp_in_packets;
    unsigned  int udp_out_packets;

    unsigned  int udp_in_bytes;
    unsigned  int udp_out_bytes;
} map_element;


std::map <uint32_t, map_element> DataCounter;
boost::mutex data_counter_mutex;

std::unordered_map <uint32_t, map_element> DataCounterUnordered;
tbb::concurrent_unordered_map <uint32_t, map_element> DataCounterUnorderedConcurrent;

using namespace std;

int number_of_ips = 100000;
int number_of_retries = 100;

// 83 seconds
// without mutexes segmentation fault
void packet_collector_thread_std_map() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for(uint32_t i = 0; i < number_of_ips; i++) {
            data_counter_mutex.lock();
            DataCounter[i].udp_in_bytes++;
            data_counter_mutex.unlock();
        }
    }
}

// 52 seconds
// without mutexes segmentation fault
void packet_collector_thread_unordered_map() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for(uint32_t i = 0; i < number_of_ips; i++) {
            data_counter_mutex.lock();
            DataCounterUnordered[i].udp_in_bytes++;
            data_counter_mutex.unlock();
        }   
    }   
}

void packet_collector_thread_unordered_concurrent_map() {
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for(uint32_t i = 0; i < number_of_ips; i++) {
            DataCounterUnorderedConcurrent[i].udp_in_bytes++;
        }   
    }   
}

int run_tests(void (*tested_function)(void)) {
    timespec start_time;
    clock_gettime(CLOCK_REALTIME, &start_time);

    std::cout<<"Run threads"<<endl;
    boost::thread* threads[8];
    for (int i = 0; i < 9; i++) {
        threads[i] = new boost::thread(tested_function);
    }

    std::cout<<"All threads started"<<endl;

    std::cout<<"Wait for finishing"<<endl;
    for (int i = 0; i < 9; i++) {
        threads[i]->join();
    }
    cout<<"All threads finished"<<endl;

    timespec finish_time;
    clock_gettime(CLOCK_REALTIME, &finish_time);

    double total_operations = number_of_ips*number_of_retries*8;
    std::cout<<"Seconds: "<<finish_time.tv_sec - start_time.tv_sec<<std::endl;
    std::cout<<"Operations per second: "<<int(total_operations/(finish_time.tv_sec - start_time.tv_sec))<<endl;
}

int main() {
    std::cout<<"Standard map"<<endl;
    run_tests(packet_collector_thread_std_map);
    std::cout<<"Standard unordered map from C++11"<<endl;
    run_tests(packet_collector_thread_unordered_map);
    std::cout<<"Standard unordered concurrent map from Intel TBB"<<endl; 
    run_tests(packet_collector_thread_unordered_concurrent_map);

}
