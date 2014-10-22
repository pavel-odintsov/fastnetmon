#include <map>
#include <iostream>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>
#include <unordered_map>

#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>

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

using namespace std;

int number_of_ips = 100000;
int number_of_retries = 100;

// 83 seconds
// without mutexes segmentation fault
void packet_collector_thread_std_map() {
    std::cout<<"Start thread"<<endl;
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
    std::cout<<"Start thread"<<endl;
    for (int iteration = 0; iteration < number_of_retries; iteration++) {
        for(uint32_t i = 0; i < number_of_ips; i++) {
            data_counter_mutex.lock();
            DataCounterUnordered[i].udp_in_bytes++;
            data_counter_mutex.unlock();
        }   
    }   
}

int main() {
    timespec start_time;
    clock_gettime(CLOCK_REALTIME, &start_time);

    std::cout<<"Run threads"<<endl;
    boost::thread* threads[8];
    for (int i = 0; i < 9; i++) {
        cout<<"Run thread: "<<i<<endl;
        threads[i] = new boost::thread(packet_collector_thread_std_map);
    }

    std::cout<<"All threads started"<<endl;

    std::cout<<"Wait for finishing"<<endl;
    for (int i = 0; i < 9; i++) {
        threads[i]->join();
    }
    cout<<"All threads finished"<<endl;

    timespec finish_time;
    clock_gettime(CLOCK_REALTIME, &finish_time);

    std::cout<<"Seconds: "<<finish_time.tv_sec - start_time.tv_sec<<std::endl;
}
