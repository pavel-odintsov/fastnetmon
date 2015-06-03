#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>
#include <ctime>
#include <vector>
#include <map>
#include <math.h>
#include <boost/unordered_map.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../libpatricia/patricia.h"

using namespace std;

// main data structure for storing traffic and speed data for all our IPs
class map_element {
    public:
    map_element()
    : in_bytes(0), out_bytes(0), in_packets(0), out_packets(0), tcp_in_packets(0),
      tcp_out_packets(0), tcp_in_bytes(0), tcp_out_bytes(0), udp_in_packets(0), udp_out_packets(0),
      udp_in_bytes(0), udp_out_bytes(0), in_flows(0), out_flows(0), icmp_in_packets(0),
      icmp_out_packets(0), icmp_in_bytes(0), icmp_out_bytes(0) {
    }
    unsigned int in_bytes;
    unsigned int out_bytes;
    unsigned int in_packets;
    unsigned int out_packets;

    // Additional data for correct attack protocol detection
    unsigned int tcp_in_packets;
    unsigned int tcp_out_packets;
    unsigned int tcp_in_bytes;
    unsigned int tcp_out_bytes;

    unsigned int udp_in_packets;
    unsigned int udp_out_packets;
    unsigned int udp_in_bytes;
    unsigned int udp_out_bytes;

    unsigned int icmp_in_packets;
    unsigned int icmp_out_packets;
    unsigned int icmp_in_bytes;
    unsigned int icmp_out_bytes;

    unsigned int in_flows;
    unsigned int out_flows;
};

typedef vector<map_element> vector_of_counters;
typedef std::map<unsigned long int, vector_of_counters*> map_of_vector_counters;

typedef std::pair<unsigned long int, vector_of_counters*> pair_of_subnets_with_key;

typedef vector<pair_of_subnets_with_key> vector_of_vector_counters;

map_of_vector_counters SubnetVectorMap;

vector_of_vector_counters SubnetVectorVector;

#include <algorithm>

void subnet_vectors_allocator(prefix_t* prefix, void* data) {
    uint32_t subnet_as_integer = prefix->add.sin.s_addr;
    u_short bitlen = prefix->bitlen;

    int network_size_in_ips = pow(2, 32 - bitlen);
    network_size_in_ips = 1;

    SubnetVectorMap[subnet_as_integer] = new vector_of_counters(network_size_in_ips);

    pair_of_subnets_with_key my_pair;
    my_pair.first = subnet_as_integer;
    my_pair.second = new vector_of_counters(network_size_in_ips);

    SubnetVectorVector.push_back(my_pair);
}

void suxx_func(unsigned long suxx) {
}

uint32_t convert_ip_as_string_to_uint(string ip) {
    struct in_addr ip_addr;
    inet_aton(ip.c_str(), &ip_addr);

    // in network byte order
    return ip_addr.s_addr;
}

bool mysortfunction(pair_of_subnets_with_key i, pair_of_subnets_with_key j) {
    return (i.first < j.first);
}

int main() {
    patricia_tree_t* lookup_tree;
    lookup_tree = New_Patricia(32);

    make_and_lookup(lookup_tree, "46.36.216.0/21");
    make_and_lookup(lookup_tree, "159.253.16.0/21");
    make_and_lookup(lookup_tree, "5.45.112.0/21");
    make_and_lookup(lookup_tree, "5.45.120.0/21");
    make_and_lookup(lookup_tree, "5.101.112.0/21");
    make_and_lookup(lookup_tree, "5.101.120.0/21");
    make_and_lookup(lookup_tree, "185.4.72.0/22");
    make_and_lookup(lookup_tree, "181.114.240.0/20");
    make_and_lookup(lookup_tree, "193.42.142.0/24");

    // patricia_process (lookup_tree, (void_fn_t)subnet_vectors_allocator);
    // std::sort(SubnetVectorVector.begin(), SubnetVectorVector.end(), mysortfunction);

    prefix_t prefix_for_check_adreess;
    prefix_for_check_adreess.family = AF_INET;
    prefix_for_check_adreess.bitlen = 32;
    patricia_node_t* found_patrica_node = NULL;
    // prefix_for_check_adreess.add.sin.s_addr = 123123123;

    // std::map <unsigned int, bool> lpm_cache;
    // Without cache: 16.7 million of operations

    int i_iter = 100;
    // Million operations
    int j_iter = 1000000;

    // printf("Preallocate table\n");
    // Iterate over all our IP addresses
    // for (int j = 0; j < j_iter; j++) {
    //    for (int i = 0; i < i_iter; i++) {
    //        lpm_cache[i*j] = true;
    //    }
    //}

    printf("Start tests\n");
    timespec start_time;
    clock_gettime(CLOCK_REALTIME, &start_time);

    prefix_for_check_adreess.add.sin.s_addr = convert_ip_as_string_to_uint("159.253.17.1");

    for (int j = 0; j < j_iter; j++) {
        for (int i = 0; i < i_iter; i++) {
            // Random Pseudo IP
            // prefix_for_check_adreess.add.sin.s_addr = i*j;
            patricia_node_t* found_patrica_node =
            patricia_search_best2(lookup_tree, &prefix_for_check_adreess, 1);

            unsigned long destination_subnet = 0;

            suxx_func(found_patrica_node != NULL);

            if (found_patrica_node != NULL) {
                destination_subnet = found_patrica_node->prefix->add.sin.s_addr;
                suxx_func(destination_subnet);
                // std::cout<<"*";
                /*
                for (vector_of_vector_counters::iterator it = SubnetVectorVector.begin() ; it !=
                SubnetVectorVector.end(); ++it) {
                    std::cout<<it->first<<",";
                    if (it->first == destination_subnet) {
                        suxx_func(destination_subnet);
                    }
                }

                std::cout<<"\n";
                */

                /*
                map_of_vector_counters::iterator itr;
                itr = SubnetVectorMap.find(destination_subnet);

                if (itr == SubnetVectorMap.end()) {

                } else {
                    suxx_func(destination_subnet);
                }
                */
            }

            // prefix_for_check_adreess.add.sin.s_addr = i*j + 1;
            // patricia_node_t* found_second_patrica_node = patricia_search_best(lookup_tree,
            // &prefix_for_check_adreess);

            // std::map <unsigned int, bool>::iterator itr = lpm_cache.find(i*j);

            // if (itr !=  lpm_cache.end()) {
            // found it!
            //} else {
            // cache miss
            // bool result = patricia_search_best(lookup_tree, &prefix_for_check_adreess) != NULL;
            // lpm_cache[i*j] = result;
            // not found!
            //}
        }
    }

    timespec finish_time;
    clock_gettime(CLOCK_REALTIME, &finish_time);

    unsigned long used_seconds = finish_time.tv_sec - start_time.tv_sec;
    unsigned long total_ops = i_iter * j_iter;
    float megaops_per_second = (float)total_ops / (float)used_seconds / 1000000;

    printf("Total time is %d seconds total ops: %d\nMillion of ops per second: %.1f\n",
           used_seconds, total_ops, megaops_per_second);

    Destroy_Patricia(lookup_tree, (void_fn_t)0);
}
