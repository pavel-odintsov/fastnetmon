#include <vector>
#include <iostream>
#include <algorithm>
#include <map>

#include <stdio.h>
#include <stdlib.h>

#include "../fastnetmon_types.h"

// It's very raw API implementation for connection tracking code. Due to HUGE amount of collisions it's very slow: ~1Mpps
// For performance it's very close to std::map but much times more buggy :)

// https://code.google.com/p/smhasher/source/browse/trunk/MurmurHash2.cpp
// 64-bit hash for 64-bit platforms
#define BIG_CONSTANT(x) (x##LLU)
uint64_t MurmurHash64A(const void* key, int len, uint64_t seed) {
    const uint64_t m = BIG_CONSTANT(0xc6a4a7935bd1e995);
    const int r = 47;

    uint64_t h = seed ^ (len * m);

    const uint64_t* data = (const uint64_t*)key;
    const uint64_t* end = data + (len / 8);

    while (data != end) {
        uint64_t k = *data++;

        k *= m;
        k ^= k >> r;
        k *= m;

        h ^= k;
        h *= m;
    }

    const unsigned char* data2 = (const unsigned char*)data;

    switch (len & 7) {
    case 7:
        h ^= uint64_t(data2[6]) << 48;
    case 6:
        h ^= uint64_t(data2[5]) << 40;
    case 5:
        h ^= uint64_t(data2[4]) << 32;
    case 4:
        h ^= uint64_t(data2[3]) << 24;
    case 3:
        h ^= uint64_t(data2[2]) << 16;
    case 2:
        h ^= uint64_t(data2[1]) << 8;
    case 1:
        h ^= uint64_t(data2[0]);
        h *= m;
    };

    h ^= h >> r;
    h *= m;
    h ^= h >> r;

    return h;
}

class conntrack_hash_struct_for_simple_packet_t {
    public:
        uint32_t src_ip;
        uint32_t dst_ip;
        
        uint16_t source_port;
        uint16_t destination_port;

        unsigned int protocol;
        bool operator==(const conntrack_hash_struct_for_simple_packet_t& rhs) {
            // TODO: not so smart, we should fix this!
            return memcmp(this, &rhs, sizeof(conntrack_hash_struct_for_simple_packet_t)) == 0; 
        }
};

// Extract only important for us fields from main simple_packet structure
bool convert_simple_packet_toconntrack_hash_struct(simple_packet& packet, conntrack_hash_struct_for_simple_packet_t& conntrack_struct) {
    conntrack_struct.src_ip = packet.src_ip;
    conntrack_struct.dst_ip = packet.dst_ip;

    conntrack_struct.protocol = packet.protocol;

    conntrack_struct.source_port = packet.source_port;
    conntrack_struct.destination_port = packet.destination_port; 
}

// Class prototype for connection tracking
typedef std::vector< conntrack_hash_struct_for_simple_packet_t > vector_of_connetrack_structs_t;
class connection_tracking_fast_storage_t {
    public:
        connection_tracking_fast_storage_t(unsigned int structure_size) {
            murmur_seed = 13;
            max_vector_size = 0;    

            number_of_buckets = structure_size;

            buckets_storage.reserve(structure_size); 
        }
    
        uint64_t get_bucket_number(conntrack_hash_struct_for_simple_packet_t& element) {
            uint64_t conntrack_hash = MurmurHash64A(&element, sizeof(conntrack_hash_struct_for_simple_packet_t), murmur_seed);

            return conntrack_hash % number_of_buckets; 
        }

        bool lookup(conntrack_hash_struct_for_simple_packet_t* element) {
            uint64_t bucket_number = get_bucket_number(*element);            

            vector_of_connetrack_structs_t* vector_pointer = &buckets_storage[bucket_number]; 

            unsigned int vector_size = vector_pointer->size();
            if (vector_size > max_vector_size) {
                max_vector_size = vector_size;

                if (max_vector_size > 100) {
                    printf("We got %u collisions for key %llu\n", max_vector_size, bucket_number);
                }
            }
            
            if (vector_size == 0) {
                return false;
            }

            vector_of_connetrack_structs_t::iterator itr = std::find(vector_pointer->begin(), vector_pointer->end(), *element);

            if (itr == vector_pointer->end()) {
                return false;
            }
            
            return true;
        }

        bool insert(conntrack_hash_struct_for_simple_packet_t element) {
            uint64_t bucket_number = get_bucket_number(element);

            buckets_storage[bucket_number].push_back(element); 
        }
    public:
        unsigned int number_of_buckets;
        std::vector<vector_of_connetrack_structs_t> buckets_storage;
        unsigned int murmur_seed;
        // conntrack_hash_struct_for_simple_packet_t conntrack_structure; 
        unsigned int max_vector_size;
};

connection_tracking_fast_storage_t my_conntrack_storage(32000);


int main() {
    // fake data
    char data[1500];

    simple_packet current_packet;
    // parse_raw_packet_to_simple_packet((u_char*)data, length, current_packet); 
    
    conntrack_hash_struct_for_simple_packet_t conntrack_structure;
    convert_simple_packet_toconntrack_hash_struct(current_packet, conntrack_structure);


    if (my_conntrack_storage.lookup(&conntrack_structure)) {
        //printf("Already exists\n");
        // found it
    } else {
        //printf("New\n");
        my_conntrack_storage.insert(conntrack_structure);
    }

}
