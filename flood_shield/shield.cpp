#include "picohttpparser.h"
#include "pfring.h"
#include <sys/time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <numeric>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <list>

/* Prototypes */
void parse_packet_pf_ring(const struct pfring_pkthdr *packet_header, const u_char *packetptr, const u_char *user_bytes);
int shield();
int extract_bit_value(uint8_t num, int bit);
std::string convert_ip_as_integer_to_string(uint32_t ip_in_host_byte_order);

// https://www.mppmu.mpg.de/~huber/util/timevaldiff.c
double timevaldiff(struct timeval *starttime, struct timeval *finishtime) {
    double microsec = 0;

    microsec =  (finishtime->tv_sec -  starttime->tv_sec)  * 1000000;
    microsec += (finishtime->tv_usec - starttime->tv_usec);

    return microsec;
}

class moving_average_irregular_time_series {
    public:
        moving_average_irregular_time_series() {
            gettimeofday(&last_sample_time, NULL);
            moving_average = 0;
            
            // 5 seconds, calculated in microseconds
            tau = 5 * 1000 * 1000;
        }
        struct timeval last_sample_time;
        double moving_average; 
        double tau;        

        double increment() {
            return add_sample(1.0);
        }

        // http://www.eckner.com/papers/ts_alg.pdf
        // ts_alg_moving_average_with_time.pdf at DropBox
        // EMAeq
        double add_sample(double sample) {
            // Get current time
            struct timeval current_time;
            gettimeofday(&current_time, NULL);

            double difference_microsec = timevaldiff(&this->last_sample_time, &current_time);
            // std::cout<<"diff time: "<<difference_msec<<std::endl; 
            double w = exp( -difference_microsec / tau);

            std::cout<<"w:"<<w<<std::endl;

            moving_average = moving_average * w + sample * (1.0 - w);

            this->last_sample_time = current_time;

            return moving_average; 
        }
};

int main() {
    shield();
}

// http://stackoverflow.com/questions/14528233/bit-masking-in-c-how-to-get-first-bit-of-a-byte
int extract_bit_value(uint8_t num, int bit) {
    if (bit > 0 && bit <= 8) {
        return ( (num >> (bit-1)) & 1 );
    } else {
        return 0;
    }
}

int shield() {
    unsigned int snaplen = 1500;
    u_int8_t wait_for_packet = 1;
    u_int32_t flags = 0;
   
    flags |= PF_RING_PROMISC;
    flags |= PF_RING_DO_NOT_PARSE; 
    
    pfring* pf_ring_descr = pfring_open("eth4", snaplen, flags); 

    if (pf_ring_descr == NULL) {
        printf("Can't create PF_RING descriptor: %s\n", strerror(errno));
        exit(1);
    }

    pfring_set_application_name(pf_ring_descr, (char*)"flood_shield");
    
    int pfring_set_socket_mode_result =  pfring_set_socket_mode(pf_ring_descr, recv_only_mode);
    if (pfring_set_socket_mode_result != 0) {
        printf("Function pfring_set_socket_mode failed\n");
    } 

    if (pfring_enable_ring(pf_ring_descr) != 0) {
        printf("Can't enable PF_RING\n");
        exit(1);
    }

    pfring_loop(pf_ring_descr, parse_packet_pf_ring, (u_char*)NULL, wait_for_packet);
}

typedef struct leaf_struct {
    time_t* last_modified_time;
} leaf_struct;


//typedef std::map<std::string, moving_average_irregular_time_series> map_struct_for_counters_t;
typedef std::map<std::string, std::vector<unsigned int> > map_struct_for_counters_t;
map_struct_for_counters_t hashmap_for_counters;

int parse_http_request(const u_char* buf, int packet_len, uint32_t client_ip_as_integer) {
    std::string client_ip = convert_ip_as_integer_to_string(client_ip_as_integer);

    const char *method, *path;
    int pret, minor_version;
    struct phr_header headers[100];
    size_t buflen = 0, prevbuflen = 0, method_len, path_len, num_headers;
    ssize_t rret;

    prevbuflen = buflen;
    buflen += packet_len;

    /* parse the request */
    num_headers = sizeof(headers) / sizeof(headers[0]);

    pret = phr_parse_request((const char*)buf, buflen, &method, &method_len, &path, &path_len, &minor_version, headers, &num_headers, prevbuflen);

    if (pret > 0) {
        // printf("We successfully parsed the request\n");
    } else {
        printf("Parser failed\n");
        return 1;
    }

    std::string host_string = "";
    std::string method_string = std::string(method, method_len);
    std::string path_string = std::string(path, (int)path_len);

    // You could find examples for parser here: https://github.com/h2o/picohttpparser/blob/master/test.c
    for (int i = 0; i != num_headers; ++i) {
        if (strstr(headers[i].name, "Host") != NULL) {
            host_string = std::string(headers[i].value, (int)headers[i].value_len);
        }

        //printf("%.*s: %.*s\n", (int)headers[i].name_len, headers[i].name,
        //    (int)headers[i].value_len, headers[i].value);
    }

    std::string hash_key = client_ip + ":" + host_string + ":" + method_string + ":" + path_string; 
    //printf("key: %s\n", hash_key.c_str());
    
    map_struct_for_counters_t::iterator itr = hashmap_for_counters.find(hash_key);

    // We will ban on 5 request per second
    unsigned int ban_limit = 10; 
    unsigned int recalculation_time = 5;

    struct timeval current_time;
    gettimeofday(&current_time, NULL);

    unsigned int current_second = current_time.tv_sec % recalculation_time;

    if (itr == hashmap_for_counters.end()) {
        // not found, create new record
        hashmap_for_counters[hash_key] = std::vector<unsigned int>();
        hashmap_for_counters[hash_key].resize(recalculation_time);
        std::fill(hashmap_for_counters[hash_key].begin(), hashmap_for_counters[hash_key].end(), 0);
        hashmap_for_counters[hash_key][current_second] = 1;
    } else {
        int index_for_nullify = abs(recalculation_time - current_second);
        itr->second[index_for_nullify] = 0;        

        // std::cout<<"I process "<<current_second<<" and will zero: "<<index_for_nullify<<std::endl;
        itr->second[current_second]++;
    
        unsigned long requests_per_calculation_period = std::accumulate(itr->second.begin(), itr->second.end(), 0);
        //std::cout<<"rps: "<<requests_per_minute<<std::endl;
        double request_per_second = (double)requests_per_calculation_period / (double)recalculation_time;

        if (request_per_second > ban_limit) {
            std::cout<<"We will ban this IP: "<<client_ip<<std::endl;
        }        
    }
    
    return 0;
}

std::string convert_ip_as_integer_to_string(uint32_t ip_in_host_byte_order) {
    struct sockaddr_in sa; 
    // convert host byte order to network byte order
    sa.sin_addr.s_addr = htonl(ip_in_host_byte_order);
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN);
    
    return std::string(str);
}

void parse_packet_pf_ring(const struct pfring_pkthdr *packet_header, const u_char *packetptr, const u_char *user_bytes) {
    memset((void*)&packet_header->extended_hdr.parsed_pkt, 0, sizeof(packet_header->extended_hdr.parsed_pkt));
    pfring_parse_pkt((u_char*)packetptr, (struct pfring_pkthdr*)packet_header, 4, 1, 0);
    
    // Ignore tcp handshake requests
    if (extract_bit_value(packet_header->extended_hdr.parsed_pkt.tcp.flags, 2) or // SYN
        extract_bit_value(packet_header->extended_hdr.parsed_pkt.tcp.flags, 1)    // FIN
    ) {
        // printf("!!! skip syn/fin !!!\n");
        return;
    }

    // Skip zero length packets (also part of tcp/ip handshake)
    if (packet_header->len == packet_header->extended_hdr.parsed_pkt.offset.payload_offset) {
        // printf("Skip zero length packet\n");
        return;
    }

    // We process only packets arrives at 80 port
    // TBD: add SNI support
    if (packet_header->extended_hdr.parsed_pkt.l4_dst_port != 80) {
        //char print_buffer[512];
        //pfring_print_parsed_pkt(print_buffer, 512, (u_char*)packetptr, &packet_header);
        //printf("%s", print_buffer);
        return;
    } 

    //printf("We got request to 80 port\n");
    //printf("payload shift: %d\n", packet_header.extended_hdr.parsed_pkt.offset.payload_offset);

    int result = parse_http_request(packetptr + packet_header->extended_hdr.parsed_pkt.offset.payload_offset,
        packet_header->len,
        packet_header->extended_hdr.parsed_pkt.ip_src.v4
    ); 
    
    if (result != 0) {
        char print_buffer[512];
        pfring_print_parsed_pkt(print_buffer, 512, (u_char*)packetptr, packet_header);
        printf("%s", print_buffer);
    }
}
