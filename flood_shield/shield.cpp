#include "picohttpparser.h"
#include "pfring.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

void parse_packet_pf_ring(const struct pfring_pkthdr *packet_header, const u_char *packetptr, const u_char *user_bytes);
int shield();
int extract_bit_value(uint8_t num, int bit);

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

int parse_http_request(const u_char* buf, int packet_len) {
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

    /*
    printf("request is %d bytes long\n", pret);
    printf("method is %.*s\n", (int)method_len, method);
    printf("path is %.*s\n", (int)path_len, path);
    printf("HTTP version is 1.%d\n", minor_version);
    printf("headers:\n");
    for (int i = 0; i != num_headers; ++i) {
        printf("%.*s: %.*s\n", (int)headers[i].name_len, headers[i].name,
            (int)headers[i].value_len, headers[i].value);
    }
    */

    return 0;
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

    int result = parse_http_request(packetptr + packet_header->extended_hdr.parsed_pkt.offset.payload_offset, packet_header->len);    
    
    if (result != 0) {
        char print_buffer[512];
        pfring_print_parsed_pkt(print_buffer, 512, (u_char*)packetptr, packet_header);
        printf("%s", print_buffer);
    }
}
