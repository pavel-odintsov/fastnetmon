#include "../fastnetmon_packet_parser.h"
#include "picohttpparser.h"
#include <pcap.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

void process_packet(u_char *user, struct pcap_pkthdr *packethdr, const u_char *packetptr);
int shield();

int main() {
    shield();
}

int shield() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr = pcap_create("eth0", errbuf);

    if (descr == NULL) {
        printf("Can't create pcap descriptor\n");
        exit(1);
    }

    unsigned int pcap_buffer_size_mbytes = 10;
    int set_buffer_size_res = pcap_set_buffer_size(descr, pcap_buffer_size_mbytes * 1024 * 1024);

    if (set_buffer_size_res != 0 ) {
        printf("Can't set buffer size due to error: %s", set_buffer_size_res);
        exit(1);
    } 

    if (pcap_activate(descr) != 0) {
        printf("Call pcap_activate was failed");
        exit(1);
    }

    pcap_loop(descr, -1, (pcap_handler)process_packet, NULL);
}

void parse_http_request(const u_char* buf, int packet_len) {
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
        printf("We successfully parsed the request\n");
    } else {
        printf("Parser failed");
        return;
    }

    printf("request is %d bytes long\n", pret);
    printf("method is %.*s\n", (int)method_len, method);
    printf("path is %.*s\n", (int)path_len, path);
    printf("HTTP version is 1.%d\n", minor_version);
    printf("headers:\n");
    for (int i = 0; i != num_headers; ++i) {
        printf("%.*s: %.*s\n", (int)headers[i].name_len, headers[i].name,
            (int)headers[i].value_len, headers[i].value);
    }
}

void process_packet(u_char *user, struct pcap_pkthdr *packethdr, const u_char *packetptr) {
    struct pfring_pkthdr packet_header;
    memset(&packet_header, 0, sizeof(packet_header));
    packet_header.len = packethdr->len;
    packet_header.caplen = packethdr->caplen;

    fastnetmon_parse_pkt((u_char*)packetptr, &packet_header, 4, 1, 0);

    // We process only packets arrives at 80 port
    // TBD: add SNI support
    if (packet_header.extended_hdr.parsed_pkt.l4_dst_port != 80) {
        return;
    }

    parse_http_request(packetptr, packethdr->len);    
}
