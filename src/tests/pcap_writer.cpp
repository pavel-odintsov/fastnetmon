#include <iostream>
#include <stdlib.h>
#include <stdint.h>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <sys/time.h>

#include "../fastnetmon_pcap_format.h"


int main() {
    std::string pcap_file_path = "/tmp/fastnetmon_example.pcap" ;

    int filedesc = open(pcap_file_path.c_str(), O_WRONLY|O_CREAT);
    
     if (filedesc <= 0) {
        printf("Can't open dump file for writing");
        return -1;
    }

    struct fastnetmon_pcap_file_header pcap_header;
    pcap_header.magic = 0xa1b2c3d4;
    pcap_header.version_major = 2;
    pcap_header.version_minor = 4;
    pcap_header.thiszone = 0;
    pcap_header.sigfigs = 0;
    // TODO: fix this!!!
    pcap_header.snaplen = 1500;
    // http://www.tcpdump.org/linktypes.html
    // DLT_EN10MB = 1
    pcap_header.linktype = 1;

    ssize_t file_header_wrote_bytes = write(filedesc, &pcap_header, sizeof(struct fastnetmon_pcap_file_header));

    if (file_header_wrote_bytes != sizeof(struct fastnetmon_pcap_file_header)) {
        printf("Can't write pcap file header\n");
        return -1;
    }

    struct fastnetmon_pcap_pkthdr pcap_packet_header;
    
    unsigned char payload1[] = { 0x90,0xE2,0xBA,0x83,0x3F,0x25,0x90,0xE2,0xBA,0x2C,0xCB,0x02,0x08,0x00,0x45,0x00,0x00,0x2E,0x00,0x00,0x00,0x00,0x40,0x06,0x69,0xDC,0x0A,0x84,0xF1,0x83,0x0A,0x0A,0x0A,0xDD,0x04,0x01,0x00,0x50,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x50,0x02,0x00,0x0A,0x9A,0x92,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

    // TODO: performance killer! Check it!
    bool we_do_timestamps = true;

    struct timeval current_time;
    current_time.tv_sec  = 0;
    current_time.tv_usec = 0;

    if (we_do_timestamps) {
        gettimeofday(&current_time, NULL);
    }

    pcap_packet_header.ts_sec  = current_time.tv_sec; 
    pcap_packet_header.ts_usec = current_time.tv_usec; 

    pcap_packet_header.incl_len = sizeof(payload1);
    pcap_packet_header.orig_len = sizeof(payload1);

    ssize_t packet_header_wrote_bytes = write(filedesc, &pcap_packet_header, sizeof(struct fastnetmon_pcap_pkthdr));

    if (packet_header_wrote_bytes != sizeof(struct fastnetmon_pcap_pkthdr)) {
        printf("Can't write pcap packet header\n"); 
        return -1;
    }

    ssize_t packet_payload_wrote_bytes = write(filedesc, payload1, sizeof(payload1));

    if (packet_payload_wrote_bytes != sizeof(payload1)) {
        printf("Can't write packet payload");
        return -1;
    }

    close(filedesc);
}
