#include <stdio.h>
#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

/* It's prototype for moc testing of FastNetMon, it's very useful for netflow or direct packet parsers debug */

/* 
   pcap dump format:
    global header: struct pcap_file_header
    packet header: struct fastnetmon_pcap_pkthdr
*/

// We can't use pcap_pkthdr from upstream because it uses 16 bytes timeval instead of 8 byte and broke everything
struct fastnetmon_pcap_pkthdr {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};

int pcap_reader(const char* pcap_file_path) {
    int filedesc = open(pcap_file_path, O_RDONLY);

    if (filedesc <= 0) {
        printf("Can't open dump file");
        return -1;
    } 

    struct pcap_file_header pcap_header;
    ssize_t file_header_readed_bytes = read(filedesc, &pcap_header, sizeof(struct pcap_file_header));

    if (file_header_readed_bytes != sizeof(struct pcap_file_header)) {
        printf("Can't read pcap file header");
    }

    // http://www.tcpdump.org/manpages/pcap-savefile.5.html
    if (pcap_header.magic == 0xa1b2c3d4 or pcap_header.magic == 0xd4c3b2a1) {
        // printf("Magic readed correctly\n");
    } else {
        printf("Magic in file header broken\n");
        return -2;
    }

    // Buffer for packets
    char packet_bufer[pcap_header.snaplen];

    unsigned int read_packets = 0; 
    while (1) {
        struct fastnetmon_pcap_pkthdr pcap_packet_header;
        ssize_t packet_header_readed_bytes = read(filedesc, &pcap_packet_header, sizeof(struct fastnetmon_pcap_pkthdr));
      
        if (packet_header_readed_bytes != sizeof(struct fastnetmon_pcap_pkthdr)) {
            // We haven't any packets 
            break;
        }

        if (pcap_packet_header.incl_len > pcap_header.snaplen) {
            printf("Please enlarge packet buffer! We got packet with size: %d but our buffer is %d bytes\n",
                pcap_packet_header.incl_len, pcap_header.snaplen);
            return -4;
        }

        ssize_t packet_payload_readed_bytes = read(filedesc, packet_bufer, pcap_packet_header.incl_len);
 
        if (pcap_packet_header.incl_len != packet_payload_readed_bytes) {
            printf("I read packet header but can't read packet payload\n");
            return -3;
        }

        // printf("packet payload read\n");
        
        read_packets++;
    }

    printf("I correctly read %d packets from this dump\n", read_packets);

    return 0;
}

int main() {
    pcap_reader("/root/ipfix_example_ipt_netflow_syn_flood.pcap");
    //pcap_reader("/Users/pavel-odintsov/Dropbox/ipfix_example_ipt_netflow_syn_flood.pcap");
}
