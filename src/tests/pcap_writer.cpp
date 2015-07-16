#include <iostream>
#include <stdlib.h>
#include <stdint.h>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <sys/time.h>

#include "../fastnetmon_pcap_format.h"
#include "../packet_storage.h"

int main() {
    packet_storage_t packet_storage;
   
    // We specify in in packets
    if (!packet_storage.allocate_buffer(500)) {
        printf("Can't allocate buffer");
        return -1;
    }

    unsigned char payload1[] = { 0x90,0xE2,0xBA,0x83,0x3F,0x25,0x90,0xE2,0xBA,0x2C,0xCB,0x02,0x08,0x00,0x45,0x00,0x00,0x2E,0x00,0x00,0x00,0x00,0x40,0x06,0x69,0xDC,0x0A,0x84,0xF1,0x83,0x0A,0x0A,0x0A,0xDD,0x04,0x01,0x00,0x50,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x50,0x02,0x00,0x0A,0x9A,0x92,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

    if (!packet_storage.write_packet(payload1, sizeof(payload1))) {
        printf("Can't write packet to the storage\n");
        return -1;
    }


    // Dump buffer to memory
    std::string pcap_file_path = "/tmp/fastnetmon_example.pcap";

    int filedesc = open(pcap_file_path.c_str(), O_WRONLY|O_CREAT);

     if (filedesc <= 0) {
        printf("Can't open dump file for writing");
        return -1;
    }

    std::cout << "Used size: " << packet_storage.get_used_memory() << std::endl;

    ssize_t wrote_bytes = write(filedesc, (void*)packet_storage.get_buffer_pointer(), packet_storage.get_used_memory());

    if (wrote_bytes != packet_storage.get_used_memory()) {
        printf("Can't write data to the file\n");
        return -1;
    }

    close(filedesc);

    return(0);
}
