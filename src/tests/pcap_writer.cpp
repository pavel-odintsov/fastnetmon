#include <iostream>
#include <stdlib.h>
#include <stdint.h>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <sys/time.h>

#include "../fastnetmon_pcap_format.h"

class packet_storage_t {
    public:
        packet_storage_t() {
            memory_pointer = NULL;
            memory_pos = NULL;
            buffer_size = 0;

            packet_size = 1500;
        }

        bool allocate_buffer(unsigned int buffer_size_in_packets) {
            unsigned int memory_size_in_bytes = buffer_size_in_packets * (packet_size + sizeof(fastnetmon_pcap_pkthdr))
                + sizeof(fastnetmon_pcap_file_header);

            std::cout << "We will allocate " << memory_size_in_bytes << std::endl;
    
            memory_pointer = (unsigned char*)malloc( memory_size_in_bytes );

            if (memory_pointer != NULL) {
                this->buffer_size = memory_size_in_bytes;
                memory_pos = memory_pointer;
                return true;
            } else {
                return false;
            }
        } 

        bool write_binary_data(void* data_pointer, unsigned int length) {
            if (we_have_free_space_for_x_bytes(length)) {
                memcpy(memory_pos, data_pointer, length);
                memory_pos += length; 

                return true;
            } else {
                return false;
            }
        }

        bool write_packet(void* payload_pointer, unsigned int length) {
            // TODO: performance killer! Check it!
            bool we_do_timestamps = true;

            struct timeval current_time;
            current_time.tv_sec  = 0;
            current_time.tv_usec = 0;

            if (we_do_timestamps) {
                gettimeofday(&current_time, NULL);
            }

            struct fastnetmon_pcap_pkthdr pcap_packet_header;

            pcap_packet_header.ts_sec  = current_time.tv_sec;
            pcap_packet_header.ts_usec = current_time.tv_usec;

            pcap_packet_header.incl_len = length;
            pcap_packet_header.orig_len = length;
            
            if (!this->write_binary_data(&pcap_packet_header, sizeof(pcap_packet_header))) {
                return false;
            }

            return (this->write_binary_data(payload_pointer, length)); 
        }

        bool we_have_free_space_for_x_bytes(unsigned int length) {
            if (this->get_used_memory() + length <= this->buffer_size) {
                return true;
            } else {
                return false;
            }
        }


        bool write_header() {
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

            return this->write_binary_data(&pcap_header, sizeof(pcap_header));
        }

        int64_t get_used_memory() {
            return memory_pos - memory_pointer;
        } 

        bool deallocate_buffer() {
            if (memory_pointer == NULL or buffer_size == 0) {
                return true;
            }

            free(this->memory_pointer); 
            this->memory_pointer = NULL;   
            this->memory_pos = NULL;
            this->buffer_size = 0;

            return true;
        }

        void* get_buffer_pointer() {
            return memory_pointer;
        }
    private:
        unsigned char* memory_pointer;
        unsigned char* memory_pos;
        unsigned int buffer_size;
        unsigned int packet_size;
};

int main() {
    packet_storage_t packet_storage;
   
    // We specify in in packets
    if (!packet_storage.allocate_buffer(500)) {
        printf("Can't allocate buffer");
        return -1;
    }

    if (!packet_storage.write_header()) {
        printf("Can't write header");
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
