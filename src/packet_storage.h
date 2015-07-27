#ifndef PACKET_STORAGE_H
#define PACKET_STORAGE_H

#include <stdlib.h>
#include <string.h>
#include "fastnetmon_pcap_format.h"

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

            // std::cout << "We will allocate " << memory_size_in_bytes << std::endl;
    
            memory_pointer = (unsigned char*)malloc( memory_size_in_bytes );

            if (memory_pointer != NULL) {
                this->buffer_size = memory_size_in_bytes;
                memory_pos = memory_pointer;

                // Add header to newely allocated memory block
                return this->write_header();
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

            // TODO: fix hardcoded mtu size this!!!
            fill_pcap_header(&pcap_header, 1500);

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

#endif
