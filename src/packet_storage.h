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
            
            read_pos	= NULL;

            // TODO: fix hardcoded mtu size this!!!
            max_packet_size = 1500;
        }

        bool load_from_pcap_file(std::string pcap_file_path) {
            deallocate_buffer();
            
            int filedesc = open(pcap_file_path.c_str(), O_RDONLY);
            if (!filedesc) {
              return false;
            }
            
            struct stat stat_buff;
            if ( fstat(filedesc, &stat_buff) < 0 ) {
                close(filedesc);
                return false;
            }
            
            memory_pointer = (unsigned char*)malloc( stat_buff.st_size );
                        
            if (memory_pointer == NULL) {
              return false;
            }
            
            buffer_size = stat_buff.st_size;
            memory_pos = memory_pointer;
            read_pos = memory_pointer;
            
            ssize_t read_bytes = read(filedesc,memory_pointer,buffer_size);
            
            close(filedesc);
            
            if (read_bytes != buffer_size) {
                deallocate_buffer();
                return false;
            }
            
            memory_pos = memory_pointer+buffer_size;
            return true;
                              
        }
        
        bool allocate_buffer(unsigned int buffer_size_in_packets) {
            unsigned int memory_size_in_bytes = buffer_size_in_packets * (max_packet_size + sizeof(fastnetmon_pcap_pkthdr))
                + sizeof(fastnetmon_pcap_file_header);

            // std::cout << "We will allocate " << memory_size_in_bytes << std::endl;
    
            memory_pointer = (unsigned char*)malloc( memory_size_in_bytes );

            if (memory_pointer != NULL) {
                this->buffer_size = memory_size_in_bytes;
                memory_pos = memory_pointer;
                read_pos = memory_pointer;

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

        bool read_binary_data(void* data_pointer, unsigned int buffer_length, unsigned int bytes_to_read, long int *read_bytes) {

            // uninitialized or on the end        
            if (!read_pos || read_pos >= memory_pos) {
                *read_bytes = 0;
                return false;
            };
            
            // requested data longer than stored ones
            if (read_pos+bytes_to_read > memory_pos) {
                *read_bytes = memory_pos - read_pos;
            } else {
                *read_bytes = bytes_to_read;
            };
            
            memcpy(data_pointer,read_pos,*read_bytes);
            
            read_pos+= *read_bytes;

            return true;
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

            // Store full length of packet
            pcap_packet_header.orig_len = length;

            if (length > max_packet_size) {
                // We whould crop packet because it's too big
                pcap_packet_header.incl_len = max_packet_size;
            } else {
                pcap_packet_header.incl_len = length;
            }

            if (!this->write_binary_data(&pcap_packet_header, sizeof(pcap_packet_header))) {
                return false;
            }

            return (this->write_binary_data(payload_pointer, pcap_packet_header.incl_len)); 
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

            fill_pcap_header(&pcap_header, max_packet_size);

            return this->write_binary_data(&pcap_header, sizeof(pcap_header));
        }

        bool read_header(struct fastnetmon_pcap_file_header &pcap_file_header) {

            long int read_bytes;

            if ( this->read_binary_data(&pcap_file_header, sizeof(pcap_file_header), sizeof(pcap_file_header), &read_bytes) ) {

                if ( read_bytes == sizeof(pcap_file_header) ) {
                    return true;
                }
            }
            return false;
        }

        
        bool read_packet_header(struct fastnetmon_pcap_pkthdr &pcap_packet_header) {

            unsigned int bytes_to_read = sizeof(pcap_packet_header);
            long int read_bytes;
            
            if ( read_binary_data(&pcap_packet_header, sizeof(pcap_packet_header), bytes_to_read, &read_bytes) ) {
                
                if ( read_bytes == sizeof(pcap_packet_header) ) {
                    return true;
                }
            }
            return false;
        }

        bool read_packet_payload(void *payload_buffer, unsigned int buffer_size, unsigned int bytes_to_read, long int *read_bytes) {
           
            return read_binary_data(payload_buffer, buffer_size, bytes_to_read, read_bytes);

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
            this->read_pos = NULL;

            return true;
        }

        void* get_buffer_pointer() {
            return memory_pointer;
        }
        
        unsigned int get_max_packet_size() {
            return this->max_packet_size;
        }

        void set_max_packet_size(unsigned int new_max_packet_size) {
            this->max_packet_size = new_max_packet_size;
        }
        
        void rewind_read_pos() {
            read_pos = memory_pointer;
        }
        
        int bytes_to_read() {
            return memory_pos - read_pos;
        }
        
    private:
        unsigned char* memory_pointer;
        unsigned char* memory_pos;
        unsigned char* read_pos;
        unsigned int buffer_size;
        unsigned int max_packet_size;
};

#endif
