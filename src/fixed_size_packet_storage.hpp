#pragma once
#include "fastnetmon_pcap_format.h"

// We are using this class for storing packet meta information with their payload into fixed size memory region
class fixed_size_packet_storage_t {
    public:
    fixed_size_packet_storage_t() = default;
    fixed_size_packet_storage_t(void* payload_pointer, unsigned int captured_length, unsigned int real_packet_length) {
        // TODO: performance killer! Check it!
        bool we_do_timestamps = true;

        struct timeval current_time;
        current_time.tv_sec  = 0;
        current_time.tv_usec = 0;

        if (we_do_timestamps) {
            gettimeofday(&current_time, NULL);
        }


        packet_metadata.ts_sec  = current_time.tv_sec;
        packet_metadata.ts_usec = current_time.tv_usec;

        // Store full length of packet
        packet_metadata.orig_len = real_packet_length;
        packet_metadata.incl_len = captured_length;

        // Copy only first 2048 bytes of data
        unsigned packet_length_for_storing = captured_length;

        if (captured_length > 2048) {
            packet_length_for_storing = 2048;
        }

        // Copy data into internal storage
        memcpy(packet_payload, payload_pointer, packet_length_for_storing);
    }

    // Some useful information about this packet
    fastnetmon_pcap_pkthdr packet_metadata;

    // Packet itself. Let's zeroify packet payload
    uint8_t packet_payload[2048] = {};
};
