#pragma once

#include <boost/circular_buffer.hpp>

extern log4cpp::Category& logger;

// Pattern of packet collection
enum class collection_pattern_t {
    // Just fill whole buffer one time and stop collection process
    ONCE = 1,

    // Infinitely add packets to storage
    INFINITE = 2,
};

// In this class we are storing circular buffers with full packet payloads and with parsed packet details
class packet_bucket_t {
    public:
    packet_bucket_t() {
    }

    void set_capacity(unsigned int capacity) {
        parsed_packets_circular_buffer.set_capacity(capacity);
        raw_packets_circular_buffer.set_capacity(capacity);
    }

    // Bucket type. We use it for actions tuning
    collection_pattern_t collection_pattern = collection_pattern_t::ONCE;

    // By default we could but for some container cases (single)
    bool we_could_receive_new_data = true;

    // We are using this flag for preventing double call of handle thread on same data
    bool is_already_processed = false;

    // We've filled buffer completely least once
    bool we_collected_full_buffer_least_once = false;

    // Here we are storing high level packed packets
    boost::circular_buffer<simple_packet_t> parsed_packets_circular_buffer;

    std::chrono::time_point<std::chrono::system_clock> collection_start_time;
    std::chrono::time_point<std::chrono::system_clock> collection_finished_time;

    // Here we are storing raw packets if they are availible (sflow, mirror)
    boost::circular_buffer<fixed_size_packet_storage_t> raw_packets_circular_buffer;

    // Attack details information extracted at time when we detected attack
    attack_details_t attack_details;
};

// That's thread safe container which consist of all lock logic inside it
template <typename TemplateKeyType> class packet_buckets_storage_t {
    public:
    void set_buffers_capacity(unsigned int capacity) {
        buffers_maximum_capacity = capacity;
    }

    bool we_want_to_capture_data_for_this_ip(TemplateKeyType lookup_ip) {
        std::lock_guard<std::mutex> lock_guard(packet_buckets_map_mutex);

        auto itr = packet_buckets_map.find(lookup_ip);

        // We haven't any records about this IP
        if (itr == packet_buckets_map.end()) {
            return false;
        }

        // Return internal value about
        return itr->second.we_could_receive_new_data;
    }

    // Return true if we have buckets for specified IP
    bool we_have_bucket_for_this_ip(TemplateKeyType lookup_ip) {
        std::lock_guard<std::mutex> lock_guard(packet_buckets_map_mutex);

        return packet_buckets_map.count(lookup_ip) > 0;
    }

    bool remove_packet_capture_for_ip(TemplateKeyType lookup_ip) {
        std::lock_guard<std::mutex> lock_guard(packet_buckets_map_mutex);

        packet_buckets_map.erase(lookup_ip);
        return true;
    }

    // We could enable packet capture for certain IP address with this function
    bool enable_packet_capture(TemplateKeyType client_ip, attack_details_t attack_details, collection_pattern_t collection_pattern) {
        std::lock_guard<std::mutex> lock_guard(packet_buckets_map_mutex);

        if (packet_buckets_map.count(client_ip) > 0) {
            logger << log4cpp::Priority::ERROR << "Capture for IP " << convert_any_ip_to_string(client_ip) << " already exists";
            return false;
        }

        packet_bucket_t new_packet_bucket;
        new_packet_bucket.set_capacity(buffers_maximum_capacity);

        // Specify start time
        new_packet_bucket.collection_start_time = std::chrono::system_clock::now();

        if (buffers_maximum_capacity == 0) {
            // In this case we mark this bucket as already collected to trigger immediate detection without tpacket capture
            new_packet_bucket.we_could_receive_new_data           = false;
            new_packet_bucket.we_collected_full_buffer_least_once = true;
            new_packet_bucket.collection_finished_time            = std::chrono::system_clock::now();
        } else {
            new_packet_bucket.we_could_receive_new_data = true;
        }

        new_packet_bucket.collection_pattern = collection_pattern;
        new_packet_bucket.attack_details     = attack_details;

        packet_buckets_map[client_ip] = new_packet_bucket;

        return true;
    }

    bool disable_packet_capture(TemplateKeyType client_ip) {
        std::lock_guard<std::mutex> lock_guard(packet_buckets_map_mutex);

        auto itr = packet_buckets_map.find(client_ip);

        if (itr == packet_buckets_map.end()) {
            logger << log4cpp::Priority::ERROR << "Capture for this IP " << convert_any_ip_to_string(client_ip) << " does not exists";
            return false;
        }

        // Just disable capture
        itr->second.we_could_receive_new_data = false;

        return true;
    }

    // Add packet to storage if we want to receive this packet
    bool add_packet_to_storage(TemplateKeyType client_ip, simple_packet_t& current_packet) {
        std::lock_guard<std::mutex> lock_guard(packet_buckets_map_mutex);

        bool we_will_call_overflow_with_this_append_operation = false;

        // We should explicitly add map element here before starting collection
        auto itr = packet_buckets_map.find(client_ip);

        if (itr == packet_buckets_map.end()) {
            // logger << log4cpp::Priority::ERROR << "We could not find bucket for IP " << convert_any_ip_to_string(client_ip);
            // logger << log4cpp::Priority::ERROR << "Element in map should be created before any append operations";

            return false;
        }

        if (!itr->second.we_could_receive_new_data) {
            return false;
        }

        // if we are near to overflow for one from two buffers just switch off collection
        if (itr->second.collection_pattern == collection_pattern_t::ONCE) {

            if (itr->second.parsed_packets_circular_buffer.size() + 1 == itr->second.parsed_packets_circular_buffer.capacity() ||
                itr->second.raw_packets_circular_buffer.size() + 1 == itr->second.raw_packets_circular_buffer.capacity()) {

                // Just switch off traffic new collection
                itr->second.we_could_receive_new_data = false;

                // Specify flag about correctly filled buffer
                itr->second.we_collected_full_buffer_least_once = true;

                itr->second.collection_finished_time = std::chrono::system_clock::now();

                // TODO: we could not print IP in pretty form here because we will got circullar dependency in this
                // case...
                logger << log4cpp::Priority::INFO << "We've filled circullar buffer for ip "
                       << convert_any_ip_to_string(client_ip) << " with "
                       << itr->second.raw_packets_circular_buffer.capacity() << " elements in raw_packets_circular_buffer"
                       << " and " << itr->second.parsed_packets_circular_buffer.capacity()
                       << " elements in parsed_packets_circular_buffer";

                std::chrono::duration<double> elapsed_seconds = itr->second.collection_finished_time - itr->second.collection_start_time;
                logger << log4cpp::Priority::INFO << "We've collected packets for "
                       << convert_any_ip_to_string(client_ip) << " in " << elapsed_seconds.count() << " seconds";
            }
        }

        logger << log4cpp::Priority::DEBUG << "Buffer size before adding packet for "
               << convert_any_ip_to_string(client_ip) << " is " << itr->second.parsed_packets_circular_buffer.size()
               << " for parsed and " << itr->second.raw_packets_circular_buffer.size() << " for raw";

        logger << log4cpp::Priority::DEBUG << "Adding following packet for bucket for IP "
               << convert_any_ip_to_string(client_ip) << " " << print_simple_packet(current_packet);

        itr->second.parsed_packets_circular_buffer.push_back(current_packet);

        // If we have packet payload for this packet add it to storage too
        if (current_packet.packet_payload_length > 0 && current_packet.packet_payload_pointer != NULL) {
            logger << log4cpp::Priority::DEBUG << "Add raw packet to storage with packet_payload_length "
                   << current_packet.packet_payload_length << " and packet_payload_full_length "
                   << current_packet.packet_payload_full_length;

            itr->second.raw_packets_circular_buffer.push_back(
                fixed_size_packet_storage_t(current_packet.packet_payload_pointer, current_packet.packet_payload_length,
                                            current_packet.packet_payload_full_length));
        }

        logger << log4cpp::Priority::DEBUG << "Buffer size after adding packet for "
               << convert_any_ip_to_string(client_ip) << " is " << itr->second.parsed_packets_circular_buffer.size()
               << " for parsed and " << itr->second.raw_packets_circular_buffer.size() << " for raw";

        return true;
    }

    // Because we could need mutexes somewhere
    public:
    unsigned int buffers_maximum_capacity = 500;
    std::mutex packet_buckets_map_mutex;
    std::map<TemplateKeyType, packet_bucket_t> packet_buckets_map;
};
