#pragma once

#include <mutex>
#include <functional>

#include "speed_counters.hpp"

//
// Even latest Debian Sid (March 2023) uses Boost 1.74 which does not behave well with very fresh compilers and triggers this error:
// https://github.com/pavel-odintsov/fastnetmon/issues/970
// This bug was fixed in fresh Boost versions: https://github.com/boostorg/serialization/issues/219 and we apply workaround only for 1.74
//

#include <boost/serialization/version.hpp>
#if BOOST_VERSION / 100000 == 1 && BOOST_VERSION / 100 % 1000 == 74
#include <boost/serialization/library_version_type.hpp>
#endif

#include <boost/serialization/unordered_map.hpp>

// Class for abstract per key counters
template <typename T, typename Counter, typename UM = std::unordered_map<T, Counter>> class abstract_subnet_counters_t {
    public:
    UM counter_map;
    std::mutex counter_map_mutex;

    UM average_speed_map;

    // By using single map for speed and data we can accomplish improvement from 3-4 seconds for 14m hosts to 2-3 seconds

    template <class Archive> void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
        ar& BOOST_SERIALIZATION_NVP(counter_map);
        ar& BOOST_SERIALIZATION_NVP(average_speed_map);
    }

    // Increments outgoing counters for specified key
    void increment_outgoing_counters_for_key(const T& key,
                                             const simple_packet_t& current_packet,
                                             uint64_t sampled_number_of_packets,
                                             uint64_t sampled_number_of_bytes) {
        std::lock_guard<std::mutex> lock_guard(counter_map_mutex);

        Counter& counters = counter_map[key];
        increment_outgoing_counters(counters, current_packet, sampled_number_of_packets, sampled_number_of_bytes);
    }

    // Increments outgoing counters for specified key using multimatch array with indexes of matched thresholds
    template <size_t N>
    void increment_outgoing_counters_for_key(const T& key,
                                             const std::array<bool, N>& matched_indexes,
                                             uint64_t sampled_number_of_packets,
                                             uint64_t sampled_number_of_bytes) {
        std::lock_guard<std::mutex> lock_guard(counter_map_mutex);
        Counter& counters = counter_map[key];

        extern time_t current_inaccurate_time;

        // Update last update time
        counters.last_update_time = current_inaccurate_time;

        for (std::size_t current_index = 0; current_index < counters.flexible_counters.size(); current_index++) {
            // Increment only counters which are relevant to specific flexible threshold
            if (matched_indexes[current_index]) {
                counters.flexible_counters[current_index].out_packets += sampled_number_of_packets;
                counters.flexible_counters[current_index].out_bytes += sampled_number_of_bytes;
            }
        }
    }

    // Increments incoming counters for specified key
    void increment_incoming_counters_for_key(const T& key,
                                             const simple_packet_t& current_packet,
                                             uint64_t sampled_number_of_packets,
                                             uint64_t sampled_number_of_bytes) {
        std::lock_guard<std::mutex> lock_guard(counter_map_mutex);

        Counter& counters = counter_map[key];
        increment_incoming_counters(counters, current_packet, sampled_number_of_packets, sampled_number_of_bytes);
    }

    // Increments incoming counters for specified key using multi match array with indexes of matched thresholds
    template <size_t N>
    void increment_incoming_counters_for_key(const T& key,
                                             const std::array<bool, N>& matched_indexes,
                                             uint64_t sampled_number_of_packets,
                                             uint64_t sampled_number_of_bytes) {
        std::lock_guard<std::mutex> lock_guard(counter_map_mutex);
        Counter& counters = counter_map[key];

        extern time_t current_inaccurate_time;

        // Update last update time
        counters.last_update_time = current_inaccurate_time;

        for (std::size_t current_index = 0; current_index < counters.flexible_counters.size(); current_index++) {
            // Increment only counters which are relevant to specific flexible threshold
            if (matched_indexes[current_index]) {
                counters.flexible_counters[current_index].in_packets += sampled_number_of_packets;
                counters.flexible_counters[current_index].in_bytes += sampled_number_of_bytes;
            }
        }
    }

    // Retrieves all elements
    void get_all_average_speed_elements(UM& copy_of_average_speed_map) {
        std::lock_guard<std::mutex> lock_guard(counter_map_mutex);

        copy_of_average_speed_map = this->average_speed_map;
    }

    uint64_t purge_old_data(unsigned int automatic_data_cleanup_threshold) {
        std::lock_guard<std::mutex> lock_guard(this->counter_map_mutex);

        std::vector<T> keys_to_remove;

        time_t current_time = 0;

        time(&current_time);

        for (auto itr = this->counter_map.begin(); itr != this->counter_map.end(); ++itr) {
            if ((int64_t)itr->second.last_update_time < int64_t((int64_t)current_time - (int64_t)automatic_data_cleanup_threshold)) {
                keys_to_remove.push_back(itr->first);
            }
        }

        for (const auto& key : keys_to_remove) {
            counter_map.erase(key);
            average_speed_map.erase(key);
        }

        // Report number of removed records
        return keys_to_remove.size();
    }

    void recalculate_speed(double speed_calc_period,
                           double average_calculation_time,
                           std::function<void(const T&, const Counter&)> speed_check_callback      = nullptr,
                           std::function<void(const T&, Counter&, double)> new_speed_calc_callback = nullptr) {
        // http://en.wikipedia.org/wiki/Moving_average#Application_to_measuring_computer_performance
        double exp_power_subnet = -speed_calc_period / average_calculation_time;
        double exp_value_subnet = exp(exp_power_subnet);

        std::lock_guard<std::mutex> lock_guard(this->counter_map_mutex);

        for (auto itr = this->counter_map.begin(); itr != this->counter_map.end(); ++itr) {
            // Create const reference to key to easily reference to it in code
            const T& current_key = itr->first;

            // Create normal reference
            Counter& traffic_counters = itr->second;

            // Create element for instant speed
            Counter new_speed_element;

            build_speed_counters_from_packet_counters(new_speed_element, traffic_counters, speed_calc_period);

            // We can call callback function to populate more data here
            if (new_speed_calc_callback != nullptr) {
                new_speed_calc_callback(current_key, new_speed_element, speed_calc_period);
            }

            // Get reference to average speed element
            Counter& current_average_speed_element = average_speed_map[current_key];

            build_average_speed_counters_from_speed_counters(current_average_speed_element, new_speed_element, exp_value_subnet);

            traffic_counters.zeroify();

            // Check thresholds
            if (speed_check_callback != nullptr) {
                speed_check_callback(current_key, current_average_speed_element);
            }
        }
    }

    // Returns all non zero average speed elements
    void get_all_non_zero_average_speed_elements_as_pairs(std::vector<std::pair<T, Counter>>& all_elements) {
        std::lock_guard<std::mutex> lock_guard(this->counter_map_mutex);

        for (auto itr = this->average_speed_map.begin(); itr != this->average_speed_map.end(); ++itr) {
            if (itr->second.is_zero()) {
                continue;
            }

            all_elements.push_back(std::make_pair(itr->first, itr->second));
        }
    }

    void get_sorted_average_speed(std::vector<std::pair<T, Counter>>& vector_for_sort,
                                  const attack_detection_threshold_type_t& sorter_type,
                                  const attack_detection_direction_type_t& sort_direction) {
        std::lock_guard<std::mutex> lock_guard(this->counter_map_mutex);

        vector_for_sort.reserve(average_speed_map.size());
        std::copy(average_speed_map.begin(), average_speed_map.end(), std::back_inserter(vector_for_sort));

        std::sort(vector_for_sort.begin(), vector_for_sort.end(),
                  TrafficComparatorClass<std::pair<T, Counter>>(sort_direction, sorter_type));
    }

    // Retrieves average speed for specified key with all locks
    bool get_average_speed(const T& key, Counter& average_speed_element) {
        std::lock_guard<std::mutex> lock_guard(this->counter_map_mutex);

        auto average_speed_itr = this->average_speed_map.find(key);

        if (average_speed_itr == this->average_speed_map.end()) {
            return false;
        }

        average_speed_element = average_speed_itr->second;
        return true;
    }

    // Please create vector_for_sort this way on callers side: top_four(4);
    void get_top_k_average_speed(std::vector<std::pair<T, Counter>>& vector_for_sort,
                                 const attack_detection_threshold_type_t& sorter_type,
                                 const attack_detection_direction_type_t& sort_direction) {

        std::lock_guard<std::mutex> lock_guard(this->counter_map_mutex);

        std::partial_sort_copy(average_speed_map.begin(), average_speed_map.end(), vector_for_sort.begin(),
                               vector_for_sort.end(), TrafficComparatorClass<std::pair<T, Counter>>(sort_direction, sorter_type));
    }
};
