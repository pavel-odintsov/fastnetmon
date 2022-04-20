#pragma once

#include <mutex>
#include <unordered_map>

// I keep these declaration here because of following error:
// error: there are no arguments to ‘increment_outgoing_counters’ that depend on a template parameter, so a declaration
// of ‘increment_outgoing_counters’ must be available [-fpermissive]
//  increment_outgoing_counters(counter_ptr, current_packet, sampled_number_of_packets, sampled_number_of_bytes);
void increment_incoming_counters(map_element_t* current_element,
                                 simple_packet_t& current_packet,
                                 uint64_t sampled_number_of_packets,
                                 uint64_t sampled_number_of_bytes);

void build_speed_counters_from_packet_counters(map_element_t& new_speed_element, map_element_t* vector_itr, double speed_calc_period);
void increment_outgoing_counters(map_element_t* current_element,
                                 simple_packet_t& current_packet,
                                 uint64_t sampled_number_of_packets,
                                 uint64_t sampled_number_of_bytes);
void build_average_speed_counters_from_speed_counters(map_element_t* current_average_speed_element,
                                                      map_element_t& new_speed_element,
                                                      double exp_value,
                                                      double exp_power);

// Class for abstract per key counters
template <typename T> class abstract_subnet_counters_t {
    public:
    std::unordered_map<T, subnet_counter_t> counter_map;
    std::mutex counter_map_mutex;

    std::unordered_map<T, subnet_counter_t> speed_map;
    std::unordered_map<T, subnet_counter_t> average_speed_map;

    // Increments outgoing counters for specified key
    void increment_outgoing_counters_for_key(T key, simple_packet_t& current_packet, uint64_t sampled_number_of_packets, uint64_t sampled_number_of_bytes) {
        std::lock_guard<std::mutex> lock_guard(counter_map_mutex);

        subnet_counter_t* counter_ptr = &counter_map[key];
        increment_outgoing_counters(counter_ptr, current_packet, sampled_number_of_packets, sampled_number_of_bytes);
    }

    // Increments incoming counters for specified key
    void increment_incoming_counters_for_key(T key, simple_packet_t& current_packet, uint64_t sampled_number_of_packets, uint64_t sampled_number_of_bytes) {
        std::lock_guard<std::mutex> lock_guard(counter_map_mutex);

        subnet_counter_t* counter_ptr = &counter_map[key];
        increment_incoming_counters(counter_ptr, current_packet, sampled_number_of_packets, sampled_number_of_bytes);
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
            speed_map.erase(key);
            average_speed_map.erase(key);
        }

        // Report number of removed records
        return keys_to_remove.size();
    }

    void recalculate_speed(double speed_calc_period,
                           double average_calculation_time_for_subnets,
                           std::function<void(T*, map_element_t*)> speed_check_callback) {
        std::lock_guard<std::mutex> lock_guard(this->counter_map_mutex);

        for (auto itr = this->counter_map.begin(); itr != this->counter_map.end(); ++itr) {
            T current_key                    = itr->first;
            subnet_counter_t* subnet_traffic = &itr->second;

            subnet_counter_t new_speed_element;

            build_speed_counters_from_packet_counters(new_speed_element, subnet_traffic, speed_calc_period);

            /* Moving average recalculation for subnets */
            /* http://en.wikipedia.org/wiki/Moving_average#Application_to_measuring_computer_performance
             */
            double exp_power_subnet = -speed_calc_period / average_calculation_time_for_subnets;
            double exp_value_subnet = exp(exp_power_subnet);

            map_element_t* current_average_speed_element = &average_speed_map[current_key];

            build_average_speed_counters_from_speed_counters(current_average_speed_element, new_speed_element,
                                                             exp_value_subnet, exp_power_subnet);

            // Update speed calculation structure in single step
            this->speed_map[current_key] = new_speed_element;
            subnet_traffic->zeroify();

            // Check thresholds
            speed_check_callback(&current_key, current_average_speed_element);
        }
    }

    // Returns all non zero average speed elements
    void get_all_non_zero_average_speed_elements_as_pairs(std::vector<std::pair<T, subnet_counter_t>>& all_elements) {
        std::lock_guard<std::mutex> lock_guard(this->counter_map_mutex);

        for (auto itr = this->average_speed_map.begin(); itr != this->average_speed_map.end(); ++itr) {
            if (itr->second.is_zero()) {
                continue;
            }

            all_elements.push_back(std::make_pair(itr->first, itr->second));
        }
    }

    void get_sorted_average_speed(std::vector<std::pair<T, subnet_counter_t>>& vector_for_sort, sort_type_t sorter_type, direction_t sort_direction) {
        std::lock_guard<std::mutex> lock_guard(this->counter_map_mutex);

        vector_for_sort.reserve(average_speed_map.size());
        std::copy(average_speed_map.begin(), average_speed_map.end(), std::back_inserter(vector_for_sort));

        std::sort(vector_for_sort.begin(), vector_for_sort.end(),
                  TrafficComparatorClass<std::pair<T, subnet_counter_t>>(sort_direction, sorter_type));
    }

    // Retrieves average speed for specified key with all locks
    bool get_average_speed_subnet(T key, map_element_t& average_speed_element) {
        std::lock_guard<std::mutex> lock_guard(this->counter_map_mutex);

        auto average_speed_itr = this->average_speed_map.find(key);

        if (average_speed_itr == this->average_speed_map.end()) {
            return false;
        }

        average_speed_element = average_speed_itr->second;
        return true;
    }

    // Please create vector_for_sort this way on callers side: top_four(4);
    void get_top_k_average_speed(std::vector<std::pair<T, subnet_counter_t>>& vector_for_sort, sort_type_t sorter_type, direction_t sort_direction) {

        std::lock_guard<std::mutex> lock_guard(this->counter_map_mutex);

        std::partial_sort_copy(average_speed_map.begin(), average_speed_map.end(), vector_for_sort.begin(),
                               vector_for_sort.end(),
                               TrafficComparatorClass<std::pair<T, subnet_counter_t>>(sort_direction, sorter_type));
    }
};
