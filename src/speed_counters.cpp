#include "speed_counters.hpp"

#include "fast_library.hpp"

extern time_t current_inaccurate_time;


#ifdef USE_NEW_ATOMIC_BUILTINS
// Increment fields using data from specified packet
void increment_outgoing_counters(subnet_counter_t& current_element,
                                 const simple_packet_t& current_packet,
                                 uint64_t sampled_number_of_packets,
                                 uint64_t sampled_number_of_bytes) {

    // Update last update time
    current_element.last_update_time = current_inaccurate_time;

    // Main packet/bytes counter
    __atomic_add_fetch(&current_element.total.out_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
    __atomic_add_fetch(&current_element.total.out_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);

    // Fragmented IP packets
    if (current_packet.ip_fragmented) {
        __atomic_add_fetch(&current_element.fragmented.out_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
        __atomic_add_fetch(&current_element.fragmented.out_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
    }

    if (current_packet.protocol == IPPROTO_TCP) {
        __atomic_add_fetch(&current_element.tcp.out_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
        __atomic_add_fetch(&current_element.tcp.out_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);

        if (extract_bit_value(current_packet.flags, TCP_SYN_FLAG_SHIFT)) {
            __atomic_add_fetch(&current_element.tcp_syn.out_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
            __atomic_add_fetch(&current_element.tcp_syn.out_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
        }
    } else if (current_packet.protocol == IPPROTO_UDP) {
        __atomic_add_fetch(&current_element.udp.out_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
        __atomic_add_fetch(&current_element.udp.out_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
    } else if (current_packet.protocol == IPPROTO_ICMP) {
        __atomic_add_fetch(&current_element.icmp.out_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
        __atomic_add_fetch(&current_element.icmp.out_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
        // no flow tracking for icmp
    } else {
    }
}
#else
// Increment fields using data from specified packet
void increment_outgoing_counters(subnet_counter_t& current_element,
                                 const simple_packet_t& current_packet,
                                 uint64_t sampled_number_of_packets,
                                 uint64_t sampled_number_of_bytes) {

    // Update last update time
    current_element.last_update_time = current_inaccurate_time;

    // Main packet/bytes counter
    __sync_fetch_and_add(&current_element.total.out_packets, sampled_number_of_packets);
    __sync_fetch_and_add(&current_element.total.out_bytes, sampled_number_of_bytes);

    // Fragmented IP packets
    if (current_packet.ip_fragmented) {
        __sync_fetch_and_add(&current_element.fragmented.out_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element.fragmented.out_bytes, sampled_number_of_bytes);
    }

    if (current_packet.protocol == IPPROTO_TCP) {
        __sync_fetch_and_add(&current_element.tcp.out_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element.tcp.out_bytes, sampled_number_of_bytes);

        if (extract_bit_value(current_packet.flags, TCP_SYN_FLAG_SHIFT)) {
            __sync_fetch_and_add(&current_element.tcp_syn.out_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element.tcp_syn.out_bytes, sampled_number_of_bytes);
        }
    } else if (current_packet.protocol == IPPROTO_UDP) {
        __sync_fetch_and_add(&current_element.udp.out_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element.udp.out_bytes, sampled_number_of_bytes);
    } else if (current_packet.protocol == IPPROTO_ICMP) {
        __sync_fetch_and_add(&current_element.icmp.out_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element.icmp.out_bytes, sampled_number_of_bytes);
        // no flow tracking for icmp
    } else {
    }
}
#endif

#ifdef USE_NEW_ATOMIC_BUILTINS

// This function increments all our accumulators according to data from packet
void increment_incoming_counters(subnet_counter_t& current_element,
                                 const simple_packet_t& current_packet,
                                 uint64_t sampled_number_of_packets,
                                 uint64_t sampled_number_of_bytes) {

    // Uodate last update time
    current_element.last_update_time = current_inaccurate_time;

    // Main packet/bytes counter
    __atomic_add_fetch(&current_element.total.in_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
    __atomic_add_fetch(&current_element.total.in_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);

    // Count fragmented IP packets
    if (current_packet.ip_fragmented) {
        __atomic_add_fetch(&current_element.fragmented.in_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
        __atomic_add_fetch(&current_element.fragmented.in_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
    }

    // Count per protocol packets
    if (current_packet.protocol == IPPROTO_TCP) {
        __atomic_add_fetch(&current_element.tcp.in_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
        __atomic_add_fetch(&current_element.tcp.in_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);

        if (extract_bit_value(current_packet.flags, TCP_SYN_FLAG_SHIFT)) {
            __atomic_add_fetch(&current_element.tcp_syn.in_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
            __atomic_add_fetch(&current_element.tcp_syn.in_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
        }
    } else if (current_packet.protocol == IPPROTO_UDP) {
        __atomic_add_fetch(&current_element.udp.in_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
        __atomic_add_fetch(&current_element.udp.in_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
    } else if (current_packet.protocol == IPPROTO_ICMP) {
        __atomic_add_fetch(&current_element.icmp.in_packets, sampled_number_of_packets, __ATOMIC_RELAXED);
        __atomic_add_fetch(&current_element.icmp.in_bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
    } else {
        // TBD
    }
}

#else

// This function increments all our accumulators according to data from packet
void increment_incoming_counters(subnet_counter_t& current_element,
                                 const simple_packet_t& current_packet,
                                 uint64_t sampled_number_of_packets,
                                 uint64_t sampled_number_of_bytes) {

    // Uodate last update time
    current_element.last_update_time = current_inaccurate_time;

    // Main packet/bytes counter
    __sync_fetch_and_add(&current_element.total.in_packets, sampled_number_of_packets);
    __sync_fetch_and_add(&current_element.total.in_bytes, sampled_number_of_bytes);

    // Count fragmented IP packets
    if (current_packet.ip_fragmented) {
        __sync_fetch_and_add(&current_element.fragmented.in_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element.fragmented.in_bytes, sampled_number_of_bytes);
    }

    // Count per protocol packets
    if (current_packet.protocol == IPPROTO_TCP) {
        __sync_fetch_and_add(&current_element.tcp.in_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element.tcp.in_bytes, sampled_number_of_bytes);

        if (extract_bit_value(current_packet.flags, TCP_SYN_FLAG_SHIFT)) {
            __sync_fetch_and_add(&current_element.tcp_syn.in_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element.tcp_syn.in_bytes, sampled_number_of_bytes);
        }
    } else if (current_packet.protocol == IPPROTO_UDP) {
        __sync_fetch_and_add(&current_element.udp.in_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element.udp.in_bytes, sampled_number_of_bytes);
    } else if (current_packet.protocol == IPPROTO_ICMP) {
        __sync_fetch_and_add(&current_element.icmp.in_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element.icmp.in_bytes, sampled_number_of_bytes);
    } else {
        // TBD
    }
}

#endif

// We calculate speed from packet counters here
void build_speed_counters_from_packet_counters(subnet_counter_t& new_speed_element, const subnet_counter_t& data_counters, double speed_calc_period) {
    new_speed_element.total.calculate_speed(data_counters.total, speed_calc_period);
    new_speed_element.dropped.calculate_speed(data_counters.dropped, speed_calc_period);

    new_speed_element.fragmented.calculate_speed(data_counters.fragmented, speed_calc_period);
    new_speed_element.tcp_syn.calculate_speed(data_counters.tcp_syn, speed_calc_period);

    new_speed_element.tcp.calculate_speed(data_counters.tcp, speed_calc_period);
    new_speed_element.udp.calculate_speed(data_counters.udp, speed_calc_period);
    new_speed_element.icmp.calculate_speed(data_counters.icmp, speed_calc_period);
}

// We use this code to create smoothed speed of traffic from instant speed (per second)
void build_average_speed_counters_from_speed_counters(subnet_counter_t& current_average_speed_element,
                                                      const subnet_counter_t& new_speed_element,
                                                      double exp_value) {

    current_average_speed_element.total.calulate_exponential_moving_average_speed(new_speed_element.total, exp_value);
    current_average_speed_element.dropped.calulate_exponential_moving_average_speed(new_speed_element.dropped, exp_value);

    current_average_speed_element.fragmented.calulate_exponential_moving_average_speed(new_speed_element.fragmented, exp_value);
    current_average_speed_element.tcp_syn.calulate_exponential_moving_average_speed(new_speed_element.tcp_syn, exp_value);

    current_average_speed_element.tcp.calulate_exponential_moving_average_speed(new_speed_element.tcp, exp_value);
    current_average_speed_element.udp.calulate_exponential_moving_average_speed(new_speed_element.udp, exp_value);
    current_average_speed_element.icmp.calulate_exponential_moving_average_speed(new_speed_element.icmp, exp_value);

    // We do calculate flow counters for all cases
    current_average_speed_element.out_flows =
        uint64_t(new_speed_element.out_flows +
                 exp_value * ((double)current_average_speed_element.out_flows - (double)new_speed_element.out_flows));

    current_average_speed_element.in_flows =
        uint64_t(new_speed_element.in_flows +
                 exp_value * ((double)current_average_speed_element.in_flows - (double)new_speed_element.in_flows));
}
