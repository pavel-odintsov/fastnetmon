#include "speed_counters.hpp"

#include "fast_library.hpp"

#include "iana_ip_protocols.hpp"

extern time_t current_inaccurate_time;
extern log4cpp::Category& logger;

// This function increments all our accumulators according to data from packet
void increment_incoming_counters(subnet_counter_t& current_element,
                                 const simple_packet_t& current_packet,
                                 uint64_t sampled_number_of_packets,
                                 uint64_t sampled_number_of_bytes) {

    // Update last update time
    current_element.last_update_time = current_inaccurate_time;

    // Main packet/bytes counter
    current_element.total.in_packets += sampled_number_of_packets;
    current_element.total.in_bytes += sampled_number_of_bytes;

    // Count fragmented IP packets
    if (current_packet.ip_fragmented) {
        current_element.fragmented.in_packets += sampled_number_of_packets;
        current_element.fragmented.in_bytes += sampled_number_of_bytes;
    }

    // Count dropped packets
    if (current_packet.forwarding_status == forwarding_status_t::dropped) {
        current_element.dropped.in_packets += sampled_number_of_packets;
        current_element.dropped.in_bytes += sampled_number_of_bytes;
    }

    // Count per protocol packets
    if (current_packet.protocol == IPPROTO_TCP) {
        current_element.tcp.in_packets += sampled_number_of_packets;
        current_element.tcp.in_bytes += sampled_number_of_bytes;

        if (extract_bit_value(current_packet.flags, TCP_SYN_FLAG_SHIFT)) {
            current_element.tcp_syn.in_packets += sampled_number_of_packets;
            current_element.tcp_syn.in_bytes += sampled_number_of_bytes;
        }

        // // rafael decoders
        if(current_packet.source_port == 0 || current_packet.destination_port == 0)
        {
            current_element.decoder_p0.in_packets += sampled_number_of_packets;
            current_element.decoder_p0.in_bytes += sampled_number_of_bytes;
        }
        if(current_packet.source_port == 53 || current_packet.destination_port == 53)
        {
            current_element.decoder_p53.in_packets += sampled_number_of_packets;
            current_element.decoder_p53.in_bytes += sampled_number_of_bytes;
        }
        if(current_packet.source_port == 123 || current_packet.destination_port == 123)
        {
            current_element.decoder_p123.in_packets += sampled_number_of_packets;
            current_element.decoder_p123.in_bytes += sampled_number_of_bytes;
        }
        if(current_packet.source_port == 1900 || current_packet.destination_port == 1900)
        {
            current_element.decoder_p1900.in_packets += sampled_number_of_packets;
            current_element.decoder_p1900.in_bytes += sampled_number_of_bytes;
        }

    } else if (current_packet.protocol == IPPROTO_UDP) {
        current_element.udp.in_packets += sampled_number_of_packets;
        current_element.udp.in_bytes += sampled_number_of_bytes;

        // // rafael decoders
        if(current_packet.source_port == 0 || current_packet.destination_port == 0)
        {
            current_element.decoder_p0.in_packets += sampled_number_of_packets;
            current_element.decoder_p0.in_bytes += sampled_number_of_bytes;
        }
        if(current_packet.source_port == 53 || current_packet.destination_port == 53)
        {
            current_element.decoder_p53.in_packets += sampled_number_of_packets;
            current_element.decoder_p53.in_bytes += sampled_number_of_bytes;
        }
        if(current_packet.source_port == 123 || current_packet.destination_port == 123)
        {
            current_element.decoder_p123.in_packets += sampled_number_of_packets;
            current_element.decoder_p123.in_bytes += sampled_number_of_bytes;
        }
        if(current_packet.source_port == 1900 || current_packet.destination_port == 1900)
        {
            current_element.decoder_p1900.in_packets += sampled_number_of_packets;
            current_element.decoder_p1900.in_bytes += sampled_number_of_bytes;
        }

    } else {
        // TBD
    }

    // ICMP uses different protocol numbers for IPv4 and IPv6 and we need handle it
    if (current_packet.ip_protocol_version == 4) {
        if (current_packet.protocol == IpProtocolNumberICMP) {
            current_element.icmp.in_packets += sampled_number_of_packets;
            current_element.icmp.in_bytes += sampled_number_of_bytes;
        }

    } else if (current_packet.ip_protocol_version == 6) {

        if (current_packet.protocol == IpProtocolNumberIPV6_ICMP) {
            current_element.icmp.in_packets += sampled_number_of_packets;
            current_element.icmp.in_bytes += sampled_number_of_bytes;
        }

    }
}

// Increment fields using data from specified packet
void increment_outgoing_counters(subnet_counter_t& current_element,
                                 const simple_packet_t& current_packet,
                                 uint64_t sampled_number_of_packets,
                                 uint64_t sampled_number_of_bytes) {

    // Update last update time
    current_element.last_update_time = current_inaccurate_time;

    // Main packet/bytes counter
    current_element.total.out_packets += sampled_number_of_packets;
    current_element.total.out_bytes += sampled_number_of_bytes;

    // Fragmented IP packets
    if (current_packet.ip_fragmented) {
        current_element.fragmented.out_packets += sampled_number_of_packets;
        current_element.fragmented.out_bytes += sampled_number_of_bytes;
    }

    // Count dropped packets
    if (current_packet.forwarding_status == forwarding_status_t::dropped) {
        current_element.dropped.out_packets += sampled_number_of_packets;
        current_element.dropped.out_bytes += sampled_number_of_bytes;
    }

    if (current_packet.protocol == IPPROTO_TCP) {
        current_element.tcp.out_packets += sampled_number_of_packets;
        current_element.tcp.out_bytes += sampled_number_of_bytes;

        if (extract_bit_value(current_packet.flags, TCP_SYN_FLAG_SHIFT)) {
            current_element.tcp_syn.out_packets += sampled_number_of_packets;
            current_element.tcp_syn.out_bytes += sampled_number_of_bytes;
        }

        // // rafael decoders
        if(current_packet.source_port == 0 || current_packet.destination_port == 0)
        {
            current_element.decoder_p0.out_packets += sampled_number_of_packets;
            current_element.decoder_p0.out_bytes += sampled_number_of_bytes;
        }
        if(current_packet.source_port == 53 || current_packet.destination_port == 53)
        {
            current_element.decoder_p53.out_packets += sampled_number_of_packets;
            current_element.decoder_p53.out_bytes += sampled_number_of_bytes;
        }
        if(current_packet.source_port == 123 || current_packet.destination_port == 123)
        {
            current_element.decoder_p123.out_packets += sampled_number_of_packets;
            current_element.decoder_p123.out_bytes += sampled_number_of_bytes;
        }
        if(current_packet.source_port == 1900 || current_packet.destination_port == 1900)
        {
            current_element.decoder_p1900.out_packets += sampled_number_of_packets;
            current_element.decoder_p1900.out_bytes += sampled_number_of_bytes;
        }

    } else if (current_packet.protocol == IPPROTO_UDP) {
        current_element.udp.out_packets += sampled_number_of_packets;
        current_element.udp.out_bytes += sampled_number_of_bytes;

        // rafael decoders
        if(current_packet.source_port == 0 || current_packet.destination_port == 0)
        {
            current_element.decoder_p0.out_packets += sampled_number_of_packets;
            current_element.decoder_p0.out_bytes += sampled_number_of_bytes;
        }
        if(current_packet.source_port == 53 || current_packet.destination_port == 53)
        {
            //logger << log4cpp::Priority::ERROR << "Dentro da porta 53";
            current_element.decoder_p53.out_packets += sampled_number_of_packets;
            current_element.decoder_p53.out_bytes += sampled_number_of_bytes;
        }
        if(current_packet.source_port == 123 || current_packet.destination_port == 123)
        {
            current_element.decoder_p123.out_packets += sampled_number_of_packets;
            current_element.decoder_p123.out_bytes += sampled_number_of_bytes;
        }
        if(current_packet.source_port == 1900 || current_packet.destination_port == 1900)
        {
            current_element.decoder_p1900.out_packets += sampled_number_of_packets;
            current_element.decoder_p1900.out_bytes += sampled_number_of_bytes;
        }

    } else {
    }

    // ICMP uses different protocol numbers for IPv4 and IPv6 and we need handle it
    if (current_packet.ip_protocol_version == 4) {
        if (current_packet.protocol == IpProtocolNumberICMP) {
            current_element.icmp.out_packets += sampled_number_of_packets;
            current_element.icmp.out_bytes += sampled_number_of_bytes;
        }

    } else if (current_packet.ip_protocol_version == 6) {

        if (current_packet.protocol == IpProtocolNumberIPV6_ICMP) {
            current_element.icmp.out_packets += sampled_number_of_packets;
            current_element.icmp.out_bytes += sampled_number_of_bytes;
        }

    }
}


// These build_* functions are called from our heavy computation path in recalculate_speed()
// and you may have an idea that making them inline will help
// We did this experiment and inlining clearly did speed calculation performance 1-2% worse

// We calculate speed from packet counters here
void build_speed_counters_from_packet_counters(subnet_counter_t& new_speed_element, const subnet_counter_t& data_counters, double speed_calc_period) {
    new_speed_element.total.calculate_speed(data_counters.total, speed_calc_period);
    new_speed_element.dropped.calculate_speed(data_counters.dropped, speed_calc_period);

    new_speed_element.fragmented.calculate_speed(data_counters.fragmented, speed_calc_period);
    new_speed_element.tcp_syn.calculate_speed(data_counters.tcp_syn, speed_calc_period);

    new_speed_element.decoder_p0.calculate_speed(data_counters.decoder_p0, speed_calc_period);
    new_speed_element.decoder_p53.calculate_speed(data_counters.decoder_p53, speed_calc_period);
    new_speed_element.decoder_p123.calculate_speed(data_counters.decoder_p123, speed_calc_period);
    new_speed_element.decoder_p1900.calculate_speed(data_counters.decoder_p1900, speed_calc_period);

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
    
    current_average_speed_element.decoder_p0.calulate_exponential_moving_average_speed(new_speed_element.decoder_p0, exp_value);
    current_average_speed_element.decoder_p53.calulate_exponential_moving_average_speed(new_speed_element.decoder_p53, exp_value);
    current_average_speed_element.decoder_p123.calulate_exponential_moving_average_speed(new_speed_element.decoder_p123, exp_value);
    current_average_speed_element.decoder_p1900.calulate_exponential_moving_average_speed(new_speed_element.decoder_p1900, exp_value);

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
