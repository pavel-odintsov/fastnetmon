#include <stdint.h>

#include <boost/serialization/nvp.hpp>

// This class keeps all our counters for specific traffic type
class traffic_counter_element_t {
    public:
    uint64_t in_bytes    = 0;
    uint64_t out_bytes   = 0;
    uint64_t in_packets  = 0;
    uint64_t out_packets = 0;

    void zeroify() {
        in_bytes    = 0;
        out_bytes   = 0;
        in_packets  = 0;
        out_packets = 0;
    }

    // Returns zero when all counters are zero
    bool is_zero() const {
        return in_bytes == 0 && out_bytes == 0 && in_packets == 0 && out_packets == 0;
    }

    // This function compares value in object with passed value and updates our object value to it if it passed value exceeds value we have in place
    void update_if_larger(const traffic_counter_element_t& another_value) {
        if (another_value.in_bytes > this->in_bytes) {
            this->in_bytes = another_value.in_bytes;
        }

        if (another_value.out_bytes > this->out_bytes) {
            this->out_bytes = another_value.out_bytes;
        }

        if (another_value.in_packets > this->in_packets) {
            this->in_packets = another_value.in_packets;
        }


        if (another_value.out_packets > this->out_packets) {
            this->out_packets = another_value.out_packets;
        }
    }

    template <class Archive> void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
        ar& BOOST_SERIALIZATION_NVP(in_bytes);
        ar& BOOST_SERIALIZATION_NVP(out_bytes);
        ar& BOOST_SERIALIZATION_NVP(in_packets);
        ar& BOOST_SERIALIZATION_NVP(out_packets);
    }

    // Calculates speed for all counters from input data counter
    void calculate_speed(const traffic_counter_element_t& traffic_counter, double speed_calc_period) {
        this->in_packets  = uint64_t((double)traffic_counter.in_packets / speed_calc_period);
        this->out_packets = uint64_t((double)traffic_counter.out_packets / speed_calc_period);

        this->in_bytes  = uint64_t((double)traffic_counter.in_bytes / speed_calc_period);
        this->out_bytes = uint64_t((double)traffic_counter.out_bytes / speed_calc_period);
    }

    // Calculates exponential moving average speed from instant speed
    void calulate_exponential_moving_average_speed(const traffic_counter_element_t& new_speed_element, double exp_value) {
        // Bytes counters
        this->in_bytes =
            uint64_t(new_speed_element.in_bytes + exp_value * ((double)this->in_bytes - (double)new_speed_element.in_bytes));

        this->out_bytes =
            uint64_t(new_speed_element.out_bytes + exp_value * ((double)this->out_bytes - (double)new_speed_element.out_bytes));

        // Packet counters
        this->in_packets = uint64_t(new_speed_element.in_packets +
                                    exp_value * ((double)this->in_packets - (double)new_speed_element.in_packets));

        this->out_packets = uint64_t(new_speed_element.out_packets +
                                     exp_value * ((double)this->out_packets - (double)new_speed_element.out_packets));
    }
};


// Main data structure for storing traffic and speed data for all our IPs
class subnet_counter_t {
    public:
    // We use inaccurate time source for it because we do not care about precise time in this case
    time_t last_update_time = 0;

    traffic_counter_element_t total;

    traffic_counter_element_t tcp;
    traffic_counter_element_t udp;
    traffic_counter_element_t icmp;

    traffic_counter_element_t fragmented;
    traffic_counter_element_t tcp_syn;

    // // rafael decoders p0, p53, p123, p1900
    traffic_counter_element_t decoder_p0;
    traffic_counter_element_t decoder_p53;
    traffic_counter_element_t decoder_p123;
    traffic_counter_element_t decoder_p1900;

    // Total number of dropped traffic
    traffic_counter_element_t dropped;

    // Updates specific value if any of fields from another_value exceed values in our object
    void update_if_larger(const subnet_counter_t& another_value) {
        this->total.update_if_larger(another_value.total);

        this->tcp.update_if_larger(another_value.tcp);
        this->udp.update_if_larger(another_value.udp);
        this->icmp.update_if_larger(another_value.icmp);

        this->fragmented.update_if_larger(another_value.fragmented);
        this->tcp_syn.update_if_larger(another_value.tcp_syn);

        this->decoder_p0.update_if_larger(another_value.decoder_p0);
        this->decoder_p53.update_if_larger(another_value.decoder_p53);
        this->decoder_p123.update_if_larger(another_value.decoder_p123);
        this->decoder_p1900.update_if_larger(another_value.decoder_p1900);

        this->dropped.update_if_larger(another_value.dropped);

        if (in_flows < another_value.in_flows) {
            this->in_flows = another_value.in_flows;
        }

        if (out_flows < another_value.out_flows) {
            this->out_flows = another_value.out_flows;
        }
    }

    uint64_t in_flows  = 0;
    uint64_t out_flows = 0;

    // Is total counters fields are zero? We are not handling per protocol counters here because we assume they should
    // be counted twice
    // Once: in total counter (in_bytes) and secondly in per protocol counter (for example: udp_in_bytes)
    bool is_zero() const {
        return total.in_bytes == 0 && total.out_bytes == 0 && total.in_packets == 0 && total.out_packets == 0 &&
               in_flows == 0 && out_flows == 0;
    }

    // Fill all counters by zeros
    void zeroify() {
        total.zeroify();
        dropped.zeroify();

        tcp.zeroify();
        udp.zeroify();
        icmp.zeroify();

        fragmented.zeroify();
        tcp_syn.zeroify();

        decoder_p0.zeroify();
        decoder_p123.zeroify();
        decoder_p1900.zeroify();
        decoder_p53.zeroify();

        in_flows  = 0;
        out_flows = 0;
    }

    template <class Archive> void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
        ar& BOOST_SERIALIZATION_NVP(total);
        ar& BOOST_SERIALIZATION_NVP(dropped);

        ar& BOOST_SERIALIZATION_NVP(tcp);
        ar& BOOST_SERIALIZATION_NVP(udp);
        ar& BOOST_SERIALIZATION_NVP(icmp);

        ar& BOOST_SERIALIZATION_NVP(fragmented);
        ar& BOOST_SERIALIZATION_NVP(tcp_syn);

        ar& BOOST_SERIALIZATION_NVP(in_flows);
        ar& BOOST_SERIALIZATION_NVP(out_flows);

        ar& BOOST_SERIALIZATION_NVP(decoder_p0);
        ar& BOOST_SERIALIZATION_NVP(decoder_p53);
        ar& BOOST_SERIALIZATION_NVP(decoder_p123);
        ar& BOOST_SERIALIZATION_NVP(decoder_p1900);
    }
};
