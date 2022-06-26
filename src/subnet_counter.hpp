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

    template <class Archive> void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
        ar& BOOST_SERIALIZATION_NVP(in_bytes);
        ar& BOOST_SERIALIZATION_NVP(out_bytes);
        ar& BOOST_SERIALIZATION_NVP(in_packets);
        ar& BOOST_SERIALIZATION_NVP(out_packets);
    }
};

// main data structure for storing traffic and speed data for all our IPs
class subnet_counter_t {
    public:
    // We use inaccurate time source for it becasue we do not care about precise time in this case
    time_t last_update_time = 0;

    traffic_counter_element_t total;

    traffic_counter_element_t tcp;
    traffic_counter_element_t udp;
    traffic_counter_element_t icmp;

    traffic_counter_element_t fragmented;
    traffic_counter_element_t tcp_syn;

    // Total number of dropped traffic
    traffic_counter_element_t dropped;

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
    }
};
