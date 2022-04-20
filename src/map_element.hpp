#include <stdint.h>

#include <boost/serialization/nvp.hpp>

// main data structure for storing traffic and speed data for all our IPs
class map_element_t {
    public:
    // We use inaccurate time source for it becasue we do not care about precise time in this case
    time_t last_update_time = 0;

    uint64_t in_bytes    = 0;
    uint64_t out_bytes   = 0;
    uint64_t in_packets  = 0;
    uint64_t out_packets = 0;

    // Fragmented traffic is so recently used for attacks
    uint64_t fragmented_in_packets  = 0;
    uint64_t fragmented_out_packets = 0;
    uint64_t fragmented_in_bytes    = 0;
    uint64_t fragmented_out_bytes   = 0;

    // Additional data for correct attack protocol detection
    uint64_t tcp_in_packets  = 0;
    uint64_t tcp_out_packets = 0;
    uint64_t tcp_in_bytes    = 0;
    uint64_t tcp_out_bytes   = 0;

    // Additional details about one of most popular atatck type
    uint64_t tcp_syn_in_packets  = 0;
    uint64_t tcp_syn_out_packets = 0;
    uint64_t tcp_syn_in_bytes    = 0;
    uint64_t tcp_syn_out_bytes   = 0;

    uint64_t udp_in_packets  = 0;
    uint64_t udp_out_packets = 0;
    uint64_t udp_in_bytes    = 0;
    uint64_t udp_out_bytes   = 0;

    uint64_t icmp_in_packets  = 0;
    uint64_t icmp_out_packets = 0;
    uint64_t icmp_in_bytes    = 0;
    uint64_t icmp_out_bytes   = 0;

    uint64_t in_flows  = 0;
    uint64_t out_flows = 0;

    // Is total counters fields are zero? We are not handling per protocol counters here because we assume they should
    // be counted twice
    // Once: in total counter (in_bytes) and secondly in per protocol counter (for example: udp_in_bytes)
    bool is_zero() const {
        return in_bytes == 0 && out_bytes == 0 && in_packets == 0 && out_packets == 0 && in_flows == 0 && out_flows == 0;
    }

    // Fill all counters by zeros
    void zeroify() {
        in_bytes    = 0;
        out_bytes   = 0;
        in_packets  = 0;
        out_packets = 0;

        fragmented_in_packets  = 0;
        fragmented_out_packets = 0;
        fragmented_in_bytes    = 0;
        fragmented_out_bytes   = 0;

        tcp_in_packets  = 0;
        tcp_out_packets = 0;
        tcp_in_bytes    = 0;
        tcp_out_bytes   = 0;

        tcp_syn_in_packets  = 0;
        tcp_syn_out_packets = 0;
        tcp_syn_in_bytes    = 0;
        tcp_syn_out_bytes   = 0;

        udp_in_packets  = 0;
        udp_out_packets = 0;
        udp_in_bytes    = 0;
        udp_out_bytes   = 0;

        icmp_in_packets  = 0;
        icmp_out_packets = 0;
        icmp_in_bytes    = 0;
        icmp_out_bytes   = 0;

        in_flows  = 0;
        out_flows = 0;
    }

    template <class Archive> void serialize(Archive& ar, const unsigned int version) {
        ar& BOOST_SERIALIZATION_NVP(in_bytes);
        ar& BOOST_SERIALIZATION_NVP(out_bytes);
        ar& BOOST_SERIALIZATION_NVP(in_packets);
        ar& BOOST_SERIALIZATION_NVP(out_packets);
        ar& BOOST_SERIALIZATION_NVP(fragmented_in_packets);
        ar& BOOST_SERIALIZATION_NVP(fragmented_out_packets);
        ar& BOOST_SERIALIZATION_NVP(fragmented_in_bytes);
        ar& BOOST_SERIALIZATION_NVP(fragmented_out_bytes);
        ar& BOOST_SERIALIZATION_NVP(tcp_in_packets);
        ar& BOOST_SERIALIZATION_NVP(tcp_out_packets);
        ar& BOOST_SERIALIZATION_NVP(tcp_in_bytes);
        ar& BOOST_SERIALIZATION_NVP(tcp_out_bytes);
        ar& BOOST_SERIALIZATION_NVP(tcp_syn_in_packets);
        ar& BOOST_SERIALIZATION_NVP(tcp_syn_out_packets);
        ar& BOOST_SERIALIZATION_NVP(tcp_syn_in_bytes);
        ar& BOOST_SERIALIZATION_NVP(tcp_syn_out_bytes);
        ar& BOOST_SERIALIZATION_NVP(udp_in_packets);
        ar& BOOST_SERIALIZATION_NVP(udp_out_packets);
        ar& BOOST_SERIALIZATION_NVP(udp_in_bytes);
        ar& BOOST_SERIALIZATION_NVP(udp_out_bytes);
        ar& BOOST_SERIALIZATION_NVP(icmp_in_packets);
        ar& BOOST_SERIALIZATION_NVP(icmp_out_packets);
        ar& BOOST_SERIALIZATION_NVP(icmp_in_bytes);
        ar& BOOST_SERIALIZATION_NVP(icmp_out_bytes);
        ar& BOOST_SERIALIZATION_NVP(in_flows);
        ar& BOOST_SERIALIZATION_NVP(out_flows);
    }
};
