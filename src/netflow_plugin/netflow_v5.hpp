// Netflow v5 header
class __attribute__((__packed__)) netflow5_header_t {
    public:
    netflow_header_common_t header;
    uint32_t uptime_ms     = 0;
    uint32_t time_sec      = 0;
    uint32_t time_nanosec  = 0;
    uint32_t flow_sequence = 0;
    uint8_t engine_type    = 0;
    uint8_t engine_id      = 0;

    // "First two bits hold the sampling mode; remaining 14 bits hold value of
    // sampling interval"
    // according to https://www.plixer.com/support/netflow_v5.html
    // http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html
    uint16_t sampling_rate = 0;
};


// We are using this class for decoding messages from the wire
// Please do not add new fields here
class __attribute__((__packed__)) netflow5_flow_t {
    public:
    // Source IP
    uint32_t src_ip = 0;

    // Destination IP
    uint32_t dest_ip = 0;

    // IPv4 next hop
    uint32_t nexthop_ip = 0;

    // Input interface
    uint16_t if_index_in = 0;

    // Output interface
    uint16_t if_index_out = 0;

    // Number of packets in flow
    uint32_t flow_packets = 0;

    // Number of bytes / octets in flow
    uint32_t flow_octets = 0;

    // Flow start time in milliseconds
    uint32_t flow_start = 0;

    // Flow end time in milliseconds
    uint32_t flow_finish = 0;

    // Source port
    uint16_t src_port = 0;

    // Destination port
    uint16_t dest_port = 0;

    // Padding
    uint8_t pad1 = 0;

    // TCP flags
    uint8_t tcp_flags = 0;

    // Protocol number
    uint8_t protocol = 0;

    // Type of service
    uint8_t tos = 0;

    // Source ASN
    uint16_t src_as = 0;

    // Destination ASN
    uint16_t dest_as = 0;

    // Source mask length
    uint8_t src_mask = 0;

    // Destination mask length
    uint8_t dst_mask = 0;

    // Padding
    uint16_t pad2 = 0;
};

static_assert(sizeof(netflow5_flow_t) == 48, "Bad size for netflow5_flow_t");

#define NETFLOW5_MAXFLOWS 30
#define NETFLOW5_PACKET_SIZE(nflows) (sizeof(netflow5_header_t) + ((nflows) * sizeof(netflow5_flow_t)))


