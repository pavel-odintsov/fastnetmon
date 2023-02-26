#include "../../all_logcpp_libraries.hpp"
#include "../../fastnetmon_types.hpp"
#include "../../traffic_data.pb.h"

// Encode simple packet into Protobuf
bool write_simple_packet_to_protobuf(const simple_packet_t& packet, TrafficData& traffic_data) {
    extern log4cpp::Category& logger;

    traffic_data.set_protocol(packet.protocol);
    traffic_data.set_sampling_ratio(packet.sample_ratio);

    if (packet.ip_protocol_version == 4) {
        traffic_data.set_source_ip(&packet.src_ip, sizeof(packet.src_ip));
        traffic_data.set_destination_ip(&packet.dst_ip, sizeof(packet.dst_ip));
    } else if (packet.ip_protocol_version == 6) {
        traffic_data.set_source_ip(&packet.src_ipv6, sizeof(packet.src_ipv6));
        traffic_data.set_destination_ip(&packet.dst_ipv6, sizeof(packet.dst_ipv6));
    }

    traffic_data.set_ip_version(packet.ip_protocol_version);
    traffic_data.set_ttl(packet.ttl);

    traffic_data.set_source_port(packet.source_port);
    traffic_data.set_destination_port(packet.destination_port);

    traffic_data.set_octets(packet.length);
    traffic_data.set_packets(packet.number_of_packets);

    traffic_data.set_tcp_flags(packet.flags);
    traffic_data.set_ip_fragmented(packet.ip_fragmented);
    traffic_data.set_timestamp_seconds(packet.ts.tv_sec);
    traffic_data.set_timestamp_milliseconds(packet.ts.tv_usec);
    traffic_data.set_octets(packet.length);

    if (packet.packet_direction == INCOMING) {
        traffic_data.set_traffic_direction(TRAFFIC_DIRECTION_INCOMING);
    } else if (packet.packet_direction == OUTGOING) {
        traffic_data.set_traffic_direction(TRAFFIC_DIRECTION_OUTGOING);
    } else if (packet.packet_direction == INTERNAL) {
        traffic_data.set_traffic_direction(TRAFFIC_DIRECTION_INTERNAL);
    } else if (packet.packet_direction == OTHER) {
        traffic_data.set_traffic_direction(TRAFFIC_DIRECTION_OTHER);
    } else {
        traffic_data.set_traffic_direction(TRAFFIC_DIRECTION_UNKNOWN);
    }

    if (packet.source == MIRROR) {
        traffic_data.set_telemetry_type(TELEMETRY_TYPE_MIRROR);
    } else if (packet.source == SFLOW) {
        traffic_data.set_telemetry_type(TELEMETRY_TYPE_SFLOW);
    } else if (packet.source == NETFLOW) {
        traffic_data.set_telemetry_type(TELEMETRY_TYPE_NETFLOW);
    } else if (packet.source == TERAFLOW) {
        traffic_data.set_telemetry_type(TELEMETRY_TYPE_TERA_FLOW);
    } else {
        traffic_data.set_telemetry_type(TELEMETRY_TYPE_UNKNOWN);
    }

    traffic_data.set_source_asn(packet.src_asn);
    traffic_data.set_destination_asn(packet.dst_asn);
    traffic_data.set_input_interface(packet.input_interface);
    traffic_data.set_output_interface(packet.output_interface);

    // In current version we support only IPv4 agent IP
    traffic_data.set_agent_address(&packet.agent_ip_address, sizeof(packet.agent_ip_address));

    return true;
}
