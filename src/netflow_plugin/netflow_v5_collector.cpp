// That's kind of histogram emulation
void increment_duration_counters_netflow_v5(int64_t duration) {
    if (duration <= 15) {
        netflow5_duration_less_15_seconds++;
    } else if (duration <= 30) {
        netflow5_duration_less_30_seconds++;
    } else if (duration <= 60) {
        netflow5_duration_less_60_seconds++;
    } else if (duration <= 90) {
        netflow5_duration_less_90_seconds++;
    } else if (duration <= 180) {
        netflow5_duration_less_180_seconds++;
    } else {
        netflow5_duration_exceed_180_seconds++;
    }

    return;
}


bool process_netflow_packet_v5(const uint8_t* packet,
                               uint32_t packet_length,
                               const std::string& client_addres_in_string_format,
                               uint32_t client_ipv4_address) {
    // logger<< log4cpp::Priority::INFO<<"We got Netflow v5 packet!";

    const netflow5_header_t* netflow5_header = (const netflow5_header_t*)packet;

    if (packet_length < sizeof(*netflow5_header)) {
        logger << log4cpp::Priority::ERROR << "Short netflow v5 packet " << packet_length;
        return false;
    }

    uint32_t number_of_flows = ntohs(netflow5_header->header.flows);
    if (number_of_flows == 0 || number_of_flows > NETFLOW5_MAXFLOWS) {
        logger << log4cpp::Priority::ERROR << "Invalid number of flows in Netflow v5 packet: " << number_of_flows;
        return false;
    }

    uint16_t netflow5_sampling_ratio = fast_ntoh(netflow5_header->sampling_rate);

    // In first two bits we store sampling type.
    // We are not interested in it and should zeroify it for getting correct value
    // of sampling rate
    clear_bit_value(netflow5_sampling_ratio, 15);
    clear_bit_value(netflow5_sampling_ratio, 16);

    // Sampling not enabled on device
    if (netflow5_sampling_ratio == 0) {
        netflow5_sampling_ratio = 1;
    }

    // Yes, some vendors can mess up with this value and we need option to override it
    // According to old Cisco's spec 2 bits are reserved for mode what limits us to 14 bits for storing sampling rate
    // It's enough to carry only <16k of sampling value
    // For example, Juniper can encode 50 000 sampling rate using two bits from mode which is not documented anywhere
    // Juniper's docs think that this field is reserved https://www.juniper.net/documentation/en_US/junos/topics/reference/general/flowmonitoring-output-formats-version5-solutions.html

    for (uint32_t i = 0; i < number_of_flows; i++) {
        size_t offset                        = NETFLOW5_PACKET_SIZE(i);
        const netflow5_flow_t* netflow5_flow = (const netflow5_flow_t*)(packet + offset);

        // Check packet bounds
        if (offset + sizeof(netflow5_flow_t) > packet_length) {
            logger << log4cpp::Priority::ERROR << "Error! You will try to read outside the Netflow v5 packet";
            return false;
        }

        netflow_ipfix_all_protocols_total_flows++;
        netflow_v5_total_flows++;

        // convert netflow to simple packet form
        simple_packet_t current_packet;
        current_packet.source       = NETFLOW;
        current_packet.arrival_time = current_inaccurate_time;

        current_packet.agent_ip_address = client_ipv4_address;

        current_packet.src_ip     = netflow5_flow->src_ip;
        current_packet.dst_ip     = netflow5_flow->dest_ip;
        current_packet.ts.tv_sec  = ntohl(netflow5_header->time_sec);
        current_packet.ts.tv_usec = ntohl(netflow5_header->time_nanosec);
        current_packet.flags      = 0; //-V1048

        // If we have ASN information it should not be zero
        current_packet.src_asn = fast_ntoh(netflow5_flow->src_as);
        current_packet.dst_asn = fast_ntoh(netflow5_flow->dest_as);

        // We do not need fast_ntoh here because we already converted these fields before
        current_packet.input_interface  = fast_ntoh(netflow5_flow->if_index_in);
        current_packet.output_interface = fast_ntoh(netflow5_flow->if_index_out);

        current_packet.source_port      = 0; //-V1048
        current_packet.destination_port = 0; //-V1048

        // TODO: we should pass data about "flow" structure of this data
        // It's pretty interesting because according to Cisco's
        // http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006186
        // In Netflow v5 we have "Total number of Layer 3 bytes in the packets of the flow"
        // TODO: so for full length we should use flow_octets + 14 bytes per each packet for more reliable bandwidth
        // detection
        current_packet.length = fast_ntoh(netflow5_flow->flow_octets);

        // Netflow carries only information about number of octets including IP headers and IP payload
        // which is exactly what we need for ip_length field
        current_packet.ip_length = current_packet.length;

        current_packet.number_of_packets = fast_ntoh(netflow5_flow->flow_packets);

        // This interval in milliseconds, convert it to seconds
        int64_t interval_length = (fast_ntoh(netflow5_flow->flow_finish) - fast_ntoh(netflow5_flow->flow_start)) / 1000;

        increment_duration_counters_netflow_v5(interval_length);

        // TODO: use sampling data from packet, disable customization here
        // Wireshark dump approves this idea
        current_packet.sample_ratio = netflow5_sampling_ratio;

        current_packet.source_port      = fast_ntoh(netflow5_flow->src_port);
        current_packet.destination_port = fast_ntoh(netflow5_flow->dest_port);

        // We do not support IPv6 in Netflow v5 at all
        current_packet.ip_protocol_version = 4; //-V1048

        switch (netflow5_flow->protocol) {
        case 1: {
            // ICMP
            current_packet.protocol = IPPROTO_ICMP;
        } break;

        case 6: {
            // TCP
            current_packet.protocol = IPPROTO_TCP;

            // TODO: flags can be in another format!
            current_packet.flags = netflow5_flow->tcp_flags;
        } break;

        case 17: {
            // UDP
            current_packet.protocol = IPPROTO_UDP;
        } break;
        }

        // Call processing function for every flow in packet
        netflow_process_func_ptr(current_packet);
    }

    return true;
}


