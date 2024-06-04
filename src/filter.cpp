#include "filter.hpp"

#include "iana_ip_protocols.hpp"

#include "ip_lookup_tree.hpp"

// Filter packet if it matches list of active flow spec announces
bool filter_packet_by_flowspec_rule_list(const simple_packet_t& current_packet,
                                         const std::vector<flow_spec_rule_t>& active_flow_spec_announces) {
    for (auto& flow_announce : active_flow_spec_announces) {
        // Check that any rule matches specific flow spec announce
        if (filter_packet_by_flowspec_rule(current_packet, flow_announce)) {
            return true;
        }
    }

    return false;
}

// Returns true when packet matches specific rule
bool filter_packet_by_flowspec_rule(const simple_packet_t& current_packet, const flow_spec_rule_t& flow_announce) {
    bool source_port_matches         = false;
    bool destination_port_matches    = false;
    bool source_ip_matches           = false;
    bool destination_ip_matches      = false;
    bool packet_size_matches         = false;
    bool vlan_matches                = false;
    bool tcp_flags_matches           = false;
    bool fragmentation_flags_matches = false;
    bool protocol_matches            = false;

    if (flow_announce.source_ports.size() == 0) {
        source_port_matches = true;
    } else {
        if (std::find(flow_announce.source_ports.begin(), flow_announce.source_ports.end(), current_packet.source_port) !=
            flow_announce.source_ports.end()) {
            // We found this IP in list
            source_port_matches = true;
        }
    }

    if (flow_announce.destination_ports.size() == 0) {
        destination_port_matches = true;
    } else {
        if (std::find(flow_announce.destination_ports.begin(), flow_announce.destination_ports.end(),
                      current_packet.destination_port) != flow_announce.destination_ports.end()) {
            // We found this IP in list
            destination_port_matches = true;
        }
    }

    if (flow_announce.protocols.size() == 0) {
        protocol_matches = true;
    } else {
        if (current_packet.protocol <= 255) {
            // Convert protocol as number into strictly typed protocol_type
            ip_protocol_t flow_protocol = get_ip_protocol_enum_type_from_integer(uint8_t(current_packet.protocol));

            if (std::find(flow_announce.protocols.begin(), flow_announce.protocols.end(), flow_protocol) !=
                flow_announce.protocols.end()) {
                protocol_matches = true;
            }
        } else {
            // Protocol cannot exceed 255!
        }
    }

    if (flow_announce.source_subnet_ipv4_used) {
        subnet_cidr_mask_t src_subnet;

        if (flow_announce.source_subnet_ipv4.cidr_prefix_length == 32) {

            src_subnet.set_cidr_prefix_length(32);
            src_subnet.set_subnet_address(current_packet.src_ip);

            if (flow_announce.source_subnet_ipv4 == src_subnet) {
                source_ip_matches = true;
            }
        } else {
            // We build Patricia tree for lookup but it's not very effective from performance perspective
            // To improve performance you may write native function to check if IP belongs to subnet_cidr_mask_t
            lookup_tree_32bit_t lookup_tree;

            lookup_tree.add_subnet(flow_announce.source_subnet_ipv4);

            if (lookup_tree.lookup_ip(current_packet.src_ip)) {
                source_ip_matches = true;
            }
        }
    } else if (flow_announce.source_subnet_ipv6_used) {
        if (flow_announce.source_subnet_ipv6.cidr_prefix_length == 128) {
            subnet_ipv6_cidr_mask_t src_subnet;

            src_subnet.set_cidr_prefix_length(128);
            src_subnet.set_subnet_address(&current_packet.src_ipv6);

            if (flow_announce.source_subnet_ipv6 == src_subnet) {
                source_ip_matches = true;
            }
        } else {
            // We do not support non /128 boundaries yet
        }
    } else {
        source_ip_matches = true;
    }

    if (flow_announce.destination_subnet_ipv4_used) {
        if (flow_announce.destination_subnet_ipv4.cidr_prefix_length == 32) {
            subnet_cidr_mask_t dst_subnet;

            dst_subnet.set_cidr_prefix_length(32);
            dst_subnet.set_subnet_address(current_packet.dst_ip);

            if (flow_announce.destination_subnet_ipv4 == dst_subnet) {
                destination_ip_matches = true;
            }
        } else {
            // We build Patricia tree for lookup but it's not very effective from performance perspective
            // To improve performance you may write native function to check if IP belongs to subnet_cidr_mask_t
            lookup_tree_32bit_t lookup_tree;

            lookup_tree.add_subnet(flow_announce.destination_subnet_ipv4);

            if (lookup_tree.lookup_ip(current_packet.dst_ip)) {
                destination_ip_matches = true;
            }
        }
    } else if (flow_announce.destination_subnet_ipv6_used) {
        if (flow_announce.destination_subnet_ipv6.cidr_prefix_length == 128) {
            subnet_ipv6_cidr_mask_t dst_subnet;

            dst_subnet.set_cidr_prefix_length(128);
            dst_subnet.set_subnet_address(&current_packet.dst_ipv6);

            if (flow_announce.destination_subnet_ipv6 == dst_subnet) {
                destination_ip_matches = true;
            }
        } else {
            // We do not support non /128 boundaries yet
        }
    } else {
        destination_ip_matches = true;
    }

    if (flow_announce.fragmentation_flags.size() == 0) {
        fragmentation_flags_matches = true;
    } else {
        for (auto& fragmentation_flag : flow_announce.fragmentation_flags) {
            // TODO: we are using only this two options in detection code but we should cover ALL possible cases!
            if (fragmentation_flag == flow_spec_fragmentation_types_t::FLOW_SPEC_DONT_FRAGMENT) {
                if (current_packet.ip_dont_fragment) {
                    fragmentation_flags_matches = true;
                }
            } else if (fragmentation_flag == flow_spec_fragmentation_types_t::FLOW_SPEC_IS_A_FRAGMENT) {
                if (current_packet.ip_fragmented) {
                    fragmentation_flags_matches = true;
                }
            }
        }
    }

    if (flow_announce.tcp_flags.size() == 0) {
        tcp_flags_matches = true;
    } else {
        // Convert 8bit representation of flags for this packet into flagset representation for flow spec
        flow_spec_tcp_flagset_t flagset;
        uint8t_representation_of_tcp_flags_to_flow_spec(current_packet.flags, flagset);

        // logger << log4cpp::Priority::WARN <<"Packet's tcp flagset: " << flagset.to_string();

        if (std::find(flow_announce.tcp_flags.begin(), flow_announce.tcp_flags.end(), flagset) !=
            flow_announce.tcp_flags.end()) {
            tcp_flags_matches = true;
        }
    }

    if (flow_announce.packet_lengths.size() == 0) {
        packet_size_matches = true;
    } else {
        // Use matching only if we can convert it to 16 bit value
        if (current_packet.length <= 65635) {
            // Convert 64 bit (we need it because netflow) value to 16 bit
            uint16_t packet_length_uint16 = (uint16_t)current_packet.length;

            // TODO: it's a bit incorrect to use check against packet length here
            // because as mentioned below we use total ip length for flow spec rules.
            // And here we have FULL packet length (including L2, Ethernet header)
            // But we just added ip_length field and need to check both
            if (std::find(flow_announce.packet_lengths.begin(), flow_announce.packet_lengths.end(), packet_length_uint16) !=
                flow_announce.packet_lengths.end()) {
                packet_size_matches = true;
            }

            // Flow spec uses length in form "total length of IP packet" and we should check it
            uint16_t ip_packet_length_uint16 = (uint16_t)current_packet.ip_length;

            if (std::find(flow_announce.packet_lengths.begin(), flow_announce.packet_lengths.end(),
                          ip_packet_length_uint16) != flow_announce.packet_lengths.end()) {
                packet_size_matches = true;
            }
        }
    }

    if (flow_announce.vlans.size() == 0) {
        vlan_matches = true;
    } else {
        if (std::find(flow_announce.vlans.begin(), flow_announce.vlans.end(), current_packet.vlan) !=
            flow_announce.vlans.end()) {
            vlan_matches = true;
        }
    }

    // Nice thing for debug
    /*
    logger << log4cpp::Priority::WARN
        << "source_port_matches: " << source_port_matches << " "
        << "destination_port_matches: " << destination_port_matches << " "
        << "source_ip_matches: " << source_ip_matches << " "
        << "destination_ip_matches: " << destination_ip_matches << " "
        << "packet_size_matches: " << packet_size_matches << " "
        << "tcp_flags_matches: " << tcp_flags_matches << " "
        << "fragmentation_flags_matches: " << fragmentation_flags_matches << " "
        << "protocol_matches: " << protocol_matches;
    */

    // Return true only of all parts matched
    if (source_port_matches && destination_port_matches && source_ip_matches && destination_ip_matches &&
        packet_size_matches && tcp_flags_matches && fragmentation_flags_matches && protocol_matches && vlan_matches) {
        return true;
    }

    return false;
}
