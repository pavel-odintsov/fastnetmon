#include "gobgp_action.hpp"
#include "../fastnetmon_actions.hpp"

#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

#include "../bgp_protocol.hpp"

#include "../gobgp_client/gobgp_client.hpp"

#include "../fastnetmon_configuration_scheme.hpp"

extern fastnetmon_configuration_t fastnetmon_global_configuration;

void gobgp_action_init() {
    logger << log4cpp::Priority::INFO << "GoBGP action module loaded";

    if (configuration_map.count("gobgp_next_hop")) {
        fastnetmon_global_configuration.gobgp_next_hop = configuration_map["gobgp_next_hop"];
    }

    if (configuration_map.count("gobgp_next_hop_ipv6")) {
        fastnetmon_global_configuration.gobgp_next_hop_ipv6 = configuration_map["gobgp_next_hop_ipv6"];
    }

    if (configuration_map.count("gobgp_next_hop_host_ipv6")) {
        fastnetmon_global_configuration.gobgp_next_hop_host_ipv6 = configuration_map["gobgp_next_hop_host_ipv6"];
    }

    if (configuration_map.count("gobgp_next_hop_subnet_ipv6")) {
        fastnetmon_global_configuration.gobgp_next_hop_subnet_ipv6 = configuration_map["gobgp_next_hop_subnet_ipv6"];
    }

    if (configuration_map.count("gobgp_announce_host")) {
        fastnetmon_global_configuration.gobgp_announce_host = configuration_map["gobgp_announce_host"] == "on";
    }

    if (configuration_map.count("gobgp_announce_whole_subnet")) {
        fastnetmon_global_configuration.gobgp_announce_whole_subnet = configuration_map["gobgp_announce_whole_subnet"] == "on";
    }

    if (configuration_map.count("gobgp_announce_host_ipv6")) {
        fastnetmon_global_configuration.gobgp_announce_host_ipv6 = configuration_map["gobgp_announce_host_ipv6"] == "on";
    }

    if (configuration_map.count("gobgp_announce_whole_subnet_ipv6")) {
        fastnetmon_global_configuration.gobgp_announce_whole_subnet_ipv6 = configuration_map["gobgp_announce_whole_subnet_ipv6"] == "on";
    }

    if (configuration_map.count("gobgp_community_host")) {
	fastnetmon_global_configuration.gobgp_community_host = configuration_map["gobgp_community_host"];
    }

    if (configuration_map.count("gobgp_community_subnet")) {
        fastnetmon_global_configuration.gobgp_community_subnet = configuration_map["gobgp_community_subnet"];
    }

    if (configuration_map.count("gobgp_community_host_ipv6")) {
        fastnetmon_global_configuration.gobgp_community_host_ipv6 = configuration_map["gobgp_community_host_ipv6"];	    
    }

    if (configuration_map.count("gobgp_community_subnet_ipv6")) {
        fastnetmon_global_configuration.gobgp_community_subnet_ipv6 = configuration_map["gobgp_community_subnet_ipv6"];
    }
}

void gobgp_action_shutdown() {
}

void gobgp_ban_manage_ipv6(GrpcClient& gobgp_client,
                           const subnet_ipv6_cidr_mask_t& client_ipv6,
                           bool is_withdrawal,
                           const attack_details_t& current_attack) {
    // TODO: that's very weird approach to use subnet_ipv6_cidr_mask_t for storing next hop which is HOST address
    // We need to rework all structures in stack of BGP logic to switch it to plain in6_addr

    subnet_ipv6_cidr_mask_t ipv6_next_hop_legacy{};
    ipv6_next_hop_legacy.cidr_prefix_length = 128; //-V1048

    bool parsed_next_hop_result =
        read_ipv6_host_from_string(fastnetmon_global_configuration.gobgp_next_hop_ipv6, ipv6_next_hop_legacy.subnet_address);

    if (!parsed_next_hop_result) {
        logger << log4cpp::Priority::ERROR
               << "Can't parse specified IPv6 next hop to IPv6 address: " << fastnetmon_global_configuration.gobgp_next_hop_ipv6;
        return;
    }

    // Starting July 2024, 1.2.8 we have capability to specify different next hops for host and subnet
    subnet_ipv6_cidr_mask_t gobgp_next_hop_host_ipv6{};
    gobgp_next_hop_host_ipv6.cidr_prefix_length = 128; //-V1048

    if (fastnetmon_global_configuration.gobgp_next_hop_host_ipv6 != "") {
        if (!read_ipv6_host_from_string(fastnetmon_global_configuration.gobgp_next_hop_host_ipv6,
                                        gobgp_next_hop_host_ipv6.subnet_address)) {
            logger << log4cpp::Priority::ERROR << "Can't parse specified IPv6 next hop gobgp_next_hop_host_ipv6 as IPv6 address: "
                   << fastnetmon_global_configuration.gobgp_next_hop_host_ipv6;
            // We do not stop processing here. If we failed then let's keep it zero
        }
    } else {
        // That's fine. It's expected to be empty on new installations
    }

    // Starting July 2024, 1.2.8 we have capability to specify different next hops for host and subnet
    subnet_ipv6_cidr_mask_t gobgp_next_hop_subnet_ipv6{};
    gobgp_next_hop_subnet_ipv6.cidr_prefix_length = 128; //-V1048

    if (fastnetmon_global_configuration.gobgp_next_hop_subnet_ipv6 != "") {
        if (!read_ipv6_host_from_string(fastnetmon_global_configuration.gobgp_next_hop_subnet_ipv6,
                                        gobgp_next_hop_subnet_ipv6.subnet_address)) {
            logger << log4cpp::Priority::ERROR << "Can't parse specified IPv6 next hop gobgp_next_hop_subnet_ipv6 as IPv6 address: "
                   << fastnetmon_global_configuration.gobgp_next_hop_subnet_ipv6;
            // We do not stop processing here. If we failed then let's keep it zero
        }
    } else {
        // That's fine. It's expected to be empty on new installations
    }

    // For backward compatibility with old deployments which still use value gobgp_next_hop_ipv6 we check new value and if it's zero use old one
    if (is_zero_ipv6_address(gobgp_next_hop_host_ipv6.subnet_address)) {
        logger << log4cpp::Priority::INFO << "gobgp_next_hop_host_ipv6 is zero, will use global gobgp_next_hop_ipv6: "
               << fastnetmon_global_configuration.gobgp_next_hop_ipv6;

        gobgp_next_hop_host_ipv6.subnet_address = ipv6_next_hop_legacy.subnet_address;
    }

    if (is_zero_ipv6_address(gobgp_next_hop_subnet_ipv6.subnet_address)) {
        logger << log4cpp::Priority::INFO << "gobgp_next_hop_subnet_ipv6 is zero, will use global gobgp_next_hop_ipv6: "
               << fastnetmon_global_configuration.gobgp_next_hop_ipv6;

        gobgp_next_hop_subnet_ipv6.subnet_address = ipv6_next_hop_legacy.subnet_address;
    }

    if (fastnetmon_global_configuration.gobgp_announce_host_ipv6) {
        IPv6UnicastAnnounce unicast_ipv6_announce;

        std::vector<std::string> host_ipv6_communities;

        // This one is an old configuration option which can carry only single community
        host_ipv6_communities.push_back(fastnetmon_global_configuration.gobgp_community_host_ipv6);

        for (auto community_string : host_ipv6_communities) {
            bgp_community_attribute_element_t bgp_community_host;

            if (!read_bgp_community_from_string(community_string, bgp_community_host)) {
                logger << log4cpp::Priority::ERROR << "Could not decode BGP community for IPv6 host: " << community_string;
                // We may have multiple communities and other communities may be correct, skip only broken one
                continue;
            }

            unicast_ipv6_announce.add_community(bgp_community_host);
        }

        unicast_ipv6_announce.set_prefix(client_ipv6);
        unicast_ipv6_announce.set_next_hop(gobgp_next_hop_host_ipv6);

        gobgp_client.AnnounceUnicastPrefixLowLevelIPv6(unicast_ipv6_announce, is_withdrawal);
    }

    if (fastnetmon_global_configuration.gobgp_announce_whole_subnet_ipv6) {
        logger << log4cpp::Priority::ERROR << "Sorry but we do not support IPv6 per subnet announces";
    }
}

void gobgp_ban_manage_ipv4(GrpcClient& gobgp_client, uint32_t client_ip, bool is_withdrawal, const attack_details_t& current_attack) {
    // Previously we used same next hop for both subnet and host
    uint32_t next_hop_as_integer_legacy = 0;

    if (!convert_ip_as_string_to_uint_safe(fastnetmon_global_configuration.gobgp_next_hop, next_hop_as_integer_legacy)) {
        logger << log4cpp::Priority::ERROR
               << "Could not decode next hop to numeric form: " << fastnetmon_global_configuration.gobgp_next_hop;
        return;
    }

    // Starting July 2024, 1.1.8 we have capability to specify different next hops for host and subnet
    uint32_t gobgp_next_hop_host_ipv4   = 0;
    uint32_t gobgp_next_hop_subnet_ipv4 = 0;

    // Read next hop for host
    if (fastnetmon_global_configuration.gobgp_next_hop_host_ipv4 != "") {
        if (!convert_ip_as_string_to_uint_safe(fastnetmon_global_configuration.gobgp_next_hop_host_ipv4, gobgp_next_hop_host_ipv4)) {
            logger << log4cpp::Priority::ERROR << "Could not decode next hop to numeric form for gobgp_next_hop_host_ipv4: "
                   << fastnetmon_global_configuration.gobgp_next_hop_host_ipv4;
            // We do not stop processing here. If we failed then let's keep it zero
        }
    } else {
        // That's fine. It's expected to be empty on new installations
    }


    // Read next hop for subnet
    if (fastnetmon_global_configuration.gobgp_next_hop_subnet_ipv4 != "") {
        if (!convert_ip_as_string_to_uint_safe(fastnetmon_global_configuration.gobgp_next_hop_subnet_ipv4, gobgp_next_hop_subnet_ipv4)) {
            logger << log4cpp::Priority::ERROR << "Could not decode next hop to numeric form for gobgp_next_hop_subnet_ipv4: "
                   << fastnetmon_global_configuration.gobgp_next_hop_subnet_ipv4;

            // We do not stop processing here. If we failed then let's keep it zero
        }
    } else {
        // That's fine. It's expected to be empty on new installations
    }

    // For backward compatibility with old deployments which still use value gobgp_next_hop we check new value and if it's zero use old one
    if (gobgp_next_hop_host_ipv4 == 0) {
        logger << log4cpp::Priority::INFO << "gobgp_next_hop_host_ipv4 is empty, will use global gobgp_next_hop: "
               << fastnetmon_global_configuration.gobgp_next_hop;
        gobgp_next_hop_host_ipv4 = next_hop_as_integer_legacy;
    }

    if (gobgp_next_hop_subnet_ipv4 == 0) {
        logger << log4cpp::Priority::INFO << "gobgp_next_hop_subnet_ipv4 is empty, will use global gobgp_next_hop: "
               << fastnetmon_global_configuration.gobgp_next_hop;
        gobgp_next_hop_subnet_ipv4 = next_hop_as_integer_legacy;
    }

    if (fastnetmon_global_configuration.gobgp_announce_whole_subnet) {
        IPv4UnicastAnnounce unicast_ipv4_announce;

        std::vector<std::string> subnet_ipv4_communities;

        subnet_ipv4_communities.push_back(fastnetmon_global_configuration.gobgp_community_subnet);

        for (auto community_string : subnet_ipv4_communities) {
            bgp_community_attribute_element_t bgp_community_subnet;

            if (!read_bgp_community_from_string(community_string, bgp_community_subnet)) {
                logger << log4cpp::Priority::ERROR << "Could not decode BGP community for IPv4 subnet";
                // We may have multiple communities and other communities may be correct, skip only broken one
                continue;
            }

            unicast_ipv4_announce.add_community(bgp_community_subnet);
        }

        // By default use network from attack
        subnet_cidr_mask_t customer_network;
        customer_network.subnet_address     = current_attack.customer_network.subnet_address;
        customer_network.cidr_prefix_length = current_attack.customer_network.cidr_prefix_length;

        unicast_ipv4_announce.set_prefix(customer_network);
        unicast_ipv4_announce.set_next_hop(gobgp_next_hop_subnet_ipv4);

        gobgp_client.AnnounceUnicastPrefixLowLevelIPv4(unicast_ipv4_announce, is_withdrawal);
    }

    if (fastnetmon_global_configuration.gobgp_announce_host) {
        IPv4UnicastAnnounce unicast_ipv4_announce;

        std::vector<std::string> host_ipv4_communities;

        host_ipv4_communities.push_back(fastnetmon_global_configuration.gobgp_community_host);

        for (auto community_string : host_ipv4_communities) {
            bgp_community_attribute_element_t bgp_community_host;

            if (!read_bgp_community_from_string(community_string, bgp_community_host)) {
                logger << log4cpp::Priority::ERROR << "Could not decode BGP community for IPv4 host: " << community_string;
                // We may have multiple communities and other communities may be correct, skip only broken one
                continue;
            }

            unicast_ipv4_announce.add_community(bgp_community_host);
        }

        subnet_cidr_mask_t host_address_as_subnet(client_ip, 32);

        unicast_ipv4_announce.set_prefix(host_address_as_subnet);
        unicast_ipv4_announce.set_next_hop(gobgp_next_hop_host_ipv4);

        gobgp_client.AnnounceUnicastPrefixLowLevelIPv4(unicast_ipv4_announce, is_withdrawal);
    }
}


void gobgp_ban_manage(const std::string& action,
                      bool ipv6,
                      uint32_t client_ip,
                      const subnet_ipv6_cidr_mask_t& client_ipv6,
                      const attack_details_t& current_attack) {
    GrpcClient gobgp_client = GrpcClient(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));

    bool is_withdrawal = false;

    std::string action_name;

    if (action == "ban") {
        is_withdrawal = false;
        action_name   = "announce";
    } else {
        is_withdrawal = true;
        action_name   = "withdraw";
    }

    if (ipv6) {
        gobgp_ban_manage_ipv6(gobgp_client, client_ipv6, is_withdrawal, current_attack);
    } else {
    	gobgp_ban_manage_ipv4(gobgp_client, client_ip, is_withdrawal, current_attack);
    }
}
