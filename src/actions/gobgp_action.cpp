#include "gobgp_action.hpp"
#include "../fastnetmon_actions.hpp"

#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

#include "../bgp_protocol.hpp"

#include "../gobgp_client/gobgp_client.hpp"

#include "../fastnetmon_configuration_scheme.hpp"

std::string gobgp_nexthop        = "0.0.0.0";

bgp_community_attribute_element_t bgp_community_host;
bgp_community_attribute_element_t bgp_community_subnet;

extern fastnetmon_configuration_t fastnetmon_global_configuration;

void gobgp_action_init() {
    logger << log4cpp::Priority::INFO << "GoBGP action module loaded";

    if (configuration_map.count("gobgp_next_hop")) {
        gobgp_nexthop = configuration_map["gobgp_next_hop"];
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

    // Set them to safe defaults
    bgp_community_host.asn_number       = 65001;
    bgp_community_host.community_number = 666;

    if (configuration_map.count("gobgp_community_host")) {
        if (!read_bgp_community_from_string(configuration_map["gobgp_community_host"], bgp_community_host)) {
            logger << log4cpp::Priority::ERROR << "Cannot parse GoBGP community for host "
                   << configuration_map["gobgp_community_host"];
        }
    }

    logger << log4cpp::Priority::INFO << "GoBGP host IPv4 community: " << bgp_community_host.asn_number << ":"
           << bgp_community_host.community_number;

    // Set them to safe defaults
    bgp_community_subnet.asn_number       = 65001;
    bgp_community_subnet.community_number = 666;

    if (configuration_map.count("gobgp_community_subnet")) {
        if (!read_bgp_community_from_string(configuration_map["gobgp_community_subnet"], bgp_community_subnet)) {
            logger << log4cpp::Priority::ERROR << "Cannot parse GoBGP community for subnet "
                   << configuration_map["gobgp_community_subnet"];
        }
    }

    logger << log4cpp::Priority::INFO << "GoBGP subnet IPv4 community: " << bgp_community_subnet.asn_number << ":"
           << bgp_community_subnet.community_number;

    if (configuration_map.count("gobgp_community_host_ipv6")) {
        fastnetmon_global_configuration.gobgp_community_host_ipv6 = configuration_map["gobgp_community_host_ipv6"];	    
    }

    logger << log4cpp::Priority::INFO << "GoBGP host IPv6 community: " << bgp_community_host_ipv6.asn_number << ":"
           << bgp_community_host_ipv6.community_number;

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
        if (fastnetmon_global_configuration.gobgp_announce_whole_subnet) {
	    // By default use network from attack
	    subnet_cidr_mask_t customer_network;
	    customer_network.subnet_address     = current_attack.customer_network.subnet_address;
	    customer_network.cidr_prefix_length = current_attack.customer_network.cidr_prefix_length;

            std::string subnet_as_string_with_mask = convert_subnet_to_string(customer_network);
            
	    logger << log4cpp::Priority::INFO << action_name << " "
                   << convert_subnet_to_string(customer_network) << " to GoBGP";

            // https://github.com/osrg/gobgp/blob/0aff30a74216f499b8abfabc50016b041b319749/internal/pkg/table/policy_test.go#L2870
            uint32_t community_as_32bit_int =
                uint32_t(bgp_community_subnet.asn_number << 16 | bgp_community_subnet.community_number);

            gobgp_client.AnnounceUnicastPrefixIPv4(convert_ip_as_uint_to_string(customer_network.subnet_address),
                                                    gobgp_nexthop, is_withdrawal,
                                                    customer_network.cidr_prefix_length, community_as_32bit_int);
        }

        if (fastnetmon_global_configuration.gobgp_announce_host) {
	    std::string ip_as_string = convert_ip_as_uint_to_string(client_ip);
            std::string ip_as_string_with_mask = ip_as_string + "/32";

            logger << log4cpp::Priority::INFO << action_name << " " << ip_as_string_with_mask << " to GoBGP";

            uint32_t community_as_32bit_int = uint32_t(bgp_community_host.asn_number << 16 | bgp_community_host.community_number);

            gobgp_client.AnnounceUnicastPrefixIPv4(ip_as_string, gobgp_nexthop, is_withdrawal, 32, community_as_32bit_int);
        }
    }
}
