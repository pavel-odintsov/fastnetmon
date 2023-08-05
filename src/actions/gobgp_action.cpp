#include "gobgp_action.hpp"
#include "../fastnetmon_actions.hpp"

#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

#include "../bgp_protocol.hpp"

#include "../gobgp_client/gobgp_client.hpp"

GrpcClient* gobgp_client         = NULL;
std::string gobgp_nexthop        = "0.0.0.0";
bool gobgp_announce_whole_subnet = false;
bool gobgp_announce_host         = false;

bgp_community_attribute_element_t bgp_community_host;
bgp_community_attribute_element_t bgp_community_subnet;

// IPv6
bool gobgp_announce_whole_subnet_ipv6 = false;
bool gobgp_announce_host_ipv6         = false;

bgp_community_attribute_element_t bgp_community_host_ipv6;
bgp_community_attribute_element_t bgp_community_subnet_ipv6;
;

subnet_ipv6_cidr_mask_t ipv6_next_hop;

void gobgp_action_init() {
    logger << log4cpp::Priority::INFO << "GoBGP action module loaded";
    gobgp_client = new GrpcClient(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));

    if (configuration_map.count("gobgp_next_hop")) {
        gobgp_nexthop = configuration_map["gobgp_next_hop"];
    }

    // Set IPv6 hop to safe default
    ipv6_next_hop.cidr_prefix_length = 128;
    read_ipv6_host_from_string("100::1", ipv6_next_hop.subnet_address);

    if (configuration_map.count("gobgp_next_hop_ipv6")) {
        bool parsed_next_hop_result =
            read_ipv6_host_from_string(configuration_map["gobgp_next_hop_ipv6"], ipv6_next_hop.subnet_address);

        if (!parsed_next_hop_result) {
            logger << log4cpp::Priority::ERROR
                   << "Can't parse specified IPv6 next hop to IPv6 address: " << configuration_map["gobgp_next_hop_ipv6"];
        }
    }

    logger << log4cpp::Priority::INFO << "IPv6 next hop: " << print_ipv6_cidr_subnet(ipv6_next_hop);

    if (configuration_map.count("gobgp_announce_host")) {
        gobgp_announce_host = configuration_map["gobgp_announce_host"] == "on";
    }

    if (configuration_map.count("gobgp_announce_whole_subnet")) {
        gobgp_announce_whole_subnet = configuration_map["gobgp_announce_whole_subnet"] == "on";
    }

    if (configuration_map.count("gobgp_announce_host_ipv6")) {
        gobgp_announce_host_ipv6 = configuration_map["gobgp_announce_host_ipv6"] == "on";
    }

    if (configuration_map.count("gobgp_announce_whole_subnet_ipv6")) {
        gobgp_announce_whole_subnet_ipv6 = configuration_map["gobgp_announce_whole_subnet_ipv6"] == "on";
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

    // IPv6 communities
    bgp_community_host_ipv6.asn_number       = 65001;
    bgp_community_host_ipv6.community_number = 666;

    if (configuration_map.count("gobgp_community_host_ipv6")) {
        if (!read_bgp_community_from_string(configuration_map["gobgp_community_host_ipv6"], bgp_community_host_ipv6)) {
            logger << log4cpp::Priority::ERROR << "Cannot parse GoBGP community for IPv6 host "
                   << configuration_map["gobgp_community_host_ipv6"];
        }
    }

    logger << log4cpp::Priority::INFO << "GoBGP host IPv6 community: " << bgp_community_host_ipv6.asn_number << ":"
           << bgp_community_host_ipv6.community_number;

    // Set them to safe defaults
    bgp_community_subnet_ipv6.asn_number       = 65001;
    bgp_community_subnet_ipv6.community_number = 666;


    if (configuration_map.count("gobgp_community_subnet_ipv6")) {
        if (!read_bgp_community_from_string(configuration_map["gobgp_community_subnet_ipv6"], bgp_community_subnet_ipv6)) {
            logger << log4cpp::Priority::ERROR << "Cannot parse GoBGP community for IPv6 subnet "
                   << configuration_map["gobgp_community_subnet_ipv6"];
        }
    }

    logger << log4cpp::Priority::INFO << "GoBGP subnet IPv6 community: " << bgp_community_subnet_ipv6.asn_number << ":"
           << bgp_community_subnet_ipv6.community_number;
}

void gobgp_action_shutdown() {
    delete gobgp_client;
}

void gobgp_ban_manage(const std::string& action, bool ipv6, const std::string& ip_as_string, const subnet_ipv6_cidr_mask_t& client_ipv6, const subnet_cidr_mask_t& customer_network) {
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
        if (gobgp_announce_whole_subnet_ipv6) {
            logger << log4cpp::Priority::ERROR << "Sorry but we do not support IPv6 per subnet announces";
        }

        if (gobgp_announce_host_ipv6) {
            logger << log4cpp::Priority::INFO << action_name << " " << print_ipv6_cidr_subnet(client_ipv6) << " to GoBGP";
            uint32_t community_as_32bit_int =
                uint32_t(bgp_community_host_ipv6.asn_number << 16 | bgp_community_host_ipv6.community_number);

            gobgp_client->AnnounceUnicastPrefixIPv6(client_ipv6, ipv6_next_hop, is_withdrawal, community_as_32bit_int);
        }
    } else {
        if (gobgp_announce_whole_subnet) {
            std::string subnet_as_string_with_mask = convert_subnet_to_string(customer_network);
            logger << log4cpp::Priority::INFO << action_name << " "
                   << convert_subnet_to_string(customer_network) << " to GoBGP";

            // https://github.com/osrg/gobgp/blob/0aff30a74216f499b8abfabc50016b041b319749/internal/pkg/table/policy_test.go#L2870
            uint32_t community_as_32bit_int =
                uint32_t(bgp_community_subnet.asn_number << 16 | bgp_community_subnet.community_number);

            gobgp_client->AnnounceUnicastPrefixIPv4(convert_ip_as_uint_to_string(customer_network.subnet_address),
                                                    gobgp_nexthop, is_withdrawal,
                                                    customer_network.cidr_prefix_length, community_as_32bit_int);
        }

        if (gobgp_announce_host) {
            std::string ip_as_string_with_mask = ip_as_string + "/32";

            logger << log4cpp::Priority::INFO << action_name << " " << ip_as_string_with_mask << " to GoBGP";

            uint32_t community_as_32bit_int = uint32_t(bgp_community_host.asn_number << 16 | bgp_community_host.community_number);

            gobgp_client->AnnounceUnicastPrefixIPv4(ip_as_string, gobgp_nexthop, is_withdrawal, 32, community_as_32bit_int);
        }
    }
}
