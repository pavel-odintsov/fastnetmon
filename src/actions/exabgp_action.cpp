#include "exabgp_action.hpp"

#include <string>

#include "../fast_library.hpp"

#include "../all_logcpp_libraries.hpp"

extern bool exabgp_enabled;
extern std::string exabgp_community;
extern std::string exabgp_community_subnet;
extern std::string exabgp_community_host;
extern std::string exabgp_command_pipe;
extern std::string exabgp_next_hop;
extern bool exabgp_announce_host;
extern bool exabgp_announce_whole_subnet;

extern log4cpp::Category& logger;

// Low level ExaBGP ban management
void exabgp_prefix_ban_manage(std::string action, std::string prefix_as_string_with_mask, std::string exabgp_next_hop, std::string exabgp_community) {

    /* Buffer for BGP message */
    char bgp_message[256];

    if (action == "ban") {
        sprintf(bgp_message, "announce route %s next-hop %s community %s\n", prefix_as_string_with_mask.c_str(),
                exabgp_next_hop.c_str(), exabgp_community.c_str());
    } else {
        sprintf(bgp_message, "withdraw route %s next-hop %s\n", prefix_as_string_with_mask.c_str(), exabgp_next_hop.c_str());
    }

    logger << log4cpp::Priority::INFO << "ExaBGP announce message: " << bgp_message;

    int exabgp_pipe = open(exabgp_command_pipe.c_str(), O_WRONLY);

    if (exabgp_pipe <= 0) {
        logger << log4cpp::Priority::ERROR << "Can't open ExaBGP pipe " << exabgp_command_pipe << " Ban is not executed";
        return;
    }

    int wrote_bytes = write(exabgp_pipe, bgp_message, strlen(bgp_message));

    if (wrote_bytes != strlen(bgp_message)) {
        logger << log4cpp::Priority::ERROR << "Can't write message to ExaBGP pipe";
    }

    close(exabgp_pipe);
}

void exabgp_ban_manage(const std::string& action, const std::string& ip_as_string, const subnet_cidr_mask_t& customer_network) {
    // We will announce whole subnet here
    if (exabgp_announce_whole_subnet) {
        std::string subnet_as_string_with_mask = convert_subnet_to_string(customer_network);

        exabgp_prefix_ban_manage(action, subnet_as_string_with_mask, exabgp_next_hop, exabgp_community_subnet);
    }

    // And we could announce single host here (/32)
    if (exabgp_announce_host) {
        std::string ip_as_string_with_mask = ip_as_string + "/32";

        exabgp_prefix_ban_manage(action, ip_as_string_with_mask, exabgp_next_hop, exabgp_community_host);
    }
}
