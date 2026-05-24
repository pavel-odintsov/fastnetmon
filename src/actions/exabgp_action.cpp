#include "exabgp_action.hpp"

#include <string>

// Migrate to STL <format> after migration to GCC 13+

#define FMT_HEADER_ONLY
#include "../fmt/compile.h"
#include "../fmt/format.h"

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
    std::string bgp_message;

    if (action == "ban") {
        // Migrate fmt::format to std::format after migration to GCC 13+
        bgp_message = fmt::format("announce route {} next-hop {} community {}\n",
            prefix_as_string_with_mask, exabgp_next_hop, exabgp_community);
    } else {
        bgp_message = fmt::format("withdraw route {} next-hop {}\n",
            prefix_as_string_with_mask, exabgp_next_hop);
    }

    logger << log4cpp::Priority::INFO << "ExaBGP announce message: " << bgp_message;

    int exabgp_pipe = open(exabgp_command_pipe.c_str(), O_WRONLY);

    if (exabgp_pipe <= 0) {
        logger << log4cpp::Priority::ERROR << "Can't open ExaBGP pipe " << exabgp_command_pipe << " Ban is not executed";
        return;
    }

    int wrote_bytes = write(exabgp_pipe, bgp_message.c_str(), bgp_message.size());

    if (wrote_bytes != bgp_message.size()) {
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
