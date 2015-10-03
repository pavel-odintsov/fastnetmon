#include "gobgp_action.h"
#include "../fastnetmon_actions.h"
#include "../fastnetmon_types.h"

extern "C" {
    // Gobgp library
    #include "libgobgp.h"
}

#include <grpc/grpc.h>
#include <grpc++/channel.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

void gobgp_ban_manage(std::string action, std::string ip_as_string, attack_details current_attack) {
    // std::string subnet_as_string_with_mask = convert_subnet_to_string(current_attack.customer_network);
    // std::string ip_as_string_with_mask = ip_as_string + "/32";
}
