#ifndef GOBGP_ACTION_H
#define GOBGP_ACTION_H

#include "../fastnetmon_types.h"
#include <string>

void gobgp_action_init();
void gobgp_action_shutdown();
void gobgp_ban_manage(std::string action, bool ipv6, std::string ip_as_string, subnet_ipv6_cidr_mask_t client_ipv6, attack_details_t current_attack);

#endif
