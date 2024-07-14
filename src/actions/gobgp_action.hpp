#pragma once

#include "../fastnetmon_types.hpp"
#include "..//attack_details.hpp"

#include <string>

void gobgp_action_init();
void gobgp_action_shutdown();
void gobgp_ban_manage(const std::string& action,
                      bool ipv6,
                      uint32_t client_ip,
                      const subnet_ipv6_cidr_mask_t& client_ipv6,
                      const attack_details_t& current_attack);
