#pragma once

#include "../fastnetmon_types.hpp"
#include <string>

void gobgp_action_init();
void gobgp_action_shutdown();
void gobgp_ban_manage(const std::string& action, bool ipv6, const std::string& ip_as_string, const subnet_ipv6_cidr_mask_t& client_ipv6, const subnet_cidr_mask_t& customer_network);
