#ifndef GOBGP_ACTION_H
#define GOBGP_ACTION_H

#include <string>
#include "../fastnetmon_types.h"

void gobgp_action_init();
void gobgp_action_shutdown();
void gobgp_ban_manage(std::string action, std::string ip_as_string, attack_details current_attack);

#endif
