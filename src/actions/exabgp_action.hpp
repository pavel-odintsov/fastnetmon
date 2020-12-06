#include <string>
#include "../fastnetmon_types.h"

void exabgp_ban_manage(std::string action, std::string ip_as_string, attack_details_t current_attack);
bool exabgp_flow_spec_ban_manage(std::string action, std::string flow_spec_rule_as_text);
