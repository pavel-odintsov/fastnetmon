#include "pfring.h"

#include <string.h>
#include <string>
#include <vector>

#include "../fastnetmon_actions.h"

// Got it from global namespace
extern pfring* pf_ring_descr;

void pfring_hardware_filter_action_block(std::string client_ip_as_string) {
    /* 6 - tcp, 17 - udp, 0 - other (non tcp and non udp) */
    std::vector<int> banned_protocols;
    banned_protocols.push_back(17);
    banned_protocols.push_back(6);
    banned_protocols.push_back(0);

    int rule_number = 10;

    // Iterate over incoming and outgoing direction
    for (int rule_direction = 0; rule_direction < 2; rule_direction++) {
        for (std::vector<int>::iterator banned_protocol = banned_protocols.begin();
             banned_protocol != banned_protocols.end(); ++banned_protocol) {

            /* On 82599 NIC we can ban traffic using hardware filtering rules */

            // Difference between fie tuple and perfect filters:
            // http://www.ntop.org/products/pf_ring/hardware-packet-filtering/

            hw_filtering_rule rule;
            intel_82599_five_tuple_filter_hw_rule* ft_rule;

            ft_rule = &rule.rule_family.five_tuple_rule;

            memset(&rule, 0, sizeof(rule));
            rule.rule_family_type = intel_82599_five_tuple_rule;
            rule.rule_id = rule_number++;
            ft_rule->queue_id = -1; // drop traffic
            ft_rule->proto = *banned_protocol;

            std::string hw_filter_rule_direction = "";
            if (rule_direction == 0) {
                hw_filter_rule_direction = "outgoing";
                ft_rule->s_addr = ntohl(inet_addr(client_ip_as_string.c_str()));
            } else {
                hw_filter_rule_direction = "incoming";
                ft_rule->d_addr = ntohl(inet_addr(client_ip_as_string.c_str()));
            }

            if (pfring_add_hw_rule(pf_ring_descr, &rule) != 0) {
                logger << log4cpp::Priority::ERROR
                       << "Can't add hardware filtering rule for protocol: " << *banned_protocol
                       << " in direction: " << hw_filter_rule_direction;
            }

            rule_number++;
        }
    }
}
