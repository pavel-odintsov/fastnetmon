#pragma once

#include <boost/serialization/array.hpp>
#include <boost/serialization/nvp.hpp>

// structure with attack details
class attack_details_t {
    public:
    // This operation is very heavy, it may crash in case of entropy shortage and it actually happened to our customer
    bool generate_uuid() {
        boost::uuids::random_generator gen;

        try {
            attack_uuid = gen();
        } catch (...) {
            return false;
        }

        return true;
    }

    std::string get_protocol_name() const {
        if (ipv6) {
            return "IPv6";
        } else {
            return "IPv4";
        }
    }

    // Host group for this attack
    std::string host_group;

    // Parent hostgroup for host's host group
    std::string parent_host_group;

    direction_t attack_direction = OTHER;

    // first attackpower detected
    uint64_t attack_power = 0;

    // max attack power
    uint64_t max_attack_power    = 0;
    unsigned int attack_protocol = 0;

    // Separate section with traffic counters
    subnet_counter_t traffic_counters{};

    // Time when we ban this IP
    time_t ban_timestamp = 0;
    bool unban_enabled   = true;
    int ban_time         = 0; // seconds of the ban

    // If this attack was detected for IPv6 protocol
    bool ipv6 = false;

    subnet_cidr_mask_t customer_network;

    attack_detection_source_t attack_detection_source = attack_detection_source_t::Automatic;
    boost::uuids::uuid attack_uuid{};
    attack_severity_t attack_severity = ATTACK_SEVERITY_MIDDLE;

    // Threshold used to trigger this attack
    attack_detection_threshold_type_t attack_detection_threshold = attack_detection_threshold_type_t::unknown;

    packet_storage_t pcap_attack_dump;

    // Direction of threshold used to trigger this attack
    attack_detection_direction_type_t attack_detection_direction = attack_detection_direction_type_t::unknown;

    std::string get_attack_uuid_as_string() const {
        return boost::uuids::to_string(attack_uuid);
    }
};

// TODO: remove it
typedef attack_details_t banlist_item_t;
