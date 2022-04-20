#pragma once

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>


// This class stores blocked with blackhole hosts
template <typename TemplateKeyType> class blackhole_ban_list_t {
    public:
    blackhole_ban_list_t() {
    }

    // Is this host blackholed?
    bool is_blackholed(TemplateKeyType client_id) {
        std::lock_guard<std::mutex> lock_guard(structure_mutex);

        return ban_list_storage.count(client_id) > 0;
    }

    // Do we have blackhole with certain uuid?
    // If we have we will return IP address for this mitigation
    bool is_blackholed_by_uuid(boost::uuids::uuid mitigation_uuid, TemplateKeyType& client_id) {
        std::lock_guard<std::mutex> lock_guard(structure_mutex);

        auto itr = std::find_if(ban_list_storage.begin(), ban_list_storage.end(),
                                [mitigation_uuid](const std::pair<const TemplateKeyType, attack_details_t>& pair) {
                                    return pair.second.attack_uuid == mitigation_uuid;
                                });

        if (itr == ban_list_storage.end()) {
            return false;
        }

        client_id = itr->first;
        return true;
    }

    // Add host to blackhole
    bool add_to_blackhole(TemplateKeyType client_id, attack_details_t current_attack) {
        std::lock_guard<std::mutex> lock_guard(structure_mutex);

        ban_list_storage[client_id] = current_attack;
        return true;
    }

    bool remove_from_blackhole(TemplateKeyType client_id) {
        std::lock_guard<std::mutex> lock_guard(structure_mutex);

        ban_list_storage.erase(client_id);

        return true;
    }

    bool remove_from_blackhole_and_keep_copy(TemplateKeyType client_id, attack_details_t& current_attack) {
        std::lock_guard<std::mutex> lock_guard(structure_mutex);

        // Confirm that we still have this element in storage
        if (ban_list_storage.count(client_id) == 0) {
            return false;
        }

        // Copy current value
        current_attack = ban_list_storage[client_id];

        // Remove it
        ban_list_storage.erase(client_id);

        return true;
    }

    // Add blackholed hosts from external storage to internal
    bool set_whole_banlist(std::map<TemplateKeyType, banlist_item_t>& ban_list_param) {
        std::lock_guard<std::mutex> lock_guard(structure_mutex);

        // Copy whole content of passed list to current list
        ban_list_storage.insert(ban_list_param.begin(), ban_list_param.end());

        return true;
    }

    // Get list of all blackholed hosts
    bool get_blackholed_hosts(std::vector<TemplateKeyType>& blackholed_hosts) {
        std::lock_guard<std::mutex> lock_guard(structure_mutex);

        for (auto& elem : ban_list_storage) {
            blackholed_hosts.push_back(elem.first);
        }

        return true;
    }

    bool get_whole_banlist(std::map<TemplateKeyType, banlist_item_t>& ban_list_copy) {
        std::lock_guard<std::mutex> lock_guard(structure_mutex);

        // Copy whole content of this structure
        ban_list_copy.insert(ban_list_storage.begin(), ban_list_storage.end());

        return true;
    }

    bool get_blackhole_details(TemplateKeyType client_id, banlist_item_t& banlist_item) {
        std::lock_guard<std::mutex> lock_guard(structure_mutex);

        auto itr = ban_list_storage.find(client_id);

        if (itr == ban_list_storage.end()) {
            return false;
        }

        banlist_item = itr->second;
        return true;
    }

    private:
    std::map<TemplateKeyType, banlist_item_t> ban_list_storage;
    std::mutex structure_mutex;
};
