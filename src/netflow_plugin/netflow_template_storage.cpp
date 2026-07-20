#include "netflow_template_storage.hpp"

#include "../all_logcpp_libraries.hpp"

extern log4cpp::Category& logger;


// We copy the template into caller-owned storage under the lock
bool peer_find_template(const std::map<std::string, std::map<uint32_t, template_t>>& table_for_lookup,
                        std::mutex& table_for_lookup_mutex,
                        uint32_t source_id,
                        uint32_t template_id,
                        const std::string& client_addres_in_string_format,
                        template_t& found_template) {

    // We use source_id for distinguish multiple Netflow / IPFIX agents with same IP
    std::string key = client_addres_in_string_format + "_" + std::to_string(source_id);

    std::lock_guard<std::mutex> lock(table_for_lookup_mutex);

    auto itr = table_for_lookup.find(key);

    if (itr == table_for_lookup.end()) {
        return false;
    }

    // We found entry for specific agent instance and we need to find specific template in it
    auto itr_template_id = itr->second.find(template_id);

    // We have no such template
    if (itr_template_id == itr->second.end()) {
        return false;
    }

    // Copy the element into caller-owned storage so callers are unaffected by concurrent updates
    found_template = itr_template_id->second;
    return true;
}


void add_update_peer_template(const netflow_protocol_version_t& netflow_protocol_version,
                              std::map<std::string, std::map<uint32_t, template_t>>& table_for_add,
                              std::mutex& table_for_add_mutex,
                              uint32_t source_id,
                              uint32_t template_id,
                              const std::string& client_address_in_string_format,
                              const template_t& field_template,
                              bool& updated,
                              bool& updated_existing_template) {
    extern uint64_t template_update_attempts_with_same_template_data;

    std::string key = client_address_in_string_format + "_" + std::to_string(source_id);

    if (logger.getPriority() == log4cpp::Priority::DEBUG) {
        logger << log4cpp::Priority::DEBUG << "Received " << get_netflow_protocol_version_as_string(netflow_protocol_version)
               << " " << get_netflow_template_type_as_string(field_template.type) << " template with id " << template_id
               << " from host " << client_address_in_string_format << " source id: " << source_id;
    }

    // We need to put lock on it
    std::lock_guard<std::mutex> lock(table_for_add_mutex);

    auto itr = table_for_add.find(key);

    if (itr == table_for_add.end()) {
        std::map<uint32_t, template_t> temp_template_storage;
        temp_template_storage[template_id] = field_template;

        table_for_add[key] = temp_template_storage;
        updated            = true;

        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "We had no "
                   << get_netflow_protocol_version_as_string(netflow_protocol_version) << " templates for source " << key;

            logger << log4cpp::Priority::DEBUG << "Added " << get_netflow_protocol_version_as_string(netflow_protocol_version)
                   << " template with ID " << template_id << " for " << key;
        }

        return;
    }

    // We have information about this agent

    // Try to find actual template id here
    if (itr->second.count(template_id) == 0) {

        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "We had no information about "
                   << get_netflow_protocol_version_as_string(netflow_protocol_version) << " template with ID "
                   << template_id << " for " << key;

            logger << log4cpp::Priority::DEBUG << "Added " << get_netflow_protocol_version_as_string(netflow_protocol_version)
                   << " template with ID " << template_id << " for " << key;
        }

        itr->second[template_id] = field_template;
        updated                  = true;

        return;
    }

    // TODO: Should I track timestamp here and drop old templates after some time?
    if (itr->second[template_id] != field_template) {
        //
        // We can see that template definition actually changed
        //
        // In case of IPFIX this is clear protocol violation:
        // https://datatracker.ietf.org/doc/html/rfc7011#section-8.1
        //

        //
        // If a Collecting Process receives a new Template Record or Options
        // Template Record for an already-allocated Template ID, and that
        // Template or Options Template is different from the already-received
        // Template or Options Template, this indicates a malfunctioning or
        // improperly implemented Exporting Process.  The continued receipt and
        // unambiguous interpretation of Data Records for this Template ID are
        // no longer possible, and the Collecting Process SHOULD log the error.
        // Further Collecting Process actions are out of scope for this
        // specification.
        //

        //
        // We cannot follow RFC recommendation for IPFIX as it will break our on disk template caching.
        // I.e. we may have template with specific list of fields in cache
        // Then after firmware upgrade vendor changes list of fields but does not change template id
        // We have to accept new one and update to be able to decode data
        //

        //
        // Netflow v9 explicitly prohibits template content updates: https://www.ietf.org/rfc/rfc3954.txt
        //
        // A newly created Template record is assigned an unused Template ID
        // from the Exporter. If the template configuration is changed, the
        // current Template ID is abandoned and SHOULD NOT be reused until the
        // NetFlow process or Exporter restarts.
        //
        //

        //
        // But in same time Netflow v9 RFC allows template update for collector and that's exactly what we do:
        //
        // If a Collector should receive a new definition for an already existing Template ID, it MUST discard
        // the previous template definition and use the new one.
        //

        // On debug level we have to print templates
        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "Old " << get_netflow_protocol_version_as_string(netflow_protocol_version)
                   << " template: " << print_template(itr->second[template_id]);

            logger << log4cpp::Priority::DEBUG << "New " << get_netflow_protocol_version_as_string(netflow_protocol_version)
                   << " template: " << print_template(field_template);
        }

        // We use ERROR level as this behavior is definitely not a common and must be carefully investigated
        logger << log4cpp::Priority::ERROR << get_netflow_protocol_version_as_string(netflow_protocol_version)
               << " template " << template_id << " was updated for " << key;

        // Warn user that something bad going on
        logger << log4cpp::Priority::ERROR << get_netflow_protocol_version_as_string(netflow_protocol_version)
               << " template update may be sign of RFC violation by vendor and if you observe this behaviour please "
                  "reach support@fastnetmon.com and share information about your equipment and firmware versions";


        itr->second[template_id] = field_template;

        // We need to track this case as it's pretty unusual and in some cases it may be very destructive when router does it incorrectly
        updated_existing_template = true;

        updated = true;
    } else {
        template_update_attempts_with_same_template_data++;
    }

    return;
}