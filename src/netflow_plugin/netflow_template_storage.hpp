#pragma once

#include <map>
#include <mutex>
#include <string>

#include "netflow.hpp"

#include "netflow_template.hpp"

bool peer_find_template(const std::map<std::string, std::map<uint32_t, template_t>>& table_for_lookup,
                        std::mutex& table_for_lookup_mutex,
                        uint32_t source_id,
                        uint32_t template_id,
                        const std::string& client_addres_in_string_format,
                        template_t& found_template);

void add_update_peer_template(const netflow_protocol_version_t& netflow_protocol_version,
                              std::map<std::string, std::map<uint32_t, template_t>>& table_for_add,
                              std::mutex& table_for_add_mutex,
                              uint32_t source_id,
                              uint32_t template_id,
                              const std::string& client_address_in_string_format,
                              const template_t& field_template,
                              bool& updated,
                              bool& updated_existing_template);                        