#include "netflow_template.hpp"

#include <sstream>

#include "../ipfix_fields/ipfix_rfc.hpp"

extern ipfix_information_database ipfix_db_instance;

bool operator==(const template_t& lhs, const template_t& rhs) {
    return lhs.template_id == rhs.template_id && lhs.num_records == rhs.num_records && lhs.total_length == rhs.total_length &&
           lhs.records == rhs.records && lhs.type == rhs.type && lhs.option_scope_length == rhs.option_scope_length &&
           lhs.ipfix_variable_length_elements_used == rhs.ipfix_variable_length_elements_used;
}

bool operator!=(const template_t& lhs, const template_t& rhs) {
    return !(lhs == rhs);
}

bool operator==(const template_record_t& lhs, const template_record_t& rhs) {
    return lhs.record_type == rhs.record_type && lhs.record_length == rhs.record_length;
}

bool operator!=(const template_record_t& lhs, const template_record_t& rhs) {
    return !(lhs == rhs);
}

std::string get_netflow_template_type_as_string(netflow_template_type_t type) {
    if (type == netflow_template_type_t::Data) {
        return std::string("data");
    } else if (type == netflow_template_type_t::Options) {
        return std::string("options");
    } else {
        return std::string("unknown");
    }
}

std::string print_template(const template_t& field_template) {
    std::stringstream buffer;

    buffer << "template_id: " << field_template.template_id << "\n"
           << "type: " << get_netflow_template_type_as_string(field_template.type) << "\n"
           << "number of records: " << field_template.num_records << "\n"
           << "total length: " << field_template.total_length << "\n"
           << "ipfix_variable_length_elements_used: " << field_template.ipfix_variable_length_elements_used << "\n"
           << "option_scope_length: " << field_template.option_scope_length << "\n";

    buffer << "Records\n";
    for (auto elem : field_template.records) {
        buffer << "record_type: " << elem.record_type << "\n";
        buffer << "record_length: " << elem.record_length << "\n";
        buffer << "name from database: " << ipfix_db_instance.get_name_by_id(elem.record_type) << "\n";

        buffer << "\n";
    }

    return buffer.str();
}
