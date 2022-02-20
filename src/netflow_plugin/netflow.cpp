#include "netflow.hpp"

#include "../ipfix_rfc.h"
#include <vector>

extern ipfix_information_database ipfix_db_instance;

bool operator==(const peer_nf9_template& lhs, const peer_nf9_template& rhs) {
    return lhs.template_id == rhs.template_id && lhs.num_records == rhs.num_records && lhs.total_len == rhs.total_len &&
           lhs.records == rhs.records && lhs.type == rhs.type && lhs.option_scope_length == rhs.option_scope_length;
}

bool operator!=(const peer_nf9_template& lhs, const peer_nf9_template& rhs) {
    return !(lhs == rhs);
}

bool operator==(const peer_nf9_record& lhs, const peer_nf9_record& rhs) {
    return lhs.record_type == rhs.record_type && lhs.record_length == rhs.record_length;
}

bool operator!=(const peer_nf9_record& lhs, const peer_nf9_record& rhs) {
    return !(lhs == rhs);
}

std::string get_netflow9_template_type_as_string(netflow9_template_type type) {
    if (type == netflow9_template_type::Data) {
        return std::string("data");
    } else if (type == netflow9_template_type::Options) {
        return std::string("options");
    } else {
        return std::string("unknown");
    }
}

std::string print_peer_nf9_template(const peer_nf9_template& field_template) {
    std::stringstream buffer;

    buffer << "template_id: " << field_template.template_id << "\n"
           << "type: " << get_netflow9_template_type_as_string(field_template.type) << "\n"
           << "num records: " << field_template.num_records << "\n"
           << "total len: " << field_template.total_len << "\n"
           << "option_scope_length: " << field_template.option_scope_length << "\n";

    buffer << "Records\n";
    for (auto elem : field_template.records) {
        unsigned int length_from_database = ipfix_db_instance.get_length_by_id(elem.record_type);

        buffer << "record_type: " << elem.record_type << "\n";
        buffer << "recprd_length: " << elem.record_length << "\n";
        buffer << "name from database: " << ipfix_db_instance.get_name_by_id(elem.record_type) << "\n";
        buffer << "length from database: " << length_from_database << "\n";

        if (length_from_database != elem.record_length) {
            buffer << "ATTENTION!!!! Length from database is not equal to length "
                      "from received "
                      "from the device\n";
        }

        buffer << "\n";
    }

    return buffer.str();
}
