#pragma once

#include <boost/serialization/nvp.hpp>
#include <cstdint>
#include <vector>

#include "../nlohmann/json.hpp"

enum class netflow_template_type_t { Unknown, Data, Options };

// A record in a Netflow v9 template aka IPFIX field specifier
class template_record_t {
    public:
    uint32_t record_type   = 0;
    uint32_t record_length = 0;

    // Enterprise bit used in IPFIX RFC:
    // https://datatracker.ietf.org/doc/html/rfc7011#page-17
    bool enterprise_bit = false;

    // Enterprise number used in IPFIX RFC:
    // https://datatracker.ietf.org/doc/html/rfc7011#page-17
    uint32_t enterprise_number = 0;

    template_record_t(uint32_t record_type, uint32_t record_length) {
        this->record_type   = record_type;
        this->record_length = record_length;
    }

    // We created custom constructor but I still want to have default with no arguments
    template_record_t() = default;

    // For boost serialize
    template <typename Archive> void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
        ar& BOOST_SERIALIZATION_NVP(record_type);
        ar& BOOST_SERIALIZATION_NVP(record_length);
        ar& BOOST_SERIALIZATION_NVP(enterprise_bit);
        ar& BOOST_SERIALIZATION_NVP(enterprise_number);
    }

    // Needed for JSON serialisation: https://json.nlohmann.me/api/macros/nlohmann_define_type_non_intrusive/
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(template_record_t, record_type, record_length, enterprise_bit, enterprise_number)
};

bool operator==(const template_record_t& lhs, const template_record_t& rhs);
bool operator!=(const template_record_t& lhs, const template_record_t& rhs);

// Netflow v9 or IPFIX template record
// It's not used for wire data decoding. Feel free to add any new fields
class template_t {
    public:
    uint16_t template_id = 0;
    uint32_t num_records = 0;

    // Total length of all standard records and scope section records
    // IPFIX: please note that we do not include "fake" length of variable length fields 
    // In this case total length gets meaning "minimum data length" and will be useful for padding detection
    uint32_t total_length = 0;

    // Only for options templates
    uint32_t option_scope_length = 0;

    // Can be set to true when we use Variable-Length Information Element
    // https://datatracker.ietf.org/doc/html/rfc7011#page-37
    // We need this flag as it triggers special processing logic
    bool ipfix_variable_length_elements_used = false;

    // When we received this template for very first time
    time_t timestamp = 0;

    // Netflow v9 or IPFIX
    netflow_template_type_t type = netflow_template_type_t::Unknown;
    std::vector<template_record_t> records;

    // For boost serialize
    template <typename Archive> void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
        ar& BOOST_SERIALIZATION_NVP(template_id);
        ar& BOOST_SERIALIZATION_NVP(num_records);
        ar& BOOST_SERIALIZATION_NVP(total_length);
        ar& BOOST_SERIALIZATION_NVP(option_scope_length);
        ar& BOOST_SERIALIZATION_NVP(timestamp);
        ar& BOOST_SERIALIZATION_NVP(ipfix_variable_length_elements_used);
        ar& BOOST_SERIALIZATION_NVP(type);
        ar& BOOST_SERIALIZATION_NVP(records);
    }

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(template_t, template_id, num_records, total_length, option_scope_length, ipfix_variable_length_elements_used, timestamp, type, records)
};

std::string print_template(const template_t& field_template);
bool operator==(const template_t& lhs, const template_t& rhs);
bool operator!=(const template_t& lhs, const template_t& rhs);

std::string get_netflow_template_type_as_string(netflow_template_type_t type);
