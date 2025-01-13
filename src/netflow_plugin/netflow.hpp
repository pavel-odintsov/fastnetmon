// Netflow packet definitions

#pragma once

#include <cstdint>
#include <optional>
#include <string>

enum class netflow_protocol_version_t { netflow_v5, netflow_v9, ipfix };

// Common header fields
class __attribute__((__packed__)) netflow_header_common_t {
    public:
    uint16_t version = 0;
    uint16_t flows   = 0;
};

// This class carries mapping between interface ID and human friendly interface name
class interface_id_to_name_t {
    public:
    uint32_t interface_id = 0;
    std::string interface_description{};
};

// Active timeout for IPFIX
class device_timeouts_t {
    public:
    // Both values use seconds
    std::optional<uint32_t> active_timeout   = 0;
    std::optional<uint32_t> inactive_timeout = 0;

    bool operator!=(const device_timeouts_t& rhs) const {
        return !(*this == rhs);
    }

    // We generate default == operator which compares each field in class using standard compare operators for each class
    bool operator==(const device_timeouts_t& rhs) const = default;
};
