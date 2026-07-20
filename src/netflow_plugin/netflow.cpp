#include "netflow.hpp"

// Returns fancy name of protocol version
std::string get_netflow_protocol_version_as_string(const netflow_protocol_version_t& netflow_protocol_version) {
    std::string protocol_name = "unknown";

    if (netflow_protocol_version == netflow_protocol_version_t::netflow_v9) {
        protocol_name = "Netflow v9";
    } else if (netflow_protocol_version == netflow_protocol_version_t::ipfix) {
        protocol_name = "IPFIX";
    }

    return protocol_name;
}