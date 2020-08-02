#include "network_data_structures.hpp"
#include <cstring>

namespace network_data_stuctures {

std::string parser_code_to_string(parser_code_t code) {
    if (code == parser_code_t::memory_violation) {
        return "memory_violation";
    } else if (code == parser_code_t::not_ipv4) {
        return "not_ipv4";
    } else if (code == parser_code_t::success) {
        return "success";
    } else {
        return "unknown";
    }
}

} // namespace network_data_stuctures
