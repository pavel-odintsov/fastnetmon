#pragma once

#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>

#include <boost/functional/hash.hpp>

#include <boost/serialization/nvp.hpp>

// IPv6 subnet with mask in cidr form
class subnet_ipv6_cidr_mask_t {
    public:
    subnet_ipv6_cidr_mask_t() {
        // Fill subnet by zeros
        memset(&this->subnet_address, 0, sizeof(in6_addr));
    }

    void set_cidr_prefix_length(uint32_t cidr_prefix_length) {
        this->cidr_prefix_length = cidr_prefix_length;
    }

    // Just copy this data by pointer
    void set_subnet_address(in6_addr* ipv6_host_address_param) {
        memcpy(&subnet_address, ipv6_host_address_param, sizeof(in6_addr));
    }

    template <class Archive> void serialize(Archive& ar, const unsigned int version) {
        // Boost does not know how to serialize in6_addr but nested s6_addr is a just array with 16 elements of char and we do serialzie it instead
        ar& BOOST_SERIALIZATION_NVP(subnet_address.s6_addr);
        ar& BOOST_SERIALIZATION_NVP(cidr_prefix_length);
    }

    in6_addr subnet_address;
    uint32_t cidr_prefix_length = 128;
};

// We need this operator because we are using this class in std::map which
// requires ordering
// We use inline to suppress angry compiler
inline bool operator<(const subnet_ipv6_cidr_mask_t& lhs, const subnet_ipv6_cidr_mask_t& rhs) {
    if (lhs.cidr_prefix_length < rhs.cidr_prefix_length) {
        return true;
    } else if (lhs.cidr_prefix_length == rhs.cidr_prefix_length) {
        // Compare addresses as memory blocks
        // Order may be incorrect (desc vs asc)
        return memcmp(&lhs.subnet_address, &rhs.subnet_address, sizeof(in6_addr)) < 0;
    } else {
        return false;
    }
}

// Inject custom specialization of std::hash in namespace std
// We need it for std::unordered_map
namespace std {
template <> struct hash<subnet_ipv6_cidr_mask_t> {
    typedef std::size_t result_type;
    std::size_t operator()(subnet_ipv6_cidr_mask_t const& s) const {
        std::size_t seed = 0;

        const uint8_t* b = s.subnet_address.s6_addr;

        boost::hash_combine(seed, s.cidr_prefix_length);

        // Add all elements from IPv6 into hash
        for (int i = 0; i < 16; i++) {
            boost::hash_combine(seed, b[i]);
        }

        return seed;
    }
};
} // namespace std

inline bool operator==(const subnet_ipv6_cidr_mask_t& lhs, const subnet_ipv6_cidr_mask_t& rhs) {
    // Prefixes has different lengths
    if (lhs.cidr_prefix_length != rhs.cidr_prefix_length) {
        return false;
    }

    return memcmp(&lhs.subnet_address, &rhs.subnet_address, sizeof(in6_addr)) == 0;
}

inline bool operator!=(const subnet_ipv6_cidr_mask_t& lhs, const subnet_ipv6_cidr_mask_t& rhs) {
    return !(lhs == rhs);
}

// Subnet with cidr mask
class subnet_cidr_mask_t {
    public:
    subnet_cidr_mask_t() {
        this->subnet_address     = 0;
        this->cidr_prefix_length = 0;
    }
    subnet_cidr_mask_t(uint32_t subnet_address, uint32_t cidr_prefix_length) {
        this->subnet_address     = subnet_address;
        this->cidr_prefix_length = cidr_prefix_length;
    }

    // We need this operator because we are using this class in std::map which
    // requires order
    bool operator<(const subnet_cidr_mask_t& rhs) {
        if (this->cidr_prefix_length < rhs.cidr_prefix_length) {
            return true;
        } else if (this->cidr_prefix_length == rhs.cidr_prefix_length) {
            return this->subnet_address < rhs.subnet_address;
        } else {
            return false;
        }
    }

    bool is_zero_subnet() {
        if (subnet_address == 0 && cidr_prefix_length == 0) {
            return true;
        } else {
            return false;
        }
    }

    void set_subnet_address(uint32_t subnet_address) {
        this->subnet_address = subnet_address;
    }

    void set_cidr_prefix_length(uint32_t cidr_prefix_length) {
        this->cidr_prefix_length = cidr_prefix_length;
    }

    template <class Archive> void serialize(Archive& ar, const unsigned int version) {
        ar& BOOST_SERIALIZATION_NVP(subnet_address);
        ar& BOOST_SERIALIZATION_NVP(cidr_prefix_length);
    }

    // Big endian (network byte order)
    uint32_t subnet_address = 0;

    // Little endian
    uint32_t cidr_prefix_length = 0;
};

// TODO: move to .cpp file!!!
inline bool operator==(const subnet_cidr_mask_t& lhs, const subnet_cidr_mask_t& rhs) {
    // Prefixes has different lengths
    if (lhs.cidr_prefix_length != rhs.cidr_prefix_length) {
        return false;
    }

    return lhs.subnet_address == rhs.subnet_address;
}

inline bool operator!=(const subnet_cidr_mask_t& lhs, const subnet_cidr_mask_t& rhs) {
    return !(lhs == rhs);
}

// TODO: move to .cpp file!!!
// We need free function for comparision code
inline bool operator<(const subnet_cidr_mask_t& lhs, const subnet_cidr_mask_t& rhs) {
    if (lhs.cidr_prefix_length < rhs.cidr_prefix_length) {
        return true;
    } else if (lhs.cidr_prefix_length == rhs.cidr_prefix_length) {
        return lhs.subnet_address < rhs.subnet_address;
    } else {
        return false;
    }
}

// Subnet with binary mask
class subnet_binary_netmask_t {
    public:
    subnet_binary_netmask_t() {
        this->subnet_address     = 0;
        this->subnet_binary_mask = 0;
    }
    subnet_binary_netmask_t(uint32_t subnet_address, uint32_t subnet_binary_mask) {
        this->subnet_address     = subnet_address;
        this->subnet_binary_mask = subnet_binary_mask;
    }
    uint32_t subnet_address     = 0;
    uint32_t subnet_binary_mask = 0;
};

namespace std {

// Inject custom specialization of std::hash in namespace std
// We need it for std::unordered_map
template <> struct hash<subnet_cidr_mask_t> {
    typedef std::size_t result_type;
    std::size_t operator()(subnet_cidr_mask_t const& s) const {
        std::size_t seed = 0;

        boost::hash_combine(seed, s.cidr_prefix_length);
        boost::hash_combine(seed, s.subnet_address);

        return seed;
    }
};

} // namespace std
