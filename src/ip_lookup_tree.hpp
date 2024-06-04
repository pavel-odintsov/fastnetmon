#pragma once

#include <iostream>

#include "fastnetmon_networks.hpp"
#include "libpatricia/patricia.hpp"

// Here we have pretty nice wrappers for patricia tree
class lookup_tree_128bit_t {
    public:
    lookup_tree_128bit_t() {
        patricia_tree = New_Patricia(128);
    }

    ~lookup_tree_128bit_t() {
        if (patricia_tree) {
            Destroy_Patricia(patricia_tree);
            patricia_tree = nullptr;
        }
    }

    bool add_subnet(const subnet_ipv6_cidr_mask_t& subnet) {
        // TODO: rewrite this code to native prefix adding. Get rid useless string conversion
        std::string subnet_as_string = convert_ipv6_subnet_to_string(subnet);

        make_and_lookup_ipv6(patricia_tree, (char*)subnet_as_string.c_str());

        return true;
    }

    // Lookup this IP in Patricia tree
    bool lookup_ip(const in6_addr& client_ipv6_address) const {
        prefix_t prefix_for_check_address;

        prefix_for_check_address.family   = AF_INET6;
        prefix_for_check_address.bitlen   = 128;
        prefix_for_check_address.add.sin6 = client_ipv6_address;

        patricia_node_t* found_patrica_node = patricia_search_best2(patricia_tree, &prefix_for_check_address, 1);

        // Could not find anything
        if (found_patrica_node == NULL) {
            return false;
        }

        return true;

    }

    // TODO: rework get_packet_direction_ipv6 and make it public
    public:
    patricia_tree_t* patricia_tree = nullptr;
};

class lookup_tree_32bit_t {
    public:
    lookup_tree_32bit_t() {
        patricia_tree = New_Patricia(32);
    }

    bool add_subnet(const subnet_cidr_mask_t& subnet) {
        // TODO: rewrite this code to native prefix adding. Get rid useless string conversion
        std::string subnet_as_string = convert_ipv4_subnet_to_string(subnet);

        make_and_lookup(patricia_tree, (char*)subnet_as_string.c_str());

        return true;
    }

    // Lookup this IP in Patricia tree
    bool lookup_ip(uint32_t ip_address_big_endian) const {
        prefix_t prefix_for_check_address;

        prefix_for_check_address.add.sin.s_addr = ip_address_big_endian;
        prefix_for_check_address.family         = AF_INET;
        prefix_for_check_address.bitlen         = 32;

        patricia_node_t* found_patrica_node = patricia_search_best2(patricia_tree, &prefix_for_check_address, 1);

        // Could not find anything
        if (found_patrica_node == NULL) {
            return false;
        }

        return true;
    }

    // Lookup this network in Patricia tree
    bool lookup_network(const subnet_cidr_mask_t& subnet) const {
        prefix_t prefix_for_check_adreess;
        
        prefix_for_check_adreess.add.sin.s_addr = subnet.subnet_address;
        prefix_for_check_adreess.family         = AF_INET;
        prefix_for_check_adreess.bitlen         = subnet.cidr_prefix_length;

        patricia_node_t* found_patrica_node = patricia_search_best2(patricia_tree, &prefix_for_check_adreess, 1);

        // Could not find anything
        if (found_patrica_node == NULL) {
            return false;
        }

        return true;
    }

    // Lookups this IP in Patricia tree and returns network prefix which consists this IP in our tree
    // Returns false when IP is not a part of tree
    bool lookup_network_which_includes_ip(uint32_t ip_address_big_endian, subnet_cidr_mask_t& subnet) const {
        prefix_t prefix_for_check_address;

        prefix_for_check_address.add.sin.s_addr = ip_address_big_endian;
        prefix_for_check_address.family         = AF_INET;
        prefix_for_check_address.bitlen         = 32;

        patricia_node_t* found_patrica_node = patricia_search_best2(patricia_tree, &prefix_for_check_address, 1);

        // Could not find anything
        if (found_patrica_node == NULL) {
            return false;
        }

        prefix_t* prefix = found_patrica_node->prefix;

        // It should not happen but I prefer to be on safe side
        if (prefix == NULL) {
            return false;
        }

        subnet.subnet_address     = prefix->add.sin.s_addr;
        subnet.cidr_prefix_length = prefix->bitlen;

        return true;
    }

    ~lookup_tree_32bit_t() {
        if (patricia_tree) {
            Destroy_Patricia(patricia_tree);
            patricia_tree = nullptr;
        }
    }
    
    // Allow access to private variables from tests
    friend class patricia_process_ipv4_Test;
    friend class patricia_positive_lookup_ipv4_check_data_field_value_Test;
    friend class patricia_positive_lookup_ipv4_lookup_24_in_same_24_Test;
    friend class patricia_positive_lookup_ipv4_Test;
    friend class patricia_positive_lookup_ipv4_lookup_24_in_same_24_not_inclusive_Test;
    friend class patricia_positive_lookup_32_in32_with_24_Test;
    friend class patricia_positive_lookup_multiple_networks_Test;
    friend class patricia_positive_lookup_32_in32_Test;

    private:
    patricia_tree_t* patricia_tree = nullptr;
};

