#pragma once

#include "fastnetmon_networks.hpp"
#include "libpatricia/patricia.hpp"
#include <iostream>

// This is safe wrapper for Patricia with support for storing data directly in tree leafs without doing memory
// allocations We can store only types which does not exceed void* by length
template <typename T> class lookup_tree_128bit_with_payload_t {
    public:
    lookup_tree_128bit_with_payload_t() {
        patricia_tree = New_Patricia(128);
    }

    // Loads all the elements from passed tree to our tree
    // using inline storage method
    void load_inline(const lookup_tree_128bit_with_payload_t<T>& another_tree) {

        patricia_process(another_tree.patricia_tree, [this](prefix_t* prefix, void* data) {
            subnet_ipv6_cidr_mask_t subnet;

            memcpy(&subnet.subnet_address, &prefix->add.sin6, sizeof(subnet.subnet_address));
            subnet.cidr_prefix_length = prefix->bitlen;

            // Add it to tree
            this->add_subnet_with_payload_inline(subnet, (T)data);
        });
    }

    bool add_subnet_with_payload_inline(const subnet_ipv6_cidr_mask_t& ipv6_subnet, T object_to_store) {
        std::string subnet_as_string = convert_ipv6_subnet_to_string(ipv6_subnet);

        make_and_lookup_ipv6_with_data(patricia_tree, (char*)subnet_as_string.c_str(), (void*)object_to_store);
        return true;
    }

    // Try to find payload for certain subnet. But we return value directly
    bool lookup_value_inline_for_subnet(const subnet_ipv6_cidr_mask_t& ipv6_subnet, T& target_object_ptr) {
        prefix_t prefix_for_check_address;

        prefix_for_check_address.add.sin6 = ipv6_subnet.subnet_address;
        prefix_for_check_address.family   = AF_INET6;
        prefix_for_check_address.bitlen   = ipv6_subnet.cidr_prefix_length;

        patricia_node_t* found_patrica_node = patricia_search_best2(patricia_tree, &prefix_for_check_address, 1);

        // Could not find anything
        if (found_patrica_node == NULL) {
            return false;
        }

        // Return value itself
        target_object_ptr = (T)found_patrica_node->data;
        return true;
    }

    // Try to find payload for certain subnet. But we return value directly
    // It will return data only if we have exactly this subnet with exactly this prefix
    bool lookup_value_inline_for_subnet_exact_match(const subnet_ipv6_cidr_mask_t& ipv6_subnet, T& target_object_ptr) {
        prefix_t prefix_for_check_address;

        prefix_for_check_address.add.sin6 = ipv6_subnet.subnet_address;
        prefix_for_check_address.family   = AF_INET6;
        prefix_for_check_address.bitlen   = ipv6_subnet.cidr_prefix_length;

        patricia_node_t* found_patrica_node = patricia_search_exact(patricia_tree, &prefix_for_check_address);

        // Could not find anything
        if (found_patrica_node == NULL) {
            return false;
        }

        // Return value itself
        target_object_ptr = (T)found_patrica_node->data;
        return true;
    }

    ~lookup_tree_128bit_with_payload_t() {
        if (patricia_tree) {
            Destroy_Patricia(patricia_tree);
        }
    }

    patricia_tree_t* patricia_tree = nullptr;
};

// This is safe wrapper for Patricia with support for storing data directly in tree leafs without doing memory
// allocations We can store only types which does not exceed void* by length
template <typename T> class lookup_tree_32bit_with_payload_t {
    public:
    lookup_tree_32bit_with_payload_t() {
        patricia_tree = New_Patricia(32);
    }

    // Loads all the elements from passed tree to our tree
    // using inline storage method
    void load_inline(const lookup_tree_32bit_with_payload_t<T>& another_tree) {
        patricia_process(another_tree.patricia_tree, [this](prefix_t* prefix, void* data) {
            // Construct our network from low level structure in Patricia
            subnet_cidr_mask_t subnet;
            subnet.subnet_address     = prefix->add.sin.s_addr;
            subnet.cidr_prefix_length = prefix->bitlen;

            // Add it to tree
            add_subnet_with_payload_inline(subnet, (T)data);
        });
    }

    bool add_subnet_with_payload_inline(const subnet_cidr_mask_t& subnet, T object_to_store) {
        std::string subnet_as_string = convert_ipv4_subnet_to_string(subnet);

        make_and_lookup_with_data(patricia_tree, (char*)subnet_as_string.c_str(), (void*)object_to_store);
        return true;
    }

    // Try to find payload for certain subnet. But we return value directly
    bool lookup_value_inline_for_subnet(const subnet_cidr_mask_t& subnet, T& target_object_ptr) {
        prefix_t prefix_for_check_address;

        prefix_for_check_address.add.sin.s_addr = subnet.subnet_address;
        prefix_for_check_address.family         = AF_INET;
        prefix_for_check_address.bitlen         = subnet.cidr_prefix_length;

        patricia_node_t* found_patrica_node = patricia_search_best2(patricia_tree, &prefix_for_check_address, 1);

        // Could not find anything
        if (found_patrica_node == NULL) {
            return false;
        }

        // Return value itself
        target_object_ptr = (T)found_patrica_node->data;
        return true;
    }


    // Try to find payload for certain subnet. But we return value directly
    // It will return data only if we have exactly this subnet with exactly t
    bool lookup_value_inline_for_subnet_exact_match(const subnet_cidr_mask_t& subnet, T& target_object_ptr) {
        prefix_t prefix_for_check_address;

        prefix_for_check_address.add.sin.s_addr = subnet.subnet_address;
        prefix_for_check_address.family         = AF_INET;
        prefix_for_check_address.bitlen         = subnet.cidr_prefix_length;

        patricia_node_t* found_patrica_node = patricia_search_exact(patricia_tree, &prefix_for_check_address);

        // Could not find anything
        if (found_patrica_node == NULL) {
            return false;
        }

        // Return value itself
        target_object_ptr = (T)found_patrica_node->data;
        return true;
    }


    // Try to find payload for certain IP. But we return pointer to value instead of value
    bool lookup_value_inline_for_ip(uint32_t ip, T& target_object_ptr) {
        subnet_cidr_mask_t subnet(ip, 32);

        return lookup_value_inline_for_subnet(subnet, target_object_ptr);
    }

    ~lookup_tree_32bit_with_payload_t() {
        if (patricia_tree) {
            Destroy_Patricia(patricia_tree);

            patricia_tree = nullptr;
        }
    }

    patricia_tree_t* patricia_tree = nullptr;
};
