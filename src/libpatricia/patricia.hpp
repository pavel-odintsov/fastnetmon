/*
 * $Id: patricia.h,v 1.6 2005/12/07 20:53:01 dplonka Exp $
 * Dave Plonka <plonka@doit.wisc.edu>
 *
 * This product includes software developed by the University of Michigan,
 * Merit Network, Inc., and their contributors.
 *
 * This file had been called "radix.h" in the MRT sources.
 *
 * I renamed it to "patricia.h" since it's not an implementation of a general
 * radix trie.  Also, pulled in various requirements from "mrt.h" and added
 * some other things it could be used as a standalone API.
 */

#pragma once

#include <sys/types.h> /* for u_* definitions (on FreeBSD 5) */

#include <errno.h> /* for EAFNOSUPPORT */

#ifdef _WIN32

#include <winsock2.h>
#include <in6addr.h>

#else

#include <netinet/in.h> /* for struct in_addr */
#include <sys/socket.h> /* for AF_INET */

#endif

#include <functional>
#include <iostream>

class prefix4_t {
    public:
    u_short family = 0; /* AF_INET | AF_INET6 */
    u_short bitlen = 0; /* same as mask? */
    int ref_count  = 0; /* reference count */
    struct in_addr sin {};
};

class prefix_t {
    public:
    u_short family = 0; /* AF_INET | AF_INET6 */
    u_short bitlen = 0; /* same as mask? */
    int ref_count  = 0; /* reference count */
    union {
        struct in_addr sin;
        // IPV6
        struct in6_addr sin6;
    } add;
};

class patricia_node_t {
    public:
    u_int bit                      = 0; /* flag if this node used */
    prefix_t* prefix               = 0; /* who we are in patricia tree */
    struct patricia_node_t* l      = nullptr; // left children
    struct patricia_node_t* r      = nullptr; // right children
    struct patricia_node_t* parent = nullptr; /* may be used */
    void* data                     = nullptr; /* pointer to data */
};

class patricia_tree_t {
    public:
    patricia_node_t* head = nullptr;
    u_int maxbits         = 0; /* for IP, 32 bit addresses */
    int num_active_node   = 0; /* for debug purpose */
};

// Create tree
patricia_tree_t* New_Patricia(int maxbits);

// Add elements to IPv4 tree
patricia_node_t* make_and_lookup(patricia_tree_t* tree, const char* string);
patricia_node_t* make_and_lookup_with_data(patricia_tree_t* tree, const char* string, void* user_data);

// Add elements to IPv6 tree
patricia_node_t* make_and_lookup_ipv6(patricia_tree_t* tree, const char* string);
patricia_node_t* make_and_lookup_ipv6_with_data(patricia_tree_t* tree, const char* string, void* user_data);

// Search in tree
patricia_node_t* patricia_search_exact(patricia_tree_t* patricia, prefix_t* prefix);
patricia_node_t* patricia_search_best(patricia_tree_t* patricia, prefix_t* prefix);
patricia_node_t* patricia_search_best2(patricia_tree_t* patricia, prefix_t* prefix, int inclusive);
patricia_node_t* patricia_lookup(patricia_tree_t* patricia, prefix_t* prefix);

// Tree traversal
void patricia_process(patricia_tree_t* patricia, std::function<void(prefix_t*, void*)> func);

// Erase of all elements from tree
void Clear_Patricia(patricia_tree_t* patricia, std::function<void(void*)> func);

// Destruction of tree
void Destroy_Patricia(patricia_tree_t* patricia, std::function<void(void*)> func);
void Destroy_Patricia(patricia_tree_t* patricia);

// Prefix to ASCII
char* prefix_toa(prefix_t* prefix);

// ASCII to prefix
prefix_t* ascii2prefix(int family, const char* string);
