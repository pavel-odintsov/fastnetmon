/*
 * $Id: patricia.c,v 1.7 2005/12/07 20:46:41 dplonka Exp $
 * Dave Plonka <plonka@doit.wisc.edu>
 *
 * This product includes software developed by the University of Michigan,
 * Merit Network, Inc., and their contributors.
 *
 * This file had been called "radix.c" in the MRT sources.
 *
 * I renamed it to "patricia.c" since it's not an implementation of a general
 * radix trie.  Also I pulled in various requirements from "prefix.c" and
 * "demo.c" so that it could be used as a standalone API.
 */

// Actual link to MRT project located here: https://github.com/deepfield/MRT

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
static char copyright[] = "This product includes software developed by the University of Michigan, Merit"
                          "Network, Inc., and their contributors.";
#pragma GCC diagnostic pop

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h> // for inet_ntop
#else
// for inet_addr
#include <arpa/inet.h> // for inet_addr
#endif 

#include <assert.h> /* assert */
#include <ctype.h> /* isdigit */
#include <errno.h> /* errno */
#include <stdio.h> /* sprintf, fprintf, stderr */
#include <stdlib.h> /* free, atol, calloc */
#include <string.h> /* memcpy, strchr, strlen */

#include "patricia.hpp"

#define PATRICIA_MAXBITS (sizeof(struct in6_addr) * 8)
#define prefix_touchar(prefix) ((u_char*)&(prefix)->add.sin)
#define MAXLINE 1024
#define BIT_TEST(f, b) ((f) & (b))

/* prefix_tochar  convert prefix information to bytes */
u_char* prefix_tochar(prefix_t* prefix) {
    if (prefix == NULL) {
        return NULL;
    }

    return ((u_char*)&prefix->add.sin);
}

int comp_with_mask(void* addr, void* dest, u_int mask) {
    if (/* mask/8 == 0 || */ memcmp(addr, dest, mask / 8) == 0) {
        int n = mask / 8;

        int m = ((-1) << (8 - (mask % 8)));

        if (mask % 8 == 0 || (((u_char*)addr)[n] & m) == (((u_char*)dest)[n] & m)) {
            return 1;
        }
    }

    return 0;
}

/* this allows imcomplete prefix */
int my_inet_pton(int af, const char* src, void* dst) {
    if (af == AF_INET) {
        int i   = 0;
        int c   = 0;
        int val = 0;

        u_char xp[sizeof(struct in_addr)] = { 0, 0, 0, 0 };

        for (i = 0;; i++) {
            c = *src++;

            if (!isdigit(c)) {
                return -1;
            }

            val = 0;

            do {
                val = val * 10 + c - '0';

                if (val > 255) {
                    return 0;
                }

                c = *src++;
            } while (c && isdigit(c));

            xp[i] = val;

            if (c == '\0') break;

            if (c != '.') {
                return 0;
            }

            if (i >= 3) {
                return 0;
            }
        }

        memcpy(dst, xp, sizeof(struct in_addr));

        return 1;
    } else if (af == AF_INET6) {
        return inet_pton(af, src, dst);
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }
}

#define PATRICIA_MAX_THREADS 16

/*
 * convert prefix information to ascii string with length
 * thread safe and (almost) re-entrant implementation
 */
char* prefix_toa2x(prefix_t* prefix, char* buff, int with_len) {
    if (prefix == NULL) {
        return (char*)"(Null)";
    }

    assert(prefix->ref_count >= 0);

    if (buff == NULL) {

        struct buffer {
            char buffs[PATRICIA_MAX_THREADS][48 + 5];
            u_int i;
        } * buffp;

        { /* for scope only */
            static struct buffer local_buff;
            buffp = &local_buff;
        }

        if (buffp == NULL) {
            /* XXX should we report an error? */
            return NULL;
        }

        buff = buffp->buffs[buffp->i++ % PATRICIA_MAX_THREADS];
    }

    if (prefix->family == AF_INET) {
        assert(prefix->bitlen <= sizeof(struct in_addr) * 8);

        u_char* a = prefix_touchar(prefix);

        if (with_len) {
            sprintf(buff, "%d.%d.%d.%d/%d", a[0], a[1], a[2], a[3], prefix->bitlen);
        } else {
            sprintf(buff, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
        }

        return (buff);
    } else if (prefix->family == AF_INET6) {
        char* r = (char*)inet_ntop(AF_INET6, &prefix->add.sin6, buff, 48 /* a guess value */);

        if (r && with_len) {
            assert(prefix->bitlen <= sizeof(struct in6_addr) * 8);
            sprintf(buff + strlen(buff), "/%d", prefix->bitlen);
        }

        return buff;
    } else {
        return NULL;
    }
}

/* prefix_toa2
 * convert prefix information to ascii string
 */
char* prefix_toa2(prefix_t* prefix, char* buff) {
    return prefix_toa2x(prefix, buff, 0);
}

/* prefix_toa
 */
char* prefix_toa(prefix_t* prefix) {
    return prefix_toa2(prefix, (char*)NULL);
}

prefix_t* New_Prefix2(int family, void* dest, int bitlen, prefix_t* prefix) {
    int dynamic_allocated = 0;
    int default_bitlen    = sizeof(struct in_addr) * 8;

    if (family == AF_INET6) {
        default_bitlen = sizeof(struct in6_addr) * 8;

        if (prefix == NULL) {
            prefix = (prefix_t*)calloc(1, sizeof(prefix_t));
            dynamic_allocated++;
        }

        memcpy(&prefix->add.sin6, dest, sizeof(struct in6_addr));
    } else if (family == AF_INET) {
        if (prefix == NULL) {
            prefix = (prefix_t*)calloc(1, sizeof(prefix4_t));
            dynamic_allocated++;
        }

        memcpy(&prefix->add.sin, dest, sizeof(struct in_addr));
    } else {
        return NULL;
    }

    prefix->bitlen    = (bitlen >= 0) ? bitlen : default_bitlen;
    prefix->family    = family;
    prefix->ref_count = 0;

    if (dynamic_allocated) {
        prefix->ref_count++;
    }

    /* printf("[C %s, %d]\n", prefix_toa (prefix), prefix->ref_count); */
    return prefix;
}

prefix_t* New_Prefix(int family, void* dest, int bitlen) {
    return New_Prefix2(family, dest, bitlen, NULL);
}

// Converts string representation of prefix into out prefix_t structure
prefix_t* ascii2prefix(int family, const char* string) {
    u_long bitlen    = 0;
    u_long maxbitlen = 0;

    const char* cp = nullptr;

    struct in_addr sin {};
    struct in6_addr sin6 {};

    int result = 0;
    char save[MAXLINE];

    if (string == NULL) {
        return NULL;
    }

    /* easy way to handle both families */
    if (family == 0) {
        family = AF_INET;

        if (strchr(string, ':')) {
            family = AF_INET6;
        }
    }

    if (family == AF_INET) {
        maxbitlen = sizeof(struct in_addr) * 8;
    } else if (family == AF_INET6) {
        maxbitlen = sizeof(struct in6_addr) * 8;
    }

    if ((cp = strchr(string, '/')) != NULL) {
        bitlen = atol(cp + 1);
        /* *cp = '\0'; */
        /* copy the string to save. Avoid destroying the string */
        assert(cp - string < MAXLINE);

        memcpy(save, string, cp - string);
        save[cp - string] = '\0';
        string            = save;

        if (bitlen < 0 || bitlen > maxbitlen) {
            bitlen = maxbitlen;
        }
    } else {
        bitlen = maxbitlen;
    }

    if (family == AF_INET) {
        if ((result = my_inet_pton(AF_INET, string, &sin)) <= 0) {
            return NULL;
        }

        return New_Prefix(AF_INET, &sin, bitlen);
    } else if (family == AF_INET6) {
        if ((result = inet_pton(AF_INET6, string, &sin6)) <= 0) {
            return NULL;
        }

        return New_Prefix(AF_INET6, &sin6, bitlen);
    } else {
        return NULL;
    }
}

prefix_t* Ref_Prefix(prefix_t* prefix) {
    if (prefix == NULL) {
        return NULL;
    }

    if (prefix->ref_count == 0) {
        /* make a copy in case of a static prefix */
        return New_Prefix2(prefix->family, &prefix->add, prefix->bitlen, NULL);
    }

    prefix->ref_count++;

    return prefix;
}

void Deref_Prefix(prefix_t* prefix) {
    if (prefix == NULL) {
        return;
    }

    /* for secure programming, raise an assert. no static prefix can call this */
    assert(prefix->ref_count > 0);

    prefix->ref_count--;
    assert(prefix->ref_count >= 0);

    if (prefix->ref_count <= 0) {
        free(prefix);
        return;
    }
}

/* these routines support continuous mask only */
patricia_tree_t* New_Patricia(int maxbits) {
    patricia_tree_t* patricia = (patricia_tree_t*)calloc(1, sizeof *patricia);

    patricia->maxbits         = maxbits;
    patricia->head            = NULL;
    patricia->num_active_node = 0;

    assert(maxbits <= PATRICIA_MAXBITS); /* XXX */

    return patricia;
}


// if func is supplied, it will be called as func(node->data)  before deleting the node
void Clear_Patricia(patricia_tree_t* patricia, std::function<void(void*)> func) {
    assert(patricia);

    if (patricia->head) {

        patricia_node_t* Xstack[PATRICIA_MAXBITS + 1];
        patricia_node_t** Xsp = Xstack;
        patricia_node_t* Xrn  = patricia->head;

        while (Xrn) {
            patricia_node_t* l = Xrn->l;
            patricia_node_t* r = Xrn->r;

            if (Xrn->prefix) {
                Deref_Prefix(Xrn->prefix);

                // printf("We are near function call on nested data\n");

                if (Xrn->data && func) {
                    func(Xrn->data);
                }
            } else {
                assert(Xrn->data == NULL);
            }

            free(Xrn);
            patricia->num_active_node--;

            if (l) {
                if (r) {
                    *Xsp++ = r;
                }

                Xrn = l;
            } else if (r) {
                Xrn = r;
            } else if (Xsp != Xstack) {
                Xrn = *(--Xsp);
            } else {
                Xrn = NULL;
            }
        }
    }
    assert(patricia->num_active_node == 0);
    /* free (patricia); */
}


void Destroy_Patricia(patricia_tree_t* patricia, std::function<void(void*)> func) {
    Clear_Patricia(patricia, func);
    free(patricia);
}

// Overload where we are not doing any actions with data payload
// But please be carefeul! If you have used data field you should use extended version of function
void Destroy_Patricia(patricia_tree_t* patricia) {
    auto function_which_do_nothing = [](void* ptr) {};

    Clear_Patricia(patricia, function_which_do_nothing);
    free(patricia);
}

/*
 * if func is supplied, it will be called as func(node->prefix, node->data)
 */

void patricia_process(patricia_tree_t* patricia, std::function<void(prefix_t*, void*)> func) {
    patricia_node_t* node;
    assert(func);

    patricia_node_t* Xstack[PATRICIA_MAXBITS + 1];
    patricia_node_t** Xsp = Xstack;
    patricia_node_t* Xrn  = patricia->head;

    while ((node = Xrn)) {
        if (node->prefix) {
            func(node->prefix, node->data);
        }

        if (Xrn->l) {
            if (Xrn->r) {
                *Xsp++ = Xrn->r;
            }

            Xrn = Xrn->l;
        } else if (Xrn->r) {
            Xrn = Xrn->r;
        } else if (Xsp != Xstack) {
            Xrn = *(--Xsp);
        } else {
            Xrn = (patricia_node_t*)0;
        }
    }
}


patricia_node_t* patricia_search_exact(patricia_tree_t* patricia, prefix_t* prefix) {
    patricia_node_t* node;
    u_char* addr;
    u_int bitlen;

    assert(patricia);
    assert(prefix);
    assert(prefix->bitlen <= patricia->maxbits);

    if (patricia->head == NULL) {
        return NULL;
    }

    node   = patricia->head;
    addr   = prefix_touchar(prefix);
    bitlen = prefix->bitlen;

    while (node->bit < bitlen) {

        if (BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
            node = node->r;
        } else {
            node = node->l;
        }

        if (node == NULL) {
            return NULL;
        }
    }

    if (node->bit > bitlen || node->prefix == NULL) {
        return NULL;
    }

    assert(node->bit == bitlen);
    assert(node->bit == node->prefix->bitlen);

    if (comp_with_mask(prefix_tochar(node->prefix), prefix_tochar(prefix), bitlen)) {
        // printf("patricia_search_exact: found %s/%d\n", prefix_toa(node->prefix), node->prefix->bitlen);
        return (node);
    }

    return NULL;
}


/* if inclusive != 0, "best" may be the given prefix itself */
patricia_node_t* patricia_search_best2(patricia_tree_t* patricia, prefix_t* prefix, int inclusive) {
    patricia_node_t* node = nullptr;
    patricia_node_t* stack[PATRICIA_MAXBITS + 1];

    u_char* addr = nullptr;
    u_int bitlen = 0;
    int cnt      = 0;

    assert(patricia);
    assert(prefix);
    assert(prefix->bitlen <= patricia->maxbits);

    if (patricia->head == NULL) return (NULL);

    node   = patricia->head;
    addr   = prefix_touchar(prefix);
    bitlen = prefix->bitlen;

    while (node->bit < bitlen) {

        if (node->prefix) {
            stack[cnt++] = node;
        }

        if (BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
            node = node->r;
        } else {
            node = node->l;
        }

        if (node == NULL) break;
    }

    if (inclusive && node && node->prefix) stack[cnt++] = node;

    if (cnt <= 0) {
        return NULL;
    }

    while (--cnt >= 0) {
        node = stack[cnt];
        if (comp_with_mask(prefix_tochar(node->prefix), prefix_tochar(prefix), node->prefix->bitlen) && node->prefix->bitlen <= bitlen) {
            return (node);
        }
    }
    return NULL;
}


patricia_node_t* patricia_search_best(patricia_tree_t* patricia, prefix_t* prefix) {
    return patricia_search_best2(patricia, prefix, 1);
}


patricia_node_t* patricia_lookup(patricia_tree_t* patricia, prefix_t* prefix) {
    patricia_node_t* node     = nullptr;
    patricia_node_t* new_node = nullptr;
    patricia_node_t* parent   = nullptr;
    patricia_node_t* glue     = nullptr;

    u_char* addr      = nullptr;
    u_char* test_addr = nullptr;

    u_int bitlen     = 0;
    u_int check_bit  = 0;
    u_int differ_bit = 0;

    int i = 0;
    int j = 0;
    int r = 0;

    assert(patricia);
    assert(prefix);
    assert(prefix->bitlen <= patricia->maxbits);

    if (patricia->head == NULL) {
        node         = (patricia_node_t*)calloc(1, sizeof *node);
        node->bit    = prefix->bitlen;
        node->prefix = Ref_Prefix(prefix);
        node->parent = NULL;
        node->l = node->r = NULL;
        node->data        = NULL;
        patricia->head    = node;

        // printf("patricia_lookup: new_node #0 %s/%d (head)\n", prefix_toa(prefix), prefix->bitlen);

        patricia->num_active_node++;
        return node;
    }

    addr   = prefix_touchar(prefix);
    bitlen = prefix->bitlen;
    node   = patricia->head;

    while (node->bit < bitlen || node->prefix == NULL) {

        if (node->bit < patricia->maxbits && BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
            if (node->r == NULL) break;

            node = node->r;
        } else {
            if (node->l == NULL) break;
            node = node->l;
        }

        assert(node);
    }

    assert(node->prefix);

    // printf("patricia_lookup: stop at %s/%d\n", prefix_toa(node->prefix), node->prefix->bitlen);

    test_addr = prefix_touchar(node->prefix);
    /* find the first bit different */
    check_bit  = (node->bit < bitlen) ? node->bit : bitlen;
    differ_bit = 0;

    for (i = 0; i * 8 < check_bit; i++) {
        if ((r = (addr[i] ^ test_addr[i])) == 0) {
            differ_bit = (i + 1) * 8;
            continue;
        }

        /* I know the better way, but for now */
        for (j = 0; j < 8; j++) {
            if (BIT_TEST(r, (0x80 >> j))) break;
        }

        /* must be found */
        assert(j < 8);
        differ_bit = i * 8 + j;

        break;
    }

    if (differ_bit > check_bit) differ_bit = check_bit;
    // printf("patricia_lookup: differ_bit %d\n", differ_bit);

    parent = node->parent;
    while (parent && parent->bit >= differ_bit) {
        node   = parent;
        parent = node->parent;
    }

    if (differ_bit == bitlen && node->bit == bitlen) {
        if (node->prefix) {
            // fprintf("patricia_lookup: found %s/%d\n", prefix_toa(node->prefix), node->prefix->bitlen);
            return (node);
        }

        node->prefix = Ref_Prefix(prefix);

        // fprintf("patricia_lookup: new node #1 %s/%d (glue mod)\n", prefix_toa(prefix), prefix->bitlen);

        assert(node->data == NULL);
        return (node);
    }

    new_node         = (patricia_node_t*)calloc(1, sizeof *new_node);
    new_node->bit    = prefix->bitlen;
    new_node->prefix = Ref_Prefix(prefix);
    new_node->parent = NULL;
    new_node->l = new_node->r = NULL;
    new_node->data            = NULL;
    patricia->num_active_node++;

    if (node->bit == differ_bit) {
        new_node->parent = node;

        if (node->bit < patricia->maxbits && BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
            assert(node->r == NULL);
            node->r = new_node;
        } else {
            assert(node->l == NULL);
            node->l = new_node;
        }

        // printf("patricia_lookup: new_node #2 %s/%d (child)\n", prefix_toa(prefix), prefix->bitlen);

        return new_node;
    }

    if (bitlen == differ_bit) {
        if (bitlen < patricia->maxbits && BIT_TEST(test_addr[bitlen >> 3], 0x80 >> (bitlen & 0x07))) {
            new_node->r = node;
        } else {
            new_node->l = node;
        }

        new_node->parent = node->parent;

        if (node->parent == NULL) {
            assert(patricia->head == node);
            patricia->head = new_node;
        } else if (node->parent->r == node) {
            node->parent->r = new_node;
        } else {
            node->parent->l = new_node;
        }

        node->parent = new_node;

        // printf("patricia_lookup: new_node #3 %s/%d (parent)\n", prefix_toa(prefix), prefix->bitlen);
    } else {
        glue         = (patricia_node_t*)calloc(1, sizeof *glue);
        glue->bit    = differ_bit;
        glue->prefix = NULL;
        glue->parent = node->parent;
        glue->data   = NULL;
        patricia->num_active_node++;

        if (differ_bit < patricia->maxbits && BIT_TEST(addr[differ_bit >> 3], 0x80 >> (differ_bit & 0x07))) {
            glue->r = new_node;
            glue->l = node;
        } else {
            glue->r = node;
            glue->l = new_node;
        }

        new_node->parent = glue;

        if (node->parent == NULL) {
            assert(patricia->head == node);
            patricia->head = glue;
        } else if (node->parent->r == node) {
            node->parent->r = glue;
        } else {
            node->parent->l = glue;
        }

        node->parent = glue;

        // printf("patricia_lookup: new_node #4 %s/%d (glue+node)\n", prefix_toa(prefix), prefix->bitlen);
    }

    return new_node;
}

patricia_node_t* make_and_lookup(patricia_tree_t* tree, const char* prefix_as_string) {
    prefix_t* prefix = ascii2prefix(AF_INET, prefix_as_string);

    patricia_node_t* node = patricia_lookup(tree, prefix);

    Deref_Prefix(prefix);

    return node;
}


patricia_node_t* make_and_lookup_ipv6(patricia_tree_t* tree, const char* prefix_as_string) {
    prefix_t* prefix = ascii2prefix(AF_INET6, prefix_as_string);

    patricia_node_t* node = patricia_lookup(tree, prefix);

    Deref_Prefix(prefix);

    return node;
}

// Add custom pointer to this subnet leaf
patricia_node_t* make_and_lookup_with_data(patricia_tree_t* tree, const char* prefix_as_string, void* user_data) {
    prefix_t* prefix = ascii2prefix(AF_INET, prefix_as_string);

    patricia_node_t* node = patricia_lookup(tree, prefix);
    node->data            = user_data;

    Deref_Prefix(prefix);

    return node;
}

// Add custom pointer to subnet leaf for IPv6
patricia_node_t* make_and_lookup_ipv6_with_data(patricia_tree_t* tree, const char* prefix_as_string, void* user_data) {
    prefix_t* prefix = ascii2prefix(AF_INET6, prefix_as_string);

    patricia_node_t* node = patricia_lookup(tree, prefix);

    node->data = user_data;

    Deref_Prefix(prefix);

    return node;
}
