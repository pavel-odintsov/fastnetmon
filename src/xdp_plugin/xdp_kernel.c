// SPDX-License-Identifier: GPL-2.0
#define KBUILD_MODNAME "foo"
#include <linux/bpf.h>
#include "bpf/bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} qidconf_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 4);
    __type(key, int);
    __type(value, int);
} xsks_map SEC(".maps");


SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
    int *qidconf, key = 0, idx;
    unsigned int *rr;

    qidconf = bpf_map_lookup_elem(&qidconf_map, &key);
    if (!qidconf)
        return XDP_ABORTED;

    if (*qidconf != ctx->rx_queue_index)
        return XDP_PASS;

    idx = 0;

    return bpf_redirect_map(&xsks_map, idx, 0);
}

char _license[] SEC("license") = "GPL";

