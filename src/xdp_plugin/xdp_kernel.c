// SPDX-License-Identifier: GPL-2.0
#define KBUILD_MODNAME "foo"

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

//
// To compile it on Ubuntu 22.04 x86_64 you will need following packages:
// sudo apt install -y clang libbpf-dev  gcc-multilib
//
// Sadly ARM64 has no gcc-multilib package and we cannot compile it on ARM64 boxes
//
// Compile command:
//
// clang -c -g -O2 -target bpf xdp_kernel.c -o xdp_kernel.o
//
// To unload BPF for specific interface you need to apply following command:
//
// sudo xdp-loader unload <interface> --all
//

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
int xdp_sock_prog(struct xdp_md* ctx) {
    int *qidconf, key = 0, idx;
    unsigned int* rr;

    qidconf = bpf_map_lookup_elem(&qidconf_map, &key);
    if (!qidconf) return XDP_ABORTED;

    if (*qidconf != ctx->rx_queue_index) return XDP_PASS;

    idx = 0;

    return bpf_redirect_map(&xsks_map, idx, 0);
}

char _license[] SEC("license") = "GPL";
