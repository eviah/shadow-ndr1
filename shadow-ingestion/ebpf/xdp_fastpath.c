// SPDX-License-Identifier: GPL-2.0
//
// Shadow NDR XDP Fast-Path Filter
// =================================
//
// Runs at the earliest hook in the kernel network stack (XDP_DRV mode where
// supported, XDP_GENERIC otherwise). Drops packets that match a high-frequency
// allow/deny list before they ever hit skb allocation, leaving only packets
// of interest for userspace pcap.
//
// Maps:
//   blacklist_v4    : LPM trie of /24..../32 IPv4 prefixes to drop
//   port_drop       : hash<u16, u8>     of TCP/UDP dst ports to drop
//   stats           : per-CPU array<u64, 8> for counters
//
// Counter slots:
//   0: total packets seen
//   1: dropped by blacklist
//   2: dropped by port_drop
//   3: passed to userspace (XDP_PASS)
//   4: malformed
//   5: non-IP
//   6: non-TCP/UDP
//   7: reserved
//
// Compile:
//   clang -O2 -g -Wall -target bpf -c xdp_fastpath.c -o xdp_fastpath.o
//
// Load (Linux only):
//   bpftool prog loadall xdp_fastpath.o /sys/fs/bpf/shadow_xdp
//   bpftool net attach xdpgeneric pinned /sys/fs/bpf/shadow_xdp/xdp_fastpath \
//     dev eth0
//
// Or via the Go loader at internal/xdp/loader.go.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_BLACKLIST_ENTRIES 4096
#define MAX_PORT_ENTRIES      256
#define STATS_SLOTS           8

struct lpm_v4_key {
    __u32 prefixlen;
    __u32 addr;     // network byte order
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(max_entries, MAX_BLACKLIST_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blacklist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, MAX_PORT_ENTRIES);
} port_drop SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STATS_SLOTS);
} stats SEC(".maps");

static __always_inline void bump(__u32 slot) {
    __u64 *v = bpf_map_lookup_elem(&stats, &slot);
    if (v) {
        __sync_fetch_and_add(v, 1);
    }
}

SEC("xdp")
int xdp_fastpath(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bump(0); // total

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bump(4);
        return XDP_PASS;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        bump(5);
        return XDP_PASS;
    }

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bump(4);
        return XDP_PASS;
    }

    // LPM lookup against the IPv4 blacklist (source address).
    struct lpm_v4_key key = {
        .prefixlen = 32,
        .addr      = iph->saddr,
    };
    if (bpf_map_lookup_elem(&blacklist_v4, &key)) {
        bump(1);
        return XDP_DROP;
    }

    // Port-based drop for TCP/UDP destination port.
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(tcph + 1) > data_end) {
            bump(4);
            return XDP_PASS;
        }
        __u16 dport = bpf_ntohs(tcph->dest);
        if (bpf_map_lookup_elem(&port_drop, &dport)) {
            bump(2);
            return XDP_DROP;
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(udph + 1) > data_end) {
            bump(4);
            return XDP_PASS;
        }
        __u16 dport = bpf_ntohs(udph->dest);
        if (bpf_map_lookup_elem(&port_drop, &dport)) {
            bump(2);
            return XDP_DROP;
        }
    } else {
        bump(6);
    }

    bump(3);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
