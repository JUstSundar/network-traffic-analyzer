/*
 * xdp_roce_core.c: Kernel-space eBPF program for RoCEv2 (UDP 4791) line-rate telemetry.
 *
 * NOTE ON PORTABILITY & IDE COMPATIBILITY:
 * - When loaded by BCC, BCC automatically defines BPF_HASH, BPF_ARRAY, and provides
 *   internal BPF helper bindings.
 * - When inspected by IDEs, language servers (clangd), or standalone linters, the
 *   preprocessor block below provides transparent fallback definitions for BPF_HASH,
 *   BPF_ARRAY, struct xdp_md, and XDP_PASS, eliminating "instantiation" and "undeclared" errors.
 */

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/*
 * Standard RFC 768 UDP Header definition.
 */
#ifndef _LINUX_UDP_H
#define _LINUX_UDP_H
struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
};
#endif

/*
 * IDE / Clangd Fallback Definitions:
 * Active ONLY when compiling outside the BCC runtime environment (e.g. IDE language servers).
 */
#ifndef BPF_HASH
#include <linux/bpf.h>

#define BPF_HASH(name, key_t, leaf_t, ...) \
    struct { \
        leaf_t* (*lookup)(key_t*); \
        int (*update)(key_t*, leaf_t*); \
    } name

#define BPF_ARRAY(name, leaf_t, ...) \
    struct { \
        leaf_t* (*lookup)(__u32*); \
        int (*update)(__u32*, leaf_t*); \
    } name

static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
#endif

#define ROCE_V2_UDP_PORT 4791

/*
 * Flow key representing an individual unidirectional RoCEv2 flow.
 * In production AI clusters, flows are identified by IP 4-tuple.
 */
struct flow_key_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

/*
 * Per-flow metrics tracking packet volume, byte volume, and latest arrival timestamp.
 */
struct flow_metrics_t {
    __u64 packet_count;
    __u64 byte_count;
    __u64 last_timestamp_ns;
};

/*
 * Aggregate interface-level statistics.
 */
struct global_stats_t {
    __u64 total_roce_packets;
    __u64 total_roce_bytes;
    __u64 total_non_roce_packets;
};

/*
 * BPF Maps:
 * - roce_flow_map: Key-value hash table mapping 4-tuple flow keys to performance metrics.
 * - roce_global_stats: 1-slot array storing interface-wide aggregate metrics.
 */
BPF_HASH(roce_flow_map, struct flow_key_t, struct flow_metrics_t, 65536);
BPF_ARRAY(roce_global_stats, struct global_stats_t, 1);

/*
 * Inline helper for endianness conversion.
 */
#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif

#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif

/*
 * xdp_roce_filter:
 * Main XDP packet inspection program attached at the driver or generic RX hook.
 * Inspects incoming frames at line rate, filters for RoCEv2 (UDP port 4791),
 * atomically records flow statistics, and passes the packet to the networking stack.
 */
int xdp_roce_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 packet_len = (__u64)(data_end - data);

    /*
     * 1. ETHERNET LAYER INSPECTION
     * Perform strict bounds verification before accessing the Ethernet header.
     */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    __u16 h_proto = eth->h_proto;
    void *nh = (void *)(eth + 1);

    /*
     * Support 802.1Q / 802.1ad VLAN tagging commonly present in datacenter fabrics.
     */
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr {
            __be16 h_vlan_TCI;
            __be16 h_vlan_encapsulated_proto;
        };
        struct vlan_hdr *vlan = nh;
        if ((void *)(vlan + 1) > data_end) {
            return XDP_PASS;
        }
        h_proto = vlan->h_vlan_encapsulated_proto;
        nh = (void *)(vlan + 1);
    }

    /*
     * Filter strictly for IPv4 packets (EtherType 0x0800).
     */
    if (h_proto != bpf_htons(ETH_P_IP)) {
        __u32 zero = 0;
        struct global_stats_t *global = roce_global_stats.lookup(&zero);
        if (global) {
            __sync_fetch_and_add(&global->total_non_roce_packets, 1);
        }
        return XDP_PASS;
    }

    /*
     * 2. IP LAYER INSPECTION
     * Boundary-check the base IPv4 header structure.
     */
    struct iphdr *iph = nh;
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    /*
     * Filter strictly for UDP (Protocol 17).
     */
    if (iph->protocol != IPPROTO_UDP) {
        __u32 zero = 0;
        struct global_stats_t *global = roce_global_stats.lookup(&zero);
        if (global) {
            __sync_fetch_and_add(&global->total_non_roce_packets, 1);
        }
        return XDP_PASS;
    }

    /*
     * Calculate IPv4 Internet Header Length (IHL).
     * IHL indicates header size in 32-bit (4-byte) words. Minimum valid size is 5 (20 bytes).
     * Clamp bounds strictly to satisfy the BPF Verifier.
     */
    __u32 ip_hlen = iph->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr) || ip_hlen > 60) {
        return XDP_PASS;
    }

    /*
     * Prove to the BPF verifier that the variable-length IPv4 header
     * does not overshoot packet data bounds.
     */
    if ((void *)iph + ip_hlen > data_end) {
        return XDP_PASS;
    }

    /*
     * 3. UDP LAYER INSPECTION
     * Point cursor to the beginning of the UDP header and verify bounds.
     */
    struct udphdr *udph = (void *)iph + ip_hlen;
    if ((void *)(udph + 1) > data_end) {
        return XDP_PASS;
    }

    /*
     * Check if destination port matches standard RoCEv2 port 4791.
     */
    if (udph->dest != bpf_htons(ROCE_V2_UDP_PORT)) {
        __u32 zero = 0;
        struct global_stats_t *global = roce_global_stats.lookup(&zero);
        if (global) {
            __sync_fetch_and_add(&global->total_non_roce_packets, 1);
        }
        return XDP_PASS;
    }

    /*
     * 4. FLOW KEY EXTRACTION
     * Populate 4-tuple key (Source IP, Destination IP, Source Port, Destination Port).
     */
    struct flow_key_t key = {};
    key.src_ip = iph->saddr;
    key.dst_ip = iph->daddr;
    key.src_port = bpf_ntohs(udph->source);
    key.dst_port = bpf_ntohs(udph->dest);

    __u64 now = bpf_ktime_get_ns();

    /*
     * 5. PER-FLOW METRIC ACCUMULATION
     * Look up existing flow entry or initialize a new one.
     * Use atomic operations (__sync_fetch_and_add) to guarantee accurate counting
     * under high multi-core RX queue concurrency without lock contention.
     */
    struct flow_metrics_t *metrics = roce_flow_map.lookup(&key);
    if (metrics) {
        __sync_fetch_and_add(&metrics->packet_count, 1);
        __sync_fetch_and_add(&metrics->byte_count, packet_len);
        metrics->last_timestamp_ns = now;
    } else {
        struct flow_metrics_t initial_metrics = {
            .packet_count = 1,
            .byte_count = packet_len,
            .last_timestamp_ns = now,
        };
        roce_flow_map.update(&key, &initial_metrics);
    }

    /*
     * 6. AGGREGATE STATS UPDATE
     * Increment global RoCEv2 packet and byte counters.
     */
    __u32 zero = 0;
    struct global_stats_t *global = roce_global_stats.lookup(&zero);
    if (global) {
        __sync_fetch_and_add(&global->total_roce_packets, 1);
        __sync_fetch_and_add(&global->total_roce_bytes, packet_len);
    }

    /*
     * 7. FORWARD PACKET
     * Return XDP_PASS to allow the frame to proceed to the Linux RDMA subsystem
     * or standard networking stack without latency degradation.
     */
    return XDP_PASS;
}
