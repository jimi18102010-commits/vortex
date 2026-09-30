#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_BLOCKED_IPS 65536

/* Map to store blacklisted IPv4 addresses */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS);
    __type(key, __u32);   /* IPv4 in network byte order */
    __type(value, __u64); /* Drop counter / timestamp */
} blocked_ips SEC(".maps");

/* Map to store global statistics */
struct stats_record {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 dropped_packets;
    __u64 passed_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_record);
} vortex_stats SEC(".maps");

SEC("xdp")
int xdp_vortex_shield(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u32 stats_key = 0;
    struct stats_record *stats = bpf_map_lookup_elem(&vortex_stats, &stats_key);

    /* 1. Parse Ethernet Header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only handle IPv4 for this filter (pass ARP, IPv6, etc.) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* 2. Parse IPv4 Header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Strict IP header length validation */
    if (ip->ihl < 5)
        return XDP_DROP;

    __u64 pkt_len = (long)data_end - (long)data;
    if (stats) {
        __sync_fetch_and_add(&stats->rx_packets, 1);
        __sync_fetch_and_add(&stats->rx_bytes, pkt_len);
    }

    __u32 src_ip = ip->saddr;

    /* 3. Check Blacklist BPF Map (O(1) lookup in kernel) */
    __u64 *drop_count = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (drop_count) {
        __sync_fetch_and_add(drop_count, 1);
        if (stats) {
            __sync_fetch_and_add(&stats->dropped_packets, 1);
        }
        return XDP_DROP; /* ZERO-COPY WIRE DROP */
    }

    /* 4. Malformed packet mitigation (SYN-flood without payload, NULL scan, XMAS scan) */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((char *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) <= data_end) {
            /* NULL scan (no flags set) */
            if (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst && !tcp->psh && !tcp->urg) {
                if (stats) __sync_fetch_and_add(&stats->dropped_packets, 1);
                return XDP_DROP;
            }
            /* SYN + FIN impossible combination */
            if (tcp->syn && tcp->fin) {
                if (stats) __sync_fetch_and_add(&stats->dropped_packets, 1);
                return XDP_DROP;
            }
        }
    }

    if (stats) {
        __sync_fetch_and_add(&stats->passed_packets, 1);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
