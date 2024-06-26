#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

#define HP_IP 0xC0A83870 // 192.168.56.112 in hexadecimal
#define LP_IP 0xC0A83873 // 192.168.56.115 in hexadecimal

#define HP_HPP 7001
#define HP_LPP 7002
#define LP_HPP 7003
#define LP_LPP 7004

#define HP_TOKENS_PER_SEC 100000000 // 100 Mbit/s in bits per second
#define LP_TOKENS_PER_SEC 20000000  // 20 Mbit/s in bits per second

#define NSEC_PER_SEC 1000000000ULL  // Nanoseconds per second

// Define token bucket maps
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, __u64);
} hp_tokens SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, __u64);
} lp_tokens SEC(".maps");

// Define timestamp map to refill tokens periodically
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, __u64);
} last_refill_time SEC(".maps");

// Define control map for LP to use HP bandwidth
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct {
        __u8 lp_can_use_hp;
        __u64 hp_access_time;
    });
} hp_lp_control SEC(".maps");

// Define dropped packets map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4);
    __type(key, __u16);
    __type(value, __u64);
} dropped_packets SEC(".maps");

// Define passed packets map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4);
    __type(key, __u16);
    __type(value, __u64);
} passed_packets SEC(".maps");

static __always_inline void increment_dropped_packets(__u16 port) {
    __u64 *counter = bpf_map_lookup_elem(&dropped_packets, &port);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    } else {
        __u64 initial_value = 1;
        bpf_map_update_elem(&dropped_packets, &port, &initial_value, BPF_ANY);
    }
}

static __always_inline void increment_passed_packets(__u16 port) {
    __u64 *counter = bpf_map_lookup_elem(&passed_packets, &port);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    } else {
        __u64 initial_value = 1;
        bpf_map_update_elem(&passed_packets, &port, &initial_value, BPF_ANY);
    }
}

SEC("xdp")
int xdp_rate_limiter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    __u16 dest_port = 0;

    // Ensure the packet is long enough to contain an Ethernet and IP header
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Extract destination port based on protocol
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        dest_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;

        dest_port = bpf_ntohs(udp->dest);
    }

    // Retrieve token bucket and control information
    int index = 0;
    __u64 *hp_token_count = bpf_map_lookup_elem(&hp_tokens, &index);
    __u64 *lp_token_count = bpf_map_lookup_elem(&lp_tokens, &index);
    __u64 *refill_time = bpf_map_lookup_elem(&last_refill_time, &index);
    struct {
        __u8 lp_can_use_hp;
        __u64 hp_access_time;
    } *control = bpf_map_lookup_elem(&hp_lp_control, &index);

    if (!hp_token_count || !lp_token_count || !refill_time || !control)
        return XDP_ABORTED;

    // Packet size in bits
    __u64 packet_size_bits = (data_end - data) * 8;

    // Current time in nanoseconds
    __u64 current_time = bpf_ktime_get_ns();

    // Refill tokens every second
    if (current_time - *refill_time > NSEC_PER_SEC) {
        // Calculate elapsed time since last refill in seconds
        __u64 elapsed_ns = current_time - *refill_time;
        __u64 elapsed_sec = elapsed_ns / NSEC_PER_SEC;

        // Refill tokens for both buckets
        *hp_token_count += elapsed_sec * HP_TOKENS_PER_SEC;
        *lp_token_count += elapsed_sec * LP_TOKENS_PER_SEC;

        // Cap tokens to their maximum values
        if (*hp_token_count > HP_TOKENS_PER_SEC)
            *hp_token_count = HP_TOKENS_PER_SEC;
        if (*lp_token_count > LP_TOKENS_PER_SEC)
            *lp_token_count = LP_TOKENS_PER_SEC;

        // Update refill time
        *refill_time = current_time;

        // Reset LP to use HP flag after refill
        control->lp_can_use_hp = 1;
    }

    // Determine packet type and process accordingly
    if (ip->saddr == __constant_htonl(HP_IP)) {
        if (dest_port == HP_HPP) {
            increment_passed_packets(dest_port); // Increment passed packet counter
            return XDP_PASS;
        } else if (dest_port == HP_LPP) {
            if (*hp_token_count >= packet_size_bits) {
                *hp_token_count -= packet_size_bits;
                control->lp_can_use_hp = 0;             // Set flag to 0 when HP packet is processed
                control->hp_access_time = current_time; // Start timer for LP access to HP bandwidth
                increment_passed_packets(dest_port);    // Increment passed packet counter
                return XDP_PASS;                        // Allow HP packet
            } else if (*lp_token_count >= packet_size_bits - *hp_token_count) {
                *lp_token_count -= (packet_size_bits - *hp_token_count);
                *hp_token_count = 0;
                increment_passed_packets(dest_port); // Increment passed packet counter
                return XDP_PASS; // Allow HP packet using LP tokens
            } else {
                increment_dropped_packets(dest_port); // Increment dropped packet counter
                return XDP_DROP; // Drop HP packet if not enough tokens in either bucket
            }
        }
    } else if (ip->saddr == __constant_htonl(LP_IP)) {
        if (dest_port == LP_LPP) {
            if (*lp_token_count >= packet_size_bits) {
                *lp_token_count -= packet_size_bits;
                increment_passed_packets(dest_port); // Increment passed packet counter
                return XDP_PASS; // Allow LP packet with enough tokens
            } else {
                // Check if LP can use HP bandwidth
                if (control->lp_can_use_hp && *hp_token_count >= (packet_size_bits - *lp_token_count)) {
                    *hp_token_count -= (packet_size_bits - *lp_token_count);
                    *lp_token_count = 0;
                    increment_passed_packets(dest_port); // Increment passed packet counter
                    return XDP_PASS; // Allow LP packet using HP tokens
                } else {
                    increment_dropped_packets(dest_port); // Increment dropped packet counter
                    return XDP_DROP; // Drop LP packet if not allowed or not enough tokens
                }
            }
        } else if (dest_port == LP_HPP) {
            if (*lp_token_count >= packet_size_bits) {
                *lp_token_count -= packet_size_bits;
                increment_passed_packets(dest_port); // Increment passed packet counter
                return XDP_PASS; // Allow LP packet with enough tokens
            } else {
                // Check if LP can use HP bandwidth
                if (*hp_token_count >= (packet_size_bits - *lp_token_count)) {
                    *hp_token_count -= (packet_size_bits - *lp_token_count);
                    *lp_token_count = 0;
                    increment_passed_packets(dest_port); // Increment passed packet counter
                    return XDP_PASS; // Allow LP packet using HP tokens
                } else {
                    increment_dropped_packets(dest_port); // Increment dropped packet counter
                    return XDP_DROP; // Drop LP packet if not allowed or not enough tokens
                }
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
