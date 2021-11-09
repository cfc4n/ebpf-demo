// +build ignore

#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

// ---------------------------------------------
// -- The real program will be somewhere here --
// ---------------------------------------------

struct bpf_map_def SEC("maps") cgroup_counters_map = {
    .type = BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
    .key_size = sizeof(struct bpf_cgroup_storage_key),
    .value_size = sizeof(__u64),
};

inline int handle_skb(struct __sk_buff *skb)
{
    __u16 bytes = 0;

    // Extract packet size from IPv4 / IPv6 header
    switch (skb->family)
    {
    case AF_INET:
        {
            struct iphdr iph;
            bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));
            bytes = ntohs(iph.tot_len);
            break;
        }
    case AF_INET6:
        {
            struct ip6_hdr ip6h;
            bpf_skb_load_bytes(skb, 0, &ip6h, sizeof(struct ip6_hdr));
            bytes = ntohs(ip6h.ip6_plen);
            break;
        }
    default:
        // This should never be the case as this eBPF hook is called in
        // netfilter context and thus not for AF_PACKET, AF_UNIX nor AF_NETLINK
        // for instance.
        return true;
    }

    // Update counters in the per-cgroup map
    __u64 *bytes_counter = bpf_get_local_storage(&cgroup_counters_map, 0);
    __sync_fetch_and_add(bytes_counter, bytes);

    // Let the packet pass
    return true;
}

// Ingress hook - handle incoming packets
SEC("cgroup_skb/ingress") int ingress(struct __sk_buff *skb)
{
    return handle_skb(skb);
}

// Egress hook - handle outgoing packets
SEC("cgroup_skb/egress") int egress(struct __sk_buff *skb)
{
    return handle_skb(skb);
}


char __license[] __attribute__((section("license"), used)) = "MIT";