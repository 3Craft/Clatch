// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "guard.h"

struct policy_map {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, POLICY_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct prefix_key);
    __type(value, __u32);
};
struct policy_map policy_template SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, struct policy_map);
} policy_sets SEC(".maps") = { .values = { [0] = &policy_template } };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct guard_settings);
} settings SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, COUNTERS);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

static __always_inline int verdict(__u32 reason, int result)
{
    __u64 *count = bpf_map_lookup_elem(&counters, &reason);
    if (count) (*count)++;
    return result;
}

static __always_inline __u32 flags(void *policy, __u32 family, const void *addr)
{
    struct prefix_key key = { .prefixlen = family == 4 ? 64 : 160, .family = family };
    if (family == 4) __builtin_memcpy(key.address, addr, 4);
    else __builtin_memcpy(key.address, addr, 16);
    __u32 *value = bpf_map_lookup_elem(policy, &key);
    return value ? *value : 0;
}

static __always_inline int diagnostic_echo4(struct __sk_buff *skb, __u32 offset,
                                           const struct iphdr *ip, __u8 expected_type)
{
    __u8 icmp[8];
    if (ip->protocol != IPPROTO_ICMP || (bpf_ntohs(ip->frag_off) & 0x3fff) ||
        bpf_ntohs(ip->tot_len) < ip->ihl * 4 + sizeof(icmp) ||
        bpf_skb_load_bytes(skb, offset + ip->ihl * 4, icmp, sizeof(icmp)))
        return 0;
    return icmp[0] == expected_type && icmp[1] == 0;
}

// TCX_NEXT (-1) continues to the normal device path; DROP is terminal.
SEC("tcx/egress")
int gateway_egress(struct __sk_buff *skb)
{
    __u16 protocol;
    __u32 offset = ETH_HLEN, zero = 0;
    if (bpf_skb_load_bytes(skb, 12, &protocol, 2))
        return verdict(DENY_PARSE, 2);
#pragma unroll
    for (int tag = 0; tag < 2; tag++) {
        if (protocol == bpf_htons(ETH_P_8021Q) || protocol == bpf_htons(ETH_P_8021AD)) {
            if (bpf_skb_load_bytes(skb, offset + 2, &protocol, 2))
                return verdict(DENY_PARSE, 2);
            offset += 4;
        }
    }
    if (protocol == bpf_htons(ETH_P_ARP)) {
        // Ethernet/IPv4 ARP only. It carries no routed IP payload.
        __u8 arp[28];
        if (bpf_skb_load_bytes(skb, offset, arp, sizeof(arp)) ||
            arp[0] || arp[1] != 1 || arp[2] != 8 || arp[3] ||
            arp[4] != 6 || arp[5] != 4 || arp[6] || (arp[7] != 1 && arp[7] != 2))
            return verdict(DENY_PARSE, 2);
        return verdict(ALLOW_ARP, -1);
    }
    void *policy = bpf_map_lookup_elem(&policy_sets, &zero);
    struct guard_settings *config = bpf_map_lookup_elem(&settings, &zero);
    if (!policy || !config || !config->diagnostic_uid)
        return verdict(DENY_POLICY, 2);

    if (protocol == bpf_htons(ETH_P_IP)) {
        struct iphdr ip;
        if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) || ip.version != 4 ||
            ip.ihl < 5 || bpf_ntohs(ip.tot_len) < ip.ihl * 4)
            return verdict(DENY_PARSE, 2);
        __u32 destination = flags(policy, 4, &ip.daddr);
        __u32 source = flags(policy, 4, &ip.saddr);
        if (destination & LAN) {
            // Local transparent replies can have the remote server's source IP.
            if (!skb->ingress_ifindex || (source & DIRECT) ||
                (config->trusted_tun_ifindex && skb->ingress_ifindex == config->trusted_tun_ifindex))
                return verdict(ALLOW_RETURN, -1);
            if (skb->ingress_ifindex == skb->ifindex && (source & DIAG_DEST) &&
                (destination & DIAG_CLIENT) && diagnostic_echo4(skb, offset, &ip, 0))
                return verdict(ALLOW_RETURN, -1);
            return verdict(DENY_RETURN, 2);
        }
        // A TUN can inject remote-source replies to LAN, never a second WAN path.
        if (config->trusted_tun_ifindex && skb->ingress_ifindex == config->trusted_tun_ifindex)
            return verdict(DENY_RETURN, 2);
        if (skb->ingress_ifindex && !(source & LAN))
            return verdict(DENY_RETURN, 2);
        if (destination & DIRECT)
            return verdict(ALLOW_DIRECT, -1);
        if (skb->ingress_ifindex == skb->ifindex && (source & DIAG_CLIENT) &&
            (destination & DIAG_DEST) && diagnostic_echo4(skb, offset, &ip, 8))
            return verdict(ALLOW_DIAGNOSTIC, -1);
        if (!skb->ingress_ifindex && (source & LOCAL) &&
            bpf_get_socket_uid(skb) == config->diagnostic_uid &&
            !(bpf_ntohs(ip.frag_off) & 0x3fff)) {
            if (ip.protocol == IPPROTO_TCP || ip.protocol == IPPROTO_UDP)
                return verdict(ALLOW_DIAGNOSTIC, -1);
            __u8 type;
            if (ip.protocol == IPPROTO_ICMP &&
                !bpf_skb_load_bytes(skb, offset + ip.ihl * 4, &type, 1) && type == 8)
                return verdict(ALLOW_DIAGNOSTIC, -1);
        }
        return verdict(DENY_DESTINATION, 2);
    }
    if (protocol == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr ip;
        if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) || ip.version != 6)
            return verdict(DENY_PARSE, 2);
        // Keep IPv6 link discovery, but do not make public IPv6 an accidental exit.
        __u8 control[24];
        int link_source = ip.saddr.s6_addr[0] == 0xfe && (ip.saddr.s6_addr[1] & 0xc0) == 0x80;
        int unspecified = !(ip.saddr.s6_addr32[0] | ip.saddr.s6_addr32[1] | ip.saddr.s6_addr32[2] | ip.saddr.s6_addr32[3]);
        int link_destination = ip.daddr.s6_addr[0] == 0xfe && (ip.daddr.s6_addr[1] & 0xc0) == 0x80;
        int solicited = ip.daddr.s6_addr32[0] == bpf_htonl(0xff020000) &&
            !ip.daddr.s6_addr32[1] && ip.daddr.s6_addr32[2] == bpf_htonl(1) && ip.daddr.s6_addr[12] == 0xff;
        int all_nodes = ip.daddr.s6_addr32[0] == bpf_htonl(0xff020000) &&
            !ip.daddr.s6_addr32[1] && !ip.daddr.s6_addr32[2] && ip.daddr.s6_addr32[3] == bpf_htonl(1);
        if (!skb->ingress_ifindex && ip.hop_limit == 255 && ip.nexthdr == IPPROTO_ICMPV6 &&
            !bpf_skb_load_bytes(skb, offset + sizeof(ip), control, sizeof(control)) && !control[1] &&
            ((control[0] == 135 && (link_source || unspecified) && (solicited || (link_source && link_destination))) ||
             (control[0] == 136 && link_source && (all_nodes || link_destination))))
            return verdict(ALLOW_NDP, -1);
        // Linux MLD reports use a single Hop-by-Hop Router Alert header.
        __u8 hbh[8], mld[8];
        if (!skb->ingress_ifindex && link_source && ip.hop_limit == 1 && ip.nexthdr == 0 &&
            ip.daddr.s6_addr[0] == 0xff && ip.daddr.s6_addr[1] == 2 &&
            !bpf_skb_load_bytes(skb, offset + sizeof(ip), hbh, sizeof(hbh)) &&
            hbh[0] == IPPROTO_ICMPV6 && !hbh[1] && hbh[2] == 5 && hbh[3] == 2 && !hbh[4] && !hbh[5] &&
            !bpf_skb_load_bytes(skb, offset + sizeof(ip) + 8, mld, sizeof(mld)) && !mld[1] &&
            (mld[0] == 130 || mld[0] == 131 || mld[0] == 132 || mld[0] == 143))
            return verdict(ALLOW_NDP, -1);
        __u32 destination = flags(policy, 6, &ip.daddr);
        __u32 source = flags(policy, 6, &ip.saddr);
        if (!config->public_ipv6 &&
            !((ip.daddr.s6_addr[0] & 0xfe) == 0xfc ||
              (ip.daddr.s6_addr[0] == 0xfe && (ip.daddr.s6_addr[1] & 0xc0) == 0x80)))
            return verdict(DENY_IPV6, 2);
        if (destination & LAN) {
            if (!skb->ingress_ifindex || (source & DIRECT))
                return verdict(ALLOW_RETURN, -1);
            return verdict(DENY_RETURN, 2);
        }
        if ((!skb->ingress_ifindex || (source & LAN)) && (destination & DIRECT))
            return verdict(ALLOW_DIRECT, -1);
        return verdict(DENY_IPV6, 2);
    }
    return verdict(DENY_PARSE, 2);
}
char LICENSE[] SEC("license") = "GPL";
