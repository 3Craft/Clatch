#ifndef JDN_GATEWAY_GUARD_H
#define JDN_GATEWAY_GUARD_H
#include <linux/types.h>

#define DIRECT 1
#define LAN 2
#define LOCAL 4
#define DIAG_CLIENT 8
#define DIAG_DEST 16
#define POLICY_MAX 20000
struct prefix_key { __u32 prefixlen; __u32 family; __u8 address[16]; };
struct guard_settings { __u32 diagnostic_uid; __u32 public_ipv6; __u32 trusted_tun_ifindex; };
enum verdict_counter {
    ALLOW_DIRECT, ALLOW_RETURN, ALLOW_DIAGNOSTIC, ALLOW_ARP, ALLOW_NDP,
    DENY_DESTINATION, DENY_RETURN, DENY_PARSE, DENY_IPV6, DENY_POLICY, COUNTERS
};
#endif
