#!/bin/sh
set -eu

upstream="${1:-/lib/netifd/proto/dhcp.sh}"
awk '
/^[[:space:]]*add_protocol dhcp[[:space:]]*$/ { count++; next }
{ print }
END { if (count != 1) exit 1 }
' "$upstream"

cat <<'PROTO'

proto_clatch_dhcp_init_config() {
	proto_dhcp_init_config
}

proto_clatch_dhcp_setup() {
	/usr/sbin/clatch openwrt prepare /etc/clatch/openwrt.json "$1" "$2" || {
		proto_notify_error "$1" CLATCH_GUARD_FAILED
		return 1
	}
	proto_dhcp_setup "$@"
}

proto_clatch_dhcp_renew() {
	/usr/sbin/clatch openwrt prepare /etc/clatch/openwrt.json "$1" "$2" || {
		proto_notify_error "$1" CLATCH_GUARD_FAILED
		return 1
	}
	proto_dhcp_renew "$@"
}

proto_clatch_dhcp_teardown() {
	proto_dhcp_teardown "$@"
}

add_protocol clatch_dhcp
PROTO
