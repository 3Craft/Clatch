#!/bin/sh

. /lib/functions.sh
. ../netifd-proto.sh
init_proto "$@"

proto_clatch_static_init_config() {
	proto_config_add_string 'ipaddr:ipaddr'
	proto_config_add_string 'netmask:netmask'
	proto_config_add_string 'gateway:ipaddr'
	proto_config_add_array 'dns:list(string)'
	proto_config_add_int 'metric'
	proto_config_add_boolean 'defaultroute:bool'
}

proto_clatch_static_setup() {
	local config="$1"
	local device="$2"
	local ipaddr netmask gateway metric defaultroute dns server
	json_get_vars ipaddr netmask gateway metric defaultroute
	json_get_values dns dns

	[ -n "$ipaddr" ] && [ -n "$device" ] || return 1
	case "$ipaddr" in
		*/*)
			netmask="${ipaddr#*/}"
			ipaddr="${ipaddr%/*}"
			;;
	esac
	[ -n "$netmask" ] || return 1
	/usr/sbin/clatch openwrt prepare /etc/clatch/openwrt.json "$config" "$device" || {
		proto_notify_error "$config" CLATCH_GUARD_FAILED
		return 1
	}

	proto_init_update "$device" 1
	proto_add_ipv4_address "$ipaddr" "$netmask"
	if [ -n "$gateway" ] && [ "$defaultroute" != 0 ]; then
		proto_add_ipv4_route 0.0.0.0 0 "$gateway" "" "$metric"
	fi
	for server in $dns; do
		proto_add_dns_server "$server"
	done
	proto_send_update "$config"
}

proto_clatch_static_teardown() {
	return 0
}

add_protocol clatch_static
