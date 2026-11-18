package firewall

import (
	"fmt"
	"strings"
	"text/template"

	"clatch-gateway/internal/policy"
)

const tableName = "jdn_gateway_guard"

type guardRules struct {
	TableName  string
	Interface  string
	UID        uint32
	Direct4    string
	Direct6    string
	LAN4       string
	Local4     string
	TUN        string
	TUNIndex   uint32
	Diagnostic *policy.Diagnostic
}

var guardTemplate = template.Must(template.New("egress guard").Parse(`add table inet {{.TableName}}
delete table inet {{.TableName}}
table inet {{.TableName}} {
 set direct4 { type ipv4_addr; flags interval; auto-merge; elements = { {{.Direct4}} }; }
 set direct6 { type ipv6_addr; flags interval; auto-merge; {{if .Direct6}}elements = { {{.Direct6}} };{{end}} }
 set lan4 { type ipv4_addr; flags interval; elements = { {{.LAN4}} }; }
 set local4 { type ipv4_addr; flags interval; elements = { {{.Local4}} }; }
{{if .Diagnostic}} chain lan_icmp_fragment_guard {
  type filter hook prerouting priority -450; policy accept;
  iifname "{{.Interface}}" ip saddr {{.Diagnostic.Source}} ip daddr {{.Diagnostic.Destination}} ip daddr != @direct4 ip protocol icmp ip frag-off & 0x3fff != 0 counter drop comment "jdn-lan-icmp-request-fragment"
  iifname "{{.Interface}}" ip saddr {{.Diagnostic.Destination}} ip daddr {{.Diagnostic.Source}} ip saddr != @direct4 ip protocol icmp ip frag-off & 0x3fff != 0 counter drop comment "jdn-lan-icmp-reply-fragment"
 }
{{end}} chain forward {
  type filter hook forward priority 300; policy drop;
{{if .TUNIndex}}  meta iif {{.TUNIndex}} ip daddr @lan4 counter accept comment "jdn-tun-return"
  meta iif {{.TUNIndex}} counter drop comment "jdn-tun-no-wan-forward"
  iifname "{{.Interface}}" oifname "{{.TUN}}" ip saddr @lan4 counter accept comment "jdn-tun-capture"
{{end}}{{if .Diagnostic}}{{template "request" .}} comment "jdn-lan-icmp-request-forward"
{{template "reply" .}} comment "jdn-lan-icmp-reply-forward"
{{end}}  ip saddr @lan4 ip daddr @direct4 counter accept comment "jdn-approved-forward"
  ip saddr @direct4 ip daddr @lan4 counter accept comment "jdn-approved-return"
 }
 chain lan_return {
{{if .TUNIndex}}  meta iif {{.TUNIndex}} counter accept comment "jdn-tun-lan-reply"
{{end}}  meta iif 0 counter accept comment "jdn-local-transparent-reply"
  ip saddr @direct4 counter accept
{{if .Diagnostic}}{{template "reply" .}} comment "jdn-lan-icmp-reply-egress"
{{end}}  counter drop
 }
 chain egress {
  type filter hook postrouting priority 310; policy accept;
  oifname != "{{.Interface}}" accept
  ip daddr @lan4 jump lan_return
{{if .TUNIndex}}  meta iif {{.TUNIndex}} counter drop comment "jdn-tun-no-wan-egress"
{{end}}  meta nfproto ipv4 meta iif != 0 ip saddr != @lan4 counter drop
  ip daddr @direct4 counter accept comment "jdn-approved-destination"
{{if .Diagnostic}}{{template "request" .}} comment "jdn-lan-icmp-request-egress"
{{end}}  meta iif 0 ip saddr @local4 meta skuid {{.UID}} meta l4proto { tcp, udp } counter accept comment "jdn-traceroute-socket"
  meta iif 0 ip saddr @local4 meta skuid {{.UID}} ip protocol icmp icmp type echo-request counter accept
  meta nfproto ipv6 meta iif 0 ip6 saddr :: ip6 daddr ff02::1:ff00:0/104 ip6 hoplimit 255 icmpv6 type nd-neighbor-solicit icmpv6 code 0 counter accept
  meta nfproto ipv6 meta iif 0 ip6 saddr fe80::/10 ip6 daddr { fe80::/10, ff02::1:ff00:0/104 } ip6 hoplimit 255 icmpv6 type nd-neighbor-solicit icmpv6 code 0 counter accept
  meta nfproto ipv6 meta iif 0 ip6 saddr fe80::/10 ip6 daddr { fe80::/10, ff02::1 } ip6 hoplimit 255 icmpv6 type nd-neighbor-advert icmpv6 code 0 counter accept
  meta nfproto ipv6 meta iif 0 ip6 saddr fe80::/10 ip6 daddr ff02::/16 ip6 hoplimit 1 ip6 nexthdr hopopt icmpv6 type { 130, 131, 132, 143 } icmpv6 code 0 counter accept
  meta nfproto ipv6 meta iif 0 ip6 daddr { fc00::/7, fe80::/10 } ip6 daddr @direct6 counter accept
  counter drop comment "jdn-default-deny"
 }
}
{{define "request"}}  iifname "{{.Interface}}" oifname "{{.Interface}}" ip saddr {{.Diagnostic.Source}} ip daddr {{.Diagnostic.Destination}} ip protocol icmp icmp type echo-request icmp code 0 ip frag-off & 0x3fff == 0 ct state { new, established } counter accept{{end}}
{{define "reply"}}  iifname "{{.Interface}}" oifname "{{.Interface}}" ip saddr {{.Diagnostic.Destination}} ip daddr {{.Diagnostic.Source}} ip protocol icmp icmp type echo-reply icmp code 0 ip frag-off & 0x3fff == 0 ct state established counter accept{{end}}`))

func RenderGuard(config policy.Config, approved policy.Approved, tunIndex uint32) (string, error) {
	rules := guardRules{
		TableName:  tableName,
		Interface:  config.Interface,
		UID:        config.DiagnosticUID,
		Direct4:    policy.Elements(approved.Prefixes, 32),
		Direct6:    policy.Elements(approved.Prefixes, 128),
		LAN4:       policy.Elements(config.LANPrefixes, 32),
		Local4:     policy.Elements(config.LocalPrefixes, 32),
		TUN:        config.TUNDevice(),
		TUNIndex:   tunIndex,
		Diagnostic: config.Diagnostic,
	}
	if rules.Direct4 == "" || rules.LAN4 == "" || rules.Local4 == "" {
		return "", fmt.Errorf("guard requires approved IPv4, LAN and local prefixes")
	}
	if tunIndex > 0 && rules.TUN == "" {
		return "", fmt.Errorf("non-TUN guard cannot authorize a TUN interface index")
	}

	var output strings.Builder
	if err := guardTemplate.Execute(&output, rules); err != nil {
		return "", err
	}
	return output.String(), nil
}
