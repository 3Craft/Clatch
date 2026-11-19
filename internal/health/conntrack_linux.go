//go:build linux

package health

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"

	"clatch-gateway/internal/native"
	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
)

type nativeTUNCheck struct {
	egress  string
	tunnel  string
	gateway netip.Addr
	direct  []netip.Prefix
}

func prepareNativeTUNCheck() (*nativeTUNCheck, error) {
	config, err := policy.ReadConfig("/etc/jdn-gateway/config.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // The connection-mark check also supports hosts without a Clatch profile.
	}
	if err != nil || !config.NativeTUN {
		return nil, err
	}
	approved, err := config.ReadApproved()
	if err != nil {
		return nil, err
	}
	tunnel, err := native.Identity(config)
	if err != nil {
		return nil, err
	}
	if tunnel.Ifindex == 0 {
		return nil, fmt.Errorf("native TUN is not bound")
	}
	if err := native.VerifyCapture(config, approved); err != nil {
		return nil, err
	}
	check := nativeTUNCheck{egress: config.Interface, tunnel: tunnel.Device, direct: approved.Prefixes}
	for _, prefix := range config.LocalPrefixes {
		if prefix.Addr().Is4() {
			if check.gateway.IsValid() {
				return nil, fmt.Errorf("native TUN expects one local IPv4 address")
			}
			check.gateway = prefix.Addr()
		}
	}
	return &check, nil
}

func (t nativeTUNCheck) verify(check *httpCheck, local, remote netip.AddrPort) error {
	localIP, remoteIP := local.Addr().Unmap(), remote.Addr().Unmap()
	direct := check.Role == "direct"
	if policy.Match(t.direct, netip.PrefixFrom(remoteIP, 32)) != direct {
		return fmt.Errorf("peer %s does not match the %s role in the native TUN policy", remoteIP, check.Role)
	}
	tunIP := netip.MustParseAddr(native.TUNIPv4)
	if localIP != tunIP && !(direct && localIP == t.gateway) {
		return fmt.Errorf("unexpected native TUN socket source %s for the %s probe", localIP, check.Role)
	}
	localPort, remotePort := strconv.Itoa(int(local.Port())), strconv.Itoa(int(remote.Port()))
	routeArgs := []string{"-4", "-j", "route", "get", remoteIP.String(), "from", localIP.String(),
		"ipproto", "tcp", "sport", localPort, "dport", remotePort}
	device, reply := t.tunnel, localIP
	if direct {
		// The OUTPUT rule reroutes approved destinations with the packet mark.
		routeArgs = append(routeArgs, "mark", native.TUNBypassMark)
		device, reply = t.egress, t.gateway
	}
	raw, err := system.Command("", "ip", routeArgs...)
	if err != nil {
		return err
	}
	var routes []struct {
		Device string `json:"dev"`
	}
	if err := json.Unmarshal(raw, &routes); err != nil {
		return fmt.Errorf("decode native TUN route: %w", err)
	}
	if len(routes) != 1 || routes[0].Device != device {
		return fmt.Errorf("expected native TUN %s route via %s", check.Role, device)
	}

	// Direct flows can have source NAT. The tunnel flow must keep its source tuple.
	filters := []string{"--reply-src", remoteIP.String(), "--reply-dst", reply.String(),
		"--reply-port-src", remotePort, "--status", "ASSURED"}
	if !direct {
		filters = append(filters, "--reply-port-dst", localPort)
	}
	marks, err := inspectMarks(local, remote, 0, filters...)
	if err != nil {
		return fmt.Errorf("native TUN conntrack reply to %s: %w", reply, err)
	}
	check.Marks, check.ReplyDestination = marks, reply
	return nil
}
