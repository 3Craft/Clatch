//go:build linux

package health

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"clatch-gateway/internal/system"

	"golang.org/x/net/dns/dnsmessage"
)

type Request struct {
	Resolver  netip.AddrPort
	DirectURL string
	ProxyURL  string
	Exits     []netip.Addr
	EmptyAAAA bool
	Marks     bool
}

type dnsCheck struct {
	Domain        string `json:"domain"`
	Kind          uint16 `json:"type"`
	Transport     string `json:"transport"`
	Answers       int    `json:"answers"`
	ExpectedEmpty bool   `json:"expected_empty"`
}

type httpCheck struct {
	Domain           string     `json:"domain"`
	Role             string     `json:"role"`
	Status           int        `json:"status"`
	Peer             netip.Addr `json:"peer"`
	Exit             netip.Addr `json:"exit_ip,omitzero"`
	Marks            []uint32   `json:"conntrack_marks,omitempty"`
	ReplyDestination netip.Addr `json:"conntrack_reply_dst,omitzero"`
}

type Report struct {
	Time   time.Time   `json:"time"`
	DNS    []dnsCheck  `json:"dns"`
	HTTP   []httpCheck `json:"http"`
	Passed bool        `json:"passed"`
}

func Check(ctx context.Context, request Request) (Report, error) {
	report := Report{Time: time.Now().UTC()}
	if len(request.Exits) == 0 {
		return report, fmt.Errorf("at least one approved proxy exit is required")
	}
	var nativeTUN *nativeTUNCheck
	if request.Marks {
		var err error
		nativeTUN, err = prepareNativeTUNCheck()
		if err != nil {
			return report, fmt.Errorf("prepare conntrack check: %w", err)
		}
	}
	for _, probe := range []struct {
		domain string
		kind   dnsmessage.Type
	}{
		{"www.baidu.com", dnsmessage.TypeA}, {"www.qq.com", dnsmessage.TypeA}, {"ip.fm", dnsmessage.TypeA},
		{"www.google.com", dnsmessage.TypeA}, {"www.google.com", dnsmessage.TypeAAAA},
	} {
		for _, transport := range []string{"udp", "tcp"} {
			empty := request.EmptyAAAA && probe.kind == dnsmessage.TypeAAAA
			answers, err := DNS(ctx, request.Resolver, transport+"4", probe.domain, probe.kind, empty)
			if err != nil {
				return report, fmt.Errorf("DNS %s %s over %s: %w", probe.domain, probe.kind, transport, err)
			}
			report.DNS = append(report.DNS, dnsCheck{probe.domain, uint16(probe.kind), transport, answers, empty})
		}
	}
	for _, probe := range []struct {
		url  string
		role string
		mark uint32
	}{{request.DirectURL, "direct", 0}, {request.ProxyURL, "proxy", 64}} {
		result, err := inspectHTTP(ctx, request, probe.url, probe.role, probe.mark, nativeTUN)
		if err != nil {
			return report, fmt.Errorf("%s application probe: %w", probe.role, err)
		}
		report.HTTP = append(report.HTTP, result)
	}
	report.Passed = true
	return report, nil
}

func inspectHTTP(ctx context.Context, request Request, url, role string, mark uint32, nativeTUN *nativeTUNCheck) (httpCheck, error) {
	var check httpCheck
	dialer := net.Dialer{Resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, transport, _ string) (net.Conn, error) {
			var resolverDialer net.Dialer
			return resolverDialer.DialContext(ctx, transport, request.Resolver.String())
		},
	}}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	transport.Proxy = nil
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP1(true)
	transport.Protocols.SetHTTP2(true)
	transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", address)
	}
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var local, remote netip.AddrPort
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		local = info.Conn.LocalAddr().(*net.TCPAddr).AddrPort()
		remote = info.Conn.RemoteAddr().(*net.TCPAddr).AddrPort()
	}})
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return check, err
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		return check, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !remote.IsValid() {
		return check, fmt.Errorf("unexpected HTTP status %d or missing peer", response.StatusCode)
	}
	check = httpCheck{Domain: httpRequest.URL.Hostname(), Role: role, Status: response.StatusCode, Peer: remote.Addr().Unmap()}
	if role == "proxy" {
		body, err := io.ReadAll(io.LimitReader(response.Body, 128*1024))
		if err != nil {
			return check, err
		}
		exit := parseExit(string(body))
		if !slices.Contains(request.Exits, exit) {
			return check, fmt.Errorf("exit address %s is outside the expected list", exit)
		}
		check.Exit = exit
	}
	if nativeTUN != nil {
		err = nativeTUN.verify(&check, local, remote)
	} else if request.Marks {
		check.Marks, err = inspectMarks(local, remote, mark)
	}
	return check, err
}

var legacyExit = regexp.MustCompile(`\bIP:\s*([0-9.]+)`)

func parseExit(body string) netip.Addr {
	if address, err := netip.ParseAddr(strings.TrimSpace(body)); err == nil {
		return address.Unmap()
	}
	if match := legacyExit.FindStringSubmatch(body); match != nil {
		address, _ := netip.ParseAddr(match[1])
		return address
	}
	return netip.Addr{}
}

func inspectMarks(local, remote netip.AddrPort, expected uint32, filters ...string) ([]uint32, error) {
	args := []string{"-L", "-p", "tcp", "-s", local.Addr().Unmap().String(), "-d", remote.Addr().Unmap().String(),
		"--sport", strconv.Itoa(int(local.Port())), "--dport", strconv.Itoa(int(remote.Port()))}
	raw, err := system.Command("", "conntrack", append(args, filters...)...)
	if err != nil {
		return nil, err
	}
	var marks []uint32
	for field := range strings.FieldsSeq(string(raw)) {
		if value, ok := strings.CutPrefix(field, "mark="); ok {
			if mark, err := strconv.ParseUint(value, 10, 32); err == nil {
				marks = append(marks, uint32(mark))
			}
		}
	}
	if !slices.Contains(marks, expected) {
		return marks, fmt.Errorf("expected conntrack mark %d for the probed socket", expected)
	}
	return marks, nil
}
