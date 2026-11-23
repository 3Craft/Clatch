//go:build linux

package health

import (
	"context"
	"errors"
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
	"sync"
	"time"

	"clatch-gateway/internal/system"

	"golang.org/x/net/dns/dnsmessage"
)

type Request struct {
	ConfigPath string
	Resolver   netip.AddrPort
	DirectURL  string
	ProxyURL   string
	Exits      []netip.Addr
	EmptyAAAA  bool
	Marks      bool
	DNSProbes  []DNSProbe
}

type dnsCheck struct {
	Domain        string `json:"domain"`
	Kind          uint16 `json:"type"`
	TypeName      string `json:"type_name"`
	Transport     string `json:"transport"`
	Answers       int    `json:"answers"`
	ExpectedEmpty bool   `json:"expected_empty"`
	State         string `json:"state"`
	Error         string `json:"error,omitempty"`
}

type httpCheck struct {
	Domain           string     `json:"domain"`
	Role             string     `json:"role"`
	Status           int        `json:"status"`
	Peer             netip.Addr `json:"peer"`
	Exit             netip.Addr `json:"exit_ip,omitzero"`
	Marks            []uint32   `json:"conntrack_marks,omitempty"`
	ReplyDestination netip.Addr `json:"conntrack_reply_dst,omitzero"`
	State            string     `json:"state"`
	Error            string     `json:"error,omitempty"`
}

type Report struct {
	Time           time.Time      `json:"time"`
	ConfigPath     string         `json:"config,omitempty"`
	Resolver       netip.AddrPort `json:"resolver,omitzero"`
	ExpectedExits  []netip.Addr   `json:"expected_exits,omitempty"`
	DNS            []dnsCheck     `json:"dns"`
	HTTP           []httpCheck    `json:"http"`
	ConntrackError string         `json:"conntrack_error,omitempty"`
	Error          string         `json:"error,omitempty"`
	Passed         bool           `json:"passed"`
}

func Check(ctx context.Context, request Request) (Report, error) {
	report := Report{Time: time.Now().UTC(), ConfigPath: request.ConfigPath,
		Resolver: request.Resolver, ExpectedExits: request.Exits}
	var firstError string
	var nativeTUN *nativeTUNCheck
	if request.Marks {
		var err error
		nativeTUN, err = prepareNativeTUNCheck(request.ConfigPath)
		if err != nil {
			report.ConntrackError = err.Error()
			firstError = "prepare conntrack check: " + report.ConntrackError
			request.Marks = false
		}
	}
	dnsTargets := request.DNSProbes
	if len(dnsTargets) == 0 {
		dnsTargets = []DNSProbe{
			{Domain: "www.baidu.com", Type: "A"},
			{Domain: "www.qq.com", Type: "A"},
			{Domain: "ip.fm", Type: "A"},
			{Domain: "www.google.com", Type: "A"},
			{Domain: "www.google.com", Type: "AAAA"},
		}
	}
	for _, probe := range dnsTargets {
		kind := dnsmessage.TypeA
		typeName := "A"
		if strings.EqualFold(probe.Type, "AAAA") {
			kind = dnsmessage.TypeAAAA
			typeName = "AAAA"
		}
		for _, transport := range []string{"udp", "tcp"} {
			empty := request.EmptyAAAA && kind == dnsmessage.TypeAAAA
			report.DNS = append(report.DNS, dnsCheck{
				Domain: probe.Domain, Kind: uint16(kind), TypeName: typeName, Transport: transport, ExpectedEmpty: empty,
			})
		}
	}
	probes := []struct {
		url  string
		role string
		mark uint32
	}{{request.DirectURL, "direct", 0}, {request.ProxyURL, "proxy", 64}}
	report.HTTP = make([]httpCheck, len(probes))
	const missingDNS = "no DNS endpoint configured; set dns in health.json or pass --dns"
	var group sync.WaitGroup
	for i := range report.DNS {
		check := &report.DNS[i]
		if !request.Resolver.IsValid() {
			check.State, check.Error = "skipped", missingDNS
			continue
		}
		group.Go(func() {
			answers, err := DNS(ctx, request.Resolver, check.Transport+"4", check.Domain, dnsmessage.Type(check.Kind), check.ExpectedEmpty)
			check.Answers = answers
			check.State, check.Error = checkResult(err)
		})
	}
	for i, probe := range probes {
		switch {
		case !request.Resolver.IsValid():
			report.HTTP[i] = httpCheck{Role: probe.role, State: "skipped", Error: missingDNS}
		case probe.role == "proxy" && len(request.Exits) == 0:
			report.HTTP[i] = httpCheck{Role: probe.role, State: "skipped",
				Error: "no expected proxy exit configured; set expected_exits in health.json or pass --expected-exit"}
		default:
			group.Go(func() {
				result, err := inspectHTTP(ctx, request, probe.url, probe.role, probe.mark, nativeTUN)
				result.State, result.Error = checkResult(err)
				report.HTTP[i] = result
			})
		}
	}
	group.Wait()
	for _, check := range report.DNS {
		if firstError == "" && check.Error != "" {
			firstError = fmt.Sprintf("DNS %s %s over %s: %s", check.Domain, dnsmessage.Type(check.Kind), check.Transport, check.Error)
		}
	}
	for _, check := range report.HTTP {
		if firstError == "" && check.Error != "" {
			firstError = fmt.Sprintf("%s application probe: %s", check.Role, check.Error)
		}
	}
	report.Error, report.Passed = firstError, firstError == ""
	if !report.Passed {
		return report, errors.New(firstError)
	}
	return report, nil
}

func checkResult(err error) (string, string) {
	if err != nil {
		return "failed", err.Error()
	}
	return "passed", ""
}

func inspectHTTP(ctx context.Context, request Request, url, role string, mark uint32, nativeTUN *nativeTUNCheck) (httpCheck, error) {
	check := httpCheck{Role: role}
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
	check.Domain = httpRequest.URL.Hostname()
	response, err := client.Do(httpRequest)
	if err != nil {
		return check, err
	}
	defer response.Body.Close()
	check.Status, check.Peer = response.StatusCode, remote.Addr().Unmap()
	if response.StatusCode != http.StatusOK || !remote.IsValid() {
		return check, fmt.Errorf("unexpected HTTP status %d or missing peer", response.StatusCode)
	}
	var exitErr error
	if role == "proxy" {
		body, err := io.ReadAll(io.LimitReader(response.Body, 128*1024))
		if err != nil {
			return check, err
		}
		check.Exit = parseExit(string(body))
		if !slices.Contains(request.Exits, check.Exit) {
			exitErr = fmt.Errorf("exit address %s is outside the expected list", check.Exit)
		}
	}
	if nativeTUN != nil {
		err = nativeTUN.verify(&check, local, remote)
	} else if request.Marks {
		check.Marks, err = inspectMarks(local, remote, mark)
	}
	return check, errors.Join(exitErr, err)
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
