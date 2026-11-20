package health

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestCheckRetainsAllFailedProbes(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	report, err := Check(ctx, Request{
		Resolver:  netip.MustParseAddrPort("127.0.0.1:53"),
		DirectURL: "https://192.0.2.1/", ProxyURL: "https://203.0.113.10/",
		Exits: []netip.Addr{netip.MustParseAddr("203.0.113.10")},
	})
	if err == nil || report.Passed || len(report.DNS) != 10 || len(report.HTTP) != 2 {
		t.Fatalf("incomplete failure report: %+v, %v", report, err)
	}
	for _, check := range report.DNS {
		if check.State != "failed" || check.Error == "" {
			t.Fatalf("invalid DNS failure: %+v", check)
		}
	}
	for _, check := range report.HTTP {
		if check.State != "failed" || check.Error == "" || check.Role == "" {
			t.Fatalf("invalid HTTPS failure: %+v", check)
		}
	}
}

func TestInspectHTTPNegotiatesTLS(t *testing.T) {
	exit := netip.MustParseAddr("203.0.113.10")
	for _, test := range []struct {
		protocol string
		http2    bool
	}{
		{"HTTP/1.1", false},
		{"HTTP/2.0", true},
	} {
		t.Run(test.protocol, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Proto != test.protocol {
					t.Errorf("negotiated %s, want %s", r.Proto, test.protocol)
				}
				_, _ = io.WriteString(w, exit.String())
			}))
			server.EnableHTTP2 = test.http2
			server.StartTLS()
			t.Cleanup(server.Close)

			// Trust the fixture certificate while exercising the real probe transport.
			original := http.DefaultTransport
			transport := original.(*http.Transport).Clone()
			transport.TLSClientConfig = &tls.Config{
				RootCAs: server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
			}
			http.DefaultTransport = transport
			t.Cleanup(func() { http.DefaultTransport = original })

			result, err := inspectHTTP(t.Context(), Request{Exits: []netip.Addr{exit}}, server.URL, "proxy", 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			if result.Exit != exit || result.Status != http.StatusOK {
				t.Fatalf("unexpected probe result: %+v", result)
			}
		})
	}
}
