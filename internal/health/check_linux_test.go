package health

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

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
