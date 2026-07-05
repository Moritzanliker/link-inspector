package inspect

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/eluv-io/errors-go"
)

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		ip      string
		blocked bool
	}{
		// loopback
		{"127.0.0.1", true},
		{"127.255.255.254", true},
		{"::1", true},
		// RFC 1918 private
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		// link-local, incl. the GCP metadata IP
		{"169.254.169.254", true},
		{"169.254.0.1", true},
		{"fe80::1", true},
		// IPv6 unique local
		{"fc00::1", true},
		{"fd12:3456:789a::1", true},
		// unspecified / "this network" / broadcast / multicast
		{"0.0.0.0", true},
		{"0.1.2.3", true},
		{"::", true},
		{"255.255.255.255", true},
		{"224.0.0.1", true},
		{"ff02::1", true},
		// IPv4-mapped IPv6 must not bypass the IPv4 checks
		{"::ffff:127.0.0.1", true},
		{"::ffff:10.0.0.1", true},
		{"::ffff:169.254.169.254", true},
		// public addresses stay reachable
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},
		{"172.32.0.1", false}, // just outside 172.16.0.0/12
		{"9.255.255.255", false},
		{"2606:4700:4700::1111", false},
		{"2001:4860:4860::8888", false},
		{"::ffff:8.8.8.8", false},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("test bug: %q does not parse as an IP", tt.ip)
			}
			if got := isBlockedIP(ip); got != tt.blocked {
				t.Errorf("isBlockedIP(%s) = %v, want %v", tt.ip, got, tt.blocked)
			}
		})
	}
}

func TestGuardValidate(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		ips      []net.IP // stubbed DNS answer for hostname URLs
		wantKind errors.Kind
	}{
		{
			name: "public hostname",
			url:  "https://example.com/",
			ips:  []net.IP{net.ParseIP("93.184.216.34")},
		},
		{
			name:     "hostname resolving to loopback",
			url:      "https://internal.example.com/",
			ips:      []net.IP{net.ParseIP("127.0.0.1")},
			wantKind: errors.K.Permission,
		},
		{
			name:     "hostname resolving to metadata IP",
			url:      "http://metadata.example.com/",
			ips:      []net.IP{net.ParseIP("169.254.169.254")},
			wantKind: errors.K.Permission,
		},
		{
			// one private IP in a mixed answer blocks the whole host: DNS
			// is attacker-controlled, the mix could steer the connection.
			name:     "one private IP among public ones",
			url:      "https://mixed.example.com/",
			ips:      []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("10.0.0.1")},
			wantKind: errors.K.Permission,
		},
		{
			name:     "literal loopback IP",
			url:      "http://127.0.0.1/admin",
			wantKind: errors.K.Permission,
		},
		{
			name:     "literal metadata IP",
			url:      "http://169.254.169.254/latest/meta-data/",
			wantKind: errors.K.Permission,
		},
		{
			name:     "literal IPv6 loopback",
			url:      "http://[::1]:8080/",
			wantKind: errors.K.Permission,
		},
		{
			name:     "ftp scheme",
			url:      "ftp://example.com/file",
			wantKind: errors.K.Invalid,
		},
		{
			name:     "file scheme",
			url:      "file:///etc/passwd",
			wantKind: errors.K.Invalid,
		},
		{
			name:     "javascript scheme",
			url:      "javascript:alert(1)",
			wantKind: errors.K.Invalid,
		},
		{
			name:     "missing host",
			url:      "http:///path-only",
			wantKind: errors.K.Invalid,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGuard()
			g.lookup = func(context.Context, string) ([]net.IP, error) {
				return tt.ips, nil
			}
			u, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("test bug: %q does not parse: %v", tt.url, err)
			}
			err = g.Validate(context.Background(), u)
			if tt.wantKind == "" {
				if err != nil {
					t.Fatalf("Validate(%s) = %v, want nil", tt.url, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate(%s) = nil, want kind %q", tt.url, tt.wantKind)
			}
			if !errors.IsKind(tt.wantKind, err) {
				t.Errorf("Validate(%s) = %v, want kind %q", tt.url, err, tt.wantKind)
			}
		})
	}
}

// TestDialTimeRevalidation simulates DNS rebinding: the resolver answers
// with a public IP while the URL is validated, and with 127.0.0.1 once the
// connection is dialed. The dial-time re-resolution in the guarded transport
// must catch this even though Validate passed.
func TestDialTimeRevalidation(t *testing.T) {
	g := NewGuard()
	calls := 0
	g.lookup = func(context.Context, string) ([]net.IP, error) {
		calls++
		if calls == 1 {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}

	u, _ := url.Parse("http://rebind.test/")
	if err := g.Validate(context.Background(), u); err != nil {
		t.Fatalf("Validate should pass on the public DNS answer, got %v", err)
	}

	client := &http.Client{Transport: g.Transport()}
	resp, err := client.Get("http://rebind.test/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("request succeeded, want dial-time block of rebound address")
	}
	if !IsBlocked(err) {
		t.Errorf("IsBlocked(%v) = false, want guard rejection in the error chain", err)
	}
	if calls < 2 {
		t.Errorf("lookup called %d time(s), want a second dial-time resolution", calls)
	}
}
