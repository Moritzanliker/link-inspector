package inspect

import (
	"net/url"
	"testing"
)

func TestCheckURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantCodes []string
	}{
		{
			name:      "clean https URL",
			url:       "https://example.com/page",
			wantCodes: nil,
		},
		{
			name:      "userinfo trick",
			url:       "https://www.paypal.com@evil.example/login",
			wantCodes: []string{"USERINFO"},
		},
		{
			name:      "raw IP over http",
			url:       "http://93.184.216.34/download",
			wantCodes: []string{"RAW_IP", "INSECURE_HTTP"},
		},
		{
			name:      "plain http",
			url:       "http://example.com/",
			wantCodes: []string{"INSECURE_HTTP"},
		},
		{
			name:      "unusual port",
			url:       "https://example.com:8443/",
			wantCodes: []string{"UNUSUAL_PORT"},
		},
		{
			name:      "standard port is not flagged",
			url:       "https://example.com:443/",
			wantCodes: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("test bug: %q does not parse: %v", tt.url, err)
			}
			assertCodes(t, CheckURL(u), tt.wantCodes)
		})
	}
}

func TestCheckHost(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		wantCodes []string
	}{
		{
			name:      "plain domain",
			host:      "example.com",
			wantCodes: nil,
		},
		{
			name:      "ordinary www subdomain",
			host:      "www.example.com",
			wantCodes: nil,
		},
		{
			name:      "shortener",
			host:      "bit.ly",
			wantCodes: []string{"SHORTENER"},
		},
		{
			name:      "shortener with subdomain",
			host:      "www.tinyurl.com",
			wantCodes: []string{"SHORTENER"},
		},
		{
			name:      "deceptive registrable domain in subdomain",
			host:      "paypal.com.evil.example",
			wantCodes: []string{"DECEPTIVE_SUBDOMAIN", "BRAND_IN_SUBDOMAIN"},
		},
		{
			name:      "deceptive subdomain with www prefix",
			host:      "www.ubs.com.evil.example",
			wantCodes: []string{"DECEPTIVE_SUBDOMAIN", "BRAND_IN_SUBDOMAIN"},
		},
		{
			name:      "brand keyword in subdomain",
			host:      "paypal.evil.example",
			wantCodes: []string{"BRAND_IN_SUBDOMAIN"},
		},
		{
			name:      "brand keyword as token in subdomain label",
			host:      "paypal-login.evil.example",
			wantCodes: []string{"BRAND_IN_SUBDOMAIN"},
		},
		{
			name:      "brand as substring of label is not flagged",
			host:      "paypalooza.evil.example",
			wantCodes: nil,
		},
		{
			name:      "brand inside its own domain",
			host:      "paypal.paypal.com",
			wantCodes: nil,
		},
		{
			name:      "suspicious TLD",
			host:      "attachment.zip",
			wantCodes: []string{"SUSPICIOUS_TLD"},
		},
		{
			name:      "suspicious TLD with brand subdomain",
			host:      "microsoft.login.example.top",
			wantCodes: []string{"SUSPICIOUS_TLD", "BRAND_IN_SUBDOMAIN"},
		},
		{
			name:      "deep subdomain nesting",
			host:      "a.b.c.d.example.com",
			wantCodes: []string{"SUBDOMAIN_DEPTH"},
		},
		{
			name:      "three subdomain levels are fine",
			host:      "a.b.c.example.com",
			wantCodes: nil,
		},
		{
			name:      "unregistrable host is skipped",
			host:      "localhost",
			wantCodes: nil,
		},
		{
			name:      "raw IP is skipped",
			host:      "10.0.0.1",
			wantCodes: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertCodes(t, CheckHost(tt.host), tt.wantCodes)
		})
	}
}
