package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterAllow(t *testing.T) {
	tests := []struct {
		name    string
		limit   int
		run     func(rl *rateLimiter, clock *time.Time) bool
		allowed bool
	}{
		{
			name:  "requests within limit pass",
			limit: 3,
			run: func(rl *rateLimiter, _ *time.Time) bool {
				rl.allow("a")
				rl.allow("a")
				return rl.allow("a")
			},
			allowed: true,
		},
		{
			name:  "request over limit is refused",
			limit: 3,
			run: func(rl *rateLimiter, _ *time.Time) bool {
				for i := 0; i < 3; i++ {
					rl.allow("a")
				}
				return rl.allow("a")
			},
			allowed: false,
		},
		{
			name:  "clients are limited independently",
			limit: 1,
			run: func(rl *rateLimiter, _ *time.Time) bool {
				rl.allow("a")
				return rl.allow("b")
			},
			allowed: true,
		},
		{
			name:  "window expiry resets the budget",
			limit: 1,
			run: func(rl *rateLimiter, clock *time.Time) bool {
				rl.allow("a")
				*clock = clock.Add(61 * time.Second)
				return rl.allow("a")
			},
			allowed: true,
		},
		{
			name:  "budget does not reset within the window",
			limit: 1,
			run: func(rl *rateLimiter, clock *time.Time) bool {
				rl.allow("a")
				*clock = clock.Add(59 * time.Second)
				return rl.allow("a")
			},
			allowed: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := time.Unix(1_700_000_000, 0)
			rl := newRateLimiter(tt.limit, time.Minute)
			rl.now = func() time.Time { return clock }
			if got := tt.run(rl, &clock); got != tt.allowed {
				t.Errorf("allow() = %v, want %v", got, tt.allowed)
			}
		})
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"direct connection", "203.0.113.7:51234", "", "203.0.113.7"},
		{"behind cloud run", "10.0.0.1:1234", "203.0.113.7", "203.0.113.7"},
		{
			// A client trying to rotate identities by spoofing entries:
			// only the last (infrastructure-appended) one counts.
			name:       "spoofed forwarded entries ignored",
			remoteAddr: "10.0.0.1:1234",
			xff:        "1.2.3.4, 5.6.7.8, 203.0.113.7",
			want:       "203.0.113.7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/inspect", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := clientIP(r); got != tt.want {
				t.Errorf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	rl := newRateLimiter(2, time.Minute)
	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	statuses := make([]int, 0, 3)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/inspect", nil)
		req.RemoteAddr = "203.0.113.7:1000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		statuses = append(statuses, rec.Code)
	}
	if want := fmt.Sprint([]int{200, 200, 429}); fmt.Sprint(statuses) != want {
		t.Errorf("statuses = %v, want %v", statuses, want)
	}
}
