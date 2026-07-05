package inspect

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eluv-io/errors-go"
)

// testFollower returns a Follower whose guard whitelists loopback so it can
// reach httptest servers on 127.0.0.1. Everything else — including the
// private and metadata ranges the tests redirect into — stays blocked.
func testFollower() *Follower {
	g := NewGuard()
	g.allow = func(ip net.IP) bool { return ip.IsLoopback() }
	return NewFollower(g)
}

// newChainServer serves all redirect scenarios used by the table test below.
func newChainServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/chain/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/chain/b", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/chain/b", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ok", http.StatusFound)
	})
	mux.HandleFunc("/loop/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop/b", http.StatusFound)
	})
	mux.HandleFunc("/loop/b", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop/a", http.StatusFound)
	})
	mux.HandleFunc("/deep/", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/deep/"))
		http.Redirect(w, r, fmt.Sprintf("/deep/%d", n+1), http.StatusFound)
	})
	mux.HandleFunc("/private", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	})
	mux.HandleFunc("/badscheme", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "ftp://example.com/file", http.StatusFound)
	})
	mux.HandleFunc("/nolocation", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/head405", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write([]byte("hello"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestFollow(t *testing.T) {
	srv := newChainServer(t)

	repeat := func(status, n int) []int {
		s := make([]int, n)
		for i := range s {
			s[i] = status
		}
		return s
	}

	tests := []struct {
		name         string
		path         string
		wantStatuses []int
		wantReason   string // value of the error's "reason" field, "" = no error
		wantBlocked  bool
	}{
		{
			name:         "no redirect",
			path:         "/ok",
			wantStatuses: []int{200},
		},
		{
			name:         "three hop chain",
			path:         "/chain/a",
			wantStatuses: []int{301, 302, 200},
		},
		{
			name:         "redirect into private address blocked mid-chain",
			path:         "/private",
			wantStatuses: []int{302},
			wantReason:   "blocked internal address",
			wantBlocked:  true,
		},
		{
			name:         "redirect to disallowed scheme",
			path:         "/badscheme",
			wantStatuses: []int{302},
			wantReason:   "unsupported scheme, only http and https are allowed",
		},
		{
			name:         "too many redirects",
			path:         "/deep/0",
			wantStatuses: repeat(302, maxHops),
			wantReason:   "too many redirects",
		},
		{
			name:         "redirect loop",
			path:         "/loop/a",
			wantStatuses: []int{302, 302},
			wantReason:   "redirect loop",
		},
		{
			name:         "redirect without location",
			path:         "/nolocation",
			wantStatuses: []int{302},
			wantReason:   "redirect without Location header",
		},
		{
			name:         "HEAD rejected falls back to GET",
			path:         "/head405",
			wantStatuses: []int{200},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := testFollower()
			chain, err := f.Follow(context.Background(), srv.URL+tt.path)

			if tt.wantReason == "" {
				if err != nil {
					t.Fatalf("Follow() error = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Follow() error = nil, want reason %q", tt.wantReason)
				}
				if reason, _ := errors.GetField(err, "reason"); reason != tt.wantReason {
					t.Errorf("error reason = %q, want %q (err: %v)", reason, tt.wantReason, err)
				}
				if IsBlocked(err) != tt.wantBlocked {
					t.Errorf("IsBlocked() = %v, want %v (err: %v)", !tt.wantBlocked, tt.wantBlocked, err)
				}
			}

			var statuses []int
			for _, h := range chain {
				statuses = append(statuses, h.Status)
				if h.HTTPS {
					t.Errorf("hop %s reported HTTPS for an http:// server", h.URL)
				}
			}
			if fmt.Sprint(statuses) != fmt.Sprint(tt.wantStatuses) {
				t.Errorf("chain statuses = %v, want %v", statuses, tt.wantStatuses)
			}
			if len(tt.wantStatuses) > 0 && len(chain) > 0 && chain[0].URL != srv.URL+tt.path {
				t.Errorf("first hop URL = %q, want %q", chain[0].URL, srv.URL+tt.path)
			}
		})
	}
}

func TestFollowInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"unparsable URL", "http://[::1"},
		{"no scheme", "example.com/page"},
		{"file scheme", "file:///etc/passwd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := testFollower()
			chain, err := f.Follow(context.Background(), tt.url)
			if err == nil {
				t.Fatalf("Follow(%q) error = nil, want invalid-input error", tt.url)
			}
			if !errors.IsKind(errors.K.Invalid, err) {
				t.Errorf("Follow(%q) error = %v, want kind %q", tt.url, err, errors.K.Invalid)
			}
			if len(chain) != 0 {
				t.Errorf("Follow(%q) chain = %v, want empty", tt.url, chain)
			}
		})
	}
}

func TestFollowHopTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	t.Cleanup(srv.Close)

	f := testFollower()
	f.hopTimeout = 50 * time.Millisecond
	_, err := f.Follow(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("Follow() error = nil, want timeout")
	}
	if !errors.IsKind(errors.K.Timeout, err) {
		t.Errorf("Follow() error = %v, want kind %q", err, errors.K.Timeout)
	}
}

// TestFollowLargeBodyNotBuffered forces the GET fallback against a handler
// that streams far more than maxBodyDrain. The follower must return the hop
// promptly instead of consuming the whole body.
func TestFollowLargeBodyNotBuffered(t *testing.T) {
	const chunk = 64 << 10
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		buf := make([]byte, chunk)
		for i := 0; i < 1024; i++ { // up to 64 MiB unless the client hangs up
			if _, err := w.Write(buf); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	t.Cleanup(srv.Close)

	f := testFollower()
	done := make(chan struct{})
	var chain []Hop
	var err error
	go func() {
		chain, err = f.Follow(context.Background(), srv.URL)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Follow() still running after 3s — response body is being consumed")
	}
	if err != nil {
		t.Fatalf("Follow() error = %v, want nil", err)
	}
	if len(chain) != 1 || chain[0].Status != 200 {
		t.Errorf("chain = %v, want single 200 hop", chain)
	}
}
