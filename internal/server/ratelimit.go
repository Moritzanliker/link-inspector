package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// rateLimiter is the simple in-memory per-IP limiter PLAN.md asks for: a
// fixed window per client, no persistence, suitable for a single Cloud Run
// instance. It exists to keep one client from turning the inspector into
// their bulk URL scanner, not to survive distributed abuse.
type rateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	clients map[string]*windowCount
	now     func() time.Time // injectable for tests
}

type windowCount struct {
	start time.Time
	count int
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		limit:   limit,
		window:  window,
		clients: make(map[string]*windowCount),
		now:     time.Now,
	}
}

// allow reports whether the client may make another request now.
func (rl *rateLimiter) allow(client string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()

	// Opportunistic cleanup keeps the map from growing unboundedly without
	// needing a background goroutine.
	if len(rl.clients) > 10_000 {
		for k, w := range rl.clients {
			if now.Sub(w.start) >= rl.window {
				delete(rl.clients, k)
			}
		}
	}

	w := rl.clients[client]
	if w == nil || now.Sub(w.start) >= rl.window {
		rl.clients[client] = &windowCount{start: now, count: 1}
		return true
	}
	w.count++
	return w.count <= rl.limit
}

// middleware wraps h with the limiter, answering 429 when a client is over
// its budget.
func (rl *rateLimiter) middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(clientIP(r)) {
			writeJSON(w, http.StatusTooManyRequests, errorResponse{"too many requests — please slow down"})
			return
		}
		h.ServeHTTP(w, r)
	})
}

// clientIP identifies the caller. Cloud Run terminates TLS in front of us
// and appends the real client to X-Forwarded-For; the last entry is the one
// added by Google's infrastructure and therefore trustworthy. Locally the
// header is absent and RemoteAddr is the socket peer.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
