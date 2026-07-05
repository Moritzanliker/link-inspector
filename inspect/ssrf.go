// Package inspect implements the URL inspection checks: SSRF-guarded
// redirect following and, in later milestones, homoglyph and heuristic
// analysis.
package inspect

import (
	"context"
	stderrors "errors"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"github.com/eluv-io/errors-go"
	elog "github.com/eluv-io/log-go"
)

var log = elog.Get("/link-inspector/inspect")

// Guard is the SSRF protection for the whole service. Nothing may be fetched
// unless it passed Validate, and the transport returned by Transport
// re-resolves and re-validates the address actually being dialed, so a DNS
// answer that changes between check and dial (DNS rebinding) cannot smuggle
// a request to an internal address.
type Guard struct {
	// lookup resolves a hostname to its IPs. A field (not a direct call to
	// the resolver) so tests can stub DNS answers.
	lookup func(ctx context.Context, host string) ([]net.IP, error)
	// allow, when non-nil, may whitelist an otherwise-blocked IP. It exists
	// only so tests can reach httptest servers on 127.0.0.1; it is
	// unexported and never set in production code, and it can only ever
	// loosen a single IP decision, not disable scheme or resolution checks.
	allow func(ip net.IP) bool
	// dialTimeout bounds connection establishment (the per-request timeout
	// lives in the redirect follower).
	dialTimeout time.Duration
}

// NewGuard returns a Guard using the default system resolver.
func NewGuard() *Guard {
	return &Guard{
		lookup: func(ctx context.Context, host string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			ips := make([]net.IP, len(addrs))
			for i, a := range addrs {
				ips[i] = a.IP
			}
			return ips, nil
		},
		dialTimeout: 5 * time.Second,
	}
}

// Validate checks a URL before a request is made to it: only http/https
// schemes are accepted, and the host must not resolve to any blocked
// (private, loopback, link-local, unspecified, multicast) address. It must
// be called for every hop of a redirect chain, not just the first URL.
func (g *Guard) Validate(ctx context.Context, u *url.URL) error {
	e := errors.Template("ssrf.validate", "url", u.String())
	switch u.Scheme {
	case "http", "https":
	default:
		return e(errors.K.Invalid, "reason", "unsupported scheme, only http and https are allowed", "scheme", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return e(errors.K.Invalid, "reason", "URL has no host")
	}
	ips, err := g.resolve(ctx, host)
	if err != nil {
		return e(errors.K.NotExist, err, "reason", "host cannot be resolved", "host", host)
	}
	// One blocked address blocks the whole host: an attacker controlling
	// DNS could otherwise mix a public IP into the answer to pass this
	// check and steer the connection to the private one.
	for _, ip := range ips {
		if g.blocked(ip) {
			log.Warn("blocked internal address", "host", host, "ip", ip.String())
			return e(errors.K.Permission, "reason", "blocked internal address", "host", host, "ip", ip.String())
		}
	}
	return nil
}

// Transport returns an http.Transport that funnels every connection through
// the guard's dialContext. Keep-alives are disabled so each request dials —
// and therefore re-validates — fresh, instead of reusing a connection that
// was validated for an earlier hop.
func (g *Guard) Transport() *http.Transport {
	return &http.Transport{
		// No Proxy: a proxy would make the outbound connection on our
		// behalf and bypass the IP validation in dialContext.
		DialContext:         g.dialContext,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: g.dialTimeout,
	}
}

// dialContext resolves addr itself, validates all resolved IPs, and then
// dials one validated IP literally. Resolving here — at dial time — instead
// of trusting the earlier Validate call closes the DNS-rebinding window: the
// address we actually connect to is exactly the one that was checked.
func (g *Guard) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	e := errors.Template("ssrf.dial", "address", addr)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, e(errors.K.Invalid, err)
	}
	ips, err := g.resolve(ctx, host)
	if err != nil {
		return nil, e(errors.K.NotExist, err, "reason", "host cannot be resolved", "host", host)
	}
	if len(ips) == 0 {
		return nil, e(errors.K.NotExist, "reason", "host resolved to no addresses", "host", host)
	}
	for _, ip := range ips {
		if g.blocked(ip) {
			log.Warn("blocked internal address at dial time", "host", host, "ip", ip.String())
			return nil, e(errors.K.Permission, "reason", "blocked internal address", "host", host, "ip", ip.String())
		}
	}
	dialer := &net.Dialer{
		Timeout: g.dialTimeout,
		// Control sees the literal socket address and re-checks it — a
		// last line of defense in case a future refactoring ever routes a
		// dial past the validation above.
		Control: func(_, address string, _ syscall.RawConn) error {
			h, _, err := net.SplitHostPort(address)
			if err != nil {
				return errors.E("ssrf.dial.control", errors.K.Invalid, err, "address", address)
			}
			ip := net.ParseIP(h)
			if ip == nil || g.blocked(ip) {
				return errors.E("ssrf.dial.control", errors.K.Permission, "reason", "blocked internal address", "ip", h)
			}
			return nil
		},
	}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

// resolve returns the IPs for host, skipping DNS for literal IP addresses.
func (g *Guard) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	return g.lookup(ctx, host)
}

func (g *Guard) blocked(ip net.IP) bool {
	if g.allow != nil && g.allow(ip) {
		return false
	}
	return isBlockedIP(ip)
}

// isBlockedIP reports whether ip must never be contacted. To4 normalizes
// IPv4-mapped IPv6 addresses (::ffff:127.0.0.1) first, so they cannot bypass
// the IPv4 classification. The stdlib methods cover loopback (127/8, ::1),
// private (RFC 1918, fc00::/7), link-local (169.254/16 incl. the GCP
// metadata IP, fe80::/10), unspecified and multicast ranges; 0/8 and the
// IPv4 broadcast address are checked explicitly because no stdlib method
// classifies them.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 0 || ip4.Equal(net.IPv4bcast) {
			return true
		}
	}
	return false
}

// IsBlocked reports whether err is, or was caused by, a guard rejection.
// The http client wraps dial errors in *url.Error and *net.OpError, so the
// whole unwrap chain is searched, not just the top error.
func IsBlocked(err error) bool {
	for cur := err; cur != nil; cur = stderrors.Unwrap(cur) {
		if e, ok := cur.(*errors.Error); ok && e.Kind() == errors.K.Permission {
			return true
		}
	}
	return false
}
