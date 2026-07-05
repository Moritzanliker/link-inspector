package inspect

import (
	"context"
	stderrors "errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/eluv-io/errors-go"
)

const (
	// maxHops bounds the redirect chain (PLAN.md: max 10 hops).
	maxHops = 10
	// defaultHopTimeout bounds each individual request (PLAN.md: 5s per hop).
	defaultHopTimeout = 5 * time.Second
	// maxBodyDrain is the most we ever read (and discard) of a response
	// body; bodies are never buffered or returned.
	maxBodyDrain = 4 << 10

	userAgent = "link-inspector/1.0 (+https://github.com/moritzanliker/link-inspector)"
)

// Hop is one step in a redirect chain, in the shape the API returns.
type Hop struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	HTTPS  bool   `json:"https"`
}

// Follower follows redirect chains manually so that every hop is captured
// and validated by the SSRF guard before any connection is made.
type Follower struct {
	guard      *Guard
	client     *http.Client
	hopTimeout time.Duration
}

// NewFollower returns a Follower whose requests all go through g's guarded
// transport.
func NewFollower(g *Guard) *Follower {
	return &Follower{
		guard: g,
		client: &http.Client{
			Transport: g.Transport(),
			// Redirects are followed manually in Follow; the client must
			// never follow one on its own, because that would skip the
			// per-hop guard validation.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		hopTimeout: defaultHopTimeout,
	}
}

// Follow fetches rawURL and follows redirects up to maxHops, returning every
// hop. On error, the hops collected so far are returned alongside it, so
// callers can still show how far the chain got before it was stopped.
func (f *Follower) Follow(ctx context.Context, rawURL string) ([]Hop, error) {
	e := errors.Template("follow", errors.K.Invalid, "url", rawURL)
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, e(err, "reason", "invalid URL")
	}

	visited := make(map[string]bool, maxHops)
	var chain []Hop
	for len(chain) < maxHops {
		target := u.String()
		if visited[target] {
			return chain, e("reason", "redirect loop", "loop_url", target)
		}
		visited[target] = true

		if err := f.guard.Validate(ctx, u); err != nil {
			return chain, err
		}
		status, location, err := f.fetch(ctx, u)
		if err != nil {
			return chain, err
		}
		log.Debug("hop", "url", target, "status", status)
		chain = append(chain, Hop{URL: target, Status: status, HTTPS: u.Scheme == "https"})

		if !isRedirect(status) {
			return chain, nil
		}
		if location == "" {
			return chain, e("reason", "redirect without Location header", "status", status)
		}
		next, err := u.Parse(location)
		if err != nil {
			return chain, e(err, "reason", "invalid redirect location", "location", location)
		}
		u = next
	}
	return chain, e("reason", "too many redirects", "max_hops", maxHops)
}

// fetch performs a single request. HEAD is tried first so no body is
// transferred at all; servers that reject HEAD get a GET retry, whose body
// is drained up to maxBodyDrain and discarded.
func (f *Follower) fetch(ctx context.Context, u *url.URL) (status int, location string, err error) {
	status, location, err = f.do(ctx, http.MethodHead, u)
	if err == nil && (status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented) {
		return f.do(ctx, http.MethodGet, u)
	}
	return status, location, err
}

func (f *Follower) do(ctx context.Context, method string, u *url.URL) (int, string, error) {
	hctx, cancel := context.WithTimeout(ctx, f.hopTimeout)
	defer cancel()

	e := errors.Template("fetch", "url", u.String(), "method", method)
	req, err := http.NewRequestWithContext(hctx, method, u.String(), nil)
	if err != nil {
		return 0, "", e(errors.K.Invalid, err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := f.client.Do(req)
	if err != nil {
		switch {
		case IsBlocked(err):
			// Preserve the guard's rejection so it surfaces as a "blocked
			// internal address" finding rather than a generic fetch error.
			return 0, "", e(errors.K.Permission, err, "reason", "blocked internal address")
		case stderrors.Is(err, context.DeadlineExceeded):
			return 0, "", e(errors.K.Timeout, err, "reason", "host did not respond in time")
		default:
			return 0, "", e(errors.K.IO, err, "reason", "host unreachable")
		}
	}
	defer errors.Ignore(resp.Body.Close)
	// Drain a bounded amount so the connection shuts down cleanly; the body
	// itself is never used.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyDrain))
	return resp.StatusCode, resp.Header.Get("Location"), nil
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}
