# Link-Inspector — Project Plan

> Paste a URL, see where it *really* leads: full redirect chain, domain tricks,
> and a plain-language verdict. Defensive tool — it helps people avoid phishing links.

## Goals

- Small, polished, demoable in 30 seconds without login.
- Go backend + React/TypeScript frontend, single binary serving both, deployed on GCP Cloud Run.
- Honest heuristics with listed reasons — no fake "phishing scores".
- Security-conscious by design (SSRF is the core risk, see below).

## Non-goals (v1 — do NOT build these)

- No database, no user accounts, no history.
- No WHOIS/domain-age lookup, no screenshots, no VirusTotal/SafeBrowsing integration.
- No admin UI, no rate-limit dashboard (a simple in-memory rate limit is enough).

## Repository layout

```
.
├── cmd/linkcheck/main.go   // server entry: wiring + ListenAndServe
├── internal/server/        // HTTP handlers, rate limit, doc routes + tests
├── api/                    // openapi.yaml + vendored Scalar viewer (go:embed)
├── inspect/
│   ├── inspector.go        // orchestrates all checks, builds the response
│   ├── redirects.go        // manual redirect-chain follower
│   ├── ssrf.go             // hostname resolution + private-range guard
│   ├── homoglyph.go        // punycode & lookalike-character detection
│   ├── heuristics.go       // TLD, subdomain tricks, HTTPS, keyword checks
│   └── *_test.go           // table-driven tests per check file
├── web/                    // React + TypeScript (Vite)
├── CLAUDE.md
├── README.md
└── Dockerfile              // multi-stage: build web, build Go, minimal runtime image
```

(Layout updated after v1: server code moved from the repo root into
cmd/ + internal/server/ + api/ — agreed 2026-07-06.)

## API

### `POST /api/inspect`

Request:

```json
{ "url": "https://bit.ly/abc" }
```

Response:

```json
{
  "input_url": "https://bit.ly/abc",
  "final_url": "https://example-target.com/page",
  "redirect_chain": [
    { "url": "https://bit.ly/abc", "status": 301, "https": true },
    { "url": "https://example-target.com/page", "status": 200, "https": true }
  ],
  "findings": [
    { "severity": "warn", "code": "SHORTENER", "message": "Link uses a URL shortener (bit.ly)" }
  ],
  "verdict": "caution"
}
```

- `severity`: `"info" | "warn" | "danger"`
- `verdict`: `"ok" | "caution" | "suspicious"`
- Errors return a proper HTTP status + `{ "error": "..." }` with a human-readable message
  (invalid URL, unreachable host, timeout, blocked internal address).

## Checks (v1)

### 1. Redirect chain (redirects.go)
- Follow redirects MANUALLY (http.Client with CheckRedirect returning ErrUseLastResponse,
  or explicit loop). Capture every hop: URL, status code, https yes/no.
- Max 10 hops. Per-hop timeout 5s. Use HEAD first, fall back to GET if HEAD not allowed.
- Never read more than a few KB of any response body; discard bodies.
- Detect redirect loops.

### 2. SSRF guard (ssrf.go) — SECURITY-CRITICAL
- Before EVERY hop (including redirects!): resolve the hostname, check ALL resolved IPs.
- Block: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
  (incl. GCP metadata 169.254.169.254), 0.0.0.0/8, ::1, fc00::/7, fe80::/10,
  and any other net.IP.IsPrivate/IsLoopback/IsLinkLocal* ranges.
- Only allow schemes http and https. Block non-standard ports? No — allow, but add an
  `info` finding for unusual ports.
- Use a custom DialContext that re-validates the IP actually being dialed
  (protects against DNS rebinding between check and dial).
- A blocked request must produce a clear finding, not a crash.

### 3. Homoglyph / punycode (homoglyph.go)
- Flag `xn--` (punycode) domains; decode and show the Unicode form.
- Flag mixed-script hostnames (e.g. Cyrillic chars inside otherwise-Latin domain).
- Flag classic lookalike patterns in the registered domain: capital I vs l, 0 vs o, rn vs m.

### 4. Heuristics (heuristics.go)
- HTTP-only (no TLS) anywhere in the chain → warn.
- Known shortener domains (bit.ly, tinyurl.com, t.co, goo.gl, is.gd, cutt.ly, rb.gy, …) → warn.
- Deceptive subdomain: well-known brand name or a "registrable-looking" domain appearing
  as a subdomain of a different registered domain (paypal.com.evil.xyz) → danger.
  Use the public-suffix list (golang.org/x/net/publicsuffix) to find the registrable domain.
- Brand keywords (paypal, apple, google, microsoft, post, ubs, swisscom, …) in subdomain
  of an unrelated domain → warn.
- Suspicious TLDs (zip, mov, tk, top, gq, ml, cf, …) → warn.
- `@` in URL (userinfo trick) → danger. Raw-IP URL → warn. Subdomain depth > 3 → info.

### 5. Verdict (inspector.go)
- any danger → "suspicious"; else any warn → "caution"; else "ok".
- Findings are always returned so the user sees WHY.

## Frontend (web/)

Single page, React + TypeScript + Vite:
- URL input + "Inspect" button (Enter submits). Loading state while inspecting.
- Result card: verdict banner (green/yellow/red), redirect chain as a vertical step list
  (each hop: status badge, https padlock or warning, URL), findings grouped by severity.
- Friendly error states. No router, no state library — useState is enough.
- Clean, fast, readable. Simple CSS (or plain CSS modules). No heavy UI framework.

## Testing

- Table-driven Go tests for: ssrf (blocked ranges incl. metadata IP, allowed public IPs),
  homoglyph (punycode, mixed script, lookalikes), heuristics (deceptive subdomain,
  shorteners, @-trick, raw IP), verdict aggregation.
- Redirect follower tested against httptest.Server with scripted redirect chains,
  incl. a redirect INTO a private address (must be blocked mid-chain).
- `go test ./...` must pass; treat failing tests as blockers.

## Deployment

- Multi-stage Dockerfile: node stage builds web/dist, go stage builds static binary,
  final stage FROM gcr.io/distroless/static or alpine. Binary serves web/dist.
- Target: GCP Cloud Run. PORT from env. README documents the deploy commands.

## Milestones (work in this order, one commit theme at a time)

1. **M1**: redirect follower + SSRF guard + their tests. Core of the project.
2. **M2**: homoglyph + heuristics + verdict, `/api/inspect` wired, curl-testable.
3. **M3**: React frontend against the real API.
4. **M4**: Dockerfile + Cloud Run deployment.
5. **M5**: README polish (story, security considerations, AI-workflow section).

## Definition of done

- Live URL: pasting a bit.ly link shows the full chain in < 3s.
- Pasting http://169.254.169.254/ is cleanly refused with a "blocked internal address" finding.
- `go test ./...` green. README tells the story.
