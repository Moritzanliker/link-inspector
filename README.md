# LinkCheck

**See where a link really leads before you click it.**

Paste a URL and LinkCheck follows every redirect server-side, shows the full
trail, flags the classic deception tricks, and gives a plain-language verdict
— `ok`, `caution`, or `suspicious`.

**Live:** https://linkcheck-259669005968.europe-west6.run.app

## Why

Most phishing succeeds through the link itself: a shortener that hides the
destination, `paypal.com.account-check.xyz` reading like PayPal, a Cyrillic
`а` inside `аpple.com`, or `https://paypal.com@evil.example` where everything
before the `@` is a decoy. None of this is visible at a glance — but all of
it is mechanically detectable. LinkCheck makes it visible *before* the click.

## What it checks

Every hop of the redirect chain runs through the same battery:

| Trick | Example | Verdict impact |
|---|---|---|
| Userinfo decoy | `https://paypal.com@evil.example` | danger |
| Deceptive subdomain | `paypal.com.evil.xyz` | danger |
| Mixed alphabets | `аpple.com` (Cyrillic а) | danger |
| Redirect loop / >10 hops | — | danger |
| Internal address | `http://169.254.169.254/` | danger (blocked, never contacted) |
| URL shortener | `bit.ly`, `tinyurl.com`, … | warn |
| Lookalike characters | `g00gle.com`, `paypa1.com` | warn |
| Punycode domain | `xn--pple-43d.com` → decoded | warn |
| Unencrypted http, raw IP, abusive TLD, brand in subdomain | — | warn |
| Unusual port, deep subdomain nesting | — | info |

The verdict is simply the highest finding severity. There is no "phishing
score" — the findings themselves are the explanation, and every one is
worded for non-technical readers.

**Honest limitation:** LinkCheck detects tricks *in the link*. A phishing
page on a clean, freshly registered domain with no URL games will come back
`ok` — which is why the ok-verdict copy still says "only continue if you
expected this link."

## API

The interactive API reference (OpenAPI 3.0, rendered with
[Scalar](https://github.com/scalar/scalar)) is served by the app itself at
[`/doc`](https://linkcheck-259669005968.europe-west6.run.app/doc); the raw
spec lives in [`api/openapi.yaml`](api/openapi.yaml) and at `/openapi.yaml`.
The viewer is vendored (`api/`), so docs work without internet access.

```sh
curl -s -X POST https://linkcheck-259669005968.europe-west6.run.app/api/inspect \
  -d '{"url":"https://tinyurl.com/2fcpre6"}'
```

Rate limit: 20 requests/min per client IP.

## Security considerations

A URL inspector is, by definition, a server that fetches attacker-chosen
URLs — SSRF is the core risk, and the guard in
[`inspect/ssrf.go`](inspect/ssrf.go) is the most important code in this
repo. Three layers, applied to **every hop**, not just the first URL:

1. **Pre-flight validation** — only http/https; the hostname is resolved
   and the request refused if *any* answer is a private, loopback,
   link-local, metadata, unspecified, or multicast address (one bad IP in a
   mixed DNS answer blocks the whole host).
2. **Dial-time re-resolution** — the HTTP transport resolves again at
   connect time, validates again, and dials the literal validated IP. A DNS
   answer that changes between check and connect (DNS rebinding) is caught.
   Keep-alives are off so every request re-validates; there is deliberately
   no proxy support, which would bypass the check.
3. **Socket-level control hook** — the dialer's `Control` callback re-checks
   the final socket address as a last line of defense.

Further hardening: redirects are followed manually (max 10 hops, 5 s per
hop), response bodies are drained at most 4 KB and never buffered, request
bodies are capped at 4 KB, a whole inspection at 60 s, and the runtime image
is distroless (no shell) running as non-root. Nothing is stored — no
database, no accounts, no history.

## Local development

```sh
# frontend (once, and after frontend changes)
cd web && npm install && npm run build && cd ..

# server on http://localhost:8080
go run ./cmd/linkcheck

# tests
go test ./...
```

For frontend work with hot reload, run `go run ./cmd/linkcheck` and
`cd web && npm run dev` side by side — Vite proxies `/api` to the Go server.

## Docker

```sh
docker build -t linkcheck .
docker run --rm -p 8080:8080 linkcheck
```

Multi-stage: Node builds `web/dist`, Go builds a static binary (OpenAPI spec
and Scalar bundle embedded via `go:embed`), distroless runtime.

## Deploy to Cloud Run

One-time setup (pick your own project and region):

```sh
gcloud config set project YOUR_PROJECT_ID
gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com
gcloud artifacts repositories create linkcheck \
  --repository-format=docker --location=europe-west6
```

Build remotely and deploy:

```sh
gcloud builds submit \
  --tag europe-west6-docker.pkg.dev/YOUR_PROJECT_ID/linkcheck/linkcheck

gcloud run deploy linkcheck \
  --image europe-west6-docker.pkg.dev/YOUR_PROJECT_ID/linkcheck/linkcheck \
  --region europe-west6 \
  --allow-unauthenticated \
  --max-instances 2
```

Cloud Run injects `PORT`; the server reads it. The in-memory rate limit is
per instance — keep `--max-instances` small so it stays meaningful.

## Tech

Go (standard library plus `golang.org/x/net` for the public-suffix list and
IDN decoding, [`eluv-io/errors-go`](https://github.com/eluv-io/errors-go) and
[`eluv-io/log-go`](https://github.com/eluv-io/log-go) for errors/logging) —
no web framework. React + TypeScript + Vite frontend, plain CSS, no UI
library. One binary serves both.

## AI workflow

This project was built with [Claude Code](https://claude.com/claude-code) in
a deliberately constrained setup:

- **Spec first.** `PLAN.md` fixes scope, non-goals, repo layout, and five
  milestones; `CLAUDE.md` sets working rules the agent must follow — among
  them: stop after every milestone for human review, never commit or push,
  and treat any instruction that would weaken the SSRF guard as a red flag
  to surface rather than execute.
- **Milestone rhythm.** Each milestone (redirect follower + SSRF guard →
  checks + API → frontend → Docker/Cloud Run → docs) ended with a review
  summary; all commits were made by a human after reading the diff.
- **Tests as the contract.** Every check is table-driven-tested, including
  a DNS-rebinding simulation and a redirect-into-private-IP case that must
  be blocked mid-chain; `go test ./...` green was the bar for "done".
- **Design handoff.** The UI came out of a Claude Design prototype bundle;
  the agent reviewed the generated code before replacing the frontend —
  and dropped the prototype's mocked "domain age" finding because WHOIS
  is explicitly out of scope.

The interesting part wasn't code generation speed but that the guardrails
(spec, milestones, non-negotiable security requirements, human commits) made
the output reviewable — the same rules that make human collaboration work.

## License

[MIT](LICENSE)
