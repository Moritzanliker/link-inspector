# LinkCheck

See where a link really leads before you click it — full redirect chain,
domain tricks, and a plain-language verdict.

## API documentation

The full API reference (OpenAPI 3.0, rendered with [Scalar](https://github.com/scalar/scalar))
is served by the app itself at [`/doc`](http://localhost:8080/doc); the raw
spec lives in [`openapi.yaml`](openapi.yaml) and is available at
[`/openapi.yaml`](http://localhost:8080/openapi.yaml). The Scalar viewer is
vendored (`assets/`), so the docs work without internet access.

## Local development

```sh
# frontend (once, and after frontend changes)
cd web && npm install && npm run build && cd ..

# server on http://localhost:8080
go run .

# tests
go test ./...
```

For frontend work with hot reload, run `go run .` and `cd web && npm run dev`
side by side — Vite proxies `/api` to the Go server.

## Docker

```sh
docker build -t linkcheck .
docker run --rm -p 8080:8080 linkcheck
```

Multi-stage build: Node builds `web/dist`, Go builds a static binary
(OpenAPI spec and Scalar bundle embedded), and the runtime image is
distroless — no shell, non-root.

## Deploy to Cloud Run

One-time setup (pick your own project and region):

```sh
gcloud auth login
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

Cloud Run injects `PORT`; the server reads it. The in-memory rate limit
(20 requests/min per client IP) is per instance — keep `--max-instances`
small so it stays meaningful.

## Security

Outbound requests are the core risk of a URL inspector (SSRF). Every hop of
every redirect chain is validated: only http/https, hostnames resolved and
checked against private/loopback/link-local/metadata ranges, and the dialed
IP re-validated at connect time (DNS-rebinding protection). See
`inspect/ssrf.go`.
