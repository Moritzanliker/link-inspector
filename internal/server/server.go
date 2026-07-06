// Package server wires the LinkCheck HTTP surface: the inspection API, the
// embedded API documentation, and the built frontend.
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/eluv-io/errors-go"
	elog "github.com/eluv-io/log-go"

	"github.com/moritzanliker/link-inspector/api"
	"github.com/moritzanliker/link-inspector/inspect"
)

var log = elog.Get("/link-inspector/server")

// inspectTimeout caps a whole inspection: 10 hops x 5s per hop, plus slack.
const inspectTimeout = 60 * time.Second

// Rate limit per client IP: generous for a human clicking around, tight
// enough that the service is useless as a bulk URL scanner.
const (
	rateLimit  = 20
	rateWindow = time.Minute
)

// docHTML renders the OpenAPI spec with Scalar's API reference viewer.
const docHTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>LinkCheck API Reference</title>
  </head>
  <body>
    <div id="app"></div>
    <script src="/doc/scalar.js"></script>
    <script>
      Scalar.createApiReference("#app", { url: "/openapi.yaml" });
    </script>
  </body>
</html>
`

// New returns the complete LinkCheck handler. frontendDir is the directory
// holding the built frontend (web/dist), resolved relative to the working
// directory.
func New(ins *inspect.Inspector, frontendDir string) *http.ServeMux {
	limiter := newRateLimiter(rateLimit, rateWindow)
	mux := http.NewServeMux()
	mux.Handle("POST /api/inspect", limiter.middleware(handleInspect(ins)))
	mux.HandleFunc("GET /openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(api.OpenAPISpec)
	})
	mux.HandleFunc("GET /doc", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(docHTML))
	})
	mux.HandleFunc("GET /doc/scalar.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		// The bundle only changes when we re-vendor it; let browsers cache.
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(api.ScalarJS)
	})
	mux.Handle("GET /", frontendHandler(frontendDir))
	return mux
}

type inspectRequest struct {
	URL string `json:"url"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func handleInspect(ins *inspect.Inspector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		var req inspectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{`invalid request body: expected {"url": "https://..."}`})
			return
		}
		if req.URL == "" {
			writeJSON(w, http.StatusBadRequest, errorResponse{`missing "url" in request body`})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), inspectTimeout)
		defer cancel()
		result, err := ins.Inspect(ctx, req.URL)
		if err != nil {
			log.Warn("inspection failed", "url", req.URL, err)
			writeJSON(w, statusFor(err), errorResponse{messageFor(err)})
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

// statusFor maps inspection error kinds to HTTP statuses. Blocked internal
// addresses never reach this point — they come back as findings, not errors.
func statusFor(err error) int {
	switch {
	case errors.IsKind(errors.K.Invalid, err):
		return http.StatusBadRequest
	case errors.IsKind(errors.K.Timeout, err):
		return http.StatusGatewayTimeout
	case errors.IsKind(errors.K.NotExist, err), errors.IsKind(errors.K.IO, err):
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

// messageFor returns the human-readable reason the checks attached to the
// error; the full error with all fields stays in the server log.
func messageFor(err error) string {
	if reason, ok := errors.GetField(err, "reason"); ok {
		return reason
	}
	return "inspection failed"
}

// frontendHandler serves the built frontend from dir. It is a single-page
// app, so any path that is not an existing file gets index.html. When the
// frontend has not been built, the API keeps working and / explains itself.
func frontendHandler(dir string) http.Handler {
	if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
		log.Warn("frontend not built, serving placeholder", "dir", dir)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "LinkCheck API. Frontend not built — run `npm run build` in web/.", http.StatusNotFound)
		})
	}
	files := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join(dir, filepath.Clean("/"+r.URL.Path))
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
			return
		}
		files.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Warn("writing response failed", err)
	}
}
