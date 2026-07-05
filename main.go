// Command link-inspector serves the inspection API (and, from M3 on, the
// built frontend from web/dist).
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/eluv-io/errors-go"
	elog "github.com/eluv-io/log-go"

	"github.com/moritzanliker/link-inspector/inspect"
)

var log = elog.Get("/link-inspector")

// inspectTimeout caps a whole inspection: 10 hops x 5s per hop, plus slack.
const inspectTimeout = 60 * time.Second

func main() {
	ins := inspect.NewInspector(inspect.NewFollower(inspect.NewGuard()))

	mux := http.NewServeMux()
	mux.Handle("POST /api/inspect", handleInspect(ins))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Info("listening", "port", port)
	log.Fatal("server stopped", srv.ListenAndServe())
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Warn("writing response failed", err)
	}
}
