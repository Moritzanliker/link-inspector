package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/moritzanliker/link-inspector/inspect"
)

func newTestHandler() http.HandlerFunc {
	return handleInspect(inspect.NewInspector(inspect.NewFollower(inspect.NewGuard())))
}

func TestDocRoutes(t *testing.T) {
	mux := New(inspect.NewInspector(inspect.NewFollower(inspect.NewGuard())), "web/dist")
	tests := []struct {
		path        string
		contentType string
		mustContain string
	}{
		{"/doc", "text/html; charset=utf-8", "/doc/scalar.js"},
		{"/doc/scalar.js", "text/javascript; charset=utf-8", "createApiReference"},
		{"/openapi.yaml", "application/yaml", "LinkCheck API"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200", tt.path, rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != tt.contentType {
				t.Errorf("Content-Type = %q, want %q", got, tt.contentType)
			}
			if !strings.Contains(rec.Body.String(), tt.mustContain) {
				t.Errorf("GET %s body does not contain %q", tt.path, tt.mustContain)
			}
		})
	}
}

func postInspect(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/inspect", strings.NewReader(body))
	rec := httptest.NewRecorder()
	newTestHandler()(rec, req)
	return rec
}

func TestHandleInspectBadRequests(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"invalid JSON", `{"url": `},
		{"missing url", `{}`},
		{"empty url", `{"url": ""}`},
		{"URL without scheme", `{"url": "example.com"}`},
		{"unsupported scheme", `{"url": "file:///etc/passwd"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := postInspect(t, tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body)
			}
			var resp struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Error == "" {
				t.Errorf("body = %s, want JSON with non-empty error message", rec.Body)
			}
		})
	}
}

// TestHandleInspectBlockedAddress covers the PLAN.md definition of done:
// an internal address is cleanly refused with a finding, not an HTTP error.
// The guard rejects it before any connection, so no network is involved.
func TestHandleInspectBlockedAddress(t *testing.T) {
	rec := postInspect(t, `{"url": "http://169.254.169.254/"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with findings (body: %s)", rec.Code, rec.Body)
	}
	var res inspect.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("response is not a Result: %v (body: %s)", err, rec.Body)
	}
	if res.Verdict != inspect.VerdictSuspicious {
		t.Errorf("verdict = %q, want %q", res.Verdict, inspect.VerdictSuspicious)
	}
	found := false
	for _, f := range res.Findings {
		if f.Code == "BLOCKED_INTERNAL" && f.Severity == inspect.SeverityDanger {
			found = true
		}
	}
	if !found {
		t.Errorf("findings = %+v, want BLOCKED_INTERNAL danger finding", res.Findings)
	}
}
