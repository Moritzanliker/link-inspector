package main

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
