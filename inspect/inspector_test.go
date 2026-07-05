package inspect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerdictFor(t *testing.T) {
	tests := []struct {
		name       string
		severities []Severity
		want       Verdict
	}{
		{"no findings", nil, VerdictOK},
		{"info only", []Severity{SeverityInfo, SeverityInfo}, VerdictOK},
		{"warn", []Severity{SeverityInfo, SeverityWarn}, VerdictCaution},
		{"danger", []Severity{SeverityDanger}, VerdictSuspicious},
		{"danger beats warn", []Severity{SeverityWarn, SeverityDanger, SeverityInfo}, VerdictSuspicious},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := make([]Finding, len(tt.severities))
			for i, s := range tt.severities {
				findings[i] = Finding{Severity: s}
			}
			if got := verdictFor(findings); got != tt.want {
				t.Errorf("verdictFor(%v) = %q, want %q", tt.severities, got, tt.want)
			}
		})
	}
}

func TestInspectChain(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ins := NewInspector(testFollower())
	res, err := ins.Inspect(context.Background(), srv.URL+"/start")
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if len(res.RedirectChain) != 2 {
		t.Fatalf("chain = %+v, want 2 hops", res.RedirectChain)
	}
	if res.FinalURL != srv.URL+"/final" {
		t.Errorf("final_url = %q, want %q", res.FinalURL, srv.URL+"/final")
	}
	// The httptest server is plain http on 127.0.0.1:random-port, so the
	// URL checks must flag exactly: insecure http, raw IP, unusual port.
	assertCodes(t, res.Findings, []string{"INSECURE_HTTP", "RAW_IP", "UNUSUAL_PORT"})
	if res.Verdict != VerdictCaution {
		t.Errorf("verdict = %q, want %q", res.Verdict, VerdictCaution)
	}
}

func TestInspectBlockedInput(t *testing.T) {
	// Real guard, no test hook: the metadata IP must be refused without any
	// network traffic and come back as a finding, not an error.
	ins := NewInspector(NewFollower(NewGuard()))
	res, err := ins.Inspect(context.Background(), "http://169.254.169.254/latest/meta-data/")
	if err != nil {
		t.Fatalf("Inspect() error = %v, want blocked-as-finding", err)
	}
	if len(res.RedirectChain) != 0 {
		t.Errorf("chain = %+v, want empty", res.RedirectChain)
	}
	assertCodes(t, res.Findings, []string{"BLOCKED_INTERNAL", "RAW_IP", "INSECURE_HTTP"})
	if res.Verdict != VerdictSuspicious {
		t.Errorf("verdict = %q, want %q", res.Verdict, VerdictSuspicious)
	}
	if res.Findings[0].Code != "BLOCKED_INTERNAL" {
		t.Errorf("first finding = %+v, want the danger finding sorted first", res.Findings[0])
	}
}

func TestInspectRedirectLoop(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/loop/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop/b", http.StatusFound)
	})
	mux.HandleFunc("/loop/b", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop/a", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ins := NewInspector(testFollower())
	res, err := ins.Inspect(context.Background(), srv.URL+"/loop/a")
	if err != nil {
		t.Fatalf("Inspect() error = %v, want loop-as-finding", err)
	}
	if len(res.RedirectChain) != 2 {
		t.Errorf("chain = %+v, want the 2 hops before the loop closed", res.RedirectChain)
	}
	assertCodes(t, res.Findings, []string{"REDIRECT_LOOP", "INSECURE_HTTP", "RAW_IP", "UNUSUAL_PORT"})
	if res.Verdict != VerdictSuspicious {
		t.Errorf("verdict = %q, want %q", res.Verdict, VerdictSuspicious)
	}
}

func TestInspectInvalidURLIsError(t *testing.T) {
	ins := NewInspector(NewFollower(NewGuard()))
	res, err := ins.Inspect(context.Background(), "not-a-url")
	if err == nil {
		t.Fatalf("Inspect() = %+v, want error for URL without scheme", res)
	}
}
