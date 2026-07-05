package inspect

import (
	"context"
	"net/url"
	"sort"

	"github.com/eluv-io/errors-go"
)

// Severity of a finding, from harmless observation to strong phishing signal.
type Severity string

const (
	SeverityInfo   Severity = "info"
	SeverityWarn   Severity = "warn"
	SeverityDanger Severity = "danger"
)

// Finding is one observation about the inspected link, with a stable code
// and a message written for non-technical readers.
type Finding struct {
	Severity Severity `json:"severity"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
}

// Verdict is the aggregate of all findings.
type Verdict string

const (
	VerdictOK         Verdict = "ok"
	VerdictCaution    Verdict = "caution"
	VerdictSuspicious Verdict = "suspicious"
)

// Result is the response body of POST /api/inspect.
type Result struct {
	InputURL      string    `json:"input_url"`
	FinalURL      string    `json:"final_url"`
	RedirectChain []Hop     `json:"redirect_chain"`
	Findings      []Finding `json:"findings"`
	Verdict       Verdict   `json:"verdict"`
}

// Inspector runs all checks on a URL and aggregates them into a Result.
type Inspector struct {
	follower *Follower
}

// NewInspector returns an Inspector using f for redirect following. The
// follower carries the SSRF guard; there is no way to build an Inspector
// that bypasses it.
func NewInspector(f *Follower) *Inspector {
	return &Inspector{follower: f}
}

// Inspect follows rawURL's redirect chain and runs every check on every hop.
// Outcomes the user should see as findings (blocked internal address,
// redirect loop, hop limit) produce a Result; only conditions where there is
// nothing to show (invalid URL, unreachable host, timeout) return an error.
func (ins *Inspector) Inspect(ctx context.Context, rawURL string) (*Result, error) {
	chain, ferr := ins.follower.Follow(ctx, rawURL)

	findings := []Finding{}
	if ferr != nil {
		reason, _ := errors.GetField(ferr, "reason")
		switch {
		case IsBlocked(ferr):
			findings = append(findings, Finding{
				Severity: SeverityDanger,
				Code:     "BLOCKED_INTERNAL",
				Message:  "The link leads to an internal or private network address; it was not followed",
			})
		case reason == reasonRedirectLoop:
			findings = append(findings, Finding{
				Severity: SeverityDanger,
				Code:     "REDIRECT_LOOP",
				Message:  "The link redirects in a circle and never reaches a destination",
			})
		case reason == reasonTooManyRedirects:
			findings = append(findings, Finding{
				Severity: SeverityDanger,
				Code:     "TOO_MANY_REDIRECTS",
				Message:  "The link redirects more than 10 times; inspection stopped before reaching a destination",
			})
		default:
			return nil, ferr
		}
	}

	// Check the input URL plus every hop. The chain already starts with the
	// normalized input when following got that far; parsing rawURL as well
	// covers the case where hop 1 itself was refused.
	urls := make([]*url.URL, 0, len(chain)+1)
	if u, err := url.Parse(rawURL); err == nil {
		urls = append(urls, u)
	}
	for _, hop := range chain {
		if u, err := url.Parse(hop.URL); err == nil {
			urls = append(urls, u)
		}
	}
	seen := map[string]bool{}
	add := func(fs []Finding) {
		for _, f := range fs {
			key := f.Code + "|" + f.Message
			if !seen[key] {
				seen[key] = true
				findings = append(findings, f)
			}
		}
	}
	for _, u := range urls {
		add(CheckURL(u))
		add(CheckHost(u.Hostname()))
		add(CheckHomoglyphs(u.Hostname()))
	}

	// Highest severity first, so the response reads top-down; the sort is
	// stable to keep same-severity findings in discovery order.
	rank := map[Severity]int{SeverityDanger: 0, SeverityWarn: 1, SeverityInfo: 2}
	sort.SliceStable(findings, func(i, j int) bool {
		return rank[findings[i].Severity] < rank[findings[j].Severity]
	})

	finalURL := ""
	if len(chain) > 0 {
		finalURL = chain[len(chain)-1].URL
	}
	if chain == nil {
		chain = []Hop{}
	}
	return &Result{
		InputURL:      rawURL,
		FinalURL:      finalURL,
		RedirectChain: chain,
		Findings:      findings,
		Verdict:       verdictFor(findings),
	}, nil
}

// verdictFor aggregates findings per PLAN.md: any danger → suspicious, else
// any warn → caution, else ok.
func verdictFor(findings []Finding) Verdict {
	verdict := VerdictOK
	for _, f := range findings {
		switch f.Severity {
		case SeverityDanger:
			return VerdictSuspicious
		case SeverityWarn:
			verdict = VerdictCaution
		}
	}
	return verdict
}
