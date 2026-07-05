package inspect

import "testing"

func TestCheckHomoglyphs(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		wantCodes []string // exact set of expected finding codes (with duplicates)
	}{
		{
			name:      "plain domain",
			host:      "example.com",
			wantCodes: nil,
		},
		{
			name:      "plain domain with subdomain",
			host:      "www.google.com",
			wantCodes: nil,
		},
		{
			name:      "raw IP is skipped",
			host:      "192.0.2.1",
			wantCodes: nil,
		},
		{
			// xn--pple-43d decodes to аpple with a Cyrillic а: both the
			// punycode itself and the resulting mixed script must be flagged.
			name:      "punycode hiding cyrillic a",
			host:      "xn--pple-43d.com",
			wantCodes: []string{"PUNYCODE", "MIXED_SCRIPT"},
		},
		{
			// A domain entirely in one non-Latin script is punycode but NOT
			// mixed script — that is what IDNs are for.
			name:      "all-cyrillic domain",
			host:      "xn--80a1acny.xn--p1ai", // почта.рф
			wantCodes: []string{"PUNYCODE"},
		},
		{
			name:      "unicode host mixing scripts directly",
			host:      "аpple.com", // Cyrillic а + Latin pple
			wantCodes: []string{"MIXED_SCRIPT"},
		},
		{
			name:      "digit zero posing as o",
			host:      "g00gle.com",
			wantCodes: []string{"LOOKALIKE"},
		},
		{
			name:      "digit one posing as l",
			host:      "paypa1.com",
			wantCodes: []string{"LOOKALIKE"},
		},
		{
			name:      "standalone number is not a lookalike",
			host:      "365.com",
			wantCodes: nil,
		},
		{
			name:      "number token in name is not a lookalike",
			host:      "web404.com",
			wantCodes: nil,
		},
		{
			name:      "rn posing as m",
			host:      "rnicrosoft.com",
			wantCodes: []string{"LOOKALIKE"},
		},
		{
			name:      "capital I posing as l",
			host:      "PayPaI.com",
			wantCodes: []string{"LOOKALIKE"},
		},
		{
			name:      "lookalike only checked in registered domain",
			host:      "g00gle.example.com", // the "brand" part here is example
			wantCodes: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckHomoglyphs(tt.host)
			assertCodes(t, got, tt.wantCodes)
		})
	}
}

// assertCodes compares the codes of got against want, order-insensitively.
func assertCodes(t *testing.T, got []Finding, want []string) {
	t.Helper()
	gotSet := map[string]int{}
	for _, f := range got {
		gotSet[f.Code]++
	}
	wantSet := map[string]int{}
	for _, c := range want {
		wantSet[c]++
	}
	for c, n := range wantSet {
		if gotSet[c] != n {
			t.Errorf("finding %s: got %d, want %d (all findings: %+v)", c, gotSet[c], n, got)
		}
	}
	for c, n := range gotSet {
		if wantSet[c] == 0 {
			t.Errorf("unexpected finding %s (x%d) (all findings: %+v)", c, n, got)
		}
	}
}
