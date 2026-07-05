package inspect

import (
	"fmt"
	"net"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// CheckHomoglyphs inspects a hostname for characters that make it look like
// a different, well-known name: punycode/IDN encoding, labels mixing
// alphabets, and classic ASCII lookalike substitutions. host is the raw
// hostname as it appeared in the URL — case is preserved on purpose, because
// the capital-I-for-l trick is only visible before lowercasing.
func CheckHomoglyphs(host string) []Finding {
	if host == "" || net.ParseIP(host) != nil {
		return nil
	}
	var findings []Finding
	lower := strings.ToLower(host)

	unicodeHost, err := idna.ToUnicode(lower)
	if err != nil {
		findings = append(findings, Finding{
			Severity: SeverityWarn,
			Code:     "PUNYCODE_INVALID",
			Message:  fmt.Sprintf("Domain %q uses punycode that cannot be decoded — it may be trying to hide its real name", lower),
		})
		unicodeHost = lower
	} else if unicodeHost != lower {
		findings = append(findings, Finding{
			Severity: SeverityWarn,
			Code:     "PUNYCODE",
			Message:  fmt.Sprintf("Domain %q is punycode for %q — check that the decoded name is what you expect", lower, unicodeHost),
		})
	}

	findings = append(findings, checkMixedScript(unicodeHost)...)
	findings = append(findings, checkLookalikes(host)...)
	return findings
}

// checkMixedScript flags labels that mix letters from different alphabets
// (e.g. a Cyrillic "а" inside an otherwise-Latin "аpple"), the strongest
// homoglyph signal there is: no legitimate name needs to do that.
func checkMixedScript(host string) []Finding {
	var findings []Finding
	for _, label := range strings.Split(host, ".") {
		scripts := map[string]bool{}
		for _, r := range label {
			if !unicode.IsLetter(r) {
				continue
			}
			switch {
			case unicode.Is(unicode.Latin, r):
				scripts["Latin"] = true
			case unicode.Is(unicode.Cyrillic, r):
				scripts["Cyrillic"] = true
			case unicode.Is(unicode.Greek, r):
				scripts["Greek"] = true
			default:
				scripts["other"] = true
			}
		}
		if len(scripts) > 1 {
			names := make([]string, 0, len(scripts))
			for s := range scripts {
				names = append(names, s)
			}
			findings = append(findings, Finding{
				Severity: SeverityDanger,
				Code:     "MIXED_SCRIPT",
				Message:  fmt.Sprintf("Domain part %q mixes letters from different alphabets (%s) — a common way to imitate a well-known name", label, strings.Join(names, ", ")),
			})
		}
	}
	return findings
}

// checkLookalikes flags classic ASCII substitutions in the registered
// domain: digits 0/1 posing as o/l, "rn" posing as "m", and a capital I
// posing as a lowercase l. Only the registered domain matters — that is the
// part a victim reads to decide whom they are talking to.
func checkLookalikes(rawHost string) []Finding {
	lower := strings.ToLower(rawHost)
	reg, err := publicsuffix.EffectiveTLDPlusOne(lower)
	if err != nil {
		reg = lower
	}
	// The registered domain's leftmost label is the "brand" part a reader
	// judges; the public suffix cannot be chosen by an attacker.
	name := reg
	if i := strings.IndexByte(reg, '.'); i > 0 {
		name = reg[:i]
	}
	if strings.HasPrefix(name, "xn--") {
		// Punycode is an encoding, not something a human reads — digits in
		// it are meaningless. The PUNYCODE and MIXED_SCRIPT findings cover
		// IDN tricks.
		return nil
	}
	// Same slice of the raw (case-preserved) host, for the capital-I check.
	rawReg := rawHost[len(rawHost)-len(reg):]

	var findings []Finding
	lookalike := func(severity Severity, msg string) {
		findings = append(findings, Finding{Severity: severity, Code: "LOOKALIKE", Message: msg})
	}
	if digitPosingAsLetter(name, '0') {
		lookalike(SeverityWarn, fmt.Sprintf("Domain %q contains the digit 0 next to letters — it can imitate the letter o", reg))
	}
	if digitPosingAsLetter(name, '1') {
		lookalike(SeverityWarn, fmt.Sprintf("Domain %q contains the digit 1 next to letters — it can imitate the letter l", reg))
	}
	if strings.ContainsRune(rawReg, 'I') {
		lookalike(SeverityWarn, fmt.Sprintf("Domain %q contains a capital I — it can look identical to a lowercase l", rawReg))
	}
	if strings.Contains(name, "rn") {
		lookalike(SeverityInfo, fmt.Sprintf("Domain %q contains \"rn\" — together these letters can look like an m", reg))
	}
	return findings
}

// digitPosingAsLetter reports whether s contains d directly adjacent to a
// letter, i.e. used inside a word ("g00gle") rather than as a standalone
// number ("365").
func digitPosingAsLetter(s string, d byte) bool {
	isLetter := func(i int) bool {
		return i >= 0 && i < len(s) && s[i] >= 'a' && s[i] <= 'z'
	}
	for i := 0; i < len(s); i++ {
		if s[i] == d && (isLetter(i-1) || isLetter(i+1)) {
			return true
		}
	}
	return false
}
