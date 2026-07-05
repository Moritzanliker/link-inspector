package inspect

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// shortenerDomains are registered domains of well-known URL shorteners.
// A shortener is not malicious by itself, but it hides the real target.
var shortenerDomains = map[string]bool{
	"bit.ly":      true,
	"tinyurl.com": true,
	"t.co":        true,
	"goo.gl":      true,
	"is.gd":       true,
	"cutt.ly":     true,
	"rb.gy":       true,
	"ow.ly":       true,
	"buff.ly":     true,
	"rebrand.ly":  true,
	"tiny.cc":     true,
	"shorturl.at": true,
	"t.ly":        true,
	"lnkd.in":     true,
}

// brandKeywords are names phishers like to put into subdomains of unrelated
// domains (paypal.evil.example). Matched as whole '-'-separated tokens of a
// label, not substrings, to keep false positives down.
var brandKeywords = []string{
	"paypal", "apple", "google", "microsoft", "amazon", "netflix",
	"facebook", "instagram", "whatsapp", "post", "dhl", "ups", "fedex",
	"ubs", "swisscom", "raiffeisen", "zkb", "postfinance", "twint",
}

// suspiciousTLDs see disproportionate abuse (or, for zip/mov, collide with
// file extensions people trust).
var suspiciousTLDs = map[string]bool{
	"zip": true, "mov": true, "tk": true, "top": true, "gq": true,
	"ml": true, "cf": true, "ga": true, "icu": true, "cam": true,
}

// CheckURL flags tricks visible in a single URL, independent of DNS: the
// userinfo-@ trick, raw-IP hosts, unencrypted http and unusual ports.
func CheckURL(u *url.URL) []Finding {
	var findings []Finding
	if u.User != nil {
		findings = append(findings, Finding{
			Severity: SeverityDanger,
			Code:     "USERINFO",
			Message:  fmt.Sprintf("The URL contains %q before an @ sign — everything before the @ is a decoy, the link really leads to %q", u.User.String(), u.Hostname()),
		})
	}
	if net.ParseIP(u.Hostname()) != nil {
		findings = append(findings, Finding{
			Severity: SeverityWarn,
			Code:     "RAW_IP",
			Message:  fmt.Sprintf("The URL points to the raw IP address %s instead of a named website", u.Hostname()),
		})
	}
	if u.Scheme == "http" {
		findings = append(findings, Finding{
			Severity: SeverityWarn,
			Code:     "INSECURE_HTTP",
			Message:  "Part of the link's path uses unencrypted HTTP — data sent there can be read or altered in transit",
		})
	}
	if p := u.Port(); p != "" && p != "80" && p != "443" {
		findings = append(findings, Finding{
			Severity: SeverityInfo,
			Code:     "UNUSUAL_PORT",
			Message:  fmt.Sprintf("The URL uses the unusual port %s", p),
		})
	}
	return findings
}

// CheckHost flags domain-level tricks on a hostname (no port). Raw IPs are
// handled by CheckURL and skipped here.
func CheckHost(host string) []Finding {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || net.ParseIP(host) != nil {
		return nil
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// Not a registrable public name (e.g. "localhost", bare TLD) —
		// nothing domain-shaped to judge. The SSRF guard, not heuristics,
		// decides whether such hosts may be contacted at all.
		return nil
	}

	var findings []Finding
	if tld := reg[strings.LastIndexByte(reg, '.')+1:]; suspiciousTLDs[tld] {
		findings = append(findings, Finding{
			Severity: SeverityWarn,
			Code:     "SUSPICIOUS_TLD",
			Message:  fmt.Sprintf("The domain ends in .%s, an ending frequently used in abusive registrations", tld),
		})
	}
	if shortenerDomains[reg] {
		findings = append(findings, Finding{
			Severity: SeverityWarn,
			Code:     "SHORTENER",
			Message:  fmt.Sprintf("Link uses a URL shortener (%s) — the visible link says nothing about the destination", reg),
		})
	}

	sub := strings.TrimSuffix(strings.TrimSuffix(host, reg), ".")
	if sub == "" {
		return findings
	}
	labels := strings.Split(sub, ".")
	if len(labels) > 3 {
		findings = append(findings, Finding{
			Severity: SeverityInfo,
			Code:     "SUBDOMAIN_DEPTH",
			Message:  fmt.Sprintf("The hostname has %d subdomain levels — long prefixes can push the real domain out of sight", len(labels)),
		})
	}
	findings = append(findings, checkDeceptiveSubdomain(labels, reg)...)
	return findings
}

// checkDeceptiveSubdomain looks for a foreign identity planted in the
// subdomain part: either a full registrable domain (paypal.com.evil.xyz —
// the strongest deception, danger) or a known brand keyword
// (paypal-login.evil.xyz — warn). reg is the actual registered domain, used
// to avoid flagging a brand inside its own domain (paypal.paypal.com).
func checkDeceptiveSubdomain(labels []string, reg string) []Finding {
	var findings []Finding
	// Right to left: the pair closest to the real registered domain is the
	// one a reader mistakes for it (ubs.com in www.ubs.com.evil.example).
	// One finding per host is enough — stop at the first hit.
	for i := len(labels) - 2; i >= 0; i-- {
		cand := labels[i] + "." + labels[i+1]
		suffix, icann := publicsuffix.PublicSuffix(cand)
		if !icann || suffix == cand {
			// Only real, ICANN-managed suffixes count: without this,
			// any two stacked labels ("www.images") would look like a
			// registrable domain.
			continue
		}
		if etld1, err := publicsuffix.EffectiveTLDPlusOne(cand); err == nil && etld1 == cand {
			findings = append(findings, Finding{
				Severity: SeverityDanger,
				Code:     "DECEPTIVE_SUBDOMAIN",
				Message:  fmt.Sprintf("The address starts with %q but that is only a subdomain — the site actually belongs to %q", cand, reg),
			})
			break
		}
	}
	for _, label := range labels {
		for _, brand := range brandKeywords {
			if strings.Contains(reg, brand) {
				continue // the brand's own domain
			}
			for _, token := range strings.Split(label, "-") {
				if token == brand {
					findings = append(findings, Finding{
						Severity: SeverityWarn,
						Code:     "BRAND_IN_SUBDOMAIN",
						Message:  fmt.Sprintf("%q appears in the subdomain, but the site actually belongs to %q", brand, reg),
					})
				}
			}
		}
	}
	return findings
}
