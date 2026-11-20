// Package repocheck holds repository-wide checks that are not about any one
// package. The one so far: the tree contains no real hostnames, email
// addresses or IP addresses (SPEC 15), only placeholders and a short list of
// exact public hosts.
//
// Host rules, in order of precedence:
//
//   - A host is judged by EXACT match after normalisation. Normalisation
//     lower-cases the name (DNS is case-insensitive, so FIREWALLA.NET is the
//     same host as firewalla.net) and drops one trailing root dot
//     ("firewalla.net." is the same host too). Anything still odd afterwards
//     (non-ASCII labels, empty labels, more than one trailing dot) is not a
//     plain documentation host and is reported.
//   - There are no wildcard subdomains. A subdomain of an allowed host, an allowed
//     host followed by further labels, and one used as a prefix of another domain
//     are all different hosts from the allowed one. With a title-case top-level
//     label a name counts as a host when it contains an allowed host as whole
//     labels; a bare `evil.Com` is indistinguishable from code and is not one.
//   - Punycode (xn--) labels are never on the list, so they are reported.
//   - U+FF0E, U+3002, U+FF61, U+2024 and U+FE52 are label separators, like a dot.
//   - Percent-escapes and HTML numeric references (&#46;) are decoded
//     (repeatedly, to a fixed point) and both the raw and the decoded line are
//     judged; a decoded CR, LF or TAB is also dropped for a joined view, as a URL
//     parser would. A host split by a real line break is NOT joined (DECISIONS.md).
//   - Placeholder hosts stay allowed: example.com, example.net, example.org
//     and their subdomains (RFC 2606), and the RFC 5737 / 3849 address blocks.
package repocheck

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// AllowedHosts are the exact hosts that may appear in the tree (SPEC 15):
// Firewalla's own public documentation and this project's own dependencies.
var AllowedHosts = map[string]bool{
	"firewalla.net":      true,
	"docs.firewalla.net": true,
	"firewalla.com":      true,
	"help.firewalla.com": true,
	"github.com":         true,
	"go.dev":             true,
	"pkg.go.dev":         true,
	"proxy.golang.org":   true,
	"sum.golang.org":     true,
	"gnu.org":            true,
	"www.gnu.org":        true,
}

// topLevel is the list of real top-level domains the host scan looks for.
// Source code is full of dotted identifiers (`s.cfg.Upstream`, `check.sh`)
// and a name only counts as a host when it ends like a real one.
const topLevel = "com|net|org|io|dev|app|cloud|info|biz|edu|gov|co|uk|us|de|eu|ai|xyz|tv|cc|ru|cn|jp|fr|nl|ch|ca|au|tech|online|site|link|network|systems"

var (
	tldSet = func() map[string]bool {
		m := map[string]bool{}
		for _, t := range strings.Split(topLevel, "|") {
			m[t] = true
		}
		return m
	}()
	// RFC 2606 / 6761 reserved top-level names.
	reservedTLD = map[string]bool{"example": true, "invalid": true, "test": true, "localhost": true}

	// A dotted token of letters (any script), digits and hyphens. Underscore,
	// colon, slash, @ and so on end a token, which is what we want: they are
	// not part of a host name.
	// Trailing dots stay with the token so a second one can be judged.
	tokenRE = regexp.MustCompile(`[\p{L}\p{N}\p{M}-]+(?:\.[\p{L}\p{N}\p{M}-]+)+\.*`)
	emailRE = regexp.MustCompile(`(?i)[a-z0-9._%+-]+@((?:[a-z0-9-]+\.)+[a-z]{2,})`)
	ip4RE   = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	ip6RE   = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`)
	pctRE   = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
)

// Placeholder spaces: RFC 5737 / 3849 address blocks, loopback and the
// unspecified address.
var placeholderNets = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", // documentation
		"127.0.0.0/8", "0.0.0.0/32", // loopback, unspecified
		"2001:db8::/32", "::1/128", "::/128", // documentation, loopback, unspecified
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Normalise returns the canonical form of host: lower case, one trailing root
// dot removed. ok is false when what is left is not a plain ASCII host name
// (empty or non-ASCII labels, a second trailing dot).
func Normalise(host string) (string, bool) {
	h := strings.ToLower(host)
	h = strings.TrimSuffix(h, ".")
	if h == "" || strings.HasSuffix(h, ".") {
		return "", false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			if label[i] >= 0x80 {
				return "", false
			}
		}
	}
	return h, true
}

func placeholderHost(h string) bool {
	for _, d := range []string{"example.com", "example.net", "example.org"} {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// HostAllowed reports whether host, after normalisation, is on the exact
// allowlist or is a placeholder name. extra, if non-nil, excuses further
// normalised hosts (a per-file allowance).
func HostAllowed(host string, extra func(normalised string) bool) bool {
	n, ok := Normalise(host)
	if !ok {
		return false
	}
	return AllowedHosts[n] || placeholderHost(n) || (extra != nil && extra(n))
}

func placeholderEmailDomain(d string) bool {
	n, ok := Normalise(d)
	if !ok {
		return false
	}
	if placeholderHost(n) {
		return true
	}
	for t := range reservedTLD {
		if n == t || strings.HasSuffix(n, "."+t) {
			return true
		}
	}
	return false
}

// hostLike reports whether a dotted token should be treated as a host name
// rather than a code identifier or file name.
func hostLike(tok string) bool {
	lc := strings.ToLower(tok)
	labels := strings.Split(lc, ".")
	last := labels[len(labels)-1]
	asWritten := tok[strings.LastIndexByte(tok, '.')+1:]
	// A real TLD written all lower or all upper case; `logger.Info` is neither.
	if tldSet[last] && (asWritten == strings.ToLower(asWritten) || asWritten == strings.ToUpper(asWritten)) {
		return true
	}
	// A reserved TLD (.example, .test ...) with a real TLD label inside, such
	// as <allowed host>.example: a look-alike, not a bare placeholder.
	if reservedTLD[last] {
		for _, l := range labels[:len(labels)-1] {
			if tldSet[l] {
				return true
			}
		}
	}
	// A host that contains an allowed host as whole labels, as a prefix, in
	// the middle or as the end, is a look-alike or a subdomain of it even
	// when its top-level label is written in mixed case (`logger.Info` has
	// no such label run and stays clean).
	padded := "." + lc + "."
	for h := range AllowedHosts {
		if strings.Contains(padded, "."+h+".") {
			return true
		}
	}
	return false
}

// dotFold maps the characters that Unicode normalisation and URL parsers
// treat as a full stop to U+002E, so they separate labels like one:
// fullwidth full stop, ideographic full stop, halfwidth ideographic full
// stop, one dot leader and small full stop.
var dotFold = strings.NewReplacer("\uff0e", ".", "\u3002", ".", "\uff61", ".", "\u2024", ".", "\ufe52", ".")

// entityRE matches HTML numeric character references (the semicolon is
// optional, as in a browser) and the named full stop.
var entityRE = regexp.MustCompile(`&#[xX]([0-9A-Fa-f]{1,8});?|&#([0-9]{1,10});?|&period;`)

func decodeEntities(s string) string {
	return entityRE.ReplaceAllStringFunc(s, func(m string) string {
		if m == "&period;" {
			return "."
		}
		var v uint64
		var err error
		if m[2] == 'x' || m[2] == 'X' {
			v, err = strconv.ParseUint(strings.TrimSuffix(m[3:], ";"), 16, 32)
		} else {
			v, err = strconv.ParseUint(strings.TrimSuffix(m[2:], ";"), 10, 32)
		}
		if err != nil || !utf8.ValidRune(rune(v)) {
			return m
		}
		return string(rune(v))
	})
}

// decode undoes percent-escapes and HTML numeric references until the text
// stops changing (at most 8 rounds), so nested encodings (%252E, &#38;#46;,
// %26%2346%3B) are undone as well.
func decode(s string) string {
	for i := 0; i < 8; i++ {
		d := decodeEntities(percentDecode(s))
		if d == s {
			break
		}
		s = d
	}
	return s
}

// breaksRE matches the characters a URL parser drops from a URL: CR, LF, TAB.
var breaksRE = regexp.MustCompile(`[\r\n	]`)

// percentDecode decodes %XX escapes once.
func percentDecode(s string) string {
	return pctRE.ReplaceAllStringFunc(s, func(m string) string {
		v, _ := strconv.ParseUint(m[1:], 16, 8)
		return string([]byte{byte(v)})
	})
}

func placeholderAddr(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range placeholderNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Scan returns one message per non-placeholder hostname, email address or IP
// address in text. extra reports normalised hosts the file is excused for;
// nil excuses none. It excuses hostnames only: an email address is never
// excused, not even at an allowlisted host (that is still a real address).
func Scan(text string, extra func(normalised string) bool) []string {
	var hits []string
	seen := map[string]bool{}
	for n, line := range strings.Split(text, "\n") {
		report := func(kind, what string, decoded bool) {
			msg := fmt.Sprintf("line %d: %s %s", n+1, kind, what)
			if decoded {
				msg += " (after percent-decoding)"
			}
			if !seen[msg] {
				seen[msg] = true
				hits = append(hits, msg)
			}
		}
		views := []string{dotFold.Replace(line)}
		if d := decode(line); d != line {
			views = append(views, dotFold.Replace(d))
			// A decoded CR, LF or TAB inside a label is dropped by a URL
			// parser, so the host it split is judged joined as well.
			if j := breaksRE.ReplaceAllString(d, ""); j != d {
				views = append(views, dotFold.Replace(j))
			}
		}
		for i, v := range views {
			dec := i > 0
			for _, m := range emailRE.FindAllStringSubmatch(v, -1) {
				if !placeholderEmailDomain(m[1]) {
					report("email", m[0], dec)
				}
			}
			for _, tok := range tokenRE.FindAllString(v, -1) {
				if hostLike(strings.TrimRight(tok, ".")) && !HostAllowed(tok, extra) {
					report("hostname", tok, dec)
				}
			}
			for _, s := range ip4RE.FindAllString(v, -1) {
				if a, err := netip.ParseAddr(s); err == nil && !placeholderAddr(a) {
					report("IPv4 address", s, dec)
				}
			}
			for _, s := range ip6RE.FindAllString(v, -1) {
				a, err := netip.ParseAddr(strings.Trim(s, "."))
				if err != nil || !strings.Contains(s, ":") {
					continue
				}
				if !placeholderAddr(a) {
					report("IPv6 address", s, dec)
				}
			}
		}
	}
	return hits
}
