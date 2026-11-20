package repocheck

import (
	"regexp"
	"sort"
	"strings"
)

// Go module paths start with the host of a code registry. Those hosts are
// not on the SPEC 15 list, and they are
// excused ONLY in that position: go.mod and go.sum are scanned with the
// leading `host/` of each module path removed, and Go import paths in .go
// files with the `host/` of a module that go.mod requires removed. Every
// other mention of a host in those files (a comment, a replace target, a
// second host on the line) is judged like any other text.

// moduleHostOK reports whether h may be excused as the host of a module
// path: a plain lower-case ASCII name with a dot that is either an allowed
// host itself, or is unrelated to the allowlist. A name that merely contains
// an allowed host, as a prefix, a subdomain or in the middle, and anything
// containing the vendor's name is never excused.
func moduleHostOK(h string) bool {
	if h == "" || !strings.Contains(h, ".") {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || strings.HasPrefix(l, "xn--") {
			return false
		}
	}
	if AllowedHosts[h] {
		return true
	}
	if strings.Contains(h, "firewalla") {
		return false
	}
	padded := "." + h + "."
	for a := range AllowedHosts {
		if strings.Contains(padded, "."+a+".") {
			return false
		}
	}
	return true
}

var fieldRE = regexp.MustCompile(`\S+`)

// modulePathHosts finds the module paths in go.mod or go.sum text and
// returns the [start, end) offset of each `host/` prefix (end is just past
// the slash). go.mod: any field of the code part of a line (before `//`)
// that starts with a valid host and a slash. go.sum: only the first field of
// a line, the module path.
func modulePathHosts(text string, goSum bool) (spans [][2]int) {
	off := 0
	for _, line := range strings.SplitAfter(text, "\n") {
		code := line
		if !goSum {
			if i := strings.Index(code, "//"); i >= 0 {
				code = code[:i]
			}
		}
		for i, loc := range fieldRE.FindAllStringIndex(code, -1) {
			if goSum && i > 0 {
				break
			}
			f := code[loc[0]:loc[1]]
			host, _, found := strings.Cut(f, "/")
			if found && moduleHostOK(host) {
				spans = append(spans, [2]int{off + loc[0], off + loc[0] + len(host) + 1})
			}
		}
		off += len(line)
	}
	return spans
}

// StripModulePaths returns the text of a go.mod (goSum false) or go.sum
// (goSum true) with the `host/` of every module path removed, ready for
// Scan with no allowance at all.
func StripModulePaths(text string, goSum bool) string {
	var b strings.Builder
	last := 0
	for _, s := range modulePathHosts(text, goSum) {
		b.WriteString(text[last:s[0]])
		last = s[1]
	}
	b.WriteString(text[last:])
	return b.String()
}

// ModuleHosts returns the sorted, de-duplicated hosts of the module paths in
// a go.mod (goSum false) or go.sum (goSum true) text.
func ModuleHosts(text string, goSum bool) []string {
	set := map[string]bool{}
	for _, s := range modulePathHosts(text, goSum) {
		set[text[s[0]:s[1]-1]] = true
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// StripImports removes `host/` from Go source text for each of hosts, but
// only where it starts a path: at the start of a line or after white space,
// a quote, a bracket or `=`. `customer.<host>/x`, `user@<host>/x` and
// `https://<host>/x` are left alone and are judged.
func StripImports(text string, hosts []string) string {
	if len(hosts) == 0 {
		return text
	}
	quoted := make([]string, len(hosts))
	for i, h := range hosts {
		quoted[i] = regexp.QuoteMeta(h)
	}
	re := regexp.MustCompile("(?m)(^|[\\s\"'`(<>=])(?:" + strings.Join(quoted, "|") + ")/")
	return re.ReplaceAllString(text, "$1")
}
