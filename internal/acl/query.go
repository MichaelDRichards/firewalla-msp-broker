package acl

import (
	"fmt"
	"sort"
	"strings"
)

// The upstream `query` parameter (alarms, flows, rules) is a small search
// language: key:value terms, quoted phrases, implicit AND, OR, NOT / "-",
// and parentheses. The broker must make sure no caller-supplied `box.id`
// qualifier survives, and add its own box filter.
//
// Strategy, in layers:
//
//  1. Decode percent-escapes repeatedly until stable, so what the broker parses
//     is what upstream would see after any number of decodes.
//  2. Parse into a tree. Every `box.id` term (any case, quoted key, negated,
//     in OR groups or parentheses, comma lists, value groups) is checked
//     against scope: all values must be well-formed gids inside scope or the
//     whole query is rejected. In-scope qualifiers are removed.
//  3. Hard invariant: if the text that remains still contains "box.id" in any
//     case (parser confusion, quoted phrase, odd grammar), reject.
//  4. Append the broker's own filter, parenthesising the user's part when it has
//     a top-level OR so the filter binds as AND.
//
// The post-filter on responses remains the actual control; this is the
// optimisation plus defence in depth.

const (
	maxQueryLen      = 8192
	maxDecodeRounds  = 8
	maxGroupDepth    = 32
	boxIDKey         = "box.id"
	maxDetailValueSz = 80
)

// QueryError is a syntactically unusable query (HTTP 400).
type QueryError struct{ Detail string }

func (e *QueryError) Error() string { return "invalid query: " + e.Detail }

// ScopedQuery is the result of ScopeQuery.
type ScopedQuery struct {
	// Query is the caller's query with every box.id qualifier removed.
	Query string
	// Requested are the in-scope gids the caller asked for with positive
	// box.id qualifiers; Excluded are those it excluded. Both are sorted,
	// lowercase and de-duplicated. They only ever narrow the broker's filter.
	Requested []string
	Excluded  []string
	// GIDs are the boxes to query: Requested if any, else the whole scope,
	// minus Excluded. Nil when Unrestricted.
	GIDs []string
	// Unrestricted means the key's scope is All and the caller named no
	// box: no positive box filter is added (negative ones may be).
	Unrestricted bool
	// Empty means no box remains in scope: do not call upstream.
	Empty bool
	// Final is Query with the broker's own box filter appended. Empty when Empty.
	Final string
}

// ScopeQuery applies scope e to a caller-supplied upstream query. The error
// is a *Denial (code out_of_scope) when a box.id qualifier is outside scope
// or malformed, or a *QueryError when the query cannot be parsed.
func ScopeQuery(raw string, e *Effective) (*ScopedQuery, error) {
	if len(raw) > maxQueryLen {
		return nil, &QueryError{"query too long"}
	}
	q, err := decodeFully(raw)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(q); i++ {
		if c := q[i]; (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return nil, &QueryError{"query contains control characters"}
		}
	}

	p := &parser{s: q}
	root, err := p.parseGroup(0)
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.s) {
		return nil, &QueryError{"unbalanced parentheses"}
	}

	var requested, excluded []string
	if err := collect(root, false, e, &requested, &excluded); err != nil {
		return nil, err
	}
	requested, excluded = uniqSorted(requested), uniqSorted(excluded)

	stripped, hasOr := render(root, true)
	if strings.Contains(strings.ToLower(stripped), boxIDKey) {
		return nil, &Denial{CodeOutOfScope, "box.id must be a plain qualifier; it cannot appear in phrases or unusual syntax"}
	}

	res := &ScopedQuery{Query: stripped, Requested: requested, Excluded: excluded}
	exclSet := toSet(excluded)
	switch {
	case len(requested) > 0:
		res.GIDs = subtract(requested, exclSet)
	case e.All():
		res.Unrestricted = true
	default:
		res.GIDs = subtract(e.GIDs(), exclSet)
	}
	if !res.Unrestricted && len(res.GIDs) == 0 {
		res.Empty = true
		res.GIDs = []string{}
		return res, nil
	}

	var filter []string
	switch {
	case res.Unrestricted:
		for _, g := range excluded {
			filter = append(filter, "-"+boxIDKey+":"+g)
		}
	case len(res.GIDs) == 1:
		filter = append(filter, boxIDKey+":"+res.GIDs[0])
	default:
		terms := make([]string, len(res.GIDs))
		for i, g := range res.GIDs {
			terms[i] = boxIDKey + ":" + g
		}
		filter = append(filter, "("+strings.Join(terms, " OR ")+")")
	}
	f := strings.Join(filter, " ")
	switch {
	case stripped == "":
		res.Final = f
	case f == "":
		res.Final = stripped
	case hasOr:
		res.Final = "(" + stripped + ") " + f
	default:
		res.Final = stripped + " " + f
	}
	return res, nil
}

// decodeFully percent-decodes s repeatedly until it stops changing. Invalid
// escapes are left alone (they do not block decoding of valid ones).
func decodeFully(s string) (string, error) {
	for i := 0; i < maxDecodeRounds; i++ {
		d := decodeOnce(s)
		if d == s {
			return s, nil
		}
		s = d
	}
	return "", &QueryError{"query is encoded too many times"}
}

func decodeOnce(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, ok1 := unhex(s[i+1]); ok1 {
				if lo, ok2 := unhex(s[i+2]); ok2 {
					b.WriteByte(hi<<4 | lo)
					i += 2
					continue
				}
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// ---- tree ----

type node struct {
	neg   []string // "-", "!", "NOT "
	group []item   // non-nil for a parenthesised group
	isGrp bool
	raw   string // term text as written (without neg prefixes)
	key   string // lowercase key; "" for bare words and phrases
	// box-term value, set only when key == box.id
	valueRaw string
	valueGrp *node
}

type item struct {
	op   string // "", "AND" or "OR" joining this operand to the previous
	node *node
}

type parser struct {
	s   string
	pos int
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func (p *parser) skipSpace() {
	for p.pos < len(p.s) && isSpace(p.s[p.pos]) {
		p.pos++
	}
}

// peekWord returns the bare run at pos up to whitespace or a parenthesis.
func (p *parser) peekWord() string {
	i := p.pos
	for i < len(p.s) && !isSpace(p.s[i]) && p.s[i] != '(' && p.s[i] != ')' {
		i++
	}
	return p.s[p.pos:i]
}

// parseGroup parses operands until EOF or an unconsumed ')'.
func (p *parser) parseGroup(depth int) (*node, error) {
	if depth > maxGroupDepth {
		return nil, &QueryError{"query nested too deeply"}
	}
	g := &node{isGrp: true}
	pending := ""
	for {
		p.skipSpace()
		if p.pos >= len(p.s) {
			return g, nil
		}
		if p.s[p.pos] == ')' {
			if depth == 0 {
				return nil, &QueryError{"unbalanced parentheses"}
			}
			return g, nil
		}
		// Operators, only between operands.
		if w := p.peekWord(); len(g.group) > 0 && pending == "" && (strings.EqualFold(w, "OR") || strings.EqualFold(w, "AND")) {
			pending = strings.ToUpper(w)
			p.pos += len(w)
			continue
		}
		// Negation prefixes.
		var neg []string
		for {
			if p.pos >= len(p.s) {
				break
			}
			c := p.s[p.pos]
			if (c == '-' || c == '!') && p.pos+1 < len(p.s) && !isSpace(p.s[p.pos+1]) && p.s[p.pos+1] != ')' {
				neg = append(neg, string(c))
				p.pos++
				continue
			}
			if w := p.peekWord(); strings.EqualFold(w, "NOT") {
				end := p.pos + len(w)
				if end < len(p.s) && (isSpace(p.s[end]) || p.s[end] == '(') {
					rest := strings.TrimLeft(p.s[end:], " \t\r\n")
					if rest != "" && rest[0] != ')' {
						neg = append(neg, "NOT ")
						p.pos = end
						p.skipSpace()
						continue
					}
				}
			}
			break
		}
		if p.pos >= len(p.s) || p.s[p.pos] == ')' {
			// Prefixes with nothing to apply to cannot happen (guarded above).
			return nil, &QueryError{"dangling negation"}
		}
		var n *node
		if p.s[p.pos] == '(' {
			p.pos++
			inner, err := p.parseGroup(depth + 1)
			if err != nil {
				return nil, err
			}
			if p.pos >= len(p.s) || p.s[p.pos] != ')' {
				return nil, &QueryError{"unbalanced parentheses"}
			}
			p.pos++
			n = inner
		} else {
			t, err := p.parseTerm(depth)
			if err != nil {
				return nil, err
			}
			n = t
		}
		n.neg = neg
		g.group = append(g.group, item{op: pending, node: n})
		pending = ""
	}
}

// readQuoted reads a quoted string starting at pos (the quote char) and
// returns its content and leaves pos after the closing quote.
func (p *parser) readQuoted() (string, error) {
	q := p.s[p.pos]
	i := p.pos + 1
	var b strings.Builder
	for i < len(p.s) {
		c := p.s[i]
		if c == '\\' && i+1 < len(p.s) {
			b.WriteByte(p.s[i+1])
			i += 2
			continue
		}
		if c == q {
			p.pos = i + 1
			return b.String(), nil
		}
		b.WriteByte(c)
		i++
	}
	return "", &QueryError{"unterminated quote"}
}

func (p *parser) parseTerm(depth int) (*node, error) {
	start := p.pos
	n := &node{}
	var key string

	if c := p.s[p.pos]; c == '"' || c == '\'' {
		content, err := p.readQuoted()
		if err != nil {
			return nil, err
		}
		if p.pos < len(p.s) && p.s[p.pos] == ':' {
			key = content
			p.pos++
		} else {
			n.raw = p.s[start:p.pos]
			return n, nil
		}
	} else {
		i := p.pos
		for i < len(p.s) && !isSpace(p.s[i]) && p.s[i] != '(' && p.s[i] != ')' && p.s[i] != ':' {
			i++
		}
		if i < len(p.s) && p.s[i] == ':' {
			key = p.s[p.pos:i]
			p.pos = i + 1
		} else {
			p.pos = i
			n.raw = p.s[start:p.pos]
			return n, nil
		}
	}

	// key:value
	n.key = strings.ToLower(strings.TrimSpace(key))
	vstart := p.pos
	switch {
	case p.pos >= len(p.s) || isSpace(p.s[p.pos]) || p.s[p.pos] == ')':
		// empty value
	case p.s[p.pos] == '"' || p.s[p.pos] == '\'':
		if _, err := p.readQuoted(); err != nil {
			return nil, err
		}
	case p.s[p.pos] == '(':
		p.pos++
		inner, err := p.parseGroup(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.pos >= len(p.s) || p.s[p.pos] != ')' {
			return nil, &QueryError{"unbalanced parentheses"}
		}
		p.pos++
		n.valueGrp = inner
	default:
		for p.pos < len(p.s) && !isSpace(p.s[p.pos]) && p.s[p.pos] != ')' {
			p.pos++
		}
	}
	n.valueRaw = p.s[vstart:p.pos]
	n.raw = p.s[start:p.pos]
	return n, nil
}

// ---- box.id handling ----

// collect walks the tree, validating every box.id term against scope and
// recording requested / excluded gids. parity is true inside an odd number
// of negations.
func collect(n *node, parity bool, e *Effective, req, excl *[]string) error {
	if len(n.neg)%2 == 1 {
		parity = !parity
	}
	if n.isGrp {
		for _, it := range n.group {
			if err := collect(it.node, parity, e, req, excl); err != nil {
				return err
			}
		}
		return nil
	}
	if n.key != boxIDKey {
		return nil
	}
	vals, err := boxValues(n)
	if err != nil {
		return err
	}
	for _, v := range vals {
		if !ValidGID(v) {
			return &Denial{CodeOutOfScope, fmt.Sprintf("box.id value %q is not a valid box id", clip(v))}
		}
		if !e.Contains(v) {
			return &Denial{CodeOutOfScope, fmt.Sprintf("box %s is outside this key's scope", clip(v))}
		}
		if parity {
			*excl = append(*excl, strings.ToLower(v))
		} else {
			*req = append(*req, strings.ToLower(v))
		}
	}
	return nil
}

func clip(s string) string {
	if len(s) > maxDetailValueSz {
		return s[:maxDetailValueSz] + "..."
	}
	return s
}

// boxValues extracts the comma/OR separated values of a box.id term.
func boxValues(n *node) ([]string, error) {
	var raws []string
	switch {
	case n.valueGrp != nil:
		for _, it := range n.valueGrp.group {
			c := it.node
			if c.isGrp || c.key != "" || len(c.neg) > 0 {
				return nil, &QueryError{"unsupported box.id value syntax"}
			}
			raws = append(raws, c.raw)
		}
	default:
		raws = append(raws, n.valueRaw)
	}
	var out []string
	for _, r := range raws {
		r = strings.TrimSpace(r)
		if len(r) >= 2 && (r[0] == '"' || r[0] == '\'') && r[len(r)-1] == r[0] {
			r = r[1 : len(r)-1]
		}
		for _, v := range strings.Split(r, ",") {
			v = strings.TrimSpace(v)
			if v == "" {
				return nil, &QueryError{"box.id needs a value"}
			}
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, &QueryError{"box.id needs a value"}
	}
	return out, nil
}

// render writes the tree back to text without box.id terms. Operators next
// to a removed operand go with it; groups that become empty disappear. The
// bool reports whether the top level (root only) joins operands with OR.
func render(n *node, root bool) (string, bool) {
	if !n.isGrp {
		if n.key == boxIDKey {
			return "", false
		}
		return strings.Join(n.neg, "") + n.raw, false
	}
	var b strings.Builder
	hasOr := false
	printed := 0
	for _, it := range n.group {
		s, _ := render(it.node, false)
		if s == "" {
			continue
		}
		if printed > 0 {
			switch it.op {
			case "OR":
				b.WriteString(" OR ")
				hasOr = true
			case "AND":
				b.WriteString(" AND ")
			default:
				b.WriteByte(' ')
			}
		}
		b.WriteString(s)
		printed++
	}
	inner := b.String()
	if root {
		return inner, hasOr
	}
	if inner == "" {
		return "", false
	}
	return strings.Join(n.neg, "") + "(" + inner + ")", hasOr
}

// ---- small helpers ----

func uniqSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := toSet(in)
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func toSet(in []string) map[string]struct{} {
	m := make(map[string]struct{}, len(in))
	for _, s := range in {
		m[s] = struct{}{}
	}
	return m
}

func subtract(in []string, drop map[string]struct{}) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, d := drop[s]; !d {
			out = append(out, s)
		}
	}
	return out
}
