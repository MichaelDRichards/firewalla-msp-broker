package mock

import (
	"encoding/json"
	"fmt"
	"strings"
)

// The mock understands a small subset of the upstream `query` language:
// key:value terms, quoted phrases, implicit AND, AND, OR, NOT / "-" / "!",
// parentheses, comma lists and parenthesised value groups. `box.id:` matches
// an object's gid. Any other key is looked up by dotted path in the object
// and compared case-insensitively (with `*` wildcards). A bare word or
// phrase matches as a case-insensitive substring of the object's JSON.
//
// This is the mock's own reading of the documented syntax, not a statement
// about the real service (see docs/UPSTREAM-NOTES.md).

type matcher func(obj map[string]any) bool

func matchAll(map[string]any) bool { return true }

const maxQueryDepth = 32

// parseQuery compiles q. An empty query matches everything.
func parseQuery(q string) (matcher, error) {
	p := &qparser{s: q}
	m, err := p.or(0)
	if err != nil {
		return nil, err
	}
	p.skip()
	if p.i < len(p.s) {
		return nil, fmt.Errorf("unexpected %q at position %d", p.s[p.i], p.i)
	}
	return m, nil
}

type qparser struct {
	s string
	i int
}

func isSp(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func (p *qparser) skip() {
	for p.i < len(p.s) && isSp(p.s[p.i]) {
		p.i++
	}
}

// word returns the bare run at the cursor up to whitespace or a parenthesis.
func (p *qparser) word() string {
	j := p.i
	for j < len(p.s) && !isSp(p.s[j]) && p.s[j] != '(' && p.s[j] != ')' {
		j++
	}
	return p.s[p.i:j]
}

func (p *qparser) keyword(kw string) bool {
	p.skip()
	if w := p.word(); strings.EqualFold(w, kw) {
		p.i += len(w)
		return true
	}
	return false
}

func (p *qparser) or(depth int) (matcher, error) {
	if depth > maxQueryDepth {
		return nil, fmt.Errorf("query nested too deeply")
	}
	left, err := p.and(depth)
	if err != nil {
		return nil, err
	}
	for p.keyword("OR") {
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] == ')' {
			return nil, fmt.Errorf("dangling OR")
		}
		right, err := p.and(depth)
		if err != nil {
			return nil, err
		}
		l, r := left, right
		left = func(o map[string]any) bool { return l(o) || r(o) }
	}
	return left, nil
}

func (p *qparser) and(depth int) (matcher, error) {
	var ops []matcher
	for {
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] == ')' {
			break
		}
		if strings.EqualFold(p.word(), "OR") {
			break
		}
		if len(ops) > 0 {
			p.keyword("AND")
			p.skip()
			if p.i >= len(p.s) || p.s[p.i] == ')' {
				return nil, fmt.Errorf("dangling AND")
			}
		}
		m, err := p.unary(depth)
		if err != nil {
			return nil, err
		}
		ops = append(ops, m)
	}
	if len(ops) == 0 {
		return matchAll, nil
	}
	return func(o map[string]any) bool {
		for _, m := range ops {
			if !m(o) {
				return false
			}
		}
		return true
	}, nil
}

func (p *qparser) unary(depth int) (matcher, error) {
	p.skip()
	neg := false
	for p.i < len(p.s) {
		c := p.s[p.i]
		if (c == '-' || c == '!') && p.i+1 < len(p.s) && !isSp(p.s[p.i+1]) && p.s[p.i+1] != ')' {
			neg = !neg
			p.i++
			continue
		}
		if w := p.word(); strings.EqualFold(w, "NOT") && p.i+len(w) < len(p.s) && (isSp(p.s[p.i+len(w)]) || p.s[p.i+len(w)] == '(') {
			neg = !neg
			p.i += len(w)
			p.skip()
			continue
		}
		break
	}
	if p.i >= len(p.s) || p.s[p.i] == ')' {
		return nil, fmt.Errorf("dangling negation")
	}
	var m matcher
	if p.s[p.i] == '(' {
		p.i++
		inner, err := p.or(depth + 1)
		if err != nil {
			return nil, err
		}
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != ')' {
			return nil, fmt.Errorf("unbalanced parentheses")
		}
		p.i++
		m = inner
	} else {
		t, err := p.term()
		if err != nil {
			return nil, err
		}
		m = t
	}
	if neg {
		inner := m
		return func(o map[string]any) bool { return !inner(o) }, nil
	}
	return m, nil
}

func (p *qparser) quoted() (string, error) {
	q := p.s[p.i]
	var b strings.Builder
	for j := p.i + 1; j < len(p.s); j++ {
		c := p.s[j]
		if c == '\\' && j+1 < len(p.s) {
			j++
			b.WriteByte(p.s[j])
			continue
		}
		if c == q {
			p.i = j + 1
			return b.String(), nil
		}
		b.WriteByte(c)
	}
	return "", fmt.Errorf("unterminated quote")
}

func (p *qparser) term() (matcher, error) {
	var key string
	if c := p.s[p.i]; c == '"' || c == '\'' {
		content, err := p.quoted()
		if err != nil {
			return nil, err
		}
		if p.i < len(p.s) && p.s[p.i] == ':' {
			key = content
			p.i++
		} else {
			return substring(content), nil
		}
	} else {
		j := p.i
		for j < len(p.s) && !isSp(p.s[j]) && p.s[j] != '(' && p.s[j] != ')' && p.s[j] != ':' {
			j++
		}
		if j >= len(p.s) || p.s[j] != ':' {
			w := p.s[p.i:j]
			p.i = j
			return substring(w), nil
		}
		key = p.s[p.i:j]
		p.i = j + 1
	}
	key = strings.ToLower(strings.TrimSpace(key))
	vals, err := p.values()
	if err != nil {
		return nil, err
	}
	if key == "" || len(vals) == 0 {
		return nil, fmt.Errorf("term %q needs a key and a value", key)
	}
	return func(o map[string]any) bool {
		for _, v := range vals {
			if fieldMatches(o, key, v) {
				return true
			}
		}
		return false
	}, nil
}

// values reads the value of a key:value term: a bare or quoted value (commas
// separate alternatives) or a parenthesised list of alternatives.
func (p *qparser) values() ([]string, error) {
	if p.i >= len(p.s) || isSp(p.s[p.i]) || p.s[p.i] == ')' {
		return nil, nil
	}
	switch c := p.s[p.i]; {
	case c == '"' || c == '\'':
		v, err := p.quoted()
		if err != nil {
			return nil, err
		}
		return []string{v}, nil
	case c == '(':
		end := strings.IndexByte(p.s[p.i:], ')')
		if end < 0 {
			return nil, fmt.Errorf("unbalanced parentheses")
		}
		inner := p.s[p.i+1 : p.i+end]
		p.i += end + 1
		var out []string
		for _, f := range strings.Fields(strings.ReplaceAll(inner, ",", " ")) {
			if strings.EqualFold(f, "OR") {
				continue
			}
			out = append(out, f)
		}
		return out, nil
	}
	j := p.i
	for j < len(p.s) && !isSp(p.s[j]) && p.s[j] != ')' {
		j++
	}
	raw := p.s[p.i:j]
	p.i = j
	var out []string
	for _, v := range strings.Split(raw, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out, nil
}

func substring(needle string) matcher {
	needle = strings.ToLower(needle)
	return func(o map[string]any) bool {
		b, err := json.Marshal(o)
		return err == nil && strings.Contains(strings.ToLower(string(b)), needle)
	}
}

// fieldMatches compares the value at a dotted path with want. "box.id"
// is an alias for the object's gid.
func fieldMatches(o map[string]any, key, want string) bool {
	var got any
	if key == "box.id" {
		got = o["gid"]
	} else {
		got = lookup(o, key)
	}
	if got == nil {
		return false
	}
	if list, ok := got.([]any); ok {
		for _, e := range list {
			if globEqual(want, fmt.Sprint(e)) {
				return true
			}
		}
		return false
	}
	return globEqual(want, fmt.Sprint(got))
}

func lookup(o map[string]any, path string) any {
	var cur any = o
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		next, found := m[part]
		if !found {
			// keys in the mock are lower camel case; compare ignoring case.
			for k, v := range m {
				if strings.EqualFold(k, part) {
					next, found = v, true
					break
				}
			}
		}
		if !found {
			return nil
		}
		cur = next
	}
	return cur
}

// globEqual compares case-insensitively; `*` in pattern matches any run.
func globEqual(pattern, s string) bool {
	pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, mid := range parts[1 : len(parts)-1] {
		idx := strings.Index(s, mid)
		if idx < 0 {
			return false
		}
		s = s[idx+len(mid):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}
