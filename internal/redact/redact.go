// Package redact scrubs secrets out of text on its way to logs and the audit
// table. It is a last line of defence: the code that handles secrets is
// meant to never pass them on, and this package catches what slips through.
//
// Two kinds of secret are covered: broker key secrets, recognised by shape
// ("mb_" followed by a long base62 run), and literal strings handed to New
// (the upstream token), in plain, URL-escaped and JSON-escaped forms.
package redact

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Placeholders that replace secrets.
const (
	Redacted       = "[redacted]"
	RedactedSecret = "mb_[redacted]"
)

// brokerSecret matches a key secret or a truncated/mangled copy of one. The
// 8-character prefix that identifies a key in logs is stored without "mb_",
// so it never matches.
var brokerSecret = regexp.MustCompile(`mb_[0-9A-Za-z]{16,}`)

// Scrubber replaces secrets in strings. The zero value scrubs broker secrets
// only. It is safe for concurrent use.
type Scrubber struct {
	forms []string // literal forms, longest first
}

// New returns a Scrubber that also replaces each non-empty literal.
func New(literals ...string) *Scrubber {
	set := map[string]bool{}
	add := func(s string) {
		if s != "" {
			set[s] = true
		}
	}
	for _, lit := range literals {
		add(lit)
		add(url.QueryEscape(lit))
		add(url.PathEscape(lit))
		if b, err := json.Marshal(lit); err == nil && len(b) >= 2 {
			add(string(b[1 : len(b)-1]))
		}
		// Encoders that do not HTML-escape (<, >, &) produce another form.
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(lit); err == nil {
			if b := bytes.TrimSpace(buf.Bytes()); len(b) >= 2 {
				add(string(b[1 : len(b)-1]))
			}
		}
	}
	forms := make([]string, 0, len(set))
	for f := range set {
		forms = append(forms, f)
	}
	sort.Slice(forms, func(i, j int) bool {
		if len(forms[i]) != len(forms[j]) {
			return len(forms[i]) > len(forms[j])
		}
		return forms[i] < forms[j]
	})
	return &Scrubber{forms: forms}
}

// String scrubs s: the literals, then anything shaped like a broker secret.
func (s *Scrubber) String(in string) string {
	in = s.Literals(in)
	if strings.Contains(in, "mb_") {
		in = brokerSecret.ReplaceAllString(in, RedactedSecret)
	}
	return in
}

// Literals replaces only the literal secrets given to New, leaving anything
// merely shaped like a broker secret alone. It is for text that may
// legitimately carry a freshly issued key secret, such as the response that
// creates a key.
func (s *Scrubber) Literals(in string) string {
	if s != nil {
		for _, f := range s.forms {
			if strings.Contains(in, f) {
				in = strings.ReplaceAll(in, f, Redacted)
			}
		}
	}
	return in
}

// LiteralBytes is Literals for bytes, returning b itself when unchanged.
func (s *Scrubber) LiteralBytes(b []byte) []byte {
	in := string(b)
	if out := s.Literals(in); out != in {
		return []byte(out)
	}
	return b
}

// Bytes scrubs b, returning b itself when nothing changed.
func (s *Scrubber) Bytes(b []byte) []byte {
	in := string(b)
	if out := s.String(in); out != in {
		return []byte(out)
	}
	return b
}

// Handler wraps next so that no record carries a secret, whatever the
// attribute kind.
func (s *Scrubber) Handler(next slog.Handler) slog.Handler {
	return &handler{next: next, s: s}
}

type handler struct {
	next slog.Handler
	s    *Scrubber
}

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool { return h.next.Enabled(ctx, l) }

func (h *handler) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, h.s.String(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.attr(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		red[i] = h.attr(a)
	}
	return &handler{next: h.next.WithAttrs(red), s: h.s}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{next: h.next.WithGroup(h.s.String(name)), s: h.s}
}

func (h *handler) attr(a slog.Attr) slog.Attr {
	a.Key = h.s.String(a.Key)
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(h.s.String(v.String()))
	case slog.KindGroup:
		g := v.Group()
		red := make([]slog.Attr, len(g))
		for i, ga := range g {
			red[i] = h.attr(ga)
		}
		a.Value = slog.GroupValue(red...)
	case slog.KindAny:
		var text string
		if err, ok := v.Any().(error); ok {
			text = err.Error()
		} else {
			text = fmt.Sprint(v.Any())
		}
		a.Value = slog.StringValue(h.s.String(text))
	default:
		a.Value = v
	}
	return a
}
