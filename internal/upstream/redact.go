package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
)

// Redacted replaces the upstream token wherever it would otherwise escape
// this package: error text, log lines, and copies of response bodies.
const Redacted = "[redacted]"

// redactor replaces every encoding of one secret string.
type redactor struct {
	forms []string // longest first
}

func newRedactor(secret string) *redactor {
	set := map[string]bool{}
	add := func(s string) {
		if s != "" {
			set[s] = true
		}
	}
	add(secret)
	add(url.QueryEscape(secret))
	add(url.PathEscape(secret))
	if b, err := json.Marshal(secret); err == nil && len(b) >= 2 {
		add(string(b[1 : len(b)-1]))
	}
	// json.Marshal escapes <, >, & as \u003c etc.; encoders that do not
	// escape them are covered by the plain form above.
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
	return &redactor{forms: forms}
}

// String redacts s.
func (r *redactor) String(s string) string {
	for _, f := range r.forms {
		if strings.Contains(s, f) {
			s = strings.ReplaceAll(s, f, Redacted)
		}
	}
	return s
}

// Value returns v with every string, and every object key, redacted. v is a
// decoded JSON value (maps, slices, strings, numbers, bools, nil); the input
// is not modified.
func (r *redactor) Value(v any) any {
	switch x := v.(type) {
	case string:
		return r.String(x)
	case map[string]any:
		return r.Object(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = r.Value(e)
		}
		return out
	}
	return v
}

// Object is Value for a JSON object.
func (r *redactor) Object(o map[string]any) map[string]any {
	if o == nil {
		return nil
	}
	out := make(map[string]any, len(o))
	for k, v := range o {
		out[r.String(k)] = r.Value(v)
	}
	return out
}

// Bytes redacts b, returning b itself when nothing needed replacing.
func (r *redactor) Bytes(b []byte) []byte {
	s := string(b)
	if out := r.String(s); out != s {
		return []byte(out)
	}
	return b
}

// handler wraps a slog.Handler so that no record leaving the client
// carries the secret, whatever the attribute kind.
func (r *redactor) handler(next slog.Handler) slog.Handler {
	return &redactHandler{next: next, r: r}
}

type redactHandler struct {
	next slog.Handler
	r    *redactor
}

func (h *redactHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h *redactHandler) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, h.r.String(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.attr(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

func (h *redactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		red[i] = h.attr(a)
	}
	return &redactHandler{next: h.next.WithAttrs(red), r: h.r}
}

func (h *redactHandler) WithGroup(name string) slog.Handler {
	return &redactHandler{next: h.next.WithGroup(h.r.String(name)), r: h.r}
}

func (h *redactHandler) attr(a slog.Attr) slog.Attr {
	a.Key = h.r.String(a.Key)
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(h.r.String(v.String()))
	case slog.KindGroup:
		g := v.Group()
		red := make([]slog.Attr, len(g))
		for i, ga := range g {
			red[i] = h.attr(ga)
		}
		a.Value = slog.GroupValue(red...)
	case slog.KindAny:
		// Errors, Stringers and arbitrary values: log their redacted text.
		var text string
		if err, ok := v.Any().(error); ok {
			text = err.Error()
		} else {
			text = fmt.Sprint(v.Any())
		}
		a.Value = slog.StringValue(h.r.String(text))
	default:
		a.Value = v
	}
	return a
}
