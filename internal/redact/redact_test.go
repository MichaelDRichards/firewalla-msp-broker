package redact

import (
	"bytes"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	token  = "mg-test-CANARY-0000"
	secret = "mb_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG" // placeholder shape
)

func TestStringScrubsLiteralForms(t *testing.T) {
	s := New("tok en&\"x")
	for _, in := range []string{
		"tok en&\"x",
		url.QueryEscape("tok en&\"x"),
		url.PathEscape("tok en&\"x"),
		`tok en&\"x`,
		`tok en\u0026\"x`,
	} {
		got := s.String("before " + in + " after")
		if got != "before [redacted] after" {
			t.Errorf("%q -> %q", in, got)
		}
	}
	if got := New(token).String("clean text"); got != "clean text" {
		t.Errorf("clean text changed: %q", got)
	}
	if got := New("").String("abc"); got != "abc" {
		t.Errorf("empty literal changed text: %q", got)
	}
}

func TestStringScrubsBrokerSecrets(t *testing.T) {
	var zero *Scrubber
	cases := map[string]string{
		"Authorization: Bearer " + secret:    "Authorization: Bearer mb_[redacted]",
		"x=" + secret + "&y=1":               "x=mb_[redacted]&y=1",
		"truncated mb_0123456789abcdef rest": "truncated mb_[redacted] rest",
		"prefix only 01234567":               "prefix only 01234567",
		"short mb_abc stays":                 "short mb_abc stays",
	}
	for in, want := range cases {
		if got := zero.String(in); got != want {
			t.Errorf("nil scrubber %q -> %q, want %q", in, got, want)
		}
		if got := New(token).String(in); got != want {
			t.Errorf("scrubber %q -> %q, want %q", in, got, want)
		}
	}
}

func TestBytes(t *testing.T) {
	s := New(token)
	in := []byte(`{"a":"` + token + `"}`)
	if got := string(s.Bytes(in)); strings.Contains(got, token) {
		t.Errorf("not scrubbed: %s", got)
	}
	clean := []byte("clean")
	if got := s.Bytes(clean); &got[0] != &clean[0] {
		t.Error("clean input should be returned as is")
	}
}

type stringer struct{}

func (stringer) String() string { return "stringer holds " + token }

func TestHandlerCoversEveryAttrKind(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	log := slog.New(New(token).Handler(base)).With("pre", token).WithGroup("grp")
	log.Info("message "+token,
		"str", token,
		"err", errors.New("failed with "+token),
		"any", stringer{},
		slog.Group("g", slog.String("inner", secret)),
		"n", 42,
		"dur", time.Second,
		token+"-key", "v")
	out := buf.String()
	for _, bad := range []string{token, secret} {
		if strings.Contains(out, bad) {
			t.Errorf("log leaked %q: %s", bad, out)
		}
	}
	if !strings.Contains(out, `"n":42`) {
		t.Errorf("non-string attrs were damaged: %s", out)
	}
}

// Literals leaves broker-secret shapes alone: the response that creates a key
// must carry its secret.
func TestLiteralsLeaveBrokerSecretShapesAlone(t *testing.T) {
	s := New("tok-literal-1234")
	shaped := "mb_" + strings.Repeat("A", 40)
	in := "a tok-literal-1234 b " + shaped
	if got := s.Literals(in); got != "a [redacted] b "+shaped {
		t.Errorf("Literals = %q", got)
	}
	if got := string(s.LiteralBytes([]byte(shaped))); got != shaped {
		t.Errorf("LiteralBytes changed a broker-secret shape: %q", got)
	}
	if got := s.String(shaped); got == shaped {
		t.Error("String must still scrub broker-secret shapes")
	}
	var none *Scrubber
	if got := none.Literals("x"); got != "x" {
		t.Errorf("nil scrubber: %q", got)
	}
}
