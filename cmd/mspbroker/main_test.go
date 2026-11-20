package main

import (
	"bytes"
	"strings"
	"testing"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb, envOf(nil)); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(out.String(), "mspbroker ") {
		t.Errorf("output %q", out.String())
	}
}

func TestUsageAndUnknown(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb, envOf(nil)); code != 2 {
		t.Errorf("no args: exit %d", code)
	}
	if code := run([]string{"bogus"}, &out, &errb, envOf(nil)); code != 2 || !strings.Contains(errb.String(), "unknown command") {
		t.Errorf("unknown: exit %d %q", code, errb.String())
	}
	out.Reset()
	if code := run([]string{"help"}, &out, &errb, envOf(nil)); code != 0 || !strings.Contains(out.String(), "serve") {
		t.Errorf("help: exit %d", code)
	}
}

func TestServeBadConfigViaRun(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"serve"}, &out, &errb, envOf(nil)); code != 1 || !strings.Contains(errb.String(), "MSP_BASE_URL") {
		t.Errorf("bad config: exit %d %q", code, errb.String())
	}
	if strings.Contains(out.String(), "listening") {
		t.Error("serve started with a bad config")
	}
}
