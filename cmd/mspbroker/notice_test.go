package main

import (
	"bytes"
	"strings"
	"testing"
)

// wantNotice is deliberately spelled out here, not taken from the code, so
// the test fails if the shipped text drifts.
const wantNotice = "Independent project; not affiliated with or endorsed by Firewalla Inc."

// hasLine reports whether text contains want as a complete line.
func hasLine(text, want string) bool {
	for _, l := range strings.Split(text, "\n") {
		if l == want {
			return true
		}
	}
	return false
}

func TestRootHelpPrintsNotice(t *testing.T) {
	for _, arg := range []string{"--help", "-h", "help"} {
		var out, errb bytes.Buffer
		if code := run([]string{arg}, &out, &errb, envOf(nil)); code != 0 {
			t.Fatalf("%s: exit %d", arg, code)
		}
		if !hasLine(out.String(), wantNotice) {
			t.Errorf("%s: notice missing from stdout: %q", arg, out.String())
		}
	}
	// The usage printed for a missing or unknown command carries it too.
	var out, errb bytes.Buffer
	run(nil, &out, &errb, envOf(nil))
	if !hasLine(errb.String(), wantNotice) {
		t.Errorf("no-args usage lacks the notice: %q", errb.String())
	}
}

// commandsListed returns the command names in the root usage text.
func commandsListed(t *testing.T) []string {
	t.Helper()
	var out, errb bytes.Buffer
	run([]string{"--help"}, &out, &errb, envOf(nil))
	var cmds []string
	for _, l := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(l, "  ") {
			if f := strings.Fields(l); len(f) > 0 {
				cmds = append(cmds, f[0])
			}
		}
	}
	return cmds
}

func TestEverySubcommandHelpPrintsNotice(t *testing.T) {
	cmds := commandsListed(t)
	// Guard the guard: the listing must at least know today's commands, so a
	// change to the usage layout cannot silently empty this test.
	for _, want := range []string{"serve", "mock-upstream", "version"} {
		found := false
		for _, c := range cmds {
			found = found || c == want
		}
		if !found {
			t.Fatalf("root usage does not list %q (got %v)", want, cmds)
		}
	}
	for _, cmd := range cmds {
		for _, flagName := range []string{"--help", "-h"} {
			var out, errb bytes.Buffer
			code := run([]string{cmd, flagName}, &out, &errb, envOf(nil))
			if code != 0 {
				t.Errorf("%s %s: exit %d", cmd, flagName, code)
			}
			if !hasLine(out.String()+errb.String(), wantNotice) {
				t.Errorf("%s %s: notice missing: stdout %q stderr %q", cmd, flagName, out.String(), errb.String())
			}
		}
	}
}

func TestVersionStillPrintsOnlyTheVersion(t *testing.T) {
	var out, errb bytes.Buffer
	run([]string{"version"}, &out, &errb, envOf(nil))
	if strings.Contains(out.String(), "Independent") || strings.Count(out.String(), "\n") != 1 {
		t.Errorf("version output changed: %q", out.String())
	}
}

func TestServeStartupLogPrintsNotice(t *testing.T) {
	_, upURL := newUpstream(t)
	g := startBroker(t, brokerEnv(upURL, t.TempDir()))
	log := g.errb.String()
	var found string
	for _, l := range strings.Split(log, "\n") {
		if strings.Contains(l, wantNotice) {
			found = l
			break
		}
	}
	if found == "" {
		t.Fatalf("notice missing from the startup log:\n%s", log)
	}
	if !strings.Contains(found, "level=INFO") || strings.Index(log, found) > strings.Index(log, "msg=serving") {
		t.Errorf("notice should be an INFO line logged before the serving line:\n%s", log)
	}
}
