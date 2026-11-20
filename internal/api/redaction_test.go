package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"mspbroker/internal/acl"
	"mspbroker/internal/upstream/mock"
)

// failingTransport fails every upstream call with an error that echoes the
// Authorization header, as a careless HTTP stack might.
type failingTransport struct{}

func (failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, errors.New("dial failed for request carrying " + r.Header.Get("Authorization") + " to " + r.URL.String())
}

// The canary upstream token must appear in no log line, no audit row (the
// whole database is scanned), and no response body, error bodies and
// upstream-error paths included; key secrets must appear in none of those
// either, apart from the single response that creates them.
func TestRedaction(t *testing.T) {
	modes := []struct {
		name string
		opts []hopt
	}{
		{"default", nil},
		// The broker's own logger and audit recorder are told nothing about the
		// upstream token: only the client's redaction and the code paths
		// themselves keep it out.
		{"strict", []hopt{withStrictScrub()}},
		{"strict, upstream ignores filters", []hopt{withStrictScrub(), withIgnoreFilters(), withTTL(0)}},
		{"strict, transport errors echo the token", []hopt{withStrictScrub(), withTransport(failingTransport{})}},
	}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			h := newHarness(t, m.opts...)
			secrets := exerciseEverything(t, h, strings.Contains(m.name, "transport"))
			assertNoLeaks(t, h, secrets, !strings.Contains(m.name, "transport"))
		})
	}
}

// Faults whose bodies echo the token in many shapes.
var echoFaults = []mock.Fault{
	{Status: 400, Body: `{"error":"bad request for token ` + upstreamCanary + `","message":"Bearer ` + upstreamCanary + `"}`},
	{Status: 401, Body: `{"error":"invalid token ` + upstreamCanary + `"}`},
	{Status: 403, Body: `Forbidden for ` + upstreamCanary},
	{Status: 404, Body: `{"message":"` + upstreamCanary + ` not found"}`},
	{Status: 429, RetryAfter: "3", Body: `{"error":"slow down ` + upstreamCanary + `"}`},
	{Status: 500, Body: `<html><body>` + upstreamCanary + `</body></html>`},
	{Status: 502, Body: strings.Repeat("x", 1000) + upstreamCanary},
	{Status: 200, Body: `<html>` + upstreamCanary + `</html>`},
	{Status: 200, Body: `{"results":[{"gid":"` + mock.GID1 + `","message":"` + upstreamCanary + `"}]}`},
	{Status: 200, Body: `[{"gid":"` + mock.GID1 + `","name":"` + upstreamCanary + `"}]`},
}

func exerciseEverything(t *testing.T, h *harness, transportBroken bool) (secrets []string) {
	t.Helper()
	// Plant the canary in upstream data: it is echoed to the broker in good
	// responses too.
	h.mock.Update(func(s *mock.State) {
		s.Boxes[0]["name"] = "Box " + upstreamCanary
		s.Alarms[0]["message"] = "alarm " + upstreamCanary
		s.Rules[0]["note"] = upstreamCanary
		s.TargetLists[0]["name"] = upstreamCanary
		s.Flows[0]["domain"] = upstreamCanary
	})

	_, admin := h.adminKey("redaction-admin")
	secrets = append(secrets, admin)
	create := func(name string, scope acl.Scope) string {
		r := h.do(admin, "POST", "/admin/v1/keys", j(kv{
			"name": name, "kind": "data", "scope": scope,
			"permissions": kv{"boxes": "read", "devices": "read", "alarms": "read", "rules": "read", "flows": "read", "target_lists": "read", "global_target_lists": "read"},
		}))
		if r.status != 201 {
			t.Fatalf("create %s: %d %s", name, r.status, r.body)
		}
		s := r.obj(t)["secret"].(string)
		secrets = append(secrets, s)
		return s
	}
	keys := []string{
		create("red-explicit", scopeExplicit),
		create("red-group", scopeGroupA),
		create("red-all", scopeAll),
	}

	dataPaths := []string{
		"/api/v1/me", "/api/v1/boxes", "/api/v1/boxes/" + mock.GID1, "/api/v1/boxes/" + mock.GID1 + "/devices",
		"/api/v1/alarms", "/api/v1/boxes/" + mock.GID1 + "/alarms", "/api/v1/boxes/" + mock.GID1 + "/alarms/11",
		"/api/v1/rules", "/api/v1/boxes/" + mock.GID1 + "/rules", "/api/v1/flows", "/api/v1/boxes/" + mock.GID1 + "/flows",
		"/api/v1/target-lists", "/api/v1/target-lists/tl-1", "/api/v1/target-lists/tl-global-1", "/api/v1/target-lists?owner=global",
	}
	adminPaths := []string{"/admin/v1/boxes", "/admin/v1/keys", "/admin/v1/audit", "/admin/v1/audit/1"}

	// Good traffic with the planted echoes.
	for _, k := range keys {
		for _, p := range dataPaths {
			h.get(k, p)
		}
	}
	for _, p := range adminPaths {
		h.get(admin, p)
	}

	// Upstream failures with echoing bodies, on every endpoint family.
	for _, f := range echoFaults {
		for _, k := range keys {
			for _, p := range dataPaths {
				h.mock.InjectFault(f)
				h.get(k, p)
			}
		}
		for _, p := range adminPaths {
			h.mock.InjectFault(f)
			h.get(admin, p)
		}
		h.mock.InjectFault(f)
		h.get("", "/readyz")
		h.clk.advance(60e9)
	}
	h.mock.ClearFaults()

	// Hostile requests that carry broker secrets in places they do not belong.
	k := keys[0]
	for _, tc := range []struct{ secret, method, path string }{
		{"", "GET", "/api/v1/boxes/" + k + "/devices"},
		{keys[0], "GET", "/api/v1/alarms?query=" + q("box.id:"+k)},
		{keys[0], "GET", "/api/v1/alarms?query=" + q(k+" type:1")},
		{keys[0], "GET", "/api/v1/alarms?cursor=" + k},
		{keys[0], "GET", "/api/v1/target-lists/" + k},
		{keys[0], "GET", "/api/v1/target-lists?owner=" + k},
		{keys[0], "GET", "/api/v1/boxes/" + mock.GID1 + "/alarms/" + k},
		{keys[0], "GET", "/" + k},
		{keys[0], "POST", "/api/v1/boxes?token=" + k},
		{k, "GET", "/api/v1/" + k},
		{admin, "GET", "/admin/v1/keys/" + k},
		{admin, "GET", "/admin/v1/audit?key_id=" + k},
		{admin, "GET", "/admin/v1/audit?gid=" + k},
	} {
		h.do(tc.secret, tc.method, tc.path)
	}
	h.do("", "GET", "/api/v1/boxes", withHeader("Authorization", "Bearer "+k+" extra"))
	h.do("", "GET", "/api/v1/boxes", withHeader("Authorization", "Bearer "+k+"x"))
	h.do("", "GET", "/api/v1/boxes", withHeader("Authorization", "Bearer "+k[:20]))
	h.do("", "GET", "/api/v1/boxes", withHeader("Authorization", "Token "+k))
	h.do("", "GET", "/api/v1/boxes", withHeader("X-Forwarded-For", k))
	h.do(admin, "POST", "/admin/v1/keys", withBody(`{"name":"`+k+`","kind":"data","scope":{"type":"all"},"secret":"`+k+`"}`))
	h.do(admin, "PATCH", "/admin/v1/keys/"+k, withBody(`{"name":"`+k+`"}`))
	h.do(admin, "POST", "/admin/v1/keys", withBody(`{"name":"x","kind":"`+upstreamCanary+`"}`))
	return secrets
}

func assertNoLeaks(t *testing.T, h *harness, secrets []string, upstreamReachable bool) {
	t.Helper()
	logs := h.logs.String()
	dump := h.dump()
	if len(logs) < 2000 {
		t.Fatalf("suspiciously little log output (%d bytes): the scan proves nothing", len(logs))
	}
	if len(h.auditRows()) < 100 {
		t.Fatalf("only %d audit rows: the scan proves nothing", len(h.auditRows()))
	}
	// The canary really was in play: the mock saw it as a valid token.
	authed := 0
	for _, r := range h.mock.Requests() {
		if r.Authenticated {
			authed++
		}
	}
	if upstreamReachable && authed == 0 {
		t.Fatal("the upstream never accepted the canary token")
	}

	// Forms in which the canary or a secret could appear.
	needles := map[string]string{"canary": upstreamCanary, "canary lower": strings.ToLower(upstreamCanary)}
	for i, s := range secrets {
		needles[fmt.Sprintf("secret %d", i)] = s
		needles[fmt.Sprintf("secret %d body", i)] = s[3:]
	}
	where := map[string]string{"logs": logs, "database dump": dump}
	for name, hay := range where {
		for what, n := range needles {
			if strings.Contains(hay, n) {
				t.Errorf("%s contain the %s", name, what)
			}
		}
	}

	// Response bodies. A created key's secret appears in exactly the response
	// that created it, and nowhere else.
	created := map[string]int{}
	for i, b := range h.bodies {
		body := string(b)
		for what, n := range needles {
			if !strings.Contains(body, n) {
				continue
			}
			if strings.HasPrefix(what, "secret") && !strings.HasSuffix(what, "body") && strings.Contains(body, `"secret"`) && strings.Contains(body, `"id":"k_`) {
				created[n]++
				continue
			}
			if strings.HasSuffix(what, "body") && strings.Contains(body, `"secret"`) {
				continue // the same create response, matched by the secret's body
			}
			t.Errorf("response %d contains the %s: %.300s", i, what, body)
		}
	}
	for n, c := range created {
		if c != 1 {
			t.Errorf("a secret was returned %d times (want once): %s...", c, n[:6])
		}
	}

	// Proof the redactors worked rather than the data never arriving.
	if !strings.Contains(dump, "mb_[redacted]") {
		t.Error("expected broker-secret scrubbing to show in the audit table (hostile paths and queries)")
	}
	seen := false
	for _, b := range h.bodies {
		if bytes.Contains(b, []byte("[redacted]")) {
			seen = true
			break
		}
	}
	if !seen && !strings.Contains(logs, "[redacted]") {
		t.Error("planted canary never came back redacted in any response")
	}
	var anyJSONLine bool
	for _, line := range strings.Split(logs, "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		anyJSONLine = true
	}
	if !anyJSONLine {
		t.Error("no log lines")
	}
	_ = context.Background
	_ = slog.LevelInfo
}
