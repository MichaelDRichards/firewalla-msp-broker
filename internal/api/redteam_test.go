package api_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"mspbroker/internal/acl"
	"mspbroker/internal/api"
	"mspbroker/internal/upstream"
	"mspbroker/internal/upstream/mock"
)

// The red-team regression set: one test per finding from a blind review or
// an attack that once worked. Every test is named TestRedTeam* so
// `go test -run TestRedTeam ./...` (make redteam) runs the whole set.

// ---- finding 1: JSON \u escapes must not reconstitute the upstream token ----

// uEscape writes every character of s as a JSON \uXXXX escape.
func uEscape(s string) string {
	var sb strings.Builder
	for _, r := range s {
		fmt.Fprintf(&sb, `\u%04x`, r)
	}
	return sb.String()
}

// uEscapeUpper is uEscape with upper-case hex digits (\u006D).
func uEscapeUpper(s string) string {
	var sb strings.Builder
	for _, r := range s {
		fmt.Fprintf(&sb, `\u%04X`, r)
	}
	return sb.String()
}

// uEscapeFirst escapes only the first character: `\u006dg-test-...`.
func uEscapeFirst(s string) string {
	return uEscape(s[:1]) + s[1:]
}

// escapedForms are the spellings of the canary that the raw-byte redaction
// does not recognise but a JSON decoder turns back into the token.
func escapedForms() map[string]string {
	return map[string]string{
		"full escape":    uEscape(upstreamCanary),
		"partial escape": uEscapeFirst(upstreamCanary),
		"embedded":       "x" + uEscape(upstreamCanary) + "y",
		"upper case hex": uEscapeUpper(upstreamCanary),
	}
}

func TestRedTeamEscapedUpstreamTokenNeverReachesTheClient(t *testing.T) {
	g1 := mock.GID1
	for _, mode := range []struct {
		name string
		opts []hopt
	}{
		{"default", nil},
		// The broker's own scrubber knows nothing of the token here: the
		// upstream client alone must keep it out.
		{"strict", []hopt{withStrictScrub()}},
	} {
		for form, esc := range escapedForms() {
			bodies := map[string]struct {
				path, body string
			}{
				"list: name and next_cursor": {"/api/v1/alarms",
					`{"results":[{"gid":"` + g1 + `","name":"` + esc + `","` + esc + `":"key"}],"next_cursor":"` + esc + `"}`},
				"list: nextCursor spelling": {"/api/v1/alarms",
					`{"results":[{"gid":"` + g1 + `","name":"a"}],"nextCursor":"` + esc + `"}`},
				"list: nested value": {"/api/v1/flows",
					`{"results":[{"gid":"` + g1 + `","detail":{"list":["` + esc + `"]}}]}`},
				"bare array": {"/api/v1/rules",
					`[{"gid":"` + g1 + `","note":"` + esc + `"}]`},
				"per-box list": {"/api/v1/boxes/" + g1 + "/alarms",
					`{"results":[{"gid":"` + g1 + `","name":"` + esc + `"}],"next_cursor":"` + esc + `"}`},
				"single alarm": {"/api/v1/boxes/" + g1 + "/alarms/11",
					`{"gid":"` + g1 + `","aid":11,"message":"` + esc + `"}`},
				"devices": {"/api/v1/boxes/" + g1 + "/devices",
					`[{"gid":"` + g1 + `","name":"` + esc + `"}]`},
				"boxes": {"/api/v1/boxes",
					`[{"gid":"` + g1 + `","name":"` + esc + `"}]`},
				"target list": {"/api/v1/target-lists/tl-1",
					`{"owner":"` + g1 + `","name":"` + esc + `"}`},
			}
			for name, tc := range bodies {
				t.Run(mode.name+"/"+form+"/"+name, func(t *testing.T) {
					h := newHarness(t, mode.opts...)
					_, secret := h.key("escape", scopeExplicit, allRead())
					h.mock.InjectFault(mock.Fault{Status: 200, Body: tc.body, Times: 1})
					r := h.get(secret, tc.path)
					if r.status != http.StatusOK {
						t.Fatalf("%d %s", r.status, r.body)
					}
					body := string(r.body)
					for _, needle := range []string{upstreamCanary, strings.ToLower(upstreamCanary), upstreamCanary[1:]} {
						if strings.Contains(body, needle) {
							t.Fatalf("response contains %q: %s", needle, body)
						}
					}
					if !strings.Contains(body, "[redacted]") {
						t.Fatalf("the planted value is gone but nothing was redacted (did the fault apply?): %s", body)
					}
				})
			}
		}
	}
}

// echoingUpstream hands the API decoded objects that already carry the
// token, as if the client's own redaction had missed it. The outbound body
// must be scrubbed on its own account.
type echoingUpstream struct{ api.Upstream }

func (echoingUpstream) Alarms(_ context.Context, _ upstream.ListParams) (*upstream.Page, error) {
	return &upstream.Page{
		Results:    []upstream.Object{{"gid": mock.GID1, "name": upstreamCanary, upstreamCanary: "as a key", "n": []any{"a", upstreamCanary}}},
		NextCursor: "cur-" + upstreamCanary,
	}, nil
}

func (echoingUpstream) Alarm(_ context.Context, gid, _ string) (upstream.Object, error) {
	return upstream.Object{"gid": gid, "message": upstreamCanary}, nil
}

func TestRedTeamOutboundBodyIsScrubbedAfterMarshal(t *testing.T) {
	h := newHarness(t, withWrapUpstream(func(u api.Upstream) api.Upstream { return echoingUpstream{u} }))
	_, secret := h.key("outbound", scopeExplicit, allRead())
	for _, path := range []string{"/api/v1/alarms", "/api/v1/boxes/" + mock.GID1 + "/alarms", "/api/v1/boxes/" + mock.GID1 + "/alarms/11"} {
		r := h.get(secret, path)
		if r.status != http.StatusOK {
			t.Fatalf("%s: %d %s", path, r.status, r.body)
		}
		if strings.Contains(string(r.body), upstreamCanary) || !strings.Contains(string(r.body), "[redacted]") {
			t.Errorf("%s: outbound body not scrubbed: %s", path, r.body)
		}
	}
}

// The scrub of outbound bodies must be literal-only: the broker-secret shape
// regex would hide the one-time secret of a newly created key (SPEC 10).
func TestRedTeamOutboundScrubKeepsTheOneTimeSecret(t *testing.T) {
	h := newHarness(t)
	_, admin := h.adminKey("creator")
	r := h.do(admin, "POST", "/admin/v1/keys", j(kv{
		"name": "fresh", "kind": "data", "scope": scopeExplicit,
		"permissions": kv{"boxes": "read"},
	}))
	if r.status != http.StatusCreated {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	secret, _ := r.obj(t)["secret"].(string)
	if !strings.HasPrefix(secret, "mb_") || len(secret) < 20 || strings.Contains(secret, "redacted") {
		t.Fatalf("the one-time secret was not returned intact: %q", secret)
	}
}

// ---- finding 2: the post-filter must walk nested objects ----

// nestedPayload is the reviewer's hostile object: in scope at the top, with
// another box's object hanging off it. idField is the ownership key of the
// top-level object.
func nestedPayload(idField string) string {
	return `{"` + idField + `":"` + mock.GID1 + `","name":"mine","related":[{"gid":"` + mock.GID2 + `","name":"nested-foreign","tokenish":"should-not-pass"}],` +
		`"parent":{"owner":"` + mock.GID2 + `","name":"nested-foreign-2"}}`
}

func TestRedTeamNestedForeignObjectsAreDropped(t *testing.T) {
	g1 := mock.GID1
	cases := []struct {
		name, path, body, idField string
		list                      bool
	}{
		{"global alarms", "/api/v1/alarms", "", "gid", true},
		{"global alarms, cursor path", "/api/v1/alarms?cursor=abc", "", "gid", true},
		{"global flows", "/api/v1/flows", "", "gid", true},
		{"global rules", "/api/v1/rules", "", "gid", true},
		{"box alarms", "/api/v1/boxes/" + g1 + "/alarms", "", "gid", true},
		{"box flows", "/api/v1/boxes/" + g1 + "/flows", "", "gid", true},
		{"box rules", "/api/v1/boxes/" + g1 + "/rules", "", "gid", true},
		{"box devices", "/api/v1/boxes/" + g1 + "/devices", "", "gid", true},
		{"box list", "/api/v1/boxes", "", "gid", true},
		{"target lists", "/api/v1/target-lists", "", "owner", true},
		{"single box", "/api/v1/boxes/" + g1, "", "gid", false},
		{"single alarm", "/api/v1/boxes/" + g1 + "/alarms/11", "", "gid", false},
		{"single target list", "/api/v1/target-lists/tl-1", "", "owner", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			_, secret := h.key("nested", acl.Scope{Type: acl.ScopeBoxes, GIDs: []string{g1}}, allRead())
			one := nestedPayload(c.idField)
			body := one
			switch {
			case c.name == "box list" || c.name == "single box" || c.name == "box devices" || c.name == "global rules" || c.name == "box rules":
				body = "[" + one + "]" // a bare array, the other accepted shape
			case c.list:
				body = `{"results":[` + one + `],"next_cursor":"next"}`
			}
			h.mock.InjectFault(mock.Fault{Status: 200, Body: body, Times: 1})
			r := h.get(secret, c.path)
			if r.status != http.StatusOK {
				t.Fatalf("%d %s", r.status, r.body)
			}
			got := string(r.body)
			for _, bad := range []string{mock.GID2, "nested-foreign", "should-not-pass"} {
				if strings.Contains(got, bad) {
					t.Errorf("response contains %q: %s", bad, got)
				}
			}
			if !strings.Contains(got, `"mine"`) {
				t.Errorf("the in-scope parent is gone (did the fault apply?): %s", got)
			}
		})
	}
}
