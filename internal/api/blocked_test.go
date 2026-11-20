package api_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"mspbroker/internal/acl"
	"mspbroker/internal/auth"
	"mspbroker/internal/store"
	"mspbroker/internal/upstream/mock"
)

// (d) Every way a request can be blocked leaves one audit row with the right
// reason code, the right status and no data.
func TestBlockedAttemptsAreAuditedWithReasonCodes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	okKey, okSecret := h.key("good", scopeExplicit, allRead())

	// Unknown, malformed and missing credentials: indistinguishable (401 auth).
	other, err := auth.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		secret string
		opts   []reqOpt
	}{
		"missing":   {"", nil},
		"malformed": {"not-a-secret", nil},
		"unknown":   {other, nil},
		"basic":     {"", []reqOpt{withHeader("Authorization", "Basic Zm9vOmJhcg==")}},
	} {
		before := len(h.auditRows())
		r := h.get(tc.secret, "/api/v1/boxes", tc.opts...)
		if r.status != 401 || r.errCode(t) != "auth" || r.hdr.Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
		rows := h.auditRows()
		if len(rows) != before+1 {
			t.Fatalf("%s: %d audit rows added", name, len(rows)-before)
		}
		e := h.wantBlocked("auth")
		if e.KeyID != "" || e.ClientIP != "192.0.2.50" || e.Method != "GET" || e.Path != "/api/v1/boxes" {
			t.Errorf("%s: audit %+v", name, e)
		}
		if name == "unknown" && e.SecretPrefix != auth.Prefix(other) {
			t.Errorf("unknown secret prefix not recorded: %q", e.SecretPrefix)
		}
		if name != "unknown" && e.SecretPrefix != "" {
			t.Errorf("%s: junk was echoed into the prefix: %q", name, e.SecretPrefix)
		}
	}

	// Revoked secret and deleted key: also 401 auth, with the key identified in
	// the audit row only.
	revKey, revSecret := h.key("revoked", scopeAll, allRead())
	secs, _ := h.st.ListSecrets(ctx, revKey.ID)
	if err := h.st.RevokeSecret(ctx, revKey.ID, secs[0].ID, h.clk.now()); err != nil {
		t.Fatal(err)
	}
	r := h.get(revSecret, "/api/v1/boxes")
	if r.status != 401 || r.errCode(t) != "auth" {
		t.Errorf("revoked: %d %s", r.status, r.body)
	}
	if e := h.wantBlocked("auth"); e.KeyID != revKey.ID || e.KeyNameAtTime != "revoked" {
		t.Errorf("revoked audit: %+v", e)
	}
	delKey, delSecret := h.key("deleted", scopeAll, allRead())
	if err := h.st.SoftDeleteKey(ctx, delKey.ID, h.clk.now()); err != nil {
		t.Fatal(err)
	}
	if r := h.get(delSecret, "/api/v1/boxes"); r.status != 401 || r.errCode(t) != "auth" {
		t.Errorf("deleted: %d %s", r.status, r.body)
	}
	h.wantBlocked("auth")

	// Expired key.
	past := t0.Add(-time.Hour)
	_, expSecret := h.key("expired", scopeAll, allRead(), func(k *store.Key) { k.ExpiresAt = &past })
	r = h.get(expSecret, "/api/v1/boxes")
	if r.status != 401 || r.errCode(t) != "expired" {
		t.Errorf("expired: %d %s", r.status, r.body)
	}
	if e := h.wantBlocked("expired"); e.KeyNameAtTime != "expired" {
		t.Errorf("expired audit: %+v", e)
	}

	// Disabled key.
	_, disSecret := h.key("disabled", scopeAll, allRead(), func(k *store.Key) { k.Enabled = false })
	r = h.get(disSecret, "/api/v1/boxes")
	if r.status != 403 || r.errCode(t) != "disabled" || r.obj(t)["error"] != "forbidden" {
		t.Errorf("disabled: %d %s", r.status, r.body)
	}
	h.wantBlocked("disabled")

	// IP allowlist.
	_, ipSecret := h.key("ip-limited", scopeAll, allRead(), func(k *store.Key) { k.IPAllow = []string{"198.51.100.0/24"} })
	r = h.get(ipSecret, "/api/v1/boxes")
	if r.status != 403 || r.errCode(t) != "ip" {
		t.Errorf("ip: %d %s", r.status, r.body)
	}
	if e := h.wantBlocked("ip"); e.ClientIP != "192.0.2.50" {
		t.Errorf("ip audit: %+v", e)
	}
	if r := h.get(ipSecret, "/api/v1/boxes", withIP("198.51.100.9")); r.status != 200 {
		t.Errorf("allowed address refused: %d %s", r.status, r.body)
	}

	// Rate limit: a bucket of 2 per minute.
	_, rlSecret := h.key("limited", scopeAll, allRead(), func(k *store.Key) { n := 2; k.RateLimitPerMinute = &n })
	h.get(rlSecret, "/api/v1/boxes")
	h.get(rlSecret, "/api/v1/boxes")
	r = h.get(rlSecret, "/api/v1/boxes")
	if r.status != 429 || r.errCode(t) != "rate_limit" || r.hdr.Get("Retry-After") == "" {
		t.Errorf("rate limit: %d %v %s", r.status, r.hdr, r.body)
	}
	h.wantBlocked("rate_limit")

	// Permission and scope.
	_, noPerm := h.key("no-flows", scopeAll, acl.Permissions{Alarms: acl.Read})
	r = h.get(noPerm, "/api/v1/flows")
	if r.status != 403 || r.errCode(t) != "permission" {
		t.Errorf("permission: %d %s", r.status, r.body)
	}
	if e := h.wantBlocked("permission"); e.KeyID == "" || e.Resource != "flows" || e.Action != "list" {
		t.Errorf("permission audit: %+v", e)
	}
	r = h.get(okSecret, "/api/v1/boxes/"+mock.GID2+"/alarms")
	if r.status != 403 || r.errCode(t) != "out_of_scope" {
		t.Errorf("scope: %d %s", r.status, r.body)
	}
	if e := h.wantBlocked("out_of_scope"); e.KeyID != okKey.ID || e.GID != mock.GID2 || e.SecretPrefix == "" {
		t.Errorf("scope audit: %+v", e)
	}

	// Kind: admin and data keys on the wrong surface.
	admKey, admSecret := h.adminKey("admin-1")
	r = h.get(admSecret, "/api/v1/boxes")
	if r.status != 403 || r.errCode(t) != "kind" {
		t.Errorf("admin on data: %d %s", r.status, r.body)
	}
	if e := h.wantBlocked("kind"); e.KeyID != admKey.ID {
		t.Errorf("kind audit: %+v", e)
	}
	r = h.get(okSecret, "/admin/v1/keys")
	if r.status != 403 || r.errCode(t) != "kind" {
		t.Errorf("data on admin: %d %s", r.status, r.body)
	}
	h.wantBlocked("kind")

	// No blocked response carried a result.
	for _, e := range h.auditRows() {
		if e.Outcome == store.OutcomeBlocked && (e.ResultCount != nil || e.UpstreamStatus != nil) {
			t.Errorf("blocked row with result data: %+v", e)
		}
	}
	// Nothing blocked before step 4 reached the upstream.
	for _, rq := range h.mock.Requests() {
		if rq.Path != "/v2/boxes" {
			t.Errorf("blocked requests reached the upstream: %s %s", rq.Path, rq.RawQuery)
		}
	}
}

// A request that fails authentication does not drain the real key's bucket.
func TestRateLimitIsPerKeyAndRefills(t *testing.T) {
	h := newHarness(t, withRate(3))
	_, a := h.key("a", scopeAll, allRead())
	_, b := h.key("b", scopeAll, allRead())
	for i := 0; i < 3; i++ {
		if r := h.get(a, "/api/v1/me"); r.status != 200 {
			t.Fatalf("request %d: %d", i, r.status)
		}
	}
	if r := h.get(a, "/api/v1/me"); r.status != 429 {
		t.Errorf("4th request: %d", r.status)
	}
	if r := h.get(b, "/api/v1/me"); r.status != 200 {
		t.Errorf("other key throttled: %d", r.status)
	}
	h.clk.advance(30 * time.Second)
	if r := h.get(a, "/api/v1/me"); r.status != 200 {
		t.Errorf("after refill: %d", r.status)
	}
}

// Admin keys never reach data resources and data keys never reach the admin
// API, on every registered route.
func TestKindSeparationOnEveryRoute(t *testing.T) {
	h := newHarness(t)
	_, data := h.key("data", scopeAll, allRead())
	_, admin := h.adminKey("admin")
	for _, rt := range h.srv.Routes() {
		path := fillParams(rt.Pattern)
		switch {
		case strings.HasPrefix(rt.Pattern, "/api/v1/"):
			r := h.do(admin, rt.Method, path)
			if r.status != 403 || r.errCode(t) != "kind" {
				t.Errorf("admin key on %s %s: %d %s", rt.Method, rt.Pattern, r.status, r.body)
			}
		case strings.HasPrefix(rt.Pattern, "/admin/v1/"):
			r := h.do(data, rt.Method, path)
			if r.status != 403 || r.errCode(t) != "kind" {
				t.Errorf("data key on %s %s: %d %s", rt.Method, rt.Pattern, r.status, r.body)
			}
		}
		if strings.HasPrefix(rt.Pattern, "/api/v1/") || strings.HasPrefix(rt.Pattern, "/admin/v1/") {
			h.wantBlocked("kind")
		}
	}
	// Even an unmodelled path on the other surface is a kind failure first.
	if r := h.get(admin, "/api/v1/nope"); r.status != 403 || r.errCode(t) != "kind" {
		t.Errorf("admin on unmodelled data path: %d %s", r.status, r.body)
	}
	if r := h.get(data, "/admin/v1/nope"); r.status != 403 || r.errCode(t) != "kind" {
		t.Errorf("data on unmodelled admin path: %d %s", r.status, r.body)
	}
}

func fillParams(pattern string) string {
	segs := strings.Split(pattern, "/")
	for i, s := range segs {
		switch s {
		case "{gid}":
			segs[i] = mock.GID1
		case "{aid}":
			segs[i] = "11"
		case "{id}":
			segs[i] = "1"
		}
	}
	return strings.Join(segs, "/")
}

// Default deny: unmodelled paths and methods are refused after
// authentication and audited, and never reach the upstream.
func TestDefaultDeny(t *testing.T) {
	h := newHarness(t)
	_, data := h.key("data", scopeAll, allRead())
	_, admin := h.adminKey("admin")
	h.mock.ResetRequests()

	unmodelled := []string{
		"/", "/api", "/api/v1", "/api/v1/", "/api/v1/nope", "/api/v1/stats", "/api/v1/boxes/" + mock.GID1 + "/stats/x",
		"/api/v1/boxes/" + mock.GID1 + "/trends/x", "/api/v1/devices", "/api/v1/boxes/" + mock.GID1 + "/devices/AA:BB:CC:DD:EE:FF",
		"/api/v1/rules/rule-11", "/api/v1/rules/rule-11/pause", "/api/v1/boxes/" + mock.GID1 + "/alarms/11/archive",
		"/api/v1/boxes/", "/api/v1/boxes//devices", "//api/v1/boxes", "/api/v1/boxes/%2F", "/api/v1/boxes/" + mock.GID1 + "%2Fdevices",
		"/api/v1/boxes/" + mock.GID1 + "/devices/", "/API/V1/boxes", "/api/v1/boxes/" + mock.GID1 + "/../" + mock.GID2 + "/devices",
		"/v2/boxes", "/healthz/x", "/metrics", "/admin", "/admin/v1", "/admin/v1/keys/1/rotate", "/admin/v1/keys/1/secrets/s/revoke",
		"/admin/v1/scope/expand", "/admin/v1/keys/1/activity", "/admin/v1/audit/1/revert",
	}
	for _, p := range unmodelled {
		key := data
		if strings.HasPrefix(p, "/admin") {
			key = admin
		}
		r := h.get(key, p)
		if r.status != 404 {
			t.Errorf("GET %s: %d %s", p, r.status, r.body)
			continue
		}
		if r.errCode(t) != "not_found" {
			t.Errorf("GET %s: code %s", p, r.errCode(t))
		}
		h.wantBlocked("unmodelled")
	}

	// Unauthenticated probes of unmodelled paths are authentication failures.
	if r := h.get("", "/api/v1/nope"); r.status != 401 {
		t.Errorf("unauthenticated unmodelled: %d", r.status)
	}
	h.wantBlocked("auth")

	// Every method that is not registered for a path, on every path.
	methods := []string{"POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "get"}
	registered := map[string]map[string]bool{}
	for _, rt := range h.srv.Routes() {
		if registered[rt.Pattern] == nil {
			registered[rt.Pattern] = map[string]bool{}
		}
		registered[rt.Pattern][rt.Method] = true
	}
	for pattern, have := range registered {
		if pattern == "/healthz" || pattern == "/readyz" || pattern == "/api/openapi.json" {
			continue // public routes: auth comes first, covered below
		}
		key := data
		if strings.HasPrefix(pattern, "/admin") {
			key = admin
		}
		for _, m := range methods {
			if have[m] {
				continue
			}
			before := len(h.auditRows())
			r := h.do(key, m, fillParams(pattern), withBody(`{"name":"x"}`))
			if r.status != 405 {
				t.Errorf("%s %s: %d %s", m, pattern, r.status, r.body)
				continue
			}
			if r.hdr.Get("Allow") == "" {
				t.Errorf("%s %s: no Allow header", m, pattern)
			}
			if len(h.auditRows()) != before+1 {
				t.Errorf("%s %s: not audited", m, pattern)
			}
			h.wantBlocked("unmodelled")
		}
	}

	// No write reached the upstream, and no unmodelled request reached it at all.
	if n := len(h.mock.Requests()); n != 0 {
		t.Errorf("%d upstream requests from denied traffic: %+v", n, h.mock.Requests())
	}

	// The same for the public paths: a non-GET needs authentication.
	if r := h.do("", "POST", "/healthz"); r.status != 401 {
		t.Errorf("POST /healthz unauthenticated: %d", r.status)
	}
	if r := h.do(data, "POST", "/healthz"); r.status != 405 {
		t.Errorf("POST /healthz: %d", r.status)
	}
}

// Writes on modelled paths are refused and audited in M1.
func TestNoWriteEndpointsInM1(t *testing.T) {
	h := newHarness(t)
	_, w := h.key("writer", scopeAll, acl.Permissions{Boxes: acl.Read, Devices: acl.Write, Alarms: acl.Write, Rules: acl.Write,
		Flows: acl.Read, TargetLists: acl.Write, GlobalTargetLists: acl.Write})
	h.mock.ResetRequests()
	cases := []struct{ method, path string }{
		{"PATCH", "/api/v1/boxes/" + mock.GID1 + "/devices/AA:BB:CC:DD:EE:FF"},
		{"DELETE", "/api/v1/boxes/" + mock.GID1 + "/alarms/11"},
		{"POST", "/api/v1/boxes/" + mock.GID1 + "/alarms/11/archive"},
		{"POST", "/api/v1/boxes/" + mock.GID1 + "/rules"},
		{"POST", "/api/v1/rules/rule-11/pause"},
		{"DELETE", "/api/v1/rules/rule-11"},
		{"POST", "/api/v1/target-lists"},
		{"PATCH", "/api/v1/target-lists/tl-1"},
		{"DELETE", "/api/v1/target-lists/tl-global-1"},
		{"DELETE", "/api/v1/boxes/" + mock.GID1},
		{"PUT", "/api/v1/alarms"},
	}
	for _, c := range cases {
		r := h.do(w, c.method, c.path, withBody(`{"gid":"`+mock.GID1+`"}`))
		if r.status != 404 && r.status != 405 {
			t.Errorf("%s %s: %d %s", c.method, c.path, r.status, r.body)
		}
		h.wantBlocked("unmodelled")
	}
	if n := len(h.mock.Requests()); n != 0 {
		t.Errorf("upstream was called %d times by refused writes", n)
	}
}
