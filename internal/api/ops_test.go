package api_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"mspbroker/internal/acl"
	"mspbroker/internal/store"
	"mspbroker/internal/upstream/mock"
)

func TestHealthz(t *testing.T) {
	h := newHarness(t)
	n := len(h.auditRows())
	r := h.get("", "/healthz")
	if r.status != 200 || r.obj(t)["status"] != "ok" {
		t.Errorf("%d %s", r.status, r.body)
	}
	if len(h.mock.Requests()) != 0 {
		t.Error("healthz must not touch the upstream")
	}
	if len(h.auditRows()) != n {
		t.Error("probes are not audited")
	}
}

func TestReadyz(t *testing.T) {
	h := newHarness(t, withReadyInterval(30*time.Second))
	r := h.get("", "/readyz")
	if r.status != 200 || r.obj(t)["status"] != "ready" {
		t.Fatalf("%d %s", r.status, r.body)
	}
	// Within the check interval the answer is reused: no second probe.
	h.get("", "/readyz")
	h.get("", "/readyz")
	if n := h.boxesCalls(); n != 1 {
		t.Errorf("%d upstream probes inside one interval", n)
	}

	// Upstream goes away: still "ready" until the interval lapses, then not.
	h.mock.InjectFault(mock.Fault{Status: 503})
	if r := h.get("", "/readyz"); r.status != 200 {
		t.Errorf("inside the interval: %d", r.status)
	}
	h.clk.advance(31 * time.Second)
	r = h.get("", "/readyz")
	if r.status != 503 || r.obj(t)["status"] != "not_ready" || r.obj(t)["checks"].(map[string]any)["upstream"] != "error" {
		t.Errorf("upstream down: %d %s", r.status, r.body)
	}
	if strings.Contains(string(r.body), "503") || strings.Contains(string(r.body), h.upSrv.URL) {
		t.Errorf("readyz explains why: %s", r.body)
	}
	// Failures are rechecked sooner than successes, so recovery is noticed.
	h.mock.ClearFaults()
	h.clk.advance(6 * time.Second)
	if r := h.get("", "/readyz"); r.status != 200 {
		t.Errorf("after recovery: %d %s", r.status, r.body)
	}

	// Database failure.
	h.st.Close()
	if r := h.get("", "/readyz"); r.status != 503 || r.obj(t)["checks"].(map[string]any)["database"] != "error" {
		t.Errorf("database closed: %d %s", r.status, r.body)
	}
}

func TestSecurityHeadersAndNoCORS(t *testing.T) {
	h := newHarness(t)
	_, secret := h.key("k", scopeAll, allRead())
	_, admin := h.adminKey("a")
	want := map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Content-Security-Policy":      "default-src 'none'; frame-ancestors 'none'",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":                "no-store",
	}
	targets := []struct{ secret, method, path string }{
		{"", "GET", "/healthz"}, {"", "GET", "/readyz"}, {"", "GET", "/api/openapi.json"},
		{secret, "GET", "/api/v1/boxes"}, {secret, "GET", "/api/v1/boxes/" + mock.GID2 + "/devices"}, {secret, "GET", "/api/v1/nope"},
		{secret, "POST", "/api/v1/boxes"}, {"", "GET", "/api/v1/boxes"}, {"bad", "GET", "/api/v1/boxes"},
		{admin, "GET", "/admin/v1/keys"}, {secret, "GET", "/admin/v1/keys"}, {"", "OPTIONS", "/api/v1/boxes"}, {secret, "OPTIONS", "/api/v1/boxes"},
		{"", "GET", "/"},
	}
	for _, tc := range targets {
		r := h.do(tc.secret, tc.method, tc.path, withHeader("Origin", "https://app.example.com"),
			withHeader("Access-Control-Request-Method", "GET"))
		for k, v := range want {
			if got := r.hdr.Get(k); got != v {
				t.Errorf("%s %s: header %s = %q", tc.method, tc.path, k, got)
			}
		}
		for k := range r.hdr {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Errorf("%s %s: CORS header %s present", tc.method, tc.path, k)
			}
		}
		if ct := r.hdr.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s %s: content type %q", tc.method, tc.path, ct)
		}
	}
	// A preflight is just an unauthenticated OPTIONS: refused, no CORS grant.
	r := h.do("", "OPTIONS", "/api/v1/boxes", withHeader("Origin", "https://app.example.com"))
	if r.status != 401 {
		t.Errorf("preflight: %d", r.status)
	}
}

func TestMe(t *testing.T) {
	h := newHarness(t, withRate(90))
	exp := h.clk.now().Add(48 * time.Hour)
	k, secret := h.key("me-key", scopeGroupA, acl.Permissions{Alarms: acl.Write, Boxes: acl.Read, Flows: acl.Read},
		func(k *store.Key) { k.ExpiresAt = &exp; k.IPAllow = []string{"192.0.2.0/24"} })
	r := h.get(secret, "/api/v1/me")
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	m := r.obj(t)
	key := m["key"].(map[string]any)
	if key["id"] != k.ID || key["name"] != "me-key" || key["kind"] != "data" || key["enabled"] != true {
		t.Errorf("key: %v", key)
	}
	if !reflect.DeepEqual(m["resolved_gids"], []any{mock.GID1, mock.GID2}) {
		t.Errorf("resolved_gids: %v", m["resolved_gids"])
	}
	if m["scope"].(map[string]any)["type"] != "groups" || m["permissions"].(map[string]any)["alarms"] != "write" ||
		m["permissions"].(map[string]any)["rules"] != "none" {
		t.Errorf("scope/permissions: %v %v", m["scope"], m["permissions"])
	}
	if m["expires_at"] == nil || m["rate_limit_per_minute"] != 90.0 || !reflect.DeepEqual(m["ip_allow"], []any{"192.0.2.0/24"}) {
		t.Errorf("limits: %v", m)
	}
	rot := m["rotation"].(map[string]any)
	secs := rot["secrets"].([]any)
	if rot["in_progress"] != false || len(secs) != 1 || secs[0].(map[string]any)["current"] != true || secs[0].(map[string]any)["prefix"] != secret[3:11] {
		t.Errorf("rotation: %v", rot)
	}
	if strings.Contains(string(r.body), secret) {
		t.Error("/me contains the secret")
	}
	if e := h.lastAudit(); e.Resource != "me" || e.Action != "read" || e.Outcome != store.OutcomeOK {
		t.Errorf("audit: %+v", e)
	}

	// Rotation state: a second, expiring secret on the same key.
	sec2 := mustSecret(t, h, k.ID, &exp)
	r = h.get(sec2, "/api/v1/me")
	rot = r.obj(t)["rotation"].(map[string]any)
	if rot["in_progress"] != true || len(rot["secrets"].([]any)) != 2 {
		t.Errorf("rotation window: %v", rot)
	}
	cur := 0
	for _, s := range rot["secrets"].([]any) {
		if s.(map[string]any)["current"] == true {
			cur++
			if s.(map[string]any)["prefix"] != sec2[3:11] {
				t.Errorf("current marks the wrong secret: %v", s)
			}
		}
	}
	if cur != 1 {
		t.Errorf("%d current secrets", cur)
	}

	// `all` is expanded to the boxes that exist now.
	_, all := h.key("me-all", scopeAll, acl.Permissions{Boxes: acl.Read})
	m = h.get(all, "/api/v1/me").obj(t)
	if len(m["resolved_gids"].([]any)) != 5 {
		t.Errorf("all resolved to %v", m["resolved_gids"])
	}
	// Explicit boxes with no read permission at all can still call /me.
	_, none := h.key("me-none", scopeExplicit, acl.Permissions{})
	if r := h.get(none, "/api/v1/me"); r.status != 200 || len(r.obj(t)["resolved_gids"].([]any)) != 2 {
		t.Errorf("no-permission key: %d %s", r.status, r.body)
	}
	if r := h.get(secret, "/api/v1/me?x=1"); r.status != 400 {
		t.Errorf("unknown parameter: %d", r.status)
	}
}

// Upstream failures: mapped to broker errors with fixed text, audited as
// upstream_error with the upstream status, and an upstream 401/403 (the
// broker's own credentials) is never relayed as the client's.
func TestUpstreamErrorMapping(t *testing.T) {
	h := newHarness(t)
	_, secret := h.key("errs", scopeExplicit, allRead())
	cases := []struct {
		name   string
		fault  mock.Fault
		status int
		code   string
		upst   int
		retry  string
	}{
		{"rate limited with retry", mock.Fault{Status: 429, RetryAfter: "7", Times: 1}, 429, "upstream_rate_limit", 429, "7"},
		{"rate limited without retry", mock.Fault{Status: 429, Times: 1}, 429, "upstream_rate_limit", 429, ""},
		{"server error", mock.Fault{Status: 500, Times: 1}, 502, "upstream_error", 500, ""},
		{"bad gateway", mock.Fault{Status: 503, Times: 1}, 502, "upstream_error", 503, ""},
		{"upstream rejects token", mock.Fault{Status: 401, Times: 1}, 502, "upstream_auth", 401, ""},
		{"upstream forbids token", mock.Fault{Status: 403, Times: 1}, 502, "upstream_auth", 403, ""},
		{"upstream bad request", mock.Fault{Status: 400, Times: 1}, 400, "upstream_rejected", 400, ""},
		{"garbage body", mock.Fault{Status: 200, Body: "<html>not json</html>", Times: 1}, 502, "upstream_unexpected", 200, ""},
	}
	for _, c := range cases {
		for _, p := range ids("/api/v1/alarms", "/api/v1/boxes/"+mock.GID1+"/devices", "/api/v1/boxes", "/api/v1/target-lists") {
			h.mock.InjectFault(c.fault)
			r := h.get(secret, p)
			if r.status != c.status || r.errCode(t) != c.code {
				t.Errorf("%s %s: %d %s", c.name, p, r.status, r.body)
				continue
			}
			if got := r.hdr.Get("Retry-After"); got != c.retry {
				t.Errorf("%s %s: Retry-After %q, want %q", c.name, p, got, c.retry)
			}
			e := h.lastAudit()
			if e.Outcome != store.OutcomeUpstreamError || e.BlockReason != "" {
				t.Errorf("%s %s: audit %+v", c.name, p, e)
			}
			if c.upst != 200 && (e.UpstreamStatus == nil || *e.UpstreamStatus != c.upst) {
				t.Errorf("%s %s: upstream status %v", c.name, p, e.UpstreamStatus)
			}
			if body := string(r.body); strings.Contains(body, "mock") || strings.Contains(body, "injected") || strings.Contains(body, "<html>") {
				t.Errorf("%s %s: upstream text relayed: %s", c.name, p, body)
			}
		}
	}
	// Single objects: an upstream 404 is a 404.
	h.mock.InjectFault(mock.Fault{Status: 404, Times: 1})
	if r := h.get(secret, "/api/v1/boxes/"+mock.GID1+"/alarms/11"); r.status != 404 {
		t.Errorf("single 404: %d", r.status)
	}
	if r := h.get(secret, "/api/v1/boxes/"+mock.GID1+"/alarms/999"); r.status != 404 || r.errCode(t) != "not_found" {
		t.Errorf("missing alarm: %d %s", r.status, r.body)
	}
	if r := h.get(secret, "/api/v1/boxes/"+mock.GID1+"/alarms/a%20b"); r.status != 400 {
		t.Errorf("bad alarm id: %d", r.status)
	}
	if r := h.get(secret, "/api/v1/boxes/"+mock.GID1+"/alarms/"+strings.Repeat("a", 200)); r.status != 400 {
		t.Errorf("long alarm id: %d", r.status)
	}
	// An alarm that belongs to another box than the path says is refused.
	h.mock.Update(func(s *mock.State) { s.Alarms[0]["aid"] = "77"; s.Alarms[0]["gid"] = mock.GID1 })
	h.mock.Update(func(s *mock.State) { s.Alarms[3]["aid"] = "77" }) // box 2's alarm shares the id
	if r := h.get(secret, "/api/v1/boxes/"+mock.GID1+"/alarms/77"); r.status != 200 || r.obj(t)["gid"] != mock.GID1 {
		t.Errorf("shared alarm id: %d %s", r.status, r.body)
	}
	// An upstream that answers a per-box alarm request with another box's
	// object (a bug or a hostile upstream) is not believed.
	for name, body := range map[string]string{
		"out of scope box":   `{"aid":"11","gid":"` + mock.GID2 + `","message":"Example"}`,
		"in scope other box": `{"aid":"11","gid":"` + mock.GID3 + `","message":"Example"}`,
		"no gid":             `{"aid":"11","message":"Example"}`,
		"gid not a string":   `{"aid":"11","gid":5}`,
	} {
		h.mock.InjectFault(mock.Fault{Status: 200, Body: body, Times: 1})
		r := h.get(secret, "/api/v1/boxes/"+mock.GID1+"/alarms/11")
		if r.status != 403 || r.errCode(t) != "out_of_scope" || strings.Contains(string(r.body), "Example") {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
		h.wantBlocked("out_of_scope")
	}
}

func TestUpstreamTimeoutAndUnreachable(t *testing.T) {
	h := newHarness(t, withUpstreamTimeout(50*time.Millisecond))
	_, secret := h.key("slow", scopeExplicit, allRead())
	h.mock.SetLatency(300 * time.Millisecond)
	r := h.get(secret, "/api/v1/alarms")
	if r.status != 504 || r.errCode(t) != "upstream_timeout" {
		t.Errorf("timeout: %d %s", r.status, r.body)
	}
	if e := h.lastAudit(); e.Outcome != store.OutcomeUpstreamError {
		t.Errorf("audit: %+v", e)
	}
	h.mock.SetLatency(0)
	h.upSrv.Close()
	r = h.get(secret, "/api/v1/alarms")
	if r.status != 502 || r.errCode(t) != "upstream_unavailable" {
		t.Errorf("unreachable: %d %s", r.status, r.body)
	}
	if strings.Contains(string(r.body), "127.0.0.1") || strings.Contains(string(r.body), "refused") {
		t.Errorf("transport details relayed: %s", r.body)
	}
}

// Audit: one row per request that got past authentication, one per blocked
// attempt, metadata only.
func TestAuditRowPerRequestAndMetadataOnly(t *testing.T) {
	h := newHarness(t, withIgnoreFilters())
	k, secret := h.key("auditee", scopeExplicit, allRead())
	reqs := []struct {
		path   string
		status int
	}{
		{"/api/v1/alarms", 200}, {"/api/v1/boxes/" + mock.GID1 + "/flows?limit=500", 200}, {"/api/v1/boxes", 200},
		{"/api/v1/target-lists", 200}, {"/api/v1/nope", 404}, {"/api/v1/boxes/" + mock.GID2, 403}, {"/api/v1/me", 200},
	}
	for i, rq := range reqs {
		before := len(h.auditRows())
		r := h.get(secret, rq.path)
		if r.status != rq.status {
			t.Fatalf("%s: %d", rq.path, r.status)
		}
		if got := len(h.auditRows()) - before; got != 1 {
			t.Fatalf("request %d %s wrote %d audit rows", i, rq.path, got)
		}
		e := h.lastAudit()
		if e.KeyID != k.ID || e.KeyNameAtTime != "auditee" || e.SecretPrefix != secret[3:11] || e.ClientIP != "192.0.2.50" ||
			e.Method != "GET" || !strings.HasPrefix(rq.path, e.Path) || !e.TS.Equal(h.clk.now()) {
			t.Errorf("%s: audit %+v", rq.path, e)
		}
	}
	// result_count is the filtered count: the upstream (ignoring filters)
	// returned 15 alarms, the key may see 6.
	rows := h.auditRows()
	if c := rows[0].ResultCount; rows[0].Resource != "alarms" || rows[0].Action != "list" || c == nil || *c != 6 {
		t.Errorf("alarms audit: %+v", rows[0])
	}
	if rows[0].UpstreamStatus == nil || *rows[0].UpstreamStatus != 200 {
		t.Errorf("upstream status: %+v", rows[0])
	}
	if rows[1].GID != mock.GID1 || rows[1].Query != "limit=500" || *rows[1].ResultCount != 4 {
		t.Errorf("flows audit: %+v", rows[1])
	}
	if c := rows[3].ResultCount; rows[3].Resource != "target_lists" || c == nil || *c != 4 { // two global lists + tl-1 + tl-3
		t.Errorf("target list audit: %+v", rows[3])
	}

	// Metadata only: no response content anywhere in the table, no bodies on reads.
	h.dumpContains(t, "Example alarm", false)
	h.dumpContains(t, "example.com", false)
	h.dumpContains(t, "Example Box", false)
	for _, e := range rows {
		if e.Before != nil || e.After != nil {
			if e.Resource != "keys" {
				t.Errorf("body on a non-key row: %+v", e)
			}
		}
	}
	// The one-row-per-request rule also holds for the blocked auth attempt.
	n := len(h.auditRows())
	h.get("", "/api/v1/boxes")
	if len(h.auditRows()) != n+1 {
		t.Error("auth failure not audited exactly once")
	}
}

// dumpContains scans every column of every table.
func (h *harness) dumpContains(t *testing.T, needle string, want bool) {
	t.Helper()
	if got := strings.Contains(h.dump(), needle); got != want {
		t.Errorf("database dump contains %q = %v, want %v", needle, got, want)
	}
}

func TestAuditFailureMeansNoData(t *testing.T) {
	h := newHarness(t)
	_, secret := h.key("k", scopeAll, allRead())
	if r := h.get(secret, "/api/v1/boxes"); r.status != 200 {
		t.Fatal(r.status)
	}
	// Make audit writes fail: drop the table behind the broker's back.
	if _, err := h.rawDB().Exec(`ALTER TABLE audit RENAME TO audit_gone`); err != nil {
		t.Fatal(err)
	}
	r := h.get(secret, "/api/v1/boxes")
	if r.status != http.StatusInternalServerError || strings.Contains(string(r.body), "results") {
		t.Errorf("request served without an audit row: %d %s", r.status, r.body)
	}
	if r.errCode(t) != "audit_unavailable" {
		t.Errorf("code: %s", r.errCode(t))
	}
}
