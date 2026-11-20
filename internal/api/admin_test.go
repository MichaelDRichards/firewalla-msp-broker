package api_test

import (
	"encoding/json"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"mspbroker/internal/store"
	"mspbroker/internal/upstream/mock"
)

func j(v any) reqOpt {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return withBody(string(b))
}

type kv = map[string]any

func TestAdminCreateKeyAndUseIt(t *testing.T) {
	h := newHarness(t)
	_, admin := h.adminKey("admin")

	r := h.do(admin, "POST", "/admin/v1/keys", j(kv{
		"name": "homelab-agent", "kind": "data",
		"scope":       kv{"type": "boxes", "gids": []string{strings.ToUpper(mock.GID1), mock.GID3}},
		"permissions": kv{"alarms": "read", "boxes": "read"},
		"ip_allow":    []string{"192.0.2.0/24", "198.51.100.7"},
		"rate_limit":  kv{"per_minute": 50},
		"notes":       "example",
	}))
	if r.status != 201 {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	created := r.obj(t)
	secret, _ := created["secret"].(string)
	if !strings.HasPrefix(secret, "mb_") || len(secret) != 46 {
		t.Fatalf("secret: %q", secret)
	}
	id := created["id"].(string)
	if created["name"] != "homelab-agent" || created["kind"] != "data" || created["enabled"] != true {
		t.Errorf("created: %v", created)
	}
	scope := created["scope"].(kv)
	if !reflect.DeepEqual(scope["gids"], []any{mock.GID1, mock.GID3}) { // stored lower-case
		t.Errorf("scope: %v", scope)
	}
	if !reflect.DeepEqual(created["ip_allow"], []any{"192.0.2.0/24", "198.51.100.7/32"}) {
		t.Errorf("ip_allow: %v", created["ip_allow"])
	}
	if created["permissions"].(kv)["rules"] != "none" || created["rate_limit"].(kv)["per_minute"] != 50.0 {
		t.Errorf("permissions/rate_limit: %v", created)
	}
	secs := created["secrets"].([]any)
	if len(secs) != 1 || secs[0].(kv)["prefix"] != secret[3:11] {
		t.Errorf("secrets: %v", secs)
	}

	// The new key works immediately, within its limits.
	me := h.get(secret, "/api/v1/me")
	if me.status != 200 || me.obj(t)["key"].(kv)["id"] != id {
		t.Fatalf("new key /me: %d %s", me.status, me.body)
	}
	if r := h.get(secret, "/api/v1/alarms"); r.status != 200 || !reflect.DeepEqual(r.owners(t, "gid"), ids(mock.GID1, mock.GID3)) {
		t.Errorf("new key alarms: %d %s", r.status, r.body)
	}
	if r := h.get(secret, "/api/v1/rules"); r.status != 403 {
		t.Errorf("rules should be none: %d", r.status)
	}
	if r := h.get(secret, "/api/v1/alarms", withIP("203.0.113.5")); r.status != 403 || r.errCode(t) != "ip" {
		t.Errorf("ip allowlist: %d %s", r.status, r.body)
	}

	// The secret is never returned again, by any admin read.
	for _, p := range ids("/admin/v1/keys", "/admin/v1/keys/"+id) {
		g := h.get(admin, p)
		if g.status != 200 || strings.Contains(string(g.body), secret) {
			t.Errorf("%s: %d, leaks the secret: %v", p, g.status, strings.Contains(string(g.body), secret))
		}
		if strings.Contains(string(g.body), `"secret"`) || strings.Contains(string(g.body), `"hash"`) {
			t.Errorf("%s exposes a secret field: %s", p, g.body)
		}
	}
	one := h.get(admin, "/admin/v1/keys/"+id).obj(t)
	if one["secrets"].([]any)[0].(kv)["prefix"] != secret[3:11] {
		t.Errorf("prefix missing from key view: %v", one)
	}
	list := h.get(admin, "/admin/v1/keys").obj(t)
	if list["count"] != 2.0 { // admin + new
		t.Errorf("list: %v", list)
	}

	// The create is audited with the key as `after`, without the secret.
	var found *store.AuditEntry
	for _, e := range h.auditRows() {
		if e.Resource == "keys" && e.Action == "create" && e.Outcome == store.OutcomeOK {
			found = e
		}
	}
	if found == nil || found.ObjectID != id || !strings.Contains(string(found.After), "homelab-agent") || found.Before != nil {
		t.Fatalf("create audit: %+v", found)
	}
	if strings.Contains(string(found.After), secret) || strings.Contains(string(found.After), secret[3:]) {
		t.Error("audit after-snapshot contains the secret")
	}
}

func TestAdminCreateValidation(t *testing.T) {
	h := newHarness(t)
	_, admin := h.adminKey("admin")
	h.key("taken", scopeAll, allRead())
	past := h.clk.now().Add(-time.Hour).Format(time.RFC3339)
	long := strings.Repeat("n", 129)
	bad := map[string]kv{
		"no name":            {"kind": "data", "scope": kv{"type": "all"}},
		"blank name":         {"name": "  ", "kind": "data", "scope": kv{"type": "all"}},
		"long name":          {"name": long, "kind": "data", "scope": kv{"type": "all"}},
		"control in name":    {"name": "a\u0001b", "kind": "data", "scope": kv{"type": "all"}},
		"no kind":            {"name": "k", "scope": kv{"type": "all"}},
		"bad kind":           {"name": "k", "kind": "root", "scope": kv{"type": "all"}},
		"data without scope": {"name": "k", "kind": "data"},
		"empty boxes scope":  {"name": "k", "kind": "data", "scope": kv{"type": "boxes"}},
		"bad gid":            {"name": "k", "kind": "data", "scope": kv{"type": "boxes", "gids": []string{"a b"}}},
		"wildcard gid":       {"name": "k", "kind": "data", "scope": kv{"type": "boxes", "gids": []string{"*"}}},
		"all with gids":      {"name": "k", "kind": "data", "scope": kv{"type": "all", "gids": []string{mock.GID1}}},
		"unknown scope type": {"name": "k", "kind": "data", "scope": kv{"type": "everything"}},
		"unknown permission": {"name": "k", "kind": "data", "scope": kv{"type": "all"}, "permissions": kv{"admin": "write"}},
		"bad level":          {"name": "k", "kind": "data", "scope": kv{"type": "all"}, "permissions": kv{"alarms": "owner"}},
		"flows write":        {"name": "k", "kind": "data", "scope": kv{"type": "all"}, "permissions": kv{"flows": "write"}},
		"boxes write":        {"name": "k", "kind": "data", "scope": kv{"type": "all"}, "permissions": kv{"boxes": "write"}},
		"admin with scope":   {"name": "k", "kind": "admin", "scope": kv{"type": "all"}},
		"admin with perms":   {"name": "k", "kind": "admin", "permissions": kv{"alarms": "read"}},
		"unknown field":      {"name": "k", "kind": "data", "scope": kv{"type": "all"}, "secret": "mb_x"},
		"id supplied":        {"name": "k", "kind": "data", "scope": kv{"type": "all"}, "id": "k_custom"},
		"past expiry":        {"name": "k", "kind": "data", "scope": kv{"type": "all"}, "expires_at": past},
		"bad expiry":         {"name": "k", "kind": "data", "scope": kv{"type": "all"}, "expires_at": "tomorrow"},
		"bad ip":             {"name": "k", "kind": "data", "scope": kv{"type": "all"}, "ip_allow": []string{"not-an-ip"}},
		"negative rate":      {"name": "k", "kind": "data", "scope": kv{"type": "all"}, "rate_limit": kv{"per_minute": -1}},
		"huge rate":          {"name": "k", "kind": "data", "scope": kv{"type": "all"}, "rate_limit": kv{"per_minute": 99999999}},
		"unknown rate field": {"name": "k", "kind": "data", "scope": kv{"type": "all"}, "rate_limit": kv{"per_hour": 5}},
		"notes too long":     {"name": "k", "kind": "data", "scope": kv{"type": "all"}, "notes": strings.Repeat("x", 1025)},
	}
	for name, body := range bad {
		r := h.do(admin, "POST", "/admin/v1/keys", j(body))
		if r.status != 400 {
			t.Errorf("%s: %d %s", name, r.status, r.body)
			continue
		}
		if r.obj(t)["error"] != "bad_request" || r.errCode(t) != "bad_request" || r.obj(t)["detail"] == "" {
			t.Errorf("%s: error shape %s", name, r.body)
		}
		h.wantBlocked("bad_request")
	}
	for name, body := range map[string]string{"empty": "", "not json": "name=x", "array": "[]", "trailing": `{"name":"k","kind":"data","scope":{"type":"all"}} {}`, "null": "null"} {
		r := h.do(admin, "POST", "/admin/v1/keys", withBody(body))
		if r.status != 400 {
			t.Errorf("body %s: %d %s", name, r.status, r.body)
		}
	}
	if r := h.do(admin, "POST", "/admin/v1/keys", withBody(strings.Repeat("x", 70000))); r.status != 413 {
		t.Errorf("oversize body: %d", r.status)
	}
	// Name conflict among active keys.
	r := h.do(admin, "POST", "/admin/v1/keys", j(kv{"name": "taken", "kind": "data", "scope": kv{"type": "all"}}))
	if r.status != 409 || r.errCode(t) != "name_taken" {
		t.Errorf("duplicate name: %d %s", r.status, r.body)
	}
	h.wantBlocked("conflict")
	// Nothing was created by any rejected request.
	keys, _ := h.st.ListKeys(t.Context(), true)
	if len(keys) != 2 {
		t.Errorf("%d keys exist, want 2", len(keys))
	}
}

func TestAdminCreateAdminKeyHasNoDataAccess(t *testing.T) {
	h := newHarness(t)
	_, admin := h.adminKey("admin")
	r := h.do(admin, "POST", "/admin/v1/keys", j(kv{"name": "second-admin", "kind": "admin"}))
	if r.status != 201 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	c := r.obj(t)
	if c["scope"] != nil || c["permissions"] != nil {
		t.Errorf("admin key view has scope/permissions: %v", c)
	}
	secret := c["secret"].(string)
	if r := h.get(secret, "/admin/v1/keys"); r.status != 200 {
		t.Errorf("new admin cannot administer: %d", r.status)
	}
	for _, p := range ids("/api/v1/me", "/api/v1/boxes", "/api/v1/alarms") {
		if r := h.get(secret, p); r.status != 403 || r.errCode(t) != "kind" {
			t.Errorf("admin on %s: %d %s", p, r.status, r.body)
		}
	}
}

// PATCH changes any field but kind, takes effect on the next request and
// leaves secrets alone.
func TestAdminPatchKey(t *testing.T) {
	h := newHarness(t)
	_, admin := h.adminKey("admin")
	k, secret := h.key("target", scopeExplicit, allRead())
	path := "/admin/v1/keys/" + k.ID
	before := h.get(admin, path).obj(t)
	prefix := before["secrets"].([]any)[0].(kv)["prefix"]

	if r := h.get(secret, "/api/v1/rules"); r.status != 200 {
		t.Fatalf("precondition: %d", r.status)
	}

	// Permission change: effective on the very next request, same secret.
	r := h.do(admin, "PATCH", path, j(kv{"permissions": kv{"rules": "none"}}))
	if r.status != 200 {
		t.Fatalf("patch: %d %s", r.status, r.body)
	}
	got := r.obj(t)
	if got["permissions"].(kv)["rules"] != "none" || got["permissions"].(kv)["alarms"] != "read" {
		t.Errorf("permissions are merged per resource: %v", got["permissions"])
	}
	if got["secrets"].([]any)[0].(kv)["prefix"] != prefix {
		t.Error("secrets changed")
	}
	if r := h.get(secret, "/api/v1/rules"); r.status != 403 || r.errCode(t) != "permission" {
		t.Errorf("after patch: %d %s", r.status, r.body)
	}
	if r := h.get(secret, "/api/v1/alarms"); r.status != 200 {
		t.Errorf("other permissions lost: %d", r.status)
	}

	// Scope replaced.
	if r := h.do(admin, "PATCH", path, j(kv{"scope": kv{"type": "groups", "group_ids": []string{mock.GroupB}}})); r.status != 200 {
		t.Fatalf("scope patch: %d %s", r.status, r.body)
	}
	if r := h.get(secret, "/api/v1/alarms"); !reflect.DeepEqual(r.owners(t, "gid"), ids(mock.GID3, mock.GID4)) {
		t.Errorf("scope not applied: %s", r.body)
	}

	// Disable, enable, expire, rename, notes, ip, rate limit.
	if r := h.do(admin, "PATCH", path, j(kv{"enabled": false})); r.status != 200 {
		t.Fatal(r.status)
	}
	if r := h.get(secret, "/api/v1/me"); r.status != 403 || r.errCode(t) != "disabled" {
		t.Errorf("disabled: %d %s", r.status, r.body)
	}
	h.do(admin, "PATCH", path, j(kv{"enabled": true}))
	if r := h.get(secret, "/api/v1/me"); r.status != 200 {
		t.Errorf("re-enabled: %d", r.status)
	}
	exp := h.clk.now().Add(time.Hour).Format(time.RFC3339)
	r = h.do(admin, "PATCH", path, j(kv{"expires_at": exp, "name": "renamed", "notes": "n", "ip_allow": []string{"192.0.2.50"}, "rate_limit": kv{"per_minute": 7}}))
	if r.status != 200 {
		t.Fatalf("multi patch: %d %s", r.status, r.body)
	}
	v := r.obj(t)
	if v["name"] != "renamed" || v["notes"] != "n" || v["expires_at"] == nil || v["rate_limit"].(kv)["per_minute"] != 7.0 ||
		!reflect.DeepEqual(v["ip_allow"], []any{"192.0.2.50/32"}) {
		t.Errorf("patched view: %v", v)
	}
	if r := h.get(secret, "/api/v1/me"); r.status != 200 || r.obj(t)["key"].(kv)["name"] != "renamed" {
		t.Errorf("renamed key: %d %s", r.status, r.body)
	}
	h.clk.advance(2 * time.Hour)
	if r := h.get(secret, "/api/v1/me"); r.status != 401 || r.errCode(t) != "expired" {
		t.Errorf("expired by patch: %d %s", r.status, r.body)
	}
	// null clears.
	r = h.do(admin, "PATCH", path, j(kv{"expires_at": nil, "ip_allow": nil, "rate_limit": nil}))
	if r.status != 200 {
		t.Fatalf("clear: %d %s", r.status, r.body)
	}
	v = r.obj(t)
	if v["expires_at"] != nil || v["rate_limit"] != nil || len(v["ip_allow"].([]any)) != 0 {
		t.Errorf("not cleared: %v", v)
	}
	if r := h.get(secret, "/api/v1/me"); r.status != 200 {
		t.Errorf("after clear: %d", r.status)
	}

	// The patch is audited with before and after, still without secrets.
	var upd []*store.AuditEntry
	for _, e := range h.auditRows() {
		if e.Resource == "keys" && e.Action == "update" && e.Outcome == store.OutcomeOK {
			upd = append(upd, e)
		}
	}
	if len(upd) < 5 {
		t.Fatalf("update audit rows: %d", len(upd))
	}
	first := upd[0]
	if !strings.Contains(string(first.Before), `"rules":"read"`) || !strings.Contains(string(first.After), `"rules":"none"`) || first.ObjectID != k.ID {
		t.Errorf("before/after: %s -> %s", first.Before, first.After)
	}
	if strings.Contains(string(first.Before)+string(first.After), secret) {
		t.Error("audit snapshot contains the secret")
	}
}

func TestAdminPatchRejects(t *testing.T) {
	h := newHarness(t)
	_, admin := h.adminKey("admin")
	k, _ := h.key("target", scopeExplicit, allRead())
	other, _ := h.key("other", scopeAll, allRead())
	adm2, _ := h.adminKey("admin-2")
	path := "/admin/v1/keys/" + k.ID
	bad := map[string]kv{
		"kind":                {"kind": "admin"},
		"same kind":           {"kind": "data"},
		"id":                  {"id": "k_new"},
		"secrets":             {"secrets": []any{}},
		"secret":              {"secret": "mb_x"},
		"created_at":          {"created_at": "2026-01-01T00:00:00Z"},
		"unknown":             {"colour": "red"},
		"empty":               {},
		"name type":           {"name": 5},
		"blank name":          {"name": ""},
		"enabled type":        {"enabled": "yes"},
		"flows write":         {"permissions": kv{"flows": "write"}},
		"unknown permission":  {"permissions": kv{"admin": "read"}},
		"invalid scope":       {"scope": kv{"type": "boxes", "gids": []string{}}},
		"scope extra field":   {"scope": kv{"type": "all", "x": 1}},
		"bad ip":              {"ip_allow": []string{"999.1.1.1"}},
		"bad rate":            {"rate_limit": kv{"per_minute": -5}},
		"permissions not obj": {"permissions": "read"},
	}
	for name, body := range bad {
		r := h.do(admin, "PATCH", path, j(body))
		if r.status != 400 {
			t.Errorf("%s: %d %s", name, r.status, r.body)
			continue
		}
		h.wantBlocked("bad_request")
	}
	// Nothing changed.
	now, _ := h.st.GetKey(t.Context(), k.ID)
	if now.Name != "target" || now.Kind != "data" || now.Permissions != allRead() {
		t.Errorf("a rejected patch changed the key: %+v", now)
	}
	// Admin keys take no scope or permissions, even by patch.
	for _, body := range []kv{{"scope": kv{"type": "all"}}, {"permissions": kv{"alarms": "read"}}} {
		if r := h.do(admin, "PATCH", "/admin/v1/keys/"+adm2.ID, j(body)); r.status != 400 {
			t.Errorf("admin key patch %v: %d %s", body, r.status, r.body)
		}
	}
	// Name conflicts, unknown and deleted keys.
	if r := h.do(admin, "PATCH", path, j(kv{"name": "other"})); r.status != 409 || r.errCode(t) != "name_taken" {
		t.Errorf("rename conflict: %d %s", r.status, r.body)
	}
	if r := h.do(admin, "PATCH", path, j(kv{"name": "target"})); r.status != 200 {
		t.Errorf("renaming to own name: %d", r.status)
	}
	if r := h.do(admin, "PATCH", "/admin/v1/keys/k_nope", j(kv{"notes": "x"})); r.status != 404 {
		t.Errorf("unknown key: %d", r.status)
	}
	if err := h.st.SoftDeleteKey(t.Context(), other.ID, h.clk.now()); err != nil {
		t.Fatal(err)
	}
	if r := h.do(admin, "PATCH", "/admin/v1/keys/"+other.ID, j(kv{"notes": "x"})); r.status != 404 {
		t.Errorf("deleted key patch: %d", r.status)
	}
	if r := h.get(admin, "/admin/v1/keys/"+other.ID); r.status != 404 {
		t.Errorf("deleted key get: %d", r.status)
	}
	list := h.get(admin, "/admin/v1/keys").obj(t)
	for _, it := range list["results"].([]any) {
		if it.(kv)["id"] == other.ID {
			t.Error("deleted key listed")
		}
	}
	// Odd ids in the path.
	for _, id := range ids("..", "k_a%2Fb", "%00", strings.Repeat("a", 300)) {
		if r := h.get(admin, "/admin/v1/keys/"+id); r.status != 404 {
			t.Errorf("id %q: %d", id, r.status)
		}
	}
}

func TestAdminBoxes(t *testing.T) {
	h := newHarness(t)
	_, admin := h.adminKey("admin")
	r := h.get(admin, "/admin/v1/boxes")
	if r.status != 200 || len(r.results(t)) != 5 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	byGID := map[string]any{}
	for _, b := range r.results(t) {
		byGID[b["gid"].(string)] = b["group"]
	}
	if byGID[mock.GID1] != mock.GroupA || byGID[mock.GID3] != mock.GroupB || byGID[mock.GID5] != nil {
		t.Errorf("groups: %v", byGID)
	}
	if strings.Contains(string(r.body), "publicIP") || strings.Contains(string(r.body), "203.0.113") {
		t.Errorf("admin box list should be the slim picker form: %s", r.body)
	}
	if e := h.lastAudit(); e.Resource != "boxes" || e.Action != "list" || e.ResultCount == nil || *e.ResultCount != 5 {
		t.Errorf("audit: %+v", e)
	}
	h.mock.InjectFault(mock.Fault{Status: 500, Times: 1})
	if r := h.get(admin, "/admin/v1/boxes"); r.status != 502 {
		t.Errorf("upstream failure: %d", r.status)
	}
}

func TestAdminAuditBrowsing(t *testing.T) {
	h := newHarness(t)
	_, admin := h.adminKey("admin")
	k1, s1 := h.key("alpha", scopeExplicit, allRead())
	_, s2 := h.key("beta", scopeAll, allRead())
	h.get(s1, "/api/v1/boxes/"+mock.GID1+"/alarms")
	h.clk.advance(time.Minute)
	h.get(s1, "/api/v1/boxes/"+mock.GID2+"/alarms") // blocked
	h.clk.advance(time.Minute)
	h.get(s2, "/api/v1/flows")
	h.get("", "/api/v1/flows") // auth failure

	type page struct {
		Count   float64 `json:"count"`
		Results []kv    `json:"results"`
		Next    string  `json:"next_cursor"`
	}
	list := func(qs string) page {
		t.Helper()
		r := h.get(admin, "/admin/v1/audit"+qs)
		if r.status != 200 {
			t.Fatalf("%s: %d %s", qs, r.status, r.body)
		}
		var p page
		if err := json.Unmarshal(r.body, &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	all := list("")
	if len(all.Results) < 4 || all.Results[0]["id"].(float64) < all.Results[1]["id"].(float64) {
		t.Fatalf("newest first expected: %v", all.Results)
	}
	if n := len(list("?key_id=" + k1.ID).Results); n != 2 {
		t.Errorf("key_id filter: %d", n)
	}
	if n := len(list("?gid=" + mock.GID2).Results); n != 1 {
		t.Errorf("gid filter: %d", n)
	}
	if n := len(list("?gid=" + strings.ToUpper(mock.GID2)).Results); n != 1 {
		t.Errorf("gid filter is case-insensitive: %d", n)
	}
	if n := len(list("?outcome=blocked").Results); n < 2 {
		t.Errorf("outcome filter: %d", n)
	}
	for _, e := range list("?outcome=blocked").Results {
		if e["outcome"] != "blocked" || e["block_reason"] == nil {
			t.Errorf("blocked row: %v", e)
		}
	}
	if n := len(list("?resource=flows").Results); n != 1 { // the unauthenticated attempt has no resource
		t.Errorf("resource filter: %d", n)
	}
	since := t0.Add(time.Minute).Format(time.RFC3339)
	for _, e := range list("?since=" + url.QueryEscape(since)).Results {
		if ts, _ := time.Parse(time.RFC3339Nano, e["ts"].(string)); ts.Before(t0.Add(time.Minute)) {
			t.Errorf("since not applied: %v", e["ts"])
		}
	}
	until := t0.Add(time.Minute).Format(time.RFC3339)
	for _, e := range list("?until=" + url.QueryEscape(until)).Results {
		if ts, _ := time.Parse(time.RFC3339Nano, e["ts"].(string)); !ts.Before(t0.Add(time.Minute)) {
			t.Errorf("until not applied: %v", e["ts"])
		}
	}
	// Cursor paging covers everything exactly once.
	seen := map[float64]bool{}
	p := list("?limit=2")
	for {
		if len(p.Results) > 2 {
			t.Fatalf("page too big: %d", len(p.Results))
		}
		for _, e := range p.Results {
			if seen[e["id"].(float64)] {
				t.Fatalf("id %v repeated", e["id"])
			}
			seen[e["id"].(float64)] = true
		}
		if p.Next == "" {
			break
		}
		p = list("?limit=2&cursor=" + p.Next)
	}
	if len(seen) < 6 {
		t.Errorf("paging saw %d entries", len(seen))
	}
	// Single entry.
	id := int(all.Results[len(all.Results)-1]["id"].(float64))
	r := h.get(admin, "/admin/v1/audit/"+strconv.Itoa(id))
	if r.status != 200 || r.obj(t)["id"] != float64(id) {
		t.Errorf("single: %d %s", r.status, r.body)
	}
	if r := h.get(admin, "/admin/v1/audit/999999"); r.status != 404 {
		t.Errorf("missing entry: %d", r.status)
	}
	for _, bad := range ids("?outcome=weird", "?since=yesterday", "?until=1", "?cursor=abc", "?cursor=0", "?limit=0", "?limit=5000",
		"?gid=a%20b", "?key_id=a%2Fb", "?unknown=1", "?key_id=a&key_id=b") {
		if r := h.get(admin, "/admin/v1/audit"+bad); r.status != 400 {
			t.Errorf("%s: %d %s", bad, r.status, r.body)
		}
	}
	for _, bad := range ids("abc", "0", "-1", "1.5") {
		if r := h.get(admin, "/admin/v1/audit/"+bad); r.status != 400 {
			t.Errorf("audit/%s: %d", bad, r.status)
		}
	}
}
