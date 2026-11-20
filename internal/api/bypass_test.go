package api_test

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"mspbroker/internal/acl"
	"mspbroker/internal/store"
	"mspbroker/internal/upstream/mock"
)

func q(s string) string { return url.QueryEscape(s) }

// nestedEscape percent-encodes s n times.
func nestedEscape(s string, n int) string {
	for i := 0; i < n; i++ {
		s = url.QueryEscape(s)
	}
	return s
}

// Box-qualifier bypass attempts in the `query` parameter. A key scoped to
// boxes 1 and 3 must never see box 2, whatever the spelling.
func TestBoxQualifierBypassAttempts(t *testing.T) {
	g1, g2, g3 := mock.GID1, mock.GID2, mock.GID3
	rejected := map[string]string{
		"plain":                 "box.id:" + g2,
		"upper case key":        "BOX.ID:" + g2,
		"mixed case key":        "Box.Id:" + g2,
		"upper case value":      "box.id:" + strings.ToUpper(g2),
		"single encoded":        q("box.id:" + g2),
		"double encoded":        q(q("box.id:" + g2)),
		"encoded dot":           "box%2Eid:" + g2,
		"encoded colon":         "box.id%3A" + g2,
		"or with allowed":       "box.id:" + g1 + " OR box.id:" + g2,
		"or lowercase":          "box.id:" + g1 + " or box.id:" + g2,
		"parenthesised":         "(box.id:" + g2 + ")",
		"nested":                "type:1 ((box.id:" + g1 + " OR box.id:" + g2 + ") status:1)",
		"negated dash":          "-box.id:" + g2,
		"negated NOT":           "NOT box.id:" + g2,
		"negated not lowercase": "not box.id:" + g2,
		"quoted key":            `"box.id":` + g2,
		"quoted value":          `box.id:"` + g2 + `"`,
		"quoted phrase":         `"box.id:` + g2 + `"`,
		"wildcard":              "box.id:*",
		"prefix wildcard":       "box.id:00000000*",
		"comma list":            "box.id:" + g1 + "," + g2,
		"value group":           "box.id:(" + g1 + " OR " + g2 + ")",
		"empty value":           "box.id:",
		"two qualifiers":        "box.id:" + g1 + " box.id:" + g2,
		"tab separated":         "box.id:" + g1 + "\tOR\tbox.id:" + g2,
		"newline separated":     "type:1\nbox.id:" + g2,
		"other qualifier case":  "box.id:" + g3 + " BOX.ID:" + g2,
		"trailing garbage":      "box.id:" + g2 + ")",
	}
	bothModes(t, func(t *testing.T, h *harness) {
		_, secret := h.key("bypass", scopeExplicit, allRead())
		for name, raw := range rejected {
			for _, base := range []string{"/api/v1/alarms", "/api/v1/flows", "/api/v1/rules"} {
				h.mock.ResetRequests()
				// Pre-encode: the value goes through the URL as-is.
				target := base + "?query=" + q(raw)
				r := h.get(secret, target)
				if r.status != 403 && r.status != 400 {
					t.Errorf("%s %s: %d %s", name, base, r.status, r.body)
					continue
				}
				if r.status == 403 {
					if r.errCode(t) != "out_of_scope" {
						t.Errorf("%s %s: code %s", name, base, r.errCode(t))
					}
					h.wantBlocked("out_of_scope")
				} else {
					h.wantBlocked("bad_request")
				}
				if n := len(h.mock.Requests()); n != 0 {
					t.Errorf("%s %s: rejected query reached the upstream (%d calls)", name, base, n)
				}
			}
		}
		// A per-box route accepts only its own box as a qualifier.
		for name, raw := range map[string]string{
			"other in-scope box":   "box.id:" + g3,
			"own box plus another": "box.id:" + g1 + " OR box.id:" + g3,
			"out of scope":         "box.id:" + g2,
		} {
			r := h.get(secret, "/api/v1/boxes/"+g1+"/alarms?query="+q(raw))
			if r.status != 403 || r.errCode(t) != "out_of_scope" {
				t.Errorf("per-box %s: %d %s", name, r.status, r.body)
			}
			if e := h.wantBlocked("out_of_scope"); e.GID != g1 {
				t.Errorf("per-box %s: audit gid %q", name, e.GID)
			}
		}
	})
}

// Parameter shapes that could smuggle a second query or a second box.
func TestQueryParameterBypassAttempts(t *testing.T) {
	g1, g2 := mock.GID1, mock.GID2
	bothModes(t, func(t *testing.T, h *harness) {
		_, secret := h.key("params", scopeExplicit, allRead())
		bad := map[string]string{
			"duplicate query":          "/api/v1/alarms?query=" + q("box.id:"+g1) + "&query=" + q("box.id:"+g2),
			"duplicate harmless":       "/api/v1/alarms?query=type:1&query=type:2",
			"upper case parameter":     "/api/v1/alarms?QUERY=" + q("box.id:"+g2),
			"box parameter":            "/api/v1/alarms?box=" + g2,
			"gid parameter":            "/api/v1/alarms?gid=" + g2,
			"group parameter":          "/api/v1/boxes/" + g1 + "/devices?group=" + mock.GroupB,
			"owner on alarms":          "/api/v1/alarms?owner=" + g2,
			"encoded parameter name":   "/api/v1/alarms?qu%65ry=" + q("box.id:"+g2),
			"semicolon separator":      "/api/v1/alarms?query=type:1;query=" + q("box.id:"+g2),
			"unknown parameter":        "/api/v1/alarms?debug=1",
			"query on rules paging":    "/api/v1/rules?limit=1",
			"query on boxes":           "/api/v1/boxes?query=" + q("box.id:"+g2),
			"query on devices":         "/api/v1/boxes/" + g1 + "/devices?box=" + g2,
			"duplicate limit":          "/api/v1/alarms?limit=1&limit=2",
			"negative limit":           "/api/v1/alarms?limit=-1",
			"zero limit":               "/api/v1/alarms?limit=0",
			"non numeric limit":        "/api/v1/alarms?limit=abc",
			"cursor with space":        "/api/v1/alarms?cursor=a%20b",
			"cursor with control":      "/api/v1/alarms?cursor=a%00b",
			"groupBy injection":        "/api/v1/alarms?groupBy=" + q("gid&box=x"),
			"sortBy injection":         "/api/v1/flows?sortBy=" + q("ts desc"),
			"overlong query":           "/api/v1/alarms?query=" + strings.Repeat("a", 9000),
			"control chars in query":   "/api/v1/alarms?query=" + q("type:1\x01"),
			"encoded too many times":   "/api/v1/alarms?query=" + nestedEscape("type:1", 12),
			"unbalanced parens":        "/api/v1/alarms?query=" + q("(type:1"),
			"bad percent escape in qs": "/api/v1/alarms?query=%zz",
		}
		for name, target := range bad {
			h.mock.ResetRequests()
			r := h.get(secret, target)
			if r.status != 400 && r.status != 403 {
				t.Errorf("%s: %d %s", name, r.status, r.body)
				continue
			}
			if e := h.lastAudit(); e.Outcome != store.OutcomeBlocked {
				t.Errorf("%s: audit %+v", name, e)
			}
			for _, rq := range h.mock.Requests() {
				if rq.Path != "/v2/boxes" {
					t.Errorf("%s: reached the upstream: %s?%s", name, rq.Path, rq.RawQuery)
				}
			}
		}
	})
}

// Qualifiers for boxes that are in scope are accepted, narrow the answer,
// and are re-issued by the broker in its own syntax.
func TestInScopeQualifiersNarrow(t *testing.T) {
	g1, g3 := mock.GID1, mock.GID3
	bothModes(t, func(t *testing.T, h *harness) {
		_, secret := h.key("narrow", scopeExplicit, allRead())
		// Narrowing is the upstream's job; against one that ignores filters
		// the guarantee is only that nothing outside the scope comes back.
		ignoring := strings.Contains(t.Name(), "ignores")
		cases := map[string][]string{
			"box.id:" + g1:                             ids(g1),
			"BOX.ID:" + strings.ToUpper(g3):            ids(g3),
			"box.id:" + g1 + " OR box.id:" + g3:        ids(g1, g3),
			"-box.id:" + g1:                            ids(g3),
			"type:1 OR type:2":                         ids(g1, g3), // top-level OR must not escape the filter
			"type:1":                                   ids(g1, g3),
			"box.id:" + g1 + " OR type:2":              ids(g1),
			"(type:1 OR type:2) -box.id:" + g3:         ids(g1),
			"status:1 box.id:" + g3 + " -box.id:" + g1: ids(g3),
		}
		for raw, want := range cases {
			r := h.get(secret, "/api/v1/alarms?query="+q(raw))
			if r.status != 200 {
				t.Errorf("%q: %d %s", raw, r.status, r.body)
				continue
			}
			got := r.owners(t, "gid")
			if ignoring {
				want = ids(g1, g3)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%q reached %v, want %v", raw, got, want)
			}
		}
		if ignoring {
			return
		}
		// What the upstream is asked is the broker's expression, not the caller's.
		h.mock.ResetRequests()
		h.get(secret, "/api/v1/alarms?query="+q("BOX.ID:"+strings.ToUpper(g1)+" type:1"))
		reqs := h.mock.RequestsTo("/v2/alarms")
		if len(reqs) != 1 {
			t.Fatalf("upstream alarm calls: %d", len(reqs))
		}
		if got := reqs[0].Param("query"); got != "type:1 box.id:"+g1 {
			t.Errorf("upstream saw %q", got)
		}
	})
}

// (c) With the upstream ignoring every filter, nothing out of scope leaks, on
// every list and every shape of query, including the empty one.
func TestPostFilterIsTheControl(t *testing.T) {
	h := newHarness(t, withIgnoreFilters())
	_, secret := h.key("pf", scopeExplicit, allRead())
	for _, p := range ids("/api/v1/alarms", "/api/v1/flows", "/api/v1/rules", "/api/v1/boxes", "/api/v1/target-lists",
		"/api/v1/alarms?query="+q("type:1"), "/api/v1/flows?limit=500", "/api/v1/alarms?sortBy=ts:desc") {
		r := h.get(secret, p)
		if r.status != 200 {
			t.Fatalf("%s: %d %s", p, r.status, r.body)
		}
		for _, o := range r.results(t) {
			for _, f := range ids("gid", "owner") {
				if v, ok := o[f].(string); ok && v != mock.GID1 && v != mock.GID3 && v != "global" {
					t.Errorf("%s leaked %s=%s", p, f, v)
				}
			}
		}
	}
	// The upstream really did return everything: the filter did the work.
	h.mock.ResetRequests()
	h.get(secret, "/api/v1/alarms")
	if n := len(h.mock.RequestsTo("/v2/alarms")); n != 1 {
		t.Fatalf("upstream calls: %d", n)
	}
}

// Short pages: post-filtering shrinks a page, the cursor still advances and
// the union of pages is exactly the in-scope set.
func TestPaginationWithPostFilter(t *testing.T) {
	h := newHarness(t, withIgnoreFilters())
	_, secret := h.key("pages", scopeExplicit, allRead())
	seen := map[string]bool{}
	cursor, pages, short := "", 0, false
	for {
		target := "/api/v1/alarms?limit=4"
		if cursor != "" {
			target += "&cursor=" + url.QueryEscape(cursor)
		}
		r := h.get(secret, target)
		if r.status != 200 {
			t.Fatalf("page %d: %d %s", pages, r.status, r.body)
		}
		pages++
		res := r.results(t)
		if len(res) < 4 {
			short = true
		}
		for _, o := range res {
			seen[o["aid"].(string)] = true
			if g := o["gid"]; g != mock.GID1 && g != mock.GID3 {
				t.Fatalf("leak: %v", o)
			}
		}
		next, _ := r.obj(t)["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
		if pages > 10 {
			t.Fatal("no end")
		}
	}
	if len(seen) != 6 || pages != 4 || !short {
		t.Errorf("alarms seen %d over %d pages (short page seen: %v)", len(seen), pages, short)
	}
	// groupBy, sortBy and limit are passed through; limit is clamped.
	h.mock.ResetRequests()
	h.get(secret, "/api/v1/alarms?limit=9999&sortBy=ts:asc&groupBy=type")
	reqs := h.mock.RequestsTo("/v2/alarms")
	if len(reqs) != 1 || reqs[0].Param("limit") != "500" || reqs[0].Param("sortBy") != "ts:asc" || reqs[0].Param("groupBy") != "type" {
		t.Errorf("pass-through: %+v", reqs)
	}
}

// Group membership is read from the box list and cached for the TTL.
func TestGroupMembershipChangeAfterCacheTTL(t *testing.T) {
	h := newHarness(t, withTTL(60*time.Second))
	_, secret := h.key("grp", scopeGroupA, allRead())
	flows := func() []string {
		t.Helper()
		r := h.get(secret, "/api/v1/flows")
		if r.status != 200 {
			t.Fatalf("flows: %d %s", r.status, r.body)
		}
		return r.owners(t, "gid")
	}
	if got := flows(); !reflect.DeepEqual(got, ids(mock.GID1, mock.GID2)) {
		t.Fatalf("initial: %v", got)
	}
	if h.boxesCalls() != 1 {
		t.Fatalf("box list fetched %d times", h.boxesCalls())
	}

	// Box 3 joins group A and box 2 leaves it.
	h.mock.Update(func(s *mock.State) {
		s.Boxes[1]["group"] = mock.GroupB
		s.Boxes[2]["group"] = mock.GroupA
	})
	h.clk.advance(30 * time.Second)
	if got := flows(); !reflect.DeepEqual(got, ids(mock.GID1, mock.GID2)) {
		t.Errorf("inside the TTL the old membership applies, got %v", got)
	}
	if h.boxesCalls() != 1 {
		t.Errorf("box list refetched inside the TTL (%d)", h.boxesCalls())
	}
	// Explicit access to the departed box still works until the cache turns over.
	if r := h.get(secret, "/api/v1/boxes/"+mock.GID2+"/devices"); r.status != 200 {
		t.Errorf("inside the TTL: %d", r.status)
	}

	h.clk.advance(31 * time.Second)
	if got := flows(); !reflect.DeepEqual(got, ids(mock.GID1, mock.GID3)) {
		t.Errorf("after the TTL: %v", got)
	}
	if h.boxesCalls() != 2 {
		t.Errorf("box list fetches: %d", h.boxesCalls())
	}
	if r := h.get(secret, "/api/v1/boxes/"+mock.GID2+"/devices"); r.status != 403 || r.errCode(t) != "out_of_scope" {
		t.Errorf("departed box: %d %s", r.status, r.body)
	}
	if r := h.get(secret, "/api/v1/boxes/"+mock.GID3+"/devices"); r.status != 200 {
		t.Errorf("joined box: %d %s", r.status, r.body)
	}
}

// A group-scoped request whose cache is stale and whose refresh fails is
// refused, not served from the stale list; explicit and `all` keys do not
// depend on the box list at all.
func TestGroupResolutionFailsClosed(t *testing.T) {
	h := newHarness(t, withTTL(time.Minute))
	_, grp := h.key("grp", scopeGroupA, allRead())
	_, explicit := h.key("exp", scopeExplicit, allRead())
	_, all := h.key("all", scopeAll, allRead())
	if r := h.get(grp, "/api/v1/flows"); r.status != 200 {
		t.Fatal(r.status)
	}
	h.clk.advance(2 * time.Minute)
	h.mock.InjectFault(mock.Fault{Status: 500, Times: 1})
	r := h.get(grp, "/api/v1/flows")
	if r.status != 502 || len(r.body) == 0 || strings.Contains(string(r.body), "results") {
		t.Errorf("stale + failing refresh: %d %s", r.status, r.body)
	}
	if e := h.lastAudit(); e.Outcome != store.OutcomeUpstreamError || e.UpstreamStatus == nil || *e.UpstreamStatus != 500 {
		t.Errorf("audit: %+v", e)
	}
	// Recovers when the upstream does.
	if r := h.get(grp, "/api/v1/flows"); r.status != 200 {
		t.Errorf("after recovery: %d", r.status)
	}
	// Explicit and `all` keys never need the box list: an outage of the box
	// endpoint alone does not affect them.
	h.mock.ResetRequests()
	for _, secret := range ids(explicit, all) {
		if r := h.get(secret, "/api/v1/flows"); r.status != 200 {
			t.Errorf("flows: %d", r.status)
		}
	}
	if n := h.boxesCalls(); n != 0 {
		t.Errorf("explicit/all keys fetched the box list %d times", n)
	}
}

// A box that appears later is in scope for `all` keys and not for lists.
func TestNewBoxUnderAll(t *testing.T) {
	h := newHarness(t)
	_, all := h.key("all", scopeAll, allRead())
	_, explicit := h.key("exp", scopeExplicit, allRead())
	_, grp := h.key("grp", scopeGroupA, allRead())
	h.get(grp, "/api/v1/flows") // fills the group cache before the box appears

	const gid6 = "00000000-0000-0000-0000-000000000006"
	h.mock.Update(func(s *mock.State) {
		s.Boxes = append(s.Boxes, mock.Object{"gid": gid6, "name": "Example Box 6", "group": mock.GroupA})
		s.Alarms = append(s.Alarms, mock.Object{"aid": "61", "gid": gid6, "ts": 1700009999, "type": 1, "message": "Example alarm on box 6"})
		s.Devices = append(s.Devices, mock.Object{"id": mock.DeviceMAC, "gid": gid6, "name": "Example Device 6"})
	})
	for _, mode := range []string{"filtering", "ignoring"} {
		h.mock.SetIgnoreFilters(mode == "ignoring")
		r := h.get(all, "/api/v1/alarms")
		if !contains(r.owners(t, "gid"), gid6) {
			t.Errorf("%s: all key does not see the new box: %v", mode, r.owners(t, "gid"))
		}
		if r := h.get(all, "/api/v1/boxes/"+gid6+"/alarms/61"); r.status != 200 {
			t.Errorf("%s: new box alarm: %d %s", mode, r.status, r.body)
		}
		if r := h.get(all, "/api/v1/boxes"); !contains(r.owners(t, "gid"), gid6) {
			t.Errorf("%s: boxes list lacks the new box", mode)
		}
		r = h.get(explicit, "/api/v1/alarms")
		if contains(r.owners(t, "gid"), gid6) {
			t.Errorf("%s: explicit key sees the new box", mode)
		}
		if r := h.get(explicit, "/api/v1/boxes/"+gid6+"/devices"); r.status != 403 {
			t.Errorf("%s: explicit key on new box: %d", mode, r.status)
		}
	}
	// The new box is in group A, but the group cache has not turned over.
	h.mock.SetIgnoreFilters(false)
	if r := h.get(grp, "/api/v1/alarms"); contains(r.owners(t, "gid"), gid6) {
		t.Error("group key saw the new box before the cache refreshed")
	}
	h.clk.advance(2 * time.Minute)
	if r := h.get(grp, "/api/v1/alarms"); !contains(r.owners(t, "gid"), gid6) {
		t.Errorf("group key does not see the new box after the TTL: %v", r.owners(t, "gid"))
	}
}

// Case and whitespace tricks in path gids never reach another box.
func TestPathGIDTricks(t *testing.T) {
	bothModes(t, func(t *testing.T, h *harness) {
		_, secret := h.key("paths", scopeExplicit, allRead())
		for _, g := range ids(mock.GID2, strings.ToUpper(mock.GID2), "%2e%2e", "%00", "..", "*", "00000000-0000-0000-0000-00000000000%32",
			"00000000-0000-0000-0000-000000000002%20", "%20"+mock.GID2, mock.GID1+"%2C"+mock.GID2, mock.GID1+"%00", mock.GID1+"x") {
			r := h.get(secret, "/api/v1/boxes/"+g+"/devices")
			if r.status != 403 && r.status != 404 {
				t.Errorf("gid %q: %d %s", g, r.status, r.body)
			}
		}
		// The in-scope id in another case is the same box.
		r := h.get(secret, "/api/v1/boxes/"+strings.ToUpper(mock.GID1)+"/devices")
		if r.status != 200 || !reflect.DeepEqual(r.owners(t, "gid"), ids(mock.GID1)) {
			t.Errorf("upper-case gid: %d %s", r.status, r.body)
		}
	})
}

var _ = acl.ScopeAll
var _ = http.StatusOK
