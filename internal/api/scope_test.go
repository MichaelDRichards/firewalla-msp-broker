package api_test

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"mspbroker/internal/acl"
	"mspbroker/internal/store"
	"mspbroker/internal/upstream/mock"
)

// scopeCase names a scope fixture and the boxes it must reach on the seed.
type scopeCase struct {
	name  string
	scope acl.Scope
	boxes []string
}

var scopeCases = []scopeCase{
	{"explicit boxes", scopeExplicit, ids(mock.GID1, mock.GID3)},
	{"group", scopeGroupA, ids(mock.GID1, mock.GID2)},
	{"all", scopeAll, ids(mock.GID1, mock.GID2, mock.GID3, mock.GID4, mock.GID5)},
	{"boxes+groups", scopeMixed, ids(mock.GID3, mock.GID4, mock.GID5)},
}

var allGIDs = ids(mock.GID1, mock.GID2, mock.GID3, mock.GID4, mock.GID5)

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// listEndpoint is a global (not per-box) list and the field that carries the
// owning box of each result.
type listEndpoint struct {
	path     string
	field    string
	perBox   int // objects per box in the seed
	resource string
}

var globalLists = []listEndpoint{
	{"/api/v1/boxes", "gid", 1, "boxes"},
	{"/api/v1/alarms", "gid", 3, "alarms"},
	{"/api/v1/rules", "gid", 2, "rules"},
	{"/api/v1/flows", "gid", 4, "flows"},
}

// perBoxLists are the per-box list endpoints.
var perBoxLists = []struct {
	suffix   string
	perBox   int
	resource string
}{
	{"/devices", 1, "devices"},
	{"/alarms", 3, "alarms"},
	{"/rules", 2, "rules"},
	{"/flows", 4, "flows"},
}

// bothModes runs f against a normal upstream and one that ignores every
// filter, which is the case the post-filter exists for.
func bothModes(t *testing.T, f func(t *testing.T, h *harness)) {
	t.Run("filtering upstream", func(t *testing.T) { f(t, newHarness(t)) })
	t.Run("upstream ignores filters", func(t *testing.T) { f(t, newHarness(t, withIgnoreFilters())) })
}

// (a) Scope filtering on every global read endpoint, for every scope shape.
func TestGlobalListsAreScoped(t *testing.T) {
	bothModes(t, func(t *testing.T, h *harness) {
		for _, sc := range scopeCases {
			_, secret := h.key("scope-"+strings.ReplaceAll(sc.name, " ", "-"), sc.scope, allRead())
			for _, ep := range globalLists {
				r := h.get(secret, ep.path)
				if r.status != http.StatusOK {
					t.Fatalf("%s %s: %d %s", sc.name, ep.path, r.status, r.body)
				}
				if got := r.owners(t, ep.field); !reflect.DeepEqual(got, sc.boxes) {
					t.Errorf("%s %s reached boxes %v, want %v", sc.name, ep.path, got, sc.boxes)
				}
				if want := len(sc.boxes) * ep.perBox; len(r.results(t)) != want {
					t.Errorf("%s %s: %d results, want %d", sc.name, ep.path, len(r.results(t)), want)
				}
				if c := r.obj(t)["count"]; int(c.(float64)) != len(r.results(t)) {
					t.Errorf("%s %s: count %v disagrees with results", sc.name, ep.path, c)
				}
				// The audit row says how many objects survived filtering.
				e := h.lastAudit()
				if e.Outcome != store.OutcomeOK || e.ResultCount == nil || *e.ResultCount != len(r.results(t)) {
					t.Errorf("%s %s: audit %+v", sc.name, ep.path, e)
				}
			}
		}
	})
}

// Target lists: owner is the ownership field, global lists need their own
// permission.
func TestTargetListsAreScoped(t *testing.T) {
	bothModes(t, func(t *testing.T, h *harness) {
		want := map[string][]string{
			"explicit boxes": ids("global", mock.GID1, mock.GID3),
			"group":          ids("global", mock.GID1),
			"all":            ids("global", mock.GID1, mock.GID3, mock.GID5),
			"boxes+groups":   ids("global", mock.GID3, mock.GID5),
		}
		for _, sc := range scopeCases {
			_, secret := h.key("tl-"+strings.ReplaceAll(sc.name, " ", "-"), sc.scope, allRead())
			r := h.get(secret, "/api/v1/target-lists")
			if r.status != 200 {
				t.Fatalf("%s: %d %s", sc.name, r.status, r.body)
			}
			got := r.owners(t, "owner")
			if !reflect.DeepEqual(got, sortedCopy(want[sc.name])) {
				t.Errorf("%s: owners %v, want %v", sc.name, got, want[sc.name])
			}
		}
	})
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// Per-box lists and single-object reads: every box is either served with
// only its own objects or refused with out_of_scope, and the refusal is
// audited with the box id.
func TestPerBoxEndpointsAreScoped(t *testing.T) {
	bothModes(t, func(t *testing.T, h *harness) {
		for _, sc := range scopeCases {
			_, secret := h.key("pb-"+strings.ReplaceAll(sc.name, " ", "-"), sc.scope, allRead())
			for _, gid := range allGIDs {
				in := contains(sc.boxes, gid)
				for _, ep := range perBoxLists {
					path := "/api/v1/boxes/" + gid + ep.suffix
					r := h.get(secret, path)
					if in {
						if r.status != 200 {
							t.Fatalf("%s %s: %d %s", sc.name, path, r.status, r.body)
						}
						if got := r.owners(t, "gid"); !reflect.DeepEqual(got, ids(gid)) {
							t.Errorf("%s %s returned boxes %v", sc.name, path, got)
						}
						if len(r.results(t)) != ep.perBox {
							t.Errorf("%s %s: %d results, want %d", sc.name, path, len(r.results(t)), ep.perBox)
						}
						continue
					}
					if r.status != 403 || r.errCode(t) != "out_of_scope" || r.obj(t)["error"] != "forbidden" {
						t.Errorf("%s %s: %d %s", sc.name, path, r.status, r.body)
					}
					if e := h.wantBlocked("out_of_scope"); e.GID != gid {
						t.Errorf("%s %s: audit gid %q", sc.name, path, e.GID)
					}
				}

				// Single box.
				r := h.get(secret, "/api/v1/boxes/"+gid)
				checkSingle(t, h, sc.name+" box", r, in, gid, "gid")

				// Single alarm: aid is "<box number><alarm number>".
				n := gid[len(gid)-1:]
				r = h.get(secret, "/api/v1/boxes/"+gid+"/alarms/"+n+"2")
				checkSingle(t, h, sc.name+" alarm", r, in, gid, "gid")
			}
		}
	})
}

func checkSingle(t *testing.T, h *harness, what string, r *resp, in bool, gid, field string) {
	t.Helper()
	if in {
		if r.status != 200 || r.obj(t)[field] != gid {
			t.Errorf("%s %s: %d %s", what, gid, r.status, r.body)
		}
		return
	}
	if r.status != 403 || r.errCode(t) != "out_of_scope" {
		t.Errorf("%s %s: %d %s", what, gid, r.status, r.body)
	}
	h.wantBlocked("out_of_scope")
}

// Single target lists: ownership decides.
func TestSingleTargetListScope(t *testing.T) {
	bothModes(t, func(t *testing.T, h *harness) {
		_, secret := h.key("tl-single", scopeExplicit, allRead())
		for id, want := range map[string]int{"tl-1": 200, "tl-3": 200, "tl-5": 403, "tl-global-1": 200, "tl-global-2": 200} {
			r := h.get(secret, "/api/v1/target-lists/"+id)
			if r.status != want {
				t.Errorf("%s: %d %s", id, r.status, r.body)
			}
			if want == 403 && r.errCode(t) != "out_of_scope" {
				t.Errorf("%s: code %s", id, r.errCode(t))
			}
		}
		if r := h.get(secret, "/api/v1/target-lists/tl-missing"); r.status != 404 {
			t.Errorf("missing list: %d %s", r.status, r.body)
		}
	})
}

// (b) Permission levels: none is refused with code permission, read and
// write both pass (write implies read).
func TestPermissionLevelsOnEveryReadEndpoint(t *testing.T) {
	type ep struct {
		resource acl.Resource
		paths    []string
	}
	eps := []ep{
		{acl.Boxes, ids("/api/v1/boxes", "/api/v1/boxes/"+mock.GID1)},
		{acl.Devices, ids("/api/v1/boxes/" + mock.GID1 + "/devices")},
		{acl.Alarms, ids("/api/v1/alarms", "/api/v1/boxes/"+mock.GID1+"/alarms", "/api/v1/boxes/"+mock.GID1+"/alarms/12")},
		{acl.Rules, ids("/api/v1/rules", "/api/v1/boxes/"+mock.GID1+"/rules")},
		{acl.Flows, ids("/api/v1/flows", "/api/v1/boxes/"+mock.GID1+"/flows")},
		{acl.TargetLists, ids("/api/v1/target-lists/tl-1")},
	}
	bothModes(t, func(t *testing.T, h *harness) {
		for _, e := range eps {
			for _, level := range []acl.Level{acl.None, acl.Read, acl.Write} {
				perms, err := (acl.Permissions{}).Set(e.resource, level)
				if err != nil {
					t.Fatal(err)
				}
				_, secret := h.key(fmt.Sprintf("perm-%s-%s", e.resource, level), scopeAll, perms)
				for _, p := range e.paths {
					r := h.get(secret, p)
					if level == acl.None {
						if r.status != 403 || r.errCode(t) != "permission" || r.obj(t)["error"] != "forbidden" {
							t.Errorf("%s=%s %s: %d %s", e.resource, level, p, r.status, r.body)
						}
						h.wantBlocked("permission")
						continue
					}
					if r.status != 200 {
						t.Errorf("%s=%s %s: %d %s", e.resource, level, p, r.status, r.body)
					}
				}
			}
		}
		// A key with only one resource cannot read the others.
		_, secret := h.key("only-alarms", scopeAll, acl.Permissions{Alarms: acl.Read})
		for _, p := range ids("/api/v1/boxes", "/api/v1/rules", "/api/v1/flows", "/api/v1/boxes/"+mock.GID1+"/devices", "/api/v1/target-lists") {
			if r := h.get(secret, p); r.status != 403 || r.errCode(t) != "permission" {
				t.Errorf("only-alarms %s: %d %s", p, r.status, r.body)
			}
		}
	})
}

// The read-only resources cap at read: a stored "write" on flows or boxes
// (not creatable through the admin API) behaves as read.
func TestReadOnlyResourcesCapAtRead(t *testing.T) {
	h := newHarness(t)
	_, secret := h.key("capped", scopeAll, acl.Permissions{Boxes: acl.Write, Flows: acl.Write})
	for _, p := range ids("/api/v1/boxes", "/api/v1/flows") {
		if r := h.get(secret, p); r.status != 200 {
			t.Errorf("%s: %d %s", p, r.status, r.body)
		}
	}
}

// Target lists have two permissions: target_lists for box-owned lists and
// global_target_lists for MSP-owned ones.
func TestTargetListPermissionMatrix(t *testing.T) {
	type tc struct {
		boxes, global acl.Level
		list          []string // owners expected from the list endpoint
		status        int
	}
	cases := []tc{
		{acl.None, acl.None, nil, 403},
		{acl.Read, acl.None, ids(mock.GID1, mock.GID3), 200},
		{acl.None, acl.Read, ids("global"), 200},
		{acl.Read, acl.Read, ids("global", mock.GID1, mock.GID3), 200},
		{acl.Write, acl.Write, ids("global", mock.GID1, mock.GID3), 200},
		{acl.Write, acl.None, ids(mock.GID1, mock.GID3), 200},
		{acl.None, acl.Write, ids("global"), 200},
	}
	bothModes(t, func(t *testing.T, h *harness) {
		for i, c := range cases {
			_, secret := h.key(fmt.Sprintf("tlm-%d", i), scopeExplicit, acl.Permissions{TargetLists: c.boxes, GlobalTargetLists: c.global})
			label := fmt.Sprintf("target_lists=%s global=%s", c.boxes, c.global)
			r := h.get(secret, "/api/v1/target-lists")
			if r.status != c.status {
				t.Fatalf("%s list: %d %s", label, r.status, r.body)
			}
			if c.status == 403 {
				if r.errCode(t) != "permission" {
					t.Errorf("%s: code %s", label, r.errCode(t))
				}
				h.wantBlocked("permission")
			} else if got := r.owners(t, "owner"); !reflect.DeepEqual(got, sortedCopy(c.list)) {
				t.Errorf("%s list owners %v, want %v", label, got, c.list)
			}

			// Single lists: global needs the global permission, box-owned
			// the box permission, whatever the other says.
			wantGlobal, wantBox := 403, 403
			if c.global >= acl.Read {
				wantGlobal = 200
			}
			if c.boxes >= acl.Read {
				wantBox = 200
			}
			rg := h.get(secret, "/api/v1/target-lists/tl-global-1")
			rb := h.get(secret, "/api/v1/target-lists/tl-1")
			if rg.status != wantGlobal || rb.status != wantBox {
				t.Errorf("%s single: global %d box %d, want %d %d", label, rg.status, rb.status, wantGlobal, wantBox)
			}
			for _, rr := range []*resp{rg, rb} {
				if rr.status == 403 && rr.errCode(t) != "permission" {
					t.Errorf("%s: single 403 code %s", label, rr.errCode(t))
				}
			}
		}
	})
}

// owner= narrows the list but never widens it.
func TestTargetListOwnerParameter(t *testing.T) {
	bothModes(t, func(t *testing.T, h *harness) {
		_, secret := h.key("owner-param", scopeExplicit, allRead())
		r := h.get(secret, "/api/v1/target-lists?owner="+mock.GID1)
		if r.status != 200 || !reflect.DeepEqual(r.owners(t, "owner"), ids(mock.GID1)) {
			t.Errorf("owner=gid1: %d %s", r.status, r.body)
		}
		r = h.get(secret, "/api/v1/target-lists?owner=GLOBAL,"+strings.ToUpper(mock.GID3))
		if r.status != 200 || !reflect.DeepEqual(r.owners(t, "owner"), sortedCopy(ids("global", mock.GID3))) {
			t.Errorf("owner=global,gid3: %d %s", r.status, r.body)
		}
		for _, bad := range ids("?owner="+mock.GID2, "?owner="+mock.GID1+","+mock.GID5, "?owner=*", "?owner=,", "?owner="+mock.GID1+",%20"+mock.GID2) {
			r := h.get(secret, "/api/v1/target-lists"+bad)
			if r.status != 403 && r.status != 400 {
				t.Errorf("%s: %d %s", bad, r.status, r.body)
			}
		}
		// global requested without the permission, box list without its own.
		_, onlyBox := h.key("owner-box", scopeExplicit, acl.Permissions{TargetLists: acl.Read})
		if r := h.get(onlyBox, "/api/v1/target-lists?owner=global"); r.status != 403 || r.errCode(t) != "permission" {
			t.Errorf("owner=global without permission: %d %s", r.status, r.body)
		}
		_, onlyGlobal := h.key("owner-global", scopeExplicit, acl.Permissions{GlobalTargetLists: acl.Read})
		if r := h.get(onlyGlobal, "/api/v1/target-lists?owner="+mock.GID1); r.status != 403 || r.errCode(t) != "permission" {
			t.Errorf("owner=gid without target_lists: %d %s", r.status, r.body)
		}
	})
}

// A key whose scope resolves to nothing gets empty lists without any
// upstream call.
func TestEmptyScopeMakesNoUpstreamCall(t *testing.T) {
	h := newHarness(t)
	_, secret := h.key("empty-group", acl.Scope{Type: acl.ScopeGroups, GroupIDs: []string{"group-does-not-exist"}}, allRead())
	h.mock.ResetRequests()
	for _, p := range ids("/api/v1/alarms", "/api/v1/rules", "/api/v1/flows") {
		r := h.get(secret, p)
		if r.status != 200 || len(r.results(t)) != 0 {
			t.Errorf("%s: %d %s", p, r.status, r.body)
		}
	}
	// Box-owned target lists: nothing in scope. Global lists are a separate
	// grant and this key holds it.
	if r := h.get(secret, "/api/v1/target-lists"); r.status != 200 || !reflect.DeepEqual(r.owners(t, "owner"), ids("global")) {
		t.Errorf("target-lists: %d %s", r.status, r.body)
	}
	for _, rq := range h.mock.Requests() {
		if rq.Path != "/v2/boxes" && rq.Path != "/v2/target-lists" {
			t.Errorf("unexpected upstream call %s?%s", rq.Path, rq.RawQuery)
		}
	}
}
