package acl

import (
	"encoding/json"
	"strings"
	"testing"
)

// Placeholder fixtures (SPEC 15).
const (
	g1 = "00000000-0000-0000-0000-000000000001"
	g2 = "00000000-0000-0000-0000-000000000002"
	g3 = "00000000-0000-0000-0000-000000000003"
	g4 = "00000000-0000-0000-0000-000000000004"
	g5 = "00000000-0000-0000-0000-000000000005"
)

// Fleet: g1,g2 in group-a; g3 in group-b; g4 ungrouped.
var fleet = []Box{
	{GID: g1, GroupID: "group-a"},
	{GID: g2, GroupID: "group-a"},
	{GID: g3, GroupID: "group-b"},
	{GID: g4},
}

var allGIDs = []string{g1, g2, g3, g4, g5} // g5 is not in the fleet ("future" box)

func TestLevelText(t *testing.T) {
	for _, l := range []Level{None, Read, Write} {
		b, err := l.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var back Level
		if err := back.UnmarshalText(b); err != nil || back != l {
			t.Errorf("round trip %v: %v %v", l, back, err)
		}
	}
	var l Level
	for _, bad := range []string{"", "admin", "READ", "2"} {
		if err := l.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("UnmarshalText(%q) accepted", bad)
		}
	}
	if _, err := Level(9).MarshalText(); err == nil {
		t.Error("Level(9) marshalled")
	}
}

func TestPermissionsJSON(t *testing.T) {
	var p Permissions
	if err := json.Unmarshal([]byte(`{"rules":"write","alarms":"read"}`), &p); err != nil {
		t.Fatal(err)
	}
	if p.Rules != Write || p.Alarms != Read || p.Devices != None || p.GlobalTargetLists != None {
		t.Errorf("missing fields must default to none: %+v", p)
	}
	b, _ := json.Marshal(p)
	if !strings.Contains(string(b), `"rules":"write"`) || !strings.Contains(string(b), `"global_target_lists":"none"`) {
		t.Errorf("marshal: %s", b)
	}
	if err := json.Unmarshal([]byte(`{"rules":"root"}`), &p); err == nil {
		t.Error("accepted bogus level")
	}
}

// TestAllowsMatrix checks every resource x level x action, with expectations
// written out independently of the implementation.
func TestAllowsMatrix(t *testing.T) {
	writable := map[Resource]bool{
		Boxes: false, Devices: true, Alarms: true, Rules: true,
		Flows: false, TargetLists: true, Stats: false, GlobalTargetLists: true,
	}
	if len(writable) != len(Resources) {
		t.Fatal("matrix does not cover every resource")
	}
	for _, r := range Resources {
		for _, lvl := range []Level{None, Read, Write} {
			p, err := Permissions{}.Set(r, lvl)
			if err != nil {
				t.Fatal(err)
			}
			wantRead := lvl >= Read
			wantWrite := lvl == Write && writable[r]
			if got := p.Allows(r, ActionRead); got != wantRead {
				t.Errorf("%s=%s read: got %v want %v", r, lvl, got, wantRead)
			}
			if got := p.Allows(r, ActionWrite); got != wantWrite {
				t.Errorf("%s=%s write: got %v want %v", r, lvl, got, wantWrite)
			}
			// Granting one resource never grants another.
			for _, other := range Resources {
				if other == r {
					continue
				}
				if p.Allows(other, ActionRead) || p.Allows(other, ActionWrite) {
					t.Errorf("%s=%s leaked access to %s", r, lvl, other)
				}
			}
			// Validate accepts exactly what the resource can hold.
			err = p.Validate()
			if (lvl == Write && !writable[r]) == (err == nil) {
				t.Errorf("%s=%s Validate: %v", r, lvl, err)
			}
		}
	}
}

func TestAllowsDefaultDeny(t *testing.T) {
	full := Permissions{Boxes: Read, Devices: Write, Alarms: Write, Rules: Write, Flows: Read, TargetLists: Write, Stats: Read, GlobalTargetLists: Write}
	for _, r := range []Resource{"", "users", "keys", "BOXES", "boxes ", "audit", "target-lists"} {
		for _, a := range []Action{ActionRead, ActionWrite} {
			if full.Allows(r, a) {
				t.Errorf("unknown resource %q allowed for %s", r, a)
			}
		}
	}
	for _, a := range []Action{"", "delete", "archive", "READ", "admin"} {
		for _, r := range Resources {
			if full.Allows(r, a) {
				t.Errorf("unknown action %q allowed on %s", a, r)
			}
		}
	}
	// Out-of-range stored levels are not honoured.
	if (Permissions{Rules: Level(99)}).Allows(Rules, ActionWrite) {
		t.Error("Level(99) granted write")
	}
	if (Permissions{Rules: Level(-1)}).Allows(Rules, ActionRead) {
		t.Error("Level(-1) granted read")
	}
	// A hand-built flows=write is capped at read.
	p := Permissions{Flows: Write}
	if !p.Allows(Flows, ActionRead) || p.Allows(Flows, ActionWrite) {
		t.Error("flows must cap at read")
	}
	if _, err := p.Set("nope", Read); err == nil {
		t.Error("Set accepted unknown resource")
	}
	if err := (Permissions{Rules: Level(7)}).Validate(); err == nil {
		t.Error("Validate accepted bad level")
	}
}

func TestKindAndAuthorize(t *testing.T) {
	rw := Permissions{Rules: Write, Alarms: Read}
	cases := []struct {
		name string
		kind Kind
		surf Surface
		want Code
	}{
		{"data on data", KindData, SurfaceData, ""},
		{"admin on admin", KindAdmin, SurfaceAdmin, ""},
		{"admin on data", KindAdmin, SurfaceData, CodeKind},
		{"data on admin", KindData, SurfaceAdmin, CodeKind},
		{"unknown kind on data", "root", SurfaceData, CodeKind},
		{"empty kind on admin", "", SurfaceAdmin, CodeKind},
		{"data on unknown surface", KindData, "internal", CodeKind},
	}
	for _, c := range cases {
		d := CheckKind(c.kind, c.surf)
		if (d == nil) != (c.want == "") || (d != nil && d.Code != c.want) {
			t.Errorf("%s: got %v want %q", c.name, d, c.want)
		}
	}

	az := []struct {
		name string
		kind Kind
		res  Resource
		act  Action
		want Code
	}{
		{"data rules write", KindData, Rules, ActionWrite, ""},
		{"data rules read (write implies read)", KindData, Rules, ActionRead, ""},
		{"data alarms read", KindData, Alarms, ActionRead, ""},
		{"data alarms write denied", KindData, Alarms, ActionWrite, CodePermission},
		{"data devices read denied", KindData, Devices, ActionRead, CodePermission},
		{"data unknown resource", KindData, "keys", ActionRead, CodePermission},
		{"admin key with full perms still kind-denied", KindAdmin, Rules, ActionRead, CodeKind},
	}
	for _, c := range az {
		d := Authorize(c.kind, rw, c.res, c.act)
		if (d == nil) != (c.want == "") || (d != nil && d.Code != c.want) {
			t.Errorf("%s: got %v want %q", c.name, d, c.want)
		}
	}
	if d := Authorize(KindData, rw, Devices, ActionRead); d == nil || d.Error() == "" || d.Detail == "" {
		t.Errorf("denial should carry a detail: %v", d)
	}
}

func TestScopeValidate(t *testing.T) {
	bad := []Scope{
		{},
		{Type: "everything"},
		{Type: ScopeAll, GIDs: []string{g1}},
		{Type: ScopeAll, GroupIDs: []string{"a"}},
		{Type: ScopeBoxes},
		{Type: ScopeBoxes, GIDs: []string{g1}, GroupIDs: []string{"a"}},
		{Type: ScopeBoxes, GIDs: []string{"has space"}},
		{Type: ScopeBoxes, GIDs: []string{"a,b"}},
		{Type: ScopeBoxes, GIDs: []string{"*"}},
		{Type: ScopeGroups},
		{Type: ScopeGroups, GroupIDs: []string{"a"}, GIDs: []string{g1}},
		{Type: ScopeGroups, GroupIDs: []string{" "}},
		{Type: ScopeBoxesGroups, GIDs: []string{g1}},
		{Type: ScopeBoxesGroups, GroupIDs: []string{"a"}},
	}
	for i, s := range bad {
		if s.Validate() == nil {
			t.Errorf("bad[%d] %+v accepted", i, s)
		}
	}
	good := []Scope{
		{Type: ScopeAll},
		{Type: ScopeBoxes, GIDs: []string{g1, g2}},
		{Type: ScopeGroups, GroupIDs: []string{"group-a"}},
		{Type: ScopeBoxesGroups, GIDs: []string{g3}, GroupIDs: []string{"group-a"}},
	}
	for i, s := range good {
		if err := s.Validate(); err != nil {
			t.Errorf("good[%d]: %v", i, err)
		}
	}
}

func TestValidGID(t *testing.T) {
	for _, s := range []string{g1, "abc-123", "A", strings.Repeat("a", 64)} {
		if !ValidGID(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []string{"", " ", "a b", "a,b", "a:b", "a(b", "a)b", "*", "a*", "a\"b", "a\nb", "é", strings.Repeat("a", 65), "a%20b"} {
		if ValidGID(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

// TestScopeResolutionMatrix: scope type x box in fleet -> allowed or not.
func TestScopeResolutionMatrix(t *testing.T) {
	scopes := []struct {
		name  string
		scope Scope
		allow map[string]bool // gid -> allowed
		all   bool
	}{
		{"all", Scope{Type: ScopeAll}, map[string]bool{g1: true, g2: true, g3: true, g4: true, g5: true}, true},
		{"boxes g1,g3", Scope{Type: ScopeBoxes, GIDs: []string{g1, g3}}, map[string]bool{g1: true, g3: true}, false},
		{"boxes lists a box not in fleet", Scope{Type: ScopeBoxes, GIDs: []string{g5}}, map[string]bool{g5: true}, false},
		{"group-a", Scope{Type: ScopeGroups, GroupIDs: []string{"group-a"}}, map[string]bool{g1: true, g2: true}, false},
		{"group-a,group-b", Scope{Type: ScopeGroups, GroupIDs: []string{"group-a", "group-b"}}, map[string]bool{g1: true, g2: true, g3: true}, false},
		{"unknown group", Scope{Type: ScopeGroups, GroupIDs: []string{"group-z"}}, map[string]bool{}, false},
		{"group-b + box g4", Scope{Type: ScopeBoxesGroups, GIDs: []string{g4}, GroupIDs: []string{"group-b"}}, map[string]bool{g3: true, g4: true}, false},
		{"group-a + box g1 (overlap)", Scope{Type: ScopeBoxesGroups, GIDs: []string{g1}, GroupIDs: []string{"group-a"}}, map[string]bool{g1: true, g2: true}, false},
		{"invalid scope fails closed", Scope{Type: ScopeBoxes}, map[string]bool{}, false},
		{"zero scope fails closed", Scope{}, map[string]bool{}, false},
	}
	for _, sc := range scopes {
		t.Run(sc.name, func(t *testing.T) {
			e := Resolve(sc.scope, fleet)
			if e.All() != sc.all {
				t.Errorf("All() = %v", e.All())
			}
			for _, g := range allGIDs {
				if got := e.Contains(g); got != sc.allow[g] {
					t.Errorf("Contains(%s) = %v want %v", g, got, sc.allow[g])
				}
			}
			if wantEmpty := !sc.all && len(sc.allow) == 0; e.Empty() != wantEmpty {
				t.Errorf("Empty() = %v", e.Empty())
			}
			if !sc.all {
				if got := len(e.GIDs()); got != len(sc.allow) {
					t.Errorf("GIDs() = %v", e.GIDs())
				}
			}
			if e.Contains("") {
				t.Error("empty gid must never be in scope")
			}
		})
	}
}

func TestScopeGroupMembershipChanges(t *testing.T) {
	s := Scope{Type: ScopeGroups, GroupIDs: []string{"group-a"}}
	// g3 moves into group-a, g1 leaves it (the next cache refresh).
	moved := []Box{{GID: g1, GroupID: "group-b"}, {GID: g2, GroupID: "group-a"}, {GID: g3, GroupID: "group-a"}, {GID: g4}}
	e := Resolve(s, moved)
	if e.Contains(g1) || !e.Contains(g2) || !e.Contains(g3) || e.Contains(g4) {
		t.Errorf("membership move not reflected: %v", e.GIDs())
	}
	// Empty box list: groups resolve to nothing, explicit gids survive.
	if !Resolve(s, nil).Empty() {
		t.Error("group scope with no boxes must be empty")
	}
	if !Resolve(Scope{Type: ScopeBoxes, GIDs: []string{g1}}, nil).Contains(g1) {
		t.Error("explicit gid must survive an empty box list")
	}
	// A box with no gid never matches.
	if !Resolve(s, []Box{{GID: "", GroupID: "group-a"}}).Empty() {
		t.Error("gid-less box must not enter scope")
	}
}

func TestEffectiveCaseAndNilSafety(t *testing.T) {
	e := Resolve(Scope{Type: ScopeBoxes, GIDs: []string{"AbC-1"}}, nil)
	for _, g := range []string{"abc-1", "ABC-1", " abc-1 "} {
		if !e.Contains(g) {
			t.Errorf("%q should match case-insensitively", g)
		}
	}
	if e.Contains("abc-2") {
		t.Error("different gid matched")
	}
	var nilE *Effective
	if nilE.Contains(g1) || nilE.All() || !nilE.Empty() || nilE.GIDs() != nil {
		t.Error("nil Effective must deny everything")
	}
	if (&Effective{}).Contains(g1) {
		t.Error("zero Effective must deny")
	}
}

func objs(ms ...map[string]any) []map[string]any { return ms }

func TestPostFilter(t *testing.T) {
	e := Resolve(Scope{Type: ScopeBoxes, GIDs: []string{g1, g2}}, fleet)
	in := objs(
		map[string]any{"gid": g1, "id": "a"},
		map[string]any{"gid": g3, "id": "b"},
		map[string]any{"gid": g2, "id": "c"},
		map[string]any{"gid": strings.ToUpper(g2), "id": "d"},
		map[string]any{"id": "no-owner"},
		map[string]any{"gid": 7, "id": "numeric"},
		map[string]any{"gid": nil, "id": "null"},
		map[string]any{"gid": "", "id": "empty"},
		map[string]any{"gid": "  ", "id": "blank"},
		map[string]any{"gid": g1, "owner": g3, "id": "conflict"},
		map[string]any{"owner": g1, "id": "e"},
		map[string]any{"owner": "global", "id": "global-list"},
		map[string]any{"owner": "GLOBAL", "id": "global-upper"},
		map[string]any{"owner": g4, "id": "other-owner"},
		nil,
	)
	ids := func(out []map[string]any) string {
		var s []string
		for _, o := range out {
			s = append(s, o["id"].(string))
		}
		return strings.Join(s, ",")
	}
	if got := ids(FilterObjects(in, e, false)); got != "a,c,d,e" {
		t.Errorf("without global: %s", got)
	}
	if got := ids(FilterObjects(in, e, true)); got != "a,c,d,e,global-list,global-upper" {
		t.Errorf("with global: %s", got)
	}
	if got := FilterObjects(nil, e, true); got == nil || len(got) != 0 {
		t.Errorf("nil input must give empty non-nil slice, got %#v", got)
	}
	if len(in) != 15 {
		t.Error("input was modified")
	}
	// Empty and nil scopes drop everything, even global when not allowed.
	if len(FilterObjects(in, Resolve(Scope{}, fleet), false)) != 0 || len(FilterObjects(in, nil, false)) != 0 {
		t.Error("empty scope must drop all")
	}
	// All scope still drops objects without an owner, and gates global.
	all := Resolve(Scope{Type: ScopeAll}, nil)
	if got := ids(FilterObjects(in, all, false)); !strings.Contains(got, "other-owner") || strings.Contains(got, "no-owner") || strings.Contains(got, "numeric") || strings.Contains(got, "global") {
		t.Errorf("all scope: %s", got)
	}
}

func TestPostFilterGeneric(t *testing.T) {
	type dev struct{ GID, Name string }
	e := Resolve(Scope{Type: ScopeBoxes, GIDs: []string{g1}}, nil)
	in := []dev{{g1, "a"}, {g2, "b"}, {"", "c"}}
	out := Filter(in, e, false, func(d dev) []string { return []string{d.GID} })
	if len(out) != 1 || out[0].Name != "a" {
		t.Errorf("got %+v", out)
	}
	if got := Filter([]dev{{g1, "a"}}, e, false, func(dev) []string { return nil }); len(got) != 0 {
		t.Error("no identifiers must drop")
	}
}
