package mock

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

type resp struct {
	status int
	header http.Header
	body   []byte
}

func do(t *testing.T, srv *httptest.Server, method, path, auth string) resp {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, res.Header, b}
}

func newServer(t *testing.T, opts ...Option) (*Mock, *httptest.Server) {
	t.Helper()
	m := New(opts...)
	srv := m.Start()
	t.Cleanup(srv.Close)
	return m, srv
}

func get(t *testing.T, m *Mock, srv *httptest.Server, path string) resp {
	t.Helper()
	return do(t, srv, "GET", path, "Bearer "+m.Token())
}

func objects(t *testing.T, b []byte) []Object {
	t.Helper()
	var out []Object
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("not an array: %v: %s", err, b)
	}
	return out
}

type page struct {
	Count      int      `json:"count"`
	Results    []Object `json:"results"`
	NextCursor string   `json:"next_cursor"`
}

func pageOf(t *testing.T, r resp) page {
	t.Helper()
	if r.status != 200 {
		t.Fatalf("status %d: %s", r.status, r.body)
	}
	var p page
	if err := json.Unmarshal(r.body, &p); err != nil {
		t.Fatalf("not an envelope: %v: %s", err, r.body)
	}
	return p
}

func gids(objs []Object, field string) []string {
	seen := map[string]bool{}
	for _, o := range objs {
		seen[str(o[field])] = true
	}
	var out []string
	for g := range seen {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

func eq(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

func TestAuth(t *testing.T) {
	m, srv := newServer(t)
	cases := []struct {
		name, auth string
		want       int
	}{
		{"none", "", 401},
		{"wrong", "Bearer nope", 401},
		{"empty bearer", "Bearer ", 401},
		{"wrong scheme", "Basic " + m.Token(), 401},
		{"bare token", m.Token(), 401},
		{"bearer", "Bearer " + m.Token(), 200},
		{"token scheme", "Token " + m.Token(), 200},
		{"lowercase scheme", "bearer " + m.Token(), 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if r := do(t, srv, "GET", "/v2/boxes", c.auth); r.status != c.want {
				t.Fatalf("status %d, want %d: %s", r.status, c.want, r.body)
			}
		})
	}
	r := do(t, srv, "GET", "/v2/boxes", "Bearer nope")
	var e Object
	_ = json.Unmarshal(r.body, &e)
	if e["error"] != "unauthorized" || strings.Contains(string(r.body), "nope") {
		t.Fatalf("bad 401 body: %s", r.body)
	}
	// Unknown paths are also behind auth.
	if r := do(t, srv, "GET", "/v2/nothing", ""); r.status != 401 {
		t.Fatalf("unauthenticated unknown path: %d", r.status)
	}
	if r := get(t, m, srv, "/v2/nothing"); r.status != 404 {
		t.Fatalf("authenticated unknown path: %d", r.status)
	}
}

func TestCustomToken(t *testing.T) {
	_, srv := newServer(t, WithToken("other-example-token"))
	if r := do(t, srv, "GET", "/v2/boxes", "Bearer "+DefaultToken); r.status != 401 {
		t.Fatalf("default token accepted: %d", r.status)
	}
	if r := do(t, srv, "GET", "/v2/boxes", "Bearer other-example-token"); r.status != 200 {
		t.Fatalf("custom token rejected: %d", r.status)
	}
}

func TestOnlyReadEndpointsAreModelled(t *testing.T) {
	m, srv := newServer(t)
	for _, method := range []string{"POST", "PATCH", "DELETE", "PUT"} {
		if r := do(t, srv, method, "/v2/rules", "Bearer "+m.Token()); r.status != 404 {
			t.Fatalf("%s /v2/rules = %d", method, r.status)
		}
	}
	if r := get(t, m, srv, "/v2/groups"); r.status != 404 {
		t.Fatalf("groups listing exists: %d", r.status)
	}
}

func TestBoxes(t *testing.T) {
	m, srv := newServer(t)
	boxes := objects(t, get(t, m, srv, "/v2/boxes").body)
	if len(boxes) != 5 {
		t.Fatalf("%d boxes", len(boxes))
	}
	groups := map[string]any{}
	for _, b := range boxes {
		groups[str(b["gid"])] = b["group"]
	}
	want := map[string]any{GID1: GroupA, GID2: GroupA, GID3: GroupB, GID4: GroupB, GID5: nil}
	for g, w := range want {
		if groups[g] != w {
			t.Errorf("box %s group = %v, want %v", g, groups[g], w)
		}
	}
}

func TestDevicesFilters(t *testing.T) {
	m, srv := newServer(t)
	cases := []struct {
		query string
		want  []string
	}{
		{"", []string{GID1, GID2, GID3, GID4, GID5}},
		{"?box=" + GID2, []string{GID2}},
		{"?box=" + GID1 + "," + GID5, []string{GID1, GID5}},
		{"?box=" + strings.ToUpper(GID3), []string{GID3}},
		{"?group=" + GroupA, []string{GID1, GID2}},
		{"?group=" + GroupB, []string{GID3, GID4}},
		{"?group=" + GroupA + "," + GroupB, []string{GID1, GID2, GID3, GID4}},
		{"?group=" + GroupA + "&box=" + GID2, []string{GID2}},
		{"?group=" + GroupA + "&box=" + GID3, nil},
		{"?group=no-such-group", nil},
		{"?box=" + GID5 + "&group=" + GroupA, nil},
	}
	for _, c := range cases {
		devs := objects(t, get(t, m, srv, "/v2/devices"+c.query).body)
		if got := gids(devs, "gid"); !eq(got, c.want) {
			t.Errorf("devices%s = %v, want %v", c.query, got, c.want)
		}
	}
}

func TestAlarmsQueryFilter(t *testing.T) {
	m, srv := newServer(t)
	cases := []struct {
		name, query string
		want        []string
	}{
		{"none", "", []string{GID1, GID2, GID3, GID4, GID5}},
		{"one box", "box.id:" + GID2, []string{GID2}},
		{"two boxes", "(box.id:" + GID1 + " OR box.id:" + GID4 + ")", []string{GID1, GID4}},
		{"comma list", "box.id:" + GID1 + "," + GID3, []string{GID1, GID3}},
		{"exclusion", "-box.id:" + GID1 + " -box.id:" + GID2, []string{GID3, GID4, GID5}},
		{"NOT", "NOT box.id:" + GID5, []string{GID1, GID2, GID3, GID4}},
		{"user term and box", "type:2 box.id:" + GID3, []string{GID3}},
		{"user OR parenthesised then box", "(type:1 OR type:2) box.id:" + GID1, []string{GID1}},
		{"nothing matches", "box.id:" + GID1 + " box.id:" + GID2, nil},
		{"unknown box", "box.id:00000000-0000-0000-0000-0000000000ff", nil},
		{"nested path", "device.name:\"Example Device 4\"", []string{GID4}},
		{"wildcard", "message:\"*box 5\"", []string{GID5}},
		{"bare word", "\"alarm 3 on box 2\"", []string{GID2}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := pageOf(t, get(t, m, srv, "/v2/alarms?limit=500&query="+urlEscape(c.query)))
			if got := gids(p.Results, "gid"); !eq(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			if p.Count != len(p.Results) {
				t.Fatalf("count %d != %d results", p.Count, len(p.Results))
			}
		})
	}
}

func urlEscape(s string) string {
	r := strings.NewReplacer("%", "%25", " ", "%20", "&", "%26", "+", "%2B", "\"", "%22", "#", "%23")
	return r.Replace(s)
}

func TestBadQuery(t *testing.T) {
	m, srv := newServer(t)
	for _, q := range []string{"(box.id:" + GID1, "box.id:" + GID1 + ")", "type:\"unterminated", "a AND"} {
		r := get(t, m, srv, "/v2/alarms?query="+urlEscape(q))
		if r.status != 400 {
			t.Errorf("query %q: status %d", q, r.status)
		}
	}
}

func TestCursorPagination(t *testing.T) {
	m, srv := newServer(t)
	var all []Object
	path := "/v2/alarms?limit=4"
	pages := 0
	for path != "" {
		p := pageOf(t, get(t, m, srv, path))
		pages++
		if len(p.Results) > 4 {
			t.Fatalf("page too big: %d", len(p.Results))
		}
		all = append(all, p.Results...)
		path = ""
		if p.NextCursor != "" {
			path = "/v2/alarms?limit=4&cursor=" + p.NextCursor
		}
		if pages > 10 {
			t.Fatal("pagination does not terminate")
		}
	}
	if pages != 4 || len(all) != 15 {
		t.Fatalf("pages=%d items=%d", pages, len(all))
	}
	seen := map[string]bool{}
	var prev float64 = 1 << 60
	for _, a := range all {
		id := str(a["gid"]) + "/" + str(a["aid"])
		if seen[id] {
			t.Fatalf("duplicate %s", id)
		}
		seen[id] = true
		if ts := num(a["ts"]); ts > prev {
			t.Fatalf("not newest first at %s", id)
		} else {
			prev = ts
		}
	}
	// Pagination applies to the filtered set.
	p := pageOf(t, get(t, m, srv, "/v2/alarms?limit=2&query=box.id:"+GID1))
	if len(p.Results) != 2 || p.NextCursor == "" {
		t.Fatalf("filtered first page: %+v", p)
	}
	p2 := pageOf(t, get(t, m, srv, "/v2/alarms?limit=2&query=box.id:"+GID1+"&cursor="+p.NextCursor))
	if len(p2.Results) != 1 || p2.NextCursor != "" {
		t.Fatalf("filtered last page: %+v", p2)
	}
	// Invalid input.
	for _, q := range []string{"cursor=!!!", "cursor=" + encodeCursor(1) + "x", "limit=0", "limit=abc", "limit=-1"} {
		if r := get(t, m, srv, "/v2/alarms?"+q); r.status != 400 {
			t.Errorf("%s: status %d", q, r.status)
		}
	}
	// A cursor past the end is an empty last page; a huge limit is clamped.
	if p := pageOf(t, get(t, m, srv, "/v2/alarms?cursor="+encodeCursor(9999))); len(p.Results) != 0 || p.NextCursor != "" {
		t.Fatalf("past end: %+v", p)
	}
	if p := pageOf(t, get(t, m, srv, "/v2/alarms?limit=100000")); len(p.Results) != 15 {
		t.Fatalf("clamped limit: %d", len(p.Results))
	}
}

func TestAlarmGet(t *testing.T) {
	m, srv := newServer(t)
	r := get(t, m, srv, "/v2/alarms/"+GID2+"/21")
	if r.status != 200 {
		t.Fatalf("status %d: %s", r.status, r.body)
	}
	var a Object
	_ = json.Unmarshal(r.body, &a)
	if a["gid"] != GID2 || a["aid"] != "21" {
		t.Fatalf("wrong alarm: %v", a)
	}
	// An alarm id under the wrong box is not found.
	for _, p := range []string{"/v2/alarms/" + GID1 + "/21", "/v2/alarms/" + GID2 + "/999"} {
		if r := get(t, m, srv, p); r.status != 404 {
			t.Errorf("%s: %d", p, r.status)
		}
	}
}

func TestRulesAndFlows(t *testing.T) {
	m, srv := newServer(t)
	p := pageOf(t, get(t, m, srv, "/v2/rules"))
	if len(p.Results) != 10 {
		t.Fatalf("%d rules", len(p.Results))
	}
	p = pageOf(t, get(t, m, srv, "/v2/rules?query="+urlEscape("box.id:"+GID3+" status:paused")))
	if len(p.Results) != 1 || p.Results[0]["id"] != "rule-32" {
		t.Fatalf("paused rule of box 3: %v", p.Results)
	}
	p = pageOf(t, get(t, m, srv, "/v2/flows?limit=500"))
	if len(p.Results) != 20 {
		t.Fatalf("%d flows", len(p.Results))
	}
	p = pageOf(t, get(t, m, srv, "/v2/flows?query="+urlEscape("(box.id:"+GID4+" OR box.id:"+GID5+") block:true")))
	if got := gids(p.Results, "gid"); !eq(got, []string{GID4, GID5}) || len(p.Results) != 2 {
		t.Fatalf("blocked flows: %v", p.Results)
	}
}

func TestTargetLists(t *testing.T) {
	m, srv := newServer(t)
	owners := func(q string) []string {
		return gids(objects(t, get(t, m, srv, "/v2/target-lists"+q).body), "owner")
	}
	cases := []struct {
		q    string
		want []string
	}{
		{"", []string{GID1, GID3, GID5, GlobalOwner}},
		{"?owner=global", []string{GlobalOwner}},
		{"?owner=" + GID1, []string{GID1}},
		{"?owner=global," + GID3, []string{GID3, GlobalOwner}},
		{"?owner=" + GID2, nil},
		{"?owner=GLOBAL", []string{GlobalOwner}},
	}
	for _, c := range cases {
		if got := owners(c.q); !eq(got, c.want) {
			t.Errorf("owner query %q = %v, want %v", c.q, got, c.want)
		}
	}
	if n := len(objects(t, get(t, m, srv, "/v2/target-lists?owner=global").body)); n != 2 {
		t.Errorf("%d global lists", n)
	}
	if r := get(t, m, srv, "/v2/target-lists/tl-3"); r.status != 200 {
		t.Errorf("tl-3: %d", r.status)
	}
	if r := get(t, m, srv, "/v2/target-lists/nope"); r.status != 404 {
		t.Errorf("missing list: %d", r.status)
	}
}

func TestStatsAndTrends(t *testing.T) {
	m, srv := newServer(t)
	s := objects(t, get(t, m, srv, "/v2/stats/topBoxesByBlockedFlows").body)
	if len(s) != 5 {
		t.Fatalf("%d stats rows", len(s))
	}
	s = objects(t, get(t, m, srv, "/v2/stats/topBoxesBySecurityAlarms?group="+GroupB).body)
	if got := gids(s, "gid"); !eq(got, []string{GID3, GID4}) {
		t.Fatalf("stats group filter: %v", got)
	}
	tr := objects(t, get(t, m, srv, "/v2/trends/flows?box="+GID5).body)
	if got := gids(tr, "gid"); !eq(got, []string{GID5}) || len(tr) != 3 {
		t.Fatalf("trend box filter: %v (%d rows)", got, len(tr))
	}
	for _, p := range []string{"/v2/stats/nope", "/v2/trends/nope"} {
		if r := get(t, m, srv, p); r.status != 404 {
			t.Errorf("%s: %d", p, r.status)
		}
	}
}

// The switch that proves the post-filter is the control: with filters
// ignored the mock returns everything whatever was asked.
func TestIgnoreFilters(t *testing.T) {
	m, srv := newServer(t)
	m.SetIgnoreFilters(true)
	for _, c := range []struct {
		path  string
		count int
	}{
		{"/v2/devices?box=" + GID1, 5},
		{"/v2/devices?group=" + GroupA, 5},
		{"/v2/target-lists?owner=" + GID1, 5},
		{"/v2/stats/topBoxesByBlockedFlows?box=" + GID1, 5},
		{"/v2/trends/flows?box=" + GID1, 15},
	} {
		if n := len(objects(t, get(t, m, srv, c.path).body)); n != c.count {
			t.Errorf("%s: %d items, want %d", c.path, n, c.count)
		}
	}
	for path, want := range map[string]int{
		"/v2/alarms?limit=500&query=box.id:" + GID1: 15,
		"/v2/rules?query=box.id:" + GID1:            10,
		"/v2/flows?limit=500&query=box.id:" + GID1:  20,
		"/v2/alarms?limit=500&query=(((":            15, // not even parsed
	} {
		if n := len(pageOf(t, get(t, m, srv, path)).Results); n != want {
			t.Errorf("%s: %d items, want %d", path, n, want)
		}
	}
	// Cursors still work with filters ignored.
	p := pageOf(t, get(t, m, srv, "/v2/alarms?limit=10&query=box.id:"+GID1))
	if len(p.Results) != 10 || p.NextCursor == "" {
		t.Fatalf("paging with ignored filters: %+v", p)
	}
	m.SetIgnoreFilters(false)
	if n := len(objects(t, get(t, m, srv, "/v2/devices?box="+GID1).body)); n != 1 {
		t.Fatalf("filters did not come back: %d", n)
	}
}

func TestIgnoreFiltersOption(t *testing.T) {
	m, srv := newServer(t, WithIgnoreFilters(true))
	if n := len(objects(t, get(t, m, srv, "/v2/devices?box="+GID1).body)); n != 5 {
		t.Fatalf("got %d", n)
	}
}

func TestRecordsRequests(t *testing.T) {
	m, srv := newServer(t)
	q := "box.id:" + GID1 + " OR box.id:" + GID2
	get(t, m, srv, "/v2/alarms?limit=3&query="+urlEscape(q))
	do(t, srv, "GET", "/v2/boxes", "Bearer wrong")
	get(t, m, srv, "/v2/devices?box="+GID3)

	reqs := m.Requests()
	if len(reqs) != 3 {
		t.Fatalf("%d requests", len(reqs))
	}
	if r := reqs[0]; r.Method != "GET" || r.Path != "/v2/alarms" || r.Param("query") != q || r.Param("limit") != "3" || !r.Authenticated || r.Status != 200 {
		t.Errorf("request 0: %+v", r)
	}
	if r := reqs[1]; r.Authenticated || r.Status != 401 {
		t.Errorf("request 1: %+v", r)
	}
	if got := m.RequestsTo("/v2/devices"); len(got) != 1 || got[0].Param("box") != GID3 {
		t.Errorf("RequestsTo: %+v", got)
	}
	// The recorder never keeps credentials.
	if strings.Contains(strings.ToLower(strings.Join(func() []string {
		var s []string
		for _, r := range reqs {
			s = append(s, r.RawQuery, r.Path)
		}
		return s
	}(), " ")), "bearer") {
		t.Error("recorded request leaks auth")
	}
	m.ResetRequests()
	if len(m.Requests()) != 0 {
		t.Error("not reset")
	}
}

func TestFaults(t *testing.T) {
	m, srv := newServer(t)
	m.InjectFault(Fault{Status: 429, RetryAfter: "7", Times: 2})
	for i := 0; i < 2; i++ {
		r := get(t, m, srv, "/v2/boxes")
		if r.status != 429 || r.header.Get("Retry-After") != "7" {
			t.Fatalf("attempt %d: %d %v", i, r.status, r.header)
		}
	}
	if r := get(t, m, srv, "/v2/boxes"); r.status != 200 {
		t.Fatalf("fault should be spent: %d", r.status)
	}
	// Faults do not apply to unauthenticated requests: they still get 401.
	m.InjectFault(Fault{Status: 503, Body: `{"error":"x"}`})
	if r := do(t, srv, "GET", "/v2/boxes", ""); r.status != 401 {
		t.Fatalf("unauthenticated: %d", r.status)
	}
	if r := get(t, m, srv, "/v2/boxes"); r.status != 503 || string(r.body) != `{"error":"x"}` {
		t.Fatalf("custom body: %d %s", r.status, r.body)
	}
	m.ClearFaults()
	if r := get(t, m, srv, "/v2/boxes"); r.status != 200 {
		t.Fatalf("cleared: %d", r.status)
	}
}

func TestLatencyHonoursCancellation(t *testing.T) {
	m, srv := newServer(t)
	m.SetLatency(2 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/v2/boxes", nil)
	req.Header.Set("Authorization", "Bearer "+m.Token())
	start := time.Now()
	if _, err := http.DefaultClient.Do(req); err == nil {
		t.Fatal("expected a timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatal("did not stop early")
	}
}

func TestUpdateState(t *testing.T) {
	m, srv := newServer(t)
	m.Update(func(s *State) {
		// Box 5 joins group A.
		s.Boxes[4]["group"] = GroupA
	})
	devs := objects(t, get(t, m, srv, "/v2/devices?group="+GroupA).body)
	if got := gids(devs, "gid"); !eq(got, []string{GID1, GID2, GID5}) {
		t.Fatalf("after move: %v", got)
	}
}

func TestEmptyState(t *testing.T) {
	m, srv := newServer(t, WithState(State{}))
	if r := get(t, m, srv, "/v2/boxes"); strings.TrimSpace(string(r.body)) != "[]" {
		t.Fatalf("boxes: %s", r.body)
	}
	if r := get(t, m, srv, "/v2/alarms"); !strings.Contains(string(r.body), `"results":[]`) {
		t.Fatalf("alarms: %s", r.body)
	}
}

// Seed data must contain only documented placeholder values (SPEC 15).
func TestSeedUsesOnlyPlaceholders(t *testing.T) {
	s := Seed()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)

	for _, ip := range regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`).FindAllString(text, -1) {
		if !(strings.HasPrefix(ip, "192.0.2.") || strings.HasPrefix(ip, "198.51.100.") || strings.HasPrefix(ip, "203.0.113.")) {
			t.Errorf("non-placeholder IP %s", ip)
		}
	}
	for _, mac := range regexp.MustCompile(`(?i)\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b`).FindAllString(text, -1) {
		if mac != DeviceMAC {
			t.Errorf("non-placeholder MAC %s", mac)
		}
	}
	for _, h := range regexp.MustCompile(`[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.(com|net|org|io|local|lan)\b`).FindAllString(text, -1) {
		if !strings.HasSuffix(h, "example.com") && !strings.HasSuffix(h, "example.net") {
			t.Errorf("non-placeholder host %s", h)
		}
	}
	if strings.Contains(text, "@") {
		t.Error("seed contains an @ (email-like value)")
	}
	for _, g := range regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`).FindAllString(text, -1) {
		if !strings.HasPrefix(g, "00000000-0000-0000-0000-00000000000") {
			t.Errorf("non-placeholder id %s", g)
		}
	}

	// Shape of the seed: 2 groups, one ungrouped box, global lists, objects everywhere.
	groups := map[string]int{}
	for _, bx := range s.Boxes {
		g, _ := bx["group"].(string)
		groups[g]++
	}
	if groups[GroupA] != 2 || groups[GroupB] != 2 || groups[""] != 1 {
		t.Errorf("group layout: %v", groups)
	}
	global := 0
	for _, tl := range s.TargetLists {
		if tl["owner"] == GlobalOwner {
			global++
		}
	}
	if global != 2 {
		t.Errorf("%d global lists", global)
	}
	for name, objs := range map[string][]Object{"devices": s.Devices, "alarms": s.Alarms, "rules": s.Rules, "flows": s.Flows} {
		if got := gids(objs, "gid"); len(got) != 5 {
			t.Errorf("%s span %d boxes", name, len(got))
		}
	}
	// Alarm ids are unique per box.
	seen := map[string]bool{}
	for _, a := range s.Alarms {
		k := str(a["gid"]) + "/" + str(a["aid"])
		if seen[k] {
			t.Errorf("duplicate alarm %s", k)
		}
		seen[k] = true
	}
}

func TestSeedIsFreshEachCall(t *testing.T) {
	a := Seed()
	a.Boxes[0]["name"] = "changed"
	if Seed().Boxes[0]["name"] == "changed" {
		t.Fatal("Seed shares state between calls")
	}
}

func TestParseQuery(t *testing.T) {
	obj := Object{"gid": "g1", "type": 2, "device": Object{"name": "Dev One"}, "tags": []any{"a", "b"}, "msg": "Hello World"}
	cases := []struct {
		q    string
		want bool
	}{
		{"", true},
		{"   ", true},
		{"box.id:g1", true},
		{"box.id:G1", true},
		{"box.id:g2", false},
		{"box.id:g2,g1", true},
		{"box.id:(g2 OR g1)", true},
		{"-box.id:g1", false},
		{"!box.id:g2", true},
		{"NOT box.id:g1", false},
		{"not box.id:g1", false},
		{"NOT NOT box.id:g1", true},
		{"--box.id:g1", true},
		{"type:2", true},
		{"type:3", false},
		{"device.name:\"dev one\"", true},
		{"device.name:dev*", true},
		{"device.name:*one", true},
		{"device.name:\"*v o*\"", true},
		{"device.name:x*", false},
		{"tags:b", true},
		{"tags:c", false},
		{"hello", true},
		{"\"hello world\"", true},
		{"hello zzz", false},
		{"hello OR zzz", true},
		{"zzz OR hello", true},
		{"zzz hello OR box.id:g1", true},
		{"(zzz OR hello) box.id:g1", true},
		{"(zzz OR hello) box.id:g2", false},
		{"hello AND box.id:g1", true},
		{"hello AND box.id:g2", false},
		{"\"box.id\":g1", true},
		{"BOX.ID:g1", true},
		{"missing.field:x", false},
		{"((box.id:g1))", true},
	}
	for _, c := range cases {
		m, err := parseQuery(c.q)
		if err != nil {
			t.Errorf("%q: %v", c.q, err)
			continue
		}
		if got := m(obj); got != c.want {
			t.Errorf("%q = %v, want %v", c.q, got, c.want)
		}
	}
	for _, q := range []string{"(", ")", "(a", "a)", "box.id:", "type:\"x", "\"x", "a AND", "a OR", "()x:", "x:(a"} {
		if _, err := parseQuery(q); err == nil {
			t.Errorf("%q should be rejected", q)
		}
	}
	deep := strings.Repeat("(", 100) + "x" + strings.Repeat(")", 100)
	if _, err := parseQuery(deep); err == nil {
		t.Error("deep nesting accepted")
	}
}
