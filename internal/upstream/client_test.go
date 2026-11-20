package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"mspbroker/internal/acl"
	"mspbroker/internal/config"
	"mspbroker/internal/upstream/mock"
)

const canary = "canary-upstream-token-0123456789"

func setup(t *testing.T, opts ...mock.Option) (*Client, *mock.Mock) {
	t.Helper()
	m := mock.New(append([]mock.Option{mock.WithToken(canary)}, opts...)...)
	srv := m.Start()
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL, Token: config.NewSecret(canary)})
	if err != nil {
		t.Fatal(err)
	}
	return c, m
}

func ctx() context.Context { return context.Background() }

func gidsOf(objs []Object, field string) string {
	seen := map[string]bool{}
	var out []string
	for _, o := range objs {
		g, _ := o[field].(string)
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return strings.Join(out, ",")
}

func TestNewValidation(t *testing.T) {
	tok := config.NewSecret(canary)
	bad := []Config{
		{BaseURL: "", Token: tok},
		{BaseURL: "msp.example.com", Token: tok},
		{BaseURL: "ftp://msp.example.com", Token: tok},
		{BaseURL: "https://user:pw@msp.example.com", Token: tok},
		{BaseURL: "https://msp.example.com?x=1", Token: tok},
		{BaseURL: "https://msp.example.com#f", Token: tok},
		{BaseURL: "https://msp.example.com"},
		{BaseURL: "https://msp.example.com", Token: tok, AuthScheme: "Bad Scheme"},
		{BaseURL: "https://msp.example.com", Token: tok, AuthScheme: "Bearer\r\nX: y"},
	}
	for i, cfg := range bad {
		if _, err := New(cfg); err == nil {
			t.Errorf("config %d accepted", i)
		}
	}
	if _, err := New(Config{BaseURL: "https://msp.example.com/api", Token: tok}); err != nil {
		t.Errorf("path in base URL rejected: %v", err)
	}
}

func TestBoxes(t *testing.T) {
	c, m := setup(t)
	boxes, err := c.Boxes(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(boxes) != 5 {
		t.Fatalf("%d boxes", len(boxes))
	}
	got := map[string]string{}
	for _, b := range boxes {
		got[b.GID] = b.Group
		if b.Name == "" || b.Object["model"] != "example-model" {
			t.Errorf("box %s lost fields: %+v", b.GID, b)
		}
	}
	want := map[string]string{mock.GID1: mock.GroupA, mock.GID2: mock.GroupA, mock.GID3: mock.GroupB, mock.GID4: mock.GroupB, mock.GID5: ""}
	for g, w := range want {
		if got[g] != w {
			t.Errorf("box %s group %q, want %q", g, got[g], w)
		}
	}
	reqs := m.Requests()
	if len(reqs) != 1 || reqs[0].Path != "/v2/boxes" || reqs[0].RawQuery != "" || !reqs[0].Authenticated {
		t.Errorf("requests: %+v", reqs)
	}
}

// serve starts a one-off upstream that answers every request with body.
func serve(t *testing.T, status int, body string, hdr map[string]string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL, Token: config.NewSecret(canary)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBoxGroupEncodings(t *testing.T) {
	c := serve(t, 200, `[
		{"gid":"g1","name":"a","group":"grp"},
		{"gid":"g2","group":{"id":"grp2","name":"x"}},
		{"gid":"g3","group":null},
		{"gid":"g4"},
		{"gid":"g5","group":42},
		{"gid":"g6","group":{"name":"no id"}},
		{"name":"no gid"},
		{"gid":"","name":"empty gid"}
	]`, nil)
	boxes, err := c.Boxes(ctx())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, b := range boxes {
		got = append(got, b.GID+"="+b.Group)
	}
	if want := "g1=grp g2=grp2 g3= g4= g5= g6="; strings.Join(got, " ") != want {
		t.Fatalf("got %v, want %s", got, want)
	}
}

func TestDevices(t *testing.T) {
	c, m := setup(t)
	cases := []struct {
		p     DevicesParams
		query string
		gids  string
	}{
		{DevicesParams{}, "", "5"},
		{DevicesParams{Box: mock.GID2}, "box=" + mock.GID2, mock.GID2},
		{DevicesParams{Group: mock.GroupA}, "group=" + mock.GroupA, mock.GID1 + "," + mock.GID2},
		{DevicesParams{Box: mock.GID1 + "," + mock.GID5}, "box=" + url.QueryEscape(mock.GID1+","+mock.GID5), mock.GID1 + "," + mock.GID5},
	}
	for _, tc := range cases {
		m.ResetRequests()
		devs, err := c.Devices(ctx(), tc.p)
		if err != nil {
			t.Fatal(err)
		}
		if tc.gids == "5" {
			if len(devs) != 5 {
				t.Errorf("%d devices", len(devs))
			}
		} else if got := gidsOf(devs, "gid"); got != tc.gids {
			t.Errorf("%+v: gids %s, want %s", tc.p, got, tc.gids)
		}
		reqs := m.Requests()
		if len(reqs) != 1 || reqs[0].Path != "/v2/devices" || reqs[0].RawQuery != tc.query {
			t.Errorf("%+v: sent %+v, want query %q", tc.p, reqs, tc.query)
		}
	}
}

func TestAlarmsPassThroughAndPaging(t *testing.T) {
	c, m := setup(t)
	q := "(box.id:" + mock.GID1 + " OR box.id:" + mock.GID3 + ") type:1"
	p, err := c.Alarms(ctx(), ListParams{Query: q, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Results) != 1 || p.NextCursor == "" || p.Count != 1 {
		t.Fatalf("page: %+v", p)
	}
	last := m.Requests()[0]
	if last.Param("query") != q || last.Param("limit") != "1" || last.Param("cursor") != "" {
		t.Errorf("sent %+v", last)
	}

	// Walk every page of the whole set.
	m.ResetRequests()
	var all []Object
	cursor := ""
	pages := 0
	for {
		pg, err := c.Alarms(ctx(), ListParams{Cursor: cursor, Limit: 4})
		if err != nil {
			t.Fatal(err)
		}
		pages++
		all = append(all, pg.Results...)
		if pg.NextCursor == "" {
			break
		}
		cursor = pg.NextCursor
		if pages > 10 {
			t.Fatal("no end")
		}
	}
	if pages != 4 || len(all) != 15 {
		t.Fatalf("pages %d, items %d", pages, len(all))
	}
	if r := m.Requests(); len(r) != 4 || r[1].Param("cursor") == "" || r[0].Param("cursor") != "" {
		t.Errorf("cursor not passed through: %+v", r)
	}
	// Numbers survive as json.Number, not float64.
	if _, ok := all[0]["ts"].(interface{ Int64() (int64, error) }); !ok {
		t.Errorf("ts is %T", all[0]["ts"])
	}

	if _, err := c.Alarms(ctx(), ListParams{Limit: -1}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("negative limit: %v", err)
	}
	if _, err := c.Alarms(ctx(), ListParams{Cursor: "!!!"}); err == nil {
		t.Error("bad cursor accepted by upstream mock")
	} else if e, ok := AsError(err); !ok || e.Status != 400 || e.Code != "bad_cursor" {
		t.Errorf("bad cursor error: %v", err)
	}
}

func TestAlarmsGroupBySortByPassThrough(t *testing.T) {
	c, m := setup(t)
	if _, err := c.Alarms(ctx(), ListParams{GroupBy: "type", SortBy: "ts:desc"}); err != nil {
		t.Fatal(err)
	}
	r := m.Requests()
	if len(r) != 1 || r[0].Param("groupBy") != "type" || r[0].Param("sortBy") != "ts:desc" {
		t.Errorf("sent %+v", r)
	}
}

func TestAlarmGet(t *testing.T) {
	c, m := setup(t)
	a, err := c.Alarm(ctx(), mock.GID2, "21")
	if err != nil {
		t.Fatal(err)
	}
	if a["gid"] != mock.GID2 || a["aid"] != "21" {
		t.Fatalf("%v", a)
	}
	if r := m.Requests()[0]; r.Path != "/v2/alarms/"+mock.GID2+"/21" {
		t.Errorf("path %s", r.Path)
	}
	_, err = c.Alarm(ctx(), mock.GID2, "999")
	if e, ok := AsError(err); !ok || !e.IsNotFound() {
		t.Errorf("want 404, got %v", err)
	}
}

func TestPathSegmentsAreChecked(t *testing.T) {
	c, m := setup(t)
	for _, bad := range []string{"", ".", "..", "a/b", "a%2Fb", "a?b", "a#b", "a b", "a\x00b", "../x", `a\b`, strings.Repeat("a", 129)} {
		if _, err := c.Alarm(ctx(), bad, "1"); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("gid %q: %v", bad, err)
		}
		if _, err := c.Alarm(ctx(), mock.GID1, bad); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("aid %q: %v", bad, err)
		}
		if _, err := c.TargetList(ctx(), bad); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("target list %q: %v", bad, err)
		}
	}
	if n := len(m.Requests()); n != 0 {
		t.Errorf("%d requests were sent for invalid input", n)
	}
	for _, bad := range []string{"", "1x", "a/b", "a b", "..", "a.b", strings.Repeat("a", 65)} {
		if _, err := c.Stats(ctx(), bad, nil); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("stats name %q: %v", bad, err)
		}
		if _, err := c.Trends(ctx(), bad, nil); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("trends name %q: %v", bad, err)
		}
	}
}

func TestRulesAndFlows(t *testing.T) {
	c, m := setup(t)
	p, err := c.Rules(ctx(), "box.id:"+mock.GID3+" status:paused")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Results) != 1 || p.Results[0]["id"] != "rule-32" {
		t.Fatalf("%v", p.Results)
	}
	if r := m.Requests()[0]; r.Path != "/v2/rules" || r.Param("limit") != "" || r.Param("cursor") != "" {
		t.Errorf("rules request: %+v", r)
	}
	fp, err := c.Flows(ctx(), ListParams{Query: "box.id:" + mock.GID5, Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(fp.Results) != 3 || fp.NextCursor == "" || gidsOf(fp.Results, "gid") != mock.GID5 {
		t.Fatalf("%+v", fp)
	}
	fp2, err := c.Flows(ctx(), ListParams{Query: "box.id:" + mock.GID5, Limit: 3, Cursor: fp.NextCursor})
	if err != nil || len(fp2.Results) != 1 || fp2.NextCursor != "" {
		t.Fatalf("%+v %v", fp2, err)
	}
	if _, err := c.Rules(ctx(), "(("); err == nil {
		t.Error("bad query accepted")
	} else if e, ok := AsError(err); !ok || e.Status != 400 {
		t.Errorf("%v", err)
	}
}

func TestTargetLists(t *testing.T) {
	c, m := setup(t)
	lists, err := c.TargetLists(ctx(), "global,"+mock.GID1)
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 3 || gidsOf(lists, "owner") != "global,"+mock.GID1 {
		t.Fatalf("%v", gidsOf(lists, "owner"))
	}
	if r := m.Requests()[0]; r.Param("owner") != "global,"+mock.GID1 {
		t.Errorf("sent %+v", r)
	}
	m.ResetRequests()
	if all, err := c.TargetLists(ctx(), ""); err != nil || len(all) != 5 {
		t.Fatalf("%d %v", len(all), err)
	}
	if r := m.Requests()[0]; r.RawQuery != "" {
		t.Errorf("owner sent when empty: %q", r.RawQuery)
	}
	tl, err := c.TargetList(ctx(), "tl-global-2")
	if err != nil || tl["owner"] != "global" {
		t.Fatalf("%v %v", tl, err)
	}
	if _, err := c.TargetList(ctx(), "nope"); err == nil {
		t.Error("missing list found")
	}
}

func TestStatsAndTrends(t *testing.T) {
	c, m := setup(t)
	raw, err := c.Stats(ctx(), "topBoxesByBlockedFlows", url.Values{"group": {mock.GroupA}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), mock.GID1) || strings.Contains(string(raw), mock.GID3) {
		t.Errorf("stats body: %s", raw)
	}
	if r := m.Requests()[0]; r.Path != "/v2/stats/topBoxesByBlockedFlows" || r.Param("group") != mock.GroupA {
		t.Errorf("sent %+v", r)
	}
	if raw, err = c.Trends(ctx(), "flows", url.Values{"box": {mock.GID5}}); err != nil || !strings.Contains(string(raw), mock.GID5) {
		t.Errorf("trends: %s %v", raw, err)
	}
	if _, err = c.Trends(ctx(), "nonesuch", nil); err == nil {
		t.Error("unknown trend accepted")
	}
	nonJSON := serve(t, 200, "<html>", nil)
	if _, err := nonJSON.Stats(ctx(), "x", nil); !errors.Is(err, ErrUnexpectedResponse) {
		t.Errorf("non-JSON stats: %v", err)
	}
}

func TestBodyShapes(t *testing.T) {
	good := map[string]string{
		"bare array":   `[{"gid":"g"}]`,
		"envelope":     `{"count":1,"results":[{"gid":"g"}],"next_cursor":"abc"}`,
		"camel cursor": `{"results":[{"gid":"g"}],"nextCursor":"abc"}`,
		"empty array":  `[]`,
		"empty env":    `{"count":0,"results":[]}`,
		"whitespace":   "  \n[{\"gid\":\"g\"}]\n",
	}
	for name, body := range good {
		c := serve(t, 200, body, nil)
		p, err := c.Alarms(ctx(), ListParams{})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if p.Results == nil {
			t.Errorf("%s: nil results", name)
		}
	}
	p, _ := serve(t, 200, good["envelope"], nil).Alarms(ctx(), ListParams{})
	if p.Count != 1 || p.NextCursor != "abc" {
		t.Errorf("envelope: %+v", p)
	}
	p, _ = serve(t, 200, good["camel cursor"], nil).Alarms(ctx(), ListParams{})
	if p.NextCursor != "abc" || p.Count != 1 {
		t.Errorf("camel: %+v", p)
	}
	bad := map[string]string{
		"empty":           ``,
		"not json":        `<html>`,
		"string":          `"x"`,
		"null":            `null`,
		"array of nums":   `[1,2]`,
		"null element":    `[null]`,
		"env no results":  `{"count":1}`,
		"results not arr": `{"results":{"a":1}}`,
		"results nums":    `{"results":[1]}`,
		"trailing":        `[] []`,
		"count string":    `{"count":"x","results":[]}`,
	}
	for name, body := range bad {
		c := serve(t, 200, body, nil)
		if _, err := c.Alarms(ctx(), ListParams{}); !errors.Is(err, ErrUnexpectedResponse) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, body := range map[string]string{"array": `[]`, "null": `null`, "string": `"x"`} {
		if _, err := serve(t, 200, body, nil).Alarm(ctx(), "g", "1"); !errors.Is(err, ErrUnexpectedResponse) {
			t.Errorf("single %s: %v", name, err)
		}
	}
}

func TestAuthToUpstream(t *testing.T) {
	c, m := setup(t)
	if _, err := c.Boxes(ctx()); err != nil {
		t.Fatal(err)
	}
	if r := m.Requests()[0]; !r.Authenticated {
		t.Fatal("token not accepted")
	}

	// A client with the wrong token gets a typed 401.
	srv := m.Start()
	defer srv.Close()
	wrong, _ := New(Config{BaseURL: srv.URL, Token: config.NewSecret("not-the-token")})
	_, err := wrong.Boxes(ctx())
	e, ok := AsError(err)
	if !ok || e.Status != 401 || !e.IsAuth() || e.IsRateLimited() {
		t.Fatalf("want typed 401, got %v", err)
	}

	// The scheme word is configurable; the mock accepts Token too.
	tc, _ := New(Config{BaseURL: srv.URL, Token: config.NewSecret(canary), AuthScheme: "Token"})
	if _, err := tc.Boxes(ctx()); err != nil {
		t.Errorf("Token scheme: %v", err)
	}

	// The header actually sent.
	var gotAuth, gotUA string
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotUA = r.Header.Get("Authorization"), r.Header.Get("User-Agent")
		_, _ = io.WriteString(w, `[]`)
	}))
	defer h.Close()
	hc, _ := New(Config{BaseURL: h.URL, Token: config.NewSecret(canary)})
	if _, err := hc.Boxes(ctx()); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer "+canary || gotUA == "" {
		t.Errorf("headers: %q %q", gotAuth, gotUA)
	}
}

func TestBasePathPrefix(t *testing.T) {
	var path string
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = io.WriteString(w, `[]`)
	}))
	defer h.Close()
	c, _ := New(Config{BaseURL: h.URL + "/api/", Token: config.NewSecret(canary)})
	if _, err := c.Boxes(ctx()); err != nil {
		t.Fatal(err)
	}
	if path != "/api/v2/boxes" {
		t.Errorf("path %q", path)
	}
}

func TestStatusErrors(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		status int
		hdr    map[string]string
		body   string
		retry  time.Duration
		code   string
	}{
		{"429 seconds", 429, map[string]string{"Retry-After": "7"}, `{"error":"rate_limited","message":"slow down"}`, 7 * time.Second, "rate_limited"},
		{"429 http date", 429, map[string]string{"Retry-After": now.Add(90 * time.Second).UTC().Format(http.TimeFormat)}, `{}`, 90 * time.Second, ""},
		{"429 past date", 429, map[string]string{"Retry-After": now.Add(-time.Hour).UTC().Format(http.TimeFormat)}, ``, 0, ""},
		{"429 no header", 429, nil, `{"error":"x"}`, 0, "x"},
		{"429 garbage header", 429, map[string]string{"Retry-After": "soon"}, ``, 0, ""},
		{"429 negative", 429, map[string]string{"Retry-After": "-5"}, ``, 0, ""},
		{"429 huge", 429, map[string]string{"Retry-After": "99999999999"}, ``, 24 * time.Hour, ""},
		{"500 html", 500, nil, `<html>oops</html>`, 0, ""},
		{"503 retry", 503, map[string]string{"Retry-After": "30"}, `{"message":"maintenance"}`, 30 * time.Second, ""},
		{"404", 404, nil, `{"error":"not_found"}`, 0, "not_found"},
		{"403", 403, nil, ``, 0, ""},
		{"error object", 400, nil, `{"error":{"code":1},"message":"m"}`, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := serve(t, tc.status, tc.body, tc.hdr)
			c.now = func() time.Time { return now }
			_, err := c.Boxes(ctx())
			e, ok := AsError(err)
			if !ok {
				t.Fatalf("not an *Error: %T %v", err, err)
			}
			if e.Status != tc.status || e.RetryAfter != tc.retry || e.Code != tc.code {
				t.Errorf("got status=%d retry=%s code=%q; want %d %s %q", e.Status, e.RetryAfter, e.Code, tc.status, tc.retry, tc.code)
			}
			if e.Method != "GET" || e.Path != "/v2/boxes" {
				t.Errorf("method/path: %s %s", e.Method, e.Path)
			}
			if e.IsRateLimited() != (tc.status == 429) {
				t.Errorf("IsRateLimited")
			}
			if tc.body != "" && e.Body != tc.body {
				t.Errorf("body %q", e.Body)
			}
			if !strings.Contains(err.Error(), fmt.Sprint(tc.status)) {
				t.Errorf("text %q lacks status", err)
			}
			if _, ok := AsError(fmt.Errorf("wrapped: %w", err)); !ok {
				t.Error("not found through wrapping")
			}
		})
	}
}

func TestErrorBodyIsTruncated(t *testing.T) {
	c := serve(t, 500, strings.Repeat("x", 100000), nil)
	_, err := c.Boxes(ctx())
	e, ok := AsError(err)
	if !ok || e.Status != 500 || len(e.Body) > maxBodyKept+3 {
		t.Fatalf("%v", err)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var hits int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = io.WriteString(w, `[]`)
	}))
	defer other.Close()
	c := serve(t, 302, "", map[string]string{"Location": other.URL + "/v2/boxes"})
	_, err := c.Boxes(ctx())
	if e, ok := AsError(err); !ok || e.Status != 302 {
		t.Fatalf("want typed 302, got %v", err)
	}
	if hits != 0 {
		t.Fatal("redirect was followed")
	}
}

func TestResponseSizeCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[`+strings.Repeat(`{"gid":"g"},`, 100)+`{"gid":"g"}]`)
	}))
	defer srv.Close()
	c, _ := New(Config{BaseURL: srv.URL, Token: config.NewSecret(canary), MaxResponseBytes: 200})
	if _, err := c.Boxes(ctx()); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("got %v", err)
	}
	c, _ = New(Config{BaseURL: srv.URL, Token: config.NewSecret(canary)})
	if b, err := c.Boxes(ctx()); err != nil || len(b) != 101 {
		t.Fatalf("%d %v", len(b), err)
	}
}

func TestTimeoutAndCancellation(t *testing.T) {
	m := mock.New(mock.WithToken(canary))
	m.SetLatency(3 * time.Second)
	srv := m.Start()
	defer srv.Close()

	c, _ := New(Config{BaseURL: srv.URL, Token: config.NewSecret(canary), Timeout: 100 * time.Millisecond})
	start := time.Now()
	_, err := c.Boxes(ctx())
	var te *TransportError
	if !errors.As(err, &te) || !te.Timeout() || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want a timeout TransportError, got %T %v", err, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not honoured")
	}

	c2, _ := New(Config{BaseURL: srv.URL, Token: config.NewSecret(canary)})
	cctx, cancel := context.WithCancel(ctx())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	start = time.Now()
	_, err = c2.Boxes(cctx)
	if !errors.Is(err, context.Canceled) || errors.As(err, &te) && te.Timeout() {
		t.Fatalf("want cancellation, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancellation not honoured")
	}
	// The caller's deadline wins when shorter than the client timeout.
	dctx, cancel2 := context.WithTimeout(ctx(), 50*time.Millisecond)
	defer cancel2()
	if _, err = c2.Boxes(dctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller deadline: %v", err)
	}
}

func TestConnectionRefused(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c, _ := New(Config{BaseURL: url, Token: config.NewSecret(canary)})
	_, err := c.Boxes(ctx())
	var te *TransportError
	if !errors.As(err, &te) || te.Timeout() {
		t.Fatalf("got %T %v", err, err)
	}
	if _, ok := AsError(err); ok {
		t.Fatal("transport failure typed as a status error")
	}
}

// ---- redaction ----

func logged(t *testing.T) (*bytes.Buffer, *slog.Logger) {
	var buf bytes.Buffer
	return &buf, slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func noCanary(t *testing.T, what, s string) {
	t.Helper()
	for _, form := range newRedactor(canary).forms {
		if strings.Contains(s, form) {
			t.Errorf("%s contains the token (%q): %s", what, form, s)
		}
	}
}

// An upstream that echoes the token it was given, in a status error body,
// in a JSON message, and in a success body, must not get it out.
func TestRedactionOfEchoedToken(t *testing.T) {
	echo := func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch r.URL.Path {
		case "/v2/boxes":
			w.WriteHeader(401)
			fmt.Fprintf(w, `{"error":"bad token %s","message":"token %s is invalid"}`, tok, tok)
		case "/v2/devices":
			w.WriteHeader(500)
			fmt.Fprintf(w, "stack trace: Authorization: Bearer %s\n", tok)
		case "/v2/rules":
			fmt.Fprintf(w, `{"results":[{"id":"r","note":"%s"}]}`, tok)
		case "/v2/stats/x":
			fmt.Fprintf(w, `{"echo":"%s"}`, url.QueryEscape(tok))
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(echo))
	defer srv.Close()
	buf, lg := logged(t)
	c, _ := New(Config{BaseURL: srv.URL, Token: config.NewSecret(canary), Logger: lg})

	_, err := c.Boxes(ctx())
	noCanary(t, "401 error text", err.Error())
	e, _ := AsError(err)
	noCanary(t, "error Body", e.Body)
	noCanary(t, "error Message", e.Message)
	noCanary(t, "error Code", e.Code)
	if !strings.Contains(e.Message, Redacted) {
		t.Errorf("message not marked: %q", e.Message)
	}

	_, err = c.Devices(ctx(), DevicesParams{})
	e, _ = AsError(err)
	noCanary(t, "500 body", e.Body+err.Error())
	if !strings.Contains(e.Body, Redacted) {
		t.Errorf("body not marked: %q", e.Body)
	}

	p, err := c.Rules(ctx(), "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Results[0]["note"] != Redacted {
		t.Errorf("success body not redacted: %v", p.Results[0])
	}
	raw, err := c.Stats(ctx(), "x", nil)
	if err != nil {
		t.Fatal(err)
	}
	noCanary(t, "raw stats", string(raw))

	noCanary(t, "log output", buf.String())
	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

// The token can reach a transport error through the URL (here a caller-chosen
// query value that happens to equal it) and must not survive in error text
// or logs.
func TestRedactionInTransportErrorsAndLogs(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()
	buf, lg := logged(t)
	c, _ := New(Config{BaseURL: base, Token: config.NewSecret(canary), Logger: lg})
	_, err := c.Alarms(ctx(), ListParams{Query: canary})
	if err == nil {
		t.Fatal("expected failure")
	}
	noCanary(t, "transport error", err.Error())
	noCanary(t, "log", buf.String())

	// And on a successful request whose query carries it.
	c2, m := setup(t)
	buf2, lg2 := logged(t)
	c2.log = slog.New(c2.red.handler(lg2.Handler()))
	if _, err := c2.Alarms(ctx(), ListParams{Query: "x:" + canary}); err != nil {
		t.Fatal(err)
	}
	noCanary(t, "debug log", buf2.String())
	if !strings.Contains(buf2.String(), Redacted) {
		t.Errorf("log lacks marker: %s", buf2.String())
	}
	_ = m
}

func TestRedactingHandlerCoversAllAttrKinds(t *testing.T) {
	var buf bytes.Buffer
	r := newRedactor(canary)
	lg := slog.New(r.handler(slog.NewJSONHandler(&buf, nil)))
	lg = lg.With("pre", "p-"+canary).WithGroup("grp-" + canary).With(slog.Group("g", slog.String("s", canary)))
	lg.Info("msg "+canary,
		"str", canary,
		"err", errors.New("wrapped "+canary),
		"any", struct{ T string }{canary},
		"stringer", stringer(canary),
		slog.Group("inner", "deep", slog.GroupValue(slog.String("x", canary))),
		canary, "key-redacted",
		"num", 42,
		"url", url.URL{Path: "/" + canary},
	)
	noCanary(t, "handler output", buf.String())
	if !strings.Contains(buf.String(), `"num":42`) {
		t.Errorf("non-string attrs mangled: %s", buf.String())
	}
}

type stringer string

func (s stringer) String() string { return "s:" + string(s) }

func TestRedactorForms(t *testing.T) {
	odd := `tok/+ en"<&>\x`
	r := newRedactor(odd)
	for _, enc := range []string{odd, url.QueryEscape(odd), url.PathEscape(odd), `tok/+ en\"\u003c\u0026\u003e\\x`} {
		if got := r.String("a " + enc + " b"); got != "a "+Redacted+" b" {
			t.Errorf("%q -> %q", enc, got)
		}
	}
	if got := r.String("nothing here"); got != "nothing here" {
		t.Errorf("changed: %q", got)
	}
	// An empty secret must never make the redactor rewrite everything.
	if got := newRedactor("").String("abc"); got != "abc" {
		t.Errorf("empty secret: %q", got)
	}
	in := []byte("keep")
	if out := r.Bytes(in); &out[0] != &in[0] {
		t.Error("Bytes copied unchanged input")
	}
}

func TestClientPrintsWithoutToken(t *testing.T) {
	c, _ := setup(t)
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		noCanary(t, f, fmt.Sprintf(f, c))
		noCanary(t, f+" value", fmt.Sprintf(f, *c))
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("client", "c", c)
	noCanary(t, "slog", buf.String())
	noCanary(t, "config", fmt.Sprintf("%+v", Config{Token: config.NewSecret(canary)}))
}

// The post-filter, not the upstream filter, is the control: with the mock
// ignoring filters the client still returns everything, and acl removes
// what is out of scope.
func TestPostFilterIsTheControl(t *testing.T) {
	c, m := setup(t)
	m.SetIgnoreFilters(true)
	eff := acl.Resolve(acl.Scope{Type: acl.ScopeBoxes, GIDs: []string{mock.GID1, mock.GID5}}, nil)

	devs, err := c.Devices(ctx(), DevicesParams{Box: mock.GID1})
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 5 {
		t.Fatalf("upstream mock did not ignore the filter: %d", len(devs))
	}
	if kept := acl.FilterObjects(devs, eff, false); gidsOf(kept, "gid") != mock.GID1+","+mock.GID5 {
		t.Errorf("devices after post-filter: %s", gidsOf(kept, "gid"))
	}

	al, err := c.Alarms(ctx(), ListParams{Query: "box.id:" + mock.GID1, Limit: 500})
	if err != nil || len(al.Results) != 15 {
		t.Fatalf("%v %d", err, len(al.Results))
	}
	if kept := acl.FilterObjects(al.Results, eff, false); len(kept) != 6 {
		t.Errorf("alarms after post-filter: %d", len(kept))
	}

	tl, err := c.TargetLists(ctx(), mock.GID1)
	if err != nil || len(tl) != 5 {
		t.Fatalf("%v %d", err, len(tl))
	}
	if kept := acl.FilterObjects(tl, eff, false); gidsOf(kept, "owner") != mock.GID1+","+mock.GID5 {
		t.Errorf("target lists without global: %s", gidsOf(kept, "owner"))
	}
	if kept := acl.FilterObjects(tl, eff, true); len(kept) != 4 {
		t.Errorf("target lists with global: %d", len(kept))
	}

	// Group scope resolved from the client's own box list.
	boxes, err := c.Boxes(ctx())
	if err != nil {
		t.Fatal(err)
	}
	var abox []acl.Box
	for _, b := range boxes {
		abox = append(abox, acl.Box{GID: b.GID, GroupID: b.Group})
	}
	geff := acl.Resolve(acl.Scope{Type: acl.ScopeGroups, GroupIDs: []string{mock.GroupB}}, abox)
	devs, _ = c.Devices(ctx(), DevicesParams{Group: mock.GroupB})
	if len(devs) != 5 {
		t.Fatalf("ignored group filter returned %d", len(devs))
	}
	if kept := acl.FilterObjects(devs, geff, false); gidsOf(kept, "gid") != mock.GID3+","+mock.GID4 {
		t.Errorf("group scope devices: %s", gidsOf(kept, "gid"))
	}
}

// A JSON \u escape is not the token string, so the raw-byte redaction cannot
// see it, but decoding turns it back into the token. Decoded strings (and
// keys, and cursors) must be redacted as well.
func TestDecodedStringsAreRedacted(t *testing.T) {
	esc := ""
	for _, r := range canary {
		esc += fmt.Sprintf(`\u%04x`, r)
	}
	partial := `\u0063` + canary[1:]
	for _, enc := range []string{esc, partial} {
		c, m := setup(t)
		m.InjectFault(mock.Fault{Status: 200, Times: 1, Body: `{"results":[{"gid":"g1","name":"` + enc + `","` + enc + `":["` + enc + `"]}],"next_cursor":"` + enc + `"}`})
		page, err := c.Alarms(ctx(), ListParams{})
		if err != nil {
			t.Fatal(err)
		}
		out, _ := json.Marshal(page)
		if strings.Contains(string(out), canary) {
			t.Errorf("page still holds the token: %s", out)
		}
		if !strings.Contains(string(out), Redacted) {
			t.Errorf("nothing was redacted: %s", out)
		}

		m.InjectFault(mock.Fault{Status: 200, Times: 1, Body: `{"gid":"g1","message":"` + enc + `"}`})
		obj, err := c.Alarm(ctx(), "g1", "11")
		if err != nil {
			t.Fatal(err)
		}
		out, _ = json.Marshal(obj)
		if strings.Contains(string(out), canary) || !strings.Contains(string(out), Redacted) {
			t.Errorf("object not redacted: %s", out)
		}

		m.InjectFault(mock.Fault{Status: 200, Times: 1, Body: `[{"gid":"g1","name":"` + enc + `"}]`})
		boxes, err := c.Boxes(ctx())
		if err != nil {
			t.Fatal(err)
		}
		out, _ = json.Marshal(boxes)
		if strings.Contains(string(out), canary) {
			t.Errorf("boxes not redacted: %s", out)
		}
	}
}
