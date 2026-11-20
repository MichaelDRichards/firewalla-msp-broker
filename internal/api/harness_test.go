package api_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"mspbroker/internal/acl"
	"mspbroker/internal/api"
	"mspbroker/internal/audit"
	"mspbroker/internal/auth"
	"mspbroker/internal/config"
	"mspbroker/internal/redact"
	"mspbroker/internal/store"
	"mspbroker/internal/upstream"
	"mspbroker/internal/upstream/mock"

	_ "modernc.org/sqlite" // second connection for dumps
)

// upstreamCanary is the planted upstream token: placeholder-looking, and
// recognisable if it ever shows up somewhere it must not.
const upstreamCanary = "mg-test-CANARY-0000"

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

const defaultPeer = "192.0.2.50:5000"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// syncBuf is a goroutine-safe log sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type hcfg struct {
	ttl       time.Duration
	rate      int
	ignore    bool
	timeout   time.Duration
	ready     time.Duration
	transport http.RoundTripper
	// strictScrub gives the broker's own logger and audit recorder no knowledge
	// of the upstream token, so only the upstream client's redaction and the
	// code paths themselves keep the canary out. Broker key secrets are always
	// scrubbed by shape.
	strictScrub bool
	// wrapUpstream decorates the real client, to hand the API objects the
	// client itself would never produce.
	wrapUpstream func(api.Upstream) api.Upstream
}

type hopt func(*hcfg)

func withWrapUpstream(f func(api.Upstream) api.Upstream) hopt {
	return func(c *hcfg) { c.wrapUpstream = f }
}

func withTTL(d time.Duration) hopt             { return func(c *hcfg) { c.ttl = d } }
func withRate(n int) hopt                      { return func(c *hcfg) { c.rate = n } }
func withIgnoreFilters() hopt                  { return func(c *hcfg) { c.ignore = true } }
func withUpstreamTimeout(d time.Duration) hopt { return func(c *hcfg) { c.timeout = d } }
func withReadyInterval(d time.Duration) hopt   { return func(c *hcfg) { c.ready = d } }
func withTransport(rt http.RoundTripper) hopt  { return func(c *hcfg) { c.transport = rt } }
func withStrictScrub() hopt                    { return func(c *hcfg) { c.strictScrub = true } }

// harness is a broker wired to an in-process mock upstream, a temporary
// database, a controllable clock and captured logs.
type harness struct {
	t      *testing.T
	mock   *mock.Mock
	upSrv  *httptest.Server
	st     *store.Store
	clk    *clock
	srv    *api.Server
	logs   *syncBuf
	dbDir  string
	bodies [][]byte // every response body, for leak scans
}

func newHarness(t *testing.T, opts ...hopt) *harness {
	t.Helper()
	cfg := hcfg{ttl: 60 * time.Second, ready: 30 * time.Second}
	for _, o := range opts {
		o(&cfg)
	}
	h := &harness{t: t, clk: &clock{t: t0}, logs: &syncBuf{}, dbDir: t.TempDir()}

	h.mock = mock.New(mock.WithToken(upstreamCanary), mock.WithIgnoreFilters(cfg.ignore))
	h.upSrv = h.mock.Start()
	t.Cleanup(h.upSrv.Close)

	st, err := store.Open(context.Background(), filepath.Join(h.dbDir, "broker.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	st.SetClock(h.clk.now)
	h.st = st

	scrub := redact.New(upstreamCanary)
	if cfg.strictScrub {
		scrub = redact.New()
	}
	base := slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(scrub.Handler(base))

	up, err := upstream.New(upstream.Config{
		BaseURL: h.upSrv.URL, Token: config.NewSecret(upstreamCanary), Timeout: cfg.timeout, Transport: cfg.transport,
		// As in production: the client redacts the upstream token itself and
		// its log sink also scrubs broker secrets by shape.
		Logger: slog.New(redact.New().Handler(base)),
	})
	if err != nil {
		t.Fatal(err)
	}

	var upIface api.Upstream = up
	if cfg.wrapUpstream != nil {
		upIface = cfg.wrapUpstream(up)
	}
	authn := auth.New(auth.Config{Store: st, DefaultRateLimit: cfg.rate, Now: h.clk.now})
	srv, err := api.New(api.Config{
		Store: st, Upstream: upIface, Auth: authn, Audit: audit.New(st, scrub, logger), Logger: logger, Scrub: scrub,
		GroupCacheTTL: cfg.ttl, DefaultRateLimit: cfg.rate, ReadyInterval: cfg.ready, Now: h.clk.now, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	return h
}

// ---- keys ----

func allRead() acl.Permissions {
	return acl.Permissions{Boxes: acl.Read, Devices: acl.Read, Alarms: acl.Read, Rules: acl.Read, Flows: acl.Read,
		TargetLists: acl.Read, Stats: acl.Read, GlobalTargetLists: acl.Read}
}

var (
	scopeAll      = acl.Scope{Type: acl.ScopeAll}
	scopeExplicit = acl.Scope{Type: acl.ScopeBoxes, GIDs: []string{mock.GID1, mock.GID3}}
	scopeGroupA   = acl.Scope{Type: acl.ScopeGroups, GroupIDs: []string{mock.GroupA}}
	scopeMixed    = acl.Scope{Type: acl.ScopeBoxesGroups, GIDs: []string{mock.GID5}, GroupIDs: []string{mock.GroupB}}
)

// key stores a data key with one secret and returns it with the secret.
func (h *harness) key(name string, scope acl.Scope, perms acl.Permissions, mods ...func(*store.Key)) (*store.Key, string) {
	h.t.Helper()
	k := &store.Key{Name: name, Kind: acl.KindData, Enabled: true, Scope: scope, Permissions: perms}
	for _, m := range mods {
		m(k)
	}
	full, row, err := auth.NewSecret("", h.clk.now(), nil)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.st.CreateKey(context.Background(), k, row); err != nil {
		h.t.Fatal(err)
	}
	return k, full
}

func (h *harness) adminKey(name string) (*store.Key, string) {
	h.t.Helper()
	k := &store.Key{Name: name, Kind: acl.KindAdmin, Enabled: true}
	full, row, err := auth.NewSecret("", h.clk.now(), nil)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.st.CreateKey(context.Background(), k, row); err != nil {
		h.t.Fatal(err)
	}
	return k, full
}

// ---- requests ----

type resp struct {
	status int
	hdr    http.Header
	body   []byte
}

func (r *resp) obj(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("response is not a JSON object (%d): %s", r.status, r.body)
	}
	return m
}

func (r *resp) results(t *testing.T) []map[string]any {
	t.Helper()
	m := r.obj(t)
	raw, ok := m["results"].([]any)
	if !ok {
		t.Fatalf("no results array (%d): %s", r.status, r.body)
	}
	out := make([]map[string]any, len(raw))
	for i, v := range raw {
		out[i] = v.(map[string]any)
	}
	return out
}

// owners returns the sorted distinct values of field over the results.
func (r *resp) owners(t *testing.T, field string) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, o := range r.results(t) {
		s, _ := o[field].(string)
		seen[s] = true
	}
	var out []string
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func (r *resp) errCode(t *testing.T) string {
	t.Helper()
	m := r.obj(t)
	c, _ := m["code"].(string)
	return c
}

type reqOpt func(*http.Request)

func withIP(ip string) reqOpt {
	return func(r *http.Request) { r.RemoteAddr = ip + ":4000" }
}

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

func withBody(s string) reqOpt {
	return func(r *http.Request) {
		r.Body = io.NopCloser(strings.NewReader(s))
		r.ContentLength = int64(len(s))
		r.Header.Set("Content-Type", "application/json")
	}
}

func (h *harness) do(secret, method, target string, opts ...reqOpt) *resp {
	h.t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = defaultPeer
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	h.bodies = append(h.bodies, b)
	return &resp{status: res.StatusCode, hdr: res.Header, body: b}
}

func (h *harness) get(secret, target string, opts ...reqOpt) *resp {
	h.t.Helper()
	return h.do(secret, "GET", target, opts...)
}

// ---- audit ----

// auditRows returns every audit row, oldest first.
func (h *harness) auditRows() []*store.AuditEntry {
	h.t.Helper()
	ents, _, err := h.st.ListAudit(context.Background(), store.AuditFilter{Limit: store.MaxAuditLimit})
	if err != nil {
		h.t.Fatal(err)
	}
	for i, j := 0, len(ents)-1; i < j; i, j = i+1, j-1 {
		ents[i], ents[j] = ents[j], ents[i]
	}
	return ents
}

func (h *harness) lastAudit() *store.AuditEntry {
	h.t.Helper()
	rows := h.auditRows()
	if len(rows) == 0 {
		h.t.Fatal("no audit rows")
	}
	return rows[len(rows)-1]
}

// wantBlocked asserts the newest audit row is a blocked attempt with reason.
func (h *harness) wantBlocked(reason string) *store.AuditEntry {
	h.t.Helper()
	e := h.lastAudit()
	if e.Outcome != store.OutcomeBlocked || e.BlockReason != reason {
		h.t.Fatalf("audit row: outcome %q reason %q, want blocked/%s (%+v)", e.Outcome, e.BlockReason, reason, e)
	}
	return e
}

func (h *harness) upstreamCalls(path string) int {
	return len(h.mock.RequestsTo(path))
}

func (h *harness) boxesCalls() int { return h.upstreamCalls("/v2/boxes") }

func ids(gs ...string) []string { return gs }

// mustSecret adds a second secret to a key (a rotation window) and returns it.
func mustSecret(t *testing.T, h *harness, keyID string, expires *time.Time) string {
	t.Helper()
	full, row, err := auth.NewSecret(keyID, h.clk.now(), expires)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.st.AddSecret(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	return full
}

// rawDB opens a second connection to the broker's database file.
func (h *harness) rawDB() *sql.DB {
	h.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(h.dbDir, "broker.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { db.Close() })
	return db
}

// dump renders every row of every table as text (blobs both raw and hex),
// for scans that must find nothing.
func (h *harness) dump() string {
	h.t.Helper()
	db := h.rawDB()
	tables, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		h.t.Fatal(err)
	}
	var names []string
	for tables.Next() {
		var n string
		if err := tables.Scan(&n); err != nil {
			h.t.Fatal(err)
		}
		names = append(names, n)
	}
	tables.Close()
	var sb strings.Builder
	for _, n := range names {
		rows, err := db.Query(`SELECT * FROM "` + n + `"`)
		if err != nil {
			h.t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				h.t.Fatal(err)
			}
			sb.WriteString(n + ":")
			for i, v := range vals {
				switch x := v.(type) {
				case []byte:
					fmt.Fprintf(&sb, " %s=%s|%x", cols[i], x, x)
				default:
					fmt.Fprintf(&sb, " %s=%v", cols[i], x)
				}
			}
			sb.WriteString("\n")
		}
		rows.Close()
	}
	return sb.String()
}
