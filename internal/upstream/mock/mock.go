// Package mock is an in-memory stand-in for the upstream MSP API. It
// implements every endpoint the upstream client models (read only in M1),
// with seed data that uses only placeholder values.
//
// It exists so that tests and demos need no MSP account. It is NOT a
// statement of how the real service behaves: every response shape here is
// the mock's own, documented in docs/UPSTREAM-NOTES.md with the label of
// what is and is not verified.
//
// Response shapes:
//
//	GET /v2/boxes                      [ box, ... ]
//	GET /v2/devices?box=&group=        [ device, ... ]
//	GET /v2/alarms?query=&cursor=&limit=   { count, results: [alarm], next_cursor? }
//	GET /v2/alarms/{gid}/{aid}         alarm
//	GET /v2/rules?query=               { count, results: [rule], next_cursor? }
//	GET /v2/flows?query=&cursor=&limit=    { count, results: [flow], next_cursor? }
//	GET /v2/target-lists?owner=        [ target list, ... ]
//	GET /v2/target-lists/{id}          target list
//	GET /v2/stats/{name}, /v2/trends/{name}   [ item, ... ]  (MOCK-ONLY SHAPE)
//
// Errors are {"error": "<code>", "message": "<text>"} with the HTTP status.
// Every request needs `Authorization: Bearer <token>` (the scheme `Token`
// is accepted too); anything else is 401.
package mock

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Object is a JSON object as the mock stores and serves it.
type Object = map[string]any

// State is the mock's data. Mutate it through Mock.Update.
type State struct {
	Boxes       []Object
	Devices     []Object
	Alarms      []Object
	Rules       []Object
	Flows       []Object
	TargetLists []Object
}

// Pagination limits of the mock (its own choice; the real limits are unknown).
const (
	DefaultLimit = 200
	MaxLimit     = 500
)

// Request is one request the mock received.
type Request struct {
	Method string
	Path   string
	// RawQuery is the query string exactly as sent; Query is its parse.
	RawQuery string
	Query    url.Values
	// Authenticated is false when the request was rejected with 401.
	Authenticated bool
	// Status is the status code the mock answered with.
	Status int
}

// Param returns one query parameter of the request.
func (r Request) Param(name string) string { return r.Query.Get(name) }

// Fault makes the mock answer authenticated requests with an error.
type Fault struct {
	Status     int
	RetryAfter string // Retry-After header value, if non-empty
	Body       string // response body; default is a JSON error
	// Times is how many requests the fault applies to; 0 = until cleared.
	Times int
}

// Option configures New.
type Option func(*Mock)

// WithToken sets the accepted token.
func WithToken(t string) Option { return func(m *Mock) { m.token = t } }

// WithState replaces the seed data.
func WithState(s State) Option { return func(m *Mock) { m.state = s } }

// WithIgnoreFilters makes the mock ignore every filter (see SetIgnoreFilters).
func WithIgnoreFilters(b bool) Option { return func(m *Mock) { m.ignoreFilters = b } }

// Mock is the fake upstream. It is an http.Handler.
type Mock struct {
	token string
	mux   *http.ServeMux

	mu            sync.RWMutex
	state         State
	ignoreFilters bool

	ctlMu   sync.Mutex
	faults  []*Fault
	latency time.Duration
	reqs    []Request
}

// New builds a mock with the standard Seed unless WithState is given.
func New(opts ...Option) *Mock {
	m := &Mock{token: DefaultToken, state: Seed()}
	for _, o := range opts {
		o(m)
	}
	m.mux = http.NewServeMux()
	m.mux.HandleFunc("GET /v2/boxes", m.boxes)
	m.mux.HandleFunc("GET /v2/devices", m.devices)
	m.mux.HandleFunc("GET /v2/alarms", m.alarms)
	m.mux.HandleFunc("GET /v2/alarms/{gid}/{aid}", m.alarm)
	m.mux.HandleFunc("GET /v2/rules", m.rules)
	m.mux.HandleFunc("GET /v2/flows", m.flows)
	m.mux.HandleFunc("GET /v2/target-lists", m.targetLists)
	m.mux.HandleFunc("GET /v2/target-lists/{id}", m.targetList)
	m.mux.HandleFunc("GET /v2/stats/{name}", m.stats)
	m.mux.HandleFunc("GET /v2/trends/{name}", m.trends)
	m.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "not_found", "no such endpoint")
	})
	return m
}

// Start serves the mock on a loopback httptest server. The caller closes it.
func (m *Mock) Start() *httptest.Server { return httptest.NewServer(m) }

// Token is the accepted token.
func (m *Mock) Token() string { return m.token }

// SetIgnoreFilters switches filter handling. When true the mock ignores the
// `query` parameter, `box=`, `group=` and `owner=` and returns everything,
// which is what a misbehaving or older upstream might do. Tests use it to
// prove the broker's post-filter, not the upstream filter, is the control.
func (m *Mock) SetIgnoreFilters(b bool) {
	m.mu.Lock()
	m.ignoreFilters = b
	m.mu.Unlock()
}

// Update mutates the state under the mock's lock.
func (m *Mock) Update(f func(*State)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(&m.state)
}

// InjectFault queues an error response for authenticated requests.
func (m *Mock) InjectFault(f Fault) {
	m.ctlMu.Lock()
	defer m.ctlMu.Unlock()
	m.faults = append(m.faults, &f)
}

// ClearFaults removes all injected faults.
func (m *Mock) ClearFaults() {
	m.ctlMu.Lock()
	defer m.ctlMu.Unlock()
	m.faults = nil
}

// SetLatency delays every response (for timeout tests).
func (m *Mock) SetLatency(d time.Duration) {
	m.ctlMu.Lock()
	defer m.ctlMu.Unlock()
	m.latency = d
}

// Requests returns a copy of the recorded requests, oldest first.
func (m *Mock) Requests() []Request {
	m.ctlMu.Lock()
	defer m.ctlMu.Unlock()
	return append([]Request(nil), m.reqs...)
}

// RequestsTo returns the recorded requests for one path.
func (m *Mock) RequestsTo(path string) []Request {
	var out []Request
	for _, r := range m.Requests() {
		if r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

// ResetRequests forgets the recorded requests.
func (m *Mock) ResetRequests() {
	m.ctlMu.Lock()
	defer m.ctlMu.Unlock()
	m.reqs = nil
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// ServeHTTP records the request, authenticates, applies faults and routes.
func (m *Mock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	authed := m.authenticated(r)
	defer func() {
		m.ctlMu.Lock()
		m.reqs = append(m.reqs, Request{
			Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery,
			Query: r.URL.Query(), Authenticated: authed, Status: rec.status,
		})
		m.ctlMu.Unlock()
	}()

	if !authed {
		writeErr(rec, http.StatusUnauthorized, "unauthorized", "missing or invalid token")
		return
	}
	if d := m.currentLatency(); d > 0 {
		select {
		case <-time.After(d):
		case <-r.Context().Done():
			return
		}
	}
	if f := m.nextFault(); f != nil {
		if f.RetryAfter != "" {
			rec.Header().Set("Retry-After", f.RetryAfter)
		}
		if f.Body != "" {
			rec.Header().Set("Content-Type", "application/json")
			rec.WriteHeader(f.Status)
			_, _ = rec.Write([]byte(f.Body))
			return
		}
		writeErr(rec, f.Status, "injected_fault", "fault injected by test")
		return
	}
	m.mux.ServeHTTP(rec, r)
}

func (m *Mock) currentLatency() time.Duration {
	m.ctlMu.Lock()
	defer m.ctlMu.Unlock()
	return m.latency
}

func (m *Mock) nextFault() *Fault {
	m.ctlMu.Lock()
	defer m.ctlMu.Unlock()
	if len(m.faults) == 0 {
		return nil
	}
	f := m.faults[0]
	if f.Times > 0 {
		f.Times--
		if f.Times == 0 {
			m.faults = m.faults[1:]
		}
	}
	cp := *f
	return &cp
}

func (m *Mock) authenticated(r *http.Request) bool {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !(strings.EqualFold(scheme, "Bearer") || strings.EqualFold(scheme, "Token")) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(tok)), []byte(m.token)) == 1
}

// ---- handlers ----

func (m *Mock) boxes(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	writeJSON(w, http.StatusOK, nonNil(m.state.Boxes))
}

func (m *Mock) devices(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	q := r.URL.Query()
	out := m.state.Devices
	if !m.ignoreFilters {
		boxes := csvSet(q.Get("box"))
		groups := csvSet(q.Get("group"))
		inGroup := map[string]bool{}
		for _, b := range m.state.Boxes {
			if g, _ := b["group"].(string); g != "" && groups[strings.ToLower(g)] {
				inGroup[strings.ToLower(str(b["gid"]))] = true
			}
		}
		var kept []Object
		for _, d := range out {
			gid := strings.ToLower(str(d["gid"]))
			if len(boxes) > 0 && !boxes[gid] {
				continue
			}
			if len(groups) > 0 && !inGroup[gid] {
				continue
			}
			kept = append(kept, d)
		}
		out = kept
	}
	writeJSON(w, http.StatusOK, nonNil(out))
}

func (m *Mock) alarms(w http.ResponseWriter, r *http.Request) {
	m.paged(w, r, func(s *State) []Object { return s.Alarms })
}

func (m *Mock) rules(w http.ResponseWriter, r *http.Request) {
	m.paged(w, r, func(s *State) []Object { return s.Rules })
}

func (m *Mock) flows(w http.ResponseWriter, r *http.Request) {
	m.paged(w, r, func(s *State) []Object { return s.Flows })
}

// paged serves a query-filtered, cursor-paginated envelope. Newest first.
func (m *Mock) paged(w http.ResponseWriter, r *http.Request, pick func(*State) []Object) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	q := r.URL.Query()
	items := append([]Object(nil), pick(&m.state)...)
	if !m.ignoreFilters {
		match, err := parseQuery(q.Get("query"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_query", err.Error())
			return
		}
		kept := items[:0]
		for _, o := range items {
			if match(o) {
				kept = append(kept, o)
			}
		}
		items = kept
	}
	sort.SliceStable(items, func(i, j int) bool { return num(items[i]["ts"]) > num(items[j]["ts"]) })

	limit := DefaultLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeErr(w, http.StatusBadRequest, "bad_limit", "limit must be a positive integer")
			return
		}
		limit = min(n, MaxLimit)
	}
	start := 0
	if c := q.Get("cursor"); c != "" {
		n, err := decodeCursor(c)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_cursor", "invalid cursor")
			return
		}
		start = n
	}
	start = min(start, len(items))
	end := min(start+limit, len(items))
	body := Object{"count": end - start, "results": nonNil(items[start:end])}
	if end < len(items) {
		body["next_cursor"] = encodeCursor(end)
	}
	writeJSON(w, http.StatusOK, body)
}

func (m *Mock) alarm(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	gid, aid := r.PathValue("gid"), r.PathValue("aid")
	for _, a := range m.state.Alarms {
		if strings.EqualFold(str(a["gid"]), gid) && str(a["aid"]) == aid {
			writeJSON(w, http.StatusOK, a)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "not_found", "alarm not found")
}

func (m *Mock) targetLists(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := m.state.TargetLists
	if owners := csvSet(r.URL.Query().Get("owner")); len(owners) > 0 && !m.ignoreFilters {
		var kept []Object
		for _, t := range out {
			if owners[strings.ToLower(str(t["owner"]))] {
				kept = append(kept, t)
			}
		}
		out = kept
	}
	writeJSON(w, http.StatusOK, nonNil(out))
}

func (m *Mock) targetList(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id := r.PathValue("id")
	for _, t := range m.state.TargetLists {
		if str(t["id"]) == id {
			writeJSON(w, http.StatusOK, t)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "not_found", "target list not found")
}

// stats and trends: names, shapes and filter support are the mock's own
// (UNKNOWN upstream). Both accept box= and group= and honour them unless
// filters are ignored.
func (m *Mock) stats(w http.ResponseWriter, r *http.Request) {
	switch name := r.PathValue("name"); name {
	case "topBoxesByBlockedFlows", "topBoxesBySecurityAlarms":
		m.series(w, r, func(s *State) []Object {
			var out []Object
			for i, b := range s.Boxes {
				out = append(out, Object{"gid": b["gid"], "name": b["name"], "count": 100 - 10*i})
			}
			return out
		})
	default:
		writeErr(w, http.StatusNotFound, "not_found", "unknown statistic")
	}
}

func (m *Mock) trends(w http.ResponseWriter, r *http.Request) {
	switch name := r.PathValue("name"); name {
	case "flows", "alarms", "rules":
		m.series(w, r, func(s *State) []Object {
			var out []Object
			for i, b := range s.Boxes {
				for day := 1; day <= 3; day++ {
					out = append(out, Object{"gid": b["gid"], "ts": baseTS + day*86400, "value": (i + 1) * day})
				}
			}
			return out
		})
	default:
		writeErr(w, http.StatusNotFound, "not_found", "unknown trend")
	}
}

func (m *Mock) series(w http.ResponseWriter, r *http.Request, build func(*State) []Object) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := build(&m.state)
	if !m.ignoreFilters {
		q := r.URL.Query()
		boxes, groups := csvSet(q.Get("box")), csvSet(q.Get("group"))
		inGroup := map[string]bool{}
		for _, b := range m.state.Boxes {
			if g, _ := b["group"].(string); g != "" && groups[strings.ToLower(g)] {
				inGroup[strings.ToLower(str(b["gid"]))] = true
			}
		}
		var kept []Object
		for _, o := range out {
			gid := strings.ToLower(str(o["gid"]))
			if (len(boxes) > 0 && !boxes[gid]) || (len(groups) > 0 && !inGroup[gid]) {
				continue
			}
			kept = append(kept, o)
		}
		out = kept
	}
	writeJSON(w, http.StatusOK, nonNil(out))
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, Object{"error": code, "message": msg})
}

func nonNil(o []Object) []Object {
	if o == nil {
		return []Object{}
	}
	return o
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func num(v any) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}

// csvSet turns "a,B" into {"a","b"} (lowercase); empty input gives nil.
func csvSet(s string) map[string]bool {
	var out map[string]bool
	for _, p := range strings.Split(s, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			if out == nil {
				out = map[string]bool{}
			}
			out[p] = true
		}
	}
	return out
}

const cursorPrefix = "c1:"

func encodeCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursorPrefix + strconv.Itoa(offset)))
}

func decodeCursor(c string) (int, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil || !strings.HasPrefix(string(b), cursorPrefix) {
		return 0, fmt.Errorf("bad cursor")
	}
	n, err := strconv.Atoi(strings.TrimPrefix(string(b), cursorPrefix))
	if err != nil || n < 0 {
		return 0, fmt.Errorf("bad cursor")
	}
	return n, nil
}
