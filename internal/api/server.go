// Package api is the HTTP surface of mspbroker: the data API under /api/v1, the
// admin API under /admin/v1, health probes and the OpenAPI document.
//
// Every request that is not a public probe runs one pipeline (SPEC 6.4):
// authenticate (401), kind (403 kind), permission (403 permission), effective
// box set, then the handler. The handler's outcome is audited before the
// response is sent; if the audit row cannot be written the client gets a 500
// and no data. There is no route table the mux could fall back from: a path
// or method that is not registered gets a 404/405 after authentication and is
// audited like any other blocked attempt (default deny).
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"mspbroker/internal/acl"
	"mspbroker/internal/audit"
	"mspbroker/internal/auth"
	"mspbroker/internal/redact"
	"mspbroker/internal/store"
	"mspbroker/internal/upstream"
)

// Upstream is the part of the upstream client the API uses. *upstream.Client
// implements it.
type Upstream interface {
	Boxes(ctx context.Context) ([]upstream.Box, error)
	Devices(ctx context.Context, p upstream.DevicesParams) ([]upstream.Object, error)
	Alarms(ctx context.Context, p upstream.ListParams) (*upstream.Page, error)
	Alarm(ctx context.Context, gid, aid string) (upstream.Object, error)
	Rules(ctx context.Context, query string) (*upstream.Page, error)
	Flows(ctx context.Context, p upstream.ListParams) (*upstream.Page, error)
	TargetLists(ctx context.Context, owner string) ([]upstream.Object, error)
	TargetList(ctx context.Context, id string) (upstream.Object, error)
}

// Defaults.
const (
	DefaultReadyInterval = 30 * time.Second
	maxBodyBytes         = 64 << 10
	readyProbeTimeout    = 5 * time.Second
)

// Config wires a Server.
type Config struct {
	Store    *store.Store
	Upstream Upstream
	Auth     *auth.Authenticator
	Audit    *audit.Recorder
	// Logger receives request lines and errors. Wrap its handler with
	// redact.Scrubber.Handler; nil discards.
	Logger *slog.Logger
	// Scrub removes secrets from error details before they are sent, logged
	// or audited. The server also applies it to every response error detail,
	// which may echo client input. Nil scrubs broker secrets by shape only.
	Scrub *redact.Scrubber
	// GroupCacheTTL is how long the box list used to resolve groups is
	// trusted. 0 refreshes on every group-scoped request.
	GroupCacheTTL time.Duration
	// DefaultRateLimit is shown by /me for keys without their own limit.
	DefaultRateLimit int
	// ReadyInterval bounds how stale a /readyz upstream probe may be.
	ReadyInterval time.Duration
	// Now is the clock; time.Now if nil. It should be the clock the store
	// and authenticator use.
	Now func() time.Time
	// Version is reported by /healthz.
	Version string
}

// Server is the HTTP handler.
type Server struct {
	cfg    Config
	log    *slog.Logger
	scrub  *redact.Scrubber
	boxes  *boxSource
	routes []*route
	ready  readiness
	doc    []byte
}

// New builds a Server. Store, Upstream, Auth and Audit are required.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.Upstream == nil || cfg.Auth == nil || cfg.Audit == nil {
		return nil, errors.New("api: Store, Upstream, Auth and Audit are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ReadyInterval <= 0 {
		cfg.ReadyInterval = DefaultReadyInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Server{cfg: cfg, log: cfg.Logger, scrub: cfg.Scrub}
	if s.scrub == nil {
		s.scrub = redact.New()
	}
	s.boxes = &boxSource{st: cfg.Store, up: cfg.Upstream, ttl: cfg.GroupCacheTTL, now: cfg.Now}
	s.ready = readiness{interval: cfg.ReadyInterval, now: cfg.Now}
	s.registerRoutes()
	doc, err := buildOpenAPI(cfg.Version)
	if err != nil {
		return nil, err
	}
	s.doc = doc
	return s, nil
}

// RouteInfo names one registered route.
type RouteInfo struct {
	Method  string
	Pattern string
}

// Routes lists every registered route. The OpenAPI test checks each appears
// in the document.
func (s *Server) Routes() []RouteInfo {
	out := make([]RouteInfo, len(s.routes))
	for i, r := range s.routes {
		out[i] = RouteInfo{r.method, r.pattern}
	}
	return out
}

// OpenAPI returns the OpenAPI 3.1 document.
func (s *Server) OpenAPI() []byte { return s.doc }

// statusWriter records the status for the request log.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w := &statusWriter{ResponseWriter: rw}
	setSecurityHeaders(w.Header(), r.TLS != nil)
	start := time.Now()
	defer func() {
		if p := recover(); p != nil {
			s.log.Error("panic while serving request", "method", r.Method, "path", r.URL.EscapedPath(), "panic", fmt.Sprint(p))
			if w.status == 0 {
				s.writeJSON(w, http.StatusInternalServerError, apiError{"internal", "internal", "internal error"}, nil)
			}
		}
		s.log.Debug("request", "method", r.Method, "path", r.URL.EscapedPath(), "status", w.status, "elapsed", time.Since(start))
	}()

	m := s.match(r.Method, r.URL.EscapedPath())
	if m.route != nil && m.route.surface == surfacePublic {
		m.route.public(s, w, r)
		return
	}
	s.pipeline(w, r, m)
}

// setSecurityHeaders applies the headers every response carries. There is
// deliberately no CORS header anywhere: browsers are not API clients.
func setSecurityHeaders(h http.Header, tls bool) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
	if tls {
		h.Set("Strict-Transport-Security", "max-age=63072000")
	}
}

// ---- pipeline ----

// call is one authenticated request in flight.
type call struct {
	s      *Server
	w      http.ResponseWriter
	r      *http.Request
	p      *auth.Principal
	rt     *route
	params map[string]string
	eff    *acl.Effective
}

func (c *call) ctx() context.Context { return c.r.Context() }

func (s *Server) pipeline(w http.ResponseWriter, r *http.Request, m matched) {
	ctx := r.Context()
	entry := &store.AuditEntry{
		Method: r.Method,
		Path:   r.URL.EscapedPath(),
		Query:  r.URL.RawQuery,
	}

	// 1. Authenticate.
	p, err := s.cfg.Auth.Authenticate(ctx, r.Header, r.RemoteAddr)
	if err != nil {
		f, ok := auth.AsFailure(err)
		if !ok {
			s.log.ErrorContext(ctx, "authentication infrastructure error", "error", err)
			s.finish(w, r, entry, internalError("internal error"))
			return
		}
		entry.KeyID, entry.KeyNameAtTime, entry.SecretPrefix, entry.ClientIP = f.KeyID, f.KeyName, f.SecretPrefix, f.ClientIP
		res := authFailure(f)
		s.finish(w, r, entry, res)
		return
	}
	entry.KeyID, entry.KeyNameAtTime, entry.SecretPrefix, entry.ClientIP = p.Key.ID, p.Key.Name, p.SecretPrefix, p.ClientIP

	// 2. Kind. The surface comes from the route, or from the path prefix for
	// anything unmodelled, so probing the other surface is a kind failure.
	surface := m.surface()
	if surface != "" {
		if d := acl.CheckKind(p.Key.Kind, surface); d != nil {
			s.finish(w, r, entry, denial(d))
			return
		}
	}

	// Default deny: nothing below this line runs for an unmodelled request.
	if m.route == nil {
		res := failure(http.StatusNotFound, "not_found", "not_found", "no such endpoint", audit.ReasonUnmodelled)
		if len(m.allow) > 0 {
			res = failure(http.StatusMethodNotAllowed, "method_not_allowed", "method_not_allowed",
				"this endpoint does not support "+safeMethod(r.Method), audit.ReasonUnmodelled)
			res.setHeader("Allow", strings.Join(m.allow, ", "))
		}
		s.finish(w, r, entry, res)
		return
	}
	rt := m.route
	entry.Resource, entry.Action = rt.auditResource, rt.auditAction

	c := &call{s: s, w: w, r: r, p: p, rt: rt, params: m.params}

	// 3. Permission (data API).
	if rt.surface == surfaceData && len(rt.need) > 0 {
		allowed := false
		for _, res := range rt.need {
			if p.Key.Permissions.Allows(res, acl.ActionRead) {
				allowed = true
				break
			}
		}
		if !allowed {
			d := &acl.Denial{Code: acl.CodePermission, Detail: fmt.Sprintf("key has no read access to %s", rt.need[0])}
			s.finish(w, r, entry, denial(d))
			return
		}
	}

	// 4. Effective box set (data API).
	if rt.surface == surfaceData {
		eff, err := s.effective(ctx, p.Key)
		if err != nil {
			s.finish(w, r, entry, s.upstreamFailure(ctx, err, false))
			return
		}
		c.eff = eff
	}

	// 5. Handler.
	res := s.run(c)
	s.finish(w, r, entry, res)
}

// run calls the handler, turning a panic into an internal error so the
// request is still audited.
func (s *Server) run(c *call) (res *result) {
	defer func() {
		if p := recover(); p != nil {
			s.log.ErrorContext(c.ctx(), "panic in handler", "route", c.rt.method+" "+c.rt.pattern, "panic", fmt.Sprint(p))
			res = internalError("internal error")
		}
	}()
	return c.rt.handler(c)
}

func safeMethod(m string) string {
	if len(m) > 16 {
		m = m[:16]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x21 || r > 0x7e {
			return -1
		}
		return r
	}, m)
}

func authFailure(f *auth.Failure) *result {
	name := "unauthorized"
	switch f.Status {
	case http.StatusForbidden:
		name = "forbidden"
	case http.StatusTooManyRequests:
		name = "rate_limited"
	}
	res := failure(f.Status, name, string(f.Reason), f.Message(), string(f.Reason))
	switch f.Status {
	case http.StatusUnauthorized:
		res.setHeader("WWW-Authenticate", "Bearer")
	case http.StatusTooManyRequests:
		res.setHeader("Retry-After", fmt.Sprint(f.RetryAfterSeconds()))
	}
	return res
}

// finish fills the audit entry from res, records it, then writes the
// response. An audit failure replaces the response with a 500: a request
// that cannot be audited is not served.
func (s *Server) finish(w http.ResponseWriter, r *http.Request, e *store.AuditEntry, res *result) {
	ctx := r.Context()
	if res.resource != "" {
		e.Resource = res.resource
	}
	if res.action != "" {
		e.Action = res.action
	}
	e.Outcome, e.BlockReason = res.outcome, res.reason
	if e.Outcome == "" {
		e.Outcome = store.OutcomeOK
		if res.status >= 400 {
			e.Outcome, e.BlockReason = store.OutcomeBlocked, audit.ReasonInternal
		}
	}
	e.GID, e.ObjectID = res.gid, res.objectID
	if res.upstreamStatus != 0 {
		st := res.upstreamStatus
		e.UpstreamStatus = &st
	}
	e.ResultCount = res.count
	e.Before, e.After = res.before, res.after

	// Error details may echo client input; scrub them before they are sent.
	if ae, ok := res.body.(apiError); ok {
		ae.Detail = s.scrub.String(ae.Detail)
		res.body = ae
	}
	if err := s.cfg.Audit.Record(ctx, e); err != nil {
		s.log.ErrorContext(ctx, "audit write failed; request not served", "error", err, "status", res.status)
		s.writeJSON(w, http.StatusInternalServerError, apiError{"internal", "audit_unavailable", "the request could not be recorded and was not served"}, nil)
		return
	}
	s.log.InfoContext(ctx, "request",
		"method", r.Method, "path", e.Path, "status", res.status, "outcome", e.Outcome,
		"block_reason", e.BlockReason, "key_id", e.KeyID, "audit_id", e.ID)
	s.writeJSON(w, res.status, res.body, res.header)
}

// ---- helpers shared by handlers ----

// effective resolves a key's box set. Scopes with groups need the box list.
func (s *Server) effective(ctx context.Context, k *store.Key) (*acl.Effective, error) {
	switch k.Scope.Type {
	case acl.ScopeGroups, acl.ScopeBoxesGroups:
		boxes, err := s.boxes.List(ctx)
		if err != nil {
			return nil, err
		}
		return acl.Resolve(k.Scope, boxes), nil
	}
	return acl.Resolve(k.Scope, nil), nil
}

// strictQuery parses the request query string allowing only the named
// parameters, each at most once. Anything else is a 400: unknown parameters
// are never forwarded and repeated parameters are ambiguous.
func (c *call) strictQuery(allowed ...string) (url.Values, *result) {
	raw := c.r.URL.RawQuery
	if len(raw) > 16384 {
		return nil, badRequest("query string too long")
	}
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return nil, badRequest("query string is not valid")
	}
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for k, vs := range vals {
		if !ok[k] {
			return nil, badRequest("unknown query parameter " + quoteShort(k))
		}
		if len(vs) > 1 {
			return nil, badRequest("query parameter " + quoteShort(k) + " given more than once")
		}
	}
	return vals, nil
}

func quoteShort(s string) string {
	if len(s) > 40 {
		s = s[:40] + "..."
	}
	b, _ := json.Marshal(s)
	return string(b)
}

// ---- readiness ----

type readiness struct {
	interval time.Duration
	now      func() time.Time

	mu     sync.Mutex
	at     time.Time
	result bool
}

// upstreamOK probes the upstream at most once per interval. A failure is
// remembered for at most readyFailTTL so recovery is noticed quickly.
func (s *Server) upstreamOK(ctx context.Context) bool {
	rd := &s.ready
	rd.mu.Lock()
	defer rd.mu.Unlock()
	now := rd.now()
	ttl := rd.interval
	if !rd.result && ttl > 5*time.Second {
		ttl = 5 * time.Second
	}
	if !rd.at.IsZero() && now.Sub(rd.at) < ttl {
		return rd.result
	}
	pctx, cancel := context.WithTimeout(ctx, readyProbeTimeout)
	defer cancel()
	_, err := s.cfg.Upstream.Boxes(pctx)
	rd.at, rd.result = now, err == nil
	if err != nil {
		s.log.WarnContext(ctx, "readiness probe: upstream not reachable", "error", err)
	}
	return rd.result
}
