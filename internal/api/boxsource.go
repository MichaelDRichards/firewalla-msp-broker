package api

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"mspbroker/internal/acl"
	"mspbroker/internal/store"
)

// boxSource supplies the box list (with group membership) used to resolve
// group scopes. The list is cached in SQLite and refreshed from the upstream
// when older than ttl (SPEC 6.2). If a refresh is due and fails, the error is
// returned: a stale membership list could grant access to a box that has left
// a group, so group-scoped requests fail closed (502/504) rather than guess.
type boxSource struct {
	st  *store.Store
	up  Upstream
	ttl time.Duration
	now func() time.Time

	mu sync.Mutex // serialises refreshes
}

// List returns the boxes for scope resolution.
func (b *boxSource) List(ctx context.Context) ([]acl.Box, error) {
	cached, err := b.cached(ctx)
	if cached != nil || err != nil {
		return cached, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	// Another request may have refreshed while we waited for the lock.
	if cached, err := b.cached(ctx); cached != nil || err != nil {
		return cached, err
	}
	boxes, err := b.up.Boxes(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]store.CachedBox, len(boxes))
	for i, bx := range boxes {
		rows[i] = store.CachedBox{GID: bx.GID, Name: bx.Name, GroupID: bx.Group}
	}
	if err := b.st.ReplaceBoxes(ctx, rows, b.now()); err != nil {
		return nil, err
	}
	out := store.ACLBoxes(rows)
	if out == nil {
		out = []acl.Box{}
	}
	return out, nil
}

// cached returns the cached list if it is fresh, else nil (never an empty
// non-nil slice for "stale").
func (b *boxSource) cached(ctx context.Context) ([]acl.Box, error) {
	rows, fetched, err := b.st.LoadBoxes(ctx)
	if err != nil {
		return nil, err
	}
	if fetched.IsZero() || b.now().Sub(fetched) >= b.ttl {
		return nil, nil
	}
	out := store.ACLBoxes(rows)
	if out == nil {
		out = []acl.Box{}
	}
	return out, nil
}

// ---- public endpoints ----

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.cfg.Version}, nil)
}

// readyz reports whether the broker can serve: the database answers and the
// upstream was reachable within the last check interval. It says which check
// failed but never why.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{"database": "ok", "upstream": "ok"}
	ready := true
	if err := s.cfg.Store.Ping(r.Context()); err != nil {
		checks["database"], ready = "error", false
		s.log.WarnContext(r.Context(), "readiness probe: database not reachable", "error", err)
	}
	if !s.upstreamOK(r.Context()) {
		checks["upstream"], ready = "error", false
	}
	status, word := http.StatusOK, "ready"
	if !ready {
		status, word = http.StatusServiceUnavailable, "not_ready"
	}
	s.writeJSON(w, status, map[string]any{"status": word, "checks": checks}, nil)
}

func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(s.doc)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.doc)
}
