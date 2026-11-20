package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"mspbroker/internal/acl"
	"mspbroker/internal/store"
)

// ---- boxes (for scope pickers) ----

type adminBox struct {
	GID   string  `json:"gid"`
	Name  string  `json:"name"`
	Group *string `json:"group"`
}

// adminBoxes lists every box the upstream reports, with its group. It is
// the one place the broker shows boxes outside any key's scope, and only to
// admin keys.
func (c *call) adminBoxes() *result {
	if _, rr := c.strictQuery(); rr != nil {
		return rr
	}
	boxes, err := c.s.cfg.Upstream.Boxes(c.ctx())
	if err != nil {
		return c.s.upstreamFailure(c.ctx(), err, false)
	}
	out := make([]adminBox, 0, len(boxes))
	for _, b := range boxes {
		ab := adminBox{GID: strings.ToLower(b.GID), Name: b.Name}
		if b.Group != "" {
			g := b.Group
			ab.Group = &g
		}
		out = append(out, ab)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GID < out[j].GID })
	n := len(out)
	r := okResult(http.StatusOK, map[string]any{"count": n, "results": out})
	r.count = &n
	r.upstreamStatus = http.StatusOK
	return r
}

// ---- audit browsing ----

type auditView struct {
	ID             int64           `json:"id"`
	TS             time.Time       `json:"ts"`
	KeyID          string          `json:"key_id,omitempty"`
	KeyNameAtTime  string          `json:"key_name_at_time,omitempty"`
	SecretPrefix   string          `json:"secret_prefix,omitempty"`
	ClientIP       string          `json:"client_ip,omitempty"`
	Outcome        string          `json:"outcome"`
	BlockReason    string          `json:"block_reason,omitempty"`
	Method         string          `json:"method"`
	Path           string          `json:"path"`
	Query          string          `json:"query,omitempty"`
	Resource       string          `json:"resource,omitempty"`
	Action         string          `json:"action,omitempty"`
	GID            string          `json:"gid,omitempty"`
	ObjectID       string          `json:"object_id,omitempty"`
	UpstreamStatus *int            `json:"upstream_status,omitempty"`
	Before         json.RawMessage `json:"before,omitempty"`
	After          json.RawMessage `json:"after,omitempty"`
	RevertOf       *int64          `json:"revert_of,omitempty"`
	RevertedBy     *int64          `json:"reverted_by,omitempty"`
	ResultCount    *int            `json:"result_count,omitempty"`
}

func newAuditView(e *store.AuditEntry) auditView {
	return auditView{
		ID: e.ID, TS: e.TS, KeyID: e.KeyID, KeyNameAtTime: e.KeyNameAtTime, SecretPrefix: e.SecretPrefix,
		ClientIP: e.ClientIP, Outcome: e.Outcome, BlockReason: e.BlockReason, Method: e.Method, Path: e.Path,
		Query: e.Query, Resource: e.Resource, Action: e.Action, GID: e.GID, ObjectID: e.ObjectID,
		UpstreamStatus: e.UpstreamStatus, Before: e.Before, After: e.After, RevertOf: e.RevertOf,
		RevertedBy: e.RevertedBy, ResultCount: e.ResultCount,
	}
}

func (c *call) listAudit() *result {
	vals, rr := c.strictQuery("key_id", "gid", "resource", "outcome", "since", "until", "cursor", "limit")
	if rr != nil {
		return rr
	}
	var f store.AuditFilter
	f.KeyID = vals.Get("key_id")
	f.Resource = vals.Get("resource")
	for name, v := range map[string]string{"key_id": f.KeyID, "resource": f.Resource} {
		if v != "" && !validObjectID(v) {
			return badRequest(name + " is not valid")
		}
	}
	if g := vals.Get("gid"); g != "" {
		if !acl.ValidGID(g) {
			return badRequest("gid is not valid")
		}
		f.GID = strings.ToLower(g)
	}
	if o := vals.Get("outcome"); o != "" {
		switch o {
		case store.OutcomeOK, store.OutcomeUpstreamError, store.OutcomeBlocked:
			f.Outcome = o
		default:
			return badRequest("outcome must be ok, upstream_error or blocked")
		}
	}
	for name, dst := range map[string]*time.Time{"since": &f.Since, "until": &f.Until} {
		if v := vals.Get(name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return badRequest(name + " must be an RFC 3339 timestamp")
			}
			*dst = t
		}
	}
	if v := vals.Get("cursor"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			return badRequest("cursor is not valid")
		}
		f.Cursor = n
	}
	if v := vals.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > store.MaxAuditLimit {
			return badRequest("limit must be 1.." + strconv.Itoa(store.MaxAuditLimit))
		}
		f.Limit = n
	}

	entries, next, err := c.s.cfg.Store.ListAudit(c.ctx(), f)
	if err != nil {
		c.s.log.ErrorContext(c.ctx(), "listing audit failed", "error", err)
		return internalError("internal error")
	}
	views := make([]auditView, len(entries))
	for i, e := range entries {
		views[i] = newAuditView(e)
	}
	body := map[string]any{"count": len(views), "results": views}
	if next > 0 {
		body["next_cursor"] = strconv.FormatInt(next, 10)
	}
	r := okResult(http.StatusOK, body)
	n := len(views)
	r.count = &n
	return r
}

func (c *call) getAudit() *result {
	if _, rr := c.strictQuery(); rr != nil {
		return rr
	}
	idStr := c.params["id"]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id < 1 {
		return badRequest("audit id must be a positive integer")
	}
	e, err := c.s.cfg.Store.GetAudit(c.ctx(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			r := notFound("no such audit entry")
			r.objectID = idStr
			return r
		}
		c.s.log.ErrorContext(c.ctx(), "reading audit failed", "error", err)
		return internalError("internal error")
	}
	r := okResult(http.StatusOK, newAuditView(e))
	r.objectID = idStr
	return r
}
