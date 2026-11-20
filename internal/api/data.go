package api

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"mspbroker/internal/acl"
	"mspbroker/internal/upstream"
)

// ---- parameter validation ----

const maxLimit = 500

// validObjectID: the alphabet the upstream client allows in path segments.
func validObjectID(s string) bool {
	if s == "" || len(s) > 128 || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		ok := ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' ||
			ch == '-' || ch == '_' || ch == '.' || ch == ':'
		if !ok {
			return false
		}
	}
	return true
}

// validToken: printable ASCII without spaces, bounded. Used for cursors,
// whose format is the upstream's business.
func validToken(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// validField: a groupBy/sortBy value such as "ts:desc" or "type,gid".
func validField(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		ok := ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' ||
			ch == '_' || ch == '.' || ch == ':' || ch == ',' || ch == '-'
		if !ok {
			return false
		}
	}
	return true
}

// boxScope checks that the gid in the path is in the key's scope and returns
// a box set containing just that box, so the query parser treats any other
// box.id qualifier on a per-box route as out of scope.
func (c *call) boxScope(gid string) (*acl.Effective, *result) {
	if !acl.ValidGID(gid) {
		return nil, denial(&acl.Denial{Code: acl.CodeOutOfScope, Detail: "box id is not a valid gid"})
	}
	if !c.eff.Contains(gid) {
		return nil, withGID(denial(&acl.Denial{Code: acl.CodeOutOfScope, Detail: "box " + strings.ToLower(gid) + " is not in this key's scope"}), gid)
	}
	return acl.Resolve(acl.Scope{Type: acl.ScopeBoxes, GIDs: []string{gid}}, nil), nil
}

func withGID(r *result, gid string) *result {
	r.gid = strings.ToLower(gid)
	return r
}

// ---- boxes ----

func (c *call) listBoxes() *result {
	if _, rr := c.strictQuery(); rr != nil {
		return rr
	}
	boxes, err := c.s.cfg.Upstream.Boxes(c.ctx())
	if err != nil {
		return c.s.upstreamFailure(c.ctx(), err, false)
	}
	objs := make([]upstream.Object, 0, len(boxes))
	for _, b := range boxes {
		objs = append(objs, b.Object)
	}
	return listResult(acl.FilterObjects(objs, c.eff, false), "")
}

func (c *call) getBox() *result {
	gid := c.params["gid"]
	eff, rr := c.boxScope(gid)
	if rr != nil {
		return rr
	}
	if _, rr := c.strictQuery(); rr != nil {
		return rr
	}
	boxes, err := c.s.cfg.Upstream.Boxes(c.ctx())
	if err != nil {
		return withGID(c.s.upstreamFailure(c.ctx(), err, false), gid)
	}
	for _, b := range boxes {
		if !strings.EqualFold(b.GID, gid) {
			continue
		}
		if obj, ok := acl.ScopeObject(b.Object, eff, false); ok {
			r := okResult(http.StatusOK, obj)
			r.upstreamStatus = http.StatusOK
			return withGID(r, gid)
		}
	}
	return withGID(notFound("no such box"), gid)
}

func (c *call) listDevices() *result {
	gid := c.params["gid"]
	eff, rr := c.boxScope(gid)
	if rr != nil {
		return rr
	}
	if _, rr := c.strictQuery(); rr != nil {
		return rr
	}
	objs, err := c.s.cfg.Upstream.Devices(c.ctx(), upstream.DevicesParams{Box: strings.ToLower(gid)})
	if err != nil {
		return withGID(c.s.upstreamFailure(c.ctx(), err, false), gid)
	}
	return withGID(listResult(acl.FilterObjects(objs, eff, false), ""), gid)
}

// ---- alarms, rules, flows ----

type listQuery struct {
	cursor, groupBy, sortBy string
	limit                   int
}

type fetchFunc func(ctx context.Context, finalQuery string, lq listQuery) (*upstream.Page, error)

func (c *call) parseListQuery(withPaging bool) (rawQuery string, lq listQuery, rr *result) {
	allowed := []string{"query"}
	if withPaging {
		allowed = append(allowed, "limit", "cursor", "groupBy", "sortBy")
	}
	vals, rr := c.strictQuery(allowed...)
	if rr != nil {
		return "", lq, rr
	}
	rawQuery = vals.Get("query")
	if v := vals.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return "", lq, badRequest("limit must be a positive integer")
		}
		lq.limit = min(n, maxLimit)
	}
	if v := vals.Get("cursor"); v != "" {
		if !validToken(v, 1024) {
			return "", lq, badRequest("cursor is not valid")
		}
		lq.cursor = v
	}
	for name, dst := range map[string]*string{"groupBy": &lq.groupBy, "sortBy": &lq.sortBy} {
		if v := vals.Get(name); v != "" {
			if !validField(v) {
				return "", lq, badRequest(name + " is not valid")
			}
			*dst = v
		}
	}
	return rawQuery, lq, nil
}

// scopedList serves a query-filtered list: gid is "" for the global
// endpoints. The key's box set (or just the path's box) is injected into the
// query, the upstream is called, and the answer is post-filtered.
func (c *call) scopedList(gid string, withPaging bool, fetch fetchFunc) *result {
	eff := c.eff
	if gid != "" {
		var rr *result
		if eff, rr = c.boxScope(gid); rr != nil {
			return rr
		}
	}
	tag := func(r *result) *result {
		if gid != "" {
			return withGID(r, gid)
		}
		return r
	}
	raw, lq, rr := c.parseListQuery(withPaging)
	if rr != nil {
		return tag(rr)
	}
	sq, err := acl.ScopeQuery(raw, eff)
	if err != nil {
		var d *acl.Denial
		var qe *acl.QueryError
		switch {
		case errors.As(err, &d):
			return tag(denial(d))
		case errors.As(err, &qe):
			return tag(badRequest(qe.Error()))
		}
		return tag(internalError("internal error"))
	}
	if sq.Empty {
		r := listResult(nil, "")
		r.upstreamStatus = 0 // nothing was asked of the upstream
		return tag(r)
	}
	page, err := fetch(c.ctx(), sq.Final, lq)
	if err != nil {
		return tag(c.s.upstreamFailure(c.ctx(), err, false))
	}
	return tag(listResult(acl.FilterObjects(page.Results, eff, false), page.NextCursor))
}

func (c *call) alarmsFetch() fetchFunc {
	return func(ctx context.Context, q string, lq listQuery) (*upstream.Page, error) {
		return c.s.cfg.Upstream.Alarms(ctx, upstream.ListParams{Query: q, Cursor: lq.cursor, Limit: lq.limit, GroupBy: lq.groupBy, SortBy: lq.sortBy})
	}
}

func (c *call) flowsFetch() fetchFunc {
	return func(ctx context.Context, q string, lq listQuery) (*upstream.Page, error) {
		return c.s.cfg.Upstream.Flows(ctx, upstream.ListParams{Query: q, Cursor: lq.cursor, Limit: lq.limit, GroupBy: lq.groupBy, SortBy: lq.sortBy})
	}
}

func (c *call) rulesFetch() fetchFunc {
	return func(ctx context.Context, q string, _ listQuery) (*upstream.Page, error) {
		return c.s.cfg.Upstream.Rules(ctx, q)
	}
}

func (c *call) listAlarms() *result    { return c.scopedList("", true, c.alarmsFetch()) }
func (c *call) listFlows() *result     { return c.scopedList("", true, c.flowsFetch()) }
func (c *call) listRules() *result     { return c.scopedList("", false, c.rulesFetch()) }
func (c *call) listBoxAlarms() *result { return c.scopedList(c.params["gid"], true, c.alarmsFetch()) }
func (c *call) listBoxFlows() *result  { return c.scopedList(c.params["gid"], true, c.flowsFetch()) }
func (c *call) listBoxRules() *result  { return c.scopedList(c.params["gid"], false, c.rulesFetch()) }

func (c *call) getAlarm() *result {
	gid, aid := c.params["gid"], c.params["aid"]
	eff, rr := c.boxScope(gid)
	if rr != nil {
		return rr
	}
	if _, rr := c.strictQuery(); rr != nil {
		return withGID(rr, gid)
	}
	if !validObjectID(aid) {
		return withGID(badRequest("alarm id is not valid"), gid)
	}
	obj, err := c.s.cfg.Upstream.Alarm(c.ctx(), strings.ToLower(gid), aid)
	if err != nil {
		r := withGID(c.s.upstreamFailure(c.ctx(), err, true), gid)
		r.objectID = aid
		return r
	}
	// Post-filter: the object must be in scope and belong to the box asked for.
	owner, _ := obj["gid"].(string)
	scoped, ok := acl.ScopeObject(obj, eff, false)
	if !ok || !strings.EqualFold(owner, gid) {
		r := withGID(denial(&acl.Denial{Code: acl.CodeOutOfScope, Detail: "the alarm does not belong to a box in this key's scope"}), gid)
		r.objectID = aid
		return r
	}
	r := okResult(http.StatusOK, scoped)
	r.upstreamStatus = http.StatusOK
	r.objectID = aid
	return withGID(r, gid)
}

// ---- target lists ----

func (c *call) listTargetLists() *result {
	perms := c.p.Key.Permissions
	boxLists := perms.Allows(acl.TargetLists, acl.ActionRead)
	global := perms.Allows(acl.GlobalTargetLists, acl.ActionRead)

	vals, rr := c.strictQuery("owner")
	if rr != nil {
		return rr
	}
	var requested []string
	if v := vals.Get("owner"); v != "" {
		seen := map[string]bool{}
		for _, part := range strings.Split(v, ",") {
			o := strings.ToLower(strings.TrimSpace(part))
			if o == "" {
				return badRequest("owner contains an empty entry")
			}
			switch {
			case seen[o]:
				continue
			case o == acl.GlobalOwner:
				if !global {
					return denial(&acl.Denial{Code: acl.CodePermission, Detail: "key has no read access to global_target_lists"})
				}
			case !acl.ValidGID(o) || !c.eff.Contains(o):
				return denial(&acl.Denial{Code: acl.CodeOutOfScope, Detail: "owner is not in this key's scope"})
			case !boxLists:
				return denial(&acl.Denial{Code: acl.CodePermission, Detail: "key has no read access to target_lists"})
			}
			seen[o] = true
			requested = append(requested, o)
		}
	}

	var owner string
	switch {
	case requested != nil:
		owner = strings.Join(requested, ",")
	case c.eff.All():
		if !boxLists {
			owner = acl.GlobalOwner
		}
	default:
		var owners []string
		if boxLists {
			owners = append(owners, c.eff.GIDs()...)
		}
		if global {
			owners = append(owners, acl.GlobalOwner)
		}
		if len(owners) == 0 {
			r := listResult(nil, "")
			r.upstreamStatus = 0
			return r
		}
		owner = strings.Join(owners, ",")
	}

	objs, err := c.s.cfg.Upstream.TargetLists(c.ctx(), owner)
	if err != nil {
		return c.s.upstreamFailure(c.ctx(), err, false)
	}
	var want map[string]bool
	if requested != nil {
		want = map[string]bool{}
		for _, o := range requested {
			want[o] = true
		}
	}
	kept := make([]upstream.Object, 0, len(objs))
	for _, o := range objs {
		ow, _ := o["owner"].(string)
		ow = strings.ToLower(strings.TrimSpace(ow))
		scoped, ok := acl.ScopeObject(o, c.eff, global)
		switch {
		case !ok:
		case ow != acl.GlobalOwner && !boxLists:
		case want != nil && !want[ow]:
		default:
			kept = append(kept, scoped)
		}
	}
	return listResult(kept, "")
}

func (c *call) getTargetList() *result {
	id := c.params["id"]
	if _, rr := c.strictQuery(); rr != nil {
		return rr
	}
	if !validObjectID(id) {
		return badRequest("target list id is not valid")
	}
	perms := c.p.Key.Permissions
	boxLists := perms.Allows(acl.TargetLists, acl.ActionRead)
	global := perms.Allows(acl.GlobalTargetLists, acl.ActionRead)

	obj, err := c.s.cfg.Upstream.TargetList(c.ctx(), id)
	if err != nil {
		r := c.s.upstreamFailure(c.ctx(), err, true)
		r.objectID = id
		return r
	}
	ow, _ := obj["owner"].(string)
	isGlobal := strings.EqualFold(strings.TrimSpace(ow), acl.GlobalOwner)
	deny := func(code acl.Code, detail string) *result {
		r := denial(&acl.Denial{Code: code, Detail: detail})
		r.objectID = id
		return r
	}
	scoped, inScope := acl.ScopeObject(obj, c.eff, global)
	switch {
	case isGlobal && !global:
		return deny(acl.CodePermission, "key has no read access to global_target_lists")
	case !isGlobal && !boxLists:
		return deny(acl.CodePermission, "key has no read access to target_lists")
	case !inScope:
		return deny(acl.CodeOutOfScope, "the target list is not owned by a box in this key's scope")
	}
	r := okResult(http.StatusOK, scoped)
	r.upstreamStatus = http.StatusOK
	r.objectID = id
	if !isGlobal {
		r.gid = strings.ToLower(ow)
	}
	return r
}

// ---- /me ----

type meSecret struct {
	Prefix    string     `json:"prefix"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	Current   bool       `json:"current"`
}

type meBody struct {
	Key struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Kind    acl.Kind `json:"kind"`
		Enabled bool     `json:"enabled"`
	} `json:"key"`
	Scope        acl.Scope       `json:"scope"`
	ResolvedGIDs []string        `json:"resolved_gids"`
	Permissions  acl.Permissions `json:"permissions"`
	ExpiresAt    *time.Time      `json:"expires_at"`
	IPAllow      []string        `json:"ip_allow"`
	// RateLimitPerMinute is the limit in force; 0 means unlimited.
	RateLimitPerMinute int `json:"rate_limit_per_minute"`
	Rotation           struct {
		InProgress bool       `json:"in_progress"`
		Secrets    []meSecret `json:"secrets"`
	} `json:"rotation"`
}

func (c *call) me() *result {
	if _, rr := c.strictQuery(); rr != nil {
		return rr
	}
	k := c.p.Key
	var b meBody
	b.Key.ID, b.Key.Name, b.Key.Kind, b.Key.Enabled = k.ID, k.Name, k.Kind, k.Enabled
	b.Scope, b.Permissions, b.ExpiresAt = k.Scope, k.Permissions, k.ExpiresAt
	b.IPAllow = k.IPAllow
	if b.IPAllow == nil {
		b.IPAllow = []string{}
	}
	b.RateLimitPerMinute = c.s.cfg.DefaultRateLimit
	if k.RateLimitPerMinute != nil {
		b.RateLimitPerMinute = *k.RateLimitPerMinute
	}

	if c.eff.All() {
		boxes, err := c.s.boxes.List(c.ctx())
		if err != nil {
			return c.s.upstreamFailure(c.ctx(), err, false)
		}
		for _, bx := range boxes {
			b.ResolvedGIDs = append(b.ResolvedGIDs, strings.ToLower(bx.GID))
		}
		sort.Strings(b.ResolvedGIDs)
	} else {
		b.ResolvedGIDs = c.eff.GIDs()
	}
	if b.ResolvedGIDs == nil {
		b.ResolvedGIDs = []string{}
	}

	secrets, err := c.s.cfg.Store.ListSecrets(c.ctx(), k.ID)
	if err != nil {
		c.s.log.ErrorContext(c.ctx(), "listing secrets failed", "error", err)
		return internalError("internal error")
	}
	now := c.s.cfg.Now()
	b.Rotation.Secrets = []meSecret{}
	for _, sec := range secrets {
		if sec.RevokedAt != nil || (sec.ExpiresAt != nil && !now.Before(*sec.ExpiresAt)) {
			continue
		}
		b.Rotation.Secrets = append(b.Rotation.Secrets, meSecret{
			Prefix: sec.Prefix, CreatedAt: sec.CreatedAt, ExpiresAt: sec.ExpiresAt, Current: sec.ID == c.p.SecretID,
		})
	}
	b.Rotation.InProgress = len(b.Rotation.Secrets) > 1
	return okResult(http.StatusOK, b)
}
