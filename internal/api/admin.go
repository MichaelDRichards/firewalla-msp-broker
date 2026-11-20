package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"mspbroker/internal/acl"
	"mspbroker/internal/audit"
	"mspbroker/internal/auth"
	"mspbroker/internal/store"
)

// Limits on key fields.
const (
	maxNameLen   = 128
	maxNotesLen  = 1024
	maxIPAllow   = 64
	maxGroupLen  = 128
	maxRatePerMn = 1_000_000
)

// ---- views ----

type secretView struct {
	ID        string     `json:"id"`
	Prefix    string     `json:"prefix"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

type rateLimitView struct {
	PerMinute int `json:"per_minute"`
}

// keyView is the admin API's representation of a key. It never carries a
// secret value; Secrets lists prefixes and validity windows only. Admin
// keys have no scope or permissions (both null).
type keyView struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Kind        acl.Kind         `json:"kind"`
	Enabled     bool             `json:"enabled"`
	ExpiresAt   *time.Time       `json:"expires_at"`
	IPAllow     []string         `json:"ip_allow"`
	Scope       *acl.Scope       `json:"scope"`
	Permissions *acl.Permissions `json:"permissions"`
	RateLimit   *rateLimitView   `json:"rate_limit"`
	Notes       string           `json:"notes"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	LastUsedAt  *time.Time       `json:"last_used_at"`
	Secrets     []secretView     `json:"secrets,omitempty"`
}

func newKeyView(k *store.Key, secrets []*store.Secret) keyView {
	v := keyView{
		ID: k.ID, Name: k.Name, Kind: k.Kind, Enabled: k.Enabled, ExpiresAt: k.ExpiresAt,
		IPAllow: k.IPAllow, Notes: k.Notes, CreatedAt: k.CreatedAt, UpdatedAt: k.UpdatedAt, LastUsedAt: k.LastUsedAt,
	}
	if v.IPAllow == nil {
		v.IPAllow = []string{}
	}
	if k.Kind == acl.KindData {
		sc, pm := k.Scope, k.Permissions
		v.Scope, v.Permissions = &sc, &pm
	}
	if k.RateLimitPerMinute != nil {
		v.RateLimit = &rateLimitView{PerMinute: *k.RateLimitPerMinute}
	}
	for _, s := range secrets {
		v.Secrets = append(v.Secrets, secretView{s.ID, s.Prefix, s.CreatedAt, s.ExpiresAt, s.RevokedAt})
	}
	return v
}

// snapshot is a key view as stored in audit before/after: no secret list.
func snapshot(k *store.Key) json.RawMessage {
	b, err := json.Marshal(newKeyView(k, nil))
	if err != nil {
		return nil
	}
	return b
}

// ---- validation ----

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// normalizeKey cleans and validates a key in place and reports the first
// problem in words the caller can act on.
func normalizeKey(k *store.Key, now time.Time, creating bool) error {
	k.Name = strings.TrimSpace(k.Name)
	switch {
	case k.Name == "":
		return errors.New("name is required")
	case utf8.RuneCountInString(k.Name) > maxNameLen || hasControl(k.Name) || !utf8.ValidString(k.Name):
		return fmt.Errorf("name must be at most %d printable characters", maxNameLen)
	case len(k.Notes) > maxNotesLen || hasControl(strings.NewReplacer("\n", "", "\r", "", "\t", "").Replace(k.Notes)):
		return fmt.Errorf("notes must be at most %d characters without control characters", maxNotesLen)
	case !k.Kind.Valid():
		return errors.New("kind must be data or admin")
	}
	if creating && k.ExpiresAt != nil && !k.ExpiresAt.After(now) {
		return errors.New("expires_at must be in the future")
	}
	if len(k.IPAllow) > maxIPAllow {
		return fmt.Errorf("ip_allow has more than %d entries", maxIPAllow)
	}
	norm := make([]string, 0, len(k.IPAllow))
	for _, e := range k.IPAllow {
		p, err := auth.ParseAllowEntry(e)
		if err != nil {
			return fmt.Errorf("ip_allow: %q is not a CIDR or IP address", clipString(e, 64))
		}
		norm = append(norm, p.String())
	}
	k.IPAllow = norm
	if k.RateLimitPerMinute != nil && (*k.RateLimitPerMinute < 0 || *k.RateLimitPerMinute > maxRatePerMn) {
		return fmt.Errorf("rate_limit.per_minute must be 0..%d (0 = unlimited)", maxRatePerMn)
	}

	if k.Kind == acl.KindAdmin {
		// Admin keys reach no data resource: no scope, all permissions none.
		if k.Scope.Type != "" || len(k.Scope.GIDs) > 0 || len(k.Scope.GroupIDs) > 0 || k.Permissions != (acl.Permissions{}) {
			return errors.New("admin keys take no scope and no permissions")
		}
		return nil
	}
	if err := k.Scope.Validate(); err != nil {
		return fmt.Errorf("scope: %v", err)
	}
	for i, g := range k.Scope.GIDs {
		k.Scope.GIDs[i] = strings.ToLower(strings.TrimSpace(g))
	}
	for i, g := range k.Scope.GroupIDs {
		g = strings.TrimSpace(g)
		if len(g) > maxGroupLen || hasControl(g) {
			return errors.New("scope: group id is too long or has control characters")
		}
		k.Scope.GroupIDs[i] = g
	}
	if err := k.Permissions.Validate(); err != nil {
		return fmt.Errorf("permissions: %v", err)
	}
	return nil
}

func clipString(s string, n int) string {
	if len(s) > n {
		return strings.ToValidUTF8(s[:n], "") + "..."
	}
	return s
}

// decodeStrict decodes exactly one JSON value into dst, rejecting unknown
// fields and trailing data.
func decodeStrict(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected data after the JSON value")
	}
	return nil
}

func (c *call) readBody() ([]byte, *result) {
	b, err := io.ReadAll(http.MaxBytesReader(c.w, c.r.Body, maxBodyBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, failure(http.StatusRequestEntityTooLarge, "bad_request", "body_too_large", "request body is too large", audit.ReasonBadRequest)
		}
		return nil, badRequest("request body could not be read")
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, badRequest("a JSON body is required")
	}
	return b, nil
}

func jsonProblem(err error) *result {
	return badRequest("invalid JSON body: " + clipString(err.Error(), 200))
}

// ---- keys ----

type createKeyRequest struct {
	Name        string           `json:"name"`
	Kind        acl.Kind         `json:"kind"`
	Enabled     *bool            `json:"enabled"`
	Scope       *acl.Scope       `json:"scope"`
	Permissions *acl.Permissions `json:"permissions"`
	ExpiresAt   *time.Time       `json:"expires_at"`
	IPAllow     []string         `json:"ip_allow"`
	RateLimit   *rateLimitView   `json:"rate_limit"`
	Notes       string           `json:"notes"`
}

type createKeyResponse struct {
	keyView
	// Secret is the only time the full secret is ever returned.
	Secret string `json:"secret"`
}

func (c *call) createKey() *result {
	body, rr := c.readBody()
	if rr != nil {
		return rr
	}
	var req createKeyRequest
	if err := decodeStrict(body, &req); err != nil {
		return jsonProblem(err)
	}
	now := c.s.cfg.Now().UTC()
	k := &store.Key{
		Name: req.Name, Kind: req.Kind, Enabled: true, ExpiresAt: req.ExpiresAt,
		IPAllow: req.IPAllow, Notes: req.Notes,
	}
	if req.Enabled != nil {
		k.Enabled = *req.Enabled
	}
	if req.Scope != nil {
		k.Scope = *req.Scope
	}
	if req.Permissions != nil {
		k.Permissions = *req.Permissions
	}
	if req.RateLimit != nil {
		n := req.RateLimit.PerMinute
		k.RateLimitPerMinute = &n
	}
	if k.ExpiresAt != nil {
		t := k.ExpiresAt.UTC()
		k.ExpiresAt = &t
	}
	if err := normalizeKey(k, now, true); err != nil {
		return badRequest(err.Error())
	}

	full, sec, err := auth.NewSecret("", now, nil)
	if err != nil {
		c.s.log.ErrorContext(c.ctx(), "secret generation failed", "error", err)
		return internalError("internal error")
	}
	if err := c.s.cfg.Store.CreateKey(c.ctx(), k, sec); err != nil {
		if errors.Is(err, store.ErrNameTaken) {
			return failure(http.StatusConflict, "conflict", "name_taken", "an active key already uses that name", audit.ReasonConflict)
		}
		c.s.log.ErrorContext(c.ctx(), "creating key failed", "error", err)
		return internalError("internal error")
	}
	r := okResult(http.StatusCreated, createKeyResponse{keyView: newKeyView(k, []*store.Secret{sec}), Secret: full})
	r.objectID = k.ID
	r.after = snapshot(k)
	return r
}

func (c *call) listKeys() *result {
	if _, rr := c.strictQuery(); rr != nil {
		return rr
	}
	keys, err := c.s.cfg.Store.ListKeys(c.ctx(), false)
	if err != nil {
		c.s.log.ErrorContext(c.ctx(), "listing keys failed", "error", err)
		return internalError("internal error")
	}
	views := make([]keyView, 0, len(keys))
	for _, k := range keys {
		secrets, err := c.s.cfg.Store.ListSecrets(c.ctx(), k.ID)
		if err != nil {
			c.s.log.ErrorContext(c.ctx(), "listing secrets failed", "error", err)
			return internalError("internal error")
		}
		views = append(views, newKeyView(k, secrets))
	}
	r := okResult(http.StatusOK, map[string]any{"count": len(views), "results": views})
	n := len(views)
	r.count = &n
	return r
}

// loadKey fetches an active key by id for the admin handlers.
func (c *call) loadKey(id string) (*store.Key, []*store.Secret, *result) {
	k, err := c.s.cfg.Store.GetKey(c.ctx(), id)
	if err != nil || k.DeletedAt != nil {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			c.s.log.ErrorContext(c.ctx(), "loading key failed", "error", err)
			return nil, nil, internalError("internal error")
		}
		r := notFound("no such key")
		r.objectID = clipString(id, 64)
		return nil, nil, r
	}
	secrets, err := c.s.cfg.Store.ListSecrets(c.ctx(), k.ID)
	if err != nil {
		c.s.log.ErrorContext(c.ctx(), "listing secrets failed", "error", err)
		return nil, nil, internalError("internal error")
	}
	return k, secrets, nil
}

func (c *call) getKey() *result {
	if _, rr := c.strictQuery(); rr != nil {
		return rr
	}
	k, secrets, rr := c.loadKey(c.params["id"])
	if rr != nil {
		return rr
	}
	r := okResult(http.StatusOK, newKeyView(k, secrets))
	r.objectID = k.ID
	return r
}

// patchKey applies a partial update. Fields absent from the body are left
// alone; null clears expires_at, ip_allow and rate_limit. permissions is
// merged per resource, scope is replaced. kind and secrets cannot be touched.
func (c *call) patchKey() *result {
	body, rr := c.readBody()
	if rr != nil {
		return rr
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return badRequest("body must be a JSON object")
	}
	k, _, rr := c.loadKey(c.params["id"])
	if rr != nil {
		return rr
	}
	before := snapshot(k)
	now := c.s.cfg.Now().UTC()

	fail := func(format string, a ...any) *result {
		r := badRequest(fmt.Sprintf(format, a...))
		r.objectID = k.ID
		return r
	}
	if len(fields) == 0 {
		return fail("no fields to update")
	}
	for name, raw := range fields {
		var err error
		switch name {
		case "name":
			err = json.Unmarshal(raw, &k.Name)
		case "enabled":
			err = json.Unmarshal(raw, &k.Enabled)
		case "notes":
			err = json.Unmarshal(raw, &k.Notes)
		case "expires_at":
			var t *time.Time
			if err = json.Unmarshal(raw, &t); err == nil {
				if t != nil {
					u := t.UTC()
					t = &u
				}
				k.ExpiresAt = t
			}
		case "ip_allow":
			var l []string
			if err = json.Unmarshal(raw, &l); err == nil {
				k.IPAllow = l
			}
		case "rate_limit":
			var rl *rateLimitView
			if err = decodeStrict(raw, &rl); err == nil {
				k.RateLimitPerMinute = nil
				if rl != nil {
					n := rl.PerMinute
					k.RateLimitPerMinute = &n
				}
			}
		case "scope":
			if k.Kind != acl.KindData {
				return fail("admin keys take no scope")
			}
			var sc acl.Scope
			if err = decodeStrict(raw, &sc); err == nil {
				k.Scope = sc
			}
		case "permissions":
			if k.Kind != acl.KindData {
				return fail("admin keys take no permissions")
			}
			pm := k.Permissions
			if err = decodeStrict(raw, &pm); err == nil {
				k.Permissions = pm
			}
		case "kind":
			return fail("kind cannot be changed")
		default:
			return fail("unknown or read-only field %s", quoteShort(name))
		}
		if err != nil {
			return fail("field %s: %s", quoteShort(name), clipString(err.Error(), 200))
		}
	}
	if err := normalizeKey(k, now, false); err != nil {
		return fail("%s", err.Error())
	}
	if err := c.s.cfg.Store.UpdateKey(c.ctx(), k); err != nil {
		switch {
		case errors.Is(err, store.ErrNameTaken):
			r := failure(http.StatusConflict, "conflict", "name_taken", "an active key already uses that name", audit.ReasonConflict)
			r.objectID = k.ID
			return r
		case errors.Is(err, store.ErrNotFound):
			return notFound("no such key")
		}
		c.s.log.ErrorContext(c.ctx(), "updating key failed", "error", err)
		return internalError("internal error")
	}
	secrets, err := c.s.cfg.Store.ListSecrets(c.ctx(), k.ID)
	if err != nil {
		c.s.log.ErrorContext(c.ctx(), "listing secrets failed", "error", err)
		return internalError("internal error")
	}
	r := okResult(http.StatusOK, newKeyView(k, secrets))
	r.objectID = k.ID
	r.before, r.after = before, snapshot(k)
	return r
}
