package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"mspbroker/internal/store"
)

// KeyStore is the part of the store the authenticator needs.
type KeyStore interface {
	SecretByHash(ctx context.Context, hash []byte) (*store.Secret, error)
	GetKey(ctx context.Context, id string) (*store.Key, error)
	TouchKeyLastUsed(ctx context.Context, id string, at time.Time) error
}

// Config configures an Authenticator.
type Config struct {
	Store KeyStore
	// TrustedProxies are the peers whose X-Forwarded-For is believed.
	TrustedProxies []netip.Prefix
	// DefaultRateLimit applies to keys without their own limit (per minute;
	// 0 = unlimited).
	DefaultRateLimit int
	// Now is the clock; time.Now if nil.
	Now func() time.Time
}

// Authenticator authenticates requests.
type Authenticator struct {
	cfg     Config
	limiter *Limiter
}

// New returns an Authenticator.
func New(cfg Config) *Authenticator {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Authenticator{cfg: cfg, limiter: NewLimiter(cfg.Now)}
}

// Principal is an authenticated caller. It never contains the secret.
type Principal struct {
	Key          *store.Key
	SecretID     string
	SecretPrefix string
	ClientIP     string
}

// lastUsedGranularity limits how often last_used_at is written.
const lastUsedGranularity = time.Minute

// Authenticate runs SPEC 6.1 lookup: hash the presented secret, find the
// secret row, check revoked/expired, load the key, check enabled/expired,
// the IP allowlist and the rate limit.
//
// On success it returns the Principal. An authentication failure is returned
// as a *Failure (use AsFailure); any other error is an infrastructure fault
// and should be a 500. The rate limit is charged only after every other
// check passes, so unauthenticated traffic cannot drain a key's bucket.
func (a *Authenticator) Authenticate(ctx context.Context, h http.Header, remoteAddr string) (*Principal, error) {
	now := a.cfg.Now()
	ip := ClientIP(remoteAddr, h.Values("X-Forwarded-For"), a.cfg.TrustedProxies)
	ipStr := ""
	if ip.IsValid() {
		ipStr = ip.String()
	}
	fail := func(r Reason, status int, internal string) *Failure {
		return &Failure{Reason: r, Status: status, ClientIP: ipStr, Internal: internal}
	}

	token, ok := ParseBearer(h.Get("Authorization"))
	if !ok {
		return nil, fail(ReasonAuth, http.StatusUnauthorized, "missing or malformed Authorization header")
	}
	if !WellFormed(token) {
		return nil, fail(ReasonAuth, http.StatusUnauthorized, "malformed secret")
	}
	prefix := Prefix(token)
	hash := Hash(token)

	sec, err := a.cfg.Store.SecretByHash(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		f := fail(ReasonAuth, http.StatusUnauthorized, "unknown secret")
		f.SecretPrefix = prefix
		return nil, f
	}
	if err != nil {
		return nil, err
	}
	// Defence in depth: the row came from an index lookup, but compare the
	// hash bytes in constant time before trusting it.
	if subtle.ConstantTimeCompare(sec.Hash, hash) != 1 {
		f := fail(ReasonAuth, http.StatusUnauthorized, "hash mismatch")
		f.SecretPrefix = prefix
		return nil, f
	}

	key, err := a.cfg.Store.GetKey(ctx, sec.KeyID)
	if errors.Is(err, store.ErrNotFound) {
		f := fail(ReasonAuth, http.StatusUnauthorized, "secret without key")
		f.SecretPrefix = prefix
		return nil, f
	}
	if err != nil {
		return nil, err
	}
	known := func(r Reason, status int, internal string) *Failure {
		f := fail(r, status, internal)
		f.KeyID, f.KeyName, f.SecretPrefix = key.ID, key.Name, prefix
		return f
	}

	switch {
	case sec.RevokedAt != nil:
		return nil, known(ReasonAuth, http.StatusUnauthorized, "revoked secret")
	case sec.ExpiresAt != nil && !now.Before(*sec.ExpiresAt):
		return nil, known(ReasonExpired, http.StatusUnauthorized, "secret expired")
	case key.DeletedAt != nil:
		return nil, known(ReasonAuth, http.StatusUnauthorized, "deleted key")
	case !key.Enabled:
		return nil, known(ReasonDisabled, http.StatusForbidden, "key disabled")
	case key.ExpiresAt != nil && !now.Before(*key.ExpiresAt):
		return nil, known(ReasonExpired, http.StatusUnauthorized, "key expired")
	case !IPAllowed(key.IPAllow, ip):
		return nil, known(ReasonIP, http.StatusForbidden, "client address not allowed")
	}

	limit := a.cfg.DefaultRateLimit
	if key.RateLimitPerMinute != nil {
		limit = *key.RateLimitPerMinute
	}
	if allowed, wait := a.limiter.Allow(key.ID, limit); !allowed {
		f := known(ReasonRateLimit, http.StatusTooManyRequests, "rate limit exceeded")
		f.RetryAfter = wait
		return nil, f
	}

	if key.LastUsedAt == nil || now.Sub(*key.LastUsedAt) >= lastUsedGranularity {
		// Best effort: a failed bookkeeping write must not fail the request.
		_ = a.cfg.Store.TouchKeyLastUsed(ctx, key.ID, now)
	}
	return &Principal{Key: key, SecretID: sec.ID, SecretPrefix: prefix, ClientIP: ipStr}, nil
}

// NewSecret generates a secret for a key and returns the string to show the
// client once plus the row to store. expiresAt may be nil.
func NewSecret(keyID string, now time.Time, expiresAt *time.Time) (full string, row *store.Secret, err error) {
	full, err = GenerateSecret()
	if err != nil {
		return "", nil, err
	}
	return full, &store.Secret{
		ID:        store.NewSecretID(),
		KeyID:     keyID,
		Prefix:    Prefix(full),
		Hash:      Hash(full),
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}, nil
}
