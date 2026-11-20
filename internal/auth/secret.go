// Package auth turns a presented bearer secret into an authenticated key:
// secret generation and hashing, expiry and enabled checks, IP allowlists
// and per-key rate limiting. Failures are typed reason codes.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Secret format (SPEC 6.1): "mb_" + base62 of 32 random bytes, left-padded to
// a fixed 43 characters (62^43 > 2^256). The first 8 characters after the
// prefix are stored in clear for identification.
const (
	SecretPrefix  = "mb_"
	secretBodyLen = 43
	secretLen     = len(SecretPrefix) + secretBodyLen
	// PrefixLen is the number of characters after "mb_" kept in clear.
	PrefixLen = 8

	base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// GenerateSecret returns a new random secret string. It is shown to the
// client exactly once; only Hash and Prefix are stored.
func GenerateSecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("auth: random: %w", err)
	}
	return SecretPrefix + encodeBase62(raw[:]), nil
}

func encodeBase62(b []byte) string {
	n := new(big.Int).SetBytes(b)
	out := make([]byte, secretBodyLen)
	for i := range out {
		out[i] = base62[0]
	}
	base, mod := big.NewInt(62), new(big.Int)
	for i := secretBodyLen - 1; n.Sign() > 0 && i >= 0; i-- {
		n.DivMod(n, base, mod)
		out[i] = base62[mod.Int64()]
	}
	return string(out)
}

// WellFormed reports whether s has the exact shape of a broker secret. It is
// a cheap pre-check; passing it says nothing about validity.
func WellFormed(s string) bool {
	if len(s) != secretLen || !strings.HasPrefix(s, SecretPrefix) {
		return false
	}
	for i := len(SecretPrefix); i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}

// Hash returns the SHA-256 of the full secret string, as stored.
func Hash(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// Prefix returns the 8 characters after "mb_", safe to log. It returns ""
// for strings that are not well-formed secrets, so junk is never echoed.
func Prefix(secret string) string {
	if !WellFormed(secret) {
		return ""
	}
	return secret[len(SecretPrefix) : len(SecretPrefix)+PrefixLen]
}

// ParseBearer extracts the token from an Authorization header value. The
// scheme is case-insensitive; exactly one space must separate it from the
// token.
func ParseBearer(header string) (string, bool) {
	const scheme = "bearer "
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	tok := header[len(scheme):]
	if tok == "" || strings.ContainsAny(tok, " \t\r\n") {
		return "", false
	}
	return tok, true
}

// Reason is a stable code for why authentication failed. These are the
// auth-stage values of the audit log's block_reason.
type Reason string

// Failure reasons.
const (
	ReasonAuth      Reason = "auth"       // missing, malformed, unknown, revoked or deleted: indistinguishable
	ReasonExpired   Reason = "expired"    // secret or key past its expiry
	ReasonDisabled  Reason = "disabled"   // key switched off
	ReasonIP        Reason = "ip"         // client address not in the key's allowlist
	ReasonRateLimit Reason = "rate_limit" // token bucket empty
)

// Failure is an authentication failure. Error and Message are safe to send
// to the client. The other fields are for the audit log only.
type Failure struct {
	Reason Reason
	// Status is the HTTP status to return.
	Status int
	// RetryAfter is set for rate_limit failures.
	RetryAfter time.Duration

	// Audit-only context; KeyID/KeyName are empty when no key was identified.
	KeyID        string
	KeyName      string
	SecretPrefix string
	ClientIP     string
	// Internal says why, in words ("revoked", "unknown secret"). Never send it
	// to the client: it is what makes unknown and revoked distinguishable.
	Internal string
}

// Message is the client-facing explanation. Unknown, revoked, deleted and
// malformed credentials all share one message.
func (f *Failure) Message() string {
	switch f.Reason {
	case ReasonExpired:
		return "credentials have expired"
	case ReasonDisabled:
		return "key is disabled"
	case ReasonIP:
		return "request not allowed from this address"
	case ReasonRateLimit:
		return "rate limit exceeded"
	}
	return "invalid or missing credentials"
}

func (f *Failure) Error() string { return string(f.Reason) + ": " + f.Message() }

// RetryAfterSeconds is the value for the Retry-After header: whole seconds,
// rounded up, at least 1.
func (f *Failure) RetryAfterSeconds() int {
	s := int((f.RetryAfter + time.Second - 1) / time.Second)
	if s < 1 {
		s = 1
	}
	return s
}

// AsFailure unwraps err to a *Failure.
func AsFailure(err error) (*Failure, bool) {
	var f *Failure
	if errors.As(err, &f) {
		return f, true
	}
	return nil, false
}
