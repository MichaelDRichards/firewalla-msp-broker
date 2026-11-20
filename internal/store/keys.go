package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"mspbroker/internal/acl"
)

// Key is a credential's identity, scope and permissions. Secrets are separate.
type Key struct {
	ID                 string
	Name               string
	Kind               acl.Kind
	Enabled            bool
	ExpiresAt          *time.Time
	IPAllow            []string // CIDRs or bare IPs; empty = any
	Scope              acl.Scope
	Permissions        acl.Permissions
	RateLimitPerMinute *int // nil = configured default; 0 = unlimited
	Notes              string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	LastUsedAt         *time.Time
	DeletedAt          *time.Time
}

// Secret is one bearer credential of a key. Hash is SHA-256 of the full
// secret string; Prefix is the first 8 characters after "mb_".
type Secret struct {
	ID        string
	KeyID     string
	Prefix    string
	Hash      []byte
	CreatedAt time.Time
	ExpiresAt *time.Time
	RevokedAt *time.Time
}

const keyColumns = `id, name, kind, enabled, expires_at, ip_allow, scope, permissions,
	rate_limit_per_minute, notes, created_at, updated_at, last_used_at, deleted_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanKey(r rowScanner) (*Key, error) {
	var (
		k                                  Key
		enabled                            int
		expires, rate, lastUsed, deletedAt sql.NullInt64
		created, updated                   int64
		ipAllow, scope, perms              string
		kind                               string
	)
	if err := r.Scan(&k.ID, &k.Name, &kind, &enabled, &expires, &ipAllow, &scope, &perms,
		&rate, &k.Notes, &created, &updated, &lastUsed, &deletedAt); err != nil {
		return nil, err
	}
	k.Kind = acl.Kind(kind)
	k.Enabled = enabled == 1
	k.ExpiresAt = fromMsPtr(expires)
	k.LastUsedAt = fromMsPtr(lastUsed)
	k.DeletedAt = fromMsPtr(deletedAt)
	k.CreatedAt, k.UpdatedAt = fromMs(created), fromMs(updated)
	if rate.Valid {
		v := int(rate.Int64)
		k.RateLimitPerMinute = &v
	}
	if err := json.Unmarshal([]byte(ipAllow), &k.IPAllow); err != nil {
		return nil, fmt.Errorf("store: key %s ip_allow: %w", k.ID, err)
	}
	if err := json.Unmarshal([]byte(scope), &k.Scope); err != nil {
		return nil, fmt.Errorf("store: key %s scope: %w", k.ID, err)
	}
	if err := json.Unmarshal([]byte(perms), &k.Permissions); err != nil {
		return nil, fmt.Errorf("store: key %s permissions: %w", k.ID, err)
	}
	return &k, nil
}

func (k *Key) encode() (ipAllow, scope, perms []byte, err error) {
	allow := k.IPAllow
	if allow == nil {
		allow = []string{}
	}
	if ipAllow, err = json.Marshal(allow); err != nil {
		return
	}
	if scope, err = json.Marshal(k.Scope); err != nil {
		return
	}
	perms, err = json.Marshal(k.Permissions)
	return
}

func (k *Key) validate() error {
	if k.Name == "" {
		return errors.New("store: key name is required")
	}
	if !k.Kind.Valid() {
		return fmt.Errorf("store: invalid key kind %q", k.Kind)
	}
	return nil
}

// CreateKey inserts a key and its first secret atomically. Zero CreatedAt /
// UpdatedAt are filled from the store clock; empty ids are generated. The
// stored values are written back into k and first.
func (s *Store) CreateKey(ctx context.Context, k *Key, first *Secret) error {
	if err := k.validate(); err != nil {
		return err
	}
	now := s.now().UTC()
	if k.ID == "" {
		k.ID = NewKeyID()
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = now
	}
	if k.UpdatedAt.IsZero() {
		k.UpdatedAt = k.CreatedAt
	}
	ip, sc, pm, err := k.encode()
	if err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO keys (`+keyColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			k.ID, k.Name, string(k.Kind), boolInt(k.Enabled), msPtr(k.ExpiresAt), string(ip), string(sc), string(pm),
			intPtr(k.RateLimitPerMinute), k.Notes, toMs(k.CreatedAt), toMs(k.UpdatedAt), msPtr(k.LastUsedAt), msPtr(k.DeletedAt))
		if err != nil {
			return mapKeyErr(err)
		}
		if first == nil {
			return nil
		}
		first.KeyID = k.ID
		return insertSecret(ctx, tx, first, now)
	})
}

func mapKeyErr(err error) error {
	if isUnique(err) {
		if strings.Contains(err.Error(), "keys.name") || strings.Contains(err.Error(), "keys_name_active") {
			return ErrNameTaken
		}
		return ErrConflict
	}
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func intPtr(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

// GetKey returns a key by id, including soft-deleted ones (check DeletedAt).
func (s *Store) GetKey(ctx context.Context, id string) (*Key, error) {
	k, err := scanKey(s.db.QueryRowContext(ctx, `SELECT `+keyColumns+` FROM keys WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return k, err
}

// ListKeys returns keys ordered by creation time then id. Soft-deleted keys
// are included only if includeDeleted is set.
func (s *Store) ListKeys(ctx context.Context, includeDeleted bool) ([]*Key, error) {
	q := `SELECT ` + keyColumns + ` FROM keys`
	if !includeDeleted {
		q += ` WHERE deleted_at IS NULL`
	}
	q += ` ORDER BY created_at, rowid`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// CountKeys returns the number of key rows including soft-deleted ones; zero
// means a fresh database that needs bootstrapping.
func (s *Store) CountKeys(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM keys`).Scan(&n)
	return n, err
}

// UpdateKey writes the mutable fields of k (everything except id, kind,
// created_at and secrets) and bumps updated_at. Soft-deleted keys cannot be
// updated.
func (s *Store) UpdateKey(ctx context.Context, k *Key) error {
	if err := k.validate(); err != nil {
		return err
	}
	ip, sc, pm, err := k.encode()
	if err != nil {
		return err
	}
	k.UpdatedAt = s.now().UTC()
	res, err := s.db.ExecContext(ctx, `UPDATE keys SET name=?, enabled=?, expires_at=?, ip_allow=?, scope=?,
		permissions=?, rate_limit_per_minute=?, notes=?, updated_at=?
		WHERE id=? AND kind=? AND deleted_at IS NULL`,
		k.Name, boolInt(k.Enabled), msPtr(k.ExpiresAt), string(ip), string(sc), string(pm),
		intPtr(k.RateLimitPerMinute), k.Notes, toMs(k.UpdatedAt), k.ID, string(k.Kind))
	if err != nil {
		return mapKeyErr(err)
	}
	return expectOne(res)
}

// SoftDeleteKey marks a key deleted. Its secrets stop authenticating (the
// auth layer treats a deleted key as unknown) and its name becomes reusable.
func (s *Store) SoftDeleteKey(ctx context.Context, id string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE keys SET deleted_at=?, updated_at=? WHERE id=? AND deleted_at IS NULL`,
		toMs(at), toMs(at), id)
	if err != nil {
		return err
	}
	return expectOne(res)
}

// TouchKeyLastUsed records the last successful use of a key.
func (s *Store) TouchKeyLastUsed(ctx context.Context, id string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE keys SET last_used_at=? WHERE id=?`, toMs(at), id)
	if err != nil {
		return err
	}
	return expectOne(res)
}

func expectOne(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- secrets ----

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertSecret(ctx context.Context, tx execer, sec *Secret, now time.Time) error {
	if sec.ID == "" {
		sec.ID = NewSecretID()
	}
	if sec.CreatedAt.IsZero() {
		sec.CreatedAt = now
	}
	if len(sec.Hash) == 0 || sec.Prefix == "" || sec.KeyID == "" {
		return errors.New("store: secret needs key id, prefix and hash")
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO secrets (id, key_id, prefix, hash, created_at, expires_at, revoked_at)
		VALUES (?,?,?,?,?,?,?)`, sec.ID, sec.KeyID, sec.Prefix, sec.Hash, toMs(sec.CreatedAt), msPtr(sec.ExpiresAt), msPtr(sec.RevokedAt))
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// AddSecret adds a secret to an existing key (rotation).
func (s *Store) AddSecret(ctx context.Context, sec *Secret) error {
	return insertSecret(ctx, s.db, sec, s.now().UTC())
}

const secretColumns = `id, key_id, prefix, hash, created_at, expires_at, revoked_at`

func scanSecret(r rowScanner) (*Secret, error) {
	var (
		sec              Secret
		created          int64
		expires, revoked sql.NullInt64
	)
	if err := r.Scan(&sec.ID, &sec.KeyID, &sec.Prefix, &sec.Hash, &created, &expires, &revoked); err != nil {
		return nil, err
	}
	sec.CreatedAt = fromMs(created)
	sec.ExpiresAt, sec.RevokedAt = fromMsPtr(expires), fromMsPtr(revoked)
	return &sec, nil
}

// SecretByHash finds the secret with the given SHA-256 hash.
func (s *Store) SecretByHash(ctx context.Context, hash []byte) (*Secret, error) {
	sec, err := scanSecret(s.db.QueryRowContext(ctx, `SELECT `+secretColumns+` FROM secrets WHERE hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sec, err
}

// ListSecrets returns a key's secrets, oldest first.
func (s *Store) ListSecrets(ctx context.Context, keyID string) ([]*Secret, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+secretColumns+` FROM secrets WHERE key_id = ? ORDER BY created_at, rowid`, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Secret
	for rows.Next() {
		sec, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sec)
	}
	return out, rows.Err()
}

// RevokeSecret revokes a secret of the given key. Revoking twice keeps the
// first revocation time and is not an error.
func (s *Store) RevokeSecret(ctx context.Context, keyID, secretID string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE secrets SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ? AND key_id = ?`,
		toMs(at), secretID, keyID)
	if err != nil {
		return err
	}
	return expectOne(res)
}

// SetSecretExpiry sets (or with nil clears) a secret's expiry, used to open a
// rotation grace window.
func (s *Store) SetSecretExpiry(ctx context.Context, keyID, secretID string, at *time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE secrets SET expires_at = ? WHERE id = ? AND key_id = ?`,
		msPtr(at), secretID, keyID)
	if err != nil {
		return err
	}
	return expectOne(res)
}
