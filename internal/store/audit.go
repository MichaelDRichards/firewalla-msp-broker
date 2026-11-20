package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Audit outcomes (SPEC 8).
const (
	OutcomeOK            = "ok"
	OutcomeUpstreamError = "upstream_error"
	OutcomeBlocked       = "blocked"
)

// AuditEntry is one row of the audit log (SPEC 8). Zero strings and nil
// pointers are stored as NULL.
type AuditEntry struct {
	ID             int64
	TS             time.Time
	KeyID          string
	KeyNameAtTime  string
	SecretPrefix   string
	ClientIP       string
	Outcome        string
	BlockReason    string // auth, permission, out_of_scope, rate_limit, expired, ip, disabled
	Method         string
	Path           string
	Query          string
	Resource       string
	Action         string
	GID            string
	ObjectID       string
	UpstreamStatus *int
	Before         json.RawMessage // writes only
	After          json.RawMessage // writes only
	RevertOf       *int64          // set when this entry is itself a reversion
	RevertedBy     *int64          // set when a later entry reverted this one
	ResultCount    *int            // reads: objects returned after filtering
}

const auditColumns = `id, ts, key_id, key_name_at_time, secret_prefix, client_ip, outcome, block_reason,
	method, path, query, resource, action, gid, object_id, upstream_status, before_json, after_json,
	revert_of, reverted_by, result_count`

// InsertAudit appends an entry and returns its id (also set on e). A zero TS
// is filled from the store clock.
func (s *Store) InsertAudit(ctx context.Context, e *AuditEntry) (int64, error) {
	switch e.Outcome {
	case OutcomeOK, OutcomeUpstreamError, OutcomeBlocked:
	default:
		return 0, fmt.Errorf("store: invalid audit outcome %q", e.Outcome)
	}
	if e.TS.IsZero() {
		e.TS = s.now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO audit (`+strings.TrimPrefix(auditColumns, "id, ")+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		toMs(e.TS), nullStr(e.KeyID), nullStr(e.KeyNameAtTime), nullStr(e.SecretPrefix), nullStr(e.ClientIP),
		e.Outcome, nullStr(e.BlockReason), e.Method, e.Path, nullStr(e.Query), nullStr(e.Resource), nullStr(e.Action),
		nullStr(e.GID), nullStr(e.ObjectID), intPtr(e.UpstreamStatus), rawOrNil(e.Before), rawOrNil(e.After),
		int64Ptr(e.RevertOf), int64Ptr(e.RevertedBy), intPtr(e.ResultCount))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	e.ID = id
	return id, nil
}

func rawOrNil(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

func int64Ptr(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

func scanAudit(r rowScanner) (*AuditEntry, error) {
	var (
		e                                                                     AuditEntry
		ts                                                                    int64
		keyID, keyName, prefix, ip, reason, query, res, act, gid, obj, bf, af sql.NullString
		status, revertOf, revertedBy, count                                   sql.NullInt64
	)
	if err := r.Scan(&e.ID, &ts, &keyID, &keyName, &prefix, &ip, &e.Outcome, &reason, &e.Method, &e.Path,
		&query, &res, &act, &gid, &obj, &status, &bf, &af, &revertOf, &revertedBy, &count); err != nil {
		return nil, err
	}
	e.TS = fromMs(ts)
	e.KeyID, e.KeyNameAtTime, e.SecretPrefix, e.ClientIP = keyID.String, keyName.String, prefix.String, ip.String
	e.BlockReason, e.Query, e.Resource, e.Action = reason.String, query.String, res.String, act.String
	e.GID, e.ObjectID = gid.String, obj.String
	if status.Valid {
		v := int(status.Int64)
		e.UpstreamStatus = &v
	}
	if count.Valid {
		v := int(count.Int64)
		e.ResultCount = &v
	}
	if revertOf.Valid {
		v := revertOf.Int64
		e.RevertOf = &v
	}
	if revertedBy.Valid {
		v := revertedBy.Int64
		e.RevertedBy = &v
	}
	if bf.Valid {
		e.Before = json.RawMessage(bf.String)
	}
	if af.Valid {
		e.After = json.RawMessage(af.String)
	}
	return &e, nil
}

// GetAudit returns one entry.
func (s *Store) GetAudit(ctx context.Context, id int64) (*AuditEntry, error) {
	e, err := scanAudit(s.db.QueryRowContext(ctx, `SELECT `+auditColumns+` FROM audit WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

// AuditFilter selects entries for ListAudit. Zero fields do not filter.
type AuditFilter struct {
	KeyID    string
	GID      string
	Resource string
	Outcome  string
	Since    time.Time // inclusive
	Until    time.Time // exclusive
	// Cursor is the NextCursor of a previous page; only entries with a
	// smaller id are returned.
	Cursor int64
	Limit  int // default 100, max 1000
}

// Limits for ListAudit.
const (
	DefaultAuditLimit = 100
	MaxAuditLimit     = 1000
)

// ListAudit returns entries newest first. NextCursor is 0 when there are no
// more entries.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) (entries []*AuditEntry, nextCursor int64, err error) {
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultAuditLimit
	}
	if limit > MaxAuditLimit {
		limit = MaxAuditLimit
	}
	var where []string
	var args []any
	add := func(cond string, v any) { where = append(where, cond); args = append(args, v) }
	if f.KeyID != "" {
		add("key_id = ?", f.KeyID)
	}
	if f.GID != "" {
		add("gid = ?", f.GID)
	}
	if f.Resource != "" {
		add("resource = ?", f.Resource)
	}
	if f.Outcome != "" {
		add("outcome = ?", f.Outcome)
	}
	if !f.Since.IsZero() {
		add("ts >= ?", toMs(f.Since))
	}
	if !f.Until.IsZero() {
		add("ts < ?", toMs(f.Until))
	}
	if f.Cursor > 0 {
		add("id < ?", f.Cursor)
	}
	q := `SELECT ` + auditColumns + ` FROM audit`
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, " AND ")
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, 0, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(entries) > limit {
		entries = entries[:limit]
		nextCursor = entries[limit-1].ID
	}
	return entries, nextCursor, nil
}

// MarkReverted links an original entry to the entry that reverted it. It
// fails with ErrConflict if the original was already reverted and
// ErrNotFound if either entry is missing.
func (s *Store) MarkReverted(ctx context.Context, originalID, revertEntryID int64) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit WHERE id IN (?, ?)`, originalID, revertEntryID).Scan(&n); err != nil {
			return err
		}
		if want := 2; originalID == revertEntryID || n != want {
			return ErrNotFound
		}
		res, err := tx.ExecContext(ctx, `UPDATE audit SET reverted_by = ? WHERE id = ? AND reverted_by IS NULL`, revertEntryID, originalID)
		if err != nil {
			return err
		}
		if c, _ := res.RowsAffected(); c == 0 {
			return ErrConflict
		}
		return nil
	})
}
