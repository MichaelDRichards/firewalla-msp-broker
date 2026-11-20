package store

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	"mspbroker/internal/acl"
)

// CachedBox is a box as last seen upstream.
type CachedBox struct {
	GID     string
	Name    string
	GroupID string
}

const metaBoxesFetched = "box_cache_fetched_at"

// ReplaceBoxes atomically replaces the cached box list and records when it
// was fetched. An empty list is valid (an account with no boxes).
func (s *Store) ReplaceBoxes(ctx context.Context, boxes []CachedBox, fetchedAt time.Time) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM box_cache`); err != nil {
			return err
		}
		for _, b := range boxes {
			if _, err := tx.ExecContext(ctx, `INSERT INTO box_cache (gid, name, group_id) VALUES (?,?,?)
				ON CONFLICT(gid) DO UPDATE SET name=excluded.name, group_id=excluded.group_id`,
				b.GID, b.Name, b.GroupID); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`, metaBoxesFetched, strconv.FormatInt(toMs(fetchedAt), 10))
		return err
	})
}

// LoadBoxes returns the cached boxes ordered by gid and when they were
// fetched. The time is zero if the cache has never been filled.
func (s *Store) LoadBoxes(ctx context.Context) ([]CachedBox, time.Time, error) {
	var fetched time.Time
	var v string
	switch err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, metaBoxesFetched).Scan(&v); err {
	case nil:
		n, perr := strconv.ParseInt(v, 10, 64)
		if perr != nil {
			return nil, time.Time{}, perr
		}
		fetched = fromMs(n)
	case sql.ErrNoRows:
	default:
		return nil, time.Time{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT gid, name, group_id FROM box_cache ORDER BY gid`)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer rows.Close()
	var out []CachedBox
	for rows.Next() {
		var b CachedBox
		if err := rows.Scan(&b.GID, &b.Name, &b.GroupID); err != nil {
			return nil, time.Time{}, err
		}
		out = append(out, b)
	}
	return out, fetched, rows.Err()
}

// ACLBoxes converts cached boxes to the form acl.Resolve takes.
func ACLBoxes(in []CachedBox) []acl.Box {
	out := make([]acl.Box, len(in))
	for i, b := range in {
		out[i] = acl.Box{GID: b.GID, GroupID: b.GroupID}
	}
	return out
}
