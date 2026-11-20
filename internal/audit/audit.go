// Package audit records one row per request that reached the permission
// stage and one per blocked attempt (SPEC 8). It sits between the HTTP layer
// and the store and enforces the rules the store does not: text is scrubbed
// of secrets, lengths are bounded, and reads carry metadata only.
package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"mspbroker/internal/redact"
	"mspbroker/internal/store"
)

// Block reasons written to audit.block_reason. The first group is the
// SPEC 8 list plus kind (SPEC 6.4 step 2); the rest cover requests the broker
// refused or could not serve for reasons of its own.
const (
	ReasonAuth       = "auth"
	ReasonExpired    = "expired"
	ReasonDisabled   = "disabled"
	ReasonIP         = "ip"
	ReasonRateLimit  = "rate_limit"
	ReasonKind       = "kind"
	ReasonPermission = "permission"
	ReasonOutOfScope = "out_of_scope"

	// ReasonUnmodelled: the path or method is not modelled (default deny).
	ReasonUnmodelled = "unmodelled"
	// ReasonBadRequest: the request is malformed; nothing was sent upstream.
	ReasonBadRequest = "bad_request"
	// ReasonNotFound: a broker-side lookup (key, audit entry) found nothing.
	ReasonNotFound = "not_found"
	// ReasonConflict: the request conflicts with current state (name taken).
	ReasonConflict = "conflict"
	// ReasonInternal: the broker failed while serving the request.
	ReasonInternal = "internal"
)

// Field limits. Longer values are truncated, never rejected: a hostile
// client must not be able to make its own audit row fail to write.
const (
	maxPath  = 2048
	maxQuery = 4096
	maxShort = 256
)

// ErrBodyOnRead is returned when a read entry carries before/after bodies.
var ErrBodyOnRead = errors.New("audit: reads must not carry before/after bodies")

// Inserter is the part of the store the recorder needs.
type Inserter interface {
	InsertAudit(ctx context.Context, e *store.AuditEntry) (int64, error)
}

// Recorder writes audit entries.
type Recorder struct {
	st    Inserter
	scrub *redact.Scrubber
	log   *slog.Logger
}

// New returns a Recorder. scrub may be nil (broker secrets are still scrubbed);
// log may be nil.
func New(st Inserter, scrub *redact.Scrubber, log *slog.Logger) *Recorder {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Recorder{st: st, scrub: scrub, log: log}
}

// Record validates, scrubs and stores e, setting e.ID. Reads (Action "read"
// or "list") may not carry Before or After. Blocked entries need a reason and
// other outcomes must not have one.
func (r *Recorder) Record(ctx context.Context, e *store.AuditEntry) error {
	switch {
	case e.Outcome == store.OutcomeBlocked && e.BlockReason == "":
		return errors.New("audit: blocked entry needs a reason")
	case e.Outcome != store.OutcomeBlocked && e.BlockReason != "":
		return fmt.Errorf("audit: %s entry must not have a block reason", e.Outcome)
	}
	if (e.Action == "read" || e.Action == "list") && (len(e.Before) > 0 || len(e.After) > 0) {
		return ErrBodyOnRead
	}

	c := *e // never mutate what the caller still holds
	c.KeyNameAtTime = r.text(c.KeyNameAtTime, maxShort)
	c.Method = r.text(c.Method, 16)
	c.Path = r.text(c.Path, maxPath)
	c.Query = r.text(c.Query, maxQuery)
	c.Resource = r.text(c.Resource, maxShort)
	c.Action = r.text(c.Action, maxShort)
	c.GID = strings.ToLower(r.text(c.GID, maxShort))
	c.ObjectID = r.text(c.ObjectID, maxShort)
	c.ClientIP = r.text(c.ClientIP, 64)
	c.SecretPrefix = r.text(c.SecretPrefix, 16)
	c.Before = r.scrub.Bytes(c.Before)
	c.After = r.scrub.Bytes(c.After)

	id, err := r.st.InsertAudit(ctx, &c)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	e.ID, e.TS = id, c.TS
	return nil
}

func (r *Recorder) text(s string, max int) string {
	s = r.scrub.String(s)
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "") + "..."
	}
	return s
}
