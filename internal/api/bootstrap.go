package api

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"mspbroker/internal/acl"
	"mspbroker/internal/auth"
	"mspbroker/internal/store"
)

// BootstrapKeyName is the name of the admin key created on first start.
const BootstrapKeyName = "bootstrap"

// BootstrapSecretFileName is written under DATA_DIR when the secret goes to
// a file instead of the log.
const BootstrapSecretFileName = "bootstrap-admin-secret"

// Bootstrap creates the first admin key when the database holds no keys at
// all (SPEC 10). The secret is delivered exactly once: written to
// dataDir/bootstrap-admin-secret with mode 0600 when toFile is set, otherwise
// logged through secretLog. secretLog is deliberately separate from the
// server's scrubbing logger, which would (rightly) erase the secret; it must
// not be used for anything else. A database that has ever held a key,
// including a soft-deleted one, is never bootstrapped again.
func Bootstrap(ctx context.Context, st *store.Store, now time.Time, dataDir string, toFile bool, secretLog *slog.Logger) (created bool, err error) {
	n, err := st.CountKeys(ctx)
	if err != nil {
		return false, fmt.Errorf("bootstrap: %w", err)
	}
	if n > 0 {
		return false, nil
	}
	full, sec, err := auth.NewSecret("", now, nil)
	if err != nil {
		return false, fmt.Errorf("bootstrap: %w", err)
	}
	k := &store.Key{
		Name: BootstrapKeyName, Kind: acl.KindAdmin, Enabled: true,
		Notes: "created on first start; create a named admin key and revoke this one",
	}
	if err := st.CreateKey(ctx, k, sec); err != nil {
		return false, fmt.Errorf("bootstrap: %w", err)
	}
	// Record the creation. The row has no key (the system acted) and no
	// secret material.
	_, err = st.InsertAudit(ctx, &store.AuditEntry{
		Outcome: store.OutcomeOK, Method: "SYSTEM", Path: "bootstrap", Resource: "keys", Action: "create",
		ObjectID: k.ID, KeyNameAtTime: "system", After: snapshot(k),
	})
	if err != nil {
		return true, fmt.Errorf("bootstrap: audit: %w", err)
	}

	if toFile {
		path := filepath.Join(dataDir, BootstrapSecretFileName)
		if err := writeSecretFile(path, full+"\n"); err != nil {
			return true, fmt.Errorf("bootstrap: writing secret file: %w", err)
		}
		secretLog.Warn("bootstrap admin key created; secret written to file (mode 0600), read it once and delete it",
			"key_name", k.Name, "key_id", k.ID, "file", path)
		return true, nil
	}
	secretLog.Warn("bootstrap admin key created; this secret is shown once and cannot be recovered",
		"key_name", k.Name, "key_id", k.ID, "secret", full)
	return true, nil
}

func writeSecretFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil { // the file may have existed with other modes
		f.Close()
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
