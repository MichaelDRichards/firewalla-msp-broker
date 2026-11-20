package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mspbroker/internal/api"
	"mspbroker/internal/store"
)

// secretSink captures the bootstrap log, which is separate from the server
// log precisely because it is the one place a secret is printed.
func secretSink() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, nil)), &buf
}

func loggedSecret(t *testing.T, buf *bytes.Buffer) string {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("bootstrap log: %v: %s", err, buf)
	}
	s, _ := rec["secret"].(string)
	return s
}

func TestBootstrapPrintsSecretOnceToTheLog(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	log, buf := secretSink()

	created, err := api.Bootstrap(ctx, h.st, h.clk.now(), t.TempDir(), false, log)
	if err != nil || !created {
		t.Fatalf("bootstrap: %v %v", created, err)
	}
	secret := loggedSecret(t, buf)
	if !strings.HasPrefix(secret, "mb_") || strings.Count(buf.String(), secret) != 1 {
		t.Fatalf("log: %s", buf)
	}

	keys, _ := h.st.ListKeys(ctx, false)
	if len(keys) != 1 || keys[0].Name != "bootstrap" || keys[0].Kind != "admin" || !keys[0].Enabled || keys[0].ExpiresAt != nil {
		t.Fatalf("keys: %+v", keys)
	}

	// The secret works as an admin credential and reaches no data.
	if r := h.get(secret, "/admin/v1/keys"); r.status != 200 {
		t.Fatalf("bootstrap admin: %d %s", r.status, r.body)
	}
	if r := h.get(secret, "/api/v1/boxes"); r.status != 403 || r.errCode(t) != "kind" {
		t.Errorf("bootstrap on data: %d %s", r.status, r.body)
	}

	// The documented first step: create a named admin key and revoke bootstrap.
	r := h.do(secret, "POST", "/admin/v1/keys", j(kv{"name": "ops-admin", "kind": "admin"}))
	if r.status != 201 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	if r := h.do(secret, "PATCH", "/admin/v1/keys/"+keys[0].ID, j(kv{"enabled": false})); r.status != 200 {
		t.Fatalf("disable bootstrap: %d", r.status)
	}
	if r := h.get(secret, "/admin/v1/keys"); r.status != 403 || r.errCode(t) != "disabled" {
		t.Errorf("disabled bootstrap key: %d %s", r.status, r.body)
	}

	// Restart: the database has keys, nothing is created, nothing is printed.
	log2, buf2 := secretSink()
	created, err = api.Bootstrap(ctx, h.st, h.clk.now(), t.TempDir(), false, log2)
	if err != nil || created || buf2.Len() != 0 {
		t.Errorf("second start: created=%v err=%v log=%s", created, err, buf2)
	}
	if n, _ := h.st.CountKeys(ctx); n != 2 {
		t.Errorf("%d keys after restart", n)
	}

	// The secret is in neither the database nor the server's logs, and the
	// creation is audited without it.
	h.dumpContains(t, secret, false)
	h.dumpContains(t, secret[3:], false)
	if strings.Contains(h.logs.String(), secret) {
		t.Error("server log contains the bootstrap secret")
	}
	var boot *store.AuditEntry
	for _, e := range h.auditRows() {
		if e.Method == "SYSTEM" {
			boot = e
		}
	}
	if boot == nil || boot.Resource != "keys" || boot.Action != "create" || boot.ObjectID != keys[0].ID {
		t.Errorf("bootstrap audit row: %+v", boot)
	}
}

func TestBootstrapSecretFile(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, api.BootstrapSecretFileName)
	// A stale, world-readable file from an earlier install must not survive.
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	log, buf := secretSink()
	created, err := api.Bootstrap(ctx, h.st, h.clk.now(), dir, true, log)
	if err != nil || !created {
		t.Fatalf("%v %v", created, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	secret := strings.TrimSpace(string(b))
	if !strings.HasPrefix(secret, "mb_") || len(secret) != 46 || strings.Contains(string(b), "stale") {
		t.Fatalf("file content: %q", b)
	}
	if strings.Contains(buf.String(), secret) || strings.Contains(buf.String(), secret[3:]) {
		t.Errorf("secret also written to the log: %s", buf)
	}
	if !strings.Contains(buf.String(), path) {
		t.Errorf("log does not say where the secret is: %s", buf)
	}
	if r := h.get(secret, "/admin/v1/keys"); r.status != 200 {
		t.Errorf("secret from file: %d", r.status)
	}
	h.dumpContains(t, secret, false)

	// An unwritable directory is an error, not a silent loss of the secret.
	h2 := newHarness(t)
	if _, err := api.Bootstrap(ctx, h2.st, h2.clk.now(), filepath.Join(dir, "missing", "dir"), true, log); err == nil {
		t.Error("bootstrap succeeded without a place to put the secret")
	}
}

// A database whose only key was soft-deleted is not empty: bootstrap must
// not mint a new admin key behind the operator's back.
func TestBootstrapNeverRunsOnUsedDatabase(t *testing.T) {
	h := newHarness(t)
	k, _ := h.adminKey("only")
	if err := h.st.SoftDeleteKey(context.Background(), k.ID, h.clk.now()); err != nil {
		t.Fatal(err)
	}
	log, buf := secretSink()
	created, err := api.Bootstrap(context.Background(), h.st, h.clk.now(), t.TempDir(), false, log)
	if err != nil || created || buf.Len() != 0 {
		t.Errorf("created=%v err=%v log=%s", created, err, buf)
	}
}
