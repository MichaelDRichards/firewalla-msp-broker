package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"mspbroker/internal/acl"
)

const (
	gidA = "00000000-0000-0000-0000-000000000001"
	gidB = "00000000-0000-0000-0000-000000000002"
	gidC = "00000000-0000-0000-0000-000000000003"
)

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mspbroker.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func sampleKey(name string) *Key {
	return &Key{
		Name:    name,
		Kind:    acl.KindData,
		Enabled: true,
		IPAllow: []string{"192.0.2.0/24", "198.51.100.7"},
		Scope:   acl.Scope{Type: acl.ScopeBoxesGroups, GIDs: []string{gidA}, GroupIDs: []string{"group-a"}},
		Permissions: acl.Permissions{
			Boxes: acl.Read, Rules: acl.Write, Alarms: acl.Read, GlobalTargetLists: acl.Read,
		},
		Notes: "fixture",
	}
}

var hashN byte

func sampleSecret() *Secret {
	hashN++
	h := make([]byte, 32)
	h[0] = hashN
	return &Secret{Prefix: fmt.Sprintf("pref%04d", hashN), Hash: h}
}

func TestOpenMigratesAndReopens(t *testing.T) {
	ctx := context.Background()
	s, path := openTemp(t)
	v, err := s.SchemaVersion(ctx)
	if err != nil || v != 1 {
		t.Fatalf("schema version %d, %v", v, err)
	}
	k := sampleKey("persist")
	if err := s.CreateKey(ctx, k, sampleSecret()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if v, _ := s2.SchemaVersion(ctx); v != 1 {
		t.Errorf("version after reopen %d", v)
	}
	got, err := s2.GetKey(ctx, k.ID)
	if err != nil || got.Name != "persist" {
		t.Errorf("key lost across reopen: %v %v", got, err)
	}
	if err := s2.Ping(ctx); err != nil {
		t.Error(err)
	}
}

func TestOpenRefusesNewerSchema(t *testing.T) {
	ctx := context.Background()
	s, path := openTemp(t)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (99, 'future', 0)`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(ctx, path); err == nil {
		t.Fatal("opened a database from the future")
	}
}

func TestOpenBadPath(t *testing.T) {
	if _, err := Open(context.Background(), filepath.Join(t.TempDir(), "missing", "dir", "x.db")); err == nil {
		t.Fatal("expected error for unwritable path")
	}
}

func TestMigrationsAreAtomicAndOrdered(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	bad := []migration{{version: 2, name: "002_bad.sql", sql: `CREATE TABLE ok_table (x INTEGER); THIS IS NOT SQL;`}}
	if err := s.applyMigrations(ctx, append(mustLoad(t), bad...)); err == nil {
		t.Fatal("bad migration applied")
	}
	if v, _ := s.SchemaVersion(ctx); v != 1 {
		t.Errorf("version moved to %d after failed migration", v)
	}
	if _, err := s.db.ExecContext(ctx, `SELECT x FROM ok_table`); err == nil {
		t.Error("partial migration left a table behind")
	}
	good := []migration{{version: 2, name: "002_ok.sql", sql: `CREATE TABLE later (x INTEGER);`}}
	if err := s.applyMigrations(ctx, append(mustLoad(t), good...)); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.SchemaVersion(ctx); v != 2 {
		t.Errorf("version %d", v)
	}
	// Re-applying is a no-op.
	if err := s.applyMigrations(ctx, append(mustLoad(t), good...)); err != nil {
		t.Fatal(err)
	}
}

func mustLoad(t *testing.T) []migration {
	t.Helper()
	ms, err := loadMigrations()
	if err != nil || len(ms) == 0 {
		t.Fatalf("loadMigrations: %v", err)
	}
	return ms
}

func TestKeyRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	s.SetClock(func() time.Time { return t0 })
	exp := t0.Add(48 * time.Hour)
	rate := 30
	k := sampleKey("round-trip")
	k.ExpiresAt = &exp
	k.RateLimitPerMinute = &rate
	sec := sampleSecret()
	if err := s.CreateKey(ctx, k, sec); err != nil {
		t.Fatal(err)
	}
	if k.ID == "" || k.ID[:2] != "k_" || sec.ID == "" || sec.ID[:2] != "s_" || sec.KeyID != k.ID {
		t.Errorf("ids not assigned: %q %q %q", k.ID, sec.ID, sec.KeyID)
	}
	got, err := s.GetKey(ctx, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != k.Name || got.Kind != acl.KindData || !got.Enabled || got.Notes != "fixture" {
		t.Errorf("basic fields: %+v", got)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) || got.RateLimitPerMinute == nil || *got.RateLimitPerMinute != 30 {
		t.Errorf("expiry/rate: %+v", got)
	}
	if !got.CreatedAt.Equal(t0) || !got.UpdatedAt.Equal(t0) || got.LastUsedAt != nil || got.DeletedAt != nil {
		t.Errorf("times: %+v", got)
	}
	gj, _ := json.Marshal(got.Scope)
	kj, _ := json.Marshal(k.Scope)
	if string(gj) != string(kj) || got.Permissions != k.Permissions || len(got.IPAllow) != 2 || got.IPAllow[1] != "198.51.100.7" {
		t.Errorf("scope/permissions/ip_allow: %+v", got)
	}

	// Defaults: nil expiry, nil rate, nil ip_allow.
	d := &Key{Name: "defaults", Kind: acl.KindAdmin, Enabled: false, Scope: acl.Scope{Type: acl.ScopeAll}}
	if err := s.CreateKey(ctx, d, nil); err != nil {
		t.Fatal(err)
	}
	gd, _ := s.GetKey(ctx, d.ID)
	if gd.ExpiresAt != nil || gd.RateLimitPerMinute != nil || gd.Enabled || gd.IPAllow == nil || len(gd.IPAllow) != 0 || gd.Kind != acl.KindAdmin {
		t.Errorf("defaults: %+v", gd)
	}
	// Zero rate limit (unlimited) is distinct from nil.
	zero := 0
	z := sampleKey("zero-rate")
	z.RateLimitPerMinute = &zero
	if err := s.CreateKey(ctx, z, nil); err != nil {
		t.Fatal(err)
	}
	if gz, _ := s.GetKey(ctx, z.ID); gz.RateLimitPerMinute == nil || *gz.RateLimitPerMinute != 0 {
		t.Errorf("zero rate lost: %+v", gz)
	}
}

func TestKeyValidationAndNotFound(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if err := s.CreateKey(ctx, &Key{Kind: acl.KindData}, nil); err == nil {
		t.Error("nameless key accepted")
	}
	if err := s.CreateKey(ctx, &Key{Name: "x", Kind: "root"}, nil); err == nil {
		t.Error("bad kind accepted")
	}
	if _, err := s.GetKey(ctx, "k_nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetKey: %v", err)
	}
	if err := s.UpdateKey(ctx, &Key{ID: "k_nope", Name: "x", Kind: acl.KindData}); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateKey: %v", err)
	}
	if err := s.SoftDeleteKey(ctx, "k_nope", t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("SoftDeleteKey: %v", err)
	}
	if err := s.TouchKeyLastUsed(ctx, "k_nope", t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("Touch: %v", err)
	}
	if n, err := s.CountKeys(ctx); err != nil || n != 0 {
		t.Errorf("CountKeys %d %v", n, err)
	}
}

func TestKeyNamesUniqueAmongActive(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	a := sampleKey("agent")
	if err := s.CreateKey(ctx, a, sampleSecret()); err != nil {
		t.Fatal(err)
	}
	dupSecret := sampleSecret()
	if err := s.CreateKey(ctx, sampleKey("agent"), dupSecret); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}
	// The failed create must not leave its secret behind.
	if _, err := s.SecretByHash(ctx, dupSecret.Hash); !errors.Is(err, ErrNotFound) {
		t.Errorf("secret of failed create persisted: %v", err)
	}
	// Rename into a taken name fails; free name works.
	b := sampleKey("other")
	if err := s.CreateKey(ctx, b, nil); err != nil {
		t.Fatal(err)
	}
	b.Name = "agent"
	if err := s.UpdateKey(ctx, b); !errors.Is(err, ErrNameTaken) {
		t.Errorf("rename into taken name: %v", err)
	}
	// After soft delete the name is reusable, and deleted keys stay readable.
	if err := s.SoftDeleteKey(ctx, a.ID, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateKey(ctx, sampleKey("agent"), nil); err != nil {
		t.Errorf("reuse after delete: %v", err)
	}
	gone, err := s.GetKey(ctx, a.ID)
	if err != nil || gone.DeletedAt == nil {
		t.Errorf("deleted key: %+v %v", gone, err)
	}
	// Deleting twice, or updating a deleted key, is not found.
	if err := s.SoftDeleteKey(ctx, a.ID, t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("double delete: %v", err)
	}
	if err := s.UpdateKey(ctx, gone); !errors.Is(err, ErrNotFound) {
		t.Errorf("update deleted: %v", err)
	}
}

func TestUpdateKeyKeepsKindAndSecrets(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	clock := t0
	s.SetClock(func() time.Time { return clock })
	k := sampleKey("editable")
	sec := sampleSecret()
	if err := s.CreateKey(ctx, k, sec); err != nil {
		t.Fatal(err)
	}
	clock = t0.Add(time.Hour)
	k.Name = "renamed"
	k.Enabled = false
	k.Scope = acl.Scope{Type: acl.ScopeAll}
	k.Permissions = acl.Permissions{Flows: acl.Read}
	k.IPAllow = nil
	k.Notes = "changed"
	if err := s.UpdateKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetKey(ctx, k.ID)
	if got.Name != "renamed" || got.Enabled || got.Scope.Type != acl.ScopeAll || got.Permissions.Flows != acl.Read ||
		got.Permissions.Rules != acl.None || len(got.IPAllow) != 0 || got.Notes != "changed" {
		t.Errorf("update not applied: %+v", got)
	}
	if !got.CreatedAt.Equal(t0) || !got.UpdatedAt.Equal(clock) {
		t.Errorf("times: created %v updated %v", got.CreatedAt, got.UpdatedAt)
	}
	// Kind cannot change through UpdateKey.
	k.Kind = acl.KindAdmin
	if err := s.UpdateKey(ctx, k); !errors.Is(err, ErrNotFound) {
		t.Errorf("kind change: %v", err)
	}
	if again, _ := s.GetKey(ctx, k.ID); again.Kind != acl.KindData {
		t.Error("kind changed")
	}
	// The secret is untouched by editing the key.
	if _, err := s.SecretByHash(ctx, sec.Hash); err != nil {
		t.Errorf("secret lost on key edit: %v", err)
	}
}

func TestListKeysAndCount(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	clock := t0
	s.SetClock(func() time.Time { clock = clock.Add(time.Second); return clock })
	var ids []string
	for _, n := range []string{"one", "two", "three"} {
		k := sampleKey(n)
		if err := s.CreateKey(ctx, k, nil); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, k.ID)
	}
	if err := s.SoftDeleteKey(ctx, ids[1], t0); err != nil {
		t.Fatal(err)
	}
	active, err := s.ListKeys(ctx, false)
	if err != nil || len(active) != 2 || active[0].Name != "one" || active[1].Name != "three" {
		t.Errorf("active: %v %v", active, err)
	}
	all, _ := s.ListKeys(ctx, true)
	if len(all) != 3 {
		t.Errorf("all: %d", len(all))
	}
	if n, _ := s.CountKeys(ctx); n != 3 {
		t.Errorf("count includes deleted keys, got %d", n)
	}
	at := t0.Add(time.Minute)
	if err := s.TouchKeyLastUsed(ctx, ids[0], at); err != nil {
		t.Fatal(err)
	}
	if k, _ := s.GetKey(ctx, ids[0]); k.LastUsedAt == nil || !k.LastUsedAt.Equal(at) {
		t.Errorf("last used: %+v", k)
	}
}

func TestSecrets(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	k, other := sampleKey("owner"), sampleKey("other")
	first := sampleSecret()
	if err := s.CreateKey(ctx, k, first); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateKey(ctx, other, nil); err != nil {
		t.Fatal(err)
	}

	got, err := s.SecretByHash(ctx, first.Hash)
	if err != nil || got.KeyID != k.ID || got.Prefix != first.Prefix || got.RevokedAt != nil || got.ExpiresAt != nil {
		t.Fatalf("lookup: %+v %v", got, err)
	}
	if _, err := s.SecretByHash(ctx, make([]byte, 32)); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown hash: %v", err)
	}

	// Rotation: a second secret, old one gets an expiry.
	second := sampleSecret()
	second.KeyID = k.ID
	if err := s.AddSecret(ctx, second); err != nil {
		t.Fatal(err)
	}
	grace := t0.Add(72 * time.Hour)
	if err := s.SetSecretExpiry(ctx, k.ID, first.ID, &grace); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListSecrets(ctx, k.ID)
	if len(list) != 2 || list[0].ID != first.ID || list[0].ExpiresAt == nil || !list[0].ExpiresAt.Equal(grace) || list[1].ExpiresAt != nil {
		t.Errorf("list: %+v", list)
	}
	if err := s.SetSecretExpiry(ctx, k.ID, first.ID, nil); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.SecretByHash(ctx, first.Hash); g.ExpiresAt != nil {
		t.Error("expiry not cleared")
	}

	// Revoke keeps the first revocation time and is scoped to the key.
	r1, r2 := t0.Add(time.Hour), t0.Add(2*time.Hour)
	if err := s.RevokeSecret(ctx, k.ID, first.ID, r1); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSecret(ctx, k.ID, first.ID, r2); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.SecretByHash(ctx, first.Hash); g.RevokedAt == nil || !g.RevokedAt.Equal(r1) {
		t.Errorf("revoked_at: %+v", g.RevokedAt)
	}
	if err := s.RevokeSecret(ctx, other.ID, second.ID, r1); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking another key's secret: %v", err)
	}
	if err := s.SetSecretExpiry(ctx, other.ID, second.ID, &grace); !errors.Is(err, ErrNotFound) {
		t.Errorf("expiring another key's secret: %v", err)
	}
	if g, _ := s.SecretByHash(ctx, second.Hash); g.RevokedAt != nil || g.ExpiresAt != nil {
		t.Error("another key's call modified the secret")
	}
}

func TestSecretConstraints(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	k := sampleKey("owner")
	first := sampleSecret()
	if err := s.CreateKey(ctx, k, first); err != nil {
		t.Fatal(err)
	}
	dup := &Secret{KeyID: k.ID, Prefix: "dupdupdu", Hash: first.Hash}
	if err := s.AddSecret(ctx, dup); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate hash: %v", err)
	}
	if err := s.AddSecret(ctx, &Secret{KeyID: "k_missing", Prefix: "abcdefgh", Hash: []byte{9, 9, 9}}); err == nil {
		t.Error("secret for unknown key accepted (foreign key not enforced)")
	}
	for _, bad := range []*Secret{{KeyID: k.ID, Prefix: "", Hash: []byte{1}}, {KeyID: k.ID, Prefix: "abcdefgh"}, {Prefix: "abcdefgh", Hash: []byte{1}}} {
		if err := s.AddSecret(ctx, bad); err == nil {
			t.Errorf("incomplete secret accepted: %+v", bad)
		}
	}
}

func TestAuditRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	s.SetClock(func() time.Time { return t0 })
	status, count := 200, 3
	e := &AuditEntry{
		KeyID: "k_abc", KeyNameAtTime: "agent", SecretPrefix: "abcd1234", ClientIP: "192.0.2.10",
		Outcome: OutcomeOK, Method: "GET", Path: "/api/v1/rules", Query: "limit=5",
		Resource: "rules", Action: "list", GID: gidA, ObjectID: "rule-1",
		UpstreamStatus: &status, ResultCount: &count,
		Before: json.RawMessage(`{"paused":false}`), After: json.RawMessage(`{"paused":true}`),
	}
	id, err := s.InsertAudit(ctx, e)
	if err != nil || id == 0 || e.ID != id || !e.TS.Equal(t0) {
		t.Fatalf("insert: %d %v %+v", id, err, e)
	}
	got, err := s.GetAudit(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyID != "k_abc" || got.KeyNameAtTime != "agent" || got.SecretPrefix != "abcd1234" || got.ClientIP != "192.0.2.10" ||
		got.Outcome != OutcomeOK || got.Method != "GET" || got.Path != "/api/v1/rules" || got.Query != "limit=5" ||
		got.Resource != "rules" || got.Action != "list" || got.GID != gidA || got.ObjectID != "rule-1" ||
		*got.UpstreamStatus != 200 || *got.ResultCount != 3 || !got.TS.Equal(t0) ||
		string(got.Before) != `{"paused":false}` || string(got.After) != `{"paused":true}` ||
		got.RevertOf != nil || got.RevertedBy != nil || got.BlockReason != "" {
		t.Errorf("round trip mismatch: %+v", got)
	}

	// A blocked attempt with an unknown secret has no key at all.
	b := &AuditEntry{Outcome: OutcomeBlocked, BlockReason: "auth", ClientIP: "203.0.113.9", Method: "GET", Path: "/api/v1/me"}
	if _, err := s.InsertAudit(ctx, b); err != nil {
		t.Fatal(err)
	}
	gb, _ := s.GetAudit(ctx, b.ID)
	if gb.KeyID != "" || gb.BlockReason != "auth" || gb.Before != nil || gb.UpstreamStatus != nil || gb.ResultCount != nil {
		t.Errorf("blocked: %+v", gb)
	}

	if _, err := s.InsertAudit(ctx, &AuditEntry{Outcome: "weird"}); err == nil {
		t.Error("invalid outcome accepted")
	}
	if _, err := s.GetAudit(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing audit: %v", err)
	}
}

func TestAuditListFilterAndPaging(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	for i := 0; i < 25; i++ {
		e := &AuditEntry{
			TS: t0.Add(time.Duration(i) * time.Minute), KeyID: fmt.Sprintf("k_%d", i%2), Outcome: OutcomeOK,
			Method: "GET", Path: "/x", Resource: []string{"rules", "alarms", "flows"}[i%3], GID: []string{gidA, gidB}[i%2],
		}
		if i%5 == 0 {
			e.Outcome = OutcomeBlocked
			e.BlockReason = "out_of_scope"
		}
		if _, err := s.InsertAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	// Paging walks every row exactly once, newest first.
	var seen []int64
	cursor := int64(0)
	for pages := 0; pages < 10; pages++ {
		es, next, err := s.ListAudit(ctx, AuditFilter{Limit: 10, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			seen = append(seen, e.ID)
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	if len(seen) != 25 {
		t.Fatalf("paged %d rows", len(seen))
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] >= seen[i-1] {
			t.Fatalf("not strictly descending at %d: %v", i, seen)
		}
	}
	// Exactly one page: no cursor.
	if es, next, _ := s.ListAudit(ctx, AuditFilter{Limit: 25}); len(es) != 25 || next != 0 {
		t.Errorf("full page: %d next %d", len(es), next)
	}

	count := func(f AuditFilter) int {
		f.Limit = 1000
		es, _, err := s.ListAudit(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		return len(es)
	}
	if n := count(AuditFilter{KeyID: "k_0"}); n != 13 {
		t.Errorf("key filter: %d", n)
	}
	if n := count(AuditFilter{GID: gidB}); n != 12 {
		t.Errorf("gid filter: %d", n)
	}
	if n := count(AuditFilter{Resource: "flows"}); n != 8 {
		t.Errorf("resource filter: %d", n)
	}
	if n := count(AuditFilter{Outcome: OutcomeBlocked}); n != 5 {
		t.Errorf("outcome filter: %d", n)
	}
	if n := count(AuditFilter{Since: t0.Add(10 * time.Minute), Until: t0.Add(20 * time.Minute)}); n != 10 {
		t.Errorf("time window (since inclusive, until exclusive): %d", n)
	}
	if n := count(AuditFilter{KeyID: "k_0", Outcome: OutcomeBlocked, Resource: "rules"}); n != 1 {
		t.Errorf("combined filter: %d", n)
	}
	if es, _, _ := s.ListAudit(ctx, AuditFilter{}); len(es) != 25 {
		t.Errorf("default limit should cover 25 rows, got %d", len(es))
	}
	if es, _, _ := s.ListAudit(ctx, AuditFilter{Limit: 5000}); len(es) != 25 {
		t.Errorf("clamped limit: %d", len(es))
	}
}

func TestMarkReverted(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	mk := func() int64 {
		e := &AuditEntry{Outcome: OutcomeOK, Method: "POST", Path: "/x"}
		id, err := s.InsertAudit(ctx, e)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	orig, rev := mk(), mk()
	// The reverting entry points back with revert_of.
	re := &AuditEntry{Outcome: OutcomeOK, Method: "POST", Path: "/x", RevertOf: &orig}
	revID, err := s.InsertAudit(ctx, re)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkReverted(ctx, orig, revID); err != nil {
		t.Fatal(err)
	}
	g, _ := s.GetAudit(ctx, orig)
	if g.RevertedBy == nil || *g.RevertedBy != revID {
		t.Errorf("reverted_by: %+v", g.RevertedBy)
	}
	if gr, _ := s.GetAudit(ctx, revID); gr.RevertOf == nil || *gr.RevertOf != orig {
		t.Errorf("revert_of: %+v", gr.RevertOf)
	}
	if err := s.MarkReverted(ctx, orig, rev); !errors.Is(err, ErrConflict) {
		t.Errorf("second revert: %v", err)
	}
	if err := s.MarkReverted(ctx, 9999, rev); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing original: %v", err)
	}
	if err := s.MarkReverted(ctx, rev, 9999); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing reverter: %v", err)
	}
	if err := s.MarkReverted(ctx, rev, rev); !errors.Is(err, ErrNotFound) {
		t.Errorf("self revert: %v", err)
	}
	bogus := int64(424242)
	if _, err := s.InsertAudit(ctx, &AuditEntry{Outcome: OutcomeOK, RevertOf: &bogus}); err == nil {
		t.Error("revert_of to a missing entry accepted")
	}
}

func TestBoxCache(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	boxes, at, err := s.LoadBoxes(ctx)
	if err != nil || len(boxes) != 0 || !at.IsZero() {
		t.Fatalf("empty cache: %v %v %v", boxes, at, err)
	}
	if err := s.ReplaceBoxes(ctx, []CachedBox{{gidB, "Box B", "group-a"}, {gidA, "Box A", ""}, {gidC, "Box C", "group-b"}}, t0); err != nil {
		t.Fatal(err)
	}
	boxes, at, _ = s.LoadBoxes(ctx)
	if len(boxes) != 3 || boxes[0].GID != gidA || boxes[1].GroupID != "group-a" || !at.Equal(t0) {
		t.Errorf("after fill: %+v %v", boxes, at)
	}
	// Replacement drops boxes that vanished and tolerates duplicates.
	t1 := t0.Add(time.Minute)
	if err := s.ReplaceBoxes(ctx, []CachedBox{{gidA, "Box A2", "group-b"}, {gidA, "Box A3", "group-b"}}, t1); err != nil {
		t.Fatal(err)
	}
	boxes, at, _ = s.LoadBoxes(ctx)
	if len(boxes) != 1 || boxes[0].Name != "Box A3" || !at.Equal(t1) {
		t.Errorf("after replace: %+v %v", boxes, at)
	}
	// An empty list is a real answer, and remembers when it was fetched.
	t2 := t1.Add(time.Minute)
	if err := s.ReplaceBoxes(ctx, nil, t2); err != nil {
		t.Fatal(err)
	}
	boxes, at, _ = s.LoadBoxes(ctx)
	if len(boxes) != 0 || !at.Equal(t2) {
		t.Errorf("after empty replace: %+v %v", boxes, at)
	}
	// Feeds acl directly.
	_ = s.ReplaceBoxes(ctx, []CachedBox{{gidA, "A", "group-a"}}, t2)
	boxes, _, _ = s.LoadBoxes(ctx)
	e := acl.Resolve(acl.Scope{Type: acl.ScopeGroups, GroupIDs: []string{"group-a"}}, ACLBoxes(boxes))
	if !e.Contains(gidA) || e.Contains(gidB) {
		t.Error("ACLBoxes conversion wrong")
	}
}

func TestConcurrentWritesDoNotBusy(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	k := sampleKey("busy")
	if err := s.CreateKey(ctx, k, nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if _, err := s.InsertAudit(ctx, &AuditEntry{KeyID: k.ID, Outcome: OutcomeOK, Method: "GET", Path: "/x"}); err != nil {
					errs <- err
				}
				if err := s.TouchKeyLastUsed(ctx, k.ID, t0); err != nil {
					errs <- err
				}
				if _, err := s.ListKeys(ctx, false); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if es, _, _ := s.ListAudit(ctx, AuditFilter{Limit: 1000}); len(es) != 160 {
		t.Errorf("audit rows: %d", len(es))
	}
}

func TestContextCancelled(t *testing.T) {
	s, _ := openTemp(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ListKeys(ctx, false); err == nil {
		t.Error("cancelled context ignored")
	}
	if _, err := s.InsertAudit(ctx, &AuditEntry{Outcome: OutcomeOK}); err == nil {
		t.Error("cancelled context ignored on write")
	}
}
