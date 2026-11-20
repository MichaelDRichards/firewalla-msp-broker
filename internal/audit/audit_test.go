package audit

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"mspbroker/internal/redact"
	"mspbroker/internal/store"
)

const canary = "mg-test-CANARY-0000"

func newRecorder(t *testing.T) (*Recorder, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, redact.New(canary), nil), st
}

func TestRecordStoresMetadata(t *testing.T) {
	r, st := newRecorder(t)
	ctx := context.Background()
	n := 3
	status := 200
	e := &store.AuditEntry{
		KeyID: "k_1", KeyNameAtTime: "agent", SecretPrefix: "abcd1234", ClientIP: "192.0.2.10",
		Outcome: store.OutcomeOK, Method: "GET", Path: "/api/v1/alarms", Query: "limit=3",
		Resource: "alarms", Action: "list", GID: "00000000-0000-0000-0000-00000000000A",
		UpstreamStatus: &status, ResultCount: &n,
	}
	if err := r.Record(ctx, e); err != nil || e.ID == 0 || e.TS.IsZero() {
		t.Fatalf("record: id %d ts %v err %v", e.ID, e.TS, err)
	}
	got, err := st.GetAudit(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyNameAtTime != "agent" || got.SecretPrefix != "abcd1234" || got.ClientIP != "192.0.2.10" ||
		*got.ResultCount != 3 || *got.UpstreamStatus != 200 || got.Path != "/api/v1/alarms" {
		t.Errorf("stored %+v", got)
	}
	if got.GID != "00000000-0000-0000-0000-00000000000a" {
		t.Errorf("gid not lowercased: %q", got.GID)
	}
}

func TestRecordScrubsSecrets(t *testing.T) {
	r, st := newRecorder(t)
	ctx := context.Background()
	secret := "mb_" + strings.Repeat("A1", 21) + "z"
	e := &store.AuditEntry{
		Outcome: store.OutcomeBlocked, BlockReason: ReasonAuth, Method: "GET",
		Path:     "/api/v1/boxes/" + secret,
		Query:    "token=" + canary + "&x=" + secret,
		Resource: "boxes", Action: "read", KeyNameAtTime: "name " + canary,
		After: json.RawMessage(`{"note":"` + canary + `"}`),
	}
	e.Action = "update" // after-bodies are allowed on writes
	if err := r.Record(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetAudit(ctx, e.ID)
	all := got.Path + got.Query + got.KeyNameAtTime + string(got.After)
	if strings.Contains(all, canary) || strings.Contains(all, secret) {
		t.Errorf("secret stored: %+v", got)
	}
	if e.Path != "/api/v1/boxes/"+secret {
		t.Error("Record mutated the caller's entry")
	}
}

func TestRecordBoundsLengths(t *testing.T) {
	r, st := newRecorder(t)
	ctx := context.Background()
	e := &store.AuditEntry{Outcome: store.OutcomeOK, Method: "GET", Path: "/" + strings.Repeat("a", 10000),
		Query: strings.Repeat("q", 10000), Action: "read"}
	if err := r.Record(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetAudit(ctx, e.ID)
	if len(got.Path) > maxPath+3 || len(got.Query) > maxQuery+3 {
		t.Errorf("not bounded: %d %d", len(got.Path), len(got.Query))
	}
}

func TestRecordRules(t *testing.T) {
	r, _ := newRecorder(t)
	ctx := context.Background()
	if err := r.Record(ctx, &store.AuditEntry{Outcome: store.OutcomeBlocked, Method: "GET", Path: "/"}); err == nil {
		t.Error("blocked entry without reason accepted")
	}
	if err := r.Record(ctx, &store.AuditEntry{Outcome: store.OutcomeOK, BlockReason: ReasonAuth, Method: "GET", Path: "/"}); err == nil {
		t.Error("ok entry with reason accepted")
	}
	for _, action := range []string{"read", "list"} {
		err := r.Record(ctx, &store.AuditEntry{Outcome: store.OutcomeOK, Method: "GET", Path: "/", Action: action,
			After: json.RawMessage(`{"x":1}`)})
		if !errors.Is(err, ErrBodyOnRead) {
			t.Errorf("%s with body: %v", action, err)
		}
	}
	if err := r.Record(ctx, &store.AuditEntry{Outcome: "weird", Method: "GET", Path: "/"}); err == nil {
		t.Error("unknown outcome accepted")
	}
}
