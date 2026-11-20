package auth

import (
	"context"
	"errors"
	"math/big"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mspbroker/internal/acl"
	"mspbroker/internal/store"
)

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

// clock is a settable time source.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

type env struct {
	st  *store.Store
	clk *clock
	a   *Authenticator
}

func newEnv(t *testing.T, trusted string, defaultLimit int) *env {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	clk := &clock{t: t0}
	st.SetClock(clk.now)
	cfg := Config{Store: st, DefaultRateLimit: defaultLimit, Now: clk.now}
	if trusted != "" {
		for _, p := range strings.Split(trusted, ",") {
			pf, err := ParseAllowEntry(p)
			if err != nil {
				t.Fatal(err)
			}
			cfg.TrustedProxies = append(cfg.TrustedProxies, pf)
		}
	}
	return &env{st: st, clk: clk, a: New(cfg)}
}

// addKey creates a key and its first secret, returning the secret string.
func (e *env) addKey(t *testing.T, name string, mod func(*store.Key)) (*store.Key, string) {
	t.Helper()
	k := &store.Key{
		Name: name, Kind: acl.KindData, Enabled: true,
		Scope:       acl.Scope{Type: acl.ScopeAll},
		Permissions: acl.Permissions{Boxes: acl.Read},
	}
	if mod != nil {
		mod(k)
	}
	full, row, err := NewSecret("", e.clk.now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.CreateKey(context.Background(), k, row); err != nil {
		t.Fatal(err)
	}
	return k, full
}

func hdr(secret string) http.Header {
	h := http.Header{}
	if secret != "" {
		h.Set("Authorization", "Bearer "+secret)
	}
	return h
}

func (e *env) auth(secret, remote string) (*Principal, *Failure, error) {
	p, err := e.a.Authenticate(context.Background(), hdr(secret), remote)
	if f, ok := AsFailure(err); ok {
		return nil, f, nil
	}
	return p, nil, err
}

func mustFail(t *testing.T, e *env, secret, remote string, want Reason, status int) *Failure {
	t.Helper()
	p, f, err := e.auth(secret, remote)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f == nil {
		t.Fatalf("authenticated, want %s (principal %+v)", want, p)
	}
	if f.Reason != want || f.Status != status {
		t.Fatalf("got %s/%d (%s), want %s/%d", f.Reason, f.Status, f.Internal, want, status)
	}
	return f
}

// ---- secrets ----

func TestGenerateSecretFormat(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		s, err := GenerateSecret()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(s, "mb_") || len(s) != 46 || !WellFormed(s) {
			t.Fatalf("bad secret %q", s)
		}
		if seen[s] {
			t.Fatal("duplicate secret")
		}
		seen[s] = true
		if p := Prefix(s); len(p) != 8 || p != s[3:11] {
			t.Fatalf("prefix %q of %q", p, s)
		}
		if h := Hash(s); len(h) != 32 {
			t.Fatalf("hash length %d", len(h))
		}
	}
}

func TestBase62EncodingIsExact(t *testing.T) {
	zero := make([]byte, 32)
	if got := encodeBase62(zero); got != strings.Repeat("0", 43) {
		t.Errorf("zero: %q", got)
	}
	max := make([]byte, 32)
	for i := range max {
		max[i] = 0xff
	}
	one := make([]byte, 32)
	one[31] = 1
	for _, in := range [][]byte{zero, one, max, append([]byte{0x80}, make([]byte, 31)...)} {
		enc := encodeBase62(in)
		if len(enc) != 43 {
			t.Fatalf("length %d", len(enc))
		}
		// Decode independently and compare.
		n := new(big.Int)
		for _, c := range enc {
			n.Mul(n, big.NewInt(62))
			n.Add(n, big.NewInt(int64(strings.IndexRune(base62, c))))
		}
		if n.Cmp(new(big.Int).SetBytes(in)) != 0 {
			t.Errorf("round trip failed for %x", in)
		}
	}
}

func TestHashKnownVector(t *testing.T) {
	// SHA-256("abc")
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	got := Hash("abc")
	var sb strings.Builder
	for _, b := range got {
		sb.WriteString(string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&15]))
	}
	if sb.String() != want {
		t.Errorf("sha256 = %s", sb.String())
	}
}

func TestWellFormedAndPrefix(t *testing.T) {
	good := "mb_" + strings.Repeat("a", 43)
	if !WellFormed(good) || Prefix(good) != "aaaaaaaa" {
		t.Fatal("good secret rejected")
	}
	for _, bad := range []string{
		"", "mb_", "mb_" + strings.Repeat("a", 42), "mb_" + strings.Repeat("a", 44),
		"xx_" + strings.Repeat("a", 43), "MB_" + strings.Repeat("a", 43), "mb_" + strings.Repeat("a", 42) + "-",
		"mb_" + strings.Repeat("a", 42) + " ", "mb_" + strings.Repeat("a", 42) + "é", "mb_" + strings.Repeat("a", 41) + "\n\n",
	} {
		if WellFormed(bad) {
			t.Errorf("accepted %q", bad)
		}
		if Prefix(bad) != "" {
			t.Errorf("Prefix echoed junk for %q", bad)
		}
	}
}

func TestParseBearer(t *testing.T) {
	cases := []struct {
		in   string
		tok  string
		good bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true},
		{"BEARER abc", "abc", true},
		{"", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false},
		{"Bearer  abc", "", false},
		{"Bearer abc def", "", false},
		{"Bearer abc\t", "", false},
		{"Basic abc", "", false},
		{"Bearerabc", "", false},
		{"Token abc", "", false},
	}
	for _, c := range cases {
		tok, ok := ParseBearer(c.in)
		if ok != c.good || tok != c.tok {
			t.Errorf("ParseBearer(%q) = %q,%v", c.in, tok, ok)
		}
	}
}

// ---- authentication ----

func TestAuthenticateSuccess(t *testing.T) {
	e := newEnv(t, "", 60)
	k, secret := e.addKey(t, "agent", nil)
	p, f, err := e.auth(secret, "192.0.2.10:5555")
	if err != nil || f != nil {
		t.Fatalf("%v %v", f, err)
	}
	if p.Key.ID != k.ID || p.Key.Name != "agent" || p.SecretPrefix != secret[3:11] || p.ClientIP != "192.0.2.10" || p.SecretID == "" {
		t.Errorf("principal: %+v", p)
	}
	// last_used_at is recorded, then throttled.
	got, _ := e.st.GetKey(context.Background(), k.ID)
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(t0) {
		t.Fatalf("last used: %v", got.LastUsedAt)
	}
	e.clk.advance(10 * time.Second)
	if _, f, err := e.auth(secret, "192.0.2.10:1"); f != nil || err != nil {
		t.Fatal(f, err)
	}
	got, _ = e.st.GetKey(context.Background(), k.ID)
	if !got.LastUsedAt.Equal(t0) {
		t.Errorf("last_used_at written more often than once a minute: %v", got.LastUsedAt)
	}
	e.clk.advance(2 * time.Minute)
	e.auth(secret, "192.0.2.10:1")
	got, _ = e.st.GetKey(context.Background(), k.ID)
	if !got.LastUsedAt.Equal(e.clk.now()) {
		t.Errorf("last_used_at not refreshed: %v", got.LastUsedAt)
	}
}

func TestAuthenticateAdminKeyAlsoAuthenticates(t *testing.T) {
	// Kind separation is the ACL's job; auth just identifies the caller.
	e := newEnv(t, "", 60)
	_, secret := e.addKey(t, "root", func(k *store.Key) { k.Kind = acl.KindAdmin })
	p, f, err := e.auth(secret, "192.0.2.1:1")
	if err != nil || f != nil || p.Key.Kind != acl.KindAdmin {
		t.Fatalf("%v %v %+v", f, err, p)
	}
}

func TestAuthenticateFailures(t *testing.T) {
	e := newEnv(t, "", 60)
	ctx := context.Background()
	remote := "192.0.2.10:5555"

	// Missing / malformed / unknown.
	mustFail(t, e, "", remote, ReasonAuth, 401)
	mustFail(t, e, "garbage", remote, ReasonAuth, 401)
	mustFail(t, e, "mb_short", remote, ReasonAuth, 401)
	unknown, _ := GenerateSecret()
	fu := mustFail(t, e, unknown, remote, ReasonAuth, 401)
	if fu.KeyID != "" || fu.SecretPrefix != unknown[3:11] || fu.ClientIP != "192.0.2.10" {
		t.Errorf("unknown failure context: %+v", fu)
	}
	h := http.Header{}
	h.Set("Authorization", "Basic abc")
	if _, err := e.a.Authenticate(ctx, h, remote); !isReason(err, ReasonAuth) {
		t.Errorf("basic auth: %v", err)
	}

	// Revoked secret: same public face as unknown.
	k, secret := e.addKey(t, "revoked-soon", nil)
	secs, _ := e.st.ListSecrets(ctx, k.ID)
	if err := e.st.RevokeSecret(ctx, k.ID, secs[0].ID, t0); err != nil {
		t.Fatal(err)
	}
	fr := mustFail(t, e, secret, remote, ReasonAuth, 401)
	if fr.KeyID != k.ID || fr.KeyName != "revoked-soon" || fr.Internal != "revoked secret" {
		t.Errorf("revoked audit context: %+v", fr)
	}

	// Secret expiry (rotation grace window ended).
	k2, s2 := e.addKey(t, "rotating", nil)
	secs, _ = e.st.ListSecrets(ctx, k2.ID)
	exp := t0.Add(time.Hour)
	e.st.SetSecretExpiry(ctx, k2.ID, secs[0].ID, &exp)
	if _, f, err := e.auth(s2, remote); f != nil || err != nil {
		t.Fatalf("inside grace window: %v %v", f, err)
	}
	e.clk.advance(time.Hour) // exactly at expiry: expired
	mustFail(t, e, s2, remote, ReasonExpired, 401)

	// Key disabled, key expired, key deleted.
	e.clk.t = t0
	_, s3 := e.addKey(t, "off", func(k *store.Key) { k.Enabled = false })
	mustFail(t, e, s3, remote, ReasonDisabled, 403)

	kexp := t0.Add(time.Hour)
	_, s4 := e.addKey(t, "short-lived", func(k *store.Key) { k.ExpiresAt = &kexp })
	if _, f, _ := e.auth(s4, remote); f != nil {
		t.Fatalf("before key expiry: %v", f)
	}
	e.clk.advance(time.Hour)
	mustFail(t, e, s4, remote, ReasonExpired, 401)
	e.clk.t = t0

	k5, s5 := e.addKey(t, "deleted", nil)
	e.st.SoftDeleteKey(ctx, k5.ID, t0)
	f5 := mustFail(t, e, s5, remote, ReasonAuth, 401)
	if f5.Internal != "deleted key" {
		t.Errorf("internal: %q", f5.Internal)
	}
}

func isReason(err error, r Reason) bool {
	f, ok := AsFailure(err)
	return ok && f.Reason == r
}

// TestUnknownAndRevokedAreIndistinguishable compares everything a client can
// observe about the two failures.
func TestUnknownAndRevokedAreIndistinguishable(t *testing.T) {
	e := newEnv(t, "", 60)
	ctx := context.Background()
	k, secret := e.addKey(t, "k", nil)
	secs, _ := e.st.ListSecrets(ctx, k.ID)
	e.st.RevokeSecret(ctx, k.ID, secs[0].ID, t0)
	unknown, _ := GenerateSecret()

	fr := mustFail(t, e, secret, "192.0.2.1:1", ReasonAuth, 401)
	fu := mustFail(t, e, unknown, "192.0.2.1:1", ReasonAuth, 401)
	if fr.Reason != fu.Reason || fr.Status != fu.Status || fr.Message() != fu.Message() || fr.Error() != fu.Error() ||
		fr.RetryAfter != fu.RetryAfter || fr.RetryAfterSeconds() != fu.RetryAfterSeconds() {
		t.Errorf("client-visible difference:\n revoked: %#v\n unknown: %#v", fr, fu)
	}
	// Malformed, missing and deleted-key failures share the same face too.
	k2, s2 := e.addKey(t, "gone", nil)
	e.st.SoftDeleteKey(ctx, k2.ID, t0)
	for name, f := range map[string]*Failure{
		"missing":   mustFail(t, e, "", "192.0.2.1:1", ReasonAuth, 401),
		"malformed": mustFail(t, e, "mb_x", "192.0.2.1:1", ReasonAuth, 401),
		"deleted":   mustFail(t, e, s2, "192.0.2.1:1", ReasonAuth, 401),
	} {
		if f.Message() != fu.Message() || f.Error() != fu.Error() || f.Status != fu.Status {
			t.Errorf("%s differs: %#v", name, f)
		}
	}
	for _, f := range []*Failure{fr, fu} {
		if strings.Contains(f.Error(), "revoked") || strings.Contains(f.Message(), "unknown") {
			t.Errorf("message leaks cause: %q", f.Error())
		}
	}
}

// fakeStore returns a secret whose hash does not match the lookup.
type fakeStore struct {
	sec *store.Secret
	key *store.Key
	err error
}

func (f fakeStore) SecretByHash(context.Context, []byte) (*store.Secret, error) { return f.sec, f.err }
func (f fakeStore) GetKey(context.Context, string) (*store.Key, error)          { return f.key, f.err }
func (f fakeStore) TouchKeyLastUsed(context.Context, string, time.Time) error   { return nil }

func TestHashMismatchFromStoreIsRejected(t *testing.T) {
	secret, _ := GenerateSecret()
	other, _ := GenerateSecret()
	a := New(Config{Store: fakeStore{
		sec: &store.Secret{ID: "s_1", KeyID: "k_1", Hash: Hash(other)},
		key: &store.Key{ID: "k_1", Enabled: true},
	}})
	_, err := a.Authenticate(context.Background(), hdr(secret), "192.0.2.1:1")
	if !isReason(err, ReasonAuth) {
		t.Errorf("mismatched hash accepted: %v", err)
	}
}

func TestStoreErrorsAreNotAuthFailures(t *testing.T) {
	secret, _ := GenerateSecret()
	boom := errors.New("disk on fire")
	a := New(Config{Store: fakeStore{err: boom}})
	_, err := a.Authenticate(context.Background(), hdr(secret), "192.0.2.1:1")
	if !errors.Is(err, boom) {
		t.Errorf("want store error, got %v", err)
	}
	if _, ok := AsFailure(err); ok {
		t.Error("infrastructure error masquerades as a client failure")
	}
}

func TestFailuresNeverContainTheSecret(t *testing.T) {
	e := newEnv(t, "", 60)
	k, secret := e.addKey(t, "k", nil)
	secs, _ := e.st.ListSecrets(context.Background(), k.ID)
	e.st.RevokeSecret(context.Background(), k.ID, secs[0].ID, t0)
	unknown, _ := GenerateSecret()
	for _, s := range []string{secret, unknown} {
		f := mustFail(t, e, s, "192.0.2.1:1", ReasonAuth, 401)
		body := f.Error() + f.Message() + f.Internal + f.KeyID + f.KeyName + f.SecretPrefix + f.ClientIP
		if strings.Contains(body, s) || strings.Contains(body, s[11:]) {
			t.Errorf("failure leaks secret material: %q", body)
		}
	}
	p := &Principal{SecretPrefix: Prefix(secret)}
	if strings.Contains(p.SecretPrefix, secret[11:]) {
		t.Error("principal prefix too long")
	}
}

// ---- IP allowlist ----

func TestIPAllowlist(t *testing.T) {
	e := newEnv(t, "", 0)
	_, secret := e.addKey(t, "restricted", func(k *store.Key) {
		k.IPAllow = []string{"192.0.2.0/24", "198.51.100.7", "2001:db8::/48"}
	})
	for _, ok := range []string{"192.0.2.1:1", "192.0.2.254:9", "198.51.100.7:1", "[2001:db8::5]:80", "[::ffff:192.0.2.9]:80"} {
		if _, f, err := e.auth(secret, ok); f != nil || err != nil {
			t.Errorf("%s should be allowed: %v %v", ok, f, err)
		}
	}
	for _, bad := range []string{"203.0.113.1:1", "198.51.100.8:1", "198.51.100.200:1", "[2001:db8:1::1]:1", "garbage"} {
		mustFail(t, e, secret, bad, ReasonIP, 403)
	}
	// Empty allowlist allows anything, even an unparseable peer.
	_, open := e.addKey(t, "open", nil)
	if _, f, err := e.auth(open, "garbage"); f != nil || err != nil {
		t.Errorf("open key: %v %v", f, err)
	}
	// Unparseable entries match nothing; if all are bad, nobody gets in.
	_, broken := e.addKey(t, "broken", func(k *store.Key) { k.IPAllow = []string{"not-an-ip", "300.1.1.1/8"} })
	mustFail(t, e, broken, "192.0.2.1:1", ReasonIP, 403)
}

func TestIPAllowedDirect(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.77")
	if !IPAllowed(nil, ip) || !IPAllowed([]string{}, netip.Addr{}) {
		t.Error("empty list must allow all")
	}
	if IPAllowed([]string{"192.0.2.0/26"}, ip) || !IPAllowed([]string{"192.0.2.0/24"}, ip) || IPAllowed([]string{"192.0.2.0/24"}, netip.Addr{}) {
		t.Error("prefix matching wrong")
	}
	if _, err := ParseAllowEntry("192.0.2.0/33"); err == nil {
		t.Error("bad mask accepted")
	}
}

func TestClientIPTrustedProxies(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	cases := []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{"no header", "198.51.100.5:1", nil, "198.51.100.5"},
		{"untrusted peer, header ignored", "198.51.100.5:1", []string{"203.0.113.9"}, "198.51.100.5"},
		{"untrusted peer, spoof attempt", "198.51.100.5:1", []string{"192.0.2.1"}, "198.51.100.5"},
		{"trusted peer, single hop", "192.0.2.10:1", []string{"203.0.113.9"}, "203.0.113.9"},
		{"left entries are not believed", "192.0.2.10:1", []string{"198.51.100.77, 203.0.113.9"}, "203.0.113.9"},
		{"trusted hops skipped", "192.0.2.10:1", []string{"203.0.113.9, 192.0.2.20"}, "203.0.113.9"},
		{"multiple header lines", "192.0.2.10:1", []string{"198.51.100.77", "203.0.113.9, 192.0.2.30"}, "203.0.113.9"},
		{"all hops trusted -> leftmost", "192.0.2.10:1", []string{"192.0.2.40, 192.0.2.20"}, "192.0.2.40"},
		{"garbage entry falls back to peer", "192.0.2.10:1", []string{"203.0.113.9, not-an-ip"}, "192.0.2.10"},
		{"garbage left of a real client is never reached", "192.0.2.10:1", []string{"not-an-ip, 203.0.113.9"}, "203.0.113.9"},
		{"empty header value", "192.0.2.10:1", []string{""}, "192.0.2.10"},
		{"ipv6 client", "192.0.2.10:1", []string{"2001:db8::7"}, "2001:db8::7"},
		{"mapped client", "192.0.2.10:1", []string{"::ffff:203.0.113.9"}, "203.0.113.9"},
		{"zone stripped", "192.0.2.10:1", []string{"2001:db8::2%eth0"}, "2001:db8::2"},
		{"peer without port", "192.0.2.10", []string{"203.0.113.9"}, "203.0.113.9"},
		{"ipv6 peer with port", "[2001:db8::1]:443", nil, "2001:db8::1"},
		{"mapped peer is unmapped", "[::ffff:192.0.2.10]:443", []string{"203.0.113.9"}, "203.0.113.9"},
	}
	for _, c := range cases {
		got := ClientIP(c.remote, c.xff, trusted)
		if got.String() != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
	if ClientIP("garbage", []string{"203.0.113.9"}, trusted).IsValid() {
		t.Error("unparseable peer must stay invalid")
	}
	// No trusted proxies configured: header never honoured.
	if got := ClientIP("192.0.2.10:1", []string{"203.0.113.9"}, nil); got.String() != "192.0.2.10" {
		t.Errorf("default must use the socket peer, got %s", got)
	}
}

func TestAllowlistHonoursForwardedForOnlyFromTrustedPeer(t *testing.T) {
	e := newEnv(t, "192.0.2.0/24", 0)
	_, secret := e.addKey(t, "behind-proxy", func(k *store.Key) { k.IPAllow = []string{"203.0.113.0/24"} })
	call := func(remote, xff string) error {
		h := hdr(secret)
		if xff != "" {
			h.Set("X-Forwarded-For", xff)
		}
		_, err := e.a.Authenticate(context.Background(), h, remote)
		return err
	}
	if err := call("192.0.2.10:1", "203.0.113.50"); err != nil {
		t.Errorf("trusted proxy forwarding an allowed client: %v", err)
	}
	if err := call("192.0.2.10:1", "198.51.100.50"); !isReason(err, ReasonIP) {
		t.Errorf("trusted proxy forwarding a disallowed client: %v", err)
	}
	if err := call("198.51.100.99:1", "203.0.113.50"); !isReason(err, ReasonIP) {
		t.Errorf("untrusted peer spoofing an allowed client: %v", err)
	}
	if err := call("192.0.2.10:1", "203.0.113.50, 198.51.100.50"); !isReason(err, ReasonIP) {
		t.Errorf("spoofed left entry must not win: %v", err)
	}
	f, _ := AsFailure(call("192.0.2.10:1", "198.51.100.50"))
	if f.ClientIP != "198.51.100.50" {
		t.Errorf("audit client ip: %q", f.ClientIP)
	}
}

// ---- rate limiting ----

func TestRateLimit(t *testing.T) {
	e := newEnv(t, "", 600)
	three := 3
	_, secret := e.addKey(t, "limited", func(k *store.Key) { k.RateLimitPerMinute = &three })
	remote := "192.0.2.10:1"
	for i := 0; i < 3; i++ {
		if _, f, err := e.auth(secret, remote); f != nil || err != nil {
			t.Fatalf("request %d: %v %v", i, f, err)
		}
	}
	f := mustFail(t, e, secret, remote, ReasonRateLimit, 429)
	// 3/min = 1 token per 20s.
	if f.RetryAfter != 20*time.Second || f.RetryAfterSeconds() != 20 {
		t.Errorf("retry after %v / %d", f.RetryAfter, f.RetryAfterSeconds())
	}
	if f.KeyID == "" || f.KeyName != "limited" {
		t.Errorf("audit context missing: %+v", f)
	}
	e.clk.advance(10 * time.Second)
	f = mustFail(t, e, secret, remote, ReasonRateLimit, 429)
	if f.RetryAfter != 10*time.Second {
		t.Errorf("after 10s retry after = %v", f.RetryAfter)
	}
	e.clk.advance(10 * time.Second)
	if _, f, err := e.auth(secret, remote); f != nil || err != nil {
		t.Fatalf("token should have refilled: %v %v", f, err)
	}
	mustFail(t, e, secret, remote, ReasonRateLimit, 429)
	// A long pause refills to capacity, not beyond.
	e.clk.advance(time.Hour)
	for i := 0; i < 3; i++ {
		if _, f, _ := e.auth(secret, remote); f != nil {
			t.Fatalf("burst %d after idle: %v", i, f)
		}
	}
	mustFail(t, e, secret, remote, ReasonRateLimit, 429)
}

func TestRateLimitDefaultsAndUnlimited(t *testing.T) {
	e := newEnv(t, "", 2) // default 2/min
	_, def := e.addKey(t, "default", nil)
	zero := 0
	_, unl := e.addKey(t, "unlimited", func(k *store.Key) { k.RateLimitPerMinute = &zero })
	remote := "192.0.2.10:1"
	e.auth(def, remote)
	e.auth(def, remote)
	mustFail(t, e, def, remote, ReasonRateLimit, 429)
	for i := 0; i < 500; i++ {
		if _, f, _ := e.auth(unl, remote); f != nil {
			t.Fatalf("unlimited key limited at %d", i)
		}
	}
	// Default 0 = unlimited too.
	e0 := newEnv(t, "", 0)
	_, s0 := e0.addKey(t, "k", nil)
	for i := 0; i < 200; i++ {
		if _, f, _ := e0.auth(s0, remote); f != nil {
			t.Fatalf("limited at %d with default 0", i)
		}
	}
}

func TestRateLimitIsPerKeyAndOnlyChargedWhenAuthenticated(t *testing.T) {
	e := newEnv(t, "", 1)
	_, a := e.addKey(t, "a", nil)
	_, b := e.addKey(t, "b", nil)
	remote := "192.0.2.10:1"
	// Junk and unknown secrets are free and cannot drain anyone's bucket.
	unknown, _ := GenerateSecret()
	for i := 0; i < 50; i++ {
		e.auth(unknown, remote)
		e.auth("", remote)
	}
	if e.a.limiter.Len() != 0 {
		t.Errorf("unauthenticated traffic created %d buckets", e.a.limiter.Len())
	}
	if _, f, _ := e.auth(a, remote); f != nil {
		t.Fatal(f)
	}
	mustFail(t, e, a, remote, ReasonRateLimit, 429)
	if _, f, _ := e.auth(b, remote); f != nil {
		t.Errorf("key b limited by key a's traffic: %v", f)
	}
	// A disabled/IP-blocked key does not consume tokens either.
	_, off := e.addKey(t, "off", func(k *store.Key) { k.Enabled = false })
	for i := 0; i < 5; i++ {
		mustFail(t, e, off, remote, ReasonDisabled, 403)
	}
}

func TestLimiterResizeAndSweep(t *testing.T) {
	clk := &clock{t: t0}
	l := NewLimiter(clk.now)
	for i := 0; i < 10; i++ {
		if ok, _ := l.Allow("k", 10); !ok {
			t.Fatalf("burst %d", i)
		}
	}
	if ok, wait := l.Allow("k", 10); ok || wait != 6*time.Second {
		t.Errorf("empty bucket: %v %v", ok, wait)
	}
	// Lowering the limit caps the stored tokens to the new capacity.
	clk.advance(30 * time.Second) // +5 tokens at 10/min
	if ok, _ := l.Allow("k", 10); !ok {
		t.Error("should allow after refill") // 4 tokens left
	}
	if ok, _ := l.Allow("k", 2); !ok {
		t.Error("capacity 2 allows one")
	}
	if ok, _ := l.Allow("k", 2); !ok {
		t.Error("capacity 2 allows a second")
	}
	if ok, _ := l.Allow("k", 2); ok {
		t.Error("tokens must be capped to the lowered capacity")
	}
	// Sweep drops idle buckets once the table is large.
	for i := 0; i < sweepThreshold+10; i++ {
		l.Allow(strings.Repeat("x", 1)+string(rune('a'+i%26))+string(rune('A'+(i/26)%26))+string(rune('0'+(i/676)%10)), 5)
	}
	clk.advance(10 * time.Minute)
	l.Allow("fresh-trigger", 5)
	if l.Len() > 2 {
		t.Errorf("idle buckets not swept: %d", l.Len())
	}
	if ok, w := l.Allow("any", 0); !ok || w != 0 {
		t.Error("unlimited must allow")
	}
}

func TestRetryAfterSecondsRounding(t *testing.T) {
	for in, want := range map[time.Duration]int{0: 1, time.Millisecond: 1, time.Second: 1, 1001 * time.Millisecond: 2, 20 * time.Second: 20, 59500 * time.Millisecond: 60} {
		if got := (&Failure{RetryAfter: in}).RetryAfterSeconds(); got != want {
			t.Errorf("%v -> %d, want %d", in, got, want)
		}
	}
}

func TestNewSecretRow(t *testing.T) {
	exp := t0.Add(time.Hour)
	full, row, err := NewSecret("k_1", t0, &exp)
	if err != nil {
		t.Fatal(err)
	}
	if row.KeyID != "k_1" || row.Prefix != full[3:11] || string(row.Hash) != string(Hash(full)) || row.ExpiresAt == nil || !row.CreatedAt.Equal(t0) || !strings.HasPrefix(row.ID, "s_") {
		t.Errorf("row: %+v", row)
	}
	if strings.Contains(string(row.Hash), full) || row.Prefix == full {
		t.Error("row must not hold the full secret")
	}
}
