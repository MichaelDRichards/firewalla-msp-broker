package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

const canary = "CANARY-upstream-token-0123456789"

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func noFiles(string) ([]byte, error) { return nil, errors.New("no files in this test") }

func baseEnv() map[string]string {
	return map[string]string{
		"MSP_BASE_URL": "https://msp.example.com",
		"MSP_TOKEN":    canary,
	}
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(baseEnv()), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	if c.DataDir != "/data" || c.ListenAddr != "0.0.0.0:8080" {
		t.Errorf("dir/listen defaults: %q %q", c.DataDir, c.ListenAddr)
	}
	if c.GroupCacheTTL != 60*time.Second || c.DefaultRateLimit != 120 || c.AuditRetentionDays != 365 {
		t.Errorf("numeric defaults: %v %d %d", c.GroupCacheTTL, c.DefaultRateLimit, c.AuditRetentionDays)
	}
	if c.BootstrapSecretFile || len(c.TrustedProxies) != 0 {
		t.Errorf("bootstrap/proxies defaults wrong")
	}
	if c.MSPToken.Reveal() != canary {
		t.Error("token not loaded")
	}
}

func TestLoadOverrides(t *testing.T) {
	e := baseEnv()
	e["MSP_BASE_URL"] = "http://192.0.2.10:9000/"
	e["DATA_DIR"] = "/tmp/x"
	e["LISTEN_ADDR"] = "127.0.0.1:9"
	e["TRUSTED_PROXIES"] = "198.51.100.0/24, 203.0.113.7"
	e["GROUP_CACHE_TTL"] = "5s"
	e["DEFAULT_RATE_LIMIT_PER_MINUTE"] = "0"
	e["AUDIT_RETENTION_DAYS"] = "0"
	e["BOOTSTRAP_SECRET_FILE"] = "true"
	c, err := Load(env(e), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	if c.MSPBaseURL != "http://192.0.2.10:9000" {
		t.Errorf("base url %q", c.MSPBaseURL)
	}
	if c.DataDir != "/tmp/x" || c.ListenAddr != "127.0.0.1:9" || c.GroupCacheTTL != 5*time.Second ||
		c.DefaultRateLimit != 0 || c.AuditRetentionDays != 0 || !c.BootstrapSecretFile {
		t.Errorf("overrides not applied: %v", c)
	}
	if len(c.TrustedProxies) != 2 || c.TrustedProxies[0].String() != "198.51.100.0/24" || c.TrustedProxies[1].String() != "203.0.113.7/32" {
		t.Errorf("proxies: %v", c.TrustedProxies)
	}
}

func TestTokenFile(t *testing.T) {
	e := baseEnv()
	delete(e, "MSP_TOKEN")
	e["MSP_TOKEN_FILE"] = "/run/secrets/msp"
	rf := func(p string) ([]byte, error) {
		if p != "/run/secrets/msp" {
			return nil, errors.New("wrong path")
		}
		return []byte("  " + canary + "\n"), nil
	}
	c, err := Load(env(e), rf)
	if err != nil {
		t.Fatal(err)
	}
	if c.MSPToken.Reveal() != canary {
		t.Errorf("token file not trimmed/loaded: %q", c.MSPToken.Reveal())
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name string
		mod  func(map[string]string)
		rf   func(string) ([]byte, error)
		want string
	}{
		{"no base url", func(e map[string]string) { delete(e, "MSP_BASE_URL") }, nil, "MSP_BASE_URL is required"},
		{"relative base url", func(e map[string]string) { e["MSP_BASE_URL"] = "msp.example.com" }, nil, "absolute http(s) URL"},
		{"ftp base url", func(e map[string]string) { e["MSP_BASE_URL"] = "ftp://msp.example.com" }, nil, "absolute http(s) URL"},
		{"creds in base url", func(e map[string]string) { e["MSP_BASE_URL"] = "https://u:p@msp.example.com" }, nil, "credentials"},
		{"no token", func(e map[string]string) { delete(e, "MSP_TOKEN") }, nil, "MSP_TOKEN or MSP_TOKEN_FILE is required"},
		{"blank token", func(e map[string]string) { e["MSP_TOKEN"] = "   " }, nil, "MSP_TOKEN is blank"},
		{"both token sources", func(e map[string]string) { e["MSP_TOKEN_FILE"] = "/x" }, nil, "only one of"},
		{"token file unreadable", func(e map[string]string) { delete(e, "MSP_TOKEN"); e["MSP_TOKEN_FILE"] = "/x" }, nil, "cannot read"},
		{"token file empty", func(e map[string]string) { delete(e, "MSP_TOKEN"); e["MSP_TOKEN_FILE"] = "/x" },
			func(string) ([]byte, error) { return []byte(" \n"), nil }, "is empty"},
		{"bad proxies", func(e map[string]string) { e["TRUSTED_PROXIES"] = "not-an-ip" }, nil, "TRUSTED_PROXIES"},
		{"bad ttl", func(e map[string]string) { e["GROUP_CACHE_TTL"] = "soon" }, nil, "GROUP_CACHE_TTL"},
		{"negative ttl", func(e map[string]string) { e["GROUP_CACHE_TTL"] = "-1s" }, nil, "GROUP_CACHE_TTL"},
		{"bad rate", func(e map[string]string) { e["DEFAULT_RATE_LIMIT_PER_MINUTE"] = "-3" }, nil, "DEFAULT_RATE_LIMIT_PER_MINUTE"},
		{"bad retention", func(e map[string]string) { e["AUDIT_RETENTION_DAYS"] = "x" }, nil, "AUDIT_RETENTION_DAYS"},
		{"bad bootstrap bool", func(e map[string]string) { e["BOOTSTRAP_SECRET_FILE"] = "maybe" }, nil, "BOOTSTRAP_SECRET_FILE"},
		{"half tls", func(e map[string]string) { e["TLS_CERT_FILE"] = "/c" }, nil, "TLS_CERT_FILE and TLS_KEY_FILE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := baseEnv()
			tc.mod(e)
			rf := tc.rf
			if rf == nil {
				rf = noFiles
			}
			c, err := Load(env(e), rf)
			if err == nil {
				t.Fatalf("want error containing %q, got config %v", tc.want, c)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q lacks %q", err, tc.want)
			}
			if strings.Contains(err.Error(), canary) {
				t.Errorf("error leaks token: %q", err)
			}
		})
	}
}

func TestErrorsReportAllProblems(t *testing.T) {
	_, err := Load(env(map[string]string{"GROUP_CACHE_TTL": "x"}), noFiles)
	if err == nil || !strings.Contains(err.Error(), "MSP_BASE_URL") || !strings.Contains(err.Error(), "GROUP_CACHE_TTL") {
		t.Errorf("want all problems reported, got %v", err)
	}
}

// TestRedaction renders the config and token through every formatting path
// and asserts the canary never appears.
func TestRedaction(t *testing.T) {
	c, err := Load(env(baseEnv()), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%d", "%T"} {
		out["config "+verb] = fmt.Sprintf(verb, *c)
		out["configptr "+verb] = fmt.Sprintf(verb, c)
		out["token "+verb] = fmt.Sprintf(verb, c.MSPToken)
		out["tokenptr "+verb] = fmt.Sprintf(verb, &c.MSPToken)
	}
	out["Sprint"] = fmt.Sprint(c, c.MSPToken, *c)
	out["String"] = c.String() + c.MSPToken.String()
	out["Errorf"] = fmt.Errorf("wrapped: %w %v", errors.New("x"), c).Error()
	j, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	out["json config"] = string(j)
	j, _ = json.Marshal(struct{ T Secret }{c.MSPToken})
	out["json secret"] = string(j)
	jt, _ := json.Marshal(map[Secret]int{})
	out["json map"] = string(jt)

	var sb strings.Builder
	l := slog.New(slog.NewTextHandler(&sb, nil))
	l.Info("cfg", "config", c, "token", c.MSPToken, slog.Any("cfgv", *c))
	out["slog text"] = sb.String()
	sb.Reset()
	l = slog.New(slog.NewJSONHandler(&sb, nil))
	l.Info("cfg", "config", *c, "token", c.MSPToken)
	out["slog json"] = sb.String()

	for name, s := range out {
		if strings.Contains(s, canary) {
			t.Errorf("%s leaks the token: %s", name, s)
		}
	}
	if !strings.Contains(c.String(), "[redacted]") {
		t.Errorf("String should say redacted: %s", c.String())
	}
}

func TestParsePrefixes(t *testing.T) {
	ps, err := ParsePrefixes("192.0.2.5, 198.51.100.9/24 ,,::ffff:203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, p := range ps {
		got = append(got, p.String())
	}
	want := "192.0.2.5/32 198.51.100.0/24 203.0.113.1/32"
	if strings.Join(got, " ") != want {
		t.Errorf("got %v want %s", got, want)
	}
	if _, err := ParsePrefixes("192.0.2.0/33"); err == nil {
		t.Error("want error for bad mask")
	}
}
