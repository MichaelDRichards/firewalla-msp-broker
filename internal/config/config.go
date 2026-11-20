// Package config loads mspbroker configuration from environment variables.
//
// The upstream MSP token is held in a Secret, which redacts itself under
// every formatting path, so a Config can be logged or printed safely.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const redacted = "[redacted]"

// Secret is a string that never reveals itself except through Reveal.
// It redacts under %s, %v, %+v, %#v, %q, %x, JSON, text and slog.
type Secret struct{ v string }

// NewSecret wraps a sensitive value.
func NewSecret(v string) Secret { return Secret{v: v} }

// Reveal returns the underlying value. Call it only where the value is used.
func (s Secret) Reveal() string { return s.v }

// IsSet reports whether a value is present.
func (s Secret) IsSet() bool { return s.v != "" }

func (s Secret) String() string   { return redacted }
func (s Secret) GoString() string { return redacted }

// Format implements fmt.Formatter so no verb can print the value.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// MarshalJSON implements json.Marshaler.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }

// MarshalText implements encoding.TextMarshaler.
func (s Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// Defaults.
const (
	DefaultDataDir          = "/data"
	DefaultListenAddr       = "0.0.0.0:8080"
	DefaultGroupCacheTTL    = 60 * time.Second
	DefaultRateLimit        = 120
	DefaultAuditRetention   = 365
	maxRateLimitPerMinute   = 1_000_000
	maxAuditRetentionInDays = 36500
)

// Config is the process configuration.
type Config struct {
	MSPBaseURL     string
	MSPToken       Secret
	DataDir        string
	ListenAddr     string
	TrustedProxies []netip.Prefix
	GroupCacheTTL  time.Duration
	// DefaultRateLimit is requests per minute for keys without their own
	// limit. 0 means unlimited.
	DefaultRateLimit int
	// AuditRetentionDays prunes audit rows older than this. 0 means forever.
	AuditRetentionDays  int
	BootstrapSecretFile bool
	TLSCertFile         string
	TLSKeyFile          string
}

// String renders the config for logs. It never includes the token value.
func (c Config) String() string {
	proxies := make([]string, len(c.TrustedProxies))
	for i, p := range c.TrustedProxies {
		proxies[i] = p.String()
	}
	return fmt.Sprintf("Config{MSPBaseURL:%s MSPToken:%s DataDir:%s ListenAddr:%s TrustedProxies:[%s] GroupCacheTTL:%s DefaultRateLimit:%d AuditRetentionDays:%d BootstrapSecretFile:%t TLSCertFile:%s TLSKeyFile:%s}",
		c.MSPBaseURL, tokenState(c.MSPToken), c.DataDir, c.ListenAddr, strings.Join(proxies, ","),
		c.GroupCacheTTL, c.DefaultRateLimit, c.AuditRetentionDays, c.BootstrapSecretFile, c.TLSCertFile, c.TLSKeyFile)
}

func tokenState(s Secret) string {
	if s.IsSet() {
		return redacted
	}
	return "unset"
}

// Format makes %v, %+v and %#v all use String.
func (c Config) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(c.String())) }

// LogValue implements slog.LogValuer.
func (c Config) LogValue() slog.Value { return slog.StringValue(c.String()) }

// MarshalJSON renders the config without the token value.
func (c Config) MarshalJSON() ([]byte, error) {
	proxies := make([]string, len(c.TrustedProxies))
	for i, p := range c.TrustedProxies {
		proxies[i] = p.String()
	}
	return json.Marshal(map[string]any{
		"msp_base_url":          c.MSPBaseURL,
		"msp_token":             tokenState(c.MSPToken),
		"data_dir":              c.DataDir,
		"listen_addr":           c.ListenAddr,
		"trusted_proxies":       proxies,
		"group_cache_ttl":       c.GroupCacheTTL.String(),
		"default_rate_limit":    c.DefaultRateLimit,
		"audit_retention_days":  c.AuditRetentionDays,
		"bootstrap_secret_file": c.BootstrapSecretFile,
		"tls_cert_file":         c.TLSCertFile,
		"tls_key_file":          c.TLSKeyFile,
	})
}

// Load reads configuration. getenv is os.Getenv in production; readFile is
// os.ReadFile. Errors never include the token value.
func Load(getenv func(string) string, readFile func(string) ([]byte, error)) (*Config, error) {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	c := &Config{
		DataDir:            orDefault(getenv("DATA_DIR"), DefaultDataDir),
		ListenAddr:         orDefault(getenv("LISTEN_ADDR"), DefaultListenAddr),
		GroupCacheTTL:      DefaultGroupCacheTTL,
		DefaultRateLimit:   DefaultRateLimit,
		AuditRetentionDays: DefaultAuditRetention,
		TLSCertFile:        getenv("TLS_CERT_FILE"),
		TLSKeyFile:         getenv("TLS_KEY_FILE"),
	}

	// Upstream base URL.
	base := strings.TrimSpace(getenv("MSP_BASE_URL"))
	switch {
	case base == "":
		fail("MSP_BASE_URL is required")
	default:
		u, err := url.Parse(base)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			fail("MSP_BASE_URL must be an absolute http(s) URL")
		} else {
			if u.User != nil {
				fail("MSP_BASE_URL must not contain credentials")
			}
			c.MSPBaseURL = strings.TrimRight(base, "/")
		}
	}

	// Upstream token.
	tok, tokFile := getenv("MSP_TOKEN"), getenv("MSP_TOKEN_FILE")
	switch {
	case tok != "" && tokFile != "":
		fail("set only one of MSP_TOKEN and MSP_TOKEN_FILE")
	case tok != "":
		c.MSPToken = NewSecret(strings.TrimSpace(tok))
	case tokFile != "":
		b, err := readFile(tokFile)
		if err != nil {
			fail("MSP_TOKEN_FILE: cannot read %q", tokFile)
		} else if t := strings.TrimSpace(string(b)); t == "" {
			fail("MSP_TOKEN_FILE: %q is empty", tokFile)
		} else {
			c.MSPToken = NewSecret(t)
		}
	default:
		fail("MSP_TOKEN or MSP_TOKEN_FILE is required")
	}
	if tok != "" && !c.MSPToken.IsSet() {
		fail("MSP_TOKEN is blank")
	}

	// Trusted proxies.
	if v := strings.TrimSpace(getenv("TRUSTED_PROXIES")); v != "" {
		ps, err := ParsePrefixes(v)
		if err != nil {
			fail("TRUSTED_PROXIES: %v", err)
		}
		c.TrustedProxies = ps
	}

	if v := strings.TrimSpace(getenv("GROUP_CACHE_TTL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			fail("GROUP_CACHE_TTL: want a non-negative duration such as 60s")
		} else {
			c.GroupCacheTTL = d
		}
	}
	if v := strings.TrimSpace(getenv("DEFAULT_RATE_LIMIT_PER_MINUTE")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > maxRateLimitPerMinute {
			fail("DEFAULT_RATE_LIMIT_PER_MINUTE: want an integer 0..%d (0 = unlimited)", maxRateLimitPerMinute)
		} else {
			c.DefaultRateLimit = n
		}
	}
	if v := strings.TrimSpace(getenv("AUDIT_RETENTION_DAYS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > maxAuditRetentionInDays {
			fail("AUDIT_RETENTION_DAYS: want an integer 0..%d (0 = forever)", maxAuditRetentionInDays)
		} else {
			c.AuditRetentionDays = n
		}
	}
	if v := strings.TrimSpace(getenv("BOOTSTRAP_SECRET_FILE")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			fail("BOOTSTRAP_SECRET_FILE: want true or false")
		} else {
			c.BootstrapSecretFile = b
		}
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		fail("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// ParsePrefixes parses a comma-separated list of CIDRs or bare IPs.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := ParsePrefix(part)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// ParsePrefix parses one CIDR or bare IP address (a bare IP becomes a /32
// or /128). IPv4-mapped IPv6 addresses are unmapped.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a CIDR or IP address", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func orDefault(v, def string) string {
	if v = strings.TrimSpace(v); v != "" {
		return v
	}
	return def
}
