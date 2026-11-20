package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"mspbroker/internal/upstream/mock"
)

const serveCanary = "mg-test-CANARY-0000"

var secretInLog = regexp.MustCompile(`secret=(mb_[0-9A-Za-z]+)`)

type runningBroker struct {
	addr string
	out  *syncBuffer
	errb *syncBuffer
	stop func() int // cancels and waits for the exit code
	code int
}

func startBroker(t *testing.T, env map[string]string) *runningBroker {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	g := &runningBroker{out: &syncBuffer{}, errb: &syncBuffer{}}
	if env["LISTEN_ADDR"] == "" {
		env["LISTEN_ADDR"] = "127.0.0.1:0"
	}
	addrCh := make(chan string, 1)
	codeCh := make(chan int, 1)
	go func() {
		codeCh <- serve(ctx, nil, g.out, g.errb, envOf(env), func(a string) { addrCh <- a })
	}()
	select {
	case g.addr = <-addrCh:
	case code := <-codeCh:
		cancel()
		t.Fatalf("serve exited early with %d: %s", code, g.errb.String())
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("serve did not start")
	}
	stopped := false
	g.stop = func() int {
		if stopped {
			return g.code
		}
		stopped = true
		cancel()
		select {
		case g.code = <-codeCh:
		case <-time.After(20 * time.Second):
			t.Fatal("serve did not stop")
		}
		return g.code
	}
	t.Cleanup(func() { g.stop() })
	return g
}

func (g *runningBroker) call(t *testing.T, secret, method, path, body string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+g.addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, b
}

func newUpstream(t *testing.T, opts ...mock.Option) (*mock.Mock, string) {
	t.Helper()
	m := mock.New(append([]mock.Option{mock.WithToken(serveCanary)}, opts...)...)
	srv := m.Start()
	t.Cleanup(srv.Close)
	return m, srv.URL
}

func brokerEnv(upURL, dataDir string) map[string]string {
	return map[string]string{"MSP_BASE_URL": upURL, "MSP_TOKEN": serveCanary, "DATA_DIR": dataDir}
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not JSON: %s", b)
	}
	return m
}

func TestServeBadConfig(t *testing.T) {
	var out, errb syncBuffer
	if code := serve(context.Background(), nil, &out, &errb, envOf(nil), nil); code != 1 || !strings.Contains(errb.String(), "MSP_BASE_URL") {
		t.Errorf("exit %d %q", code, errb.String())
	}
	if code := serve(context.Background(), []string{"--bogus"}, &out, &errb, envOf(nil), nil); code != 2 {
		t.Errorf("bad flag: exit %d", code)
	}
	if code := serve(context.Background(), []string{"extra"}, &out, &errb, envOf(nil), nil); code != 2 {
		t.Errorf("extra arg: exit %d", code)
	}
}

func TestServeCheck(t *testing.T) {
	_, upURL := newUpstream(t)
	dir := t.TempDir()

	var out, errb syncBuffer
	code := serve(context.Background(), []string{"--check"}, &out, &errb, envOf(brokerEnv(upURL, filepath.Join(dir, "data"))), nil)
	if code != 0 || !strings.Contains(out.String(), "config ok") || !strings.Contains(out.String(), "upstream ok") || !strings.Contains(out.String(), "5 boxes") {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out.String(), errb.String())
	}
	if strings.Contains(out.String()+errb.String(), serveCanary) {
		t.Error("--check output contains the upstream token")
	}
	// --check creates nothing: no data dir, no database, no bootstrap key.
	if _, err := os.Stat(filepath.Join(dir, "data")); !os.IsNotExist(err) {
		t.Error("--check created the data directory")
	}

	// A rejected token is reported without the token.
	env := brokerEnv(upURL, dir)
	env["MSP_TOKEN"] = "wrong-" + serveCanary
	out.Reset()
	errb.Reset()
	if code := serve(context.Background(), []string{"--check"}, &out, &errb, envOf(env), nil); code != 1 || !strings.Contains(errb.String(), "upstream check failed") {
		t.Errorf("wrong token: exit %d %q", code, errb.String())
	}
	if strings.Contains(out.String()+errb.String(), "wrong-"+serveCanary) {
		t.Error("check failure output contains the token")
	}

	// An unreachable upstream.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + ln.Addr().String()
	ln.Close()
	errb.Reset()
	if code := serve(context.Background(), []string{"--check"}, &out, &errb, envOf(brokerEnv(dead, dir)), nil); code != 1 {
		t.Errorf("unreachable upstream: exit %d", code)
	}
}

// The whole thing, over real sockets: bootstrap, key creation with the
// printed secret, scoped reads, restart, graceful stop.
func TestServeEndToEnd(t *testing.T) {
	m, upURL := newUpstream(t)
	dir := t.TempDir()
	env := brokerEnv(upURL, dir)

	g := startBroker(t, env)
	sm := secretInLog.FindStringSubmatch(g.errb.String())
	if sm == nil {
		t.Fatalf("no bootstrap secret in the log:\n%s", g.errb.String())
	}
	boot := sm[1]
	if n := strings.Count(g.errb.String(), boot); n != 1 {
		t.Errorf("bootstrap secret printed %d times", n)
	}
	if !strings.Contains(g.out.String(), "listening on http://") {
		t.Errorf("stdout: %s", g.out.String())
	}

	// Probes, unauthenticated.
	if code, h, b := g.call(t, "", "GET", "/healthz", ""); code != 200 || h.Get("X-Content-Type-Options") != "nosniff" || decode(t, b)["status"] != "ok" {
		t.Errorf("healthz: %d %s", code, b)
	}
	if code, _, b := g.call(t, "", "GET", "/readyz", ""); code != 200 {
		t.Errorf("readyz: %d %s", code, b)
	}
	if code, _, b := g.call(t, "", "GET", "/api/openapi.json", ""); code != 200 || decode(t, b)["openapi"] != "3.1.0" {
		t.Errorf("openapi: %d", code)
	}

	// Create a data key with the bootstrap admin secret, as the README does.
	body := `{"name":"demo-agent","kind":"data","scope":{"type":"boxes","gids":["` + mock.GID1 + `"]},"permissions":{"boxes":"read","alarms":"read"}}`
	code, _, b := g.call(t, boot, "POST", "/admin/v1/keys", body)
	if code != 201 {
		t.Fatalf("create key: %d %s", code, b)
	}
	secret := decode(t, b)["secret"].(string)

	code, _, b = g.call(t, secret, "GET", "/api/v1/me", "")
	if code != 200 || decode(t, b)["key"].(map[string]any)["name"] != "demo-agent" {
		t.Fatalf("me: %d %s", code, b)
	}
	code, _, b = g.call(t, secret, "GET", "/api/v1/alarms", "")
	if code != 200 || len(decode(t, b)["results"].([]any)) != 3 {
		t.Errorf("alarms: %d %s", code, b)
	}
	if code, _, b = g.call(t, secret, "GET", "/api/v1/boxes/"+mock.GID2+"/alarms", ""); code != 403 {
		t.Errorf("out of scope: %d %s", code, b)
	}
	if code, _, _ = g.call(t, boot, "GET", "/api/v1/alarms", ""); code != 403 {
		t.Errorf("bootstrap key reached data: %d", code)
	}
	if code, _, b = g.call(t, secret, "GET", "/admin/v1/keys", ""); code != 403 {
		t.Errorf("data key reached admin: %d %s", code, b)
	}
	// The audit trail is browsable by the admin and shows the data key's use.
	code, _, b = g.call(t, boot, "GET", "/admin/v1/audit?resource=alarms", "")
	if code != 200 || !strings.Contains(string(b), `"key_name_at_time":"demo-agent"`) || !strings.Contains(string(b), `"block_reason":"out_of_scope"`) {
		t.Errorf("audit: %d %s", code, b)
	}

	// Stop: clean exit, port released.
	if code := g.stop(); code != 0 {
		t.Fatalf("exit %d\n%s", code, g.errb.String())
	}
	if c, err := net.DialTimeout("tcp", g.addr, time.Second); err == nil {
		c.Close()
		t.Error("port still open after shutdown")
	}
	if !strings.Contains(g.errb.String(), "stopped") {
		t.Errorf("no shutdown log:\n%s", g.errb.String())
	}

	// Restart on the same data directory: no new bootstrap secret, old keys
	// keep working.
	g2 := startBroker(t, env)
	if secretInLog.MatchString(g2.errb.String()) {
		t.Errorf("second start printed a secret:\n%s", g2.errb.String())
	}
	if code, _, _ := g2.call(t, secret, "GET", "/api/v1/me", ""); code != 200 {
		t.Errorf("key lost across restart: %d", code)
	}
	if code, _, _ := g2.call(t, boot, "GET", "/admin/v1/keys", ""); code != 200 {
		t.Errorf("bootstrap key lost across restart: %d", code)
	}
	g2.stop()

	// No log line or stdout mentions the upstream token or any key secret
	// other than the one bootstrap print.
	for name, text := range map[string]string{"stderr 1": g.errb.String(), "stdout 1": g.out.String(), "stderr 2": g2.errb.String(), "stdout 2": g2.out.String()} {
		if strings.Contains(text, serveCanary) || strings.Contains(text, secret) || strings.Contains(text, secret[3:]) {
			t.Errorf("%s leaks a secret:\n%s", name, text)
		}
	}
	if strings.Contains(g2.errb.String(), boot) {
		t.Error("second start's log contains the bootstrap secret")
	}
	// The upstream saw only the broker's token.
	for _, r := range m.Requests() {
		if !r.Authenticated {
			t.Errorf("unauthenticated upstream request %s", r.Path)
		}
	}
}

func TestServeBootstrapSecretFile(t *testing.T) {
	_, upURL := newUpstream(t)
	dir := t.TempDir()
	env := brokerEnv(upURL, dir)
	env["BOOTSTRAP_SECRET_FILE"] = "true"
	g := startBroker(t, env)
	path := filepath.Join(dir, "bootstrap-admin-secret")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("no secret file: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	secret := strings.TrimSpace(string(raw))
	if strings.Contains(g.errb.String(), secret) || secretInLog.MatchString(g.errb.String()) {
		t.Errorf("secret also in the log:\n%s", g.errb.String())
	}
	if code, _, b := g.call(t, secret, "GET", "/admin/v1/keys", ""); code != 200 {
		t.Errorf("secret from file: %d %s", code, b)
	}
}

// Shutdown waits for a request that is already being served.
func TestServeGracefulShutdown(t *testing.T) {
	m, upURL := newUpstream(t)
	g := startBroker(t, brokerEnv(upURL, t.TempDir()))
	boot := secretInLog.FindStringSubmatch(g.errb.String())[1]
	code, _, b := g.call(t, boot, "POST", "/admin/v1/keys", `{"name":"slow","kind":"data","scope":{"type":"all"},"permissions":{"alarms":"read"}}`)
	if code != 201 {
		t.Fatalf("%d %s", code, b)
	}
	secret := decode(t, b)["secret"].(string)

	m.SetLatency(800 * time.Millisecond)
	type res struct {
		code int
		body []byte
	}
	ch := make(chan res, 1)
	go func() {
		c, _, bb := g.call(t, secret, "GET", "/api/v1/alarms", "")
		ch <- res{c, bb}
	}()
	// The request is now sitting in the slow upstream call; stop the broker.
	time.Sleep(250 * time.Millisecond)
	exit := make(chan int, 1)
	go func() { exit <- g.stop() }()
	select {
	case r := <-ch:
		if r.code != 200 || len(decode(t, r.body)["results"].([]any)) != 15 {
			t.Errorf("in-flight request: %d %s", r.code, r.body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("in-flight request never finished")
	}
	if c := <-exit; c != 0 {
		t.Errorf("exit %d", c)
	}
}
