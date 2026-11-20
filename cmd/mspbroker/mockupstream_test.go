package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"mspbroker/internal/upstream/mock"
)

// syncBuffer is a bytes.Buffer safe to read while the server goroutine writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}

type runningMock struct {
	addr    string
	out     *syncBuffer
	errb    *syncBuffer
	stop    func() int
	stopped bool
}

func startMock(t *testing.T, args []string, env map[string]string) *runningMock {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	rm := &runningMock{out: &syncBuffer{}, errb: &syncBuffer{}}
	addrCh := make(chan string, 1)
	codeCh := make(chan int, 1)
	go func() {
		codeCh <- mockUpstream(ctx, append([]string{"--listen", "127.0.0.1:0"}, args...), rm.out, rm.errb, envOf(env), func(a string) { addrCh <- a })
	}()
	select {
	case rm.addr = <-addrCh:
	case code := <-codeCh:
		cancel()
		t.Fatalf("exited early with %d: %s", code, rm.errb.String())
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("mock did not start")
	}
	rm.stop = func() int {
		if rm.stopped {
			return 0
		}
		rm.stopped = true
		cancel()
		select {
		case c := <-codeCh:
			return c
		case <-time.After(10 * time.Second):
			t.Error("mock did not stop")
			return -1
		}
	}
	t.Cleanup(func() { rm.stop() })
	return rm
}

func (rm *runningMock) get(t *testing.T, path, token string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+rm.addr+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b
}

func TestMockUpstreamDefaults(t *testing.T) {
	rm := startMock(t, nil, nil)
	if !strings.HasPrefix(rm.addr, "127.0.0.1:") {
		t.Errorf("addr %s", rm.addr)
	}
	if code, _ := rm.get(t, "/v2/boxes", ""); code != 401 {
		t.Errorf("no token: %d", code)
	}
	if code, _ := rm.get(t, "/v2/boxes", "wrong"); code != 401 {
		t.Errorf("wrong token: %d", code)
	}
	code, body := rm.get(t, "/v2/boxes", mock.DefaultToken)
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	var boxes []map[string]any
	if err := json.Unmarshal(body, &boxes); err != nil || len(boxes) != 5 {
		t.Fatalf("boxes: %v %s", err, body)
	}
	if code, body := rm.get(t, "/v2/devices?box="+mock.GID1, mock.DefaultToken); code != 200 || strings.Count(string(body), `"gid"`) != 1 {
		t.Errorf("filters off: %d %s", code, body)
	}
	if out := rm.out.String(); !strings.Contains(out, "listening on http://127.0.0.1:") || !strings.Contains(out, mock.DefaultToken) {
		t.Errorf("banner: %q", out)
	}
	if c := rm.stop(); c != 0 {
		t.Errorf("exit %d", c)
	}
	if out := rm.out.String(); !strings.Contains(out, "stopped") {
		t.Errorf("no stop message: %q", out)
	}
	if _, err := http.Get("http://" + rm.addr + "/v2/boxes"); err == nil {
		t.Error("still listening after stop")
	}
}

func TestMockUpstreamTokenFlagAndEnv(t *testing.T) {
	rm := startMock(t, []string{"--token", "flag-token-example"}, map[string]string{"MOCK_UPSTREAM_TOKEN": "env-token-example"})
	if code, _ := rm.get(t, "/v2/boxes", "flag-token-example"); code != 200 {
		t.Errorf("flag token rejected: %d", code)
	}
	for _, tok := range []string{"env-token-example", mock.DefaultToken} {
		if code, _ := rm.get(t, "/v2/boxes", tok); code != 401 {
			t.Errorf("%s accepted: %d", tok, code)
		}
	}
	if out := rm.out.String(); strings.Contains(out, "flag-token-example") {
		t.Errorf("custom token echoed: %q", out)
	}

	rm2 := startMock(t, nil, map[string]string{"MOCK_UPSTREAM_TOKEN": "env-token-example"})
	if code, _ := rm2.get(t, "/v2/boxes", "env-token-example"); code != 200 {
		t.Errorf("env token rejected: %d", code)
	}
}

func TestMockUpstreamIgnoreFilters(t *testing.T) {
	rm := startMock(t, []string{"--ignore-filters"}, nil)
	_, body := rm.get(t, "/v2/devices?box="+mock.GID1, mock.DefaultToken)
	if n := strings.Count(string(body), `"gid"`); n != 5 {
		t.Errorf("%d devices", n)
	}
	if out := rm.out.String(); !strings.Contains(out, "IGNORED") {
		t.Errorf("banner: %q", out)
	}
}

func TestMockUpstreamBadInput(t *testing.T) {
	var out, errb bytes.Buffer
	ctx := context.Background()
	if code := mockUpstream(ctx, []string{"--nope"}, &out, &errb, envOf(nil), nil); code != 2 {
		t.Errorf("bad flag: %d", code)
	}
	if code := mockUpstream(ctx, []string{"extra"}, &out, &errb, envOf(nil), nil); code != 2 || !strings.Contains(errb.String(), "unexpected argument") {
		t.Errorf("extra arg: %d %q", code, errb.String())
	}
	errb.Reset()
	if code := mockUpstream(ctx, []string{"--listen", "not-an-address"}, &out, &errb, envOf(nil), nil); code != 1 || errb.Len() == 0 {
		t.Errorf("bad listen: %d %q", code, errb.String())
	}
	if code := mockUpstream(ctx, []string{"-h"}, &out, &errb, envOf(nil), nil); code != 0 {
		t.Errorf("help: %d", code)
	}
}

func TestMockUpstreamAddressInUse(t *testing.T) {
	rm := startMock(t, nil, nil)
	var out, errb bytes.Buffer
	if code := mockUpstream(context.Background(), []string{"--listen", rm.addr}, &out, &errb, envOf(nil), nil); code != 1 {
		t.Errorf("exit %d", code)
	}
}

func TestRunDispatchesMockUpstream(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"mock-upstream", "--bogus"}, &out, &errb, envOf(nil)); code != 2 {
		t.Errorf("exit %d", code)
	}
	if code := run([]string{"help"}, &out, &errb, envOf(nil)); code != 0 || !strings.Contains(out.String(), "mock-upstream") {
		t.Errorf("usage lacks mock-upstream: %q", out.String())
	}
}
