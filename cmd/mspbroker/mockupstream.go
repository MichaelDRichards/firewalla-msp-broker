package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"mspbroker/internal/upstream/mock"
)

const defaultMockListen = "127.0.0.1:8099"

// mockUpstream runs the standalone mock MSP API until ctx is cancelled, so a
// demo or UI developer needs no MSP account. ready, if non-nil, is called
// with the bound address once the listener is up.
func mockUpstream(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, ready func(addr string)) int {
	fs := flag.NewFlagSet("mock-upstream", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", defaultMockListen, "address to listen on")
	token := fs.String("token", "", "token the mock accepts (default: $MOCK_UPSTREAM_TOKEN, else a built-in placeholder)")
	ignore := fs.Bool("ignore-filters", false, "ignore query, box, group and owner filters and return everything")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: mspbroker mock-upstream [--listen addr] [--token token] [--ignore-filters]")
		fs.PrintDefaults()
		fmt.Fprintln(stderr, notice)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "mspbroker: mock-upstream: unexpected argument %q\n", fs.Arg(0))
		return 2
	}

	tok := *token
	if tok == "" {
		tok = getenv("MOCK_UPSTREAM_TOKEN")
	}
	custom := tok != ""
	if !custom {
		tok = mock.DefaultToken
	}
	m := mock.New(mock.WithToken(tok), mock.WithIgnoreFilters(*ignore))

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(stderr, "mspbroker: mock-upstream: %v\n", err)
		return 1
	}
	srv := &http.Server{Handler: m, ReadHeaderTimeout: 10 * time.Second}

	fmt.Fprintf(stdout, "mock upstream listening on http://%s\n", ln.Addr())
	if custom {
		fmt.Fprintln(stdout, "token: as given (not printed)")
	} else {
		fmt.Fprintf(stdout, "token: %s (placeholder; use --token to change)\n", tok)
	}
	if *ignore {
		fmt.Fprintln(stdout, "filters are IGNORED: every list returns everything")
	}
	if ready != nil {
		ready(ln.Addr().String())
	}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case err := <-done:
		fmt.Fprintf(stderr, "mspbroker: mock-upstream: %v\n", err)
		return 1
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil {
		_ = srv.Close()
	}
	fmt.Fprintln(stdout, "mock upstream stopped")
	return 0
}
