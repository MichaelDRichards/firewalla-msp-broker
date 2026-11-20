package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"mspbroker/internal/api"
	"mspbroker/internal/audit"
	"mspbroker/internal/auth"
	"mspbroker/internal/config"
	"mspbroker/internal/redact"
	"mspbroker/internal/store"
	"mspbroker/internal/upstream"
)

const (
	checkTimeout    = 15 * time.Second
	shutdownTimeout = 15 * time.Second
	dbFileName      = "mspbroker.db"
)

// serve runs the broker until ctx is cancelled, then shuts down gracefully
// (in-flight requests get shutdownTimeout to finish). With --check it only
// validates the configuration and the upstream and exits. ready, if non-nil,
// is called with the bound address once the listener is up.
func serve(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, ready func(addr string)) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	check := fs.Bool("check", false, "validate the configuration and upstream reachability (GET /v2/boxes), then exit")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: mspbroker serve [--check]")
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
		fmt.Fprintf(stderr, "mspbroker: serve: unexpected argument %q\n", fs.Arg(0))
		return 2
	}

	cfg, err := config.Load(getenv, os.ReadFile)
	if err != nil {
		fmt.Fprintf(stderr, "mspbroker: config: %v\n", err)
		return 1
	}

	// Logging. Everything the broker logs goes through the scrubber, which
	// knows the upstream token and recognises key secrets by shape. The one
	// exception is the bootstrap logger: it prints the first admin secret,
	// once, and is used for nothing else.
	scrub := redact.New(cfg.MSPToken.Reveal())
	base := slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(scrub.Handler(base))
	bootstrapLog := slog.New(base)
	logger.Info(notice)

	up, err := upstream.New(upstream.Config{
		BaseURL: cfg.MSPBaseURL,
		Token:   cfg.MSPToken,
		Logger:  logger,
	})
	if err != nil {
		fmt.Fprintf(stderr, "mspbroker: upstream: %s\n", scrub.String(err.Error()))
		return 1
	}

	if *check {
		return runCheck(ctx, cfg, up, scrub, stdout, stderr)
	}

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		fmt.Fprintf(stderr, "mspbroker: data dir: %v\n", err)
		return 1
	}
	st, err := store.Open(ctx, filepath.Join(cfg.DataDir, dbFileName))
	if err != nil {
		fmt.Fprintf(stderr, "mspbroker: %v\n", err)
		return 1
	}
	defer st.Close()

	if _, err := api.Bootstrap(ctx, st, time.Now(), cfg.DataDir, cfg.BootstrapSecretFile, bootstrapLog); err != nil {
		fmt.Fprintf(stderr, "mspbroker: %v\n", err)
		return 1
	}

	authn := auth.New(auth.Config{
		Store:            st,
		TrustedProxies:   cfg.TrustedProxies,
		DefaultRateLimit: cfg.DefaultRateLimit,
	})
	srv, err := api.New(api.Config{
		Store:            st,
		Upstream:         up,
		Auth:             authn,
		Audit:            audit.New(st, scrub, logger),
		Logger:           logger,
		Scrub:            scrub,
		GroupCacheTTL:    cfg.GroupCacheTTL,
		DefaultRateLimit: cfg.DefaultRateLimit,
		Version:          version,
	})
	if err != nil {
		fmt.Fprintf(stderr, "mspbroker: %v\n", err)
		return 1
	}

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		fmt.Fprintf(stderr, "mspbroker: listen: %v\n", err)
		return 1
	}
	hs := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	scheme := "http"
	if cfg.TLSCertFile != "" {
		scheme = "https"
	}
	fmt.Fprintf(stdout, "mspbroker %s listening on %s://%s\n", version, scheme, ln.Addr())
	logger.Info("serving", "addr", ln.Addr().String(), "tls", scheme == "https", "config", cfg)
	if ready != nil {
		ready(ln.Addr().String())
	}

	done := make(chan error, 1)
	go func() {
		if cfg.TLSCertFile != "" {
			done <- hs.ServeTLS(ln, cfg.TLSCertFile, cfg.TLSKeyFile)
			return
		}
		done <- hs.Serve(ln)
	}()

	select {
	case err := <-done:
		fmt.Fprintf(stderr, "mspbroker: server stopped: %v\n", err)
		return 1
	case <-ctx.Done():
	}

	logger.Info("shutting down; waiting for in-flight requests")
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := hs.Shutdown(sctx); err != nil {
		logger.Warn("graceful shutdown timed out; closing connections", "error", err)
		_ = hs.Close()
	}
	logger.Info("stopped")
	return 0
}

// runCheck validates the configuration (already loaded) and asks the
// upstream for its boxes. The configuration is printed with the token
// redacted by type.
func runCheck(ctx context.Context, cfg *config.Config, up *upstream.Client, scrub *redact.Scrubber, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "config ok: %v\n", cfg)
	cctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	boxes, err := up.Boxes(cctx)
	if err != nil {
		fmt.Fprintf(stderr, "mspbroker: upstream check failed: %s\n", scrub.String(err.Error()))
		return 1
	}
	fmt.Fprintf(stdout, "upstream ok: GET /v2/boxes returned %d boxes\n", len(boxes))
	return 0
}
