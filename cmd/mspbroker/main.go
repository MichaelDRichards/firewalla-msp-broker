// Command mspbroker is the mspbroker server and (later) admin CLI.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "0.0.0-dev"

// notice is printed by --help (root and every subcommand) and logged at the
// start of serve. It is exact text: tests compare against it.
const notice = "Independent project; not affiliated with or endorsed by Firewalla Inc."

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version":
		if len(args) > 1 && isHelpFlag(args[1]) {
			fmt.Fprintln(stdout, "usage: mspbroker version")
			fmt.Fprintln(stdout, notice)
			return 0
		}
		fmt.Fprintf(stdout, "mspbroker %s\n", version)
		return 0
	case "serve":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return serve(ctx, args[1:], stdout, stderr, getenv, nil)
	case "mock-upstream":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return mockUpstream(ctx, args[1:], stdout, stderr, getenv, nil)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "mspbroker: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: mspbroker <command>")
	fmt.Fprintln(w, "  serve          run the broker (--check validates config and upstream, then exits)")
	fmt.Fprintln(w, "  mock-upstream  run a fake MSP API with placeholder data (demos, tests)")
	fmt.Fprintln(w, "  version        print the version")
	fmt.Fprintln(w, notice)
}

func isHelpFlag(s string) bool {
	return s == "-h" || s == "--help" || s == "-help" || s == "help"
}
