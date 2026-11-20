#!/bin/sh
# Quality gate: gofmt, build, vet, staticcheck, tests (incl. the repository scan), govulncheck. Run from anywhere.
set -eu

cd "$(dirname "$0")/.."
export PATH="$PATH:$HOME/.local/go/bin:$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"

unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
	echo "gofmt needed on:" >&2
	echo "$unformatted" >&2
	exit 1
fi

go build ./...
go vet ./...
staticcheck ./...
go test -count=1 ./...
govulncheck ./...
echo "check: OK"
