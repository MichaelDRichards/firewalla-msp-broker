.PHONY: check build test redteam

check:
	sh scripts/check.sh

build:
	go build -o bin/mspbroker ./cmd/mspbroker

test:
	go test ./...

redteam:
	go test -count=1 -run TestRedTeam ./...
