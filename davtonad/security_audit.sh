#!/usr/bin/env bash

set -euo pipefail

export GOCACHE="${GOCACHE:-/tmp/go-cache}"
export GOMODCACHE="${GOMODCACHE:-/tmp/go-mod-cache}"

echo "======================================="
echo "Go Security + Quality Audit"
echo "======================================="

echo ""
echo "Running go vet"
go vet ./...

echo ""
echo "Running tests"
go test ./...

echo ""
echo "Audit complete."
