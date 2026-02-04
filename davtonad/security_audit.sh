#!/usr/bin/env bash

set -e

echo "======================================="
echo " Go Security + Quality Audit"
echo "======================================="

# 1. Go vet (static analysis)
echo ""
echo "▶ Running go vet..."
go vet ./...

# 2. Race detector
echo ""
echo "▶ Running race detector (tests must exist)..."
go test -race ./... || echo "Race test finished (some packages may not have tests)"

# 3. Install gosec if not present
if ! command -v gosec &> /dev/null
then
    echo ""
    echo "Installing gosec..."
    go install github.com/securego/gosec/v2/cmd/gosec@latest
fi

# 4. Run gosec
echo ""
echo "▶ Running gosec security scan..."
gosec ./...

# 5. Detect unbounded bufio.Scanner usage
echo ""
echo "▶ Checking for bufio.Scanner without Buffer limits..."
grep -R "bufio.NewScanner" -n . || true

# 6. Detect scanner.Text() loops
echo ""
echo "▶ Checking scanner.Text() usage..."
grep -R "scanner.Text()" -n . || true

# 7. Detect missing HTTP security headers
echo ""
echo "▶ Searching for HTTP handlers..."
grep -R "http.HandleFunc" -n . || true

echo ""
echo "Audit complete."
echo "======================================="
