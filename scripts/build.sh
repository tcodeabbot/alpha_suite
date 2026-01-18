#!/bin/bash

#############################################
#        ALPHA SUITE - Build Script         #
#############################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "╔═══════════════════════════════════════╗"
echo "║      ALPHA SUITE - Build Tools        ║"
echo "╚═══════════════════════════════════════╝"
echo ""

# Check Go installation
if ! command -v go &> /dev/null; then
    echo "[-] Go is not installed. Please install Go 1.21+ first."
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}')
echo "[*] Go version: $GO_VERSION"
echo ""

# Build port scanner
echo "[*] Building portscan..."
cd "$ROOT_DIR/go-tools/portscan"
go build -o portscan .
echo "[+] Built: go-tools/portscan/portscan"

# Build subdomain enumerator
echo "[*] Building subenum..."
cd "$ROOT_DIR/go-tools/subenum"
go build -o subenum .
echo "[+] Built: go-tools/subenum/subenum"

# Build directory brute-forcer
echo "[*] Building dirbuster..."
cd "$ROOT_DIR/go-tools/dirbuster"
go build -o dirbuster .
echo "[+] Built: go-tools/dirbuster/dirbuster"

# Make scripts executable
echo ""
echo "[*] Making scripts executable..."
chmod +x "$ROOT_DIR/scripts/"*.sh
echo "[+] Scripts are now executable"

echo ""
echo "╔═══════════════════════════════════════╗"
echo "║          Build Complete!              ║"
echo "╚═══════════════════════════════════════╝"
echo ""
echo "Tools built:"
echo "  - go-tools/portscan/portscan"
echo "  - go-tools/subenum/subenum"
echo "  - go-tools/dirbuster/dirbuster"
echo ""
echo "Run ./scripts/recon.sh <domain> to start reconnaissance"
