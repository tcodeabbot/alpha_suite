# Alpha Suite - Security Testing Toolkit

A comprehensive security testing toolkit for penetration testers and security researchers. This suite includes custom Nuclei templates, Go-based security tools, and automation scripts.

> **Disclaimer**: This toolkit is intended for authorized security testing, educational purposes, and legitimate penetration testing engagements only. Always obtain proper authorization before testing any systems.

## Components

### Nuclei Templates (`nuclei-templates/`)
Custom templates for vulnerability detection:
- **CVEs**: Known vulnerability detection
- **Misconfigs**: Server and application misconfigurations
- **Exposures**: Sensitive file and information exposure
- **Vulnerabilities**: Common web vulnerabilities (SQLi, XSS, etc.)

### Go Tools (`go-tools/`)
1. **portscan** - Fast concurrent TCP port scanner
2. **subenum** - Subdomain enumeration tool
3. **dirbuster** - Directory and file brute-forcing tool

### Scripts (`scripts/`)
- **recon.sh** - Automated reconnaissance script

## Installation

### Prerequisites
- Go 1.21+
- Nuclei (`go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`)

### Build Go Tools
```bash
# Build all tools
cd go-tools/portscan && go build -o portscan . && cd ../..
cd go-tools/subenum && go build -o subenum . && cd ../..
cd go-tools/dirbuster && go build -o dirbuster . && cd ../..

# Or use the build script
./scripts/build.sh
```

## Usage

### Port Scanner
```bash
./go-tools/portscan/portscan -target 192.168.1.1 -ports 1-1000 -threads 100
```

### Subdomain Enumerator
```bash
./go-tools/subenum/subenum -domain example.com -wordlist wordlists/subdomains.txt -threads 50
```

### Directory Brute-forcer
```bash
./go-tools/dirbuster/dirbuster -url https://example.com -wordlist wordlists/directories.txt -threads 20
```

### Nuclei Templates
```bash
nuclei -t nuclei-templates/ -u https://example.com
```

### Recon Script
```bash
./scripts/recon.sh example.com
```

## License
MIT License - See LICENSE file for details.

## Author
Built for authorized security testing and educational purposes.
