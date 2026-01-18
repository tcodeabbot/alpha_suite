#!/bin/bash

#############################################
#        ALPHA SUITE - Recon Script         #
#     Automated Reconnaissance Toolkit      #
#############################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║           ALPHA SUITE - Reconnaissance                ║"
    echo "║         Automated Security Assessment Tool            ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Usage
usage() {
    echo -e "Usage: $0 <domain> [options]"
    echo ""
    echo "Options:"
    echo "  -o, --output DIR    Output directory (default: ./recon_<domain>)"
    echo "  -q, --quick         Quick scan (skip slow checks)"
    echo "  -v, --verbose       Verbose output"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 example.com -o /tmp/recon_output"
    echo "  $0 example.com -q -v"
    exit 1
}

# Logging functions
log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${PURPLE}  $1${NC}"
    echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Check if a command exists
check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# DNS enumeration
dns_enum() {
    local domain=$1
    local output_dir=$2

    log_section "DNS ENUMERATION"

    # Basic DNS records
    log_info "Querying DNS records for $domain..."

    echo "=== A Records ===" > "$output_dir/dns_records.txt"
    dig +short A "$domain" >> "$output_dir/dns_records.txt" 2>/dev/null

    echo -e "\n=== AAAA Records ===" >> "$output_dir/dns_records.txt"
    dig +short AAAA "$domain" >> "$output_dir/dns_records.txt" 2>/dev/null

    echo -e "\n=== MX Records ===" >> "$output_dir/dns_records.txt"
    dig +short MX "$domain" >> "$output_dir/dns_records.txt" 2>/dev/null

    echo -e "\n=== NS Records ===" >> "$output_dir/dns_records.txt"
    dig +short NS "$domain" >> "$output_dir/dns_records.txt" 2>/dev/null

    echo -e "\n=== TXT Records ===" >> "$output_dir/dns_records.txt"
    dig +short TXT "$domain" >> "$output_dir/dns_records.txt" 2>/dev/null

    echo -e "\n=== SOA Record ===" >> "$output_dir/dns_records.txt"
    dig +short SOA "$domain" >> "$output_dir/dns_records.txt" 2>/dev/null

    log_success "DNS records saved to dns_records.txt"

    # Try zone transfer
    log_info "Attempting zone transfer..."
    for ns in $(dig +short NS "$domain" 2>/dev/null); do
        ns_clean=$(echo "$ns" | sed 's/\.$//')
        result=$(dig @"$ns_clean" "$domain" AXFR +noall +answer 2>/dev/null)
        if [ -n "$result" ]; then
            echo "$result" > "$output_dir/zone_transfer_$ns_clean.txt"
            log_warning "Zone transfer successful from $ns_clean!"
        fi
    done
}

# Subdomain enumeration
subdomain_enum() {
    local domain=$1
    local output_dir=$2
    local script_dir=$3

    log_section "SUBDOMAIN ENUMERATION"

    # Check if our subenum tool exists
    if [ -f "$script_dir/../go-tools/subenum/subenum" ]; then
        log_info "Using Alpha Suite subenum..."
        "$script_dir/../go-tools/subenum/subenum" -domain "$domain" -output "$output_dir/subdomains.txt" -threads 50
    elif check_command subfinder; then
        log_info "Using subfinder..."
        subfinder -d "$domain" -o "$output_dir/subdomains.txt" -silent
    elif check_command amass; then
        log_info "Using amass..."
        amass enum -passive -d "$domain" -o "$output_dir/subdomains.txt"
    else
        log_warning "No subdomain enumeration tool found. Using basic DNS brute-force..."
        # Basic brute force with common subdomains
        for sub in www mail ftp admin api dev staging test beta portal vpn; do
            if host "$sub.$domain" &>/dev/null; then
                echo "$sub.$domain" >> "$output_dir/subdomains.txt"
            fi
        done
    fi

    if [ -f "$output_dir/subdomains.txt" ]; then
        count=$(wc -l < "$output_dir/subdomains.txt" | tr -d ' ')
        log_success "Found $count subdomains"
    fi
}

# HTTP probing
http_probe() {
    local domain=$1
    local output_dir=$2

    log_section "HTTP PROBING"

    log_info "Checking HTTP/HTTPS connectivity..."

    {
        echo "=== HTTP Check ==="
        curl -s -o /dev/null -w "HTTP Status: %{http_code}\nResponse Time: %{time_total}s\n" "http://$domain" 2>/dev/null || echo "HTTP not available"

        echo -e "\n=== HTTPS Check ==="
        curl -s -o /dev/null -w "HTTPS Status: %{http_code}\nResponse Time: %{time_total}s\n" "https://$domain" 2>/dev/null || echo "HTTPS not available"

        echo -e "\n=== Response Headers ==="
        curl -s -I "https://$domain" 2>/dev/null || curl -s -I "http://$domain" 2>/dev/null
    } > "$output_dir/http_probe.txt"

    log_success "HTTP probe results saved to http_probe.txt"
}

# Technology detection
tech_detect() {
    local domain=$1
    local output_dir=$2

    log_section "TECHNOLOGY DETECTION"

    log_info "Detecting technologies..."

    # Get headers for analysis
    headers=$(curl -s -I "https://$domain" 2>/dev/null || curl -s -I "http://$domain" 2>/dev/null)

    {
        echo "=== Server Headers ==="
        echo "$headers" | grep -i "^server:" || echo "No server header found"

        echo -e "\n=== Powered By ==="
        echo "$headers" | grep -i "x-powered-by" || echo "No X-Powered-By header found"

        echo -e "\n=== Technology Indicators ==="
        echo "$headers" | grep -iE "(x-aspnet|x-drupal|x-generator|x-wordpress)" || echo "No obvious indicators found"

        echo -e "\n=== Security Headers ==="
        echo "$headers" | grep -iE "(x-frame-options|x-xss-protection|x-content-type|strict-transport|content-security-policy)" || echo "Security headers check needed"

        echo -e "\n=== Cookies ==="
        echo "$headers" | grep -i "set-cookie" || echo "No cookies set"

    } > "$output_dir/technology.txt"

    # Check for common paths
    log_info "Checking common technology paths..."
    {
        echo -e "\n=== Path Detection ==="

        # WordPress
        wp_check=$(curl -s -o /dev/null -w "%{http_code}" "https://$domain/wp-admin/" 2>/dev/null)
        if [ "$wp_check" = "200" ] || [ "$wp_check" = "302" ]; then
            echo "WordPress: Detected (/wp-admin/ returned $wp_check)"
        fi

        # Drupal
        drupal_check=$(curl -s -o /dev/null -w "%{http_code}" "https://$domain/core/CHANGELOG.txt" 2>/dev/null)
        if [ "$drupal_check" = "200" ]; then
            echo "Drupal: Detected (/core/CHANGELOG.txt found)"
        fi

        # Git exposure
        git_check=$(curl -s -o /dev/null -w "%{http_code}" "https://$domain/.git/config" 2>/dev/null)
        if [ "$git_check" = "200" ]; then
            echo "CRITICAL: Git repository exposed!"
        fi

    } >> "$output_dir/technology.txt"

    log_success "Technology detection saved to technology.txt"
}

# Port scanning
port_scan() {
    local domain=$1
    local output_dir=$2
    local script_dir=$3
    local quick=$4

    log_section "PORT SCANNING"

    # Resolve domain to IP
    ip=$(dig +short A "$domain" | head -1)
    if [ -z "$ip" ]; then
        log_error "Could not resolve $domain to IP"
        return
    fi

    log_info "Target IP: $ip"

    # Check if our portscan tool exists
    if [ -f "$script_dir/../go-tools/portscan/portscan" ]; then
        log_info "Using Alpha Suite portscan..."
        if [ "$quick" = "true" ]; then
            "$script_dir/../go-tools/portscan/portscan" -target "$ip" -ports common > "$output_dir/ports.txt"
        else
            "$script_dir/../go-tools/portscan/portscan" -target "$ip" -ports 1-10000 -threads 200 > "$output_dir/ports.txt"
        fi
    elif check_command nmap; then
        log_info "Using nmap..."
        if [ "$quick" = "true" ]; then
            nmap -F -T4 "$ip" -oN "$output_dir/ports.txt"
        else
            nmap -sV -T4 "$ip" -oN "$output_dir/ports.txt"
        fi
    elif check_command nc; then
        log_info "Using netcat (limited scan)..."
        for port in 21 22 23 25 53 80 110 143 443 445 3306 3389 5432 8080; do
            if nc -z -w1 "$ip" "$port" 2>/dev/null; then
                echo "Port $port: open" >> "$output_dir/ports.txt"
            fi
        done
    else
        log_warning "No port scanning tool found"
    fi

    if [ -f "$output_dir/ports.txt" ]; then
        log_success "Port scan results saved to ports.txt"
    fi
}

# Vulnerability scanning with Nuclei
nuclei_scan() {
    local domain=$1
    local output_dir=$2
    local script_dir=$3

    log_section "VULNERABILITY SCANNING"

    if check_command nuclei; then
        log_info "Running Nuclei with Alpha Suite templates..."

        # Use our custom templates
        if [ -d "$script_dir/../nuclei-templates" ]; then
            nuclei -u "https://$domain" -t "$script_dir/../nuclei-templates/" -o "$output_dir/nuclei_results.txt" -silent

            if [ -f "$output_dir/nuclei_results.txt" ] && [ -s "$output_dir/nuclei_results.txt" ]; then
                count=$(wc -l < "$output_dir/nuclei_results.txt" | tr -d ' ')
                log_warning "Found $count potential vulnerabilities!"
            else
                log_success "No vulnerabilities found with custom templates"
            fi
        else
            log_warning "Alpha Suite templates not found"
        fi
    else
        log_warning "Nuclei not installed. Skipping vulnerability scan."
        log_info "Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    fi
}

# Directory brute-forcing
dir_bruteforce() {
    local domain=$1
    local output_dir=$2
    local script_dir=$3

    log_section "DIRECTORY BRUTE-FORCING"

    # Check if our dirbuster tool exists
    if [ -f "$script_dir/../go-tools/dirbuster/dirbuster" ]; then
        log_info "Using Alpha Suite dirbuster..."
        "$script_dir/../go-tools/dirbuster/dirbuster" -url "https://$domain" -threads 30 -output "$output_dir/directories.txt"
    elif check_command gobuster; then
        log_info "Using gobuster..."
        gobuster dir -u "https://$domain" -w /usr/share/wordlists/dirb/common.txt -o "$output_dir/directories.txt" -q 2>/dev/null
    elif check_command ffuf; then
        log_info "Using ffuf..."
        ffuf -u "https://$domain/FUZZ" -w /usr/share/wordlists/dirb/common.txt -o "$output_dir/directories.txt" -s 2>/dev/null
    else
        log_warning "No directory brute-forcing tool found"
    fi

    if [ -f "$output_dir/directories.txt" ]; then
        log_success "Directory scan results saved to directories.txt"
    fi
}

# Generate report
generate_report() {
    local domain=$1
    local output_dir=$2

    log_section "GENERATING REPORT"

    report_file="$output_dir/REPORT.txt"

    {
        echo "╔═══════════════════════════════════════════════════════════════════╗"
        echo "║                    ALPHA SUITE RECON REPORT                       ║"
        echo "╚═══════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Target: $domain"
        echo "Date: $(date)"
        echo "Output Directory: $output_dir"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "SUMMARY"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

        if [ -f "$output_dir/subdomains.txt" ]; then
            echo "Subdomains found: $(wc -l < "$output_dir/subdomains.txt" | tr -d ' ')"
        fi

        if [ -f "$output_dir/ports.txt" ]; then
            echo "Open ports: $(grep -c "open" "$output_dir/ports.txt" 2>/dev/null || echo "See ports.txt")"
        fi

        if [ -f "$output_dir/nuclei_results.txt" ]; then
            echo "Potential vulnerabilities: $(wc -l < "$output_dir/nuclei_results.txt" | tr -d ' ')"
        fi

        if [ -f "$output_dir/directories.txt" ]; then
            echo "Directories found: $(wc -l < "$output_dir/directories.txt" | tr -d ' ')"
        fi

        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "FILES GENERATED"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        ls -la "$output_dir"

    } > "$report_file"

    log_success "Report generated: $report_file"
}

# Main function
main() {
    # Parse arguments
    DOMAIN=""
    OUTPUT_DIR=""
    QUICK=false
    VERBOSE=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -q|--quick)
                QUICK=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                print_banner
                usage
                ;;
            *)
                if [ -z "$DOMAIN" ]; then
                    DOMAIN="$1"
                fi
                shift
                ;;
        esac
    done

    # Validate domain
    if [ -z "$DOMAIN" ]; then
        print_banner
        usage
    fi

    # Setup output directory
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="./recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
    fi

    # Get script directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Print banner and start
    print_banner

    log_info "Target: $DOMAIN"
    log_info "Output: $OUTPUT_DIR"
    log_info "Quick mode: $QUICK"

    # Create output directory
    mkdir -p "$OUTPUT_DIR"

    # Run reconnaissance modules
    START_TIME=$(date +%s)

    dns_enum "$DOMAIN" "$OUTPUT_DIR"
    subdomain_enum "$DOMAIN" "$OUTPUT_DIR" "$SCRIPT_DIR"
    http_probe "$DOMAIN" "$OUTPUT_DIR"
    tech_detect "$DOMAIN" "$OUTPUT_DIR"
    port_scan "$DOMAIN" "$OUTPUT_DIR" "$SCRIPT_DIR" "$QUICK"

    if [ "$QUICK" != "true" ]; then
        nuclei_scan "$DOMAIN" "$OUTPUT_DIR" "$SCRIPT_DIR"
        dir_bruteforce "$DOMAIN" "$OUTPUT_DIR" "$SCRIPT_DIR"
    fi

    generate_report "$DOMAIN" "$OUTPUT_DIR"

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    log_section "RECONNAISSANCE COMPLETE"
    log_success "Duration: ${DURATION}s"
    log_success "Results saved to: $OUTPUT_DIR"
}

# Run main
main "$@"
