package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const banner = `
╔═══════════════════════════════════════╗
║        ALPHA SUITE - SubEnum          ║
║     Subdomain Enumeration Tool        ║
╚═══════════════════════════════════════╝
`

var defaultSubdomains = []string{
	"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
	"dns", "dns1", "dns2", "mx", "mx1", "mx2", "vpn", "proxy", "admin", "portal",
	"api", "dev", "staging", "test", "beta", "demo", "app", "apps", "blog",
	"cdn", "cloud", "git", "gitlab", "github", "jenkins", "jira", "confluence",
	"docs", "help", "support", "status", "monitor", "grafana", "kibana", "elastic",
	"db", "database", "mysql", "postgres", "redis", "mongo", "cache", "memcache",
	"auth", "login", "sso", "oauth", "ldap", "ad", "internal", "intranet", "extranet",
	"secure", "ssl", "shop", "store", "payment", "billing", "checkout", "cart",
	"m", "mobile", "static", "assets", "images", "img", "media", "files", "download",
	"upload", "backup", "bak", "old", "new", "v1", "v2", "api-v1", "api-v2",
	"sandbox", "stage", "uat", "qa", "prod", "production", "live", "web", "www1", "www2",
}

type Result struct {
	Subdomain string
	IP        []string
	CNAME     []string
}

func main() {
	domain := flag.String("domain", "", "Target domain to enumerate")
	wordlist := flag.String("wordlist", "", "Path to wordlist file (optional, uses built-in list if not provided)")
	threads := flag.Int("threads", 50, "Number of concurrent threads")
	timeout := flag.Int("timeout", 3, "DNS timeout in seconds")
	output := flag.String("output", "", "Output file to save results")
	resolver := flag.String("resolver", "", "Custom DNS resolver (e.g., 8.8.8.8)")
	showIP := flag.Bool("show-ip", true, "Show resolved IP addresses")
	flag.Parse()

	if *domain == "" {
		fmt.Println(banner)
		fmt.Println("Usage: subenum -domain <domain> [options]")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  subenum -domain example.com -threads 100")
		fmt.Println("  subenum -domain example.com -wordlist subdomains.txt -output results.txt")
		fmt.Println("  subenum -domain example.com -resolver 8.8.8.8")
		os.Exit(1)
	}

	fmt.Println(banner)
	fmt.Printf("[*] Target domain: %s\n", *domain)
	fmt.Printf("[*] Threads: %d\n", *threads)
	fmt.Printf("[*] Timeout: %ds\n", *timeout)

	// Load wordlist
	var subdomains []string
	if *wordlist != "" {
		var err error
		subdomains, err = loadWordlist(*wordlist)
		if err != nil {
			fmt.Printf("[-] Failed to load wordlist: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Loaded %d entries from wordlist\n", len(subdomains))
	} else {
		subdomains = defaultSubdomains
		fmt.Printf("[*] Using built-in wordlist (%d entries)\n", len(subdomains))
	}

	// Setup resolver
	var resolverAddr string
	if *resolver != "" {
		resolverAddr = *resolver + ":53"
		fmt.Printf("[*] Using custom resolver: %s\n", *resolver)
	}

	fmt.Println("\n[*] Starting enumeration...")
	startTime := time.Now()

	// Enumerate subdomains
	results := enumerate(*domain, subdomains, *threads, time.Duration(*timeout)*time.Second, resolverAddr)

	// Sort results
	sort.Slice(results, func(i, j int) bool {
		return results[i].Subdomain < results[j].Subdomain
	})

	// Print results
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("DISCOVERED SUBDOMAINS")
	fmt.Println(strings.Repeat("=", 70))

	if *showIP {
		fmt.Printf("%-40s %-30s\n", "SUBDOMAIN", "IP ADDRESS(ES)")
		fmt.Println(strings.Repeat("-", 70))
	}

	var outputLines []string
	for _, result := range results {
		if *showIP {
			ips := strings.Join(result.IP, ", ")
			if len(ips) > 28 {
				ips = ips[:25] + "..."
			}
			line := fmt.Sprintf("%-40s %-30s", result.Subdomain, ips)
			fmt.Println(line)
			outputLines = append(outputLines, result.Subdomain)
		} else {
			fmt.Println(result.Subdomain)
			outputLines = append(outputLines, result.Subdomain)
		}
	}

	elapsed := time.Since(startTime)
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("\n[+] Enumeration completed in %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("[+] Found %d subdomains\n", len(results))

	// Save to file
	if *output != "" {
		err := saveResults(*output, outputLines)
		if err != nil {
			fmt.Printf("[-] Failed to save results: %v\n", err)
		} else {
			fmt.Printf("[+] Results saved to %s\n", *output)
		}
	}
}

func loadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	return lines, scanner.Err()
}

func enumerate(domain string, subdomains []string, threads int, timeout time.Duration, resolver string) []Result {
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup
	var count int64

	semaphore := make(chan struct{}, threads)
	total := len(subdomains)

	// Create custom resolver if specified
	var customResolver *net.Resolver
	if resolver != "" {
		customResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "udp", resolver)
			},
		}
	}

	for _, sub := range subdomains {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fqdn := subdomain + "." + domain
			result := resolve(fqdn, timeout, customResolver)

			current := atomic.AddInt64(&count, 1)
			if current%100 == 0 {
				fmt.Printf("\r[*] Progress: %d/%d", current, total)
			}

			if result != nil {
				mu.Lock()
				results = append(results, *result)
				fmt.Printf("\r[+] Found: %-50s\n", fqdn)
				mu.Unlock()
			}
		}(sub)
	}

	wg.Wait()
	fmt.Printf("\r[*] Progress: %d/%d\n", total, total)

	return results
}

func resolve(fqdn string, timeout time.Duration, customResolver *net.Resolver) *Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var resolver *net.Resolver
	if customResolver != nil {
		resolver = customResolver
	} else {
		resolver = net.DefaultResolver
	}

	// Try to resolve A records
	ips, err := resolver.LookupIP(ctx, "ip4", fqdn)
	if err != nil {
		return nil
	}

	if len(ips) == 0 {
		return nil
	}

	result := &Result{
		Subdomain: fqdn,
	}

	for _, ip := range ips {
		result.IP = append(result.IP, ip.String())
	}

	// Try to get CNAME
	cname, err := resolver.LookupCNAME(ctx, fqdn)
	if err == nil && cname != fqdn+"." {
		result.CNAME = append(result.CNAME, strings.TrimSuffix(cname, "."))
	}

	return result
}

func saveResults(path string, results []string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, line := range results {
		_, err := file.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}

	return nil
}
