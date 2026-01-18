package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const banner = `
╔═══════════════════════════════════════╗
║         ALPHA SUITE - PortScan        ║
║       Fast Concurrent Port Scanner    ║
╚═══════════════════════════════════════╝
`

var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888,
}

var portServices = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	111:   "RPC",
	135:   "MSRPC",
	139:   "NetBIOS",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	1723:  "PPTP",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	8080:  "HTTP-Proxy",
	8443:  "HTTPS-Alt",
	8888:  "HTTP-Alt",
	27017: "MongoDB",
}

type ScanResult struct {
	Port    int
	Open    bool
	Service string
}

func main() {
	target := flag.String("target", "", "Target IP address or hostname")
	portRange := flag.String("ports", "1-1000", "Port range (e.g., 1-1000) or 'common' for common ports")
	threads := flag.Int("threads", 100, "Number of concurrent threads")
	timeout := flag.Int("timeout", 1000, "Connection timeout in milliseconds")
	verbose := flag.Bool("verbose", false, "Show closed ports too")
	flag.Parse()

	if *target == "" {
		fmt.Println(banner)
		fmt.Println("Usage: portscan -target <ip/hostname> [options]")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  portscan -target 192.168.1.1 -ports 1-65535 -threads 500")
		fmt.Println("  portscan -target example.com -ports common")
		os.Exit(1)
	}

	fmt.Println(banner)
	fmt.Printf("[*] Target: %s\n", *target)
	fmt.Printf("[*] Threads: %d\n", *threads)
	fmt.Printf("[*] Timeout: %dms\n", *timeout)

	// Resolve hostname
	ips, err := net.LookupIP(*target)
	if err != nil {
		fmt.Printf("[-] Failed to resolve hostname: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[*] Resolved IP: %s\n", ips[0].String())

	// Parse ports
	var ports []int
	if *portRange == "common" {
		ports = commonPorts
		fmt.Printf("[*] Scanning common ports (%d ports)\n", len(ports))
	} else {
		ports, err = parsePortRange(*portRange)
		if err != nil {
			fmt.Printf("[-] Invalid port range: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Port range: %s (%d ports)\n", *portRange, len(ports))
	}

	fmt.Println("\n[*] Starting scan...")
	startTime := time.Now()

	// Scan ports
	results := scanPorts(*target, ports, *threads, time.Duration(*timeout)*time.Millisecond)

	// Filter and sort results
	var openPorts []ScanResult
	for _, result := range results {
		if result.Open || *verbose {
			openPorts = append(openPorts, result)
		}
	}

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	// Print results
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("%-10s %-10s %-20s\n", "PORT", "STATE", "SERVICE")
	fmt.Println(strings.Repeat("-", 50))

	openCount := 0
	for _, result := range openPorts {
		state := "closed"
		if result.Open {
			state = "open"
			openCount++
		}
		fmt.Printf("%-10d %-10s %-20s\n", result.Port, state, result.Service)
	}

	elapsed := time.Since(startTime)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("\n[+] Scan completed in %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("[+] Found %d open ports out of %d scanned\n", openCount, len(ports))
}

func parsePortRange(portRange string) ([]int, error) {
	var ports []int

	// Handle comma-separated values and ranges
	parts := strings.Split(portRange, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range: %s", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, err
			}
			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid range: %d-%d", start, end)
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid port: %d", port)
			}
			ports = append(ports, port)
		}
	}

	return ports, nil
}

func scanPorts(target string, ports []int, threads int, timeout time.Duration) []ScanResult {
	results := make([]ScanResult, len(ports))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, threads)

	for i, port := range ports {
		wg.Add(1)
		go func(idx, p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := scanPort(target, p, timeout)
			results[idx] = result
		}(i, port)
	}

	wg.Wait()
	return results
}

func scanPort(target string, port int, timeout time.Duration) ScanResult {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)

	result := ScanResult{
		Port:    port,
		Open:    false,
		Service: getService(port),
	}

	if err == nil {
		conn.Close()
		result.Open = true
	}

	return result
}

func getService(port int) string {
	if service, ok := portServices[port]; ok {
		return service
	}
	return "unknown"
}
