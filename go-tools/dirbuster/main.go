package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const banner = `
╔═══════════════════════════════════════╗
║       ALPHA SUITE - DirBuster         ║
║    Directory & File Brute-forcer      ║
╚═══════════════════════════════════════╝
`

var defaultWordlist = []string{
	"admin", "administrator", "login", "wp-admin", "wp-login.php", "dashboard",
	"panel", "cpanel", "webmail", "mail", "api", "v1", "v2", "graphql",
	"config", "configuration", "settings", "setup", "install", "backup",
	"backups", "bak", "old", "tmp", "temp", "cache", "logs", "log",
	"uploads", "upload", "files", "file", "images", "image", "img", "assets",
	"static", "css", "js", "javascript", "scripts", "fonts", "media",
	"docs", "documentation", "doc", "readme", "readme.txt", "readme.md",
	"robots.txt", "sitemap.xml", "sitemap", ".htaccess", ".htpasswd",
	".git", ".git/config", ".git/HEAD", ".svn", ".env", ".env.local",
	"wp-config.php", "config.php", "database.php", "db.php", "connection.php",
	"phpinfo.php", "info.php", "test.php", "test", "debug", "server-status",
	"server-info", ".well-known", "security.txt", "humans.txt",
	"package.json", "composer.json", "Gemfile", "requirements.txt",
	"node_modules", "vendor", "bin", "app", "src", "public", "private",
	"internal", "secret", "secrets", "keys", "key", "creds", "credentials",
	"data", "db", "database", "sql", "mysql", "phpmyadmin", "adminer",
	"manager", "console", "shell", "cmd", "command", "terminal", "ssh",
	"ftp", "sftp", "status", "health", "ping", "version", "info",
}

var defaultExtensions = []string{"", ".php", ".html", ".js", ".txt", ".bak", ".old"}

type Result struct {
	URL          string
	StatusCode   int
	ContentLength int64
	RedirectURL  string
}

func main() {
	targetURL := flag.String("url", "", "Target URL to scan")
	wordlist := flag.String("wordlist", "", "Path to wordlist file")
	threads := flag.Int("threads", 20, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "HTTP timeout in seconds")
	extensions := flag.String("extensions", "", "File extensions to append (comma-separated, e.g., .php,.html,.txt)")
	statusCodes := flag.String("status", "200,201,204,301,302,307,308,401,403", "Status codes to show (comma-separated)")
	output := flag.String("output", "", "Output file to save results")
	userAgent := flag.String("user-agent", "Alpha-Suite-DirBuster/1.0", "Custom User-Agent header")
	followRedirects := flag.Bool("follow-redirects", false, "Follow redirects")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification")
	cookie := flag.String("cookie", "", "Cookie header value")
	flag.Parse()

	if *targetURL == "" {
		fmt.Println(banner)
		fmt.Println("Usage: dirbuster -url <target> [options]")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  dirbuster -url https://example.com -threads 50")
		fmt.Println("  dirbuster -url https://example.com -wordlist dirs.txt -extensions .php,.html")
		fmt.Println("  dirbuster -url https://example.com -status 200,301,403 -output results.txt")
		os.Exit(1)
	}

	// Validate URL
	parsedURL, err := url.Parse(*targetURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		fmt.Printf("[-] Invalid URL: %s\n", *targetURL)
		os.Exit(1)
	}

	fmt.Println(banner)
	fmt.Printf("[*] Target URL: %s\n", *targetURL)
	fmt.Printf("[*] Threads: %d\n", *threads)
	fmt.Printf("[*] Timeout: %ds\n", *timeout)

	// Load wordlist
	var words []string
	if *wordlist != "" {
		var err error
		words, err = loadWordlist(*wordlist)
		if err != nil {
			fmt.Printf("[-] Failed to load wordlist: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Loaded %d entries from wordlist\n", len(words))
	} else {
		words = defaultWordlist
		fmt.Printf("[*] Using built-in wordlist (%d entries)\n", len(words))
	}

	// Parse extensions
	var exts []string
	if *extensions != "" {
		for _, ext := range strings.Split(*extensions, ",") {
			ext = strings.TrimSpace(ext)
			if !strings.HasPrefix(ext, ".") && ext != "" {
				ext = "." + ext
			}
			exts = append(exts, ext)
		}
	} else {
		exts = defaultExtensions
	}
	fmt.Printf("[*] Extensions: %v\n", exts)

	// Parse status codes
	allowedCodes := make(map[int]bool)
	for _, code := range strings.Split(*statusCodes, ",") {
		var c int
		fmt.Sscanf(strings.TrimSpace(code), "%d", &c)
		allowedCodes[c] = true
	}
	fmt.Printf("[*] Status codes: %s\n", *statusCodes)

	// Create HTTP client
	client := createHTTPClient(*timeout, *followRedirects, *insecure)

	// Generate all paths to test
	var paths []string
	for _, word := range words {
		for _, ext := range exts {
			paths = append(paths, word+ext)
		}
	}
	fmt.Printf("[*] Total paths to test: %d\n", len(paths))

	fmt.Println("\n[*] Starting scan...")
	startTime := time.Now()

	// Scan paths
	results := scanPaths(*targetURL, paths, *threads, client, allowedCodes, *userAgent, *cookie)

	// Sort results by status code
	sort.Slice(results, func(i, j int) bool {
		if results[i].StatusCode != results[j].StatusCode {
			return results[i].StatusCode < results[j].StatusCode
		}
		return results[i].URL < results[j].URL
	})

	// Print results
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("DISCOVERED PATHS")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("%-50s %-10s %-15s\n", "URL", "STATUS", "SIZE")
	fmt.Println(strings.Repeat("-", 80))

	var outputLines []string
	for _, result := range results {
		size := fmt.Sprintf("%d", result.ContentLength)
		if result.ContentLength < 0 {
			size = "N/A"
		}
		displayURL := result.URL
		if len(displayURL) > 48 {
			displayURL = displayURL[:45] + "..."
		}

		line := fmt.Sprintf("%-50s %-10d %-15s", displayURL, result.StatusCode, size)
		fmt.Println(line)

		if result.RedirectURL != "" {
			fmt.Printf("    -> Redirects to: %s\n", result.RedirectURL)
		}

		outputLines = append(outputLines, fmt.Sprintf("%s [%d] [%s]", result.URL, result.StatusCode, size))
	}

	elapsed := time.Since(startTime)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("\n[+] Scan completed in %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("[+] Found %d paths\n", len(results))

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

func createHTTPClient(timeout int, followRedirects, insecure bool) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

func scanPaths(baseURL string, paths []string, threads int, client *http.Client, allowedCodes map[int]bool, userAgent, cookie string) []Result {
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup
	var count int64

	semaphore := make(chan struct{}, threads)
	total := len(paths)

	// Ensure base URL has no trailing slash
	baseURL = strings.TrimSuffix(baseURL, "/")

	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fullURL := baseURL + "/" + p
			result := checkPath(fullURL, client, userAgent, cookie)

			current := atomic.AddInt64(&count, 1)
			if current%50 == 0 {
				fmt.Printf("\r[*] Progress: %d/%d", current, total)
			}

			if result != nil && allowedCodes[result.StatusCode] {
				mu.Lock()
				results = append(results, *result)
				statusColor := getStatusColor(result.StatusCode)
				fmt.Printf("\r%s[+] Found: %-40s [%d]\033[0m\n", statusColor, p, result.StatusCode)
				mu.Unlock()
			}
		}(path)
	}

	wg.Wait()
	fmt.Printf("\r[*] Progress: %d/%d\n", total, total)

	return results
}

func checkPath(targetURL string, client *http.Client, userAgent, cookie string) *Result {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", userAgent)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Discard body to allow connection reuse
	io.Copy(io.Discard, resp.Body)

	result := &Result{
		URL:           targetURL,
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
	}

	// Capture redirect location
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		result.RedirectURL = resp.Header.Get("Location")
	}

	return result
}

func getStatusColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "\033[32m" // Green
	case code >= 300 && code < 400:
		return "\033[33m" // Yellow
	case code == 401 || code == 403:
		return "\033[35m" // Magenta
	case code >= 400 && code < 500:
		return "\033[31m" // Red
	default:
		return "\033[0m" // Default
	}
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
