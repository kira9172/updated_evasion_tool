package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
)

// --- Configuration Structs ---

// Config holds all configuration from the yaml file.
type Config struct {
	Targets  []string `yaml:"targets"`
	Proxies  []string `yaml:"proxies"`
	Settings Settings `yaml:"settings"`
}

// Settings define the operational parameters for requests.
type Settings struct {
	RequestCount  int               `yaml:"request_count"`
	MaxRetries    int               `yaml:"max_retries"`
	TlsProfile    string            `yaml:"tls_profile"`
	UseCookies    bool              `yaml:"use_cookies"`
	CustomHeaders map[string]string `yaml:"custom_headers"`
	Delay         Delay             `yaml:"delay_ms"`
}

// Delay specifies the min/max wait time between requests.
type Delay struct {
	Min int `yaml:"min"`
	Max int `yaml:"max"`
}

// --- Proxy Manager ---

// ProxyInfo stores details for a single proxy.
type ProxyInfo struct {
	URL    *url.URL
	Scheme string
}

// ProxyManager handles thread-safe, round-robin proxy rotation with health tracking.
type ProxyManager struct {
	proxies     []ProxyInfo
	healthyOnly []int // indices of healthy proxies
	index       int
	mutex       sync.Mutex
	lastCheck   time.Time
}

// NewProxyManager creates and initializes a proxy manager, parsing and validating proxy strings.
func NewProxyManager(proxyStrings []string) (*ProxyManager, error) {
	if len(proxyStrings) == 0 {
		return nil, fmt.Errorf("proxy list cannot be empty")
	}

	proxies := make([]ProxyInfo, 0, len(proxyStrings))
	for _, pStr := range proxyStrings {
		// Default to http scheme if not specified for backward compatibility
		if !strings.Contains(pStr, "://") {
			pStr = "http://" + pStr
		}
		parsedURL, err := url.Parse(pStr)
		if err != nil {
			log.Printf("Warning: Skipping invalid proxy URL '%s': %v", pStr, err)
			continue
		}
		proxies = append(proxies, ProxyInfo{URL: parsedURL, Scheme: parsedURL.Scheme})
	}

	if len(proxies) == 0 {
		return nil, fmt.Errorf("no valid proxies found in the list")
	}

	// Initialize all proxies as potentially healthy
	healthyIndices := make([]int, len(proxies))
	for i := range healthyIndices {
		healthyIndices[i] = i
	}

	return &ProxyManager{
		proxies:     proxies,
		healthyOnly: healthyIndices,
		lastCheck:   time.Now(),
	}, nil
}

// GetNextProxy safely rotates to the next healthy proxy.
func (pm *ProxyManager) GetNextProxy() ProxyInfo {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Use healthy proxies if available, otherwise fall back to all proxies
	if len(pm.healthyOnly) > 0 {
		healthyIndex := pm.healthyOnly[pm.index%len(pm.healthyOnly)]
		pm.index = (pm.index + 1) % len(pm.healthyOnly)
		return pm.proxies[healthyIndex]
	}

	// Fallback to all proxies if none are marked healthy
	proxy := pm.proxies[pm.index%len(pm.proxies)]
	pm.index = (pm.index + 1) % len(pm.proxies)
	return proxy
}

// MarkProxyUnhealthy removes a proxy from the healthy rotation temporarily
func (pm *ProxyManager) MarkProxyUnhealthy(proxyURL *url.URL) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Find the proxy index
	for i, proxy := range pm.proxies {
		if proxy.URL.String() == proxyURL.String() {
			// Remove from healthy list
			newHealthy := make([]int, 0, len(pm.healthyOnly))
			for _, idx := range pm.healthyOnly {
				if idx != i {
					newHealthy = append(newHealthy, idx)
				}
			}
			pm.healthyOnly = newHealthy
			break
		}
	}
}

// --- TLS Profile & Header Definitions ---

var (
	// browserProfiles maps readable names to uTLS ClientHelloIDs.
	browserProfiles = map[string]utls.ClientHelloID{
		"chrome":  utls.HelloChrome_120,
		"firefox": utls.HelloFirefox_120,
		"safari":  utls.HelloSafari_16_0,
	}
	// browserHeaders maps ClientHelloIDs to consistent browser headers.
	browserHeaders = map[utls.ClientHelloID]http.Header{
		utls.HelloChrome_120: {
			"sec-ch-ua":                 {`"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`},
			"sec-ch-ua-mobile":          {`?0`},
			"sec-ch-ua-platform":        {`"Windows"`},
			"upgrade-insecure-requests": {`1`},
			"user-agent":                {`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`},
			"accept":                    {`text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`},
			"sec-fetch-site":            {`none`},
			"sec-fetch-mode":            {`navigate`},
			"sec-fetch-user":            {`?1`},
			"sec-fetch-dest":            {`document`},
			"accept-encoding":           {`gzip, deflate, br`},
			"accept-language":           {`en-US,en;q=0.9`},
		},
		utls.HelloFirefox_120: {
			"user-agent":                {`Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0`},
			"accept":                    {`text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8`},
			"accept-language":           {`en-US,en;q=0.5`},
			"accept-encoding":           {`gzip, deflate, br`},
			"upgrade-insecure-requests": {`1`},
			"sec-fetch-dest":            {`document`},
			"sec-fetch-mode":            {`navigate`},
			"sec-fetch-site":            {`none`},
			"sec-fetch-user":            {`?1`},
		},
		utls.HelloSafari_16_0: {
			"user-agent":      {`Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15`},
			"accept":          {`text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`},
			"accept-language": {`en-US,en;q=0.9`},
			"accept-encoding": {`gzip, deflate, br`},
		},
	}
)

// selectClientProfile chooses a TLS fingerprint and matching headers, randomizing if requested.
func selectClientProfile(profileName string) (utls.ClientHelloID, http.Header) {
	profileName = strings.ToLower(profileName)
	if profileName == "random" {
		keys := make([]utls.ClientHelloID, 0, len(browserHeaders))
		for k := range browserHeaders {
			keys = append(keys, k)
		}
		selectedKey := keys[rand.Intn(len(keys))]
		return selectedKey, browserHeaders[selectedKey].Clone() // Clone to prevent race conditions
	}
	if profile, ok := browserProfiles[profileName]; ok {
		return profile, browserHeaders[profile].Clone()
	}
	log.Printf("Warning: Unknown profile '%s', defaulting to random.", profileName)
	return selectClientProfile("random")
}

// --- Core Logic ---

func main() {
	// Setup graceful shutdown handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Printf("Shutdown signal received, finishing current requests...")
		cancel()
	}()

	// 1. Load and validate Configuration
	configFile, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatalf("Error reading config.yaml: %v", err)
	}
	var config Config
	if err := yaml.Unmarshal(configFile, &config); err != nil {
		log.Fatalf("Error parsing config.yaml: %v", err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	// 2. Initialize Proxy Manager
	proxyManager, err := NewProxyManager(config.Proxies)
	if err != nil {
		log.Fatalf("Failed to initialize proxy manager: %v", err)
	}
	log.Printf("Successfully loaded %d proxies.", len(proxyManager.proxies))

	// 3. Setup Session (Cookie Jar)
	var jar http.CookieJar
	if config.Settings.UseCookies {
		jar, _ = cookiejar.New(nil)
	}

	// 4. Main Request Loop with graceful shutdown support
	successCount := 0
	for successCount < config.Settings.RequestCount {
		// Check for shutdown signal
		select {
		case <-ctx.Done():
			log.Printf("Shutting down gracefully. Completed %d/%d requests.", successCount, config.Settings.RequestCount)
			return
		default:
		}
		targetURL := config.Targets[rand.Intn(len(config.Targets))]
		var resp *http.Response

		// 5. Retry Logic Loop
		for i := 0; i < config.Settings.MaxRetries; i++ {
			proxyInfo := proxyManager.GetNextProxy()

			// Select new identity for each attempt
			clientProfile, headers := selectClientProfile(config.Settings.TlsProfile)
			for key, val := range config.Settings.CustomHeaders {
				headers.Set(key, val)
			}

			// Create a uTLS-powered HTTP client with proxy support and connection limits
			client := &http.Client{
				Jar:     jar,
				Timeout: 45 * time.Second, // Overall request timeout for stability
				Transport: &http.Transport{
					MaxIdleConns:        10, // Limit idle connections for stability
					MaxIdleConnsPerHost: 2,  // Conservative per-host limit
					IdleConnTimeout:     30 * time.Second,
					// This function dials the proxy and wraps the connection with uTLS
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						var dialer proxy.Dialer = &net.Dialer{Timeout: 30 * time.Second}
						var conn net.Conn
						var err error

						// Dial through the appropriate proxy type
						switch proxyInfo.Scheme {
						case "socks5":
							var auth *proxy.Auth
							if user := proxyInfo.URL.User; user != nil {
								password, _ := user.Password()
								auth = &proxy.Auth{User: user.Username(), Password: password}
							}
							dialer, err = proxy.SOCKS5("tcp", proxyInfo.URL.Host, auth, dialer)
							if err != nil {
								return nil, fmt.Errorf("failed to create socks5 dialer: %w", err)
							}
							conn, err = dialer.(proxy.ContextDialer).DialContext(ctx, network, addr)
						default: // http/https
							conn, err = dialer.Dial(network, addr)
						}
						if err != nil {
							return nil, fmt.Errorf("proxy dial failed: %w", err)
						}

						// Wrap the connection with uTLS
						config := &utls.Config{ServerName: strings.Split(addr, ":")[0]}
						uTLSConn := utls.UClient(conn, config, clientProfile)

						if err := uTLSConn.HandshakeContext(ctx); err != nil {
							return nil, fmt.Errorf("uTLS handshake failed: %w", err)
						}

						return uTLSConn, nil
					},
					Proxy:                 http.ProxyURL(proxyInfo.URL), // Only used for http/https proxies
					ResponseHeaderTimeout: 30 * time.Second,
					TLSHandshakeTimeout:   15 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				},
				// Disable automatic redirects to handle them manually
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			// For SOCKS5, the transport's Proxy field must be nil
			if proxyInfo.Scheme == "socks5" {
				client.Transport.(*http.Transport).Proxy = nil
			}

			// Create request with context for timeout control
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
			if err != nil {
				log.Printf("[ATTEMPT %d/%d] FAILED: Request creation error: %v", i+1, config.Settings.MaxRetries, err)
				continue
			}
			req.Header = headers

			resp, err = client.Do(req)
			if err != nil {
				// More discreet error logging for stealth
				log.Printf("[%d/%d] Retry needed (proxy rotation)", i+1, config.Settings.MaxRetries)

				// Mark proxy as potentially unhealthy if it's a connection error
				if strings.Contains(err.Error(), "connection") || strings.Contains(err.Error(), "timeout") {
					proxyManager.MarkProxyUnhealthy(proxyInfo.URL)
				}

				time.Sleep(time.Duration(1000+rand.Intn(2000)) * time.Millisecond) // Randomized backoff
				continue
			}
			// Ensure response body is always closed for resource cleanup
			defer func() {
				if resp != nil && resp.Body != nil {
					resp.Body.Close()
				}
			}()

			// 6. Analyze Response
			status := analyzeResponse(resp)
			// More discreet logging - only log essential info
			if status == "SUCCESS" {
				log.Printf("[%d/%d] OK", i+1, config.Settings.MaxRetries)
			} else {
				log.Printf("[%d/%d] %s - rotating", i+1, config.Settings.MaxRetries, status)
			}

			if status == "SUCCESS" {
				break // Exit retry loop
			}

			// Handle redirects manually to maintain control
			if status == "REDIRECT" {
				locationHeader := resp.Header.Get("Location")
				if locationHeader == "" {
					log.Printf("[%d/%d] Invalid redirect", i+1, config.Settings.MaxRetries)
				} else if newURL, err := resp.Request.URL.Parse(locationHeader); err != nil {
					log.Printf("[%d/%d] Redirect parse error", i+1, config.Settings.MaxRetries)
				} else {
					targetURL = newURL.String()
					log.Printf("--> Following redirect")
					i = -1 // Reset retry counter for the new URL
				}
				resp.Body.Close()
				continue
			}

			// If blocked or failed, the loop will continue to the next retry
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}

		// Check final status after all retries
		if resp != nil {
			if analyzeResponse(resp) == "SUCCESS" {
				successCount++
				log.Printf("Progress: %d/%d", successCount, config.Settings.RequestCount)
			} else {
				log.Printf("Request failed - continuing")
			}
			if resp.Body != nil {
				resp.Body.Close()
			}
		}

		// 7. Randomized Delay with more realistic timing patterns
		if successCount < config.Settings.RequestCount {
			// Add extra randomization to mimic human browsing patterns
			baseDelay := rand.Intn(config.Settings.Delay.Max-config.Settings.Delay.Min+1) + config.Settings.Delay.Min
			// Occasionally add longer pauses (10% chance) to simulate reading/thinking
			if rand.Float32() < 0.1 {
				baseDelay += rand.Intn(5000) + 2000 // 2-7 second additional pause
			}
			time.Sleep(time.Duration(baseDelay) * time.Millisecond)
		}
	}
	log.Printf("Session completed: %d requests", config.Settings.RequestCount)
}

// validateConfig ensures the configuration is safe and complete
func validateConfig(config *Config) error {
	if len(config.Targets) == 0 {
		return fmt.Errorf("no target URLs specified")
	}
	if len(config.Proxies) == 0 {
		return fmt.Errorf("no proxies specified")
	}
	if config.Settings.RequestCount <= 0 {
		return fmt.Errorf("request_count must be positive")
	}
	if config.Settings.MaxRetries < 1 {
		return fmt.Errorf("max_retries must be at least 1")
	}
	if config.Settings.Delay.Min < 0 || config.Settings.Delay.Max < config.Settings.Delay.Min {
		return fmt.Errorf("invalid delay configuration")
	}

	// Validate URLs
	for _, target := range config.Targets {
		if _, err := url.Parse(target); err != nil {
			return fmt.Errorf("invalid target URL '%s': %v", target, err)
		}
	}

	// Set reasonable defaults
	if config.Settings.Delay.Min == 0 && config.Settings.Delay.Max == 0 {
		config.Settings.Delay.Min = 1000
		config.Settings.Delay.Max = 3000
	}

	return nil
}

// analyzeResponse categorizes the HTTP response status.
func analyzeResponse(resp *http.Response) string {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return "SUCCESS"
	}
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		return "REDIRECT"
	}
	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		return "BLOCKED"
	}

	// Read body to check for challenge keywords without consuming it
	bodyBytes, err := io.ReadAll(resp.Body)
	if err == nil {
		resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes))) // Restore body
		bodyString := strings.ToLower(string(bodyBytes))
		challengeWords := []string{"captcha", "challenge", "verify you are human", "are you a robot"}
		for _, word := range challengeWords {
			if strings.Contains(bodyString, word) {
				return "BLOCKED"
			}
		}
	}
	return fmt.Sprintf("FAILED_HTTP_%d", resp.StatusCode)
}
