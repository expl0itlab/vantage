package jsanalysis

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/expl0itlab/vantage/internal/config"
	"github.com/expl0itlab/vantage/internal/models"
)

type Finding struct {
	JSURL       string
	FindingType string
	Value       string
	Context     string
	Severity    string
}

type Analyzer struct {
	cfg    *config.JSAnalysisConfig
	client *http.Client
	logger func(string, ...interface{})
}

func New(cfg *config.JSAnalysisConfig, logger func(string, ...interface{})) *Analyzer {
	if logger == nil {
		logger = func(s string, a ...interface{}) { fmt.Printf("[js] "+s+"\n", a...) }
	}
	t := cfg.Timeout
	if t == 0 {
		t = 15
	}
	return &Analyzer{
		cfg:    cfg,
		logger: logger,
		client: &http.Client{
			Timeout: time.Duration(t) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func (a *Analyzer) AnalyzeHosts(ctx context.Context, hosts []models.Host) []Finding {
	// Expand hosts to also include www. variants if not already present
	seen := map[string]bool{}
	var expanded []models.Host
	for _, h := range hosts {
		if !seen[h.URL] {
			seen[h.URL] = true
			expanded = append(expanded, h)
		}
		// Add www variant
		wwwURL := ""
		if strings.HasPrefix(h.URL, "https://") {
			rest := h.URL[8:]
			if !strings.HasPrefix(rest, "www.") {
				wwwURL = "https://www." + rest
			}
		} else if strings.HasPrefix(h.URL, "http://") {
			rest := h.URL[7:]
			if !strings.HasPrefix(rest, "www.") {
				wwwURL = "http://www." + rest
			}
		}
		if wwwURL != "" && !seen[wwwURL] {
			seen[wwwURL] = true
			expanded = append(expanded, models.Host{
				ID: h.ID, AssetID: h.AssetID, URL: wwwURL,
			})
		}
	}
	hosts = expanded
	if !a.cfg.Enabled || len(hosts) == 0 {
		return nil
	}
	a.logger("discovering JS files across %d hosts", len(hosts))

	jsURLs := a.discoverJSURLs(ctx, hosts)
	a.logger("found %d JS files", len(jsURLs))
	if len(jsURLs) == 0 {
		return nil
	}

	threads := a.cfg.Threads
	if threads == 0 {
		threads = 20
	}
	sem := make(chan struct{}, threads)
	var mu sync.Mutex
	var all []Finding
	var wg sync.WaitGroup

	for jsURL, hostURL := range jsURLs {
		wg.Add(1)
		sem <- struct{}{}
		go func(ju, hu string) {
			defer wg.Done()
			defer func() { <-sem }()
			findings := a.analyzeFile(ctx, ju, hu)
			if len(findings) > 0 {
				mu.Lock()
				all = append(all, findings...)
				mu.Unlock()
			}
		}(jsURL, hostURL)
	}
	wg.Wait()

	a.logger("extracted %d findings", len(all))
	return all
}

func (a *Analyzer) discoverJSURLs(ctx context.Context, hosts []models.Host) map[string]string {
	result := make(map[string]string)
	var mu sync.Mutex
	threads := a.cfg.Threads
	if threads == 0 {
		threads = 20
	}
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(host models.Host) {
			defer wg.Done()
			defer func() { <-sem }()
			urls := a.extractJSFromPage(ctx, host.URL)
			mu.Lock()
			for _, u := range urls {
				result[u] = host.URL
			}
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	return result
}

var (
	reScriptSrc  = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js[^"']*)["']`)
	reScriptSrc2 = regexp.MustCompile(`(?i)src:\s*["']([^"']+\.js[^"']*)["']`)
)

func (a *Analyzer) extractJSFromPage(ctx context.Context, pageURL string) []string {
	t := a.cfg.Timeout
	if t == 0 {
		t = 15
	}
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(t)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", pageURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := a.client.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "html") && !strings.Contains(ct, "text") {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}

	base := baseURL(pageURL)
	seen := map[string]bool{}
	var jsURLs []string

	for _, re := range []*regexp.Regexp{reScriptSrc, reScriptSrc2} {
		for _, match := range re.FindAllSubmatch(body, -1) {
			if len(match) < 2 {
				continue
			}
			rawURL := string(match[1])
			if strings.HasPrefix(rawURL, "data:") || a.shouldSkip(rawURL) {
				continue
			}
			abs := toAbsolute(rawURL, base)
			if abs == "" || seen[abs] {
				continue
			}
			seen[abs] = true
			jsURLs = append(jsURLs, abs)
		}
	}
	return jsURLs
}

func (a *Analyzer) shouldSkip(url string) bool {
	noisy := []string{
		"google-analytics.com",
		"googletagmanager.com",
		"hotjar.com",
		"facebook.net/en_US/fbevents",
		"connect.facebook.net",
		"cdn.segment.com",
		"js.intercomcdn.com",
		"snap.licdn.com",
		"sc-static.net/scevent",
		"static.ads-twitter.com",
		"cdn.jsdelivr.net/npm/bootstrap@",
		"cdn.jsdelivr.net/npm/jquery@",
		"cdnjs.cloudflare.com",
		"unpkg.com/react@",
		"unpkg.com/vue@",
	}
	lower := strings.ToLower(url)
	for _, n := range noisy {
		if strings.Contains(lower, n) {
			return true
		}
	}
	for _, pat := range a.cfg.ExcludePatterns {
		if strings.Contains(lower, strings.ToLower(pat)) {
			return true
		}
	}
	return false
}

func (a *Analyzer) analyzeFile(ctx context.Context, jsURL, hostURL string) []Finding {
	t := a.cfg.Timeout
	if t == 0 {
		t = 15
	}
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(t)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", jsURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := a.client.Do(req)
	if err != nil || resp == nil || resp.StatusCode >= 400 {
		return nil
	}
	defer resp.Body.Close()

	maxBytes := int64(a.cfg.MaxFileSizeKB) * 1024
	if maxBytes == 0 {
		maxBytes = 2 * 1024 * 1024
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil || len(body) == 0 {
		return nil
	}

	content := string(body)
	var findings []Finding
	if a.cfg.ExtractSecrets {
		findings = append(findings, extractSecrets(content, jsURL)...)
	}
	if a.cfg.ExtractPaths {
		findings = append(findings, extractEndpoints(content, jsURL, hostURL)...)
	}
	findings = append(findings, extractSensitiveFiles(content, jsURL)...)
	return dedup(findings)
}

// ──────────────────────────── SECRET PATTERNS ────────────────────────────

type secretPattern struct {
	name     string
	re       *regexp.Regexp
	severity string
	group    int
}

var secretPatterns = []secretPattern{
	{"aws-access-key", regexp.MustCompile("(AKIA[0-9A-Z]{16})"), "critical", 1},
	{"aws-secret-key", regexp.MustCompile("(?i)aws[_\\-.]*secret[_\\-.]*key[\"'\\s]*[:=][\"'\\s]*([A-Za-z0-9/+]{40})"), "critical", 1},
	{"private-key", regexp.MustCompile("-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "critical", 0},
	{"github-token", regexp.MustCompile("ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{59}"), "critical", 0},
	{"stripe-key", regexp.MustCompile("(?i)(sk_live_[A-Za-z0-9]{24,}|pk_live_[A-Za-z0-9]{24,})"), "critical", 1},
	{"db-connection", regexp.MustCompile("(?i)(?:mongodb|mysql|postgres|redis|amqp)://[^\\s\"'<>]+"), "critical", 0},
	{"jwt-token", regexp.MustCompile("eyJ[A-Za-z0-9\\-_]{10,}\\.eyJ[A-Za-z0-9\\-_]{10,}\\.[A-Za-z0-9\\-_]+"), "high", 0},
	{"api-key", regexp.MustCompile("(?i)(?:api[_\\-.]?key|apikey|api[_\\-.]?token)[\"'\\s]*[:=][\"'\\s]*([A-Za-z0-9\\-_]{20,64})"), "high", 1},
	{"bearer-token", regexp.MustCompile("(?i)(?:bearer|authorization)[\"'\\s]*[:=][\"'\\s]*(Bearer\\s+[A-Za-z0-9\\-_.~+/]{20,})"), "high", 1},
	{"hardcoded-password", regexp.MustCompile("(?i)(?:password|passwd|pwd)[\"'\\s]*[:=][\"'\\s]+([^\\s\"';&,]{8,})"), "high", 1},
	{"secret", regexp.MustCompile("(?i)(?:secret|client_secret|app_secret)[\"'\\s]*[:=][\"'\\s]*([A-Za-z0-9\\-_]{16,64})"), "high", 1},
	{"google-api-key", regexp.MustCompile("AIza[0-9A-Za-z\\-_]{35}"), "high", 0},
	{"slack-token", regexp.MustCompile("xox[baprs]-[A-Za-z0-9\\-]{10,}"), "high", 0},
	{"internal-ip", regexp.MustCompile("\"((?:10|172\\.(?:1[6-9]|2\\d|3[01])|192\\.168)\\.\\d{1,3}\\.\\d{1,3})\""), "medium", 1},
	{"s3-bucket", regexp.MustCompile("(?i)([a-z0-9\\-_.]{3,63})\\.s3[.\\-]amazonaws\\.com"), "medium", 1},
	// HIGH VALUE — CRITICAL severity
	{"twilio-account", regexp.MustCompile("AC[a-z0-9]{32}"), "critical", 0},
	{"sendgrid-api", regexp.MustCompile("SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}"), "critical", 0},
	{"mailgun-api", regexp.MustCompile("key-[a-z0-9]{32}"), "critical", 0},
	{"npm-token", regexp.MustCompile("npm_[A-Za-z0-9]{36}"), "critical", 0},
	{"docker-hub-token", regexp.MustCompile("dckr_pat_[A-Za-z0-9_-]{27}"), "critical", 0},
	{"shopify-token", regexp.MustCompile("shpat_[a-fA-F0-9]{32}|shpss_[a-fA-F0-9]{32}"), "critical", 0},
	{"firebase-key", regexp.MustCompile("AIza[0-9A-Za-z\\-_]{35}"), "critical", 0},
	{"square-token", regexp.MustCompile("sq0atp-[0-9A-Za-z\\-_]{22}"), "critical", 0},
	{"square-oauth", regexp.MustCompile("sq0csp-[0-9A-Za-z\\-_]{43}"), "critical", 0},
	{"braintree-token", regexp.MustCompile("access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"), "critical", 0},
	{"flutterwave-secret", regexp.MustCompile("FLWSECK-[a-zA-Z0-9]{32}-X"), "critical", 0},
	{"paystack-secret", regexp.MustCompile("sk_live_[a-zA-Z0-9]{40}"), "critical", 0},
	{"razorpay-key", regexp.MustCompile("rzp_live_[a-zA-Z0-9]{14}"), "critical", 0},
	{"ssh-private-key", regexp.MustCompile("-----BEGIN OPENSSH PRIVATE KEY-----"), "critical", 0},
	{"pgp-private-key", regexp.MustCompile("-----BEGIN PGP PRIVATE KEY BLOCK-----"), "critical", 0},
	{"sentry-dsn", regexp.MustCompile("https://[a-z0-9]{32}@[a-z0-9]+\\.ingest\\.sentry\\.io/[0-9]+"), "critical", 0},
	{"vault-token", regexp.MustCompile("s\\.[a-zA-Z0-9]{24}"), "high", 0},
	{"linear-api", regexp.MustCompile("lin_api_[a-zA-Z0-9]{40}"), "critical", 0},
	{"notion-api", regexp.MustCompile("secret_[a-zA-Z0-9]{43}"), "critical", 0},
	{"heroku-api", regexp.MustCompile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "high", 0},
	{"cloudflare-token", regexp.MustCompile("[A-Za-z0-9_-]{40}"), "high", 0},
	{"okta-token", regexp.MustCompile("00[a-zA-Z0-9_-]{40}"), "critical", 0},
	{"pagerduty-key", regexp.MustCompile("[uo]_[a-z0-9]{16}"), "high", 0},
	// MEDIUM severity patterns
	{"graphql-endpoint", regexp.MustCompile("(?i)(?:fetch|axios|get|post)\\s*\\(\\s*[\"']/graphql"), "medium", 0},
	{"internal-service-url", regexp.MustCompile("http://[a-z0-9\\-]+:\\d{2,5}"), "medium", 0},
	{"k8s-internal", regexp.MustCompile("(?i)kubernetes\\.default\\.svc|svc\\.cluster\\.local"), "medium", 0},
	{"env-secret-leak", regexp.MustCompile("(?i)process\\.env\\.[A-Z_]{5,}|os\\.environ\\[['\"][A-Z_]{5,}"), "medium", 0},
	{"webhook-url", regexp.MustCompile("https://hooks\\.[a-z]+\\.[a-z]+/[^\\s\"']+"), "medium", 0},
}

func extractSecrets(content, jsURL string) []Finding {
	var findings []Finding
	lines := strings.Split(content, "\n")

	for _, pat := range secretPatterns {
		for lineNum, line := range lines {
			if len(line) > 2000 {
				line = line[:2000]
			}
			matches := pat.re.FindAllStringSubmatchIndex(line, -1)
			for _, loc := range matches {
				var value string
				if pat.group == 0 {
					value = line[loc[0]:loc[1]]
				} else if pat.group*2+1 < len(loc) && loc[pat.group*2] >= 0 {
					value = line[loc[pat.group*2]:loc[pat.group*2+1]]
				}
				if value == "" || isFP(value, pat.name) {
					continue
				}

				// Skip findings in comments
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") {
					continue
				}

				// Skip findings surrounded by template syntax
				if strings.Contains(value, "{{") || strings.Contains(value, "}}") ||
					strings.Contains(value, "<%") || strings.Contains(value, "%>") {
					continue
				}

				// Calculate entropy and skip low-entropy long values
				entropy := shannonEntropy(value)
				if len(value) > 20 && entropy < 3.5 {
					continue
				}

				ctx := snippet(lines, lineNum, 80)
				findings = append(findings, Finding{
					JSURL: jsURL, FindingType: pat.name,
					Value: truncate(value, 200), Context: ctx, Severity: pat.severity,
				})
			}
		}
	}
	return findings
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

var (
	reEndpoint = regexp.MustCompile("\"(/(?:api|v\\d|graphql|rest|admin|auth|oauth|login|dashboard|internal|debug|actuator|console|panel|config|backup|setup|manage|swagger|openapi)[^\"\\s<>]{0,120})\"")
	reFetchURL = regexp.MustCompile("(?i)(?:fetch|axios\\.(?:get|post|put|delete|patch))\\s*\\(\\s*[\"']([^\"'\\s]{5,120})")
	reWSURL    = regexp.MustCompile("(?i)new WebSocket\\s*\\(\\s*[\"'](wss?://[^\"'\\s]+)")
)

func extractEndpoints(content, jsURL, hostURL string) []Finding {
	var findings []Finding
	base := baseURL(hostURL)
	seen := map[string]bool{}

	add := func(raw, ftype, severity string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || seen[raw] {
			return
		}
		for _, ext := range []string{".js", ".css", ".png", ".jpg", ".svg", ".woff", ".ttf"} {
			if strings.HasSuffix(strings.ToLower(raw), ext) {
				return
			}
		}
		seen[raw] = true
		abs := toAbsolute(raw, base)
		if abs == "" {
			abs = raw
		}
		findings = append(findings, Finding{
			JSURL: jsURL, FindingType: ftype,
			Value: truncate(abs, 300), Severity: severity,
		})
	}

	for _, m := range reEndpoint.FindAllStringSubmatch(content, 200) {
		if len(m) >= 2 {
			add(m[1], "api-endpoint", endpointSeverity(m[1]))
		}
	}
	for _, m := range reFetchURL.FindAllStringSubmatch(content, 200) {
		if len(m) >= 2 {
			add(m[1], "fetch-endpoint", "medium")
		}
	}
	for _, m := range reWSURL.FindAllStringSubmatch(content, 50) {
		if len(m) >= 2 {
			add(m[1], "websocket", "medium")
		}
	}
	return findings
}

func endpointSeverity(path string) string {
	lower := strings.ToLower(path)
	for _, c := range []string{"/admin", "/actuator", "/debug", "/console", "/internal"} {
		if strings.HasPrefix(lower, c) {
			return "high"
		}
	}
	for _, h := range []string{"/api/", "/graphql", "/oauth", "/login", "/config", "/backup"} {
		if strings.Contains(lower, h) {
			return "medium"
		}
	}
	return "low"
}

var sensitiveFileRe = regexp.MustCompile(
	"(?i)\"(/[^\"\\s<>]*(?:\\.env|\\.config|\\.bak|\\.backup|\\.sql|\\.db|\\.key|\\.pem|\\.yaml|\\.yml|\\.conf|\\.log|\\.dump|\\.zip|\\.tar)[^\"\\s<>]{0,80})\"",
)

func extractSensitiveFiles(content, jsURL string) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	for _, m := range sensitiveFileRe.FindAllStringSubmatch(content, 50) {
		if len(m) < 2 || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		findings = append(findings, Finding{
			JSURL: jsURL, FindingType: "sensitive-file",
			Value: truncate(m[1], 300), Severity: "high",
		})
	}
	return findings
}

func isFP(val, ptype string) bool {
	lower := strings.ToLower(val)
	placeholders := []string{
		"your_", "YOUR_", "example", "EXAMPLE", "placeholder", "changeme",
		"xxxxxxx", "test", "TEST", "demo", "DEMO", "sample", "SAMPLE",
		"xxx", "000", "aaa", "change_me", "CHANGE_ME", "todo", "TODO",
		"fixme", "FIXME", "replace", "REPLACE", "insert", "INSERT",
	}
	for _, p := range placeholders {
		if strings.Contains(lower, p) {
			return true
		}
	}
	if ptype == "hardcoded-password" && len(val) < 8 {
		return true
	}
	return false
}

func snippet(lines []string, lineNum, maxLen int) string {
	start := lineNum - 3
	if start < 0 {
		start = 0
	}
	end := lineNum + 4
	if end > len(lines) {
		end = len(lines)
	}
	var parts []string
	for i := start; i < end; i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" {
			continue
		}
		if len(trimmed) > maxLen {
			trimmed = trimmed[:maxLen] + "..."
		}
		parts = append(parts, trimmed)
	}
	result := strings.Join(parts, " | ")
	if len(result) > 500 {
		result = result[:500]
	}
	return result
}

func dedup(findings []Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, f := range findings {
		key := f.FindingType + "|" + f.Value
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

func baseURL(rawURL string) string {
	if idx := strings.Index(rawURL, "://"); idx != -1 {
		rest := rawURL[idx+3:]
		if slash := strings.Index(rest, "/"); slash != -1 {
			return rawURL[:idx+3+slash]
		}
		return rawURL
	}
	return rawURL
}

func toAbsolute(ref, base string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	if strings.HasPrefix(ref, "//") {
		scheme := "https"
		if strings.HasPrefix(base, "http://") {
			scheme = "http"
		}
		return scheme + ":" + ref
	}
	if strings.HasPrefix(ref, "/") {
		return base + ref
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
