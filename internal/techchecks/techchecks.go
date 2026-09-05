package techchecks

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/expl0itlab/vantage/internal/models"
)

type TechFinding struct {
	ID         int64     `json:"id"`
	Domain     string    `json:"domain"`
	HostURL    string    `json:"host_url"`
	HostID     int64     `json:"host_id"`
	AssetID    int64     `json:"asset_id"`
	Technology string    `json:"technology"`
	CheckName  string    `json:"check_name"`
	URL        string    `json:"url"`
	Result     string    `json:"result"`
	Severity   string    `json:"severity"`
	Detail     string    `json:"detail"`
	Confirmed  bool      `json:"confirmed"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	ScanID     int64     `json:"scan_id"`
}

type Runner struct {
	client  *http.Client
	logger  func(string, ...interface{})
	threads int
}

func New(timeout int, threads int, logger func(string, ...interface{})) *Runner {
	if timeout <= 0 {
		timeout = 8
	}
	if threads <= 0 {
		threads = 5
	}
	if logger == nil {
		logger = func(string, ...interface{}) {}
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        threads * 2,
		MaxIdleConnsPerHost: threads * 2,
		IdleConnTimeout:     30 * time.Second,
	}

	return &Runner{
		client: &http.Client{
			Timeout:   time.Duration(timeout) * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger:  logger,
		threads: threads,
	}
}

func (r *Runner) httpGet(ctx context.Context, url string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Vantage/1.0)")

	resp, err := r.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}

func (r *Runner) RunChecks(ctx context.Context, hosts []models.Host, scanID int64) []TechFinding {
	var mu sync.Mutex
	var findings []TechFinding

	sem := make(chan struct{}, r.threads)
	var wg sync.WaitGroup

	for _, host := range hosts {
		var techs []string
		if host.Technologies != "" {
			if err := json.Unmarshal([]byte(host.Technologies), &techs); err != nil {
				r.logger("failed to parse technologies for host %d: %v", host.ID, err)
				continue
			}
		}

		baseURL := host.URL
		if baseURL == "" {
			continue
		}

		packs := r.matchPacks(techs)
		for _, pack := range packs {
			for _, tech := range pack.techs {
				sem <- struct{}{}
				wg.Add(1)
				go func(t checkPack, technology string) {
					defer wg.Done()
					defer func() { <-sem }()

					results := t.fn(ctx, baseURL)
					if len(results) > 5 {
						results = results[:5]
					}

					mu.Lock()
					for i := range results {
						results[i].HostURL = host.URL
						results[i].HostID = host.ID
						results[i].AssetID = host.AssetID
						results[i].Technology = technology
						results[i].ScanID = scanID
						results[i].FirstSeen = time.Now().UTC()
						results[i].LastSeen = time.Now().UTC()
					}
					findings = append(findings, results...)
					mu.Unlock()
				}(pack, tech)
			}
		}
	}

	wg.Wait()
	return findings
}

type checkPack struct {
	techs []string
	fn    func(ctx context.Context, baseURL string) []TechFinding
}

func (r *Runner) matchPacks(techs []string) []checkPack {
	packMap := map[string]checkPack{
		"wordpress": {
			techs: []string{"wordpress"},
			fn:    r.checkWordpress,
		},
		"laravel": {
			techs: []string{"laravel"},
			fn:    r.checkLaravel,
		},
		"django": {
			techs: []string{"django"},
			fn:    r.checkDjango,
		},
		"next": {
			techs: []string{"next"},
			fn:    r.checkNextjs,
		},
		"jenkins": {
			techs: []string{"jenkins"},
			fn:    r.checkJenkins,
		},
		"gitlab": {
			techs: []string{"gitlab"},
			fn:    r.checkGitlab,
		},
		"grafana": {
			techs: []string{"grafana"},
			fn:    r.checkGrafana,
		},
		"kubernetes": {
			techs: []string{"kubernetes", "k8s"},
			fn:    r.checkKubernetes,
		},
		"k8s": {
			techs: []string{"kubernetes", "k8s"},
			fn:    r.checkKubernetes,
		},
		"elasticsearch": {
			techs: []string{"elasticsearch"},
			fn:    r.checkElasticsearch,
		},
		"docker": {
			techs: []string{"docker"},
			fn:    r.checkDocker,
		},
	}

	seen := make(map[string]bool)
	var matched []checkPack

	for _, tech := range techs {
		lower := strings.ToLower(tech)
		for key, pack := range packMap {
			if strings.Contains(lower, key) {
				if !seen[key] {
					seen[key] = true
					matched = append(matched, pack)
				}
				break
			}
		}
	}

	return matched
}

func (r *Runner) newFinding(baseURL, checkName, url, severity, detail string, confirmed bool) TechFinding {
	return TechFinding{
		CheckName: checkName,
		URL:       url,
		Result:    detail,
		Severity:  severity,
		Detail:    detail,
		Confirmed: confirmed,
	}
}

// WordPress checks

func (r *Runner) checkWordpress(ctx context.Context, baseURL string) []TechFinding {
	var findings []TechFinding

	// Check wp-login.php
	func() {
		url := strings.TrimRight(baseURL, "/") + "/wp-login.php"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 || (code >= 300 && code < 400 && strings.Contains(body, "wp-login"))
		findings = append(findings, r.newFinding(baseURL, "WordPress Login Page", url, "info",
			fmt.Sprintf("wp-login.php returned %d", code), confirmed))
	}()

	// Check wp-json user enumeration
	func() {
		url := strings.TrimRight(baseURL, "/") + "/wp-json/wp/v2/users"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := false
		if code == 200 && strings.Contains(body, "[") && strings.Contains(body, "id") {
			confirmed = true
		}
		findings = append(findings, r.newFinding(baseURL, "WordPress User Enumeration", url, "high",
			fmt.Sprintf("wp-json users endpoint returned %d", code), confirmed))
	}()

	// Check xmlrpc.php
	func() {
		url := strings.TrimRight(baseURL, "/") + "/xmlrpc.php"
		code, _, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200
		findings = append(findings, r.newFinding(baseURL, "WordPress XML-RPC", url, "medium",
			fmt.Sprintf("xmlrpc.php returned %d", code), confirmed))
	}()

	// Check debug.log
	func() {
		url := strings.TrimRight(baseURL, "/") + "/wp-content/debug.log"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && len(body) > 0
		findings = append(findings, r.newFinding(baseURL, "WordPress Debug Log Exposed", url, "high",
			fmt.Sprintf("debug.log returned %d, length %d", code, len(body)), confirmed))
	}()

	// Check ?author=1
	func() {
		url := strings.TrimRight(baseURL, "/") + "/?author=1"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := false
		detail := fmt.Sprintf("author enumeration returned %d", code)
		if code >= 300 && code < 400 {
			confirmed = true
			detail = "author enumeration via redirect"
		} else if code == 200 && strings.Contains(body, "/author/") {
			confirmed = true
			detail = "author enumeration via page content"
		}
		findings = append(findings, r.newFinding(baseURL, "WordPress Author Enumeration", url, "medium", detail, confirmed))
	}()

	return findings
}

// Laravel checks

func (r *Runner) checkLaravel(ctx context.Context, baseURL string) []TechFinding {
	var findings []TechFinding

	// Check .env
	func() {
		url := strings.TrimRight(baseURL, "/") + "/.env"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.Contains(body, "APP_KEY")
		findings = append(findings, r.newFinding(baseURL, "Laravel .env Exposed", url, "critical",
			fmt.Sprintf(".env returned %d, contains APP_KEY: %v", code, confirmed), confirmed))
	}()

	// Check /api/user
	func() {
		url := strings.TrimRight(baseURL, "/") + "/api/user"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && !strings.Contains(body, "Unauthenticated") && !strings.Contains(body, "401")
		findings = append(findings, r.newFinding(baseURL, "Laravel API User Endpoint", url, "high",
			fmt.Sprintf("/api/user returned %d", code), confirmed))
	}()

	// Check /telescope
	func() {
		url := strings.TrimRight(baseURL, "/") + "/telescope"
		code, _, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200
		findings = append(findings, r.newFinding(baseURL, "Laravel Telescope Exposed", url, "high",
			fmt.Sprintf("telescope returned %d", code), confirmed))
	}()

	// Check /horizon
	func() {
		url := strings.TrimRight(baseURL, "/") + "/horizon"
		code, _, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200
		findings = append(findings, r.newFinding(baseURL, "Laravel Horizon Exposed", url, "high",
			fmt.Sprintf("horizon returned %d", code), confirmed))
	}()

	// Check /storage/logs/laravel.log
	func() {
		url := strings.TrimRight(baseURL, "/") + "/storage/logs/laravel.log"
		code, _, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200
		findings = append(findings, r.newFinding(baseURL, "Laravel Log Exposed", url, "medium",
			fmt.Sprintf("laravel.log returned %d", code), confirmed))
	}()

	return findings
}

// Django checks

func (r *Runner) checkDjango(ctx context.Context, baseURL string) []TechFinding {
	var findings []TechFinding

	// Check /admin/
	func() {
		url := strings.TrimRight(baseURL, "/") + "/admin/"
		code, _, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200
		findings = append(findings, r.newFinding(baseURL, "Django Admin Panel", url, "medium",
			fmt.Sprintf("/admin/ returned %d", code), confirmed))
	}()

	// Check /__debug__/
	func() {
		url := strings.TrimRight(baseURL, "/") + "/__debug__/"
		code, _, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200
		findings = append(findings, r.newFinding(baseURL, "Django Debug Toolbar", url, "high",
			fmt.Sprintf("/__debug__/ returned %d", code), confirmed))
	}()

	// Check 404 for debug info leak
	func() {
		url := strings.TrimRight(baseURL, "/") + "/nonexistent-trigger-404"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := false
		detail := fmt.Sprintf("404 page returned %d", code)
		if strings.Contains(strings.ToLower(body), "traceback") || strings.Contains(strings.ToLower(body), "django") || strings.Contains(body, "DEBUG") {
			confirmed = true
			detail = "404 page leaks debug information"
		}
		findings = append(findings, r.newFinding(baseURL, "Django Debug Info Leak", url, "high", detail, confirmed))
	}()

	return findings
}

// Next.js checks

func (r *Runner) checkNextjs(ctx context.Context, baseURL string) []TechFinding {
	var findings []TechFinding

	// Check x-powered-by header
	func() {
		url := strings.TrimRight(baseURL, "/") + "/"
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Vantage/1.0)")
		resp, err := r.client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		powered := resp.Header.Get("X-Powered-By")
		confirmed := strings.Contains(strings.ToLower(powered), "next")
		findings = append(findings, r.newFinding(baseURL, "Next.js X-Powered-By Header", url, "info",
			fmt.Sprintf("X-Powered-By: %s", powered), confirmed))
	}()

	// Check /_next/static/
	func() {
		url := strings.TrimRight(baseURL, "/") + "/_next/static/"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.Contains(body, ".js")
		findings = append(findings, r.newFinding(baseURL, "Next.js Static Assets", url, "info",
			fmt.Sprintf("/_next/static/ returned %d", code), confirmed))
	}()

	// Check /api/
	func() {
		url := strings.TrimRight(baseURL, "/") + "/api/"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && (strings.Contains(body, "error") || strings.Contains(body, "message") || strings.Contains(body, "data"))
		findings = append(findings, r.newFinding(baseURL, "Next.js API Routes", url, "medium",
			fmt.Sprintf("/api/ returned %d", code), confirmed))
	}()

	// Check /_next/data/
	func() {
		url := strings.TrimRight(baseURL, "/") + "/_next/data/"
		code, _, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200
		findings = append(findings, r.newFinding(baseURL, "Next.js Data Routes", url, "medium",
			fmt.Sprintf("/_next/data/ returned %d", code), confirmed))
	}()

	return findings
}

// Jenkins checks

func (r *Runner) checkJenkins(ctx context.Context, baseURL string) []TechFinding {
	var findings []TechFinding

	// Check /api/json
	func() {
		url := strings.TrimRight(baseURL, "/") + "/api/json"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.Contains(body, "jobs")
		findings = append(findings, r.newFinding(baseURL, "Jenkins Unauthenticated API", url, "critical",
			fmt.Sprintf("/api/json returned %d", code), confirmed))
	}()

	// Check /script
	func() {
		url := strings.TrimRight(baseURL, "/") + "/script"
		code, _, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200
		findings = append(findings, r.newFinding(baseURL, "Jenkins Script Console", url, "critical",
			fmt.Sprintf("/script returned %d", code), confirmed))
	}()

	// Check /asynchPeople/
	func() {
		url := strings.TrimRight(baseURL, "/") + "/asynchPeople/"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.Contains(body, "user")
		findings = append(findings, r.newFinding(baseURL, "Jenkins User Enumeration", url, "high",
			fmt.Sprintf("/asynchPeople/ returned %d", code), confirmed))
	}()

	// Check /credentials/
	func() {
		url := strings.TrimRight(baseURL, "/") + "/credentials/"
		code, _, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200
		findings = append(findings, r.newFinding(baseURL, "Jenkins Credentials Exposed", url, "critical",
			fmt.Sprintf("/credentials/ returned %d", code), confirmed))
	}()

	// Check /systemInfo
	func() {
		url := strings.TrimRight(baseURL, "/") + "/systemInfo"
		code, _, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200
		findings = append(findings, r.newFinding(baseURL, "Jenkins System Info", url, "high",
			fmt.Sprintf("/systemInfo returned %d", code), confirmed))
	}()

	return findings
}

// GitLab checks

func (r *Runner) checkGitlab(ctx context.Context, baseURL string) []TechFinding {
	var findings []TechFinding

	// Check X-Gitlab-Version header
	func() {
		url := strings.TrimRight(baseURL, "/") + "/"
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Vantage/1.0)")
		resp, err := r.client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		version := resp.Header.Get("X-Gitlab-Version")
		confirmed := version != ""
		findings = append(findings, r.newFinding(baseURL, "GitLab Version Disclosure", url, "info",
			fmt.Sprintf("X-Gitlab-Version: %s", version), confirmed))
	}()

	// Check /api/v4/projects
	func() {
		url := strings.TrimRight(baseURL, "/") + "/api/v4/projects?visibility=public"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.HasPrefix(strings.TrimSpace(body), "[")
		findings = append(findings, r.newFinding(baseURL, "GitLab Public Projects", url, "high",
			fmt.Sprintf("/api/v4/projects returned %d", code), confirmed))
	}()

	// Check /-/health
	func() {
		url := strings.TrimRight(baseURL, "/") + "/-/health"
		code, _, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200
		findings = append(findings, r.newFinding(baseURL, "GitLab Health Check", url, "info",
			fmt.Sprintf("/-/health returned %d", code), confirmed))
	}()

	// Check /users
	func() {
		url := strings.TrimRight(baseURL, "/") + "/users"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.HasPrefix(strings.TrimSpace(body), "[")
		findings = append(findings, r.newFinding(baseURL, "GitLab User Enumeration", url, "high",
			fmt.Sprintf("/users returned %d", code), confirmed))
	}()

	return findings
}

// Grafana checks

func (r *Runner) checkGrafana(ctx context.Context, baseURL string) []TechFinding {
	var findings []TechFinding

	// Check /api/health
	func() {
		url := strings.TrimRight(baseURL, "/") + "/api/health"
		code, _, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200
		findings = append(findings, r.newFinding(baseURL, "Grafana Health Check", url, "info",
			fmt.Sprintf("/api/health returned %d", code), confirmed))
	}()

	// Check /api/datasources
	func() {
		url := strings.TrimRight(baseURL, "/") + "/api/datasources"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.HasPrefix(strings.TrimSpace(body), "[")
		findings = append(findings, r.newFinding(baseURL, "Grafana Datasources Exposed", url, "high",
			fmt.Sprintf("/api/datasources returned %d", code), confirmed))
	}()

	// Check /api/users
	func() {
		url := strings.TrimRight(baseURL, "/") + "/api/users"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.HasPrefix(strings.TrimSpace(body), "[")
		findings = append(findings, r.newFinding(baseURL, "Grafana User Enumeration", url, "high",
			fmt.Sprintf("/api/users returned %d", code), confirmed))
	}()

	// Check /login for default credentials
	func() {
		url := strings.TrimRight(baseURL, "/") + "/login"
		code, _, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200
		findings = append(findings, r.newFinding(baseURL, "Grafana Default Login", url, "critical",
			fmt.Sprintf("/login returned %d, check for default admin:admin credentials", code), confirmed))
	}()

	return findings
}

// Kubernetes checks

func (r *Runner) checkKubernetes(ctx context.Context, baseURL string) []TechFinding {
	var findings []TechFinding

	// Check /api/v1/namespaces
	func() {
		url := strings.TrimRight(baseURL, "/") + "/api/v1/namespaces"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.Contains(body, "items")
		findings = append(findings, r.newFinding(baseURL, "Kubernetes API Namespaces", url, "critical",
			fmt.Sprintf("/api/v1/namespaces returned %d", code), confirmed))
	}()

	// Check /api/
	func() {
		url := strings.TrimRight(baseURL, "/") + "/api/"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.Contains(body, "versions")
		findings = append(findings, r.newFinding(baseURL, "Kubernetes API Discovery", url, "high",
			fmt.Sprintf("/api/ returned %d", code), confirmed))
	}()

	// Check /healthz
	func() {
		url := strings.TrimRight(baseURL, "/") + "/healthz"
		code, _, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200
		findings = append(findings, r.newFinding(baseURL, "Kubernetes Health Check", url, "info",
			fmt.Sprintf("/healthz returned %d", code), confirmed))
	}()

	// Check /metrics
	func() {
		url := strings.TrimRight(baseURL, "/") + "/metrics"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.Contains(body, "# HELP")
		findings = append(findings, r.newFinding(baseURL, "Kubernetes Metrics Exposed", url, "high",
			fmt.Sprintf("/metrics returned %d", code), confirmed))
	}()

	return findings
}

// Elasticsearch checks

func (r *Runner) checkElasticsearch(ctx context.Context, baseURL string) []TechFinding {
	var findings []TechFinding

	// Check root for cluster info
	func() {
		url := strings.TrimRight(baseURL, "/") + "/"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.Contains(body, "cluster_name") && strings.Contains(body, "cluster_uuid")
		findings = append(findings, r.newFinding(baseURL, "Elasticsearch Cluster Info", url, "critical",
			fmt.Sprintf("/ returned %d, cluster info exposed without auth", code), confirmed))
	}()

	// Check /_cat/indices
	func() {
		url := strings.TrimRight(baseURL, "/") + "/_cat/indices?v"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.Contains(body, "index")
		findings = append(findings, r.newFinding(baseURL, "Elasticsearch Indices Exposed", url, "high",
			fmt.Sprintf("/_cat/indices returned %d", code), confirmed))
	}()

	// Check /_cluster/health
	func() {
		url := strings.TrimRight(baseURL, "/") + "/_cluster/health"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.Contains(body, "status")
		findings = append(findings, r.newFinding(baseURL, "Elasticsearch Cluster Health", url, "high",
			fmt.Sprintf("/_cluster/health returned %d", code), confirmed))
	}()

	// Check /_nodes
	func() {
		url := strings.TrimRight(baseURL, "/") + "/_nodes"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.Contains(body, "nodes")
		findings = append(findings, r.newFinding(baseURL, "Elasticsearch Nodes Exposed", url, "high",
			fmt.Sprintf("/_nodes returned %d", code), confirmed))
	}()

	return findings
}

// Docker API checks

func (r *Runner) checkDocker(ctx context.Context, baseURL string) []TechFinding {
	var findings []TechFinding

	// Check /containers/json
	func() {
		url := strings.TrimRight(baseURL, "/") + "/containers/json"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.HasPrefix(strings.TrimSpace(body), "[")
		findings = append(findings, r.newFinding(baseURL, "Docker Containers API", url, "critical",
			fmt.Sprintf("/containers/json returned %d, containers listed without auth", code), confirmed))
	}()

	// Check /info
	func() {
		url := strings.TrimRight(baseURL, "/") + "/info"
		code, body, err := r.httpGet(ctx, url)
		if err != nil {
			return
		}
		confirmed := code == 200 && strings.Contains(body, "DockerRootDir")
		findings = append(findings, r.newFinding(baseURL, "Docker Info Exposed", url, "critical",
			fmt.Sprintf("/info returned %d", code), confirmed))
	}()

	return findings
}

func (r *Runner) RunCheckForHost(ctx context.Context, host models.Host, scanID int64) []TechFinding {
	return r.RunChecks(ctx, []models.Host{host}, scanID)
}

func (r *Runner) GetSupportedTechnologies() []string {
	return []string{
		"wordpress", "laravel", "django", "next", "jenkins",
		"gitlab", "grafana", "kubernetes", "k8s", "elasticsearch", "docker",
	}
}

func (r *Runner) HasCheckPack(tech string) bool {
	lower := strings.ToLower(tech)
	supported := r.GetSupportedTechnologies()
	for _, s := range supported {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}
