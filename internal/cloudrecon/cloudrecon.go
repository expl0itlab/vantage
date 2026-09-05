package cloudrecon

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type CloudFinding struct {
	ID          int64     `json:"id"`
	Domain      string    `json:"domain"`
	ScanID      int64     `json:"scan_id"`
	FindingType string    `json:"finding_type"`
	URL         string    `json:"url"`
	Provider    string    `json:"provider"`
	Region      string    `json:"region"`
	Service     string    `json:"service"`
	Severity    string    `json:"severity"`
	Detail      string    `json:"detail"`
	Accessible  bool      `json:"accessible"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

type Scanner struct {
	client *http.Client
	logger func(string, ...interface{})
}

type s3ListResponse struct {
	XMLName  xml.Name `xml:"ListBucketResult"`
	Contents []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
}

func New(timeout int, logger func(string, ...interface{})) *Scanner {
	if logger == nil {
		logger = func(string, ...interface{}) {}
	}
	return &Scanner{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		logger: logger,
	}
}

func (s *Scanner) ScanCloud(ctx context.Context, domain string, subdomains []string, ips []string, scanID int64) []CloudFinding {
	var findings []CloudFinding
	var mu sync.Mutex
	var wg sync.WaitGroup

	names := append([]string{domain}, subdomains...)

	// S3 bucket detection
	for _, name := range names {
		base := strings.Split(name, ".")[0]
		patterns := []string{
			base,
			base + "-backup",
			base + "-assets",
			base + "-static",
			base + "-media",
			base + "-files",
			base + "-uploads",
			base + "-data",
		}
		for _, p := range patterns {
			wg.Add(1)
			go func(name, pattern string) {
				defer wg.Done()
				f := s.checkS3(ctx, name, pattern, scanID)
				if f != nil {
					mu.Lock()
					findings = append(findings, *f)
					mu.Unlock()
				}
			}(name, p)
		}
	}

	// Azure blob detection
	for _, name := range names {
		base := strings.Split(name, ".")[0]
		patterns := []string{
			base + ".blob.core.windows.net",
			base + "storage.blob.core.windows.net",
			base + "-storage.blob.core.windows.net",
		}
		for _, p := range patterns {
			wg.Add(1)
			go func(name, pattern string) {
				defer wg.Done()
				f := s.checkAzure(ctx, name, pattern, scanID)
				if f != nil {
					mu.Lock()
					findings = append(findings, *f)
					mu.Unlock()
				}
			}(name, p)
		}
	}

	// GCP storage detection
	for _, name := range names {
		base := strings.Split(name, ".")[0]
		patterns := []string{
			"https://storage.googleapis.com/" + base,
			"https://" + base + ".storage.googleapis.com",
		}
		for _, p := range patterns {
			wg.Add(1)
			go func(name, pattern string) {
				defer wg.Done()
				f := s.checkGCP(ctx, name, pattern, scanID)
				if f != nil {
					mu.Lock()
					findings = append(findings, *f)
					mu.Unlock()
				}
			}(name, p)
		}
	}

	// Cloud IP detection
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			f := s.checkCloudIP(ctx, domain, ip, scanID)
			if f != nil {
				mu.Lock()
				findings = append(findings, *f)
				mu.Unlock()
			}
		}(ip)
	}

	// Kubernetes endpoint detection
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			fs := s.checkKubernetes(ctx, domain, ip, scanID)
			mu.Lock()
			findings = append(findings, fs...)
			mu.Unlock()
		}(ip)
	}

	// Docker API detection
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			fs := s.checkDocker(ctx, domain, ip, scanID)
			mu.Lock()
			findings = append(findings, fs...)
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	return findings
}

func (s *Scanner) checkS3(ctx context.Context, domain, pattern string, scanID int64) *CloudFinding {
	url := fmt.Sprintf("https://%s.s3.amazonaws.com/", pattern)
	code, body, _, err := s.httpGet(ctx, url)
	if err != nil {
		return nil
	}

	now := time.Now()

	if code == 200 {
		detail := "Public S3 bucket detected (listable)"
		if body != "" {
			var listResp s3ListResponse
			if xml.Unmarshal([]byte(body), &listResp) == nil && len(listResp.Contents) > 0 {
				n := len(listResp.Contents)
				if n > 20 {
					n = 20
				}
				keys := make([]string, 0, n)
				for i := 0; i < n; i++ {
					keys = append(keys, listResp.Contents[i].Key)
				}
				detail = fmt.Sprintf("Public bucket: found %d objects including %s", len(listResp.Contents), strings.Join(keys[:min(n, 3)], ", "))
			}
		}
		s.logger("[cloudrecon] CRITICAL: public S3 bucket: %s", pattern)
		return &CloudFinding{
			Domain:      domain,
			ScanID:      scanID,
			FindingType: "s3_bucket",
			URL:         url,
			Provider:    "aws",
			Service:     "s3",
			Severity:    "critical",
			Detail:      detail,
			Accessible:  true,
			FirstSeen:   now,
			LastSeen:    now,
		}
	}

	if code == 403 {
		s.logger("[cloudrecon] S3 bucket exists (private): %s", pattern)
		return &CloudFinding{
			Domain:      domain,
			ScanID:      scanID,
			FindingType: "s3_bucket",
			URL:         url,
			Provider:    "aws",
			Service:     "s3",
			Severity:    "info",
			Detail:      "Bucket exists but is private (403)",
			Accessible:  false,
			FirstSeen:   now,
			LastSeen:    now,
		}
	}

	return nil
}

func (s *Scanner) checkAzure(ctx context.Context, domain, pattern string, scanID int64) *CloudFinding {
	url := fmt.Sprintf("https://%s/", pattern)
	code, _, _, err := s.httpGet(ctx, url)
	if err != nil {
		return nil
	}

	now := time.Now()

	if code == 200 {
		s.logger("[cloudrecon] CRITICAL: exposed Azure blob storage: %s", pattern)
		return &CloudFinding{
			Domain:      domain,
			ScanID:      scanID,
			FindingType: "azure_blob",
			URL:         url,
			Provider:    "azure",
			Service:     "blob",
			Severity:    "critical",
			Detail:      "Exposed Azure Blob Storage container",
			Accessible:  true,
			FirstSeen:   now,
			LastSeen:    now,
		}
	}

	return nil
}

func (s *Scanner) checkGCP(ctx context.Context, domain, url string, scanID int64) *CloudFinding {
	code, _, _, err := s.httpGet(ctx, url)
	if err != nil {
		return nil
	}

	now := time.Now()

	if code == 200 {
		s.logger("[cloudrecon] CRITICAL: exposed GCP storage: %s", url)
		return &CloudFinding{
			Domain:      domain,
			ScanID:      scanID,
			FindingType: "gcp_storage",
			URL:         url,
			Provider:    "gcp",
			Service:     "storage",
			Severity:    "critical",
			Detail:      "Exposed GCP Cloud Storage bucket",
			Accessible:  true,
			FirstSeen:   now,
			LastSeen:    now,
		}
	}

	return nil
}

func (s *Scanner) checkCloudIP(ctx context.Context, domain, ip string, scanID int64) *CloudFinding {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return nil
	}

	now := time.Now()
	provider := ""
	service := ""

	switch parts[0] {
	case "52", "54", "3":
		provider = "aws"
		service = "ec2"
	case "13", "20", "40", "104":
		if parts[0] == "104" {
			provider = "cloudflare"
			service = "cdn"
		} else {
			provider = "azure"
			service = "vm"
		}
	case "34", "35":
		provider = "gcp"
		service = "gce"
	case "172":
		if provider == "" {
			provider = "cloudflare"
			service = "cdn"
		}
	default:
		return nil
	}

	return &CloudFinding{
		Domain:      domain,
		ScanID:      scanID,
		FindingType: "cloud_ip",
		URL:         fmt.Sprintf("ip://%s", ip),
		Provider:    provider,
		Service:     service,
		Severity:    "info",
		Detail:      fmt.Sprintf("Cloud-hosted IP on %s (%s)", provider, ip),
		Accessible:  false,
		FirstSeen:   now,
		LastSeen:    now,
	}
}

func (s *Scanner) checkKubernetes(ctx context.Context, domain, ip string, scanID int64) []CloudFinding {
	var findings []CloudFinding
	now := time.Now()

	type endpoint struct {
		url     string
		port    string
		service string
		detail  string
	}

	endpoints := []endpoint{
		{fmt.Sprintf("https://%s:6443/api/v1", ip), "6443", "kubernetes_api", "Kubernetes API server on port 6443"},
		{fmt.Sprintf("https://%s:8443/api/v1", ip), "8443", "kubernetes_api", "Kubernetes API server on port 8443"},
		{fmt.Sprintf("http://%s:10250/pods", ip), "10250", "kubelet", "Kubelet API exposed on port 10250"},
		{fmt.Sprintf("http://%s:2379/v2/keys", ip), "2379", "etcd", "etcd exposed on port 2379"},
	}

	for _, ep := range endpoints {
		code, _, _, err := s.httpGet(ctx, ep.url)
		if err != nil {
			continue
		}
		if code == 200 || code == 401 || code == 403 {
			s.logger("[cloudrecon] CRITICAL: %s at %s", ep.detail, ip)
			findings = append(findings, CloudFinding{
				Domain:      domain,
				ScanID:      scanID,
				FindingType: "kubernetes_endpoint",
				URL:         ep.url,
				Provider:    "",
				Service:     ep.service,
				Severity:    "critical",
				Detail:      ep.detail,
				Accessible:  true,
				FirstSeen:   now,
				LastSeen:    now,
			})
		}
	}

	return findings
}

func (s *Scanner) checkDocker(ctx context.Context, domain, ip string, scanID int64) []CloudFinding {
	var findings []CloudFinding
	now := time.Now()

	ports := []string{"2375", "2376"}

	for _, port := range ports {
		url := fmt.Sprintf("http://%s:%s/containers/json", ip, port)
		code, body, _, err := s.httpGet(ctx, url)
		if err != nil {
			continue
		}
		if code == 200 && strings.HasPrefix(strings.TrimSpace(body), "[") {
			s.logger("[cloudrecon] CRITICAL: Docker API exposed at %s:%s", ip, port)
			findings = append(findings, CloudFinding{
				Domain:      domain,
				ScanID:      scanID,
				FindingType: "docker_api",
				URL:         url,
				Provider:    "",
				Service:     "docker",
				Severity:    "critical",
				Detail:      fmt.Sprintf("Docker API exposed on port %s", port),
				Accessible:  true,
				FirstSeen:   now,
				LastSeen:    now,
			})
		}
	}

	return findings
}

func (s *Scanner) httpGet(ctx context.Context, url string) (int, string, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, "", nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Vantage/1.0)")

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
	if err != nil {
		return resp.StatusCode, "", nil, err
	}
	return resp.StatusCode, string(body), resp.Header, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
