package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/expl0itlab/vantage/internal/config"
	"github.com/expl0itlab/vantage/internal/models"
)

type Scanner struct {
	cfg    *config.Config
	logger func(string, ...interface{})
}

func New(cfg *config.Config, logger func(string, ...interface{})) *Scanner {
	if logger == nil {
		logger = func(s string, a ...interface{}) { fmt.Printf("[scanner] "+s+"\n", a...) }
	}
	return &Scanner{cfg: cfg, logger: logger}
}

// RunHTTPx probes hosts for live HTTP/S services
func (s *Scanner) RunHTTPx(ctx context.Context, hosts []string, profile config.ProfileOverride) ([]models.HTTPXResult, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	// Expand hosts with www. variants to catch redirects
	expandedHosts := make([]string, 0, len(hosts)*2)
	seen := map[string]bool{}
	for _, h := range hosts {
		if !seen[h] {
			seen[h] = true
			expandedHosts = append(expandedHosts, h)
		}
		www := "www." + h
		if !seen[www] {
			seen[www] = true
			expandedHosts = append(expandedHosts, www)
		}
	}
	hosts = expandedHosts
	s.logger("httpx: probing %d hosts (incl. www variants)", len(hosts))

	tmpFile, err := os.CreateTemp("", "vantage-httpx-*.txt")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())
	for _, h := range hosts {
		fmt.Fprintln(tmpFile, h)
	}
	tmpFile.Close()

	threads := profile.Threads
	if threads == 0 {
		threads = s.cfg.Scanning.HTTPx.Threads
	}
	if threads == 0 {
		threads = 50
	}

	args := []string{
		"-l", tmpFile.Name(),
		"-silent", "-j",
		"-threads", fmt.Sprintf("%d", threads),
		"-timeout", fmt.Sprintf("%d", s.cfg.Scanning.HTTPx.Timeout),
		"-retries", fmt.Sprintf("%d", s.cfg.Scanning.HTTPx.Retries),
		"-status-code", "-title", "-server", "-content-type",
		"-web-server", "-random-agent",
		"-follow-redirects", "-max-redirects", "5",
	}

	if s.cfg.Scanning.HTTPx.TechDetect {
		args = append(args, "-tech-detect")
	}
	if s.cfg.Scanning.HTTPx.TLSProbe {
		args = append(args, "-tls-grab")
	}
	if s.cfg.Scanning.HTTPx.FollowRedirects {
		args = append(args, "-follow-redirects",
			"-max-redirects", fmt.Sprintf("%d", s.cfg.Scanning.HTTPx.MaxRedirects))
	}

	s.logger("httpx: %s %s", s.cfg.Tools.HTTPxPath, strings.Join(args, " "))

	scanCtx, cancel := context.WithTimeout(ctx, 25*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, s.cfg.Tools.HTTPxPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		s.logger("httpx stderr: %s", truncate(stderr.String(), 300))
		return nil, fmt.Errorf("httpx: %w", err)
	}

	var results []models.HTTPXResult
	sc := bufio.NewScanner(&stdout)
	sc.Buffer(make([]byte, 512*1024), 512*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r models.HTTPXResult
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		if r.URL != "" {
			results = append(results, r)
		}
	}

	s.logger("httpx: found %d live hosts", len(results))
	return results, nil
}

// RunNaabu runs port scanning
func (s *Scanner) RunNaabu(ctx context.Context, targets []string, profile config.ProfileOverride) ([]models.NaabuResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	s.logger("naabu: scanning %d targets", len(targets))

	tmpFile, err := os.CreateTemp("", "vantage-naabu-*.txt")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())
	for _, t := range targets {
		fmt.Fprintln(tmpFile, t)
	}
	tmpFile.Close()

	rate := profile.RateLimit
	if rate == 0 {
		rate = s.cfg.Scanning.Naabu.RateLimit
	}
	threads := profile.Threads
	if threads == 0 {
		threads = s.cfg.Scanning.Naabu.Threads
	}

	ports := profile.Ports
	if ports == "" {
		ports = s.cfg.Scanning.Naabu.Ports
	}

	args := []string{
		"-l", tmpFile.Name(),
		"-silent", "-j",
		"-rate", fmt.Sprintf("%d", rate),
		"-retries", fmt.Sprintf("%d", s.cfg.Scanning.Naabu.Retries),
		"-timeout", fmt.Sprintf("%d", s.cfg.Scanning.Naabu.Timeout),
		"-c", fmt.Sprintf("%d", threads),
		"-scan-type", "c",
	}

	switch ports {
	case "top-100":
		args = append(args, "-top-ports", "100")
	case "top-1000":
		args = append(args, "-top-ports", "1000")
	case "full":
		args = append(args, "-p", "1-65535")
	default:
		if ports != "" {
			args = append(args, "-p", ports)
		} else {
			args = append(args, "-top-ports", "100")
		}
	}

	if s.cfg.Scanning.Naabu.Interface != "" {
		args = append(args, "-interface", s.cfg.Scanning.Naabu.Interface)
	}

	s.logger("naabu: %s %s", s.cfg.Tools.NaabuPath, strings.Join(args, " "))

	scanCtx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, s.cfg.Tools.NaabuPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		s.logger("naabu stderr: %s", truncate(stderr.String(), 300))
		return nil, fmt.Errorf("naabu: %w", err)
	}

	var results []models.NaabuResult
	sc := bufio.NewScanner(&stdout)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		if line[0] == '{' {
			var r models.NaabuResult
			if err := json.Unmarshal(line, &r); err == nil && r.Port > 0 {
				if r.IP == "" {
					r.IP = r.Host
				}
				results = append(results, r)
				continue
			}
		}
		// Fallback: host:port
		text := strings.TrimSpace(string(line))
		if idx := strings.LastIndex(text, ":"); idx > 0 {
			var port int
			fmt.Sscanf(text[idx+1:], "%d", &port)
			if port > 0 {
				results = append(results, models.NaabuResult{
					Host: text[:idx], IP: text[:idx], Port: port, Protocol: "tcp",
				})
			}
		}
	}

	s.logger("naabu: found %d open ports", len(results))
	return results, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
