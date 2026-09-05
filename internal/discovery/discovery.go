package discovery

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/expl0itlab/vantage/internal/config"
)

type Result struct {
	Subdomain string
	Source    string
	IP        string
}

type Discoverer struct {
	cfg    *config.Config
	logger func(string, ...interface{})
}

func New(cfg *config.Config, logger func(string, ...interface{})) *Discoverer {
	if logger == nil {
		logger = func(s string, a ...interface{}) { fmt.Printf("[discovery] "+s+"\n", a...) }
	}
	return &Discoverer{cfg: cfg, logger: logger}
}

func (d *Discoverer) Discover(ctx context.Context, domain string, profile config.ProfileOverride) ([]Result, error) {
	d.logger("discovery: starting for %s (bruteforce=%v)", domain, profile.BruteForce)

	sources := d.cfg.Discovery.Sources
	resultCh := make(chan Result, 2000)
	var wg sync.WaitGroup

	for _, source := range sources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()
			var results []Result
			var err error
			switch src {
			case "subfinder":
				results, err = d.runSubfinder(ctx, domain, profile.RateLimit)
			case "assetfinder":
				results, err = d.runAssetfinder(ctx, domain)
			case "amass":
				results, err = d.runAmass(ctx, domain)
			}
			if err != nil {
				d.logger("discovery: %s error: %v", src, err)
				return
			}
			d.logger("discovery: %s found %d subdomains", src, len(results))
			for _, r := range results {
				select {
				case resultCh <- r:
				case <-ctx.Done():
					return
				}
			}
		}(source)
	}

	if profile.BruteForce && d.cfg.Discovery.WordlistPath != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := d.runBruteForce(ctx, domain)
			if err != nil {
				d.logger("discovery: bruteforce error: %v", err)
				return
			}
			for _, r := range results {
				select {
				case resultCh <- r:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	seen := map[string]bool{}
	var results []Result
	for r := range resultCh {
		sub := normalizeDomain(r.Subdomain)
		if sub == "" || seen[sub] || !isSubdomainOf(sub, domain) {
			continue
		}
		seen[sub] = true
		r.Subdomain = sub
		results = append(results, r)
		if len(results) >= d.cfg.Discovery.MaxSubdomains {
			break
		}
	}

	d.logger("discovery: found %d unique subdomains", len(results))
	return results, nil
}

func (d *Discoverer) runSubfinder(ctx context.Context, domain string, rateLimit int) ([]Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	rate := rateLimit
	if rate == 0 {
		rate = 200
	}

	args := []string{"-d", domain, "-silent", "-all", "-t", "100",
		"-rate-limit", fmt.Sprintf("%d", rate)}
	cmd := exec.CommandContext(ctx, d.cfg.Tools.SubfinderPath, args...)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("subfinder: %w", err)
	}
	return parseLines(string(out), "subfinder"), nil
}

func (d *Discoverer) runAssetfinder(ctx context.Context, domain string) ([]Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, d.cfg.Tools.AssetfinderPath, "--subs-only", domain)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("assetfinder: %w", err)
	}
	return parseLines(string(out), "assetfinder"), nil
}

func (d *Discoverer) runAmass(ctx context.Context, domain string) ([]Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	args := []string{"enum", "-passive", "-d", domain, "-silent", "-timeout", "10"}
	cmd := exec.CommandContext(ctx, d.cfg.Tools.AmassPath, args...)
	out, _ := cmd.Output()
	return parseLines(string(out), "amass"), nil
}

func (d *Discoverer) runBruteForce(ctx context.Context, domain string) ([]Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	args := []string{"-d", domain, "-w", d.cfg.Discovery.WordlistPath,
		"-silent", "-t", "100", "-r", "8.8.8.8,1.1.1.1"}
	cmd := exec.CommandContext(ctx, d.cfg.Tools.DNSXPath, args...)
	out, _ := cmd.Output()
	return parseLines(string(out), "bruteforce"), nil
}

func (d *Discoverer) DNSResolve(ctx context.Context, subdomains []string) (map[string]string, error) {
	if len(subdomains) == 0 {
		return map[string]string{}, nil
	}
	input := strings.Join(subdomains, "\n")

	// Try dnsx first
	if path := d.cfg.Tools.DNSXPath; path != "" {
		for _, args := range [][]string{
			{"-silent", "-a", "-resp", "-t", "100", "-r", "8.8.8.8,1.1.1.1"},
			{"-silent", "-a", "-t", "100", "-r", "8.8.8.8,1.1.1.1"},
		} {
			resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			cmd := exec.CommandContext(resolveCtx, path, args...)
			cmd.Stdin = strings.NewReader(input)
			out, err := cmd.Output()
			cancel()
			if err == nil && len(out) > 0 {
				ipMap := parseDNSX(string(out))
				if len(ipMap) > 0 {
					d.logger("discovery: dnsx resolved %d/%d", len(ipMap), len(subdomains))
					return d.fillMissing(ctx, subdomains, ipMap), nil
				}
			}
		}
	}

	// Fallback: Go resolver
	return d.goResolve(ctx, subdomains), nil
}

func parseDNSX(output string) map[string]string {
	result := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := stripANSI(strings.TrimSpace(scanner.Text()))
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(parts[0], "."))
		for _, p := range parts[1:] {
			p = strings.Trim(p, "[](),")
			if isIPv4(p) {
				result[host] = p
				break
			}
		}
	}
	return result
}

func (d *Discoverer) goResolve(ctx context.Context, subdomains []string) map[string]string {
	ipMap := make(map[string]string)
	var mu sync.Mutex
	sem := make(chan struct{}, 50)
	var wg sync.WaitGroup

	for _, sub := range subdomains {
		wg.Add(1)
		sem <- struct{}{}
		go func(s string) {
			defer wg.Done()
			defer func() { <-sem }()
			resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			addrs, err := net.DefaultResolver.LookupHost(resolveCtx, s)
			if err != nil || len(addrs) == 0 {
				return
			}
			ip := addrs[0]
			for _, a := range addrs {
				if isIPv4(a) {
					ip = a
					break
				}
			}
			mu.Lock()
			ipMap[strings.ToLower(s)] = ip
			mu.Unlock()
		}(sub)
	}
	wg.Wait()
	d.logger("discovery: go resolver resolved %d/%d", len(ipMap), len(subdomains))
	return ipMap
}

func (d *Discoverer) fillMissing(ctx context.Context, subdomains []string, existing map[string]string) map[string]string {
	var missing []string
	for _, s := range subdomains {
		if existing[strings.ToLower(s)] == "" {
			missing = append(missing, s)
		}
	}
	if len(missing) == 0 {
		return existing
	}
	extras := d.goResolve(ctx, missing)
	for k, v := range extras {
		existing[k] = v
	}
	return existing
}

func parseLines(output, source string) []Result {
	var results []Result
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSuffix(line, ".")
		results = append(results, Result{Subdomain: strings.ToLower(line), Source: source})
	}
	return results
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	if idx := strings.IndexByte(d, '/'); idx != -1 {
		d = d[:idx]
	}
	return strings.TrimSuffix(d, ".")
}

func isSubdomainOf(sub, parent string) bool {
	return sub == parent || strings.HasSuffix(sub, "."+parent)
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func stripANSI(s string) string {
	var out strings.Builder
	inEsc := false
	for _, r := range s {
		if r == '\x1b' {
			inEsc = true
			continue
		}
		if inEsc {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEsc = false
			}
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}
