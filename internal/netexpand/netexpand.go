package netexpand

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Result struct {
	IP       string
	Source   string // the original IP that triggered the expansion
	NetRange string // the /24 range
}

type Expander struct {
	naabuPath string
	maxHosts  int
	ports     string
	logger    func(string, ...interface{})
}

func New(naabuPath string, maxHosts int, ports string, logger func(string, ...interface{})) *Expander {
	if logger == nil {
		logger = func(s string, a ...interface{}) { fmt.Printf("[netexpand] "+s+"\n", a...) }
	}
	if maxHosts == 0 {
		maxHosts = 254
	}
	if ports == "" {
		ports = "top-100"
	}
	return &Expander{
		naabuPath: naabuPath,
		maxHosts:  maxHosts,
		ports:     ports,
		logger:    logger,
	}
}

// ExpandIPs takes a list of IPs, derives their /24 ranges, and scans for live hosts
func (e *Expander) ExpandIPs(ctx context.Context, ips []string) []Result {
	if len(ips) == 0 {
		return nil
	}

	// Deduplicate /24 ranges
	ranges := e.deriveRanges(ips)
	if len(ranges) == 0 {
		return nil
	}

	e.logger("netexpand: scanning %d /24 ranges from %d IPs", len(ranges), len(ips))

	var allResults []Result

	for cidr, sourceIP := range ranges {
		hosts := cidrHosts(cidr)
		if len(hosts) > e.maxHosts {
			hosts = hosts[:e.maxHosts]
		}

		e.logger("netexpand: scanning %s (%d hosts)", cidr, len(hosts))
		live := e.scanRange(ctx, hosts, cidr)

		for _, ip := range live {
			allResults = append(allResults, Result{
				IP:       ip,
				Source:   sourceIP,
				NetRange: cidr,
			})
		}
	}

	e.logger("netexpand: found %d additional live hosts", len(allResults))
	return allResults
}

func (e *Expander) deriveRanges(ips []string) map[string]string {
	ranges := map[string]string{} // cidr -> first IP that triggered it
	for _, ip := range ips {
		// Skip private and loopback
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() {
			continue
		}

		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			continue
		}
		cidr := fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		if _, exists := ranges[cidr]; !exists {
			ranges[cidr] = ip
		}
	}
	return ranges
}

func cidrHosts(cidr string) []string {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	var hosts []string
	for ip := cloneIP(network.IP); network.Contains(ip); incrementIP(ip) {
		// Skip network and broadcast addresses
		host := ip.String()
		last := strings.Split(host, ".")[3]
		if last == "0" || last == "255" {
			continue
		}
		hosts = append(hosts, host)
	}
	return hosts
}

func (e *Expander) scanRange(ctx context.Context, hosts []string, cidr string) []string {
	if len(hosts) == 0 {
		return nil
	}

	// Write hosts to temp file
	tmpFile, err := os.CreateTemp("", "vantage-expand-*.txt")
	if err != nil {
		return nil
	}
	defer os.Remove(tmpFile.Name())
	for _, h := range hosts {
		fmt.Fprintln(tmpFile, h)
	}
	tmpFile.Close()

	args := []string{
		"-l", tmpFile.Name(),
		"-silent",
		"-rate", "500",
		"-scan-type", "c",
		"-c", "25",
		"-timeout", "500",
	}

	switch e.ports {
	case "top-100":
		args = append(args, "-top-ports", "100")
	case "top-1000":
		args = append(args, "-top-ports", "1000")
	default:
		args = append(args, "-p", e.ports)
	}

	scanCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, e.naabuPath, args...)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil
	}

	// Parse host:port output to extract unique live IPs
	seen := map[string]bool{}
	var liveIPs []string

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: host:port or just host
		ip := line
		if idx := strings.LastIndex(line, ":"); idx > 0 {
			ip = line[:idx]
		}
		if !seen[ip] {
			seen[ip] = true
			liveIPs = append(liveIPs, ip)
		}
	}

	return liveIPs
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}
