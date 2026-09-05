package banner

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/expl0itlab/vantage/internal/models"
)

type Result struct {
	IP      string
	Port    int
	Banner  string
	Service string
	Version string
}

type Grabber struct {
	timeout int
	threads int
	logger  func(string, ...interface{})
}

func New(timeout, threads int, logger func(string, ...interface{})) *Grabber {
	if logger == nil {
		logger = func(s string, a ...interface{}) { fmt.Printf("[banner] "+s+"\n", a...) }
	}
	if timeout == 0 {
		timeout = 5
	}
	if threads == 0 {
		threads = 30
	}
	return &Grabber{timeout: timeout, threads: threads, logger: logger}
}

// GrabAll grabs banners for all open ports concurrently
func (g *Grabber) GrabAll(ports []models.Port) []Result {
	if len(ports) == 0 {
		return nil
	}

	g.logger("banner: grabbing %d ports", len(ports))

	jobs := make(chan models.Port, len(ports))
	results := make(chan Result, len(ports))

	var wg sync.WaitGroup
	for i := 0; i < g.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				r := g.grab(p.IP, p.Port)
				if r != nil {
					results <- *r
				}
			}
		}()
	}

	for _, p := range ports {
		jobs <- p
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var out []Result
	for r := range results {
		out = append(out, r)
	}

	g.logger("banner: got %d banners from %d ports", len(out), len(ports))
	return out
}

func (g *Grabber) grab(ip string, port int) *Result {
	addr := fmt.Sprintf("%s:%d", ip, port)
	timeout := time.Duration(g.timeout) * time.Second

	// Try TLS first for known TLS ports
	if isTLSPort(port) {
		if r := g.grabTLS(addr, ip, port, timeout); r != nil {
			return r
		}
	}

	// Plain TCP
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Send protocol-specific probe
	probe := getProbe(port, ip)
	if probe != "" {
		conn.Write([]byte(probe))
	}

	// Read response
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 4096)

	var lines []string
	for i := 0; i < 5 && scanner.Scan(); i++ {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	if len(lines) == 0 {
		// Try reading raw bytes
		buf := make([]byte, 512)
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		n, _ := conn.Read(buf)
		if n > 0 {
			lines = append(lines, strings.TrimSpace(string(buf[:n])))
		}
	}

	if len(lines) == 0 {
		return &Result{IP: ip, Port: port, Service: guessService(port)}
	}

	banner := strings.Join(lines, " | ")
	banner = sanitize(banner)

	service, version := parseServiceVersion(banner, port)

	return &Result{
		IP:      ip,
		Port:    port,
		Banner:  truncate(banner, 500),
		Service: service,
		Version: version,
	}
}

func (g *Grabber) grabTLS(addr, ip string, port int, timeout time.Duration) *Result {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Send HTTP probe for web ports
	probe := getProbe(port, ip)
	if probe == "" {
		probe = "HEAD / HTTP/1.0\r\nHost: " + ip + "\r\n\r\n"
	}
	conn.Write([]byte(probe))

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 4096)

	var lines []string
	for i := 0; i < 5 && scanner.Scan(); i++ {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	if len(lines) == 0 {
		// Still return TLS info even with no banner
		state := conn.ConnectionState()
		return &Result{
			IP:      ip,
			Port:    port,
			Banner:  fmt.Sprintf("TLS/%s", tlsVersionName(state.Version)),
			Service: guessService(port),
		}
	}

	banner := sanitize(strings.Join(lines, " | "))
	service, version := parseServiceVersion(banner, port)

	return &Result{
		IP:      ip,
		Port:    port,
		Banner:  truncate(banner, 500),
		Service: service,
		Version: version,
	}
}

func getProbe(port int, ip string) string {
	httpProbe := "HEAD / HTTP/1.0\r\nHost: " + ip + "\r\n\r\n"
	probes := map[int]string{
		21:   "",              // FTP sends banner
		22:   "",              // SSH sends banner
		23:   "",              // Telnet sends banner
		25:   "EHLO mail\r\n", // SMTP
		80:   httpProbe,
		110:  "", // POP3 sends banner
		143:  "", // IMAP sends banner
		443:  httpProbe,
		3306: "",         // MySQL sends banner
		5432: "",         // PostgreSQL sends banner
		6379: "INFO\r\n", // Redis
		8080: httpProbe,
		8443: httpProbe,
		9200: "GET / HTTP/1.0\r\nHost: " + ip + "\r\n\r\n", // Elasticsearch
	}
	if p, ok := probes[port]; ok {
		return p
	}
	return ""
}

func parseServiceVersion(banner string, port int) (service, version string) {
	service = guessService(port)
	lower := strings.ToLower(banner)

	// SSH
	if strings.HasPrefix(banner, "SSH-") {
		service = "ssh"
		parts := strings.SplitN(banner, "-", 3)
		if len(parts) >= 3 {
			version = strings.Split(parts[2], " ")[0]
		}
		return
	}

	// FTP
	if strings.HasPrefix(banner, "220 ") {
		if strings.Contains(lower, "ftp") {
			service = "ftp"
		}
		version = extractAfter(banner, "220 ")
		return
	}

	// SMTP
	if strings.HasPrefix(banner, "220 ") && strings.Contains(lower, "smtp") {
		service = "smtp"
		version = extractAfter(banner, "220 ")
		return
	}

	// HTTP
	if strings.HasPrefix(banner, "HTTP/") {
		service = "http"
		// Extract Server header if present
		if idx := strings.Index(lower, "server: "); idx != -1 {
			rest := banner[idx+8:]
			if nl := strings.Index(rest, "\n"); nl != -1 {
				version = strings.TrimSpace(rest[:nl])
			} else {
				version = strings.TrimSpace(rest)
			}
		}
		return
	}

	// Redis
	if strings.Contains(lower, "redis_version") {
		service = "redis"
		if idx := strings.Index(lower, "redis_version:"); idx != -1 {
			rest := banner[idx+14:]
			if nl := strings.Index(rest, "\n"); nl != -1 {
				version = strings.TrimSpace(rest[:nl])
			}
		}
		return
	}

	// MySQL
	if port == 3306 && len(banner) > 5 {
		service = "mysql"
		if strings.Contains(banner, ".") {
			version = extractVersion(banner)
		}
		return
	}

	// PostgreSQL
	if port == 5432 {
		service = "postgresql"
		return
	}

	// Elasticsearch
	if strings.Contains(lower, "elasticsearch") || strings.Contains(lower, "\"name\"") {
		service = "elasticsearch"
		if idx := strings.Index(lower, "\"version\""); idx != -1 {
			version = extractVersion(banner[idx:])
		}
		return
	}

	// Generic version extraction
	version = extractVersion(banner)
	return
}

func extractVersion(s string) string {
	for _, word := range strings.Fields(s) {
		word = strings.Trim(word, `"',;{}[]`)
		if isVersion(word) {
			return word
		}
	}
	return ""
}

func isVersion(s string) bool {
	if len(s) < 3 || len(s) > 30 {
		return false
	}
	dots := strings.Count(s, ".")
	if dots == 0 {
		return false
	}
	start := s
	if strings.HasPrefix(s, "v") || strings.HasPrefix(s, "V") {
		start = s[1:]
	}
	return len(start) > 0 && start[0] >= '0' && start[0] <= '9'
}

func extractAfter(s, prefix string) string {
	if idx := strings.Index(s, prefix); idx != -1 {
		rest := strings.TrimSpace(s[idx+len(prefix):])
		if nl := strings.Index(rest, "\n"); nl != -1 {
			return strings.TrimSpace(rest[:nl])
		}
		if len(rest) > 100 {
			return rest[:100]
		}
		return rest
	}
	return ""
}

func guessService(port int) string {
	services := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
		53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
		135: "msrpc", 139: "netbios", 143: "imap",
		161: "snmp", 443: "https", 445: "smb",
		465: "smtps", 587: "smtp", 993: "imaps", 995: "pop3s",
		1433: "mssql", 1521: "oracle", 2049: "nfs",
		2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
		3000: "dev-server", 3306: "mysql", 3389: "rdp",
		4848: "glassfish", 5000: "dev-server", 5432: "postgresql",
		5900: "vnc", 5984: "couchdb", 6379: "redis",
		7474: "neo4j", 8080: "http-alt", 8443: "https-alt",
		8888: "jupyter", 9000: "php-fpm", 9090: "http-alt",
		9200: "elasticsearch", 9300: "elasticsearch-transport",
		11211: "memcached", 15672: "rabbitmq-mgmt",
		27017: "mongodb", 50000: "ibm-db2",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return "unknown"
}

func isTLSPort(port int) bool {
	tlsPorts := map[int]bool{
		443: true, 465: true, 636: true, 993: true, 995: true,
		8443: true, 4443: true, 8843: true, 9443: true,
	}
	return tlsPorts[port]
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "unknown"
	}
}

func sanitize(s string) string {
	var out strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			out.WriteRune(r)
		} else if r == '\t' {
			out.WriteRune(' ')
		}
	}
	return strings.TrimSpace(out.String())
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
