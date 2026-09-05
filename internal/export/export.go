package export

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/expl0itlab/vantage/internal/models"
)

// ──────────────────────────── Caido Scope ────────────────────────────

type CaidoScope struct {
	Version   int              `json:"version"`
	Generated string           `json:"generated"`
	Domain    string           `json:"domain"`
	Scope     []CaidoScopeItem `json:"scope"`
}

type CaidoScopeItem struct {
	URL         string   `json:"url"`
	Title       string   `json:"title"`
	IP          string   `json:"ip"`
	Tags        []string `json:"tags"`
	Interesting bool     `json:"interesting"`
	InterestTag string   `json:"interest_tag,omitempty"`
	Notes       string   `json:"notes,omitempty"`
}

func ToCaidoScope(domain string, hosts []models.Host) ([]byte, error) {
	scope := CaidoScope{
		Version:   1,
		Generated: time.Now().Format(time.RFC3339),
		Domain:    domain,
	}

	for _, h := range hosts {
		item := CaidoScopeItem{
			URL:         h.URL,
			Title:       h.Title,
			IP:          h.IP,
			Tags:        []string{},
			Interesting: h.Interesting,
			InterestTag: h.InterestTag,
		}

		// Parse technologies into tags
		var techs []string
		if err := json.Unmarshal([]byte(h.Technologies), &techs); err == nil {
			for _, t := range techs {
				item.Tags = append(item.Tags, strings.Split(t, ":")[0])
			}
		}

		// Add attack surface as notes
		if h.AttackSurface != "" && h.AttackSurface != "[]" {
			var notes []map[string]string
			if err := json.Unmarshal([]byte(h.AttackSurface), &notes); err == nil {
				var noteLines []string
				for _, n := range notes {
					noteLines = append(noteLines, fmt.Sprintf("[%s] %s: %s", n["severity"], n["signal"], n["detail"]))
				}
				item.Notes = strings.Join(noteLines, "\n")
			}
		}

		scope.Scope = append(scope.Scope, item)
	}

	return json.MarshalIndent(scope, "", "  ")
}

// ──────────────────────────── Burp Suite XML ────────────────────────────

type BurpSuiteConfig struct {
	XMLName xml.Name   `xml:"burp-configuration"`
	Version string     `xml:"version,attr"`
	Target  BurpTarget `xml:"target"`
}

type BurpTarget struct {
	Scope BurpScope `xml:"scope"`
}

type BurpScope struct {
	AdvancedMode string     `xml:"advanced_mode"`
	Exclude      []BurpRule `xml:"exclude"`
	Include      []BurpRule `xml:"include"`
}

type BurpRule struct {
	Enabled  bool   `xml:"enabled"`
	File     string `xml:"file"`
	Host     string `xml:"host"`
	Port     string `xml:"port"`
	Protocol string `xml:"protocol"`
}

func ToBurpScope(domain string, hosts []models.Host) ([]byte, error) {
	config := BurpSuiteConfig{
		Version: "2.0",
		Target: BurpTarget{
			Scope: BurpScope{
				AdvancedMode: "true",
			},
		},
	}

	seen := map[string]bool{}
	for _, h := range hosts {
		parsed, err := url.Parse(h.URL)
		if err != nil {
			continue
		}

		host := parsed.Hostname()
		if seen[host] {
			continue
		}
		seen[host] = true

		port := parsed.Port()
		if port == "" {
			if parsed.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}

		rule := BurpRule{
			Enabled:  true,
			File:     "^/.*$",
			Host:     strings.ReplaceAll(host, ".", "\\."),
			Port:     port,
			Protocol: parsed.Scheme,
		}
		config.Target.Scope.Include = append(config.Target.Scope.Include, rule)
	}

	output, err := xml.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), output...), nil
}

// ──────────────────────────── Metasploit Resource Script ────────────────────────────

func ToMetasploitRC(domain string, hosts []models.Host, ports []models.Port) string {
	var sb strings.Builder

	sb.WriteString("# Vantage Metasploit Resource Script\n")
	sb.WriteString(fmt.Sprintf("# Domain: %s\n", domain))
	sb.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString("# Usage: msfconsole -r vantage-targets.rc\n\n")

	// Add all hosts to workspace
	sb.WriteString("workspace -a vantage-" + sanitizeName(domain) + "\n\n")

	// Import hosts
	sb.WriteString("# --- Target Hosts ---\n")
	seen := map[string]bool{}
	for _, h := range hosts {
		if h.IP != "" && !seen[h.IP] {
			seen[h.IP] = true
			sb.WriteString(fmt.Sprintf("hosts -a %s\n", h.IP))
		}
	}
	sb.WriteString("\n")

	// High-risk service modules
	sb.WriteString("# --- High-Risk Services ---\n")
	for _, p := range ports {
		switch p.Service {
		case "smb", "microsoft-ds":
			sb.WriteString(fmt.Sprintf("\n# SMB on %s:%d\n", p.IP, p.Port))
			sb.WriteString("use auxiliary/scanner/smb/smb_version\n")
			sb.WriteString(fmt.Sprintf("set RHOSTS %s\n", p.IP))
			sb.WriteString("run\n")
			sb.WriteString("use auxiliary/scanner/smb/smb_ms17_010\n")
			sb.WriteString(fmt.Sprintf("set RHOSTS %s\n", p.IP))
			sb.WriteString("run\n")

		case "rdp":
			sb.WriteString(fmt.Sprintf("\n# RDP on %s:%d\n", p.IP, p.Port))
			sb.WriteString("use auxiliary/scanner/rdp/rdp_scanner\n")
			sb.WriteString(fmt.Sprintf("set RHOSTS %s\n", p.IP))
			sb.WriteString(fmt.Sprintf("set RPORT %d\n", p.Port))
			sb.WriteString("run\n")

		case "ssh":
			sb.WriteString(fmt.Sprintf("\n# SSH on %s:%d\n", p.IP, p.Port))
			sb.WriteString("use auxiliary/scanner/ssh/ssh_version\n")
			sb.WriteString(fmt.Sprintf("set RHOSTS %s\n", p.IP))
			sb.WriteString(fmt.Sprintf("set RPORT %d\n", p.Port))
			sb.WriteString("run\n")

		case "ftp":
			sb.WriteString(fmt.Sprintf("\n# FTP on %s:%d\n", p.IP, p.Port))
			sb.WriteString("use auxiliary/scanner/ftp/ftp_version\n")
			sb.WriteString(fmt.Sprintf("set RHOSTS %s\n", p.IP))
			sb.WriteString(fmt.Sprintf("set RPORT %d\n", p.Port))
			sb.WriteString("run\n")
			sb.WriteString("use auxiliary/scanner/ftp/anonymous\n")
			sb.WriteString(fmt.Sprintf("set RHOSTS %s\n", p.IP))
			sb.WriteString(fmt.Sprintf("set RPORT %d\n", p.Port))
			sb.WriteString("run\n")

		case "mysql":
			sb.WriteString(fmt.Sprintf("\n# MySQL on %s:%d\n", p.IP, p.Port))
			sb.WriteString("use auxiliary/scanner/mysql/mysql_version\n")
			sb.WriteString(fmt.Sprintf("set RHOSTS %s\n", p.IP))
			sb.WriteString(fmt.Sprintf("set RPORT %d\n", p.Port))
			sb.WriteString("run\n")
			sb.WriteString("use auxiliary/scanner/mysql/mysql_login\n")
			sb.WriteString(fmt.Sprintf("set RHOSTS %s\n", p.IP))
			sb.WriteString(fmt.Sprintf("set RPORT %d\n", p.Port))
			sb.WriteString("set USERNAME root\n")
			sb.WriteString("set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt\n")
			sb.WriteString("run\n")

		case "postgresql":
			sb.WriteString(fmt.Sprintf("\n# PostgreSQL on %s:%d\n", p.IP, p.Port))
			sb.WriteString("use auxiliary/scanner/postgres/postgres_version\n")
			sb.WriteString(fmt.Sprintf("set RHOSTS %s\n", p.IP))
			sb.WriteString(fmt.Sprintf("set RPORT %d\n", p.Port))
			sb.WriteString("run\n")

		case "mongodb":
			sb.WriteString(fmt.Sprintf("\n# MongoDB on %s:%d\n", p.IP, p.Port))
			sb.WriteString("use auxiliary/scanner/mongodb/mongodb_login\n")
			sb.WriteString(fmt.Sprintf("set RHOSTS %s\n", p.IP))
			sb.WriteString(fmt.Sprintf("set RPORT %d\n", p.Port))
			sb.WriteString("run\n")

		case "redis":
			sb.WriteString(fmt.Sprintf("\n# Redis on %s:%d\n", p.IP, p.Port))
			sb.WriteString("use auxiliary/scanner/redis/redis_server\n")
			sb.WriteString(fmt.Sprintf("set RHOSTS %s\n", p.IP))
			sb.WriteString(fmt.Sprintf("set RPORT %d\n", p.Port))
			sb.WriteString("run\n")

		case "vnc":
			sb.WriteString(fmt.Sprintf("\n# VNC on %s:%d\n", p.IP, p.Port))
			sb.WriteString("use auxiliary/scanner/vnc/vnc_login\n")
			sb.WriteString(fmt.Sprintf("set RHOSTS %s\n", p.IP))
			sb.WriteString(fmt.Sprintf("set RPORT %d\n", p.Port))
			sb.WriteString("run\n")

		case "telnet":
			sb.WriteString(fmt.Sprintf("\n# Telnet on %s:%d — CRITICAL EXPOSURE\n", p.IP, p.Port))
			sb.WriteString("use auxiliary/scanner/telnet/telnet_version\n")
			sb.WriteString(fmt.Sprintf("set RHOSTS %s\n", p.IP))
			sb.WriteString(fmt.Sprintf("set RPORT %d\n", p.Port))
			sb.WriteString("run\n")
		}
	}

	sb.WriteString("\n# --- Service Version Summary ---\n")
	sb.WriteString("db_hosts\n")
	sb.WriteString("db_services\n")

	return sb.String()
}

// ──────────────────────────── Target List ────────────────────────────

// ToTargetList returns a plain text list of URLs for use with any tool
func ToTargetList(hosts []models.Host) string {
	var sb strings.Builder
	for _, h := range hosts {
		sb.WriteString(h.URL + "\n")
	}
	return sb.String()
}

// ToIPList returns unique IPs one per line
func ToIPList(ports []models.Port) string {
	seen := map[string]bool{}
	var sb strings.Builder
	for _, p := range ports {
		if !seen[p.IP] {
			seen[p.IP] = true
			sb.WriteString(p.IP + "\n")
		}
	}
	return sb.String()
}

// ToIPPortList returns ip:port pairs
func ToIPPortList(ports []models.Port) string {
	var sb strings.Builder
	for _, p := range ports {
		sb.WriteString(fmt.Sprintf("%s:%d\n", p.IP, p.Port))
	}
	return sb.String()
}

func sanitizeName(s string) string {
	r := strings.NewReplacer(".", "-", ":", "-", "/", "-", " ", "-")
	return r.Replace(s)
}
