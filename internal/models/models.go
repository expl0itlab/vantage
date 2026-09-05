package models

import "time"

type ScanProfile string

const (
	ProfileStealth    ScanProfile = "stealth"
	ProfileStandard   ScanProfile = "standard"
	ProfileAggressive ScanProfile = "aggressive"
)

type Asset struct {
	ID          int64     `json:"id"`
	Domain      string    `json:"domain"`
	Subdomain   string    `json:"subdomain"`
	IP          string    `json:"ip"`
	ASN         string    `json:"asn"`
	ASNOrg      string    `json:"asn_org"`
	NetRange    string    `json:"net_range"`
	AssetType   string    `json:"asset_type"`
	Status      string    `json:"status"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	ScanID      int64     `json:"scan_id"`
	Tags        string    `json:"tags"`
	Interesting bool      `json:"interesting"`
	InterestTag string    `json:"interest_tag"`
}

type Host struct {
	ID             int64     `json:"id"`
	AssetID        int64     `json:"asset_id"`
	URL            string    `json:"url"`
	StatusCode     int       `json:"status_code"`
	Title          string    `json:"title"`
	ContentType    string    `json:"content_type"`
	Server         string    `json:"server"`
	Technologies   string    `json:"technologies"`
	Headers        string    `json:"headers"`
	TLSInfo        string    `json:"tls_info"`
	WebServer      string    `json:"web_server"`
	CDN            string    `json:"cdn"`
	IP             string    `json:"ip"`
	Interesting    bool      `json:"interesting"`
	InterestTag    string    `json:"interest_tag"`
	ScreenshotPath string    `json:"screenshot_path"`
	AttackSurface  string    `json:"attack_surface"` // JSON array of attack surface notes
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	ScanID         int64     `json:"scan_id"`
}

type Port struct {
	ID          int64     `json:"id"`
	AssetID     int64     `json:"asset_id"`
	IP          string    `json:"ip"`
	Port        int       `json:"port"`
	Protocol    string    `json:"protocol"`
	Service     string    `json:"service"`
	Version     string    `json:"version"`
	Banner      string    `json:"banner"`
	State       string    `json:"state"`
	RiskLevel   string    `json:"risk_level"`
	Interesting bool      `json:"interesting"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	ScanID      int64     `json:"scan_id"`
}

type JSFinding struct {
	ID          int64     `json:"id"`
	AssetID     int64     `json:"asset_id"`
	HostID      int64     `json:"host_id"`
	JSURL       string    `json:"js_url"`
	FindingType string    `json:"finding_type"`
	Value       string    `json:"value"`
	Context     string    `json:"context"`
	Severity    string    `json:"severity"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	ScanID      int64     `json:"scan_id"`
}

type ChangeEvent struct {
	ID          int64     `json:"id"`
	ScanID      int64     `json:"scan_id"`
	Domain      string    `json:"domain"`
	EventType   string    `json:"event_type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Details     string    `json:"details"`
	Alerted     bool      `json:"alerted"`
	CreatedAt   time.Time `json:"created_at"`
}

type Fingerprint struct {
	ID         int64     `json:"id"`
	AssetID    int64     `json:"asset_id"`
	HostID     int64     `json:"host_id"`
	Technology string    `json:"technology"`
	Version    string    `json:"version"`
	Category   string    `json:"category"`
	Confidence int       `json:"confidence"`
	Source     string    `json:"source"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Scan struct {
	ID          int64      `json:"id"`
	Domain      string     `json:"domain"`
	Profile     string     `json:"profile"`
	Status      string     `json:"status"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	Duration    int64      `json:"duration"`
	AssetsFound int        `json:"assets_found"`
	HostsFound  int        `json:"hosts_found"`
	PortsFound  int        `json:"ports_found"`
	JSFindings  int        `json:"js_findings"`
	Config      string     `json:"config"`
	Error       string     `json:"error"`
}

type DashboardStats struct {
	TotalAssets      int        `json:"total_assets"`
	ActiveHosts      int        `json:"active_hosts"`
	OpenPorts        int        `json:"open_ports"`
	JSFindings       int        `json:"js_findings"`
	NewChanges       int        `json:"new_changes"`
	LastScanTime     *time.Time `json:"last_scan_time"`
	TotalScans       int        `json:"total_scans"`
	MonitoredDomains int        `json:"monitored_domains"`
	InterestingHosts int        `json:"interesting_hosts"`
	HighRiskPorts    int        `json:"high_risk_ports"`
	Screenshots      int        `json:"screenshots"`
}

// HTTPXResult matches actual httpx v3 JSON output
type HTTPXResult struct {
	URL          string            `json:"url"`
	Input        string            `json:"input"`
	StatusCode   int               `json:"status_code"`
	ContentType  string            `json:"content_type"`
	Title        string            `json:"title"`
	Server       string            `json:"server"`
	WebServer    string            `json:"webserver"`
	Technologies []string          `json:"tech"`
	Headers      map[string]string `json:"headers"`
	Host         string            `json:"host"`
	HostIP       string            `json:"host_ip"`
	IPs          []string          `json:"a"`
	TLS          *TLSData          `json:"tls"`
	CDNName      string            `json:"cdn-name"`
	CDN          bool              `json:"cdn"`
	Scheme       string            `json:"scheme"`
	Port         string            `json:"port"`
	Location     string            `json:"location"`
	Failed       bool              `json:"failed"`
}

func (h *HTTPXResult) FirstIP() string {
	// httpx v3 puts IP in host_ip field
	if h.HostIP != "" {
		return h.HostIP
	}
	if len(h.IPs) > 0 && h.IPs[0] != "" {
		return h.IPs[0]
	}
	if h.Host != "" && isIP(h.Host) {
		return h.Host
	}
	return ""
}

func isIP(s string) bool {
	parts := 0
	current := 0
	for _, c := range s {
		if c == '.' {
			if current > 255 {
				return false
			}
			parts++
			current = 0
		} else if c >= '0' && c <= '9' {
			current = current*10 + int(c-'0')
		} else {
			return false
		}
	}
	return parts == 3 && current <= 255
}

type TLSData struct {
	Host       string    `json:"host"`
	Port       string    `json:"port"`
	Cipher     string    `json:"cipher"`
	Version    string    `json:"tls_version"`
	Expired    bool      `json:"expired"`
	SelfSigned bool      `json:"self_signed"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	SubjectCN  string    `json:"subject_cn"`
	IssuerCN   string    `json:"issuer_cn"`
}

type NaabuResult struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Host     string `json:"host"`
	Protocol string `json:"protocol"`
}

func (n *NaabuResult) EffectiveIP() string {
	if n.IP != "" {
		return n.IP
	}
	return n.Host
}
