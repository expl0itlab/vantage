package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type AlertEvent struct {
	Domain    string
	EventType string
	Value     string
	Severity  string
	Title     string
	Details   map[string]interface{}
	ScanID    int64
}

type AlertConfig struct {
	NewSubdomain    bool
	HighRiskPort    bool
	JSSecret        bool
	InterestingHost bool
	HostDown        bool
	NewTechnology   bool
}

type AlertDB interface {
	HasAlerted(domain, eventType, value string) (bool, error)
	RecordAlert(domain, eventType, message string, success bool) error
}

type AlertManager struct {
	db       AlertDB
	botToken string
	chatID   string
	minSev   string
	newOnly  bool
	alertOn  AlertConfig
	client   *http.Client
	logger   func(string, ...interface{})

	mu      sync.Mutex
	buffers map[string]*scanBuffer
}

type scanBuffer struct {
	domain      string
	subdomains  []string
	hosts       []alertEntry
	ports       []alertEntry
	secrets     []alertEntry
	interesting []alertEntry
	down        []alertEntry
	tech        []alertEntry
	cloud       []alertEntry
}

type alertEntry struct {
	summary string
	detail  string
	severity string
}

func New(db AlertDB, botToken, chatID, minSeverity string, newOnly bool, alertOn AlertConfig, logger func(string, ...interface{})) *AlertManager {
	return &AlertManager{
		db:       db,
		botToken: botToken,
		chatID:   chatID,
		minSev:   minSeverity,
		newOnly:  newOnly,
		alertOn:  alertOn,
		client:   &http.Client{Timeout: 10 * time.Second},
		buffers:  make(map[string]*scanBuffer),
		logger:   logger,
	}
}

func (a *AlertManager) Start() {}

func (a *AlertManager) Close() {}

func (a *AlertManager) getBuffer(domain string) *scanBuffer {
	a.mu.Lock()
	defer a.mu.Unlock()
	if b, ok := a.buffers[domain]; ok {
		return b
	}
	b := &scanBuffer{domain: domain}
	a.buffers[domain] = b
	return b
}

func (a *AlertManager) Send(event AlertEvent) {
	if !a.isAlertEnabled(event.EventType) {
		return
	}
	if !a.meetsSeverity(event.Severity) {
		return
	}
	if a.newOnly {
		has, err := a.db.HasAlerted(event.Domain, event.EventType, event.Value)
		if err == nil && has {
			return
		}
	}

	b := a.getBuffer(event.Domain)
	summary, detail := a.extractEntry(event)

	a.mu.Lock()
	switch event.EventType {
	case "new_subdomain", "new_host":
		b.subdomains = append(b.subdomains, summary)
	case "high_risk_port":
		b.ports = append(b.ports, alertEntry{summary: summary, detail: detail, severity: event.Severity})
	case "js_secret":
		b.secrets = append(b.secrets, alertEntry{summary: summary, detail: detail, severity: event.Severity})
	case "interesting_host":
		b.interesting = append(b.interesting, alertEntry{summary: summary, detail: detail, severity: event.Severity})
	case "host_down":
		b.down = append(b.down, alertEntry{summary: summary, detail: detail, severity: event.Severity})
	case "new_technology":
		b.tech = append(b.tech, alertEntry{summary: summary, detail: detail, severity: event.Severity})
	case "cloud_exposure":
		b.cloud = append(b.cloud, alertEntry{summary: summary, detail: detail, severity: event.Severity})
	}
	a.mu.Unlock()
}

func (a *AlertManager) Flush(domain string) {
	a.mu.Lock()
	b, ok := a.buffers[domain]
	if !ok || b == nil {
		a.mu.Unlock()
		return
	}
	delete(a.buffers, domain)
	a.mu.Unlock()

	msg := a.buildSummary(b)
	if msg == "" {
		return
	}

	success := a.doSend(msg)
	_ = a.db.RecordAlert(domain, "scan_summary", msg, success)
	if success {
		a.logger("[alerting] summary sent for %s", domain)
	}
}

func (a *AlertManager) buildSummary(b *scanBuffer) string {
	var sb strings.Builder

	total := len(b.subdomains) + len(b.ports) + len(b.secrets) + len(b.interesting) + len(b.down) + len(b.tech) + len(b.cloud)
	if total == 0 {
		return ""
	}

	sb.WriteString(fmt.Sprintf("🎯 <b>VANTAGE — %s</b>\n", a.escapeHTML(b.domain)))
	sb.WriteString(fmt.Sprintf("─ totals: %d sub · %d host · %d port · %d secret · %d cloud\n\n", len(b.subdomains), len(b.interesting), len(b.ports), len(b.secrets), len(b.cloud)))

	if len(b.interesting) > 0 {
		sb.WriteString("🔴 <b>interesting targets</b>\n")
		for _, e := range b.interesting {
			sb.WriteString(fmt.Sprintf("  %s\n", e.summary))
		}
		sb.WriteString("\n")
	}

	if len(b.secrets) > 0 {
		sb.WriteString("🔑 <b>secrets found</b>\n")
		for _, e := range b.secrets {
			sb.WriteString(fmt.Sprintf("  %s\n", e.summary))
		}
		sb.WriteString("\n")
	}

	if len(b.ports) > 0 {
		sb.WriteString("🚪 <b>high-risk ports</b>\n")
		for _, e := range b.ports {
			sb.WriteString(fmt.Sprintf("  %s\n", e.summary))
		}
		sb.WriteString("\n")
	}

	if len(b.cloud) > 0 {
		sb.WriteString("☁️ <b>cloud exposure</b>\n")
		for _, e := range b.cloud {
			sb.WriteString(fmt.Sprintf("  %s\n", e.summary))
		}
		sb.WriteString("\n")
	}

	if len(b.tech) > 0 {
		sb.WriteString("🛠 <b>technology</b>\n")
		for _, e := range b.tech {
			sb.WriteString(fmt.Sprintf("  %s\n", e.summary))
		}
		sb.WriteString("\n")
	}

	if len(b.down) > 0 {
		sb.WriteString("⚠️ <b>host down</b>\n")
		for _, e := range b.down {
			sb.WriteString(fmt.Sprintf("  %s\n", e.summary))
		}
		sb.WriteString("\n")
	}

	if len(b.subdomains) > 0 {
		subs := b.subdomains
		if len(subs) > 15 {
			sort.Strings(subs)
			sb.WriteString(fmt.Sprintf("📁 <b>new subdomains</b> (%d)\n", len(subs)))
			for _, s := range subs[:15] {
				sb.WriteString(fmt.Sprintf("  %s\n", s))
			}
			sb.WriteString(fmt.Sprintf("  ... +%d more\n", len(subs)-15))
		} else {
			sb.WriteString(fmt.Sprintf("📁 <b>new subdomains</b> (%d)\n", len(subs)))
			for _, s := range subs {
				sb.WriteString(fmt.Sprintf("  %s\n", s))
			}
		}
		sb.WriteString("\n")
	}

	result := strings.TrimSpace(sb.String())
	return result
}

func (a *AlertManager) extractEntry(event AlertEvent) (summary string, detail string) {
	d := event.Details
	switch event.EventType {
	case "new_subdomain", "new_host":
		ip := a.getDetailString(d, "ip")
		resolved := ""
		if a.getDetailBool(d, "resolved") || ip != "" {
			resolved = " ✓"
		}
		if ip != "" {
			return fmt.Sprintf("%s (%s%s)", a.escapeHTML(event.Value), a.escapeHTML(ip), resolved), ""
		}
		return fmt.Sprintf("%s%s", a.escapeHTML(event.Value), resolved), ""

	case "high_risk_port":
		ip := a.getDetailString(d, "ip")
		port := a.getDetailString(d, "port")
		service := a.getDetailString(d, "service")
		return fmt.Sprintf("%s:%s %s", a.escapeHTML(ip), a.escapeHTML(port), a.escapeHTML(service)), ""

	case "js_secret":
		secretType := a.getDetailString(d, "type")
		jsURL := a.getDetailString(d, "js_url")
		shortURL := jsURL
		if len(shortURL) > 60 {
			parts := strings.Split(shortURL, "/")
			if len(parts) > 3 {
				shortURL = ".../" + strings.Join(parts[len(parts)-2:], "/")
			}
		}
		return fmt.Sprintf("[%s] %s", a.escapeHTML(secretType), a.escapeHTML(shortURL)), ""

	case "interesting_host":
		url := a.getDetailString(d, "url")
		tag := a.getDetailString(d, "tag")
		code := a.getDetailString(d, "status_code")
		title := a.getDetailString(d, "title")
		if len(title) > 40 {
			title = title[:40] + "..."
		}
		return fmt.Sprintf("%s [%s] %s — %s", a.escapeHTML(url), code, a.escapeHTML(tag), a.escapeHTML(title)), ""

	case "host_down":
		url := a.getDetailString(d, "url")
		return fmt.Sprintf("%s", a.escapeHTML(url)), ""

	case "new_technology":
		tech := a.getDetailString(d, "tech")
		host := a.getDetailString(d, "url")
		return fmt.Sprintf("%s @ %s", a.escapeHTML(tech), a.escapeHTML(host)), ""

	case "cloud_exposure":
		findType := a.getDetailString(d, "finding_type")
		provider := a.getDetailString(d, "provider")
		url := a.getDetailString(d, "url")
		return fmt.Sprintf("[%s] %s %s", a.escapeHTML(provider), a.escapeHTML(findType), a.escapeHTML(url)), ""
	}
	return event.Value, ""
}

func (a *AlertManager) isAlertEnabled(eventType string) bool {
	switch eventType {
	case "new_subdomain", "new_host":
		return a.alertOn.NewSubdomain
	case "high_risk_port":
		return a.alertOn.HighRiskPort
	case "js_secret":
		return a.alertOn.JSSecret
	case "interesting_host":
		return a.alertOn.InterestingHost
	case "host_down":
		return a.alertOn.HostDown
	case "new_technology":
		return a.alertOn.NewTechnology
	case "cloud_exposure":
		return true
	default:
		return true
	}
}

func (a *AlertManager) meetsSeverity(severity string) bool {
	levels := map[string]int{
		"critical": 0,
		"high":     1,
		"medium":   2,
		"low":      3,
		"info":     4,
	}
	eventLevel, ok := levels[strings.ToLower(severity)]
	if !ok {
		return false
	}
	minLevel, ok := levels[strings.ToLower(a.minSev)]
	if !ok {
		return true
	}
	return eventLevel <= minLevel
}

func (a *AlertManager) doSend(message string) bool {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", a.botToken)

	payload := map[string]interface{}{
		"chat_id":                  a.chatID,
		"text":                     message,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		a.logger("failed to marshal telegram payload: %v", err)
		return false
	}

	time.Sleep(200 * time.Millisecond)

	resp, err := a.client.Post(apiURL, "application/json", bytes.NewReader(data))
	if err != nil {
		a.logger("telegram send failed: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.logger("telegram API returned status %d", resp.StatusCode)
		return false
	}

	return true
}

func (a *AlertManager) escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func (a *AlertManager) getDetailString(details map[string]interface{}, key string) string {
	if details == nil {
		return ""
	}
	val, ok := details[key]
	if !ok {
		return ""
	}
	if s, ok := val.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", val)
}

func (a *AlertManager) getDetailBool(details map[string]interface{}, key string) bool {
	if details == nil {
		return false
	}
	val, ok := details[key]
	if !ok {
		return false
	}
	b, ok := val.(bool)
	return ok && b
}
