package dashboard

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/expl0itlab/vantage/internal/config"
	"github.com/expl0itlab/vantage/internal/db"
	"github.com/expl0itlab/vantage/internal/export"
	"github.com/expl0itlab/vantage/internal/models"
)

//go:embed templates/*.html
var templateFS embed.FS

type Server struct {
	cfg       *config.Config
	db        *db.DB
	logger    func(string, ...interface{})
	mux       *http.ServeMux
	startScan func(domain, profile string) error

	sseMu      sync.RWMutex
	sseClients map[chan string]struct{}
}

func New(cfg *config.Config, database *db.DB, logger func(string, ...interface{})) *Server {
	if logger == nil {
		logger = func(s string, a ...interface{}) { fmt.Printf("[dashboard] "+s+"\n", a...) }
	}
	s := &Server{
		cfg:        cfg,
		db:         database,
		logger:     logger,
		mux:        http.NewServeMux(),
		sseClients: make(map[chan string]struct{}),
	}
	s.registerRoutes()
	return s
}

func (s *Server) SetScanHandler(fn func(domain, profile string) error) { s.startScan = fn }

func (s *Server) BroadcastEvent(eventType string, data interface{}) {
	payload, err := json.Marshal(map[string]interface{}{
		"type": eventType, "data": data, "ts": time.Now().Unix(),
	})
	if err != nil {
		return
	}
	msg := fmt.Sprintf("data: %s\n\n", payload)
	s.sseMu.RLock()
	defer s.sseMu.RUnlock()
	for ch := range s.sseClients {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Dashboard.Host, s.cfg.Dashboard.Port)
	s.logger("dashboard: http://%s", addr)
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.authMiddleware(s.mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	if s.cfg.Dashboard.Username == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != s.cfg.Dashboard.Username || pass != s.cfg.Dashboard.Password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Vantage"`)
			http.Error(w, "Unauthorized", 401)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerRoutes() {
	// Pages
	s.mux.HandleFunc("/", s.page("dashboard"))
	s.mux.HandleFunc("/assets", s.page("assets"))
	s.mux.HandleFunc("/hosts", s.page("hosts"))
	s.mux.HandleFunc("/ports", s.page("ports"))
	s.mux.HandleFunc("/js-findings", s.page("js-findings"))
	s.mux.HandleFunc("/interesting", s.page("interesting"))
	s.mux.HandleFunc("/changes", s.page("changes"))
	s.mux.HandleFunc("/scans", s.page("scans"))
	s.mux.HandleFunc("/attack-surface", s.page("attack-surface"))

	// Screenshots static
	screenshotDir := s.cfg.Scanning.Screenshot.OutputDir
	if screenshotDir != "" {
		s.mux.Handle("/screenshots/", http.StripPrefix("/screenshots/",
			http.FileServer(http.Dir(screenshotDir))))
	}

	// API
	s.mux.HandleFunc("/api/stats", s.apiStats)
	s.mux.HandleFunc("/api/assets", s.apiAssets)
	s.mux.HandleFunc("/api/hosts", s.apiHosts)
	s.mux.HandleFunc("/api/ports", s.apiPorts)
	s.mux.HandleFunc("/api/js-findings", s.apiJSFindings)
	s.mux.HandleFunc("/api/changes", s.apiChanges)
	s.mux.HandleFunc("/api/scans", s.apiScans)
	s.mux.HandleFunc("/api/scan/start", s.apiStartScan)
	s.mux.HandleFunc("/api/domains", s.apiDomains)
	s.mux.HandleFunc("/api/wipe", s.apiWipe)

	// Exports
	s.mux.HandleFunc("/api/export/json", s.apiExportJSON)
	s.mux.HandleFunc("/api/export/csv", s.apiExportCSV)
	s.mux.HandleFunc("/api/export/caido", s.apiExportCaido)
	s.mux.HandleFunc("/api/export/burp", s.apiExportBurp)
	s.mux.HandleFunc("/api/export/msf", s.apiExportMSF)
	s.mux.HandleFunc("/api/export/targets", s.apiExportTargets)

	// SSE
	s.mux.HandleFunc("/api/events", s.handleSSE)
}

// ──────────────────────────── PAGE RENDERER ────────────────────────────

func (s *Server) page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if name == "dashboard" && r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		titles := map[string]string{
			"dashboard": "Dashboard", "assets": "Assets", "hosts": "Live Hosts",
			"ports": "Ports & Services", "js-findings": "JS Analysis",
			"interesting": "Interesting Targets", "changes": "Change Tracking",
			"scans": "Scan History", "attack-surface": "Attack Surface",
		}
		s.renderPage(w, name, map[string]interface{}{
			"Title": titles[name],
			"Name":  name,
		})
	}
}

func (s *Server) renderPage(w http.ResponseWriter, name string, data interface{}) {
	baseBytes, err := templateFS.ReadFile("templates/base.html")
	if err != nil {
		http.Error(w, "template error: "+err.Error(), 500)
		return
	}
	pageBytes, err := templateFS.ReadFile("templates/" + name + ".html")
	if err != nil {
		http.Error(w, "template not found: "+name, 500)
		return
	}

	t, err := template.New("base").Funcs(template.FuncMap{
		"lower": strings.ToLower,
		"upper": strings.ToUpper,
	}).Parse(string(baseBytes) + string(pageBytes))
	if err != nil {
		log.Printf("template parse error: %v", err)
		http.Error(w, "template error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		log.Printf("template exec error: %v", err)
	}
}

// ──────────────────────────── API HANDLERS ────────────────────────────

func (s *Server) apiStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.GetDashboardStats()
	if err != nil {
		jsonError(w, err, 500)
		return
	}
	jsonOK(w, stats)
}

func (s *Server) apiAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	assets, total, err := s.db.GetAllAssets(db.AssetFilter{
		Domain:      q.Get("domain"),
		Search:      q.Get("search"),
		Status:      q.Get("status"),
		Interesting: q.Get("interesting") == "1",
		OrderBy:     q.Get("order_by"),
		OrderDir:    q.Get("order_dir"),
		Limit:       intQ(q.Get("limit"), 100),
		Page:        intQ(q.Get("page"), 1),
	})
	if err != nil {
		jsonError(w, err, 500)
		return
	}
	jsonPage(w, assets, total, intQ(q.Get("page"), 1), intQ(q.Get("limit"), 100))
}

func (s *Server) apiHosts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hosts, total, err := s.db.GetHosts(db.HostFilter{
		Domain:      q.Get("domain"),
		Search:      q.Get("search"),
		StatusCode:  intQ(q.Get("status_code"), 0),
		Interesting: q.Get("interesting") == "1",
		Limit:       intQ(q.Get("limit"), 50),
		Page:        intQ(q.Get("page"), 1),
	})
	if err != nil {
		jsonError(w, err, 500)
		return
	}
	jsonPage(w, hosts, total, intQ(q.Get("page"), 1), intQ(q.Get("limit"), 50))
}

func (s *Server) apiPorts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ports, total, err := s.db.GetPorts(db.PortFilter{
		Domain:      q.Get("domain"),
		IP:          q.Get("ip"),
		Port:        intQ(q.Get("port"), 0),
		Search:      q.Get("search"),
		RiskLevel:   q.Get("risk"),
		Interesting: q.Get("interesting") == "1",
		Limit:       intQ(q.Get("limit"), 200),
		Page:        intQ(q.Get("page"), 1),
	})
	if err != nil {
		jsonError(w, err, 500)
		return
	}
	jsonPage(w, ports, total, intQ(q.Get("page"), 1), intQ(q.Get("limit"), 200))
}

func (s *Server) apiJSFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	findings, total, err := s.db.GetJSFindings(db.JSFindingFilter{
		Domain:      q.Get("domain"),
		FindingType: q.Get("type"),
		Severity:    q.Get("severity"),
		Search:      q.Get("search"),
		Limit:       intQ(q.Get("limit"), 100),
		Page:        intQ(q.Get("page"), 1),
	})
	if err != nil {
		jsonError(w, err, 500)
		return
	}
	jsonPage(w, findings, total, intQ(q.Get("page"), 1), intQ(q.Get("limit"), 100))
}

func (s *Server) apiChanges(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var scanID int64
	if sid := q.Get("scan_id"); sid != "" {
		scanID, _ = strconv.ParseInt(sid, 10, 64)
	}
	events, total, err := s.db.GetChangeEvents(db.ChangeFilter{
		Domain:    q.Get("domain"),
		EventType: q.Get("event_type"),
		Severity:  q.Get("severity"),
		ScanID:    scanID,
		Limit:     intQ(q.Get("limit"), 100),
		Page:      intQ(q.Get("page"), 1),
	})
	if err != nil {
		jsonError(w, err, 500)
		return
	}
	jsonPage(w, events, total, intQ(q.Get("page"), 1), intQ(q.Get("limit"), 100))
}

func (s *Server) apiScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.db.GetScans(intQ(r.URL.Query().Get("limit"), 100))
	if err != nil {
		jsonError(w, err, 500)
		return
	}
	if scans == nil {
		scans = []models.Scan{}
	}
	jsonOK(w, scans)
}

func (s *Server) apiStartScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	var body struct {
		Domain  string `json:"domain"`
		Profile string `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Domain == "" {
		jsonError(w, fmt.Errorf("domain required"), 400)
		return
	}
	if body.Profile == "" {
		body.Profile = "standard"
	}
	if s.startScan == nil {
		jsonError(w, fmt.Errorf("scan handler not configured"), 500)
		return
	}
	go func() {
		if err := s.startScan(strings.TrimSpace(strings.ToLower(body.Domain)), body.Profile); err != nil {
			s.logger("scan error for %s: %v", body.Domain, err)
		}
	}()
	jsonOK(w, map[string]string{"status": "started", "domain": body.Domain, "profile": body.Profile})
}

func (s *Server) apiDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := s.db.GetDomains()
	if err != nil {
		jsonError(w, err, 500)
		return
	}
	if domains == nil {
		domains = []string{}
	}
	jsonOK(w, domains)
}

func (s *Server) apiWipe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	var body struct {
		Domain string `json:"domain"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	var err error
	if body.Domain == "" {
		err = s.db.WipeAll()
	} else {
		err = s.db.WipeDomain(body.Domain)
	}
	if err != nil {
		jsonError(w, err, 500)
		return
	}
	msg := "All data wiped"
	if body.Domain != "" {
		msg = "Wiped: " + body.Domain
	}
	jsonOK(w, map[string]string{"status": "ok", "message": msg})
}

// ──────────────────────────── EXPORTS ────────────────────────────

func (s *Server) apiExportJSON(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		jsonError(w, fmt.Errorf("domain required"), 400)
		return
	}
	data, err := s.db.ExportDomain(domain)
	if err != nil {
		jsonError(w, err, 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="vantage-%s-%s.json"`, domain, time.Now().Format("20060102")))
	json.NewEncoder(w).Encode(data)
}

func (s *Server) apiExportCSV(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	kind := r.URL.Query().Get("type")
	if domain == "" {
		jsonError(w, fmt.Errorf("domain required"), 400)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="vantage-%s-%s-%s.csv"`, kind, domain, time.Now().Format("20060102")))

	switch kind {
	case "assets":
		assets, _, _ := s.db.GetAllAssets(db.AssetFilter{Domain: domain, Limit: 100000})
		fmt.Fprintln(w, "subdomain,domain,ip,type,status,interesting,interest_tag,first_seen")
		for _, a := range assets {
			fmt.Fprintf(w, "%s,%s,%s,%s,%s,%v,%s,%s\n",
				csv(a.Subdomain), csv(a.Domain), csv(a.IP), a.AssetType, a.Status,
				a.Interesting, csv(a.InterestTag), a.FirstSeen.Format("2006-01-02 15:04:05"))
		}
	case "hosts":
		hosts, _, _ := s.db.GetHosts(db.HostFilter{Domain: domain, Limit: 100000})
		fmt.Fprintln(w, "url,status_code,title,server,ip,technologies,cdn,interesting,interest_tag,screenshot")
		for _, h := range hosts {
			fmt.Fprintf(w, "%s,%d,%s,%s,%s,%s,%s,%v,%s,%s\n",
				csv(h.URL), h.StatusCode, csv(h.Title), csv(h.Server), csv(h.IP),
				csv(h.Technologies), csv(h.CDN), h.Interesting, csv(h.InterestTag), csv(h.ScreenshotPath))
		}
	case "ports":
		ports, _, _ := s.db.GetPorts(db.PortFilter{Domain: domain, Limit: 100000})
		fmt.Fprintln(w, "ip,port,protocol,service,version,banner,risk_level,interesting")
		for _, p := range ports {
			fmt.Fprintf(w, "%s,%d,%s,%s,%s,%s,%s,%v\n",
				csv(p.IP), p.Port, p.Protocol, csv(p.Service), csv(p.Version),
				csv(p.Banner), p.RiskLevel, p.Interesting)
		}
	case "js":
		findings, _, _ := s.db.GetJSFindings(db.JSFindingFilter{Domain: domain, Limit: 100000})
		fmt.Fprintln(w, "js_url,finding_type,severity,value,context,first_seen")
		for _, f := range findings {
			fmt.Fprintf(w, "%s,%s,%s,%s,%s,%s\n",
				csv(f.JSURL), csv(f.FindingType), f.Severity,
				csv(f.Value), csv(f.Context), f.FirstSeen.Format("2006-01-02 15:04:05"))
		}
	default:
		http.Error(w, "unknown type", 400)
	}
}

func (s *Server) apiExportCaido(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		jsonError(w, fmt.Errorf("domain required"), 400)
		return
	}
	hosts, _, _ := s.db.GetHosts(db.HostFilter{Domain: domain, Limit: 100000})
	data, err := export.ToCaidoScope(domain, hosts)
	if err != nil {
		jsonError(w, err, 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="caido-scope-%s.json"`, domain))
	w.Write(data)
}

func (s *Server) apiExportBurp(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		jsonError(w, fmt.Errorf("domain required"), 400)
		return
	}
	hosts, _, _ := s.db.GetHosts(db.HostFilter{Domain: domain, Limit: 100000})
	data, err := export.ToBurpScope(domain, hosts)
	if err != nil {
		jsonError(w, err, 500)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="burp-scope-%s.xml"`, domain))
	w.Write(data)
}

func (s *Server) apiExportMSF(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		jsonError(w, fmt.Errorf("domain required"), 400)
		return
	}
	hosts, _, _ := s.db.GetHosts(db.HostFilter{Domain: domain, Limit: 100000})
	ports, _, _ := s.db.GetPorts(db.PortFilter{Domain: domain, Limit: 100000})
	rc := export.ToMetasploitRC(domain, hosts, ports)
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="vantage-%s.rc"`, domain))
	w.Write([]byte(rc))
}

func (s *Server) apiExportTargets(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	kind := r.URL.Query().Get("type") // urls, ips, ip-ports
	if domain == "" {
		jsonError(w, fmt.Errorf("domain required"), 400)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="targets-%s-%s.txt"`, kind, domain))
	switch kind {
	case "urls":
		hosts, _, _ := s.db.GetHosts(db.HostFilter{Domain: domain, Limit: 100000})
		w.Write([]byte(export.ToTargetList(hosts)))
	case "ips":
		ports, _, _ := s.db.GetPorts(db.PortFilter{Domain: domain, Limit: 100000})
		w.Write([]byte(export.ToIPList(ports)))
	case "ip-ports":
		ports, _, _ := s.db.GetPorts(db.PortFilter{Domain: domain, Limit: 100000})
		w.Write([]byte(export.ToIPPortList(ports)))
	default:
		hosts, _, _ := s.db.GetHosts(db.HostFilter{Domain: domain, Limit: 100000})
		w.Write([]byte(export.ToTargetList(hosts)))
	}
}

// ──────────────────────────── SSE ────────────────────────────

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := make(chan string, 32)
	s.sseMu.Lock()
	s.sseClients[ch] = struct{}{}
	s.sseMu.Unlock()
	defer func() {
		s.sseMu.Lock()
		delete(s.sseClients, ch)
		s.sseMu.Unlock()
	}()

	fmt.Fprintf(w, "data: {\"type\":\"connected\"}\n\n")
	flusher.Flush()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case msg := <-ch:
			fmt.Fprint(w, msg)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// ──────────────────────────── HELPERS ────────────────────────────

type pageResp struct {
	Data  interface{} `json:"data"`
	Total int         `json:"total"`
	Page  int         `json:"page"`
	Limit int         `json:"limit"`
	Pages int         `json:"pages"`
}

func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
}

func jsonPage(w http.ResponseWriter, data interface{}, total, page, limit int) {
	pages := 1
	if limit > 0 {
		pages = (total + limit - 1) / limit
	}
	if pages == 0 {
		pages = 1
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pageResp{Data: data, Total: total, Page: page, Limit: limit, Pages: pages})
}

func jsonError(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func intQ(s string, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

func csv(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// ensure templates dir is available for embed
var _ fs.ReadFileFS = templateFS
