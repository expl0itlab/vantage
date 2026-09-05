package processor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/expl0itlab/vantage/internal/attacksurface"
	"github.com/expl0itlab/vantage/internal/banner"
	"github.com/expl0itlab/vantage/internal/config"
	"github.com/expl0itlab/vantage/internal/db"
	"github.com/expl0itlab/vantage/internal/discovery"
	"github.com/expl0itlab/vantage/internal/jsanalysis"
	"github.com/expl0itlab/vantage/internal/models"
	"github.com/expl0itlab/vantage/internal/netexpand"
	"github.com/expl0itlab/vantage/internal/scanner"
	"github.com/expl0itlab/vantage/internal/screenshot"
)

type Processor struct {
	cfg          *config.Config
	db           *db.DB
	discoverer   *discovery.Discoverer
	scanner      *scanner.Scanner
	jsAnalyzer   *jsanalysis.Analyzer
	bannerGrab   *banner.Grabber
	screenshoter *screenshot.Engine
	netExpand    *netexpand.Expander
	logger       func(string, ...interface{})
	onEvent      func(string, interface{})
}

func New(cfg *config.Config, database *db.DB, logger func(string, ...interface{})) *Processor {
	if logger == nil {
		logger = func(s string, a ...interface{}) { fmt.Printf("[processor] "+s+"\n", a...) }
	}
	return &Processor{
		cfg:        cfg,
		db:         database,
		discoverer: discovery.New(cfg, logger),
		scanner:    scanner.New(cfg, logger),
		jsAnalyzer: jsanalysis.New(&cfg.Scanning.JSAnalysis, logger),
		bannerGrab: banner.New(cfg.Scanning.Banner.Timeout, cfg.Scanning.Banner.Threads, logger),
		screenshoter: screenshot.New(
			cfg.Tools.GoWitnessPath,
			cfg.Scanning.Screenshot.OutputDir,
			cfg.Scanning.Screenshot.Timeout,
			cfg.Scanning.Screenshot.Threads,
			logger,
		),
		netExpand: netexpand.New(
			cfg.Tools.NaabuPath,
			cfg.Scanning.NetExpand.MaxHosts,
			cfg.Scanning.NetExpand.Ports,
			logger,
		),
		logger:  logger,
		onEvent: func(string, interface{}) {},
	}
}

func (p *Processor) SetEventHook(fn func(string, interface{})) { p.onEvent = fn }

type ScanResult struct {
	ScanID  int64
	Domain  string
	Profile string
	Stats   models.Scan
	Changes []models.ChangeEvent
	Errors  []string
}

func (p *Processor) RunScan(ctx context.Context, domain, profileName string) (*ScanResult, error) {
	start := time.Now()
	if profileName == "" {
		profileName = "standard"
	}
	profile := p.cfg.GetProfile(profileName)

	p.logger("═══ Scan [%s] for %s ═══", strings.ToUpper(profileName), domain)

	cfgJSON, _ := json.Marshal(map[string]interface{}{"profile": profileName, "domain": domain})
	scanID, err := p.db.CreateScan(domain, profileName, string(cfgJSON))
	if err != nil {
		return nil, fmt.Errorf("creating scan: %w", err)
	}

	result := &ScanResult{ScanID: scanID, Domain: domain, Profile: profileName}
	p.onEvent("scan_started", map[string]interface{}{
		"scan_id": scanID, "domain": domain, "profile": profileName,
	})

	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("panic: %v", r)
			p.db.FailScan(scanID, msg)
			result.Errors = append(result.Errors, msg)
		}
	}()

	// ── Phase 1: Discovery ────────────────────────────────────────
	p.phase(scanID, "discovery", domain)
	discoveries, err := p.discoverer.Discover(ctx, domain, profile)
	if err != nil {
		p.logger("[1] discovery error: %v", err)
		result.Errors = append(result.Errors, err.Error())
	}
	discoveries = append(discoveries, discovery.Result{Subdomain: domain, Source: "root"})

	// Deduplicate
	subSeen := map[string]bool{}
	var uniqueSubs []string
	for _, d := range discoveries {
		if !subSeen[d.Subdomain] {
			subSeen[d.Subdomain] = true
			uniqueSubs = append(uniqueSubs, d.Subdomain)
		}
	}
	p.logger("[1] %d unique subdomains", len(uniqueSubs))

	// ── Phase 2: DNS Resolution ───────────────────────────────────
	p.phase(scanID, "dns", domain)
	ipMap, _ := p.discoverer.DNSResolve(ctx, uniqueSubs)

	resolved := 0
	for _, v := range ipMap {
		if v != "" {
			resolved++
		}
	}
	p.logger("[2] resolved %d/%d", resolved, len(uniqueSubs))

	// Store assets
	assetIDMap := map[string]int64{}
	for _, sub := range uniqueSubs {
		ip := ipMap[sub]
		asset := models.Asset{
			Domain: domain, Subdomain: sub, IP: ip,
			AssetType: assetType(sub, domain), ScanID: scanID,
		}
		id, isNew, err := p.db.UpsertAsset(asset)
		if err != nil {
			continue
		}
		assetIDMap[sub] = id
		result.Stats.AssetsFound++
		if isNew {
			p.change(scanID, domain, "new_subdomain", "medium",
				fmt.Sprintf("New subdomain: %s (%s)", sub, ip),
				map[string]interface{}{"subdomain": sub, "ip": ip})
		}
	}
	p.logger("[2] stored %d assets", result.Stats.AssetsFound)

	// ── Phase 3: HTTP Probing ─────────────────────────────────────
	p.phase(scanID, "httpx", domain)
	httpxResults, err := p.scanner.RunHTTPx(ctx, uniqueSubs, profile)
	if err != nil {
		p.logger("[3] httpx error: %v", err)
		result.Errors = append(result.Errors, err.Error())
	}

	liveURLs := make([]string, 0)
	hostIDMap := map[string]int64{}
	var liveHosts []models.Host

	for _, hr := range httpxResults {
		assetID := p.resolveAssetID(assetIDMap, hr.Input, hr.URL, domain)
		resolvedIP := hr.FirstIP()
		if resolvedIP != "" && assetID > 0 {
			p.db.UpdateAssetIP(assetID, resolvedIP)
			if ipMap[normalizeHost(hr.Input)] == "" {
				ipMap[normalizeHost(hr.Input)] = resolvedIP
			}
		}

		techJSON, _ := json.Marshal(hr.Technologies)
		headerJSON, _ := json.Marshal(hr.Headers)
		tlsJSON := "{}"
		if hr.TLS != nil {
			b, _ := json.Marshal(hr.TLS)
			tlsJSON = string(b)
		}

		// Attack surface analysis
		asSurface := attacksurface.Analyze(
			hr.Technologies, hr.Server, hr.Title, hr.URL, 0, hr.StatusCode,
		)
		asJSON := attacksurface.ToJSON(asSurface)

		// Skip failed results
		if hr.Failed {
			continue
		}
		// If status code is 0 and we have a location, it means redirect wasn't followed
		// Use 301/302 as the code in that case
		if hr.StatusCode == 0 && hr.Location != "" {
			hr.StatusCode = 301
		}

		interesting, interestTag := classifyHost(hr.URL, hr.Title, hr.Technologies)

		host := models.Host{
			AssetID: assetID, URL: hr.URL, StatusCode: hr.StatusCode,
			Title: truncate(hr.Title, 255), ContentType: hr.ContentType,
			Server: hr.Server, Technologies: string(techJSON),
			Headers: string(headerJSON), TLSInfo: tlsJSON,
			WebServer: hr.WebServer, CDN: hr.CDNName, IP: resolvedIP,
			Interesting: interesting, InterestTag: interestTag,
			AttackSurface: asJSON, ScanID: scanID,
		}

		hostID, isNew, err := p.db.UpsertHost(host)
		if err != nil {
			continue
		}
		hostIDMap[hr.URL] = hostID
		result.Stats.HostsFound++
		liveURLs = append(liveURLs, hr.URL)
		host.ID = hostID
		liveHosts = append(liveHosts, host)

		if isNew {
			sev := "info"
			if interesting {
				sev = "high"
			}
			p.change(scanID, domain, "new_host", sev,
				fmt.Sprintf("New host: %s [%d] %s", hr.URL, hr.StatusCode, hr.Title),
				map[string]interface{}{
					"url": hr.URL, "status_code": hr.StatusCode,
					"title": hr.Title, "server": hr.Server,
					"interesting": interesting, "interest_tag": interestTag,
					"attack_surface": len(asSurface),
				})
		}

		// Store fingerprints
		for _, tech := range hr.Technologies {
			name, ver := parseTech(tech)
			if name != "" {
				p.db.UpsertFingerprint(models.Fingerprint{
					AssetID: assetID, HostID: hostID, Technology: name,
					Version: ver, Category: categorizeTech(name),
					Confidence: 80, Source: "httpx",
				})
			}
		}
	}
	p.logger("[3] %d live hosts", result.Stats.HostsFound)

	// ── Phase 4: Port Scanning ────────────────────────────────────
	uniqueIPs := uniqueValues(ipMap)

	// Net expansion (aggressive profile)
	if profile.NetExpand && p.cfg.Scanning.NetExpand.Enabled && len(uniqueIPs) > 0 {
		p.phase(scanID, "net-expand", domain)
		expanded := p.netExpand.ExpandIPs(ctx, uniqueIPs)
		for _, r := range expanded {
			if !contains(uniqueIPs, r.IP) {
				uniqueIPs = append(uniqueIPs, r.IP)
				// Store as asset
				asset := models.Asset{
					Domain: domain, Subdomain: r.IP, IP: r.IP,
					AssetType: "ip", NetRange: r.NetRange, ScanID: scanID,
				}
				id, isNew, _ := p.db.UpsertAsset(asset)
				if isNew {
					assetIDMap[r.IP] = id
					result.Stats.AssetsFound++
					p.change(scanID, domain, "new_ip_expanded", "medium",
						fmt.Sprintf("Network expansion found: %s (from %s range %s)", r.IP, r.Source, r.NetRange),
						map[string]interface{}{"ip": r.IP, "source": r.Source, "range": r.NetRange})
				}
			}
		}
		p.logger("[4-expand] %d total IPs after expansion", len(uniqueIPs))
	}

	p.phase(scanID, "naabu", domain)
	p.logger("[4] port scanning %d IPs", len(uniqueIPs))
	naabuResults, err := p.scanner.RunNaabu(ctx, uniqueIPs, profile)
	if err != nil {
		p.logger("[4] naabu error: %v", err)
		result.Errors = append(result.Errors, err.Error())
	}

	// Banner grabbing
	var bannerMap map[string]banner.Result
	if profile.BannerGrab && p.cfg.Scanning.Banner.Enabled && len(naabuResults) > 0 {
		p.phase(scanID, "banner", domain)
		var portModels []models.Port
		for _, nr := range naabuResults {
			portModels = append(portModels, models.Port{
				IP: nr.EffectiveIP(), Port: nr.Port, Protocol: nr.Protocol,
			})
		}
		bannerResults := p.bannerGrab.GrabAll(portModels)
		bannerMap = make(map[string]banner.Result)
		for _, br := range bannerResults {
			key := fmt.Sprintf("%s:%d", br.IP, br.Port)
			bannerMap[key] = br
		}
	}

	for _, nr := range naabuResults {
		ip := nr.EffectiveIP()
		key := fmt.Sprintf("%s:%d", ip, nr.Port)
		assetID := p.resolveAssetIDByIP(assetIDMap, ipMap, ip)
		proto := nr.Protocol
		if proto == "" {
			proto = "tcp"
		}

		svc := classifyPort(nr.Port)
		ver := ""
		bannerStr := ""

		if bannerMap != nil {
			if br, ok := bannerMap[key]; ok {
				if br.Service != "" {
					svc.name = br.Service
				}
				if br.Version != "" {
					ver = br.Version
				}
				bannerStr = br.Banner
			}
		}

		port := models.Port{
			AssetID: assetID, IP: ip, Port: nr.Port, Protocol: proto,
			Service: svc.name, Version: ver, Banner: truncate(bannerStr, 500),
			RiskLevel: svc.risk, Interesting: svc.interesting, ScanID: scanID,
		}

		_, isNew, err := p.db.UpsertPort(port)
		if err != nil {
			continue
		}
		result.Stats.PortsFound++
		if isNew {
			detail := fmt.Sprintf("New port: %s:%d/%s (%s) [%s]", ip, nr.Port, proto, svc.name, svc.risk)
			if ver != "" {
				detail += " v" + ver
			}
			p.change(scanID, domain, "new_port", svc.risk, detail,
				map[string]interface{}{
					"ip": ip, "port": nr.Port, "protocol": proto,
					"service": svc.name, "version": ver, "risk": svc.risk,
					"banner": truncate(bannerStr, 100),
				})
		}
	}
	p.logger("[4] %d open ports", result.Stats.PortsFound)

	// ── Phase 5: Screenshots ──────────────────────────────────────
	if profile.Screenshot && p.cfg.Scanning.Screenshot.Enabled && len(liveURLs) > 0 {
		p.phase(scanID, "screenshot", domain)
		screenshots := p.screenshoter.CaptureAll(ctx, liveURLs)
		if len(screenshots) > 0 {
			// Map screenshots back to hosts
			for _, sr := range screenshots {
				if sr.URL != "" && sr.Path != "" {
					if hid, ok := hostIDMap[sr.URL]; ok {
						p.db.UpdateHostScreenshot(hid, sr.Path)
					}
				}
			}
			p.logger("[5] %d screenshots captured", len(screenshots))
		}
	}

	// ── Phase 6: JS Analysis ──────────────────────────────────────
	if profile.JSAnalysis && p.cfg.Scanning.JSAnalysis.Enabled && len(liveHosts) > 0 {
		p.phase(scanID, "js-analysis", domain)
		jsFindings := p.jsAnalyzer.AnalyzeHosts(ctx, liveHosts)

		var wg sync.WaitGroup
		var jsMu sync.Mutex
		sem := make(chan struct{}, 10)

		for _, jf := range jsFindings {
			wg.Add(1)
			sem <- struct{}{}
			go func(jf jsanalysis.Finding) {
				defer wg.Done()
				defer func() { <-sem }()

				assetID := p.resolveAssetIDFromURL(assetIDMap, jf.JSURL, domain)
				hostID := hostIDMap[jf.JSURL]
				if hostID == 0 {
					for _, h := range liveHosts {
						if strings.HasPrefix(jf.JSURL, h.URL) {
							hostID = h.ID
							if assetID == 0 {
								assetID = h.AssetID
							}
							break
						}
					}
				}

				finding := models.JSFinding{
					AssetID: assetID, HostID: hostID, JSURL: jf.JSURL,
					FindingType: jf.FindingType, Value: jf.Value,
					Context: jf.Context, Severity: jf.Severity, ScanID: scanID,
				}
				_, isNew, err := p.db.UpsertJSFinding(finding)
				if err != nil {
					return
				}
				jsMu.Lock()
				result.Stats.JSFindings++
				jsMu.Unlock()

				if isNew && (jf.Severity == "critical" || jf.Severity == "high") {
					p.change(scanID, domain, "js_secret", jf.Severity,
						fmt.Sprintf("[JS:%s] %s in %s", jf.FindingType, truncate(jf.Value, 60), jf.JSURL),
						map[string]interface{}{
							"js_url": jf.JSURL, "type": jf.FindingType,
							"value": truncate(jf.Value, 200), "severity": jf.Severity,
						})
				}
			}(jf)
		}
		wg.Wait()
		p.logger("[6] %d JS findings", result.Stats.JSFindings)
	}

	// ── Finalise ──────────────────────────────────────────────────
	result.Stats.Duration = int64(time.Since(start).Seconds())
	p.db.CompleteScan(scanID, result.Stats)

	changes, _, _ := p.db.GetChangeEvents(db.ChangeFilter{ScanID: scanID, Limit: 2000})
	result.Changes = changes

	p.logger("═══ Complete [%s] %s: assets=%d hosts=%d ports=%d js=%d changes=%d (%ds) ═══",
		strings.ToUpper(profileName), domain,
		result.Stats.AssetsFound, result.Stats.HostsFound,
		result.Stats.PortsFound, result.Stats.JSFindings,
		len(changes), result.Stats.Duration)

	p.onEvent("scan_completed", map[string]interface{}{
		"scan_id": scanID, "domain": domain, "profile": profileName,
		"duration": result.Stats.Duration, "changes": len(changes),
		"stats": result.Stats,
	})

	return result, nil
}

// ──────────────────────────── helpers ────────────────────────────

func (p *Processor) phase(scanID int64, phase, domain string) {
	p.logger("[phase] %s", phase)
	p.onEvent("phase", map[string]interface{}{
		"phase": phase, "scan_id": scanID, "domain": domain,
	})
}

func (p *Processor) change(scanID int64, domain, eventType, severity, desc string, details map[string]interface{}) {
	detailsJSON := db.MarshalDetails(details)
	event := models.ChangeEvent{
		ScanID: scanID, Domain: domain, EventType: eventType,
		Severity: severity, Description: desc, Details: detailsJSON,
	}
	id, err := p.db.CreateChangeEvent(event)
	if err != nil {
		return
	}
	event.ID = id
	p.onEvent("change", event)
}

func (p *Processor) resolveAssetID(assetIDMap map[string]int64, input, urlStr, domain string) int64 {
	for _, candidate := range []string{normalizeHost(input), normalizeHost(urlStr)} {
		if id, ok := assetIDMap[candidate]; ok && id > 0 {
			return id
		}
	}
	return 0
}

func (p *Processor) resolveAssetIDByIP(assetIDMap map[string]int64, ipMap map[string]string, ip string) int64 {
	for sub, resolvedIP := range ipMap {
		if resolvedIP == ip {
			if id, ok := assetIDMap[sub]; ok {
				return id
			}
		}
	}
	return 0
}

func (p *Processor) resolveAssetIDFromURL(assetIDMap map[string]int64, urlStr, domain string) int64 {
	host := normalizeHost(urlStr)
	if id, ok := assetIDMap[host]; ok {
		return id
	}
	return 0
}

func normalizeHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.IndexByte(s, '/'); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.LastIndexByte(s, ':'); idx != -1 {
		possible := s[idx+1:]
		isPort := len(possible) > 0
		for _, c := range possible {
			if c < '0' || c > '9' {
				isPort = false
				break
			}
		}
		if isPort {
			s = s[:idx]
		}
	}
	return strings.TrimSuffix(s, ".")
}

func assetType(sub, domain string) string {
	if sub == domain {
		return "domain"
	}
	return "subdomain"
}

func uniqueValues(m map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range m {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func parseTech(tech string) (name, version string) {
	parts := strings.SplitN(tech, ":", 2)
	name = strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		version = strings.TrimSpace(parts[1])
	}
	return
}

func categorizeTech(name string) string {
	lower := strings.ToLower(name)
	cats := map[string][]string{
		"cms":       {"wordpress", "drupal", "joomla", "magento"},
		"framework": {"react", "angular", "vue", "next", "django", "laravel", "spring", "rails"},
		"server":    {"nginx", "apache", "iis", "caddy", "tomcat"},
		"cdn":       {"cloudflare", "fastly", "akamai", "cloudfront"},
		"database":  {"mysql", "postgresql", "mongodb", "redis", "elasticsearch"},
	}
	for cat, techs := range cats {
		for _, t := range techs {
			if strings.Contains(lower, t) {
				return cat
			}
		}
	}
	return "other"
}

type portInfo struct {
	name        string
	risk        string
	interesting bool
}

func classifyPort(port int) portInfo {
	defs := map[int]portInfo{
		21:    {"ftp", "medium", true},
		22:    {"ssh", "medium", false},
		23:    {"telnet", "high", true},
		25:    {"smtp", "medium", false},
		53:    {"dns", "low", false},
		80:    {"http", "low", false},
		111:   {"rpcbind", "high", true},
		135:   {"msrpc", "high", true},
		139:   {"netbios", "high", true},
		161:   {"snmp", "high", true},
		389:   {"ldap", "high", true},
		443:   {"https", "low", false},
		445:   {"smb", "high", true},
		512:   {"rexec", "high", true},
		513:   {"rlogin", "high", true},
		514:   {"rsh", "high", true},
		873:   {"rsync", "high", true},
		1433:  {"mssql", "high", true},
		1521:  {"oracle", "high", true},
		2049:  {"nfs", "high", true},
		2181:  {"zookeeper", "high", true},
		2375:  {"docker", "high", true},
		2376:  {"docker-tls", "high", true},
		3000:  {"dev-server", "medium", true},
		3306:  {"mysql", "high", true},
		3389:  {"rdp", "high", true},
		4848:  {"glassfish", "high", true},
		5000:  {"dev-server", "medium", true},
		5432:  {"postgresql", "high", true},
		5601:  {"kibana", "high", true},
		5900:  {"vnc", "high", true},
		5984:  {"couchdb", "high", true},
		6379:  {"redis", "high", true},
		7474:  {"neo4j", "high", true},
		8080:  {"http-alt", "medium", true},
		8443:  {"https-alt", "medium", true},
		8888:  {"jupyter", "high", true},
		9000:  {"php-fpm", "medium", true},
		9090:  {"http-alt", "medium", true},
		9200:  {"elasticsearch", "high", true},
		9300:  {"elasticsearch-transport", "high", true},
		11211: {"memcached", "high", true},
		15672: {"rabbitmq-mgmt", "high", true},
		27017: {"mongodb", "high", true},
		50000: {"ibm-db2", "high", true},
		61616: {"activemq", "high", true},
	}
	if d, ok := defs[port]; ok {
		return d
	}
	if port > 1024 && port < 10000 {
		return portInfo{"unknown", "medium", true}
	}
	return portInfo{"unknown", "low", false}
}

func classifyHost(url, title string, techs []string) (bool, string) {
	urlL := strings.ToLower(url)
	titleL := strings.ToLower(title)
	techStr := strings.ToLower(strings.Join(techs, " "))

	// Admin panels
	adminPaths := []string{
		"/admin", "/administrator", "/wp-admin", "/wp-login",
		"/cpanel", "/phpmyadmin", "/pma", "/webmin",
		"/plesk", "/directadmin", "/whm",
		"/manage/admin", "/admin/login", "/admin/dashboard",
		"/backend/admin", "/staff/login", "/ops/admin",
	}
	for _, p := range adminPaths {
		if strings.Contains(urlL, p) {
			return true, "admin-panel"
		}
	}
	adminTitles := []string{
		"admin", "dashboard", "management", "control panel",
		"manager", "portal", "console", "back office", "backoffice",
		"cms", "phpmyadmin", "webmin", "plesk", "cpanel",
	}
	for _, t := range adminTitles {
		if strings.Contains(titleL, t) {
			return true, "admin-panel"
		}
	}

	// Login/Auth pages
	loginPaths := []string{"/login", "/signin", "/sign-in", "/auth", "/sso", "/oauth", "/saml", "/session"}
	for _, p := range loginPaths {
		if strings.Contains(urlL, p) {
			return true, "login-page"
		}
	}
	loginTitles := []string{"login", "sign in", "sign-in", "log in", "log-in", "authenticate", "account access"}
	for _, t := range loginTitles {
		if strings.Contains(titleL, t) {
			return true, "login-page"
		}
	}

	// APIs
	apiPaths := []string{"/api/", "/api-", "/graphql", "/swagger", "/openapi", "/v1/", "/v2/", "/v3/", "/rest/", "/rpc"}
	for _, p := range apiPaths {
		if strings.Contains(urlL, p) {
			return true, "api"
		}
	}
	if strings.Contains(techStr, "graphql") || strings.Contains(techStr, "swagger") {
		return true, "api"
	}

	// Dev/staging environments
	devIndicators := []string{
		"dev.", "develop.", "development.", "staging.", "stage.",
		"test.", "testing.", "uat.", "qa.", "demo.", "sandbox.",
		"stg.", "beta.", "preview.", "preprod.", "pre-prod.",
		"internal.", "intranet.", "corp.", "vpn.", "remote.",
	}
	for _, p := range devIndicators {
		if strings.Contains(urlL, p) {
			return true, "dev-env"
		}
	}
	devTitles := []string{"staging", "development", "sandbox", "test environment", "demo"}
	for _, t := range devTitles {
		if strings.Contains(titleL, t) {
			return true, "dev-env"
		}
	}

	// High value tech stacks
	highValueTech := []string{
		"jenkins", "grafana", "kibana", "elasticsearch", "gitlab",
		"jira", "confluence", "sonarqube", "portainer", "rancher",
		"jupyter", "airflow", "superset", "metabase", "redash",
		"wordpress", "drupal", "tomcat", "spring", "strapi",
	}
	for _, t := range highValueTech {
		if strings.Contains(techStr, t) || strings.Contains(titleL, t) {
			return true, "tech-" + t
		}
	}

	// Exposed services by subdomain name
	exposedSubdomains := []string{
		"mail.", "webmail.", "email.", "smtp.", "mx.",
		"vpn.", "remote.", "citrix.", "rdp.", "ssh.",
		"ftp.", "sftp.", "files.", "upload.", "download.",
		"git.", "gitlab.", "github.", "bitbucket.", "code.", "repo.",
		"monitor.", "nagios.", "zabbix.", "prometheus.", "grafana.",
		"jenkins.", "ci.", "cd.", "build.", "deploy.", "release.",
		"db.", "database.", "mysql.", "postgres.", "mongo.", "redis.",
		"s3.", "storage.", "backup.", "archive.",
		"chat.", "slack.", "teams.", "mattermost.",
		"wiki.", "docs.", "confluence.", "notion.",
		"jira.", "tracker.", "tickets.", "support.",
		"shop.", "store.", "checkout.", "payment.",
		"cdn.", "assets.", "static.", "media.",
	}
	for _, sub := range exposedSubdomains {
		if strings.Contains(urlL, "//"+sub) || strings.Contains(urlL, "."+sub) {
			return true, "exposed-service"
		}
	}

	// Non-standard ports are always interesting
	for _, port := range []string{":8080", ":8443", ":8888", ":9000", ":9090", ":3000", ":4000", ":5000", ":7000"} {
		if strings.Contains(urlL, port) {
			return true, "alt-port"
		}
	}

	return false, ""
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
