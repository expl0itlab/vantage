package attacksurface

import (
	"fmt"
	"strings"
)

// Note is a single attack surface observation
type Note struct {
	Category string // auth, exposure, injection, misconfig, recon
	Signal   string // what was detected
	Detail   string // what to check
	Severity string // high, medium, low
}

// Analyze returns attack surface notes for a host based on its fingerprints
func Analyze(technologies []string, server, title, url string, port int, statusCode int) []Note {
	var notes []Note

	techLower := make([]string, len(technologies))
	for i, t := range technologies {
		techLower[i] = strings.ToLower(t)
	}
	serverLower := strings.ToLower(server)
	titleLower := strings.ToLower(title)
	urlLower := strings.ToLower(url)

	// ── CMS ──────────────────────────────────────────────────────
	if hasTech(techLower, "wordpress") {
		notes = append(notes,
			Note{"recon", "WordPress", "Check /wp-login.php, /wp-admin/, /xmlrpc.php", "high"},
			Note{"recon", "WordPress", "Enumerate users: /?author=1 and /wp-json/wp/v2/users", "medium"},
			Note{"exposure", "WordPress", "Check /wp-config.php.bak, /wp-content/debug.log", "high"},
		)
	}
	if hasTech(techLower, "drupal") {
		notes = append(notes,
			Note{"recon", "Drupal", "Check /CHANGELOG.txt for version, /user/login", "high"},
			Note{"injection", "Drupal", "Test Drupalgeddon2 (SA-CORE-2018-002) if outdated", "high"},
		)
	}
	if hasTech(techLower, "joomla") {
		notes = append(notes,
			Note{"recon", "Joomla", "Check /administrator/, /README.txt for version", "high"},
		)
	}
	if hasTech(techLower, "magento") {
		notes = append(notes,
			Note{"recon", "Magento", "Check /downloader/, /admin/, Shoplift bug if old", "high"},
		)
	}

	// ── Application Servers ───────────────────────────────────────
	if hasTech(techLower, "tomcat") || strings.Contains(serverLower, "tomcat") {
		notes = append(notes,
			Note{"auth", "Apache Tomcat", "Test /manager/html with admin:admin, tomcat:tomcat, admin:tomcat", "high"},
			Note{"exposure", "Apache Tomcat", "Check /manager/status, /host-manager/html", "high"},
		)
	}
	if hasTech(techLower, "jenkins") || strings.Contains(titleLower, "jenkins") {
		notes = append(notes,
			Note{"auth", "Jenkins", "Test unauthenticated script console: /script", "high"},
			Note{"exposure", "Jenkins", "Check /asynchPeople/, /systemInfo, /env-vars.html", "high"},
			Note{"injection", "Jenkins", "Script console RCE if accessible", "high"},
		)
	}
	if hasTech(techLower, "grafana") || strings.Contains(titleLower, "grafana") {
		notes = append(notes,
			Note{"auth", "Grafana", "Test admin:admin default credentials", "high"},
			Note{"injection", "Grafana", "CVE-2021-43798 path traversal if < 8.3.1", "high"},
		)
	}
	if hasTech(techLower, "kibana") || strings.Contains(titleLower, "kibana") {
		notes = append(notes,
			Note{"exposure", "Kibana", "Check for unauthenticated access to index data", "high"},
			Note{"injection", "Kibana", "CVE-2019-7609 prototype pollution if < 6.6.1", "high"},
		)
	}
	if hasTech(techLower, "gitlab") || strings.Contains(titleLower, "gitlab") {
		notes = append(notes,
			Note{"auth", "GitLab", "Test open registration, check public repos", "high"},
			Note{"injection", "GitLab", "CVE-2021-22205 RCE via image upload if < 13.10.3", "high"},
		)
	}

	// ── Frameworks ────────────────────────────────────────────────
	if hasTech(techLower, "spring") || hasTech(techLower, "spring boot") {
		notes = append(notes,
			Note{"exposure", "Spring Boot Actuator", "Check /actuator, /actuator/env, /actuator/heapdump", "high"},
			Note{"injection", "Spring", "Test Spring4Shell (CVE-2022-22965) if Java 9+", "high"},
			Note{"exposure", "Spring", "Check /actuator/mappings for all endpoints", "medium"},
		)
	}
	if hasTech(techLower, "laravel") {
		notes = append(notes,
			Note{"exposure", "Laravel", "Check APP_DEBUG=true in responses, /.env exposure", "high"},
			Note{"injection", "Laravel", "Test deserialization if debug mode active", "medium"},
		)
	}
	if hasTech(techLower, "django") {
		notes = append(notes,
			Note{"exposure", "Django", "Check for debug page exposure (DEBUG=True)", "medium"},
			Note{"recon", "Django", "Check /admin/ for Django admin panel", "medium"},
		)
	}
	if hasTech(techLower, "rails") || hasTech(techLower, "ruby on rails") {
		notes = append(notes,
			Note{"recon", "Rails", "Check /rails/info/properties if development mode", "medium"},
		)
	}
	if hasTech(techLower, "php") {
		notes = append(notes,
			Note{"exposure", "PHP", "Check phpinfo() exposure, .php~ backup files", "medium"},
		)
	}

	// ── Servers ───────────────────────────────────────────────────
	if strings.Contains(serverLower, "apache") {
		notes = append(notes,
			Note{"recon", "Apache", "Check /server-status, /server-info if mod_status enabled", "medium"},
		)
		if strings.Contains(serverLower, "2.4.49") || strings.Contains(serverLower, "2.4.50") {
			notes = append(notes,
				Note{"injection", "Apache", "CVE-2021-41773/42013 path traversal — CRITICAL", "high"},
			)
		}
	}
	if strings.Contains(serverLower, "nginx") {
		notes = append(notes,
			Note{"misconfig", "Nginx", "Test path traversal via alias misconfiguration", "medium"},
		)
	}
	if strings.Contains(serverLower, "iis") {
		notes = append(notes,
			Note{"recon", "IIS", "Check /_vti_bin/, /.git/, /web.config", "medium"},
		)
	}

	// ── URL-based signals ─────────────────────────────────────────
	authPaths := map[string]string{
		"/admin":         "Admin panel exposed — test auth bypass, default creds",
		"/administrator": "Admin panel — test default credentials",
		"/wp-admin":      "WordPress admin — test credential spray",
		"/wp-login.php":  "WordPress login — test common passwords",
		"/login":         "Login page — test SQLi, credential spray",
		"/signin":        "Sign-in page — test auth bypass",
		"/dashboard":     "Dashboard — check for unauth access",
		"/console":       "Console — check for unauth RCE",
		"/phpmyadmin":    "phpMyAdmin — test default creds, CVE exposure",
		"/pma":           "phpMyAdmin alias — test default creds",
		"/cpanel":        "cPanel — test default credentials",
		"/webmail":       "Webmail — credential spray target",
		"/manager":       "Manager panel — test default creds (Tomcat?)",
		"/portal":        "Portal — check for auth bypass",
		"/api":           "API endpoint — check for unauth access, IDOR",
		"/graphql":       "GraphQL — test introspection, batch attacks",
		"/swagger":       "Swagger UI — full API spec exposed",
		"/openapi":       "OpenAPI spec — full API enumeration",
		"/v1":            "API v1 — check for IDOR, missing auth",
		"/v2":            "API v2 — check for IDOR, missing auth",
		"/actuator":      "Spring Actuator — check /env, /heapdump",
		"/setup":         "Setup page — potential takeover if unconfigured",
		"/install":       "Install page — potential takeover",
		"/backup":        "Backup path — check for sensitive file exposure",
		"/debug":         "Debug endpoint — check for information disclosure",
		"/test":          "Test endpoint — may have reduced security controls",
		"/dev":           "Dev endpoint — likely unprotected",
		"/staging":       "Staging environment — likely weaker controls",
		"/old":           "Old/legacy endpoint — check for known vulns",
		"/.git":          "Git repo exposed — extract source code",
		"/.env":          "Environment file — credentials likely exposed",
		"/xmlrpc.php":    "WordPress XMLRPC — test brute force, SSRF",
	}

	for path, detail := range authPaths {
		if strings.Contains(urlLower, path) {
			sev := "medium"
			if strings.Contains(detail, "default creds") || strings.Contains(detail, "RCE") ||
				strings.Contains(detail, "CRITICAL") || strings.Contains(detail, "exposed") {
				sev = "high"
			}
			notes = append(notes, Note{"auth", fmt.Sprintf("Path: %s", path), detail, sev})
		}
	}

	// ── Title-based signals ───────────────────────────────────────
	titleSignals := map[string]Note{
		"phpmyadmin":  {"auth", "phpMyAdmin", "Test root with empty password, root:root", "high"},
		"adminer":     {"auth", "Adminer DB UI", "Test database access with common credentials", "high"},
		"webmin":      {"auth", "Webmin", "Test default credentials, CVE-2019-15107 RCE", "high"},
		"glassfish":   {"auth", "GlassFish", "Test admin:adminadmin on /common/logon.jsf", "high"},
		"websphere":   {"auth", "WebSphere", "Test wsadmin:wsadmin default credentials", "high"},
		"jboss":       {"auth", "JBoss", "Test /jmx-console/, /web-console/ unauth access", "high"},
		"roundcube":   {"auth", "Roundcube", "CVE-2023-43770 XSS, test default admin creds", "high"},
		"outlook":     {"auth", "OWA/Outlook", "Credential spray target — password spray carefully", "medium"},
		"citrix":      {"auth", "Citrix", "CVE-2019-19781 path traversal if unpatched", "high"},
		"pulsesecure": {"auth", "Pulse Secure VPN", "CVE-2021-22893 if unpatched", "high"},
		"fortinet":    {"auth", "Fortinet", "CVE-2022-40684 auth bypass if < 7.2.2", "high"},
		"sonarqube":   {"auth", "SonarQube", "Test admin:admin, check for public project access", "high"},
		"jupyter":     {"auth", "Jupyter Notebook", "Check for unauthenticated code execution", "high"},
		"airflow":     {"auth", "Apache Airflow", "Test admin:admin, /api/v1/dags unauth", "high"},
		"rancher":     {"auth", "Rancher", "Test default admin credentials", "high"},
		"portainer":   {"auth", "Portainer", "Test admin:portainer default creds", "high"},
		"traefik":     {"exposure", "Traefik Dashboard", "Check /dashboard/, /api/ for route disclosure", "medium"},
	}

	for keyword, note := range titleSignals {
		if strings.Contains(titleLower, keyword) {
			notes = append(notes, note)
		}
	}

	// ── Status code signals ───────────────────────────────────────
	if statusCode == 401 || statusCode == 403 {
		notes = append(notes,
			Note{"auth", fmt.Sprintf("HTTP %d", statusCode), "Try auth bypass: X-Forwarded-For: 127.0.0.1, X-Original-URL, method override", "medium"},
		)
	}
	if statusCode == 200 && (strings.Contains(urlLower, "admin") || strings.Contains(urlLower, "manage")) {
		notes = append(notes,
			Note{"auth", "Admin 200 OK", "Admin panel returns 200 — verify auth is enforced", "high"},
		)
	}

	// ── Port-based signals ────────────────────────────────────────
	portNotes := map[int]Note{
		2375:  {"exposure", "Docker API (no TLS)", "Unauthenticated Docker API — container escape to host", "high"},
		2376:  {"exposure", "Docker API (TLS)", "Docker API with TLS — check for client cert bypass", "high"},
		4848:  {"auth", "GlassFish Admin", "Default admin:adminadmin at /common/logon.jsf", "high"},
		5601:  {"exposure", "Kibana", "Check for unauthenticated Elasticsearch data access", "high"},
		8888:  {"auth", "Jupyter/Alt HTTP", "Check for unauthenticated Jupyter notebook", "high"},
		9000:  {"exposure", "PHP-FPM/SonarQube", "May expose PHP-FPM or SonarQube admin", "medium"},
		9200:  {"exposure", "Elasticsearch HTTP", "Check for unauth data access /_cat/indices", "high"},
		9300:  {"exposure", "Elasticsearch Transport", "Internal cluster port exposed externally", "high"},
		15672: {"auth", "RabbitMQ Management", "Test guest:guest default credentials", "high"},
		61616: {"exposure", "ActiveMQ", "CVE-2023-46604 RCE if < 5.15.16", "high"},
	}
	if n, ok := portNotes[port]; ok {
		notes = append(notes, n)
	}

	return dedup(notes)
}

func hasTech(techs []string, name string) bool {
	nameLower := strings.ToLower(name)
	for _, t := range techs {
		if strings.Contains(t, nameLower) {
			return true
		}
	}
	return false
}

func dedup(notes []Note) []Note {
	seen := map[string]bool{}
	var out []Note
	for _, n := range notes {
		key := n.Category + "|" + n.Signal
		if !seen[key] {
			seen[key] = true
			out = append(out, n)
		}
	}
	return out
}

// ToJSON serializes notes to a JSON array string
func ToJSON(notes []Note) string {
	if len(notes) == 0 {
		return "[]"
	}
	var parts []string
	for _, n := range notes {
		parts = append(parts, fmt.Sprintf(
			`{"category":%q,"signal":%q,"detail":%q,"severity":%q}`,
			n.Category, n.Signal, n.Detail, n.Severity,
		))
	}
	return "[" + strings.Join(parts, ",") + "]"
}
