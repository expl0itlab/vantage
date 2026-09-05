package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/expl0itlab/vantage/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=10000;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS scans (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	domain        TEXT NOT NULL,
	profile       TEXT NOT NULL DEFAULT 'standard',
	status        TEXT NOT NULL DEFAULT 'running',
	started_at    DATETIME NOT NULL,
	completed_at  DATETIME,
	duration      INTEGER DEFAULT 0,
	assets_found  INTEGER DEFAULT 0,
	hosts_found   INTEGER DEFAULT 0,
	ports_found   INTEGER DEFAULT 0,
	js_findings   INTEGER DEFAULT 0,
	config        TEXT DEFAULT '',
	error         TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

CREATE TABLE IF NOT EXISTS assets (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	domain       TEXT NOT NULL,
	subdomain    TEXT NOT NULL,
	ip           TEXT DEFAULT '',
	asn          TEXT DEFAULT '',
	asn_org      TEXT DEFAULT '',
	net_range    TEXT DEFAULT '',
	asset_type   TEXT NOT NULL DEFAULT 'subdomain',
	status       TEXT NOT NULL DEFAULT 'active',
	first_seen   DATETIME NOT NULL,
	last_seen    DATETIME NOT NULL,
	scan_id      INTEGER,
	tags         TEXT DEFAULT '',
	interesting  INTEGER DEFAULT 0,
	interest_tag TEXT DEFAULT '',
	UNIQUE(domain, subdomain)
);
CREATE INDEX IF NOT EXISTS idx_assets_domain ON assets(domain);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);

CREATE TABLE IF NOT EXISTS hosts (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	asset_id        INTEGER NOT NULL,
	url             TEXT NOT NULL,
	status_code     INTEGER DEFAULT 0,
	title           TEXT DEFAULT '',
	content_type    TEXT DEFAULT '',
	server          TEXT DEFAULT '',
	technologies    TEXT DEFAULT '[]',
	headers         TEXT DEFAULT '{}',
	tls_info        TEXT DEFAULT '{}',
	web_server      TEXT DEFAULT '',
	cdn             TEXT DEFAULT '',
	ip              TEXT DEFAULT '',
	interesting     INTEGER DEFAULT 0,
	interest_tag    TEXT DEFAULT '',
	screenshot_path TEXT DEFAULT '',
	attack_surface  TEXT DEFAULT '[]',
	first_seen      DATETIME NOT NULL,
	last_seen       DATETIME NOT NULL,
	scan_id         INTEGER,
	UNIQUE(url)
);
CREATE INDEX IF NOT EXISTS idx_hosts_asset_id ON hosts(asset_id);
CREATE INDEX IF NOT EXISTS idx_hosts_status_code ON hosts(status_code);
CREATE INDEX IF NOT EXISTS idx_hosts_interesting ON hosts(interesting);

CREATE TABLE IF NOT EXISTS ports (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	asset_id     INTEGER NOT NULL,
	ip           TEXT NOT NULL,
	port         INTEGER NOT NULL,
	protocol     TEXT NOT NULL DEFAULT 'tcp',
	service      TEXT DEFAULT '',
	version      TEXT DEFAULT '',
	banner       TEXT DEFAULT '',
	state        TEXT NOT NULL DEFAULT 'open',
	risk_level   TEXT DEFAULT 'low',
	interesting  INTEGER DEFAULT 0,
	first_seen   DATETIME NOT NULL,
	last_seen    DATETIME NOT NULL,
	scan_id      INTEGER,
	UNIQUE(ip, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_ports_ip ON ports(ip);
CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port);
CREATE INDEX IF NOT EXISTS idx_ports_risk ON ports(risk_level);

CREATE TABLE IF NOT EXISTS js_findings (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	asset_id     INTEGER NOT NULL,
	host_id      INTEGER DEFAULT 0,
	js_url       TEXT NOT NULL,
	finding_type TEXT NOT NULL,
	value        TEXT NOT NULL,
	context      TEXT DEFAULT '',
	severity     TEXT NOT NULL DEFAULT 'info',
	first_seen   DATETIME NOT NULL,
	last_seen    DATETIME NOT NULL,
	scan_id      INTEGER,
	UNIQUE(js_url, finding_type, value)
);
CREATE INDEX IF NOT EXISTS idx_js_asset_id ON js_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_js_severity ON js_findings(severity);
CREATE INDEX IF NOT EXISTS idx_js_type ON js_findings(finding_type);

CREATE TABLE IF NOT EXISTS change_events (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id     INTEGER NOT NULL,
	domain      TEXT NOT NULL,
	event_type  TEXT NOT NULL,
	severity    TEXT NOT NULL DEFAULT 'info',
	description TEXT NOT NULL,
	details     TEXT DEFAULT '{}',
	alerted     INTEGER DEFAULT 0,
	created_at  DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_changes_domain ON change_events(domain);
CREATE INDEX IF NOT EXISTS idx_changes_severity ON change_events(severity);
CREATE INDEX IF NOT EXISTS idx_changes_created ON change_events(created_at);

CREATE TABLE IF NOT EXISTS fingerprints (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	asset_id    INTEGER NOT NULL,
	host_id     INTEGER DEFAULT 0,
	technology  TEXT NOT NULL,
	version     TEXT DEFAULT '',
	category    TEXT DEFAULT '',
	confidence  INTEGER DEFAULT 50,
	source      TEXT DEFAULT '',
	updated_at  DATETIME NOT NULL,
	UNIQUE(asset_id, host_id, technology)
);
CREATE INDEX IF NOT EXISTS idx_fp_asset ON fingerprints(asset_id);
CREATE INDEX IF NOT EXISTS idx_fp_tech ON fingerprints(technology);

CREATE TABLE IF NOT EXISTS alert_history (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	domain      TEXT NOT NULL,
	event_type  TEXT NOT NULL,
	message     TEXT NOT NULL,
	success     INTEGER DEFAULT 0,
	sent_at     DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_domain ON alert_history(domain);
CREATE INDEX IF NOT EXISTS idx_alert_sent ON alert_history(sent_at);

CREATE TABLE IF NOT EXISTS tech_findings (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	domain      TEXT NOT NULL,
	host_url    TEXT NOT NULL,
	host_id     INTEGER DEFAULT 0,
	asset_id    INTEGER DEFAULT 0,
	technology  TEXT NOT NULL,
	check_name  TEXT NOT NULL,
	url         TEXT NOT NULL,
	result      TEXT DEFAULT '',
	severity    TEXT NOT NULL DEFAULT 'info',
	detail      TEXT DEFAULT '',
	confirmed   INTEGER DEFAULT 0,
	first_seen  DATETIME NOT NULL,
	last_seen   DATETIME NOT NULL,
	scan_id     INTEGER,
	UNIQUE(domain, host_url, technology, check_name)
);
CREATE INDEX IF NOT EXISTS idx_tech_domain ON tech_findings(domain);
CREATE INDEX IF NOT EXISTS idx_tech_severity ON tech_findings(severity);
CREATE INDEX IF NOT EXISTS idx_tech_confirmed ON tech_findings(confirmed);

CREATE TABLE IF NOT EXISTS cloud_findings (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	domain       TEXT NOT NULL,
	scan_id      INTEGER,
	finding_type TEXT NOT NULL,
	url          TEXT NOT NULL,
	provider     TEXT DEFAULT '',
	region       TEXT DEFAULT '',
	service      TEXT DEFAULT '',
	severity     TEXT NOT NULL DEFAULT 'info',
	detail       TEXT DEFAULT '',
	accessible   INTEGER DEFAULT 0,
	first_seen   DATETIME NOT NULL,
	last_seen    DATETIME NOT NULL,
	UNIQUE(domain, finding_type, url)
);
CREATE INDEX IF NOT EXISTS idx_cloud_domain ON cloud_findings(domain);
CREATE INDEX IF NOT EXISTS idx_cloud_provider ON cloud_findings(provider);
CREATE INDEX IF NOT EXISTS idx_cloud_severity ON cloud_findings(severity);
CREATE INDEX IF NOT EXISTS idx_cloud_type ON cloud_findings(finding_type);
`

type DB struct {
	db *sql.DB
}

func Open(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite3", path+"?_timeout=5000&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)

	if _, err := sqlDB.Exec(schema); err != nil {
		return nil, fmt.Errorf("applying schema: %w", err)
	}

	d := &DB{db: sqlDB}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migration: %w", err)
	}
	return d, nil
}

// migrate adds new columns to existing databases without losing data
func (d *DB) migrate() error {
	cols := []struct{ table, col, def string }{
		{"scans", "profile", "TEXT DEFAULT 'standard'"},
		{"scans", "js_findings", "INTEGER DEFAULT 0"},
		{"assets", "asn", "TEXT DEFAULT ''"},
		{"assets", "asn_org", "TEXT DEFAULT ''"},
		{"assets", "net_range", "TEXT DEFAULT ''"},
		{"assets", "interesting", "INTEGER DEFAULT 0"},
		{"assets", "interest_tag", "TEXT DEFAULT ''"},
		{"hosts", "ip", "TEXT DEFAULT ''"},
		{"hosts", "interesting", "INTEGER DEFAULT 0"},
		{"hosts", "interest_tag", "TEXT DEFAULT ''"},
		{"hosts", "screenshot_path", "TEXT DEFAULT ''"},
		{"hosts", "attack_surface", "TEXT DEFAULT '[]'"},
		{"ports", "risk_level", "TEXT DEFAULT 'low'"},
		{"ports", "interesting", "INTEGER DEFAULT 0"},
		{"js_findings", "entropy_score", "REAL DEFAULT 0"},
		{"js_findings", "variable_name", "TEXT DEFAULT ''"},
		{"js_findings", "context_lines", "TEXT DEFAULT ''"},
	}
	for _, m := range cols {
		var dummy string
		err := d.db.QueryRow(fmt.Sprintf("SELECT %s FROM %s LIMIT 1", m.col, m.table)).Scan(&dummy)
		if err == nil || err == sql.ErrNoRows {
			continue
		}
		if _, err := d.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", m.table, m.col, m.def)); err != nil {
			if !strings.Contains(err.Error(), "duplicate column") {
				return fmt.Errorf("alter %s.%s: %w", m.table, m.col, err)
			}
		}
	}
	return nil
}

func (d *DB) Close() error { return d.db.Close() }

// ──────────────────────────── SCANS ────────────────────────────

func (d *DB) CreateScan(domain, profile, configJSON string) (int64, error) {
	res, err := d.db.Exec(
		`INSERT INTO scans (domain, profile, status, started_at, config) VALUES (?, ?, 'running', ?, ?)`,
		domain, profile, time.Now(), configJSON,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) CompleteScan(id int64, s models.Scan) error {
	now := time.Now()
	_, err := d.db.Exec(`UPDATE scans SET status='completed', completed_at=?, duration=?,
		assets_found=?, hosts_found=?, ports_found=?, js_findings=? WHERE id=?`,
		now, s.Duration, s.AssetsFound, s.HostsFound, s.PortsFound, s.JSFindings, id)
	return err
}

func (d *DB) FailScan(id int64, errMsg string) error {
	now := time.Now()
	_, err := d.db.Exec(`UPDATE scans SET status='failed', completed_at=?, error=? WHERE id=?`,
		now, errMsg, id)
	return err
}

func (d *DB) GetScans(limit int) ([]models.Scan, error) {
	rows, err := d.db.Query(`SELECT id, domain, COALESCE(profile,'standard'),
		status, started_at, completed_at, COALESCE(duration,0),
		COALESCE(assets_found,0), COALESCE(hosts_found,0), COALESCE(ports_found,0),
		COALESCE(js_findings,0), COALESCE(error,'')
		FROM scans ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var scans []models.Scan
	for rows.Next() {
		s := models.Scan{}
		var completedAt sql.NullTime
		if err := rows.Scan(&s.ID, &s.Domain, &s.Profile, &s.Status, &s.StartedAt,
			&completedAt, &s.Duration, &s.AssetsFound, &s.HostsFound,
			&s.PortsFound, &s.JSFindings, &s.Error); err != nil {
			return nil, err
		}
		if completedAt.Valid {
			s.CompletedAt = &completedAt.Time
		}
		scans = append(scans, s)
	}
	return scans, rows.Err()
}

// ──────────────────────────── ASSETS ────────────────────────────

func (d *DB) UpsertAsset(a models.Asset) (int64, bool, error) {
	var existingID int64
	err := d.db.QueryRow(`SELECT id FROM assets WHERE domain=? AND subdomain=?`,
		a.Domain, a.Subdomain).Scan(&existingID)

	if err == sql.ErrNoRows {
		res, err := d.db.Exec(
			`INSERT INTO assets (domain, subdomain, ip, asn, asn_org, net_range, asset_type, status,
			first_seen, last_seen, scan_id, tags, interesting, interest_tag)
			VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)`,
			a.Domain, a.Subdomain, a.IP, a.ASN, a.ASNOrg, a.NetRange,
			a.AssetType, time.Now(), time.Now(), a.ScanID, a.Tags,
			boolInt(a.Interesting), a.InterestTag,
		)
		if err != nil {
			return 0, false, err
		}
		id, _ := res.LastInsertId()
		return id, true, nil
	} else if err != nil {
		return 0, false, err
	}

	_, err = d.db.Exec(`UPDATE assets SET
		ip=COALESCE(NULLIF(?,ip), ip),
		status='active', last_seen=?, scan_id=? WHERE id=?`,
		a.IP, time.Now(), a.ScanID, existingID)
	return existingID, false, err
}

func (d *DB) UpdateAssetIP(id int64, ip string) error {
	_, err := d.db.Exec(`UPDATE assets SET ip=? WHERE id=? AND (ip='' OR ip IS NULL)`, ip, id)
	return err
}

func (d *DB) GetAllAssets(filter AssetFilter) ([]models.Asset, int, error) {
	where, args := "1=1", []interface{}{}
	if filter.Domain != "" {
		where += " AND domain=?"
		args = append(args, filter.Domain)
	}
	if filter.Search != "" {
		s := "%" + filter.Search + "%"
		where += " AND (subdomain LIKE ? OR ip LIKE ?)"
		args = append(args, s, s)
	}
	if filter.Status != "" {
		where += " AND status=?"
		args = append(args, filter.Status)
	}
	if filter.Interesting {
		where += " AND interesting=1"
	}

	var total int
	d.db.QueryRow("SELECT COUNT(*) FROM assets WHERE "+where, args...).Scan(&total)

	limit := 100
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Page > 1 {
		offset = (filter.Page - 1) * limit
	}
	order := "subdomain"
	if filter.OrderBy != "" {
		order = filter.OrderBy
	}
	if filter.OrderDir == "desc" {
		order += " DESC"
	}

	rows, err := d.db.Query(fmt.Sprintf(
		`SELECT id, domain, subdomain, COALESCE(ip,''), COALESCE(asn,''), COALESCE(asn_org,''),
		COALESCE(net_range,''), asset_type, status, first_seen, last_seen,
		COALESCE(scan_id,0), COALESCE(tags,''), COALESCE(interesting,0), COALESCE(interest_tag,'')
		FROM assets WHERE %s ORDER BY %s LIMIT ? OFFSET ?`, where, order),
		append(args, limit, offset)...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	assets, err := scanAssets(rows)
	return assets, total, err
}

func scanAssets(rows *sql.Rows) ([]models.Asset, error) {
	var assets []models.Asset
	for rows.Next() {
		a := models.Asset{}
		var interesting int
		if err := rows.Scan(&a.ID, &a.Domain, &a.Subdomain, &a.IP, &a.ASN, &a.ASNOrg,
			&a.NetRange, &a.AssetType, &a.Status, &a.FirstSeen, &a.LastSeen,
			&a.ScanID, &a.Tags, &interesting, &a.InterestTag); err != nil {
			return nil, err
		}
		a.Interesting = interesting == 1
		assets = append(assets, a)
	}
	return assets, rows.Err()
}

// ──────────────────────────── HOSTS ────────────────────────────

func (d *DB) UpsertHost(h models.Host) (int64, bool, error) {
	var existingID int64
	err := d.db.QueryRow(`SELECT id FROM hosts WHERE url=?`, h.URL).Scan(&existingID)

	if err == sql.ErrNoRows {
		res, err := d.db.Exec(
			`INSERT INTO hosts (asset_id, url, status_code, title, content_type, server,
			technologies, headers, tls_info, web_server, cdn, ip, interesting, interest_tag,
			screenshot_path, attack_surface, first_seen, last_seen, scan_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			h.AssetID, h.URL, h.StatusCode, h.Title, h.ContentType, h.Server,
			h.Technologies, h.Headers, h.TLSInfo, h.WebServer, h.CDN, h.IP,
			boolInt(h.Interesting), h.InterestTag, h.ScreenshotPath, h.AttackSurface,
			time.Now(), time.Now(), h.ScanID,
		)
		if err != nil {
			return 0, false, err
		}
		id, _ := res.LastInsertId()
		return id, true, nil
	} else if err != nil {
		return 0, false, err
	}

	_, err = d.db.Exec(`UPDATE hosts SET status_code=?, title=?, server=?, technologies=?,
		tls_info=?, web_server=?, cdn=?, ip=COALESCE(NULLIF(?,''), ip),
		interesting=?, interest_tag=?, attack_surface=?,
		screenshot_path=COALESCE(NULLIF(?,''), screenshot_path),
		last_seen=?, scan_id=? WHERE id=?`,
		h.StatusCode, h.Title, h.Server, h.Technologies, h.TLSInfo, h.WebServer, h.CDN,
		h.IP, boolInt(h.Interesting), h.InterestTag, h.AttackSurface,
		h.ScreenshotPath, time.Now(), h.ScanID, existingID)
	return existingID, false, err
}

func (d *DB) GetHosts(filter HostFilter) ([]models.Host, int, error) {
	where, args := "1=1", []interface{}{}
	if filter.Domain != "" {
		where += " AND a.domain=?"
		args = append(args, filter.Domain)
	}
	if filter.Search != "" {
		s := "%" + filter.Search + "%"
		where += " AND (h.url LIKE ? OR h.title LIKE ? OR h.ip LIKE ?)"
		args = append(args, s, s, s)
	}
	if filter.Interesting {
		where += " AND h.interesting=1"
	}
	if filter.StatusCode != 0 {
		where += " AND h.status_code=?"
		args = append(args, filter.StatusCode)
	}

	var total int
	d.db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM hosts h LEFT JOIN assets a ON h.asset_id=a.id WHERE %s`, where), args...).Scan(&total)

	limit := 50
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Page > 1 {
		offset = (filter.Page - 1) * limit
	}

	rows, err := d.db.Query(fmt.Sprintf(
		`SELECT h.id, h.asset_id, h.url, h.status_code, COALESCE(h.title,''),
		COALESCE(h.content_type,''), COALESCE(h.server,''), COALESCE(h.technologies,'[]'),
		COALESCE(h.headers,'{}'), COALESCE(h.tls_info,'{}'), COALESCE(h.web_server,''),
		COALESCE(h.cdn,''), COALESCE(h.ip,''), COALESCE(h.interesting,0),
		COALESCE(h.interest_tag,''), COALESCE(h.screenshot_path,''),
		COALESCE(h.attack_surface,'[]'), h.first_seen, h.last_seen, COALESCE(h.scan_id,0)
		FROM hosts h LEFT JOIN assets a ON h.asset_id=a.id
		WHERE %s ORDER BY h.last_seen DESC LIMIT ? OFFSET ?`, where),
		append(args, limit, offset)...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var hosts []models.Host
	for rows.Next() {
		h := models.Host{}
		var interesting int
		if err := rows.Scan(&h.ID, &h.AssetID, &h.URL, &h.StatusCode, &h.Title,
			&h.ContentType, &h.Server, &h.Technologies, &h.Headers, &h.TLSInfo,
			&h.WebServer, &h.CDN, &h.IP, &interesting, &h.InterestTag,
			&h.ScreenshotPath, &h.AttackSurface, &h.FirstSeen, &h.LastSeen, &h.ScanID); err != nil {
			return nil, 0, err
		}
		h.Interesting = interesting == 1
		hosts = append(hosts, h)
	}
	return hosts, total, rows.Err()
}

// ──────────────────────────── PORTS ────────────────────────────

func (d *DB) UpsertPort(p models.Port) (int64, bool, error) {
	var existingID int64
	err := d.db.QueryRow(`SELECT id FROM ports WHERE ip=? AND port=? AND protocol=?`,
		p.IP, p.Port, p.Protocol).Scan(&existingID)

	if err == sql.ErrNoRows {
		res, err := d.db.Exec(
			`INSERT INTO ports (asset_id, ip, port, protocol, service, version, banner, state,
			risk_level, interesting, first_seen, last_seen, scan_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)`,
			p.AssetID, p.IP, p.Port, p.Protocol, p.Service, p.Version, p.Banner,
			p.RiskLevel, boolInt(p.Interesting), time.Now(), time.Now(), p.ScanID,
		)
		if err != nil {
			return 0, false, err
		}
		id, _ := res.LastInsertId()
		return id, true, nil
	} else if err != nil {
		return 0, false, err
	}

	_, err = d.db.Exec(`UPDATE ports SET service=?, version=COALESCE(NULLIF(?,''),version),
		banner=COALESCE(NULLIF(?,''),banner), risk_level=?, interesting=?,
		state='open', last_seen=?, scan_id=? WHERE id=?`,
		p.Service, p.Version, p.Banner, p.RiskLevel, boolInt(p.Interesting),
		time.Now(), p.ScanID, existingID)
	return existingID, false, err
}

func (d *DB) GetPorts(filter PortFilter) ([]models.Port, int, error) {
	where, args := "state='open'", []interface{}{}
	if filter.Domain != "" {
		where += " AND asset_id IN (SELECT id FROM assets WHERE domain=?)"
		args = append(args, filter.Domain)
	}
	if filter.IP != "" {
		where += " AND ip=?"
		args = append(args, filter.IP)
	}
	if filter.Port != 0 {
		where += " AND port=?"
		args = append(args, filter.Port)
	}
	if filter.Search != "" {
		s := "%" + filter.Search + "%"
		where += " AND (ip LIKE ? OR service LIKE ? OR banner LIKE ?)"
		args = append(args, s, s, s)
	}
	if filter.RiskLevel != "" {
		where += " AND risk_level=?"
		args = append(args, filter.RiskLevel)
	}
	if filter.Interesting {
		where += " AND interesting=1"
	}

	var total int
	d.db.QueryRow("SELECT COUNT(*) FROM ports WHERE "+where, args...).Scan(&total)

	limit := 200
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Page > 1 {
		offset = (filter.Page - 1) * limit
	}

	sevOrder := `CASE risk_level WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END`
	rows, err := d.db.Query(fmt.Sprintf(
		`SELECT id, COALESCE(asset_id,0), ip, port, protocol, COALESCE(service,''),
		COALESCE(version,''), COALESCE(banner,''), state,
		COALESCE(risk_level,'low'), COALESCE(interesting,0), first_seen, last_seen, COALESCE(scan_id,0)
		FROM ports WHERE %s ORDER BY %s, ip, port LIMIT ? OFFSET ?`, where, sevOrder),
		append(args, limit, offset)...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var ports []models.Port
	for rows.Next() {
		p := models.Port{}
		var interesting int
		if err := rows.Scan(&p.ID, &p.AssetID, &p.IP, &p.Port, &p.Protocol,
			&p.Service, &p.Version, &p.Banner, &p.State, &p.RiskLevel,
			&interesting, &p.FirstSeen, &p.LastSeen, &p.ScanID); err != nil {
			return nil, 0, err
		}
		p.Interesting = interesting == 1
		ports = append(ports, p)
	}
	return ports, total, rows.Err()
}

// ──────────────────────────── JS FINDINGS ────────────────────────────

func (d *DB) UpsertJSFinding(f models.JSFinding) (int64, bool, error) {
	var existingID int64
	err := d.db.QueryRow(`SELECT id FROM js_findings WHERE js_url=? AND finding_type=? AND value=?`,
		f.JSURL, f.FindingType, f.Value).Scan(&existingID)

	if err == sql.ErrNoRows {
		res, err := d.db.Exec(
			`INSERT INTO js_findings (asset_id, host_id, js_url, finding_type, value, context, severity, first_seen, last_seen, scan_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.AssetID, f.HostID, f.JSURL, f.FindingType, f.Value, f.Context, f.Severity,
			time.Now(), time.Now(), f.ScanID,
		)
		if err != nil {
			return 0, false, err
		}
		id, _ := res.LastInsertId()
		return id, true, nil
	} else if err != nil {
		return 0, false, err
	}
	_, err = d.db.Exec(`UPDATE js_findings SET last_seen=?, scan_id=? WHERE id=?`,
		time.Now(), f.ScanID, existingID)
	return existingID, false, err
}

func (d *DB) GetJSFindings(filter JSFindingFilter) ([]models.JSFinding, int, error) {
	where, args := "1=1", []interface{}{}
	if filter.Domain != "" {
		where += " AND asset_id IN (SELECT id FROM assets WHERE domain=?)"
		args = append(args, filter.Domain)
	}
	if filter.FindingType != "" {
		where += " AND finding_type=?"
		args = append(args, filter.FindingType)
	}
	if filter.Severity != "" {
		where += " AND severity=?"
		args = append(args, filter.Severity)
	}
	if filter.Search != "" {
		s := "%" + filter.Search + "%"
		where += " AND (value LIKE ? OR js_url LIKE ?)"
		args = append(args, s, s)
	}

	var total int
	d.db.QueryRow("SELECT COUNT(*) FROM js_findings WHERE "+where, args...).Scan(&total)

	limit := 100
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Page > 1 {
		offset = (filter.Page - 1) * limit
	}

	sevOrder := `CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`
	rows, err := d.db.Query(fmt.Sprintf(
		`SELECT id, COALESCE(asset_id,0), COALESCE(host_id,0), js_url, finding_type, value,
		COALESCE(context,''), severity, first_seen, last_seen, COALESCE(scan_id,0)
		FROM js_findings WHERE %s ORDER BY %s, last_seen DESC LIMIT ? OFFSET ?`, where, sevOrder),
		append(args, limit, offset)...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var findings []models.JSFinding
	for rows.Next() {
		f := models.JSFinding{}
		if err := rows.Scan(&f.ID, &f.AssetID, &f.HostID, &f.JSURL, &f.FindingType,
			&f.Value, &f.Context, &f.Severity, &f.FirstSeen, &f.LastSeen, &f.ScanID); err != nil {
			return nil, 0, err
		}
		findings = append(findings, f)
	}
	return findings, total, rows.Err()
}

// ──────────────────────────── CHANGES ────────────────────────────

func (d *DB) CreateChangeEvent(e models.ChangeEvent) (int64, error) {
	res, err := d.db.Exec(
		`INSERT INTO change_events (scan_id, domain, event_type, severity, description, details, alerted, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
		e.ScanID, e.Domain, e.EventType, e.Severity, e.Description, e.Details, time.Now(),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) GetChangeEvents(filter ChangeFilter) ([]models.ChangeEvent, int, error) {
	where, args := "1=1", []interface{}{}
	if filter.Domain != "" {
		where += " AND domain=?"
		args = append(args, filter.Domain)
	}
	if filter.EventType != "" {
		where += " AND event_type=?"
		args = append(args, filter.EventType)
	}
	if filter.Severity != "" {
		where += " AND severity=?"
		args = append(args, filter.Severity)
	}
	if filter.ScanID != 0 {
		where += " AND scan_id=?"
		args = append(args, filter.ScanID)
	}

	var total int
	d.db.QueryRow("SELECT COUNT(*) FROM change_events WHERE "+where, args...).Scan(&total)

	limit := 100
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Page > 1 {
		offset = (filter.Page - 1) * limit
	}

	rows, err := d.db.Query(fmt.Sprintf(
		`SELECT id, COALESCE(scan_id,0), domain, event_type, severity, description,
		COALESCE(details,'{}'), COALESCE(alerted,0), created_at
		FROM change_events WHERE %s ORDER BY created_at DESC LIMIT ? OFFSET ?`, where),
		append(args, limit, offset)...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var events []models.ChangeEvent
	for rows.Next() {
		e := models.ChangeEvent{}
		var alerted int
		if err := rows.Scan(&e.ID, &e.ScanID, &e.Domain, &e.EventType, &e.Severity,
			&e.Description, &e.Details, &alerted, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		e.Alerted = alerted == 1
		events = append(events, e)
	}
	return events, total, rows.Err()
}

// ──────────────────────────── FINGERPRINTS ────────────────────────────

func (d *DB) UpsertFingerprint(f models.Fingerprint) error {
	_, err := d.db.Exec(
		`INSERT INTO fingerprints (asset_id, host_id, technology, version, category, confidence, source, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(asset_id, host_id, technology) DO UPDATE SET
		version=excluded.version, confidence=excluded.confidence, updated_at=excluded.updated_at`,
		f.AssetID, f.HostID, f.Technology, f.Version, f.Category, f.Confidence, f.Source, time.Now(),
	)
	return err
}

// ──────────────────────────── STATS ────────────────────────────

func (d *DB) GetDashboardStats() (*models.DashboardStats, error) {
	s := &models.DashboardStats{}
	d.db.QueryRow(`SELECT COUNT(*) FROM assets WHERE status='active'`).Scan(&s.TotalAssets)
	d.db.QueryRow(`SELECT COUNT(*) FROM hosts`).Scan(&s.ActiveHosts)
	d.db.QueryRow(`SELECT COUNT(*) FROM ports WHERE state='open'`).Scan(&s.OpenPorts)
	d.db.QueryRow(`SELECT COUNT(*) FROM ports WHERE state='open' AND risk_level='high'`).Scan(&s.HighRiskPorts)
	d.db.QueryRow(`SELECT COUNT(*) FROM js_findings`).Scan(&s.JSFindings)
	d.db.QueryRow(`SELECT COUNT(*) FROM change_events WHERE created_at > datetime('now','-24 hours')`).Scan(&s.NewChanges)
	d.db.QueryRow(`SELECT COUNT(*) FROM scans WHERE status='completed'`).Scan(&s.TotalScans)
	d.db.QueryRow(`SELECT COUNT(DISTINCT domain) FROM assets`).Scan(&s.MonitoredDomains)
	d.db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE interesting=1`).Scan(&s.InterestingHosts)
	d.db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE screenshot_path != '' AND screenshot_path IS NOT NULL`).Scan(&s.Screenshots)
	var lastScan time.Time
	if err := d.db.QueryRow(`SELECT started_at FROM scans ORDER BY started_at DESC LIMIT 1`).Scan(&lastScan); err == nil {
		s.LastScanTime = &lastScan
	}
	return s, nil
}

// ──────────────────────────── ALERT HISTORY ────────────────────────────

func (d *DB) HasAlerted(domain, eventType, value string) (bool, error) {
	var count int
	err := d.db.QueryRow(`SELECT COUNT(*) FROM alert_history WHERE domain=? AND event_type=? AND message LIKE ?`,
		domain, eventType, "%"+value+"%").Scan(&count)
	return count > 0, err
}

func (d *DB) RecordAlert(domain, eventType, message string, success bool) error {
	succ := 0
	if success {
		succ = 1
	}
	_, err := d.db.Exec(`INSERT INTO alert_history (domain, event_type, message, success, sent_at) VALUES (?, ?, ?, ?, ?)`,
		domain, eventType, message, succ, time.Now())
	return err
}

func (d *DB) GetAlertHistory(domain string, limit int) ([]map[string]interface{}, error) {
	where, args := "1=1", []interface{}{}
	if domain != "" {
		where += " AND domain=?"
		args = append(args, domain)
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := d.db.Query(fmt.Sprintf(
		`SELECT id, domain, event_type, message, success, sent_at FROM alert_history WHERE %s ORDER BY sent_at DESC LIMIT ?`, where),
		append(args, limit)...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id int64
		var dom, evt, msg string
		var success int
		var sentAt time.Time
		if err := rows.Scan(&id, &dom, &evt, &msg, &success, &sentAt); err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{
			"id": id, "domain": dom, "event_type": evt,
			"message": msg, "success": success == 1, "sent_at": sentAt,
		})
	}
	return out, rows.Err()
}

// ──────────────────────────── TECH FINDINGS ────────────────────────────

func (d *DB) UpsertTechFinding(f struct {
	Domain     string
	HostURL    string
	HostID     int64
	AssetID    int64
	Technology string
	CheckName  string
	URL        string
	Result     string
	Severity   string
	Detail     string
	Confirmed  bool
	ScanID     int64
}) (int64, bool, error) {
	var existingID int64
	err := d.db.QueryRow(`SELECT id FROM tech_findings WHERE domain=? AND host_url=? AND technology=? AND check_name=?`,
		f.Domain, f.HostURL, f.Technology, f.CheckName).Scan(&existingID)

	if err == sql.ErrNoRows {
		res, err := d.db.Exec(
			`INSERT INTO tech_findings (domain, host_url, host_id, asset_id, technology, check_name,
			url, result, severity, detail, confirmed, first_seen, last_seen, scan_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.Domain, f.HostURL, f.HostID, f.AssetID, f.Technology, f.CheckName,
			f.URL, f.Result, f.Severity, f.Detail, boolInt(f.Confirmed), time.Now(), time.Now(), f.ScanID,
		)
		if err != nil {
			return 0, false, err
		}
		id, _ := res.LastInsertId()
		return id, true, nil
	} else if err != nil {
		return 0, false, err
	}
	_, err = d.db.Exec(`UPDATE tech_findings SET result=?, severity=?, detail=?, confirmed=?, last_seen=?, scan_id=? WHERE id=?`,
		f.Result, f.Severity, f.Detail, boolInt(f.Confirmed), time.Now(), f.ScanID, existingID)
	return existingID, false, err
}

func (d *DB) GetTechFindings(domain, tech, severity string, limit int) ([]map[string]interface{}, int, error) {
	where, args := "1=1", []interface{}{}
	if domain != "" {
		where += " AND domain=?"
		args = append(args, domain)
	}
	if tech != "" {
		where += " AND technology=?"
		args = append(args, tech)
	}
	if severity != "" {
		where += " AND severity=?"
		args = append(args, severity)
	}
	var total int
	d.db.QueryRow("SELECT COUNT(*) FROM tech_findings WHERE "+where, args...).Scan(&total)
	if limit <= 0 {
		limit = 100
	}
	rows, err := d.db.Query(fmt.Sprintf(
		`SELECT id, domain, host_url, host_id, asset_id, technology, check_name, url,
		result, severity, detail, confirmed, first_seen, last_seen, scan_id
		FROM tech_findings WHERE %s ORDER BY
		CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
		last_seen DESC LIMIT ?`, where),
		append(args, limit)...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id, hostID, assetID, scanID int64
		var dom, hostURL, tech2, checkName, url, result, sev, detail string
		var confirmed int
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(&id, &dom, &hostURL, &hostID, &assetID, &tech2, &checkName, &url,
			&result, &sev, &detail, &confirmed, &firstSeen, &lastSeen, &scanID); err != nil {
			return nil, 0, err
		}
		out = append(out, map[string]interface{}{
			"id": id, "domain": dom, "host_url": hostURL, "host_id": hostID,
			"asset_id": assetID, "technology": tech2, "check_name": checkName,
			"url": url, "result": result, "severity": sev, "detail": detail,
			"confirmed": confirmed == 1, "first_seen": firstSeen, "last_seen": lastSeen, "scan_id": scanID,
		})
	}
	return out, total, rows.Err()
}

// ──────────────────────────── CLOUD FINDINGS ────────────────────────────

func (d *DB) UpsertCloudFinding(f struct {
	FindingType string
	Domain      string
	URL         string
	Provider    string
	Region      string
	Service     string
	Severity    string
	Detail      string
	Accessible  bool
	ScanID      int64
}) (int64, bool, error) {
	var existingID int64
	err := d.db.QueryRow(`SELECT id FROM cloud_findings WHERE domain=? AND finding_type=? AND url=?`,
		f.Domain, f.FindingType, f.URL).Scan(&existingID)

	if err == sql.ErrNoRows {
		res, err := d.db.Exec(
			`INSERT INTO cloud_findings (domain, scan_id, finding_type, url, provider, region, service,
			severity, detail, accessible, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.Domain, f.ScanID, f.FindingType, f.URL, f.Provider, f.Region, f.Service,
			f.Severity, f.Detail, boolInt(f.Accessible), time.Now(), time.Now(),
		)
		if err != nil {
			return 0, false, err
		}
		id, _ := res.LastInsertId()
		return id, true, nil
	} else if err != nil {
		return 0, false, err
	}
	_, err = d.db.Exec(`UPDATE cloud_findings SET severity=?, detail=?, accessible=?, last_seen=?, scan_id=? WHERE id=?`,
		f.Severity, f.Detail, boolInt(f.Accessible), time.Now(), f.ScanID, existingID)
	return existingID, false, err
}

func (d *DB) GetCloudFindings(domain, provider, severity string, limit int) ([]map[string]interface{}, int, error) {
	where, args := "1=1", []interface{}{}
	if domain != "" {
		where += " AND domain=?"
		args = append(args, domain)
	}
	if provider != "" {
		where += " AND provider=?"
		args = append(args, provider)
	}
	if severity != "" {
		where += " AND severity=?"
		args = append(args, severity)
	}
	var total int
	d.db.QueryRow("SELECT COUNT(*) FROM cloud_findings WHERE "+where, args...).Scan(&total)
	if limit <= 0 {
		limit = 100
	}
	rows, err := d.db.Query(fmt.Sprintf(
		`SELECT id, domain, scan_id, finding_type, url, provider, region, service,
		severity, detail, accessible, first_seen, last_seen
		FROM cloud_findings WHERE %s ORDER BY
		CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
		last_seen DESC LIMIT ?`, where),
		append(args, limit)...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id, scanID int64
		var dom, ftype, url, prov, reg, svc, sev, detail string
		var accessible int
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(&id, &dom, &scanID, &ftype, &url, &prov, &reg, &svc,
			&sev, &detail, &accessible, &firstSeen, &lastSeen); err != nil {
			return nil, 0, err
		}
		out = append(out, map[string]interface{}{
			"id": id, "domain": dom, "scan_id": scanID, "finding_type": ftype,
			"url": url, "provider": prov, "region": reg, "service": svc,
			"severity": sev, "detail": detail, "accessible": accessible == 1,
			"first_seen": firstSeen, "last_seen": lastSeen,
		})
	}
	return out, total, rows.Err()
}

// ──────────────────────────── WIPE ────────────────────────────

func (d *DB) WipeDomain(domain string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	rows, _ := tx.Query(`SELECT id FROM assets WHERE domain=?`, domain)
	var assetIDs []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		assetIDs = append(assetIDs, id)
	}
	rows.Close()

	for _, aid := range assetIDs {
		tx.Exec(`DELETE FROM js_findings WHERE asset_id=?`, aid)
		tx.Exec(`DELETE FROM fingerprints WHERE asset_id=?`, aid)
		tx.Exec(`DELETE FROM ports WHERE asset_id=?`, aid)
		tx.Exec(`DELETE FROM hosts WHERE asset_id=?`, aid)
	}
	tx.Exec(`DELETE FROM assets WHERE domain=?`, domain)
	tx.Exec(`DELETE FROM change_events WHERE domain=?`, domain)
	tx.Exec(`DELETE FROM scans WHERE domain=?`, domain)
	return tx.Commit()
}

func (d *DB) WipeAll() error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range []string{"js_findings", "fingerprints", "ports", "hosts", "assets", "change_events", "scans"} {
		tx.Exec("DELETE FROM " + t)
	}
	return tx.Commit()
}

func (d *DB) GetDomains() ([]string, error) {
	rows, err := d.db.Query(`SELECT DISTINCT domain FROM assets ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var domains []string
	for rows.Next() {
		var d string
		rows.Scan(&d)
		domains = append(domains, d)
	}
	return domains, rows.Err()
}

// ──────────────────────────── EXPORT ────────────────────────────

func (d *DB) ExportDomain(domain string) (map[string]interface{}, error) {
	assets, _, _ := d.GetAllAssets(AssetFilter{Domain: domain, Limit: 100000})
	hosts, _, _ := d.GetHosts(HostFilter{Domain: domain, Limit: 100000})
	ports, _, _ := d.GetPorts(PortFilter{Domain: domain, Limit: 100000})
	jsFin, _, _ := d.GetJSFindings(JSFindingFilter{Domain: domain, Limit: 100000})
	changes, _, _ := d.GetChangeEvents(ChangeFilter{Domain: domain, Limit: 10000})

	return map[string]interface{}{
		"domain":      domain,
		"exported_at": time.Now(),
		"assets":      assets,
		"hosts":       hosts,
		"ports":       ports,
		"js_findings": jsFin,
		"changes":     changes,
	}, nil
}

// ──────────────────────────── HELPERS ────────────────────────────

func (d *DB) UpdateHostScreenshot(id int64, path string) error {
	_, err := d.db.Exec(`UPDATE hosts SET screenshot_path=? WHERE id=?`, path, id)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func MarshalDetails(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ──────────────────────────── FILTER TYPES ────────────────────────────

type AssetFilter struct {
	Domain      string
	Search      string
	Status      string
	Interesting bool
	OrderBy     string
	OrderDir    string
	Limit       int
	Page        int
}

type HostFilter struct {
	Domain      string
	Search      string
	StatusCode  int
	Interesting bool
	Limit       int
	Page        int
}

type PortFilter struct {
	Domain      string
	IP          string
	Port        int
	Search      string
	RiskLevel   string
	Interesting bool
	Limit       int
	Page        int
}

type JSFindingFilter struct {
	Domain      string
	FindingType string
	Severity    string
	Search      string
	Limit       int
	Page        int
}

type ChangeFilter struct {
	Domain    string
	EventType string
	Severity  string
	ScanID    int64
	Limit     int
	Page      int
}
