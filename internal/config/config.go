package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Database   DatabaseConfig   `yaml:"database"`
	Discovery  DiscoveryConfig  `yaml:"discovery"`
	Scanning   ScanningConfig   `yaml:"scanning"`
	Dashboard  DashboardConfig  `yaml:"dashboard"`
	Scheduler  SchedulerConfig  `yaml:"scheduler"`
	Alerting   AlertingConfig   `yaml:"alerting"`
	TechChecks TechChecksConfig `yaml:"tech_checks"`
	CloudRecon CloudReconConfig `yaml:"cloud_recon"`
	Targets    []TargetConfig   `yaml:"targets"`
	Tools      ToolsConfig      `yaml:"tools"`
	// Active profile override (set via CLI flag)
	ActiveProfile string `yaml:"-"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type DiscoveryConfig struct {
	Sources       []string `yaml:"sources"`
	BruteForce    bool     `yaml:"brute_force"`
	WordlistPath  string   `yaml:"wordlist_path"`
	ResolverList  string   `yaml:"resolver_list"`
	MaxSubdomains int      `yaml:"max_subdomains"`
	Timeout       int      `yaml:"timeout"`
	RateLimit     int      `yaml:"rate_limit"`
}

type ScanningConfig struct {
	Profiles   ProfilesConfig   `yaml:"profiles"`
	HTTPx      HTTPxConfig      `yaml:"httpx"`
	Naabu      NaabuConfig      `yaml:"naabu"`
	Banner     BannerConfig     `yaml:"banner"`
	JSAnalysis JSAnalysisConfig `yaml:"js_analysis"`
	Screenshot ScreenshotConfig `yaml:"screenshot"`
	NetExpand  NetExpandConfig  `yaml:"net_expand"`
}

// ProfilesConfig holds per-profile overrides
type ProfilesConfig struct {
	Stealth    ProfileOverride `yaml:"stealth"`
	Standard   ProfileOverride `yaml:"standard"`
	Aggressive ProfileOverride `yaml:"aggressive"`
}

type ProfileOverride struct {
	RateLimit  int    `yaml:"rate_limit"`
	Threads    int    `yaml:"threads"`
	Ports      string `yaml:"ports"`
	BruteForce bool   `yaml:"brute_force"`
	NetExpand  bool   `yaml:"net_expand"`
	Screenshot bool   `yaml:"screenshot"`
	BannerGrab bool   `yaml:"banner_grab"`
	JSAnalysis bool   `yaml:"js_analysis"`
}

type HTTPxConfig struct {
	Threads         int  `yaml:"threads"`
	Timeout         int  `yaml:"timeout"`
	Retries         int  `yaml:"retries"`
	FollowRedirects bool `yaml:"follow_redirects"`
	MaxRedirects    int  `yaml:"max_redirects"`
	TechDetect      bool `yaml:"tech_detect"`
	TLSProbe        bool `yaml:"tls_probe"`
}

type NaabuConfig struct {
	Ports     string `yaml:"ports"`
	Threads   int    `yaml:"threads"`
	Timeout   int    `yaml:"timeout"`
	RateLimit int    `yaml:"rate_limit"`
	Retries   int    `yaml:"retries"`
	Interface string `yaml:"interface"`
}

type BannerConfig struct {
	Enabled bool `yaml:"enabled"`
	Timeout int  `yaml:"timeout"`
	Threads int  `yaml:"threads"`
}

type JSAnalysisConfig struct {
	Enabled         bool     `yaml:"enabled"`
	Threads         int      `yaml:"threads"`
	Timeout         int      `yaml:"timeout"`
	MaxFileSizeKB   int      `yaml:"max_file_size_kb"`
	ExtractPaths    bool     `yaml:"extract_paths"`
	ExtractSecrets  bool     `yaml:"extract_secrets"`
	ExcludePatterns []string `yaml:"exclude_patterns"`
}

type ScreenshotConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Timeout   int    `yaml:"timeout"`
	OutputDir string `yaml:"output_dir"`
	Threads   int    `yaml:"threads"`
}

type NetExpandConfig struct {
	Enabled  bool   `yaml:"enabled"`
	MaxHosts int    `yaml:"max_hosts"` // max IPs to add per /24
	Ports    string `yaml:"ports"`
	// RequireConfirm: if true, operator must approve before scanning expanded range
	RequireConfirm bool `yaml:"require_confirm"`
}

type DashboardConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type SchedulerConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
}

type AlertingConfig struct {
	Telegram    TelegramConfig `yaml:"telegram"`
	MinSeverity string         `yaml:"min_severity"`
	NewOnly     bool           `yaml:"new_only"`
	AlertOn     AlertOnConfig  `yaml:"alert_on"`
}

type TelegramConfig struct {
	Enabled  bool   `yaml:"enabled"`
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}

type AlertOnConfig struct {
	NewSubdomain    bool `yaml:"new_subdomain"`
	HighRiskPort    bool `yaml:"high_risk_port"`
	JSSecret        bool `yaml:"js_secret"`
	InterestingHost bool `yaml:"interesting_host"`
	HostDown        bool `yaml:"host_down"`
	NewTechnology   bool `yaml:"new_technology"`
}

type TechChecksConfig struct {
	Enabled bool `yaml:"enabled"`
	Threads int  `yaml:"threads"`
	Timeout int  `yaml:"timeout"`
}

type CloudReconConfig struct {
	Enabled bool `yaml:"enabled"`
	Timeout int  `yaml:"timeout"`
}

type TargetConfig struct {
	Domain     string   `yaml:"domain"`
	Tags       []string `yaml:"tags"`
	Scope      []string `yaml:"scope"`
	OutOfScope []string `yaml:"out_of_scope"`
	Profile    string   `yaml:"profile"`
	Disabled   bool     `yaml:"disabled"`
}

type ToolsConfig struct {
	AmassPath       string `yaml:"amass_path"`
	SubfinderPath   string `yaml:"subfinder_path"`
	AssetfinderPath string `yaml:"assetfinder_path"`
	HTTPxPath       string `yaml:"httpx_path"`
	NaabuPath       string `yaml:"naabu_path"`
	DNSXPath        string `yaml:"dnsx_path"`
	GoWitnessPath   string `yaml:"gowitness_path"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Database.Path == "" {
		c.Database.Path = "./vantage.db"
	}
	if len(c.Discovery.Sources) == 0 {
		c.Discovery.Sources = []string{"subfinder", "assetfinder"}
	}
	if c.Discovery.Timeout == 0 {
		c.Discovery.Timeout = 10
	}
	if c.Discovery.RateLimit == 0 {
		c.Discovery.RateLimit = 200
	}
	if c.Discovery.MaxSubdomains == 0 {
		c.Discovery.MaxSubdomains = 10000
	}

	// HTTPx defaults
	if c.Scanning.HTTPx.Threads == 0 {
		c.Scanning.HTTPx.Threads = 50
	}
	if c.Scanning.HTTPx.Timeout == 0 {
		c.Scanning.HTTPx.Timeout = 10
	}
	if c.Scanning.HTTPx.Retries == 0 {
		c.Scanning.HTTPx.Retries = 2
	}

	// Naabu defaults
	if c.Scanning.Naabu.Ports == "" {
		c.Scanning.Naabu.Ports = "top-100"
	}
	if c.Scanning.Naabu.Threads == 0 {
		c.Scanning.Naabu.Threads = 25
	}
	if c.Scanning.Naabu.RateLimit == 0 {
		c.Scanning.Naabu.RateLimit = 1000
	}
	if c.Scanning.Naabu.Retries == 0 {
		c.Scanning.Naabu.Retries = 2
	}
	if c.Scanning.Naabu.Timeout == 0 {
		c.Scanning.Naabu.Timeout = 100
	}

	// Banner defaults
	if c.Scanning.Banner.Timeout == 0 {
		c.Scanning.Banner.Timeout = 5
	}
	if c.Scanning.Banner.Threads == 0 {
		c.Scanning.Banner.Threads = 30
	}

	// JS defaults
	if c.Scanning.JSAnalysis.Threads == 0 {
		c.Scanning.JSAnalysis.Threads = 20
	}
	if c.Scanning.JSAnalysis.Timeout == 0 {
		c.Scanning.JSAnalysis.Timeout = 15
	}
	if c.Scanning.JSAnalysis.MaxFileSizeKB == 0 {
		c.Scanning.JSAnalysis.MaxFileSizeKB = 2048
	}
	c.Scanning.JSAnalysis.ExtractPaths = true
	c.Scanning.JSAnalysis.ExtractSecrets = true

	// Screenshot defaults
	if c.Scanning.Screenshot.Timeout == 0 {
		c.Scanning.Screenshot.Timeout = 20
	}
	if c.Scanning.Screenshot.OutputDir == "" {
		c.Scanning.Screenshot.OutputDir = "./screenshots"
	}
	if c.Scanning.Screenshot.Threads == 0 {
		c.Scanning.Screenshot.Threads = 4
	}

	// NetExpand defaults
	if c.Scanning.NetExpand.MaxHosts == 0 {
		c.Scanning.NetExpand.MaxHosts = 254
	}
	if c.Scanning.NetExpand.Ports == "" {
		c.Scanning.NetExpand.Ports = "top-100"
	}

	// Profile defaults
	c.Scanning.Profiles.Stealth = ProfileOverride{
		RateLimit:  50,
		Threads:    10,
		Ports:      "80,443,8080,8443",
		BruteForce: false,
		NetExpand:  false,
		Screenshot: false,
		BannerGrab: false,
		JSAnalysis: true,
	}
	c.Scanning.Profiles.Standard = ProfileOverride{
		RateLimit:  500,
		Threads:    25,
		Ports:      "top-100",
		BruteForce: false,
		NetExpand:  false,
		Screenshot: true,
		BannerGrab: true,
		JSAnalysis: true,
	}
	c.Scanning.Profiles.Aggressive = ProfileOverride{
		RateLimit:  2000,
		Threads:    50,
		Ports:      "top-1000",
		BruteForce: true,
		NetExpand:  true,
		Screenshot: true,
		BannerGrab: true,
		JSAnalysis: true,
	}

	// Tool paths
	if c.Tools.SubfinderPath == "" {
		c.Tools.SubfinderPath = "subfinder"
	}
	if c.Tools.AssetfinderPath == "" {
		c.Tools.AssetfinderPath = "assetfinder"
	}
	if c.Tools.AmassPath == "" {
		c.Tools.AmassPath = "amass"
	}
	if c.Tools.HTTPxPath == "" {
		c.Tools.HTTPxPath = "httpx"
	}
	if c.Tools.NaabuPath == "" {
		c.Tools.NaabuPath = "naabu"
	}
	if c.Tools.DNSXPath == "" {
		c.Tools.DNSXPath = "dnsx"
	}
	if c.Tools.GoWitnessPath == "" {
		c.Tools.GoWitnessPath = "gowitness"
	}

	if c.Dashboard.Host == "" {
		c.Dashboard.Host = "127.0.0.1"
	}
	if c.Dashboard.Port == 0 {
		c.Dashboard.Port = 8080
	}
	if c.Scheduler.Schedule == "" {
		c.Scheduler.Schedule = "0 0 2 * * *"
	}

	// Alerting defaults
	if c.Alerting.MinSeverity == "" {
		c.Alerting.MinSeverity = "high"
	}
	c.Alerting.NewOnly = true
	c.Alerting.AlertOn.NewSubdomain = true
	c.Alerting.AlertOn.HighRiskPort = true
	c.Alerting.AlertOn.JSSecret = true
	c.Alerting.AlertOn.InterestingHost = true
	c.Alerting.AlertOn.HostDown = false
	c.Alerting.AlertOn.NewTechnology = true

	// Tech checks defaults
	if c.TechChecks.Threads == 0 {
		c.TechChecks.Threads = 10
	}
	if c.TechChecks.Timeout == 0 {
		c.TechChecks.Timeout = 8
	}
	c.TechChecks.Enabled = true

	// Cloud recon defaults
	if c.CloudRecon.Timeout == 0 {
		c.CloudRecon.Timeout = 8
	}
	c.CloudRecon.Enabled = true
}

// GetProfile returns the active profile override
func (c *Config) GetProfile(name string) ProfileOverride {
	switch name {
	case "stealth":
		return c.Scanning.Profiles.Stealth
	case "aggressive":
		return c.Scanning.Profiles.Aggressive
	default:
		return c.Scanning.Profiles.Standard
	}
}

func DefaultConfig() *Config {
	cfg := &Config{}
	cfg.applyDefaults()
	return cfg
}
