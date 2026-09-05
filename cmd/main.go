package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/expl0itlab/vantage/internal/config"
	"github.com/expl0itlab/vantage/internal/dashboard"
	"github.com/expl0itlab/vantage/internal/db"
	"github.com/expl0itlab/vantage/internal/models"
	"github.com/expl0itlab/vantage/internal/notify"
	"github.com/expl0itlab/vantage/internal/processor"
	"github.com/expl0itlab/vantage/internal/scheduler"
)

var (
	cfgPath  string
	cfg      *config.Config
	database *db.DB
)

func main() {
	root := &cobra.Command{
		Use:   "vantage",
		Short: "Vantage — Red Team Attack Surface Management Platform",
		Long: `External attack surface management for red teams.
Profiles: stealth | standard | aggressive
`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "init" || cmd.Name() == "version" {
				return nil
			}
			var err error
			cfg, err = config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			database, err = db.Open(cfg.Database.Path)
			if err != nil {
				return fmt.Errorf("database: %w", err)
			}
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if database != nil {
				database.Close()
			}
		},
	}

	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "vantage.yaml", "config file")

	root.AddCommand(
		cmdInit(),
		cmdScan(),
		cmdServe(),
		cmdMonitor(),
		cmdVersion(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ──────────────────────────── init ────────────────────────────

func cmdInit() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "generate default vantage.yaml",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := os.Stat(cfgPath); err == nil {
				return fmt.Errorf("%s already exists", cfgPath)
			}
			if err := os.WriteFile(cfgPath, []byte(defaultConfig), 0644); err != nil {
				return err
			}
			fmt.Printf("✓ config written: %s\n\n", cfgPath)
			fmt.Println("next steps:")
			fmt.Println("  edit vantage.yaml — set targets")
			fmt.Println("  ./vantage scan -d target.com -p standard")
			fmt.Println("  ./vantage serve")
			return nil
		},
	}
}

// ──────────────────────────── scan ────────────────────────────

func cmdScan() *cobra.Command {
	var domain string
	var profile string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "run a scan against a domain",
		Example: `  vantage scan -d target.com
  vantage scan -d target.com -p stealth
  vantage scan -d target.com -p aggressive
  vantage scan   # uses targets from config`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := makeLogger()
			proc := processor.New(cfg, database, logger)
			tg := notify.New(
				cfg.Alerting.Telegram.BotToken,
				cfg.Alerting.Telegram.ChatID,
				cfg.Alerting.MinSeverity,
				cfg.Alerting.Telegram.Enabled,
			)
			defer tg.Close()

			proc.SetEventHook(func(eventType string, data interface{}) {
				if eventType == "change" {
					if evt, ok := data.(models.ChangeEvent); ok {
						tg.SendIfSeverity(evt.Severity, formatAlert(evt))
					}
				}
			})

			targets := []string{}
			if domain != "" {
				targets = append(targets, domain)
			} else {
				for _, t := range cfg.Targets {
					if !t.Disabled {
						targets = append(targets, t.Domain)
						if profile == "" && t.Profile != "" {
							profile = t.Profile
						}
					}
				}
			}
			if len(targets) == 0 {
				return fmt.Errorf("no targets — use -d domain.com or set targets in config")
			}
			if profile == "" {
				profile = "standard"
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sig
				fmt.Println("\ninterrupt — stopping...")
				cancel()
			}()

			for _, t := range dedup(targets) {
				if t == "" {
					continue
				}
				result, err := proc.RunScan(ctx, t, profile)
				if err != nil {
					if ctx.Err() != nil {
						fmt.Println("scan interrupted")
						break
					}
					logger("scan error for %s: %v", t, err)
					continue
				}
				printSummary(result)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&domain, "domain", "d", "", "target domain")
	cmd.Flags().StringVarP(&profile, "profile", "p", "standard", "scan profile: stealth|standard|aggressive")
	return cmd
}

// ──────────────────────────── serve ────────────────────────────

func cmdServe() *cobra.Command {
	var profile string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "start the web dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := makeLogger()
			proc := processor.New(cfg, database, logger)
			dash := dashboard.New(cfg, database, logger)
			tg := notify.New(
				cfg.Alerting.Telegram.BotToken,
				cfg.Alerting.Telegram.ChatID,
				cfg.Alerting.MinSeverity,
				cfg.Alerting.Telegram.Enabled,
			)
			defer tg.Close()

			proc.SetEventHook(func(eventType string, data interface{}) {
				dash.BroadcastEvent(eventType, data)
				if eventType == "change" {
					if evt, ok := data.(models.ChangeEvent); ok {
						tg.SendIfSeverity(evt.Severity, formatAlert(evt))
					}
				}
			})

			dash.SetScanHandler(func(domain, p string) error {
				ctx := context.Background()
				if p == "" {
					p = profile
				}
				_, err := proc.RunScan(ctx, domain, p)
				return err
			})

			sched := scheduler.New(cfg, proc, logger)
			if cfg.Scheduler.Enabled {
				if err := sched.Start(); err != nil {
					logger("scheduler error: %v", err)
				}
				defer sched.Stop()
			}

			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sig
				fmt.Println("\nshutting down...")
				if database != nil {
					database.Close()
				}
				os.Exit(0)
			}()

			fmt.Printf("✓ dashboard: http://%s:%d\n", cfg.Dashboard.Host, cfg.Dashboard.Port)
			if cfg.Scheduler.Enabled {
				fmt.Printf("✓ scheduler: %s\n", cfg.Scheduler.Schedule)
			}
			return dash.Start()
		},
	}

	cmd.Flags().StringVarP(&profile, "profile", "p", "standard", "default scan profile")
	return cmd
}

// ──────────────────────────── monitor ────────────────────────────

func cmdMonitor() *cobra.Command {
	return &cobra.Command{
		Use:   "monitor",
		Short: "headless scheduler — no dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := makeLogger()
			proc := processor.New(cfg, database, logger)
			tg := notify.New(
				cfg.Alerting.Telegram.BotToken,
				cfg.Alerting.Telegram.ChatID,
				cfg.Alerting.MinSeverity,
				cfg.Alerting.Telegram.Enabled,
			)
			defer tg.Close()

			proc.SetEventHook(func(eventType string, data interface{}) {
				if eventType == "change" {
					if evt, ok := data.(models.ChangeEvent); ok {
						tg.SendIfSeverity(evt.Severity, formatAlert(evt))
					}
				}
			})

			sched := scheduler.New(cfg, proc, logger)
			if err := sched.Start(); err != nil {
				return fmt.Errorf("scheduler: %w", err)
			}
			defer sched.Stop()

			fmt.Printf("✓ monitor running — schedule: %s\n", cfg.Scheduler.Schedule)
			fmt.Printf("✓ watching %d targets\n", len(cfg.Targets))
			fmt.Println("  ctrl+c to stop")

			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			<-sig
			fmt.Println("\nstopped.")
			return nil
		},
	}
}

// ──────────────────────────── version ────────────────────────────

func cmdVersion() *cobra.Command {
	return &cobra.Command{
		Use: "version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("vantage v1.0.0 // red team edition")
			fmt.Println("profiles: stealth | standard | aggressive")
			fmt.Println("tools: subfinder, assetfinder, httpx, naabu, dnsx, gowitness")
		},
	}
}

// ──────────────────────────── helpers ────────────────────────────

func formatAlert(evt models.ChangeEvent) string {
	icon := "ℹ️"
	switch evt.Severity {
	case "critical":
		icon = "🔴"
	case "high":
		icon = "🟠"
	case "medium":
		icon = "🟡"
	case "low":
		icon = "🔵"
	}
	return fmt.Sprintf("%s <b>[%s]</b> %s\nDomain: <i>%s</i>",
		icon,
		strings.ToUpper(evt.Severity),
		notify.EscapeHTML(evt.Description),
		notify.EscapeHTML(evt.Domain))
}

func makeLogger() func(string, ...interface{}) {
	return func(format string, args ...interface{}) {
		log.Printf(format, args...)
	}
}

func printSummary(r *processor.ScanResult) {
	fmt.Printf("\n─── %s [%s] ───\n", r.Domain, r.Profile)
	fmt.Printf("  assets   : %d\n", r.Stats.AssetsFound)
	fmt.Printf("  hosts    : %d\n", r.Stats.HostsFound)
	fmt.Printf("  ports    : %d\n", r.Stats.PortsFound)
	fmt.Printf("  js       : %d\n", r.Stats.JSFindings)
	fmt.Printf("  changes  : %d\n", len(r.Changes))
	fmt.Printf("  duration : %ds\n", r.Stats.Duration)
	if len(r.Errors) > 0 {
		fmt.Printf("  errors   : %d\n", len(r.Errors))
	}
	for _, c := range r.Changes {
		if c.Severity == "critical" || c.Severity == "high" {
			icon := "[HIGH]"
			if c.Severity == "critical" {
				icon = "[CRIT]"
			}
			fmt.Printf("  %s %s\n", icon, c.Description)
		}
	}
}

func dedup(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		s = strings.TrimSpace(strings.ToLower(s))
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

const defaultConfig = `# Vantage Configuration — Red Team Edition
# Generated: ` + "2026" + `

database:
  path: "./vantage.db"

targets:
  - domain: "example.com"
    profile: "standard"
    disabled: false

discovery:
  sources:
    - subfinder
    - assetfinder
  brute_force: false
  rate_limit: 200
  max_subdomains: 10000
  timeout: 10

scanning:
  httpx:
    threads: 50
    timeout: 10
    retries: 2
    follow_redirects: true
    max_redirects: 3
    tech_detect: true
    tls_probe: true

  naabu:
    ports: "top-100"
    threads: 25
    rate_limit: 1000
    retries: 2
    timeout: 100

  banner:
    enabled: true
    timeout: 5
    threads: 30

  js_analysis:
    enabled: true
    threads: 20
    timeout: 15
    max_file_size_kb: 2048
    extract_paths: true
    extract_secrets: true

  screenshot:
    enabled: true
    timeout: 20
    output_dir: "./screenshots"
    threads: 4

  net_expand:
    enabled: false          # enable for aggressive internal recon
    max_hosts: 254
    ports: "top-100"
    require_confirm: true   # safety: require explicit --expand flag

dashboard:
  host: "127.0.0.1"
  port: 8080
  username: ""             # set for basic auth
  password: ""

scheduler:
  enabled: false
  schedule: "0 0 2 * * *"  # daily 02:00

alerting:
  telegram:
    enabled: false
    bot_token: ""            # get from @BotFather on Telegram
    chat_id: ""              # your chat or group ID
  min_severity: "high"       # critical, high, medium, low, info
  new_only: true             # only alert on first occurrence
  alert_on:
    new_subdomain: true
    high_risk_port: true
    js_secret: true
    interesting_host: true
    host_down: false         # noisy — disable by default
    new_technology: true

tech_checks:
  enabled: true
  threads: 10
  timeout: 8                 # seconds per HTTP request

cloud_recon:
  enabled: true
  timeout: 8

tools:
  subfinder_path:    "subfinder"
  assetfinder_path:  "assetfinder"
  amass_path:        "amass"
  httpx_path:        "httpx"
  naabu_path:        "naabu"
  dnsx_path:         "dnsx"
  gowitness_path:    "gowitness"
`
