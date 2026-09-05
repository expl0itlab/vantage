package scheduler

import (
	"context"
	"fmt"
	"sync"

	"github.com/expl0itlab/vantage/internal/config"
	"github.com/expl0itlab/vantage/internal/processor"
	"github.com/robfig/cron/v3"
)

type Scheduler struct {
	cfg       *config.Config
	processor *processor.Processor
	logger    func(string, ...interface{})
	cron      *cron.Cron
	running   map[string]bool
	mu        sync.Mutex
}

func New(cfg *config.Config, proc *processor.Processor, logger func(string, ...interface{})) *Scheduler {
	if logger == nil {
		logger = func(s string, a ...interface{}) { fmt.Printf("[scheduler] "+s+"\n", a...) }
	}
	return &Scheduler{
		cfg:       cfg,
		processor: proc,
		logger:    logger,
		cron:      cron.New(cron.WithSeconds()),
		running:   make(map[string]bool),
	}
}

func (s *Scheduler) Start() error {
	if !s.cfg.Scheduler.Enabled {
		return nil
	}
	schedule := s.cfg.Scheduler.Schedule
	for _, target := range s.cfg.Targets {
		if target.Disabled {
			continue
		}
		domain := target.Domain
		profile := target.Profile
		if profile == "" {
			profile = "standard"
		}
		_, err := s.cron.AddFunc(schedule, func() {
			s.runScan(domain, profile)
		})
		if err != nil {
			return fmt.Errorf("scheduling %s: %w", domain, err)
		}
		s.logger("scheduled %s [%s] at %s", domain, profile, schedule)
	}
	s.cron.Start()
	return nil
}

func (s *Scheduler) Stop() { s.cron.Stop() }

func (s *Scheduler) TriggerNow(domain, profile string) {
	go s.runScan(domain, profile)
}

func (s *Scheduler) IsRunning(domain string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running[domain]
}

func (s *Scheduler) runScan(domain, profile string) {
	s.mu.Lock()
	if s.running[domain] {
		s.logger("scan for %s already running — skipping", domain)
		s.mu.Unlock()
		return
	}
	s.running[domain] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.running, domain)
		s.mu.Unlock()
	}()

	s.logger("starting scheduled scan for %s [%s]", domain, profile)
	_, err := s.processor.RunScan(context.Background(), domain, profile)
	if err != nil {
		s.logger("scheduled scan failed for %s: %v", domain, err)
	}
}
