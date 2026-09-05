package screenshot

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Result struct {
	URL   string
	Path  string // relative path to screenshot file
	Error string
}

type Engine struct {
	goWitnessPath string
	outputDir     string
	timeout       int
	threads       int
	logger        func(string, ...interface{})
}

func New(goWitnessPath, outputDir string, timeout, threads int, logger func(string, ...interface{})) *Engine {
	if logger == nil {
		logger = func(s string, a ...interface{}) { fmt.Printf("[screenshot] "+s+"\n", a...) }
	}
	if timeout == 0 {
		timeout = 20
	}
	if threads == 0 {
		threads = 4
	}
	if outputDir == "" {
		outputDir = "./screenshots"
	}
	return &Engine{
		goWitnessPath: goWitnessPath,
		outputDir:     outputDir,
		timeout:       timeout,
		threads:       threads,
		logger:        logger,
	}
}

// CaptureAll takes screenshots of all provided URLs using gowitness
func (e *Engine) CaptureAll(ctx context.Context, urls []string) []Result {
	if len(urls) == 0 {
		return nil
	}

	// Check gowitness is available
	if _, err := exec.LookPath(e.goWitnessPath); err != nil {
		e.logger("screenshot: gowitness not found at %s — skipping", e.goWitnessPath)
		return nil
	}

	e.logger("screenshot: capturing %d URLs", len(urls))

	// Create output directory
	if err := os.MkdirAll(e.outputDir, 0755); err != nil {
		e.logger("screenshot: failed to create output dir: %v", err)
		return nil
	}

	// Write URLs to temp file
	tmpFile, err := os.CreateTemp("", "vantage-screenshot-*.txt")
	if err != nil {
		return nil
	}
	defer os.Remove(tmpFile.Name())
	for _, u := range urls {
		fmt.Fprintln(tmpFile, u)
	}
	tmpFile.Close()

	scanCtx, cancel := context.WithTimeout(ctx, time.Duration(len(urls)*e.timeout+60)*time.Second)
	defer cancel()

	args := []string{
		"scan", "file",
		"-f", tmpFile.Name(),
		"-s", e.outputDir,
		"-t", fmt.Sprintf("%d", e.threads),
		"-T", fmt.Sprintf("%d", e.timeout),
		"--write-none",
	}

	cmd := exec.CommandContext(scanCtx, e.goWitnessPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		e.logger("screenshot: gowitness error: %v | %s", err, truncate(string(out), 200))
	}

	// Parse what got created
	results := e.collectResults(urls)
	e.logger("screenshot: captured %d/%d screenshots", len(results), len(urls))
	return results
}

func (e *Engine) collectResults(urls []string) []Result {
	var results []Result

	for _, u := range urls {
		filename := urlToFilename(u)
		candidates := []string{
			filepath.Join(e.outputDir, filename+".png"),
			filepath.Join(e.outputDir, filename+".jpg"),
			filepath.Join(e.outputDir, filename+".jpeg"),
		}

		for _, path := range candidates {
			if _, err := os.Stat(path); err == nil {
				results = append(results, Result{
					URL:  u,
					Path: path,
				})
				break
			}
		}
	}

	// Also scan directory for any new PNG files
	entries, err := os.ReadDir(e.outputDir)
	if err != nil {
		return results
	}

	seen := map[string]bool{}
	for _, r := range results {
		seen[r.Path] = true
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".png") && !strings.HasSuffix(name, ".jpg") && !strings.HasSuffix(name, ".jpeg") {
			continue
		}
		fullPath := filepath.Join(e.outputDir, name)
		if !seen[fullPath] {
			// Try to match back to a URL
			results = append(results, Result{Path: fullPath})
		}
	}

	return results
}

// ListScreenshots returns all screenshot files in the output directory
func (e *Engine) ListScreenshots() []string {
	entries, err := os.ReadDir(e.outputDir)
	if err != nil {
		return nil
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() {
			name := entry.Name()
			if strings.HasSuffix(name, ".png") || strings.HasSuffix(name, ".jpg") || strings.HasSuffix(name, ".jpeg") {
				files = append(files, filepath.Join(e.outputDir, name))
			}
		}
	}
	return files
}

// OutputDir returns the screenshot output directory
func (e *Engine) OutputDir() string {
	return e.outputDir
}

func urlToFilename(u string) string {
	// gowitness v3 uses a specific naming convention
	r := strings.NewReplacer(
		"https://", "https-",
		"http://", "http-",
		"/", "-",
		":", "-",
		"?", "-",
		"&", "-",
		"=", "-",
		".", "-",
	)
	name := r.Replace(u)
	// trim trailing dashes
	name = strings.Trim(name, "-")
	if len(name) > 200 {
		name = name[:200]
	}
	return name
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// ParseGoWitnessOutput parses gowitness output for screenshot paths mapped to URLs
func ParseGoWitnessOutput(output string) map[string]string {
	result := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "->") {
			parts := strings.SplitN(line, "->", 2)
			if len(parts) == 2 {
				url := strings.TrimSpace(parts[0])
				path := strings.TrimSpace(parts[1])
				result[url] = path
			}
		}
	}
	return result
}
