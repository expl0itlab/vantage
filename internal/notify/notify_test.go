package notify

import (
	"fmt"
	"strings"
	"testing"
)

func TestEscapeHTML(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello world", "hello world"},
		{"<script>alert(1)</script>", "&lt;script&gt;alert(1)&lt;/script&gt;"},
		{"a & b", "a &amp; b"},
		{"tag <b>bold</b>", "tag &lt;b&gt;bold&lt;/b&gt;"},
		{"no special chars", "no special chars"},
	}

	for _, tt := range tests {
		got := EscapeHTML(tt.input)
		if got != tt.expected {
			t.Errorf("EscapeHTML(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func severityAbove(sev, minSev string) bool {
	rank, ok := severityRank[strings.ToLower(sev)]
	if !ok {
		rank = 0
	}
	return rank >= severityRank[strings.ToLower(minSev)]
}

func TestSeverityRanking(t *testing.T) {
	tests := []struct {
		sev        string
		minSev     string
		shouldSend bool
	}{
		{"critical", "high", true},
		{"high", "high", true},
		{"medium", "high", false},
		{"low", "high", false},
		{"info", "high", false},
		{"critical", "critical", true},
		{"high", "critical", false},
		{"CRITICAL", "high", true},
		{"High", "high", true},
		{"unknown", "high", false},
	}

	for _, tt := range tests {
		got := severityAbove(tt.sev, tt.minSev)
		if got != tt.shouldSend {
			t.Errorf("sev=%q minSev=%q: got %v, want %v", tt.sev, tt.minSev, got, tt.shouldSend)
		}
	}
}

func TestFormatAlert(t *testing.T) {
	desc := "New port: 10.0.0.1:22/tcp (ssh) [high]"
	domain := "target.com"

	icon := "🔴"
	msg := fmt.Sprintf("%s <b>[%s]</b> %s\nDomain: <i>%s</i>",
		icon,
		"CRITICAL",
		EscapeHTML(desc),
		EscapeHTML(domain))

	fmt.Println("Formatted Telegram message:")
	fmt.Println(msg)
}
