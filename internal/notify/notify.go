package notify

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Telegram struct {
	botToken string
	chatID   string
	minSev   string
	enabled  bool
	client   *http.Client
	queue    chan string
	wg       sync.WaitGroup
	quit     chan struct{}
}

var severityRank = map[string]int{
	"info":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

func New(botToken, chatID, minSeverity string, enabled bool) *Telegram {
	if minSeverity == "" {
		minSeverity = "high"
	}
	t := &Telegram{
		botToken: botToken,
		chatID:   chatID,
		minSev:   strings.ToLower(minSeverity),
		enabled:  enabled && botToken != "" && chatID != "" && severityRank[strings.ToLower(minSeverity)] > 0,
		client:   &http.Client{Timeout: 10 * time.Second},
		queue:    make(chan string, 100),
		quit:     make(chan struct{}),
	}
	if t.enabled {
		t.wg.Add(1)
		go t.sender()
	}
	return t
}

func (t *Telegram) Send(message string) {
	if !t.enabled {
		return
	}
	select {
	case t.queue <- message:
	default:
	}
}

func (t *Telegram) SendIfSeverity(severity, message string) {
	if !t.enabled {
		return
	}
	sev := strings.ToLower(strings.TrimSpace(severity))
	rank, ok := severityRank[sev]
	if !ok {
		rank = 0 // unknown severity treated as info
	}
	if rank < severityRank[t.minSev] {
		return
	}
	t.Send(message)
}

func (t *Telegram) Close() {
	if !t.enabled {
		return
	}
	close(t.quit)
	t.wg.Wait()
}

func (t *Telegram) sender() {
	defer t.wg.Done()
	for {
		select {
		case <-t.quit:
			// drain remaining queue before exit
			for {
				select {
				case msg := <-t.queue:
					t.doSend(msg)
				default:
					return
				}
			}
		case msg := <-t.queue:
			t.doSend(msg)
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func (t *Telegram) doSend(text string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.botToken)
	data := url.Values{
		"chat_id":                  {t.chatID},
		"text":                     {text},
		"parse_mode":               {"HTML"},
		"disable_web_page_preview": {"true"},
	}

	resp, err := t.client.PostForm(apiURL, data)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

// EscapeHTML escapes special characters for Telegram HTML parse mode.
func EscapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
