// Package tui implements a terminal dashboard for Kumo using bubbletea.
package tui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kumo-ai/kumo/pkg/types"
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	allowStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	blockStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	flagStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("255"))
)

type model struct {
	entries   []types.TrafficEntry
	logDir    string
	offset    int
	height    int
	width     int
	lastLoad  time.Time
	err       error
}

type tickMsg time.Time

// Run starts the TUI dashboard.
func Run(logDir string) error {
	m := model{
		logDir: logDir,
		height: 24,
		width:  120,
	}
	m.loadEntries()

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (m model) Init() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "j", "down":
			if m.offset < len(m.entries)-1 {
				m.offset++
			}
		case "k", "up":
			if m.offset > 0 {
				m.offset--
			}
		case "G":
			m.offset = max(0, len(m.entries)-(m.height-6))
		case "g":
			m.offset = 0
		case "r":
			m.loadEntries()
		}

	case tea.WindowSizeMsg:
		m.height = msg.Height
		m.width = msg.Width

	case tickMsg:
		m.loadEntries()
		return m, tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		})
	}

	return m, nil
}

func (m model) View() string {
	var b strings.Builder

	// Header
	b.WriteString(titleStyle.Render("  Kumo Traffic Dashboard"))
	b.WriteString(dimStyle.Render(fmt.Sprintf("  (%d requests)", len(m.entries))))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  Press q to quit, j/k to scroll, G/g for bottom/top, r to refresh"))
	b.WriteString("\n\n")

	// Column headers
	header := fmt.Sprintf("  %-8s %-6s %-30s %-40s %-6s %s",
		"DECISION", "METHOD", "HOST", "PATH", "STATUS", "DURATION")
	b.WriteString(headerStyle.Render(header))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  " + strings.Repeat("─", min(m.width-4, 120))))
	b.WriteString("\n")

	// Entries
	visibleLines := m.height - 7
	if visibleLines < 1 {
		visibleLines = 10
	}

	start := m.offset
	end := start + visibleLines
	if end > len(m.entries) {
		end = len(m.entries)
	}

	for i := start; i < end; i++ {
		e := m.entries[i]
		decision := colorDecision(e.Decision)
		host := truncate(e.Host, 30)
		path := truncate(e.Path, 40)

		line := fmt.Sprintf("  %-19s %-6s %-30s %-40s %-6d %dms",
			decision, e.Method, host, path, e.ResponseStatus, e.DurationMs)
		b.WriteString(line)
		b.WriteString("\n")
	}

	// Footer
	if len(m.entries) > 0 {
		b.WriteString("\n")
		allows, blocks, flags := 0, 0, 0
		for _, e := range m.entries {
			switch e.Decision {
			case "allow":
				allows++
			case "block":
				blocks++
			case "flag":
				flags++
			}
		}
		summary := fmt.Sprintf("  %s %d  %s %d  %s %d",
			allowStyle.Render("ALLOW"), allows,
			blockStyle.Render("BLOCK"), blocks,
			flagStyle.Render("FLAG"), flags)
		b.WriteString(summary)
	}

	return b.String()
}

func (m *model) loadEntries() {
	files, err := filepath.Glob(filepath.Join(m.logDir, "traffic-*.jsonl"))
	if err != nil {
		m.err = err
		return
	}

	var entries []types.TrafficEntry
	for _, f := range files {
		file, err := os.Open(f)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			var e types.TrafficEntry
			if json.Unmarshal(scanner.Bytes(), &e) == nil {
				entries = append(entries, e)
			}
		}
		file.Close()
	}

	m.entries = entries
	m.lastLoad = time.Now()
}

func colorDecision(d string) string {
	switch d {
	case "allow":
		return allowStyle.Render("ALLOW")
	case "block":
		return blockStyle.Render("BLOCK")
	case "flag":
		return flagStyle.Render("FLAG")
	default:
		return dimStyle.Render(d)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
