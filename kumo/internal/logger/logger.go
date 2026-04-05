// Package logger implements JSONL traffic logging with daily rotation and disk safety.
package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kumo-ai/kumo/pkg/types"
)

// Logger writes traffic entries to JSONL files with daily rotation.
type Logger struct {
	dir     string
	entries chan types.TrafficEntry
	done    chan struct{}
	closed  sync.Once

	mu      sync.Mutex
	file    *os.File
	fileDay string // YYYY-MM-DD of current file
}

// New creates a new Logger that writes to the given directory.
func New(dir string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create log directory %s: %w", dir, err)
	}

	l := &Logger{
		dir:     dir,
		entries: make(chan types.TrafficEntry, 1000),
		done:    make(chan struct{}),
	}

	go l.writeLoop()
	return l, nil
}

// Log queues a traffic entry for writing.
// Safe to call after Flush(): recovers from send-on-closed-channel
// (in-flight requests that complete after shutdown will be dropped).
func (l *Logger) Log(entry types.TrafficEntry) {
	defer func() { recover() }()
	select {
	case l.entries <- entry:
	default:
		log.Printf("WARNING: log buffer full, dropping entry %s", entry.ID)
	}
}

// Flush drains the buffer and syncs to disk. Safe to call multiple times.
func (l *Logger) Flush() {
	l.closed.Do(func() {
		close(l.entries)
	})
	<-l.done

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		l.file.Sync()
		l.file.Close()
		l.file = nil
	}
}

func (l *Logger) writeLoop() {
	defer close(l.done)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var batch []types.TrafficEntry

	for {
		select {
		case entry, ok := <-l.entries:
			if !ok {
				// Channel closed, flush remaining
				l.writeBatch(batch)
				return
			}
			batch = append(batch, entry)
			if len(batch) >= 100 {
				l.writeBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				l.writeBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (l *Logger) writeBatch(batch []types.TrafficEntry) {
	if len(batch) == 0 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, entry := range batch {
		f, err := l.getFile()
		if err != nil {
			log.Printf("ERROR: cannot open log file: %v", err)
			continue
		}

		data, err := json.Marshal(entry)
		if err != nil {
			log.Printf("ERROR: marshal log entry: %v", err)
			continue
		}

		if _, err := f.Write(append(data, '\n')); err != nil {
			log.Printf("ERROR: write log entry: %v", err)
			// Disk full or other I/O error. Close file, it will be reopened next attempt.
			f.Close()
			l.file = nil
		}
	}
}

func (l *Logger) getFile() (*os.File, error) {
	today := time.Now().Format("2006-01-02")
	if l.file != nil && l.fileDay == today {
		return l.file, nil
	}

	// Close old file if day changed
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}

	path := filepath.Join(l.dir, fmt.Sprintf("traffic-%s.jsonl", today))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	l.file = f
	l.fileDay = today
	return f, nil
}
