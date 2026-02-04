package logger

import (
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	Log  *slog.Logger
	mu   sync.RWMutex // Protects Log variable from race conditions
	cleanupMu sync.Mutex // Protects cleanup operations from concurrent access
)

// Start initializes the logger. Thread-safe: uses mutex to prevent race conditions.
func Start() {
	mu.Lock()
	defer mu.Unlock()
	
	file, err := os.OpenFile(LogPath(), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0660)
	if err != nil {
		log.Println("logger: failed to open log file:", err)
		// Fall back to stderr so the application can run without a log file.
		Log = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{AddSource: true, Level: slog.LevelDebug}))
		slog.SetDefault(Log)
		return
	}
	opts := slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	}
	Log = slog.New(slog.NewJSONHandler(file, &opts))
	// Do not close file: the handler uses it for the process lifetime.
	slog.SetDefault(Log)
}

// GetLogger returns the current logger instance in a thread-safe manner.
func GetLogger() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return Log
}

func LogPath() string {
	return GetRoot() + time.Now().Format("20060102") + ".txt"
}

func GetRoot() string {
	path, err := os.Getwd()
	if err != nil {
		log.Println("logger: Getwd failed:", err)
		// Use current directory relative path so templates can still be resolved.
		return "resources/"
	}
	return path + "/resources/"
}

// LogRetentionDays is how long to keep log files before cleanup (default 3).
const LogRetentionDays = 3

// CleanupOldLogs removes log files (*.txt in resources/) older than LogRetentionDays.
// Does not delete today's file (the one currently written to).
// Thread-safe: uses mutex to prevent concurrent cleanup operations.
func CleanupOldLogs() {
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	
	root := GetRoot()
	cutoff := time.Now().AddDate(0, 0, -LogRetentionDays)
	cutoffDate := cutoff.Format("20060102")

	entries, err := os.ReadDir(root)
	if err != nil {
		log.Println("logger: cleanup ReadDir failed:", err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".txt" {
			continue
		}
		// Safe bounds check to prevent panic on malformed filenames.
		if len(name) < 5 { // minimum: "X.txt"
			continue
		}
		base := name[:len(name)-4] // strip .txt
		if len(base) != 8 {
			continue
		}
		if base < cutoffDate {
			fpath := filepath.Join(root, name)
			if err := os.Remove(fpath); err != nil {
				log.Println("logger: cleanup remove failed:", fpath, err)
			} else {
				log.Println("logger: deleted old log file:", fpath)
			}
		}
	}
}
