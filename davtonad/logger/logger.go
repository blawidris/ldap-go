package logger

import (
	"errors"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
	
	// G302: Use 0600 permissions (owner read/write only) for security best practices.
	file, err := os.OpenFile(LogPath(), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
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

// ValidateLogPath ensures the file path is safe and within the expected directory.
// Prevents path traversal attacks (G304 mitigation).
func ValidateLogPath(path string) error {
	// Clean the path to resolve any . or .. components
	cleanPath := filepath.Clean(path)
	
	// Get the expected root directory
	root := filepath.Clean(GetRoot())
	
	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return errors.New("path traversal detected: .. not allowed")
	}
	
	// Ensure the path is within the expected directory
	if !strings.HasPrefix(cleanPath, root) {
		return errors.New("path outside allowed directory")
	}
	
	// Ensure it's a .txt file in the resources directory
	if filepath.Ext(cleanPath) != ".txt" {
		return errors.New("invalid file type: only .txt files allowed")
	}
	
	return nil
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

	// Open a traversal-resistant root for all cleanup operations (Go 1.24 os.Root API). [ASCA] safe filesystem access
	r, err := os.OpenRoot(root)
	if err != nil {
		log.Println("logger: OpenRoot failed:", err)
		return
	}
	defer func() {
		if cerr := r.Close(); cerr != nil {
			log.Println("logger: root close failed:", cerr)
		}
	}()

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
			// Use the confined root to remove files safely; prevents path traversal. [ASCA] safe removal
			if err := r.Remove(name); err != nil {
				// Use structured logging and avoid leaking full filesystem paths.
				if Log != nil {
					Log.Error("CleanupOldLogs", "file", name, "err", err)
				} else {
					log.Println("logger: cleanup remove failed:", name, err)
				}
			} else {
				if Log != nil {
					Log.Info("CleanupOldLogs", "msg", "deleted old log file", "file", name)
				} else {
					log.Println("logger: deleted old log file:", name)
				}
			}
		}
	}
}
