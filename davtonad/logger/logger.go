package logger

import (
	"errors"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const (
	logDirectory       = "resources"
	logFilePermissions = 0600
	logDirPermissions  = 0700
	retentionDays      = 3
)

var (
	Log         *slog.Logger
	logNameRule = regexp.MustCompile(`^[0-9]{8}[.]txt$`)
)

func Start() {
	if err := os.MkdirAll(logDirectory, logDirPermissions); err != nil {
		log.Println("logger: failed to create log directory:", err)
		Log = slog.New(slog.NewJSONHandler(os.Stderr, nil))
		slog.SetDefault(Log)
		return
	}

	file, err := os.OpenFile(currentLogPath(), os.O_WRONLY|os.O_CREATE|os.O_APPEND, logFilePermissions)
	if err != nil {
		log.Println("logger: failed to open log file:", err)
		Log = slog.New(slog.NewJSONHandler(os.Stderr, nil))
		slog.SetDefault(Log)
		return
	}

	Log = slog.New(slog.NewJSONHandler(file, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelInfo,
	}))
	slog.SetDefault(Log)
}

func TemplateDirectory() string {
	return logDirectory
}

func OpenCurrentLogForRead() (*os.File, error) {
	name := currentLogName()
	if !isManagedLogName(name) {
		return nil, errors.New("invalid log file name")
	}
	return os.OpenInRoot(logDirectory, name)
}

func CleanupOldLogs() {
	entries, err := os.ReadDir(logDirectory)
	if err != nil {
		log.Println("logger: failed to read log directory:", err)
		return
	}
	root, err := os.OpenRoot(logDirectory)
	if err != nil {
		log.Println("logger: failed to open log directory:", err)
		return
	}
	defer func() {
		if err := root.Close(); err != nil && Log != nil {
			Log.Warn("log_cleanup", "message", "failed to close log directory", "error", err)
		}
	}()

	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format("20060102") + ".txt"
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isManagedLogName(name) {
			continue
		}
		if name >= cutoff {
			continue
		}
		if err := root.Remove(name); err != nil && Log != nil {
			Log.Warn("log_cleanup", "message", "failed to remove old log", "error", err)
		}
	}
}

func currentLogPath() string {
	return filepath.Join(logDirectory, currentLogName())
}

func currentLogName() string {
	return time.Now().Format("20060102") + ".txt"
}

func isManagedLogName(name string) bool {
	return logNameRule.MatchString(name)
}
