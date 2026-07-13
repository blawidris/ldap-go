package main

import (
	"bufio"
	"crypto/tls"
	"davtonad/logger"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-ldap/ldap/v3"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/template/html/v2"
)

const (
	defaultPort      = "9876"
	dotEnvFileName   = ".env"
	maxEnvFileBytes  = 64 * 1024
	maxEnvLineBytes  = 4096
	maxRequestBytes  = 16 * 1024
	maxUsernameBytes = 256
	minPasswordBytes = 15
	maxPasswordBytes = 128

	loginAttemptsBeforeLock = 3
	lockoutDuration         = 15 * time.Minute
	sessionTimeout          = 15 * time.Minute

	defaultLogPageSize = 20
	maxLogPageSize     = 200
	maxLogLineBytes    = 16 * 1024
	maxLogLines        = 1000
	maxLogReadBytes    = 2 * 1024 * 1024
	maxLogFileBytes    = 10 * 1024 * 1024
)

var (
	errMissingConfig = errors.New("required configuration is missing")
	errInvalidConfig = errors.New("configuration value is invalid")
	errLineTooLong   = errors.New("log line exceeds maximum size")
	errTooManyLines  = errors.New("log file has too many lines")
	errReadTooLarge  = errors.New("log read exceeds maximum size")
)

type serverConfig struct {
	Port             string
	TLSCertificate   string
	TLSPrivateKey    string
	LDAPURL          string
	LDAPBaseDN       string
	LDAPBindDN       string
	LDAPBindPassword string
	LDAPServerName   string
}

type userDetails struct {
	FirstName string
	LastName  string
	Email     string
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type lockoutEntry struct {
	attempts int
	locked   time.Time
}

type authState struct {
	mu       sync.Mutex
	lockouts map[string]lockoutEntry
	sessions *session.Store
}

func main() {
	logger.Start()
	logger.CleanupOldLogs()
	go runDailyLogCleanup()

	if err := loadDotEnv(); err != nil {
		logger.Log.Error("startup", "error", err)
		os.Exit(1)
	}

	cfg, err := loadConfig()
	if err != nil {
		logger.Log.Error("startup", "error", err)
		os.Exit(1)
	}

	auth := &authState{
		lockouts: make(map[string]lockoutEntry),
		sessions: session.New(session.Config{
			Expiration:     sessionTimeout,
			CookieHTTPOnly: true,
			CookieSecure:   true,
			CookieSameSite: "Strict",
			CookiePath:     "/",
		}),
	}

	engine := html.New(logger.TemplateDirectory(), ".html")
	engine.Reload(false)

	app := fiber.New(fiber.Config{
		Views:        engine,
		BodyLimit:    maxRequestBytes,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	})

	app.Use(limiter.New(limiter.Config{
		Max:        10,
		Expiration: time.Minute,
	}))
	app.Use(securityHeaders)

	app.Post("/login", auth.loginHandler(cfg))
	app.Get("/logs", auth.requireLogin, showLogs)

	logger.Log.Info("startup", "message", "starting HTTPS server", "port", cfg.Port)
	if err := app.ListenTLS(":"+cfg.Port, cfg.TLSCertificate, cfg.TLSPrivateKey); err != nil {
		logger.Log.Error("startup", "error", err)
		os.Exit(1)
	}
}

func runDailyLogCleanup() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		logger.CleanupOldLogs()
	}
}

func loadConfig() (serverConfig, error) {
	cfg := serverConfig{
		Port:             envWithDefault("DAVTON_PORT", defaultPort),
		TLSCertificate:   strings.TrimSpace(os.Getenv("TLS_CERT_FILE")),
		TLSPrivateKey:    strings.TrimSpace(os.Getenv("TLS_KEY_FILE")),
		LDAPURL:          strings.TrimSpace(os.Getenv("LDAP_URL")),
		LDAPBaseDN:       strings.TrimSpace(os.Getenv("LDAP_BASE_DN")),
		LDAPBindDN:       strings.TrimSpace(os.Getenv("LDAP_BIND_DN")),
		LDAPBindPassword: os.Getenv("LDAP_BIND_PASSWORD"),
		LDAPServerName:   strings.TrimSpace(os.Getenv("LDAP_SERVER_NAME")),
	}

	if cfg.TLSCertificate == "" ||
		cfg.TLSPrivateKey == "" ||
		cfg.LDAPURL == "" ||
		cfg.LDAPBaseDN == "" ||
		cfg.LDAPBindDN == "" ||
		cfg.LDAPBindPassword == "" ||
		cfg.LDAPServerName == "" {
		return cfg, errMissingConfig
	}
	if !isSafeAbsolutePath(cfg.TLSCertificate) {
		return cfg, fmt.Errorf("%w: TLS_CERT_FILE", errInvalidConfig)
	}
	if !isSafeAbsolutePath(cfg.TLSPrivateKey) {
		return cfg, fmt.Errorf("%w: TLS_KEY_FILE", errInvalidConfig)
	}

	parsedLDAPURL, err := url.Parse(cfg.LDAPURL)
	if err != nil {
		return cfg, fmt.Errorf("%w: LDAP_URL", errInvalidConfig)
	}
	if parsedLDAPURL.Scheme != "ldaps" {
		return cfg, fmt.Errorf("%w: LDAP_URL must use ldaps", errInvalidConfig)
	}
	if !isSafePort(cfg.Port) {
		return cfg, fmt.Errorf("%w: DAVTON_PORT", errInvalidConfig)
	}
	return cfg, nil
}

func loadDotEnv() error {
	file, err := os.Open(dotEnvFileName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() > maxEnvFileBytes {
		return errors.New("environment file is too large")
	}

	reader := bufio.NewReaderSize(file, maxEnvLineBytes)
	for {
		line, err := reader.ReadString('\n')
		if len(line) > maxEnvLineBytes {
			return errors.New("environment file line is too long")
		}
		if errors.Is(err, io.EOF) {
			if parseErr := setEnvLine(line); parseErr != nil {
				return parseErr
			}
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			return errors.New("environment file line is too long")
		}
		if err != nil {
			return err
		}
		if parseErr := setEnvLine(line); parseErr != nil {
			return parseErr
		}
	}
	return nil
}

func setEnvLine(line string) error {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	key, value, found := strings.Cut(line, "=")
	if !found {
		return errors.New("environment file contains an invalid line")
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if !isEnvKey(key) {
		return errors.New("environment file contains an invalid key")
	}
	value = strings.Trim(value, `"'`)
	return os.Setenv(key, value)
}

func isEnvKey(key string) bool {
	if key == "" {
		return false
	}
	for index, char := range key {
		if char == '_' || unicode.IsUpper(char) || unicode.IsDigit(char) && index > 0 {
			continue
		}
		return false
	}
	return true
}

func envWithDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func isSafePort(port string) bool {
	if port == "" || len(port) > 5 {
		return false
	}
	number, err := strconv.Atoi(port)
	return err == nil && number >= 1 && number <= 65535
}

func isSafeAbsolutePath(path string) bool {
	cleanPath := filepath.Clean(path)
	return filepath.IsAbs(cleanPath) && cleanPath == path && !strings.Contains(cleanPath, "..")
}

func securityHeaders(c *fiber.Ctx) error {
	c.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'sha256-/zzODLln/Gwa3ZDOkMqVIywSh5Q276XEttWs21ogIFg='; style-src 'self' 'sha256-fWouOLTlgrCXIZBIvHZywCl6NXdM+RDwPzphaQcsqvU='; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
	c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("X-Frame-Options", "DENY")
	return c.Next()
}

func (a *authState) requireLogin(c *fiber.Ctx) error {
	sess, err := a.sessions.Get(c)
	if err != nil {
		logger.Log.Error("session", "error", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
	}
	if sess.Get("user_email") == nil {
		logger.Log.Warn("session", "message", "unauthenticated request", "ip", c.IP(), "path", c.Path())
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "authentication required"})
	}
	return c.Next()
}

func (a *authState) loginHandler(cfg serverConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if len(c.Body()) > maxRequestBytes {
			return c.Status(http.StatusRequestEntityTooLarge).JSON(fiber.Map{"error": "request too large"})
		}
		if !strings.HasPrefix(c.Get("Content-Type"), "application/json") {
			return c.Status(http.StatusUnsupportedMediaType).JSON(fiber.Map{"error": "content type must be application/json"})
		}

		var req loginRequest
		if err := json.Unmarshal(c.Body(), &req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
		}
		if err := validateLogin(req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		if a.isLocked(req.Username) {
			logger.Log.Warn("login", "message", "locked account attempted login", "username", safeLogValue(normalizedUsername(req.Username)), "ip", c.IP())
			return c.Status(http.StatusTooManyRequests).JSON(fiber.Map{"error": "account temporarily locked"})
		}

		user, err := authenticateWithLDAP(cfg, req.Username, req.Password)
		if err != nil {
			a.recordFailure(req.Username)
			logger.Log.Warn("login", "message", "authentication failed", "username", safeLogValue(normalizedUsername(req.Username)), "ip", c.IP())
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "invalid username or password"})
		}

		a.clearFailures(req.Username)
		sess, err := a.sessions.Get(c)
		if err != nil {
			logger.Log.Error("session", "error", err)
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
		}
		sess.Set("user_email", user.Email)
		sess.Set("user_first_name", user.FirstName)
		sess.Set("user_last_name", user.LastName)
		if err := sess.Save(); err != nil {
			logger.Log.Error("session", "error", err)
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
		}

		logger.Log.Info("login", "message", "authentication succeeded", "username", safeLogValue(normalizedUsername(req.Username)), "ip", c.IP())
		return c.Status(http.StatusOK).JSON(fiber.Map{
			"status": true,
			"data": fiber.Map{
				"firstname": user.FirstName,
				"lastname":  user.LastName,
				"email":     user.Email,
			},
		})
	}
}

func validateLogin(req loginRequest) error {
	username := strings.TrimSpace(req.Username)
	if username == "" {
		return errors.New("username is required")
	}
	if len(username) > maxUsernameBytes {
		return errors.New("username is too long")
	}
	if len(req.Password) < minPasswordBytes {
		return errors.New("password is too short")
	}
	if len(req.Password) > maxPasswordBytes {
		return errors.New("password is too long")
	}
	if !hasRequiredPasswordClasses(req.Password) {
		return errors.New("password does not meet complexity requirements")
	}
	return nil
}

func hasRequiredPasswordClasses(password string) bool {
	var upper, lower, digit, special bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			upper = true
		case unicode.IsLower(char):
			lower = true
		case unicode.IsDigit(char):
			digit = true
		case unicode.IsPunct(char), unicode.IsSymbol(char):
			special = true
		}
	}
	return upper && lower && digit && special
}

func authenticateWithLDAP(cfg serverConfig, username, password string) (userDetails, error) {
	var user userDetails

	conn, err := ldap.DialURL(cfg.LDAPURL, ldap.DialWithTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: cfg.LDAPServerName,
	}))
	if err != nil {
		return user, err
	}
	defer conn.Close()
	conn.SetTimeout(5 * time.Second)

	if err := conn.Bind(cfg.LDAPBindDN, cfg.LDAPBindPassword); err != nil {
		return user, err
	}

	filter := fmt.Sprintf(
		"(&(|(mail=%s)(sAMAccountName=%s))(objectClass=user))",
		ldap.EscapeFilter(strings.TrimSpace(username)),
		ldap.EscapeFilter(strings.TrimSpace(username)),
	)
	request := ldap.NewSearchRequest(
		cfg.LDAPBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		5,
		false,
		filter,
		[]string{"dn", "mail", "givenName", "sn"},
		nil,
	)

	result, err := conn.Search(request)
	if err != nil {
		return user, err
	}
	if len(result.Entries) != 1 {
		return user, errors.New("user not found")
	}

	entry := result.Entries[0]
	if err := conn.Bind(entry.DN, password); err != nil {
		return user, err
	}

	user = userDetails{
		FirstName: entry.GetAttributeValue("givenName"),
		LastName:  entry.GetAttributeValue("sn"),
		Email:     entry.GetAttributeValue("mail"),
	}
	return user, nil
}

func normalizedUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func safeLogValue(value string) string {
	value = strings.Map(func(char rune) rune {
		if char == '\n' || char == '\r' || char == '\t' || unicode.IsControl(char) {
			return -1
		}
		return char
	}, value)
	if len(value) > maxUsernameBytes {
		return value[:maxUsernameBytes]
	}
	return value
}

func (a *authState) isLocked(username string) bool {
	key := normalizedUsername(username)
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	entry, exists := a.lockouts[key]
	if !exists {
		return false
	}
	if entry.attempts < loginAttemptsBeforeLock {
		return false
	}
	if now.Sub(entry.locked) >= lockoutDuration {
		delete(a.lockouts, key)
		return false
	}
	return true
}

func (a *authState) recordFailure(username string) {
	key := normalizedUsername(username)
	a.mu.Lock()
	defer a.mu.Unlock()

	entry := a.lockouts[key]
	entry.attempts++
	if entry.attempts >= loginAttemptsBeforeLock {
		entry.locked = time.Now()
	}
	a.lockouts[key] = entry
}

func (a *authState) clearFailures(username string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.lockouts, normalizedUsername(username))
}

func showLogs(c *fiber.Ctx) error {
	page := queryInt(c, "page", 1, 1, 100000)
	limit := queryInt(c, "limit", defaultLogPageSize, 1, maxLogPageSize)

	file, err := logger.OpenCurrentLogForRead()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return renderLogs(c, []string{}, page, limit, 0)
		}
		logger.Log.Error("logs", "error", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		logger.Log.Error("logs", "error", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
	}
	if info.Size() > maxLogFileBytes {
		return c.Status(http.StatusRequestEntityTooLarge).JSON(fiber.Map{"error": "log file is too large"})
	}

	lines, err := readBoundedLines(file)
	if err != nil {
		logger.Log.Warn("logs", "error", err)
		return c.Status(http.StatusRequestEntityTooLarge).JSON(fiber.Map{"error": "log file cannot be displayed"})
	}

	total := len(lines)
	start := total - (page * limit)
	if start < 0 {
		start = 0
	}
	end := total - ((page - 1) * limit)
	if end < 0 {
		end = 0
	}
	if start > end {
		start = end
	}

	pageLines := make([]string, end-start)
	copy(pageLines, lines[start:end])
	reverseStrings(pageLines)

	return renderLogs(c, pageLines, page, limit, total)
}

func queryInt(c *fiber.Ctx, name string, fallback, minValue, maxValue int) int {
	raw := c.Query(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minValue {
		return fallback
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func readBoundedLines(reader io.Reader) ([]string, error) {
	limited := io.LimitedReader{R: reader, N: maxLogReadBytes}
	buffered := bufio.NewReaderSize(&limited, maxLogLineBytes)

	lines := make([]string, 0, maxLogLines)
	for {
		if len(lines) >= maxLogLines {
			return nil, errTooManyLines
		}
		line, err := buffered.ReadString('\n')
		if len(line) > maxLogLineBytes {
			return nil, errLineTooLong
		}
		if line != "" {
			lines = append(lines, strings.TrimRight(line, "\r\n"))
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, errLineTooLong
		}
		if err != nil {
			return nil, err
		}
		if limited.N == 0 {
			return nil, errReadTooLarge
		}
	}
	return lines, nil
}

func reverseStrings(values []string) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func renderLogs(c *fiber.Ctx, lines []string, page, limit, total int) error {
	totalPages := 1
	if total > 0 {
		totalPages = (total + limit - 1) / limit
	}
	if page > totalPages {
		page = totalPages
	}
	return c.Render("showlog", fiber.Map{
		"Lines":      lines,
		"Page":       page,
		"Limit":      limit,
		"TotalLines": total,
		"TotalPages": totalPages,
		"PrevPage":   page - 1,
		"NextPage":   page + 1,
		"HasPrev":    page > 1,
		"HasNext":    page < totalPages,
	})
}
