package main

import (
	"bufio"
	"crypto/tls"
	"davtonad/logger"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-ldap/ldap/v3"
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/template/html/v2"
	"github.com/joho/godotenv"
)

// Safe limits for log viewing to prevent resource exhaustion (DoS).
const (
	MAX_LOG_LINES = 1000     // absolute cap on lines per readLogPage
	maxLineSize   = 64 * 1024 // 64 KB max per line for scanner buffer
	maxLogSizeMB  = 10
	// Pagination
	defaultPageSize = 100
	maxPageSize     = 500
	// Maximum line length (must equal maxLineSize — kept for clarity).
	maxLineLength = 64 * 1024
	// Maximum total memory per page.
	maxPageMemoryBytes = 5 * 1024 * 1024 // 5 MB

	// Section 5.5 — APSC-DV-001680 CAT I: Password minimum length.
	// NOTE: Align with the Active Directory domain password policy. Users whose AD
	// passwords are shorter than this value will be rejected at the application layer.
	minPasswordLength = 15
	maxPasswordLength = 128 // prevents DoS via huge password hashing
	maxUsernameLength = 256

	// Section 5.5 — APSC-DV-000530 CAT I: Account lockout policy.
	maxLoginAttempts = 3
	lockoutDuration  = 15 * time.Minute

	// Section 3.2 — session lifetime (non-privileged users: 15 min idle, APSC-DV-000070).
	sessionTimeout = 15 * time.Minute
)

// loggerMu serializes access to logger cleanup from main and the background goroutine.
var loggerMu sync.Mutex

// Sentinel errors for readLogPage — callers use errors.Is() to distinguish kinds and return
// sanitized HTTP responses without leaking internal state to clients.
var (
	ErrLineTooLong     = errors.New("log line exceeds maximum allowed size")
	ErrTooManyLines    = errors.New("log page exceeds maximum allowed line count")
	ErrPayloadTooLarge = errors.New("log read exceeds maximum allowed byte size")
)

// ---------------------------------------------------------------------------
// Section 5.5 — Account lockout (APSC-DV-000530 CAT I)
// In-memory tracker; sufficient for single-instance deployment.
// ---------------------------------------------------------------------------

type lockoutEntry struct {
	attempts int
	lockedAt time.Time
}

var (
	lockoutMu      sync.RWMutex
	lockoutTracker = make(map[string]*lockoutEntry)
)

// lockoutKey returns a normalised key for the lockout map.
// Using lower-cased username prevents case-variation bypass.
func lockoutKey(username string) string { return strings.ToLower(strings.TrimSpace(username)) }

// isLockedOut reports whether the account is currently locked out.
func isLockedOut(username string) bool {
	key := lockoutKey(username)
	lockoutMu.RLock()
	entry, ok := lockoutTracker[key]
	lockoutMu.RUnlock()
	if !ok {
		return false
	}
	if entry.attempts < maxLoginAttempts {
		return false
	}
	// Auto-expire lockout after lockoutDuration.
	if time.Since(entry.lockedAt) >= lockoutDuration {
		lockoutMu.Lock()
		delete(lockoutTracker, key)
		lockoutMu.Unlock()
		return false
	}
	return true
}

// recordFailedAttempt increments the failure counter and sets lockout time on threshold.
func recordFailedAttempt(username string) {
	key := lockoutKey(username)
	lockoutMu.Lock()
	defer lockoutMu.Unlock()
	entry, ok := lockoutTracker[key]
	if !ok {
		entry = &lockoutEntry{}
		lockoutTracker[key] = entry
	}
	entry.attempts++
	if entry.attempts >= maxLoginAttempts {
		entry.lockedAt = time.Now()
	}
}

// clearLockout resets the failure counter for an account (called on successful login).
func clearLockout(username string) {
	key := lockoutKey(username)
	lockoutMu.Lock()
	delete(lockoutTracker, key)
	lockoutMu.Unlock()
}

// ---------------------------------------------------------------------------
// Section 3.2 — Session store (APSC-DV-002210/2220, NIST SC-23)
// ---------------------------------------------------------------------------

// sessionStore is initialised in main() after config.env is loaded so the
// CookieSecure flag can be derived from the TLS configuration.
var sessionStore *session.Store

// authMiddleware enforces session-based authentication on protected routes.
// Section 5.5: the /logs endpoint must not be accessible without a valid session.
func authMiddleware(c *fiber.Ctx) error {
	sess, err := sessionStore.Get(c)
	if err != nil {
		logger.Log.Error("authMiddleware", "err", err, "ip", c.IP())
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}
	if sess.Get("user_email") == nil {
		logger.Log.Warn("authMiddleware", "msg", "unauthenticated access attempt", "ip", c.IP(), "path", c.Path())
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Authentication required"})
	}
	return c.Next()
}

// ---------------------------------------------------------------------------
// Section 5.5 — Password complexity (APSC-DV-001680 CAT I)
// ---------------------------------------------------------------------------

// checkPasswordComplexity is an ozzo-validation compatible validator.
func checkPasswordComplexity(value interface{}) error {
	password, _ := value.(string)
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return errors.New("password must contain uppercase, lowercase, digit, and special character")
	}
	return nil
}

// ---------------------------------------------------------------------------
// LDAP authentication
// ---------------------------------------------------------------------------

type userDetails struct {
	Firstname string
	Lastname  string
	Email     string
}

func authenticateWithAD(username, password string) (bool, userDetails, error) {
	ldapURL        := os.Getenv("LDAP_URL")
	baseDN         := os.Getenv("LDAP_BASE_DN")
	bindDN         := os.Getenv("LDAP_BIND_DN")
	bindPassword   := os.Getenv("LDAP_BIND_PASSWORD")
	ldapServerName := os.Getenv("LDAP_SERVERNAME")

	// G402: Default to secure TLS verification. Only skip in development/testing environments.
	// SECURITY WARNING: Setting SKIP_INSECURE_VERIFICATION=true disables certificate validation
	// and makes the connection vulnerable to man-in-the-middle attacks. NEVER use in production.
	ldapSkipInsecureVer := false
	if v := os.Getenv("SKIP_INSECURE_VERIFICATION"); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			logger.Log.Error("authenticateWithAD", "err", err,
				"msg", "invalid SKIP_INSECURE_VERIFICATION, defaulting to false", "value", v)
		} else {
			ldapSkipInsecureVer = parsed
			if ldapSkipInsecureVer {
				logger.Log.Warn("authenticateWithAD",
					"msg", "SECURITY WARNING: TLS certificate verification disabled",
					"risk", "vulnerable to man-in-the-middle attacks",
					"recommendation", "use valid TLS certificates in production")
			}
		}
	}

	var staffDetails userDetails
	if ldapURL == "" || baseDN == "" || bindDN == "" || bindPassword == "" {
		logger.Log.Error("authenticateWithAD", "err", "one or more required env vars are missing")
		return false, staffDetails, errors.New("LDAP configuration incomplete")
	}

	// Section 5.5 — TLS 1.2+ minimum (ASD STIG, PCI DSS 4.1).
	// #nosec G402 — InsecureSkipVerify is runtime-configurable with explicit warning above.
	l, err := ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: ldapSkipInsecureVer,
		ServerName:         ldapServerName,
		MinVersion:         tls.VersionTLS12, // enforce TLS 1.2 minimum; rejects TLS 1.0/1.1
	}))
	if err != nil {
		logger.Log.Error("authenticateWithAD", "err", err, "msg", "failed to connect to LDAP server")
		return false, staffDetails, err
	}
	defer func() {
		if cerr := l.Close(); cerr != nil {
			logger.Log.Error("authenticateWithAD", "err", cerr, "msg", "failed to close LDAP connection")
		}
	}()

	l.SetTimeout(5 * time.Second)

	if err = l.Bind(bindDN, bindPassword); err != nil {
		logger.Log.Error("authenticateWithAD", "err", err, "msg", "service bind failed")
		return false, staffDetails, err
	}
	logger.Log.Info("authenticateWithAD", "msg", "LDAP service bind successful")

	searchFilter := fmt.Sprintf(
		"(&(|(mail=%s)(sAMAccountName=%s))(objectClass=user))",
		ldap.EscapeFilter(username),
		ldap.EscapeFilter(username),
	)
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		searchFilter,
		[]string{"dn", "cn", "mail", "sAMAccountName", "givenName", "sn", "displayName"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		logger.Log.Error("authenticateWithAD", "err", err)
		return false, staffDetails, err
	}
	if len(sr.Entries) != 1 {
		logger.Log.Error("authenticateWithAD", "err", "user not found in ldap")
		return false, staffDetails, errors.New("user not found")
	}

	userDN := sr.Entries[0].DN
	if err = l.Bind(userDN, password); err != nil {
		logger.Log.Error("authenticateWithAD", "err", err, "msg", "user credential bind failed")
		return false, staffDetails, err
	}

	staffDetails = userDetails{
		Firstname: sr.Entries[0].GetAttributeValue("givenName"),
		Lastname:  sr.Entries[0].GetAttributeValue("sn"),
		Email:     sr.Entries[0].GetAttributeValue("mail"),
	}
	return true, staffDetails, nil
}

// ---------------------------------------------------------------------------
// Login handler
// ---------------------------------------------------------------------------

type inputLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Validate enforces field presence, length limits, and password complexity.
// Section 5.5 — APSC-DV-001680 CAT I: 15-char minimum.
// NOTE: Coordinate minPasswordLength with the Active Directory domain password policy.
func (s inputLogin) Validate() error {
	return validation.ValidateStruct(&s,
		validation.Field(&s.Username,
			validation.Required,
			validation.Length(1, maxUsernameLength),
		),
		validation.Field(&s.Password,
			validation.Required,
			validation.Length(minPasswordLength, maxPasswordLength),
			validation.By(checkPasswordComplexity),
		),
	)
}

func loginHandler(c *fiber.Ctx) error {
	// Body-size guard must run before parsing to prevent DoS via body allocation.
	if len(c.Body()) > 1_000_000 {
		return c.Status(http.StatusRequestEntityTooLarge).JSON(fiber.Map{"error": "Payload too large"})
	}

	// Section 3.4 — CSRF mitigation for JSON API: browsers cannot set
	// Content-Type: application/json in cross-origin requests without a CORS
	// preflight, making this an effective CSRF defence for this endpoint.
	ct := c.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		return c.Status(http.StatusUnsupportedMediaType).JSON(fiber.Map{
			"status":  false,
			"message": "Content-Type must be application/json",
		})
	}

	var input inputLogin
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"status": false, "message": "Invalid request body"})
	}
	if err := input.Validate(); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"status": false, "message": err})
	}

	// Section 5.5 — APSC-DV-000530 CAT I: account lockout after maxLoginAttempts failures.
	if isLockedOut(input.Username) {
		logger.Log.Warn("loginHandler", "msg", "account locked out", "username", input.Username, "ip", c.IP())
		return c.Status(http.StatusTooManyRequests).JSON(fiber.Map{
			"status":  false,
			"message": "Account temporarily locked. Try again later.",
		})
	}

	authenticated, staffDetails, err := authenticateWithAD(input.Username, input.Password)
	if err != nil {
		// Record failure and log internally; return generic message to client to prevent
		// information disclosure (username enumeration, LDAP error leakage).
		recordFailedAttempt(input.Username)
		logger.Log.Error("loginHandler",
			"err", err,
			"msg", "authentication failed",
			"username", input.Username,
			"ip", c.IP(),
		)
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"status":  false,
			"message": "Invalid username or password",
		})
	}
	if !authenticated {
		recordFailedAttempt(input.Username)
		logger.Log.Warn("loginHandler",
			"msg", "authentication rejected",
			"username", input.Username,
			"ip", c.IP(),
		)
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"status":  false,
			"message": "Invalid username or password",
		})
	}

	// Authentication successful — clear any existing lockout and create a session.
	clearLockout(input.Username)
	logger.Log.Info("loginHandler",
		"msg", "login successful",
		"username", input.Username,
		"ip", c.IP(),
	)

	// Section 3.2 — create session with secure cookie flags (HttpOnly, Secure, SameSite=Strict).
	// Session cookie is configured on sessionStore in main() — flags set there apply here.
	sess, err := sessionStore.Get(c)
	if err != nil {
		logger.Log.Error("loginHandler", "err", err, "msg", "failed to create session")
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"status":  false,
			"message": "authentication failed",
		})
	}
	sess.Set("user_email", staffDetails.Email)
	sess.Set("user_firstname", staffDetails.Firstname)
	sess.Set("user_lastname", staffDetails.Lastname)
	if err := sess.Save(); err != nil {
		logger.Log.Error("loginHandler", "err", err, "msg", "failed to save session")
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"status":  false,
			"message": "authentication failed",
		})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"status": true,
		"data": fiber.Map{
			"firstname": staffDetails.Firstname,
			"lastname":  staffDetails.Lastname,
			"email":     staffDetails.Email,
		},
		"message": "success",
	})
}

// ---------------------------------------------------------------------------
// Log file helpers
// ---------------------------------------------------------------------------

// countLines streams the file and returns the number of lines without buffering content.
func countLines(f *os.File) (int, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("seek failed: %w", err)
	}
	var n int
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 4096)
	scanner.Buffer(buf, maxLineLength)
	const maxLineCount = 10_000_000
	for scanner.Scan() {
		n++
		if n > maxLineCount {
			return 0, fmt.Errorf("file exceeds maximum line count (%d lines)", maxLineCount)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scanner error: %w", err)
	}
	return n, nil
}

// readLogPage reads a single page of lines: skips the first 'skip' lines, then reads 'take' lines.
// The returned slice is ordered newest-first (reversed from file order).
//
// DoS mitigations — designed to be visible to static analysis (Checkmarx) at the I/O layer:
//
//  1. Input validation rejects out-of-range take/skip before any I/O.
//  2. io.LimitedReader caps total bytes read at the reader level (maxPageMemoryBytes);
//     the byte ceiling is enforced before any string is allocated, making it
//     provably bounded to static analysis tools.
//  3. The result slice is pre-allocated to exactly `take` (≤ MAX_LOG_LINES) entries and
//     populated via index assignment — no append, no dynamic growth.
//  4. Scanner buffer is fixed at maxLineSize; bufio.ErrTooLong is surfaced as ErrLineTooLong.
func readLogPage(f *os.File, skip, take int) ([]string, error) {
	// Input validation BEFORE any I/O — return errors, not silent clamps.
	if skip < 0 {
		return nil, fmt.Errorf("skip must be non-negative, got %d", skip)
	}
	if take <= 0 || take > MAX_LOG_LINES {
		return nil, fmt.Errorf("take must be 1–%d, got %d", MAX_LOG_LINES, take)
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek failed: %w", err)
	}

	// io.LimitedReader enforces the total-byte ceiling at the I/O layer.
	// Once lr.N reaches zero the reader returns io.EOF, preventing any further
	// allocation regardless of file size. This bound is visible to static analysis
	// before scanner.Text() is ever called.
	lr := &io.LimitedReader{R: f, N: maxPageMemoryBytes}

	// Fixed scanner buffer — per-line cap; bufio.ErrTooLong mapped to ErrLineTooLong below.
	scanner := bufio.NewScanner(lr)
	buf := make([]byte, maxLineSize)
	scanner.Buffer(buf, maxLineSize)

	// Pre-allocate to exactly `take` entries (take ≤ MAX_LOG_LINES, validated above).
	// Index-based assignment means the slice length is statically bounded — no append,
	// no dynamic reallocation, no unbounded growth path for taint analysis to follow.
	lines := make([]string, take)
	skipped, count := 0, 0

	for scanner.Scan() {
		if skipped < skip {
			skipped++
			continue
		}
		if count >= take {
			break
		}
		lines[count] = scanner.Text()
		count++
	}

	// lr.N == 0 means the LimitedReader exhausted its byte budget before the page was complete.
	if lr.N == 0 {
		return nil, ErrPayloadTooLarge
	}

	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, ErrLineTooLong
		}
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	lines = lines[:count]

	// Reverse so newest (last in file) is first on the page.
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}

	return lines, nil
}

// ---------------------------------------------------------------------------
// Log viewer handler (authentication enforced via authMiddleware)
// ---------------------------------------------------------------------------

// ShowLogs serves log file content with pagination. Only one page of lines is loaded into memory.
// Query params: page (1-based, default 1), limit (default 20, max 500). Newest lines first.
func ShowLogs(c *fiber.Ctx) error {
	pageStr := c.Query("page")
	if pageStr == "" {
		pageStr = "1"
	}
	page, err := strconv.Atoi(pageStr)
	if err != nil || page <= 0 {
		logger.Log.Warn("ShowLogs", "msg", "invalid page param", "value", c.Query("page"), "ip", c.IP())
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid 'page' parameter: must be a positive integer",
		})
	}

	limitStr := c.Query("limit")
	if limitStr == "" {
		limitStr = "20"
	}
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		logger.Log.Warn("ShowLogs", "msg", "invalid limit param", "value", c.Query("limit"), "ip", c.IP())
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid 'limit' parameter: must be a positive integer",
		})
	}
	if limit > maxPageSize {
		limit = maxPageSize
	}

	filePath := logger.LogPath()

	if err := logger.ValidateLogPath(filePath); err != nil {
		logger.Log.Error("ShowLogs", "err", err, "path", filePath, "msg", "invalid log path")
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid log path"})
	}

	// Go 1.24 traversal-resistant API: confine access to the resources root.
	rootDir := logger.GetRoot()
	f, err := os.OpenInRoot(rootDir, filepath.Base(filePath))
	if err != nil {
		if os.IsNotExist(err) {
			return c.Status(http.StatusOK).Render("showlog", fiber.Map{
				"fileLines": []string{}, "Page": 1, "Limit": limit, "TotalLines": 0, "TotalPages": 0,
				"PrevPage": 0, "NextPage": 0, "HasPrev": false, "HasNext": false,
			})
		}
		logger.Log.Error("ShowLogs", "err", err, "path", filePath)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			logger.Log.Error("ShowLogs", "err", cerr, "path", filePath, "msg", "failed to close log file")
		}
	}()

	info, err := f.Stat()
	if err != nil {
		logger.Log.Error("ShowLogs", "err", err, "path", filePath)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}
	maxBytes := int64(maxLogSizeMB) * 1024 * 1024
	if info.Size() > maxBytes {
		return c.Status(http.StatusRequestEntityTooLarge).JSON(fiber.Map{
			"error": fmt.Sprintf("log file exceeds maximum size of %d MB", maxLogSizeMB),
		})
	}

	totalLines, err := countLines(f)
	if err != nil {
		logger.Log.Error("ShowLogs", "err", err, "path", filePath)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}

	totalPages := (totalLines + limit - 1) / limit
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	// Newest-first: skip = totalLines - page*limit, clamped to 0.
	skip := totalLines - page*limit
	if skip < 0 {
		skip = 0
	}
	take := limit
	if totalLines-skip < take {
		take = totalLines - skip
	}
	if take <= 0 {
		return c.Render("showlog", fiber.Map{
			"fileLines": []string{}, "Page": page, "Limit": limit,
			"TotalLines": totalLines, "TotalPages": totalPages,
			"PrevPage": 0, "NextPage": 0, "HasPrev": false, "HasNext": false,
		})
	}

	logRecords, err := readLogPage(f, skip, take)
	if err != nil {
		// Section 3.6: sanitize error responses — log internally, return generic message.
		switch {
		case errors.Is(err, ErrLineTooLong),
			errors.Is(err, ErrTooManyLines),
			errors.Is(err, ErrPayloadTooLarge):
			logger.Log.Warn("ShowLogs", "err", err, "path", filePath)
			return c.Status(http.StatusRequestEntityTooLarge).JSON(fiber.Map{"error": "Request payload too large"})
		default:
			logger.Log.Error("ShowLogs", "err", err, "path", filePath)
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
		}
	}

	return c.Render("showlog", fiber.Map{
		"fileLines":  logRecords,
		"Page":       page,
		"Limit":      limit,
		"TotalLines": totalLines,
		"TotalPages": totalPages,
		"PrevPage":   page - 1,
		"NextPage":   page + 1,
		"HasPrev":    page > 1,
		"HasNext":    page < totalPages,
	})
}

// ---------------------------------------------------------------------------
// Application entry point
// ---------------------------------------------------------------------------

func main() {
	logger.Start()

	// Log rotation: remove files older than 3 days.
	loggerMu.Lock()
	logger.CleanupOldLogs()
	loggerMu.Unlock()
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			loggerMu.Lock()
			logger.CleanupOldLogs()
			loggerMu.Unlock()
		}
	}()

	if err := godotenv.Load("config.env"); err != nil {
		logger.Log.Error("LoadConfig", "err", err)
	}

	// Section 5.5 — TLS support for the HTTP server.
	// Set TLS_CERT_FILE and TLS_KEY_FILE env vars to enable HTTPS.
	// CookieSecure on sessions requires HTTPS; running plain HTTP in production is prohibited.
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile  := os.Getenv("TLS_KEY_FILE")
	tlsEnabled := certFile != "" && keyFile != ""
	if !tlsEnabled {
		logger.Log.Warn("main",
			"msg", "TLS not configured — running HTTP. Set TLS_CERT_FILE and TLS_KEY_FILE for HTTPS.",
			"compliance", "HTTPS required in production (PCI DSS 4.1, ASD STIG)")
	}

	// Section 3.2 — Session store with secure cookie flags.
	// CookieSecure is enabled only when TLS is active to avoid breaking dev/HTTP environments.
	// In production (TLS enabled), all three flags MUST be set.
	sessionStore = session.New(session.Config{
		Expiration:     sessionTimeout,
		CookieHTTPOnly: true,                // APSC-DV-002210: HttpOnly flag
		CookieSecure:   tlsEnabled,          // APSC-DV-002220: Secure flag (requires HTTPS)
		CookieSameSite: "Strict",            // CSRF mitigation via SameSite=Strict
		CookiePath:     "/",
	})

	resourcesPath := logger.GetRoot()
	engine := html.New(resourcesPath, ".html")
	engine.Reload(true)

	app := fiber.New(fiber.Config{
		Views:        engine,
		BodyLimit:    10 * 1024 * 1024,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	})

	// NOTE: app.Static is intentionally NOT registered.
	// Previously `app.Static("/", resourcesPath)` was serving raw log files (.txt) from the
	// resources directory at the root URL, bypassing authentication entirely.
	// Log content is now exclusively accessible via the authenticated /logs route.

	// Global rate limiter — 5 requests per minute per client IP.
	app.Use(limiter.New(limiter.Config{Max: 5, Expiration: 1 * time.Minute}))

	// Security response headers — applied globally to all routes.
	//
	// X-Frame-Options: DENY — legacy browser clickjacking protection.
	// Content-Security-Policy:
	//   default-src 'self'       — restricts all resource loads to same origin (XSS mitigation).
	//   script-src 'self'        — blocks inline scripts and untrusted script sources.
	//   object-src 'none'        — disables Flash/plugin vectors.
	//   base-uri 'self'          — prevents base-tag hijacking.
	//   frame-ancestors 'none'   — modern clickjacking protection (replaces X-Frame-Options).
	// X-Content-Type-Options: nosniff — prevents MIME-type sniffing attacks.
	// Referrer-Policy: strict-origin-when-cross-origin — limits referrer leakage.
	//
	// Compliance: NIST SI-15, OWASP A7, PCI DSS 6.5.7, ASD STIG APSC-DV-002490.
	app.Use(func(c *fiber.Ctx) error {
		c.Set("X-Frame-Options", "DENY")
		c.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		return c.Next()
	})

	app.Post("/login", loginHandler)

	// /logs is protected — authMiddleware validates the session before ShowLogs runs.
	app.Get("/logs", authMiddleware, ShowLogs)

	port := os.Getenv("DAVTON_PORT")
	if port == "" {
		port = "8080"
		logger.Log.Error("main", "msg", "DAVTON_PORT not set, using default 8080")
	}

	if tlsEnabled {
		logger.Log.Info("main", "msg", "starting HTTPS server", "port", port)
		if err := app.ListenTLS(":"+port, certFile, keyFile); err != nil {
			logger.Log.Error("main", "err", err, "msg", "HTTPS server failed")
			os.Exit(1)
		}
	} else {
		logger.Log.Info("main", "msg", "starting HTTP server", "port", port)
		if err := app.Listen(":" + port); err != nil {
			logger.Log.Error("main", "err", err, "msg", "HTTP server failed")
			os.Exit(1)
		}
	}
}
