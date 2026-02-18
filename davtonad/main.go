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
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/template/html/v2"
	"github.com/joho/godotenv"
)

// Safe limits for log viewing to prevent resource exhaustion (DoS).
const (
	MAX_LOG_LINES = 1000   // absolute cap on lines per readLogPage; silences DoS via large skip/take
	maxLineSize   = 64 * 1024 // 64KB max per line for scanner buffer
	maxLogSizeMB  = 10
	// Pagination: only one page of lines is loaded into memory.
	defaultPageSize = 100
	maxPageSize     = 500
	// Maximum line length: lines longer than this are truncated to prevent memory exhaustion.
	maxLineLength = 64 * 1024 // 64KB per line
	// Maximum total memory for a single page: sum of all line lengths cannot exceed this.
	maxPageMemoryBytes = 5 * 1024 * 1024 // 5MB per page
	// maxLinesPerPage is the absolute cap on lines returned in one request; guards against unbounded slice growth.
	//maxLinesPerPage = 1000
	// maxScannerBufferSize is the explicit cap for bufio.Scanner token size (per-line); prevents huge single-line allocation.
	//maxScannerBufferSize = 64 * 1024 // 64KB
	// maxSkipLines is the maximum number of lines we will skip; prevents abuse via very large skip values.
	//	maxSkipLines = 10_000_000
)

// loggerMu serializes access to logger cleanup from main and the background goroutine (race-safe).
var loggerMu sync.Mutex

type userDetails struct {
	Firstname string
	Lastname  string
	Email     string
}

func authenticateWithAD(username, password string) (bool, userDetails, error) {
	// Retrieve LDAP credentials from environment variables
	ldapURL := os.Getenv("LDAP_URL")                // e.g., "ldap://localhost:389"
	baseDN := os.Getenv("LDAP_BASE_DN")             // e.g., "dc=example,dc=com"
	bindDN := os.Getenv("LDAP_BIND_DN")             // e.g., "cn=admin,dc=example,dc=com"
	bindPassword := os.Getenv("LDAP_BIND_PASSWORD") // e.g., "adminpassword"
	ldapServerName := os.Getenv("LDAP_SERVERNAME")  // e.g., "your-ldap-server.com"
	
	// G402: Default to secure TLS verification. Only skip in development/testing environments.
	// SECURITY WARNING: Setting SKIP_INSECURE_VERIFICATION=true disables certificate validation
	// and makes the connection vulnerable to man-in-the-middle attacks. Use ONLY in controlled
	// development/testing environments, NEVER in production.
	ldapSkipInsecureVer := false

	if v := os.Getenv("SKIP_INSECURE_VERIFICATION"); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			logger.Log.Error("authenticateWithAD", "err", err, "msg", "invalid SKIP_INSECURE_VERIFICATION, using false", "value", v)
			ldapSkipInsecureVer = false
		} else {
			ldapSkipInsecureVer = parsed
			if ldapSkipInsecureVer {
				// Log security warning when TLS verification is disabled
				logger.Log.Warn("authenticateWithAD", 
					"msg", "SECURITY WARNING: TLS certificate verification disabled",
					"risk", "vulnerable to man-in-the-middle attacks",
					"recommendation", "use valid TLS certificates in production")
			}
		}
	}

	var staffDetails userDetails

	// Check if any environment variable is missing
	if ldapURL == "" || baseDN == "" || bindDN == "" || bindPassword == "" {
		logger.Log.Error("authenticateWithAD", "err", "One or more required environment variables are missing")
		return false, staffDetails, errors.New("one or more required environment variables are missing")
	}

	// Connect to the LDAP server
	// G402: InsecureSkipVerify is configurable via SKIP_INSECURE_VERIFICATION env var.
	// Defaults to false (secure). See security warning above for risks when enabled.
	// #nosec G402 - Intentionally configurable for development environments with proper warnings
	l, err := ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: ldapSkipInsecureVer,
		ServerName:         ldapServerName,
	}))

	if err != nil {
		logger.Log.Error("authenticateWithAD", "err", err, "msg", "Failed to connect to LDAP server")
		return false, staffDetails, err
	}
	defer func() {
		if cerr := l.Close(); cerr != nil {
			logger.Log.Error("authenticateWithAD", "err", cerr, "msg", "Failed to close LDAP connection")
		}
	}()

	// Set timeouts
	l.SetTimeout(5 * time.Second)

	// Bind to the LDAP server using the admin credentials (Bind DN and Bind Password)
	err = l.Bind(bindDN, bindPassword)
	if err != nil {
		logger.Log.Error("authenticateWithAD", "err", err, "msg", "Failed to bind to LDAP server:")
		return false, staffDetails, err
	}

	logger.Log.Info("authenticateWithAD", "msg", "LDAP connection successful")

	// Create an LDAP search filter to find the user by username (sAMAccountName for AD)
	// searchFilter := fmt.Sprintf("(&(mail=%s)(objectClass=user))", ldap.EscapeFilter(username))
	searchFilter := fmt.Sprintf(
		"(&(|(mail=%s)(sAMAccountName=%s))(objectClass=user))",
		ldap.EscapeFilter(username),
		ldap.EscapeFilter(username),
	)

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		searchFilter,
		[]string{"dn", "cn", "mail", "sAMAccountName", "givenName", "sn", "displayName"},
		nil,
	)

	// Perform the LDAP search
	sr, err := l.Search(searchRequest)
	if err != nil {
		logger.Log.Error("authenticateWithAD", "err", err)
		return false, staffDetails, err
	}

	// Ensure exactly one user is found
	if len(sr.Entries) != 1 {
		logger.Log.Error("authenticateWithAD", "err", "user not found in ldap")
		return false, staffDetails, errors.New("user not found in ldap")
	}

	// Bind to the user's DN to authenticate the user
	userDN := sr.Entries[0].DN
	err = l.Bind(userDN, password)
	if err != nil {
		logger.Log.Error("authenticateWithAD", "err", err, "msg", "Failed to authenticate user:")
		return false, staffDetails, err
	}

	staffDetails = userDetails{
		Firstname: sr.Entries[0].GetAttributeValue("givenName"),
		Lastname:  sr.Entries[0].GetAttributeValue("sn"),
		Email:     sr.Entries[0].GetAttributeValue("mail"),
	}

	// Return true for successful authentication and the user details
	return true, staffDetails, nil
}

type inputLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s inputLogin) Validate() error {
	return validation.ValidateStruct(&s,
		validation.Field(&s.Username, validation.Required),
		validation.Field(&s.Password, validation.Required),
	)
}
func loginHandler(c *fiber.Ctx) error {
	// Get credentials from request (basic example: form data)

	var input inputLogin
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"status": false, "message": err})
	}
	if err := input.Validate(); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"status": false, "message": err})
	}
	if len(c.Body()) > 1_000_000 { // 1MB
		return c.Status(http.StatusRequestEntityTooLarge).JSON(fiber.Map{"error": "Payload too large"})
	}

	// Authenticate against Active Directory
	authenticated, staffDetails, err := authenticateWithAD(input.Username, input.Password)
	if err != nil {
		logger.Log.Error("loginHandler", "err", err)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"status": false, "message": err})
	}

	if !authenticated {
		logger.Log.Error("loginHandler", "err", "authentication fails!")
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"status": false, "message": "invalid username or password"})
	}

	// Authentication successful
	output := fiber.Map{
		"status": true,
		"data": fiber.Map{
			"firstname": staffDetails.Firstname,
			"lastname":  staffDetails.Lastname,
			"email":     staffDetails.Email,
		},
		"message": "success"}
	return c.Status(http.StatusOK).JSON(output)
}

// countLines streams the file and returns the number of lines. Does not retain lines in memory.
// Returns an error if the file cannot be read or exceeds maximum line count.
func countLines(f *os.File) (int, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("seek failed: %w", err)
	}
	var n int
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 4096)
	scanner.Buffer(buf, maxLineLength)
	const maxLineCount = 10_000_000 // 10M lines max
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
// The returned slice is ordered newest-first for display (reversed from file order).
// Enforces MAX_LOG_LINES and maxLineSize to prevent DoS from unbounded memory.
func readLogPage(f *os.File, skip, take int) ([]string, error) {
	// Validate and clamp inputs so a malicious caller cannot exhaust memory.
	if take <= 0 || take > MAX_LOG_LINES {
		take = MAX_LOG_LINES
	}
	if skip < 0 {
		skip = 0
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek failed: %w", err)
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, maxLineSize), maxLineSize)
	lines := make([]string, 0, take)
	skipped := 0
	totalMemory := 0
	for scanner.Scan() {
		if len(lines) >= MAX_LOG_LINES {
			break
		}
		if skipped < skip {
			skipped++
			continue
		}
		
		line := scanner.Text()
		lineLen := len(line)
		
		// Enforce maximum line length: truncate if necessary to prevent memory exhaustion.
		if lineLen > maxLineLength {
			line = line[:maxLineLength] + "... [truncated]"
			lineLen = len(line)
		}
		
		// Enforce total memory limit per page to prevent DoS.
		if totalMemory+lineLen > maxPageMemoryBytes {
			// Stop reading if adding this line would exceed memory limit.
			break
		}
		
		lines = append(lines, line)
		totalMemory += lineLen
		
		if len(lines) >= take {
			break
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}
	
	// Reverse so newest (last in file) is first on the page.
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	
	return lines, nil
}

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

	// Validate the computed log path defensively.
	if err := logger.ValidateLogPath(filePath); err != nil {
		logger.Log.Error("ShowLogs", "err", err, "path", filePath, "msg", "invalid log path")
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid log path"})
	}

	// Use Go 1.24 traversal-resistant API: confine access to the resources root.
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
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read logs"})
	}

	defer func() {
		if cerr := f.Close(); cerr != nil {
			logger.Log.Error("ShowLogs", "err", cerr, "path", filePath, "msg", "failed to close log file")
		}
	}()

	info, err := f.Stat()
	if err != nil {
		logger.Log.Error("ShowLogs", "err", err, "path", filePath)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read logs"})
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
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read logs"})
	}

	totalPages := (totalLines + limit - 1) / limit
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	// Newest-first: page 1 = lines [totalLimit, total), page 2 = [total-2*limit, total-limit), ...
	// So skip = totalLines - page*limit, take = limit. Clamp skip to 0.
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
			"fileLines": []string{}, "Page": page, "Limit": limit, "TotalLines": totalLines, "TotalPages": totalPages,
			"PrevPage": 0, "NextPage": 0, "HasPrev": false, "HasNext": false,
		})
	}

	logRecords, err := readLogPage(f, skip, take)
	if err != nil {
		logger.Log.Error("ShowLogs", "err", err, "path", filePath)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read logs"})
	}

	return c.Render("showlog", fiber.Map{
		"fileLines":   logRecords,
		"Page":        page,
		"Limit":       limit,
		"TotalLines":  totalLines,
		"TotalPages":  totalPages,
		"PrevPage":    page - 1,
		"NextPage":    page + 1,
		"HasPrev":     page > 1,
		"HasNext":     page < totalPages,
	})
}

func main() {
	logger.Start()

	// Remove log files older than 3 days (retention policy). Protected to avoid race with logger access.
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

	err := godotenv.Load("config.env")
	if err != nil {
		logger.Log.Error("LoadConfig", "err", err)
	}

	//get root directory
	resourcesPath := logger.GetRoot()

	// See examples below to load templates from embedded files
	engine := html.New(resourcesPath, ".html")
	engine.Reload(true) // Optional. Default: false

	fiberConfig := fiber.Config{
		Views:        engine,
		BodyLimit:    10 * 1024 * 1024,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	// Create a new Fiber app
	app := fiber.New(fiberConfig)
	app.Static("/", logger.GetRoot())

	app.Use(limiter.New(limiter.Config{Max: 5, Expiration: 1 * time.Minute}))

	// Clickjacking protection: prevent embedding in iframes (X-Frame-Options + CSP frame-ancestors).
	// X-Frame-Options: DENY provides legacy browser support.
	// Content-Security-Policy: frame-ancestors 'none' provides modern browser support.
	// Both headers ensure comprehensive protection against clickjacking attacks.
	app.Use(func(c *fiber.Ctx) error {
		c.Set("X-Frame-Options", "DENY")
		c.Set("Content-Security-Policy", "frame-ancestors 'none'")
		// Additional security headers for defense in depth.
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		return c.Next()
	})

	// Define a login route
	app.Post("/login", loginHandler)
	app.Get("/logs", ShowLogs)

	port := os.Getenv("DAVTON_PORT")
	if port == "" {
		port = "8080"
		logger.Log.Error("main", "msg", "DAVTON_PORT not set, using default 8080")
	}

	if err := app.Listen(":" + port); err != nil {
		logger.Log.Error("main", "err", err, "msg", "server listen failed")
		os.Exit(1)
	}
}
