package types

import "time"

type ScanHistory struct {
	ID             string                 `json:"id"`
	Target         string                 `json:"target"`
	Domain         string                 `json:"domain"`
	URL            string                 `json:"url"`
	Method         string                 `json:"method"`
	StartTime      time.Time              `json:"start_time"`
	EndTime        time.Time              `json:"end_time"`
	Duration       float64                `json:"duration"`
	Status         string                 `json:"status"`
	ScanLevel       int                    `json:"scan_level"`
	ScanMode       string                 `json:"scan_mode"`
	TechStack      []string               `json:"tech_stack"`
	WebServer      string                 `json:"web_server"`
	VulnCount      int                    `json:"vuln_count"`
	CriticalVulns  int                    `json:"critical_vulns"`
	HighVulns      int                    `json:"high_vulns"`
	MediumVulns    int                    `json:"medium_vulns"`
	LowVulns       int                    `json:"low_vulns"`
	Vulnerabilities []Vulnerability        `json:"vulnerabilities"`
	TotalRequests  int                    `json:"total_requests"`
	CrawledPages   int                    `json:"crawled_pages"`
	DirFound       int                    `json:"dir_found"`
	ParamsFound    int                    `json:"params_found"`
	Config         map[string]interface{} `json:"config"`
	ReportPath     string                 `json:"report_path"`
	ReportFormat   string                 `json:"report_format"`
	Date           string                 `json:"date"`
	YearMonth      string                 `json:"year_month"`
	Tags           []string               `json:"tags"`
	Notes          string                 `json:"notes"`
}

type HistoryGroup struct {
	Date    string        `json:"date"`
	Count   int           `json:"count"`
	Scans   []ScanHistory `json:"scans"`
}

type HistoryFilter struct {
	Query       string `json:"query"`
	Date        string `json:"date"`
	Status      string `json:"status"`
	Severity    string `json:"severity"`
	Domain      string `json:"domain"`
	DateFrom    string `json:"date_from"`
	DateTo      string `json:"date_to"`
	SortBy      string `json:"sort_by"`
	SortOrder   string `json:"sort_order"`
	Page        int    `json:"page"`
	PageSize    int    `json:"page_size"`
}

type HistoryStats struct {
	TotalScans     int            `json:"total_scans"`
	CompletedScans int            `json:"completed_scans"`
	FailedScans    int            `json:"failed_scans"`
	TotalVulns     int            `json:"total_vulns"`
	CriticalVulns  int            `json:"critical_vulns"`
	HighVulns      int            `json:"high_vulns"`
	MediumVulns    int            `json:"medium_vulns"`
	LowVulns       int            `json:"low_vulns"`
	DomainsScanned int            `json:"domains_scanned"`
	ByDate         map[string]int `json:"by_date"`
	BySeverity     map[string]int `json:"by_severity"`
}

type HistoryExport struct {
	Format   string `json:"format"`
	ScanIDs  []string `json:"scan_ids"`
	IncludeVulns bool `json:"include_vulns"`
	IncludeConfig bool `json:"include_config"`
}

type DomainStats struct {
	Domain          string        `json:"domain"`
	TotalScans      int           `json:"total_scans"`
	CompletedScans  int           `json:"completed_scans"`
	FailedScans     int           `json:"failed_scans"`
	TotalVulns      int           `json:"total_vulns"`
	CriticalVulns   int           `json:"critical_vulns"`
	HighVulns       int           `json:"high_vulns"`
	MediumVulns     int           `json:"medium_vulns"`
	LowVulns        int           `json:"low_vulns"`
	FirstScan       time.Time     `json:"first_scan"`
	LastScan        time.Time     `json:"last_scan"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}
