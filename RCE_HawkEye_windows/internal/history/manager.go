package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
)

type Manager struct {
	dataDir     string
	historyFile string
	history     []types.ScanHistory
	mutex       sync.RWMutex
}

var (
	manager     *Manager
	managerOnce sync.Once
)

func GetManager() *Manager {
	managerOnce.Do(func() {
		dataDir := "./data/history"
		manager = &Manager{
			dataDir:     dataDir,
			historyFile: filepath.Join(dataDir, "scan_history.json"),
			history:     make([]types.ScanHistory, 0),
		}
		manager.load()
	})
	return manager
}

func (m *Manager) load() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if err := os.MkdirAll(m.dataDir, 0755); err != nil {
		return err
	}

	data, err := os.ReadFile(m.historyFile)
	if err != nil {
		if os.IsNotExist(err) {
			m.history = make([]types.ScanHistory, 0)
			return nil
		}
		return err
	}

	return json.Unmarshal(data, &m.history)
}

func (m *Manager) save() error {
	data, err := json.MarshalIndent(m.history, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.historyFile, data, 0644)
}

func (m *Manager) Add(scan types.ScanHistory) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	scan.Date = scan.StartTime.Format("2006-01-02")
	scan.YearMonth = scan.StartTime.Format("2006-01")
	
	if scan.Domain == "" && scan.Target != "" {
		parts := strings.Split(strings.TrimPrefix(scan.Target, "http://"), "/")
		parts = strings.Split(strings.TrimPrefix(parts[0], "https://"), ":")
		scan.Domain = parts[0]
	}

	m.history = append(m.history, scan)
	
	sort.Slice(m.history, func(i, j int) bool {
		return m.history[i].StartTime.After(m.history[j].StartTime)
	})

	return m.save()
}

func (m *Manager) Update(scan types.ScanHistory) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for i, h := range m.history {
		if h.ID == scan.ID {
			m.history[i] = scan
			return m.save()
		}
	}

	m.history = append(m.history, scan)
	sort.Slice(m.history, func(i, j int) bool {
		return m.history[i].StartTime.After(m.history[j].StartTime)
	})

	return m.save()
}

func (m *Manager) GetByID(id string) (*types.ScanHistory, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for i := range m.history {
		if m.history[i].ID == id {
			return &m.history[i], true
		}
	}
	return nil, false
}

func (m *Manager) GetAll() []types.ScanHistory {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	result := make([]types.ScanHistory, len(m.history))
	copy(result, m.history)
	return result
}

func (m *Manager) GetByDate(date string) []types.ScanHistory {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var result []types.ScanHistory
	for _, h := range m.history {
		if h.Date == date {
			result = append(result, h)
		}
	}
	return result
}

func (m *Manager) GetGroupedByDate() []types.HistoryGroup {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	groups := make(map[string]*types.HistoryGroup)
	
	for _, h := range m.history {
		if _, exists := groups[h.Date]; !exists {
			groups[h.Date] = &types.HistoryGroup{
				Date:  h.Date,
				Count: 0,
				Scans: make([]types.ScanHistory, 0),
			}
		}
		groups[h.Date].Scans = append(groups[h.Date].Scans, h)
		groups[h.Date].Count++
	}

	var result []types.HistoryGroup
	for _, g := range groups {
		result = append(result, *g)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Date > result[j].Date
	})

	return result
}

func (m *Manager) Search(filter types.HistoryFilter) []types.ScanHistory {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var result []types.ScanHistory

	for _, h := range m.history {
		if filter.Query != "" {
			query := strings.ToLower(filter.Query)
			if !strings.Contains(strings.ToLower(h.Target), query) &&
				!strings.Contains(strings.ToLower(h.Domain), query) &&
				!strings.Contains(strings.ToLower(h.Notes), query) {
				continue
			}
		}

		if filter.Date != "" && h.Date != filter.Date {
			continue
		}

		if filter.Status != "" && h.Status != filter.Status {
			continue
		}

		if filter.Severity != "" {
			switch filter.Severity {
			case "critical":
				if h.CriticalVulns == 0 {
					continue
				}
			case "high":
				if h.HighVulns == 0 {
					continue
				}
			case "medium":
				if h.MediumVulns == 0 {
					continue
				}
			case "low":
				if h.LowVulns == 0 {
					continue
				}
			}
		}

		if filter.Domain != "" && !strings.Contains(strings.ToLower(h.Domain), strings.ToLower(filter.Domain)) {
			continue
		}

		if filter.DateFrom != "" {
			if from, err := time.Parse("2006-01-02", filter.DateFrom); err == nil {
				if h.StartTime.Before(from) {
					continue
				}
			}
		}

		if filter.DateTo != "" {
			if to, err := time.Parse("2006-01-02", filter.DateTo); err == nil {
				if h.StartTime.After(to.Add(24 * time.Hour)) {
					continue
				}
			}
		}

		result = append(result, h)
	}

	switch filter.SortBy {
	case "date", "":
		sort.Slice(result, func(i, j int) bool {
			if filter.SortOrder == "asc" {
				return result[i].StartTime.Before(result[j].StartTime)
			}
			return result[i].StartTime.After(result[j].StartTime)
		})
	case "vulns":
		sort.Slice(result, func(i, j int) bool {
			if filter.SortOrder == "asc" {
				return result[i].VulnCount < result[j].VulnCount
			}
			return result[i].VulnCount > result[j].VulnCount
		})
	case "domain":
		sort.Slice(result, func(i, j int) bool {
			if filter.SortOrder == "asc" {
				return result[i].Domain < result[j].Domain
			}
			return result[i].Domain > result[j].Domain
		})
	}

	if filter.PageSize <= 0 {
		filter.PageSize = 50
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}

	start := (filter.Page - 1) * filter.PageSize
	end := start + filter.PageSize

	if start >= len(result) {
		return []types.ScanHistory{}
	}
	if end > len(result) {
		end = len(result)
	}

	return result[start:end]
}

func (m *Manager) Delete(id string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for i, h := range m.history {
		if h.ID == id {
			m.history = append(m.history[:i], m.history[i+1:]...)
			return m.save()
		}
	}
	return nil
}

func (m *Manager) Clear() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.history = make([]types.ScanHistory, 0)
	return m.save()
}

func (m *Manager) GetStats() types.HistoryStats {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	stats := types.HistoryStats{
		ByDate:     make(map[string]int),
		BySeverity: make(map[string]int),
	}

	domains := make(map[string]bool)

	for _, h := range m.history {
		stats.TotalScans++
		
		if h.Status == "completed" {
			stats.CompletedScans++
		} else if h.Status == "error" || h.Status == "failed" {
			stats.FailedScans++
		}

		stats.TotalVulns += h.VulnCount
		stats.CriticalVulns += h.CriticalVulns
		stats.HighVulns += h.HighVulns
		stats.MediumVulns += h.MediumVulns
		stats.LowVulns += h.LowVulns

		if h.Domain != "" {
			domains[h.Domain] = true
		}

		stats.ByDate[h.Date]++
	}

	stats.DomainsScanned = len(domains)
	stats.BySeverity["critical"] = stats.CriticalVulns
	stats.BySeverity["high"] = stats.HighVulns
	stats.BySeverity["medium"] = stats.MediumVulns
	stats.BySeverity["low"] = stats.LowVulns

	return stats
}

func (m *Manager) GetUniqueDomains() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	domains := make(map[string]bool)
	for _, h := range m.history {
		if h.Domain != "" {
			domains[h.Domain] = true
		}
	}

	var result []string
	for d := range domains {
		result = append(result, d)
	}
	sort.Strings(result)
	return result
}

func (m *Manager) ExportJSON(ids []string) ([]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var toExport []types.ScanHistory
	if len(ids) == 0 {
		toExport = m.history
	} else {
		idSet := make(map[string]bool)
		for _, id := range ids {
			idSet[id] = true
		}
		for _, h := range m.history {
			if idSet[h.ID] {
				toExport = append(toExport, h)
			}
		}
	}

	return json.MarshalIndent(toExport, "", "  ")
}

func (m *Manager) ExportCSV(ids []string) ([]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var toExport []types.ScanHistory
	if len(ids) == 0 {
		toExport = m.history
	} else {
		idSet := make(map[string]bool)
		for _, id := range ids {
			idSet[id] = true
		}
		for _, h := range m.history {
			if idSet[h.ID] {
				toExport = append(toExport, h)
			}
		}
	}

	var csv strings.Builder
	csv.WriteString("ID,Domain,Target,Date,StartTime,Status,VulnCount,Critical,High,Medium,Low,Duration\n")
	
	for _, h := range toExport {
		csv.WriteString(strings.Join([]string{
			h.ID,
			h.Domain,
			h.Target,
			h.Date,
			h.StartTime.Format("2006-01-02 15:04:05"),
			h.Status,
			strings.Trim(strings.Replace(strings.Replace(string(rune(h.VulnCount+'0')), "[", "", -1), "]", "", -1), " "),
			"", "", "", "", 
		}, ",") + "\n")
	}

	return []byte(csv.String()), nil
}

func (m *Manager) GetDates() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	dates := make(map[string]bool)
	for _, h := range m.history {
		dates[h.Date] = true
	}

	var result []string
	for d := range dates {
		result = append(result, d)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(result)))
	return result
}

func (m *Manager) UpdateNotes(id string, notes string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for i, h := range m.history {
		if h.ID == id {
			m.history[i].Notes = notes
			return m.save()
		}
	}
	return nil
}

func (m *Manager) AddTags(id string, tags []string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for i, h := range m.history {
		if h.ID == id {
			existingTags := make(map[string]bool)
			for _, t := range h.Tags {
				existingTags[t] = true
			}
			for _, t := range tags {
				if !existingTags[t] {
					m.history[i].Tags = append(m.history[i].Tags, t)
				}
			}
			return m.save()
		}
	}
	return nil
}

func (m *Manager) GetByDomain(domain string) []types.ScanHistory {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var result []types.ScanHistory
	for _, h := range m.history {
		if strings.EqualFold(h.Domain, domain) {
			result = append(result, h)
		}
	}
	
	sort.Slice(result, func(i, j int) bool {
		return result[i].StartTime.After(result[j].StartTime)
	})
	
	return result
}

func (m *Manager) GetDomainStats(domain string) types.DomainStats {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	stats := types.DomainStats{
		Domain: domain,
	}
	
	for _, h := range m.history {
		if strings.EqualFold(h.Domain, domain) {
			stats.TotalScans++
			if h.Status == "completed" {
				stats.CompletedScans++
			} else if h.Status == "error" || h.Status == "failed" {
				stats.FailedScans++
			}
			stats.TotalVulns += h.VulnCount
			stats.CriticalVulns += h.CriticalVulns
			stats.HighVulns += h.HighVulns
			stats.MediumVulns += h.MediumVulns
			stats.LowVulns += h.LowVulns
			
			if stats.FirstScan.IsZero() || h.StartTime.Before(stats.FirstScan) {
				stats.FirstScan = h.StartTime
			}
			if h.StartTime.After(stats.LastScan) {
				stats.LastScan = h.StartTime
			}
			
			stats.Vulnerabilities = append(stats.Vulnerabilities, h.Vulnerabilities...)
		}
	}
	
	return stats
}

func (m *Manager) ExportMarkdown(ids []string) ([]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var toExport []types.ScanHistory
	if len(ids) == 0 {
		toExport = m.history
	} else {
		idSet := make(map[string]bool)
		for _, id := range ids {
			idSet[id] = true
		}
		for _, h := range m.history {
			if idSet[h.ID] {
				toExport = append(toExport, h)
			}
		}
	}

	var md strings.Builder
	md.WriteString("# RCE HawkEye Scan History Report\n\n")
	md.WriteString(fmt.Sprintf("**Generated**: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	md.WriteString("---\n\n")
	
	for _, h := range toExport {
		md.WriteString(fmt.Sprintf("## %s\n\n", h.Target))
		md.WriteString(fmt.Sprintf("- **Domain**: %s\n", h.Domain))
		md.WriteString(fmt.Sprintf("- **Status**: %s\n", h.Status))
		md.WriteString(fmt.Sprintf("- **Date**: %s\n", h.Date))
		md.WriteString(fmt.Sprintf("- **Duration**: %.2fs\n", h.Duration))
		md.WriteString(fmt.Sprintf("- **Scan Level**: %d\n", h.ScanLevel))
		md.WriteString("\n### Vulnerability Summary\n\n")
		md.WriteString(fmt.Sprintf("- Total: %d\n", h.VulnCount))
		md.WriteString(fmt.Sprintf("- Critical: %d\n", h.CriticalVulns))
		md.WriteString(fmt.Sprintf("- High: %d\n", h.HighVulns))
		md.WriteString(fmt.Sprintf("- Medium: %d\n", h.MediumVulns))
		md.WriteString(fmt.Sprintf("- Low: %d\n", h.LowVulns))
		
		if len(h.Vulnerabilities) > 0 {
			md.WriteString("\n### Vulnerabilities\n\n")
			md.WriteString("| Severity | Type | Parameter | Target |\n")
			md.WriteString("|----------|------|-----------|--------|\n")
			for _, v := range h.Vulnerabilities {
				md.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", 
					v.Severity, v.PayloadType, v.Parameter, v.Target))
			}
		}
		
		if h.Notes != "" {
			md.WriteString(fmt.Sprintf("\n### Notes\n\n%s\n", h.Notes))
		}
		
		md.WriteString("\n---\n\n")
	}
	
	return []byte(md.String()), nil
}

func (m *Manager) ExportHTML(ids []string) ([]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var toExport []types.ScanHistory
	if len(ids) == 0 {
		toExport = m.history
	} else {
		idSet := make(map[string]bool)
		for _, id := range ids {
			idSet[id] = true
		}
		for _, h := range m.history {
			if idSet[h.ID] {
				toExport = append(toExport, h)
			}
		}
	}

	var html strings.Builder
	html.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RCE HawkEye - Scan History Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            min-height: 100vh;
            padding: 20px;
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            text-align: center;
            padding: 40px 20px;
            background: rgba(30, 41, 59, 0.8);
            border-radius: 16px;
            margin-bottom: 30px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .header h1 {
            font-size: 2.5em;
            background: linear-gradient(135deg, #22c55e, #06b6d4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        .header .subtitle { color: #94a3b8; font-size: 1.1em; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(30, 41, 59, 0.8);
            padding: 24px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .stat-card .value { font-size: 2.5em; font-weight: bold; }
        .stat-card .label { color: #94a3b8; margin-top: 8px; }
        .stat-card.green .value { color: #22c55e; }
        .stat-card.red .value { color: #ef4444; }
        .stat-card.yellow .value { color: #f59e0b; }
        .stat-card.cyan .value { color: #06b6d4; }
        .scan-card {
            background: rgba(30, 41, 59, 0.8);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 20px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .scan-card h2 { 
            color: #22c55e;
            font-size: 1.3em;
            margin-bottom: 16px;
            word-break: break-all;
        }
        .scan-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 12px;
            margin-bottom: 20px;
        }
        .scan-info-item { 
            background: rgba(0,0,0,0.2); 
            padding: 12px; 
            border-radius: 8px; 
        }
        .scan-info-item .label { color: #94a3b8; font-size: 0.85em; }
        .scan-info-item .value { font-weight: 600; margin-top: 4px; }
        .vuln-summary {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }
        .vuln-badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
        }
        .vuln-badge.critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .vuln-badge.high { background: rgba(245, 158, 11, 0.2); color: #f59e0b; }
        .vuln-badge.medium { background: rgba(6, 182, 212, 0.2); color: #06b6d4; }
        .vuln-badge.low { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
        .vuln-table { width: 100%; border-collapse: collapse; margin-top: 16px; }
        .vuln-table th, .vuln-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .vuln-table th { color: #94a3b8; font-weight: 600; }
        .severity-tag {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }
        .severity-tag.critical { background: #ef4444; color: white; }
        .severity-tag.high { background: #f59e0b; color: white; }
        .severity-tag.medium { background: #06b6d4; color: white; }
        .severity-tag.low { background: #22c55e; color: white; }
        .status-completed { color: #22c55e; }
        .status-error { color: #ef4444; }
        .status-running { color: #06b6d4; }
        .notes-section {
            background: rgba(0,0,0,0.2);
            padding: 16px;
            border-radius: 8px;
            margin-top: 16px;
        }
        .notes-section h4 { margin-bottom: 8px; color: #94a3b8; }
        .footer {
            text-align: center;
            padding: 30px;
            color: #64748b;
            margin-top: 40px;
        }
        .footer a { color: #22c55e; text-decoration: none; }
        @media print {
            body { background: white; color: black; }
            .scan-card, .stat-card { background: #f8f9fa; border: 1px solid #ddd; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦅 RCE HawkEye</h1>
            <p class="subtitle">Scan History Report</p>
            <p class="subtitle">Generated: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
        </div>
`)

	var totalScans, totalVulns, criticalVulns, highVulns int
	for _, h := range toExport {
		totalScans++
		totalVulns += h.VulnCount
		criticalVulns += h.CriticalVulns
		highVulns += h.HighVulns
	}

	html.WriteString(fmt.Sprintf(`
        <div class="stats-grid">
            <div class="stat-card green">
                <div class="value">%d</div>
                <div class="label">Total Scans</div>
            </div>
            <div class="stat-card cyan">
                <div class="value">%d</div>
                <div class="label">Total Vulnerabilities</div>
            </div>
            <div class="stat-card red">
                <div class="value">%d</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card yellow">
                <div class="value">%d</div>
                <div class="label">High</div>
            </div>
        </div>
`, totalScans, totalVulns, criticalVulns, highVulns))

	for _, h := range toExport {
		statusClass := "status-completed"
		if h.Status == "error" || h.Status == "failed" {
			statusClass = "status-error"
		} else if h.Status == "running" {
			statusClass = "status-running"
		}

		html.WriteString(fmt.Sprintf(`
        <div class="scan-card">
            <h2>%s</h2>
            <div class="scan-info">
                <div class="scan-info-item">
                    <div class="label">Domain</div>
                    <div class="value">%s</div>
                </div>
                <div class="scan-info-item">
                    <div class="label">Status</div>
                    <div class="value %s">%s</div>
                </div>
                <div class="scan-info-item">
                    <div class="label">Date</div>
                    <div class="value">%s</div>
                </div>
                <div class="scan-info-item">
                    <div class="label">Duration</div>
                    <div class="value">%.2fs</div>
                </div>
                <div class="scan-info-item">
                    <div class="label">Scan Level</div>
                    <div class="value">%d</div>
                </div>
            </div>
            <div class="vuln-summary">
                <span class="vuln-badge critical">Critical: %d</span>
                <span class="vuln-badge high">High: %d</span>
                <span class="vuln-badge medium">Medium: %d</span>
                <span class="vuln-badge low">Low: %d</span>
            </div>
`, escapeHtmlStr(h.Target), escapeHtmlStr(h.Domain), statusClass, h.Status, h.Date, h.Duration, h.ScanLevel, h.CriticalVulns, h.HighVulns, h.MediumVulns, h.LowVulns))

		if len(h.Vulnerabilities) > 0 {
			html.WriteString(`
            <table class="vuln-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Parameter</th>
                        <th>URL</th>
                    </tr>
                </thead>
                <tbody>
`)
			for _, v := range h.Vulnerabilities {
				html.WriteString(fmt.Sprintf(`
                    <tr>
                        <td><span class="severity-tag %s">%s</span></td>
                        <td>%s</td>
                        <td>%s</td>
                        <td>%s</td>
                    </tr>
`, v.Severity, v.Severity, escapeHtmlStr(v.PayloadType), escapeHtmlStr(v.Parameter), escapeHtmlStr(v.Target)))
			}
			html.WriteString(`                </tbody>
            </table>
`)
		}

		if h.Notes != "" {
			html.WriteString(fmt.Sprintf(`
            <div class="notes-section">
                <h4>Notes</h4>
                <p>%s</p>
            </div>
`, escapeHtmlStr(h.Notes)))
		}

		html.WriteString(`        </div>
`)
	}

	html.WriteString(`
        <div class="footer">
            <p>Generated by <a href="https://github.com/hbzw201633420/RCE_HawkEye">RCE HawkEye</a></p>
        </div>
    </div>
</body>
</html>`)

	return []byte(html.String()), nil
}

func escapeHtmlStr(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
