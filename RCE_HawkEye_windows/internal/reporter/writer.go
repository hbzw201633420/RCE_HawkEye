package reporter

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
)

type ResultWriter struct {
	baseDir        string
	dateDir        string
	domainDir      string
	dirsFile       *os.File
	paramsFile     *os.File
	vulnsFile      *os.File
	vulnsMdFile    *os.File
	crawledFile    *os.File
	dirsMutex      sync.Mutex
	paramsMutex    sync.Mutex
	vulnsMutex     sync.Mutex
	crawledMutex   sync.Mutex
	initialized    bool
}

var (
	globalWriter *ResultWriter
	writerMutex  sync.Mutex
)

func GetResultWriter() *ResultWriter {
	writerMutex.Lock()
	defer writerMutex.Unlock()
	if globalWriter == nil {
		globalWriter = NewResultWriter()
	}
	return globalWriter
}

func NewResultWriter() *ResultWriter {
	return &ResultWriter{
		baseDir:     "reports",
		initialized: false,
	}
}

func (w *ResultWriter) Initialize(targetURL string) error {
	w.dirsMutex.Lock()
	w.paramsMutex.Lock()
	w.vulnsMutex.Lock()
	w.crawledMutex.Lock()
	defer w.dirsMutex.Unlock()
	defer w.paramsMutex.Unlock()
	defer w.vulnsMutex.Unlock()
	defer w.crawledMutex.Unlock()

	if w.initialized {
		return nil
	}

	now := time.Now()
	w.dateDir = now.Format("20060102")

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return err
	}
	domain := parsedURL.Host
	domain = strings.ReplaceAll(domain, ":", "_")
	w.domainDir = domain

	fullPath := filepath.Join(w.baseDir, w.dateDir, w.domainDir)
	if err := os.MkdirAll(fullPath, 0755); err != nil {
		return err
	}

	w.initialized = true
	
	if err := w.ensureFilesOpen(); err != nil {
		return err
	}
	
	return nil
}

func (w *ResultWriter) ensureFilesOpen() error {
	if w.dirsFile == nil {
		f, err := os.OpenFile(
			filepath.Join(w.baseDir, w.dateDir, w.domainDir, "directories.txt"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			0644,
		)
		if err != nil {
			return err
		}
		w.dirsFile = f
	}

	if w.paramsFile == nil {
		f, err := os.OpenFile(
			filepath.Join(w.baseDir, w.dateDir, w.domainDir, "parameters.txt"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			0644,
		)
		if err != nil {
			return err
		}
		w.paramsFile = f
	}

	if w.vulnsFile == nil {
		f, err := os.OpenFile(
			filepath.Join(w.baseDir, w.dateDir, w.domainDir, "vulnerabilities.json"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			0644,
		)
		if err != nil {
			return err
		}
		w.vulnsFile = f
	}

	if w.vulnsMdFile == nil {
		f, err := os.OpenFile(
			filepath.Join(w.baseDir, w.dateDir, w.domainDir, "vulnerabilities.md"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			0644,
		)
		if err != nil {
			return err
		}
		w.vulnsMdFile = f
		
		header := fmt.Sprintf("# 命令执行漏洞检测报告\n\n**报告生成时间**: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
		f.WriteString(header)
		f.Sync()
	}

	if w.crawledFile == nil {
		f, err := os.OpenFile(
			filepath.Join(w.baseDir, w.dateDir, w.domainDir, "crawled.txt"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			0644,
		)
		if err != nil {
			return err
		}
		w.crawledFile = f
	}

	return nil
}

func (w *ResultWriter) WriteDirectory(result types.DirResult) error {
	w.dirsMutex.Lock()
	defer w.dirsMutex.Unlock()

	if !w.initialized {
		return nil
	}

	if err := w.ensureFilesOpen(); err != nil {
		return err
	}

	if result.StatusCode == 404 {
		return nil
	}

	line := fmt.Sprintf("[%d] %d %s\n", result.StatusCode, result.ContentLength, result.URL)
	_, err := w.dirsFile.WriteString(line)
	if err == nil {
		w.dirsFile.Sync()
	}
	return err
}

func (w *ResultWriter) WriteParameter(param, source string) error {
	w.paramsMutex.Lock()
	defer w.paramsMutex.Unlock()

	if !w.initialized {
		return nil
	}

	if err := w.ensureFilesOpen(); err != nil {
		return err
	}

	line := fmt.Sprintf("%s (来源: %s)\n", param, source)
	_, err := w.paramsFile.WriteString(line)
	if err == nil {
		w.paramsFile.Sync()
	}
	return err
}

func (w *ResultWriter) WriteVulnerability(vuln types.Vulnerability) error {
	w.vulnsMutex.Lock()
	defer w.vulnsMutex.Unlock()

	if !w.initialized {
		return nil
	}

	if err := w.ensureFilesOpen(); err != nil {
		return err
	}

	data, err := json.Marshal(vuln)
	if err != nil {
		return err
	}

	_, err = w.vulnsFile.WriteString(string(data) + "\n")
	if err == nil {
		w.vulnsFile.Sync()
	}

	err = w.writeVulnerabilityMarkdown(vuln)
	return err
}

func (w *ResultWriter) writeVulnerabilityMarkdown(vuln types.Vulnerability) error {
	severityMap := map[types.Severity]string{
		types.SeverityCritical: "严重",
		types.SeverityHigh:     "高危",
		types.SeverityMedium:   "中危",
		types.SeverityLow:      "低危",
		types.SeverityInfo:     "信息",
	}
	severityName := severityMap[vuln.Severity]
	if severityName == "" {
		severityName = "未知"
	}

	markdown := fmt.Sprintf("\n### 漏洞详情 - %s\n\n", severityName)
	markdown += fmt.Sprintf("- **目标**: `%s`\n", vuln.Target)
	markdown += fmt.Sprintf("- **参数**: `%s`\n", vuln.Parameter)
	markdown += fmt.Sprintf("- **类型**: %s\n", vuln.PayloadType)
	markdown += fmt.Sprintf("- **Payload**: `%s`\n", vuln.Payload)
	markdown += fmt.Sprintf("- **严重性**: %s\n", severityName)
	if vuln.Description != "" {
		markdown += fmt.Sprintf("- **描述**: %s\n", vuln.Description)
	}
	markdown += fmt.Sprintf("- **证据**: %s\n\n", vuln.Evidence)

	markdown += "**利用方式**:\n"
	markdown += "```\n"
	markdown += vuln.Exploitation
	markdown += "\n```\n\n"

	markdown += "**修复建议**:\n"
	markdown += "```\n"
	markdown += vuln.Remediation
	markdown += "\n```\n\n"

	if vuln.RequestData != nil {
		markdown += "**请求数据**:\n"
		markdown += "```json\n"
		markdown += getJSONString(vuln.RequestData)
		markdown += "\n```\n\n"
	}

	if vuln.ResponseData != nil {
		markdown += "**响应信息**:\n\n"
		statusCode := vuln.ResponseData["status_code"]
		elapsed := vuln.ResponseData["elapsed"]
		errInfo := vuln.ResponseData["error"]

		markdown += fmt.Sprintf("- 状态码: %v\n", statusCode)
		if elapsed != nil {
			markdown += fmt.Sprintf("- 响应时间: %.2fs\n", elapsed)
		}
		if errInfo != nil && errInfo != "" {
			markdown += fmt.Sprintf("- 错误: %v\n", errInfo)
		}
		markdown += "\n"

		if content, ok := vuln.ResponseData["content"].(string); ok && content != "" {
			maxLen := 2000
			if len(content) > maxLen {
				content = content[:maxLen] + "\n... (内容已截断)"
			}
			markdown += "**响应内容**:\n"
			markdown += "```\n"
			markdown += content
			markdown += "\n```\n\n"
		}
	}

	markdown += "---\n"

	_, err := w.vulnsMdFile.WriteString(markdown)
	if err == nil {
		w.vulnsMdFile.Sync()
	}
	return err
}

func getJSONString(data interface{}) string {
	if data == nil {
		return "{}"
	}
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(jsonData)
}

func (w *ResultWriter) WriteCrawledURL(urlStr, source string) error {
	w.crawledMutex.Lock()
	defer w.crawledMutex.Unlock()

	if !w.initialized {
		return nil
	}

	if err := w.ensureFilesOpen(); err != nil {
		return err
	}

	line := fmt.Sprintf("%s (来源: %s)\n", urlStr, source)
	_, err := w.crawledFile.WriteString(line)
	if err == nil {
		w.crawledFile.Sync()
	}
	return err
}

func (w *ResultWriter) Close() {
	w.dirsMutex.Lock()
	w.paramsMutex.Lock()
	w.vulnsMutex.Lock()
	w.crawledMutex.Lock()
	defer w.dirsMutex.Unlock()
	defer w.paramsMutex.Unlock()
	defer w.vulnsMutex.Unlock()
	defer w.crawledMutex.Unlock()

	if w.dirsFile != nil {
		w.dirsFile.Close()
	}
	if w.paramsFile != nil {
		w.paramsFile.Close()
	}
	if w.vulnsFile != nil {
		w.vulnsFile.Close()
	}
	if w.vulnsMdFile != nil {
		w.vulnsMdFile.Close()
	}
	if w.crawledFile != nil {
		w.crawledFile.Close()
	}
}

func (w *ResultWriter) GetReportPath() string {
	return filepath.Join(w.baseDir, w.dateDir, w.domainDir)
}

func (w *ResultWriter) WriteSummary(summary map[string]interface{}) error {
	if !w.initialized {
		return nil
	}

	summaryPath := filepath.Join(w.baseDir, w.dateDir, w.domainDir, "summary.json")
	f, err := os.Create(summaryPath)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}
