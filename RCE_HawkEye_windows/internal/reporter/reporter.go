package reporter

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
)

type Reporter struct {
	outputDir string
}

func NewReporter(outputDir string) *Reporter {
	if outputDir == "" {
		outputDir = "./reports"
	}
	return &Reporter{outputDir: outputDir}
}

func (r *Reporter) severityToCN(severity types.Severity) string {
	severityMap := map[types.Severity]string{
		types.SeverityCritical: "严重",
		types.SeverityHigh:     "高危",
		types.SeverityMedium:   "中危",
		types.SeverityLow:      "低危",
		types.SeverityInfo:     "信息",
	}
	if v, ok := severityMap[severity]; ok {
		return v
	}
	return "未知"
}

func (r *Reporter) GenerateJSONReport(vulnerabilities []types.Vulnerability, scanInfo map[string]interface{}, includeResponse bool) string {
	report := map[string]interface{}{
		"report_time": time.Now().Format(time.RFC3339),
		"scan_info":   scanInfo,
		"summary": map[string]interface{}{
			"total": len(vulnerabilities),
			"by_severity": map[string]int{
				"critical": countBySeverity(vulnerabilities, types.SeverityCritical),
				"high":     countBySeverity(vulnerabilities, types.SeverityHigh),
				"medium":   countBySeverity(vulnerabilities, types.SeverityMedium),
				"low":      countBySeverity(vulnerabilities, types.SeverityLow),
				"info":     countBySeverity(vulnerabilities, types.SeverityInfo),
			},
		},
		"vulnerabilities": make([]map[string]interface{}, 0),
	}

	vulnList := make([]map[string]interface{}, 0)
	for _, vuln := range vulnerabilities {
		vulnData := map[string]interface{}{
			"target":        vuln.Target,
			"parameter":     vuln.Parameter,
			"payload":       vuln.Payload,
			"payload_type":  vuln.PayloadType,
			"severity":      string(vuln.Severity),
			"severity_name": r.severityToCN(vuln.Severity),
			"description":   vuln.Description,
			"evidence":      vuln.Evidence,
			"exploitation":  vuln.Exploitation,
			"remediation":   vuln.Remediation,
			"timestamp":     vuln.Timestamp,
			"request_data":  vuln.RequestData,
		}

		if includeResponse {
			responseContent := ""
			if rd, ok := vuln.ResponseData["content"].(string); ok {
				responseContent = rd
				if len(responseContent) > 5000 {
					responseContent = responseContent[:5000] + "\n... (内容已截断)"
				}
			}

			vulnData["response_data"] = map[string]interface{}{
				"status_code": vuln.ResponseData["status_code"],
				"elapsed":     vuln.ResponseData["elapsed"],
				"error":       vuln.ResponseData["error"],
				"headers":     vuln.ResponseData["headers"],
				"content":     responseContent,
			}
		} else {
			vulnData["response_data"] = map[string]interface{}{
				"status_code": vuln.ResponseData["status_code"],
				"elapsed":     vuln.ResponseData["elapsed"],
				"error":       vuln.ResponseData["error"],
			}
		}

		vulnList = append(vulnList, vulnData)
	}

	report["vulnerabilities"] = vulnList

	data, _ := json.MarshalIndent(report, "", "  ")
	return string(data)
}

func (r *Reporter) GenerateMarkdownReport(vulnerabilities []types.Vulnerability, scanInfo map[string]interface{}, includeResponse bool) string {
	var lines []string

	lines = append(lines, "# 命令执行漏洞检测报告")
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("**报告生成时间**: %s", time.Now().Format("2006-01-02 15:04:05")))
	lines = append(lines, "")

	if scanInfo != nil {
		lines = append(lines, "## 扫描信息")
		lines = append(lines, "")
		for key, value := range scanInfo {
			lines = append(lines, fmt.Sprintf("- **%s**: %v", key, value))
		}
		lines = append(lines, "")
	}

	lines = append(lines, "## 漏洞概览")
	lines = append(lines, "")

	total := len(vulnerabilities)
	critical := countBySeverity(vulnerabilities, types.SeverityCritical)
	high := countBySeverity(vulnerabilities, types.SeverityHigh)
	medium := countBySeverity(vulnerabilities, types.SeverityMedium)
	low := countBySeverity(vulnerabilities, types.SeverityLow)

	lines = append(lines, "| 严重程度 | 数量 |")
	lines = append(lines, "|----------|------|")
	lines = append(lines, fmt.Sprintf("| 严重 | %d |", critical))
	lines = append(lines, fmt.Sprintf("| 高危 | %d |", high))
	lines = append(lines, fmt.Sprintf("| 中危 | %d |", medium))
	lines = append(lines, fmt.Sprintf("| 低危 | %d |", low))
	lines = append(lines, fmt.Sprintf("| **总计** | **%d** |", total))
	lines = append(lines, "")

	if len(vulnerabilities) > 0 {
		lines = append(lines, "## 漏洞详情")
		lines = append(lines, "")

		for i, vuln := range vulnerabilities {
			severityName := r.severityToCN(vuln.Severity)
			lines = append(lines, fmt.Sprintf("### 漏洞 #%d - %s", i+1, severityName))
			lines = append(lines, "")
			lines = append(lines, fmt.Sprintf("- **目标**: `%s`", vuln.Target))
			lines = append(lines, fmt.Sprintf("- **参数**: `%s`", vuln.Parameter))
			lines = append(lines, fmt.Sprintf("- **类型**: %s", vuln.PayloadType))
			lines = append(lines, fmt.Sprintf("- **Payload**: `%s`", vuln.Payload))
			lines = append(lines, fmt.Sprintf("- **描述**: %s", vuln.Description))
			lines = append(lines, fmt.Sprintf("- **证据**: %s", vuln.Evidence))
			lines = append(lines, "")
			lines = append(lines, "**利用方式**:")
			lines = append(lines, "```")
			lines = append(lines, vuln.Exploitation)
			lines = append(lines, "```")
			lines = append(lines, "")
			lines = append(lines, "**修复建议**:")
			lines = append(lines, "```")
			lines = append(lines, vuln.Remediation)
			lines = append(lines, "```")
			lines = append(lines, "")

			if includeResponse && vuln.ResponseData != nil {
				lines = append(lines, "**响应信息**:")
				lines = append(lines, "")
				statusCode := vuln.ResponseData["status_code"]
				elapsed := vuln.ResponseData["elapsed"]
				errInfo := vuln.ResponseData["error"]

				lines = append(lines, fmt.Sprintf("- 状态码: %v", statusCode))
				if elapsed != nil {
					lines = append(lines, fmt.Sprintf("- 响应时间: %.2fs", elapsed))
				}
				if errInfo != nil && errInfo != "" {
					lines = append(lines, fmt.Sprintf("- 错误: %v", errInfo))
				}
				lines = append(lines, "")

				if content, ok := vuln.ResponseData["content"].(string); ok && content != "" {
					if len(content) > 2000 {
						content = content[:2000] + "\n... (内容已截断)"
					}
					lines = append(lines, "**响应内容**:")
					lines = append(lines, "```")
					lines = append(lines, content)
					lines = append(lines, "```")
					lines = append(lines, "")
				}
			}

			lines = append(lines, "---")
			lines = append(lines, "")
		}
	}

	return strings.Join(lines, "\n")
}

func (r *Reporter) GenerateHTMLReport(vulnerabilities []types.Vulnerability, scanInfo map[string]interface{}, includeResponse bool) string {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>命令执行漏洞检测报告</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header p { opacity: 0.9; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .summary-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .summary-card .count { font-size: 36px; font-weight: bold; margin-bottom: 5px; }
        .summary-card .label { color: #666; font-size: 14px; }
        .vulnerability { background: white; margin-bottom: 15px; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .vuln-header { padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; }
        .vuln-title { font-weight: 600; }
        .severity-badge { padding: 5px 15px; border-radius: 20px; color: white; font-size: 12px; font-weight: 600; }
        .vuln-body { padding: 20px; border-top: 1px solid #eee; }
        .vuln-row { margin-bottom: 15px; }
        .vuln-row label { font-weight: 600; display: block; margin-bottom: 5px; color: #555; }
        .vuln-row code { background: #f8f9fa; padding: 10px; border-radius: 5px; display: block; overflow-x: auto; font-size: 13px; white-space: pre-wrap; word-break: break-all; }
        .critical { background: #d32f2f; }
        .high { background: #f57c00; }
        .medium { background: #fbc02d; }
        .low { background: #388e3c; }
        .info { background: #1976d2; }
        .no-vulns { text-align: center; padding: 50px; color: #666; }
        .no-vulns h2 { color: #388e3c; margin-bottom: 10px; }
        .response-section { margin-top: 15px; padding-top: 15px; border-top: 2px dashed #eee; }
        .response-info { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 10px; }
        .response-info-item { background: #f0f0f0; padding: 10px; border-radius: 5px; text-align: center; }
        .response-info-item .value { font-size: 18px; font-weight: bold; color: #333; }
        .response-info-item .label { font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>命令执行漏洞检测报告</h1>
            <p>报告生成时间: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <div class="count" style="color: #d32f2f;">` + fmt.Sprintf("%d", countBySeverity(vulnerabilities, types.SeverityCritical)) + `</div>
                <div class="label">严重</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #f57c00;">` + fmt.Sprintf("%d", countBySeverity(vulnerabilities, types.SeverityHigh)) + `</div>
                <div class="label">高危</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #fbc02d;">` + fmt.Sprintf("%d", countBySeverity(vulnerabilities, types.SeverityMedium)) + `</div>
                <div class="label">中危</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #388e3c;">` + fmt.Sprintf("%d", countBySeverity(vulnerabilities, types.SeverityLow)) + `</div>
                <div class="label">低危</div>
            </div>
            <div class="summary-card">
                <div class="count">` + fmt.Sprintf("%d", len(vulnerabilities)) + `</div>
                <div class="label">总计</div>
            </div>
        </div>
`)

	if len(vulnerabilities) > 0 {
		sb.WriteString("        <div class=\"vulnerabilities\">\n")
		for i, vuln := range vulnerabilities {
			severityName := r.severityToCN(vuln.Severity)
			severityClass := strings.ToLower(string(vuln.Severity))

			sb.WriteString("            <div class=\"vulnerability\">\n")
			sb.WriteString("                <div class=\"vuln-header\">\n")
			sb.WriteString(fmt.Sprintf("                    <span class=\"vuln-title\">漏洞 #%d - %s</span>\n", i+1, html.EscapeString(vuln.Target)))
			sb.WriteString(fmt.Sprintf("                    <span class=\"severity-badge %s\">%s</span>\n", severityClass, severityName))
			sb.WriteString("                </div>\n")
			sb.WriteString("                <div class=\"vuln-body\">\n")

			sb.WriteString("                    <div class=\"vuln-row\">\n")
			sb.WriteString("                        <label>目标URL</label>\n")
			sb.WriteString(fmt.Sprintf("                        <code>%s</code>\n", html.EscapeString(vuln.Target)))
			sb.WriteString("                    </div>\n")

			sb.WriteString("                    <div class=\"vuln-row\">\n")
			sb.WriteString("                        <label>注入参数</label>\n")
			sb.WriteString(fmt.Sprintf("                        <code>%s</code>\n", html.EscapeString(vuln.Parameter)))
			sb.WriteString("                    </div>\n")

			sb.WriteString("                    <div class=\"vuln-row\">\n")
			sb.WriteString("                        <label>Payload</label>\n")
			sb.WriteString(fmt.Sprintf("                        <code>%s</code>\n", html.EscapeString(vuln.Payload)))
			sb.WriteString("                    </div>\n")

			sb.WriteString("                    <div class=\"vuln-row\">\n")
			sb.WriteString("                        <label>漏洞类型</label>\n")
			sb.WriteString(fmt.Sprintf("                        <code>%s</code>\n", html.EscapeString(vuln.PayloadType)))
			sb.WriteString("                    </div>\n")

			sb.WriteString("                    <div class=\"vuln-row\">\n")
			sb.WriteString("                        <label>检测证据</label>\n")
			sb.WriteString(fmt.Sprintf("                        <code>%s</code>\n", html.EscapeString(vuln.Evidence)))
			sb.WriteString("                    </div>\n")

			sb.WriteString("                    <div class=\"vuln-row\">\n")
			sb.WriteString("                        <label>利用方式</label>\n")
			sb.WriteString(fmt.Sprintf("                        <code>%s</code>\n", html.EscapeString(vuln.Exploitation)))
			sb.WriteString("                    </div>\n")

			sb.WriteString("                    <div class=\"vuln-row\">\n")
			sb.WriteString("                        <label>修复建议</label>\n")
			remediation := strings.ReplaceAll(vuln.Remediation, "\n", "<br>")
			sb.WriteString(fmt.Sprintf("                        <code>%s</code>\n", html.EscapeString(remediation)))
			sb.WriteString("                    </div>\n")

			if includeResponse && vuln.ResponseData != nil {
				statusCode := vuln.ResponseData["status_code"]
				elapsed := "0.00s"
				if e, ok := vuln.ResponseData["elapsed"].(float64); ok {
					elapsed = fmt.Sprintf("%.2fs", e)
				}
				errInfo := "无"
				if e, ok := vuln.ResponseData["error"].(string); ok && e != "" {
					errInfo = e
				}

				sb.WriteString("                    <div class=\"response-section\">\n")
				sb.WriteString("                        <div class=\"vuln-row\">\n")
				sb.WriteString("                            <label>响应信息</label>\n")
				sb.WriteString("                        </div>\n")
				sb.WriteString("                        <div class=\"response-info\">\n")
				sb.WriteString("                            <div class=\"response-info-item\">\n")
				sb.WriteString(fmt.Sprintf("                                <div class=\"value\">%v</div>\n", statusCode))
				sb.WriteString("                                <div class=\"label\">状态码</div>\n")
				sb.WriteString("                            </div>\n")
				sb.WriteString("                            <div class=\"response-info-item\">\n")
				sb.WriteString(fmt.Sprintf("                                <div class=\"value\">%s</div>\n", elapsed))
				sb.WriteString("                                <div class=\"label\">响应时间</div>\n")
				sb.WriteString("                            </div>\n")
				sb.WriteString("                            <div class=\"response-info-item\">\n")
				sb.WriteString(fmt.Sprintf("                                <div class=\"value\">%s</div>\n", html.EscapeString(errInfo)))
				sb.WriteString("                                <div class=\"label\">错误信息</div>\n")
				sb.WriteString("                            </div>\n")
				sb.WriteString("                        </div>\n")

				if content, ok := vuln.ResponseData["content"].(string); ok && content != "" {
					if len(content) > 3000 {
						content = content[:3000] + "\n... (内容已截断)"
					}
					sb.WriteString("                        <div class=\"vuln-row\">\n")
					sb.WriteString("                            <label>响应内容</label>\n")
					sb.WriteString(fmt.Sprintf("                            <code>%s</code>\n", html.EscapeString(content)))
					sb.WriteString("                        </div>\n")
				}

				sb.WriteString("                    </div>\n")
			}

			sb.WriteString("                </div>\n")
			sb.WriteString("            </div>\n")
		}
		sb.WriteString("        </div>\n")
	} else {
		sb.WriteString("        <div class=\"no-vulns\">\n")
		sb.WriteString("            <h2>未发现漏洞</h2>\n")
		sb.WriteString("            <p>扫描完成，未检测到命令执行漏洞</p>\n")
		sb.WriteString("        </div>\n")
	}

	sb.WriteString("    </div>\n</body>\n</html>")

	return sb.String()
}

func (r *Reporter) SaveReport(vulnerabilities []types.Vulnerability, format, filename string, scanInfo map[string]interface{}, includeResponse bool) (string, error) {
	timestamp := time.Now().Format("20060102_150405")

	if filename == "" {
		filename = fmt.Sprintf("rce_report_%s.%s", timestamp, format)
	}

	if err := os.MkdirAll(r.outputDir, 0755); err != nil {
		return "", err
	}

	filePath := filepath.Join(r.outputDir, filename)

	var content string
	switch format {
	case "json":
		content = r.GenerateJSONReport(vulnerabilities, scanInfo, includeResponse)
	case "md", "markdown":
		content = r.GenerateMarkdownReport(vulnerabilities, scanInfo, includeResponse)
	case "html":
		content = r.GenerateHTMLReport(vulnerabilities, scanInfo, includeResponse)
	default:
		return "", fmt.Errorf("不支持的报告格式: %s", format)
	}

	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return "", err
	}

	return filePath, nil
}

func (r *Reporter) ExportAllFormats(vulnerabilities []types.Vulnerability, scanInfo map[string]interface{}, includeResponse bool) (map[string]string, error) {
	timestamp := time.Now().Format("20060102_150405")
	files := make(map[string]string)

	for _, format := range []string{"json", "html", "md"} {
		filename := fmt.Sprintf("rce_report_%s.%s", timestamp, format)
		filePath, err := r.SaveReport(vulnerabilities, format, filename, scanInfo, includeResponse)
		if err != nil {
			return nil, err
		}
		files[format] = filePath
	}

	return files, nil
}

func countBySeverity(vulnerabilities []types.Vulnerability, severity types.Severity) int {
	count := 0
	for _, v := range vulnerabilities {
		if v.Severity == severity {
			count++
		}
	}
	return count
}
