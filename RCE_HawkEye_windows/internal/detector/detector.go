package detector

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
)

type Detector struct {
	delayThreshold float64
	echoMarkers    []string
	vulnerabilities []types.Vulnerability
	baselines      map[string]*types.BaselineResponse
}

type Option func(*Detector)

func WithDelayThreshold(threshold float64) Option {
	return func(d *Detector) {
		d.delayThreshold = threshold
	}
}

func WithEchoMarkers(markers []string) Option {
	return func(d *Detector) {
		d.echoMarkers = markers
	}
}

func NewDetector(opts ...Option) *Detector {
	d := &Detector{
		delayThreshold: 4.0,
		echoMarkers:    []string{"RCE_TEST_MARKER_12345", "VULN_DETECTED"},
		baselines:      make(map[string]*types.BaselineResponse),
	}

	for _, opt := range opts {
		opt(d)
	}

	return d
}

func (d *Detector) SetBaseline(url string, response map[string]interface{}) {
	content, _ := response["content"].(string)
	statusCode, _ := response["status_code"].(int)
	elapsed, _ := response["elapsed"].(float64)

	headers := make(map[string]string)
	if h, ok := response["headers"].(map[string]string); ok {
		headers = h
	}

	d.baselines[url] = &types.BaselineResponse{
		Content:       content,
		StatusCode:    statusCode,
		ContentLength: len(content),
		Elapsed:       elapsed,
		Headers:       headers,
	}
}

func (d *Detector) GetBaseline(url string) *types.BaselineResponse {
	return d.baselines[url]
}

func (d *Detector) DetectTimeBased(baselineTime, responseTime float64, payload types.Payload) bool {
	if payload.ExpectedDelay == 0 {
		return false
	}

	timeDiff := responseTime - baselineTime
	return timeDiff >= max(d.delayThreshold, payload.ExpectedDelay*0.8)
}

func (d *Detector) DetectEchoBased(responseContent string, payload types.Payload, baselineContent string) (bool, string) {
	if payload.ExpectedOutput != "" {
		if strings.Contains(responseContent, payload.ExpectedOutput) {
			if baselineContent != "" && strings.Contains(baselineContent, payload.ExpectedOutput) {
				return false, ""
			}
			return true, "在响应中发现预期输出: " + payload.ExpectedOutput
		}
	}

	for _, marker := range d.echoMarkers {
		if strings.Contains(responseContent, marker) {
			if baselineContent != "" && strings.Contains(baselineContent, marker) {
				continue
			}
			return true, "在响应中发现回显标记: " + marker
		}
	}

	return false, ""
}

func (d *Detector) DetectCommandOutput(responseContent string, baselineContent string) (bool, string) {
	if responseContent == "" {
		return false, ""
	}

	if baselineContent != "" {
		if responseContent == baselineContent {
			return false, ""
		}

		if abs(len(responseContent)-len(baselineContent)) < 10 {
			responseWords := make(map[string]bool)
			for _, w := range strings.Fields(responseContent) {
				responseWords[w] = true
			}
			for _, w := range strings.Fields(baselineContent) {
				delete(responseWords, w)
			}
			if len(responseWords) < 3 {
				return false, ""
			}
		}
	}

	highConfidencePatterns := []struct {
		pattern     string
		description string
		confidence  float64
	}{
		{`uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)\s+groups=`, "id命令输出", 0.95},
		{`total\s+\d+\s+drwx[rwx-]+\s+\d+`, "ls -la输出", 0.90},
		{`drwx[rwx-]+\s+\d+\s+\w+\s+\w+\s+\d+\s+\w+\s+\d+\s+[\d:]+\s+\S+`, "ls -la详细输出", 0.90},
		{`-rw[rwx-]+\s+\d+\s+\w+\s+\w+\s+\d+\s+\w+\s+\d+\s+[\d:]+\s+\S+`, "ls -la文件输出", 0.90},
		{`root:[^:]*:\d+:\d+:`, "/etc/passwd内容", 0.95},
		{`Directory of\s+[A-Z]:\\[^\n]+\n\n`, "Windows dir输出", 0.90},
		{`Volume Serial Number is [A-Z0-9-]+`, "Windows vol输出", 0.95},
		{`Linux\s+\S+\s+\d+\.\d+\.\d+`, "uname -a输出", 0.85},
		{`Darwin\s+\S+\s+\d+\.\d+\.\d+`, "macOS uname输出", 0.85},
	}

	for _, p := range highConfidencePatterns {
		matched, _ := regexp.MatchString(p.pattern, responseContent)
		if matched {
			if baselineContent != "" {
				baselineMatched, _ := regexp.MatchString(p.pattern, baselineContent)
				if baselineMatched {
					continue
				}
			}
			return true, "发现高置信度命令输出特征: " + p.description
		}
	}

	mediumConfidencePatterns := []struct {
		pattern     string
		description string
		confidence  float64
	}{
		{`/bin/(ba)?sh`, "shell路径", 0.60},
		{`/usr/bin/\w+`, "可执行文件路径", 0.50},
		{`/home/\w+/`, "用户目录路径", 0.50},
	}

	for _, p := range mediumConfidencePatterns {
		matched, _ := regexp.MatchString(p.pattern, responseContent)
		if matched {
			if baselineContent != "" {
				baselineMatched, _ := regexp.MatchString(p.pattern, baselineContent)
				if baselineMatched {
					continue
				}
			}
			return true, "发现可能的命令输出特征: " + p.description
		}
	}

	lowConfidencePatterns := []struct {
		pattern     string
		description string
		confidence  float64
	}{
		{`bin/bash`, "shell路径", 0.30},
		{`bin/sh`, "shell路径", 0.30},
	}

	for _, p := range lowConfidencePatterns {
		matched, _ := regexp.MatchString(p.pattern, responseContent)
		if matched {
			if baselineContent != "" {
				baselineMatched, _ := regexp.MatchString(p.pattern, baselineContent)
				if baselineMatched {
					continue
				}
			}

			if len(responseContent) < 500 {
				continue
			}

			return true, "发现可能的命令输出特征: " + p.description
		}
	}

	return false, ""
}

func (d *Detector) DetectResponseDiff(response map[string]interface{}, baseline *types.BaselineResponse) (bool, string) {
	content, _ := response["content"].(string)
	statusCode, _ := response["status_code"].(int)

	if baseline != nil && statusCode != baseline.StatusCode {
		return true, fmt.Sprintf("状态码变化: %d -> %d", baseline.StatusCode, statusCode)
	}

	contentLen := len(content)
	var baselineLen int
	if baseline != nil {
		baselineLen = baseline.ContentLength
	}

	if baselineLen > 0 {
		diffRatio := float64(abs(contentLen-baselineLen)) / float64(baselineLen)
		if diffRatio > 0.5 {
			return true, fmt.Sprintf("响应长度显著变化: %d -> %d", baselineLen, contentLen)
		}
	}

	if baseline != nil && content != "" && baseline.Content != "" && content != baseline.Content {
		responseWords := make(map[string]bool)
		for _, w := range strings.Fields(content) {
			responseWords[w] = true
		}
		baselineWords := make(map[string]bool)
		for _, w := range strings.Fields(baseline.Content) {
			baselineWords[w] = true
		}

		newWords := make([]string, 0)
		for w := range responseWords {
			if !baselineWords[w] {
				newWords = append(newWords, w)
			}
		}

		if len(newWords) > 5 {
			return true, "响应内容有显著差异，新增内容: " + strings.Join(newWords[:5], ", ")
		}
	}

	return false, ""
}

func (d *Detector) AnalyzeResponse(response map[string]interface{}, p types.Payload, baselineResponse map[string]interface{}) *types.Vulnerability {
	targetURL, _ := response["url"].(string)

	var baseline *types.BaselineResponse
	
	for key, b := range d.baselines {
		if strings.HasPrefix(targetURL, key) {
			baseline = b
			break
		}
	}
	
	if baseline == nil && baselineResponse != nil {
		content, _ := baselineResponse["content"].(string)
		statusCode, _ := baselineResponse["status_code"].(int)
		elapsed, _ := baselineResponse["elapsed"].(float64)
		baseline = &types.BaselineResponse{
			Content:       content,
			StatusCode:    statusCode,
			ContentLength: len(content),
			Elapsed:       elapsed,
		}
	}

	errStr, _ := response["error"].(string)
	elapsed, _ := response["elapsed"].(float64)

	if errStr == "Timeout" || errStr == "context deadline exceeded" {
		if p.PayloadType == types.PayloadTypeTimeBased {
			return d.createVulnerability(
				targetURL,
				"",
				p,
				types.SeverityHigh,
				"请求超时，可能存在时间盲注漏洞",
				"通过时间延迟判断命令是否执行",
			)
		}
		return nil
	}

	if p.PayloadType == types.PayloadTypeTimeBased {
		baselineTime := 0.0
		if baseline != nil {
			baselineTime = baseline.Elapsed
		}
		if d.DetectTimeBased(baselineTime, elapsed, p) {
			return d.createVulnerability(
				targetURL,
				"",
				p,
				types.SeverityHigh,
				fmt.Sprintf("响应延迟 %.2f秒，超过阈值 %.2f秒", elapsed, d.delayThreshold),
				"通过sleep/timeout等命令造成延迟",
			)
		}
	}

	if p.PayloadType == types.PayloadTypeEchoBased || p.PayloadType == types.PayloadTypeCodeExec {
		content, _ := response["content"].(string)
		var baselineContent string
		if baseline != nil {
			baselineContent = baseline.Content
		}

		if content == "" {
			return nil
		}

		if p.ExpectedOutput != "" && strings.Contains(content, p.ExpectedOutput) {
			if baselineContent == "" || !strings.Contains(baselineContent, p.ExpectedOutput) {
				return d.createVulnerability(
					targetURL,
					"",
					p,
					types.SeverityCritical,
					"在响应中发现预期输出: " + p.ExpectedOutput,
					"直接通过回显获取命令执行结果",
				)
			}
		}

		detected, evidence := d.DetectEchoBased(content, p, baselineContent)
		if detected {
			return d.createVulnerability(
				targetURL,
				"",
				p,
				types.SeverityCritical,
				evidence,
				"直接通过回显获取命令执行结果",
			)
		}

		detected, evidence = d.DetectCommandOutput(content, baselineContent)
		if detected {
			return d.createVulnerability(
				targetURL,
				"",
				p,
				types.SeverityCritical,
				evidence,
				"直接通过回显获取命令执行结果",
			)
		}
	}

	return nil
}

func (d *Detector) createVulnerability(target, parameter string, p types.Payload, severity types.Severity, evidence, exploitation string) *types.Vulnerability {
	return &types.Vulnerability{
		Target:       target,
		Parameter:    parameter,
		Payload:      p.Content,
		PayloadType:  string(p.PayloadType),
		Severity:     severity,
		Description:  p.Description,
		Evidence:     evidence,
		Exploitation: exploitation,
		Remediation:  d.getRemediation(p.PayloadType),
		Timestamp:    float64(time.Now().Unix()),
	}
}

func (d *Detector) getRemediation(payloadType types.PayloadType) string {
	remediations := map[types.PayloadType]string{
		types.PayloadTypeTimeBased: "1. 避免直接执行用户输入\n2. 使用参数化查询或预编译语句\n3. 对输入进行严格的白名单验证\n4. 使用最小权限运行应用",
		types.PayloadTypeEchoBased: "1. 禁用命令执行函数或使用安全替代方案\n2. 对所有用户输入进行严格过滤\n3. 使用沙箱环境隔离执行\n4. 实施输入输出编码",
		types.PayloadTypeCodeExec:  "1. 禁用危险的PHP函数(system, exec, shell_exec, passthru等)\n2. 使用disable_functions配置禁用\n3. 对所有用户输入进行严格过滤\n4. 使用最小权限运行应用",
		types.PayloadTypeDNSBased:  "1. 禁止应用发起外部网络请求\n2. 使用DNS解析白名单\n3. 监控异常DNS查询\n4. 实施网络隔离",
		types.PayloadTypeFileBased: "1. 限制文件系统访问权限\n2. 禁止写入Web目录\n3. 使用chroot或容器隔离\n4. 监控文件系统变更",
	}

	if r, ok := remediations[payloadType]; ok {
		return r
	}
	return "实施输入验证和输出编码"
}

func (d *Detector) AddVulnerability(vuln types.Vulnerability) {
	d.vulnerabilities = append(d.vulnerabilities, vuln)
}

func (d *Detector) GetVulnerabilities() []types.Vulnerability {
	return d.vulnerabilities
}

func (d *Detector) GetVulnerabilitiesBySeverity(severity types.Severity) []types.Vulnerability {
	var result []types.Vulnerability
	for _, v := range d.vulnerabilities {
		if v.Severity == severity {
			result = append(result, v)
		}
	}
	return result
}

func (d *Detector) Clear() {
	d.vulnerabilities = nil
	d.baselines = make(map[string]*types.BaselineResponse)
}

func (d *Detector) GetStatistics() map[string]int {
	return map[string]int{
		"total":    len(d.vulnerabilities),
		"critical": len(d.GetVulnerabilitiesBySeverity(types.SeverityCritical)),
		"high":     len(d.GetVulnerabilitiesBySeverity(types.SeverityHigh)),
		"medium":   len(d.GetVulnerabilitiesBySeverity(types.SeverityMedium)),
		"low":      len(d.GetVulnerabilitiesBySeverity(types.SeverityLow)),
		"info":     len(d.GetVulnerabilitiesBySeverity(types.SeverityInfo)),
	}
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
