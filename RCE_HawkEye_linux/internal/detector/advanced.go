package detector

import (
	"regexp"
	"strings"
	"time"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
)

type AdvancedDetector struct {
	*Detector
	commandPatterns    []PatternMatch
	errorPatterns      []PatternMatch
	technologyPatterns []PatternMatch
	encodingPatterns   []PatternMatch
}

type PatternMatch struct {
	Pattern     *regexp.Regexp
	Description string
	Confidence  float64
	Category    string
}

func NewAdvancedDetector(opts ...Option) *AdvancedDetector {
	d := &AdvancedDetector{
		Detector: NewDetector(opts...),
	}
	d.loadAdvancedPatterns()
	return d
}

func (d *AdvancedDetector) loadAdvancedPatterns() {
	d.commandPatterns = []PatternMatch{
		{regexp.MustCompile(`(?i)uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)\s+groups=`), "id命令输出", 0.98, "unix_id"},
		{regexp.MustCompile(`(?i)uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)`), "id命令输出(简化)", 0.95, "unix_id"},
		{regexp.MustCompile(`(?i)gid=\d+\([^)]*\)`), "gid输出", 0.85, "unix_id"},
		{regexp.MustCompile(`(?i)total\s+\d+[\s\S]*?drwx[rwx-]+`), "ls -la输出", 0.92, "unix_ls"},
		{regexp.MustCompile(`(?i)drwx[rwx-]+\s+\d+\s+\S+\s+\S+\s+\d+\s+\S+\s+\d+\s+[\d:]+\s+\S+`), "ls详细输出", 0.90, "unix_ls"},
		{regexp.MustCompile(`(?i)-rw[rwx-]+\s+\d+\s+\S+\s+\S+\s+\d+`), "ls文件输出", 0.88, "unix_ls"},
		{regexp.MustCompile(`(?i)root:[^:]*:\d+:\d+:`), "/etc/passwd内容", 0.98, "unix_file"},
		{regexp.MustCompile(`(?i)daemon:[^:]*:\d+:\d+:`), "/etc/passwd daemon用户", 0.95, "unix_file"},
		{regexp.MustCompile(`(?i)nobody:[^:]*:\d+:\d+:`), "/etc/passwd nobody用户", 0.95, "unix_file"},
		{regexp.MustCompile(`(?i)www-data:[^:]*:\d+:\d+:`), "/etc/passwd www-data用户", 0.95, "unix_file"},
		{regexp.MustCompile(`(?i)apache:[^:]*:\d+:\d+:`), "/etc/passwd apache用户", 0.95, "unix_file"},
		{regexp.MustCompile(`(?i)mysql:[^:]*:\d+:\d+:`), "/etc/passwd mysql用户", 0.95, "unix_file"},
		{regexp.MustCompile(`(?i)Directory of\s+[A-Z]:\\[^\n]+`), "Windows dir输出", 0.92, "windows_dir"},
		{regexp.MustCompile(`(?i)Volume Serial Number is\s+[A-Z0-9-]+`), "Windows vol输出", 0.95, "windows_vol"},
		{regexp.MustCompile(`(?i)Volume in drive [A-Z] is`), "Windows驱动器信息", 0.90, "windows_vol"},
		{regexp.MustCompile(`(?i)Linux\s+\S+\s+\d+\.\d+\.\d+`), "uname -a Linux输出", 0.90, "unix_uname"},
		{regexp.MustCompile(`(?i)Darwin\s+\S+\s+\d+\.\d+\.\d+`), "uname -a macOS输出", 0.90, "unix_uname"},
		{regexp.MustCompile(`(?i)FreeBSD\s+\S+\s+\d+\.\d+`), "uname -a FreeBSD输出", 0.90, "unix_uname"},
		{regexp.MustCompile(`(?i)\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+`), "可能的时间戳/进程ID输出", 0.50, "numeric"},
		{regexp.MustCompile(`(?i)PID\s+TTY\s+TIME\s+CMD`), "ps命令输出头", 0.85, "unix_ps"},
		{regexp.MustCompile(`(?i)USER\s+PID\s+%CPU\s+%MEM`), "ps aux输出头", 0.85, "unix_ps"},
		{regexp.MustCompile(`(?i)total\s+used\s+free`), "df/du输出头", 0.80, "unix_disk"},
		{regexp.MustCompile(`(?i)Filesystem\s+\d+G\s+\d+G`), "df输出", 0.80, "unix_disk"},
		{regexp.MustCompile(`(?i)CPU\s+minf\s+ltf`), "top命令输出", 0.75, "unix_top"},
		{regexp.MustCompile(`(?i)Mem:\s+\d+k`), "free命令输出", 0.75, "unix_mem"},
		{regexp.MustCompile(`(?i)eth\d+:\s+<`), "ifconfig输出", 0.80, "unix_net"},
		{regexp.MustCompile(`(?i)inet\s+\d+\.\d+\.\d+\.\d+`), "IP地址输出", 0.70, "network"},
		{regexp.MustCompile(`(?i)tcp\s+\d+\s+\d+\s+\d+\.\d+\.\d+\.\d+:\d+`), "netstat TCP输出", 0.80, "unix_net"},
		{regexp.MustCompile(`(?i)Active\s+Internet\s+connections`), "netstat输出头", 0.80, "unix_net"},
		{regexp.MustCompile(`(?i)Active\s+Connections`), "Windows netstat输出", 0.80, "windows_net"},
		{regexp.MustCompile(`(?i)Proto\s+Local\s+Address`), "netstat输出头", 0.80, "windows_net"},
		{regexp.MustCompile(`(?i)\\[A-Z]\$`), "Windows共享路径", 0.85, "windows_share"},
		{regexp.MustCompile(`(?i)HKEY_`), "Windows注册表输出", 0.90, "windows_reg"},
		{regexp.MustCompile(`(?i)HKLM\\`), "Windows注册表路径", 0.90, "windows_reg"},
		{regexp.MustCompile(`(?i)HKCU\\`), "Windows注册表路径", 0.90, "windows_reg"},
	}

	d.errorPatterns = []PatternMatch{
		{regexp.MustCompile(`(?i)sh:\s*\d+:`), "Shell错误", 0.85, "shell_error"},
		{regexp.MustCompile(`(?i)bash:\s*[^:]+:\s*command\s+not\s+found`), "Bash命令未找到", 0.90, "bash_error"},
		{regexp.MustCompile(`(?i)bash:\s*[^:]+:\s*No\s+such\s+file\s+or\s+directory`), "Bash文件不存在", 0.85, "bash_error"},
		{regexp.MustCompile(`(?i)/bin/sh:\s*\d+:`), "Shell错误", 0.85, "shell_error"},
		{regexp.MustCompile(`(?i)/bin/bash:\s*`), "Bash错误", 0.85, "bash_error"},
		{regexp.MustCompile(`(?i)command\s+not\s+found`), "命令未找到", 0.80, "cmd_error"},
		{regexp.MustCompile(`(?i)No\s+such\s+file\s+or\s+directory`), "文件不存在", 0.75, "file_error"},
		{regexp.MustCompile(`(?i)Permission\s+denied`), "权限拒绝", 0.70, "perm_error"},
		{regexp.MustCompile(`(?i)Access\s+denied`), "访问拒绝", 0.70, "perm_error"},
		{regexp.MustCompile(`(?i)is\s+not\s+recognized\s+as\s+an\s+internal\s+or\s+external\s+command`), "Windows命令错误", 0.90, "windows_error"},
		{regexp.MustCompile(`(?i)'[^']+'\s+is\s+not\s+recognized`), "Windows命令错误", 0.90, "windows_error"},
		{regexp.MustCompile(`(?i)系统找不到指定的路径`), "Windows路径错误", 0.85, "windows_error"},
		{regexp.MustCompile(`(?i)内部或外部命令`), "Windows命令错误", 0.85, "windows_error"},
		{regexp.MustCompile(`(?i)'[^']+'\s+不是内部或外部命令`), "Windows命令错误", 0.90, "windows_error"},
		{regexp.MustCompile(`(?i)The\s+system\s+cannot\s+find\s+the\s+path\s+specified`), "Windows路径错误", 0.85, "windows_error"},
		{regexp.MustCompile(`(?i)Fatal error:`), "致命错误", 0.80, "fatal_error"},
		{regexp.MustCompile(`(?i)Error:`), "错误信息", 0.60, "error"},
		{regexp.MustCompile(`(?i)Warning:`), "警告信息", 0.50, "warning"},
		{regexp.MustCompile(`(?i)Exception:`), "异常信息", 0.70, "exception"},
	}

	d.technologyPatterns = []PatternMatch{
		{regexp.MustCompile(`(?i)Fatal error:.+in\s+/[^:]+\.php`), "PHP致命错误", 0.90, "php_error"},
		{regexp.MustCompile(`(?i)Warning:.+in\s+/[^:]+\.php`), "PHP警告", 0.80, "php_error"},
		{regexp.MustCompile(`(?i)Parse error:.+in\s+/[^:]+\.php`), "PHP语法错误", 0.92, "php_error"},
		{regexp.MustCompile(`(?i)Call to undefined function`), "PHP未定义函数", 0.85, "php_error"},
		{regexp.MustCompile(`(?i)Call to undefined method`), "PHP未定义方法", 0.85, "php_error"},
		{regexp.MustCompile(`(?i)Cannot redeclare`), "PHP重复声明", 0.80, "php_error"},
		{regexp.MustCompile(`(?i)Undefined variable:`), "PHP未定义变量", 0.70, "php_error"},
		{regexp.MustCompile(`(?i)Array\s*\([^)]+\)`), "PHP数组输出", 0.60, "php_output"},
		{regexp.MustCompile(`(?i)java\.lang\.\w+Exception`), "Java异常", 0.88, "java_error"},
		{regexp.MustCompile(`(?i)java\.lang\.\w+Error`), "Java错误", 0.90, "java_error"},
		{regexp.MustCompile(`(?i)javax\.servlet\.`), "JSP Servlet", 0.85, "jsp_error"},
		{regexp.MustCompile(`(?i)at\s+java\.`), "Java堆栈跟踪", 0.80, "java_stack"},
		{regexp.MustCompile(`(?i)at\s+[a-z]+\.[a-z]+\([^)]+\)`), "Java方法调用栈", 0.75, "java_stack"},
		{regexp.MustCompile(`(?i)Traceback\s*\(most\s+recent\s+call\s+last\)`), "Python异常", 0.92, "python_error"},
		{regexp.MustCompile(`(?i)File\s+"[^"]+",\s+line\s+\d+`), "Python错误位置", 0.88, "python_error"},
		{regexp.MustCompile(`(?i)SyntaxError:`), "Python语法错误", 0.90, "python_error"},
		{regexp.MustCompile(`(?i)NameError:`), "Python名称错误", 0.85, "python_error"},
		{regexp.MustCompile(`(?i)TypeError:`), "Python类型错误", 0.80, "python_error"},
		{regexp.MustCompile(`(?i)ImportError:`), "Python导入错误", 0.80, "python_error"},
		{regexp.MustCompile(`(?i)ModuleNotFoundError:`), "Python模块未找到", 0.85, "python_error"},
		{regexp.MustCompile(`(?i)ReferenceError:`), "JavaScript引用错误", 0.85, "js_error"},
		{regexp.MustCompile(`(?i)TypeError:`), "JavaScript类型错误", 0.80, "js_error"},
		{regexp.MustCompile(`(?i)SyntaxError:`), "JavaScript语法错误", 0.85, "js_error"},
		{regexp.MustCompile(`(?i)RuntimeError:`), "Ruby运行时错误", 0.85, "ruby_error"},
		{regexp.MustCompile(`(?i)panic:`), "Go panic", 0.92, "go_error"},
		{regexp.MustCompile(`(?i)goroutine\s+\d+\s+\[`), "Go goroutine", 0.85, "go_error"},
		{regexp.MustCompile(`(?i)/usr/local/go/src/`), "Go源码路径", 0.80, "go_error"},
		{regexp.MustCompile(`(?i)perl:\s+warning:`), "Perl警告", 0.75, "perl_error"},
		{regexp.MustCompile(`(?i)Can't locate`), "Perl模块未找到", 0.80, "perl_error"},
		{regexp.MustCompile(`(?i)lua:\s+`), "Lua错误", 0.80, "lua_error"},
		{regexp.MustCompile(`(?i)attempt to`), "Lua错误描述", 0.70, "lua_error"},
	}

	d.encodingPatterns = []PatternMatch{
		{regexp.MustCompile(`(?i)^[A-Za-z0-9+/]{20,}={0,2}$`), "Base64编码输出", 0.40, "base64"},
		{regexp.MustCompile(`(?i)\\x[0-9a-f]{2}`), "十六进制编码", 0.50, "hex"},
		{regexp.MustCompile(`(?i)%[0-9a-f]{2}`), "URL编码", 0.40, "url_encode"},
		{regexp.MustCompile(`(?i)&#[0-9]+;`), "HTML实体编码", 0.40, "html_entity"},
		{regexp.MustCompile(`(?i)\\u[0-9a-f]{4}`), "Unicode编码", 0.40, "unicode"},
	}
}

func (d *AdvancedDetector) DetectAdvanced(responseContent, baselineContent string, payload types.Payload) *types.Vulnerability {
	for _, pattern := range d.commandPatterns {
		if pattern.Pattern.MatchString(responseContent) {
			if baselineContent != "" && pattern.Pattern.MatchString(baselineContent) {
				continue
			}
			return d.createVulnerability(
				"",
				"",
				payload,
				types.SeverityCritical,
				"发现命令执行输出: "+pattern.Description,
				"通过回显获取命令执行结果",
			)
		}
	}

	for _, pattern := range d.errorPatterns {
		if pattern.Pattern.MatchString(responseContent) {
			if baselineContent != "" && pattern.Pattern.MatchString(baselineContent) {
				continue
			}
			return d.createVulnerability(
				"",
				"",
				payload,
				types.SeverityHigh,
				"发现命令执行错误: "+pattern.Description,
				"错误信息表明命令被执行",
			)
		}
	}

	for _, pattern := range d.technologyPatterns {
		if pattern.Pattern.MatchString(responseContent) {
			if baselineContent != "" && pattern.Pattern.MatchString(baselineContent) {
				continue
			}
			return d.createVulnerability(
				"",
				"",
				payload,
				types.SeverityHigh,
				"发现代码执行错误: "+pattern.Description,
				"错误信息表明代码被执行",
			)
		}
	}

	return nil
}

func (d *AdvancedDetector) AnalyzeResponseAdvanced(response map[string]interface{}, p types.Payload, baselineResponse map[string]interface{}) *types.Vulnerability {
	vuln := d.AnalyzeResponse(response, p, baselineResponse)
	if vuln != nil {
		return vuln
	}

	content, _ := response["content"].(string)
	var baselineContent string
	if baselineResponse != nil {
		baselineContent, _ = baselineResponse["content"].(string)
	}

	return d.DetectAdvanced(content, baselineContent, p)
}

func (d *AdvancedDetector) DetectTimeBasedAdvanced(baselineTime, responseTime float64, payload types.Payload) *types.Vulnerability {
	if payload.ExpectedDelay == 0 {
		return nil
	}

	timeDiff := responseTime - baselineTime
	threshold := max(d.delayThreshold, payload.ExpectedDelay*0.7)

	if timeDiff >= threshold {
		return d.createVulnerability(
			"",
			"",
			payload,
			types.SeverityHigh,
			"响应延迟异常",
			"通过时间延迟判断命令执行",
		)
	}

	return nil
}

func (d *AdvancedDetector) DetectDiffAdvanced(responseContent, baselineContent string, threshold float64) (bool, string) {
	if baselineContent == "" {
		return false, ""
	}

	if responseContent == baselineContent {
		return false, ""
	}

	responseLen := len(responseContent)
	baselineLen := len(baselineContent)

	if baselineLen > 0 {
		lenDiff := float64(abs(responseLen-baselineLen)) / float64(baselineLen)
		if lenDiff > threshold {
			return true, "响应长度显著变化"
		}
	}

	responseWords := make(map[string]int)
	for _, w := range strings.Fields(responseContent) {
		responseWords[w]++
	}
	baselineWords := make(map[string]int)
	for _, w := range strings.Fields(baselineContent) {
		baselineWords[w]++
	}

	newWords := make([]string, 0)
	for w := range responseWords {
		if _, exists := baselineWords[w]; !exists {
			newWords = append(newWords, w)
		}
	}

	removedWords := make([]string, 0)
	for w := range baselineWords {
		if _, exists := responseWords[w]; !exists {
			removedWords = append(removedWords, w)
		}
	}

	if len(newWords) > 5 {
		return true, "发现新增内容: " + strings.Join(newWords[:5], ", ")
	}

	if len(removedWords) > 5 {
		return true, "发现移除内容: " + strings.Join(removedWords[:5], ", ")
	}

	return false, ""
}

func (d *AdvancedDetector) IdentifyTechnology(responseContent string) map[string]float64 {
	techScores := make(map[string]float64)

	for _, pattern := range d.technologyPatterns {
		if pattern.Pattern.MatchString(responseContent) {
			category := pattern.Category
			if strings.Contains(category, "php") {
				techScores["PHP"] = maxFloat(techScores["PHP"], pattern.Confidence)
			} else if strings.Contains(category, "java") || strings.Contains(category, "jsp") {
				techScores["Java/JSP"] = maxFloat(techScores["Java/JSP"], pattern.Confidence)
			} else if strings.Contains(category, "python") {
				techScores["Python"] = maxFloat(techScores["Python"], pattern.Confidence)
			} else if strings.Contains(category, "js") || strings.Contains(category, "node") {
				techScores["Node.js"] = maxFloat(techScores["Node.js"], pattern.Confidence)
			} else if strings.Contains(category, "ruby") {
				techScores["Ruby"] = maxFloat(techScores["Ruby"], pattern.Confidence)
			} else if strings.Contains(category, "go") {
				techScores["Go"] = maxFloat(techScores["Go"], pattern.Confidence)
			} else if strings.Contains(category, "perl") {
				techScores["Perl"] = maxFloat(techScores["Perl"], pattern.Confidence)
			} else if strings.Contains(category, "lua") {
				techScores["Lua"] = maxFloat(techScores["Lua"], pattern.Confidence)
			}
		}
	}

	return techScores
}

func (d *AdvancedDetector) IdentifyOSAdvanced(responseContent string) map[string]float64 {
	osScores := make(map[string]float64)

	for _, pattern := range d.commandPatterns {
		if pattern.Pattern.MatchString(responseContent) {
			category := pattern.Category
			if strings.Contains(category, "unix") || strings.Contains(category, "linux") {
				osScores["Linux/Unix"] = maxFloat(osScores["Linux/Unix"], pattern.Confidence)
			} else if strings.Contains(category, "windows") {
				osScores["Windows"] = maxFloat(osScores["Windows"], pattern.Confidence)
			}
		}
	}

	return osScores
}

func (d *AdvancedDetector) GetPatternStatistics() map[string]int {
	return map[string]int{
		"command_patterns":    len(d.commandPatterns),
		"error_patterns":      len(d.errorPatterns),
		"technology_patterns": len(d.technologyPatterns),
		"encoding_patterns":   len(d.encodingPatterns),
	}
}

func (d *AdvancedDetector) createVulnerability(target, parameter string, p types.Payload, severity types.Severity, evidence, exploitation string) *types.Vulnerability {
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

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
