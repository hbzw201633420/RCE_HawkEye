package heuristic

import (
	"regexp"
	"strings"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
)

type HeuristicChecker struct {
	cache map[string]types.HeuristicResult
}

func NewHeuristicChecker() *HeuristicChecker {
	return &HeuristicChecker{
		cache: make(map[string]types.HeuristicResult),
	}
}

var commandInjectionMarkers = []struct {
	pattern     string
	confidence  float64
	description string
}{
	{`uid=\d+\([^)]*\)`, 0.95, "id命令输出"},
	{`gid=\d+\([^)]*\)`, 0.90, "id命令输出"},
	{`total\s+\d+\s+drwx`, 0.90, "ls -la输出"},
	{`drwx[rwx-]+\s+\d+`, 0.85, "ls输出"},
	{`-rw[rwx-]+\s+\d+`, 0.85, "ls输出"},
	{`root:[^:]*:\d+:\d+:`, 0.95, "/etc/passwd内容"},
	{`Directory of\s+[A-Z]:\\`, 0.90, "Windows dir输出"},
	{`Volume Serial Number`, 0.90, "Windows vol输出"},
	{`Linux\s+\S+\s+\d+\.\d+`, 0.85, "uname输出"},
	{`Darwin\s+\S+\s+\d+\.\d+`, 0.85, "macOS uname输出"},
	{`/bin/(ba)?sh`, 0.70, "shell路径"},
	{`/usr/bin/\w+`, 0.60, "可执行文件路径"},
	{`/home/\w+/`, 0.50, "用户目录"},
	{`www-data:\d:`, 0.85, "www-data用户"},
	{`apache:\d:`, 0.85, "apache用户"},
	{`nginx:\d:`, 0.85, "nginx用户"},
	{`nobody:\d:`, 0.80, "nobody用户"},
}

var codeInjectionMarkers = []struct {
	pattern     string
	confidence  float64
	description string
}{
	{`Fatal error:.+in\s+/`, 0.80, "PHP错误"},
	{`Warning:.+in\s+/`, 0.70, "PHP警告"},
	{`Parse error:.+in\s+/`, 0.85, "PHP语法错误"},
	{`Call to undefined function`, 0.75, "PHP未定义函数"},
	{`Cannot redeclare`, 0.70, "PHP重复声明"},
	{`java\.lang\.\w+Exception`, 0.80, "Java异常"},
	{`java\.lang\.\w+Error`, 0.85, "Java错误"},
	{`javax\.servlet\.`, 0.75, "JSP Servlet"},
	{`at\s+java\.`, 0.70, "Java堆栈"},
	{`Traceback \(most recent call last\)`, 0.85, "Python异常"},
	{`File\s+"[^"]+",\s+line\s+\d+`, 0.80, "Python错误位置"},
	{`SyntaxError:`, 0.85, "Python语法错误"},
	{`NameError:`, 0.75, "Python名称错误"},
	{`TypeError:`, 0.70, "Python类型错误"},
	{`ReferenceError:`, 0.75, "JavaScript引用错误"},
	{`RuntimeError:`, 0.75, "Ruby运行时错误"},
	{`panic:`, 0.85, "Go panic"},
	{`goroutine\s+\d+`, 0.70, "Go goroutine"},
}

var templateInjectionMarkers = []struct {
	pattern     string
	confidence  float64
	description string
}{
	{`49`, 0.60, "7*7计算结果"},
	{`7777777`, 0.70, "7*7*7*7*7*7*7结果"},
	{`config\s*=`, 0.75, "Flask config"},
	{`Config\s*\{`, 0.75, "Flask Config对象"},
	{`<Config\s+`, 0.80, "Flask Config对象"},
	{`os\.environ`, 0.80, "环境变量"},
	{`<class\s+`, 0.70, "Python类对象"},
	{`<module\s+`, 0.70, "Python模块"},
	{`<function\s+`, 0.65, "Python函数"},
	{`__class__\s*=\s*<class`, 0.85, "Python类访问"},
	{`__mro__\s*=`, 0.85, "Python MRO"},
	{`__subclasses__\s*=`, 0.85, "Python子类"},
}

var errorPatterns = []struct {
	pattern     string
	confidence  float64
	description string
}{
	{`sh:\s*\d+:`, 0.80, "Shell错误"},
	{`bash:`, 0.80, "Bash错误"},
	{`/bin/sh:`, 0.80, "Shell错误"},
	{`command not found`, 0.75, "命令未找到"},
	{`No such file or directory`, 0.70, "文件不存在"},
	{`Permission denied`, 0.65, "权限拒绝"},
	{`Access denied`, 0.65, "访问拒绝"},
	{`is not recognized`, 0.75, "Windows命令错误"},
	{`' is not recognized`, 0.80, "Windows命令错误"},
	{`系统找不到指定的路径`, 0.75, "Windows路径错误"},
	{`内部或外部命令`, 0.75, "Windows命令错误"},
}

func (h *HeuristicChecker) CheckResponse(response, baseline, parameter, payload string) types.HeuristicResult {
	cacheKey := response[:min(100, len(response))] + "_" + parameter + "_" + payload[:min(50, len(payload))]
	if result, ok := h.cache[cacheKey]; ok {
		return result
	}

	if baseline != "" && response == baseline {
		return types.HeuristicResult{
			Injectable:    false,
			InjectionType: types.InjectionTypeUnknown,
			Confidence:    0.0,
			Evidence:      "响应与基准相同",
			Parameter:     parameter,
			Payload:       payload,
		}
	}

	result := h.analyzeResponse(response, parameter, payload)
	h.cache[cacheKey] = result
	return result
}

func (h *HeuristicChecker) analyzeResponse(response, parameter, payload string) types.HeuristicResult {
	for _, m := range commandInjectionMarkers {
		matched, _ := regexp.MatchString(m.pattern, response)
		if matched {
			return types.HeuristicResult{
				Injectable:    true,
				InjectionType: types.InjectionTypeCommandInjection,
				Confidence:    m.confidence,
				Evidence:      "发现命令注入特征: " + m.description,
				Parameter:     parameter,
				Payload:       payload,
			}
		}
	}

	for _, m := range codeInjectionMarkers {
		matched, _ := regexp.MatchString(m.pattern, response)
		if matched {
			return types.HeuristicResult{
				Injectable:    true,
				InjectionType: types.InjectionTypeCodeInjection,
				Confidence:    m.confidence,
				Evidence:      "发现代码注入特征: " + m.description,
				Parameter:     parameter,
				Payload:       payload,
			}
		}
	}

	for _, m := range templateInjectionMarkers {
		matched, _ := regexp.MatchString(m.pattern, response)
		if matched {
			if strings.Contains(payload, "7*7") || strings.Contains(payload, "{{") || strings.Contains(payload, "${") {
				return types.HeuristicResult{
					Injectable:    true,
					InjectionType: types.InjectionTypeTemplateInjection,
					Confidence:    m.confidence,
					Evidence:      "发现模板注入特征: " + m.description,
					Parameter:     parameter,
					Payload:       payload,
				}
			}
		}
	}

	for _, m := range errorPatterns {
		matched, _ := regexp.MatchString(m.pattern, response)
		if matched {
			return types.HeuristicResult{
				Injectable:    true,
				InjectionType: types.InjectionTypeCommandInjection,
				Confidence:    m.confidence * 0.8,
				Evidence:      "发现错误信息: " + m.description,
				Parameter:     parameter,
				Payload:       payload,
			}
		}
	}

	return types.HeuristicResult{
		Injectable:    false,
		InjectionType: types.InjectionTypeUnknown,
		Confidence:    0.0,
		Evidence:      "未发现注入特征",
		Parameter:     parameter,
		Payload:       payload,
	}
}

func (h *HeuristicChecker) CheckTimeBased(elapsed, threshold, expectedDelay float64) (bool, float64) {
	if elapsed >= threshold && elapsed >= expectedDelay*0.8 {
		confidence := elapsed / expectedDelay
		if confidence > 0.95 {
			confidence = 0.95
		}
		return true, confidence
	}
	return false, 0.0
}

func (h *HeuristicChecker) CheckReflection(response, marker string) (bool, float64) {
	if strings.Contains(response, marker) {
		return true, 0.90
	}
	return false, 0.0
}

func (h *HeuristicChecker) IdentifyBackend(response string) string {
	backendPatterns := []struct {
		pattern string
		backend string
	}{
		{`PHP/\d+\.\d+`, "PHP"},
		{`X-Powered-By:\s*PHP`, "PHP"},
		{`Apache/\d+\.\d+`, "Apache"},
		{`nginx/\d+\.\d+`, "Nginx"},
		{`Microsoft-IIS/\d+\.\d+`, "IIS"},
		{`Tomcat/\d+\.\d+`, "Tomcat"},
		{`JBoss`, "JBoss"},
		{`WebLogic`, "WebLogic"},
		{`gunicorn`, "Python/Gunicorn"},
		{`uWSGI`, "Python/uWSGI"},
		{`Express`, "Node.js/Express"},
		{`Phusion Passenger`, "Ruby/Passenger"},
		{`OpenResty`, "OpenResty/Lua"},
	}

	for _, p := range backendPatterns {
		matched, _ := regexp.MatchString(p.pattern, response)
		if matched {
			return p.backend
		}
	}
	return ""
}

func (h *HeuristicChecker) IdentifyOS(response string) string {
	osPatterns := []struct {
		pattern string
		osName  string
	}{
		{`Linux\s+\S+\s+\d+\.\d+`, "Linux"},
		{`Darwin\s+\S+\s+\d+\.\d+`, "macOS"},
		{`Windows\s+\d+`, "Windows"},
		{`Microsoft\s+Windows`, "Windows"},
		{`WINNT`, "Windows"},
		{`/etc/passwd`, "Unix/Linux"},
		{`/bin/(ba)?sh`, "Unix/Linux"},
		{`C:\\\\Windows`, "Windows"},
		{`D:\\\\`, "Windows"},
	}

	for _, p := range osPatterns {
		matched, _ := regexp.MatchString(p.pattern, response)
		if matched {
			return p.osName
		}
	}
	return ""
}

func (h *HeuristicChecker) GetInjectionPoints(url, method string, params, headers, cookies, data map[string]string) []map[string]interface{} {
	var injectionPoints []map[string]interface{}

	if params != nil {
		for name, value := range params {
			injectionPoints = append(injectionPoints, map[string]interface{}{
				"type":      "GET_PARAM",
				"parameter": name,
				"value":     value,
				"location":  "query",
			})
		}
	}

	if data != nil {
		for name, value := range data {
			injectionPoints = append(injectionPoints, map[string]interface{}{
				"type":      "POST_PARAM",
				"parameter": name,
				"value":     value,
				"location":  "body",
			})
		}
	}

	if headers != nil {
		for name, value := range headers {
			lowerName := strings.ToLower(name)
			if lowerName == "user-agent" || lowerName == "referer" || lowerName == "x-forwarded-for" || lowerName == "cookie" {
				injectionPoints = append(injectionPoints, map[string]interface{}{
					"type":      "HEADER",
					"parameter": name,
					"value":     value,
					"location":  "header",
				})
			}
		}
	}

	if cookies != nil {
		for name, value := range cookies {
			injectionPoints = append(injectionPoints, map[string]interface{}{
				"type":      "COOKIE",
				"parameter": name,
				"value":     value,
				"location":  "cookie",
			})
		}
	}

	return injectionPoints
}

func (h *HeuristicChecker) PrioritizeParameters(injectionPoints []map[string]interface{}) []map[string]interface{} {
	highPriority := map[string]bool{
		"cmd": true, "command": true, "exec": true, "shell": true, "system": true,
		"file": true, "path": true, "id": true, "page": true, "url": true,
		"data": true, "action": true, "code": true, "eval": true, "test": true,
		"debug": true, "input": true, "run": true, "execute": true,
	}

	mediumPriority := map[string]bool{
		"a": true, "b": true, "c": true, "q": true, "s": true,
		"p": true, "f": true, "d": true, "n": true, "m": true,
	}

	getPriority := func(point map[string]interface{}) int {
		param := strings.ToLower(point["parameter"].(string))
		if highPriority[param] {
			return 0
		}
		if mediumPriority[param] {
			return 1
		}
		return 2
	}

	sorted := make([]map[string]interface{}, len(injectionPoints))
	copy(sorted, injectionPoints)

	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if getPriority(sorted[i]) > getPriority(sorted[j]) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	return sorted
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
