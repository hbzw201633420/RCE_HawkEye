package heuristic

import (
	"regexp"
	"strings"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
)

type AdvancedHeuristicChecker struct {
	*HeuristicChecker
	rcePatterns       []HeuristicPattern
	sstiPatterns      []HeuristicPattern
	deserializationPatterns []HeuristicPattern
	fileInclusionPatterns []HeuristicPattern
}

type HeuristicPattern struct {
	Pattern     *regexp.Regexp
	Confidence  float64
	Description string
	Category    types.InjectionType
}

func NewAdvancedHeuristicChecker() *AdvancedHeuristicChecker {
	h := &AdvancedHeuristicChecker{
		HeuristicChecker: NewHeuristicChecker(),
	}
	h.loadAdvancedPatterns()
	return h
}

func (h *AdvancedHeuristicChecker) loadAdvancedPatterns() {
	h.rcePatterns = []HeuristicPattern{
		{regexp.MustCompile(`(?i)uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)`), 0.98, "Unix id命令输出", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)gid=\d+\([^)]*\)`), 0.90, "Unix gid输出", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)total\s+\d+[\s\S]*?drwx[rwx-]+`), 0.92, "Unix ls -la输出", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)drwx[rwx-]+\s+\d+\s+\S+\s+\S+\s+\d+`), 0.88, "Unix目录列表", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)-rw[rwx-]+\s+\d+\s+\S+\s+\S+`), 0.85, "Unix文件列表", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)root:[^:]*:\d+:\d+:`), 0.98, "/etc/passwd内容", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)daemon:[^:]*:\d+:\d+:`), 0.95, "/etc/passwd daemon", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)nobody:[^:]*:\d+:\d+:`), 0.95, "/etc/passwd nobody", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)www-data:[^:]*:\d+:\d+:`), 0.95, "/etc/passwd www-data", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)apache:[^:]*:\d+:\d+:`), 0.95, "/etc/passwd apache", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)mysql:[^:]*:\d+:\d+:`), 0.95, "/etc/passwd mysql", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)postgres:[^:]*:\d+:\d+:`), 0.95, "/etc/passwd postgres", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)Directory of\s+[A-Z]:\\`), 0.92, "Windows dir输出", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)Volume Serial Number is`), 0.95, "Windows vol输出", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)Volume in drive [A-Z] is`), 0.90, "Windows驱动器信息", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)Linux\s+\S+\s+\d+\.\d+\.\d+`), 0.90, "uname Linux输出", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)Darwin\s+\S+\s+\d+\.\d+\.\d+`), 0.90, "uname macOS输出", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)FreeBSD\s+\S+\s+\d+\.\d+`), 0.90, "uname FreeBSD输出", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)PID\s+TTY\s+TIME`), 0.85, "ps命令输出", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)USER\s+PID\s+%CPU`), 0.85, "ps aux输出", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)Mem:\s+\d+k\s+\d+k`), 0.80, "free命令输出", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)total\s+used\s+free`), 0.75, "df/du输出", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)eth\d+:\s+<`), 0.80, "ifconfig输出", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)inet\s+\d+\.\d+\.\d+\.\d+`), 0.70, "IP地址输出", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)tcp\s+\d+\s+\d+\s+\d+\.\d+\.\d+\.\d+:\d+`), 0.80, "netstat输出", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)Active\s+Internet\s+connections`), 0.80, "netstat输出头", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)HKEY_`), 0.90, "Windows注册表", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)HKLM\\`), 0.90, "Windows注册表路径", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)HKCU\\`), 0.90, "Windows注册表路径", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)\\[A-Z]\$`), 0.85, "Windows共享路径", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)/bin/(ba)?sh`), 0.75, "Shell路径", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)/usr/bin/\w+`), 0.65, "Unix可执行路径", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)/home/\w+/`), 0.60, "用户目录路径", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)/var/www/`), 0.70, "Web目录路径", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)/etc/\w+\.conf`), 0.75, "配置文件路径", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)C:\\Users\\`), 0.85, "Windows用户目录", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)C:\\Windows\\`), 0.85, "Windows系统目录", types.InjectionTypeCommandInjection},
		{regexp.MustCompile(`(?i)C:\\Program Files\\`), 0.85, "Windows程序目录", types.InjectionTypeCommandInjection},
	}

	h.sstiPatterns = []HeuristicPattern{
		{regexp.MustCompile(`(?m)^49$`), 0.85, "SSTI 7*7结果", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?m)^7777777$`), 0.90, "SSTI 7*7*7*7*7*7*7结果", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)config\s*=`), 0.80, "Flask config对象", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)<Config\s+`), 0.85, "Flask Config对象", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)Config\s*\{`), 0.80, "Flask Config对象", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)os\.environ`), 0.85, "环境变量访问", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)<class\s+`), 0.75, "Python类对象", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)<module\s+`), 0.75, "Python模块对象", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)<function\s+`), 0.70, "Python函数对象", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)__class__\s*=`), 0.90, "Python类访问", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)__mro__\s*=`), 0.90, "Python MRO访问", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)__subclasses__\s*=`), 0.90, "Python子类访问", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)__globals__\s*=`), 0.90, "Python全局变量访问", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)__builtins__`), 0.90, "Python内置函数访问", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)freemarker\.template\.utility`), 0.95, "FreeMarker工具类", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)java\.lang\.Runtime`), 0.90, "Java Runtime访问", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)ProcessBuilder`), 0.85, "Java ProcessBuilder", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)getClass\(\)`), 0.80, "Java getClass调用", types.InjectionTypeTemplateInjection},
		{regexp.MustCompile(`(?i)forName\(`), 0.85, "Java Class.forName", types.InjectionTypeTemplateInjection},
	}

	h.deserializationPatterns = []HeuristicPattern{
		{regexp.MustCompile(`(?i)java\.lang\.ClassNotFoundException`), 0.90, "Java类未找到异常", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)java\.io\.InvalidClassException`), 0.95, "Java反序列化异常", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)java\.io\.StreamCorruptedException`), 0.90, "Java流损坏异常", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)java\.io\.OptionalDataException`), 0.85, "Java可选数据异常", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)serialVersionUID`), 0.70, "Java序列化版本ID", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)ObjectInputStream`), 0.75, "Java对象输入流", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)ObjectOutputStream`), 0.75, "Java对象输出流", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)readObject\(`), 0.85, "Java readObject调用", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)writeObject\(`), 0.80, "Java writeObject调用", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)unserialize\(`), 0.90, "PHP反序列化", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)__wakeup`), 0.85, "PHP __wakeup魔术方法", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)__destruct`), 0.80, "PHP __destruct魔术方法", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)__toString`), 0.75, "PHP __toString魔术方法", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)O:\d+:"`), 0.85, "PHP序列化对象", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)a:\d+:\{`), 0.70, "PHP序列化数组", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)pickle\.loads`), 0.90, "Python pickle反序列化", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)pickle\.dumps`), 0.85, "Python pickle序列化", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)__reduce__`), 0.85, "Python __reduce__方法", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)marshal\.loads`), 0.85, "Python marshal反序列化", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)yaml\.load`), 0.80, "Python YAML加载", types.InjectionTypeCodeInjection},
		{regexp.MustCompile(`(?i)YAMLObject`), 0.75, "Python YAML对象", types.InjectionTypeCodeInjection},
	}

	h.fileInclusionPatterns = []HeuristicPattern{
		{regexp.MustCompile(`(?i)root:[^:]*:\d+:\d+:`), 0.95, "/etc/passwd内容", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)daemon:[^:]*:\d+:\d+:`), 0.90, "/etc/passwd内容", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)\[boot loader\]`), 0.95, "boot.ini内容", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)\[fonts\]`), 0.90, "win.ini内容", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)\[extensions\]`), 0.90, "win.ini内容", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)for\s+16-bit\s+app\s+support`), 0.95, "win.ini内容", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)\[Host\]`), 0.85, "hosts文件内容", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)localhost`), 0.60, "hosts文件内容", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)127\.0\.0\.1\s+localhost`), 0.90, "hosts文件内容", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)<?php`), 0.85, "PHP源码", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)<%@`), 0.85, "JSP源码", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)<%--`), 0.85, "JSP注释", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)import\s+java\.`), 0.80, "Java import语句", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)package\s+[\w\.]+;`), 0.80, "Java package语句", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)web\.config`), 0.85, "web.config引用", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)connectionStrings`), 0.85, "配置文件内容", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)appSettings`), 0.80, "配置文件内容", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)DB_PASSWORD`), 0.90, "数据库密码配置", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)DATABASE_URL`), 0.85, "数据库URL配置", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)SECRET_KEY`), 0.85, "密钥配置", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)API_KEY`), 0.85, "API密钥配置", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)PRIVATE_KEY`), 0.90, "私钥配置", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)BEGIN\s+RSA\s+PRIVATE\s+KEY`), 0.95, "RSA私钥", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)BEGIN\s+OPENSSH\s+PRIVATE\s+KEY`), 0.95, "SSH私钥", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)BEGIN\s+CERTIFICATE`), 0.90, "证书文件", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)aws_access_key_id`), 0.95, "AWS密钥", types.InjectionTypeFileInclusion},
		{regexp.MustCompile(`(?i)aws_secret_access_key`), 0.95, "AWS密钥", types.InjectionTypeFileInclusion},
	}
}

func (h *AdvancedHeuristicChecker) CheckResponseAdvanced(response, baseline, parameter, payload string) types.HeuristicResult {
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

	for _, pattern := range h.rcePatterns {
		if pattern.Pattern.MatchString(response) {
			if baseline != "" && pattern.Pattern.MatchString(baseline) {
				continue
			}
			return types.HeuristicResult{
				Injectable:    true,
				InjectionType: pattern.Category,
				Confidence:    pattern.Confidence,
				Evidence:      "发现命令注入特征: " + pattern.Description,
				Parameter:     parameter,
				Payload:       payload,
			}
		}
	}

	for _, pattern := range h.sstiPatterns {
		if pattern.Pattern.MatchString(response) {
			if baseline != "" && pattern.Pattern.MatchString(baseline) {
				continue
			}
			if strings.Contains(payload, "{{") || strings.Contains(payload, "${") ||
				strings.Contains(payload, "#{") || strings.Contains(payload, "7*7") {
				return types.HeuristicResult{
					Injectable:    true,
					InjectionType: pattern.Category,
					Confidence:    pattern.Confidence,
					Evidence:      "发现模板注入特征: " + pattern.Description,
					Parameter:     parameter,
					Payload:       payload,
				}
			}
		}
	}

	for _, pattern := range h.deserializationPatterns {
		if pattern.Pattern.MatchString(response) {
			if baseline != "" && pattern.Pattern.MatchString(baseline) {
				continue
			}
			return types.HeuristicResult{
				Injectable:    true,
				InjectionType: pattern.Category,
				Confidence:    pattern.Confidence,
				Evidence:      "发现反序列化特征: " + pattern.Description,
				Parameter:     parameter,
				Payload:       payload,
			}
		}
	}

	for _, pattern := range h.fileInclusionPatterns {
		if pattern.Pattern.MatchString(response) {
			if baseline != "" && pattern.Pattern.MatchString(baseline) {
				continue
			}
			return types.HeuristicResult{
				Injectable:    true,
				InjectionType: pattern.Category,
				Confidence:    pattern.Confidence,
				Evidence:      "发现文件包含特征: " + pattern.Description,
				Parameter:     parameter,
				Payload:       payload,
			}
		}
	}

	return h.CheckResponse(response, baseline, parameter, payload)
}

func (h *AdvancedHeuristicChecker) AnalyzeResponseStructure(response, baseline string) map[string]interface{} {
	analysis := make(map[string]interface{})

	analysis["response_length"] = len(response)
	analysis["baseline_length"] = len(baseline)

	if baseline != "" {
		lenDiff := len(response) - len(baseline)
		analysis["length_diff"] = lenDiff
		analysis["length_diff_ratio"] = float64(lenDiff) / float64(len(baseline))
	}

	responseLines := strings.Split(response, "\n")
	baselineLines := strings.Split(baseline, "\n")
	analysis["response_lines"] = len(responseLines)
	analysis["baseline_lines"] = len(baselineLines)

	responseWords := len(strings.Fields(response))
	baselineWords := len(strings.Fields(baseline))
	analysis["response_words"] = responseWords
	analysis["baseline_words"] = baselineWords

	if baseline != "" && baselineWords > 0 {
		analysis["word_diff_ratio"] = float64(responseWords-baselineWords) / float64(baselineWords)
	}

	return analysis
}

func (h *AdvancedHeuristicChecker) DetectErrorBased(response string) (bool, string, float64) {
	errorPatterns := []struct {
		pattern     *regexp.Regexp
		description string
		confidence  float64
	}{
		{regexp.MustCompile(`(?i)sh:\s*\d+:`), "Shell错误", 0.85},
		{regexp.MustCompile(`(?i)bash:\s*[^:]+:\s*command\s+not\s+found`), "Bash命令未找到", 0.90},
		{regexp.MustCompile(`(?i)/bin/sh:\s*\d+:`), "Shell错误", 0.85},
		{regexp.MustCompile(`(?i)command\s+not\s+found`), "命令未找到", 0.80},
		{regexp.MustCompile(`(?i)No\s+such\s+file\s+or\s+directory`), "文件不存在", 0.75},
		{regexp.MustCompile(`(?i)Permission\s+denied`), "权限拒绝", 0.70},
		{regexp.MustCompile(`(?i)Access\s+denied`), "访问拒绝", 0.70},
		{regexp.MustCompile(`(?i)is\s+not\s+recognized`), "Windows命令错误", 0.90},
		{regexp.MustCompile(`(?i)系统找不到指定的路径`), "Windows路径错误", 0.85},
		{regexp.MustCompile(`(?i)内部或外部命令`), "Windows命令错误", 0.85},
		{regexp.MustCompile(`(?i)Fatal error:`), "致命错误", 0.80},
		{regexp.MustCompile(`(?i)Exception:`), "异常", 0.70},
	}

	for _, p := range errorPatterns {
		if p.pattern.MatchString(response) {
			return true, p.description, p.confidence
		}
	}

	return false, "", 0.0
}

func (h *AdvancedHeuristicChecker) GetPatternStatistics() map[string]int {
	return map[string]int{
		"rce_patterns":            len(h.rcePatterns),
		"ssti_patterns":           len(h.sstiPatterns),
		"deserialization_patterns": len(h.deserializationPatterns),
		"file_inclusion_patterns": len(h.fileInclusionPatterns),
	}
}
