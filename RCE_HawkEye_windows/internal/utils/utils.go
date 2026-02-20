package utils

import (
	"crypto/md5"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func CalculateHash(data string) string {
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func ExtractParameters(rawURL string) map[string]string {
	params := make(map[string]string)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return params
	}

	for key, values := range parsed.Query() {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}
	return params
}

func BuildURL(baseURL string, params map[string]string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}

	query := parsed.Query()
	for k, v := range params {
		query.Set(k, v)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func IsValidURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return parsed.Scheme == "http" || parsed.Scheme == "https"
}

var domainPattern = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$`)
var ipv4Pattern = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
var ipv6Pattern = regexp.MustCompile(`^\[?[0-9a-fA-F:]+\]?$`)

func IsValidDomain(domain string) bool {
	return domainPattern.MatchString(domain)
}

func IsValidIP(ip string) bool {
	if ipv4Pattern.MatchString(ip) {
		parts := strings.Split(ip, ".")
		for _, part := range parts {
			num := 0
			for _, c := range part {
				num = num*10 + int(c-'0')
			}
			if num < 0 || num > 255 {
				return false
			}
		}
		return true
	}
	return ipv6Pattern.MatchString(ip)
}

func NormalizeTarget(target string) string {
	target = strings.TrimSpace(target)
	target = strings.TrimSuffix(target, "/")

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}

	if strings.HasPrefix(target, "//") {
		return "https:" + target
	}

	var port string
	var path string
	var hasPort bool

	if strings.Contains(target, "/") {
		parts := strings.SplitN(target, "/", 2)
		target = parts[0]
		if len(parts) > 1 {
			path = "/" + parts[1]
		}
	}

	if strings.Contains(target, ":") && !strings.HasPrefix(target, "[") {
		if strings.Count(target, ":") == 1 {
			idx := strings.LastIndex(target, ":")
			portPart := target[idx+1:]
			isPort := true
			for _, c := range portPart {
				if c < '0' || c > '9' {
					isPort = false
					break
				}
			}
			if isPort {
				port = portPart
				target = target[:idx]
				hasPort = true
			}
		}
	}

	if IsValidIP(target) || IsValidDomain(target) {
		if port != "" {
			scheme := "http"
			if port == "443" || port == "8443" {
				scheme = "https"
			}
			return scheme + "://" + target + ":" + port + path
		}
		return "http://" + target + path
	}

	if hasPort && port != "" {
		scheme := "http"
		if port == "443" || port == "8443" {
			scheme = "https"
		}
		return scheme + "://" + target + ":" + port + path
	}

	return target
}

func NormalizeTargetWithScheme(target string, preferHTTPS bool) string {
	target = strings.TrimSpace(target)
	target = strings.TrimSuffix(target, "/")

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}

	if strings.HasPrefix(target, "//") {
		if preferHTTPS {
			return "https:" + target
		}
		return "http:" + target
	}

	var port string
	var path string

	if strings.Contains(target, "/") {
		parts := strings.SplitN(target, "/", 2)
		target = parts[0]
		if len(parts) > 1 {
			path = "/" + parts[1]
		}
	}

	if strings.Contains(target, ":") && !strings.HasPrefix(target, "[") {
		if strings.Count(target, ":") == 1 {
			idx := strings.LastIndex(target, ":")
			portPart := target[idx+1:]
			isPort := true
			for _, c := range portPart {
				if c < '0' || c > '9' {
					isPort = false
					break
				}
			}
			if isPort {
				port = portPart
				target = target[:idx]
			}
		}
	}

	scheme := "http"
	if preferHTTPS {
		scheme = "https"
	}
	if port == "443" || port == "8443" {
		scheme = "https"
	}

	if IsValidIP(target) || IsValidDomain(target) {
		if port != "" {
			return scheme + "://" + target + ":" + port + path
		}
		return scheme + "://" + target + path
	}

	return target
}

func DetectHTTPS(target string) bool {
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	
	if parsed.Scheme == "https" {
		return true
	}
	
	port := parsed.Port()
	if port == "443" || port == "8443" {
		return true
	}
	
	return false
}

func ParseTarget(target string) map[string]interface{} {
	target = NormalizeTarget(target)
	parsed, err := url.Parse(target)
	if err != nil {
		return map[string]interface{}{
			"url":  target,
			"error": "invalid url",
		}
	}

	host := parsed.Hostname()
	port := parsed.Port()

	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	return map[string]interface{}{
		"url":       target,
		"scheme":    parsed.Scheme,
		"host":      host,
		"port":      port,
		"path":      parsed.Path,
		"is_ip":     IsValidIP(host),
		"is_domain": IsValidDomain(host),
	}
}

func SanitizeInput(data string) string {
	re := regexp.MustCompile(`[\x00-\x1f\x7f-\x9f]`)
	return re.ReplaceAllString(data, "")
}

func GetRiskLevel(severity string) string {
	riskMap := map[string]string{
		"critical": "严重",
		"high":     "高危",
		"medium":   "中危",
		"low":      "低危",
		"info":     "信息",
	}
	if v, ok := riskMap[strings.ToLower(severity)]; ok {
		return v
	}
	return "未知"
}

func SeverityToCN(severity string) string {
	severityMap := map[string]string{
		"critical": "严重",
		"high":     "高危",
		"medium":   "中危",
		"low":      "低危",
		"info":     "信息",
	}
	if v, ok := severityMap[strings.ToLower(severity)]; ok {
		return v
	}
	return "未知"
}

func SeverityToColor(severity string) string {
	colorMap := map[string]string{
		"critical": "#d32f2f",
		"high":     "#f57c00",
		"medium":   "#fbc02d",
		"low":      "#388e3c",
		"info":     "#1976d2",
	}
	if v, ok := colorMap[strings.ToLower(severity)]; ok {
		return v
	}
	return "#757575"
}

func FormatTimestamp(ts float64) string {
	return time.Unix(int64(ts), 0).Format("2006-01-02 15:04:05")
}

func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
