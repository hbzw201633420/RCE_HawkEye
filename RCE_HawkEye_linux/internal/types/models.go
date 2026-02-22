package types

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type Payload struct {
	Content        string      `json:"content"`
	PayloadType    PayloadType `json:"payload_type"`
	OSType         OSType      `json:"os_type"`
	Description    string      `json:"description"`
	TechType       TechType    `json:"tech_type,omitempty"`
	ExpectedDelay  float64     `json:"expected_delay,omitempty"`
	ExpectedOutput string      `json:"expected_output,omitempty"`
	Encoded        bool        `json:"encoded"`
	IsHarmless     bool        `json:"is_harmless"`
	SecondaryParam string      `json:"secondary_param,omitempty"`
	SecondaryValue string      `json:"secondary_value,omitempty"`
}

type Vulnerability struct {
	Target       string                 `json:"target"`
	Parameter    string                 `json:"parameter"`
	Payload      string                 `json:"payload"`
	PayloadType  string                 `json:"payload_type"`
	Severity     Severity               `json:"severity"`
	Description  string                 `json:"description"`
	Evidence     string                 `json:"evidence"`
	Exploitation string                 `json:"exploitation"`
	Remediation  string                 `json:"remediation"`
	RequestData  map[string]interface{} `json:"request_data"`
	ResponseData map[string]interface{} `json:"response_data"`
	Timestamp    float64                `json:"timestamp"`
}

type ScanTarget struct {
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	Parameters map[string]string `json:"parameters"`
	Headers    map[string]string `json:"headers"`
	Cookies    map[string]string `json:"cookies"`
	Data       map[string]string `json:"data"`
}

type ScanResult struct {
	Target          string           `json:"target"`
	Vulnerabilities []Vulnerability  `json:"vulnerabilities"`
	TotalRequests   int              `json:"total_requests"`
	ScanTime        float64          `json:"scan_time"`
	Error           string           `json:"error,omitempty"`
}

type BaselineResponse struct {
	Content       string            `json:"content"`
	StatusCode    int               `json:"status_code"`
	ContentLength int               `json:"content_length"`
	Elapsed       float64           `json:"elapsed"`
	Headers       map[string]string `json:"headers"`
}

type CrawledPage struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Content    string            `json:"content"`
	Links      []string          `json:"links"`
	Forms      []map[string]interface{} `json:"forms"`
	Parameters map[string]string `json:"parameters"`
}

type FormInfo struct {
	Action string            `json:"action"`
	Method string            `json:"method"`
	Inputs map[string]string `json:"inputs"`
}

type DirResult struct {
	URL           string   `json:"url"`
	StatusCode    int      `json:"status_code"`
	ContentLength int      `json:"content_length"`
	Redirect      string   `json:"redirect,omitempty"`
	Title         string   `json:"title,omitempty"`
	ContentType   string   `json:"content_type,omitempty"`
	TechStack     []string `json:"tech_stack,omitempty"`
	WebServer     string   `json:"web_server,omitempty"`
}

type HttpRequest struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Version    string            `json:"version"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	RawRequest string            `json:"raw_request"`
}

func (r *HttpRequest) GetURL(defaultHost, defaultScheme string) string {
	host := r.Headers["Host"]
	if host == "" {
		host = defaultHost
	}
	scheme := defaultScheme
	return fmt.Sprintf("%s://%s%s", scheme, host, r.Path)
}

func (r *HttpRequest) GetParameters() map[string]string {
	params := make(map[string]string)

	parsed, err := url.Parse(r.Path)
	if err == nil && parsed.RawQuery != "" {
		for key, values := range parsed.Query() {
			if len(values) > 0 {
				params[key] = values[0]
			}
		}
	}

	if r.Body != "" && strings.ToUpper(r.Method) == "POST" {
		contentType := strings.ToLower(r.Headers["Content-Type"])

		if strings.Contains(contentType, "application/x-www-form-urlencoded") {
			bodyParams, err := url.ParseQuery(r.Body)
			if err == nil {
				for key, values := range bodyParams {
					if len(values) > 0 {
						params[key] = values[0]
					}
				}
			}
		} else if strings.Contains(contentType, "application/json") {
			var jsonData map[string]interface{}
			if err := json.Unmarshal([]byte(r.Body), &jsonData); err == nil {
				flattened := r.flattenJSON(jsonData, "")
				for k, v := range flattened {
					params[k] = v
				}
			}
		}
	}

	return params
}

func (r *HttpRequest) flattenJSON(data map[string]interface{}, prefix string) map[string]string {
	params := make(map[string]string)

	for key, value := range data {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := value.(type) {
		case map[string]interface{}:
			nested := r.flattenJSON(v, fullKey)
			for k, val := range nested {
				params[k] = val
			}
		case []interface{}:
			for i, item := range v {
				if _, ok := item.(map[string]interface{}); !ok {
					if _, ok := item.([]interface{}); !ok {
						params[fmt.Sprintf("%s[%d]", fullKey, i)] = fmt.Sprintf("%v", item)
					}
				}
			}
		default:
			params[fullKey] = fmt.Sprintf("%v", value)
		}
	}

	return params
}

type DetectedTech struct {
	TechStack      TechType `json:"tech_stack"`
	Confidence     float64  `json:"confidence"`
	Evidence       []string `json:"evidence"`
	FileExtensions []string `json:"file_extensions"`
}

type BypassPayload struct {
	Original   string        `json:"original"`
	Payload    string        `json:"payload"`
	Technique  WAFTechnique  `json:"technique"`
	Description string       `json:"description"`
	TargetWAF  []string      `json:"target_waf"`
}

type HeuristicResult struct {
	Injectable    bool          `json:"injectable"`
	InjectionType InjectionType `json:"injection_type"`
	Confidence    float64       `json:"confidence"`
	Evidence      string        `json:"evidence"`
	Parameter     string        `json:"parameter"`
	Payload       string        `json:"payload"`
}

type ParamSource struct {
	URL        string `json:"url"`
	Method     string `json:"method"`
	ParamName  string `json:"param_name"`
	ParamValue string `json:"param_value"`
	SourceType string `json:"source_type"`
}

type ScanConfig struct {
	Timeout         int               `json:"timeout"`
	MaxConcurrent   int               `json:"max_concurrent"`
	DelayThreshold  float64           `json:"delay_threshold"`
	MaxRetries      int               `json:"max_retries"`
	UserAgent       string            `json:"user_agent"`
	Proxy           string            `json:"proxy,omitempty"`
	VerifySSL       bool              `json:"verify_ssl"`
	ScanLevel       ScanLevel         `json:"scan_level"`
	ScanMode        ScanMode          `json:"scan_mode"`
}

type CrawlerConfig struct {
	MaxDepth     int    `json:"max_depth"`
	MaxPages     int    `json:"max_pages"`
	Timeout      int    `json:"timeout"`
	Concurrent   int    `json:"concurrent"`
	UserAgent    string `json:"user_agent"`
}

type DirScanConfig struct {
	Threads        int      `json:"threads"`
	Timeout        int      `json:"timeout"`
	Extensions     []string `json:"extensions"`
	StatusCodes    []int    `json:"status_codes"`
	ExcludeCodes   []int    `json:"exclude_codes"`
	Wordlist       string   `json:"wordlist,omitempty"`
	MaxDepth       int      `json:"max_depth"`
	Recursive      bool     `json:"recursive"`
	FollowRedirects bool    `json:"follow_redirects"`
	UserAgent      string   `json:"user_agent"`
}

type ParamConfig struct {
	Threads         int    `json:"threads"`
	Timeout         int    `json:"timeout"`
	MaxDepth        int    `json:"max_depth"`
	MaxPages        int    `json:"max_pages"`
	UserAgent       string `json:"user_agent"`
	ParamWordlist   string `json:"param_wordlist,omitempty"`
	FuzzParams      bool   `json:"fuzz_params"`
	ExtractFromJS   bool   `json:"extract_from_js"`
	ExtractFromHTML bool   `json:"extract_from_html"`
}

type DomainConfig struct {
	AllowedDomains    []string `json:"allowed_domains"`
	BlockedDomains    []string `json:"blocked_domains"`
	RestrictToRoot    bool     `json:"restrict_to_root"`
	MaxDepth          int      `json:"max_depth"`
	MaxPages          int      `json:"max_pages"`
	ExcludeExtensions []string `json:"exclude_extensions"`
}

type ReportInfo struct {
	ReportTime     time.Time              `json:"report_time"`
	ScanInfo       map[string]interface{} `json:"scan_info"`
	Summary        ReportSummary          `json:"summary"`
	Vulnerabilities []Vulnerability       `json:"vulnerabilities"`
}

type ReportSummary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
}
