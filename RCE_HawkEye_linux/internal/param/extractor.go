package param

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
	"github.com/hbzw/RCE_HawkEye_go/internal/utils"
)

type ParamExtractor struct {
	threads       int
	timeout       int
	maxDepth      int
	maxPages      int
	userAgent     string
	paramWordlist []string
	fuzzParams    bool
	extractFromJS bool
	extractFromHTML bool
	client        *http.Client
	params        map[string][]types.ParamSource
	paramsMutex   sync.Mutex
	visited       map[string]bool
	visitedMutex  sync.Mutex
}

type ParamOption func(*ParamExtractor)

func WithThreads(threads int) ParamOption {
	return func(p *ParamExtractor) {
		p.threads = threads
	}
}

func WithTimeout(timeout int) ParamOption {
	return func(p *ParamExtractor) {
		p.timeout = timeout
	}
}

func WithMaxDepth(depth int) ParamOption {
	return func(p *ParamExtractor) {
		p.maxDepth = depth
	}
}

func WithMaxPages(pages int) ParamOption {
	return func(p *ParamExtractor) {
		p.maxPages = pages
	}
}

func WithUserAgent(ua string) ParamOption {
	return func(p *ParamExtractor) {
		p.userAgent = ua
	}
}

func WithParamWordlistFile(filepath string) ParamOption {
	return func(p *ParamExtractor) {
		if filepath != "" {
			p.paramWordlist = loadParamWordlist(filepath)
		}
	}
}

func WithFuzzParams(fuzz bool) ParamOption {
	return func(p *ParamExtractor) {
		p.fuzzParams = fuzz
	}
}

func WithExtractFromJS(extract bool) ParamOption {
	return func(p *ParamExtractor) {
		p.extractFromJS = extract
	}
}

func WithExtractFromHTML(extract bool) ParamOption {
	return func(p *ParamExtractor) {
		p.extractFromHTML = extract
	}
}

func NewParamExtractor(opts ...ParamOption) *ParamExtractor {
	p := &ParamExtractor{
		threads:        10,
		timeout:        10,
		maxDepth:       2,
		maxPages:       100,
		userAgent:      "RCE-HawkEye/1.1.0",
		paramWordlist:  getDefaultParamWordlist(),
		fuzzParams:     false,
		extractFromJS:  true,
		extractFromHTML: true,
		params:         make(map[string][]types.ParamSource),
		visited:        make(map[string]bool),
	}

	for _, opt := range opts {
		opt(p)
	}

	p.client = &http.Client{
		Timeout: time.Duration(p.timeout) * time.Second,
	}

	return p
}

func getDefaultParamWordlist() []string {
	return []string{
		"id", "ID", "Id", "iD",
		"file", "File", "FILE", "path", "Path", "PATH",
		"page", "Page", "PAGE", "p", "pg",
		"url", "URL", "Url", "link", "Link", "LINK",
		"cmd", "CMD", "Cmd", "command", "Command", "COMMAND",
		"exec", "Exec", "EXEC", "execute", "Execute",
		"action", "Action", "ACTION", "a", "act",
		"query", "Query", "QUERY", "q", "search", "Search",
		"code", "Code", "CODE", "c",
		"data", "Data", "DATA", "d",
		"input", "Input", "INPUT", "in",
		"output", "Output", "OUTPUT", "out",
		"debug", "Debug", "DEBUG", "dbg",
		"test", "Test", "TEST", "t",
		"callback", "Callback", "CALLBACK", "cb",
		"redirect", "Redirect", "REDIRECT", "redir", "r",
		"return", "Return", "RETURN", "ret",
		"next", "Next", "NEXT", "n",
		"dest", "Dest", "DEST", "destination", "Destination",
		"src", "Src", "SRC", "source", "Source",
		"load", "Load", "LOAD", "include", "Include", "INCLUDE",
		"template", "Template", "TEMPLATE", "tpl", "view", "View",
		"lang", "Lang", "LANG", "language", "Language", "locale",
		"format", "Format", "FORMAT", "fmt",
		"type", "Type", "TYPE",
		"name", "Name", "NAME",
		"value", "Value", "VALUE", "val",
		"key", "Key", "KEY", "k",
		"token", "Token", "TOKEN",
		"session", "Session", "SESSION", "sess",
		"user", "User", "USER", "u", "username", "Username",
		"pass", "Pass", "PASS", "password", "Password", "pwd",
		"email", "Email", "EMAIL", "mail",
		"phone", "Phone", "PHONE", "tel", "mobile",
		"address", "Address", "ADDRESS", "addr",
		"date", "Date", "DATE",
		"time", "Time", "TIME",
		"start", "Start", "START",
		"end", "End", "END",
		"from", "From", "FROM",
		"to", "To", "TO",
		"limit", "Limit", "LIMIT",
		"offset", "Offset", "OFFSET",
		"sort", "Sort", "SORT",
		"order", "Order", "ORDER",
		"filter", "Filter", "FILTER",
		"category", "Category", "CATEGORY", "cat",
		"tag", "Tag", "TAG",
		"status", "Status", "STATUS",
		"state", "State", "STATE",
		"mode", "Mode", "MODE",
		"option", "Option", "OPTION", "opt",
		"setting", "Setting", "SETTING",
		"config", "Config", "CONFIG", "cfg",
		"param", "Param", "PARAM",
		"arg", "Arg", "ARG", "argument",
		"var", "Var", "VAR", "variable",
	}
}

func loadParamWordlist(filepath string) []string {
	file, err := os.Open(filepath)
	if err != nil {
		return getDefaultParamWordlist()
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	if len(words) == 0 {
		return getDefaultParamWordlist()
	}

	return words
}

func (p *ParamExtractor) Extract(ctx context.Context, targetURL string) (map[string][]types.ParamSource, error) {
	normalizedURL := utils.NormalizeTarget(targetURL)

	p.extractFromURL(ctx, normalizedURL)

	return p.params, nil
}

func (p *ParamExtractor) extractFromURL(ctx context.Context, pageURL string) {
	p.visitedMutex.Lock()
	if p.visited[pageURL] {
		p.visitedMutex.Unlock()
		return
	}

	if len(p.visited) >= p.maxPages {
		p.visitedMutex.Unlock()
		return
	}

	p.visited[pageURL] = true
	p.visitedMutex.Unlock()

	parsed, err := url.Parse(pageURL)
	if err != nil {
		return
	}

	for key, values := range parsed.Query() {
		if len(values) > 0 {
			p.addParam(key, values[0], pageURL, "GET", "url_query")
		}
	}

	content, statusCode := p.fetchContent(ctx, pageURL)
	if content == "" || statusCode >= 400 {
		return
	}

	if p.extractFromHTML {
		p.extractFromHTMLContent(pageURL, content)
	}

	if p.extractFromJS {
		p.extractFromJSContent(pageURL, content)
	}
}

func (p *ParamExtractor) fetchContent(ctx context.Context, pageURL string) (string, int) {
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return "", 0
	}

	req.Header.Set("User-Agent", p.userAgent)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode
	}

	return string(body), resp.StatusCode
}

func (p *ParamExtractor) extractFromHTMLContent(pageURL, content string) {
	formPattern := regexp.MustCompile(`(?i)<form[^>]*>(.*?)</form>`)
	inputPattern := regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']+)["'][^>]*(?:value=["']([^"']*)["'])?`)

	formMatches := formPattern.FindAllStringSubmatch(content, -1)
	for _, formMatch := range formMatches {
		formHTML := formMatch[0]

		method := "GET"
		methodMatch := regexp.MustCompile(`(?i)method=["']([^"']+)["']`).FindStringSubmatch(formHTML)
		if len(methodMatch) > 1 {
			method = strings.ToUpper(methodMatch[1])
		}

		inputMatches := inputPattern.FindAllStringSubmatch(formHTML, -1)
		for _, inputMatch := range inputMatches {
			if len(inputMatch) > 1 {
				name := inputMatch[1]
				value := ""
				if len(inputMatch) > 2 {
					value = inputMatch[2]
				}
				p.addParam(name, value, pageURL, method, "form_input")
			}
		}
	}

	linkPattern := regexp.MustCompile(`(?i)<a[^>]*href=["']([^"']+)["']`)
	linkMatches := linkPattern.FindAllStringSubmatch(content, -1)
	for _, linkMatch := range linkMatches {
		if len(linkMatch) > 1 {
			linkURL := linkMatch[1]
			if strings.Contains(linkURL, "?") {
				if idx := strings.Index(linkURL, "?"); idx != -1 {
					queryString := linkURL[idx+1:]
					params := strings.Split(queryString, "&")
					for _, param := range params {
						if idx := strings.Index(param, "="); idx != -1 {
							name := param[:idx]
							value := ""
							if idx+1 < len(param) {
								value = param[idx+1:]
							}
							p.addParam(name, value, pageURL, "GET", "link_param")
						}
					}
				}
			}
		}
	}

	metaPattern := regexp.MustCompile(`(?i)<meta[^>]*content=["']([^"']+)["']`)
	metaMatches := metaPattern.FindAllStringSubmatch(content, -1)
	for _, metaMatch := range metaMatches {
		if len(metaMatch) > 1 {
			content := metaMatch[1]
			if strings.Contains(content, "=") {
				params := strings.Split(content, "&")
				for _, param := range params {
					if idx := strings.Index(param, "="); idx != -1 {
						name := param[:idx]
						if len(name) > 0 && len(name) < 50 {
							value := ""
							if idx+1 < len(param) {
								value = param[idx+1:]
							}
							p.addParam(name, value, pageURL, "GET", "meta_content")
						}
					}
				}
			}
		}
	}
}

func (p *ParamExtractor) extractFromJSContent(pageURL, content string) {
	jsPatterns := []struct {
		pattern string
		source  string
	}{
		{`(?i)\.get\(["']([^"']+)["']\)`, "js_get"},
		{`(?i)\.post\(["']([^"']+)["']\)`, "js_post"},
		{`(?i)\.ajax\(\s*\{[^}]*url\s*:\s*["']([^"']+)["']`, "js_ajax"},
		{`(?i)fetch\(["']([^"']+)["']\)`, "js_fetch"},
		{`(?i)var\s+(\w+)\s*=\s*["']([^"']+)["']`, "js_variable"},
		{`(?i)const\s+(\w+)\s*=\s*["']([^"']+)["']`, "js_const"},
		{`(?i)let\s+(\w+)\s*=\s*["']([^"']+)["']`, "js_let"},
		{`(?i)localStorage\.setItem\(["']([^"']+)["']`, "js_localStorage"},
		{`(?i)sessionStorage\.setItem\(["']([^"']+)["']`, "js_sessionStorage"},
	}

	for _, jp := range jsPatterns {
		re := regexp.MustCompile(jp.pattern)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				if strings.Contains(match[1], "=") {
					if idx := strings.Index(match[1], "?"); idx != -1 {
						queryString := match[1][idx+1:]
						params := strings.Split(queryString, "&")
						for _, param := range params {
							if idx := strings.Index(param, "="); idx != -1 {
								name := param[:idx]
								value := ""
								if idx+1 < len(param) {
									value = param[idx+1:]
								}
								p.addParam(name, value, pageURL, "GET", jp.source)
							}
						}
					}
				}

				if len(match) > 2 {
					name := match[1]
					value := match[2]
					if len(name) > 0 && len(name) < 50 {
						p.addParam(name, value, pageURL, "GET", jp.source)
					}
				}
			}
		}
	}

	apiURLPattern := regexp.MustCompile(`["']/api/[^"']+["']`)
	apiMatches := apiURLPattern.FindAllString(content, -1)
	for _, apiURL := range apiMatches {
		apiURL = strings.Trim(apiURL, `"'`)
		if strings.Contains(apiURL, "?") {
			if idx := strings.Index(apiURL, "?"); idx != -1 {
				queryString := apiURL[idx+1:]
				params := strings.Split(queryString, "&")
				for _, param := range params {
					if idx := strings.Index(param, "="); idx != -1 {
						name := param[:idx]
						value := ""
						if idx+1 < len(param) {
							value = param[idx+1:]
						}
						p.addParam(name, value, pageURL, "GET", "js_api_url")
					}
				}
			}
		}
	}
}

func (p *ParamExtractor) addParam(name, value, urlStr, method, sourceType string) {
	p.paramsMutex.Lock()
	defer p.paramsMutex.Unlock()

	paramSource := types.ParamSource{
		URL:        urlStr,
		Method:     method,
		ParamName:  name,
		ParamValue: value,
		SourceType: sourceType,
	}

	if _, exists := p.params[name]; !exists {
		p.params[name] = make([]types.ParamSource, 0)
	}

	for _, existing := range p.params[name] {
		if existing.URL == urlStr && existing.Method == method && existing.SourceType == sourceType {
			return
		}
	}

	p.params[name] = append(p.params[name], paramSource)
}

func (p *ParamExtractor) FuzzParams(ctx context.Context, targetURL string) map[string][]types.ParamSource {
	if !p.fuzzParams {
		return p.params
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return p.params
	}

	baseURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, parsed.Path)

	for _, paramName := range p.paramWordlist {
		testURL := baseURL + "?" + paramName + "=test"

		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", p.userAgent)

		resp, err := p.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 404 {
			p.addParam(paramName, "test", baseURL, "GET", "fuzz")
		}
	}

	return p.params
}

func (p *ParamExtractor) GetParams() map[string][]types.ParamSource {
	return p.params
}

func (p *ParamExtractor) GetUniqueParamNames() []string {
	var names []string
	for name := range p.params {
		names = append(names, name)
	}
	return names
}

func (p *ParamExtractor) GetHighPriorityParams() []string {
	highPriority := []string{
		"cmd", "command", "exec", "execute", "system", "shell",
		"file", "path", "page", "url", "link", "redirect",
		"action", "code", "eval", "data", "input",
		"template", "view", "include", "load",
	}

	var result []string
	for _, name := range p.GetUniqueParamNames() {
		nameLower := strings.ToLower(name)
		for _, priority := range highPriority {
			if strings.Contains(nameLower, priority) {
				result = append(result, name)
				break
			}
		}
	}
	return result
}

func (p *ParamExtractor) GetStatistics() map[string]int {
	stats := map[string]int{
		"total_params": len(p.params),
	}

	sourceCounts := make(map[string]int)
	for _, sources := range p.params {
		for _, source := range sources {
			sourceCounts[source.SourceType]++
		}
	}

	for source, count := range sourceCounts {
		stats["source_"+source] = count
	}

	return stats
}
