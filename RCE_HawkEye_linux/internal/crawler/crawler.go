package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
	"github.com/hbzw/RCE_HawkEye_go/internal/utils"
)

type Crawler struct {
	maxDepth     int
	maxPages     int
	timeout      int
	concurrent   int
	userAgent    string
	client       *http.Client
	visited      map[string]bool
	visitedMutex sync.Mutex
	results      []types.CrawledPage
	resultsMutex sync.Mutex
	allowedDomains []string
	blockedDomains []string
	restrictRoot bool
	rootDomain   string
}

type CrawlerOption func(*Crawler)

func WithMaxDepth(depth int) CrawlerOption {
	return func(c *Crawler) {
		c.maxDepth = depth
	}
}

func WithMaxPages(pages int) CrawlerOption {
	return func(c *Crawler) {
		c.maxPages = pages
	}
}

func WithTimeout(timeout int) CrawlerOption {
	return func(c *Crawler) {
		c.timeout = timeout
	}
}

func WithConcurrent(concurrent int) CrawlerOption {
	return func(c *Crawler) {
		c.concurrent = concurrent
	}
}

func WithUserAgent(ua string) CrawlerOption {
	return func(c *Crawler) {
		c.userAgent = ua
	}
}

func WithAllowedDomains(domains []string) CrawlerOption {
	return func(c *Crawler) {
		c.allowedDomains = domains
	}
}

func WithBlockedDomains(domains []string) CrawlerOption {
	return func(c *Crawler) {
		c.blockedDomains = domains
	}
}

func WithRestrictRoot(restrict bool) CrawlerOption {
	return func(c *Crawler) {
		c.restrictRoot = restrict
	}
}

func NewCrawler(opts ...CrawlerOption) *Crawler {
	c := &Crawler{
		maxDepth:     2,
		maxPages:     100,
		timeout:      10,
		concurrent:   5,
		userAgent:    "RCE-HawkEye/1.1.0",
		visited:      make(map[string]bool),
		results:      make([]types.CrawledPage, 0),
		allowedDomains: make([]string, 0),
		blockedDomains: make([]string, 0),
		restrictRoot: true,
	}

	for _, opt := range opts {
		opt(c)
	}

	c.client = &http.Client{
		Timeout: time.Duration(c.timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return c
}

func (c *Crawler) Crawl(ctx context.Context, startURL string) ([]types.CrawledPage, error) {
	normalizedURL := utils.NormalizeTarget(startURL)

	parsed, err := url.Parse(normalizedURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	c.rootDomain = parsed.Hostname()

	if len(c.allowedDomains) == 0 && c.restrictRoot {
		c.allowedDomains = []string{c.rootDomain}
	}

	c.crawlPage(ctx, normalizedURL, 0)

	return c.results, nil
}

func (c *Crawler) crawlPage(ctx context.Context, pageURL string, depth int) {
	c.visitedMutex.Lock()
	if c.visited[pageURL] {
		c.visitedMutex.Unlock()
		return
	}

	if len(c.visited) >= c.maxPages {
		c.visitedMutex.Unlock()
		return
	}

	c.visited[pageURL] = true
	c.visitedMutex.Unlock()

	if depth > c.maxDepth {
		return
	}

	page, links := c.fetchPage(ctx, pageURL)
	if page == nil {
		return
	}

	c.resultsMutex.Lock()
	c.results = append(c.results, *page)
	c.resultsMutex.Unlock()

	for _, link := range links {
		if c.isAllowedDomain(link) {
			go c.crawlPage(ctx, link, depth+1)
		}
	}
}

func (c *Crawler) fetchPage(ctx context.Context, pageURL string) (*types.CrawledPage, []string) {
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return nil, nil
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, nil
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "application/xhtml+xml") {
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil
	}

	content := string(body)
	links := c.extractLinks(pageURL, content)
	forms := c.extractForms(content)
	params := c.extractParameters(pageURL, content)

	page := &types.CrawledPage{
		URL:        pageURL,
		StatusCode: resp.StatusCode,
		Content:    content,
		Links:      links,
		Forms:      forms,
		Parameters: params,
	}

	return page, links
}

func (c *Crawler) extractLinks(baseURL, content string) []string {
	var links []string
	seen := make(map[string]bool)

	linkPatterns := []string{
		`href=["']([^"']+)["']`,
		`src=["']([^"']+)["']`,
		`action=["']([^"']+)["']`,
	}

	for _, pattern := range linkPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1)

		for _, match := range matches {
			if len(match) > 1 {
				link := match[1]
				absoluteURL := c.resolveURL(baseURL, link)

				if absoluteURL != "" && !seen[absoluteURL] && c.isValidLink(absoluteURL) {
					seen[absoluteURL] = true
					links = append(links, absoluteURL)
				}
			}
		}
	}

	return links
}

func (c *Crawler) extractForms(content string) []map[string]interface{} {
	var forms []map[string]interface{}

	formPattern := regexp.MustCompile(`(?i)<form[^>]*>(.*?)</form>`)
	inputPattern := regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']+)["'][^>]*(?:value=["']([^"']*)["'])?`)

	formMatches := formPattern.FindAllStringSubmatch(content, -1)
	for _, formMatch := range formMatches {
		formHTML := formMatch[0]

		form := map[string]interface{}{
			"action": "",
			"method": "GET",
			"inputs": make(map[string]string),
		}

		actionMatch := regexp.MustCompile(`(?i)action=["']([^"']*)["']`).FindStringSubmatch(formHTML)
		if len(actionMatch) > 1 {
			form["action"] = actionMatch[1]
		}

		methodMatch := regexp.MustCompile(`(?i)method=["']([^"']*)["']`).FindStringSubmatch(formHTML)
		if len(methodMatch) > 1 {
			form["method"] = strings.ToUpper(methodMatch[1])
		}

		inputMatches := inputPattern.FindAllStringSubmatch(formHTML, -1)
		inputs := make(map[string]string)
		for _, inputMatch := range inputMatches {
			if len(inputMatch) > 1 {
				name := inputMatch[1]
				value := ""
				if len(inputMatch) > 2 {
					value = inputMatch[2]
				}
				inputs[name] = value
			}
		}
		form["inputs"] = inputs

		forms = append(forms, form)
	}

	return forms
}

func (c *Crawler) extractParameters(pageURL, content string) map[string]string {
	params := make(map[string]string)

	parsed, err := url.Parse(pageURL)
	if err == nil {
		for key, values := range parsed.Query() {
			if len(values) > 0 {
				params[key] = values[0]
			}
		}
	}

	paramPatterns := []string{
		`var\s+(\w+)\s*=\s*["']([^"']+)["']`,
		`const\s+(\w+)\s*=\s*["']([^"']+)["']`,
		`let\s+(\w+)\s*=\s*["']([^"']+)["']`,
	}

	for _, pattern := range paramPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 2 {
				params[match[1]] = match[2]
			}
		}
	}

	apiPatterns := []string{
		`url\s*:\s*["']([^"']+)["']`,
		`endpoint\s*:\s*["']([^"']+)["']`,
		`api\s*:\s*["']([^"']+)["']`,
		`fetch\s*\(\s*["']([^"']+)["']`,
		`axios\s*\.\s*\w+\s*\(\s*["']([^"']+)["']`,
		`\$\.(?:get|post|ajax)\s*\(\s*["']([^"']+)["']`,
		`XMLHttpRequest.*open\s*\(\s*["'][^"']*["']\s*,\s*["']([^"']+)["']`,
	}
	
	for _, pattern := range apiPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 && strings.Contains(match[1], "?") {
				apiURL := match[1]
				if parsed, err := url.Parse(apiURL); err == nil {
					for key, values := range parsed.Query() {
						if len(values) > 0 {
							params[key] = values[0]
						}
					}
				}
			}
		}
	}

	dataAttrPattern := `data-[\w-]+\s*=\s*["']([^"']+)["']`
	re := regexp.MustCompile(dataAttrPattern)
	matches := re.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 && len(match[1]) > 0 && len(match[1]) < 100 {
			params["data_attr"] = match[1]
		}
	}

	ajaxPatterns := []string{
		`type\s*:\s*["'](POST|GET|PUT|DELETE)["']`,
		`method\s*:\s*["'](POST|GET|PUT|DELETE)["']`,
	}
	
	for _, pattern := range ajaxPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(content) {
			params["_ajax_method"] = "detected"
			break
		}
	}

	jsonPattern := `["'](\w+)["']\s*:\s*["']([^"']+)["']`
	re = regexp.MustCompile(jsonPattern)
	matches = re.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 2 && len(match[2]) > 0 && len(match[2]) < 100 {
			key := match[1]
			if !strings.HasPrefix(key, "_") && !strings.Contains(key, "token") {
				params[key] = match[2]
			}
		}
	}

	hiddenInputPattern := `<input[^>]*type=["']hidden["'][^>]*name=["'](\w+)["'][^>]*value=["']([^"']*)["']`
	re = regexp.MustCompile(hiddenInputPattern)
	matches = re.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 2 {
			params[match[1]] = match[2]
		}
	}

	textareaPattern := `<textarea[^>]*name=["'](\w+)["'][^>]*>([^<]*)</textarea>`
	re = regexp.MustCompile(textareaPattern)
	matches = re.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 2 {
			params[match[1]] = match[2]
		}
	}

	selectPattern := `<select[^>]*name=["'](\w+)["']`
	re = regexp.MustCompile(selectPattern)
	matches = re.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params[match[1]] = ""
		}
	}

	return params
}

func (c *Crawler) resolveURL(baseURL, link string) string {
	if link == "" {
		return ""
	}

	link = strings.TrimSpace(link)

	if strings.HasPrefix(link, "#") ||
		strings.HasPrefix(link, "javascript:") ||
		strings.HasPrefix(link, "mailto:") ||
		strings.HasPrefix(link, "tel:") ||
		strings.HasPrefix(link, "data:") {
		return ""
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	ref, err := url.Parse(link)
	if err != nil {
		return ""
	}

	resolved := base.ResolveReference(ref)

	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}

	return resolved.String()
}

func (c *Crawler) isValidLink(link string) bool {
	excludedExtensions := []string{
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico",
		".css", ".woff", ".woff2", ".ttf", ".eot",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".zip", ".rar", ".tar", ".gz", ".7z",
		".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",
		".xml", ".json", ".rss", ".atom",
	}

	linkLower := strings.ToLower(link)
	for _, ext := range excludedExtensions {
		if strings.HasSuffix(linkLower, ext) {
			return false
		}
	}

	return true
}

func (c *Crawler) isAllowedDomain(link string) bool {
	parsed, err := url.Parse(link)
	if err != nil {
		return false
	}

	domain := parsed.Hostname()

	for _, blocked := range c.blockedDomains {
		if domain == blocked || strings.HasSuffix(domain, "."+blocked) {
			return false
		}
	}

	if len(c.allowedDomains) == 0 {
		return true
	}

	for _, allowed := range c.allowedDomains {
		if domain == allowed || strings.HasSuffix(domain, "."+allowed) {
			return true
		}
	}

	return false
}

func (c *Crawler) GetResults() []types.CrawledPage {
	return c.results
}

func (c *Crawler) GetAllURLs() []string {
	var urls []string
	for _, page := range c.results {
		urls = append(urls, page.URL)
	}
	return urls
}

func (c *Crawler) GetAllForms() []map[string]interface{} {
	var allForms []map[string]interface{}
	for _, page := range c.results {
		allForms = append(allForms, page.Forms...)
	}
	return allForms
}

func (c *Crawler) GetAllParameters() map[string]string {
	allParams := make(map[string]string)
	for _, page := range c.results {
		for k, v := range page.Parameters {
			allParams[k] = v
		}
	}
	return allParams
}

func (c *Crawler) GetStatistics() map[string]int {
	return map[string]int{
		"total_pages":   len(c.results),
		"total_links":   len(c.GetAllURLs()),
		"total_forms":   len(c.GetAllForms()),
		"total_params":  len(c.GetAllParameters()),
	}
}
