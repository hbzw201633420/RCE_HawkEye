package crawler

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
	"github.com/hbzw/RCE_HawkEye_go/internal/utils"
)

type PageCallback func(page types.CrawledPage)

type AdvancedCrawler struct {
	maxDepth        int
	maxPages        int
	timeout         int
	concurrent      int
	userAgent       string
	userAgents      []string
	client          *http.Client
	visited         map[string]bool
	visitedMutex    sync.Mutex
	results         []types.CrawledPage
	resultsMutex    sync.Mutex
	allowedDomains  []string
	blockedDomains  []string
	restrictRoot    bool
	rootDomain      string
	callback        PageCallback
	delay           time.Duration
	randomDelay     bool
	followRedirects bool
	maxRedirects    int
	cookies         []*http.Cookie
	headers         map[string]string
	proxy           string
	rateLimit       int
	rateLimiter     chan struct{}
	jsParser        bool
	parseAPI        bool
	apiPatterns     []*regexp.Regexp
}

type AdvancedCrawlerOption func(*AdvancedCrawler)

func WithAdvancedMaxDepth(depth int) AdvancedCrawlerOption {
	return func(c *AdvancedCrawler) {
		c.maxDepth = depth
	}
}

func WithAdvancedMaxPages(pages int) AdvancedCrawlerOption {
	return func(c *AdvancedCrawler) {
		c.maxPages = pages
	}
}

func WithAdvancedTimeout(timeout int) AdvancedCrawlerOption {
	return func(c *AdvancedCrawler) {
		c.timeout = timeout
	}
}

func WithAdvancedConcurrent(concurrent int) AdvancedCrawlerOption {
	return func(c *AdvancedCrawler) {
		c.concurrent = concurrent
	}
}

func WithAdvancedUserAgent(ua string) AdvancedCrawlerOption {
	return func(c *AdvancedCrawler) {
		c.userAgent = ua
	}
}

func WithAdvancedCallback(cb PageCallback) AdvancedCrawlerOption {
	return func(c *AdvancedCrawler) {
		c.callback = cb
	}
}

func WithAdvancedDelay(delayMs int) AdvancedCrawlerOption {
	return func(c *AdvancedCrawler) {
		c.delay = time.Duration(delayMs) * time.Millisecond
	}
}

func WithAdvancedRandomDelay(enabled bool) AdvancedCrawlerOption {
	return func(c *AdvancedCrawler) {
		c.randomDelay = enabled
	}
}

func WithAdvancedFollowRedirects(follow bool, maxRedirects int) AdvancedCrawlerOption {
	return func(c *AdvancedCrawler) {
		c.followRedirects = follow
		c.maxRedirects = maxRedirects
	}
}

func WithAdvancedCookies(cookies []*http.Cookie) AdvancedCrawlerOption {
	return func(c *AdvancedCrawler) {
		c.cookies = cookies
	}
}

func WithAdvancedHeaders(headers map[string]string) AdvancedCrawlerOption {
	return func(c *AdvancedCrawler) {
		c.headers = headers
	}
}

func WithAdvancedProxy(proxy string) AdvancedCrawlerOption {
	return func(c *AdvancedCrawler) {
		c.proxy = proxy
	}
}

func WithAdvancedRateLimit(requestsPerSecond int) AdvancedCrawlerOption {
	return func(c *AdvancedCrawler) {
		c.rateLimit = requestsPerSecond
	}
}

func WithAdvancedJSParser(enabled bool) AdvancedCrawlerOption {
	return func(c *AdvancedCrawler) {
		c.jsParser = enabled
	}
}

func WithAdvancedAPIParser(enabled bool) AdvancedCrawlerOption {
	return func(c *AdvancedCrawler) {
		c.parseAPI = enabled
	}
}

func NewAdvancedCrawler(opts ...AdvancedCrawlerOption) *AdvancedCrawler {
	c := &AdvancedCrawler{
		maxDepth:        3,
		maxPages:        200,
		timeout:         15,
		concurrent:      10,
		userAgent:       "RCE-HawkEye/1.1.0",
		visited:         make(map[string]bool),
		results:         make([]types.CrawledPage, 0),
		allowedDomains:  make([]string, 0),
		blockedDomains:  make([]string, 0),
		restrictRoot:    true,
		delay:           100 * time.Millisecond,
		randomDelay:     true,
		followRedirects: true,
		maxRedirects:    5,
		headers:         make(map[string]string),
		rateLimit:       10,
		jsParser:        true,
		parseAPI:        true,
		userAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		},
		apiPatterns: []*regexp.Regexp{
			regexp.MustCompile(`["']url["']\s*:\s*["']([^"']+)["']`),
			regexp.MustCompile(`["']api["']\s*:\s*["']([^"']+)["']`),
			regexp.MustCompile(`["']endpoint["']\s*:\s*["']([^"']+)["']`),
			regexp.MustCompile(`fetch\s*\(\s*["']([^"']+)["']`),
			regexp.MustCompile(`axios\.[a-z]+\s*\(\s*["']([^"']+)["']`),
			regexp.MustCompile(`\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["']([^"']+)["']`),
			regexp.MustCompile(`["']path["']\s*:\s*["']([^"']+)["']`),
			regexp.MustCompile(`["']route["']\s*:\s*["']([^"']+)["']`),
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	c.rateLimiter = make(chan struct{}, c.rateLimit)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	c.client = &http.Client{
		Timeout:   time.Duration(c.timeout) * time.Second,
		Transport: transport,
	}

	if !c.followRedirects {
		c.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		c.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= c.maxRedirects {
				return fmt.Errorf("stopped after %d redirects", c.maxRedirects)
			}
			return nil
		}
	}

	return c
}

func (c *AdvancedCrawler) Crawl(ctx context.Context, startURL string) ([]types.CrawledPage, error) {
	normalizedURL := utils.NormalizeTarget(startURL)

	parsed, err := url.Parse(normalizedURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	c.rootDomain = parsed.Hostname()

	if len(c.allowedDomains) == 0 && c.restrictRoot {
		c.allowedDomains = []string{c.rootDomain}
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, c.concurrent)

	wg.Add(1)
	go c.crawlPage(ctx, &wg, sem, normalizedURL, 0)

	wg.Wait()

	return c.results, nil
}

func (c *AdvancedCrawler) crawlPage(ctx context.Context, wg *sync.WaitGroup, sem chan struct{}, pageURL string, depth int) {
	defer wg.Done()

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

	c.applyDelay()

	select {
	case c.rateLimiter <- struct{}{}:
		defer func() { <-c.rateLimiter }()
	case <-ctx.Done():
		return
	}

	page, links, jsLinks := c.fetchPage(ctx, pageURL)
	if page == nil {
		return
	}

	c.resultsMutex.Lock()
	c.results = append(c.results, *page)
	c.resultsMutex.Unlock()

	if c.callback != nil {
		c.callback(*page)
	}

	allLinks := append(links, jsLinks...)
	for _, link := range allLinks {
		if c.isAllowedDomain(link) {
			select {
			case <-ctx.Done():
				return
			default:
				wg.Add(1)
				go c.crawlPage(ctx, wg, sem, link, depth+1)
			}
		}
	}
}

func (c *AdvancedCrawler) applyDelay() {
	if c.delay > 0 {
		delay := c.delay
		if c.randomDelay {
			delay = time.Duration(rand.Int63n(int64(c.delay)*2) + int64(c.delay/2))
		}
		time.Sleep(delay)
	}
}

func (c *AdvancedCrawler) getRandomUserAgent() string {
	if len(c.userAgents) > 0 {
		return c.userAgents[rand.Intn(len(c.userAgents))]
	}
	return c.userAgent
}

func (c *AdvancedCrawler) fetchPage(ctx context.Context, pageURL string) (*types.CrawledPage, []string, []string) {
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return nil, nil, nil
	}

	req.Header.Set("User-Agent", c.getRandomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,application/javascript,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "max-age=0")

	for key, value := range c.headers {
		req.Header.Set(key, value)
	}

	if len(c.cookies) > 0 {
		for _, cookie := range c.cookies {
			req.AddCookie(cookie)
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, nil, nil
	}

	contentType := resp.Header.Get("Content-Type")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, nil
	}

	content := string(body)

	var links []string
	var jsLinks []string

	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml+xml") {
		links = c.extractLinks(pageURL, content)
		forms := c.extractForms(content)
		params := c.extractParameters(pageURL, content)

		if c.jsParser {
			jsLinks = c.extractJSLinks(pageURL, content)
		}

		if c.parseAPI {
			apiLinks := c.extractAPIEndpoints(content)
			jsLinks = append(jsLinks, apiLinks...)
		}

		page := &types.CrawledPage{
			URL:        pageURL,
			StatusCode: resp.StatusCode,
			Content:    content,
			Links:      links,
			Forms:      forms,
			Parameters: params,
		}

		return page, links, jsLinks
	}

	if strings.Contains(contentType, "javascript") || strings.Contains(contentType, "application/json") {
		jsLinks = c.extractJSLinks(pageURL, content)
		if c.parseAPI {
			apiLinks := c.extractAPIEndpoints(content)
			jsLinks = append(jsLinks, apiLinks...)
		}

		params := c.extractParameters(pageURL, content)

		page := &types.CrawledPage{
			URL:        pageURL,
			StatusCode: resp.StatusCode,
			Content:    content,
			Links:      jsLinks,
			Parameters: params,
		}

		return page, nil, jsLinks
	}

	return nil, nil, nil
}

func (c *AdvancedCrawler) extractJSLinks(baseURL, content string) []string {
	var links []string
	seen := make(map[string]bool)

	jsLinkPatterns := []string{
		`["']([^"']*(?:\.php|\.asp|\.aspx|\.jsp|\.do|\.action)[^"']*)["']`,
		`["'](/[^"']*(?:api|v1|v2|v3|graphql|query|search)[^"']*)["']`,
		`["']([^"']*\?[^"']*=)`,
		`["']([^"']*(?:get|post|put|delete|update|create|list|view|edit|add|remove)[^"']*)["']`,
	}

	for _, pattern := range jsLinkPatterns {
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

func (c *AdvancedCrawler) extractAPIEndpoints(content string) []string {
	var endpoints []string
	seen := make(map[string]bool)

	for _, pattern := range c.apiPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				endpoint := match[1]
				if !seen[endpoint] && len(endpoint) > 1 && len(endpoint) < 500 {
					seen[endpoint] = true
					endpoints = append(endpoints, endpoint)
				}
			}
		}
	}

	return endpoints
}

func (c *AdvancedCrawler) extractLinks(baseURL, content string) []string {
	var links []string
	seen := make(map[string]bool)

	linkPatterns := []string{
		`href=["']([^"']+)["']`,
		`src=["']([^"']+)["']`,
		`action=["']([^"']+)["']`,
		`data-url=["']([^"']+)["']`,
		`data-href=["']([^"']+)["']`,
		`data-src=["']([^"']+)["']`,
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

func (c *AdvancedCrawler) extractForms(content string) []map[string]interface{} {
	var forms []map[string]interface{}

	formPattern := regexp.MustCompile(`(?i)<form[^>]*>(.*?)</form>`)
	inputPattern := regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']+)["'][^>]*(?:value=["']([^"']*)["'])?`)
	selectPattern := regexp.MustCompile(`(?i)<select[^>]*name=["']([^"']+)["']`)
	textareaPattern := regexp.MustCompile(`(?i)<textarea[^>]*name=["']([^"']+)["']`)

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

		inputs := make(map[string]string)
		inputMatches := inputPattern.FindAllStringSubmatch(formHTML, -1)
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

		selectMatches := selectPattern.FindAllStringSubmatch(formHTML, -1)
		for _, selectMatch := range selectMatches {
			if len(selectMatch) > 1 {
				inputs[selectMatch[1]] = ""
			}
		}

		textareaMatches := textareaPattern.FindAllStringSubmatch(formHTML, -1)
		for _, textareaMatch := range textareaMatches {
			if len(textareaMatch) > 1 {
				inputs[textareaMatch[1]] = ""
			}
		}

		form["inputs"] = inputs
		forms = append(forms, form)
	}

	return forms
}

func (c *AdvancedCrawler) extractParameters(pageURL, content string) map[string]string {
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
		`["'](\w+)["']\s*:\s*["']([^"']+)["']`,
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

	return params
}

func (c *AdvancedCrawler) resolveURL(baseURL, link string) string {
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

func (c *AdvancedCrawler) isValidLink(link string) bool {
	excludedExtensions := []string{
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp",
		".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".zip", ".rar", ".tar", ".gz", ".7z", ".bz2",
		".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv", ".webm",
	}

	linkLower := strings.ToLower(link)
	for _, ext := range excludedExtensions {
		if strings.HasSuffix(linkLower, ext) {
			return false
		}
	}

	return true
}

func (c *AdvancedCrawler) isAllowedDomain(link string) bool {
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

func (c *AdvancedCrawler) GetResults() []types.CrawledPage {
	return c.results
}

func (c *AdvancedCrawler) GetAllURLs() []string {
	var urls []string
	seen := make(map[string]bool)
	for _, page := range c.results {
		if !seen[page.URL] {
			seen[page.URL] = true
			urls = append(urls, page.URL)
		}
	}
	return urls
}

func (c *AdvancedCrawler) GetAllForms() []map[string]interface{} {
	var allForms []map[string]interface{}
	for _, page := range c.results {
		allForms = append(allForms, page.Forms...)
	}
	return allForms
}

func (c *AdvancedCrawler) GetAllParameters() map[string]string {
	allParams := make(map[string]string)
	for _, page := range c.results {
		for k, v := range page.Parameters {
			allParams[k] = v
		}
	}
	return allParams
}

func (c *AdvancedCrawler) GetStatistics() map[string]int {
	return map[string]int{
		"total_pages":   len(c.results),
		"total_links":   len(c.GetAllURLs()),
		"total_forms":   len(c.GetAllForms()),
		"total_params":  len(c.GetAllParameters()),
	}
}
