package dirscan

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hbzw/RCE_HawkEye_go/internal/dict"
	"github.com/hbzw/RCE_HawkEye_go/internal/types"
	"github.com/hbzw/RCE_HawkEye_go/internal/utils"
)

type ResultCallback func(result types.DirResult)

type DirScanner struct {
	threads          int
	timeout          int
	extensions       []string
	statusCodes      []int
	excludeCodes     []int
	wordlist         []string
	maxDepth         int
	recursive        bool
	followRedirects  bool
	userAgent        string
	client           *http.Client
	results          []types.DirResult
	resultsMutex     sync.RWMutex
	callback         ResultCallback
	quiet            bool
	smartDict        *dict.SmartDict
	useSmartDict     bool
	scanCount        int64
	hitCount         int64
	transport        *http.Transport
	stopFlag         int32
	scannedURLs      map[string]bool
	scannedMutex     sync.Mutex
}

type DirScanOption func(*DirScanner)

func WithThreads(threads int) DirScanOption {
	return func(d *DirScanner) {
		if threads > 0 {
			d.threads = threads
		}
	}
}

func WithTimeout(timeout int) DirScanOption {
	return func(d *DirScanner) {
		if timeout > 0 {
			d.timeout = timeout
		}
	}
}

func WithExtensions(exts []string) DirScanOption {
	return func(d *DirScanner) {
		if len(exts) > 0 {
			d.extensions = exts
		}
	}
}

func WithStatusCodes(codes []int) DirScanOption {
	return func(d *DirScanner) {
		d.statusCodes = codes
	}
}

func WithExcludeCodes(codes []int) DirScanOption {
	return func(d *DirScanner) {
		d.excludeCodes = codes
	}
}

func WithWordlistFile(filepath string) DirScanOption {
	return func(d *DirScanner) {
		if filepath != "" {
			d.wordlist = loadWordlist(filepath)
		}
	}
}

func WithWordlist(words []string) DirScanOption {
	return func(d *DirScanner) {
		if len(words) > 0 {
			d.wordlist = words
		}
	}
}

func WithMaxDepth(depth int) DirScanOption {
	return func(d *DirScanner) {
		if depth > 0 {
			d.maxDepth = depth
		}
	}
}

func WithRecursive(recursive bool) DirScanOption {
	return func(d *DirScanner) {
		d.recursive = recursive
	}
}

func WithFollowRedirects(follow bool) DirScanOption {
	return func(d *DirScanner) {
		d.followRedirects = follow
	}
}

func WithUserAgent(ua string) DirScanOption {
	return func(d *DirScanner) {
		if ua != "" {
			d.userAgent = ua
		}
	}
}

func WithCallback(cb ResultCallback) DirScanOption {
	return func(d *DirScanner) {
		d.callback = cb
	}
}

func WithQuiet(quiet bool) DirScanOption {
	return func(d *DirScanner) {
		d.quiet = quiet
	}
}

func WithSmartDict(useSmartDict bool) DirScanOption {
	return func(d *DirScanner) {
		d.useSmartDict = useSmartDict
	}
}

func WithArchiveThreshold(threshold int) DirScanOption {
	return func(d *DirScanner) {
		if d.smartDict != nil {
			d.smartDict.SetArchiveThreshold(threshold)
		}
	}
}

func NewDirScanner(opts ...DirScanOption) *DirScanner {
	d := &DirScanner{
		threads:         20,
		timeout:         10,
		extensions:      []string{".php", ".asp", ".aspx", ".jsp", ".html", ".htm", ".js", ".json", ".xml", ".txt", ".bak", ".old", ".sql", ".zip", ".tar.gz", ".conf", ".cfg", ".inc", ".log", ".swp"},
		statusCodes:     []int{200, 301, 302, 303, 307, 308, 401, 403, 500},
		excludeCodes:    []int{404},
		maxDepth:        2,
		recursive:       false,
		followRedirects: false,
		userAgent:       "RCE-HawkEye/1.1.0",
		results:         make([]types.DirResult, 0),
		wordlist:        getDefaultWordlist(),
		useSmartDict:    true,
		scannedURLs:     make(map[string]bool),
	}

	for _, opt := range opts {
		opt(d)
	}

	d.transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(d.timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   20,
		DisableCompression:    false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: false,
	}

	client := &http.Client{
		Timeout:   time.Duration(d.timeout) * time.Second,
		Transport: d.transport,
	}

	if !d.followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	d.client = client

	if d.useSmartDict {
		d.smartDict = dict.NewSmartDict(
			dict.WithDictType("dir"),
			dict.WithDataFile("./data/dict/dir_dict.json"),
			dict.WithBackupDir("./data/dict/backup"),
		)
		d.smartDict.MergeWords(d.wordlist, 0)
	}

	return d
}

func getDefaultWordlist() []string {
	return []string{
		".htaccess", ".htpasswd", ".git/config", ".git/HEAD", ".gitignore",
		".svn/entries", ".svn/wc.db",
		".env", ".env.local", ".env.production",
		".DS_Store", ".idea", ".vscode",
		"admin", "administrator", "admin.php", "admin/login",
		"login", "login.php", "login.asp", "login.aspx", "login.jsp",
		"api", "api/v1", "api/v2",
		"backup", "backup.sql", "backup.zip",
		"config.php", "config.yml", "config.json",
		"phpinfo.php", "info.php", "test.php",
		"shell.php", "cmd.php", "webshell.php",
		"upload", "uploads",
		"wp-admin", "wp-login.php", "wp-config.php",
		"phpmyadmin", "adminer.php",
		"robots.txt", "sitemap.xml", "favicon.ico",
		"index.php", "index.html", "index.asp", "index.aspx",
		"readme.txt", "readme.md", "README.md",
		"install.php", "install.sql",
		"error.php", "error.log",
		"user", "users", "account",
		"search", "download", "upload",
		"doc", "docs", "documentation",
		"vendor", "node_modules",
		"composer.json", "package.json",
		"Dockerfile", "docker-compose.yml",
		"flag", "flag.txt", "flag.php",
		"secret", "secrets", "private",
		"data", "cache", "session",
		"storage", "var",
		"lib", "library", "inc", "include", "includes",
		"core", "src", "source",
		"app", "application",
		"model", "models", "view", "views", "controller", "controllers",
	}
}

func loadWordlist(filepath string) []string {
	file, err := os.Open(filepath)
	if err != nil {
		return getDefaultWordlist()
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
		return getDefaultWordlist()
	}

	return words
}

func (d *DirScanner) normalizePath(path string) string {
	path = strings.TrimSpace(path)
	for strings.HasPrefix(path, "/") {
		path = strings.TrimPrefix(path, "/")
	}
	for strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	return path
}

func (d *DirScanner) buildURL(baseURL, path string) string {
	path = d.normalizePath(path)
	if path == "" {
		return baseURL + "/"
	}
	return baseURL + "/" + path
}

func (d *DirScanner) isScanned(urlKey string) bool {
	d.scannedMutex.Lock()
	defer d.scannedMutex.Unlock()
	
	if d.scannedURLs[urlKey] {
		return true
	}
	d.scannedURLs[urlKey] = true
	return false
}

func (d *DirScanner) Scan(ctx context.Context, targetURL string) ([]types.DirResult, error) {
	normalizedURL := utils.NormalizeTarget(targetURL)

	parsed, err := url.Parse(normalizedURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	baseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	
	d.scanDirectory(ctx, baseURL, parsed.Path, 0)

	if d.smartDict != nil {
		d.smartDict.Save()
	}

	d.resultsMutex.RLock()
	defer d.resultsMutex.RUnlock()
	
	return d.results, nil
}

func (d *DirScanner) scanDirectory(ctx context.Context, baseURL, path string, depth int) {
	if depth > d.maxDepth {
		return
	}
	
	if atomic.LoadInt32(&d.stopFlag) == 1 {
		return
	}

	path = d.normalizePath(path)

	var wordlist []string
	if d.useSmartDict && d.smartDict != nil {
		wordlist = d.smartDict.GetSortedWords()
	} else {
		wordlist = d.wordlist
	}

	pathsToTest := make([]string, 0, len(wordlist))
	seenPaths := make(map[string]bool)

	for _, word := range wordlist {
		word = d.normalizePath(word)
		if word == "" {
			continue
		}

		var fullPath string
		if path != "" {
			fullPath = path + "/" + word
		} else {
			fullPath = word
		}
		fullPath = strings.ReplaceAll(fullPath, "//", "/")
		fullPath = strings.TrimPrefix(fullPath, "/")

		if !seenPaths[fullPath] {
			seenPaths[fullPath] = true
			pathsToTest = append(pathsToTest, fullPath)
		}

		for _, ext := range d.extensions {
			extPath := fullPath + ext
			if !seenPaths[extPath] {
				seenPaths[extPath] = true
				pathsToTest = append(pathsToTest, extPath)
			}
		}
	}

	if len(pathsToTest) == 0 {
		return
	}

	type scanResult struct {
		url        string
		result     *types.DirResult
		err        error
	}

	resultChan := make(chan scanResult, d.threads)
	sem := make(chan struct{}, d.threads)
	var wg sync.WaitGroup
	var activeCount int32

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		for _, testPath := range pathsToTest {
			if atomic.LoadInt32(&d.stopFlag) == 1 {
				break
			}
			
			select {
			case <-ctx.Done():
				return
			default:
			}

			fullURL := d.buildURL(baseURL, testPath)
			
			urlKey := fullURL
			if d.isScanned(urlKey) {
				continue
			}

			wg.Add(1)
			sem <- struct{}{}
			atomic.AddInt32(&activeCount, 1)

			go func(url, p string) {
				defer wg.Done()
				defer func() { 
					<-sem 
					atomic.AddInt32(&activeCount, -1)
				}()

				reqCtx, reqCancel := context.WithTimeout(ctx, time.Duration(d.timeout)*time.Second)
				defer reqCancel()

				result, err := d.testPath(reqCtx, url)
				atomic.AddInt64(&d.scanCount, 1)

				select {
				case resultChan <- scanResult{url: url, result: result, err: err}:
				case <-ctx.Done():
				}
			}(fullURL, testPath)
		}
	}()

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for res := range resultChan {
		if res.err != nil {
			continue
		}

		result := res.result
		if result == nil {
			if d.smartDict != nil {
				d.smartDict.RecordResult(res.url, 404)
			}
			continue
		}

		atomic.AddInt64(&d.hitCount, 1)

		if d.smartDict != nil {
			d.smartDict.RecordResult(res.url, result.StatusCode)
		}

		d.resultsMutex.Lock()
		d.results = append(d.results, *result)
		d.resultsMutex.Unlock()

		if d.callback != nil {
			d.callback(*result)
		}

		if d.recursive && (result.StatusCode == 200 || result.StatusCode == 301 || result.StatusCode == 302) {
			if result.Redirect != "" {
				if strings.HasPrefix(result.Redirect, "/") {
					select {
					case <-ctx.Done():
						return
					default:
					}
					d.scanDirectory(ctx, baseURL, result.Redirect, depth+1)
				}
			}
		}
	}
}

func (d *DirScanner) testPath(ctx context.Context, fullURL string) (*types.DirResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", d.userAgent)
	req.Header.Set("Connection", "keep-alive")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	statusCode := resp.StatusCode

	if len(d.statusCodes) > 0 {
		found := false
		for _, code := range d.statusCodes {
			if statusCode == code {
				found = true
				break
			}
		}
		if !found {
			return nil, nil
		}
	}

	for _, code := range d.excludeCodes {
		if statusCode == code {
			return nil, nil
		}
	}

	body, _ := io.ReadAll(resp.Body)
	contentLength := len(body)
	title := extractTitle(string(body))
	contentType := resp.Header.Get("Content-Type")
	webServer := resp.Header.Get("Server")
	techStack := detectTechStack(string(body), resp.Header)

	var redirect string
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		redirect = resp.Header.Get("Location")
	}

	return &types.DirResult{
		URL:           fullURL,
		StatusCode:    statusCode,
		ContentLength: contentLength,
		Redirect:      redirect,
		Title:         title,
		ContentType:   contentType,
		TechStack:     techStack,
		WebServer:     webServer,
	}, nil
}

func detectTechStack(content string, headers http.Header) []string {
	var techStack []string
	seen := make(map[string]bool)

	contentLower := strings.ToLower(content)

	indicators := []struct {
		name     string
		patterns []string
	}{
		{"PHP", []string{".php", "<?php", "laravel", "symfony", "wordpress", "drupal", "joomla", "thinkphp"}},
		{"Java", []string{".jsp", ".do", ".action", "tomcat", "weblogic", "spring", "struts", "servlet"}},
		{"ASP.NET", []string{".asp", ".aspx", "iis", "asp.net", "webforms", "mvc"}},
		{"Python", []string{"django", "flask", "fastapi", "python", "wsgi", "gunicorn"}},
		{"Node.js", []string{"node.js", "express", "npm", "react", "vue", "angular", "next.js"}},
		{"Ruby", []string{"ruby", "rails", "rack", "passenger"}},
		{"Go", []string{"golang", "go-http", "gin", "echo", "fiber"}},
	}

	for _, ind := range indicators {
		for _, pattern := range ind.patterns {
			if strings.Contains(contentLower, strings.ToLower(pattern)) && !seen[ind.name] {
				techStack = append(techStack, ind.name)
				seen[ind.name] = true
				break
			}
		}
	}

	poweredBy := headers.Get("X-Powered-By")
	if poweredBy != "" && !seen[poweredBy] {
		techStack = append(techStack, poweredBy)
		seen[poweredBy] = true
	}

	return techStack
}

func extractTitle(content string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func (d *DirScanner) GetResults() []types.DirResult {
	d.resultsMutex.RLock()
	defer d.resultsMutex.RUnlock()
	return d.results
}

func (d *DirScanner) GetResultsByStatus(statusCode int) []types.DirResult {
	d.resultsMutex.RLock()
	defer d.resultsMutex.RUnlock()
	
	var filtered []types.DirResult
	for _, r := range d.results {
		if r.StatusCode == statusCode {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func (d *DirScanner) GetInterestingFiles() []types.DirResult {
	d.resultsMutex.RLock()
	defer d.resultsMutex.RUnlock()

	interestingPatterns := []string{
		"admin", "login", "config", "backup", "shell", "cmd",
		"phpinfo", "info.php", "test.php", "debug",
		".git", ".env", ".htaccess", "web.config",
		"wp-admin", "wp-login", "xmlrpc",
		"phpmyadmin", "adminer", "manager",
		"jenkins", "solr", "elasticsearch",
		"webshell", "backdoor", "c99", "r57",
	}

	var interesting []types.DirResult
	for _, r := range d.results {
		for _, pattern := range interestingPatterns {
			if strings.Contains(strings.ToLower(r.URL), pattern) {
				interesting = append(interesting, r)
				break
			}
		}
	}
	return interesting
}

func (d *DirScanner) GetStatistics() map[string]int {
	d.resultsMutex.RLock()
	defer d.resultsMutex.RUnlock()

	stats := map[string]int{
		"total": len(d.results),
	}

	for _, r := range d.results {
		key := fmt.Sprintf("status_%d", r.StatusCode)
		stats[key]++
	}

	return stats
}

func (d *DirScanner) GetScanStatistics() map[string]int64 {
	return map[string]int64{
		"total_scans": atomic.LoadInt64(&d.scanCount),
		"total_hits":  atomic.LoadInt64(&d.hitCount),
	}
}

func (d *DirScanner) GetSmartDict() *dict.SmartDict {
	return d.smartDict
}

func (d *DirScanner) Stop() {
	atomic.StoreInt32(&d.stopFlag, 1)
}

func (d *DirScanner) Close() {
	if d.transport != nil {
		d.transport.CloseIdleConnections()
	}
}
