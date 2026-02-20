package web

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hbzw/RCE_HawkEye_go/internal/crawler"
	"github.com/hbzw/RCE_HawkEye_go/internal/dirscan"
	"github.com/hbzw/RCE_HawkEye_go/internal/param"
	"github.com/hbzw/RCE_HawkEye_go/internal/reporter"
	"github.com/hbzw/RCE_HawkEye_go/internal/scanner"
	"github.com/hbzw/RCE_HawkEye_go/internal/types"
	"github.com/hbzw/RCE_HawkEye_go/internal/utils"
)

func (s *Server) runScan(ctx context.Context, scanID string, req ScanRequest) {
	s.updateScanStatus(scanID, func(status *ScanStatus) {
		status.Status = "running"
		status.CurrentTask = "Initializing"
	})
	
	defer func() {
		s.cancelMutex.Lock()
		delete(s.cancelFuncs, scanID)
		s.cancelMutex.Unlock()
	}()
	
	var allTargets []*types.ScanTarget
	
	if req.URL != "" {
		target := s.prepareSingleTarget(req.URL, req)
		allTargets = append(allTargets, target)
	}
	
	if len(req.URLs) > 0 {
		for _, u := range req.URLs {
			target := s.prepareSingleTarget(u, req)
			allTargets = append(allTargets, target)
		}
	}
	
	if req.RawTraffic != "" {
		rawRequests, err := utils.ParseRawTrafficFile(req.RawTraffic)
		if err != nil {
			s.finishScanWithError(scanID, fmt.Sprintf("Failed to parse traffic file: %v", err))
			return
		}
		for _, rawReq := range rawRequests {
			target := &types.ScanTarget{
				URL:        rawReq.URL,
				Method:     rawReq.Method,
				Headers:    rawReq.Headers,
				Data:       rawReq.PostData,
				Parameters: rawReq.Parameters,
			}
			allTargets = append(allTargets, target)
		}
	}
	
	if len(allTargets) == 0 {
		s.finishScanWithError(scanID, "No valid targets found")
		return
	}
	
	s.updateScanStatus(scanID, func(status *ScanStatus) {
		status.TotalTargets = len(allTargets)
		status.CurrentTask = "Preparing targets"
	})
	
	writer := reporter.GetResultWriter()
	if len(allTargets) > 0 {
		writer.Initialize(allTargets[0].URL)
	}
	
	var discoveredTargets []*types.ScanTarget
	
	for i, target := range allTargets {
		select {
		case <-ctx.Done():
			return
		default:
		}
		
		s.updateScanStatus(scanID, func(status *ScanStatus) {
			status.CurrentTask = fmt.Sprintf("Processing target %d/%d", i+1, len(allTargets))
			status.Scanned = i
		})
		
		if req.Crawl {
			s.updateScanStatus(scanID, func(status *ScanStatus) {
				status.CurrentTask = fmt.Sprintf("Crawling %s", target.URL)
			})
			
			crawled := s.runCrawler(ctx, target.URL, req)
			discoveredTargets = append(discoveredTargets, crawled...)
		}
		
		if req.DirScan {
			s.updateScanStatus(scanID, func(status *ScanStatus) {
				status.CurrentTask = fmt.Sprintf("Directory scanning %s", target.URL)
			})
			
			dirTargets := s.runDirScan(ctx, target.URL, req, writer)
			discoveredTargets = append(discoveredTargets, dirTargets...)
		}
		
		if req.ParamFuzz {
			s.updateScanStatus(scanID, func(status *ScanStatus) {
				status.CurrentTask = fmt.Sprintf("Parameter fuzzing %s", target.URL)
			})
			
			paramTargets := s.runParamFuzz(ctx, target.URL, req, writer)
			discoveredTargets = append(discoveredTargets, paramTargets...)
		}
	}
	
	allTargets = append(allTargets, discoveredTargets...)
	allTargets = deduplicateTargets(allTargets)
	
	s.updateScanStatus(scanID, func(status *ScanStatus) {
		status.TotalTargets = len(allTargets)
		status.CurrentTask = "Starting RCE scan"
	})
	
	scanMode := types.ScanModeEcho
	switch req.ScanMode {
	case "harmless":
		scanMode = types.ScanModeHarmless
	case "waf_bypass":
		scanMode = types.ScanModeWAFBypass
	}
	
	scanLevel := types.ScanLevelNormal
	switch req.ScanLevel {
	case 1:
		scanLevel = types.ScanLevelQuick
	case 3:
		scanLevel = types.ScanLevelDeep
	case 4:
		scanLevel = types.ScanLevelExhaustive
	}
	
	concurrent := req.Concurrent
	if concurrent <= 0 {
		concurrent = 10
	}
	
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 10
	}
	
	vulnChan := make(chan types.Vulnerability, 100)
	var vulns []types.Vulnerability
	var vulnMutex sync.Mutex
	
	go func() {
		for vuln := range vulnChan {
			vulnMutex.Lock()
			vulns = append(vulns, vuln)
			vulnMutex.Unlock()
			
			s.updateScanStatus(scanID, func(status *ScanStatus) {
				status.VulnCount = len(vulns)
			})
		}
	}()
	
	opts := []scanner.Option{
		scanner.WithTimeout(timeout),
		scanner.WithMaxConcurrent(concurrent),
		scanner.WithScanLevel(scanLevel),
		scanner.WithScanMode(scanMode),
		scanner.WithVulnCallback(func(vuln types.Vulnerability) {
			vulnChan <- vuln
			writer.WriteVulnerability(vuln)
		}),
	}
	
	if req.Proxy != "" {
		opts = append(opts, scanner.WithProxy(req.Proxy))
	}
	
	if req.UserAgent != "" {
		opts = append(opts, scanner.WithUserAgent(req.UserAgent))
	}
	
	opts = append(opts, scanner.WithVerifySSL(req.VerifySSL))
	
	scan := scanner.NewScanner(opts...)
	
	progressCallback := func(current, total int, targetURL string, extra map[string]interface{}) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		
		percent := 0
		if total > 0 {
			percent = current * 100 / total
		}
		
		s.updateScanStatus(scanID, func(status *ScanStatus) {
			status.Progress = percent
			status.Scanned = current
			status.TotalTargets = total
			status.CurrentTask = fmt.Sprintf("Scanning %s", truncateURL(targetURL, 50))
		})
	}
	scan.SetProgressCallback(progressCallback)
	
	results := scan.Scan(ctx, allTargets)
	close(vulnChan)
	
	var allVulns []types.Vulnerability
	for _, result := range results {
		allVulns = append(allVulns, result.Vulnerabilities...)
	}
	
	if len(vulns) > len(allVulns) {
		allVulns = vulns
	}
	
	scanInfo := map[string]interface{}{
		"total_targets": len(allTargets),
		"concurrent":    concurrent,
		"timeout":       timeout,
		"scan_mode":     string(scanMode),
		"scan_level":    string(scanLevel),
		"crawl_enabled": req.Crawl,
		"dir_scan":      req.DirScan,
		"param_fuzz":    req.ParamFuzz,
	}
	
	rep := reporter.NewReporter(s.reportDir)
	outputFormat := req.OutputFormat
	if outputFormat == "" {
		outputFormat = "json"
	}
	
	_, err := rep.SaveReport(allVulns, outputFormat, "", scanInfo, req.IncludeResponse)
	if err != nil {
		fmt.Printf("[!] Failed to save report: %v\n", err)
	}
	
	s.updateScanStatus(scanID, func(status *ScanStatus) {
		status.Status = "completed"
		status.Progress = 100
		status.VulnCount = len(allVulns)
		status.Vulns = allVulns
		now := time.Now()
		status.EndTime = &now
		status.CurrentTask = "Completed"
	})
}

func (s *Server) prepareSingleTarget(targetURL string, req ScanRequest) *types.ScanTarget {
	normalizedURL := utils.NormalizeTarget(targetURL)
	
	target := &types.ScanTarget{
		URL:        normalizedURL,
		Method:     req.Method,
		Headers:    make(map[string]string),
		Data:       make(map[string]string),
		Parameters: make(map[string]string),
	}
	
	if target.Method == "" {
		target.Method = "GET"
	}
	
	for _, h := range req.Headers {
		if idx := strings.Index(h, ":"); idx != -1 {
			key := strings.TrimSpace(h[:idx])
			value := strings.TrimSpace(h[idx+1:])
			target.Headers[key] = value
		}
	}
	
	if req.Data != "" {
		for _, pair := range strings.Split(req.Data, "&") {
			if idx := strings.Index(pair, "="); idx != -1 {
				key := pair[:idx]
				value := pair[idx+1:]
				target.Data[key] = value
				target.Parameters[key] = value
			}
		}
	}
	
	parsedParams := utils.ExtractParameters(normalizedURL)
	for k, v := range parsedParams {
		target.Parameters[k] = v
	}
	
	return target
}

func (s *Server) runCrawler(ctx context.Context, targetURL string, req ScanRequest) []*types.ScanTarget {
	c := crawler.NewCrawler(
		crawler.WithMaxDepth(2),
		crawler.WithMaxPages(100),
		crawler.WithTimeout(req.Timeout),
		crawler.WithUserAgent(req.UserAgent),
		crawler.WithRestrictRoot(true),
	)
	
	pages, err := c.Crawl(ctx, targetURL)
	if err != nil {
		return nil
	}
	
	var targets []*types.ScanTarget
	for _, page := range pages {
		if len(page.Parameters) > 0 {
			target := &types.ScanTarget{
				URL:        page.URL,
				Method:     "GET",
				Parameters: page.Parameters,
			}
			targets = append(targets, target)
		}
		
		for _, form := range page.Forms {
			action, _ := form["action"].(string)
			method, _ := form["method"].(string)
			if method == "" {
				method = "GET"
			}
			inputs, _ := form["inputs"].(map[string]string)
			
			if action != "" && len(inputs) > 0 {
				fullURL := resolveURL(targetURL, action)
				target := &types.ScanTarget{
					URL:        fullURL,
					Method:     method,
					Parameters: inputs,
				}
				targets = append(targets, target)
			}
		}
	}
	
	return targets
}

func (s *Server) runDirScan(ctx context.Context, targetURL string, req ScanRequest, writer *reporter.ResultWriter) []*types.ScanTarget {
	var results []types.DirResult
	var resultsMutex sync.Mutex
	
	callback := func(result types.DirResult) {
		resultsMutex.Lock()
		results = append(results, result)
		resultsMutex.Unlock()
		writer.WriteDirectory(result)
	}
	
	var statusCodes []int
	var excludeCodes []int = []int{404}
	
	if req.DirFilterStatus != "" {
		statusCodes, excludeCodes = parseStatusCodeInput(req.DirFilterStatus)
	}
	
	dirThreads := req.DirThreads
	if dirThreads <= 0 {
		dirThreads = 10
	}
	
	d := dirscan.NewDirScanner(
		dirscan.WithThreads(dirThreads),
		dirscan.WithTimeout(req.Timeout),
		dirscan.WithUserAgent(req.UserAgent),
		dirscan.WithRecursive(false),
		dirscan.WithFollowRedirects(false),
		dirscan.WithCallback(callback),
		dirscan.WithStatusCodes(statusCodes),
		dirscan.WithExcludeCodes(excludeCodes),
		dirscan.WithSmartDict(true),
	)
	
	if req.DirWordlist != "" {
		d = dirscan.NewDirScanner(
			dirscan.WithThreads(dirThreads),
			dirscan.WithTimeout(req.Timeout),
			dirscan.WithUserAgent(req.UserAgent),
			dirscan.WithWordlistFile(req.DirWordlist),
			dirscan.WithCallback(callback),
			dirscan.WithStatusCodes(statusCodes),
			dirscan.WithExcludeCodes(excludeCodes),
		)
	}
	
	_, err := d.Scan(ctx, targetURL)
	if err != nil {
		return nil
	}
	
	var targets []*types.ScanTarget
	for _, result := range results {
		if strings.Contains(result.URL, "?") {
			target := &types.ScanTarget{
				URL:        result.URL,
				Method:     "GET",
				Parameters: extractParamsFromURL(result.URL),
			}
			targets = append(targets, target)
		} else if result.StatusCode == 200 || result.StatusCode == 403 {
			target := &types.ScanTarget{
				URL:        result.URL,
				Method:     "GET",
				Parameters: make(map[string]string),
			}
			targets = append(targets, target)
		}
	}
	
	return targets
}

func (s *Server) runParamFuzz(ctx context.Context, targetURL string, req ScanRequest, writer *reporter.ResultWriter) []*types.ScanTarget {
	concurrent := req.Concurrent
	if concurrent <= 0 {
		concurrent = 10
	}
	
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 10
	}
	
	p := param.NewParamExtractor(
		param.WithThreads(concurrent),
		param.WithTimeout(timeout),
		param.WithFuzzParams(true),
		param.WithExtractFromJS(true),
		param.WithExtractFromHTML(true),
	)
	
	params, err := p.Extract(ctx, targetURL)
	if err != nil {
		return nil
	}
	
	var targets []*types.ScanTarget
	highPriorityParams := p.GetHighPriorityParams()
	
	if len(highPriorityParams) > 0 {
		target := &types.ScanTarget{
			URL:        targetURL,
			Method:     "GET",
			Parameters: make(map[string]string),
		}
		for _, paramName := range highPriorityParams {
			target.Parameters[paramName] = "test"
			writer.WriteParameter(paramName, "高风险参数")
		}
		targets = append(targets, target)
	}
	
	for paramName, sources := range params {
		for _, source := range sources {
			writer.WriteParameter(paramName, source.SourceType)
			if source.Method == "GET" || source.Method == "POST" {
				target := &types.ScanTarget{
					URL:        source.URL,
					Method:     source.Method,
					Parameters: map[string]string{paramName: source.ParamValue},
				}
				targets = append(targets, target)
			}
		}
	}
	
	if len(targets) == 0 {
		parsedURL, err := url.Parse(targetURL)
		existingParams := make(map[string]string)
		if err == nil {
			for k, v := range parsedURL.Query() {
				if len(v) > 0 {
					existingParams[k] = v[0]
					writer.WriteParameter(k, "URL参数")
				}
			}
		}
		
		if len(existingParams) > 0 {
			target := &types.ScanTarget{
				URL:        targetURL,
				Method:     "GET",
				Parameters: existingParams,
			}
			targets = append(targets, target)
		} else {
			defaultParams := []string{
				"cmd", "command", "exec", "execute", "system", "shell",
				"file", "path", "page", "url", "link", "redirect",
				"id", "action", "code", "data", "input", "query",
			}
			
			target := &types.ScanTarget{
				URL:        targetURL,
				Method:     "GET",
				Parameters: make(map[string]string),
			}
			for _, paramName := range defaultParams {
				target.Parameters[paramName] = "test"
			}
			targets = append(targets, target)
		}
	}
	
	return targets
}

func (s *Server) updateScanStatus(scanID string, update func(*ScanStatus)) {
	s.scanMutex.Lock()
	defer s.scanMutex.Unlock()
	
	if status, ok := s.scans[scanID]; ok {
		update(status)
	}
}

func (s *Server) finishScanWithError(scanID string, errMsg string) {
	s.updateScanStatus(scanID, func(status *ScanStatus) {
		status.Status = "error"
		status.Error = errMsg
		now := time.Now()
		status.EndTime = &now
	})
}

func deduplicateTargets(targets []*types.ScanTarget) []*types.ScanTarget {
	seen := make(map[string]*types.ScanTarget)
	var result []*types.ScanTarget
	
	for _, t := range targets {
		key := t.URL + "|" + t.Method
		if existing, ok := seen[key]; ok {
			if existing.Parameters == nil {
				existing.Parameters = make(map[string]string)
			}
			for k, v := range t.Parameters {
				if _, exists := existing.Parameters[k]; !exists {
					existing.Parameters[k] = v
				}
			}
		} else {
			seen[key] = t
			result = append(result, t)
		}
	}
	
	return result
}

func resolveURL(baseURL, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	
	baseEnd := strings.Index(baseURL[8:], "/")
	if baseEnd == -1 {
		if strings.HasSuffix(baseURL, "/") {
			return baseURL + path
		}
		return baseURL + "/" + path
	}
	
	base := baseURL[:8+baseEnd]
	if strings.HasPrefix(path, "/") {
		return base + path
	}
	return base + "/" + path
}

func extractParamsFromURL(rawURL string) map[string]string {
	params := make(map[string]string)
	if idx := strings.Index(rawURL, "?"); idx != -1 {
		queryString := rawURL[idx+1:]
		for _, pair := range strings.Split(queryString, "&") {
			if eq := strings.Index(pair, "="); eq != -1 {
				params[pair[:eq]] = pair[eq+1:]
			}
		}
	}
	return params
}

func truncateURL(url string, maxLen int) string {
	if len(url) <= maxLen {
		return url
	}
	return url[:maxLen] + "..."
}

func parseStatusCodeInput(input string) (include, exclude []int) {
	if input == "" {
		return nil, nil
	}
	
	parts := strings.Split(strings.ReplaceAll(input, " ", ""), ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "!") {
			if code, err := strconv.Atoi(part[1:]); err == nil {
				exclude = append(exclude, code)
			}
		} else {
			if code, err := strconv.Atoi(part); err == nil {
				include = append(include, code)
			}
		}
	}
	return include, exclude
}
