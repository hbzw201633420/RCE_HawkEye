package scanner

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hbzw/RCE_HawkEye_go/internal/detector"
	"github.com/hbzw/RCE_HawkEye_go/internal/payload"
	"github.com/hbzw/RCE_HawkEye_go/internal/types"
	"github.com/hbzw/RCE_HawkEye_go/internal/utils"
)

const (
	MaxConsecutiveErrors   = 5
	MaxRetries             = 3
	RequestTimeout         = 30 * time.Second
	ProgressTimeout        = 60 * time.Second
	MaxCacheItems          = 1024
	ThreadFinalizationWait = 2 * time.Second
)

type ScanLevelConfig struct {
	MaxPayloadsPerParam int
	IncludeWAFBypass    bool
	IncludeTemplate     bool
	IncludeAdvanced     bool
	Description         string
}

var ScanLevelConfigs = map[types.ScanLevel]ScanLevelConfig{
	types.ScanLevelQuick: {
		MaxPayloadsPerParam: 10,
		IncludeWAFBypass:    false,
		IncludeTemplate:     false,
		IncludeAdvanced:     false,
		Description:         "快速扫描 - 仅测试最关键的Payload",
	},
	types.ScanLevelNormal: {
		MaxPayloadsPerParam: 30,
		IncludeWAFBypass:    false,
		IncludeTemplate:     true,
		IncludeAdvanced:     false,
		Description:         "标准扫描 - 平衡速度和覆盖率",
	},
	types.ScanLevelDeep: {
		MaxPayloadsPerParam: 60,
		IncludeWAFBypass:    true,
		IncludeTemplate:     true,
		IncludeAdvanced:     true,
		Description:         "深度扫描 - 全面检测",
	},
	types.ScanLevelExhaustive: {
		MaxPayloadsPerParam: 0,
		IncludeWAFBypass:    true,
		IncludeTemplate:     true,
		IncludeAdvanced:     true,
		Description:         "exhaustive扫描 - 测试所有Payload",
	},
}

type ProgressCallback func(current, total int, targetURL string, extra map[string]interface{})
type VulnerabilityCallback func(vuln types.Vulnerability)
type TrafficCallback func(bytesSent, bytesReceived int64)

type responseCache struct {
	mu    sync.RWMutex
	items map[string]map[string]interface{}
	size  int
}

func newResponseCache(maxSize int) *responseCache {
	return &responseCache{
		items: make(map[string]map[string]interface{}),
		size:  maxSize,
	}
}

func (c *responseCache) Get(key string) (map[string]interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.items[key]
	return item, ok
}

func (c *responseCache) Set(key string, value map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if len(c.items) >= c.size {
		for k := range c.items {
			delete(c.items, k)
			break
		}
	}
	c.items[key] = value
}

type Scanner struct {
	timeout             int
	maxConcurrent       int
	delayThreshold      float64
	maxRetries          int
	userAgent           string
	proxy               string
	verifySSL           bool
	scanLevel           types.ScanLevel
	scanMode            types.ScanMode
	payloadGenerator    *payload.PayloadGenerator
	detector            *detector.Detector
	client              *http.Client
	progressCallback    ProgressCallback
	vulnCallback        VulnerabilityCallback
	trafficCallback     TrafficCallback
	stopFlag            int32
	baselines           map[string]map[string]interface{}
	mu                  sync.Mutex
	requestTimeout      time.Duration
	progressTimeout     time.Duration
	lastProgressTime    time.Time
	progressMutex       sync.Mutex
	cache               *responseCache
	consecutiveErrors   int32
	totalRequests       int64
	successRequests     int64
	failedRequests      int64
	startTime           time.Time
	totalBytesSent      int64
	totalBytesReceived  int64
	trafficMutex        sync.Mutex
}

func NewScanner(opts ...Option) *Scanner {
	s := &Scanner{
		timeout:          10,
		maxConcurrent:    20,
		delayThreshold:   4.0,
		maxRetries:       MaxRetries,
		userAgent:        "RCE-HawkEye/1.1.0",
		verifySSL:        false,
		scanLevel:        types.ScanLevelNormal,
		scanMode:         types.ScanModeEcho,
		payloadGenerator: payload.NewPayloadGenerator(),
		baselines:        make(map[string]map[string]interface{}),
		requestTimeout:   RequestTimeout,
		progressTimeout:  ProgressTimeout,
		lastProgressTime: time.Now(),
		cache:            newResponseCache(MaxCacheItems),
		startTime:        time.Now(),
	}

	for _, opt := range opts {
		opt(s)
	}

	s.detector = detector.NewDetector(detector.WithDelayThreshold(s.delayThreshold))

	transport := &http.Transport{
		DisableKeepAlives:   false,
		MaxIdleConns:        s.maxConcurrent * 2,
		MaxIdleConnsPerHost: s.maxConcurrent,
		MaxConnsPerHost:     s.maxConcurrent * 2,
		IdleConnTimeout:     30 * time.Second,
	}

	if !s.verifySSL {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	s.client = &http.Client{
		Timeout:   time.Duration(s.timeout) * time.Second,
		Transport: transport,
	}

	return s
}

type Option func(*Scanner)

func WithTimeout(timeout int) Option {
	return func(s *Scanner) {
		s.timeout = timeout
	}
}

func WithMaxConcurrent(maxConcurrent int) Option {
	return func(s *Scanner) {
		s.maxConcurrent = maxConcurrent
	}
}

func WithDelayThreshold(threshold float64) Option {
	return func(s *Scanner) {
		s.delayThreshold = threshold
	}
}

func WithUserAgent(ua string) Option {
	return func(s *Scanner) {
		s.userAgent = ua
	}
}

func WithProxy(proxy string) Option {
	return func(s *Scanner) {
		s.proxy = proxy
	}
}

func WithVerifySSL(verify bool) Option {
	return func(s *Scanner) {
		s.verifySSL = verify
	}
}

func WithScanLevel(level types.ScanLevel) Option {
	return func(s *Scanner) {
		s.scanLevel = level
	}
}

func WithScanMode(mode types.ScanMode) Option {
	return func(s *Scanner) {
		s.scanMode = mode
	}
}

func WithVulnCallback(cb VulnerabilityCallback) Option {
	return func(s *Scanner) {
		s.vulnCallback = cb
	}
}

func WithTrafficCallback(cb TrafficCallback) Option {
	return func(s *Scanner) {
		s.trafficCallback = cb
	}
}

func (s *Scanner) SetProgressCallback(cb ProgressCallback) {
	s.progressCallback = cb
}

func (s *Scanner) SetScanMode(mode types.ScanMode) {
	s.scanMode = mode
}

func (s *Scanner) SetScanLevel(level types.ScanLevel) {
	s.scanLevel = level
}

func (s *Scanner) Stop() {
	atomic.StoreInt32(&s.stopFlag, 1)
}

func (s *Scanner) isStopped() bool {
	return atomic.LoadInt32(&s.stopFlag) == 1
}

func (s *Scanner) recordTraffic(bytesSent, bytesReceived int64) {
	s.trafficMutex.Lock()
	s.totalBytesSent += bytesSent
	s.totalBytesReceived += bytesReceived
	s.trafficMutex.Unlock()
	
	if s.trafficCallback != nil {
		s.trafficCallback(bytesSent, bytesReceived)
	}
}

func (s *Scanner) GetTrafficStats() (int64, int64) {
	s.trafficMutex.Lock()
	defer s.trafficMutex.Unlock()
	return s.totalBytesSent, s.totalBytesReceived
}

func (s *Scanner) reportProgress(current, total int, targetURL string, extra map[string]interface{}) {
	s.progressMutex.Lock()
	s.lastProgressTime = time.Now()
	s.progressMutex.Unlock()
	
	if s.progressCallback != nil {
		s.progressCallback(current, total, targetURL, extra)
	}
}

func (s *Scanner) checkProgressTimeout() bool {
	s.progressMutex.Lock()
	defer s.progressMutex.Unlock()
	return time.Since(s.lastProgressTime) > s.progressTimeout
}

func (s *Scanner) updateProgress() {
	s.progressMutex.Lock()
	s.lastProgressTime = time.Now()
	s.progressMutex.Unlock()
}

func (s *Scanner) detectTechFromURL(targetURL string) types.TechType {
	urlLower := strings.ToLower(targetURL)

	if strings.Contains(urlLower, ".php") || strings.Contains(urlLower, "wp-") ||
		strings.Contains(urlLower, "laravel") || strings.Contains(urlLower, "symfony") {
		return types.TechTypePHP
	}

	if strings.Contains(urlLower, ".jsp") || strings.Contains(urlLower, ".do") ||
		strings.Contains(urlLower, ".action") || strings.Contains(urlLower, "web-inf") {
		return types.TechTypeJSPJava
	}

	if strings.Contains(urlLower, ".aspx") || strings.Contains(urlLower, ".ashx") ||
		strings.Contains(urlLower, ".asmx") || strings.Contains(urlLower, "web.config") {
		return types.TechTypeASPXDotNet
	}

	if strings.Contains(urlLower, ".asp") {
		return types.TechTypeASP
	}

	if strings.Contains(urlLower, ".py") || strings.Contains(urlLower, "django") ||
		strings.Contains(urlLower, "flask") || strings.Contains(urlLower, "fastapi") {
		return types.TechTypePython
	}

	if strings.Contains(urlLower, "expressjs") || strings.Contains(urlLower, "nodejs") ||
		strings.Contains(urlLower, "npm") || strings.Contains(urlLower, "package.json") {
		return types.TechTypeNodeJS
	}

	if strings.Contains(urlLower, ".rb") || strings.Contains(urlLower, "rails") ||
		strings.Contains(urlLower, "ruby") {
		return types.TechTypeRuby
	}

	if strings.Contains(urlLower, ".go") || strings.Contains(urlLower, "golang") {
		return types.TechTypeGo
	}

	return types.TechTypeUnknown
}

type scanTask struct {
	param   string
	payload types.Payload
}

type scanResult struct {
	vuln *types.Vulnerability
	err  error
}

func (s *Scanner) fetchURLWithRetry(ctx context.Context, target *types.ScanTarget, params map[string]string) (map[string]interface{}, error) {
	var lastErr error
	var lastResp map[string]interface{}
	
	for i := 0; i < s.maxRetries; i++ {
		if s.isStopped() {
			return nil, nil
		}
		
		if atomic.LoadInt32(&s.consecutiveErrors) >= MaxConsecutiveErrors {
			time.Sleep(time.Second * 2)
			atomic.StoreInt32(&s.consecutiveErrors, 0)
		}
		
		resp, err := s.fetchURL(ctx, target, params)
		if err != nil {
			lastErr = err
			atomic.AddInt32(&s.consecutiveErrors, 1)
			time.Sleep(time.Duration(i+1) * time.Second)
			continue
		}
		
		atomic.StoreInt32(&s.consecutiveErrors, 0)
		lastResp = resp
		return resp, nil
	}
	
	return lastResp, lastErr
}

func (s *Scanner) fetchURL(ctx context.Context, target *types.ScanTarget, params map[string]string) (map[string]interface{}, error) {
	startTime := time.Now()
	atomic.AddInt64(&s.totalRequests, 1)

	var reqURL string
	var reqBody io.Reader
	var reqBodyLen int
	var method = target.Method

	if method == "" {
		method = "GET"
	}

	if method == "GET" {
		reqURL = utils.BuildURL(target.URL, params)
	} else if method == "POST" {
		reqURL = target.URL
		formData := url.Values{}
		
		if target.Data != nil {
			for k, v := range target.Data {
				if overrideVal, exists := params[k]; exists {
					formData.Set(k, overrideVal)
				} else {
					formData.Set(k, v)
				}
			}
		}
		
		for k, v := range params {
			if target.Data == nil || target.Data[k] == "" {
				formData.Set(k, v)
			}
		}
		
		bodyStr := formData.Encode()
		reqBody = strings.NewReader(bodyStr)
		reqBodyLen = len(bodyStr)
	} else {
		reqURL = utils.BuildURL(target.URL, params)
	}

	cacheKey := method + ":" + reqURL
	if cached, ok := s.cache.Get(cacheKey); ok {
		return cached, nil
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
	if err != nil {
		atomic.AddInt64(&s.failedRequests, 1)
		return nil, err
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "close")

	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	if method == "POST" {
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		atomic.AddInt64(&s.failedRequests, 1)
		return map[string]interface{}{
			"url":         reqURL,
			"status_code": 0,
			"content":     "",
			"elapsed":     time.Since(startTime).Seconds(),
			"headers":     map[string]string{},
			"error":       err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	elapsed := time.Since(startTime).Seconds()
	
	s.recordTraffic(int64(reqBodyLen+200), int64(len(body)+500))

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	result := map[string]interface{}{
		"url":         reqURL,
		"status_code": resp.StatusCode,
		"content":     string(body),
		"elapsed":     elapsed,
		"headers":     headers,
		"error":       nil,
	}
	
	s.cache.Set(cacheKey, result)
	atomic.AddInt64(&s.successRequests, 1)

	return result, nil
}

func (s *Scanner) filterPayloadsByLevel(payloads []types.Payload) []types.Payload {
	config := ScanLevelConfigs[s.scanLevel]
	maxPayloads := config.MaxPayloadsPerParam

	if maxPayloads == 0 {
		return payloads
	}
	
	if len(payloads) == 0 {
		return payloads
	}

	if len(payloads) <= maxPayloads {
		return payloads
	}

	var priorityPayloads, secondaryPayloads, otherPayloads []types.Payload

	for _, p := range payloads {
		if p.PayloadType == types.PayloadTypeCodeExec {
			priorityPayloads = append(priorityPayloads, p)
		} else if p.PayloadType == types.PayloadTypeEchoBased {
			secondaryPayloads = append(secondaryPayloads, p)
		} else {
			otherPayloads = append(otherPayloads, p)
		}
	}

	var result []types.Payload
	
	priorityCount := maxPayloads / 2
	if priorityCount > len(priorityPayloads) {
		priorityCount = len(priorityPayloads)
	}
	if priorityCount > 0 {
		result = append(result, priorityPayloads[:priorityCount]...)
	}

	remaining := maxPayloads - len(result)
	if remaining > 0 && len(secondaryPayloads) > 0 {
		takeCount := remaining
		if takeCount > len(secondaryPayloads) {
			takeCount = len(secondaryPayloads)
		}
		result = append(result, secondaryPayloads[:takeCount]...)
	}

	remaining = maxPayloads - len(result)
	if remaining > 0 && len(otherPayloads) > 0 {
		takeCount := remaining
		if takeCount > len(otherPayloads) {
			takeCount = len(otherPayloads)
		}
		result = append(result, otherPayloads[:takeCount]...)
	}

	if len(result) < maxPayloads && len(payloads) > len(result) {
		needed := maxPayloads - len(result)
		for _, p := range payloads {
			found := false
			for _, r := range result {
				if r.Content == p.Content {
					found = true
					break
				}
			}
			if !found {
				result = append(result, p)
				needed--
				if needed <= 0 {
					break
				}
			}
		}
	}

	return result
}

func (s *Scanner) Scan(ctx context.Context, targets []*types.ScanTarget) []*types.ScanResult {
	atomic.StoreInt32(&s.stopFlag, 0)
	results := make([]*types.ScanResult, 0)

	for i, target := range targets {
		if s.isStopped() {
			break
		}

		s.reportProgress(i+1, len(targets), target.URL, nil)

		startTime := time.Now()
		vulns := s.scanTarget(ctx, target)
		scanTime := time.Since(startTime).Seconds()

		result := &types.ScanResult{
			Target:          target.URL,
			Vulnerabilities: vulns,
			TotalRequests:   len(vulns) * 2,
			ScanTime:        scanTime,
		}
		results = append(results, result)
	}

	return results
}

func (s *Scanner) scanTarget(ctx context.Context, target *types.ScanTarget) []types.Vulnerability {
	var vulnerabilities []types.Vulnerability
	var vulnMu sync.Mutex

	s.updateProgress()

	paramsToTest := make([]struct {
		name  string
		value string
	}, 0)

	if target.Parameters != nil {
		for k, v := range target.Parameters {
			paramsToTest = append(paramsToTest, struct {
				name  string
				value string
			}{k, v})
		}
	}
	if target.Data != nil {
		for k, v := range target.Data {
			paramsToTest = append(paramsToTest, struct {
				name  string
				value string
			}{k, v})
		}
	}

	if len(paramsToTest) == 0 {
		parsed, err := url.Parse(target.URL)
		if err == nil && parsed.RawQuery != "" {
			for k, v := range parsed.Query() {
				if len(v) > 0 {
					paramsToTest = append(paramsToTest, struct {
						name  string
						value string
					}{k, v[0]})
				}
			}
		}
	}

	if len(paramsToTest) == 0 {
		return vulnerabilities
	}

	detectedTech := s.detectTechFromURL(target.URL)
	payloads := s.payloadGenerator.GetPayloadsByModeAndTech(s.scanMode, detectedTech)
	
	if s.progressCallback != nil {
		s.progressCallback(0, 0, target.URL, map[string]interface{}{
			"phase": "payloads_before_filter",
			"count": len(payloads),
			"tech": string(detectedTech),
			"mode": string(s.scanMode),
		})
	}
	
	payloads = s.filterPayloadsByLevel(payloads)

	if s.progressCallback != nil {
		s.progressCallback(0, 0, target.URL, map[string]interface{}{
			"phase": "payloads_after_filter",
			"count": len(payloads),
			"level": string(s.scanLevel),
		})
	}

	if len(payloads) == 0 {
		payloads = s.payloadGenerator.GetEchoPayloads()
		if len(payloads) == 0 {
			payloads = s.payloadGenerator.GetAllPayloads()
		}
	}
	
	if len(payloads) == 0 {
		payloads = []types.Payload{
			{Content: "system('id');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP system() - id", ExpectedOutput: "uid="},
			{Content: "system('whoami');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP system() - whoami"},
			{Content: "id", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix id命令"},
			{Content: "whoami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeBoth, Description: "whoami命令"},
		}
	}
	
	if s.progressCallback != nil {
		s.progressCallback(0, 0, target.URL, map[string]interface{}{
			"phase": "payloads_final",
			"count": len(payloads),
		})
	}

	if s.progressCallback != nil {
		s.progressCallback(0, len(payloads), target.URL, map[string]interface{}{
			"phase": "start",
			"params": len(paramsToTest),
			"payloads": len(payloads),
		})
	}

	totalPayloads := len(payloads) * len(paramsToTest)
	var testedPayloads int32

	baselineCtx, baselineCancel := context.WithTimeout(ctx, s.requestTimeout)
	defer baselineCancel()
	baselineResp, _ := s.fetchURL(baselineCtx, target, target.Parameters)
	s.mu.Lock()
	s.baselines[target.URL] = baselineResp
	s.mu.Unlock()

	baselineContent, _ := baselineResp["content"].(string)
	baselineURL, _ := baselineResp["url"].(string)
	
	s.updateProgress()
	
	if s.progressCallback != nil {
		s.progressCallback(0, len(payloads), target.URL, map[string]interface{}{
			"phase": "baseline",
			"baseline_len": len(baselineContent),
			"baseline_url": baselineURL,
			"params": len(paramsToTest),
		})
	}

	if len(payloads) == 0 {
		return vulnerabilities
	}

	tasks := make([]scanTask, 0, totalPayloads)
	for _, param := range paramsToTest {
		for _, p := range payloads {
			tasks = append(tasks, scanTask{param: param.name, payload: p})
		}
	}

	if s.progressCallback != nil && len(tasks) > 0 {
		s.progressCallback(0, len(tasks), target.URL, map[string]interface{}{
			"phase": "tasks_created",
			"task_count": len(tasks),
			"first_param": tasks[0].param,
			"first_payload": tasks[0].payload.Content,
		})
	}

	taskChan := make(chan scanTask, s.maxConcurrent*2)
	resultChan := make(chan scanResult, s.maxConcurrent*2)

	var wg sync.WaitGroup

	for i := 0; i < s.maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskChan {
				if s.isStopped() {
					return
				}

				select {
				case <-ctx.Done():
					return
				default:
				}

				testParams := make(map[string]string)
				
				if target.Method == "POST" {
					if target.Data != nil {
						for k, v := range target.Data {
							testParams[k] = v
						}
					}
				}
				
				for k, v := range target.Parameters {
					testParams[k] = v
				}
				testParams[task.param] = task.payload.Content

				reqCtx, reqCancel := context.WithTimeout(ctx, s.requestTimeout)
				resp, _ := s.fetchURL(reqCtx, target, testParams)
				reqCancel()
				
				s.updateProgress()
				
				respContent, _ := resp["content"].(string)
				respURL, _ := resp["url"].(string)
				
				if s.progressCallback != nil && len(respContent) > 0 {
					s.progressCallback(0, 0, target.URL, map[string]interface{}{
						"phase": "response",
						"param": task.param,
						"payload": task.payload.Content[:min(20, len(task.payload.Content))],
						"resp_len": len(respContent),
						"resp_url": respURL,
						"expected": task.payload.ExpectedOutput,
						"found": task.payload.ExpectedOutput != "" && strings.Contains(respContent, task.payload.ExpectedOutput),
					})
				}

				vuln := s.detector.AnalyzeResponse(resp, task.payload, baselineResp)
				if vuln != nil {
					vuln.Target = target.URL
					vuln.Parameter = task.param
					vuln.RequestData = map[string]interface{}{
						"method": target.Method,
						"params": testParams,
						"headers": target.Headers,
					}
					vuln.ResponseData = resp
					resultChan <- scanResult{vuln: vuln}
				} else {
					resultChan <- scanResult{}
				}
			}
		}()
	}

	go func() {
		for _, task := range tasks {
			if s.isStopped() {
				break
			}
			select {
			case <-ctx.Done():
				break
			default:
				taskChan <- task
			}
		}
		close(taskChan)
	}()

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	timeoutTicker := time.NewTicker(5 * time.Second)
	defer timeoutTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return vulnerabilities
		case <-timeoutTicker.C:
			if s.checkProgressTimeout() {
				return vulnerabilities
			}
		case result, ok := <-resultChan:
			if !ok {
				return vulnerabilities
			}
			current := int(atomic.AddInt32(&testedPayloads, 1))
			paramName := ""
			if result.vuln != nil {
				paramName = result.vuln.Parameter
			}
			s.reportProgress(current, totalPayloads, target.URL, map[string]interface{}{
				"param": paramName,
			})

			if result.vuln != nil {
				vulnMu.Lock()
				vulnerabilities = append(vulnerabilities, *result.vuln)
				vulnMu.Unlock()

				if s.vulnCallback != nil {
					s.vulnCallback(*result.vuln)
				}
			}
		}
	}
}

func (s *Scanner) ScanURL(ctx context.Context, rawURL string, method string, params map[string]string, data map[string]string, headers map[string]string) *types.ScanResult {
	if !utils.IsValidURL(rawURL) {
		return &types.ScanResult{
			Target: rawURL,
			Error:  "无效的URL",
		}
	}

	target := &types.ScanTarget{
		URL:        rawURL,
		Method:     method,
		Parameters: params,
		Data:       data,
		Headers:    headers,
	}

	if target.Method == "" {
		target.Method = "GET"
	}

	results := s.Scan(ctx, []*types.ScanTarget{target})
	if len(results) > 0 {
		return results[0]
	}

	return &types.ScanResult{Target: rawURL}
}

func (s *Scanner) GetStatistics() map[string]interface{} {
	detectorStats := s.detector.GetStatistics()
	stats := make(map[string]interface{})
	for k, v := range detectorStats {
		stats[k] = v
	}
	stats["scan_level"] = string(s.scanLevel)
	stats["scan_level_description"] = ScanLevelConfigs[s.scanLevel].Description
	stats["total_requests"] = atomic.LoadInt64(&s.totalRequests)
	stats["success_requests"] = atomic.LoadInt64(&s.successRequests)
	stats["failed_requests"] = atomic.LoadInt64(&s.failedRequests)
	stats["consecutive_errors"] = atomic.LoadInt32(&s.consecutiveErrors)
	stats["elapsed_time"] = time.Since(s.startTime).Seconds()
	stats["requests_per_second"] = float64(atomic.LoadInt64(&s.totalRequests)) / time.Since(s.startTime).Seconds()
	return stats
}

func (s *Scanner) GetVulnerabilities() []types.Vulnerability {
	return s.detector.GetVulnerabilities()
}

func (s *Scanner) ClearResults() {
	s.detector.Clear()
	s.baselines = make(map[string]map[string]interface{})
}

func GetAvailableLevels() map[string]string {
	result := make(map[string]string)
	for level, config := range ScanLevelConfigs {
		result[string(level)] = config.Description
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
