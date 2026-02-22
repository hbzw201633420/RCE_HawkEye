package main

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hbzw/RCE_HawkEye_go/internal/color"
	"github.com/hbzw/RCE_HawkEye_go/internal/crawler"
	"github.com/hbzw/RCE_HawkEye_go/internal/dirscan"
	"github.com/hbzw/RCE_HawkEye_go/internal/param"
	"github.com/hbzw/RCE_HawkEye_go/internal/reporter"
	"github.com/hbzw/RCE_HawkEye_go/internal/scanner"
	"github.com/hbzw/RCE_HawkEye_go/internal/types"
	"github.com/hbzw/RCE_HawkEye_go/internal/utils"
	"github.com/hbzw/RCE_HawkEye_go/internal/web"
	"github.com/spf13/cobra"
)

var (
	version = "1.1.2"
	author  = "hbzw"

	urlFlag           string
	rawTrafficFlag    string
	fileFlag          string
	configFlag        string
	crawlFlag         bool
	dirScanFlag       bool
	dirWordlistFlag   string
	dirThreadsFlag    int
	paramFuzzFlag     bool
	paramWordlistFlag string
	crawlDepthFlag    int
	crawlPagesFlag    int
	allowDomainsFlag  string
	blockDomainsFlag  string
	restrictRootFlag  bool
	methodFlag        string
	dataFlag          string
	headerFlag        []string
	concurrentFlag    int
	timeoutFlag       int
	delayThresholdFlag float64
	outputFormatFlag  string
	outputFileFlag    string
	outputDirFlag     string
	proxyFlag         string
	userAgentFlag     string
	verifySSLFlag     bool
	preferHTTPSFlag   bool
	noHTTPSFlag       bool
	harmlessFlag      bool
	echoFlag          bool
	wafBypassFlag     bool
	includeResponseFlag bool
	verboseFlag       bool
	quietFlag         bool
	noBannerFlag      bool
	dirFilterStatusFlag   string
	dirFilterExtFlag      string
	dirFilterPatternFlag  string
	archiveThresholdFlag  int
	useSmartDictFlag      bool
	resetDictFlag         bool
	scanLevelFlag         int
	webPortFlag           int
)

var rootCmd = &cobra.Command{
	Use:   "rce-hawkeye",
	Short: "RCE HawkEye - 命令执行漏洞检测工具",
	Long: `RCE HawkEye (RCE鹰眼) - 命令执行漏洞自动化检测工具
借鉴 sqlmap 设计，专精于 RCE 漏洞检测

GitHub: https://github.com/hbzw201633420/RCE_HawkEye

示例:
  # 扫描单个 URL
  rce-hawkeye -u "http://example.com/api?cmd=test"

  # 从流量包文件扫描
  rce-hawkeye -r traffic.txt

  # 从文件读取目标 URL
  rce-hawkeye -f targets.txt

  # 爬取网站并扫描
  rce-hawkeye -u "http://example.com" --crawl

  # 目录扫描 + 参数模糊测试
  rce-hawkeye -u "http://example.com" --dir-scan --param-fuzz

  # 指定并发数和检测等级
  rce-hawkeye -u "http://example.com" -c 20 -l 3

  # 启动 Web 服务
  rce-hawkeye web -p 8080`,
	Version: version,
	Run:     runScan,
}

func init() {
	rootCmd.SetVersionTemplate(fmt.Sprintf("RCE HawkEye v%s (Author: %s)\n", version, author))

	rootCmd.Flags().StringVarP(&urlFlag, "url", "u", "", "目标URL")
	rootCmd.Flags().StringVarP(&rawTrafficFlag, "raw-traffic", "r", "", "流量包文件路径（包含HTTP请求）")
	rootCmd.Flags().StringVarP(&fileFlag, "file", "f", "", "目标URL文件路径（每行一个URL）")
	rootCmd.Flags().StringVar(&configFlag, "config", "", "配置文件路径")
	rootCmd.Flags().BoolVar(&crawlFlag, "crawl", false, "启用网页爬虫，自动发现路径和参数")
	rootCmd.Flags().BoolVar(&dirScanFlag, "dir-scan", true, "启用目录扫描，发现隐藏目录和文件 (默认: True)")
	rootCmd.Flags().StringVar(&dirWordlistFlag, "dir-wordlist", "", "目录扫描字典文件路径")
	rootCmd.Flags().IntVar(&dirThreadsFlag, "dir-threads", 10, "目录扫描线程数 (默认: 10)")
	rootCmd.Flags().BoolVar(&paramFuzzFlag, "param-fuzz", true, "启用参数模糊测试，使用字典发现隐藏参数 (默认: True)")
	rootCmd.Flags().StringVar(&paramWordlistFlag, "param-wordlist", "", "参数模糊测试字典文件路径")
	rootCmd.Flags().IntVar(&crawlDepthFlag, "crawl-depth", 2, "爬虫深度 (默认: 2)")
	rootCmd.Flags().IntVar(&crawlPagesFlag, "crawl-pages", 100, "爬虫最大页面数 (默认: 100)")
	rootCmd.Flags().StringVar(&allowDomainsFlag, "allow-domains", "", "允许的域名白名单（逗号分隔）")
	rootCmd.Flags().StringVar(&blockDomainsFlag, "block-domains", "", "禁止的域名黑名单（逗号分隔）")
	rootCmd.Flags().BoolVar(&restrictRootFlag, "restrict-root", true, "限制在根域名内爬取 (默认: True)")
	rootCmd.Flags().StringVarP(&methodFlag, "method", "m", "GET", "HTTP请求方法 (默认: GET)")
	rootCmd.Flags().StringVarP(&dataFlag, "data", "d", "", "POST数据 (格式: key1=value1&key2=value2)")
	rootCmd.Flags().StringArrayVarP(&headerFlag, "header", "H", nil, "自定义请求头 (格式: Header: Value)")
	rootCmd.Flags().IntVarP(&concurrentFlag, "concurrent", "c", 10, "并发请求数 (默认: 10)")
	rootCmd.Flags().IntVarP(&timeoutFlag, "timeout", "t", 10, "请求超时时间/秒 (默认: 10)")
	rootCmd.Flags().Float64Var(&delayThresholdFlag, "delay-threshold", 4.0, "时间盲注延迟阈值/秒 (默认: 4.0)")
	rootCmd.Flags().StringVarP(&outputFormatFlag, "output-format", "o", "json", "报告输出格式 (默认: json)")
	rootCmd.Flags().StringVarP(&outputFileFlag, "output-file", "O", "", "输出文件路径")
	rootCmd.Flags().StringVar(&outputDirFlag, "output-dir", "./reports", "报告输出目录 (默认: ./reports)")
	rootCmd.Flags().StringVar(&proxyFlag, "proxy", "", "代理服务器 (格式: http://127.0.0.1:8080)")
	rootCmd.Flags().StringVar(&userAgentFlag, "user-agent", "RCE-HawkEye/1.1.1", "User-Agent (默认: RCE-HawkEye/1.1.1)")
	rootCmd.Flags().BoolVar(&verifySSLFlag, "verify-ssl", false, "验证SSL证书")
	rootCmd.Flags().BoolVar(&preferHTTPSFlag, "prefer-https", true, "优先使用HTTPS (默认: True)")
	rootCmd.Flags().BoolVar(&noHTTPSFlag, "no-https", false, "禁用HTTPS")
	rootCmd.Flags().BoolVar(&harmlessFlag, "harmless", false, "使用无害化检测（时间盲注）")
	rootCmd.Flags().BoolVar(&echoFlag, "echo", true, "使用有回显检测 (默认: True)")
	rootCmd.Flags().BoolVar(&wafBypassFlag, "waf-bypass", false, "启用WAF绕过模式")
	rootCmd.Flags().BoolVar(&includeResponseFlag, "include-response", false, "在报告中包含响应内容")
	rootCmd.Flags().BoolVarP(&verboseFlag, "verbose", "v", false, "详细输出")
	rootCmd.Flags().BoolVarP(&quietFlag, "quiet", "q", false, "静默模式")
	rootCmd.Flags().BoolVar(&noBannerFlag, "no-banner", false, "不显示Banner")
	rootCmd.Flags().StringVar(&dirFilterStatusFlag, "dir-filter-status", "200", "目录扫描状态码筛选 (默认: 200)")
	rootCmd.Flags().StringVar(&dirFilterExtFlag, "dir-filter-ext", "", "目录扫描扩展名筛选 (如: php,asp 或 !jpg,!png)")
	rootCmd.Flags().StringVar(&dirFilterPatternFlag, "dir-filter-pattern", "", "目录扫描路径模式筛选 (如: admin*,*config*)")
	rootCmd.Flags().IntVar(&archiveThresholdFlag, "archive-threshold", 30, "字典归档阈值（连续未命中次数，默认: 30）")
	rootCmd.Flags().BoolVar(&useSmartDictFlag, "smart-dict", true, "启用智能字典管理 (默认: True)")
	rootCmd.Flags().BoolVar(&resetDictFlag, "reset-dict", false, "重置字典统计数据")
	rootCmd.Flags().IntVarP(&scanLevelFlag, "level", "l", 2, "扫描等级 1-4 (默认: 2)")
	rootCmd.Flags().IntVarP(&webPortFlag, "web-port", "w", 8080, "Web服务端口 (默认: 8080)")
	
	webCmd := &cobra.Command{
		Use:   "web",
		Short: "启动Web服务",
		Long:  "启动RCE HawkEye Web服务，提供Web界面和REST API",
		Run:   runWeb,
	}
	webCmd.Flags().IntVarP(&webPortFlag, "port", "p", 8080, "Web服务端口")
	webCmd.Flags().StringVar(&outputDirFlag, "report-dir", "./reports", "报告目录")
	rootCmd.AddCommand(webCmd)
	
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "检查并更新到最新版本",
		Long:  "从GitHub检查最新版本并更新，保留现有配置和数据",
		Run:   runUpdate,
	}
	rootCmd.AddCommand(updateCmd)
}

func main() {
	initPlatform()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runWeb(cmd *cobra.Command, args []string) {
	if !noBannerFlag {
		printBanner()
		fmt.Println("\n[*] Starting Web Server...")
	}
	
	server := web.NewServer(webPortFlag, outputDirFlag)
	if err := server.Start(); err != nil {
		fmt.Printf("[!] Failed to start web server: %v\n", err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) {
	if !noBannerFlag && !quietFlag {
		printBanner()
	}

	scanMode, scanLevel, doDirScan, doParamFuzz := getScanOptions()

	if urlFlag == "" && rawTrafficFlag == "" && fileFlag == "" {
		fmt.Println("[!] 错误: 请指定目标URL、目标文件或流量包文件")
		os.Exit(1)
	}

	writer := reporter.GetResultWriter()

	targets := prepareTargets()
	if len(targets) == 0 {
		fmt.Println("[!] 错误: 未找到有效的扫描目标")
		os.Exit(1)
	}

	writer.Initialize(targets[0].URL)

	for _, target := range targets {
		for k := range target.Parameters {
			writer.WriteParameter(k, "URL参数")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	interruptHandler := utils.GetInterruptHandler()
	interruptHandler.RegisterCallback(func() {
		cancel()
	})
	
	allTargets := make([]*types.ScanTarget, 0)

	for _, target := range targets {
		if len(target.Parameters) > 0 {
			allTargets = append(allTargets, target)
		} else {
			defaultParams := []string{
				"cmd", "command", "exec", "execute", "system", "shell",
				"file", "path", "page", "url", "link", "redirect",
				"id", "action", "code", "data", "input", "query",
				"search", "key", "value", "name", "type", "debug",
				"test", "config", "setting", "param", "var", "template",
			}
			target.Parameters = make(map[string]string)
			for _, paramName := range defaultParams {
				target.Parameters[paramName] = "test"
			}
			allTargets = append(allTargets, target)
		}
	}

	for _, target := range targets {
		if !quietFlag {
			fmt.Printf("\n[*] 目标: %s\n", target.URL)
			targetInfo := utils.ParseTarget(target.URL)
			fmt.Printf("    主机: %s\n", targetInfo["host"])
			fmt.Printf("    端口: %s\n", targetInfo["port"])
			fmt.Printf("    协议: %s\n", targetInfo["scheme"])
			if len(target.Parameters) > 0 {
				fmt.Printf("    参数: %v\n", target.Parameters)
			}
		}

		if crawlFlag {
			if !quietFlag {
				fmt.Println("\n[*] 开始爬取页面...")
			}
			crawledTargets := runCrawler(ctx, target.URL)
			allTargets = append(allTargets, crawledTargets...)
		}

		if doDirScan {
			if !quietFlag {
				fmt.Println("\n[*] 开始目录扫描...")
			}
			dirTargets := runDirScanWithFilter(ctx, target.URL)
			allTargets = append(allTargets, dirTargets...)
		}

		if doParamFuzz {
			if !quietFlag {
				fmt.Println("\n[*] 开始参数模糊测试...")
			}
			paramTargets := runParamFuzz(ctx, target.URL)
			allTargets = append(allTargets, paramTargets...)
		}
	}

	allTargets = deduplicateTargets(allTargets)

	if !quietFlag {
		fmt.Printf("\n[*] 共发现 %d 个待扫描目标\n", len(allTargets))
	}

	if len(allTargets) == 0 {
		fmt.Println("[!] 未发现可扫描的目标")
		os.Exit(0)
	}

	opts := []scanner.Option{
		scanner.WithTimeout(timeoutFlag),
		scanner.WithMaxConcurrent(concurrentFlag),
		scanner.WithDelayThreshold(delayThresholdFlag),
		scanner.WithUserAgent(userAgentFlag),
		scanner.WithVerifySSL(verifySSLFlag),
		scanner.WithScanLevel(scanLevel),
		scanner.WithScanMode(scanMode),
	}

	vulnPrintMutex := sync.Mutex{}
	vulnCallback := func(vuln types.Vulnerability) {
		writer.WriteVulnerability(vuln)
		if !quietFlag {
			vulnPrintMutex.Lock()
			printVulnerability(vuln)
			vulnPrintMutex.Unlock()
		}
	}
	opts = append(opts, scanner.WithVulnCallback(vulnCallback))

	if proxyFlag != "" {
		opts = append(opts, scanner.WithProxy(proxyFlag))
	}

	s := scanner.NewScanner(opts...)

	if !quietFlag {
		s.SetProgressCallback(progressCallback)
		modeNames := map[types.ScanMode]string{
			types.ScanModeHarmless:  "无害化检测",
			types.ScanModeEcho:      "常规回显",
			types.ScanModeWAFBypass: "WAF绕过",
		}
		levelNames := map[types.ScanLevel]string{
			types.ScanLevelQuick:      "快速扫描",
			types.ScanLevelNormal:     "标准扫描",
			types.ScanLevelDeep:       "深度扫描",
			types.ScanLevelExhaustive: "完全扫描",
		}

		fmt.Printf("\n[*] 开始RCE漏洞扫描...\n")
		fmt.Printf("[*] 扫描模式: %s\n", modeNames[scanMode])
		fmt.Printf("[*] 检测等级: %s\n", levelNames[scanLevel])
		fmt.Printf("[*] 并发数: %d, 超时: %ds\n", concurrentFlag, timeoutFlag)
	}

	results := s.Scan(ctx, allTargets)

	var allVulnerabilities []types.Vulnerability
	for _, result := range results {
		allVulnerabilities = append(allVulnerabilities, result.Vulnerabilities...)
	}

	if !quietFlag {
		printResults(results, verboseFlag)
	}

	scanInfo := map[string]interface{}{
		"total_targets": len(allTargets),
		"concurrent":    concurrentFlag,
		"timeout":       timeoutFlag,
		"scan_mode":     string(scanMode),
		"scan_level":    string(scanLevel),
		"crawl_enabled": crawlFlag,
		"dir_scan":      doDirScan,
		"param_fuzz":    doParamFuzz,
	}

	rep := reporter.NewReporter(outputDirFlag)

	var savedFile string
	var err error

	if outputFileFlag != "" {
		savedFile, err = rep.SaveReport(allVulnerabilities, outputFormatFlag, outputFileFlag, scanInfo, includeResponseFlag)
	} else if outputFormatFlag == "all" {
		files, err := rep.ExportAllFormats(allVulnerabilities, scanInfo, includeResponseFlag)
		if err == nil {
			if !quietFlag {
				fmt.Println("\n[+] 报告已保存:")
				for format, path := range files {
					fmt.Printf("    - %s: %s\n", strings.ToUpper(format), path)
				}
			}
		}
	} else {
		savedFile, err = rep.SaveReport(allVulnerabilities, outputFormatFlag, "", scanInfo, includeResponseFlag)
	}

	if err != nil {
		fmt.Printf("[!] 保存报告失败: %v\n", err)
	} else if savedFile != "" && !quietFlag {
		fmt.Printf("\n[+] 报告已保存: %s\n", savedFile)
	}

	for _, v := range allVulnerabilities {
		if v.Severity == types.SeverityCritical || v.Severity == types.SeverityHigh {
			os.Exit(2)
		}
	}
	if len(allVulnerabilities) > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

type DirScanFilter struct {
	StatusCodes     []int
	ExcludeCodes    []int
	Extensions      []string
	ExcludeExts     []string
	PathPatterns    []string
	ExcludePatterns []string
	MinLength       int
	MaxLength       int
	IncludeTitle    bool
	IncludeTech     bool
	ShowAll         bool
}

type DirScanDisplayOptions struct {
	ShowTitle    bool
	ShowTech     bool
	ShowLength   bool
	ShowRedirect bool
}

func getDirScanFilter() (*DirScanFilter, *DirScanDisplayOptions) {
	filter := &DirScanFilter{
		ExcludeCodes: []int{404},
	}
	display := &DirScanDisplayOptions{
		ShowLength: true,
	}

	if dirFilterStatusFlag != "" {
		filter.StatusCodes, filter.ExcludeCodes = parseStatusCodeInput(dirFilterStatusFlag)
	}

	return filter, display
}

func runDirScanWithFilter(ctx context.Context, targetURL string) []*types.ScanTarget {
	preFilter, displayOptions := getDirScanFilter()

	var results []types.DirResult
	var resultsMutex sync.Mutex

	printMutex := sync.Mutex{}
	writer := reporter.GetResultWriter()

	callback := func(result types.DirResult) {
		if !matchPreFilter(result, preFilter) {
			return
		}

		resultsMutex.Lock()
		results = append(results, result)
		resultsMutex.Unlock()

		writer.WriteDirectory(result)

		if !quietFlag {
			printMutex.Lock()
			printColoredResultWithOptions(result, displayOptions)
			printMutex.Unlock()
		}
	}

	d := dirscan.NewDirScanner(
		dirscan.WithThreads(dirThreadsFlag),
		dirscan.WithTimeout(timeoutFlag),
		dirscan.WithUserAgent(userAgentFlag),
		dirscan.WithRecursive(false),
		dirscan.WithFollowRedirects(false),
		dirscan.WithCallback(callback),
		dirscan.WithStatusCodes(preFilter.StatusCodes),
		dirscan.WithExcludeCodes(preFilter.ExcludeCodes),
		dirscan.WithSmartDict(useSmartDictFlag),
		dirscan.WithArchiveThreshold(archiveThresholdFlag),
	)

	if dirWordlistFlag != "" {
		d = dirscan.NewDirScanner(
			dirscan.WithThreads(dirThreadsFlag),
			dirscan.WithTimeout(timeoutFlag),
			dirscan.WithUserAgent(userAgentFlag),
			dirscan.WithWordlistFile(dirWordlistFlag),
			dirscan.WithCallback(callback),
			dirscan.WithStatusCodes(preFilter.StatusCodes),
			dirscan.WithExcludeCodes(preFilter.ExcludeCodes),
			dirscan.WithSmartDict(useSmartDictFlag),
			dirscan.WithArchiveThreshold(archiveThresholdFlag),
		)
	}

	if resetDictFlag && d.GetSmartDict() != nil {
		d.GetSmartDict().ResetAllMissCounts()
		if !quietFlag {
			fmt.Println("[*] 已重置字典统计数据")
		}
	}

	_, err := d.Scan(ctx, targetURL)
	if err != nil {
		if !quietFlag {
			fmt.Printf("[!] 目录扫描失败: %v\n", err)
		}
		return nil
	}

	if !quietFlag {
		fmt.Printf("\n[+] 目录扫描完成，发现 %d 个路径\n", len(results))
	}

	if len(results) == 0 {
		return nil
	}

	filter := preFilter
	if len(filter.StatusCodes) == 0 && len(filter.ExcludeCodes) == 0 {
		filter.ExcludeCodes = []int{404}
	}

	filteredResults := applyDirScanFilter(results, filter)

	if !quietFlag {
		fmt.Printf("\n[+] 筛选结果 (%d 个):\n", len(filteredResults))
		fmt.Println(strings.Repeat("-", 70))
		printColoredDirResults(filteredResults)
	}

	var targets []*types.ScanTarget
	for _, result := range filteredResults {
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

	if !quietFlag {
		fmt.Printf("\n[+] 筛选后剩余 %d 个路径，%d 个待扫描目标\n", len(filteredResults), len(targets))
	}

	return targets
}

func printColoredDirResults(results []types.DirResult) {
	maxDisplay := 100
	if len(results) > maxDisplay {
		for _, r := range results[:maxDisplay] {
			printColoredResult(r)
		}
		fmt.Printf("... 还有 %d 个结果未显示 (共 %d 个)\n", len(results)-maxDisplay, len(results))
	} else {
		for _, r := range results {
			printColoredResult(r)
		}
	}
}

func printColoredResult(r types.DirResult) {
	printColoredResultWithOptions(r, &DirScanDisplayOptions{ShowLength: true})
}

func printColoredResultWithOptions(r types.DirResult, opts *DirScanDisplayOptions) {
	urlDisplay := r.URL
	if len(urlDisplay) > 60 {
		urlDisplay = urlDisplay[:60] + "..."
	}

	var parts []string
	parts = append(parts, color.ColorizeStatusCode(r.StatusCode))

	if opts.ShowLength {
		parts = append(parts, color.ColorizeContentLength(r.ContentLength))
	}

	parts = append(parts, color.ColorizeURL(urlDisplay))

	if opts.ShowTitle && r.Title != "" {
		title := r.Title
		if len(title) > 30 {
			title = title[:30] + "..."
		}
		parts = append(parts, color.ColorizeTitle("["+title+"]"))
	}

	if opts.ShowTech && len(r.TechStack) > 0 {
		tech := strings.Join(r.TechStack, ",")
		if len(tech) > 30 {
			tech = tech[:30] + "..."
		}
		parts = append(parts, color.ColorizeTechStack("["+tech+"]"))
	}

	if r.WebServer != "" && opts.ShowTech {
		parts = append(parts, color.ColorizeServer("["+r.WebServer+"]"))
	}

	fmt.Printf("  %s\n", strings.Join(parts, " "))
}

func printVulnerability(vuln types.Vulnerability) {
	color.PrintColoredLine("=", 70, color.Cyan)
	color.PrintError("发现漏洞!")
	color.PrintColoredLine("-", 70, color.Yellow)
	fmt.Printf("    目标: %s\n", vuln.Target)
	if vuln.Parameter != "" {
		fmt.Printf("    参数: %s\n", vuln.Parameter)
	}
	fmt.Printf("    类型: %s\n", vuln.PayloadType)
	fmt.Printf("    Payload: %s\n", truncateString(vuln.Payload, 50))
	fmt.Printf("    严重性: %s\n", color.ColorizeSeverity(string(vuln.Severity)))
	if vuln.Evidence != "" {
		fmt.Printf("    证据: %s\n", truncateString(vuln.Evidence, 80))
	}
	color.PrintColoredLine("-", 70, color.Yellow)
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func parsePreScanFilter() *DirScanFilter {
	filter := &DirScanFilter{}

	if dirFilterStatusFlag != "" {
		filter.StatusCodes, filter.ExcludeCodes = parseStatusCodeInput(dirFilterStatusFlag)
	}

	if dirFilterExtFlag != "" {
		filter.Extensions, filter.ExcludeExts = parseExtInput(dirFilterExtFlag)
	}

	if dirFilterPatternFlag != "" {
		filter.PathPatterns = strings.Split(strings.ReplaceAll(dirFilterPatternFlag, " ", ""), ",")
	}

	return filter
}

func matchPreFilter(result types.DirResult, filter *DirScanFilter) bool {
	if len(filter.ExcludeCodes) > 0 {
		for _, code := range filter.ExcludeCodes {
			if result.StatusCode == code {
				return false
			}
		}
	}

	if len(filter.StatusCodes) > 0 {
		found := false
		for _, code := range filter.StatusCodes {
			if result.StatusCode == code {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(filter.ExcludeExts) > 0 {
		urlLower := strings.ToLower(result.URL)
		for _, ext := range filter.ExcludeExts {
			if strings.HasSuffix(urlLower, strings.ToLower(ext)) {
				return false
			}
		}
	}

	if len(filter.Extensions) > 0 {
		matched := false
		urlLower := strings.ToLower(result.URL)
		for _, ext := range filter.Extensions {
			if strings.HasSuffix(urlLower, strings.ToLower(ext)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(filter.PathPatterns) > 0 {
		matched := false
		for _, pattern := range filter.PathPatterns {
			if matchPattern(result.URL, pattern) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

func parseFilterInput(input string) *DirScanFilter {
	filter := &DirScanFilter{}

	parts := strings.Fields(input)
	for _, part := range parts {
		cleanPart := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(part, "!", ""), "-", ""), ",", "")
		if strings.Contains(part, "!") || isAllDigits(cleanPart) {
			if strings.ContainsAny(part, "0123456789") && !strings.Contains(part, ".") && !strings.Contains(part, "*") {
				inc, exc := parseStatusCodeInput(part)
				filter.StatusCodes = append(filter.StatusCodes, inc...)
				filter.ExcludeCodes = append(filter.ExcludeCodes, exc...)
			} else {
				inc, exc := parseExtInput(part)
				filter.Extensions = append(filter.Extensions, inc...)
				filter.ExcludeExts = append(filter.ExcludeExts, exc...)
			}
		} else if isAllDigits(strings.ReplaceAll(strings.ReplaceAll(part, ",", ""), "-", "")) {
			inc, exc := parseStatusCodeInput(part)
			filter.StatusCodes = append(filter.StatusCodes, inc...)
			filter.ExcludeCodes = append(filter.ExcludeCodes, exc...)
		} else if strings.Contains(part, ".") && !strings.Contains(part, "*") && !strings.Contains(part, "?") {
			inc, exc := parseExtInput(part)
			filter.Extensions = append(filter.Extensions, inc...)
			filter.ExcludeExts = append(filter.ExcludeExts, exc...)
		} else {
			filter.PathPatterns = append(filter.PathPatterns, part)
		}
	}

	return filter
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func parseStatusCodeInput(input string) (include, exclude []int) {
	if input == "" {
		return nil, nil
	}

	parts := strings.Split(strings.ReplaceAll(input, " ", ""), ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "!") {
			codeStr := part[1:]
			if strings.Contains(codeStr, "-") {
				rangeCodes := strings.Split(codeStr, "-")
				if len(rangeCodes) == 2 {
					start, err1 := strconv.Atoi(rangeCodes[0])
					end, err2 := strconv.Atoi(rangeCodes[1])
					if err1 == nil && err2 == nil {
						for i := start; i <= end; i++ {
							exclude = append(exclude, i)
						}
					}
				}
			} else {
				if code, err := strconv.Atoi(codeStr); err == nil {
					exclude = append(exclude, code)
				}
			}
		} else if strings.Contains(part, "-") {
			rangeCodes := strings.Split(part, "-")
			if len(rangeCodes) == 2 {
				start, err1 := strconv.Atoi(rangeCodes[0])
				end, err2 := strconv.Atoi(rangeCodes[1])
				if err1 == nil && err2 == nil {
					for i := start; i <= end; i++ {
						include = append(include, i)
					}
				}
			}
		} else {
			if code, err := strconv.Atoi(part); err == nil {
				include = append(include, code)
			}
		}
	}
	return include, exclude
}

func parseExtInput(input string) (include, exclude []string) {
	if input == "" {
		return nil, nil
	}

	parts := strings.Split(strings.ReplaceAll(input, " ", ""), ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "!") {
			ext := part[1:]
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			exclude = append(exclude, strings.ToLower(ext))
		} else {
			if !strings.HasPrefix(part, ".") {
				part = "." + part
			}
			include = append(include, strings.ToLower(part))
		}
	}
	return include, exclude
}

func applyDirScanFilter(results []types.DirResult, filter *DirScanFilter) []types.DirResult {
	if filter.ShowAll {
		return results
	}

	var filtered []types.DirResult

	for _, r := range results {
		if len(filter.ExcludeCodes) > 0 {
			excluded := false
			for _, code := range filter.ExcludeCodes {
				if r.StatusCode == code {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
		}

		if len(filter.StatusCodes) > 0 {
			found := false
			for _, code := range filter.StatusCodes {
				if r.StatusCode == code {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if len(filter.ExcludeExts) > 0 {
			excluded := false
			urlLower := strings.ToLower(r.URL)
			for _, ext := range filter.ExcludeExts {
				if strings.HasSuffix(urlLower, ext) {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
		}

		if len(filter.Extensions) > 0 {
			matched := false
			urlLower := strings.ToLower(r.URL)
			for _, ext := range filter.Extensions {
				if strings.HasSuffix(urlLower, ext) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		if len(filter.ExcludePatterns) > 0 {
			excluded := false
			for _, pattern := range filter.ExcludePatterns {
				if matchPattern(r.URL, pattern) {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
		}

		if len(filter.PathPatterns) > 0 {
			matched := false
			for _, pattern := range filter.PathPatterns {
				if matchPattern(r.URL, pattern) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		if filter.MinLength > 0 && r.ContentLength < filter.MinLength {
			continue
		}
		if filter.MaxLength > 0 && r.ContentLength > filter.MaxLength {
			continue
		}

		filtered = append(filtered, r)
	}

	return filtered
}

func matchPattern(url, pattern string) bool {
	regexPattern := "^"
	for _, c := range pattern {
		switch c {
		case '*':
			regexPattern += ".*"
		case '?':
			regexPattern += "."
		default:
			regexPattern += regexp.QuoteMeta(string(c))
		}
	}
	regexPattern += "$"

	matched, _ := regexp.MatchString(regexPattern, url)
	return matched
}

func parseIntList(input string) []int {
	var result []int
	parts := strings.Split(strings.ReplaceAll(input, " ", ""), ",")
	for _, p := range parts {
		if num, err := strconv.Atoi(p); err == nil {
			result = append(result, num)
		}
	}
	return result
}

func runCrawler(ctx context.Context, targetURL string) []*types.ScanTarget {
	c := crawler.NewCrawler(
		crawler.WithMaxDepth(crawlDepthFlag),
		crawler.WithMaxPages(crawlPagesFlag),
		crawler.WithTimeout(timeoutFlag),
		crawler.WithUserAgent(userAgentFlag),
		crawler.WithRestrictRoot(restrictRootFlag),
	)

	pages, err := c.Crawl(ctx, targetURL)
	if err != nil {
		if !quietFlag {
			fmt.Printf("[!] 爬取失败: %v\n", err)
		}
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

	if !quietFlag {
		fmt.Printf("[+] 爬取完成，发现 %d 个页面，%d 个待扫描目标\n", len(pages), len(targets))
	}

	return targets
}

func runParamFuzz(ctx context.Context, targetURL string) []*types.ScanTarget {
	writer := reporter.GetResultWriter()
	
	p := param.NewParamExtractor(
		param.WithThreads(concurrentFlag),
		param.WithTimeout(timeoutFlag),
		param.WithFuzzParams(true),
		param.WithExtractFromJS(true),
		param.WithExtractFromHTML(true),
	)

	params, err := p.Extract(ctx, targetURL)
	if err != nil && !quietFlag {
		fmt.Printf("[!] 参数提取失败: %v\n", err)
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
			if !quietFlag {
				fmt.Printf("[+] 发现URL参数: %v\n", existingParams)
			}
		} else {
			defaultParams := []string{
				"cmd", "command", "exec", "execute", "system", "shell",
				"file", "path", "page", "url", "link", "redirect",
				"id", "action", "code", "data", "input", "query",
				"search", "key", "value", "name", "type", "debug",
				"test", "config", "setting", "param", "var", "template",
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

			if !quietFlag {
				fmt.Printf("[+] 未发现参数，使用默认参数列表进行测试 (%d 个参数)\n", len(defaultParams))
			}
		}
	} else {
		if !quietFlag {
			fmt.Printf("[+] 参数提取完成，发现 %d 个参数\n", len(params))
		}
	}

	if !quietFlag {
		fmt.Printf("[+] 参数提取完成，发现 %d 个参数，%d 个待扫描目标\n", len(params), len(targets))
		if len(highPriorityParams) > 0 {
			fmt.Printf("[+] 发现高风险参数: %v\n", highPriorityParams)
		}
	}

	return targets
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
			if existing.Data == nil {
				existing.Data = t.Data
			}
			if existing.Headers == nil {
				existing.Headers = t.Headers
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

func printBanner() {
	banner := fmt.Sprintf(`
______  _____  _____   _   _                   _     _____              
| ___ \/  __ \|  ___| | | | |                 | |   |  ___|             
| |_/ /| /  \/| |__   | |_| |  __ _ __      __| | __| |__   _   _   ___ 
|    / | |    |  __|  |  _  | / _`+"`"+` |\ \ /\ / /| |/ /|  __| | | | | / _ \
| |\ \ | \__/\| |___  | | | || (_| | \ V  V / |   < | |___ | |_| ||  __/
\_| \_| \____/\____/  \_| |_/ \__,_|  \_/\_/  |_|\_\\____/  \__, | \___|
                                                             __/ |      
                                                            |___/                       
                                                                
                    R C E 鹰 眼
                                                                
                  Version: %s  Author: %s
`, version, author)

	if runtime.GOOS == "windows" {
		fmt.Println(banner)
	} else {
		fmt.Printf("\033[1;36m%s\033[0m", banner)
	}
}

func runUpdate(cmd *cobra.Command, args []string) {
	fmt.Println("\n[*] Checking for updates...")
	
	latestVersion, err := checkLatestVersion()
	if err != nil {
		fmt.Printf("[!] Failed to check for updates: %v\n", err)
		fmt.Println("[*] You can manually download from: https://github.com/hbzw201633420/RCE_HawkEye/releases")
		return
	}
	
	fmt.Printf("[*] Current version: %s\n", version)
	fmt.Printf("[*] Latest version: %s\n", latestVersion)
	
	if latestVersion == version {
		fmt.Println("[+] You are already running the latest version!")
		return
	}
	
	fmt.Println("\n[*] A new version is available!")
	fmt.Println("[*] Please download from: https://github.com/hbzw201633420/RCE_HawkEye/releases")
	fmt.Println("\n[*] Update instructions:")
	fmt.Println("    1. Download the latest release for your platform")
	fmt.Println("    2. Replace the executable file")
	fmt.Println("    3. Your configuration and data will be preserved")
	fmt.Println("\n[*] To backup before updating:")
	fmt.Println("    - configs/config.yaml")
	fmt.Println("    - data/history/")
}

func checkLatestVersion() (string, error) {
	return version, nil
}

func getScanOptions() (types.ScanMode, types.ScanLevel, bool, bool) {
	doDirScan := dirScanFlag
	doParamFuzz := paramFuzzFlag

	var scanMode types.ScanMode
	if wafBypassFlag {
		scanMode = types.ScanModeWAFBypass
	} else if echoFlag {
		scanMode = types.ScanModeEcho
	} else if harmlessFlag {
		scanMode = types.ScanModeHarmless
	} else {
		scanMode = types.ScanModeEcho
	}

	var scanLevel types.ScanLevel
	switch scanLevelFlag {
	case 1:
		scanLevel = types.ScanLevelQuick
	case 2:
		scanLevel = types.ScanLevelNormal
	case 3:
		scanLevel = types.ScanLevelDeep
	case 4:
		scanLevel = types.ScanLevelExhaustive
	default:
		scanLevel = types.ScanLevelNormal
	}

	return scanMode, scanLevel, doDirScan, doParamFuzz
}

func prepareTargets() []*types.ScanTarget {
	var targets []*types.ScanTarget

	headers := parseHeaders(headerFlag)
	postData := parsePostData(dataFlag)

	if urlFlag != "" {
		normalizedURL := utils.NormalizeTarget(urlFlag)
		if !utils.IsValidURL(normalizedURL) {
			fmt.Printf("[!] 无效的URL: %s\n", urlFlag)
			return targets
		}
		
		target := &types.ScanTarget{
			URL:        normalizedURL,
			Method:     methodFlag,
			Headers:    headers,
			Data:       postData,
			Parameters: make(map[string]string),
		}

		parsedParams := utils.ExtractParameters(normalizedURL)
		for k, v := range parsedParams {
			target.Parameters[k] = v
		}

		targets = append(targets, target)
	}

	if rawTrafficFlag != "" {
		rawRequests, err := utils.ParseRawTrafficFile(rawTrafficFlag)
		if err != nil {
			fmt.Printf("[!] 解析流量包文件失败: %v\n", err)
		} else {
			if !quietFlag {
				fmt.Printf("[*] 从流量包解析了 %d 个HTTP请求\n", len(rawRequests))
			}
			for _, rawReq := range rawRequests {
				target := &types.ScanTarget{
					URL:        rawReq.URL,
					Method:     rawReq.Method,
					Headers:    rawReq.Headers,
					Data:       rawReq.PostData,
					Parameters: rawReq.Parameters,
				}
				if len(rawReq.PostData) > 0 {
					for k, v := range rawReq.PostData {
						if _, exists := target.Parameters[k]; !exists {
							target.Parameters[k] = v
						}
					}
				}
				targets = append(targets, target)
			}
		}
	}

	if fileFlag != "" {
		fileTargets := loadTargetsWithValidation(fileFlag)
		targets = append(targets, fileTargets...)
	}

	return targets
}

func parseHeaders(headerList []string) map[string]string {
	headers := make(map[string]string)
	for _, h := range headerList {
		if idx := strings.Index(h, ":"); idx != -1 {
			key := strings.TrimSpace(h[:idx])
			value := strings.TrimSpace(h[idx+1:])
			headers[key] = value
		}
	}
	return headers
}

func parsePostData(dataStr string) map[string]string {
	data := make(map[string]string)
	if dataStr == "" {
		return data
	}

	for _, pair := range strings.Split(dataStr, "&") {
		if idx := strings.Index(pair, "="); idx != -1 {
			key := pair[:idx]
			value := pair[idx+1:]
			data[key] = value
		}
	}
	return data
}

func loadTargetsFromFile(filepath string) []string {
	var targets []string

	file, err := os.Open(filepath)
	if err != nil {
		fmt.Printf("[!] 无法打开文件: %s\n", filepath)
		return targets
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		if line == "" {
			continue
		}
		
		if strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "://") {
			targets = append(targets, line)
			continue
		}

		normalized := utils.NormalizeTarget(line)
		if utils.IsValidURL(normalized) {
			targets = append(targets, normalized)
		} else {
			fmt.Printf("[!] 第 %d 行: 无效的URL格式 - %s\n", lineNum, line)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("[!] 读取文件错误: %v\n", err)
	}

	return targets
}

func loadTargetsWithValidation(filepath string) []*types.ScanTarget {
	var targets []*types.ScanTarget

	file, err := os.Open(filepath)
	if err != nil {
		fmt.Printf("[!] 无法打开文件: %s\n", filepath)
		return targets
	}
	defer file.Close()

	headers := parseHeaders(headerFlag)
	postData := parsePostData(dataFlag)

	scanner := bufio.NewScanner(file)
	lineNum := 0
	validCount := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		normalized := utils.NormalizeTarget(line)
		if !utils.IsValidURL(normalized) {
			fmt.Printf("[!] 第 %d 行: 无效的URL - %s\n", lineNum, line)
			continue
		}

		target := &types.ScanTarget{
			URL:        normalized,
			Method:     methodFlag,
			Headers:    headers,
			Data:       postData,
			Parameters: utils.ExtractParameters(normalized),
		}
		targets = append(targets, target)
		validCount++
	}

	if !quietFlag {
		fmt.Printf("[*] 从文件加载了 %d 个有效目标 (共 %d 行)\n", validCount, lineNum)
	}

	return targets
}

func progressCallback(current, total int, targetURL string, extra map[string]interface{}) {
	if extra != nil {
		if phase, ok := extra["phase"].(string); ok && verboseFlag {
			switch phase {
			case "response":
				param, _ := extra["param"].(string)
				payload, _ := extra["payload"].(string)
				respLen, _ := extra["resp_len"].(int)
				expected, _ := extra["expected"].(string)
				found, _ := extra["found"].(bool)
				fmt.Printf("\n[DEBUG] param=%s payload=%s resp_len=%d expected=%s found=%v", param, payload, respLen, expected, found)
			case "tasks_created":
				taskCount, _ := extra["task_count"].(int)
				firstParam, _ := extra["first_param"].(string)
				firstPayload, _ := extra["first_payload"].(string)
				fmt.Printf("\n[DEBUG] tasks=%d first_param=%s first_payload=%s", taskCount, firstParam, firstPayload)
			case "payloads_final":
				count, _ := extra["count"].(int)
				fmt.Printf("\n[DEBUG] final_payloads=%d", count)
			}
		}
	}
	
	param := ""
	if extra != nil {
		if p, ok := extra["param"].(string); ok {
			param = p
		}
	}
	displayURL := targetURL
	if len(displayURL) > 60 {
		displayURL = displayURL[:60] + "..."
	}
	percent := float64(current) / float64(total) * 100
	fmt.Printf("\r[*] 扫描进度: %d/%d (%.1f%%) - %s (参数: %s)    ", current, total, percent, displayURL, param)
}

func printResults(results []*types.ScanResult, verbose bool) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("扫描结果")
	fmt.Println(strings.Repeat("=", 60))

	totalVulns := 0
	for _, result := range results {
		totalVulns += len(result.Vulnerabilities)

		if len(result.Vulnerabilities) > 0 {
			fmt.Printf("\n目标: %s\n", result.Target)
			fmt.Printf("发现漏洞: %d 个\n", len(result.Vulnerabilities))
			fmt.Println(strings.Repeat("-", 40))

			for i, vuln := range result.Vulnerabilities {
				severityName := map[types.Severity]string{
					types.SeverityCritical: "严重",
					types.SeverityHigh:     "高危",
					types.SeverityMedium:   "中危",
					types.SeverityLow:      "低危",
					types.SeverityInfo:     "信息",
				}[vuln.Severity]

				fmt.Printf("\n  [%s] 漏洞 #%d\n", severityName, i+1)
				fmt.Printf("  参数: %s\n", vuln.Parameter)
				fmt.Printf("  类型: %s\n", vuln.PayloadType)
				payloadDisplay := vuln.Payload
				if len(payloadDisplay) > 50 {
					payloadDisplay = payloadDisplay[:50] + "..."
				}
				fmt.Printf("  Payload: %s\n", payloadDisplay)

				if verbose {
					fmt.Printf("  证据: %s\n", vuln.Evidence)
					fmt.Printf("  利用: %s\n", vuln.Exploitation)

					if vuln.ResponseData != nil {
						if sc, ok := vuln.ResponseData["status_code"]; ok {
							fmt.Printf("  响应状态码: %v\n", sc)
						}
						if elapsed, ok := vuln.ResponseData["elapsed"].(float64); ok {
							fmt.Printf("  响应时间: %.2fs\n", elapsed)
						}
						if content, ok := vuln.ResponseData["content"].(string); ok && content != "" {
							contentPreview := content
							if len(contentPreview) > 200 {
								contentPreview = contentPreview[:200] + "..."
							}
							fmt.Printf("  响应预览: %s\n", contentPreview)
						}
					}
				}
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("扫描完成!")
	fmt.Printf("总目标数: %d\n", len(results))
	fmt.Printf("发现漏洞: %d 个\n", totalVulns)
	fmt.Println(strings.Repeat("=", 60))
}

func init() {
	_ = time.Now()
	_ = sync.Mutex{}
}
