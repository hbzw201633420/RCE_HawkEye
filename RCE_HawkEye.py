#!/usr/bin/env python3
"""
RCE HawkEye - 命令执行漏洞检测工具
"""

import argparse
import sys
import json
import asyncio
import platform
import fnmatch
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse

from rce_hawkeye import Scanner, Reporter
from rce_hawkeye.scanner import ScanTarget, ScanResult
from rce_hawkeye.detector import Severity
from rce_hawkeye.traffic_parser import TrafficParser, HttpRequest
from rce_hawkeye.payload_generator import ScanMode
from rce_hawkeye.crawler import WebCrawler, CrawledPage
from rce_hawkeye.config import ConfigManager, DomainConfig
from rce_hawkeye.dir_scanner import DirectoryScanner, DirScanConfig
from rce_hawkeye.param_extractor import ParamExtractor, ParamConfig


__version__ = "0.0.3"
__author__ = "hbzw"


def print_banner():
    """打印ASCII艺术Banner"""
    banner = r"""
______  _____  _____   _   _                   _     _____              
| ___ \/  __ \|  ___| | | | |                 | |   |  ___|             
| |_/ /| /  \/| |__   | |_| |  __ _ __      __| | __| |__   _   _   ___ 
|    / | |    |  __|  |  _  | / _` |\ \ /\ / /| |/ /|  __| | | | | / _ \
| |\ \ | \__/\| |___  | | | || (_| | \ V  V / |   < | |___ | |_| ||  __/
\_| \_| \____/\____/  \_| |_/ \__,_|  \_/\_/  |_|\_\\____/  \__, | \___|
                                                             __/ |      
                                                            |___/                       
                                                                
                    R C E 鹰 眼
                                                                
                  Version: {}  Author: {}
    """.format(__version__, __author__)
    
    print("\033[1;36m" + banner + "\033[0m")


def setup_event_loop():
    """设置事件循环（Windows兼容性修复）"""
    if platform.system() == 'Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="RCE HawkEye - 命令执行漏洞检测工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 扫描单个URL
  python RCE_HawkEye.py -u "http://example.com/api?cmd=test"
  
  # 从流量包文件扫描
  python RCE_HawkEye.py -r traffic.txt
  
  # 从文件读取目标URL
  python RCE_HawkEye.py -f targets.txt
  
  # 爬取网站并扫描
  python RCE_HawkEye.py -u "http://example.com" --crawl
  
  # 指定输出格式
  python RCE_HawkEye.py -u "http://example.com" -o html -O report.html
  
  # 设置并发数和超时
  python RCE_HawkEye.py -u "http://example.com" -c 20 -t 15
  
  # POST请求扫描
  python RCE_HawkEye.py -u "http://example.com/api" -m POST -d "cmd=test"
  
  # 非交互模式（跳过询问）
  python RCE_HawkEye.py -u "http://example.com" --no-interactive --harmless
  
  # 使用配置文件
  python RCE_HawkEye.py -u "http://example.com" --config config/default.yaml
  
  # 设置域名白名单
  python RCE_HawkEye.py -u "http://example.com" --crawl --allow-domains example.com,api.example.com
  
  # 设置域名黑名单
  python RCE_HawkEye.py -u "http://example.com" --crawl --block-domains ads.example.com,tracking.example.com
"""
    )
    
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        "-u", "--url",
        help="目标URL"
    )
    target_group.add_argument(
        "-r", "--raw-traffic",
        help="流量包文件路径（包含HTTP请求）"
    )
    target_group.add_argument(
        "-f", "--file",
        help="目标URL文件路径（每行一个URL）"
    )
    
    parser.add_argument(
        "--config",
        help="配置文件路径"
    )
    
    parser.add_argument(
        "--crawl",
        action="store_true",
        help="启用网页爬虫，自动发现路径和参数"
    )
    
    parser.add_argument(
        "--dir-scan",
        action="store_true",
        help="启用目录扫描，发现隐藏目录和文件"
    )
    
    parser.add_argument(
        "--dir-wordlist",
        help="目录扫描字典文件路径"
    )
    
    parser.add_argument(
        "--dir-threads",
        type=int,
        default=10,
        help="目录扫描线程数 (默认: 10)"
    )
    
    parser.add_argument(
        "--param-fuzz",
        action="store_true",
        help="启用参数模糊测试，使用字典发现隐藏参数"
    )
    
    parser.add_argument(
        "--param-wordlist",
        help="参数模糊测试字典文件路径"
    )
    
    parser.add_argument(
        "--crawl-depth",
        type=int,
        default=2,
        help="爬虫深度 (默认: 2)"
    )
    
    parser.add_argument(
        "--crawl-pages",
        type=int,
        default=100,
        help="爬虫最大页面数 (默认: 100)"
    )
    
    parser.add_argument(
        "--allow-domains",
        help="允许的域名白名单（逗号分隔）"
    )
    
    parser.add_argument(
        "--block-domains",
        help="禁止的域名黑名单（逗号分隔）"
    )
    
    parser.add_argument(
        "--restrict-root",
        action="store_true",
        default=True,
        help="限制在根域名内爬取 (默认: True)"
    )
    
    parser.add_argument(
        "-m", "--method",
        default="GET",
        choices=["GET", "POST"],
        help="HTTP请求方法 (默认: GET)"
    )
    
    parser.add_argument(
        "-d", "--data",
        help="POST数据 (格式: key1=value1&key2=value2)"
    )
    
    parser.add_argument(
        "-H", "--header",
        action="append",
        help="自定义请求头 (格式: Header: Value)"
    )
    
    parser.add_argument(
        "-c", "--concurrent",
        type=int,
        default=10,
        help="并发请求数 (默认: 10)"
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        help="请求超时时间/秒 (默认: 10)"
    )
    
    parser.add_argument(
        "--delay-threshold",
        type=float,
        default=4.0,
        help="时间盲注延迟阈值/秒 (默认: 4.0)"
    )
    
    parser.add_argument(
        "-o", "--output-format",
        choices=["json", "html", "md", "all"],
        default="json",
        help="报告输出格式 (默认: json)"
    )
    
    parser.add_argument(
        "-O", "--output-file",
        help="输出文件路径"
    )
    
    parser.add_argument(
        "--output-dir",
        default="./reports",
        help="报告输出目录 (默认: ./reports)"
    )
    
    parser.add_argument(
        "--proxy",
        help="代理服务器 (格式: http://127.0.0.1:8080)"
    )
    
    parser.add_argument(
        "--user-agent",
        default="RCE-HawkEye/0.0.2",
        help="User-Agent (默认: RCE-HawkEye/0.0.2)"
    )
    
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="验证SSL证书"
    )
    
    parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="非交互模式（跳过所有询问）"
    )
    
    parser.add_argument(
        "--harmless",
        action="store_true",
        help="使用无害化payload（时间盲注）"
    )
    
    parser.add_argument(
        "--echo",
        action="store_true",
        help="使用有回显的payload（ls, whoami等）"
    )
    
    parser.add_argument(
        "--waf-bypass",
        action="store_true",
        help="使用WAF绕过payload"
    )
    
    parser.add_argument(
        "--include-response",
        action="store_true",
        default=True,
        help="在报告中包含响应内容 (默认: True)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="详细输出"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="静默模式"
    )
    
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="不显示Banner"
    )
    
    return parser.parse_args()


def parse_headers(header_list: List[str]) -> Dict[str, str]:
    """解析请求头"""
    headers = {}
    if header_list:
        for h in header_list:
            if ":" in h:
                key, value = h.split(":", 1)
                headers[key.strip()] = value.strip()
    return headers


def parse_post_data(data_str: str) -> Dict[str, str]:
    """解析POST数据"""
    data = {}
    if data_str:
        for pair in data_str.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                data[key] = value
    return data


def load_targets_from_file(filepath: str) -> List[str]:
    """从文件加载目标URL"""
    targets = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def ask_yes_no(question: str, default: bool = True) -> bool:
    """询问是/否问题"""
    default_str = "Y/n" if default else "y/N"
    while True:
        try:
            answer = input(f"{question} [{default_str}]: ").strip().lower()
            if answer == "":
                return default
            if answer in ["y", "yes", "是"]:
                return True
            if answer in ["n", "no", "否"]:
                return False
            print("请输入 y/n 或直接回车使用默认值")
        except (EOFError, KeyboardInterrupt):
            print("\n")
            return default


def interactive_config(args) -> Tuple[ScanMode, bool, bool]:
    """交互式配置扫描模式"""
    do_dir_scan = args.dir_scan if hasattr(args, 'dir_scan') else False
    do_param_fuzz = args.param_fuzz if hasattr(args, 'param_fuzz') else False
    
    if args.no_interactive:
        if args.waf_bypass:
            return ScanMode.WAF_BYPASS, do_dir_scan, do_param_fuzz
        elif args.echo:
            return ScanMode.ECHO, do_dir_scan, do_param_fuzz
        return ScanMode.HARMLESS, do_dir_scan, do_param_fuzz
    
    print("\n" + "=" * 50)
    print("扫描模式配置")
    print("=" * 50)
    
    harmless = ask_yes_no(
        "\n是否使用无害化检测？\n"
        "  [是] 使用时间盲注payload（sleep/timeout），不执行实际命令\n"
        "  [否] 使用有回显的payload（ls/whoami等），可获取命令执行结果",
        default=True
    )
    
    if harmless:
        print("\n已选择: 无害化检测模式")
        scan_mode = ScanMode.HARMLESS
    else:
        print("\n已选择: 常规回显模式")
        scan_mode = ScanMode.ECHO
    
    if not do_dir_scan:
        do_dir_scan = ask_yes_no(
            "\n是否启用目录扫描？\n"
            "  [是] 扫描隐藏目录和文件（如 /admin, /backup 等）\n"
            "  [否] 跳过目录扫描",
            default=False
        )
    
    if not do_param_fuzz:
        do_param_fuzz = ask_yes_no(
            "\n是否启用参数模糊测试？\n"
            "  [是] 使用字典发现隐藏参数（如 id, cmd, file 等）\n"
            "  [否] 跳过参数模糊测试",
            default=False
        )
    
    return scan_mode, do_dir_scan, do_param_fuzz


def print_progress(current: int, total: int, target: str):
    """打印扫描进度"""
    print(f"\r[*] 扫描进度: {current}/{total} - {target[:60]}", end="", flush=True)


def print_results(results: List[ScanResult], verbose: bool = False):
    """打印扫描结果"""
    print("\n")
    print("=" * 60)
    print("扫描结果")
    print("=" * 60)
    
    total_vulns = 0
    for result in results:
        total_vulns += len(result.vulnerabilities)
        
        if result.vulnerabilities:
            print(f"\n目标: {result.target}")
            print(f"发现漏洞: {len(result.vulnerabilities)} 个")
            print("-" * 40)
            
            for i, vuln in enumerate(result.vulnerabilities, 1):
                severity_name = {
                    Severity.CRITICAL: "严重",
                    Severity.HIGH: "高危",
                    Severity.MEDIUM: "中危",
                    Severity.LOW: "低危",
                    Severity.INFO: "信息"
                }.get(vuln.severity, "未知")
                
                print(f"\n  [{severity_name}] 漏洞 #{i}")
                print(f"  参数: {vuln.parameter}")
                print(f"  类型: {vuln.payload_type}")
                payload_display = vuln.payload[:50] + "..." if len(vuln.payload) > 50 else vuln.payload
                print(f"  Payload: {payload_display}")
                
                if verbose:
                    print(f"  证据: {vuln.evidence}")
                    print(f"  利用: {vuln.exploitation}")
                    
                    if vuln.response_data:
                        print(f"  响应状态码: {vuln.response_data.get('status_code', 'N/A')}")
                        print(f"  响应时间: {vuln.response_data.get('elapsed', 0):.2f}s")
                        content = vuln.response_data.get('content', '')
                        if content:
                            content_preview = content[:200] + "..." if len(content) > 200 else content
                            print(f"  响应预览: {content_preview}")
    
    print("\n" + "=" * 60)
    print(f"扫描完成!")
    print(f"总目标数: {len(results)}")
    print(f"发现漏洞: {total_vulns} 个")
    print("=" * 60)


def convert_http_request_to_target(req: HttpRequest) -> ScanTarget:
    """将HTTP请求转换为扫描目标"""
    url = req.get_url()
    params = req.get_parameters()
    
    return ScanTarget(
        url=url,
        method=req.method,
        parameters=params,
        headers=req.headers,
        data=params if req.method.upper() == "POST" else {}
    )


def convert_crawled_page_to_target(page: CrawledPage, form: Dict = None) -> ScanTarget:
    """将爬取的页面转换为扫描目标"""
    if form:
        return ScanTarget(
            url=form['action'],
            method=form['method'],
            data=form['inputs'],
            headers={}
        )
    
    return ScanTarget(
        url=page.url,
        method="GET",
        parameters=page.parameters,
        headers={}
    )


async def crawl_and_scan(args, scanner: Scanner, start_url: str, 
                         domain_config: DomainConfig) -> List[ScanTarget]:
    """爬取网站并生成扫描目标"""
    if not args.quiet:
        print(f"\n[*] 开始爬取网站: {start_url}")
        print(f"[*] 爬取深度: {args.crawl_depth}, 最大页面: {args.crawl_pages}")
    
    crawler = WebCrawler(
        max_depth=args.crawl_depth,
        max_pages=args.crawl_pages,
        timeout=args.timeout,
        concurrent=args.concurrent,
        user_agent=args.user_agent
    )
    
    allowed_domains = domain_config.allowed_domains if domain_config.allowed_domains else None
    blocked_domains = domain_config.blocked_domains if domain_config.blocked_domains else None
    
    if args.restrict_root and not allowed_domains:
        parsed = urlparse(start_url)
        allowed_domains = [parsed.netloc]
    
    pages = await crawler.crawl(start_url, allowed_domains, blocked_domains)
    
    if not args.quiet:
        print(f"[+] 爬取完成，发现 {len(pages)} 个页面")
        
        all_params = crawler.get_unique_parameters()
        if all_params:
            print(f"[+] 发现参数: {', '.join(all_params[:20])}{'...' if len(all_params) > 20 else ''}")
    
    scan_targets = []
    seen_urls = set()
    
    for page in pages:
        if page.parameters:
            target = convert_crawled_page_to_target(page)
            target_key = f"{target.url}|{target.method}|{','.join(sorted(page.parameters.keys()))}"
            if target_key not in seen_urls:
                seen_urls.add(target_key)
                scan_targets.append(target)
        
        for form in page.forms:
            target = convert_crawled_page_to_target(page, form)
            form_params = sorted(form['inputs'].keys()) if form['inputs'] else []
            target_key = f"{target.url}|{target.method}|{','.join(form_params)}"
            if target_key not in seen_urls:
                seen_urls.add(target_key)
                scan_targets.append(target)
    
    if not args.quiet:
        print(f"[+] 生成 {len(scan_targets)} 个扫描目标")
    
    return scan_targets


def filter_urls_by_pattern(urls: List[str], patterns: str, results: List = None) -> List[str]:
    """根据模式过滤URL
    
    Args:
        urls: URL列表
        patterns: 模式字符串，可以是状态码(200,301)或目录通配符(admin*,*.php)
        results: 目录扫描结果列表(包含状态码信息)
    
    Returns:
        过滤后的URL列表
    """
    if not patterns or not patterns.strip():
        return urls
    
    filtered = []
    pattern_list = [p.strip() for p in patterns.split(',')]
    
    status_codes = set()
    url_patterns = []
    
    for p in pattern_list:
        if p.isdigit():
            status_codes.add(int(p))
        else:
            url_patterns.append(p.lower())
    
    for i, url in enumerate(urls):
        matched = False
        
        if status_codes and results:
            for r in results:
                if r.url == url and r.status_code in status_codes:
                    matched = True
                    break
        
        if not matched and url_patterns:
            url_lower = url.lower()
            for pattern in url_patterns:
                if fnmatch.fnmatch(url_lower, f"*{pattern}*"):
                    matched = True
                    break
                if fnmatch.fnmatch(url_lower, pattern):
                    matched = True
                    break
        
        if not status_codes and not url_patterns:
            matched = True
        
        if matched:
            filtered.append(url)
    
    return filtered if filtered else urls


async def dir_scan_and_extract(args, start_url: str, do_dir_scan: bool = False, do_param_fuzz: bool = False) -> Tuple[List[str], Dict[str, str], List]:
    """目录扫描和参数提取"""
    found_urls = []
    found_params = {}
    dir_results = []
    
    if do_dir_scan:
        if not args.quiet:
            print(f"\n[*] 开始目录扫描: {start_url}")
        
        dir_config = DirScanConfig(
            threads=getattr(args, 'dir_threads', 10),
            timeout=args.timeout,
            wordlist=getattr(args, 'dir_wordlist', None),
            user_agent=args.user_agent
        )
        
        dir_scanner = DirectoryScanner(dir_config)
        dir_results = await dir_scanner.scan(start_url)
        
        found_urls = dir_scanner.get_found_urls()
        
        if not args.quiet:
            print(f"[+] 目录扫描完成，发现 {len(found_urls)} 个有效路径")
            
            status_groups = {}
            for r in dir_results:
                code = r.status_code
                if code not in status_groups:
                    status_groups[code] = []
                status_groups[code].append(r)
            
            for code in sorted(status_groups.keys()):
                items = status_groups[code]
                print(f"\n    [{code}] ({len(items)} 个):")
                for r in items[:5]:
                    print(f"      {r.url}")
                if len(items) > 5:
                    print(f"      ... 还有 {len(items) - 5} 个")
            
            if do_param_fuzz and not args.no_interactive:
                print("\n" + "=" * 60)
                print("选择要进行参数扫描的路径")
                print("=" * 60)
                print("输入格式:")
                print("  - 状态码: 200,301,302")
                print("  - 目录通配符: admin*, *.php, *shell*")
                print("  - 组合: 200,admin*,*.php")
                print("  - 直接回车: 扫描全部路径")
                print("-" * 60)
                
                try:
                    user_input = input("请输入过滤条件 [默认:全部]: ").strip()
                    
                    if user_input:
                        found_urls = filter_urls_by_pattern(found_urls, user_input, dir_results)
                        print(f"[+] 已选择 {len(found_urls)} 个路径进行参数扫描")
                    else:
                        print(f"[+] 将对全部 {len(found_urls)} 个路径进行参数扫描")
                except EOFError:
                    pass
    
    if do_param_fuzz:
        if not args.quiet:
            print(f"\n[*] 开始参数提取: {start_url}")
        
        param_config = ParamConfig(
            threads=args.concurrent,
            timeout=args.timeout,
            max_depth=args.crawl_depth,
            max_pages=args.crawl_pages,
            param_wordlist=getattr(args, 'param_wordlist', None),
            user_agent=args.user_agent
        )
        
        param_extractor = ParamExtractor(param_config)
        found_params = await param_extractor.extract(start_url)
        
        if not args.quiet:
            print(f"[+] 参数提取完成，发现 {len(found_params)} 个参数")
            param_list = list(found_params.keys())[:20]
            print(f"    参数: {', '.join(param_list)}{'...' if len(found_params) > 20 else ''}")
    
    return found_urls, found_params, dir_results


async def scan_async(args, scan_mode: ScanMode, do_dir_scan: bool = False, do_param_fuzz: bool = False):
    """异步扫描"""
    targets = []
    scan_targets = []
    
    config_manager = ConfigManager(args.config) if args.config else ConfigManager()
    domain_config = config_manager.domain_config
    
    if args.allow_domains:
        domain_config.allowed_domains = [d.strip() for d in args.allow_domains.split(",")]
    if args.block_domains:
        domain_config.blocked_domains = [d.strip() for d in args.block_domains.split(",")]
    
    if args.url:
        targets.append(args.url)
    
    if args.file:
        file_targets = load_targets_from_file(args.file)
        targets.extend(file_targets)
    
    if args.raw_traffic:
        parser = TrafficParser()
        http_requests = parser.parse_file(args.raw_traffic)
        
        if not args.quiet:
            print(f"[*] 从流量包解析到 {len(http_requests)} 个HTTP请求")
        
        for req in http_requests:
            scan_targets.append(convert_http_request_to_target(req))
    
    if args.url:
        if args.crawl:
            crawled_targets = await crawl_and_scan(args, None, args.url, domain_config)
            scan_targets.extend(crawled_targets)
        
        if do_dir_scan or do_param_fuzz:
            found_urls, found_params, dir_results = await dir_scan_and_extract(args, args.url, do_dir_scan, do_param_fuzz)
            
            for url in found_urls:
                if url not in [t.url for t in scan_targets]:
                    scan_targets.append(ScanTarget(url=url, method="GET"))
        
        if do_param_fuzz:
            param_config = ParamConfig(
                threads=args.concurrent,
                timeout=args.timeout,
                max_depth=1,
                max_pages=10,
                param_wordlist=getattr(args, 'param_wordlist', None),
                user_agent=args.user_agent
            )
            param_extractor = ParamExtractor(param_config)
            param_wordlist = param_extractor.get_param_wordlist()
            
            priority_params = ['a', 'b', 'c', 'cmd', 'command', 'exec', 'shell', 'system', 'file', 'path', 
                              'id', 'page', 'url', 'data', 'action', 'code', 'eval', 'test', 'debug', 'input']
            for p in priority_params:
                if p in param_wordlist:
                    param_wordlist.remove(p)
                    param_wordlist.insert(0, p)
            
            urls_to_fuzz = [args.url]
            if found_urls:
                urls_to_fuzz.extend(found_urls)
            
            for url in urls_to_fuzz:
                for param_name in param_wordlist[:50]:
                    fuzz_url = f"{url}?{param_name}=test"
                    if fuzz_url not in [t.url for t in scan_targets]:
                        scan_targets.append(ScanTarget(url=fuzz_url, method="GET"))
                    scan_targets.append(ScanTarget(
                        url=url,
                        method="POST",
                        data={param_name: "test"}
                    ))
        
        if not args.crawl:
            headers = parse_headers(args.header) if args.header else {}
            post_data = parse_post_data(args.data) if args.data else {}
            
            if args.url not in [t.url for t in scan_targets]:
                scan_targets.append(ScanTarget(
                    url=args.url,
                    method=args.method,
                    data=post_data.copy(),
                    headers=headers.copy()
                ))
    
    if args.file:
        file_targets = load_targets_from_file(args.file)
        headers = parse_headers(args.header) if args.header else {}
        post_data = parse_post_data(args.data) if args.data else {}
        
        for url in file_targets:
            scan_targets.append(ScanTarget(
                url=url,
                method=args.method,
                data=post_data.copy(),
                headers=headers.copy()
            ))
    
    if not scan_targets:
        print("[!] 错误: 请指定目标URL、目标文件或流量包文件")
        sys.exit(1)
    
    scanner = Scanner(
        timeout=args.timeout,
        max_concurrent=args.concurrent,
        delay_threshold=args.delay_threshold,
        user_agent=args.user_agent,
        proxy=args.proxy,
        verify_ssl=args.verify_ssl
    )
    
    scanner.set_scan_mode(scan_mode)
    
    if not args.quiet:
        scanner.set_progress_callback(print_progress)
    
    if not args.quiet:
        mode_names = {
            ScanMode.HARMLESS: "无害化检测",
            ScanMode.ECHO: "常规回显",
            ScanMode.WAF_BYPASS: "WAF绕过"
        }
        print(f"\n[*] 开始扫描 {len(scan_targets)} 个目标...")
        print(f"[*] 扫描模式: {mode_names.get(scan_mode, '未知')}")
        print(f"[*] 并发数: {args.concurrent}, 超时: {args.timeout}s")
        
        if domain_config.allowed_domains:
            print(f"[*] 域名白名单: {', '.join(domain_config.allowed_domains)}")
        if domain_config.blocked_domains:
            print(f"[*] 域名黑名单: {', '.join(domain_config.blocked_domains)}")
    
    results = await scanner.scan(scan_targets)
    
    all_vulnerabilities = []
    for result in results:
        all_vulnerabilities.extend(result.vulnerabilities)
    
    if not args.quiet:
        print_results(results, args.verbose)
    
    reporter = Reporter(output_dir=args.output_dir)
    
    scan_info = {
        "total_targets": len(scan_targets),
        "concurrent": args.concurrent,
        "timeout": args.timeout,
        "scan_mode": scan_mode.value,
        "scan_time": sum(r.scan_time for r in results),
        "allowed_domains": domain_config.allowed_domains,
        "blocked_domains": domain_config.blocked_domains
    }
    
    if args.output_file:
        output_path = Path(args.output_file)
        format_map = {
            ".json": "json",
            ".html": "html",
            ".md": "md",
            ".markdown": "md"
        }
        fmt = format_map.get(output_path.suffix.lower(), args.output_format)
        saved_file = reporter.save_report(
            all_vulnerabilities,
            format=fmt,
            filename=output_path.name,
            scan_info=scan_info,
            include_response=args.include_response
        )
        if not args.quiet:
            print(f"\n[+] 报告已保存: {saved_file}")
    elif args.output_format == "all":
        files = reporter.export_all_formats(all_vulnerabilities, scan_info, args.include_response)
        if not args.quiet:
            print(f"\n[+] 报告已保存:")
            for fmt, filepath in files.items():
                print(f"    - {fmt.upper()}: {filepath}")
    else:
        saved_file = reporter.save_report(
            all_vulnerabilities,
            format=args.output_format,
            scan_info=scan_info,
            include_response=args.include_response
        )
        if not args.quiet:
            print(f"\n[+] 报告已保存: {saved_file}")
    
    return all_vulnerabilities


def main():
    """主函数"""
    setup_event_loop()
    args = parse_args()
    
    if not args.no_banner and not args.quiet:
        print_banner()
    
    try:
        scan_mode, do_dir_scan, do_param_fuzz = interactive_config(args)
        
        vulnerabilities = asyncio.run(scan_async(args, scan_mode, do_dir_scan, do_param_fuzz))
        
        if any(v.severity in [Severity.CRITICAL, Severity.HIGH] for v in vulnerabilities):
            sys.exit(2)
        elif vulnerabilities:
            sys.exit(1)
        else:
            sys.exit(0)
    
    except KeyboardInterrupt:
        print("\n[!] 扫描已取消")
        sys.exit(130)
    except Exception as e:
        print(f"[!] 错误: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
