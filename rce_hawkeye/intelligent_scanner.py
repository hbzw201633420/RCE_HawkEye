"""
智能扫描器模块
集成技术栈检测和动态Payload加载
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
import aiohttp

from .payload_generator import PayloadGenerator, Payload, PayloadType, OSType, ScanMode, TechType
from .detector import Detector, Vulnerability, Severity
from .dir_scanner import DirectoryScanner, DirScanConfig, DirResult
from .tech_detector import TechStackDetector, TechStack, DetectedTech
from .utils import extract_parameters, build_url, is_valid_url, fetch_url


@dataclass
class ScanTarget:
    url: str
    method: str = "GET"
    parameters: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    data: Dict[str, str] = field(default_factory=dict)


@dataclass
class TechScanResult:
    target: str
    detected_techs: List[DetectedTech] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    total_requests: int = 0
    scan_time: float = 0
    error: Optional[str] = None


@dataclass
class IntelligentScanResult:
    target: str
    dir_scan_results: List[DirResult] = field(default_factory=list)
    detected_techs: List[DetectedTech] = field(default_factory=list)
    tech_scan_results: List[TechScanResult] = field(default_factory=list)
    all_vulnerabilities: List[Vulnerability] = field(default_factory=list)
    total_requests: int = 0
    total_scan_time: float = 0
    tech_statistics: Dict[str, int] = field(default_factory=dict)


class IntelligentScanner:
    """智能扫描器 - 自动检测技术栈并动态加载Payload"""
    
    def __init__(
        self,
        timeout: int = 10,
        max_concurrent: int = 10,
        delay_threshold: float = 4.0,
        max_retries: int = 2,
        user_agent: str = "RCE-HawkEye/0.0.2",
        proxy: Optional[str] = None,
        verify_ssl: bool = False,
        enable_dir_scan: bool = True,
        enable_tech_detection: bool = True
    ):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.delay_threshold = delay_threshold
        self.max_retries = max_retries
        self.user_agent = user_agent
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.enable_dir_scan = enable_dir_scan
        self.enable_tech_detection = enable_tech_detection
        
        self.payload_generator = PayloadGenerator()
        self.detector = Detector(delay_threshold=delay_threshold)
        self.tech_detector = TechStackDetector()
        
        self._scan_mode: ScanMode = ScanMode.HARMLESS
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._progress_callback: Optional[Callable] = None
        self._stop_flag = False
        self._detected_techs: Set[TechType] = set()
    
    def set_progress_callback(self, callback: Callable):
        """设置进度回调函数"""
        self._progress_callback = callback
    
    def set_scan_mode(self, mode: ScanMode):
        """设置扫描模式"""
        self._scan_mode = mode
    
    def stop(self):
        """停止扫描"""
        self._stop_flag = True
    
    async def _create_session(self) -> aiohttp.ClientSession:
        """创建HTTP会话"""
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        
        connector = aiohttp.TCPConnector(
            ssl=self.verify_ssl,
            limit=self.max_concurrent
        )
        
        session = aiohttp.ClientSession(
            headers=headers,
            connector=connector
        )
        
        return session
    
    async def _scan_directory(self, target_url: str) -> List[DirResult]:
        """执行目录扫描"""
        if not self.enable_dir_scan:
            return []
        
        dir_config = DirScanConfig(
            threads=self.max_concurrent,
            timeout=self.timeout,
            extensions=self._get_extensions_for_scan(),
            status_codes=[200, 301, 302, 403, 500],
            max_depth=2,
            recursive=True
        )
        
        dir_scanner = DirectoryScanner(config=dir_config)
        results = await dir_scanner.scan(target_url)
        
        return results
    
    def _get_extensions_for_scan(self) -> List[str]:
        """获取需要扫描的文件扩展名"""
        extensions = []
        for exts in PayloadGenerator.TECH_EXTENSIONS.values():
            extensions.extend(exts)
        return list(set(extensions))
    
    async def _detect_tech_stack(self, target_url: str, dir_results: List[DirResult]) -> List[DetectedTech]:
        """检测技术栈"""
        if not self.enable_tech_detection:
            return []
        
        detected = []
        
        if dir_results:
            detected = self.tech_detector.detect_from_dir_results(dir_results)
        
        try:
            async with self._session.get(target_url) as response:
                headers = dict(response.headers)
                header_detected = self.tech_detector.detect_from_headers(headers)
                
                for tech in header_detected:
                    if tech not in detected:
                        detected.append(tech)
        except Exception:
            pass
        
        for tech in detected:
            self._detected_techs.add(self._convert_tech_stack(tech.tech_stack))
        
        return detected
    
    def _convert_tech_stack(self, tech_stack: TechStack) -> TechType:
        """将TechStack转换为TechType"""
        mapping = {
            TechStack.PHP: TechType.PHP,
            TechStack.JSP_JAVA: TechType.JSP_JAVA,
            TechStack.ASP: TechType.ASP,
            TechStack.ASPX_DOTNET: TechType.ASPX_DOTNET,
            TechStack.PYTHON: TechType.PYTHON,
            TechStack.NODEJS: TechType.NODEJS,
            TechStack.RUBY: TechType.RUBY,
            TechStack.GO: TechType.GO,
            TechStack.PERL: TechType.PERL,
            TechStack.LUA: TechType.LUA,
            TechStack.COLDFUSION: TechType.COLDFUSION,
            TechStack.CGI: TechType.CGI,
        }
        return mapping.get(tech_stack, TechType.PHP)
    
    def _get_dynamic_payloads(self, url: str) -> List[Payload]:
        """根据检测到的技术栈动态获取Payload"""
        if self._detected_techs:
            tech_list = list(self._detected_techs)
            return self.payload_generator.get_payloads_by_detected_techs(tech_list, self._scan_mode)
        
        return self.payload_generator.get_payloads_by_url(url, self._scan_mode)
    
    async def _scan_parameter(
        self,
        target: ScanTarget,
        param_name: str,
        param_value: str,
        payload: Payload
    ) -> Optional[Vulnerability]:
        """扫描单个参数"""
        if self._stop_flag:
            return None
        
        test_params = target.parameters.copy()
        test_params[param_name] = payload.content
        
        if target.method.upper() == "GET":
            test_url = build_url(target.url, test_params)
            response = await fetch_url(
                self._session,
                test_url,
                method="GET",
                headers=target.headers,
                timeout=self.timeout
            )
        else:
            response = await fetch_url(
                self._session,
                target.url,
                method="POST",
                data=test_params,
                headers=target.headers,
                timeout=self.timeout
            )
        
        response["url"] = target.url
        
        baseline_response = {"elapsed": 0}
        vulnerability = self.detector.analyze_response(
            response, payload, baseline_response
        )
        
        if vulnerability:
            vulnerability.target = target.url
            vulnerability.parameter = param_name
            vulnerability.request_data = {
                "method": target.method,
                "params": test_params,
                "headers": target.headers
            }
            vulnerability.response_data = response
            return vulnerability
        
        return None
    
    async def _scan_target_with_tech(self, target: ScanTarget, detected_techs: List[DetectedTech]) -> TechScanResult:
        """使用检测到的技术栈扫描目标"""
        start_time = time.time()
        vulnerabilities = []
        
        params_to_test = []
        if target.parameters:
            params_to_test.extend(target.parameters.items())
        if target.data:
            params_to_test.extend(target.data.items())
        
        if not params_to_test:
            from urllib.parse import parse_qs
            parsed = urlparse(target.url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for key, values in params.items():
                    params_to_test.append((key, values[0] if values else ""))
        
        payloads = self._get_dynamic_payloads(target.url)
        
        tasks = []
        for param_name, param_value in params_to_test:
            for payload in payloads:
                if self._stop_flag:
                    break
                
                task = self._scan_parameter(target, param_name, param_value, payload)
                tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Vulnerability):
                vulnerabilities.append(result)
                self.detector.add_vulnerability(result)
        
        scan_time = time.time() - start_time
        
        return TechScanResult(
            target=target.url,
            detected_techs=detected_techs,
            vulnerabilities=vulnerabilities,
            total_requests=len(tasks),
            scan_time=scan_time
        )
    
    async def scan_intelligent(self, target_url: str) -> IntelligentScanResult:
        """执行智能扫描"""
        self._stop_flag = False
        self._detected_techs.clear()
        self._session = await self._create_session()
        
        total_start_time = time.time()
        all_vulnerabilities = []
        tech_scan_results = []
        dir_results = []
        detected_techs = []
        
        try:
            if self._progress_callback:
                self._progress_callback(
                    phase="directory_scan",
                    target=target_url,
                    status="scanning"
                )
            
            dir_results = await self._scan_directory(target_url)
            
            if self._progress_callback:
                self._progress_callback(
                    phase="tech_detection",
                    target=target_url,
                    status="detecting"
                )
            
            detected_techs = await self._detect_tech_stack(target_url, dir_results)
            
            tech_names = [t.tech_stack.value for t in detected_techs]
            if self._progress_callback:
                self._progress_callback(
                    phase="payload_loading",
                    target=target_url,
                    status="loading",
                    techs=tech_names
                )
            
            target = ScanTarget(url=target_url)
            
            if self._progress_callback:
                self._progress_callback(
                    phase="rce_scan",
                    target=target_url,
                    status="scanning"
                )
            
            tech_result = await self._scan_target_with_tech(target, detected_techs)
            tech_scan_results.append(tech_result)
            all_vulnerabilities.extend(tech_result.vulnerabilities)
            
            for dir_result in dir_results:
                if self._stop_flag:
                    break
                
                if dir_result.status_code == 200:
                    dir_target = ScanTarget(url=dir_result.url)
                    dir_tech_result = await self._scan_target_with_tech(dir_target, detected_techs)
                    tech_scan_results.append(dir_tech_result)
                    all_vulnerabilities.extend(dir_tech_result.vulnerabilities)
        
        finally:
            if self._session:
                await self._session.close()
        
        total_scan_time = time.time() - total_start_time
        
        return IntelligentScanResult(
            target=target_url,
            dir_scan_results=dir_results,
            detected_techs=detected_techs,
            tech_scan_results=tech_scan_results,
            all_vulnerabilities=all_vulnerabilities,
            total_requests=sum(r.total_requests for r in tech_scan_results),
            total_scan_time=total_scan_time,
            tech_statistics=self.payload_generator.get_tech_statistics()
        )
    
    async def scan_multiple(self, targets: List[str]) -> List[IntelligentScanResult]:
        """扫描多个目标"""
        results = []
        for target in targets:
            if self._stop_flag:
                break
            result = await self.scan_intelligent(target)
            results.append(result)
        return results
    
    def scan_sync(self, target_url: str) -> IntelligentScanResult:
        """同步扫描接口"""
        return asyncio.run(self.scan_intelligent(target_url))
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取扫描统计"""
        stats = self.detector.get_statistics()
        stats['detected_techs'] = [t.value for t in self._detected_techs]
        stats['payload_stats'] = self.payload_generator.get_tech_statistics()
        return stats
    
    def get_vulnerabilities(self) -> List[Vulnerability]:
        """获取所有漏洞"""
        return self.detector.get_vulnerabilities()
    
    def clear_results(self):
        """清空扫描结果"""
        self.detector.clear()
        self._detected_techs.clear()
