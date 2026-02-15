"""
核心扫描器模块
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
import aiohttp
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

from .payload_generator import PayloadGenerator, Payload, PayloadType, OSType, ScanMode
from .detector import Detector, Vulnerability, Severity
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
class ScanResult:
    target: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    total_requests: int = 0
    scan_time: float = 0
    error: Optional[str] = None


class Scanner:
    """命令执行漏洞扫描器"""
    
    def __init__(
        self,
        timeout: int = 10,
        max_concurrent: int = 10,
        delay_threshold: float = 4.0,
        max_retries: int = 2,
        user_agent: str = "RCE-Scanner/1.0",
        proxy: Optional[str] = None,
        verify_ssl: bool = False
    ):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.delay_threshold = delay_threshold
        self.max_retries = max_retries
        self.user_agent = user_agent
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        
        self.payload_generator = PayloadGenerator()
        self.detector = Detector(delay_threshold=delay_threshold)
        
        self._scan_mode: ScanMode = ScanMode.HARMLESS
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._progress_callback: Optional[Callable] = None
        self._stop_flag = False
    
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
    
    async def _scan_target(self, target: ScanTarget) -> List[Vulnerability]:
        """扫描单个目标"""
        vulnerabilities = []
        
        params_to_test = []
        if target.parameters:
            params_to_test.extend(target.parameters.items())
        if target.data:
            params_to_test.extend(target.data.items())
        
        if not params_to_test:
            parsed = urlparse(target.url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for key, values in params.items():
                    params_to_test.append((key, values[0] if values else ""))
        
        payloads = self.payload_generator.get_payloads_by_url(target.url, self._scan_mode)
        
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
        
        return vulnerabilities
    
    async def scan(self, targets: List[ScanTarget]) -> List[ScanResult]:
        """扫描多个目标"""
        self._stop_flag = False
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._session = await self._create_session()
        
        results = []
        total_targets = len(targets)
        
        try:
            for i, target in enumerate(targets):
                if self._stop_flag:
                    break
                
                start_time = time.time()
                
                if self._progress_callback:
                    self._progress_callback(
                        current=i + 1,
                        total=total_targets,
                        target=target.url
                    )
                
                vulnerabilities = await self._scan_target(target)
                
                scan_time = time.time() - start_time
                
                result = ScanResult(
                    target=target.url,
                    vulnerabilities=vulnerabilities,
                    total_requests=len(vulnerabilities) * 2,
                    scan_time=scan_time
                )
                results.append(result)
        
        finally:
            if self._session:
                await self._session.close()
        
        return results
    
    def scan_sync(self, targets: List[ScanTarget]) -> List[ScanResult]:
        """同步扫描接口"""
        return asyncio.run(self.scan(targets))
    
    async def scan_url(self, url: str, method: str = "GET", 
                       params: Dict[str, str] = None,
                       data: Dict[str, str] = None,
                       headers: Dict[str, str] = None) -> ScanResult:
        """扫描单个URL"""
        if not is_valid_url(url):
            return ScanResult(target=url, error="无效的URL")
        
        target = ScanTarget(
            url=url,
            method=method,
            parameters=params or {},
            data=data or {},
            headers=headers or {}
        )
        
        results = await self.scan([target])
        return results[0] if results else ScanResult(target=url, error="扫描失败")
    
    def scan_url_sync(self, url: str, method: str = "GET",
                      params: Dict[str, str] = None,
                      data: Dict[str, str] = None,
                      headers: Dict[str, str] = None) -> ScanResult:
        """同步扫描单个URL"""
        return asyncio.run(self.scan_url(url, method, params, data, headers))
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取扫描统计"""
        return self.detector.get_statistics()
    
    def get_vulnerabilities(self) -> List[Vulnerability]:
        """获取所有漏洞"""
        return self.detector.get_vulnerabilities()
    
    def clear_results(self):
        """清空扫描结果"""
        self.detector.clear()
