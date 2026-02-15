"""
核心扫描器模块
优化版 - 支持检测等级、并行基准响应获取
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import aiohttp
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

from .payload_generator import PayloadGenerator, Payload, PayloadType, OSType, ScanMode, TechType
from .detector import Detector, Vulnerability, Severity, BaselineResponse
from .utils import extract_parameters, build_url, is_valid_url, fetch_url


class ScanLevel(Enum):
    """检测等级"""
    QUICK = "quick"
    NORMAL = "normal"
    DEEP = "deep"
    EXHAUSTIVE = "exhaustive"


SCAN_LEVEL_CONFIG = {
    ScanLevel.QUICK: {
        "max_payloads_per_param": 10,
        "include_waf_bypass": False,
        "include_template": False,
        "include_advanced": False,
        "description": "快速扫描 - 仅测试最关键的Payload"
    },
    ScanLevel.NORMAL: {
        "max_payloads_per_param": 30,
        "include_waf_bypass": False,
        "include_template": True,
        "include_advanced": False,
        "description": "标准扫描 - 平衡速度和覆盖率"
    },
    ScanLevel.DEEP: {
        "max_payloads_per_param": 60,
        "include_waf_bypass": True,
        "include_template": True,
        "include_advanced": True,
        "description": "深度扫描 - 全面检测"
    },
    ScanLevel.EXHAUSTIVE: {
        "max_payloads_per_param": None,
        "include_waf_bypass": True,
        "include_template": True,
        "include_advanced": True,
        "description": " exhaustive扫描 - 测试所有Payload"
    }
}


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
    """命令执行漏洞扫描器 - 优化版"""
    
    def __init__(
        self,
        timeout: int = 10,
        max_concurrent: int = 20,
        delay_threshold: float = 4.0,
        max_retries: int = 2,
        user_agent: str = "RCE-Scanner/1.0",
        proxy: Optional[str] = None,
        verify_ssl: bool = False,
        scan_level: ScanLevel = ScanLevel.NORMAL
    ):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.delay_threshold = delay_threshold
        self.max_retries = max_retries
        self.user_agent = user_agent
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.scan_level = scan_level
        
        self.payload_generator = PayloadGenerator()
        self.detector = Detector(delay_threshold=delay_threshold)
        
        self._scan_mode: ScanMode = ScanMode.HARMLESS
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._progress_callback: Optional[Callable] = None
        self._stop_flag = False
        self._baselines: Dict[str, Dict[str, Any]] = {}
    
    def set_progress_callback(self, callback: Callable):
        """设置进度回调函数"""
        self._progress_callback = callback
    
    def set_scan_mode(self, mode: ScanMode):
        """设置扫描模式"""
        self._scan_mode = mode
    
    def set_scan_level(self, level: ScanLevel):
        """设置检测等级"""
        self.scan_level = level
    
    def get_scan_level_description(self) -> str:
        """获取当前检测等级描述"""
        return SCAN_LEVEL_CONFIG[self.scan_level]["description"]
    
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
            limit=self.max_concurrent,
            limit_per_host=self.max_concurrent,
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout // 2)
        
        session = aiohttp.ClientSession(
            headers=headers,
            connector=connector,
            timeout=timeout
        )
        
        return session
    
    async def _fetch_with_semaphore(self, url: str, method: str = "GET", 
                                     data: Dict = None,
                                     headers: Dict = None) -> Dict[str, Any]:
        """使用信号量限制并发请求"""
        async with self._semaphore:
            return await fetch_url(
                self._session,
                url,
                method=method,
                data=data,
                headers=headers,
                timeout=self.timeout
            )
    
    async def _fetch_baseline(self, target: ScanTarget) -> Dict[str, Any]:
        """获取基准响应"""
        if target.method.upper() == "GET":
            baseline_url = build_url(target.url, target.parameters)
            response = await self._fetch_with_semaphore(
                baseline_url,
                method="GET",
                headers=target.headers
            )
        else:
            response = await self._fetch_with_semaphore(
                target.url,
                method="POST",
                data=target.parameters,
                headers=target.headers
            )
        
        response["url"] = target.url
        return response
    
    async def _fetch_baselines_parallel(self, target: ScanTarget, 
                                         params_to_test: List[Tuple[str, str]]) -> Dict[str, Dict[str, Any]]:
        """并行获取所有参数的基准响应"""
        tasks = []
        param_names = []
        
        for param_name, param_value in params_to_test:
            test_params = target.parameters.copy()
            test_params[param_name] = "test_baseline_value_12345"
            
            if target.method.upper() == "GET":
                test_url = build_url(target.url, test_params)
                task = self._fetch_with_semaphore(test_url, method="GET", headers=target.headers)
            else:
                task = self._fetch_with_semaphore(
                    target.url, method="POST", data=test_params, headers=target.headers
                )
            
            tasks.append(task)
            param_names.append(param_name)
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        baselines = {}
        for i, response in enumerate(responses):
            if not isinstance(response, Exception):
                response["url"] = target.url
                baselines[param_names[i]] = response
        
        return baselines
    
    async def _scan_parameter(
        self,
        target: ScanTarget,
        param_name: str,
        param_value: str,
        payload: Payload,
        baseline_response: Dict[str, Any]
    ) -> Optional[Vulnerability]:
        """扫描单个参数"""
        if self._stop_flag:
            return None
        
        test_params = target.parameters.copy()
        test_params[param_name] = payload.content
        
        if target.method.upper() == "GET":
            test_url = build_url(target.url, test_params)
            response = await self._fetch_with_semaphore(
                test_url,
                method="GET",
                headers=target.headers
            )
        else:
            response = await self._fetch_with_semaphore(
                target.url,
                method="POST",
                data=test_params,
                headers=target.headers
            )
        
        response["url"] = target.url
        
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
    
    def _filter_payloads_by_level(self, payloads: List[Payload]) -> List[Payload]:
        """根据检测等级过滤Payload"""
        config = SCAN_LEVEL_CONFIG[self.scan_level]
        max_payloads = config["max_payloads_per_param"]
        
        if max_payloads is None:
            return payloads
        
        priority_payloads = []
        secondary_payloads = []
        other_payloads = []
        
        for p in payloads:
            if p.payload_type == PayloadType.CODE_EXEC:
                priority_payloads.append(p)
            elif p.payload_type == PayloadType.ECHO_BASED:
                secondary_payloads.append(p)
            else:
                other_payloads.append(p)
        
        result = []
        result.extend(priority_payloads[:max_payloads // 2])
        
        remaining = max_payloads - len(result)
        result.extend(secondary_payloads[:remaining])
        
        remaining = max_payloads - len(result)
        if remaining > 0 and config["include_waf_bypass"]:
            result.extend(other_payloads[:remaining])
        
        return result[:max_payloads]
    
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
        
        if not params_to_test:
            return vulnerabilities
        
        payloads = self.payload_generator.get_payloads_by_url(target.url, self._scan_mode)
        payloads = self._filter_payloads_by_level(payloads)
        
        target_baseline = await self._fetch_baseline(target)
        self.detector.set_baseline(target.url, target_baseline)
        
        param_baselines = await self._fetch_baselines_parallel(target, params_to_test)
        
        tasks = []
        for param_name, param_value in params_to_test:
            baseline = param_baselines.get(param_name, target_baseline)
            for payload in payloads:
                if self._stop_flag:
                    break
                
                task = self._scan_parameter(target, param_name, param_value, payload, baseline)
                tasks.append(task)
        
        batch_size = self.max_concurrent * 2
        for i in range(0, len(tasks), batch_size):
            if self._stop_flag:
                break
            
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            
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
        stats = self.detector.get_statistics()
        stats["scan_level"] = self.scan_level.value
        stats["scan_level_description"] = self.get_scan_level_description()
        return stats
    
    def get_vulnerabilities(self) -> List[Vulnerability]:
        """获取所有漏洞"""
        return self.detector.get_vulnerabilities()
    
    def clear_results(self):
        """清空扫描结果"""
        self.detector.clear()
        self._baselines.clear()
    
    @staticmethod
    def get_available_levels() -> Dict[str, str]:
        """获取所有可用的检测等级"""
        return {level.value: config["description"] for level, config in SCAN_LEVEL_CONFIG.items()}
