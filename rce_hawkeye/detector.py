"""
漏洞检测器模块
增强检测逻辑，减少误报
"""

import re
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from .payload_generator import Payload, PayloadType


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    target: str
    parameter: str
    payload: str
    payload_type: str
    severity: Severity
    description: str
    evidence: str
    exploitation: str
    remediation: str
    request_data: Dict[str, Any] = field(default_factory=dict)
    response_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class BaselineResponse:
    content: str
    status_code: int
    content_length: int
    elapsed: float
    headers: Dict[str, str] = field(default_factory=dict)


class Detector:
    """漏洞检测器 - 增强版，减少误报"""
    
    def __init__(self, delay_threshold: float = 4.0, echo_markers: List[str] = None):
        self.delay_threshold = delay_threshold
        self.echo_markers = echo_markers or ["RCE_TEST_MARKER_12345", "VULN_DETECTED"]
        self.vulnerabilities: List[Vulnerability] = []
        self._baselines: Dict[str, BaselineResponse] = {}
    
    def set_baseline(self, url: str, response: Dict[str, Any]):
        """设置基准响应"""
        self._baselines[url] = BaselineResponse(
            content=response.get("content", ""),
            status_code=response.get("status_code", 0),
            content_length=len(response.get("content", "")),
            elapsed=response.get("elapsed", 0),
            headers=response.get("headers", {})
        )
    
    def get_baseline(self, url: str) -> Optional[BaselineResponse]:
        """获取基准响应"""
        return self._baselines.get(url)
    
    def detect_time_based(self, baseline_time: float, response_time: float, 
                          payload: Payload) -> bool:
        """检测时间盲注漏洞"""
        if payload.expected_delay is None:
            return False
        
        time_diff = response_time - baseline_time
        return time_diff >= max(self.delay_threshold, payload.expected_delay * 0.8)
    
    def detect_echo_based(self, response_content: str, payload: Payload,
                         baseline_content: str = "") -> Tuple[bool, str]:
        """检测回显型漏洞 - 返回是否检测到和证据"""
        if payload.expected_output:
            if payload.expected_output in response_content:
                if baseline_content and payload.expected_output in baseline_content:
                    return False, ""
                return True, f"在响应中发现预期输出: {payload.expected_output}"
        
        for marker in self.echo_markers:
            if marker in response_content:
                if baseline_content and marker in baseline_content:
                    continue
                return True, f"在响应中发现回显标记: {marker}"
        
        return False, ""
    
    def detect_command_output(self, response_content: str, 
                              baseline_content: str = "") -> Tuple[bool, str]:
        """检测命令输出特征 - 增强版，减少误报"""
        if not response_content:
            return False, ""
        
        if baseline_content:
            if response_content == baseline_content:
                return False, ""
            
            if abs(len(response_content) - len(baseline_content)) < 10:
                content_diff = set(response_content.split()) - set(baseline_content.split())
                if len(content_diff) < 3:
                    return False, ""
        
        high_confidence_patterns = [
            (r'uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)\s+groups=', 'id命令输出', 0.95),
            (r'total\s+\d+\s+drwx[rwx-]+\s+\d+', 'ls -la输出', 0.90),
            (r'drwx[rwx-]+\s+\d+\s+\w+\s+\w+\s+\d+\s+\w+\s+\d+\s+[\d:]+\s+\S+', 'ls -la详细输出', 0.90),
            (r'-rw[rwx-]+\s+\d+\s+\w+\s+\w+\s+\d+\s+\w+\s+\d+\s+[\d:]+\s+\S+', 'ls -la文件输出', 0.90),
            (r'root:[^:]*:\d+:\d+:', '/etc/passwd内容', 0.95),
            (r'Directory of\s+[A-Z]:\\[^\n]+\n\n', 'Windows dir输出', 0.90),
            (r'Volume Serial Number is [A-Z0-9-]+', 'Windows vol输出', 0.95),
            (r'Linux\s+\S+\s+\d+\.\d+\.\d+', 'uname -a输出', 0.85),
            (r'Darwin\s+\S+\s+\d+\.\d+\.\d+', 'macOS uname输出', 0.85),
        ]
        
        medium_confidence_patterns = [
            (r'/bin/(ba)?sh', 'shell路径', 0.60),
            (r'/usr/bin/\w+', '可执行文件路径', 0.50),
            (r'/home/\w+/', '用户目录路径', 0.50),
        ]
        
        for pattern, desc, confidence in high_confidence_patterns:
            match = re.search(pattern, response_content, re.IGNORECASE)
            if match:
                if baseline_content:
                    baseline_match = re.search(pattern, baseline_content, re.IGNORECASE)
                    if baseline_match:
                        continue
                return True, f"发现高置信度命令输出特征: {desc}"
        
        low_confidence_patterns = [
            (r'bin/bash', 'shell路径', 0.30),
            (r'bin/sh', 'shell路径', 0.30),
        ]
        
        for pattern, desc, confidence in low_confidence_patterns:
            match = re.search(pattern, response_content, re.IGNORECASE)
            if match:
                if baseline_content and re.search(pattern, baseline_content, re.IGNORECASE):
                    continue
                
                if len(response_content) < 500:
                    continue
                
                return True, f"发现可能的命令输出特征: {desc}"
        
        return False, ""
    
    def detect_response_diff(self, response: Dict[str, Any], 
                            baseline: BaselineResponse) -> Tuple[bool, str]:
        """检测响应与基准的差异"""
        content = response.get("content", "")
        status_code = response.get("status_code", 0)
        
        if status_code != baseline.status_code:
            return True, f"状态码变化: {baseline.status_code} -> {status_code}"
        
        content_len = len(content)
        baseline_len = baseline.content_length
        
        if baseline_len > 0:
            diff_ratio = abs(content_len - baseline_len) / baseline_len
            if diff_ratio > 0.5:
                return True, f"响应长度显著变化: {baseline_len} -> {content_len}"
        
        if content and baseline.content:
            if content != baseline.content:
                response_words = set(content.split())
                baseline_words = set(baseline.content.split())
                new_words = response_words - baseline_words
                
                if len(new_words) > 5:
                    return True, f"响应内容有显著差异，新增内容: {list(new_words)[:5]}"
        
        return False, ""
    
    def detect_dns_based(self, dns_log: str, payload: Payload) -> bool:
        """检测DNS外带漏洞"""
        if not dns_log:
            return False
        
        patterns = [
            r'dns\.example\.com',
            r'\w+\.dns\.example\.com',
        ]
        
        for pattern in patterns:
            if re.search(pattern, dns_log):
                return True
        
        return False
    
    def analyze_response(self, response: Dict[str, Any], payload: Payload,
                        baseline_response: Dict[str, Any] = None) -> Optional[Vulnerability]:
        """分析响应，检测漏洞 - 增强版"""
        target_url = response.get("url", "")
        
        baseline = self.get_baseline(target_url)
        if not baseline and baseline_response:
            baseline = BaselineResponse(
                content=baseline_response.get("content", ""),
                status_code=baseline_response.get("status_code", 0),
                content_length=len(baseline_response.get("content", "")),
                elapsed=baseline_response.get("elapsed", 0)
            )
        
        if response.get("error") == "Timeout":
            if payload.payload_type == PayloadType.TIME_BASED:
                return self._create_vulnerability(
                    target=target_url,
                    parameter="",
                    payload=payload,
                    severity=Severity.HIGH,
                    evidence="请求超时，可能存在时间盲注漏洞",
                    exploitation="通过时间延迟判断命令是否执行"
                )
            return None
        
        if payload.payload_type == PayloadType.TIME_BASED:
            baseline_time = baseline.elapsed if baseline else 0
            if self.detect_time_based(baseline_time, response.get("elapsed", 0), payload):
                return self._create_vulnerability(
                    target=target_url,
                    parameter="",
                    payload=payload,
                    severity=Severity.HIGH,
                    evidence=f"响应延迟 {response.get('elapsed', 0):.2f}秒，超过阈值 {self.delay_threshold}秒",
                    exploitation="通过sleep/timeout等命令造成延迟"
                )
        
        if payload.payload_type in [PayloadType.ECHO_BASED, PayloadType.CODE_EXEC]:
            content = response.get("content", "")
            baseline_content = baseline.content if baseline else ""
            
            detected, evidence = self.detect_echo_based(content, payload, baseline_content)
            if detected:
                return self._create_vulnerability(
                    target=target_url,
                    parameter="",
                    payload=payload,
                    severity=Severity.CRITICAL,
                    evidence=evidence,
                    exploitation="直接通过回显获取命令执行结果"
                )
            
            detected, evidence = self.detect_command_output(content, baseline_content)
            if detected:
                return self._create_vulnerability(
                    target=target_url,
                    parameter="",
                    payload=payload,
                    severity=Severity.CRITICAL,
                    evidence=evidence,
                    exploitation="直接通过回显获取命令执行结果"
                )
        
        if payload.payload_type == PayloadType.DNS_BASED:
            pass
        
        return None
    
    def _create_vulnerability(self, target: str, parameter: str, payload: Payload,
                             severity: Severity, evidence: str,
                             exploitation: str) -> Vulnerability:
        """创建漏洞对象"""
        return Vulnerability(
            target=target,
            parameter=parameter,
            payload=payload.content,
            payload_type=payload.payload_type.value,
            severity=severity,
            description=payload.description,
            evidence=evidence,
            exploitation=exploitation,
            remediation=self._get_remediation(payload.payload_type),
            request_data={},
            response_data={}
        )
    
    def _get_remediation(self, payload_type: PayloadType) -> str:
        """获取修复建议"""
        remediations = {
            PayloadType.TIME_BASED: "1. 避免直接执行用户输入\n2. 使用参数化查询或预编译语句\n3. 对输入进行严格的白名单验证\n4. 使用最小权限运行应用",
            PayloadType.ECHO_BASED: "1. 禁用命令执行函数或使用安全替代方案\n2. 对所有用户输入进行严格过滤\n3. 使用沙箱环境隔离执行\n4. 实施输入输出编码",
            PayloadType.CODE_EXEC: "1. 禁用危险的PHP函数(system, exec, shell_exec, passthru等)\n2. 使用disable_functions配置禁用\n3. 对所有用户输入进行严格过滤\n4. 使用最小权限运行应用",
            PayloadType.DNS_BASED: "1. 禁止应用发起外部网络请求\n2. 使用DNS解析白名单\n3. 监控异常DNS查询\n4. 实施网络隔离",
            PayloadType.FILE_BASED: "1. 限制文件系统访问权限\n2. 禁止写入Web目录\n3. 使用chroot或容器隔离\n4. 监控文件系统变更"
        }
        return remediations.get(payload_type, "实施输入验证和输出编码")
    
    def add_vulnerability(self, vulnerability: Vulnerability):
        """添加漏洞"""
        self.vulnerabilities.append(vulnerability)
    
    def get_vulnerabilities(self) -> List[Vulnerability]:
        """获取所有漏洞"""
        return self.vulnerabilities
    
    def get_vulnerabilities_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """按严重程度获取漏洞"""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def clear(self):
        """清空漏洞列表"""
        self.vulnerabilities.clear()
        self._baselines.clear()
    
    def get_statistics(self) -> Dict[str, int]:
        """获取漏洞统计"""
        stats = {
            "total": len(self.vulnerabilities),
            "critical": len(self.get_vulnerabilities_by_severity(Severity.CRITICAL)),
            "high": len(self.get_vulnerabilities_by_severity(Severity.HIGH)),
            "medium": len(self.get_vulnerabilities_by_severity(Severity.MEDIUM)),
            "low": len(self.get_vulnerabilities_by_severity(Severity.LOW)),
            "info": len(self.get_vulnerabilities_by_severity(Severity.INFO))
        }
        return stats
