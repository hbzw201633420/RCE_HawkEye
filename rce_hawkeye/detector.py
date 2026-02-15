"""
漏洞检测器模块
"""

import re
import time
from typing import Dict, List, Optional, Any
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


class Detector:
    """漏洞检测器"""
    
    def __init__(self, delay_threshold: float = 4.0, echo_markers: List[str] = None):
        self.delay_threshold = delay_threshold
        self.echo_markers = echo_markers or ["RCE_TEST_MARKER_12345", "VULN_DETECTED"]
        self.vulnerabilities: List[Vulnerability] = []
    
    def detect_time_based(self, baseline_time: float, response_time: float, 
                          payload: Payload) -> bool:
        """检测时间盲注漏洞"""
        if payload.expected_delay is None:
            return False
        
        time_diff = response_time - baseline_time
        return time_diff >= self.delay_threshold
    
    def detect_echo_based(self, response_content: str, payload: Payload) -> bool:
        """检测回显型漏洞"""
        if payload.expected_output:
            return payload.expected_output in response_content
        
        for marker in self.echo_markers:
            if marker in response_content:
                return True
        
        return False
    
    def detect_command_output(self, response_content: str, baseline_content: str = "") -> bool:
        """检测命令输出特征"""
        if not response_content:
            return False
        
        if baseline_content:
            if response_content == baseline_content:
                return False
        
        command_output_patterns = [
            (r'total\s+\d+\s+drwx', 'ls -la output'),
            (r'drwx[rwx-]+\s+\d+\s+\w+\s+\w+', 'ls -la output'),
            (r'-rw[rwx-]+\s+\d+\s+\w+\s+\w+', 'ls -la output'),
            (r'uid=\d+\(.*\)\s+gid=\d+', 'id command output'),
            (r'root:.*:0:0:', '/etc/passwd content'),
            (r'bin/bash|bin/sh|bin/zsh', 'shell path'),
            (r'Linux\s+\S+\s+\d+\.\d+', 'uname output'),
            (r'Darwin\s+\S+\s+\d+\.\d+', 'macOS uname output'),
            (r'Directory of\s+[A-Z]:', 'Windows dir output'),
            (r'\d+/\d+/\d+\s+\d+:\d+\s+[AP]M', 'Windows date'),
            (r'Volume Serial Number', 'Windows vol output'),
        ]
        
        for pattern, desc in command_output_patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                if baseline_content and re.search(pattern, baseline_content, re.IGNORECASE):
                    continue
                return True
        
        return False
    
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
        """分析响应，检测漏洞"""
        if response.get("error") == "Timeout":
            if payload.payload_type == PayloadType.TIME_BASED:
                return self._create_vulnerability(
                    target=response.get("url", ""),
                    parameter="",
                    payload=payload,
                    severity=Severity.HIGH,
                    evidence="请求超时，可能存在时间盲注漏洞",
                    exploitation="通过时间延迟判断命令是否执行"
                )
            return None
        
        if payload.payload_type == PayloadType.TIME_BASED:
            baseline_time = baseline_response.get("elapsed", 0) if baseline_response else 0
            if self.detect_time_based(baseline_time, response.get("elapsed", 0), payload):
                return self._create_vulnerability(
                    target=response.get("url", ""),
                    parameter="",
                    payload=payload,
                    severity=Severity.HIGH,
                    evidence=f"响应延迟 {response.get('elapsed', 0):.2f}秒，超过阈值 {self.delay_threshold}秒",
                    exploitation="通过sleep/timeout等命令造成延迟"
                )
        
        if payload.payload_type in [PayloadType.ECHO_BASED, PayloadType.CODE_EXEC]:
            content = response.get("content", "")
            baseline_content = baseline_response.get("content", "") if baseline_response else ""
            
            if self.detect_echo_based(content, payload):
                return self._create_vulnerability(
                    target=response.get("url", ""),
                    parameter="",
                    payload=payload,
                    severity=Severity.CRITICAL,
                    evidence=f"在响应中发现预期输出: {payload.expected_output}",
                    exploitation="直接通过回显获取命令执行结果"
                )
            
            if self.detect_command_output(content, baseline_content):
                return self._create_vulnerability(
                    target=response.get("url", ""),
                    parameter="",
                    payload=payload,
                    severity=Severity.CRITICAL,
                    evidence="在响应中发现命令执行输出特征",
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
