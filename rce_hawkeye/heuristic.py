"""
启发式检测模块
借鉴sqlmap的启发式检测设计，智能识别RCE注入点
"""

import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum


class InjectionType(Enum):
    COMMAND_INJECTION = "command_injection"
    CODE_INJECTION = "code_injection"
    TEMPLATE_INJECTION = "template_injection"
    EVAL_INJECTION = "eval_injection"
    DESERIALIZATION = "deserialization"
    UNKNOWN = "unknown"


@dataclass
class HeuristicResult:
    injectable: bool
    injection_type: InjectionType
    confidence: float
    evidence: str
    parameter: str
    payload: str


class HeuristicChecker:
    """启发式检测器 - 智能识别RCE注入点"""
    
    COMMAND_INJECTION_MARKERS = [
        (r'uid=\d+\([^)]*\)', 0.95, 'id命令输出'),
        (r'gid=\d+\([^)]*\)', 0.90, 'id命令输出'),
        (r'total\s+\d+\s+drwx', 0.90, 'ls -la输出'),
        (r'drwx[rwx-]+\s+\d+', 0.85, 'ls输出'),
        (r'-rw[rwx-]+\s+\d+', 0.85, 'ls输出'),
        (r'root:[^:]*:\d+:\d+:', 0.95, '/etc/passwd内容'),
        (r'Directory of\s+[A-Z]:\\', 0.90, 'Windows dir输出'),
        (r'Volume Serial Number', 0.90, 'Windows vol输出'),
        (r'Linux\s+\S+\s+\d+\.\d+', 0.85, 'uname输出'),
        (r'Darwin\s+\S+\s+\d+\.\d+', 0.85, 'macOS uname输出'),
        (r'/bin/(ba)?sh', 0.70, 'shell路径'),
        (r'/usr/bin/\w+', 0.60, '可执行文件路径'),
        (r'/home/\w+/', 0.50, '用户目录'),
        (r'www-data:\d:', 0.85, 'www-data用户'),
        (r'apache:\d:', 0.85, 'apache用户'),
        (r'nginx:\d:', 0.85, 'nginx用户'),
        (r'nobody:\d:', 0.80, 'nobody用户'),
    ]
    
    CODE_INJECTION_MARKERS = [
        (r'Fatal error:.+in\s+/', 0.80, 'PHP错误'),
        (r'Warning:.+in\s+/', 0.70, 'PHP警告'),
        (r'Parse error:.+in\s+/', 0.85, 'PHP语法错误'),
        (r'Call to undefined function', 0.75, 'PHP未定义函数'),
        (r'Cannot redeclare', 0.70, 'PHP重复声明'),
        (r'java\.lang\.\w+Exception', 0.80, 'Java异常'),
        (r'java\.lang\.\w+Error', 0.85, 'Java错误'),
        (r'javax\.servlet\.', 0.75, 'JSP Servlet'),
        (r'at\s+java\.', 0.70, 'Java堆栈'),
        (r'Traceback \(most recent call last\)', 0.85, 'Python异常'),
        (r'File\s+"[^"]+",\s+line\s+\d+', 0.80, 'Python错误位置'),
        (r'SyntaxError:', 0.85, 'Python语法错误'),
        (r'NameError:', 0.75, 'Python名称错误'),
        (r'TypeError:', 0.70, 'Python类型错误'),
        (r'ReferenceError:', 0.75, 'JavaScript引用错误'),
        (r'SyntaxError:', 0.80, 'JavaScript语法错误'),
        (r'TypeError:', 0.70, 'JavaScript类型错误'),
        (r'RuntimeError:', 0.75, 'Ruby运行时错误'),
        (r'panic:', 0.85, 'Go panic'),
        (r'goroutine\s+\d+', 0.70, 'Go goroutine'),
    ]
    
    TEMPLATE_INJECTION_MARKERS = [
        (r'49', 0.60, '7*7计算结果'),
        (r'7777777', 0.70, '7*7*7*7*7*7*7结果'),
        (r'config\s*=', 0.75, 'Flask config'),
        (r'Config\s*\{', 0.75, 'Flask Config对象'),
        (r'<Config\s+', 0.80, 'Flask Config对象'),
        (r'os\.environ', 0.80, '环境变量'),
        (r'<class\s+', 0.70, 'Python类对象'),
        (r'<module\s+', 0.70, 'Python模块'),
        (r'<function\s+', 0.65, 'Python函数'),
        (r'__class__\s*=\s*<class', 0.85, 'Python类访问'),
        (r'__mro__\s*=', 0.85, 'Python MRO'),
        (r'__subclasses__\s*=', 0.85, 'Python子类'),
    ]
    
    ERROR_PATTERNS = [
        (r'sh:\s*\d+:', 0.80, 'Shell错误'),
        (r'bash:', 0.80, 'Bash错误'),
        (r'/bin/sh:', 0.80, 'Shell错误'),
        (r'command not found', 0.75, '命令未找到'),
        (r'No such file or directory', 0.70, '文件不存在'),
        (r'Permission denied', 0.65, '权限拒绝'),
        (r'Access denied', 0.65, '访问拒绝'),
        (r'is not recognized', 0.75, 'Windows命令错误'),
        (r"' is not recognized", 0.80, 'Windows命令错误'),
        (r'系统找不到指定的路径', 0.75, 'Windows路径错误'),
        (r'内部或外部命令', 0.75, 'Windows命令错误'),
    ]
    
    REFLECTION_PATTERNS = [
        (r'RAND_[a-f0-9]{8}', 0.90, '随机标记反射'),
        (r'RCE_TEST_[a-f0-9]{8}', 0.90, '测试标记反射'),
        (r'HAWKEYE_[a-f0-9]{8}', 0.90, 'Hawkeye标记反射'),
    ]
    
    def __init__(self):
        self._cache: Dict[str, HeuristicResult] = {}
    
    def check_response(self, response: str, baseline: str = "", 
                       parameter: str = "", payload: str = "") -> HeuristicResult:
        """检查响应是否存在注入特征"""
        cache_key = f"{response[:100]}_{parameter}_{payload[:50]}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        if baseline and response == baseline:
            return HeuristicResult(
                injectable=False,
                injection_type=InjectionType.UNKNOWN,
                confidence=0.0,
                evidence="响应与基准相同",
                parameter=parameter,
                payload=payload
            )
        
        result = self._analyze_response(response, parameter, payload)
        self._cache[cache_key] = result
        return result
    
    def _analyze_response(self, response: str, parameter: str, 
                          payload: str) -> HeuristicResult:
        """分析响应内容"""
        for pattern, confidence, desc in self.COMMAND_INJECTION_MARKERS:
            if re.search(pattern, response, re.IGNORECASE):
                return HeuristicResult(
                    injectable=True,
                    injection_type=InjectionType.COMMAND_INJECTION,
                    confidence=confidence,
                    evidence=f"发现命令注入特征: {desc}",
                    parameter=parameter,
                    payload=payload
                )
        
        for pattern, confidence, desc in self.CODE_INJECTION_MARKERS:
            if re.search(pattern, response, re.IGNORECASE):
                return HeuristicResult(
                    injectable=True,
                    injection_type=InjectionType.CODE_INJECTION,
                    confidence=confidence,
                    evidence=f"发现代码注入特征: {desc}",
                    parameter=parameter,
                    payload=payload
                )
        
        for pattern, confidence, desc in self.TEMPLATE_INJECTION_MARKERS:
            if re.search(pattern, response, re.IGNORECASE):
                if "7*7" in payload or "{{" in payload or "${" in payload:
                    return HeuristicResult(
                        injectable=True,
                        injection_type=InjectionType.TEMPLATE_INJECTION,
                        confidence=confidence,
                        evidence=f"发现模板注入特征: {desc}",
                        parameter=parameter,
                        payload=payload
                    )
        
        for pattern, confidence, desc in self.ERROR_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                return HeuristicResult(
                    injectable=True,
                    injection_type=InjectionType.COMMAND_INJECTION,
                    confidence=confidence * 0.8,
                    evidence=f"发现错误信息: {desc}",
                    parameter=parameter,
                    payload=payload
                )
        
        return HeuristicResult(
            injectable=False,
            injection_type=InjectionType.UNKNOWN,
            confidence=0.0,
            evidence="未发现注入特征",
            parameter=parameter,
            payload=payload
        )
    
    def check_time_based(self, elapsed: float, threshold: float = 4.0,
                         expected_delay: float = 5.0) -> Tuple[bool, float]:
        """检查时间盲注"""
        if elapsed >= threshold and elapsed >= expected_delay * 0.8:
            confidence = min(0.95, elapsed / expected_delay)
            return True, confidence
        return False, 0.0
    
    def check_reflection(self, response: str, marker: str) -> Tuple[bool, float]:
        """检查标记反射"""
        if marker in response:
            return True, 0.90
        return False, 0.0
    
    def identify_backend(self, response: str) -> Optional[str]:
        """识别后端技术"""
        backend_patterns = [
            (r'PHP/\d+\.\d+', 'PHP'),
            (r'X-Powered-By:\s*PHP', 'PHP'),
            (r'Apache/\d+\.\d+', 'Apache'),
            (r'nginx/\d+\.\d+', 'Nginx'),
            (r'Microsoft-IIS/\d+\.\d+', 'IIS'),
            (r'Tomcat/\d+\.\d+', 'Tomcat'),
            (r'JBoss', 'JBoss'),
            (r'WebLogic', 'WebLogic'),
            (r'gunicorn', 'Python/Gunicorn'),
            (r'uWSGI', 'Python/uWSGI'),
            (r'Express', 'Node.js/Express'),
            (r'Phusion Passenger', 'Ruby/Passenger'),
            (r'OpenResty', 'OpenResty/Lua'),
        ]
        
        for pattern, backend in backend_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return backend
        return None
    
    def identify_os(self, response: str) -> Optional[str]:
        """识别操作系统"""
        os_patterns = [
            (r'Linux\s+\S+\s+\d+\.\d+', 'Linux'),
            (r'Darwin\s+\S+\s+\d+\.\d+', 'macOS'),
            (r'Windows\s+\d+', 'Windows'),
            (r'Microsoft\s+Windows', 'Windows'),
            (r'WINNT', 'Windows'),
            (r'/etc/passwd', 'Unix/Linux'),
            (r'/bin/(ba)?sh', 'Unix/Linux'),
            (r'C:\\\\Windows', 'Windows'),
            (r'D:\\\\', 'Windows'),
        ]
        
        for pattern, os_name in os_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return os_name
        return None
    
    def get_injection_points(self, url: str, method: str = "GET",
                            params: Dict[str, str] = None,
                            headers: Dict[str, str] = None,
                            cookies: Dict[str, str] = None,
                            data: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """识别潜在注入点"""
        injection_points = []
        
        if params:
            for param_name, param_value in params.items():
                injection_points.append({
                    'type': 'GET_PARAM',
                    'parameter': param_name,
                    'value': param_value,
                    'location': 'query'
                })
        
        if data:
            for param_name, param_value in data.items():
                injection_points.append({
                    'type': 'POST_PARAM',
                    'parameter': param_name,
                    'value': param_value,
                    'location': 'body'
                })
        
        if headers:
            for header_name, header_value in headers.items():
                if header_name.lower() in ['user-agent', 'referer', 'x-forwarded-for', 'cookie']:
                    injection_points.append({
                        'type': 'HEADER',
                        'parameter': header_name,
                        'value': header_value,
                        'location': 'header'
                    })
        
        if cookies:
            for cookie_name, cookie_value in cookies.items():
                injection_points.append({
                    'type': 'COOKIE',
                    'parameter': cookie_name,
                    'value': cookie_value,
                    'location': 'cookie'
                })
        
        return injection_points
    
    def prioritize_parameters(self, injection_points: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """根据参数名优先级排序"""
        high_priority = ['cmd', 'command', 'exec', 'shell', 'system', 'file', 'path',
                        'id', 'page', 'url', 'data', 'action', 'code', 'eval', 
                        'test', 'debug', 'input', 'run', 'execute']
        
        medium_priority = ['a', 'b', 'c', 'q', 's', 'p', 'f', 'd', 'n', 'm']
        
        def get_priority(point):
            param = point['parameter'].lower()
            if param in high_priority:
                return 0
            elif param in medium_priority:
                return 1
            else:
                return 2
        
        return sorted(injection_points, key=get_priority)


heuristic_checker = HeuristicChecker()
