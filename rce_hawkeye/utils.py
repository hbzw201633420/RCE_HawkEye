"""
工具函数模块
支持域名/IP直接扫描和HTTPS自动检测
"""

import re
import hashlib
import time
import socket
import ssl
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Any, Tuple
import asyncio
import aiohttp


def calculate_hash(data: str) -> str:
    """计算字符串的MD5哈希值"""
    return hashlib.md5(data.encode()).hexdigest()


def extract_parameters(url: str) -> Dict[str, str]:
    """从URL中提取参数"""
    parsed = urlparse(url)
    params = {}
    if parsed.query:
        for param in parsed.query.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                params[key] = value
    return params


def build_url(base_url: str, params: Dict[str, str]) -> str:
    """根据参数构建URL"""
    parsed = urlparse(base_url)
    query = '&'.join([f"{k}={v}" for k, v in params.items()])
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"


def is_valid_url(url: str) -> bool:
    """验证URL是否有效"""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ['http', 'https'] and parsed.netloc
    except Exception:
        return False


def is_valid_domain(domain: str) -> bool:
    """验证是否为有效域名"""
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$'
    if re.match(domain_pattern, domain):
        return True
    return False


def is_valid_ip(ip: str) -> bool:
    """验证是否为有效IP地址"""
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^\[?[0-9a-fA-F:]+\]?$'
    
    if re.match(ipv4_pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    if re.match(ipv6_pattern, ip):
        return True
    
    return False


def normalize_target(target: str) -> str:
    """标准化目标地址，支持域名和IP直接输入"""
    target = target.strip()
    
    if target.startswith(('http://', 'https://')):
        return target
    
    if target.startswith('//'):
        return 'https:' + target
    
    port = None
    path = ''
    
    if '/' in target:
        parts = target.split('/', 1)
        host_part = parts[0]
        path = '/' + parts[1] if len(parts) > 1 else ''
    else:
        host_part = target
    
    if ':' in host_part and not host_part.startswith('['):
        if host_part.count(':') == 1:
            host_part, port_str = host_part.rsplit(':', 1)
            port = int(port_str) if port_str.isdigit() else None
    
    if is_valid_ip(host_part) or is_valid_domain(host_part):
        if port:
            return f"http://{host_part}:{port}{path}"
        return f"http://{host_part}{path}"
    
    return target


def check_https_support(target: str, timeout: int = 5) -> Tuple[bool, str]:
    """检测目标是否支持HTTPS"""
    parsed = urlparse(target)
    host = parsed.netloc
    
    if ':' in host and not host.startswith('['):
        host_part, port_part = host.split(':', 1)
        try:
            port = int(port_part)
        except ValueError:
            port = 443
    else:
        host_part = host
        port = 443
    
    if parsed.scheme == 'https':
        return True, target
    
    https_url = target.replace('http://', 'https://', 1)
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.create_connection((host_part, port), timeout=timeout)
        ssock = context.wrap_socket(sock, server_hostname=host_part)
        ssock.close()
        return True, https_url
    except Exception:
        return False, target


def get_preferred_url(target: str, prefer_https: bool = True, timeout: int = 5) -> str:
    """获取首选URL，优先使用HTTPS"""
    original_target = target.strip()
    explicit_http = original_target.startswith('http://')
    
    target = normalize_target(target)
    
    if not prefer_https:
        return target
    
    parsed = urlparse(target)
    if parsed.scheme == 'https':
        return target
    
    if explicit_http:
        return target
    
    supports_https, url = check_https_support(target, timeout)
    
    if supports_https:
        return url.replace('http://', 'https://', 1)
    
    return target


async def check_https_async(target: str, timeout: int = 5) -> Tuple[bool, str]:
    """异步检测目标是否支持HTTPS"""
    parsed = urlparse(target)
    host = parsed.netloc
    
    if ':' in host and not host.startswith('['):
        host = host.split(':')[0]
    
    if parsed.scheme == 'https':
        return True, target
    
    https_url = target.replace('http://', 'https://', 1)
    
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.head(
                https_url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False
            ) as response:
                return True, https_url
    except Exception:
        return False, target


async def fetch_url(
    session: aiohttp.ClientSession,
    url: str,
    method: str = "GET",
    data: Optional[Dict] = None,
    headers: Optional[Dict] = None,
    timeout: int = 10
) -> Dict[str, Any]:
    """异步获取URL内容"""
    start_time = time.time()
    try:
        async with session.request(
            method,
            url,
            data=data,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as response:
            content = await response.text()
            elapsed = time.time() - start_time
            return {
                "status_code": response.status,
                "content": content,
                "elapsed": elapsed,
                "headers": dict(response.headers),
                "error": None
            }
    except asyncio.TimeoutError:
        return {
            "status_code": 0,
            "content": "",
            "elapsed": timeout,
            "headers": {},
            "error": "Timeout"
        }
    except Exception as e:
        return {
            "status_code": 0,
            "content": "",
            "elapsed": time.time() - start_time,
            "headers": {},
            "error": str(e)
        }


def sanitize_input(data: str) -> str:
    """清理输入数据，防止日志注入"""
    return re.sub(r'[\x00-\x1f\x7f-\x9f]', '', data)


def get_risk_level(severity: str) -> str:
    """获取风险等级描述"""
    risk_map = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "信息"
    }
    return risk_map.get(severity.lower(), "未知")


def parse_target(target: str) -> Dict[str, Any]:
    """解析目标地址，返回详细信息"""
    target = normalize_target(target)
    parsed = urlparse(target)
    
    host = parsed.netloc
    port = None
    
    if ':' in host and not host.startswith('['):
        host, port_str = host.rsplit(':', 1)
        if port_str.isdigit():
            port = int(port_str)
    
    if not port:
        port = 443 if parsed.scheme == 'https' else 80
    
    return {
        'url': target,
        'scheme': parsed.scheme,
        'host': host,
        'port': port,
        'path': parsed.path or '/',
        'is_ip': is_valid_ip(host),
        'is_domain': is_valid_domain(host)
    }
