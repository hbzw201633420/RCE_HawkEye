"""
工具函数模块
"""

import re
import hashlib
import time
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Any
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
