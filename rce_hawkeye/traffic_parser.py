"""
流量包解析器模块
"""

import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs


@dataclass
class HttpRequest:
    method: str
    path: str
    version: str
    headers: Dict[str, str]
    body: str
    raw_request: str
    
    def get_url(self, default_host: str = "localhost", default_scheme: str = "http") -> str:
        """构建完整URL"""
        host = self.headers.get("Host", default_host)
        scheme = default_scheme
        return f"{scheme}://{host}{self.path}"
    
    def get_parameters(self) -> Dict[str, str]:
        """获取所有参数（URL参数 + POST参数）"""
        params = {}
        
        parsed = urlparse(self.path)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for key, values in query_params.items():
                params[key] = values[0] if values else ""
        
        if self.body and self.method.upper() == "POST":
            content_type = self.headers.get("Content-Type", "").lower()
            
            if "application/x-www-form-urlencoded" in content_type:
                try:
                    body_params = parse_qs(self.body)
                    for key, values in body_params.items():
                        params[key] = values[0] if values else ""
                except Exception:
                    pass
            
            elif "application/json" in content_type:
                try:
                    import json
                    json_data = json.loads(self.body)
                    if isinstance(json_data, dict):
                        params.update(self._flatten_json(json_data))
                except Exception:
                    pass
        
        return params
    
    def _flatten_json(self, data: dict, prefix: str = "") -> Dict[str, str]:
        """扁平化JSON数据"""
        params = {}
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                params.update(self._flatten_json(value, full_key))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, (dict, list)):
                        continue
                    params[f"{full_key}[{i}]"] = str(item)
            else:
                params[full_key] = str(value)
        return params


class TrafficParser:
    """流量包解析器"""
    
    def __init__(self):
        self.requests: List[HttpRequest] = []
    
    def parse_file(self, filepath: str) -> List[HttpRequest]:
        """解析流量包文件"""
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        
        self.requests = self._parse_raw_requests(content)
        return self.requests
    
    def _parse_raw_requests(self, content: str) -> List[HttpRequest]:
        """解析原始HTTP请求"""
        requests = []
        
        raw_requests = self._split_requests(content)
        
        for raw in raw_requests:
            req = self._parse_single_request(raw)
            if req:
                requests.append(req)
        
        return requests
    
    def _split_requests(self, content: str) -> List[str]:
        """分割多个HTTP请求"""
        pattern = r'(?:^|\n)(?=(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+)'
        parts = re.split(pattern, content, flags=re.MULTILINE)
        
        requests = []
        for part in parts:
            part = part.strip()
            if part and re.match(r'^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+', part):
                requests.append(part)
        
        return requests
    
    def _parse_single_request(self, raw: str) -> Optional[HttpRequest]:
        """解析单个HTTP请求"""
        lines = raw.strip().split('\n')
        if not lines:
            return None
        
        request_line = lines[0].strip()
        match = re.match(r'^(\w+)\s+([^\s]+)\s+(HTTP/[\d.]+)?$', request_line)
        if not match:
            return None
        
        method = match.group(1).upper()
        path = match.group(2)
        version = match.group(3) or "HTTP/1.1"
        
        headers = {}
        body_start = -1
        
        for i, line in enumerate(lines[1:], 1):
            line = line.rstrip('\r')
            
            if line == "":
                body_start = i + 1
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        body = ""
        if body_start > 0 and body_start < len(lines):
            body_lines = lines[body_start:]
            body = '\n'.join(body_lines).strip()
        
        return HttpRequest(
            method=method,
            path=path,
            version=version,
            headers=headers,
            body=body,
            raw_request=raw
        )
    
    def get_requests(self) -> List[HttpRequest]:
        """获取所有解析的请求"""
        return self.requests
    
    def get_requests_by_method(self, method: str) -> List[HttpRequest]:
        """按方法获取请求"""
        return [r for r in self.requests if r.method.upper() == method.upper()]
    
    def get_requests_by_path(self, path_pattern: str) -> List[HttpRequest]:
        """按路径模式获取请求"""
        pattern = re.compile(path_pattern, re.IGNORECASE)
        return [r for r in self.requests if pattern.search(r.path)]
