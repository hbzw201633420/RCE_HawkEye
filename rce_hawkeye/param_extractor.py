"""
参数爬取模块
支持从网页、JavaScript和字典中提取参数
"""

import re
import asyncio
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path
import aiohttp
from bs4 import BeautifulSoup


@dataclass
class ParamSource:
    url: str
    method: str
    param_name: str
    param_value: str
    source_type: str


@dataclass
class ParamConfig:
    threads: int = 10
    timeout: int = 10
    max_depth: int = 2
    max_pages: int = 100
    user_agent: str = "RCE-HawkEye/0.0.2"
    param_wordlist: Optional[str] = None
    fuzz_params: bool = True
    extract_from_js: bool = True
    extract_from_html: bool = True


class ParamExtractor:
    """参数提取器"""
    
    DEFAULT_PARAM_LIST = [
        "a", "b", "c", "id", "user", "username", "name", "email", "password", "pass", "pwd",
        "cmd", "command", "exec", "execute", "run", "shell", "system",
        "file", "path", "dir", "folder", "page", "url", "link", "src",
        "action", "target", "dest", "destination", "redirect", "return",
        "callback", "next", "goto", "forward", "continue", "return_url",
        "q", "query", "search", "keyword", "key", "term", "text", "input",
        "data", "content", "body", "message", "msg", "comment", "title",
        "cat", "category", "type", "kind", "sort", "order", "by", "field",
        "page", "p", "pg", "offset", "limit", "count", "num", "number",
        "start", "end", "from", "to", "begin", "finish", "min", "max",
        "date", "time", "year", "month", "day", "hour", "minute", "second",
        "ip", "host", "domain", "server", "site", "address", "port",
        "code", "token", "key", "secret", "api_key", "apikey", "auth",
        "session", "cookie", "csrf", "nonce", "salt", "hash", "signature",
        "lang", "language", "locale", "country", "region", "zone",
        "format", "type", "mode", "style", "theme", "view", "display",
        "debug", "test", "dev", "development", "production", "env",
        "config", "setting", "option", "param", "parameter", "var", "variable",
        "status", "state", "flag", "enable", "disable", "active", "visible",
        "role", "permission", "access", "level", "rank", "group", "team",
        "item", "product", "article", "post", "thread", "topic", "forum",
        "image", "img", "photo", "picture", "video", "audio", "media",
        "upload", "download", "attach", "attachment", "file", "document",
        "ajax", "json", "xml", "html", "text", "raw", "binary",
        "width", "height", "size", "length", "weight", "amount", "price",
        "first", "last", "prev", "previous", "next", "current", "new",
        "old", "original", "backup", "copy", "version", "revision",
        "eval", "assert", "preg_replace", "create_function", "call_user_func",
        "passthru", "shell_exec", "proc_open", "popen", "pcntl_exec",
    ]
    
    def __init__(self, config: ParamConfig = None):
        self.config = config or ParamConfig()
        self.param_wordlist = self._load_param_wordlist()
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._visited: Set[str] = set()
        self._found_params: Dict[str, List[ParamSource]] = {}
    
    def _load_param_wordlist(self) -> List[str]:
        """加载参数字典"""
        params = list(self.DEFAULT_PARAM_LIST)
        
        if self.config.param_wordlist:
            wordlist_path = Path(self.config.param_wordlist)
            if wordlist_path.exists():
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            params.append(line)
        
        return list(set(params))
    
    def _extract_from_url(self, url: str) -> Dict[str, str]:
        """从URL中提取参数"""
        params = {}
        parsed = urlparse(url)
        
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for key, values in query_params.items():
                params[key] = values[0] if values else ""
        
        return params
    
    def _extract_from_html(self, html: str, base_url: str) -> Dict[str, str]:
        """从HTML中提取参数"""
        params = {}
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            for input_tag in soup.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name', '')
                if name:
                    value = input_tag.get('value', '')
                    params[name] = value
            
            for tag in soup.find_all(attrs={'name': True}):
                name = tag.get('name', '')
                if name and name not in params:
                    params[name] = tag.get('value', '')
            
            patterns = [
                r'name\s*=\s*["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']',
                r'data-param\s*=\s*["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']',
                r'data-name\s*=\s*["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']',
            ]
            
            for pattern in patterns:
                for match in re.finditer(pattern, html, re.IGNORECASE):
                    param_name = match.group(1)
                    if param_name and len(param_name) < 50:
                        if param_name not in params:
                            params[param_name] = ""
        
        except Exception:
            pass
        
        return params
    
    def _extract_from_js(self, html: str, base_url: str) -> Dict[str, str]:
        """从JavaScript中提取参数"""
        params = {}
        
        try:
            patterns = [
                r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\s*:\s*["\'][^"\']*["\']',
                r'var\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\'][^"\']*["\']',
                r'let\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\'][^"\']*["\']',
                r'const\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\'][^"\']*["\']',
                r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=([^&"\'>\s]*)',
                r'\.get\(["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\)',
                r'\.post\(["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']',
                r'params\.([a-zA-Z_][a-zA-Z0-9_]*)',
                r'data\s*:\s*\{[^}]*([a-zA-Z_][a-zA-Z0-9_]*)\s*:',
            ]
            
            for pattern in patterns:
                for match in re.finditer(pattern, html, re.IGNORECASE):
                    param_name = match.group(1)
                    if param_name and len(param_name) < 50:
                        if param_name not in params:
                            params[param_name] = ""
            
            ajax_patterns = [
                r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
                r'\$\.post\s*\(\s*["\']([^"\']+)["\']',
                r'\$\.get\s*\(\s*["\']([^"\']+)["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'axios\.(?:get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
            ]
            
            for pattern in ajax_patterns:
                for match in re.finditer(pattern, html, re.IGNORECASE):
                    ajax_url = match.group(1)
                    if '?' in ajax_url:
                        ajax_params = self._extract_from_url(ajax_url)
                        params.update(ajax_params)
        
        except Exception:
            pass
        
        return params
    
    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """从HTML中提取表单"""
        forms = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action:
                    action = urljoin(base_url, action)
                else:
                    action = base_url
                
                method = form.get('method', 'GET').upper()
                
                inputs = {}
                for input_tag in form.find_all(['input', 'textarea', 'select', 'button']):
                    name = input_tag.get('name', '')
                    if name:
                        value = input_tag.get('value', '')
                        inputs[name] = value
                
                forms.append({
                    'action': action,
                    'method': method,
                    'inputs': inputs
                })
        
        except Exception:
            pass
        
        return forms
    
    async def _fetch_page(self, url: str) -> Optional[str]:
        """获取页面内容"""
        async with self._semaphore:
            try:
                async with self._session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                    allow_redirects=True
                ) as response:
                    if response.status == 200:
                        return await response.text()
            except Exception:
                pass
        return None
    
    async def _crawl_and_extract(self, start_url: str, depth: int = 0) -> Dict[str, str]:
        """爬取并提取参数"""
        params = {}
        
        if depth > self.config.max_depth:
            return params
        
        normalized = start_url.split('?')[0].rstrip('/')
        if normalized in self._visited:
            return params
        
        self._visited.add(normalized)
        
        html = await self._fetch_page(start_url)
        if not html:
            return params
        
        url_params = self._extract_from_url(start_url)
        params.update(url_params)
        
        if self.config.extract_from_html:
            html_params = self._extract_from_html(html, start_url)
            params.update(html_params)
        
        if self.config.extract_from_js:
            js_params = self._extract_from_js(html, start_url)
            params.update(js_params)
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            links = set()
            
            for tag in soup.find_all(['a', 'link', 'script', 'iframe']):
                attr = 'href' if tag.name in ['a', 'link'] else 'src'
                if tag.get(attr):
                    href = tag.get(attr, '')
                    if href and not href.startswith(('#', 'javascript:', 'mailto:')):
                        full_url = urljoin(start_url, href)
                        links.add(full_url)
            
            if depth < self.config.max_depth and len(self._visited) < self.config.max_pages:
                tasks = []
                for link in list(links)[:10]:
                    if link.split('?')[0].rstrip('/') not in self._visited:
                        tasks.append(self._crawl_and_extract(link, depth + 1))
                
                if tasks:
                    results = await asyncio.gather(*tasks)
                    for r in results:
                        params.update(r)
        
        except Exception:
            pass
        
        return params
    
    async def extract(self, target_url: str) -> Dict[str, str]:
        """提取参数"""
        self._visited = set()
        self._found_params = {}
        self._semaphore = asyncio.Semaphore(self.config.threads)
        
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        
        connector = aiohttp.TCPConnector(ssl=False)
        self._session = aiohttp.ClientSession(headers=headers, connector=connector)
        
        try:
            params = await self._crawl_and_extract(target_url)
        finally:
            await self._session.close()
        
        return params
    
    def get_param_wordlist(self) -> List[str]:
        """获取参数字典"""
        return self.param_wordlist
    
    def generate_fuzz_urls(self, base_url: str, params: List[str] = None) -> List[str]:
        """生成模糊测试URL"""
        if params is None:
            params = self.param_wordlist
        
        urls = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param in params[:50]:
            fuzz_url = f"{base}?{param}=test"
            urls.append(fuzz_url)
        
        return urls
