"""
网页爬虫模块
"""

import re
import asyncio
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, unquote
import aiohttp
from bs4 import BeautifulSoup


@dataclass
class CrawledPage:
    url: str
    status_code: int
    content: str
    links: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    parameters: Dict[str, str] = field(default_factory=dict)


@dataclass
class FormInfo:
    action: str
    method: str
    inputs: Dict[str, str]


class WebCrawler:
    """网页爬虫"""
    
    def __init__(
        self,
        max_depth: int = 2,
        max_pages: int = 100,
        timeout: int = 10,
        concurrent: int = 5,
        user_agent: str = "RCE-HawkEye/0.0.2"
    ):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.concurrent = concurrent
        self.user_agent = user_agent
        
        self._visited: Set[str] = set()
        self._results: List[CrawledPage] = []
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._all_params: Dict[str, Set[str]] = {}
    
    def _normalize_url(self, url: str) -> str:
        """标准化URL"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/')
    
    def _get_base_url(self, url: str) -> str:
        """获取基础URL"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _extract_links(self, base_url: str, html: str) -> List[str]:
        """从HTML中提取链接"""
        links = set()
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'frame', 'form', 'area', 'base', 'source']):
                attr = None
                if tag.name in ['a', 'link', 'area']:
                    attr = 'href'
                elif tag.name in ['script', 'img', 'iframe', 'frame', 'source']:
                    attr = 'src'
                elif tag.name == 'form':
                    attr = 'action'
                elif tag.name == 'base':
                    attr = 'href'
                
                if attr and tag.get(attr):
                    href = tag.get(attr, '')
                    if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                        full_url = urljoin(base_url, href)
                        links.add(full_url)
            
            patterns = [
                r'(?:href|src|action|data-url|data-href)\s*=\s*["\']([^"\']+)["\']',
                r'window\.location\s*=\s*["\']([^"\']+)["\']',
                r'window\.open\s*\(\s*["\']([^"\']+)["\']',
                r'location\.href\s*=\s*["\']([^"\']+)["\']',
            ]
            
            for pattern in patterns:
                for match in re.finditer(pattern, html, re.IGNORECASE):
                    href = match.group(1)
                    if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                        full_url = urljoin(base_url, href)
                        links.add(full_url)
            
            url_pattern = r'(?:https?://[^\s<>"\'\)]+)'
            for match in re.finditer(url_pattern, html):
                links.add(match.group(0))
        
        except Exception:
            pass
        
        return list(links)
    
    def _extract_forms(self, base_url: str, html: str) -> List[Dict]:
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
                
                for button in form.find_all('button'):
                    name = button.get('name', '')
                    if name:
                        value = button.get('value', '')
                        inputs[name] = value
                
                forms.append({
                    'action': action,
                    'method': method,
                    'inputs': inputs
                })
            
            ajax_patterns = [
                r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
                r'\$\.post\s*\(\s*["\']([^"\']+)["\']',
                r'\$\.get\s*\(\s*["\']([^"\']+)["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'axios\.(?:get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
            ]
            
            for pattern in ajax_patterns:
                for match in re.finditer(pattern, html, re.IGNORECASE):
                    url = match.group(1)
                    if url:
                        full_url = urljoin(base_url, url)
                        parsed = urlparse(full_url)
                        ajax_params = {}
                        if parsed.query:
                            query_params = parse_qs(parsed.query)
                            for key, values in query_params.items():
                                ajax_params[key] = values[0] if values else ""
                        
                        if ajax_params:
                            forms.append({
                                'action': full_url.split('?')[0],
                                'method': 'GET' if 'get' in pattern.lower() else 'POST',
                                'inputs': ajax_params
                            })
        
        except Exception:
            pass
        
        return forms
    
    def _extract_parameters_from_url(self, url: str) -> Dict[str, str]:
        """从URL中提取参数"""
        params = {}
        parsed = urlparse(url)
        
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for key, values in query_params.items():
                params[key] = values[0] if values else ""
        
        return params
    
    def _extract_parameters_from_html(self, html: str, base_url: str) -> Dict[str, str]:
        """从HTML内容中提取所有可能的参数名"""
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
                r'var\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\'][^"\']*["\']',
                r'let\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\'][^"\']*["\']',
                r'const\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\'][^"\']*["\']',
            ]
            
            for pattern in patterns:
                for match in re.finditer(pattern, html, re.IGNORECASE):
                    param_name = match.group(1)
                    if param_name and len(param_name) < 50:
                        if param_name not in params:
                            params[param_name] = ""
            
            url_param_pattern = r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=([^&"\'>\s]*)'
            for match in re.finditer(url_param_pattern, html):
                param_name = match.group(1)
                param_value = unquote(match.group(2))
                if param_name and len(param_name) < 50:
                    if param_name not in params:
                        params[param_name] = param_value
            
            json_pattern = r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:\s*"([^"]*)"'
            for match in re.finditer(json_pattern, html):
                param_name = match.group(1)
                param_value = match.group(2)
                if param_name and len(param_name) < 50 and param_name not in ['url', 'href', 'src', 'type', 'id', 'class']:
                    if param_name not in params:
                        params[param_name] = param_value
        
        except Exception:
            pass
        
        return params
    
    async def _fetch_page(self, url: str) -> Optional[CrawledPage]:
        """获取单个页面"""
        async with self._semaphore:
            try:
                async with self._session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=True
                ) as response:
                    content = await response.text()
                    
                    links = self._extract_links(url, content)
                    forms = self._extract_forms(url, content)
                    url_params = self._extract_parameters_from_url(url)
                    html_params = self._extract_parameters_from_html(content, url)
                    
                    all_params = {**html_params, **url_params}
                    
                    for param_name in all_params.keys():
                        if param_name not in self._all_params:
                            self._all_params[param_name] = set()
                        self._all_params[param_name].add(url)
                    
                    return CrawledPage(
                        url=url,
                        status_code=response.status,
                        content=content,
                        links=links,
                        forms=forms,
                        parameters=all_params
                    )
            except Exception as e:
                return None
    
    async def crawl(self, start_url: str, allowed_domains: List[str] = None, 
                   blocked_domains: List[str] = None) -> List[CrawledPage]:
        """爬取网站"""
        self._visited = set()
        self._results = []
        self._all_params = {}
        self._semaphore = asyncio.Semaphore(self.concurrent)
        
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        
        connector = aiohttp.TCPConnector(ssl=False)
        self._session = aiohttp.ClientSession(headers=headers, connector=connector)
        
        try:
            queue = [(start_url, 0)]
            
            while queue and len(self._results) < self.max_pages:
                url, depth = queue.pop(0)
                
                normalized = self._normalize_url(url)
                if normalized in self._visited:
                    continue
                
                parsed = urlparse(url)
                domain = parsed.netloc
                
                if blocked_domains and domain in blocked_domains:
                    continue
                
                if allowed_domains and domain not in allowed_domains:
                    continue
                
                self._visited.add(normalized)
                
                page = await self._fetch_page(url)
                if page:
                    self._results.append(page)
                    
                    if depth < self.max_depth:
                        for link in page.links:
                            normalized_link = self._normalize_url(link)
                            if normalized_link not in self._visited:
                                link_parsed = urlparse(link)
                                link_domain = link_parsed.netloc
                                
                                if blocked_domains and link_domain in blocked_domains:
                                    continue
                                
                                if allowed_domains and link_domain not in allowed_domains:
                                    continue
                                
                                queue.append((link, depth + 1))
        
        finally:
            await self._session.close()
        
        return self._results
    
    def get_all_urls(self) -> List[str]:
        """获取所有爬取的URL"""
        return [page.url for page in self._results]
    
    def get_all_forms(self) -> List[FormInfo]:
        """获取所有表单"""
        forms = []
        for page in self._results:
            for form in page.forms:
                forms.append(FormInfo(
                    action=form['action'],
                    method=form['method'],
                    inputs=form['inputs']
                ))
        return forms
    
    def get_all_parameters(self) -> Dict[str, List[str]]:
        """获取所有参数及其来源URL"""
        result = {}
        for param_name, urls in self._all_params.items():
            result[param_name] = list(urls)
        return result
    
    def get_unique_parameters(self) -> List[str]:
        """获取所有唯一的参数名"""
        return list(self._all_params.keys())
