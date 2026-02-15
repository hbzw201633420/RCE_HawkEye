"""
目录扫描模块
集成 dirsearch 字典扫描功能
"""

import asyncio
import re
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
from pathlib import Path
import aiohttp


@dataclass
class DirResult:
    url: str
    status_code: int
    content_length: int
    redirect: Optional[str] = None
    title: Optional[str] = None
    content_type: Optional[str] = None


@dataclass
class DirScanConfig:
    threads: int = 10
    timeout: int = 10
    extensions: List[str] = field(default_factory=lambda: [".php", ".asp", ".aspx", ".jsp", ".html", ".js"])
    status_codes: List[int] = field(default_factory=lambda: [200, 301, 302, 403, 500])
    exclude_codes: List[int] = field(default_factory=lambda: [404])
    wordlist: Optional[str] = None
    max_depth: int = 2
    recursive: bool = True
    follow_redirects: bool = False
    user_agent: str = "RCE-HawkEye/0.0.2"


class DirectoryScanner:
    """目录扫描器"""
    
    DEFAULT_WORDLIST = [
        "admin", "login", "dashboard", "api", "config", "backup", "test",
        "uploads", "images", "css", "js", "assets", "static", "files",
        "tmp", "temp", "logs", "data", "db", "database", "includes",
        "modules", "plugins", "themes", "templates", "views", "models",
        "controllers", "public", "private", "secure", "auth", "user",
        "users", "account", "accounts", "member", "members", "panel",
        "control", "manage", "management", "system", "sys", "admin.php",
        "login.php", "index.php", "config.php", "wp-admin", "wp-login",
        "wp-content", "wp-includes", "administrator", "phpmyadmin",
        "adminer", "console", "debug", "error", "status", "health",
        "info", "phpinfo.php", "test.php", "shell", "cmd", "exec",
        "upload", "download", "file", "files", "document", "documents",
        "image", "img", "media", "video", "audio", "archive", "archives",
        ".git", ".svn", ".env", ".htaccess", ".htpasswd", "web.config",
        "robots.txt", "sitemap.xml", "crossdomain.xml", ".well-known",
        "README.md", "CHANGELOG.md", "LICENSE", "package.json",
        "composer.json", "requirements.txt", "Dockerfile", "docker-compose.yml",
        ".gitignore", ".dockerignore", "Makefile", "Gemfile", "pom.xml",
        "build", "dist", "vendor", "node_modules", "bower_components",
        "cache", "session", "sessions", "log", "error_log", "access_log",
        "backup.sql", "dump.sql", "database.sql", "db.sql", "data.json",
        "config.json", "settings.json", "app.js", "main.js", "index.js",
        "server.js", "app.py", "main.py", "run.py", "server.py",
    ]
    
    def __init__(self, config: DirScanConfig = None):
        self.config = config or DirScanConfig()
        self.wordlist = self._load_wordlist()
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._results: List[DirResult] = []
        self._scanned_urls: Set[str] = set()
    
    def _load_wordlist(self) -> List[str]:
        """加载字典"""
        words = list(self.DEFAULT_WORDLIST)
        
        if self.config.wordlist:
            wordlist_path = Path(self.config.wordlist)
            if wordlist_path.exists():
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            words.append(line)
        
        return list(set(words))
    
    def _extract_title(self, html: str) -> Optional[str]:
        """从HTML中提取标题"""
        match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
        return match.group(1).strip() if match else None
    
    def _get_extension_paths(self, base_path: str) -> List[str]:
        """生成带扩展名的路径"""
        paths = [base_path]
        for ext in self.config.extensions:
            if not base_path.endswith(ext):
                paths.append(f"{base_path}{ext}")
        return paths
    
    async def _scan_path(self, base_url: str, path: str) -> Optional[DirResult]:
        """扫描单个路径"""
        async with self._semaphore:
            url = urljoin(base_url, path)
            
            if url in self._scanned_urls:
                return None
            
            self._scanned_urls.add(url)
            
            try:
                async with self._session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                    allow_redirects=self.config.follow_redirects
                ) as response:
                    if response.status in self.config.exclude_codes:
                        return None
                    
                    if response.status not in self.config.status_codes:
                        return None
                    
                    content = await response.text()
                    content_length = len(content)
                    title = self._extract_title(content)
                    content_type = response.headers.get("Content-Type", "")
                    redirect = str(response.url) if response.url != url else None
                    
                    return DirResult(
                        url=url,
                        status_code=response.status,
                        content_length=content_length,
                        redirect=redirect,
                        title=title,
                        content_type=content_type
                    )
            except Exception:
                return None
    
    async def _scan_word(self, base_url: str, word: str, current_depth: int = 0) -> List[DirResult]:
        """扫描单个字典项"""
        results = []
        
        paths = self._get_extension_paths(word)
        
        for path in paths:
            result = await self._scan_path(base_url, path)
            if result:
                results.append(result)
                
                if self.config.recursive and current_depth < self.config.max_depth:
                    if result.status_code in [200, 301, 302]:
                        sub_results = await self._scan_directory(result.url, current_depth + 1)
                        results.extend(sub_results)
        
        return results
    
    async def _scan_directory(self, base_url: str, current_depth: int = 0) -> List[DirResult]:
        """扫描目录"""
        if current_depth > self.config.max_depth:
            return []
        
        tasks = []
        for word in self.wordlist:
            task = self._scan_word(base_url, word, current_depth)
            tasks.append(task)
        
        all_results = await asyncio.gather(*tasks)
        
        results = []
        for r in all_results:
            results.extend(r)
        
        return results
    
    async def scan(self, target_url: str) -> List[DirResult]:
        """扫描目标URL"""
        self._results = []
        self._scanned_urls = set()
        self._semaphore = asyncio.Semaphore(self.config.threads)
        
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "*/*",
        }
        
        connector = aiohttp.TCPConnector(ssl=False)
        self._session = aiohttp.ClientSession(headers=headers, connector=connector)
        
        try:
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            results = await self._scan_directory(base_url)
            self._results.extend(results)
            
            path = parsed.path.rsplit('/', 1)[0] if parsed.path else '/'
            if path != '/':
                full_base = f"{base_url}{path}"
                results = await self._scan_directory(full_base)
                self._results.extend(results)
        
        finally:
            await self._session.close()
        
        return self._results
    
    def get_found_urls(self) -> List[str]:
        """获取发现的URL列表"""
        return [r.url for r in self._results]
    
    def get_found_directories(self) -> List[str]:
        """获取发现的目录列表"""
        return [r.url for r in self._results if r.status_code in [200, 301, 302]]
