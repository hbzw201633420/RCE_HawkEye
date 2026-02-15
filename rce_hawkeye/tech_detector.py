"""
技术栈检测模块
根据目录扫描结果识别目标网站使用的技术栈
"""

import re
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse


class TechStack(Enum):
    PHP = "php"
    JSP_JAVA = "jsp_java"
    ASP = "asp"
    ASPX_DOTNET = "aspx_dotnet"
    PYTHON = "python"
    NODEJS = "nodejs"
    RUBY = "ruby"
    GO = "go"
    PERL = "perl"
    LUA = "lua"
    COLDFUSION = "coldfusion"
    CGI = "cgi"


@dataclass
class TechIndicator:
    tech_stack: TechStack
    patterns: List[str]
    file_extensions: List[str]
    paths: List[str]
    headers: Dict[str, str] = field(default_factory=dict)
    confidence: float = 1.0


@dataclass
class DetectedTech:
    tech_stack: TechStack
    confidence: float
    evidence: List[str]
    file_extensions: List[str]


class TechStackDetector:
    """技术栈检测器"""
    
    TECH_INDICATORS = [
        TechIndicator(
            tech_stack=TechStack.PHP,
            patterns=[r'\.php\d?$', r'\.phtml$', r'\.phps$'],
            file_extensions=['.php', '.php3', '.php4', '.php5', '.phtml', '.phps'],
            paths=['wp-admin', 'wp-content', 'wp-includes', 'phpmyadmin', 'adminer',
                   'composer.json', 'vendor', 'laravel', 'symfony', 'codeigniter'],
            headers={'X-Powered-By': r'PHP'}
        ),
        TechIndicator(
            tech_stack=TechStack.JSP_JAVA,
            patterns=[r'\.jsp$', r'\.jspx$', r'\.jspa$', r'\.jsw$', r'\.jsv$', r'\.do$'],
            file_extensions=['.jsp', '.jspx', '.jspa', '.jsw', '.jsv', '.do', '.action'],
            paths=['WEB-INF', 'META-INF', 'struts', 'spring', 'tomcat', 'weblogic',
                   'web.xml', 'pom.xml', 'gradle', 'maven'],
            headers={'X-Powered-By': r'(JSP|Java|Servlet|Tomcat|JBoss|WebLogic)'}
        ),
        TechIndicator(
            tech_stack=TechStack.ASP,
            patterns=[r'\.asp$'],
            file_extensions=['.asp'],
            paths=['global.asa', 'iisadmin'],
            headers={'X-Powered-By': r'ASP', 'Server': r'IIS'}
        ),
        TechIndicator(
            tech_stack=TechStack.ASPX_DOTNET,
            patterns=[r'\.aspx?$', r'\.ashx$', r'\.asmx$', r'\.asax$', r'\.svc$'],
            file_extensions=['.aspx', '.ashx', '.asmx', '.asax', '.svc', '.axd'],
            paths=['web.config', 'bin/', 'App_Code', 'App_Data', 'App_Themes',
                   'Site.Master', 'ViewState'],
            headers={'X-Powered-By': r'ASP\.NET', 'X-AspNet-Version': r'.*'}
        ),
        TechIndicator(
            tech_stack=TechStack.PYTHON,
            patterns=[r'\.py$', r'\.wsgi$', r'\.cgi$'],
            file_extensions=['.py', '.wsgi', '.cgi', '.fcgi'],
            paths=['django', 'flask', 'fastapi', 'requirements.txt', 'setup.py',
                   'wsgi.py', 'asgi.py', 'manage.py', 'settings.py', 'gunicorn'],
            headers={'Server': r'(gunicorn|uWSGI|Python)'}
        ),
        TechIndicator(
            tech_stack=TechStack.NODEJS,
            patterns=[r'\.js$', r'\.mjs$', r'\.cjs$'],
            file_extensions=['.js', '.mjs', '.cjs', '.node'],
            paths=['node_modules', 'package.json', 'npm', 'yarn.lock', 'package-lock.json',
                   'express', 'koa', 'hapi', 'next.js', 'nuxt.js', 'gatsby',
                   'app.js', 'server.js', 'index.js', 'main.js', '.nuxt', '.next'],
            headers={'X-Powered-By': r'(Express|Next\.js|Nuxt|Node)'}
        ),
        TechIndicator(
            tech_stack=TechStack.RUBY,
            patterns=[r'\.rb$', r'\.erb$', r'\.rhtml$'],
            file_extensions=['.rb', '.erb', '.rhtml', '.rjs', '.rake'],
            paths=['rails', 'ruby', 'Gemfile', 'Gemfile.lock', 'Rakefile', 'config.ru',
                   'app/controllers', 'app/models', 'app/views', 'bin/rails'],
            headers={'X-Powered-By': r'(Phusion Passenger|Rails|Ruby)'}
        ),
        TechIndicator(
            tech_stack=TechStack.GO,
            patterns=[r'\.go$'],
            file_extensions=['.go'],
            paths=['go.mod', 'go.sum', 'Gopkg.toml', 'Gopkg.lock', 'main.go'],
            headers={'Server': r'(go|Go)'}
        ),
        TechIndicator(
            tech_stack=TechStack.PERL,
            patterns=[r'\.pl$', r'\.pm$', r'\.cgi$'],
            file_extensions=['.pl', '.pm', '.cgi', '.t'],
            paths=['perl', 'cpan', 'Makefile.PL', 'cpanfile'],
            headers={'Server': r'(Perl|mod_perl)'}
        ),
        TechIndicator(
            tech_stack=TechStack.LUA,
            patterns=[r'\.lua$'],
            file_extensions=['.lua', '.wlua'],
            paths=['nginx.conf', 'openresty', 'lapis', 'moonscript'],
            headers={'Server': r'(OpenResty|nginx)'}
        ),
        TechIndicator(
            tech_stack=TechStack.COLDFUSION,
            patterns=[r'\.cfm$', r'\.cfml$', r'\.cfc$'],
            file_extensions=['.cfm', '.cfml', '.cfc'],
            paths=['Application.cfc', 'Application.cfm'],
            headers={'Server': r'ColdFusion'}
        ),
        TechIndicator(
            tech_stack=TechStack.CGI,
            patterns=[r'\.cgi$', r'/cgi-bin/'],
            file_extensions=['.cgi', '.fcgi'],
            paths=['cgi-bin', 'fcgi-bin'],
            headers={}
        ),
    ]
    
    def __init__(self):
        self.detected_techs: Set[TechStack] = set()
        self.detected_extensions: Set[str] = set()
        self.evidence: Dict[TechStack, List[str]] = {}
    
    def detect_from_urls(self, urls: List[str]) -> List[DetectedTech]:
        """从URL列表检测技术栈"""
        self.detected_techs.clear()
        self.detected_extensions.clear()
        self.evidence.clear()
        
        for url in urls:
            self._analyze_url(url)
        
        return self._build_results()
    
    def detect_from_dir_results(self, dir_results: List) -> List[DetectedTech]:
        """从目录扫描结果检测技术栈"""
        self.detected_techs.clear()
        self.detected_extensions.clear()
        self.evidence.clear()
        
        for result in dir_results:
            self._analyze_url(result.url)
            if hasattr(result, 'content_type') and result.content_type:
                self._analyze_content_type(result.content_type)
        
        return self._build_results()
    
    def detect_from_headers(self, headers: Dict[str, str]) -> List[DetectedTech]:
        """从HTTP响应头检测技术栈"""
        for indicator in self.TECH_INDICATORS:
            for header_name, pattern in indicator.headers.items():
                header_value = headers.get(header_name, '')
                if header_value and re.search(pattern, header_value, re.IGNORECASE):
                    self.detected_techs.add(indicator.tech_stack)
                    if indicator.tech_stack not in self.evidence:
                        self.evidence[indicator.tech_stack] = []
                    self.evidence[indicator.tech_stack].append(f"Header: {header_name}={header_value}")
        
        return self._build_results()
    
    def _analyze_url(self, url: str):
        """分析单个URL"""
        url_lower = url.lower()
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        for indicator in self.TECH_INDICATORS:
            for ext in indicator.file_extensions:
                if path.endswith(ext):
                    self.detected_techs.add(indicator.tech_stack)
                    self.detected_extensions.add(ext)
                    if indicator.tech_stack not in self.evidence:
                        self.evidence[indicator.tech_stack] = []
                    self.evidence[indicator.tech_stack].append(f"Extension: {ext} in {url}")
            
            for pattern in indicator.patterns:
                if re.search(pattern, path):
                    self.detected_techs.add(indicator.tech_stack)
                    if indicator.tech_stack not in self.evidence:
                        self.evidence[indicator.tech_stack] = []
                    self.evidence[indicator.tech_stack].append(f"Pattern: {pattern} in {url}")
            
            for path_indicator in indicator.paths:
                if path_indicator.lower() in path:
                    self.detected_techs.add(indicator.tech_stack)
                    if indicator.tech_stack not in self.evidence:
                        self.evidence[indicator.tech_stack] = []
                    self.evidence[indicator.tech_stack].append(f"Path: {path_indicator} in {url}")
    
    def _analyze_content_type(self, content_type: str):
        """分析Content-Type"""
        tech_content_map = {
            'php': TechStack.PHP,
            'java': TechStack.JSP_JAVA,
            'python': TechStack.PYTHON,
            'node': TechStack.NODEJS,
            'ruby': TechStack.RUBY,
        }
        
        content_lower = content_type.lower()
        for keyword, tech in tech_content_map.items():
            if keyword in content_lower:
                self.detected_techs.add(tech)
    
    def _build_results(self) -> List[DetectedTech]:
        """构建检测结果"""
        results = []
        for tech in self.detected_techs:
            indicator = next((i for i in self.TECH_INDICATORS if i.tech_stack == tech), None)
            if indicator:
                results.append(DetectedTech(
                    tech_stack=tech,
                    confidence=indicator.confidence,
                    evidence=self.evidence.get(tech, []),
                    file_extensions=indicator.file_extensions
                ))
        return results
    
    def get_detected_extensions(self) -> Set[str]:
        """获取检测到的文件扩展名"""
        return self.detected_extensions
    
    def get_tech_stack_names(self) -> List[str]:
        """获取检测到的技术栈名称"""
        return [tech.value for tech in self.detected_techs]
    
    @staticmethod
    def get_extensions_for_tech(tech_stack: TechStack) -> List[str]:
        """获取指定技术栈对应的文件扩展名"""
        indicator = next((i for i in TechStackDetector.TECH_INDICATORS 
                         if i.tech_stack == tech_stack), None)
        return indicator.file_extensions if indicator else []
    
    @staticmethod
    def get_all_extensions() -> Dict[str, List[str]]:
        """获取所有技术栈及其对应的文件扩展名"""
        result = {}
        for indicator in TechStackDetector.TECH_INDICATORS:
            result[indicator.tech_stack.value] = indicator.file_extensions
        return result
