"""
域名配置模块
"""

import re
from typing import List, Set, Optional, Dict, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse
from pathlib import Path
import yaml


@dataclass
class DomainConfig:
    """域名配置"""
    allowed_domains: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)
    restrict_to_root: bool = True
    max_depth: int = 2
    max_pages: int = 100
    exclude_extensions: List[str] = field(default_factory=lambda: [
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
        '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.rar', '.tar', '.gz', '.7z',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
        '.ico', '.xml', '.json', '.rss', '.atom'
    ])
    
    def is_allowed(self, url: str) -> bool:
        """检查URL是否允许访问"""
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path.lower()
        
        for ext in self.exclude_extensions:
            if path.endswith(ext):
                return False
        
        if self.blocked_domains:
            for blocked in self.blocked_domains:
                if self._domain_matches(domain, blocked):
                    return False
        
        if self.allowed_domains:
            for allowed in self.allowed_domains:
                if self._domain_matches(domain, allowed):
                    return True
            return False
        
        return True
    
    def _domain_matches(self, domain: str, pattern: str) -> bool:
        """检查域名是否匹配模式"""
        if pattern.startswith('*.'):
            suffix = pattern[2:]
            return domain.endswith(suffix) or domain == suffix[1:]
        
        return domain == pattern
    
    def add_allowed_domain(self, domain: str):
        """添加允许的域名"""
        if domain not in self.allowed_domains:
            self.allowed_domains.append(domain)
    
    def add_blocked_domain(self, domain: str):
        """添加禁止的域名"""
        if domain not in self.blocked_domains:
            self.blocked_domains.append(domain)
    
    def remove_allowed_domain(self, domain: str):
        """移除允许的域名"""
        if domain in self.allowed_domains:
            self.allowed_domains.remove(domain)
    
    def remove_blocked_domain(self, domain: str):
        """移除禁止的域名"""
        if domain in self.blocked_domains:
            self.blocked_domains.remove(domain)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DomainConfig':
        """从字典创建配置"""
        return cls(
            allowed_domains=data.get('allowed_domains', []),
            blocked_domains=data.get('blocked_domains', []),
            restrict_to_root=data.get('restrict_to_root', True),
            max_depth=data.get('max_depth', 2),
            max_pages=data.get('max_pages', 100),
            exclude_extensions=data.get('exclude_extensions', [
                '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
                '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
                '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                '.zip', '.rar', '.tar', '.gz', '.7z',
                '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
                '.ico', '.xml', '.json', '.rss', '.atom'
            ])
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'allowed_domains': self.allowed_domains,
            'blocked_domains': self.blocked_domains,
            'restrict_to_root': self.restrict_to_root,
            'max_depth': self.max_depth,
            'max_pages': self.max_pages,
            'exclude_extensions': self.exclude_extensions
        }


class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_path: str = None):
        self.config_path = config_path
        self.domain_config = DomainConfig()
        self.scan_config: Dict[str, Any] = {}
        
        if config_path:
            self.load(config_path)
    
    def load(self, config_path: str):
        """加载配置文件"""
        path = Path(config_path)
        if not path.exists():
            return
        
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
        
        if 'domain' in data:
            self.domain_config = DomainConfig.from_dict(data['domain'])
        
        if 'scan' in data:
            self.scan_config = data['scan']
    
    def save(self, config_path: str = None):
        """保存配置文件"""
        path = Path(config_path or self.config_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'domain': self.domain_config.to_dict(),
            'scan': self.scan_config
        }
        
        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
    
    def set_allowed_domains(self, domains: List[str]):
        """设置允许的域名"""
        self.domain_config.allowed_domains = domains
    
    def set_blocked_domains(self, domains: List[str]):
        """设置禁止的域名"""
        self.domain_config.blocked_domains = domains
    
    def get_allowed_domains(self) -> List[str]:
        """获取允许的域名"""
        return self.domain_config.allowed_domains
    
    def get_blocked_domains(self) -> List[str]:
        """获取禁止的域名"""
        return self.domain_config.blocked_domains
