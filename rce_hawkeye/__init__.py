"""
RCE HawkEye - 命令执行漏洞检测工具
借鉴sqlmap设计，专精于RCE漏洞检测
"""

__version__ = "1.0.0"
__author__ = "hbzw"

from .scanner import Scanner, ScanTarget, ScanResult, ScanLevel
from .detector import Detector, Vulnerability, Severity
from .payload_generator import PayloadGenerator, ScanMode, TechType, PayloadType, OSType
from .reporter import Reporter
from .traffic_parser import TrafficParser, HttpRequest
from .crawler import WebCrawler, CrawledPage
from .config import ConfigManager, DomainConfig
from .dir_scanner import DirectoryScanner, DirScanConfig
from .param_extractor import ParamExtractor, ParamConfig
from .tech_detector import TechStackDetector, TechStack, DetectedTech
from .intelligent_scanner import IntelligentScanner, IntelligentScanResult
from .waf_bypass import WAFBypassGenerator, BypassPayload, WAFTechnique
from .tamper import tamper_manager, TamperManager
from .heuristic import HeuristicChecker, HeuristicResult, InjectionType

__all__ = [
    "Scanner", "ScanTarget", "ScanResult", "ScanLevel",
    "Detector", "Vulnerability", "Severity",
    "PayloadGenerator", "ScanMode", "TechType", "PayloadType", "OSType",
    "Reporter",
    "TrafficParser", "HttpRequest",
    "WebCrawler", "CrawledPage", "ConfigManager", "DomainConfig",
    "DirectoryScanner", "DirScanConfig", "ParamExtractor", "ParamConfig",
    "TechStackDetector", "TechStack", "DetectedTech",
    "IntelligentScanner", "IntelligentScanResult",
    "WAFBypassGenerator", "BypassPayload", "WAFTechnique",
    "tamper_manager", "TamperManager",
    "HeuristicChecker", "HeuristicResult", "InjectionType"
]
