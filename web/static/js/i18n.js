const translations = {
    zh: {
        app: {
            name: 'RCE HawkEye',
            desc: '命令执行漏洞自动化检测工具',
            version: '版本'
        },
        
        nav: {
            dashboard: '仪表板',
            scanner: '扫描器',
            monitoring: '监控',
            reports: '报告',
            settings: '设置'
        },
        
        lang: {
            zh: '中文',
            en: 'English'
        },
        
        login: {
            title: '登录',
            username: '用户名 / 邮箱',
            usernamePlaceholder: '请输入用户名或邮箱',
            password: '密码',
            passwordPlaceholder: '请输入密码',
            remember: '记住我',
            forgot: '忘记密码?',
            btn: '登 录',
            signing: '登录中...',
            error: '用户名或密码错误',
            errorConnection: '连接错误，请重试'
        },
        
        stats: {
            totalScans: '总扫描次数',
            criticalVulns: '严重漏洞',
            highVulns: '高危漏洞',
            targetsScanned: '已扫描目标'
        },
        
        scan: {
            newScan: '新建扫描',
            targetUrl: '目标 URL / IP',
            targetPlaceholder: 'http://example.com 或 192.168.1.1',
            scanLevel: '扫描等级',
            scanOptions: '扫描选项',
            advanced: '高级选项',
            startScan: '开始扫描',
            stopScan: '停止扫描',
            starting: '启动中...',
            initializing: '初始化扫描...',
            running: '正在扫描...',
            analyzing: '分析结果中...',
            completed: '扫描完成',
            stopped: '扫描已停止',
            foundVulns: '发现 {count} 个漏洞',
            phaseCrawl: '爬虫阶段',
            phaseDirScan: '目录扫描',
            phaseParamFuzz: '参数模糊测试',
            phaseRceScan: 'RCE检测'
        },
        
        level: {
            quick: '快速',
            normal: '标准',
            deep: '深度',
            full: '完全'
        },
        
        option: {
            crawl: '网页爬虫',
            dirScan: '目录扫描',
            paramFuzz: '参数模糊测试',
            wafBypass: 'WAF绕过',
            harmless: '无害化检测',
            preferHttps: '优先HTTPS'
        },
        
        advanced: {
            method: 'HTTP方法',
            concurrent: '并发数',
            timeout: '超时(秒)',
            delayThreshold: '延迟阈值(秒)',
            proxy: '代理服务器',
            headers: '自定义请求头',
            postData: 'POST数据',
            crawlDepth: '爬虫深度',
            maxPages: '最大页面数'
        },
        
        results: {
            title: '扫描结果',
            all: '全部',
            critical: '严重',
            high: '高危',
            medium: '中危',
            low: '低危',
            noResults: '暂无扫描结果',
            startScan: '开始新扫描以检测漏洞',
            parameter: '参数',
            type: '类型',
            request: '请求详情',
            exportJson: '导出 JSON',
            exportHtml: '导出 HTML',
            exportMd: '导出 Markdown'
        },
        
        progress: {
            initializing: '初始化中...',
            scanning: '扫描中...',
            analyzing: '分析中...',
            completed: '完成',
            crawled: '爬取页面',
            discovered: '发现路径',
            foundParams: '发现参数'
        },
        
        monitoring: {
            cpuUsage: 'CPU使用率',
            memoryUsage: '内存使用率',
            networkTraffic: '网络流量',
            scanPerformance: '扫描性能',
            realtime: '实时',
            requestsPerSec: '请求/秒'
        },
        
        vuln: {
            critical: '严重',
            high: '高危',
            medium: '中危',
            low: '低危'
        },
        
        history: {
            title: '扫描历史',
            noHistory: '暂无扫描历史',
            view: '查看',
            vulnFound: '个漏洞'
        },
        
        search: {
            placeholder: '搜索目标、漏洞...'
        },
        
        common: {
            logout: '退出登录',
            logoutConfirm: '确定要退出登录吗?',
            confirm: '确定',
            cancel: '取消',
            save: '保存',
            delete: '删除',
            edit: '编辑',
            close: '关闭',
            loading: '加载中...',
            noData: '暂无数据',
            error: '发生错误',
            success: '操作成功',
            noResults: '没有可导出的扫描结果'
        }
    },
    
    en: {
        app: {
            name: 'RCE HawkEye',
            desc: 'Command Execution Vulnerability Scanner',
            version: 'Version'
        },
        
        nav: {
            dashboard: 'Dashboard',
            scanner: 'Scanner',
            monitoring: 'Monitoring',
            reports: 'Reports',
            settings: 'Settings'
        },
        
        lang: {
            zh: '中文',
            en: 'English'
        },
        
        login: {
            title: 'Login',
            username: 'Username / Email',
            usernamePlaceholder: 'Enter your username or email',
            password: 'Password',
            passwordPlaceholder: 'Enter your password',
            remember: 'Remember me',
            forgot: 'Forgot password?',
            btn: 'Sign In',
            signing: 'Signing in...',
            error: 'Invalid username or password',
            errorConnection: 'Connection error. Please try again'
        },
        
        stats: {
            totalScans: 'Total Scans',
            criticalVulns: 'Critical Vulnerabilities',
            highVulns: 'High Vulnerabilities',
            targetsScanned: 'Targets Scanned'
        },
        
        scan: {
            newScan: 'New Scan',
            targetUrl: 'Target URL / IP',
            targetPlaceholder: 'http://example.com or 192.168.1.1',
            scanLevel: 'Scan Level',
            scanOptions: 'Scan Options',
            advanced: 'Advanced Options',
            startScan: 'Start Scan',
            stopScan: 'Stop Scan',
            starting: 'Starting...',
            initializing: 'Initializing scan...',
            running: 'Scanning target...',
            analyzing: 'Analyzing results...',
            completed: 'Scan completed',
            stopped: 'Scan stopped by user',
            foundVulns: 'Found {count} vulnerabilities',
            phaseCrawl: 'Crawling',
            phaseDirScan: 'Directory Scan',
            phaseParamFuzz: 'Parameter Fuzzing',
            phaseRceScan: 'RCE Detection'
        },
        
        level: {
            quick: 'Quick',
            normal: 'Normal',
            deep: 'Deep',
            full: 'Full'
        },
        
        option: {
            crawl: 'Web Crawler',
            dirScan: 'Directory Scan',
            paramFuzz: 'Parameter Fuzzing',
            wafBypass: 'WAF Bypass',
            harmless: 'Harmless Mode',
            preferHttps: 'Prefer HTTPS'
        },
        
        advanced: {
            method: 'HTTP Method',
            concurrent: 'Concurrent',
            timeout: 'Timeout (s)',
            delayThreshold: 'Delay Threshold (s)',
            proxy: 'Proxy Server',
            headers: 'Custom Headers',
            postData: 'POST Data',
            crawlDepth: 'Crawl Depth',
            maxPages: 'Max Pages'
        },
        
        results: {
            title: 'Results',
            all: 'All',
            critical: 'Critical',
            high: 'High',
            medium: 'Medium',
            low: 'Low',
            noResults: 'No scan results yet',
            startScan: 'Start a new scan to detect vulnerabilities',
            parameter: 'Parameter',
            type: 'Type',
            request: 'Request Details',
            exportJson: 'Export JSON',
            exportHtml: 'Export HTML',
            exportMd: 'Export Markdown'
        },
        
        progress: {
            initializing: 'Initializing...',
            scanning: 'Scanning...',
            analyzing: 'Analyzing...',
            completed: 'Completed',
            crawled: 'Pages crawled',
            discovered: 'Paths discovered',
            foundParams: 'Parameters found'
        },
        
        monitoring: {
            cpuUsage: 'CPU Usage',
            memoryUsage: 'Memory Usage',
            networkTraffic: 'Network Traffic',
            scanPerformance: 'Scan Performance',
            realtime: 'Real-time',
            requestsPerSec: 'Requests/s'
        },
        
        vuln: {
            critical: 'Critical',
            high: 'High',
            medium: 'Medium',
            low: 'Low'
        },
        
        history: {
            title: 'Scan History',
            noHistory: 'No scan history',
            view: 'View',
            vulnFound: 'vulnerabilities'
        },
        
        search: {
            placeholder: 'Search targets, vulnerabilities...'
        },
        
        common: {
            logout: 'Logout',
            logoutConfirm: 'Do you want to logout?',
            confirm: 'Confirm',
            cancel: 'Cancel',
            save: 'Save',
            delete: 'Delete',
            edit: 'Edit',
            close: 'Close',
            loading: 'Loading...',
            noData: 'No data',
            error: 'Error occurred',
            success: 'Success',
            noResults: 'No scan results to export'
        }
    }
};

let currentLang = localStorage.getItem('hawkeye_lang') || 'zh';

function t(key, params = {}) {
    const keys = key.split('.');
    let text = translations[currentLang];
    
    for (const k of keys) {
        if (text && text[k] !== undefined) {
            text = text[k];
        } else {
            text = translations['zh'];
            for (const k2 of keys) {
                if (text && text[k2] !== undefined) {
                    text = text[k2];
                } else {
                    return key;
                }
            }
            break;
        }
    }
    
    if (typeof text !== 'string') {
        return key;
    }
    
    Object.keys(params).forEach(param => {
        text = text.replace(new RegExp(`\\{${param}\\}`, 'g'), params[param]);
    });
    
    return text;
}

function setLanguage(lang) {
    currentLang = lang;
    localStorage.setItem('hawkeye_lang', lang);
    updatePageLanguage();
}

function updatePageLanguage() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        el.textContent = t(key);
    });
    
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        el.placeholder = t(key);
    });
    
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const key = el.getAttribute('data-i18n-title');
        el.title = t(key);
    });
    
    const langSelector = document.getElementById('langSelector');
    if (langSelector) {
        langSelector.value = currentLang;
    }
}

function getCurrentLang() {
    return currentLang;
}

document.addEventListener('DOMContentLoaded', function() {
    updatePageLanguage();
});
