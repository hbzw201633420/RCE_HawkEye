package web

var i18nJS = `
var translations = {
    zh: {
        app: {
            name: 'RCE HawkEye',
            desc: '命令执行漏洞自动化检测工具',
            version: '版本'
        },
        
        nav: {
            dashboard: '仪表板',
            scanner: '扫描器',
            exploit: '漏洞利用',
            monitoring: '监控',
            reports: '报告',
            history: '历史',
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
            success: '登录成功',
            error: '用户名或密码错误',
            errorConnection: '连接错误，请重试',
            emptyFields: '请输入用户名和密码',
            showPassword: '显示密码',
            hidePassword: '隐藏密码'
        },
        
        search: {
            placeholder: '搜索...'
        },
        
        stats: {
            totalScans: '总扫描次数',
            criticalVulns: '严重漏洞',
            highVulns: '高危漏洞',
            targetsScanned: '已扫描目标'
        },
        
        config: {
            basic: '基本配置',
            target: '目标配置',
            http: 'HTTP配置',
            payloads: '载荷配置',
            encoder: '编码器',
            advanced: '高级配置',
            dirscan: '目录扫描',
            paramfuzz: '参数模糊',
            crawl: '爬虫配置',
            output: '输出配置',
            targetSettings: '目标设置',
            scanSettings: '扫描设置',
            scanOptions: '扫描选项'
        },
        
        target: {
            urlFile: 'URL列表 (每行一个)',
            urlFilePlaceholder: '每行一个URL',
            rawTraffic: '流量包文件',
            rawTrafficPlaceholder: '流量包文件路径',
            configFile: '配置文件',
            configFilePlaceholder: '配置文件路径',
            allowDomains: '允许域名',
            blockDomains: '禁止域名',
            restrictRoot: '限制在根域名内',
            fileUpload: '或上传文件'
        },
        
        http: {
            method: '请求方法',
            proxy: '代理服务器',
            timeout: '超时时间',
            postData: 'POST数据',
            headers: '自定义请求头',
            userAgent: 'User-Agent',
            sslOptions: 'SSL选项',
            delayThreshold: '延迟阈值 (秒)'
        },
        
        proxy: {
            type: '代理类型',
            address: '代理地址',
            username: '用户名',
            password: '密码',
            test: '测试连接',
            testSuccess: '连接成功',
            testFailed: '连接失败',
            testConnection: '测试连接'
        },
        
        payload: {
            targetOS: '目标操作系统',
            techStack: '技术栈',
            types: '载荷类型',
            custom: '自定义载荷',
            wordlist: '自定义字典'
        },
        
        encoder: {
            encoding: '编码选项',
            bypass: 'WAF绕过技术',
            tool: '编码工具'
        },
        
        dirscan: {
            threads: '线程数',
            wordlist: '字典文件',
            archiveThreshold: '归档阈值',
            filterStatus: '状态码筛选',
            filterExt: '扩展名筛选',
            filterPattern: '路径模式',
            options: '目录扫描选项'
        },
        
        paramfuzz: {
            wordlist: '参数字典',
            options: '参数模糊选项'
        },
        
        crawl: {
            depth: '爬虫深度',
            maxPages: '最大页面数',
            timeout: '超时时间',
            allowDomains: '允许域名',
            blockDomains: '禁止域名',
            options: '爬虫选项'
        },
        
        output: {
            format: '输出格式',
            dir: '输出目录',
            file: '输出文件',
            settings: '输出设置'
        },
        
        scan: {
            newScan: '新建扫描',
            targetUrl: '目标 URL',
            targetPlaceholder: 'http://example.com',
            targetRequired: '请输入目标URL、URL文件或流量包文件',
            scanLevel: '扫描等级',
            scanMode: '扫描模式',
            delayThreshold: '延迟阈值 (秒)',
            scanOptions: '扫描选项',
            concurrent: '并发数',
            timeout: '超时时间 (秒)',
            retries: '重试次数',
            smartDict: '智能字典',
            advanced: '高级选项',
            startScan: '开始扫描',
            stopScan: '停止扫描',
            starting: '启动中...',
            initializing: '初始化扫描...',
            running: '正在扫描...',
            analyzing: '分析结果中...',
            completed: '扫描完成',
            stopped: '扫描已停止',
            error: '扫描出错',
            foundVulns: '发现 {count} 个漏洞',
            currentUrl: '当前URL',
            currentParam: '当前参数',
            progress: '扫描进度',
            vulnsFound: '已发现漏洞',
            terminal: '扫描终端'
        },
        
        level: {
            quick: '快速',
            normal: '标准',
            deep: '深度',
            full: '完全'
        },
        
        mode: {
            echo: '有回显',
            harmless: '无害化',
            wafBypass: 'WAF绕过'
        },
        
        option: {
            crawl: '网页爬虫',
            dirScan: '目录扫描',
            paramFuzz: '参数模糊测试',
            wafBypass: 'WAF绕过',
            harmless: '无害化检测',
            preferHTTPS: '优先HTTPS',
            verifySSL: '验证SSL证书',
            noHTTPS: '禁用HTTPS',
            verbose: '详细输出',
            smartDict: '智能字典',
            includeResponse: '包含响应',
            followRedirect: '跟随重定向',
            autoDetect: '自动检测技术栈'
        },
        
        results: {
            title: '扫描结果',
            all: '全部',
            critical: '严重',
            high: '高危',
            medium: '中危',
            low: '低危',
            noResults: '暂无扫描结果',
            startScan: '开始新扫描以检测漏洞'
        },
        
        progress: {
            initializing: '初始化中...',
            scanning: '扫描中...',
            analyzing: '分析中...',
            completed: '完成'
        },
        
        monitoring: {
            cpuUsage: 'CPU使用率',
            memoryUsage: '内存使用',
            cpuCores: 'CPU核心',
            goroutines: '协程数',
            vulnsFound: '发现漏洞',
            networkTraffic: '网络流量',
            networkIO: '网络I/O',
            scanPerformance: '扫描性能',
            realtime: '实时',
            requestsPerSec: '请求/秒',
            heapMemory: '堆内存',
            heapAlloc: '堆分配',
            heapTrend: '堆内存趋势',
            stackMemory: '栈内存',
            stackInuse: '栈使用',
            totalMemory: '总内存',
            goVersion: 'Go版本',
            memoryChart: '内存趋势',
            cpuTrend: 'CPU使用率趋势',
            memoryTrend: '内存使用趋势',
            networkTrend: '网络I/O趋势',
            goroutineTrend: '协程数趋势',
            gcTrend: 'GC暂停趋势',
            timeRange: '时间范围',
            lastHour: '最近1小时',
            lastDay: '今天',
            lastWeek: '本周',
            custom: '自定义',
            gcPause: 'GC暂停',
            trendView: '趋势图',
            gaugeView: '百分比图',
            confirmClearAlerts: '确定清除所有告警？'
        },
        
        alerts: {
            title: '告警通知',
            noAlerts: '暂无告警',
            clearAll: '清除全部',
            memory: '内存告警',
            scan: '扫描告警',
            system: '系统告警'
        },
        
        reports: {
            title: '报告列表',
            export: '导出报告',
            exportAll: '批量导出',
            download: '下载',
            view: '查看',
            delete: '删除',
            format: '格式',
            html: 'HTML报告',
            json: 'JSON数据',
            csv: 'CSV表格',
            includePerf: '包含性能数据',
            includeVulns: '包含漏洞详情',
            includeRecommendations: '包含修复建议',
            selectAll: '全选',
            deleteSelected: '删除选中',
            noReports: '暂无报告',
            confirmDelete: '确定删除选中的报告？',
            deleteSuccess: '报告删除成功',
            deleteFailed: '删除失败',
            selectFirst: '请先选择报告'
        },
        
        dashboard: {
            quickScan: '快速扫描',
            quickScanPlaceholder: '输入目标URL开始快速扫描...',
            systemStatus: '系统状态',
            online: '在线',
            memory: '内存',
            cpuCores: 'CPU核心',
            goVersion: 'Go版本',
            vulnDistribution: '漏洞分布',
            recentActivity: '最近活动',
            quickActions: '快捷操作'
        },
        
        vuln: {
            critical: '严重',
            high: '高危',
            medium: '中危',
            low: '低危'
        },
        
        settings: {
            general: '常规',
            notification: '通知',
            proxy: '代理',
            dictionary: '字典',
            security: '安全',
            about: '关于',
            reset: '重置',
            scanDefaults: '扫描默认值',
            account: '账户设置',
            admin: '管理员',
            newPassword: '新密码',
            confirmPassword: '确认密码',
            passwordMismatch: '两次密码输入不一致',
            currentUsername: '当前用户',
            userRole: '用户角色',
            outputSettings: '输出设置',
            scanOptions: '默认扫描选项',
            securityOptions: '安全选项',
            sslOptions: 'SSL/TLS选项',
            proxyConfig: '代理配置',
            dictMemory: '字典记忆设置',
            dictStats: '字典统计',
            resetData: '重置数据',
            resetWarning: '警告：这些操作无法撤销！',
            delayThreshold: '延迟阈值 (秒)',
            notificationConfig: '通知配置',
            enableNotification: '启用通知'
        },
        about: {
            buildDate: '构建日期',
            platform: '平台',
            goVersion: 'Go版本',
            checkUpdate: '检查更新',
            checking: '正在检查更新...',
            newVersion: '发现新版本！',
            upToDate: '已是最新版本！',
            checkFailed: '检查更新失败',
            download: '下载',
            reportIssue: '反馈问题'
        },
        
        history: {
            title: '扫描历史',
            totalScans: '总扫描数',
            domains: '域名数',
            vulnerabilities: '漏洞数',
            critical: '严重',
            high: '高危',
            searchPlaceholder: '搜索域名、URL...',
            allDates: '全部日期',
            allStatus: '全部状态',
            completed: '已完成',
            running: '运行中',
            error: '错误',
            export: '导出',
            clear: '清除',
            noData: '暂无扫描历史',
            noDataHint: '开始新的扫描以在此查看结果',
            detail: '扫描详情',
            basicInfo: '基本信息',
            target: '目标',
            domain: '域名',
            status: '状态',
            startTime: '开始时间',
            duration: '扫描时长',
            vulnSummary: '漏洞统计',
            total: '总计',
            medium: '中危',
            low: '低危',
            notes: '备注',
            saveNotes: '保存备注',
            notesSaved: '备注已保存',
            confirmClear: '确定清除所有历史记录？',
            exportFormat: '导出格式 (json/csv):',
            newestFirst: '最新优先',
            oldestFirst: '最早优先',
            selected: '已选择',
            exportSelected: '导出选中',
            deleteSelected: '删除选中',
            selectAll: '全选',
            selectFirst: '请先选择项目',
            confirmDelete: '确定删除选中的项目？',
            domainDetail: '域名详情',
            domainInfo: '域名信息',
            exportReport: '导出报告',
            deleteSuccess: '删除成功',
            deleteFailed: '删除失败'
        },
        
        notification: {
            wechat: '企业微信',
            wechatKey: 'Webhook Key',
            dingtalk: '钉钉',
            dingtalkUrl: 'Webhook URL',
            email: '邮件',
            smtpHost: 'SMTP服务器',
            smtpPort: 'SMTP端口',
            username: '用户名',
            password: '密码',
            from: '发件人',
            to: '收件人',
            testWechat: '测试微信',
            testDingtalk: '测试钉钉',
            testEmail: '测试邮件',
            saveSettings: '保存设置',
            testSuccess: '测试通知发送成功',
            testFailed: '测试通知发送失败',
            settingsSaved: '通知设置已保存'
        },
        
        dict: {
            archiveThreshold: '归档阈值',
            archiveThresholdHint: '连续未命中次数达到此值后归档',
            maxRetention: '最大保留天数',
            maxRetentionHint: '归档条目的保留天数',
            enableSmart: '启用智能字典',
            dirWordlist: '目录扫描字典',
            paramWordlist: '参数模糊字典',
            totalEntries: '总条目数',
            archivedEntries: '已归档',
            activeEntries: '活跃'
        },
        
        reset: {
            dictMemory: '重置字典记忆',
            dictMemoryDesc: '清除所有字典统计和归档条目',
            dictMemoryConfirm: '确定要重置字典记忆吗？此操作无法撤销。',
            scanHistory: '重置扫描历史',
            scanHistoryDesc: '清除所有扫描历史和结果',
            scanHistoryConfirm: '确定要清除所有扫描历史吗？此操作无法撤销。',
            reports: '重置报告',
            reportsDesc: '删除所有保存的报告',
            reportsConfirm: '确定要删除所有报告吗？此操作无法撤销。',
            allSettings: '重置所有设置',
            allSettingsDesc: '恢复所有设置为默认值',
            allSettingsConfirm: '确定要重置所有设置吗？此操作无法撤销。',
            factoryReset: '恢复出厂设置',
            factoryResetDesc: '重置所有数据到初始状态',
            factoryResetConfirm: '确定要恢复出厂设置吗？这将删除所有数据和设置。此操作无法撤销。'
        },
        
        exploit: {
            vulnList: '漏洞列表',
            noVulns: '暂无发现漏洞',
            selectVuln: '选择一个漏洞开始操作...',
            selectVulnFirst: '请先选择一个漏洞',
            connected: '已连接目标，准备执行命令。',
            target: '目标',
            os: '系统',
            cmdExec: '命令执行',
            reverseShell: '反弹Shell',
            webshell: '一句话木马',
            logs: '操作日志',
            operationLogs: '操作日志',
            reverseShellGen: '反弹Shell生成器'
        },
        
        shell: {
            listenIP: '监听IP',
            listenPort: '监听端口',
            autoDetect: '自动检测',
            shellType: 'Shell类型',
            targetOS: '目标系统',
            generatedCmd: '生成的命令',
            listenCmd: '监听命令'
        },
        
        webshell: {
            generator: '木马生成器',
            targetLang: '目标语言',
            password: '连接密码',
            type: '木马类型',
            simple: '简单型',
            bypass: '免杀型',
            custom: '自定义',
            customCode: '自定义代码',
            preview: '预览',
            write: '写入目标',
            writePath: '写入路径',
            writeConfirm: '确定要写入木马到目标吗？这是一个敏感操作。'
        },
        
        logs: {
            all: '全部类型',
            cmd: '命令执行',
            shell: '反弹Shell',
            webshell: '木马操作',
            noLogs: '暂无操作日志',
            export: '导出',
            clearConfirm: '确定要清除所有操作日志吗？'
        },
        
        common: {
            logout: '退出登录',
            logoutConfirm: '确定要退出登录吗?',
            confirm: '确定',
            cancel: '取消',
            save: '保存',
            reset: '重置',
            resetAll: '全部重置',
            factoryReset: '恢复出厂',
            refresh: '刷新',
            clear: '清除',
            confirmClear: '确定要清除所有历史记录吗?',
            loading: '加载中...',
            noData: '暂无数据',
            error: '发生错误',
            success: '操作成功',
            enabled: '启用',
            disabled: '禁用',
            copy: '复制',
            copied: '已复制到剪贴板',
            resetDefaults: '恢复默认',
            saveSettings: '保存设置',
            settingsReset: '设置已恢复为默认值',
            settingsSaved: '设置已保存',
            saveFailed: '保存失败',
            selectAll: '全选',
            deselectAll: '取消全选',
            deleteSelected: '删除选中',
            delete: '删除',
            deleted: '删除成功'
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
            exploit: 'Exploit',
            monitoring: 'Monitoring',
            reports: 'Reports',
            history: 'History',
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
            success: 'Login successful',
            error: 'Invalid username or password',
            errorConnection: 'Connection error. Please try again',
            emptyFields: 'Please enter username and password',
            showPassword: 'Show password',
            hidePassword: 'Hide password'
        },
        
        search: {
            placeholder: 'Search...'
        },
        
        stats: {
            totalScans: 'Total Scans',
            criticalVulns: 'Critical Vulnerabilities',
            highVulns: 'High Vulnerabilities',
            targetsScanned: 'Targets Scanned'
        },
        
        config: {
            basic: 'Basic',
            target: 'Target',
            http: 'HTTP',
            payloads: 'Payloads',
            encoder: 'Encoder',
            advanced: 'Advanced',
            dirscan: 'Dir Scan',
            paramfuzz: 'Param Fuzz',
            crawl: 'Crawler',
            output: 'Output',
            targetSettings: 'Target Settings',
            scanSettings: 'Scan Settings',
            scanOptions: 'Scan Options'
        },
        
        target: {
            urlFile: 'URL List (one per line)',
            urlFilePlaceholder: 'One URL per line',
            rawTraffic: 'Traffic File',
            rawTrafficPlaceholder: 'Traffic file path',
            configFile: 'Config File',
            configFilePlaceholder: 'Config file path',
            allowDomains: 'Allow Domains',
            blockDomains: 'Block Domains',
            restrictRoot: 'Restrict to Root Domain',
            fileUpload: 'Or Upload File'
        },
        
        http: {
            method: 'Request Method',
            proxy: 'Proxy Server',
            timeout: 'Timeout',
            postData: 'POST Data',
            headers: 'Custom Headers',
            userAgent: 'User-Agent',
            sslOptions: 'SSL Options',
            delayThreshold: 'Delay Threshold (s)'
        },
        
        proxy: {
            type: 'Proxy Type',
            address: 'Proxy Address',
            username: 'Username',
            password: 'Password',
            test: 'Test Connection',
            testSuccess: 'Connection successful',
            testFailed: 'Connection failed',
            testConnection: 'Test Connection'
        },
        
        payload: {
            targetOS: 'Target OS',
            techStack: 'Tech Stack',
            types: 'Payload Types',
            custom: 'Custom Payloads',
            wordlist: 'Custom Wordlist'
        },
        
        encoder: {
            encoding: 'Encoding Options',
            bypass: 'WAF Bypass Techniques',
            tool: 'Encoding Tool'
        },
        
        dirscan: {
            threads: 'Threads',
            wordlist: 'Wordlist File',
            archiveThreshold: 'Archive Threshold',
            filterStatus: 'Status Code Filter',
            filterExt: 'Extension Filter',
            filterPattern: 'Path Pattern',
            options: 'Directory Scan Options'
        },
        
        paramfuzz: {
            wordlist: 'Parameter Wordlist',
            options: 'Parameter Fuzz Options'
        },
        
        crawl: {
            depth: 'Crawl Depth',
            maxPages: 'Max Pages',
            timeout: 'Timeout',
            allowDomains: 'Allow Domains',
            blockDomains: 'Block Domains',
            options: 'Crawler Options'
        },
        
        output: {
            format: 'Output Format',
            dir: 'Output Directory',
            file: 'Output File',
            settings: 'Output Settings'
        },
        
        scan: {
            newScan: 'New Scan',
            targetUrl: 'Target URL',
            targetPlaceholder: 'http://example.com',
            targetRequired: 'Please enter a target URL, URLs file, or traffic file',
            scanLevel: 'Scan Level',
            scanMode: 'Scan Mode',
            delayThreshold: 'Delay Threshold (s)',
            scanOptions: 'Scan Options',
            concurrent: 'Concurrent',
            timeout: 'Timeout (s)',
            retries: 'Retries',
            smartDict: 'Smart Dictionary',
            advanced: 'Advanced Options',
            startScan: 'Start Scan',
            stopScan: 'Stop Scan',
            starting: 'Starting...',
            initializing: 'Initializing scan...',
            running: 'Scanning target...',
            analyzing: 'Analyzing results...',
            completed: 'Scan completed',
            stopped: 'Scan stopped by user',
            error: 'Scan error',
            foundVulns: 'Found {count} vulnerabilities',
            currentUrl: 'Current URL',
            currentParam: 'Current Param',
            progress: 'Progress',
            vulnsFound: 'Vulns Found',
            terminal: 'Scan Terminal'
        },
        
        level: {
            quick: 'Quick',
            normal: 'Normal',
            deep: 'Deep',
            full: 'Full'
        },
        
        mode: {
            echo: 'Echo Based',
            harmless: 'Harmless',
            wafBypass: 'WAF Bypass'
        },
        
        option: {
            crawl: 'Web Crawler',
            dirScan: 'Directory Scan',
            paramFuzz: 'Parameter Fuzzing',
            wafBypass: 'WAF Bypass',
            harmless: 'Harmless Mode',
            preferHTTPS: 'Prefer HTTPS',
            verifySSL: 'Verify SSL Certificate',
            noHTTPS: 'Disable HTTPS',
            verbose: 'Verbose Output',
            includeResponse: 'Include Response',
            recursive: 'Recursive Scan',
            followRedirects: 'Follow Redirects',
            extractJS: 'Extract from JS',
            extractHTML: 'Extract from HTML',
            restrictRoot: 'Restrict to Root Domain',
            smartDict: 'Smart Dictionary'
        },
        
        results: {
            title: 'Results',
            all: 'All',
            critical: 'Critical',
            high: 'High',
            medium: 'Medium',
            low: 'Low',
            noResults: 'No scan results yet',
            startScan: 'Start a new scan to detect vulnerabilities'
        },
        
        progress: {
            initializing: 'Initializing...',
            scanning: 'Scanning...',
            analyzing: 'Analyzing...',
            completed: 'Completed'
        },
        
        monitoring: {
            cpuUsage: 'CPU Usage',
            memoryUsage: 'Memory Usage',
            cpuCores: 'CPU Cores',
            goroutines: 'Goroutines',
            vulnsFound: 'Vulnerabilities',
            networkTraffic: 'Network Traffic',
            networkIO: 'Network I/O',
            scanPerformance: 'Scan Performance',
            realtime: 'Real-time',
            requestsPerSec: 'Requests/s',
            heapMemory: 'Heap Memory',
            heapAlloc: 'Heap Alloc',
            heapTrend: 'Heap Memory Trend',
            stackMemory: 'Stack Memory',
            stackInuse: 'Stack Inuse',
            totalMemory: 'Total Memory',
            goVersion: 'Go Version',
            memoryChart: 'Memory Trend',
            cpuTrend: 'CPU Usage Trend',
            memoryTrend: 'Memory Usage Trend',
            networkTrend: 'Network I/O Trend',
            goroutineTrend: 'Goroutine Trend',
            gcTrend: 'GC Pause Trend',
            timeRange: 'Time Range',
            lastHour: 'Last Hour',
            lastDay: 'Today',
            lastWeek: 'This Week',
            custom: 'Custom',
            gcPause: 'GC Pause',
            trendView: 'Trend',
            gaugeView: 'Gauge',
            confirmClearAlerts: 'Clear all alerts?'
        },
        
        alerts: {
            title: 'Alerts',
            noAlerts: 'No alerts',
            clearAll: 'Clear All',
            memory: 'Memory Alert',
            scan: 'Scan Alert',
            system: 'System Alert'
        },
        
        reports: {
            title: 'Reports',
            export: 'Export Report',
            exportAll: 'Export All',
            download: 'Download',
            view: 'View',
            delete: 'Delete',
            format: 'Format',
            html: 'HTML Report',
            json: 'JSON Data',
            csv: 'CSV Table',
            includePerf: 'Include Performance',
            includeVulns: 'Include Vulnerabilities',
            includeRecommendations: 'Include Recommendations',
            selectAll: 'Select All',
            deleteSelected: 'Delete Selected',
            noReports: 'No reports found',
            confirmDelete: 'Delete selected reports?',
            deleteSuccess: 'Reports deleted successfully',
            deleteFailed: 'Failed to delete',
            selectFirst: 'Please select reports first'
        },
        
        dashboard: {
            quickScan: 'Quick Scan',
            quickScanPlaceholder: 'Enter target URL for quick scan...',
            systemStatus: 'System Status',
            online: 'Online',
            memory: 'Memory',
            cpuCores: 'CPU Cores',
            goVersion: 'Go Version',
            vulnDistribution: 'Vulnerability Distribution',
            recentActivity: 'Recent Activity',
            quickActions: 'Quick Actions'
        },
        
        vuln: {
            critical: 'Critical',
            high: 'High',
            medium: 'Medium',
            low: 'Low'
        },
        
        settings: {
            general: 'General',
            notification: 'Notification',
            proxy: 'Proxy',
            dictionary: 'Dictionary',
            security: 'Security',
            about: 'About',
            reset: 'Reset',
            scanDefaults: 'Scan Defaults',
            account: 'Account Settings',
            admin: 'Administrator',
            newPassword: 'New Password',
            confirmPassword: 'Confirm Password',
            passwordMismatch: 'Passwords do not match',
            currentUsername: 'Current User',
            userRole: 'User Role',
            outputSettings: 'Output Settings',
            scanOptions: 'Default Scan Options',
            securityOptions: 'Security Options',
            sslOptions: 'SSL/TLS Options',
            proxyConfig: 'Proxy Configuration',
            dictMemory: 'Dictionary Memory Settings',
            dictStats: 'Dictionary Statistics',
            resetData: 'Reset Data',
            resetWarning: 'Warning: These actions cannot be undone!',
            delayThreshold: 'Delay Threshold (s)',
            notificationConfig: 'Notification Configuration',
            enableNotification: 'Enable Notifications'
        },
        about: {
            buildDate: 'Build Date',
            platform: 'Platform',
            goVersion: 'Go Version',
            checkUpdate: 'Check for Updates',
            checking: 'Checking for updates...',
            newVersion: 'New version available!',
            upToDate: 'You are running the latest version!',
            checkFailed: 'Failed to check for updates',
            download: 'Download',
            reportIssue: 'Report Issue'
        },
        
        history: {
            title: 'Scan History',
            totalScans: 'Total Scans',
            domains: 'Domains',
            vulnerabilities: 'Vulnerabilities',
            critical: 'Critical',
            high: 'High',
            searchPlaceholder: 'Search domain, URL...',
            allDates: 'All Dates',
            allStatus: 'All Status',
            completed: 'Completed',
            running: 'Running',
            error: 'Error',
            export: 'Export',
            clear: 'Clear',
            noData: 'No scan history',
            noDataHint: 'Start a new scan to see results here',
            detail: 'Scan Details',
            basicInfo: 'Basic Information',
            target: 'Target',
            domain: 'Domain',
            status: 'Status',
            startTime: 'Start Time',
            duration: 'Duration',
            vulnSummary: 'Vulnerability Summary',
            total: 'Total',
            medium: 'Medium',
            low: 'Low',
            notes: 'Notes',
            saveNotes: 'Save Notes',
            notesSaved: 'Notes saved',
            confirmClear: 'Clear all history records?',
            exportFormat: 'Export format (json/csv):',
            newestFirst: 'Newest First',
            oldestFirst: 'Oldest First',
            selected: 'selected',
            exportSelected: 'Export Selected',
            deleteSelected: 'Delete Selected',
            selectAll: 'Select All',
            selectFirst: 'Please select items first',
            confirmDelete: 'Delete selected items?',
            domainDetail: 'Domain Details',
            domainInfo: 'Domain Information',
            exportReport: 'Export Report',
            deleteSuccess: 'Deleted successfully',
            deleteFailed: 'Delete failed'
        },
        
        notification: {
            wechat: 'WeChat Work',
            wechatKey: 'Webhook Key',
            dingtalk: 'DingTalk',
            dingtalkUrl: 'Webhook URL',
            email: 'Email',
            smtpHost: 'SMTP Host',
            smtpPort: 'SMTP Port',
            username: 'Username',
            password: 'Password',
            from: 'From',
            to: 'To',
            testWechat: 'Test WeChat',
            testDingtalk: 'Test DingTalk',
            testEmail: 'Test Email',
            saveSettings: 'Save Settings',
            testSuccess: 'Test notification sent successfully',
            testFailed: 'Failed to send test notification',
            settingsSaved: 'Notification settings saved'
        },
        
        dict: {
            archiveThreshold: 'Archive Threshold',
            archiveThresholdHint: 'Number of consecutive misses before archiving',
            maxRetention: 'Max Retention Days',
            maxRetentionHint: 'Days to keep archived entries',
            enableSmart: 'Enable Smart Dictionary',
            dirWordlist: 'Directory Scan Wordlist',
            paramWordlist: 'Parameter Fuzz Wordlist',
            totalEntries: 'Total Entries',
            archivedEntries: 'Archived',
            activeEntries: 'Active'
        },
        
        reset: {
            dictMemory: 'Reset Dictionary Memory',
            dictMemoryDesc: 'Clear all dictionary statistics and archived entries',
            dictMemoryConfirm: 'Reset all dictionary memory? This cannot be undone.',
            scanHistory: 'Reset Scan History',
            scanHistoryDesc: 'Clear all scan history and results',
            scanHistoryConfirm: 'Clear all scan history? This cannot be undone.',
            reports: 'Reset Reports',
            reportsDesc: 'Delete all saved reports',
            reportsConfirm: 'Delete all reports? This cannot be undone.',
            allSettings: 'Reset All Settings',
            allSettingsDesc: 'Restore all settings to default values',
            allSettingsConfirm: 'Reset all settings to default? This cannot be undone.',
            factoryReset: 'Factory Reset',
            factoryResetDesc: 'Reset everything to initial state',
            factoryResetConfirm: 'Factory reset? This will delete ALL data and settings. This cannot be undone.'
        },
        
        exploit: {
            vulnList: 'Vulnerability List',
            noVulns: 'No vulnerabilities found',
            selectVuln: 'Select a vulnerability to start...',
            selectVulnFirst: 'Please select a vulnerability first',
            connected: 'Connected to target. Ready to execute commands.',
            target: 'Target',
            os: 'OS',
            cmdExec: 'Command Execution',
            reverseShell: 'Reverse Shell',
            webshell: 'Webshell',
            logs: 'Logs',
            operationLogs: 'Operation Logs',
            reverseShellGen: 'Reverse Shell Generator'
        },
        
        shell: {
            listenIP: 'Listen IP',
            listenPort: 'Listen Port',
            autoDetect: 'Auto Detect',
            shellType: 'Shell Type',
            targetOS: 'Target OS',
            generatedCmd: 'Generated Command',
            listenCmd: 'Listen Command'
        },
        
        webshell: {
            generator: 'Webshell Generator',
            targetLang: 'Target Language',
            password: 'Password',
            type: 'Shell Type',
            simple: 'Simple',
            bypass: 'WAF Bypass',
            custom: 'Custom',
            customCode: 'Custom Code',
            preview: 'Preview',
            write: 'Write to Target',
            writePath: 'Write Path',
            writeConfirm: 'Write webshell to target? This is a sensitive operation.'
        },
        
        logs: {
            all: 'All Types',
            cmd: 'Commands',
            shell: 'Reverse Shell',
            webshell: 'Webshell',
            noLogs: 'No operation logs',
            export: 'Export',
            clearConfirm: 'Clear all operation logs?'
        },
        
        common: {
            logout: 'Logout',
            logoutConfirm: 'Do you want to logout?',
            confirm: 'Confirm',
            cancel: 'Cancel',
            save: 'Save',
            reset: 'Reset',
            resetAll: 'Reset All',
            factoryReset: 'Factory Reset',
            refresh: 'Refresh',
            clear: 'Clear',
            confirmClear: 'Clear all history?',
            loading: 'Loading...',
            noData: 'No data',
            error: 'Error occurred',
            success: 'Success',
            enabled: 'Enabled',
            disabled: 'Disabled',
            copy: 'Copy',
            copied: 'Copied to clipboard',
            resetDefaults: 'Reset to Defaults',
            saveSettings: 'Save Settings',
            settingsReset: 'Settings reset to defaults',
            settingsSaved: 'Settings saved',
            saveFailed: 'Failed to save settings',
            selectAll: 'Select All',
            deselectAll: 'Deselect All',
            deleteSelected: 'Delete Selected',
            delete: 'Delete',
            deleted: 'Deleted successfully'
        }
    }
};

var currentLang = localStorage.getItem('hawkeye_lang') || 'zh';

function t(key, params) {
    if (!params) params = {};
    var keys = key.split('.');
    var text = translations[currentLang];
    
    for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        if (text && text[k] !== undefined) {
            text = text[k];
        } else {
            text = translations['zh'];
            for (var j = 0; j < keys.length; j++) {
                var k2 = keys[j];
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
    
    Object.keys(params).forEach(function(param) {
        text = text.replace(new RegExp('{' + param + '}', 'g'), params[param]);
    });
    
    return text;
}

function setLanguage(lang) {
    currentLang = lang;
    localStorage.setItem('hawkeye_lang', lang);
    updatePageLanguage();
}

function updatePageLanguage() {
    document.querySelectorAll('[data-i18n]').forEach(function(el) {
        var key = el.getAttribute('data-i18n');
        el.textContent = t(key);
    });
    
    document.querySelectorAll('[data-i18n-placeholder]').forEach(function(el) {
        var key = el.getAttribute('data-i18n-placeholder');
        el.placeholder = t(key);
    });
    
    var langSelector = document.getElementById('langSelector');
    if (langSelector) {
        langSelector.value = currentLang;
    }
}

function getCurrentLang() {
    return currentLang;
}
`
