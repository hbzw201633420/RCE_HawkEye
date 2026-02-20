package web

var dashboardHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RCE HawkEye - Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Sans:wght@300;400;500;600;700&family=Fira+Code:wght@400;500;600&display=swap" rel="stylesheet">
    <script>
        // Load Chart.js UMD version from multiple CDNs with fallback
        (function() {
            var cdns = [
                'https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js',
                'https://unpkg.com/chart.js@3.9.1/dist/chart.min.js',
                'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js',
                'https://cdn.bootcdn.net/ajax/libs/Chart.js/3.9.1/chart.min.js'
            ];
            var loaded = false;
            var index = 0;
            function loadChart() {
                if (loaded) return;
                if (index >= cdns.length) {
                    console.warn('Chart.js could not be loaded from any CDN, charts will be disabled');
                    window.ChartLoadFailed = true;
                    return;
                }
                var script = document.createElement('script');
                script.src = cdns[index];
                script.async = false;
                script.onerror = function() {
                    console.warn('Failed to load Chart.js from:', cdns[index]);
                    index++;
                    loadChart();
                };
                script.onload = function() {
                    if (typeof Chart !== 'undefined') {
                        loaded = true;
                        console.log('Chart.js loaded successfully');
                    } else {
                        index++;
                        loadChart();
                    }
                };
                document.head.appendChild(script);
            }
            loadChart();
        })();
    </script>
    <link href="/static/css/style.css" rel="stylesheet">
</head>
<body>
    <aside class="sidebar">
        <div class="sidebar-logo">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="M9 12l2 2 4-4"/>
            </svg>
            <h1>RCE HawkEye</h1>
        </div>
        
        <nav>
            <ul class="sidebar-nav">
                <li>
                    <a href="#" class="active" onclick="showSection('dashboard', event)">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                        <span data-i18n="nav.dashboard">Dashboard</span>
                    </a>
                </li>
                <li>
                    <a href="#" onclick="showSection('scanner', event)">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                        <span data-i18n="nav.scanner">Scanner</span>
                    </a>
                </li>
                <li>
                    <a href="#" onclick="showSection('exploit', event)">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
                        <span data-i18n="nav.exploit">Exploit</span>
                    </a>
                </li>
                <li>
                    <a href="#" onclick="showSection('monitoring', event)">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                        <span data-i18n="nav.monitoring">Monitoring</span>
                    </a>
                </li>
                <li>
                    <a href="#" onclick="showSection('reports', event)">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                        <span data-i18n="nav.reports">Reports</span>
                    </a>
                </li>
                <li>
                    <a href="#" onclick="showSection('history', event)">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                        <span data-i18n="nav.history">History</span>
                    </a>
                </li>
                <li>
                    <a href="#" onclick="showSection('settings', event)">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                        <span data-i18n="nav.settings">Settings</span>
                    </a>
                </li>
            </ul>
        </nav>
    </aside>
    
    <main class="main-content">
        <div class="top-bar">
            <div class="page-title">
                <h2 data-i18n="nav.dashboard">Dashboard</h2>
            </div>
            <div class="user-menu">
                <select id="langSelector" onchange="changeLanguage(this.value)">
                    <option value="zh">中文</option>
                    <option value="en">English</option>
                </select>
                <div class="alert-icon" onclick="openAlertModal()">
                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
                    <span class="alert-badge" id="alertBadge" style="display: none;">0</span>
                </div>
                <div class="user-avatar" onclick="toggleUserMenu()">A</div>
                <div id="userDropdown" class="user-dropdown">
                    <div class="user-info">
                        <div class="user-name">admin</div>
                        <div class="user-role" data-i18n="settings.admin">Administrator</div>
                    </div>
                    <a href="#" onclick="logout()" class="logout-link" data-i18n="common.logout">Logout</a>
                </div>
            </div>
        </div>
        
        <section id="dashboardSection">
            <div class="stats-grid">
                <div class="stat-card glass-card">
                    <div class="stat-card-header">
                        <div class="stat-card-icon green">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                        </div>
                        <div class="stat-card-info">
                            <span class="stat-card-label" data-i18n="stats.totalScans">Total Scans</span>
                            <span class="stat-card-value" id="totalScans">0</span>
                        </div>
                    </div>
                    <div class="stat-card-trend up">
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>
                        <span>+12% this week</span>
                    </div>
                </div>
                
                <div class="stat-card glass-card">
                    <div class="stat-card-header">
                        <div class="stat-card-icon red">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        </div>
                        <div class="stat-card-info">
                            <span class="stat-card-label" data-i18n="stats.criticalVulns">Critical</span>
                            <span class="stat-card-value" id="criticalVulns">0</span>
                        </div>
                    </div>
                    <div class="stat-card-trend down">
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 18 13.5 8.5 8.5 13.5 1 6"/><polyline points="17 18 23 18 23 12"/></svg>
                        <span>-5% this week</span>
                    </div>
                </div>
                
                <div class="stat-card glass-card">
                    <div class="stat-card-header">
                        <div class="stat-card-icon yellow">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                        </div>
                        <div class="stat-card-info">
                            <span class="stat-card-label" data-i18n="stats.highVulns">High Risk</span>
                            <span class="stat-card-value" id="highVulns">0</span>
                        </div>
                    </div>
                    <div class="stat-card-trend up">
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>
                        <span>+3% this week</span>
                    </div>
                </div>
                
                <div class="stat-card glass-card">
                    <div class="stat-card-header">
                        <div class="stat-card-icon cyan">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg>
                        </div>
                        <div class="stat-card-info">
                            <span class="stat-card-label" data-i18n="stats.targetsScanned">Targets</span>
                            <span class="stat-card-value" id="targetsScanned">0</span>
                        </div>
                    </div>
                    <div class="stat-card-trend up">
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>
                        <span>+8% this week</span>
                    </div>
                </div>
            </div>
            
            <div class="dashboard-grid">
                <div class="dashboard-main">
                    <div class="card glass-card">
                        <div class="card-header">
                            <h3 data-i18n="dashboard.vulnDistribution">Vulnerability Distribution</h3>
                        </div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="vulnChart"></canvas>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card glass-card">
                        <div class="card-header">
                            <h3 data-i18n="dashboard.recentActivity">Recent Activity</h3>
                        </div>
                        <div class="card-body">
                            <div class="activity-list" id="activityList">
                                <div class="activity-item">
                                    <div class="activity-icon green">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    </div>
                                    <div class="activity-content">
                                        <span class="activity-title">Scan completed</span>
                                        <span class="activity-desc">http://example.com - 2 vulnerabilities found</span>
                                    </div>
                                    <span class="activity-time">2 min ago</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="dashboard-sidebar">
                    <div class="card glass-card">
                        <div class="card-header">
                            <h3 data-i18n="dashboard.systemStatus">System Status</h3>
                            <span class="status-badge online">Online</span>
                        </div>
                        <div class="card-body">
                            <div class="status-list">
                                <div class="status-item">
                                    <span class="status-label" data-i18n="monitoring.cpuUsage">CPU</span>
                                    <div class="status-bar-container">
                                        <div class="status-bar purple" id="cpuBar" style="width: 0%"></div>
                                    </div>
                                    <span class="status-value" id="statusCpu">0%</span>
                                </div>
                                <div class="status-item">
                                    <span class="status-label" data-i18n="monitoring.memoryUsage">Memory</span>
                                    <div class="status-bar-container">
                                        <div class="status-bar" id="memoryBar" style="width: 45%"></div>
                                    </div>
                                    <span class="status-value" id="statusMemory">45 MB</span>
                                </div>
                                <div class="status-item">
                                    <span class="status-label" data-i18n="monitoring.goroutines">Goroutines</span>
                                    <div class="status-bar-container">
                                        <div class="status-bar cyan" id="goroutineBar" style="width: 30%"></div>
                                    </div>
                                    <span class="status-value" id="statusGoroutines">15</span>
                                </div>
                                <div class="status-item">
                                    <span class="status-label" data-i18n="monitoring.heapAlloc">Heap</span>
                                    <div class="status-bar-container">
                                        <div class="status-bar yellow" id="heapBar" style="width: 20%"></div>
                                    </div>
                                    <span class="status-value" id="statusHeap">0 MB</span>
                                </div>
                                <div class="status-item">
                                    <span class="status-label" data-i18n="monitoring.cpuCores">CPU Cores</span>
                                    <span class="status-value" id="statusCpuCores">8</span>
                                </div>
                                <div class="status-item">
                                    <span class="status-label" data-i18n="monitoring.goVersion">Go Version</span>
                                    <span class="status-value" id="statusGoVersion">1.21</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card glass-card">
                        <div class="card-header">
                            <h3 data-i18n="dashboard.quickActions">Quick Actions</h3>
                        </div>
                        <div class="card-body">
                            <div class="quick-actions">
                                <a href="#" class="quick-action-btn" onclick="showSection('scanner', event)">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                                    <span data-i18n="scan.newScan">New Scan</span>
                                </a>
                                <a href="#" class="quick-action-btn" onclick="showSection('reports', event)">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                                    <span data-i18n="reports.export">Export Report</span>
                                </a>
                                <a href="#" class="quick-action-btn" onclick="showSection('settings', event)">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                                    <span data-i18n="nav.settings">Settings</span>
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        
        <section id="scannerSection" style="display: none;">
            <div class="scanner-layout">
                <div class="scan-config-panel glass-card">
                    <div class="panel-header">
                        <h2 class="panel-title" data-i18n="scan.newScan">New Scan</h2>
                        <span class="version-badge">v1.1.1</span>
                    </div>
                    
                    <div class="config-tabs">
                        <button class="config-tab active" onclick="showConfigTab('basic', event)">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                            <span data-i18n="config.basic">Basic</span>
                        </button>
                        <button class="config-tab" onclick="showConfigTab('target', event)">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                            <span data-i18n="config.target">Target</span>
                        </button>
                        <button class="config-tab" onclick="showConfigTab('http', event)">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/></svg>
                            <span data-i18n="config.http">HTTP</span>
                        </button>
                        <button class="config-tab" onclick="showConfigTab('payloads', event)">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
                            <span data-i18n="config.payloads">Payloads</span>
                        </button>
                        <button class="config-tab" onclick="showConfigTab('encoder', event)">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                            <span data-i18n="config.encoder">Encoder</span>
                        </button>
                        <button class="config-tab" onclick="showConfigTab('advanced', event)">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
                            <span data-i18n="config.advanced">Advanced</span>
                        </button>
                    </div>
                    
                    <div class="config-content">
                        <div id="config-basic" class="config-panel active">
                            <div class="form-group">
                                <label data-i18n="scan.targetUrl">Target URL</label>
                                <input type="text" id="targetUrl" class="input-field" placeholder="http://example.com">
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label data-i18n="scan.scanLevel">Scan Level</label>
                                    <select id="scanLevel" class="input-field">
                                        <option value="1">1 - Quick</option>
                                        <option value="2" selected>2 - Normal</option>
                                        <option value="3">3 - Deep</option>
                                        <option value="4">4 - Full</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label data-i18n="scan.scanMode">Scan Mode</label>
                                    <select id="scanMode" class="input-field">
                                        <option value="echo">Echo Based</option>
                                        <option value="harmless">Harmless (Time-based)</option>
                                        <option value="waf_bypass">WAF Bypass</option>
                                    </select>
                                </div>
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label data-i18n="scan.concurrent">Concurrent</label>
                                    <input type="number" id="concurrent" class="input-field" value="10" min="1" max="100">
                                </div>
                                <div class="form-group">
                                    <label data-i18n="scan.timeout">Timeout (s)</label>
                                    <input type="number" id="timeout" class="input-field" value="10" min="1" max="120">
                                </div>
                            </div>
                            <div class="form-group">
                                <label data-i18n="scan.scanOptions">Scan Options</label>
                                <div class="checkbox-grid">
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="optCrawl">
                                        <span data-i18n="option.crawl">Crawler</span>
                                    </label>
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="optDirScan" checked>
                                        <span data-i18n="option.dirScan">Dir Scan</span>
                                    </label>
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="optParamFuzz" checked>
                                        <span data-i18n="option.paramFuzz">Param Fuzz</span>
                                    </label>
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="optSmartDict" checked>
                                        <span data-i18n="option.smartDict">Smart Dict</span>
                                    </label>
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="optIncludeResponse">
                                        <span data-i18n="option.includeResponse">Include Response</span>
                                    </label>
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="optVerifySSL">
                                        <span data-i18n="option.verifySSL">Verify SSL</span>
                                    </label>
                                </div>
                            </div>
                        </div>
                        
                        <div id="config-target" class="config-panel">
                            <div class="form-group">
                                <label data-i18n="target.urlFile">URL File (one per line)</label>
                                <textarea id="urlFile" class="input-field textarea" rows="6" placeholder="http://example1.com&#10;http://example2.com&#10;http://example3.com"></textarea>
                            </div>
                            <div class="form-group">
                                <label data-i18n="target.rawTraffic">Raw Traffic File</label>
                                <input type="text" id="rawTraffic" class="input-field" placeholder="/path/to/traffic.txt">
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label data-i18n="target.allowDomains">Allow Domains</label>
                                    <input type="text" id="allowDomains" class="input-field" placeholder="example.com,api.example.com">
                                </div>
                                <div class="form-group">
                                    <label data-i18n="target.blockDomains">Block Domains</label>
                                    <input type="text" id="blockDomains" class="input-field" placeholder="static.example.com">
                                </div>
                            </div>
                            <div class="form-group">
                                <label class="checkbox-label">
                                    <input type="checkbox" id="optRestrictRoot" checked>
                                    <span data-i18n="target.restrictRoot">Restrict to Root Domain</span>
                                </label>
                            </div>
                        </div>
                        
                        <div id="config-http" class="config-panel">
                            <div class="form-row">
                                <div class="form-group">
                                    <label data-i18n="http.method">Method</label>
                                    <select id="httpMethod" class="input-field">
                                        <option value="GET">GET</option>
                                        <option value="POST">POST</option>
                                        <option value="PUT">PUT</option>
                                        <option value="DELETE">DELETE</option>
                                        <option value="OPTIONS">OPTIONS</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label data-i18n="http.delayThreshold">Delay Threshold (s)</label>
                                    <input type="number" id="delayThreshold" class="input-field" value="4" step="0.5">
                                </div>
                            </div>
                            <div class="form-group">
                                <label data-i18n="http.postData">POST Data</label>
                                <input type="text" id="httpPostData" class="input-field" placeholder="key1=value1&amp;key2=value2">
                            </div>
                            <div class="form-group">
                                <label data-i18n="http.headers">Custom Headers</label>
                                <textarea id="httpHeaders" class="input-field textarea" rows="4" placeholder="Authorization: Bearer token&#10;X-Custom-Header: value"></textarea>
                            </div>
                            <div class="form-group">
                                <label data-i18n="http.userAgent">User-Agent</label>
                                <select id="userAgentSelect" class="input-field" onchange="setUserAgent(this.value)">
                                    <option value="default">RCE-HawkEye/1.1.1</option>
                                    <option value="chrome">Chrome</option>
                                    <option value="firefox">Firefox</option>
                                    <option value="safari">Safari</option>
                                    <option value="curl">curl</option>
                                    <option value="custom">Custom</option>
                                </select>
                                <input type="text" id="httpUserAgent" class="input-field" value="RCE-HawkEye/1.1.1" style="margin-top: 8px;">
                            </div>
                            <div class="form-group">
                                <label data-i18n="http.proxy">Proxy</label>
                                <div class="proxy-config">
                                    <div class="form-row">
                                        <div class="form-group">
                                            <label data-i18n="proxy.type">Proxy Type</label>
                                            <select id="proxyType" class="input-field">
                                                <option value="">None</option>
                                                <option value="http">HTTP</option>
                                                <option value="https">HTTPS</option>
                                                <option value="socks5">SOCKS5</option>
                                            </select>
                                        </div>
                                        <div class="form-group">
                                            <label data-i18n="proxy.address">Address</label>
                                            <input type="text" id="proxyAddress" class="input-field" placeholder="127.0.0.1:8080">
                                        </div>
                                    </div>
                                    <div class="form-row">
                                        <div class="form-group">
                                            <label data-i18n="proxy.username">Username (optional)</label>
                                            <input type="text" id="proxyUsername" class="input-field" placeholder="">
                                        </div>
                                        <div class="form-group">
                                            <label data-i18n="proxy.password">Password (optional)</label>
                                            <input type="password" id="proxyPassword" class="input-field" placeholder="">
                                        </div>
                                    </div>
                                    <button type="button" class="btn-secondary" onclick="testProxy()" style="margin-top: 8px;">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                                        <span data-i18n="proxy.test">Test Connection</span>
                                    </button>
                                    <span id="proxyTestResult" style="margin-left: 10px;"></span>
                                </div>
                            </div>
                            <div class="form-group">
                                <label data-i18n="http.sslOptions">SSL/TLS Options</label>
                                <div class="checkbox-grid">
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="optPreferHTTPS" checked>
                                        <span data-i18n="option.preferHTTPS">Prefer HTTPS</span>
                                    </label>
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="optNoHTTPS">
                                        <span data-i18n="option.noHTTPS">Disable HTTPS</span>
                                    </label>
                                </div>
                            </div>
                        </div>
                        
                        <div id="config-payloads" class="config-panel">
                            <div class="form-group">
                                <label data-i18n="payload.targetOS">Target OS</label>
                                <select id="targetOS" class="input-field">
                                    <option value="both">Auto Detect</option>
                                    <option value="unix">Unix/Linux</option>
                                    <option value="windows">Windows</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label data-i18n="payload.techStack">Tech Stack</label>
                                <div class="tech-stack-grid">
                                    <label class="checkbox-label"><input type="checkbox" name="techStack" value="php" checked> PHP</label>
                                    <label class="checkbox-label"><input type="checkbox" name="techStack" value="jsp" checked> JSP/Java</label>
                                    <label class="checkbox-label"><input type="checkbox" name="techStack" value="asp" checked> ASP</label>
                                    <label class="checkbox-label"><input type="checkbox" name="techStack" value="aspx" checked> ASPX/.NET</label>
                                    <label class="checkbox-label"><input type="checkbox" name="techStack" value="python" checked> Python</label>
                                    <label class="checkbox-label"><input type="checkbox" name="techStack" value="nodejs" checked> Node.js</label>
                                    <label class="checkbox-label"><input type="checkbox" name="techStack" value="ruby"> Ruby</label>
                                    <label class="checkbox-label"><input type="checkbox" name="techStack" value="go"> Go</label>
                                    <label class="checkbox-label"><input type="checkbox" name="techStack" value="perl"> Perl</label>
                                    <label class="checkbox-label"><input type="checkbox" name="techStack" value="lua"> Lua</label>
                                    <label class="checkbox-label"><input type="checkbox" name="techStack" value="template" checked> SSTI</label>
                                    <label class="checkbox-label"><input type="checkbox" name="techStack" value="coldfusion"> ColdFusion</label>
                                </div>
                            </div>
                            <div class="form-group">
                                <label data-i18n="payload.types">Payload Types</label>
                                <div class="checkbox-grid">
                                    <label class="checkbox-label"><input type="checkbox" name="payloadType" value="echo" checked> Echo Based</label>
                                    <label class="checkbox-label"><input type="checkbox" name="payloadType" value="time" checked> Time Based</label>
                                    <label class="checkbox-label"><input type="checkbox" name="payloadType" value="code" checked> Code Exec</label>
                                    <label class="checkbox-label"><input type="checkbox" name="payloadType" value="dns"> DNS Exfil</label>
                                </div>
                            </div>
                            <div class="form-group">
                                <label data-i18n="payload.custom">Custom Payloads</label>
                                <textarea id="customPayloads" class="input-field textarea" rows="4" placeholder="Enter custom payloads, one per line"></textarea>
                            </div>
                            <div class="form-group">
                                <label data-i18n="payload.wordlist">Custom Wordlist</label>
                                <input type="text" id="customWordlist" class="input-field" placeholder="/path/to/wordlist.txt">
                            </div>
                        </div>
                        
                        <div id="config-encoder" class="config-panel">
                            <div class="form-group">
                                <label data-i18n="encoder.encoding">Encoding Options</label>
                                <div class="checkbox-grid">
                                    <label class="checkbox-label"><input type="checkbox" name="encoding" value="url" checked> URL Encode</label>
                                    <label class="checkbox-label"><input type="checkbox" name="encoding" value="double_url"> Double URL</label>
                                    <label class="checkbox-label"><input type="checkbox" name="encoding" value="base64"> Base64</label>
                                    <label class="checkbox-label"><input type="checkbox" name="encoding" value="hex"> Hex</label>
                                    <label class="checkbox-label"><input type="checkbox" name="encoding" value="unicode"> Unicode</label>
                                    <label class="checkbox-label"><input type="checkbox" name="encoding" value="html"> HTML Entity</label>
                                    <label class="checkbox-label"><input type="checkbox" name="encoding" value="octal"> Octal</label>
                                    <label class="checkbox-label"><input type="checkbox" name="encoding" value="json"> JSON Escape</label>
                                </div>
                            </div>
                            <div class="form-group">
                                <label data-i18n="encoder.bypass">WAF Bypass Techniques</label>
                                <div class="checkbox-grid">
                                    <label class="checkbox-label"><input type="checkbox" name="bypass" value="case"> Case Variation</label>
                                    <label class="checkbox-label"><input type="checkbox" name="bypass" value="comment"> Comment Injection</label>
                                    <label class="checkbox-label"><input type="checkbox" name="bypass" value="nullbyte"> Null Byte</label>
                                    <label class="checkbox-label"><input type="checkbox" name="bypass" value="double_write"> Double Write</label>
                                    <label class="checkbox-label"><input type="checkbox" name="bypass" value="chunked"> Chunked Encoding</label>
                                    <label class="checkbox-label"><input type="checkbox" name="bypass" value="hpp"> HTTP Param Pollution</label>
                                </div>
                            </div>
                            <div class="form-group">
                                <label data-i18n="encoder.tool">Encoding Tool</label>
                                <div class="encoder-tool">
                                    <textarea id="encoderInput" class="input-field textarea" rows="3" placeholder="Enter text to encode/decode"></textarea>
                                    <div class="encoder-actions">
                                        <button type="button" class="btn-small" onclick="encodeText('url')">URL Encode</button>
                                        <button type="button" class="btn-small" onclick="encodeText('base64')">Base64</button>
                                        <button type="button" class="btn-small" onclick="encodeText('hex')">Hex</button>
                                        <button type="button" class="btn-small" onclick="encodeText('unicode')">Unicode</button>
                                        <button type="button" class="btn-small" onclick="decodeText('url')">URL Decode</button>
                                        <button type="button" class="btn-small" onclick="decodeText('base64')">Base64 Decode</button>
                                    </div>
                                    <textarea id="encoderOutput" class="input-field textarea" rows="3" placeholder="Output" readonly></textarea>
                                </div>
                            </div>
                        </div>
                        
                        <div id="config-advanced" class="config-panel">
                            <div class="form-group">
                                <label data-i18n="advanced.crawler">Crawler Settings</label>
                                <div class="form-row">
                                    <div class="form-group">
                                        <label data-i18n="crawler.depth">Crawl Depth</label>
                                        <input type="number" id="crawlDepth" class="input-field" value="2" min="1" max="10">
                                    </div>
                                    <div class="form-group">
                                        <label data-i18n="crawler.maxPages">Max Pages</label>
                                        <input type="number" id="crawlPages" class="input-field" value="100" min="1" max="1000">
                                    </div>
                                </div>
                            </div>
                            <div class="form-group">
                                <label data-i18n="advanced.dirscan">Directory Scan Settings</label>
                                <div class="form-row">
                                    <div class="form-group">
                                        <label data-i18n="dirscan.threads">Threads</label>
                                        <input type="number" id="dirThreads" class="input-field" value="10" min="1" max="100">
                                    </div>
                                    <div class="form-group">
                                        <label data-i18n="dirscan.filterStatus">Status Filter</label>
                                        <input type="text" id="dirFilterStatus" class="input-field" value="200" placeholder="200,301,302">
                                    </div>
                                </div>
                                <div class="form-row">
                                    <div class="form-group">
                                        <label data-i18n="dirscan.filterExt">Extension Filter</label>
                                        <input type="text" id="dirFilterExt" class="input-field" placeholder="php,asp,!jpg,!png">
                                    </div>
                                    <div class="form-group">
                                        <label data-i18n="dirscan.filterPattern">Pattern Filter</label>
                                        <input type="text" id="dirFilterPattern" class="input-field" placeholder="admin*,*config*">
                                    </div>
                                </div>
                                <div class="form-row">
                                    <div class="form-group">
                                        <label data-i18n="dirscan.wordlist">Custom Wordlist</label>
                                        <input type="text" id="dirWordlist" class="input-field" placeholder="/path/to/wordlist.txt">
                                    </div>
                                    <div class="form-group">
                                        <label data-i18n="dirscan.archiveThreshold">Archive Threshold</label>
                                        <input type="number" id="archiveThreshold" class="input-field" value="30" min="1" max="100">
                                    </div>
                                </div>
                            </div>
                            <div class="form-group">
                                <label data-i18n="advanced.output">Output Settings</label>
                                <div class="form-row">
                                    <div class="form-group">
                                        <label data-i18n="output.format">Format</label>
                                        <select id="outputFormat" class="input-field">
                                            <option value="html">HTML</option>
                                            <option value="json">JSON</option>
                                            <option value="md">Markdown</option>
                                            <option value="txt">Plain Text</option>
                                            <option value="all">All Formats</option>
                                        </select>
                                    </div>
                                    <div class="form-group">
                                        <label data-i18n="output.dir">Output Directory</label>
                                        <input type="text" id="outputDir" class="input-field" value="./reports">
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div id="progressSection" class="progress-section" style="display: none;">
                        <div class="progress-header">
                            <span data-i18n="progress.scanning">Scanning...</span>
                            <span id="progressPercent">0%</span>
                        </div>
                        <div class="progress-bar-container">
                            <div class="progress-bar" id="progressBar" style="width: 0%"></div>
                        </div>
                        <div class="progress-status" id="progressStatus">Initializing...</div>
                    </div>
                    
                    <div class="action-bar">
                        <button class="btn-secondary" onclick="resetForm()">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
                            <span data-i18n="common.reset">Reset</span>
                        </button>
                        <button class="btn-primary" onclick="startScan()" id="startScanBtn">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                            <span data-i18n="scan.startScan">Start Scan</span>
                        </button>
                    </div>
                </div>
                
                <div class="scan-results-panel glass-card">
                    <div class="panel-header">
                        <h2 class="panel-title" data-i18n="results.title">Scan Results</h2>
                        <div class="results-tabs">
                            <button class="results-tab active" data-filter="all">All</button>
                            <button class="results-tab" data-filter="critical">Critical</button>
                            <button class="results-tab" data-filter="high">High</button>
                        </div>
                    </div>
                    <div class="vulnerability-list" id="vulnerabilityList">
                        <div class="empty-state">
                            <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                            <p data-i18n="results.noResults">No scan results yet</p>
                            <p class="sub-text" data-i18n="results.startScan">Start a new scan to detect vulnerabilities</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        
        <section id="exploitSection" style="display: none;">
            <div class="exploit-container">
                <div class="exploit-sidebar glass-card">
                    <div class="exploit-sidebar-header">
                        <h3 data-i18n="exploit.vulnList">Vulnerability List</h3>
                        <button class="btn-small" onclick="refreshVulnList()">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/></svg>
                        </button>
                    </div>
                    <div class="vuln-filter">
                        <select id="vulnFilterSeverity" class="input-field" onchange="filterVulnList()">
                            <option value="all" data-i18n="results.all">All</option>
                            <option value="critical" data-i18n="vuln.critical">Critical</option>
                            <option value="high" data-i18n="vuln.high">High</option>
                            <option value="medium" data-i18n="vuln.medium">Medium</option>
                        </select>
                    </div>
                    <div class="vuln-select-list" id="vulnSelectList">
                        <div class="empty-state">
                            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                            <p data-i18n="exploit.noVulns">No vulnerabilities found</p>
                        </div>
                    </div>
                </div>
                
                <div class="exploit-main">
                    <div class="exploit-tabs">
                        <button class="exploit-tab active" onclick="showExploitTab('cmd', event)" data-i18n="exploit.cmdExec">Command Execution</button>
                        <button class="exploit-tab" onclick="showExploitTab('shell', event)" data-i18n="exploit.reverseShell">Reverse Shell</button>
                        <button class="exploit-tab" onclick="showExploitTab('webshell', event)" data-i18n="exploit.webshell">Webshell</button>
                        <button class="exploit-tab" onclick="showExploitTab('logs', event)" data-i18n="exploit.logs">Logs</button>
                    </div>
                    
                    <div id="exploit-cmd" class="exploit-panel active">
                        <div class="cmd-container glass-card">
                            <div class="cmd-header">
                                <div class="cmd-target-info">
                                    <span class="cmd-label" data-i18n="exploit.target">Target:</span>
                                    <span class="cmd-target-url" id="cmdTargetUrl">-</span>
                                </div>
                                <div class="cmd-os-info">
                                    <span class="cmd-label" data-i18n="exploit.os">OS:</span>
                                    <select id="targetOSType" class="input-field-small" onchange="updateCmdHistory()">
                                        <option value="auto">Auto Detect</option>
                                        <option value="linux">Linux</option>
                                        <option value="windows">Windows</option>
                                    </select>
                                </div>
                            </div>
                            
                            <div class="cmd-output" id="cmdOutput">
                                <div class="cmd-welcome">
                                    <span data-i18n="exploit.selectVuln">Select a vulnerability to start...</span>
                                </div>
                            </div>
                            
                            <div class="cmd-input-area">
                                <div class="cmd-quick-actions">
                                    <button class="cmd-quick-btn" onclick="insertQuickCmd('whoami')">whoami</button>
                                    <button class="cmd-quick-btn" onclick="insertQuickCmd('id')">id</button>
                                    <button class="cmd-quick-btn" onclick="insertQuickCmd('pwd')">pwd</button>
                                    <button class="cmd-quick-btn" onclick="insertQuickCmd('ls -la')">ls -la</button>
                                    <button class="cmd-quick-btn" onclick="insertQuickCmd('uname -a')">uname -a</button>
                                    <button class="cmd-quick-btn" onclick="insertQuickCmd('cat /etc/passwd')">cat /etc/passwd</button>
                                    <button class="cmd-quick-btn" onclick="insertQuickCmd('netstat -an')">netstat -an</button>
                                    <button class="cmd-quick-btn" onclick="insertQuickCmd('ifconfig')">ifconfig</button>
                                </div>
                                <div class="cmd-input-row">
                                    <span class="cmd-prompt">$</span>
                                    <textarea id="cmdInput" class="cmd-input" placeholder="Enter command..." rows="1" onkeydown="handleCmdKeydown(event)"></textarea>
                                    <button class="btn-primary" onclick="executeCommand()">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div id="exploit-shell" class="exploit-panel">
                        <div class="shell-config glass-card">
                            <div class="shell-config-header">
                                <h3 data-i18n="exploit.reverseShellGen">Reverse Shell Generator</h3>
                            </div>
                            <div class="shell-config-body">
                                <div class="form-row">
                                    <div class="form-group">
                                        <label data-i18n="shell.listenIP">Listen IP</label>
                                        <input type="text" id="shellListenIP" class="input-field" placeholder="0.0.0.0">
                                        <button class="btn-small" onclick="getLocalIP()" data-i18n="shell.autoDetect">Auto Detect</button>
                                    </div>
                                    <div class="form-group">
                                        <label data-i18n="shell.listenPort">Listen Port</label>
                                        <input type="number" id="shellListenPort" class="input-field" value="4444">
                                        <div class="port-quick-select">
                                            <button onclick="setPort(4444)">4444</button>
                                            <button onclick="setPort(5555)">5555</button>
                                            <button onclick="setPort(6666)">6666</button>
                                            <button onclick="setPort(7777)">7777</button>
                                            <button onclick="setPort(8888)">8888</button>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="form-group">
                                    <label data-i18n="shell.shellType">Shell Type</label>
                                    <div class="shell-type-grid">
                                        <label class="shell-type-option">
                                            <input type="radio" name="shellType" value="bash" checked onchange="generateReverseShell()">
                                            <span>Bash</span>
                                        </label>
                                        <label class="shell-type-option">
                                            <input type="radio" name="shellType" value="python" onchange="generateReverseShell()">
                                            <span>Python</span>
                                        </label>
                                        <label class="shell-type-option">
                                            <input type="radio" name="shellType" value="perl" onchange="generateReverseShell()">
                                            <span>Perl</span>
                                        </label>
                                        <label class="shell-type-option">
                                            <input type="radio" name="shellType" value="php" onchange="generateReverseShell()">
                                            <span>PHP</span>
                                        </label>
                                        <label class="shell-type-option">
                                            <input type="radio" name="shellType" value="nc" onchange="generateReverseShell()">
                                            <span>Netcat</span>
                                        </label>
                                        <label class="shell-type-option">
                                            <input type="radio" name="shellType" value="powershell" onchange="generateReverseShell()">
                                            <span>PowerShell</span>
                                        </label>
                                        <label class="shell-type-option">
                                            <input type="radio" name="shellType" value="cmd" onchange="generateReverseShell()">
                                            <span>CMD</span>
                                        </label>
                                        <label class="shell-type-option">
                                            <input type="radio" name="shellType" value="java" onchange="generateReverseShell()">
                                            <span>Java</span>
                                        </label>
                                    </div>
                                </div>
                                
                                <div class="form-group">
                                    <label data-i18n="shell.targetOS">Target OS</label>
                                    <select id="shellTargetOS" class="input-field" onchange="generateReverseShell()">
                                        <option value="linux">Linux</option>
                                        <option value="windows">Windows</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        
                        <div class="shell-output glass-card">
                            <div class="shell-output-header">
                                <h3 data-i18n="shell.generatedCmd">Generated Command</h3>
                                <button class="btn-secondary" onclick="copyShellCommand()">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                                    <span data-i18n="common.copy">Copy</span>
                                </button>
                            </div>
                            <div class="shell-command-display">
                                <pre id="shellCommandOutput">Select options to generate reverse shell command...</pre>
                            </div>
                            
                            <div class="shell-listen-section">
                                <h4 data-i18n="shell.listenCmd">Listen Command</h4>
                                <div class="listen-cmd-row">
                                    <code id="listenCommand">nc -lvnp 4444</code>
                                    <button class="btn-small" onclick="copyListenCommand()">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div id="exploit-webshell" class="exploit-panel">
                        <div class="webshell-config glass-card">
                            <div class="webshell-config-header">
                                <h3 data-i18n="webshell.generator">Webshell Generator</h3>
                            </div>
                            <div class="webshell-config-body">
                                <div class="form-group">
                                    <label data-i18n="webshell.targetLang">Target Language</label>
                                    <select id="webshellLang" class="input-field" onchange="updateWebshellPreview()">
                                        <option value="php">PHP</option>
                                        <option value="asp">ASP</option>
                                        <option value="aspx">ASPX (.NET)</option>
                                        <option value="jsp">JSP</option>
                                    </select>
                                </div>
                                
                                <div class="form-group">
                                    <label data-i18n="webshell.password">Password</label>
                                    <div class="password-input-row">
                                        <input type="text" id="webshellPassword" class="input-field" value="pass" oninput="updateWebshellPreview(); checkPasswordStrength()">
                                        <div class="password-strength" id="passwordStrength">
                                            <div class="strength-bar"></div>
                                            <span class="strength-text">Weak</span>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="form-group">
                                    <label data-i18n="webshell.type">Shell Type</label>
                                    <div class="webshell-type-grid">
                                        <label class="webshell-type-option">
                                            <input type="radio" name="webshellType" value="simple" checked onchange="updateWebshellPreview()">
                                            <span data-i18n="webshell.simple">Simple</span>
                                        </label>
                                        <label class="webshell-type-option">
                                            <input type="radio" name="webshellType" value="bypass" onchange="updateWebshellPreview()">
                                            <span data-i18n="webshell.bypass">WAF Bypass</span>
                                        </label>
                                        <label class="webshell-type-option">
                                            <input type="radio" name="webshellType" value="custom" onchange="updateWebshellPreview()">
                                            <span data-i18n="webshell.custom">Custom</span>
                                        </label>
                                    </div>
                                </div>
                                
                                <div class="form-group" id="customWebshellGroup" style="display: none;">
                                    <label data-i18n="webshell.customCode">Custom Code</label>
                                    <textarea id="customWebshellCode" class="input-field textarea code-textarea" rows="6" placeholder="Enter custom webshell code..." oninput="updateWebshellPreview()"></textarea>
                                </div>
                            </div>
                        </div>
                        
                        <div class="webshell-preview glass-card">
                            <div class="webshell-preview-header">
                                <h3 data-i18n="webshell.preview">Preview</h3>
                                <div class="webshell-actions">
                                    <button class="btn-secondary" onclick="copyWebshell()">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                                        <span data-i18n="common.copy">Copy</span>
                                    </button>
                                    <button class="btn-warning" onclick="writeWebshell()">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                                        <span data-i18n="webshell.write">Write to Target</span>
                                    </button>
                                </div>
                            </div>
                            <div class="webshell-code-display">
                                <pre id="webshellCodeOutput">Select options to generate webshell...</pre>
                            </div>
                            
                            <div class="webshell-write-config" id="webshellWriteConfig" style="display: none;">
                                <h4 data-i18n="webshell.writePath">Write Path</h4>
                                <div class="form-row">
                                    <div class="form-group">
                                        <input type="text" id="webshellWritePath" class="input-field" placeholder="/var/www/html/shell.php">
                                    </div>
                                    <div class="form-group">
                                        <input type="text" id="webshellFilename" class="input-field" placeholder="shell.php" value="shell.php">
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div id="exploit-logs" class="exploit-panel">
                        <div class="logs-container glass-card">
                            <div class="logs-header">
                                <h3 data-i18n="exploit.operationLogs">Operation Logs</h3>
                                <div class="logs-actions">
                                    <button class="btn-secondary" onclick="exportLogs()">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                                        <span data-i18n="logs.export">Export</span>
                                    </button>
                                    <button class="btn-warning" onclick="clearLogs()">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                                        <span data-i18n="common.clear">Clear</span>
                                    </button>
                                </div>
                            </div>
                            <div class="logs-filter">
                                <select id="logTypeFilter" class="input-field" onchange="filterLogs()">
                                    <option value="all" data-i18n="logs.all">All Types</option>
                                    <option value="cmd" data-i18n="logs.cmd">Commands</option>
                                    <option value="shell" data-i18n="logs.shell">Reverse Shell</option>
                                    <option value="webshell" data-i18n="logs.webshell">Webshell</option>
                                </select>
                            </div>
                            <div class="logs-list" id="logsList">
                                <div class="empty-state">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                                    <p data-i18n="logs.noLogs">No operation logs</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        
        <section id="monitoringSection" style="display: none;">
            <div class="monitoring-header">
                <div class="monitoring-title">
                    <h2 data-i18n="nav.monitoring">Performance Monitoring</h2>
                    <span class="realtime-badge" data-i18n="monitoring.realtime">Real-time</span>
                </div>
                <div class="monitoring-controls">
                    <div class="view-toggle">
                        <button class="view-toggle-btn active" onclick="setChartView('trend', event)" data-i18n="monitoring.trendView">Trend</button>
                        <button class="view-toggle-btn" onclick="setChartView('gauge', event)" data-i18n="monitoring.gaugeView">Gauge</button>
                    </div>
                    <div class="time-range-selector">
                        <button class="time-range-btn active" onclick="setTimeRange('realtime', event)">Realtime</button>
                        <button class="time-range-btn" onclick="setTimeRange('hour', event)">1H</button>
                        <button class="time-range-btn" onclick="setTimeRange('today', event)">Today</button>
                    </div>
                </div>
            </div>
            
            <div class="monitoring-stats">
                <div class="monitor-stat glass-card">
                    <div class="monitor-stat-icon green">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>
                    </div>
                    <div class="monitor-stat-value" id="monitorCpuUsage">0%</div>
                    <div class="monitor-stat-label" data-i18n="monitoring.cpuUsage">CPU Usage</div>
                    <div class="monitor-stat-bar">
                        <div class="bar-fill green" id="cpuBar" style="width: 0%"></div>
                    </div>
                </div>
                <div class="monitor-stat glass-card">
                    <div class="monitor-stat-icon cyan">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                    </div>
                    <div class="monitor-stat-value" id="monitorMemory">0 MB</div>
                    <div class="monitor-stat-label" data-i18n="monitoring.memoryUsage">Memory</div>
                    <div class="monitor-stat-bar">
                        <div class="bar-fill cyan" id="memoryBar" style="width: 0%"></div>
                    </div>
                </div>
                <div class="monitor-stat glass-card">
                    <div class="monitor-stat-icon yellow">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                    </div>
                    <div class="monitor-stat-value" id="monitorGoroutines">0</div>
                    <div class="monitor-stat-label" data-i18n="monitoring.goroutines">Goroutines</div>
                </div>
                <div class="monitor-stat glass-card">
                    <div class="monitor-stat-icon purple">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                    </div>
                    <div class="monitor-stat-value" id="monitorNetworkIO">0 KB/s</div>
                    <div class="monitor-stat-label" data-i18n="monitoring.networkIO">Network I/O</div>
                </div>
            </div>

            <div class="monitoring-stats" style="margin-top: 12px;">
                <div class="monitor-stat glass-card">
                    <div class="monitor-stat-icon red">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
                    </div>
                    <div class="monitor-stat-value" id="monitorHeapAlloc">0 MB</div>
                    <div class="monitor-stat-label" data-i18n="monitoring.heapAlloc">Heap Alloc</div>
                </div>
                <div class="monitor-stat glass-card">
                    <div class="monitor-stat-icon green">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
                    </div>
                    <div class="monitor-stat-value" id="monitorStackInuse">0 MB</div>
                    <div class="monitor-stat-label" data-i18n="monitoring.stackInuse">Stack Inuse</div>
                </div>
                <div class="monitor-stat glass-card">
                    <div class="monitor-stat-icon cyan">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                    </div>
                    <div class="monitor-stat-value" id="monitorGCPause">0 ms</div>
                    <div class="monitor-stat-label" data-i18n="monitoring.gcPause">GC Pause</div>
                </div>
                <div class="monitor-stat glass-card">
                    <div class="monitor-stat-icon yellow">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    </div>
                    <div class="monitor-stat-value" id="monitorVulns">0</div>
                    <div class="monitor-stat-label" data-i18n="monitoring.vulnsFound">Vulnerabilities</div>
                </div>
            </div>
            
            <div class="monitoring-charts" id="trendCharts">
                <div class="chart-card glass-card">
                    <div class="chart-header">
                        <h3 class="chart-title">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/></svg>
                            <span data-i18n="monitoring.cpuTrend">CPU Usage Trend</span>
                        </h3>
                        <div class="chart-legend">
                            <span class="legend-item"><span class="legend-color green"></span>CPU %</span>
                        </div>
                    </div>
                    <div class="chart-container">
                        <canvas id="cpuChart"></canvas>
                    </div>
                </div>
                <div class="chart-card glass-card">
                    <div class="chart-header">
                        <h3 class="chart-title">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                            <span data-i18n="monitoring.memoryTrend">Memory Usage Trend</span>
                        </h3>
                        <div class="chart-legend">
                            <span class="legend-item"><span class="legend-color cyan"></span>Memory MB</span>
                        </div>
                    </div>
                    <div class="chart-container">
                        <canvas id="memoryChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="monitoring-charts" style="margin-top: 16px;" id="trendCharts2">
                <div class="chart-card glass-card">
                    <div class="chart-header">
                        <h3 class="chart-title">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/></svg>
                            <span data-i18n="monitoring.networkTrend">Network I/O Trend</span>
                        </h3>
                        <div class="chart-legend">
                            <span class="legend-item"><span class="legend-color green"></span>TX</span>
                            <span class="legend-item"><span class="legend-color cyan"></span>RX</span>
                        </div>
                    </div>
                    <div class="chart-container">
                        <canvas id="networkChart"></canvas>
                    </div>
                </div>
                <div class="chart-card glass-card">
                    <div class="chart-header">
                        <h3 class="chart-title">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                            <span data-i18n="monitoring.goroutineTrend">Goroutine Trend</span>
                        </h3>
                        <div class="chart-legend">
                            <span class="legend-item"><span class="legend-color yellow"></span>Goroutines</span>
                        </div>
                    </div>
                    <div class="chart-container">
                        <canvas id="goroutineChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="monitoring-charts" style="margin-top: 16px;" id="trendCharts3">
                <div class="chart-card glass-card">
                    <div class="chart-header">
                        <h3 class="chart-title">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
                            <span data-i18n="monitoring.heapTrend">Heap Memory Trend</span>
                        </h3>
                        <div class="chart-legend">
                            <span class="legend-item"><span class="legend-color red"></span>Heap</span>
                        </div>
                    </div>
                    <div class="chart-container">
                        <canvas id="heapChart"></canvas>
                    </div>
                </div>
                <div class="chart-card glass-card">
                    <div class="chart-header">
                        <h3 class="chart-title">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                            <span data-i18n="monitoring.gcTrend">GC Pause Trend</span>
                        </h3>
                        <div class="chart-legend">
                            <span class="legend-item"><span class="legend-color cyan"></span>GC Pause</span>
                        </div>
                    </div>
                    <div class="chart-container">
                        <canvas id="gcChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="monitoring-gauges" id="gaugeCharts" style="display: none;">
                <div class="gauge-card glass-card">
                    <h3 class="gauge-title" data-i18n="monitoring.cpuUsage">CPU Usage</h3>
                    <div class="gauge-container">
                        <canvas id="cpuGauge"></canvas>
                    </div>
                    <div class="gauge-value" id="cpuGaugeValue">0%</div>
                </div>
                <div class="gauge-card glass-card">
                    <h3 class="gauge-title" data-i18n="monitoring.memoryUsage">Memory Usage</h3>
                    <div class="gauge-container">
                        <canvas id="memoryGauge"></canvas>
                    </div>
                    <div class="gauge-value" id="memoryGaugeValue">0%</div>
                </div>
                <div class="gauge-card glass-card">
                    <h3 class="gauge-title" data-i18n="monitoring.heapAlloc">Heap Usage</h3>
                    <div class="gauge-container">
                        <canvas id="heapGauge"></canvas>
                    </div>
                    <div class="gauge-value" id="heapGaugeValue">0%</div>
                </div>
                <div class="gauge-card glass-card">
                    <h3 class="gauge-title" data-i18n="monitoring.networkIO">Network I/O</h3>
                    <div class="gauge-container">
                        <canvas id="networkGauge"></canvas>
                    </div>
                    <div class="gauge-value" id="networkGaugeValue">0 KB/s</div>
                </div>
            </div>
        </section>
        
        <section id="reportsSection" style="display: none;">
            <div class="section-header">
                <h2 data-i18n="nav.reports">Reports</h2>
                <div class="section-actions">
                    <button class="btn-secondary" onclick="exportAllReports()">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        <span data-i18n="reports.exportAll">Export All</span>
                    </button>
                    <button class="btn-secondary" onclick="loadReports()">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/></svg>
                        <span data-i18n="common.refresh">Refresh</span>
                    </button>
                </div>
            </div>
            <div class="reports-grid" id="reportsList">
                <p class="text-muted" data-i18n="common.noData">No data</p>
            </div>
        </section>
        
        <section id="historySection" style="display: none;">
            <div class="section-header">
                <h2 data-i18n="nav.history">Scan History</h2>
                <div class="header-actions">
                    <button class="btn-secondary" onclick="exportHistory()">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        <span data-i18n="history.export">Export</span>
                    </button>
                    <button class="btn-secondary" onclick="clearHistory()">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                        <span data-i18n="history.clear">Clear</span>
                    </button>
                </div>
            </div>
            
            <div class="stats-grid" id="historyStatsGrid">
                <div class="stat-card glass-card">
                    <div class="stat-card-header">
                        <div class="stat-card-icon green">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                        </div>
                        <div class="stat-card-info">
                            <span class="stat-card-label" data-i18n="history.totalScans">Total Scans</span>
                            <span class="stat-card-value" id="totalScans">0</span>
                        </div>
                    </div>
                </div>
                <div class="stat-card glass-card">
                    <div class="stat-card-header">
                        <div class="stat-card-icon cyan">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                        </div>
                        <div class="stat-card-info">
                            <span class="stat-card-label" data-i18n="history.domains">Domains</span>
                            <span class="stat-card-value" id="totalDomains">0</span>
                        </div>
                    </div>
                </div>
                <div class="stat-card glass-card">
                    <div class="stat-card-header">
                        <div class="stat-card-icon yellow">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                        </div>
                        <div class="stat-card-info">
                            <span class="stat-card-label" data-i18n="history.vulnerabilities">Vulnerabilities</span>
                            <span class="stat-card-value" id="totalVulns">0</span>
                        </div>
                    </div>
                </div>
                <div class="stat-card glass-card">
                    <div class="stat-card-header">
                        <div class="stat-card-icon red">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        </div>
                        <div class="stat-card-info">
                            <span class="stat-card-label" data-i18n="history.critical">Critical</span>
                            <span class="stat-card-value" id="totalCritical">0</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="card glass-card" style="margin-bottom: 16px;">
                <div class="card-body">
                    <div class="history-toolbar">
                        <div class="search-box">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                            <input type="text" id="historySearchInput" class="search-input" data-i18n-placeholder="history.searchPlaceholder" placeholder="Search domain, URL..." onkeyup="searchHistory()">
                        </div>
                        <div class="filter-group">
                            <select id="historyDateFilter" class="input-field filter-select" onchange="filterHistory()">
                                <option value="" data-i18n="history.allDates">All Dates</option>
                            </select>
                            <select id="historyStatusFilter" class="input-field filter-select" onchange="filterHistory()">
                                <option value="" data-i18n="history.allStatus">All Status</option>
                                <option value="completed" data-i18n="history.completed">Completed</option>
                                <option value="running" data-i18n="history.running">Running</option>
                                <option value="error" data-i18n="history.error">Error</option>
                            </select>
                            <select id="historySortOrder" class="input-field filter-select" onchange="filterHistory()">
                                <option value="desc" data-i18n="history.newestFirst">Newest First</option>
                                <option value="asc" data-i18n="history.oldestFirst">Oldest First</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="history-batch-actions" id="historyBatchActions" style="display: none;">
                <span class="selected-count"><span id="selectedCount">0</span> <span data-i18n="history.selected">selected</span></span>
                <button class="btn-secondary" onclick="exportSelectedHistory()">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    <span data-i18n="history.exportSelected">Export Selected</span>
                </button>
                <button class="btn-secondary" onclick="deleteSelectedHistory()">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                    <span data-i18n="history.deleteSelected">Delete Selected</span>
                </button>
            </div>
            
            <div class="history-list" id="historyList">
                <div class="empty-state">
                    <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 3h18v18H3z"/><path d="M3 9h18"/><path d="M9 21V9"/></svg>
                    <p data-i18n="history.noData">No scan history</p>
                    <span class="sub-text" data-i18n="history.noDataHint">Start a new scan to see results here</span>
                </div>
            </div>
            
            <div id="historyDetailModal" class="modal" style="display: none;">
                <div class="modal-content glass-card" style="max-width: 700px;">
                    <div class="modal-header">
                        <h3 data-i18n="history.detail">Scan Details</h3>
                        <button class="close-btn" onclick="closeHistoryDetail()">&times;</button>
                    </div>
                    <div class="modal-body" id="historyDetailContent">
                    </div>
                    <div class="modal-footer">
                        <button class="btn-secondary" onclick="closeHistoryDetail()">
                            <span data-i18n="common.close">Close</span>
                        </button>
                    </div>
                </div>
            </div>
            
            <div id="domainDetailModal" class="modal" style="display: none;">
                <div class="modal-content glass-card" style="max-width: 800px;">
                    <div class="modal-header">
                        <h3 data-i18n="history.domainDetail">Domain Details</h3>
                        <button class="close-btn" onclick="closeDomainDetail()">&times;</button>
                    </div>
                    <div class="modal-body" id="domainDetailContent">
                    </div>
                    <div class="modal-footer">
                        <button class="btn-secondary" onclick="closeDomainDetail()">
                            <span data-i18n="common.close">Close</span>
                        </button>
                    </div>
                </div>
            </div>
            
            <div id="exportModal" class="modal" style="display: none;">
                <div class="modal-content glass-card" style="max-width: 400px;">
                    <div class="modal-header">
                        <h3 data-i18n="history.exportReport">Export Report</h3>
                        <button class="close-btn" onclick="closeExportModal()">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div class="export-options">
                            <label class="export-option">
                                <input type="radio" name="exportFormat" value="json" checked>
                                <span class="option-content">
                                    <strong>JSON</strong>
                                    <small>Raw data format</small>
                                </span>
                            </label>
                            <label class="export-option">
                                <input type="radio" name="exportFormat" value="html">
                                <span class="option-content">
                                    <strong>HTML</strong>
                                    <small>Beautiful visual report</small>
                                </span>
                            </label>
                            <label class="export-option">
                                <input type="radio" name="exportFormat" value="md">
                                <span class="option-content">
                                    <strong>Markdown</strong>
                                    <small>Documentation format</small>
                                </span>
                            </label>
                            <label class="export-option">
                                <input type="radio" name="exportFormat" value="csv">
                                <span class="option-content">
                                    <strong>CSV</strong>
                                    <small>Spreadsheet format</small>
                                </span>
                            </label>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn-secondary" onclick="closeExportModal()">
                            <span data-i18n="common.cancel">Cancel</span>
                        </button>
                        <button class="btn-primary" onclick="doExport()">
                            <span data-i18n="history.export">Export</span>
                        </button>
                    </div>
                </div>
            </div>
        </section>
        
        <section id="settingsSection" style="display: none;">
            <div class="settings-tabs">
                <button class="settings-tab active" onclick="showSettingsTab('general', event)" data-i18n="settings.general">General</button>
                <button class="settings-tab" onclick="showSettingsTab('notification', event)" data-i18n="settings.notification">Notification</button>
                <button class="settings-tab" onclick="showSettingsTab('proxy', event)" data-i18n="settings.proxy">Proxy</button>
                <button class="settings-tab" onclick="showSettingsTab('dictionary', event)" data-i18n="settings.dictionary">Dictionary</button>
                <button class="settings-tab" onclick="showSettingsTab('security', event)" data-i18n="settings.security">Security</button>
                <button class="settings-tab" onclick="showSettingsTab('about', event)" data-i18n="settings.about">About</button>
                <button class="settings-tab" onclick="showSettingsTab('reset', event)" data-i18n="settings.reset">Reset</button>
            </div>
            
            <div class="settings-container">
                <div id="settings-general" class="settings-panel active">
                    <div class="settings-card glass-card">
                        <div class="settings-card-header">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                            <h3 data-i18n="settings.scanDefaults">Scan Defaults</h3>
                        </div>
                        <div class="settings-card-body">
                            <div class="setting-row">
                                <div class="setting-item">
                                    <label data-i18n="scan.scanLevel">Scan Level</label>
                                    <select id="defaultScanLevel" class="input-field">
                                        <option value="1">1 - Quick</option>
                                        <option value="2" selected>2 - Normal</option>
                                        <option value="3">3 - Deep</option>
                                        <option value="4">4 - Full</option>
                                    </select>
                                </div>
                                <div class="setting-item">
                                    <label data-i18n="scan.concurrent">Concurrent</label>
                                    <input type="number" id="defaultConcurrent" class="input-field" value="10">
                                </div>
                            </div>
                            <div class="setting-row">
                                <div class="setting-item">
                                    <label data-i18n="scan.timeout">Timeout (s)</label>
                                    <input type="number" id="defaultTimeout" class="input-field" value="10">
                                </div>
                                <div class="setting-item">
                                    <label data-i18n="output.format">Default Format</label>
                                    <select id="defaultOutputFormat" class="input-field">
                                        <option value="html">HTML</option>
                                        <option value="json">JSON</option>
                                        <option value="md">Markdown</option>
                                    </select>
                                </div>
                            </div>
                            <div class="setting-row">
                                <div class="setting-item full-width">
                                    <label data-i18n="output.dir">Output Directory</label>
                                    <input type="text" id="defaultOutputDir" class="input-field" value="./reports">
                                </div>
                            </div>
                            <div class="setting-row">
                                <div class="setting-item full-width">
                                    <label data-i18n="settings.delayThreshold">Delay Threshold (s)</label>
                                    <input type="number" id="defaultDelayThreshold" class="input-field" value="4" step="0.5">
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="settings-card glass-card">
                        <div class="settings-card-header">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                            <h3 data-i18n="settings.account">Account</h3>
                        </div>
                        <div class="settings-card-body">
                            <div class="setting-row">
                                <div class="setting-item">
                                    <label data-i18n="settings.newPassword">New Password</label>
                                    <input type="password" id="newPassword" class="input-field" placeholder="********">
                                </div>
                                <div class="setting-item">
                                    <label data-i18n="settings.confirmPassword">Confirm Password</label>
                                    <input type="password" id="confirmPassword" class="input-field" placeholder="********">
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div id="settings-notification" class="settings-panel">
                    <div class="settings-card glass-card">
                        <div class="settings-card-header">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
                            <h3 data-i18n="settings.notificationConfig">Notification Configuration</h3>
                        </div>
                        <div class="settings-card-body">
                            <div class="setting-row">
                                <div class="setting-item full-width">
                                    <label class="toggle-label">
                                        <input type="checkbox" id="notificationEnabled" onchange="toggleNotification()">
                                        <span data-i18n="settings.enableNotification">Enable Notifications</span>
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="settings-card glass-card">
                        <div class="settings-card-header">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>
                            <h3 data-i18n="notification.wechat">WeChat Work</h3>
                        </div>
                        <div class="settings-card-body">
                            <div class="setting-row">
                                <div class="setting-item full-width">
                                    <label data-i18n="notification.wechatKey">Webhook Key</label>
                                    <input type="text" id="wechatKey" class="input-field" placeholder="Enter WeChat Work webhook key">
                                </div>
                            </div>
                            <div class="setting-row">
                                <div class="setting-item">
                                    <button class="btn-primary" onclick="testNotification('wechat')" data-i18n="notification.testWechat">Test WeChat</button>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="settings-card glass-card">
                        <div class="settings-card-header">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>
                            <h3 data-i18n="notification.dingtalk">DingTalk</h3>
                        </div>
                        <div class="settings-card-body">
                            <div class="setting-row">
                                <div class="setting-item full-width">
                                    <label data-i18n="notification.dingtalkUrl">Webhook URL</label>
                                    <input type="text" id="dingtalkKey" class="input-field" placeholder="Enter DingTalk webhook URL">
                                </div>
                            </div>
                            <div class="setting-row">
                                <div class="setting-item">
                                    <button class="btn-primary" onclick="testNotification('dingtalk')" data-i18n="notification.testDingtalk">Test DingTalk</button>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="settings-card glass-card">
                        <div class="settings-card-header">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                            <h3 data-i18n="notification.email">Email</h3>
                        </div>
                        <div class="settings-card-body">
                            <div class="setting-row">
                                <div class="setting-item">
                                    <label data-i18n="notification.smtpHost">SMTP Host</label>
                                    <input type="text" id="emailHost" class="input-field" placeholder="smtp.example.com">
                                </div>
                                <div class="setting-item">
                                    <label data-i18n="notification.smtpPort">SMTP Port</label>
                                    <input type="number" id="emailPort" class="input-field" value="587">
                                </div>
                            </div>
                            <div class="setting-row">
                                <div class="setting-item">
                                    <label data-i18n="notification.username">Username</label>
                                    <input type="text" id="emailUser" class="input-field" placeholder="your@email.com">
                                </div>
                                <div class="setting-item">
                                    <label data-i18n="notification.password">Password</label>
                                    <input type="password" id="emailPass" class="input-field" placeholder="********">
                                </div>
                            </div>
                            <div class="setting-row">
                                <div class="setting-item">
                                    <label data-i18n="notification.from">From</label>
                                    <input type="text" id="emailFrom" class="input-field" placeholder="noreply@example.com">
                                </div>
                                <div class="setting-item">
                                    <label data-i18n="notification.to">To</label>
                                    <input type="text" id="emailTo" class="input-field" placeholder="recipient@example.com">
                                </div>
                            </div>
                            <div class="setting-row">
                                <div class="setting-item">
                                    <button class="btn-primary" onclick="testNotification('email')" data-i18n="notification.testEmail">Test Email</button>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="settings-card glass-card">
                        <div class="settings-card-body">
                            <button class="btn-primary" onclick="saveNotificationConfig()" data-i18n="notification.saveSettings">Save Settings</button>
                        </div>
                    </div>
                </div>
                
                <div id="settings-proxy" class="settings-panel">
                    <div class="settings-card glass-card">
                        <div class="settings-card-header">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                            <h3 data-i18n="settings.proxyConfig">Proxy Configuration</h3>
                        </div>
                        <div class="settings-card-body">
                            <div class="setting-row">
                                <div class="setting-item">
                                    <label data-i18n="proxy.type">Proxy Type</label>
                                    <select id="settingsProxyType" class="input-field">
                                        <option value="">None</option>
                                        <option value="http">HTTP</option>
                                        <option value="https">HTTPS</option>
                                        <option value="socks5">SOCKS5</option>
                                    </select>
                                </div>
                                <div class="setting-item">
                                    <label data-i18n="proxy.address">Address</label>
                                    <input type="text" id="settingsProxyAddress" class="input-field" placeholder="127.0.0.1:8080">
                                </div>
                            </div>
                            <div class="setting-row">
                                <div class="setting-item">
                                    <label data-i18n="proxy.username">Username</label>
                                    <input type="text" id="settingsProxyUsername" class="input-field" placeholder="Optional">
                                </div>
                                <div class="setting-item">
                                    <label data-i18n="proxy.password">Password</label>
                                    <input type="password" id="settingsProxyPassword" class="input-field" placeholder="Optional">
                                </div>
                            </div>
                            <div class="setting-row">
                                <div class="setting-item full-width">
                                    <button type="button" class="btn-secondary" onclick="testSettingsProxy()">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                                        <span data-i18n="proxy.testConnection">Test Connection</span>
                                    </button>
                                    <span id="settingsProxyTestResult" style="margin-left: 10px;"></span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div id="settings-dictionary" class="settings-panel">
                    <div class="settings-card glass-card">
                        <div class="settings-card-header">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>
                            <h3 data-i18n="settings.dictMemory">Dictionary Memory Settings</h3>
                        </div>
                        <div class="settings-card-body">
                            <div class="setting-row">
                                <div class="setting-item">
                                    <label data-i18n="dict.archiveThreshold">Archive Threshold</label>
                                    <input type="number" id="dictArchiveThreshold" class="input-field" value="30" min="1" max="100">
                                    <span class="setting-hint" data-i18n="dict.archiveThresholdHint">Number of consecutive misses before archiving</span>
                                </div>
                                <div class="setting-item">
                                    <label data-i18n="dict.maxRetention">Max Retention Days</label>
                                    <input type="number" id="dictMaxRetention" class="input-field" value="30" min="1" max="365">
                                    <span class="setting-hint" data-i18n="dict.maxRetentionHint">Days to keep archived entries</span>
                                </div>
                            </div>
                            <div class="setting-row">
                                <div class="setting-item full-width">
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="optSmartDictGlobal" checked>
                                        <span data-i18n="dict.enableSmart">Enable Smart Dictionary</span>
                                    </label>
                                </div>
                            </div>
                            <div class="setting-row">
                                <div class="setting-item full-width">
                                    <label data-i18n="dict.dirWordlist">Directory Scan Wordlist</label>
                                    <input type="text" id="dictDirWordlist" class="input-field" placeholder="Leave empty for default">
                                </div>
                            </div>
                            <div class="setting-row">
                                <div class="setting-item full-width">
                                    <label data-i18n="dict.paramWordlist">Parameter Fuzz Wordlist</label>
                                    <input type="text" id="dictParamWordlist" class="input-field" placeholder="Leave empty for default">
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="settings-card glass-card">
                        <div class="settings-card-header">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                            <h3 data-i18n="settings.dictStats">Dictionary Statistics</h3>
                        </div>
                        <div class="settings-card-body">
                            <div class="dict-stats" id="dictStats">
                                <div class="dict-stat-item">
                                    <span class="dict-stat-label" data-i18n="dict.totalEntries">Total Entries</span>
                                    <span class="dict-stat-value" id="dictTotalEntries">0</span>
                                </div>
                                <div class="dict-stat-item">
                                    <span class="dict-stat-label" data-i18n="dict.archivedEntries">Archived</span>
                                    <span class="dict-stat-value" id="dictArchivedEntries">0</span>
                                </div>
                                <div class="dict-stat-item">
                                    <span class="dict-stat-label" data-i18n="dict.activeEntries">Active</span>
                                    <span class="dict-stat-value" id="dictActiveEntries">0</span>
                                </div>
                            </div>
                            <button type="button" class="btn-secondary" onclick="loadDictStats()" style="margin-top: 12px;">
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/></svg>
                                <span data-i18n="common.refresh">Refresh</span>
                            </button>
                        </div>
                    </div>
                </div>
                
                <div id="settings-security" class="settings-panel">
                    <div class="settings-card glass-card">
                        <div class="settings-card-header">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                            <h3 data-i18n="settings.securityOptions">Security Options</h3>
                        </div>
                        <div class="settings-card-body">
                            <div class="setting-row">
                                <div class="setting-item full-width">
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="optVerifySSLGlobal">
                                        <span data-i18n="option.verifySSL">Verify SSL Certificates</span>
                                    </label>
                                </div>
                            </div>
                            <div class="setting-row">
                                <div class="setting-item full-width">
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="optPreferHTTPSGlobal" checked>
                                        <span data-i18n="option.preferHTTPS">Prefer HTTPS</span>
                                    </label>
                                </div>
                            </div>
                            <div class="setting-row">
                                <div class="setting-item full-width">
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="optHarmlessGlobal">
                                        <span data-i18n="option.harmless">Use Harmless Mode by Default</span>
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div id="settings-about" class="settings-panel">
                    <div class="settings-card glass-card">
                        <div class="settings-card-header">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
                            <h3 data-i18n="settings.about">About</h3>
                        </div>
                        <div class="settings-card-body">
                            <div class="about-logo">
                                <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                                <h2>RCE HawkEye</h2>
                                <p class="version-info" id="versionInfo">v1.1.1</p>
                            </div>
                            
                            <div class="about-info">
                                <div class="info-item">
                                    <span class="info-label" data-i18n="about.buildDate">Build Date</span>
                                    <span class="info-value" id="buildDate">2026-02-20</span>
                                </div>
                                <div class="info-item">
                                    <span class="info-label" data-i18n="about.platform">Platform</span>
                                    <span class="info-value" id="platformInfo">-</span>
                                </div>
                                <div class="info-item">
                                    <span class="info-label" data-i18n="about.goVersion">Go Version</span>
                                    <span class="info-value" id="goVersion">-</span>
                                </div>
                            </div>
                            
                            <div class="update-section">
                                <button class="btn-primary" onclick="checkForUpdates()">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 11-6.219-8.56"/><polyline points="21 3 21 9 15 9"/></svg>
                                    <span data-i18n="about.checkUpdate">Check for Updates</span>
                                </button>
                                <div id="updateStatus" class="update-status"></div>
                            </div>
                            
                            <div class="about-links">
                                <a href="https://github.com/hbzw201633420/RCE_HawkEye" target="_blank" class="about-link">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>
                                    GitHub
                                </a>
                                <a href="https://github.com/hbzw201633420/RCE_HawkEye/issues" target="_blank" class="about-link">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                                    <span data-i18n="about.reportIssue">Report Issue</span>
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div id="settings-reset" class="settings-panel">
                    <div class="settings-card glass-card">
                        <div class="settings-card-header warning">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                            <h3 data-i18n="settings.resetData">Reset Data</h3>
                        </div>
                        <div class="settings-card-body">
                            <p class="warning-text" data-i18n="settings.resetWarning">Warning: These actions cannot be undone!</p>
                            
                            <div class="reset-actions">
                                <div class="reset-action-item">
                                    <div class="reset-action-info">
                                        <h4 data-i18n="reset.dictMemory">Reset Dictionary Memory</h4>
                                        <p data-i18n="reset.dictMemoryDesc">Clear all dictionary statistics and archived entries</p>
                                    </div>
                                    <button type="button" class="btn-warning" onclick="resetDictMemory()">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                                        <span data-i18n="common.reset">Reset</span>
                                    </button>
                                </div>
                                
                                <div class="reset-action-item">
                                    <div class="reset-action-info">
                                        <h4 data-i18n="reset.scanHistory">Reset Scan History</h4>
                                        <p data-i18n="reset.scanHistoryDesc">Clear all scan history and results</p>
                                    </div>
                                    <button type="button" class="btn-warning" onclick="resetScanHistory()">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                                        <span data-i18n="common.reset">Reset</span>
                                    </button>
                                </div>
                                
                                <div class="reset-action-item">
                                    <div class="reset-action-info">
                                        <h4 data-i18n="reset.reports">Reset Reports</h4>
                                        <p data-i18n="reset.reportsDesc">Delete all saved reports</p>
                                    </div>
                                    <button type="button" class="btn-warning" onclick="resetReports()">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                                        <span data-i18n="common.reset">Reset</span>
                                    </button>
                                </div>
                                
                                <div class="reset-action-item">
                                    <div class="reset-action-info">
                                        <h4 data-i18n="reset.allSettings">Reset All Settings</h4>
                                        <p data-i18n="reset.allSettingsDesc">Restore all settings to default values</p>
                                    </div>
                                    <button type="button" class="btn-danger" onclick="resetAllSettings()">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
                                        <span data-i18n="common.resetAll">Reset All</span>
                                    </button>
                                </div>
                                
                                <div class="reset-action-item">
                                    <div class="reset-action-info">
                                        <h4 data-i18n="reset.factoryReset">Factory Reset</h4>
                                        <p data-i18n="reset.factoryResetDesc">Reset everything to initial state</p>
                                    </div>
                                    <button type="button" class="btn-danger" onclick="factoryReset()">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
                                        <span data-i18n="common.factoryReset">Factory Reset</span>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="settings-actions">
                <button class="btn-secondary" onclick="resetSettingsForm()" data-i18n="common.reset">Reset</button>
                <button class="btn-primary" onclick="saveSettings()" data-i18n="common.save">Save</button>
            </div>
        </section>
    </main>
    
    <div id="alertModal" class="modal">
        <div class="modal-content glass-card">
            <div class="modal-header">
                <h3 data-i18n="alerts.title">Alerts</h3>
                <button class="modal-close" onclick="closeAlertModal()">&times;</button>
            </div>
            <div class="modal-body" id="alertList">
                <p class="text-muted" data-i18n="alerts.noAlerts">No alerts</p>
            </div>
            <div class="modal-footer">
                <button class="btn-secondary" onclick="clearAlerts()" data-i18n="alerts.clearAll">Clear All</button>
            </div>
        </div>
    </div>
    
    <div id="confirmModal" class="modal">
        <div class="modal-content glass-card" style="max-width: 400px;">
            <div class="modal-header">
                <h3 data-i18n="common.confirm">Confirm</h3>
                <button class="modal-close" onclick="closeConfirmModal()">&times;</button>
            </div>
            <div class="modal-body">
                <p id="confirmMessage"></p>
            </div>
            <div class="modal-footer">
                <button class="btn-secondary" onclick="closeConfirmModal()" data-i18n="common.cancel">Cancel</button>
                <button class="btn-danger" id="confirmBtn" data-i18n="common.confirm">Confirm</button>
            </div>
        </div>
    </div>
    
    <script src="/static/js/i18n.js?v=1.1.8"></script>
    <script src="/static/js/app.js?v=1.1.8"></script>
    <script>
        (function() {
            function initApp() {
                try {
                    var savedLang = localStorage.getItem('hawkeye_lang') || 'zh';
                    var langSelector = document.getElementById('langSelector');
                    if (langSelector) langSelector.value = savedLang;
                    
                    if (typeof initGlobalEventListeners === 'function') {
                        initGlobalEventListeners();
                    }
                    if (typeof initDashboardChart === 'function') {
                        initDashboardChart();
                    }
                    if (typeof loadStats === 'function') {
                        loadStats();
                    }
                    if (typeof loadSystemStatus === 'function') {
                        loadSystemStatus();
                    }
                    if (typeof updatePageLanguage === 'function') {
                        updatePageLanguage();
                    }
                } catch (e) {
                    console.error('Init error:', e);
                }
            }
            
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', initApp);
            } else {
                initApp();
            }
        })();
        
        function changeLanguage(lang) {
            if (typeof setLanguage === 'function') {
                setLanguage(lang);
            }
        }
    </script>
</body>
</html>
`
