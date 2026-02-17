let currentSection = 'dashboard';
let scanLevel = 2;
let charts = {};
let scanRunning = false;
let scanId = null;
let lastScanResults = null;

document.addEventListener('DOMContentLoaded', function() {
    initLevelButtons();
    initResultTabs();
    initCharts();
    loadDashboardStats();
    startMonitoring();
    loadScanHistory();
});

function showSection(section, evt) {
    document.querySelectorAll('.sidebar-nav a').forEach(a => a.classList.remove('active'));
    
    if (evt && evt.target) {
        const navLink = evt.target.closest('a');
        if (navLink) {
            navLink.classList.add('active');
        }
    } else {
        const navLinks = document.querySelectorAll('.sidebar-nav a');
        navLinks.forEach(link => {
            const span = link.querySelector('span[data-i18n]');
            if (span) {
                const key = span.getAttribute('data-i18n');
                if (key === 'nav.' + section || key === 'nav.dashboard' && section === 'dashboard') {
                    link.classList.add('active');
                }
            }
        });
    }
    
    document.getElementById('dashboardSection').style.display = section === 'dashboard' ? 'block' : 'none';
    document.getElementById('scannerSection').style.display = section === 'scanner' ? 'block' : 'none';
    document.getElementById('monitoringSection').style.display = section === 'monitoring' ? 'block' : 'none';
    document.getElementById('reportsSection').style.display = section === 'reports' ? 'block' : 'none';
    document.getElementById('settingsSection').style.display = section === 'settings' ? 'block' : 'none';
    
    currentSection = section;
    
    if (section === 'monitoring') {
        updateCharts();
    } else if (section === 'reports') {
        loadScanHistory();
    } else if (section === 'scanner') {
        loadActiveScans();
    }
}

function initLevelButtons() {
    document.querySelectorAll('.level-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            document.querySelectorAll('.level-btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            scanLevel = parseInt(this.dataset.level);
        });
    });
}

function initResultTabs() {
    document.querySelectorAll('.results-tab').forEach(tab => {
        tab.addEventListener('click', function() {
            document.querySelectorAll('.results-tab').forEach(t => t.classList.remove('active'));
            this.classList.add('active');
            filterResults(this.dataset.filter);
        });
    });
}

function filterResults(filter) {
    const items = document.querySelectorAll('.vulnerability-item');
    items.forEach(item => {
        if (filter === 'all' || item.classList.contains(filter)) {
            item.style.display = 'block';
        } else {
            item.style.display = 'none';
        }
    });
}

function detectHttps() {
    const targetUrl = document.getElementById('targetUrl').value;
    if (!targetUrl) {
        alert(getCurrentLang() === 'zh' ? '请先输入目标URL' : 'Please enter a target URL first');
        return;
    }
    
    fetch('/api/detect-https', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl })
    })
    .then(response => response.json())
    .then(data => {
        if (data.https_supported) {
            document.getElementById('targetUrl').value = data.https_url;
            document.getElementById('optHttps').checked = true;
        } else {
            alert(getCurrentLang() === 'zh' ? '该目标不支持HTTPS' : 'HTTPS is not supported for this target');
        }
    })
    .catch(error => {
        console.error('Error detecting HTTPS:', error);
    });
}

function getAdvancedOptions() {
    const headers = {};
    const headersText = document.getElementById('advHeaders').value.trim();
    if (headersText) {
        headersText.split('\n').forEach(line => {
            const idx = line.indexOf(':');
            if (idx > 0) {
                const key = line.substring(0, idx).trim();
                const value = line.substring(idx + 1).trim();
                if (key && value) {
                    headers[key] = value;
                }
            }
        });
    }
    
    return {
        method: document.getElementById('advMethod').value,
        concurrent: parseInt(document.getElementById('advConcurrent').value) || 10,
        timeout: parseInt(document.getElementById('advTimeout').value) || 10,
        delay_threshold: parseFloat(document.getElementById('advDelayThreshold').value) || 4,
        proxy: document.getElementById('advProxy').value.trim() || null,
        headers: Object.keys(headers).length > 0 ? headers : null,
        post_data: document.getElementById('advPostData').value.trim() || null,
        crawl_depth: parseInt(document.getElementById('advCrawlDepth').value) || 2,
        crawl_pages: parseInt(document.getElementById('advCrawlPages').value) || 100
    };
}

function startScan() {
    const targetUrl = document.getElementById('targetUrl').value;
    
    if (!targetUrl) {
        alert(getCurrentLang() === 'zh' ? '请输入目标URL' : 'Please enter a target URL');
        return;
    }
    
    if (scanRunning) {
        stopScan();
        return;
    }
    
    const options = {
        crawl: document.getElementById('optCrawl').checked,
        dirScan: document.getElementById('optDirScan').checked,
        paramFuzz: document.getElementById('optParamFuzz').checked,
        wafBypass: document.getElementById('optWafBypass').checked,
        harmless: document.getElementById('optHarmless').checked,
        preferHttps: document.getElementById('optHttps').checked,
        advanced: getAdvancedOptions()
    };
    
    const startBtn = document.getElementById('startScanBtn');
    startBtn.innerHTML = '<span class="loading-spinner"></span>' + t('scan.starting');
    startBtn.disabled = true;
    
    document.getElementById('progressSection').style.display = 'block';
    document.getElementById('progressBar').style.width = '0%';
    document.getElementById('progressStatus').textContent = t('progress.initializing');
    document.getElementById('progressPercent').textContent = '0%';
    
    document.getElementById('crawlInfo').style.display = 'none';
    document.getElementById('dirInfo').style.display = 'none';
    document.getElementById('paramInfo').style.display = 'none';
    
    fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            target: targetUrl,
            level: scanLevel,
            options: options
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            scanId = data.scan_id;
            scanRunning = true;
            startBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display: inline-block; vertical-align: middle; margin-right: 8px;"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>' + t('scan.stopScan');
            startBtn.disabled = false;
            pollScanStatus();
        } else {
            alert(t('common.error') + ': ' + data.message);
            startBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display: inline-block; vertical-align: middle; margin-right: 8px;"><polygon points="5 3 19 12 5 21 5 3"/></svg>' + t('scan.startScan');
            startBtn.disabled = false;
        }
    })
    .catch(error => {
        console.error('Error starting scan:', error);
        alert(t('common.error') + ': ' + error.message);
        startBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display: inline-block; vertical-align: middle; margin-right: 8px;"><polygon points="5 3 19 12 5 21 5 3"/></svg>' + t('scan.startScan');
        startBtn.disabled = false;
    });
}

function stopScan() {
    fetch('/api/scan/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: scanId })
    })
    .then(response => response.json())
    .then(data => {
        scanRunning = false;
        const startBtn = document.getElementById('startScanBtn');
        startBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display: inline-block; vertical-align: middle; margin-right: 8px;"><polygon points="5 3 19 12 5 21 5 3"/></svg>' + t('scan.startScan');
        document.getElementById('progressStatus').textContent = t('scan.stopped');
    });
}

function pollScanStatus() {
    if (!scanRunning) return;
    
    fetch('/api/scan/status?scan_id=' + scanId)
    .then(response => response.json())
    .then(data => {
        updateProgress(data);
        
        if (data.crawl_count !== undefined) {
            document.getElementById('crawlInfo').style.display = 'block';
            document.getElementById('crawlCount').textContent = data.crawl_count;
        }
        if (data.dir_count !== undefined) {
            document.getElementById('dirInfo').style.display = 'block';
            document.getElementById('dirCount').textContent = data.dir_count;
        }
        if (data.param_count !== undefined) {
            document.getElementById('paramInfo').style.display = 'block';
            document.getElementById('paramCount').textContent = data.param_count;
        }
        
        if (data.status === 'completed' || data.status === 'stopped' || data.status === 'error') {
            scanRunning = false;
            const startBtn = document.getElementById('startScanBtn');
            startBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display: inline-block; vertical-align: middle; margin-right: 8px;"><polygon points="5 3 19 12 5 21 5 3"/></svg>' + t('scan.startScan');
            
            if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                lastScanResults = data;
                displayVulnerabilities(data.vulnerabilities);
                document.getElementById('exportButtons').style.display = 'block';
            } else if (data.status === 'completed') {
                lastScanResults = data;
                displayNoVulnerabilities();
                document.getElementById('exportButtons').style.display = 'block';
            }
            
            if (data.status === 'error') {
                document.getElementById('progressStatus').textContent = t('common.error') + ': ' + (data.status_message || data.error || 'Unknown error');
            }
            
            loadDashboardStats();
            loadScanHistory();
        } else {
            if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                displayVulnerabilities(data.vulnerabilities);
            }
            setTimeout(pollScanStatus, 500);
        }
    })
    .catch(error => {
        console.error('Error polling status:', error);
        setTimeout(pollScanStatus, 2000);
    });
}

function updateProgress(data) {
    const progressBar = document.getElementById('progressBar');
    const progressStatus = document.getElementById('progressStatus');
    const progressPercent = document.getElementById('progressPercent');
    
    progressBar.style.width = data.progress + '%';
    
    let statusText = data.status_message || t('progress.scanning');
    if (data.tested_payloads && data.total_payloads && data.total_payloads > 0) {
        statusText += ` (${data.tested_payloads}/${data.total_payloads})`;
    }
    if (data.current_phase) {
        statusText = '[' + data.current_phase + '] ' + statusText;
    }
    progressStatus.textContent = statusText;
    progressPercent.textContent = data.progress + '%';
}

function displayVulnerabilities(vulns) {
    console.log('displayVulnerabilities called with:', vulns);
    
    const list = document.getElementById('vulnerabilityList');
    
    if (!vulns || !Array.isArray(vulns)) {
        list.innerHTML = '<p style="color: rgba(248,250,252,0.5); text-align: center; padding: 20px;">无漏洞数据</p>';
        return;
    }
    
    const validVulns = vulns.filter(v => v && typeof v === 'object');
    console.log('validVulns:', validVulns);
    
    if (validVulns.length === 0) {
        displayNoVulnerabilities();
        return;
    }
    
    try {
        list.innerHTML = validVulns.map((vuln, index) => {
            console.log(`Processing vuln ${index}:`, vuln);
            const severity = (vuln.severity || 'medium').toString().toLowerCase();
            const target = vuln.target || 'Unknown';
            const parameter = vuln.parameter || 'N/A';
            const payload = vuln.payload || vuln.evidence || '';
            const payloadType = vuln.payload_type || vuln.vuln_type || 'RCE';
            
            return `
            <div class="vulnerability-item ${severity}">
                <div class="vulnerability-header">
                    <span class="vulnerability-title">${escapeHtml(target)}</span>
                    <span class="vulnerability-badge ${severity}">${getSeverityText(vuln.severity || 'Medium')}</span>
                </div>
                <div class="vulnerability-meta">
                    <span>${t('results.parameter')}: ${escapeHtml(parameter)}</span>
                    <span>${t('results.type')}: ${escapeHtml(payloadType)}</span>
                </div>
                <div class="vulnerability-payload">${escapeHtml(payload)}</div>
            </div>
        `}).join('');
    } catch (error) {
        console.error('Error in displayVulnerabilities:', error);
        list.innerHTML = `<p style="color: #EF4444;">显示漏洞时出错: ${error.message}</p>`;
    }
}

function displayNoVulnerabilities() {
    const list = document.getElementById('vulnerabilityList');
    const lang = getCurrentLang();
    
    list.innerHTML = `
        <div style="text-align: center; padding: 40px; color: rgba(34, 197, 94, 0.8);">
            <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom: 16px;">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="M9 12l2 2 4-4"/>
            </svg>
            <p style="font-size: 16px; font-weight: 600;">${lang === 'zh' ? '扫描完成，未发现漏洞' : 'Scan completed, no vulnerabilities found'}</p>
        </div>
    `;
}

function getSeverityText(severity) {
    if (!severity) return t('vuln.medium');
    const key = 'vuln.' + severity.toString().toLowerCase();
    return t(key);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function loadDashboardStats() {
    fetch('/api/stats')
    .then(response => response.json())
    .then(data => {
        document.getElementById('totalScans').textContent = data.total_scans || 0;
        document.getElementById('criticalVulns').textContent = data.critical_vulns || 0;
        document.getElementById('highVulns').textContent = data.high_vulns || 0;
        document.getElementById('targetsScanned').textContent = data.targets_scanned || 0;
    })
    .catch(error => {
        console.error('Error loading stats:', error);
    });
}

function initCharts() {
    const chartConfig = {
        type: 'line',
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 0 },
            scales: {
                x: { display: false },
                y: { 
                    display: false,
                    min: 0,
                    max: 100
                }
            },
            plugins: { legend: { display: false } },
            elements: {
                point: { radius: 0 },
                line: { tension: 0.4 }
            }
        }
    };
    
    charts.cpu = new Chart(document.getElementById('cpuChart'), {
        ...chartConfig,
        data: {
            labels: Array(20).fill(''),
            datasets: [{
                data: Array(20).fill(0),
                borderColor: '#22C55E',
                backgroundColor: 'rgba(34, 197, 94, 0.1)',
                fill: true
            }]
        }
    });
    
    charts.memory = new Chart(document.getElementById('memoryChart'), {
        ...chartConfig,
        data: {
            labels: Array(20).fill(''),
            datasets: [{
                data: Array(20).fill(0),
                borderColor: '#06B6D4',
                backgroundColor: 'rgba(6, 182, 212, 0.1)',
                fill: true
            }]
        }
    });
    
    charts.network = new Chart(document.getElementById('networkChart'), {
        ...chartConfig,
        data: {
            labels: Array(20).fill(''),
            datasets: [{
                data: Array(20).fill(0),
                borderColor: '#A855F7',
                backgroundColor: 'rgba(168, 85, 247, 0.1)',
                fill: true
            }]
        }
    });
    
    charts.scanPerf = new Chart(document.getElementById('scanPerfChart'), {
        ...chartConfig,
        data: {
            labels: Array(20).fill(''),
            datasets: [{
                data: Array(20).fill(0),
                borderColor: '#F59E0B',
                backgroundColor: 'rgba(245, 158, 11, 0.1)',
                fill: true
            }]
        }
    });
}

function startMonitoring() {
    setInterval(updateCharts, 2000);
}

function updateCharts() {
    fetch('/api/monitoring')
    .then(response => response.json())
    .then(data => {
        updateChart(charts.cpu, data.cpu);
        updateChart(charts.memory, data.memory);
        updateChart(charts.network, data.network);
        updateChart(charts.scanPerf, data.scan_perf);
        
        document.getElementById('cpuValue').textContent = data.cpu + '%';
        document.getElementById('memoryValue').textContent = data.memory + '%';
        document.getElementById('networkValue').textContent = data.network + ' KB/s';
        document.getElementById('scanPerfValue').textContent = data.scan_perf + ' req/s';
    })
    .catch(error => {
        const mockData = {
            cpu: Math.floor(Math.random() * 30 + 20),
            memory: Math.floor(Math.random() * 20 + 40),
            network: Math.floor(Math.random() * 100 + 50),
            scan_perf: Math.floor(Math.random() * 20 + 10)
        };
        
        updateChart(charts.cpu, mockData.cpu);
        updateChart(charts.memory, mockData.memory);
        updateChart(charts.network, mockData.network);
        updateChart(charts.scanPerf, mockData.scan_perf);
        
        document.getElementById('cpuValue').textContent = mockData.cpu + '%';
        document.getElementById('memoryValue').textContent = mockData.memory + '%';
        document.getElementById('networkValue').textContent = mockData.network + ' KB/s';
        document.getElementById('scanPerfValue').textContent = mockData.scan_perf + ' req/s';
    });
}

function updateChart(chart, value) {
    chart.data.datasets[0].data.shift();
    chart.data.datasets[0].data.push(value);
    chart.update();
}

function toggleUserMenu() {
    if (confirm(t('common.logoutConfirm'))) {
        fetch('/api/logout', { method: 'POST' })
        .then(() => {
            window.location.href = '/login';
        });
    }
}

function exportReport(format) {
    if (!lastScanResults) {
        alert(getCurrentLang() === 'zh' ? '没有可导出的扫描结果' : 'No scan results to export');
        return;
    }
    
    fetch('/api/export/' + format, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            scan_id: scanId,
            target: lastScanResults.target || document.getElementById('targetUrl').value,
            vulnerabilities: lastScanResults.vulnerabilities || []
        })
    })
    .then(response => {
        if (format === 'json') {
            return response.json().then(data => {
                downloadFile(JSON.stringify(data, null, 2), 'scan_report.json', 'application/json');
            });
        } else {
            return response.text().then(data => {
                const ext = format === 'md' ? 'md' : 'html';
                const mime = format === 'md' ? 'text/markdown' : 'text/html';
                downloadFile(data, 'scan_report.' + ext, mime);
            });
        }
    })
    .catch(error => {
        console.error('Error exporting report:', error);
        alert(t('common.error') + ': ' + error.message);
    });
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function loadScanHistory() {
    fetch('/api/scan/history')
    .then(response => response.json())
    .then(data => {
        const container = document.getElementById('reportsList');
        if (!data.scans || data.scans.length === 0) {
            container.innerHTML = '<p style="color: rgba(248,250,252,0.5);">暂无扫描历史</p>';
            return;
        }
        
        container.innerHTML = data.scans.map(scan => `
            <div class="glass-card" style="padding: 16px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <div style="font-weight: 600; margin-bottom: 4px;">${escapeHtml(scan.target)}</div>
                    <div style="font-size: 12px; color: rgba(248,250,252,0.5);">
                        ${scan.timestamp} | 
                        <span style="color: ${scan.vuln_count > 0 ? '#EF4444' : '#22C55E'};">
                            ${scan.vuln_count} 个漏洞
                        </span>
                    </div>
                </div>
                <div>
                    <button class="btn-secondary" onclick="viewScanDetail('${scan.id}')" style="padding: 6px 12px; font-size: 12px;">查看</button>
                </div>
            </div>
        `).join('');
    })
    .catch(error => {
        console.error('Error loading scan history:', error);
    });
}

function viewScanDetail(scanId) {
    console.log('Loading scan detail for:', scanId);
    
    fetch('/api/scan/detail?scan_id=' + scanId)
    .then(response => {
        console.log('Response status:', response.status);
        return response.json();
    })
    .then(data => {
        console.log('Scan detail data:', data);
        
        if (!data.success) {
            alert('加载扫描详情失败: ' + (data.message || '未知错误'));
            return;
        }
        
        lastScanResults = data;
        
        document.getElementById('detailTarget').textContent = data.target || '-';
        document.getElementById('detailTime').textContent = data.timestamp || '-';
        document.getElementById('detailVulnCount').textContent = (data.vulnerabilities && data.vulnerabilities.length) || 0;
        document.getElementById('detailStatus').textContent = data.status || 'completed';
        
        const vulns = data.vulnerabilities;
        const vulnList = document.getElementById('reportDetailVulns');
        
        if (vulns && Array.isArray(vulns) && vulns.length > 0) {
            vulnList.innerHTML = vulns.map(vuln => {
                const severity = (vuln.severity || 'medium').toString().toLowerCase();
                return `
                <div class="vulnerability-item ${severity}">
                    <div class="vulnerability-header">
                        <span class="vulnerability-title">${escapeHtml(vuln.target || 'Unknown')}</span>
                        <span class="vulnerability-badge ${severity}">${getSeverityText(vuln.severity || 'Medium')}</span>
                    </div>
                    <div class="vulnerability-meta">
                        <span>参数: ${escapeHtml(vuln.parameter || 'N/A')}</span>
                        <span>类型: ${escapeHtml(vuln.payload_type || 'RCE')}</span>
                    </div>
                    <div class="vulnerability-payload">${escapeHtml(vuln.payload || vuln.evidence || '')}</div>
                </div>
            `}).join('');
        } else {
            vulnList.innerHTML = `
                <div style="text-align: center; padding: 40px; color: rgba(34, 197, 94, 0.8);">
                    <p style="font-size: 16px; font-weight: 600;">扫描完成，未发现漏洞</p>
                </div>
            `;
        }
        
        document.getElementById('reportDetailSection').style.display = 'block';
    })
    .catch(error => {
        console.error('Error loading scan detail:', error);
        alert('加载扫描详情失败: ' + error.message);
    });
}

function closeReportDetail() {
    document.getElementById('reportDetailSection').style.display = 'none';
}

function exportReportFromDetail(format) {
    if (!lastScanResults) {
        alert('没有可导出的扫描结果');
        return;
    }
    
    fetch('/api/export/' + format, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            scan_id: lastScanResults.scan_id,
            target: lastScanResults.target,
            vulnerabilities: lastScanResults.vulnerabilities || []
        })
    })
    .then(response => {
        if (format === 'json') {
            return response.json().then(data => {
                downloadFile(JSON.stringify(data, null, 2), 'scan_report.json', 'application/json');
            });
        } else {
            return response.text().then(data => {
                const ext = format === 'md' ? 'md' : 'html';
                const mime = format === 'md' ? 'text/markdown' : 'text/html';
                downloadFile(data, 'scan_report.' + ext, mime);
            });
        }
    })
    .catch(error => {
        console.error('Error exporting report:', error);
        alert('导出失败: ' + error.message);
    });
}

function loadActiveScans() {
    fetch('/api/scan/active')
    .then(response => response.json())
    .then(data => {
        const container = document.getElementById('activeScansList');
        if (!data.scans || data.scans.length === 0) {
            container.innerHTML = '<p style="color: rgba(248,250,252,0.5); text-align: center; padding: 20px;">当前没有正在进行的扫描</p>';
            return;
        }
        
        container.innerHTML = data.scans.map(scan => `
            <div class="glass-card" style="padding: 16px; margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span style="font-weight: 600;">${escapeHtml(scan.target)}</span>
                    <span style="color: ${scan.status === 'running' ? '#22C55E' : '#F59E0B'};">${scan.status}</span>
                </div>
                <div class="progress-bar-container" style="height: 6px;">
                    <div class="progress-bar" style="width: ${scan.progress}%;"></div>
                </div>
                <div style="font-size: 12px; color: rgba(248,250,252,0.5); margin-top: 8px;">${scan.status_message}</div>
            </div>
        `).join('');
    })
    .catch(error => {
        console.error('Error loading active scans:', error);
    });
}

let batchScanLevel = 2;

function showBatchScanModal() {
    document.getElementById('batchScanModal').style.display = 'flex';
    document.getElementById('batchScanProgress').style.display = 'none';
    document.getElementById('batchUrls').value = '';
    
    document.querySelectorAll('[data-batch-level]').forEach(btn => {
        btn.addEventListener('click', function() {
            document.querySelectorAll('[data-batch-level]').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            batchScanLevel = parseInt(this.dataset.batchLevel);
        });
    });
}

function closeBatchScanModal() {
    document.getElementById('batchScanModal').style.display = 'none';
}

function importUrlsFromFile() {
    document.getElementById('urlFileInput').click();
}

function handleFileImport(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = function(e) {
        const content = e.target.result;
        const urls = content.split(/[\r\n]+/).filter(url => url.trim());
        
        if (urls.length > 0) {
            document.getElementById('batchUrls').value = urls.join('\n');
            showBatchScanModal();
        } else {
            alert('文件中没有找到有效的URL');
        }
    };
    reader.readAsText(file);
    event.target.value = '';
}

function startBatchScan() {
    const urlsText = document.getElementById('batchUrls').value;
    const urls = urlsText.split(/[\r\n]+/).map(u => u.trim()).filter(u => u);
    
    if (urls.length === 0) {
        alert('请输入至少一个目标URL');
        return;
    }
    
    const options = {
        crawl: document.getElementById('batchOptCrawl').checked,
        dirScan: document.getElementById('batchOptDirScan').checked,
        paramFuzz: document.getElementById('batchOptParamFuzz').checked,
        harmless: document.getElementById('batchOptHarmless').checked
    };
    
    document.getElementById('batchScanProgress').style.display = 'block';
    document.getElementById('batchProgressText').textContent = `准备扫描 ${urls.length} 个目标...`;
    document.getElementById('batchProgressPercent').textContent = '0%';
    document.getElementById('batchProgressBar').style.width = '0%';
    document.getElementById('batchScanResults').innerHTML = '';
    
    fetch('/api/scan/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            targets: urls,
            level: batchScanLevel,
            options: options
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            pollBatchScanStatus(data.batch_id, urls.length);
        } else {
            alert('启动批量扫描失败: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error starting batch scan:', error);
        alert('启动批量扫描失败: ' + error.message);
    });
}

function pollBatchScanStatus(batchId, totalTargets) {
    let completed = 0;
    let totalVulns = 0;
    
    const pollInterval = setInterval(() => {
        fetch('/api/scan/batch/status?batch_id=' + batchId)
        .then(response => response.json())
        .then(data => {
            if (!data.success) {
                clearInterval(pollInterval);
                alert('获取批量扫描状态失败');
                return;
            }
            
            completed = data.completed || 0;
            totalVulns = data.total_vulns || 0;
            
            const percent = Math.round((completed / totalTargets) * 100);
            document.getElementById('batchProgressText').textContent = `已完成 ${completed}/${totalTargets} 个目标，发现 ${totalVulns} 个漏洞`;
            document.getElementById('batchProgressPercent').textContent = percent + '%';
            document.getElementById('batchProgressBar').style.width = percent + '%';
            
            if (data.results && data.results.length > 0) {
                const resultsHtml = data.results.slice(-5).map(r => {
                    const statusColor = r.status === 'completed' ? '#22C55E' : '#EF4444';
                    const vulnText = r.vuln_count > 0 ? `<span style="color: #EF4444;">${r.vuln_count} 个漏洞</span>` : '<span style="color: #22C55E;">无漏洞</span>';
                    return `<div style="padding: 8px; background: rgba(0,0,0,0.2); border-radius: 4px; margin-bottom: 4px; font-size: 12px;">
                        <span style="color: ${statusColor};">●</span> ${escapeHtml(r.target)} - ${vulnText}
                    </div>`;
                }).join('');
                document.getElementById('batchScanResults').innerHTML = resultsHtml;
            }
            
            if (data.status === 'completed' || data.status === 'error') {
                clearInterval(pollInterval);
                document.getElementById('batchProgressText').textContent = `批量扫描完成！共扫描 ${completed} 个目标，发现 ${totalVulns} 个漏洞`;
                loadDashboardStats();
                loadScanHistory();
            }
        })
        .catch(error => {
            console.error('Error polling batch status:', error);
        });
    }, 2000);
}

let notifications = [];

function addNotification(message, type = 'info') {
    const notification = {
        id: Date.now(),
        message: message,
        type: type,
        time: new Date().toLocaleTimeString()
    };
    notifications.unshift(notification);
    updateNotificationBadge();
    showNotificationToast(notification);
}

function updateNotificationBadge() {
    const badge = document.getElementById('notificationBadge');
    if (notifications.length > 0) {
        badge.style.display = 'block';
        badge.textContent = notifications.length > 99 ? '99+' : notifications.length;
    } else {
        badge.style.display = 'none';
    }
}

function showNotificationToast(notification) {
    const colors = {
        'success': '#22C55E',
        'error': '#EF4444',
        'warning': '#F59E0B',
        'info': '#3B82F6'
    };
    
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: rgba(15, 23, 42, 0.95);
        border-left: 4px solid ${colors[notification.type] || colors.info};
        padding: 16px 20px;
        border-radius: 8px;
        box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        z-index: 1000;
        max-width: 350px;
        animation: slideIn 0.3s ease;
    `;
    toast.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: start;">
            <div>
                <div style="font-weight: 600; margin-bottom: 4px;">${notification.type === 'success' ? '成功' : notification.type === 'error' ? '错误' : notification.type === 'warning' ? '警告' : '通知'}</div>
                <div style="font-size: 13px; color: rgba(248,250,252,0.7);">${escapeHtml(notification.message)}</div>
            </div>
            <button onclick="this.parentElement.parentElement.remove()" style="background: none; border: none; color: rgba(248,250,252,0.5); cursor: pointer; font-size: 18px; margin-left: 12px;">&times;</button>
        </div>
    `;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

function toggleNotifications() {
    const dropdown = document.getElementById('notificationDropdown');
    const userDropdown = document.getElementById('userDropdown');
    userDropdown.style.display = 'none';
    
    if (dropdown.style.display === 'none') {
        dropdown.style.display = 'block';
        renderNotifications();
    } else {
        dropdown.style.display = 'none';
    }
}

function renderNotifications() {
    const list = document.getElementById('notificationList');
    if (notifications.length === 0) {
        list.innerHTML = '<div style="text-align: center; padding: 20px; color: rgba(248,250,252,0.5);">暂无通知</div>';
        return;
    }
    
    const colors = {
        'success': '#22C55E',
        'error': '#EF4444',
        'warning': '#F59E0B',
        'info': '#3B82F6'
    };
    
    list.innerHTML = notifications.map(n => `
        <div style="padding: 12px; border-bottom: 1px solid rgba(255,255,255,0.05);">
            <div style="display: flex; align-items: start; gap: 8px;">
                <span style="color: ${colors[n.type] || colors.info};">●</span>
                <div style="flex: 1;">
                    <div style="font-size: 13px;">${escapeHtml(n.message)}</div>
                    <div style="font-size: 11px; color: rgba(248,250,252,0.4); margin-top: 4px;">${n.time}</div>
                </div>
            </div>
        </div>
    `).join('');
}

function clearNotifications() {
    notifications = [];
    updateNotificationBadge();
    renderNotifications();
}

function toggleUserMenu() {
    const dropdown = document.getElementById('userDropdown');
    const notifDropdown = document.getElementById('notificationDropdown');
    notifDropdown.style.display = 'none';
    
    if (dropdown.style.display === 'none') {
        dropdown.style.display = 'block';
    } else {
        dropdown.style.display = 'none';
    }
}

function logout() {
    fetch('/api/logout', { method: 'POST' })
    .then(() => {
        window.location.href = '/login';
    });
}

function loadSettings() {
    const settings = JSON.parse(localStorage.getItem('hawkeye_settings') || '{}');
    
    if (settings.defaultLevel) document.getElementById('settingDefaultLevel').value = settings.defaultLevel;
    if (settings.timeout) document.getElementById('settingTimeout').value = settings.timeout;
    if (settings.concurrent) document.getElementById('settingConcurrent').value = settings.concurrent;
    if (settings.proxy) document.getElementById('settingProxy').value = settings.proxy;
    if (settings.language) document.getElementById('settingLanguage').value = settings.language;
    if (settings.notify !== undefined) document.getElementById('settingNotify').checked = settings.notify;
    if (settings.autoSave !== undefined) document.getElementById('settingAutoSave').checked = settings.autoSave;
    if (settings.preferHttps !== undefined) document.getElementById('settingPreferHttps').checked = settings.preferHttps;
}

function saveSettings() {
    const settings = {
        defaultLevel: document.getElementById('settingDefaultLevel').value,
        timeout: document.getElementById('settingTimeout').value,
        concurrent: document.getElementById('settingConcurrent').value,
        proxy: document.getElementById('settingProxy').value,
        language: document.getElementById('settingLanguage').value,
        notify: document.getElementById('settingNotify').checked,
        autoSave: document.getElementById('settingAutoSave').checked,
        preferHttps: document.getElementById('settingPreferHttps').checked
    };
    
    localStorage.setItem('hawkeye_settings', JSON.stringify(settings));
    
    const newPassword = document.getElementById('settingNewPassword').value;
    const confirmPassword = document.getElementById('settingConfirmPassword').value;
    
    if (newPassword || confirmPassword) {
        if (newPassword !== confirmPassword) {
            addNotification('两次输入的密码不一致', 'error');
            return;
        }
        
        fetch('/api/settings/password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: newPassword })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                addNotification('密码修改成功', 'success');
                document.getElementById('settingNewPassword').value = '';
                document.getElementById('settingConfirmPassword').value = '';
            } else {
                addNotification('密码修改失败: ' + data.message, 'error');
            }
        });
    }
    
    setLanguage(settings.language);
    document.getElementById('langSelector').value = settings.language;
    
    addNotification('设置已保存', 'success');
}

function resetSettings() {
    localStorage.removeItem('hawkeye_settings');
    document.getElementById('settingDefaultLevel').value = '2';
    document.getElementById('settingTimeout').value = '10';
    document.getElementById('settingConcurrent').value = '10';
    document.getElementById('settingProxy').value = '';
    document.getElementById('settingLanguage').value = 'zh';
    document.getElementById('settingNotify').checked = true;
    document.getElementById('settingAutoSave').checked = true;
    document.getElementById('settingPreferHttps').checked = true;
    addNotification('设置已恢复默认', 'info');
}

function exportAllReports() {
    fetch('/api/reports/export')
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const blob = new Blob([JSON.stringify(data.reports, null, 2)], { type: 'application/json' });
            downloadFile(URL.createObjectURL(blob), 'all_reports.json', 'application/json');
            addNotification('报告导出成功', 'success');
        } else {
            addNotification('导出失败: ' + data.message, 'error');
        }
    });
}

function clearScanHistory() {
    if (confirm('确定要清除所有扫描历史吗？此操作不可恢复。')) {
        fetch('/api/history/clear', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                addNotification('扫描历史已清除', 'success');
                loadScanHistory();
                loadDashboardStats();
            } else {
                addNotification('清除失败: ' + data.message, 'error');
            }
        });
    }
}

function clearAllData() {
    if (confirm('确定要清除所有数据吗？此操作不可恢复。')) {
        fetch('/api/data/clear', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                addNotification('所有数据已清除', 'success');
                loadScanHistory();
                loadDashboardStats();
            } else {
                addNotification('清除失败: ' + data.message, 'error');
            }
        });
    }
}

document.addEventListener('click', function(e) {
    const notifBtn = e.target.closest('.notification-btn');
    const notifDropdown = document.getElementById('notificationDropdown');
    const userAvatar = e.target.closest('.user-avatar');
    const userDropdown = document.getElementById('userDropdown');
    
    if (!notifBtn && !e.target.closest('#notificationDropdown')) {
        notifDropdown.style.display = 'none';
    }
    if (!userAvatar && !e.target.closest('#userDropdown')) {
        userDropdown.style.display = 'none';
    }
});

function switchSettingsTab(tab, event) {
    if (event) event.preventDefault();
    
    document.querySelectorAll('.settings-nav-item').forEach(item => {
        item.classList.remove('active');
    });
    document.querySelector(`[data-settings-tab="${tab}"]`).classList.add('active');
    
    document.querySelectorAll('.settings-tab-content').forEach(content => {
        content.style.display = 'none';
    });
    
    const tabMap = {
        'general': 'settingsGeneral',
        'scan': 'settingsScan',
        'account': 'settingsAccount',
        'data': 'settingsData',
        'about': 'settingsAbout'
    };
    
    document.getElementById(tabMap[tab]).style.display = 'block';
    
    if (tab === 'data') {
        loadStorageStats();
    }
}

function loadStorageStats() {
    fetch('/api/stats')
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            document.getElementById('statsTotalScans').textContent = data.stats.total_scans || 0;
            document.getElementById('statsTotalVulns').textContent = (data.stats.critical_vulns || 0) + (data.stats.high_vulns || 0) + (data.stats.medium_vulns || 0) + (data.stats.low_vulns || 0);
        }
    });
    
    fetch('/api/scan/history')
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            document.getElementById('statsHistoryCount').textContent = data.scans ? data.scans.length : 0;
        }
    });
    
    fetch('/api/scan/active')
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            document.getElementById('statsActiveScans').textContent = data.scans ? data.scans.length : 0;
        }
    });
}

function changePassword() {
    const currentPassword = document.getElementById('settingCurrentPassword').value;
    const newPassword = document.getElementById('settingNewPassword').value;
    const confirmPassword = document.getElementById('settingConfirmPassword').value;
    
    if (!currentPassword) {
        addNotification('请输入当前密码', 'error');
        return;
    }
    
    if (!newPassword || newPassword.length < 6) {
        addNotification('新密码长度至少6位', 'error');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        addNotification('两次输入的密码不一致', 'error');
        return;
    }
    
    fetch('/api/settings/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            current_password: currentPassword,
            password: newPassword 
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            addNotification('密码修改成功', 'success');
            document.getElementById('settingCurrentPassword').value = '';
            document.getElementById('settingNewPassword').value = '';
            document.getElementById('settingConfirmPassword').value = '';
        } else {
            addNotification('密码修改失败: ' + data.message, 'error');
        }
    })
    .catch(error => {
        addNotification('密码修改失败: ' + error.message, 'error');
    });
}

function initToggleSwitches() {
    document.querySelectorAll('.toggle-switch input').forEach(toggle => {
        toggle.addEventListener('change', function() {
            const slider = this.nextElementSibling;
            if (this.checked) {
                slider.style.background = '#22C55E';
            } else {
                slider.style.background = 'rgba(255,255,255,0.1)';
            }
        });
        
        if (toggle.checked) {
            toggle.nextElementSibling.style.background = '#22C55E';
        }
    });
}

document.addEventListener('DOMContentLoaded', function() {
    initToggleSwitches();
    loadSettings();
});
