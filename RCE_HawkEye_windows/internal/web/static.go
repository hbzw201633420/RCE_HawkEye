package web

var customCSS = `
:root {
    --primary-color: #0f172a;
    --secondary-color: #1e293b;
    --accent-green: #22C55E;
    --accent-cyan: #06B6D4;
    --accent-yellow: #F59E0B;
    --accent-red: #EF4444;
    --accent-purple: #A855F7;
    --text-primary: #f8fafc;
    --text-secondary: rgba(248, 250, 252, 0.6);
    --text-muted: rgba(248, 250, 252, 0.4);
    --border-color: rgba(248, 250, 252, 0.1);
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Fira Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    color: var(--text-primary);
    min-height: 100vh;
    display: flex;
}

.sidebar {
    width: 240px;
    background: rgba(15, 23, 42, 0.8);
    backdrop-filter: blur(20px);
    border-right: 1px solid var(--border-color);
    padding: 20px 12px;
    position: fixed;
    height: 100vh;
    overflow-y: auto;
}

.sidebar-logo {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 8px;
    margin-bottom: 24px;
}

.sidebar-logo svg {
    width: 32px;
    height: 32px;
    color: var(--accent-green);
}

.sidebar-logo h1 {
    font-size: 18px;
    font-weight: 700;
    color: var(--text-primary);
}

.sidebar-nav {
    list-style: none;
}

.sidebar-nav li {
    margin-bottom: 2px;
}

.sidebar-nav a {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 12px;
    border-radius: 8px;
    color: var(--text-secondary);
    text-decoration: none;
    transition: all 0.2s ease;
    font-size: 14px;
    cursor: pointer;
}

.sidebar-nav a svg {
    width: 18px;
    height: 18px;
}

.sidebar-nav a:hover {
    background: rgba(34, 197, 94, 0.1);
    color: var(--text-primary);
}

.sidebar-nav a.active {
    background: rgba(34, 197, 94, 0.15);
    color: var(--accent-green);
}

.main-content {
    flex: 1;
    margin-left: 240px;
    padding: 20px;
    min-height: 100vh;
}

.main-content section {
    display: none;
}

.main-content section:first-of-type {
    display: block;
}

.main-content section.active {
    display: block !important;
}

.top-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border-color);
}

.page-title h2 {
    font-size: 20px;
    font-weight: 600;
}

.user-menu {
    display: flex;
    align-items: center;
    gap: 12px;
}

.user-menu select {
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 6px 10px;
    color: var(--text-primary);
    font-size: 12px;
    cursor: pointer;
}

.alert-icon {
    position: relative;
    cursor: pointer;
    padding: 8px;
    border-radius: 8px;
    transition: all 0.2s ease;
}

.alert-icon:hover {
    background: rgba(239, 68, 68, 0.1);
}

.alert-badge {
    position: absolute;
    top: -2px;
    right: -2px;
    min-width: 16px;
    height: 16px;
    background: var(--accent-red);
    border-radius: 8px;
    font-size: 10px;
    font-weight: 600;
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    padding: 0 4px;
}

.user-avatar {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    background: linear-gradient(135deg, var(--accent-green), #16A34A);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 600;
    font-size: 14px;
    cursor: pointer;
    position: relative;
}

.user-dropdown {
    display: none;
    position: absolute;
    top: 46px;
    right: 20px;
    background: rgba(30, 41, 59, 0.95);
    backdrop-filter: blur(20px);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    min-width: 160px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
    z-index: 100;
}

.user-dropdown.show {
    display: block;
}

.user-info {
    padding: 12px;
    border-bottom: 1px solid var(--border-color);
}

.user-name {
    font-weight: 600;
    margin-bottom: 2px;
    font-size: 14px;
}

.user-role {
    font-size: 11px;
    color: var(--text-muted);
}

.logout-link {
    display: block;
    padding: 10px 12px;
    color: var(--text-secondary);
    text-decoration: none;
    transition: all 0.2s ease;
    font-size: 13px;
}

.logout-link:hover {
    background: rgba(239, 68, 68, 0.1);
    color: var(--accent-red);
}

.glass-card {
    background: rgba(30, 41, 59, 0.6);
    backdrop-filter: blur(20px);
    border: 1px solid var(--border-color);
    border-radius: 12px;
}

.card {
    background: rgba(30, 41, 59, 0.6);
    backdrop-filter: blur(20px);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    margin-bottom: 16px;
}

.card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 20px;
    border-bottom: 1px solid var(--border-color);
}

.card-header h3 {
    font-size: 14px;
    font-weight: 600;
}

.card-body {
    padding: 16px 20px;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 20px;
}

.stat-card {
    padding: 20px;
}

.stat-card-header {
    display: flex;
    align-items: center;
    gap: 12px;
}

.stat-card-icon {
    width: 42px;
    height: 42px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
}

.stat-card-icon.green {
    background: rgba(34, 197, 94, 0.15);
    color: var(--accent-green);
}

.stat-card-icon.red {
    background: rgba(239, 68, 68, 0.15);
    color: var(--accent-red);
}

.stat-card-icon.yellow {
    background: rgba(245, 158, 11, 0.15);
    color: var(--accent-yellow);
}

.stat-card-icon.cyan {
    background: rgba(6, 182, 212, 0.15);
    color: var(--accent-cyan);
}

.stat-card-info {
    display: flex;
    flex-direction: column;
}

.stat-card-label {
    font-size: 12px;
    color: var(--text-secondary);
}

.stat-card-value {
    font-size: 28px;
    font-weight: 700;
}

.stat-card-trend {
    display: flex;
    align-items: center;
    gap: 4px;
    margin-top: 12px;
    font-size: 12px;
}

.stat-card-trend.up {
    color: var(--accent-green);
}

.stat-card-trend.down {
    color: var(--accent-red);
}

.dashboard-grid {
    display: grid;
    grid-template-columns: 1fr 320px;
    gap: 20px;
}

.dashboard-main {
    display: flex;
    flex-direction: column;
    gap: 16px;
}

.dashboard-sidebar {
    display: flex;
    flex-direction: column;
    gap: 16px;
}

.chart-container {
    height: 200px;
}

.chart-container canvas {
    width: 100% !important;
    height: 100% !important;
}

.status-badge {
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
}

.status-badge.online {
    background: rgba(34, 197, 94, 0.15);
    color: var(--accent-green);
}

.status-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.status-item {
    display: flex;
    align-items: center;
    gap: 12px;
}

.status-label {
    font-size: 12px;
    color: var(--text-secondary);
    width: 80px;
}

.status-bar-container {
    flex: 1;
    height: 6px;
    background: rgba(0, 0, 0, 0.3);
    border-radius: 3px;
    overflow: hidden;
}

.status-bar {
    height: 100%;
    background: linear-gradient(90deg, var(--accent-green), var(--accent-cyan));
    border-radius: 3px;
    transition: width 0.3s ease;
}

.status-bar.cyan {
    background: linear-gradient(90deg, var(--accent-cyan), var(--accent-purple));
}

.status-bar.purple {
    background: linear-gradient(90deg, var(--accent-purple), #C084FC);
}

.status-bar.yellow {
    background: linear-gradient(90deg, var(--accent-yellow), #FBBF24);
}

.status-value {
    font-size: 12px;
    font-weight: 600;
    width: 60px;
    text-align: right;
}

.quick-actions {
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.quick-action-btn {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    color: var(--text-secondary);
    text-decoration: none;
    transition: all 0.2s ease;
    font-size: 13px;
    cursor: pointer;
}

.quick-action-btn:hover {
    background: rgba(34, 197, 94, 0.1);
    border-color: var(--accent-green);
    color: var(--text-primary);
}

.activity-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.activity-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 8px;
}

.activity-icon {
    width: 32px;
    height: 32px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
}

.activity-icon.green {
    background: rgba(34, 197, 94, 0.15);
    color: var(--accent-green);
}

.activity-icon.red {
    background: rgba(239, 68, 68, 0.15);
    color: var(--accent-red);
}

.activity-icon.yellow {
    background: rgba(245, 158, 11, 0.15);
    color: var(--accent-yellow);
}

.activity-content {
    flex: 1;
    display: flex;
    flex-direction: column;
}

.activity-title {
    font-size: 13px;
    font-weight: 500;
}

.activity-desc {
    font-size: 12px;
    color: var(--text-muted);
}

.activity-time {
    font-size: 11px;
    color: var(--text-muted);
}

.scanner-layout {
    display: grid;
    grid-template-columns: 1fr 400px;
    gap: 20px;
}

.scan-config-panel {
    padding: 20px;
}

.panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}

.panel-title {
    font-size: 16px;
    font-weight: 600;
}

.version-badge {
    font-size: 11px;
    color: var(--text-muted);
    padding: 3px 6px;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 4px;
}

.config-tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 20px;
    flex-wrap: wrap;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 12px;
}

.config-tab {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 12px;
    background: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
    color: var(--text-secondary);
    font-size: 12px;
    cursor: pointer;
    transition: all 0.2s ease;
}

.config-tab svg {
    width: 14px;
    height: 14px;
}

.config-tab:hover {
    background: rgba(34, 197, 94, 0.1);
    color: var(--text-primary);
}

.config-tab.active {
    background: rgba(34, 197, 94, 0.15);
    border-color: var(--accent-green);
    color: var(--accent-green);
}

.config-panel {
    display: none;
}

.config-panel.active {
    display: block;
}

.form-row {
    display: flex;
    gap: 12px;
    margin-bottom: 16px;
}

.form-group {
    flex: 1;
}

.form-group label {
    display: block;
    margin-bottom: 6px;
    font-size: 12px;
    font-weight: 500;
    color: var(--text-secondary);
}

.input-field {
    width: 100%;
    padding: 10px 12px;
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    color: var(--text-primary);
    font-size: 13px;
    transition: all 0.2s ease;
}

.input-field:focus {
    outline: none;
    border-color: var(--accent-green);
    box-shadow: 0 0 0 2px rgba(34, 197, 94, 0.1);
}

.input-field::placeholder {
    color: var(--text-muted);
}

.input-field.textarea {
    resize: vertical;
    min-height: 80px;
    font-family: 'Fira Code', monospace;
}

select.input-field {
    cursor: pointer;
}

.checkbox-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
}

.checkbox-label {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--text-secondary);
    cursor: pointer;
}

.checkbox-label input {
    accent-color: var(--accent-green);
}

.tech-stack-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 8px;
}

.proxy-config {
    background: rgba(0, 0, 0, 0.2);
    padding: 12px;
    border-radius: 8px;
    margin-top: 8px;
}

.encoder-tool {
    background: rgba(0, 0, 0, 0.2);
    padding: 12px;
    border-radius: 8px;
}

.encoder-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin: 12px 0;
}

.btn-small {
    padding: 6px 12px;
    background: rgba(34, 197, 94, 0.15);
    border: 1px solid var(--accent-green);
    border-radius: 6px;
    color: var(--accent-green);
    font-size: 11px;
    cursor: pointer;
    transition: all 0.2s ease;
}

.btn-small:hover {
    background: rgba(34, 197, 94, 0.25);
}

.btn-warning {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 14px;
    background: rgba(245, 158, 11, 0.15);
    border: 1px solid var(--accent-yellow);
    border-radius: 6px;
    color: var(--accent-yellow);
    font-size: 12px;
    cursor: pointer;
    transition: all 0.2s ease;
}

.btn-warning:hover {
    background: rgba(245, 158, 11, 0.25);
}

.btn-danger {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 14px;
    background: rgba(239, 68, 68, 0.15);
    border: 1px solid var(--accent-red);
    border-radius: 6px;
    color: var(--accent-red);
    font-size: 12px;
    cursor: pointer;
    transition: all 0.2s ease;
}

.btn-danger:hover {
    background: rgba(239, 68, 68, 0.25);
}

.settings-tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 20px;
    flex-wrap: wrap;
}

.settings-tab {
    padding: 10px 16px;
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    color: var(--text-secondary);
    font-size: 13px;
    cursor: pointer;
    transition: all 0.2s ease;
}

.settings-tab:hover {
    background: rgba(34, 197, 94, 0.1);
    color: var(--text-primary);
}

.settings-tab.active {
    background: rgba(34, 197, 94, 0.15);
    border-color: var(--accent-green);
    color: var(--accent-green);
}

.settings-panel {
    display: none;
}

.settings-panel.active {
    display: block;
}

.reset-actions {
    display: flex;
    flex-direction: column;
    gap: 16px;
}

.reset-action-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 8px;
}

.reset-action-info h4 {
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 4px;
}

.reset-action-info p {
    font-size: 12px;
    color: var(--text-muted);
}

.warning-text {
    color: var(--accent-yellow);
    font-size: 13px;
    margin-bottom: 16px;
    padding: 12px;
    background: rgba(245, 158, 11, 0.1);
    border-radius: 8px;
    border-left: 3px solid var(--accent-yellow);
}

.dict-stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
}

.dict-stat-item {
    text-align: center;
    padding: 12px;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 8px;
}

.dict-stat-label {
    display: block;
    font-size: 11px;
    color: var(--text-muted);
    margin-bottom: 4px;
}

.dict-stat-value {
    display: block;
    font-size: 20px;
    font-weight: 600;
    color: var(--accent-green);
}

.setting-hint {
    display: block;
    font-size: 10px;
    color: var(--text-muted);
    margin-top: 4px;
}

.action-bar {
    display: flex;
    gap: 12px;
    margin-top: 20px;
    padding-top: 16px;
    border-top: 1px solid var(--border-color);
}

.btn-primary {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 10px 20px;
    background: linear-gradient(135deg, var(--accent-green), #16A34A);
    border: none;
    border-radius: 8px;
    color: white;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
}

.btn-primary:hover {
    transform: translateY(-1px);
    box-shadow: 0 6px 16px rgba(34, 197, 94, 0.3);
}

.btn-primary:disabled {
    opacity: 0.7;
    cursor: not-allowed;
    transform: none;
}

.btn-secondary {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 10px 16px;
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    color: var(--text-secondary);
    font-size: 13px;
    cursor: pointer;
    transition: all 0.2s ease;
}

.btn-secondary:hover {
    background: rgba(34, 197, 94, 0.1);
    border-color: var(--accent-green);
    color: var(--text-primary);
}

.progress-section {
    margin-top: 16px;
    padding: 16px;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 10px;
}

.progress-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: 8px;
    font-size: 13px;
}

.progress-bar-container {
    height: 6px;
    background: rgba(0, 0, 0, 0.3);
    border-radius: 3px;
    overflow: hidden;
    margin-bottom: 8px;
}

.progress-bar {
    height: 100%;
    background: linear-gradient(90deg, var(--accent-green), var(--accent-cyan));
    border-radius: 3px;
    transition: width 0.3s ease;
}

.progress-status {
    font-size: 12px;
    color: var(--text-muted);
}

.scan-results-panel {
    padding: 20px;
}

.results-tabs {
    display: flex;
    gap: 6px;
}

.results-tab {
    padding: 6px 12px;
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    color: var(--text-secondary);
    font-size: 11px;
    cursor: pointer;
    transition: all 0.2s ease;
}

.results-tab.active {
    background: rgba(34, 197, 94, 0.15);
    border-color: var(--accent-green);
    color: var(--accent-green);
}

.vulnerability-list {
    max-height: 400px;
    overflow-y: auto;
}

.empty-state {
    text-align: center;
    padding: 40px 16px;
    color: var(--text-muted);
}

.empty-state svg {
    margin-bottom: 12px;
    opacity: 0.5;
}

.empty-state p {
    margin-bottom: 6px;
    font-size: 13px;
}

.empty-state .sub-text {
    font-size: 12px;
}

.vuln-item {
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    padding: 14px;
    margin-bottom: 10px;
}

.vuln-item.critical {
    border-left: 3px solid var(--accent-red);
}

.vuln-item.high {
    border-left: 3px solid var(--accent-yellow);
}

.vuln-item.medium {
    border-left: 3px solid var(--accent-cyan);
}

.vuln-item.low {
    border-left: 3px solid var(--accent-green);
}

.vuln-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 6px;
}

.vuln-target {
    font-weight: 600;
    word-break: break-all;
    font-size: 13px;
}

.vuln-severity {
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
}

.vuln-severity.critical {
    background: rgba(239, 68, 68, 0.2);
    color: var(--accent-red);
}

.vuln-severity.high {
    background: rgba(245, 158, 11, 0.2);
    color: var(--accent-yellow);
}

.vuln-severity.medium {
    background: rgba(6, 182, 212, 0.2);
    color: var(--accent-cyan);
}

.vuln-severity.low {
    background: rgba(34, 197, 94, 0.2);
    color: var(--accent-green);
}

.vuln-param {
    font-size: 12px;
    color: var(--text-secondary);
    margin-bottom: 6px;
}

.vuln-payload {
    background: rgba(0, 0, 0, 0.3);
    padding: 8px;
    border-radius: 4px;
    font-family: 'Fira Code', monospace;
    font-size: 11px;
    word-break: break-all;
}

.section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
}

.section-header h2 {
    font-size: 18px;
    font-weight: 600;
}

.section-actions {
    display: flex;
    gap: 8px;
}

.monitoring-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}

.monitoring-title {
    display: flex;
    align-items: center;
    gap: 12px;
}

.monitoring-title h2 {
    font-size: 18px;
    font-weight: 600;
}

.realtime-badge {
    padding: 4px 10px;
    background: rgba(34, 197, 94, 0.15);
    color: var(--accent-green);
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
}

.time-range-selector {
    display: flex;
    gap: 6px;
}

.time-range-btn {
    padding: 6px 12px;
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    color: var(--text-secondary);
    font-size: 11px;
    cursor: pointer;
    transition: all 0.2s ease;
}

.time-range-btn:hover {
    background: rgba(34, 197, 94, 0.1);
    color: var(--text-primary);
}

.time-range-btn.active {
    background: rgba(34, 197, 94, 0.15);
    border-color: var(--accent-green);
    color: var(--accent-green);
}

.monitoring-stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 20px;
}

.monitor-stat {
    padding: 20px;
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
}

.monitor-stat-icon {
    width: 48px;
    height: 48px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 12px;
}

.monitor-stat-icon.green {
    background: rgba(34, 197, 94, 0.15);
    color: var(--accent-green);
}

.monitor-stat-icon.cyan {
    background: rgba(6, 182, 212, 0.15);
    color: var(--accent-cyan);
}

.monitor-stat-icon.yellow {
    background: rgba(245, 158, 11, 0.15);
    color: var(--accent-yellow);
}

.monitor-stat-icon.red {
    background: rgba(239, 68, 68, 0.15);
    color: var(--accent-red);
}

.monitor-stat-icon.purple {
    background: rgba(168, 85, 247, 0.15);
    color: var(--accent-purple);
}

.monitor-stat-value {
    font-size: 28px;
    font-weight: 700;
    margin-bottom: 4px;
}

.monitor-stat-label {
    font-size: 12px;
    color: var(--text-secondary);
}

.monitoring-charts {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 16px;
}

.chart-card {
    padding: 20px;
}

.chart-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
}

.chart-title {
    font-size: 14px;
    font-weight: 600;
}

.chart-container-large {
    height: 180px;
}

.chart-container-large canvas {
    width: 100% !important;
    height: 100% !important;
}

.scan-stats-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 16px;
}

.scan-stat-item {
    text-align: center;
    padding: 12px;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 10px;
}

.scan-stat-item .scan-stat-value {
    font-size: 24px;
    font-weight: 700;
    margin-bottom: 4px;
}

.scan-stat-item .scan-stat-value.running {
    color: var(--accent-cyan);
}

.scan-stat-item .scan-stat-value.completed {
    color: var(--accent-green);
}

.scan-stat-item .scan-stat-value.pending {
    color: var(--accent-yellow);
}

.scan-stat-item .scan-stat-label {
    font-size: 11px;
    color: var(--text-secondary);
}

.reports-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 12px;
}

.report-card {
    padding: 16px;
    background: rgba(30, 41, 59, 0.6);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    transition: all 0.2s ease;
}

.report-card:hover {
    border-color: var(--accent-green);
    background: rgba(34, 197, 94, 0.05);
}

.report-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
}

.report-card-name {
    font-size: 13px;
    font-weight: 600;
    word-break: break-all;
}

.report-card-badge {
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
}

.report-card-badge.html {
    background: rgba(34, 197, 94, 0.15);
    color: var(--accent-green);
}

.report-card-badge.json {
    background: rgba(6, 182, 212, 0.15);
    color: var(--accent-cyan);
}

.report-card-badge.md {
    background: rgba(245, 158, 11, 0.15);
    color: var(--accent-yellow);
}

.report-card-meta {
    font-size: 11px;
    color: var(--text-muted);
    margin-bottom: 12px;
}

.report-card-actions {
    display: flex;
    gap: 8px;
}

.report-card-actions a,
.report-card-actions button {
    padding: 6px 12px;
    font-size: 11px;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s ease;
    text-decoration: none;
    background: rgba(34, 197, 94, 0.15);
    border: 1px solid var(--accent-green);
    color: var(--accent-green);
}

.report-card-actions a:hover,
.report-card-actions button:hover {
    background: rgba(34, 197, 94, 0.25);
}

.history-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.history-item {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 16px;
    background: rgba(30, 41, 59, 0.6);
    border: 1px solid var(--border-color);
    border-radius: 10px;
}

.history-item:hover {
    border-color: var(--accent-green);
}

.history-icon {
    width: 40px;
    height: 40px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(34, 197, 94, 0.15);
    color: var(--accent-green);
}

.history-content {
    flex: 1;
}

.history-target {
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 4px;
}

.history-meta {
    font-size: 12px;
    color: var(--text-muted);
}

.history-status {
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
}

.history-status.completed {
    background: rgba(34, 197, 94, 0.15);
    color: var(--accent-green);
}

.history-status.running {
    background: rgba(6, 182, 212, 0.15);
    color: var(--accent-cyan);
}

.history-status.error {
    background: rgba(239, 68, 68, 0.15);
    color: var(--accent-red);
}

.settings-container {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 20px;
    margin-bottom: 20px;
}

.settings-card {
    padding: 20px;
}

.settings-card-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 20px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border-color);
}

.settings-card-header svg {
    color: var(--accent-green);
}

.settings-card-header h3 {
    font-size: 15px;
    font-weight: 600;
}

.settings-card-body {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.setting-row {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
}

.setting-item {
    display: flex;
    flex-direction: column;
}

.setting-item.full-width {
    grid-column: span 2;
}

.setting-item label {
    display: block;
    margin-bottom: 6px;
    font-size: 12px;
    font-weight: 500;
    color: var(--text-secondary);
}

.settings-actions {
    display: flex;
    gap: 12px;
    justify-content: flex-end;
}

.exploit-container {
    display: grid;
    grid-template-columns: 280px 1fr;
    gap: 16px;
    height: calc(100vh - 140px);
}

.exploit-sidebar {
    display: flex;
    flex-direction: column;
    overflow: hidden;
}

.exploit-sidebar-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border-color);
    margin-bottom: 12px;
}

.exploit-sidebar-header h3 {
    font-size: 14px;
    font-weight: 600;
}

.vuln-filter {
    margin-bottom: 12px;
}

.vuln-select-list {
    flex: 1;
    overflow-y: auto;
}

.vuln-select-item {
    padding: 10px 12px;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 8px;
    margin-bottom: 8px;
    cursor: pointer;
    transition: all 0.2s ease;
    border-left: 3px solid transparent;
}

.vuln-select-item:hover {
    background: rgba(34, 197, 94, 0.1);
}

.vuln-select-item.active {
    background: rgba(34, 197, 94, 0.15);
    border-left-color: var(--accent-green);
}

.vuln-select-item.critical {
    border-left-color: var(--accent-red);
}

.vuln-select-item.high {
    border-left-color: var(--accent-yellow);
}

.vuln-select-item.medium {
    border-left-color: var(--accent-cyan);
}

.vuln-select-item .vuln-item-url {
    font-size: 12px;
    font-weight: 500;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.vuln-select-item .vuln-item-param {
    font-size: 10px;
    color: var(--text-muted);
    margin-top: 4px;
}

.vuln-select-item .vuln-item-severity {
    display: inline-block;
    font-size: 9px;
    padding: 2px 6px;
    border-radius: 4px;
    margin-top: 4px;
    text-transform: uppercase;
}

.vuln-select-item .vuln-item-severity.critical {
    background: rgba(239, 68, 68, 0.2);
    color: var(--accent-red);
}

.vuln-select-item .vuln-item-severity.high {
    background: rgba(245, 158, 11, 0.2);
    color: var(--accent-yellow);
}

.vuln-select-item .vuln-item-severity.medium {
    background: rgba(6, 182, 212, 0.2);
    color: var(--accent-cyan);
}

.exploit-main {
    display: flex;
    flex-direction: column;
    overflow: hidden;
}

.exploit-tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 12px;
}

.exploit-tab {
    padding: 10px 16px;
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    color: var(--text-secondary);
    font-size: 12px;
    cursor: pointer;
    transition: all 0.2s ease;
}

.exploit-tab:hover {
    background: rgba(34, 197, 94, 0.1);
    color: var(--text-primary);
}

.exploit-tab.active {
    background: rgba(34, 197, 94, 0.15);
    border-color: var(--accent-green);
    color: var(--accent-green);
}

.exploit-panel {
    display: none;
    flex: 1;
    overflow: hidden;
}

.exploit-panel.active {
    display: flex;
    flex-direction: column;
    gap: 16px;
}

.cmd-container {
    display: flex;
    flex-direction: column;
    height: 100%;
    overflow: hidden;
}

.cmd-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 16px;
    background: rgba(0, 0, 0, 0.3);
    border-radius: 8px 8px 0 0;
}

.cmd-target-info, .cmd-os-info {
    display: flex;
    align-items: center;
    gap: 8px;
}

.cmd-label {
    font-size: 11px;
    color: var(--text-muted);
}

.cmd-target-url {
    font-size: 12px;
    font-weight: 500;
    color: var(--accent-green);
}

.input-field-small {
    padding: 4px 8px;
    font-size: 11px;
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    color: var(--text-primary);
}

.cmd-output {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
    background: rgba(0, 0, 0, 0.4);
    font-family: 'Fira Code', monospace;
    font-size: 12px;
    line-height: 1.6;
}

.cmd-welcome {
    color: var(--text-muted);
    text-align: center;
    padding: 40px;
}

.cmd-line {
    margin-bottom: 4px;
}

.cmd-line.input {
    color: var(--accent-green);
}

.cmd-line.output {
    color: var(--text-primary);
    white-space: pre-wrap;
    word-break: break-all;
}

.cmd-line.error {
    color: var(--accent-red);
}

.cmd-input-area {
    padding: 12px;
    background: rgba(0, 0, 0, 0.3);
    border-radius: 0 0 8px 8px;
}

.cmd-quick-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-bottom: 10px;
}

.cmd-quick-btn {
    padding: 4px 10px;
    background: rgba(34, 197, 94, 0.1);
    border: 1px solid rgba(34, 197, 94, 0.3);
    border-radius: 4px;
    color: var(--accent-green);
    font-size: 10px;
    font-family: 'Fira Code', monospace;
    cursor: pointer;
    transition: all 0.2s ease;
}

.cmd-quick-btn:hover {
    background: rgba(34, 197, 94, 0.2);
}

.cmd-input-row {
    display: flex;
    align-items: center;
    gap: 8px;
}

.cmd-prompt {
    color: var(--accent-green);
    font-family: 'Fira Code', monospace;
    font-size: 14px;
}

.cmd-input {
    flex: 1;
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 10px 12px;
    color: var(--text-primary);
    font-family: 'Fira Code', monospace;
    font-size: 13px;
    resize: none;
}

.cmd-input:focus {
    outline: none;
    border-color: var(--accent-green);
}

.shell-config, .shell-output, .webshell-config, .webshell-preview, .logs-container {
    padding: 16px;
}

.shell-config-header, .shell-output-header, .webshell-config-header, .webshell-preview-header, .logs-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border-color);
}

.shell-config-header h3, .shell-output-header h3, .webshell-config-header h3, .webshell-preview-header h3, .logs-header h3 {
    font-size: 14px;
    font-weight: 600;
}

.shell-type-grid, .webshell-type-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 8px;
}

.shell-type-option, .webshell-type-option {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 12px;
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s ease;
}

.shell-type-option:hover, .webshell-type-option:hover {
    background: rgba(34, 197, 94, 0.1);
}

.shell-type-option input:checked + span, .webshell-type-option input:checked + span {
    color: var(--accent-green);
}

.shell-type-option input:checked, .webshell-type-option input:checked {
    accent-color: var(--accent-green);
}

.port-quick-select {
    display: flex;
    gap: 4px;
    margin-top: 6px;
}

.port-quick-select button {
    padding: 4px 8px;
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    color: var(--text-secondary);
    font-size: 10px;
    cursor: pointer;
    transition: all 0.2s ease;
}

.port-quick-select button:hover {
    background: rgba(34, 197, 94, 0.1);
    color: var(--accent-green);
}

.shell-command-display, .webshell-code-display {
    background: rgba(0, 0, 0, 0.4);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 16px;
}

.shell-command-display pre, .webshell-code-display pre {
    font-family: 'Fira Code', monospace;
    font-size: 12px;
    color: var(--accent-green);
    white-space: pre-wrap;
    word-break: break-all;
    margin: 0;
}

.shell-listen-section {
    padding: 12px;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 8px;
}

.shell-listen-section h4 {
    font-size: 12px;
    margin-bottom: 8px;
    color: var(--text-secondary);
}

.listen-cmd-row {
    display: flex;
    align-items: center;
    gap: 8px;
}

.listen-cmd-row code {
    flex: 1;
    padding: 8px 12px;
    background: rgba(0, 0, 0, 0.3);
    border-radius: 6px;
    font-family: 'Fira Code', monospace;
    font-size: 12px;
    color: var(--accent-cyan);
}

.password-input-row {
    display: flex;
    align-items: center;
    gap: 12px;
}

.password-input-row .input-field {
    flex: 1;
}

.password-strength {
    display: flex;
    align-items: center;
    gap: 8px;
}

.strength-bar {
    width: 60px;
    height: 4px;
    background: rgba(255, 255, 255, 0.1);
    border-radius: 2px;
    overflow: hidden;
}

.strength-bar::before {
    content: '';
    display: block;
    height: 100%;
    width: 33%;
    background: var(--accent-red);
    transition: all 0.3s ease;
}

.password-strength.weak .strength-bar::before {
    width: 33%;
    background: var(--accent-red);
}

.password-strength.medium .strength-bar::before {
    width: 66%;
    background: var(--accent-yellow);
}

.password-strength.strong .strength-bar::before {
    width: 100%;
    background: var(--accent-green);
}

.strength-text {
    font-size: 10px;
    color: var(--text-muted);
}

.webshell-actions {
    display: flex;
    gap: 8px;
}

.webshell-write-config {
    margin-top: 16px;
    padding: 12px;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 8px;
}

.webshell-write-config h4 {
    font-size: 12px;
    margin-bottom: 12px;
    color: var(--text-secondary);
}

.code-textarea {
    font-family: 'Fira Code', monospace;
    font-size: 12px;
}

.logs-actions {
    display: flex;
    gap: 8px;
}

.logs-filter {
    margin-bottom: 12px;
}

.logs-list {
    max-height: 500px;
    overflow-y: auto;
}

.log-item {
    padding: 12px;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 8px;
    margin-bottom: 8px;
    border-left: 3px solid var(--accent-green);
}

.log-item.cmd {
    border-left-color: var(--accent-cyan);
}

.log-item.shell {
    border-left-color: var(--accent-yellow);
}

.log-item.webshell {
    border-left-color: var(--accent-purple);
}

.log-item-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 6px;
}

.log-item-type {
    font-size: 10px;
    padding: 2px 6px;
    border-radius: 4px;
    background: rgba(34, 197, 94, 0.2);
    color: var(--accent-green);
}

.log-item-time {
    font-size: 10px;
    color: var(--text-muted);
}

.log-item-content {
    font-size: 12px;
    font-family: 'Fira Code', monospace;
    color: var(--text-secondary);
    word-break: break-all;
}

.log-item-target {
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 6px;
}

@media (max-width: 1200px) {
    .exploit-container {
        grid-template-columns: 1fr;
        height: auto;
    }
    
    .exploit-sidebar {
        max-height: 300px;
    }
    
    .shell-type-grid, .webshell-type-grid {
        grid-template-columns: repeat(2, 1fr);
    }
}

@media (max-width: 768px) {
    .exploit-tabs {
        flex-wrap: wrap;
    }
    
    .shell-type-grid, .webshell-type-grid {
        grid-template-columns: 1fr;
    }
}

.modal {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.7);
    z-index: 1000;
    align-items: center;
    justify-content: center;
}

.modal.show {
    display: flex;
}

.modal-content {
    background: rgba(30, 41, 59, 0.98);
    backdrop-filter: blur(20px);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    width: 90%;
    max-width: 500px;
    max-height: 80vh;
    overflow: hidden;
}

.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 20px;
    border-bottom: 1px solid var(--border-color);
}

.modal-header h3 {
    font-size: 16px;
    font-weight: 600;
}

.modal-close {
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    padding: 4px;
    font-size: 20px;
    border-radius: 4px;
    transition: all 0.2s ease;
}

.modal-close:hover {
    background: rgba(239, 68, 68, 0.1);
    color: var(--accent-red);
}

.modal-body {
    padding: 16px;
    max-height: 400px;
    overflow-y: auto;
}

.modal-footer {
    display: flex;
    justify-content: flex-end;
    gap: 12px;
    padding: 16px 20px;
    border-top: 1px solid var(--border-color);
}

.text-muted {
    color: var(--text-muted);
    font-size: 13px;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

.loading-spinner {
    display: inline-block;
    width: 14px;
    height: 14px;
    border: 2px solid rgba(255,255,255,0.3);
    border-radius: 50%;
    border-top-color: white;
    animation: spin 1s linear infinite;
    margin-right: 6px;
    vertical-align: middle;
}

@keyframes spin {
    to { transform: rotate(360deg); }
}

@media (max-width: 1400px) {
    .scanner-layout {
        grid-template-columns: 1fr;
    }
    
    .settings-container {
        grid-template-columns: 1fr;
    }
}

@media (max-width: 1200px) {
    .stats-grid {
        grid-template-columns: repeat(2, 1fr);
    }
    
    .form-row.three-col {
        grid-template-columns: repeat(2, 1fr);
    }
    
    .monitoring-stats {
        grid-template-columns: repeat(2, 1fr);
    }
    
    .monitoring-charts {
        grid-template-columns: 1fr;
    }
    
    .scan-stats-grid {
        grid-template-columns: repeat(2, 1fr);
    }
    
    .dashboard-grid {
        grid-template-columns: 1fr;
    }
}

@media (max-width: 768px) {
    .sidebar {
        width: 56px;
        padding: 12px 4px;
    }
    
    .sidebar-logo h1,
    .sidebar-nav span {
        display: none;
    }
    
    .main-content {
        margin-left: 56px;
    }
    
    .stats-grid {
        grid-template-columns: 1fr;
    }
    
    .form-row {
        flex-direction: column;
    }
    
    .config-tabs {
        flex-direction: column;
    }
    
    .config-tab {
        justify-content: flex-start;
    }
    
    .monitoring-stats {
        grid-template-columns: 1fr;
    }
    
    .setting-row {
        grid-template-columns: 1fr;
    }
    
    .setting-item.full-width {
        grid-column: span 1;
    }
    
    .time-range-selector {
        flex-wrap: wrap;
    }
}

.history-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
}

.search-box {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
    min-width: 250px;
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 8px 12px;
    transition: all 0.2s ease;
}

.search-box:focus-within {
    border-color: var(--accent-green);
    background: rgba(34, 197, 94, 0.05);
}

.search-box svg {
    color: var(--text-muted);
    flex-shrink: 0;
}

.search-input {
    flex: 1;
    background: transparent;
    border: none;
    color: var(--text-primary);
    font-size: 13px;
    outline: none;
}

.search-input::placeholder {
    color: var(--text-muted);
}

.filter-group {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}

.filter-select {
    min-width: 120px;
    padding: 8px 12px;
}

.history-item {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 16px 20px;
    background: rgba(30, 41, 59, 0.6);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    cursor: pointer;
    transition: all 0.2s ease;
}

.history-item:hover {
    border-color: var(--accent-green);
    background: rgba(34, 197, 94, 0.05);
    transform: translateX(4px);
}

.history-item:last-child {
    margin-bottom: 0;
}

.history-icon {
    width: 44px;
    height: 44px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(34, 197, 94, 0.15);
    color: var(--accent-green);
    flex-shrink: 0;
}

.history-icon.cyan {
    background: rgba(6, 182, 212, 0.15);
    color: var(--accent-cyan);
}

.history-icon.red {
    background: rgba(239, 68, 68, 0.15);
    color: var(--accent-red);
}

.history-icon.yellow {
    background: rgba(245, 158, 11, 0.15);
    color: var(--accent-yellow);
}

.history-content {
    flex: 1;
    min-width: 0;
}

.history-target {
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 4px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.history-meta {
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 12px;
    color: var(--text-muted);
}

.history-meta-item {
    display: flex;
    align-items: center;
    gap: 4px;
}

.history-meta-item svg {
    width: 12px;
    height: 12px;
}

.history-status {
    padding: 6px 12px;
    border-radius: 16px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    flex-shrink: 0;
}

.history-status.completed {
    background: rgba(34, 197, 94, 0.15);
    color: var(--accent-green);
}

.history-status.running {
    background: rgba(6, 182, 212, 0.15);
    color: var(--accent-cyan);
    animation: pulse 1.5s ease-in-out infinite;
}

.history-status.error {
    background: rgba(239, 68, 68, 0.15);
    color: var(--accent-red);
}

.history-vuln-count {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    background: rgba(245, 158, 11, 0.15);
    border-radius: 8px;
    font-size: 12px;
    font-weight: 600;
    color: var(--accent-yellow);
    flex-shrink: 0;
}

.history-vuln-count.critical {
    background: rgba(239, 68, 68, 0.15);
    color: var(--accent-red);
}

.history-vuln-count svg {
    width: 14px;
    height: 14px;
}

.detail-section {
    margin-bottom: 20px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border-color);
}

.detail-section:last-child {
    margin-bottom: 0;
    padding-bottom: 0;
    border-bottom: none;
}

.detail-section h4 {
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 12px;
    color: var(--text-secondary);
    display: flex;
    align-items: center;
    gap: 8px;
}

.detail-section h4 svg {
    width: 16px;
    height: 16px;
    color: var(--accent-green);
}

.detail-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
}

.detail-item {
    display: flex;
    flex-direction: column;
    gap: 4px;
}

.detail-label {
    font-size: 11px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.detail-value {
    font-size: 14px;
    font-weight: 500;
}

.vuln-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.vuln-list-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 12px;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 8px;
    border-left: 3px solid var(--accent-green);
}

.vuln-list-item.critical {
    border-left-color: var(--accent-red);
}

.vuln-list-item.high {
    border-left-color: var(--accent-yellow);
}

.vuln-list-item.medium {
    border-left-color: var(--accent-cyan);
}

.vuln-list-item .vuln-severity {
    font-size: 10px;
    padding: 2px 6px;
    border-radius: 4px;
    text-transform: uppercase;
    font-weight: 600;
}

.vuln-list-item .vuln-type {
    flex: 1;
    font-size: 13px;
}

.vuln-list-item .vuln-param {
    font-size: 11px;
    color: var(--text-muted);
    font-family: 'Fira Code', monospace;
}

@media (max-width: 768px) {
    .history-toolbar {
        flex-direction: column;
        align-items: stretch;
    }
    
    .search-box {
        min-width: 100%;
    }
    
    .filter-group {
        width: 100%;
    }
    
    .filter-select {
        flex: 1;
    }
    
    .history-item {
        flex-wrap: wrap;
    }
    
    .history-status {
        order: -1;
        margin-left: auto;
    }
    
    .history-vuln-count {
        width: 100%;
        justify-content: center;
        margin-top: 8px;
    }
    
    .detail-grid {
        grid-template-columns: 1fr;
    }
}

.history-checkbox {
    width: 18px;
    height: 18px;
    cursor: pointer;
    accent-color: var(--accent-green);
    flex-shrink: 0;
}

.history-batch-actions {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 12px 20px;
    background: rgba(34, 197, 94, 0.1);
    border: 1px solid rgba(34, 197, 94, 0.3);
    border-radius: 12px;
    margin-bottom: 16px;
}

.selected-count {
    font-size: 14px;
    font-weight: 600;
    color: var(--accent-green);
}

.domain-link {
    cursor: pointer;
    transition: color 0.2s ease;
}

.domain-link:hover {
    color: var(--accent-green);
}

.export-options {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.export-option {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 16px;
    background: rgba(30, 41, 59, 0.8);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    cursor: pointer;
    transition: all 0.2s ease;
}

.export-option:hover {
    border-color: var(--accent-green);
    background: rgba(34, 197, 94, 0.05);
}

.export-option input[type="radio"] {
    accent-color: var(--accent-green);
}

.export-option input[type="radio"]:checked + .option-content {
    color: var(--accent-green);
}

.option-content {
    display: flex;
    flex-direction: column;
    gap: 4px;
}

.option-content strong {
    font-size: 14px;
}

.option-content small {
    font-size: 12px;
    color: var(--text-muted);
}

.monitoring-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    flex-wrap: wrap;
    gap: 16px;
}

.monitoring-title {
    display: flex;
    align-items: center;
    gap: 12px;
}

.monitoring-title h2 {
    margin: 0;
}

.realtime-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    background: rgba(34, 197, 94, 0.15);
    color: var(--accent-green);
    border-radius: 16px;
    font-size: 12px;
    font-weight: 600;
}

.realtime-badge::before {
    content: '';
    width: 6px;
    height: 6px;
    background: var(--accent-green);
    border-radius: 50%;
    animation: pulse 1.5s ease-in-out infinite;
}

.monitoring-controls {
    display: flex;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
}

.view-toggle {
    display: flex;
    background: rgba(30, 41, 59, 0.8);
    border-radius: 8px;
    padding: 4px;
    border: 1px solid var(--border-color);
}

.view-toggle-btn {
    padding: 8px 16px;
    background: transparent;
    border: none;
    color: var(--text-muted);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    border-radius: 6px;
    transition: all 0.2s ease;
}

.view-toggle-btn:hover {
    color: var(--text-primary);
}

.view-toggle-btn.active {
    background: var(--accent-green);
    color: white;
}

.monitor-stat-bar {
    height: 4px;
    background: rgba(248, 250, 252, 0.1);
    border-radius: 2px;
    margin-top: 8px;
    overflow: hidden;
}

.bar-fill {
    height: 100%;
    border-radius: 2px;
    transition: width 0.3s ease, background-color 0.3s ease;
}

.bar-fill.green { background: var(--accent-green); }
.bar-fill.cyan { background: var(--accent-cyan); }
.bar-fill.yellow { background: var(--accent-yellow); }
.bar-fill.red { background: var(--accent-red); }

.chart-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
}

.chart-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
    font-weight: 600;
    margin: 0;
}

.chart-title svg {
    color: var(--accent-green);
}

.chart-legend {
    display: flex;
    gap: 16px;
}

.legend-item {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--text-muted);
}

.legend-color {
    width: 12px;
    height: 3px;
    border-radius: 2px;
}

.legend-color.green { background: var(--accent-green); }
.legend-color.cyan { background: var(--accent-cyan); }
.legend-color.yellow { background: var(--accent-yellow); }
.legend-color.red { background: var(--accent-red); }

.chart-container {
    height: 200px;
    position: relative;
}

.monitoring-gauges {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
}

.gauge-card {
    padding: 24px;
    text-align: center;
}

.gauge-title {
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 16px;
    color: var(--text-secondary);
}

.gauge-container {
    width: 150px;
    height: 150px;
    margin: 0 auto 16px;
}

.gauge-value {
    font-size: 24px;
    font-weight: 700;
    color: var(--text-primary);
}

@media (max-width: 768px) {
    .monitoring-header {
        flex-direction: column;
        align-items: flex-start;
    }
    
    .monitoring-controls {
        width: 100%;
        justify-content: space-between;
    }
    
    .chart-container {
        height: 160px;
    }
    
    .gauge-container {
        width: 120px;
        height: 120px;
    }
}

.about-logo {
    text-align: center;
    padding: 24px 0;
    margin-bottom: 24px;
    border-bottom: 1px solid var(--border-color);
}

.about-logo svg {
    color: var(--accent-green);
    margin-bottom: 16px;
}

.about-logo h2 {
    font-size: 24px;
    font-weight: 700;
    margin-bottom: 8px;
}

.about-logo .version-info {
    color: var(--accent-cyan);
    font-size: 14px;
    font-weight: 600;
}

.about-info {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
    margin-bottom: 24px;
}

.about-info .info-item {
    text-align: center;
    padding: 16px;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 12px;
}

.about-info .info-label {
    display: block;
    font-size: 12px;
    color: var(--text-muted);
    margin-bottom: 8px;
}

.about-info .info-value {
    font-size: 14px;
    font-weight: 600;
}

.update-section {
    text-align: center;
    padding: 24px;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 12px;
    margin-bottom: 24px;
}

.update-status {
    margin-top: 16px;
    font-size: 14px;
}

.update-status .checking {
    color: var(--accent-cyan);
}

.update-status .up-to-date {
    color: var(--accent-green);
}

.update-status .error {
    color: var(--accent-red);
}

.update-status .update-available {
    display: flex;
    flex-direction: column;
    align-items: center;
}

.update-status .new-version {
    color: var(--accent-yellow);
    margin-bottom: 8px;
}

.about-links {
    display: flex;
    justify-content: center;
    gap: 16px;
}

.about-link {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 24px;
    background: rgba(30, 41, 59, 0.8);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    color: var(--text-primary);
    text-decoration: none;
    font-size: 14px;
    transition: all 0.2s ease;
}

.about-link:hover {
    border-color: var(--accent-green);
    background: rgba(34, 197, 94, 0.1);
}

@media (max-width: 768px) {
    .about-info {
        grid-template-columns: 1fr;
    }
    
    .about-links {
        flex-direction: column;
    }
}
`
