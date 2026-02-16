"""
RCE HawkEye Web API Server
Flask-based REST API for the web interface
完整实现所有终端功能
"""

import os
import sys
import json
import uuid
import time
import psutil
import threading
import asyncio
import platform
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, send_file
from functools import wraps
from urllib.parse import urlparse

if platform.system() == 'Windows':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rce_hawkeye import Scanner, Reporter
from rce_hawkeye.scanner import ScanTarget, ScanResult, ScanLevel
from rce_hawkeye.detector import Severity
from rce_hawkeye.payload_generator import ScanMode
from rce_hawkeye.crawler import WebCrawler
from rce_hawkeye.dir_scanner import DirectoryScanner, DirScanConfig
from rce_hawkeye.param_extractor import ParamExtractor, ParamConfig
from rce_hawkeye.traffic_parser import TrafficParser
from rce_hawkeye.utils import normalize_target, get_preferred_url, parse_target

app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')
app.secret_key = os.urandom(24)

USERS = {
    'admin': {'password': 'admin123', 'role': 'admin'},
    'scanner': {'password': 'scan123', 'role': 'user'}
}

active_scans = {}
scan_history = []
stats = {
    'total_scans': 0,
    'critical_vulns': 0,
    'high_vulns': 0,
    'medium_vulns': 0,
    'low_vulns': 0,
    'targets_scanned': 0
}

last_network_io = {'bytes_sent': 0, 'bytes_recv': 0, 'time': time.time()}

batch_scans = {}

REPORTS_DIR = Path(__file__).parent.parent / 'reports'
REPORTS_DIR.mkdir(exist_ok=True)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'message': 'Unauthorized'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if username in USERS and USERS[username]['password'] == password:
        session['user'] = username
        session['role'] = USERS[username]['role']
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'message': 'Invalid username or password'})


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})


@app.route('/api/detect-https', methods=['POST'])
@login_required
def api_detect_https():
    data = request.get_json()
    url = data.get('url', '')
    
    try:
        normalized = normalize_target(url)
        https_url = get_preferred_url(normalized, prefer_https=True)
        
        import requests
        try:
            response = requests.head(https_url, timeout=5, verify=False)
            supports_https = response.status_code < 500
        except:
            supports_https = False
        
        if supports_https:
            return jsonify({
                'success': True,
                'https_supported': True,
                'https_url': https_url
            })
        else:
            return jsonify({
                'success': True,
                'https_supported': False
            })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/scan/start', methods=['POST'])
@login_required
def api_scan_start():
    data = request.get_json()
    target = data.get('target', '')
    level = data.get('level', 2)
    options = data.get('options', {})
    advanced = options.get('advanced', {})
    
    if not target:
        return jsonify({'success': False, 'message': 'Target is required'})
    
    try:
        target = normalize_target(target)
        if options.get('preferHttps'):
            target = get_preferred_url(target, prefer_https=True)
    except Exception as e:
        return jsonify({'success': False, 'message': f'Invalid target: {str(e)}'})
    
    scan_id = str(uuid.uuid4())[:8]
    
    active_scans[scan_id] = {
        'target': target,
        'level': level,
        'options': options,
        'advanced': advanced,
        'status': 'initializing',
        'progress': 0,
        'status_message': 'Initializing scan...',
        'vulnerabilities': [],
        'start_time': time.time(),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_payloads': 0,
        'tested_payloads': 0,
        'current_param': '',
        'stop_requested': False,
        'crawl_pages': [],
        'dir_results': [],
        'found_params': []
    }
    
    thread = threading.Thread(target=run_full_scan, args=(scan_id,))
    thread.daemon = True
    thread.start()
    
    stats['total_scans'] += 1
    
    return jsonify({
        'success': True,
        'scan_id': scan_id
    })


def run_full_scan(scan_id):
    global stats
    
    scan = active_scans.get(scan_id)
    if not scan:
        return
    
    try:
        scan['status'] = 'running'
        scan['status_message'] = 'Checking target accessibility...'
        scan['progress'] = 1
        
        target_url = scan['target']
        options = scan['options']
        advanced = scan.get('advanced', {})
        
        try:
            import requests
            check_response = requests.head(target_url, timeout=10, allow_redirects=True)
            scan['status_code'] = check_response.status_code
            
            if check_response.status_code >= 400:
                scan['status_message'] = f'Target returned status code {check_response.status_code}'
                scan['progress'] = 50
                
                scan_history.append({
                    'scan_id': scan_id,
                    'target': target_url,
                    'vulnerabilities': 0,
                    'vuln_details': [],
                    'timestamp': scan.get('timestamp', datetime.now().isoformat()),
                    'status_code': check_response.status_code,
                    'options': options
                })
                
                scan['status'] = 'completed'
                scan['progress'] = 100
                scan['status_message'] = f'Target unreachable (HTTP {check_response.status_code})'
                return
        except requests.exceptions.Timeout:
            scan['status'] = 'error'
            scan['status_message'] = 'Target connection timeout'
            scan['progress'] = 100
            return
        except requests.exceptions.ConnectionError:
            scan['status'] = 'error'
            scan['status_message'] = 'Target connection failed (host unreachable)'
            scan['progress'] = 100
            return
        except Exception as e:
            scan['status_code'] = 'unknown'
        
        scan['status_message'] = 'Starting scan...'
        scan['progress'] = 5
        
        scan_targets = []
        
        if options.get('crawl'):
            scan['status_message'] = 'Crawling website...'
            scan['progress'] = 5
            crawl_result = run_crawler(scan_id, target_url, options, advanced)
            scan_targets.extend(crawl_result)
        
        if options.get('dirScan'):
            scan['status_message'] = 'Scanning directories...'
            scan['progress'] = 10 if not options.get('crawl') else 25
            dir_result = run_dir_scan(scan_id, target_url, advanced)
            for url in dir_result:
                if url not in [t.url for t in scan_targets]:
                    scan_targets.append(ScanTarget(url=url, method="GET"))
        
        if options.get('paramFuzz'):
            scan['status_message'] = 'Fuzzing parameters...'
            scan['progress'] = 15 if not options.get('dirScan') and not options.get('crawl') else 35
            fuzz_result = run_param_fuzz(scan_id, target_url, advanced)
            scan_targets.extend(fuzz_result)
        
        if not scan_targets:
            headers = {}
            if advanced.get('headers'):
                if isinstance(advanced.get('headers'), str):
                    for h in advanced['headers'].split('\n'):
                        if ':' in h:
                            k, v = h.split(':', 1)
                            headers[k.strip()] = v.strip()
                elif isinstance(advanced.get('headers'), dict):
                    headers = advanced['headers']
            
            post_data = {}
            if advanced.get('postData'):
                if isinstance(advanced.get('postData'), str):
                    for pair in advanced['postData'].split('&'):
                        if '=' in pair:
                            k, v = pair.split('=', 1)
                            post_data[k] = v
                elif isinstance(advanced.get('postData'), dict):
                    post_data = advanced['postData']
            
            parsed_url = urlparse(target_url)
            existing_params = {}
            if parsed_url.query:
                from urllib.parse import parse_qs
                query_params = parse_qs(parsed_url.query)
                for key, values in query_params.items():
                    existing_params[key] = values[0] if values else ''
            
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            if existing_params:
                scan_targets.append(ScanTarget(
                    url=base_url,
                    method=advanced.get('method', 'GET'),
                    parameters=existing_params,
                    data=post_data,
                    headers=headers
                ))
            else:
                dangerous_params = ['url', 'cmd', 'command', 'exec', 'shell', 'system', 
                                   'file', 'path', 'id', 'page', 'data', 'action', 
                                   'code', 'eval', 'input', 'query', 'search', 'template',
                                   'load', 'include', 'require', 'read', 'write', 'delete',
                                   'run', 'execute', 'process', 'call', 'func', 'function']
                for param in dangerous_params:
                    scan_targets.append(ScanTarget(
                        url=target_url,
                        method="GET",
                        parameters={param: "test"},
                        headers=headers
                    ))
                    scan_targets.append(ScanTarget(
                        url=target_url,
                        method="POST",
                        data={param: "test"},
                        headers=headers
                    ))
        
        scan['status_message'] = f'Starting RCE scan on {len(scan_targets)} targets...'
        scan['progress'] = 40
        
        run_rce_scan(scan_id, scan_targets)
        
    except Exception as e:
        scan['status'] = 'error'
        scan['status_message'] = f'Scan error: {str(e)}'
        scan['progress'] = 100
        import traceback
        traceback.print_exc()


def run_crawler(scan_id, target_url, options, advanced):
    scan = active_scans.get(scan_id)
    if not scan:
        return []
    
    try:
        crawler = WebCrawler(
            max_depth=advanced.get('crawlDepth', 2),
            max_pages=advanced.get('crawlPages', 100),
            timeout=10,
            concurrent=10,
            user_agent='RCE-HawkEye/1.0.0'
        )
        
        parsed = urlparse(target_url)
        allowed_domains = [parsed.netloc]
        
        pages = asyncio.run(crawler.crawl(target_url, allowed_domains))
        
        scan['crawl_pages'] = [
            {
                'url': p.url,
                'params': list(p.parameters.keys()) if p.parameters else [],
                'forms': len(p.forms)
            }
            for p in pages
        ]
        
        scan_targets = []
        for page in pages:
            if page.parameters:
                scan_targets.append(ScanTarget(
                    url=page.url,
                    method="GET",
                    parameters=page.parameters
                ))
            for form in page.forms:
                scan_targets.append(ScanTarget(
                    url=form['action'],
                    method=form['method'],
                    data=form['inputs']
                ))
        
        scan['status_message'] = f'Crawled {len(pages)} pages, found {len(scan_targets)} targets'
        return scan_targets
        
    except Exception as e:
        scan['status_message'] = f'Crawl error: {str(e)}'
        return []


def run_dir_scan(scan_id, target_url, advanced):
    scan = active_scans.get(scan_id)
    if not scan:
        return []
    
    try:
        dir_config = DirScanConfig(
            threads=advanced.get('dirThreads', 10),
            timeout=10,
            wordlist=advanced.get('dirWordlist'),
            user_agent='RCE-HawkEye/1.0.0'
        )
        
        dir_scanner = DirectoryScanner(dir_config)
        results = asyncio.run(dir_scanner.scan(target_url))
        
        found_urls = dir_scanner.get_found_urls()
        
        scan['dir_results'] = [
            {
                'url': r.url,
                'status': r.status_code,
                'size': r.content_length,
                'redirect': r.redirect_url
            }
            for r in results
        ]
        
        scan['status_message'] = f'Directory scan found {len(found_urls)} paths'
        return found_urls
        
    except Exception as e:
        scan['status_message'] = f'Dir scan error: {str(e)}'
        return []


def run_param_fuzz(scan_id, target_url, advanced):
    scan = active_scans.get(scan_id)
    if not scan:
        return []
    
    try:
        param_config = ParamConfig(
            threads=10,
            timeout=10,
            max_depth=1,
            max_pages=20,
            param_wordlist=advanced.get('paramWordlist'),
            user_agent='RCE-HawkEye/1.0.0'
        )
        
        param_extractor = ParamExtractor(param_config)
        found_params = asyncio.run(param_extractor.extract(target_url))
        
        scan['found_params'] = list(found_params.keys())
        
        scan_targets = []
        priority_params = ['cmd', 'command', 'exec', 'shell', 'system', 'file', 'path', 
                          'id', 'page', 'url', 'data', 'action', 'code', 'eval']
        
        for param in priority_params:
            if param in found_params:
                scan_targets.append(ScanTarget(
                    url=target_url,
                    method="GET",
                    parameters={param: "test"}
                ))
                scan_targets.append(ScanTarget(
                    url=target_url,
                    method="POST",
                    data={param: "test"}
                ))
        
        for param in list(found_params.keys())[:30]:
            if param not in priority_params:
                scan_targets.append(ScanTarget(
                    url=target_url,
                    method="GET",
                    parameters={param: "test"}
                ))
        
        scan['status_message'] = f'Param fuzzing found {len(found_params)} parameters'
        return scan_targets
        
    except Exception as e:
        scan['status_message'] = f'Param fuzz error: {str(e)}'
        return []


def run_rce_scan(scan_id, scan_targets):
    global stats
    
    scan = active_scans.get(scan_id)
    if not scan:
        return
    
    try:
        options = scan['options']
        advanced = scan.get('advanced', {})
        
        level_map = {
            1: ScanLevel.QUICK,
            2: ScanLevel.NORMAL,
            3: ScanLevel.DEEP,
            4: ScanLevel.EXHAUSTIVE
        }
        
        if options.get('wafBypass'):
            scan_mode = ScanMode.WAF_BYPASS
        elif options.get('harmless'):
            scan_mode = ScanMode.HARMLESS
        else:
            scan_mode = ScanMode.ECHO
        
        scanner = Scanner(
            timeout=advanced.get('timeout', 10),
            max_concurrent=advanced.get('concurrent', 10),
            delay_threshold=advanced.get('delayThreshold', 4.0),
            user_agent='RCE-HawkEye/1.0.0',
            proxy=advanced.get('proxy'),
            verify_ssl=False,
            scan_level=level_map.get(scan['level'], ScanLevel.NORMAL)
        )
        
        scanner.set_scan_mode(scan_mode)
        
        def progress_callback(current, total, target_url, **kwargs):
            if scan['stop_requested']:
                scanner.stop()
                return
            
            tested = kwargs.get('tested_payloads', current)
            total_p = kwargs.get('total_payloads', total)
            param = kwargs.get('param', '')
            
            scan['tested_payloads'] = tested
            scan['total_payloads'] = total_p
            scan['current_param'] = param
            
            base_progress = 40
            scan_progress = 55
            
            if total_p > 0:
                progress = base_progress + int((tested / total_p) * scan_progress)
                scan['progress'] = min(progress, 95)
            
            scan['status_message'] = f'Testing: {param} ({tested}/{total_p})'
        
        scanner.set_progress_callback(progress_callback)
        
        scan['status_message'] = f'Scanning {len(scan_targets)} targets for RCE...'
        
        results = asyncio.run(scanner.scan(scan_targets))
        
        if scan['stop_requested']:
            scan['status'] = 'stopped'
            scan['status_message'] = 'Scan stopped by user'
            scan['progress'] = 100
            return
        
        scan['progress'] = 95
        scan['status_message'] = 'Analyzing results...'
        
        all_vulns = []
        for result in results:
            for vuln in result.vulnerabilities:
                severity = 'Critical' if vuln.severity == Severity.CRITICAL else \
                          'High' if vuln.severity == Severity.HIGH else \
                          'Medium' if vuln.severity == Severity.MEDIUM else 'Low'
                
                all_vulns.append({
                    'target': vuln.target,
                    'parameter': vuln.parameter,
                    'payload': vuln.payload,
                    'payload_type': vuln.payload_type,
                    'severity': severity,
                    'evidence': vuln.evidence,
                    'exploitation': vuln.exploitation
                })
                
                if severity == 'Critical':
                    stats['critical_vulns'] += 1
                elif severity == 'High':
                    stats['high_vulns'] += 1
                elif severity == 'Medium':
                    stats['medium_vulns'] += 1
                else:
                    stats['low_vulns'] += 1
        
        scan['vulnerabilities'] = all_vulns
        scan['status'] = 'completed'
        scan['progress'] = 100
        scan['status_message'] = f'Scan completed. Found {len(all_vulns)} vulnerabilities.'
        
        stats['targets_scanned'] += len(scan_targets)
        
        scan_history.append({
            'scan_id': scan_id,
            'target': scan['target'],
            'vulnerabilities': len(all_vulns),
            'vuln_details': all_vulns,
            'timestamp': datetime.now().isoformat(),
            'options': options,
            'crawl_pages': scan.get('crawl_pages', []),
            'dir_results': scan.get('dir_results', []),
            'found_params': scan.get('found_params', [])
        })
        
    except Exception as e:
        scan['status'] = 'error'
        scan['status_message'] = f'Scan error: {str(e)}'
        scan['progress'] = 100
        import traceback
        traceback.print_exc()


@app.route('/api/scan/batch', methods=['POST'])
@login_required
def api_scan_batch():
    data = request.get_json()
    targets = data.get('targets', [])
    level = data.get('level', 2)
    options = data.get('options', {})
    
    if not targets or len(targets) == 0:
        return jsonify({'success': False, 'message': 'No targets provided'})
    
    batch_id = str(uuid.uuid4())[:8]
    
    batch_scans[batch_id] = {
        'targets': targets,
        'level': level,
        'options': options,
        'status': 'running',
        'completed': 0,
        'total': len(targets),
        'total_vulns': 0,
        'results': [],
        'start_time': time.time()
    }
    
    thread = threading.Thread(target=run_batch_scan, args=(batch_id,))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'batch_id': batch_id,
        'total_targets': len(targets)
    })


@app.route('/api/scan/batch/status')
@login_required
def api_scan_batch_status():
    batch_id = request.args.get('batch_id')
    
    if not batch_id or batch_id not in batch_scans:
        return jsonify({'success': False, 'message': 'Batch scan not found'})
    
    batch = batch_scans[batch_id]
    
    return jsonify({
        'success': True,
        'batch_id': batch_id,
        'status': batch['status'],
        'completed': batch['completed'],
        'total': batch['total'],
        'total_vulns': batch['total_vulns'],
        'results': batch['results']
    })


def run_batch_scan(batch_id):
    batch = batch_scans.get(batch_id)
    if not batch:
        return
    
    targets = batch['targets']
    level = batch['level']
    options = batch['options']
    
    for target in targets:
        if batch.get('stop_requested'):
            break
        
        try:
            target = normalize_target(target)
        except Exception as e:
            batch['results'].append({
                'target': target,
                'status': 'error',
                'vuln_count': 0,
                'error': str(e)
            })
            batch['completed'] += 1
            continue
        
        scan_id = str(uuid.uuid4())[:8]
        
        active_scans[scan_id] = {
            'target': target,
            'level': level,
            'options': options,
            'advanced': {},
            'status': 'initializing',
            'progress': 0,
            'status_message': 'Initializing...',
            'vulnerabilities': [],
            'start_time': time.time(),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'stop_requested': False
        }
        
        run_full_scan(scan_id)
        
        scan = active_scans.get(scan_id, {})
        vuln_count = len(scan.get('vulnerabilities', []))
        
        batch['results'].append({
            'target': target,
            'status': scan.get('status', 'completed'),
            'vuln_count': vuln_count
        })
        
        batch['completed'] += 1
        batch['total_vulns'] += vuln_count
        
        if vuln_count > 0:
            stats['critical_vulns'] += sum(1 for v in scan.get('vulnerabilities', []) if v.get('severity') == 'Critical')
            stats['high_vulns'] += sum(1 for v in scan.get('vulnerabilities', []) if v.get('severity') == 'High')
        
        stats['targets_scanned'] += 1
    
    batch['status'] = 'completed'


@app.route('/api/scan/status')
@login_required
def api_scan_status():
    scan_id = request.args.get('scan_id')
    
    if not scan_id or scan_id not in active_scans:
        return jsonify({'success': False, 'message': 'Scan not found'})
    
    scan = active_scans[scan_id]
    
    return jsonify({
        'success': True,
        'status': scan['status'],
        'progress': scan['progress'],
        'status_message': scan['status_message'],
        'vulnerabilities': scan['vulnerabilities'],
        'current_vulns': scan['vulnerabilities'],
        'tested_payloads': scan.get('tested_payloads', 0),
        'total_payloads': scan.get('total_payloads', 0),
        'current_param': scan.get('current_param', ''),
        'crawl_count': len(scan.get('crawl_pages', [])),
        'dir_count': len(scan.get('dir_results', [])),
        'param_count': len(scan.get('found_params', [])),
        'crawl_pages': scan.get('crawl_pages', []),
        'dir_results': scan.get('dir_results', []),
        'found_params': scan.get('found_params', [])
    })


@app.route('/api/scan/stop', methods=['POST'])
@login_required
def api_scan_stop():
    data = request.get_json()
    scan_id = data.get('scan_id')
    
    if scan_id in active_scans:
        active_scans[scan_id]['stop_requested'] = True
        active_scans[scan_id]['status'] = 'stopping'
        active_scans[scan_id]['status_message'] = 'Stopping scan...'
    
    return jsonify({'success': True})


@app.route('/api/scan/active')
@login_required
def api_scan_active():
    scans = []
    for scan_id, scan in active_scans.items():
        scans.append({
            'id': scan_id,
            'target': scan['target'],
            'status': scan['status'],
            'progress': scan['progress'],
            'status_message': scan['status_message'],
            'vuln_count': len(scan.get('vulnerabilities', []))
        })
    return jsonify({
        'success': True,
        'scans': scans
    })


@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify(stats)


@app.route('/api/monitoring')
@login_required
def api_monitoring():
    global last_network_io
    
    cpu = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory().percent
    
    current_net = psutil.net_io_counters()
    current_time = time.time()
    time_diff = current_time - last_network_io['time']
    
    if time_diff > 0:
        bytes_per_sec = (
            (current_net.bytes_sent - last_network_io['bytes_sent']) +
            (current_net.bytes_recv - last_network_io['bytes_recv'])
        ) / time_diff
        network_kb = round(bytes_per_sec / 1024, 1)
    else:
        network_kb = 0
    
    last_network_io = {
        'bytes_sent': current_net.bytes_sent,
        'bytes_recv': current_net.bytes_recv,
        'time': current_time
    }
    
    active_count = sum(1 for s in active_scans.values() if s['status'] == 'running')
    
    return jsonify({
        'cpu': round(cpu, 1),
        'memory': round(memory, 1),
        'network': network_kb,
        'scan_perf': active_count * 15
    })


@app.route('/api/reports')
@login_required
def api_reports():
    return jsonify({
        'success': True,
        'reports': scan_history
    })


@app.route('/api/scan/history')
@login_required
def api_scan_history():
    history = []
    for scan in scan_history:
        history.append({
            'id': scan.get('scan_id', ''),
            'target': scan.get('target', ''),
            'timestamp': scan.get('timestamp', ''),
            'vuln_count': scan.get('vulnerabilities', 0)
        })
    return jsonify({
        'success': True,
        'scans': history
    })


@app.route('/api/scan/detail')
@login_required
def api_scan_detail():
    scan_id = request.args.get('scan_id')
    
    print(f"[DEBUG] api_scan_detail called with scan_id: {scan_id}")
    print(f"[DEBUG] active_scans keys: {list(active_scans.keys())}")
    print(f"[DEBUG] scan_history count: {len(scan_history)}")
    
    if not scan_id:
        return jsonify({'success': False, 'message': 'Scan ID is required'})
    
    if scan_id in active_scans:
        scan = active_scans[scan_id]
        vulns = scan['vulnerabilities']
        print(f"[DEBUG] Found in active_scans, vulnerabilities count: {len(vulns)}")
        print(f"[DEBUG] Vulnerabilities data: {vulns}")
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'target': scan['target'],
            'status': scan['status'],
            'timestamp': scan.get('timestamp', ''),
            'vulnerabilities': vulns,
            'crawl_pages': scan.get('crawl_pages', []),
            'dir_results': scan.get('dir_results', []),
            'found_params': scan.get('found_params', [])
        })
    
    for hist in scan_history:
        if hist.get('scan_id') == scan_id:
            print(f"[DEBUG] Found in scan_history, vuln_details: {len(hist.get('vuln_details', []))}")
            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'target': hist['target'],
                'status': 'completed',
                'timestamp': hist.get('timestamp', ''),
                'vulnerabilities': hist.get('vuln_details', []),
                'crawl_pages': hist.get('crawl_pages', []),
                'dir_results': hist.get('dir_results', []),
                'found_params': hist.get('found_params', [])
            })
    
    print(f"[DEBUG] Scan not found: {scan_id}")
    return jsonify({'success': False, 'message': 'Scan not found'})


@app.route('/api/export/<format>', methods=['POST'])
@login_required
def api_export(format):
    if format not in ['json', 'html', 'md']:
        return jsonify({'success': False, 'message': 'Invalid format'})
    
    data = request.get_json()
    scan_id = data.get('scan_id')
    target = data.get('target', '')
    vulns_data = data.get('vulnerabilities', [])
    
    if scan_id and scan_id in active_scans:
        scan = active_scans[scan_id]
        vulns_data = scan['vulnerabilities']
        target = scan['target']
    
    if not vulns_data:
        return jsonify({'success': False, 'message': 'No vulnerabilities to export'})
    
    try:
        reporter = Reporter(output_dir=str(REPORTS_DIR))
        
        from rce_hawkeye.detector import Vulnerability
        
        vulns = []
        for v in vulns_data:
            severity_str = v.get('severity', 'Medium').upper()
            severity = Severity[severity_str] if severity_str in Severity.__members__ else Severity.MEDIUM
            
            vuln = Vulnerability(
                target=v.get('target', target),
                parameter=v.get('parameter', ''),
                payload=v.get('payload', ''),
                payload_type=v.get('payload_type', 'unknown'),
                severity=severity,
                description=v.get('description', f"在参数 '{v.get('parameter', 'unknown')}' 发现远程代码执行漏洞"),
                evidence=v.get('evidence', ''),
                exploitation=v.get('exploitation', ''),
                remediation=v.get('remediation', '建议对用户输入进行严格的过滤和验证，避免直接执行用户可控的命令或代码。')
            )
            vulns.append(vuln)
        
        scan_info = {
            'total_targets': 1,
            'scan_mode': 'web',
            'scan_time': 0
        }
        
        if scan_id and scan_id in active_scans:
            scan_info['scan_time'] = time.time() - active_scans[scan_id]['start_time']
        
        if format == 'json':
            report_data = reporter.generate_json_report(vulns, scan_info)
            return jsonify(report_data)
        elif format == 'html':
            report_data = reporter.generate_html_report(vulns, scan_info)
            return report_data
        elif format == 'md':
            report_data = reporter.generate_markdown_report(vulns, scan_info)
            return report_data
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/download/<filename>')
@login_required
def api_download(filename):
    filepath = REPORTS_DIR / filename
    if filepath.exists():
        return send_file(str(filepath), as_attachment=True)
    return jsonify({'success': False, 'message': 'File not found'}), 404


@app.route('/api/traffic/parse', methods=['POST'])
@login_required
def api_traffic_parse():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'})
    
    try:
        content = file.read().decode('utf-8')
        
        parser = TrafficParser()
        requests = parser.parse_content(content)
        
        targets = []
        for req in requests:
            targets.append({
                'url': req.get_url(),
                'method': req.method,
                'params': req.get_parameters()
            })
        
        return jsonify({
            'success': True,
            'targets': targets,
            'count': len(targets)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/settings/password', methods=['POST'])
@login_required
def api_settings_password():
    data = request.get_json()
    new_password = data.get('password', '')
    
    if not new_password or len(new_password) < 6:
        return jsonify({'success': False, 'message': '密码长度至少6位'})
    
    username = session.get('user')
    if username in USERS:
        USERS[username]['password'] = new_password
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'message': '用户不存在'})


@app.route('/api/reports/export')
@login_required
def api_reports_export():
    return jsonify({
        'success': True,
        'reports': scan_history
    })


@app.route('/api/history/clear', methods=['POST'])
@login_required
def api_history_clear():
    global scan_history
    scan_history = []
    return jsonify({'success': True})


@app.route('/api/data/clear', methods=['POST'])
@login_required
def api_data_clear():
    global scan_history, active_scans, stats
    scan_history = []
    active_scans = {}
    stats = {
        'total_scans': 0,
        'critical_vulns': 0,
        'high_vulns': 0,
        'medium_vulns': 0,
        'low_vulns': 0,
        'targets_scanned': 0
    }
    return jsonify({'success': True})


if __name__ == '__main__':
    print("=" * 50)
    print("RCE HawkEye Web Interface")
    print("=" * 50)
    print(f"Version: 1.0.0")
    print(f"Access: http://localhost:5000")
    print(f"Default credentials: admin / admin123")
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
