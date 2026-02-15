"""
报告生成器模块
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
from .detector import Vulnerability, Severity


class Reporter:
    """漏洞报告生成器"""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def _severity_to_str(self, severity: Severity) -> str:
        """转换严重程度为字符串"""
        severity_map = {
            Severity.CRITICAL: "严重",
            Severity.HIGH: "高危",
            Severity.MEDIUM: "中危",
            Severity.LOW: "低危",
            Severity.INFO: "信息"
        }
        return severity_map.get(severity, "未知")
    
    def _severity_to_color(self, severity: Severity) -> str:
        """获取严重程度对应的颜色"""
        color_map = {
            Severity.CRITICAL: "#d32f2f",
            Severity.HIGH: "#f57c00",
            Severity.MEDIUM: "#fbc02d",
            Severity.LOW: "#388e3c",
            Severity.INFO: "#1976d2"
        }
        return color_map.get(severity, "#757575")
    
    def generate_json_report(self, vulnerabilities: List[Vulnerability],
                            scan_info: Dict[str, Any] = None,
                            include_response: bool = True) -> str:
        """生成JSON格式报告"""
        report = {
            "report_time": datetime.now().isoformat(),
            "scan_info": scan_info or {},
            "summary": {
                "total": len(vulnerabilities),
                "by_severity": {
                    "critical": len([v for v in vulnerabilities if v.severity == Severity.CRITICAL]),
                    "high": len([v for v in vulnerabilities if v.severity == Severity.HIGH]),
                    "medium": len([v for v in vulnerabilities if v.severity == Severity.MEDIUM]),
                    "low": len([v for v in vulnerabilities if v.severity == Severity.LOW]),
                    "info": len([v for v in vulnerabilities if v.severity == Severity.INFO])
                }
            },
            "vulnerabilities": []
        }
        
        for vuln in vulnerabilities:
            vuln_data = {
                "target": vuln.target,
                "parameter": vuln.parameter,
                "payload": vuln.payload,
                "payload_type": vuln.payload_type,
                "severity": vuln.severity.value,
                "severity_name": self._severity_to_str(vuln.severity),
                "description": vuln.description,
                "evidence": vuln.evidence,
                "exploitation": vuln.exploitation,
                "remediation": vuln.remediation,
                "timestamp": vuln.timestamp,
                "request_data": vuln.request_data,
            }
            
            if include_response:
                response_content = vuln.response_data.get("content", "")
                max_len = 5000
                if len(response_content) > max_len:
                    response_content = response_content[:max_len] + "\n... (内容已截断)"
                
                vuln_data["response_data"] = {
                    "status_code": vuln.response_data.get("status_code"),
                    "elapsed": vuln.response_data.get("elapsed"),
                    "error": vuln.response_data.get("error"),
                    "headers": vuln.response_data.get("headers", {}),
                    "content": response_content
                }
            else:
                vuln_data["response_data"] = {
                    "status_code": vuln.response_data.get("status_code"),
                    "elapsed": vuln.response_data.get("elapsed"),
                    "error": vuln.response_data.get("error")
                }
            
            report["vulnerabilities"].append(vuln_data)
        
        return json.dumps(report, ensure_ascii=False, indent=2)
    
    def generate_markdown_report(self, vulnerabilities: List[Vulnerability],
                                 scan_info: Dict[str, Any] = None,
                                 include_response: bool = True) -> str:
        """生成Markdown格式报告"""
        lines = []
        
        lines.append("# 命令执行漏洞检测报告")
        lines.append("")
        lines.append(f"**报告生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        if scan_info:
            lines.append("## 扫描信息")
            lines.append("")
            for key, value in scan_info.items():
                lines.append(f"- **{key}**: {value}")
            lines.append("")
        
        lines.append("## 漏洞概览")
        lines.append("")
        
        total = len(vulnerabilities)
        critical = len([v for v in vulnerabilities if v.severity == Severity.CRITICAL])
        high = len([v for v in vulnerabilities if v.severity == Severity.HIGH])
        medium = len([v for v in vulnerabilities if v.severity == Severity.MEDIUM])
        low = len([v for v in vulnerabilities if v.severity == Severity.LOW])
        
        lines.append(f"| 严重程度 | 数量 |")
        lines.append(f"|----------|------|")
        lines.append(f"| 严重 | {critical} |")
        lines.append(f"| 高危 | {high} |")
        lines.append(f"| 中危 | {medium} |")
        lines.append(f"| 低危 | {low} |")
        lines.append(f"| **总计** | **{total}** |")
        lines.append("")
        
        if vulnerabilities:
            lines.append("## 漏洞详情")
            lines.append("")
            
            for i, vuln in enumerate(vulnerabilities, 1):
                severity_name = self._severity_to_str(vuln.severity)
                lines.append(f"### 漏洞 #{i} - {severity_name}")
                lines.append("")
                lines.append(f"- **目标**: `{vuln.target}`")
                lines.append(f"- **参数**: `{vuln.parameter}`")
                lines.append(f"- **类型**: {vuln.payload_type}")
                lines.append(f"- **Payload**: `{vuln.payload}`")
                lines.append(f"- **描述**: {vuln.description}")
                lines.append(f"- **证据**: {vuln.evidence}")
                lines.append("")
                lines.append("**利用方式**:")
                lines.append("```")
                lines.append(vuln.exploitation)
                lines.append("```")
                lines.append("")
                lines.append("**修复建议**:")
                lines.append("```")
                lines.append(vuln.remediation)
                lines.append("```")
                lines.append("")
                
                if include_response and vuln.response_data:
                    lines.append("**响应信息**:")
                    lines.append("")
                    lines.append(f"- 状态码: {vuln.response_data.get('status_code', 'N/A')}")
                    lines.append(f"- 响应时间: {vuln.response_data.get('elapsed', 0):.2f}s")
                    if vuln.response_data.get('error'):
                        lines.append(f"- 错误: {vuln.response_data.get('error')}")
                    lines.append("")
                    
                    response_content = vuln.response_data.get("content", "")
                    if response_content:
                        max_len = 2000
                        if len(response_content) > max_len:
                            response_content = response_content[:max_len] + "\n... (内容已截断)"
                        lines.append("**响应内容**:")
                        lines.append("```")
                        lines.append(response_content)
                        lines.append("```")
                        lines.append("")
                
                lines.append("---")
                lines.append("")
        
        return "\n".join(lines)
    
    def generate_html_report(self, vulnerabilities: List[Vulnerability],
                            scan_info: Dict[str, Any] = None,
                            include_response: bool = True) -> str:
        """生成HTML格式报告"""
        html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>命令执行漏洞检测报告</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header p { opacity: 0.9; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .summary-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .summary-card .count { font-size: 36px; font-weight: bold; margin-bottom: 5px; }
        .summary-card .label { color: #666; font-size: 14px; }
        .vulnerability { background: white; margin-bottom: 15px; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .vuln-header { padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; }
        .vuln-title { font-weight: 600; }
        .severity-badge { padding: 5px 15px; border-radius: 20px; color: white; font-size: 12px; font-weight: 600; }
        .vuln-body { padding: 20px; border-top: 1px solid #eee; }
        .vuln-row { margin-bottom: 15px; }
        .vuln-row label { font-weight: 600; display: block; margin-bottom: 5px; color: #555; }
        .vuln-row code { background: #f8f9fa; padding: 10px; border-radius: 5px; display: block; overflow-x: auto; font-size: 13px; white-space: pre-wrap; word-break: break-all; }
        .critical { background: #d32f2f; }
        .high { background: #f57c00; }
        .medium { background: #fbc02d; }
        .low { background: #388e3c; }
        .info { background: #1976d2; }
        .no-vulns { text-align: center; padding: 50px; color: #666; }
        .no-vulns h2 { color: #388e3c; margin-bottom: 10px; }
        .response-section { margin-top: 15px; padding-top: 15px; border-top: 2px dashed #eee; }
        .response-info { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 10px; }
        .response-info-item { background: #f0f0f0; padding: 10px; border-radius: 5px; text-align: center; }
        .response-info-item .value { font-size: 18px; font-weight: bold; color: #333; }
        .response-info-item .label { font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>命令执行漏洞检测报告</h1>
            <p>报告生成时间: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <div class="count" style="color: #d32f2f;">""" + str(len([v for v in vulnerabilities if v.severity == Severity.CRITICAL])) + """</div>
                <div class="label">严重</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #f57c00;">""" + str(len([v for v in vulnerabilities if v.severity == Severity.HIGH])) + """</div>
                <div class="label">高危</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #fbc02d;">""" + str(len([v for v in vulnerabilities if v.severity == Severity.MEDIUM])) + """</div>
                <div class="label">中危</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #388e3c;">""" + str(len([v for v in vulnerabilities if v.severity == Severity.LOW])) + """</div>
                <div class="label">低危</div>
            </div>
            <div class="summary-card">
                <div class="count">""" + str(len(vulnerabilities)) + """</div>
                <div class="label">总计</div>
            </div>
        </div>
"""
        
        if vulnerabilities:
            html += """
        <div class="vulnerabilities">
"""
            for i, vuln in enumerate(vulnerabilities, 1):
                severity_name = self._severity_to_str(vuln.severity)
                severity_class = vuln.severity.value
                
                html += f"""
            <div class="vulnerability">
                <div class="vuln-header">
                    <span class="vuln-title">漏洞 #{i} - {vuln.target}</span>
                    <span class="severity-badge {severity_class}">{severity_name}</span>
                </div>
                <div class="vuln-body">
                    <div class="vuln-row">
                        <label>目标URL</label>
                        <code>{vuln.target}</code>
                    </div>
                    <div class="vuln-row">
                        <label>注入参数</label>
                        <code>{vuln.parameter}</code>
                    </div>
                    <div class="vuln-row">
                        <label>Payload</label>
                        <code>{vuln.payload}</code>
                    </div>
                    <div class="vuln-row">
                        <label>漏洞类型</label>
                        <code>{vuln.payload_type}</code>
                    </div>
                    <div class="vuln-row">
                        <label>检测证据</label>
                        <code>{vuln.evidence}</code>
                    </div>
                    <div class="vuln-row">
                        <label>利用方式</label>
                        <code>{vuln.exploitation}</code>
                    </div>
                    <div class="vuln-row">
                        <label>修复建议</label>
                        <code>{vuln.remediation}</code>
                    </div>
"""
                
                if include_response and vuln.response_data:
                    status_code = vuln.response_data.get('status_code', 'N/A')
                    elapsed = f"{vuln.response_data.get('elapsed', 0):.2f}s"
                    error = vuln.response_data.get('error', '无')
                    
                    html += f"""
                    <div class="response-section">
                        <div class="vuln-row">
                            <label>响应信息</label>
                        </div>
                        <div class="response-info">
                            <div class="response-info-item">
                                <div class="value">{status_code}</div>
                                <div class="label">状态码</div>
                            </div>
                            <div class="response-info-item">
                                <div class="value">{elapsed}</div>
                                <div class="label">响应时间</div>
                            </div>
                            <div class="response-info-item">
                                <div class="value">{error}</div>
                                <div class="label">错误信息</div>
                            </div>
                        </div>
"""
                    
                    response_content = vuln.response_data.get("content", "")
                    if response_content:
                        max_len = 3000
                        if len(response_content) > max_len:
                            response_content = response_content[:max_len] + "\n... (内容已截断)"
                        import html as html_module
                        escaped_content = html_module.escape(response_content)
                        html += f"""
                        <div class="vuln-row">
                            <label>响应内容</label>
                            <code>{escaped_content}</code>
                        </div>
"""
                    
                    html += """
                    </div>
"""
                
                html += """
                </div>
            </div>
"""
            
            html += """
        </div>
"""
        else:
            html += """
        <div class="no-vulns">
            <h2>未发现漏洞</h2>
            <p>扫描完成，未检测到命令执行漏洞</p>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        return html
    
    def save_report(self, vulnerabilities: List[Vulnerability],
                   format: str = "json",
                   filename: str = None,
                   scan_info: Dict[str, Any] = None,
                   include_response: bool = True) -> str:
        """保存报告到文件"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if filename is None:
            filename = f"rce_report_{timestamp}.{format}"
        
        filepath = self.output_dir / filename
        
        if format == "json":
            content = self.generate_json_report(vulnerabilities, scan_info, include_response)
        elif format == "md" or format == "markdown":
            content = self.generate_markdown_report(vulnerabilities, scan_info, include_response)
        elif format == "html":
            content = self.generate_html_report(vulnerabilities, scan_info, include_response)
        else:
            raise ValueError(f"不支持的报告格式: {format}")
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        
        return str(filepath)
    
    def export_all_formats(self, vulnerabilities: List[Vulnerability],
                          scan_info: Dict[str, Any] = None,
                          include_response: bool = True) -> Dict[str, str]:
        """导出所有格式的报告"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        files = {}
        for fmt in ["json", "html", "md"]:
            filename = f"rce_report_{timestamp}.{fmt}"
            files[fmt] = self.save_report(vulnerabilities, fmt, filename, scan_info, include_response)
        
        return files
