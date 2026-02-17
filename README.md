# RCE HawkEye (RCE鹰眼)

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.1-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.8+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-orange.svg" alt="License">
  <img src="https://img.shields.io/badge/author-hbzw-red.svg" alt="Author">
</p>

<p align="center">
  <b>命令执行漏洞自动化检测工具</b><br>
  <sub>借鉴 sqlmap 设计，专精于 RCE 漏洞检测</sub>
</p>

---

## 📖 项目简介

**RCE HawkEye（RCE鹰眼）** 是一款专业的命令执行漏洞自动化检测工具，借鉴 sqlmap 的优秀设计，专精于 RCE 漏洞检测。

### ✨ 核心特性

- 🔍 **多维度扫描** - 支持 URL 参数、表单、HTTP 头、Cookie、POST 数据等多种输入点
- 🌐 **多语言支持** - 自动识别 PHP/JSP/ASP/ASPX/Python/Node.js/Ruby/Go/Perl/Lua 等语言的代码执行漏洞
- 🕷️ **智能爬虫** - 自动爬取网站路径和参数，发现隐藏的注入点
- 📂 **目录扫描** - 集成字典扫描，发现隐藏目录和敏感文件
- 🎯 **参数模糊测试** - 使用字典发现隐藏参数，支持 GET/POST 双模式
- 🎯 **多种检测模式** - 无害化检测、常规回显检测、WAF 绕过检测
- 📊 **Level/Risk机制** - 5级检测深度 + 3级风险控制（借鉴sqlmap）
- 🛡️ **Tamper插件** - 50+种Payload变形脚本（借鉴sqlmap）
- 🔬 **启发式检测** - 智能识别注入点特征
- 🛡️ **WAF绕过** - 支持70+种WAF绕过技术
- 📦 **流量包解析** - 支持从文本文件解析 HTTP 流量包进行检测
- 📊 **详细报告** - JSON/HTML/Markdown 多格式报告

---

## 🚀 快速开始

### 环境要求

- Python 3.8+
- Windows / Linux / macOS

### 安装

```bash
git clone https://github.com/hbzw201633420/RCE_HawkEye.git
cd RCE_HawkEye
pip install -r requirements.txt
```

### 基本使用

```bash
# 扫描单个 URL
python RCE_HawkEye.py -u "http://example.com/api?cmd=test"

# 从流量包文件扫描
python RCE_HawkEye.py -r traffic.txt

# 从文件读取目标 URL
python RCE_HawkEye.py -f targets.txt

# 爬取网站并扫描
python RCE_HawkEye.py -u "http://example.com" --crawl

# 目录扫描 + 参数模糊测试
python RCE_HawkEye.py -u "http://example.com" --dir-scan --param-fuzz

# 指定并发数和检测等级
python RCE_HawkEye.py -u "http://example.com" -c 20 --no-interactive
```

---

## 📚 详细用法

### 命令行参数

#### 基本参数

| 参数 | 说明 |
|------|------|
| `-u, --url` | 目标 URL |
| `-r, --raw-traffic` | 流量包文件路径 |
| `-f, --file` | 目标 URL 文件路径 |

#### 扫描选项

| 参数 | 说明 |
|------|------|
| `--crawl` | 启用网页爬虫 |
| `--dir-scan` | 启用目录扫描 |
| `--param-fuzz` | 启用参数模糊测试 |

#### HTTP 选项

| 参数 | 说明 |
|------|------|
| `-m, --method` | HTTP 方法 (GET/POST) |
| `-d, --data` | POST 数据 |
| `-H, --header` | 自定义请求头 |
| `-c, --concurrent` | 并发数 (默认: 10) |
| `-t, --timeout` | 超时时间/秒 (默认: 10) |

#### 扫描模式

| 参数 | 说明 |
|------|------|
| `--no-interactive` | 非交互模式 |
| `--harmless` | 无害化检测模式 |
| `--echo` | 常规回显模式 |
| `--waf-bypass` | WAF 绕过模式 |

---

## 🎯 检测模式

### 1. 无害化检测模式 (`--harmless`)

使用时间盲注 payload（sleep/timeout），不执行实际命令。

### 2. 常规回显模式 (`--echo`)

使用 ls、whoami、id 等命令，可直接获取命令执行结果。

### 3. WAF 绕过模式 (`--waf-bypass`)

使用编码、特殊字符等技术绕过 WAF 防护。

---

## 📊 Level/Risk 机制（借鉴 sqlmap）

### Level（检测深度）

| Level | 描述 | Payload数/参数 |
|-------|------|---------------|
| 1 | 基础检测 | ~10 |
| 2 | 标准检测 | ~30 |
| 3 | 深度检测 | ~60 |
| 4 | 完全检测 | 全部 |
| 5 | exhaustive | 全部+变体 |

### Risk（风险等级）

| Risk | 描述 | 允许类型 |
|------|------|---------|
| 1 | 无害 | 时间盲注 |
| 2 | 低风险 | 时间盲注+回显+代码执行 |
| 3 | 中等风险 | 全部 |

---

## 🔧 Tamper 插件（借鉴 sqlmap）

支持 50+ 种 Payload 变形脚本：

| 类别 | 脚本示例 |
|------|---------|
| 编码类 | `urlencode`, `doubleurlencode`, `base64encode`, `hexencode` |
| 混淆类 | `space2comment`, `space2ifs`, `randomcase`, `randomcomments` |
| 绕过类 | `modsecurityversioned`, `apostrophemask`, `appendnullbyte` |
| 平台类 | `sp_password`(MSSQL), `bluecoat`, `overlongutf8` |

### 使用示例

```python
from rce_hawkeye import tamper_manager

# 应用单个tamper
payload = tamper_manager.apply("; ls;", ["space2comment"])
# 结果: ";/**/ls;"

# 应用多个tamper
payload = tamper_manager.apply("; ls;", ["space2comment", "randomcase"])
# 结果: ";/**/lS;"

# 列出所有可用脚本
scripts = tamper_manager.list_scripts()
```

---

## 🔬 启发式检测

智能识别 RCE 注入特征：

- **命令注入**: uid=, ls输出, passwd内容
- **代码注入**: PHP错误, Java异常, Python Traceback
- **模板注入**: 7*7=49, config对象
- **错误信息**: command not found, Permission denied

```python
from rce_hawkeye import HeuristicChecker

checker = HeuristicChecker()
result = checker.check_response(response, baseline, "cmd", payload)

print(result.injection_type)  # InjectionType.COMMAND_INJECTION
print(result.confidence)      # 0.95
print(result.evidence)        # "发现命令注入特征: id命令输出"
```

---

## 🖥️ Web 界面

RCE HawkEye 提供现代化的 Web 界面，采用 Glassmorphism 设计风格。

### 启动 Web 服务

```bash
# 安装额外依赖
pip install flask flask-cors psutil requests

# 启动 Web 服务
cd web
python app.py

# 访问 http://localhost:5000
# 默认账号: admin / admin123
```

### Web 界面功能

| 功能 | 描述 |
|------|------|
| **登录页面** | 表单验证、记住我功能、忘记密码链接 |
| **扫描仪表板** | 目标输入、扫描配置、实时进度、结果展示 |
| **性能监控** | CPU、内存、网络流量实时图表 |
| **报告导出** | JSON/HTML/Markdown 多格式导出 |

### 界面预览

```
┌─────────────────────────────────────────────────────┐
│  🔐 RCE HawkEye - Login                             │
│  ┌─────────────────────────────────────────────┐    │
│  │  Username: [________________]                │    │
│  │  Password: [________________]                │    │
│  │  ☐ Remember me    Forgot password?          │    │
│  │  [        Sign In        ]                   │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

---

## 🌐 多语言代码执行检测

| 语言 | URL 后缀 | 检测函数 |
|------|---------|---------|
| PHP | `.php`, `.phtml` | `system()`, `exec()`, `shell_exec()`, `passthru()` |
| JSP | `.jsp`, `.jspx` | `Runtime.exec()`, `ProcessBuilder`, EL 表达式 |
| ASP | `.asp` | `WScript.Shell` |
| ASPX | `.aspx`, `.ashx` | `System.Diagnostics.Process.Start()` |
| Python | `.py`, `.cgi` | `__import__()`, `eval()`, `exec()`, `subprocess` |
| Node.js | `.js`, `.mjs` | `require('child_process')`, `process.binding()` |
| Ruby | `.rb`, `.erb` | `system()`, `exec()`, `IO.popen()` |
| Go | `.go` | `exec.Command()`, `syscall.Exec()` |
| Perl | `.pl`, `.cgi` | `system()`, `exec()`, `qx{}` |
| Lua | `.lua` | `os.execute()`, `io.popen()` |

---

## 🛡️ WAF 绕过技术

支持 70+ 种 WAF 绕过技术：

| 技术类型 | 描述 | 示例 |
|----------|------|------|
| **URL编码** | 单重/双重URL编码 | `%3B%20ls%3B` |
| **Base64编码** | Base64编码执行 | `$(echo'bHM='\|base64-d)` |
| **注释混淆** | 插入注释分割 | `sys/**/tem('ls')` |
| **大小写变换** | 混合大小写 | `sYsTeM('ls')` |
| **引号分割** | 引号打断关键词 | `l''s`, `wh''oami` |
| **变量切片** | Shell变量切片 | `l${PATH:0:0}s` |
| **IFS变量** | 使用IFS替换空格 | `l${IFS}s` |
| **通配符** | 路径通配符 | `/???/??t /???/p??s??` |

---

## 📁 项目结构

```
RCE_HawkEye/
├── rce_hawkeye/
│   ├── __init__.py          # 模块入口
│   ├── scanner.py           # 核心扫描器
│   ├── detector.py          # 漏洞检测器
│   ├── payload_generator.py # Payload 生成器
│   ├── waf_bypass.py        # WAF绕过生成器
│   ├── tech_detector.py     # 技术栈检测器
│   ├── tamper/              # Tamper插件系统
│   │   └── __init__.py      # 50+ tamper脚本
│   ├── heuristic.py         # 启发式检测
│   ├── reporter.py          # 报告生成器
│   ├── crawler.py           # 网页爬虫
│   ├── dir_scanner.py       # 目录扫描器
│   └── ...
├── config/
│   └── payloads.yaml        # YAML Payload配置
├── RCE_HawkEye.py           # 命令行入口
├── requirements.txt         # 依赖文件
└── README.md                # 说明文档
```

---

## 🔧 作为库使用

```python
import asyncio
from rce_hawkeye import Scanner, Reporter, ScanLevel, tamper_manager

async def main():
    scanner = Scanner(
        timeout=10, 
        max_concurrent=20,
        scan_level=ScanLevel.NORMAL
    )
    
    results = await scanner.scan_url("http://example.com/api?cmd=test")
    
    for vuln in scanner.get_vulnerabilities():
        print(f"发现漏洞: {vuln.parameter} - {vuln.payload}")

asyncio.run(main())
```

---

## ⚠️ 免责声明

本工具仅供**授权的安全测试**使用。在未获得明确授权的情况下，禁止对他人系统进行扫描测试。使用本工具所产生的一切后果由使用者自行承担，与作者无关。

---

## 📄 许可证

本项目采用 MIT 许可证。

---

## 📝 更新日志

### v1.0.1 (2026-02-17)

**🐛 Bug修复**
- 修复 `requests` 模块导入作用域问题（`local variable 'requests' referenced before assignment`）
- 修复前端错误信息显示问题（`status_message` 未正确传递）
- 修复设置页面布局问题（删除重复的 HTML 结构）
- 添加 CORS 支持，解决跨域请求问题

**🔧 兼容性改进**
- 支持 CentOS 7 部署（需降级 urllib3 到 v1.26.x）
- 优化 systemd 服务配置

**📝 文档更新**
- 添加 CentOS 7 部署指南

### v1.0.0 (2026-02-16)

**🎉 首个正式版本发布**

**Web界面增强**

- � **全新设置页面** - 5个设置标签（常规/扫描/账户/数据/关于）
- 📦 **批量扫描功能** - 支持文件导入和多URL输入
- 🔔 **通知系统** - Toast通知和通知下拉面板
- 👤 **用户菜单** - 下拉菜单和退出登录功能
- 📊 **存储统计** - 实时显示扫描数据统计

**Bug修复**
- 🐛 修复导出功能缺少参数问题
- 🐛 修复HTTP/HTTPS协议转换问题（非标准端口）
- 🐛 修复目标不可达时无限扫描问题
- 🐛 修复showSection函数事件处理问题
- 🐛 修复设置页面布局问题

**功能完善**
- ✨ 目标可达性预检测
- ✨ 扫描结果自动生成报告
- ✨ 多格式报告导出（JSON/HTML/Markdown）

**统计数据**
- 📊 Payload总数: 200+
- 🛡️ Tamper脚本: 50+
- 🌐 支持语言: 中文/英文

### v0.0.5 (2024-02-16)

- ✨ 新增 Tamper 插件系统（50+脚本，借鉴sqlmap）
- ✨ 新增 YAML Payload 配置（Level/Risk机制）
- ✨ 新增启发式检测模块（智能识别注入点）
- ✨ 支持域名和IP直接扫描（无需http://前缀）
- ✨ 支持HTTPS自动检测和优先使用
- ✨ 新增Web界面（Glassmorphism风格）
  - 登录页面（表单验证、记住我功能）
  - 扫描器仪表板（实时进度、结果展示）
  - 性能监控（CPU、内存、网络实时图表）
- 🐛 修复tamper模块语法错误
- 📊 Payload总数: 200+
- 🛡️ Tamper脚本: 50+

### v0.0.4 (2024-02-15)

- ✨ 新增检测等级机制
- ✨ 新增WAF绕过Payload生成器
- ✨ 新增多语言支持
- 🚀 优化并发请求性能

### v0.0.3 (2024-02-14)

- ✨ 新增目录扫描功能
- ✨ 新增参数模糊测试功能
- ✨ 新增多语言代码执行检测 (PHP/JSP/ASP/ASPX/Python)
- ✨ 新增交互式路径选择功能
- ✨ 新增 POST 参数扫描支持
- 🐛 修复交互模式下的多个问题
- 📝 完善文档和示例

---

<p align="center">
  <b>⭐ 如果这个项目对你有帮助，请给一个 Star ⭐</b>
</p>
