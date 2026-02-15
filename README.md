# RCE HawkEye (RCE鹰眼)

<p align="center">
  <img src="https://img.shields.io/badge/version-0.0.4-blue.svg" alt="Version">
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
- 🌐 **多语言支持** - 自动识别 PHP/JSP/ASP/ASPX/Python/Node.js/Ruby/Go/Perl/Lua 等语言的代码执行漏洞
- 🕷️ **智能爬虫** - 自动爬取网站路径和参数，发现隐藏的注入点
- 📂 **目录扫描** - 集成字典扫描，发现隐藏目录和敏感文件
- 🎯 **参数模糊测试** - 使用字典发现隐藏参数，支持 GET/POST 双模式
- 🔧 **交互式选择** - 目录扫描后可按状态码或通配符选择要测试的路径
- 🎯 **多种检测模式** - 无害化检测、常规回显检测、WAF 绕过检测
- 📊 **检测等级** - 快速/标准/深度/完全四级检测，平衡速度与覆盖率
- 🛡️ **WAF绕过** - 支持70+种WAF绕过技术，包括编码、混淆、变异等
- 📦 **流量包解析** - 支持从文本文件解析 HTTP 流量包进行检测
- 📊 **详细报告** - JSON/HTML/Markdown 多格式报告，包含完整响应内容
- ⚙️ **灵活配置** - 支持域名白名单/黑名单、自定义字典等配置
- 🔒 **安全测试** - 无害化模式使用时间盲注，不执行实际命令

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

## 📊 检测等级

| 等级 | Payload数量/参数 | 特点 |
|------|------------------|------|
| **快速扫描** | ~10个 | 仅测试最关键的CODE_EXEC类型Payload |
| **标准扫描** | ~30个 | 平衡速度和覆盖率，包含模板注入 |
| **深度扫描** | ~60个 | 全面检测，包含WAF绕过 |
| **完全扫描** | 全部 | 测试所有Payload |

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
| **脱字符** | Windows脱字符 | `d^ir`, `w^hoami` |

---

## 📁 项目结构

```
RCE_HawkEye/
├── rce_hawkeye/             # 核心模块
│   ├── __init__.py          # 模块入口
│   ├── scanner.py           # 核心扫描器
│   ├── detector.py          # 漏洞检测器
│   ├── payload_generator.py # Payload 生成器
│   ├── waf_bypass.py        # WAF绕过生成器
│   ├── tech_detector.py     # 技术栈检测器
│   ├── intelligent_scanner.py # 智能扫描器
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

## 🔧 作为库使用

```python
import asyncio
from rce_hawkeye import Scanner, Reporter, ScanLevel
from rce_hawkeye.scanner import ScanTarget
from rce_hawkeye.payload_generator import ScanMode

async def main():
    scanner = Scanner(
        timeout=10, 
        max_concurrent=20,
        scan_level=ScanLevel.NORMAL
    )
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

## ⚠️ 免责声明

本工具仅供**授权的安全测试**使用。在未获得明确授权的情况下，禁止对他人系统进行扫描测试。使用本工具所产生的一切后果由使用者自行承担，与作者无关。

---

## 📄 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

---

## 📝 更新日志

### v0.0.4 (2024-02-15)

- ✨ 新增检测等级机制（快速/标准/深度/完全）
- ✨ 新增WAF绕过Payload生成器（70+绕过技术）
- ✨ 新增多语言支持（Node.js/Ruby/Go/Perl/Lua/ColdFusion）
- ✨ 新增模板注入检测
- ✨ 新增技术栈自动检测
- 🚀 优化并发请求性能（并行基准响应获取）
- 🐛 修复误报问题（增加基准响应对比）
- 🐛 修复参数传递错误
- 📝 完善文档和示例

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
