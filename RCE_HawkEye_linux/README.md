<div align="center">

# 🦅 RCE HawkEye

**专业级命令执行漏洞自动化检测工具**

<p>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://golang.org/"><img src="https://img.shields.io/badge/Go-1.21%2B-00ADD8.svg" alt="Go Version"></a>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Docker-green.svg" alt="Platform">
  <img src="https://img.shields.io/badge/version-1.1.2-brightgreen.svg" alt="Version">
</p>

<p>
  <a href="#-功能特性">功能特性</a> •
  <a href="#-安装部署">安装部署</a> •
  <a href="#-快速开始">快速开始</a> •
  <a href="#-使用指南">使用指南</a> •
  <a href="#-更新日志">更新日志</a>
</p>

</div>

---

> **RCE HawkEye (RCE 鹰眼)** 是一款专业的命令执行漏洞自动化检测工具，借鉴 sqlmap 设计理念，专精于 RCE 漏洞检测。支持命令注入、代码注入、模板注入 (SSTI)、反序列化漏洞等多种漏洞类型的检测。

[English](#-english-documentation) | [中文文档](#-中文文档)

---

## 📖 中文文档

## ✨ 功能特性

### 🔍 核心扫描功能

| 功能 | 说明 |
|:-----|:-----|
| **多类型漏洞检测** | 命令注入、代码注入、服务端模板注入 (SSTI)、反序列化漏洞 |
| **多参数智能扫描** | GET/POST/JSON/XML 参数自动提取，HTTP Header 和 Cookie 注入检测 |
| **智能爬虫系统** | 自动爬取目标站点，发现隐藏的注入点，支持深度和广度优先 |
| **目录扫描** | 集成目录扫描功能，智能字典记忆，敏感文件发现 |

### 🛡️ 高级检测技术

| 技术 | 说明 |
|:-----|:-----|
| **WAF 绕过技术** | 30+ 种 Payload 变形脚本，编码绕过 (URL/Unicode/Base64)，分块传输绕过 |
| **多种检测模式** | 回显检测 (Echo-based)、时间盲注 (Time-based Blind)、DNS 外带 (Out-of-Band) |
| **智能分析引擎** | 启发式响应分析，动态基线对比，漏洞置信度评估，自动去重与合并 |
| **多语言检测** | PHP / JSP / ASP / ASPX / Python / Node.js / Ruby / Go / Perl / Lua |

### 📊 报告与监控系统

| 功能模块 | 描述 |
|:--------:|:-----|
| 🖥️ **Web 管理界面** | 现代化响应式设计，支持深色/浅色主题 |
| 📈 **实时监控** | CPU、内存、网络流量实时监控图表 |
| 📑 **多格式报告** | 支持 JSON、HTML、Markdown、CSV 格式导出 |
| 📜 **历史管理** | 完整扫描历史，支持搜索、筛选、批量操作 |
| 🔔 **通知系统** | 企业微信、钉钉、邮件通知 |
| 🌐 **国际化** | 中英文双语支持，响应式设计适配多端 |

---

## 📦 安装部署

### 方式一：直接运行

```bash
# 添加执行权限
chmod +x rce-hawkeye

# 启动 Web 服务
./rce-hawkeye web -p 8080

# 或使用启动脚本
./run.sh web -p 8080
```

### 方式二：安装为系统服务

```bash
# 运行安装脚本（需要 root 权限）
chmod +x install.sh
sudo ./install.sh

# 按提示输入安装路径和端口
# 安装完成后可使用 systemd 管理
systemctl start rce-hawkeye
systemctl status rce-hawkeye
```

### 方式三：Docker 部署

```bash
# 使用 Docker Compose
docker-compose up -d

# 或手动构建
docker build -t rce-hawkeye .
docker run -d -p 8080:8080 -v ./reports:/app/reports rce-hawkeye
```

### 卸载

```bash
# 运行卸载脚本
sudo ./uninstall.sh

# 可选择保留数据和配置
```

---

## 🚀 快速开始

### 1️⃣ 启动服务

```bash
./rce-hawkeye web -p 8080
```

### 2️⃣ 访问界面

打开浏览器访问 `http://localhost:8080`

| 用户名 | 密码 |
|:------:|:----:|
| `admin` | `admin123` |
| `scanner` | `scan123` |

### 3️⃣ 创建扫描

1. 点击「新建扫描」或使用快捷键 `Ctrl+N`
2. 输入目标 URL 或上传目标文件
3. 选择扫描级别和检测模式
4. 点击「开始扫描」

---

## 📖 使用指南

### 命令行参数

```
RCE HawkEye - RCE Vulnerability Scanner v1.1.2

Usage:
  rce-hawkeye [flags]
  rce-hawkeye [command]

Available Commands:
  web         启动 Web 管理界面
  update      检查并更新到最新版本
  version     显示版本信息
  help        显示帮助信息

Flags:
  -u, --url string        目标 URL
  -f, --file string       目标 URL 文件
  -l, --level string      扫描级别: quick, normal, deep, exhaustive (默认: normal)
  -m, --mode string       检测模式: echo, time, dns (默认: echo)
  -o, --output string     结果输出文件
  -t, --timeout int       请求超时时间(秒) (默认: 10)
  -c, --concurrent int    最大并发数 (默认: 10)
  -p, --proxy string      代理服务器 (如: http://127.0.0.1:8080)
      --waf-bypass        启用 WAF 绕过技术
      --verify-ssl        验证 SSL 证书
  -h, --help              显示帮助

Examples:
  rce-hawkeye -u "http://example.com/api?cmd=test" -l quick
  rce-hawkeye -u "http://example.com" -l deep --waf-bypass
  rce-hawkeye -f urls.txt -o results.json
  rce-hawkeye web -p 8080
```

### 扫描级别

| 级别 | 描述 | Payload 数量 | 适用场景 |
|:----:|:----:|:------------:|:--------:|
| `quick` | 快速扫描 | ~10 | 初步探测，快速验证 |
| `normal` | 标准扫描 | ~30 | 常规安全测试 |
| `deep` | 深度扫描 | ~60 | 全面漏洞检测 |
| `exhaustive` | 穷举扫描 | 全部 | 极限检测，CTF 比赛 |

### 检测模式

| 模式 | 原理 | 优点 | 缺点 |
|:----:|:----:|:----:|:----:|
| `echo` | 检测响应中的命令执行结果 | 速度快，结果直观 | 可能被过滤 |
| `time` | 通过响应延迟判断 | 绕过输出过滤 | 速度较慢 |
| `dns` | DNS 外带获取回显 | 绕过严格过滤 | 需要外网环境 |

---

## 📁 项目结构

```
RCE_HawkEye_Linux/
├── rce-hawkeye              # 主程序
├── run.sh                   # 启动脚本
├── install.sh               # 安装脚本
├── uninstall.sh             # 卸载脚本
├── Dockerfile               # Docker 构建文件
├── docker-compose.yml       # Docker Compose 配置
├── configs/
│   └── config.yaml          # 配置文件
├── data/
│   ├── dict/
│   │   └── dir_dict.json    # 目录扫描字典
│   └── history/             # 扫描历史数据
└── reports/                 # 报告输出目录
```

---

## ⚙️ 配置说明

编辑 `configs/config.yaml` 文件：

```yaml
domain:
  max_depth: 2              # 爬虫最大深度
  max_pages: 100            # 最大爬取页面数
  exclude_extensions:       # 排除的文件扩展名
    - .jpg
    - .png
    - .pdf

scan:
  timeout: 10               # 请求超时(秒)
  max_concurrent: 10        # 最大并发数
  delay_threshold: 4.0      # 时间盲注延迟阈值
  scan_level: "normal"      # 默认扫描级别

output:
  report_dir: "./reports"   # 报告输出目录
  format: "html"            # 默认报告格式
```

---

## 🔌 API 接口

| 端点 | 方法 | 说明 |
|:-----|:----:|:-----|
| `/api/login` | POST | 用户登录认证 |
| `/api/scan` | POST | 创建扫描任务 |
| `/api/scan/:id` | GET | 获取扫描状态 |
| `/api/scan/:id/stop` | POST | 停止扫描任务 |
| `/api/history` | GET | 获取扫描历史 |
| `/api/history/delete/:id` | POST | 删除历史记录 |
| `/api/reports` | GET | 获取报告列表 |
| `/api/monitor` | GET | 获取系统监控数据 |
| `/api/version` | GET | 获取版本信息 |
| `/api/version/check` | GET | 检查更新 |
| `/api/notification/config` | GET/POST | 通知配置 |

---

## 📋 更新日志

### v1.1.2 (2026-02-22)

#### 🎉 新增功能
- 新增 9 种 PHP WAF 绕过 Payload (Smarty风格、双花括号、pcntl、proc_open等)
- 新增 `monitoring.confirmClearAlerts` 翻译键
- 优化响应式布局，支持更多屏幕分辨率 (320px - 1440px+)

#### 🐛 Bug 修复
- 修复 JavaScript 重复变量定义问题 (`monitorInterval`, `goroutineChart`, `heapChart`, `currentTimeRange`)
- 修复 DOM 元素创建错误 (`document.createElement('')` → `document.createElement('a')`)
- 修复报告模块语言显示问题，所有文本正确使用 `safeT()` 函数
- 修复历史模块删除功能无法使用的问题
- 修复错误的翻译键使用 (`common.error` → 正确的翻译键)
- 修复 CSS 重复定义问题 (`.reports-list`, `.btn-danger`)

#### 🔧 优化改进
- 优化前端 JavaScript 代码结构
- 优化 CSS 响应式布局
- 清理冗余代码和调试日志
- 改进错误提示信息的国际化支持

### v1.1.1 (2026-02-21)

#### 🎉 新增功能
- 新增 Web 管理界面
- 新增实时系统监控功能
- 新增多格式报告导出 (HTML/JSON/CSV)
- 新增扫描历史管理
- 新增通知系统 (企业微信/钉钉/邮件)

#### 🛡️ 安全增强
- 新增 Session 认证机制
- 新增密码加密存储
- 新增登录失败限制

<details>
<summary>📖 查看历史版本</summary>

### v1.1.0
- 重构扫描引擎，提升性能 50%
- 新增 WAF 绕过模块
- 新增智能爬虫功能

### v1.0.0
- 首次发布
- 支持基础命令注入检测

</details>

---

## 🛡️ 安全建议

> ⚠️ **重要提示**：本工具仅供安全研究和授权测试使用

| 建议 | 说明 |
|:----:|:-----|
| ✅ **授权使用** | 仅对已获得授权的目标进行测试 |
| ✅ **网络安全** | 建议在内网或隔离环境中使用 |
| ✅ **数据保护** | 定期清理敏感扫描数据和报告 |
| ✅ **访问控制** | 修改默认密码，限制访问 IP |
| ✅ **安全配置** | 生产环境启用 HTTPS，设置强密码 |

---

## 🤝 贡献指南

欢迎参与项目开发！请遵循以下流程：

```bash
# 1. Fork 本仓库
# 2. 创建特性分支
git checkout -b feature/AmazingFeature

# 3. 提交更改
git commit -m 'Add some AmazingFeature'

# 4. 推送到分支
git push origin feature/AmazingFeature

# 5. 提交 Pull Request
```

### 代码规范
- 遵循 Go 官方代码规范
- 使用 `gofmt` 格式化代码
- 添加必要的注释和文档

---

## 📄 许可证

本项目采用 [MIT License](LICENSE) 开源协议。

---

## 🙏 致谢

感谢所有贡献者和安全社区的支持！

特别感谢以下项目的启发：
- [sqlmap](https://github.com/sqlmapproject/sqlmap) - 设计理念参考
- [ffuf](https://github.com/ffuf/ffuf) - 模糊测试框架参考

---

## 📧 联系方式

- **Issues**: [GitHub Issues](https://github.com/hbzw201633420/RCE_HawkEye/issues)
- **Pull Requests**: 欢迎提交 PR

---

## 📖 English Documentation

### ✨ Features

#### 🔍 Core Scanning
- **Multi-type Detection**: Command injection, code injection, SSTI, deserialization
- **Multi-parameter Scanning**: Auto-extract GET/POST/JSON/XML parameters
- **Smart Crawler**: Auto-discover hidden injection points
- **Directory Scanning**: Discover sensitive files and directories

#### 🛡️ Advanced Features
- **WAF Bypass**: 30+ payload mutation techniques
- **Multiple Detection Modes**: Echo-based, time-based, DNS exfiltration
- **Smart Analysis**: Heuristic response analysis, dynamic baseline comparison
- **Multi-language Support**: PHP, JSP, ASP, Python, Node.js, Ruby, Go, etc.

### 📦 Installation

```bash
# Add execute permission
chmod +x rce-hawkeye

# Run directly
./rce-hawkeye web -p 8080

# Or install as service
sudo ./install.sh
systemctl start rce-hawkeye

# Docker
docker-compose up -d
```

### 🚀 Quick Start

1. Start service: `./rce-hawkeye web -p 8080`
2. Open browser: `http://localhost:8080`
3. Login: `admin` / `admin123`
4. Create a new scan task

### 📋 Changelog

#### v1.1.2 (2026-02-22)
- Added 9 new PHP WAF bypass payloads
- Fixed JavaScript duplicate variable definitions
- Fixed DOM element creation error
- Fixed report module language display issues
- Fixed history module delete functionality
- Improved responsive layout for more screen resolutions

---

<div align="center">

**⚠️ Disclaimer**

This tool is for security research and authorized testing only.
Do not use for illegal purposes. Users are responsible for all consequences.

---

Made with ❤️ by [hbzw](https://github.com/hbzw201633420)

</div>
