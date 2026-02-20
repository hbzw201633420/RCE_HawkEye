# 🦅 RCE HawkEye

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8.svg)](https://golang.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20Docker-green.svg)]()
[![Version](https://img.shields.io/badge/version-1.1.1-brightgreen.svg)]()

**RCE HawkEye (RCE 鹰眼)** 是一款专业的命令执行漏洞自动化检测工具，支持多种 RCE 漏洞类型的检测，包括命令注入、代码注入、模板注入等。

[English](#english) | [中文文档](#中文文档)

---

## 中文文档

## ✨ 功能特性

### 🔍 核心扫描功能
- **多类型漏洞检测**：支持命令注入、代码注入、模板注入 (SSTI)、反序列化漏洞等
- **多参数扫描**：自动提取 GET/POST/JSON/XML 等参数进行测试
- **智能爬虫**：自动爬取目标站点，发现隐藏的注入点
- **目录扫描**：集成目录扫描功能，发现敏感文件和目录

### 🛡️ 高级功能
- **WAF 绕过**：内置多种 WAF 绕过技术，支持自定义绕过规则
- **免杀技术**：30+ 种 Payload 变形脚本，有效绕过安全检测
- **智能检测**：基于回显、时间盲注、DNS 外带等多种检测方式
- **启发式分析**：智能分析响应特征，减少误报

### 📊 报告与监控
- **Web 界面**：现代化 Web 管理界面，支持实时监控
- **多格式报告**：支持 JSON、HTML、Markdown、CSV 格式导出
- **历史记录**：完整的扫描历史管理，支持搜索和导出
- **通知系统**：支持企业微信、钉钉、邮件通知
- **性能监控**：实时 CPU、内存、网络流量监控

### 🌐 国际化
- **多语言支持**：支持中文和英文界面
- **响应式设计**：适配桌面和移动设备

## 📦 安装部署

### Windows

#### 方式一：直接运行
```bash
# 解压后直接运行
rce-hawkeye.exe web -p 8080

# 或使用启动脚本
run.bat web -p 8080
```

#### 方式二：命令行扫描
```bash
# 扫描单个 URL
rce-hawkeye.exe -u "http://example.com/api?cmd=test"

# 从文件批量扫描
rce-hawkeye.exe -f urls.txt

# 查看帮助
rce-hawkeye.exe -h
```

### Linux

#### 方式一：直接运行
```bash
# 添加执行权限
chmod +x rce-hawkeye

# 启动 Web 服务
./rce-hawkeye web -p 8080

# 或使用启动脚本
./run.sh web -p 8080
```

#### 方式二：安装脚本
```bash
# 运行安装脚本（需要 root 权限）
chmod +x install.sh
sudo ./install.sh

# 按提示输入安装路径和端口
# 安装完成后可使用 systemd 管理
systemctl start rce-hawkeye
systemctl status rce-hawkeye
```

#### 方式三：Docker 部署
```bash
# 使用 docker-compose
docker-compose up -d

# 或手动构建
docker build -t rce-hawkeye .
docker run -d -p 8080:8080 -v ./reports:/app/reports rce-hawkeye
```

#### 卸载
```bash
# 运行卸载脚本
sudo ./uninstall.sh

# 可选择保留数据和配置
```

## 🚀 快速开始

### 1. 启动 Web 服务

```bash
# Windows
rce-hawkeye.exe web -p 8080

# Linux
./rce-hawkeye web -p 8080
```

### 2. 访问 Web 界面

打开浏览器访问 `http://localhost:8080`

默认账号：
- 用户名：`admin`
- 密码：`admin123`

### 3. 创建扫描任务

1. 点击「新建扫描」
2. 输入目标 URL 或上传文件
3. 选择扫描级别和模式
4. 开始扫描

## 📖 使用指南

### 命令行参数

```bash
RCE HawkEye - RCE Vulnerability Scanner

Usage:
  rce-hawkeye [flags]
  rce-hawkeye [command]

Available Commands:
  web         Start web interface
  update      Check for updates
  version     Print version information
  help        Help about any command

Flags:
  -u, --url string        Target URL to scan
  -f, --file string       File containing URLs to scan
  -l, --level string      Scan level: quick, normal, deep, exhaustive (default "normal")
  -m, --mode string       Scan mode: echo, time, dns (default "echo")
  -o, --output string     Output file for results
  -t, --timeout int       Request timeout in seconds (default 10)
  -c, --concurrent int    Max concurrent requests (default 10)
  -p, --proxy string      Proxy URL (e.g., http://127.0.0.1:8080)
      --waf-bypass        Enable WAF bypass techniques
      --verify-ssl        Verify SSL certificates
  -h, --help              Help for rce-hawkeye

Examples:
  # Quick scan
  rce-hawkeye -u "http://example.com/api?cmd=test" -l quick

  # Deep scan with WAF bypass
  rce-hawkeye -u "http://example.com" -l deep --waf-bypass

  # Batch scan from file
  rce-hawkeye -f urls.txt -o results.json

  # Start web interface
  rce-hawkeye web -p 8080

  # Check for updates
  rce-hawkeye update
```

### 扫描级别

| 级别 | 说明 | Payload 数量 |
|------|------|-------------|
| quick | 快速扫描，仅测试关键 Payload | ~10 |
| normal | 标准扫描，平衡速度和覆盖率 | ~30 |
| deep | 深度扫描，全面检测 | ~60 |
| exhaustive | 穷举扫描，测试所有 Payload | 全部 |

### 检测模式

| 模式 | 说明 |
|------|------|
| echo | 回显检测 - 检测响应中的命令执行结果 |
| time | 时间盲注 - 通过响应延迟判断 |
| dns | DNS 外带 - 通过 DNS 查询获取回显 |

## 📁 目录结构

```
RCE_HawkEye/
├── rce-hawkeye          # 主程序
├── run.bat / run.sh     # 启动脚本
├── install.sh           # Linux 安装脚本
├── uninstall.sh         # Linux 卸载脚本
├── Dockerfile           # Docker 构建文件
├── docker-compose.yml   # Docker Compose 配置
├── configs/
│   └── config.yaml      # 配置文件
├── data/
│   ├── dict/
│   │   └── dir_dict.json    # 目录扫描字典
│   └── history/             # 扫描历史
└── reports/                 # 报告输出目录
```

## ⚙️ 配置说明

编辑 `configs/config.yaml` 文件：

```yaml
domain:
  max_depth: 2          # 爬虫最大深度
  max_pages: 100        # 最大爬取页面数
  exclude_extensions:   # 排除的文件扩展名
    - .jpg
    - .png
    - .pdf

scan:
  timeout: 10           # 请求超时（秒）
  max_concurrent: 10    # 最大并发数
  delay_threshold: 4.0  # 延迟阈值
  scan_level: "normal"  # 默认扫描级别
```

## 🔧 API 接口

Web 服务提供 RESTful API：

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/login` | POST | 用户登录 |
| `/api/scan` | POST | 创建扫描任务 |
| `/api/scan/:id` | GET | 获取扫描状态 |
| `/api/scan/:id/stop` | POST | 停止扫描 |
| `/api/history` | GET | 获取扫描历史 |
| `/api/history/export` | POST | 导出历史记录 |
| `/api/monitor` | GET | 获取系统监控数据 |
| `/api/version` | GET | 获取版本信息 |
| `/api/version/check` | GET | 检查更新 |
| `/api/notification/config` | GET/POST | 通知配置 |

## 🔄 更新说明

### 版本更新

```bash
# 命令行检查更新
rce-hawkeye update

# Web 界面：设置 -> 关于 -> 检查更新
```

### 更新不影响数据

更新时以下数据会自动保留：
- `configs/config.yaml` - 配置文件
- `data/history/` - 扫描历史记录
- `data/dict/` - 字典文件

## 🛡️ 安全建议

1. **授权使用**：仅对授权目标进行测试
2. **网络安全**：建议在内网环境使用
3. **数据保护**：定期清理敏感扫描数据
4. **访问控制**：修改默认密码，限制访问 IP

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 🙏 致谢

感谢所有贡献者和安全社区的支持！

---

## English

## ✨ Features

### 🔍 Core Scanning
- **Multi-type Vulnerability Detection**: Command injection, code injection, SSTI, deserialization, etc.
- **Multi-parameter Scanning**: Auto-extract GET/POST/JSON/XML parameters
- **Smart Crawler**: Auto-discover hidden injection points
- **Directory Scanning**: Discover sensitive files and directories

### 🛡️ Advanced Features
- **WAF Bypass**: Built-in WAF bypass techniques
- **Evasion**: 30+ payload mutation scripts
- **Smart Detection**: Echo-based, time-based, DNS exfiltration
- **Heuristic Analysis**: Intelligent response analysis

### 📊 Reports & Monitoring
- **Web Interface**: Modern web UI with real-time monitoring
- **Multi-format Reports**: JSON, HTML, Markdown, CSV
- **History Management**: Complete scan history with search and export
- **Notifications**: WeChat Work, DingTalk, Email
- **Performance Monitoring**: Real-time CPU, memory, network monitoring

## 📦 Installation

### Windows
```bash
# Run directly
rce-hawkeye.exe web -p 8080

# Or use the startup script
run.bat web -p 8080
```

### Linux
```bash
# Add execute permission
chmod +x rce-hawkeye

# Run directly
./rce-hawkeye web -p 8080

# Or install as service
sudo ./install.sh
systemctl start rce-hawkeye
```

### Docker
```bash
docker-compose up -d
```

## 🚀 Quick Start

1. Start the web service: `rce-hawkeye web -p 8080`
2. Open browser: `http://localhost:8080`
3. Login with default credentials: `admin` / `admin123`
4. Create a new scan task

## 📁 Required Files

### Windows Release
```
RCE_HawkEye_Windows/
├── rce-hawkeye.exe     # Main executable
├── run.bat             # Startup script
├── README.md           # Documentation
├── LICENSE             # License file
├── configs/
│   └── config.yaml     # Configuration
├── data/
│   └── dict/
│       └── dir_dict.json  # Directory dictionary
├── reports/            # Reports directory
│   └── .gitkeep
└── data/
    └── history/        # History directory
        └── .gitkeep
```

### Linux Release
```
RCE_HawkEye_Linux/
├── rce-hawkeye         # Main executable
├── run.sh              # Startup script
├── install.sh          # Installation script
├── uninstall.sh        # Uninstallation script
├── Dockerfile          # Docker build file
├── docker-compose.yml  # Docker Compose config
├── README.md           # Documentation
├── LICENSE             # License file
├── configs/
│   └── config.yaml     # Configuration
├── data/
│   └── dict/
│       └── dir_dict.json  # Directory dictionary
├── reports/            # Reports directory
│   └── .gitkeep
└── data/
    └── history/        # History directory
        └── .gitkeep
```

## 🛡️ Security Notice

1. **Authorized Use Only**: Only test targets you have permission to test
2. **Network Security**: Recommended for internal network use
3. **Data Protection**: Regularly clean sensitive scan data
4. **Access Control**: Change default password, restrict access IP

## 📄 License

MIT License - see [LICENSE](LICENSE) file

---

**⚠️ Disclaimer**: This tool is for security research and authorized testing only. Do not use for illegal purposes. Users are responsible for all consequences of using this tool.
