package types

type PayloadType string

const (
	PayloadTypeTimeBased PayloadType = "time_based"
	PayloadTypeEchoBased PayloadType = "echo_based"
	PayloadTypeDNSBased  PayloadType = "dns_based"
	PayloadTypeFileBased PayloadType = "file_based"
	PayloadTypeCodeExec  PayloadType = "code_exec"
)

type OSType string

const (
	OSTypeUnix    OSType = "unix"
	OSTypeWindows OSType = "windows"
	OSTypeBoth    OSType = "both"
)

type ScanMode string

const (
	ScanModeHarmless ScanMode = "harmless"
	ScanModeEcho     ScanMode = "echo"
	ScanModeWAFBypass ScanMode = "waf_bypass"
)

type TechType string

const (
	TechTypeUnknown     TechType = "unknown"
	TechTypePHP         TechType = "php"
	TechTypeJSPJava     TechType = "jsp_java"
	TechTypeASP         TechType = "asp"
	TechTypeASPXDotNet  TechType = "aspx_dotnet"
	TechTypePython      TechType = "python"
	TechTypeNodeJS      TechType = "nodejs"
	TechTypeRuby        TechType = "ruby"
	TechTypeGo          TechType = "go"
	TechTypePerl        TechType = "perl"
	TechTypeLua         TechType = "lua"
	TechTypeColdFusion  TechType = "coldfusion"
	TechTypeCGI         TechType = "cgi"
	TechTypeTemplate    TechType = "template"
	TechTypeExpression  TechType = "expression"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type ScanLevel string

const (
	ScanLevelQuick      ScanLevel = "quick"
	ScanLevelNormal     ScanLevel = "normal"
	ScanLevelDeep       ScanLevel = "deep"
	ScanLevelExhaustive ScanLevel = "exhaustive"
)

type InjectionType string

const (
	InjectionTypeCommandInjection  InjectionType = "command_injection"
	InjectionTypeCodeInjection     InjectionType = "code_injection"
	InjectionTypeTemplateInjection InjectionType = "template_injection"
	InjectionTypeEvalInjection     InjectionType = "eval_injection"
	InjectionTypeDeserialization   InjectionType = "deserialization"
	InjectionTypeFileInclusion     InjectionType = "file_inclusion"
	InjectionTypeUnknown           InjectionType = "unknown"
)

type WAFTechnique string

const (
	WAFTechniqueURLEncoding       WAFTechnique = "url_encoding"
	WAFTechniqueDoubleURLEncoding WAFTechnique = "double_url_encoding"
	WAFTechniqueBase64Encoding    WAFTechnique = "base64_encoding"
	WAFTechniqueUnicodeEncoding   WAFTechnique = "unicode_encoding"
	WAFTechniqueHTMLEntity        WAFTechnique = "html_entity"
	WAFTechniqueHexEncoding       WAFTechnique = "hex_encoding"
	WAFTechniqueOctalEncoding     WAFTechnique = "octal_encoding"
	WAFTechniqueCommentObfuscation WAFTechnique = "comment_obfuscation"
	WAFTechniqueCaseManipulation  WAFTechnique = "case_manipulation"
	WAFTechniqueNullByte          WAFTechnique = "null_byte"
	WAFTechniqueWhitespaceVariation WAFTechnique = "whitespace_variation"
	WAFTechniqueQuoteManipulation WAFTechnique = "quote_manipulation"
	WAFTechniqueConcatenation     WAFTechnique = "concatenation"
	WAFTechniqueVariableSubstitution WAFTechnique = "variable_substitution"
	WAFTechniquePathObfuscation   WAFTechnique = "path_obfuscation"
)
