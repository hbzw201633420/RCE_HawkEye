package payload

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
)

type Encoder struct{}

func NewEncoder() *Encoder {
	return &Encoder{}
}

func (e *Encoder) URLEncode(s string) string {
	return url.QueryEscape(s)
}

func (e *Encoder) DoubleURLEncode(s string) string {
	return url.QueryEscape(url.QueryEscape(s))
}

func (e *Encoder) Base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func (e *Encoder) HexEncode(s string) string {
	return hex.EncodeToString([]byte(s))
}

func (e *Encoder) UnicodeEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r < 128 {
			result.WriteRune(r)
		} else {
			result.WriteString(fmt.Sprintf("\\u%04x", r))
		}
	}
	return result.String()
}

func (e *Encoder) FullUnicodeEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		result.WriteString(fmt.Sprintf("\\u%04x", r))
	}
	return result.String()
}

func (e *Encoder) HTMLEntityEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		result.WriteString(fmt.Sprintf("&#%d;", r))
	}
	return result.String()
}

func (e *Encoder) OctalEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r < 128 {
			result.WriteString(fmt.Sprintf("\\%03o", r))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func (e *Encoder) GenerateVariants(payload string) []string {
	variants := []string{payload}

	variants = append(variants, e.URLEncode(payload))
	variants = append(variants, e.DoubleURLEncode(payload))
	variants = append(variants, e.Base64Encode(payload))
	variants = append(variants, e.UnicodeEncode(payload))
	variants = append(variants, e.HTMLEntityEncode(payload))

	return variants
}

func (e *Encoder) GenerateCommandVariants(cmd string) []string {
	variants := []string{cmd}

	variants = append(variants, strings.ReplaceAll(cmd, " ", "${IFS}"))
	variants = append(variants, strings.ReplaceAll(cmd, " ", "$IFS"))
	variants = append(variants, strings.ReplaceAll(cmd, " ", "%09"))
	variants = append(variants, strings.ReplaceAll(cmd, " ", "	"))

	variants = append(variants, "{"+cmd+"}")

	parts := strings.Split(cmd, " ")
	if len(parts) > 1 {
		variants = append(variants, "{"+strings.Join(parts, ",")+"}")
	}

	return variants
}

func (e *Encoder) GenerateBashVariants(cmd string) []string {
	variants := []string{}

	for i := 0; i < len(cmd); i++ {
		if i > 0 && i < len(cmd)-1 {
			v := cmd[:i] + "''" + cmd[i:]
			variants = append(variants, v)
		}
	}

	for i := 0; i < len(cmd); i++ {
		if i > 0 && i < len(cmd)-1 {
			v := cmd[:i] + "\\" + cmd[i:]
			variants = append(variants, v)
		}
	}

	variants = append(variants, strings.Replace(cmd, " ", "${PATH:0:0}", 1))

	hexCmd := ""
	for _, c := range cmd {
		hexCmd += fmt.Sprintf("\\x%02x", c)
	}
	variants = append(variants, fmt.Sprintf("$(printf '%s')", hexCmd))

	b64Cmd := base64.StdEncoding.EncodeToString([]byte(cmd))
	variants = append(variants, fmt.Sprintf("$(echo %s|base64 -d)", b64Cmd))

	return variants
}

func (e *Encoder) GenerateWindowsVariants(cmd string) []string {
	variants := []string{cmd}

	for i := 0; i < len(cmd); i++ {
		if i > 0 && i < len(cmd)-1 && cmd[i] != ' ' {
			v := cmd[:i] + "^" + string(cmd[i]) + cmd[i+1:]
			variants = append(variants, v)
		}
	}

	for i := 0; i < len(cmd); i++ {
		if i > 0 && i < len(cmd)-1 && cmd[i] != ' ' {
			v := cmd[:i] + "\"" + string(cmd[i]) + cmd[i+1:]
			variants = append(variants, v)
		}
	}

	variants = append(variants, strings.ReplaceAll(cmd, "cmd", "c\"\"md"))
	variants = append(variants, strings.ReplaceAll(cmd, "cmd", "c^md"))

	psCmd := fmt.Sprintf("powershell -enc %s", base64.StdEncoding.EncodeToString([]byte(cmd)))
	variants = append(variants, psCmd)

	return variants
}

func (e *Encoder) GeneratePHPVariants(payload string) []string {
	variants := []string{payload}

	variants = append(variants, strings.ToLower(payload))
	variants = append(variants, strings.ToUpper(payload))
	variants = append(variants, e.mixCase(payload))

	variants = append(variants, strings.ReplaceAll(payload, "system", "sys/**/tem"))
	variants = append(variants, strings.ReplaceAll(payload, "exec", "ex/**/ec"))
	variants = append(variants, strings.ReplaceAll(payload, "shell_exec", "shel/**/l_ex/**/ec"))

	variants = append(variants, "("+payload+")")
	variants = append(variants, "(("+payload+"))")

	return variants
}

func (e *Encoder) mixCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i%2 == 0 {
			result.WriteRune(rune(strings.ToUpper(string(r))[0]))
		} else {
			result.WriteRune(rune(strings.ToLower(string(r))[0]))
		}
	}
	return result.String()
}

func (e *Encoder) CharToHex(s string) string {
	var result strings.Builder
	for _, r := range s {
		result.WriteString(fmt.Sprintf("\\x%02x", r))
	}
	return result.String()
}

func (e *Encoder) CharToOctal(s string) string {
	var result strings.Builder
	for _, r := range s {
		result.WriteString(fmt.Sprintf("\\%o", r))
	}
	return result.String()
}

func (e *Encoder) GenerateNullByteVariants(payload string) []string {
	variants := []string{}

	variants = append(variants, payload+"%00")
	variants = append(variants, payload+"\x00")
	variants = append(variants, payload+"%00.jpg")
	variants = append(variants, payload+"%00.png")

	return variants
}

func (e *Encoder) GenerateCommentVariants(payload string) string {
	if strings.Contains(payload, "system") {
		return strings.ReplaceAll(payload, "system", "sys/**/tem")
	}
	if strings.Contains(payload, "exec") {
		return strings.ReplaceAll(payload, "exec", "ex/**/ec")
	}
	return payload
}

func (e *Encoder) GenerateUnicodeBypass(payload string) []string {
	variants := []string{}

	for _, r := range payload {
		if r < 128 {
			variants = append(variants, fmt.Sprintf("%%u%04x", r))
		}
	}

	return variants
}

func (e *Encoder) GenerateJSONEscape(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		if r == '"' || r == '\\' {
			result.WriteRune('\\')
		}
		result.WriteRune(r)
	}
	return result.String()
}

func (e *Encoder) GenerateXPathEscape(payload string) string {
	replacer := strings.NewReplacer(
		"'", "&apos;",
		"\"", "&quot;",
		"<", "&lt;",
		">", "&gt;",
		"&", "&amp;",
	)
	return replacer.Replace(payload)
}

func (e *Encoder) GenerateSQLCharEncode(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		if r == '\'' || r == '"' {
			result.WriteString(fmt.Sprintf("CHAR(%d)", r))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func (e *Encoder) GenerateCharCodeVariants(payload string) []string {
	variants := []string{}

	var charCodes []string
	for _, r := range payload {
		charCodes = append(charCodes, strconv.Itoa(int(r)))
	}
	variants = append(variants, "String.fromCharCode("+strings.Join(charCodes, ",")+")")

	var hexCodes []string
	for _, r := range payload {
		hexCodes = append(hexCodes, fmt.Sprintf("0x%02x", r))
	}
	variants = append(variants, "String.fromCharCode("+strings.Join(hexCodes, ",")+")")

	return variants
}

func (e *Encoder) GenerateAllVariants(payload string, osType types.OSType) []string {
	var variants []string

	variants = append(variants, payload)
	variants = append(variants, e.GenerateVariants(payload)...)

	if osType == types.OSTypeUnix || osType == types.OSTypeBoth {
		variants = append(variants, e.GenerateBashVariants(payload)...)
	}

	if osType == types.OSTypeWindows || osType == types.OSTypeBoth {
		variants = append(variants, e.GenerateWindowsVariants(payload)...)
	}

	return e.removeDuplicateStrings(variants)
}

func (e *Encoder) removeDuplicateStrings(slice []string) []string {
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
