package color

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
)

type Color string

const (
	Reset      Color = "0"
	Bold       Color = "1"
	Dim        Color = "2"
	Underline  Color = "4"
	Blink      Color = "5"
	Reverse    Color = "7"
	Hidden     Color = "8"
	
	Black      Color = "30"
	Red        Color = "31"
	Green      Color = "32"
	Yellow     Color = "33"
	Blue       Color = "34"
	Magenta    Color = "35"
	Cyan       Color = "36"
	White      Color = "37"
	
	BrightBlack   Color = "90"
	BrightRed     Color = "91"
	BrightGreen   Color = "92"
	BrightYellow  Color = "93"
	BrightBlue    Color = "94"
	BrightMagenta Color = "95"
	BrightCyan    Color = "96"
	BrightWhite   Color = "97"
	
	BgBlack    Color = "40"
	BgRed      Color = "41"
	BgGreen    Color = "42"
	BgYellow   Color = "43"
	BgBlue     Color = "44"
	BgMagenta  Color = "45"
	BgCyan     Color = "46"
	BgWhite    Color = "47"
)

type StatusCodeColor struct {
	Code        int
	Color       Color
	BgColor     Color
	Description string
}

var (
	colorEnabled = true
	colorMutex   sync.RWMutex
	
	statusCodeColors = map[int]StatusCodeColor{
		200: {Code: 200, Color: Green, Description: "OK"},
		201: {Code: 201, Color: Green, Description: "Created"},
		202: {Code: 202, Color: Green, Description: "Accepted"},
		204: {Code: 204, Color: Green, Description: "No Content"},
		
		301: {Code: 301, Color: Cyan, Description: "Moved Permanently"},
		302: {Code: 302, Color: Cyan, Description: "Found"},
		303: {Code: 303, Color: Cyan, Description: "See Other"},
		304: {Code: 304, Color: Dim, Description: "Not Modified"},
		307: {Code: 307, Color: Cyan, Description: "Temporary Redirect"},
		308: {Code: 308, Color: Cyan, Description: "Permanent Redirect"},
		
		400: {Code: 400, Color: Yellow, Description: "Bad Request"},
		401: {Code: 401, Color: Yellow, Description: "Unauthorized"},
		403: {Code: 403, Color: Magenta, Description: "Forbidden"},
		404: {Code: 404, Color: Red, Description: "Not Found"},
		405: {Code: 405, Color: Yellow, Description: "Method Not Allowed"},
		408: {Code: 408, Color: Yellow, Description: "Request Timeout"},
		409: {Code: 409, Color: Yellow, Description: "Conflict"},
		410: {Code: 410, Color: Red, Description: "Gone"},
		429: {Code: 429, Color: Yellow, Description: "Too Many Requests"},
		
		500: {Code: 500, Color: BrightRed, Description: "Internal Server Error"},
		501: {Code: 501, Color: BrightRed, Description: "Not Implemented"},
		502: {Code: 502, Color: BrightRed, Description: "Bad Gateway"},
		503: {Code: 503, Color: BrightRed, Description: "Service Unavailable"},
		504: {Code: 504, Color: BrightRed, Description: "Gateway Timeout"},
	}
)

func EnableColor(enabled bool) {
	colorMutex.Lock()
	defer colorMutex.Unlock()
	colorEnabled = enabled
}

func IsColorEnabled() bool {
	colorMutex.RLock()
	defer colorMutex.RUnlock()
	return colorEnabled
}

func GetStatusCodeColor(code int) StatusCodeColor {
	if sc, ok := statusCodeColors[code]; ok {
		return sc
	}
	
	switch {
	case code >= 200 && code < 300:
		return StatusCodeColor{Code: code, Color: Green, Description: "Success"}
	case code >= 300 && code < 400:
		return StatusCodeColor{Code: code, Color: Cyan, Description: "Redirect"}
	case code >= 400 && code < 500:
		if code == 403 {
			return StatusCodeColor{Code: code, Color: Magenta, Description: "Forbidden"}
		}
		return StatusCodeColor{Code: code, Color: Yellow, Description: "Client Error"}
	case code >= 500:
		return StatusCodeColor{Code: code, Color: BrightRed, Description: "Server Error"}
	default:
		return StatusCodeColor{Code: code, Color: White, Description: "Unknown"}
	}
}

func Colorize(text string, color Color) string {
	if !IsColorEnabled() {
		return text
	}
	
	return fmt.Sprintf("\033[%sm%s\033[0m", color, text)
}

func ColorizeWithBg(text string, fgColor, bgColor Color) string {
	if !IsColorEnabled() {
		return text
	}
	
	return fmt.Sprintf("\033[%s;%sm%s\033[0m", fgColor, bgColor, text)
}

func ColorizeStatusCode(code int) string {
	sc := GetStatusCodeColor(code)
	
	if !IsColorEnabled() {
		return fmt.Sprintf("[%d]", code)
	}
	
	return fmt.Sprintf("\033[1;%sm[%d]\033[0m", sc.Color, code)
}

func ColorizeStatusCodeWithBg(code int) string {
	if !IsColorEnabled() {
		return fmt.Sprintf("[%d]", code)
	}
	
	var bgColor Color
	switch {
	case code >= 200 && code < 300:
		bgColor = BgGreen
	case code >= 300 && code < 400:
		bgColor = BgCyan
	case code >= 400 && code < 500:
		if code == 403 {
			bgColor = BgMagenta
		} else {
			bgColor = BgYellow
		}
	case code >= 500:
		bgColor = BgRed
	default:
		bgColor = BgWhite
	}
	
	return fmt.Sprintf("\033[30;%sm %d \033[0m", bgColor, code)
}

func ColorizeTextByStatus(text string, code int) string {
	sc := GetStatusCodeColor(code)
	return Colorize(text, sc.Color)
}

func ColorizeURL(url string) string {
	if !IsColorEnabled() {
		return url
	}
	
	return fmt.Sprintf("\033[4;34m%s\033[0m", url)
}

func ColorizeTitle(title string) string {
	if !IsColorEnabled() {
		return title
	}
	
	return fmt.Sprintf("\033[36m%s\033[0m", title)
}

func ColorizeTechStack(tech string) string {
	if !IsColorEnabled() {
		return tech
	}
	
	return fmt.Sprintf("\033[33m%s\033[0m", tech)
}

func ColorizeServer(server string) string {
	if !IsColorEnabled() {
		return server
	}
	
	return fmt.Sprintf("\033[35m%s\033[0m", server)
}

func ColorizeContentLength(length int) string {
	if !IsColorEnabled() {
		return fmt.Sprintf("%d", length)
	}
	
	var color Color
	switch {
	case length == 0:
		color = Dim
	case length < 1000:
		color = White
	case length < 10000:
		color = Cyan
	case length < 100000:
		color = Yellow
	default:
		color = BrightYellow
	}
	
	return Colorize(fmt.Sprintf("%d", length), color)
}

func ColorizeSeverity(severity string) string {
	if !IsColorEnabled() {
		return severity
	}
	
	var color Color
	switch strings.ToLower(severity) {
	case "critical", "严重":
		color = BrightRed
	case "high", "高危":
		color = Red
	case "medium", "中危":
		color = Yellow
	case "low", "低危":
		color = Green
	case "info", "信息":
		color = Blue
	default:
		color = White
	}
	
	return Colorize(severity, color)
}

func ColorizeMethod(method string) string {
	if !IsColorEnabled() {
		return method
	}
	
	var color Color
	switch strings.ToUpper(method) {
	case "GET":
		color = Green
	case "POST":
		color = Yellow
	case "PUT":
		color = Cyan
	case "DELETE":
		color = Red
	case "PATCH":
		color = Magenta
	case "HEAD":
		color = Blue
	case "OPTIONS":
		color = White
	default:
		color = Dim
	}
	
	return Colorize(method, color)
}

func PrintColoredLine(char string, length int, color Color) {
	if !IsColorEnabled() {
		fmt.Println(strings.Repeat(char, length))
		return
	}
	
	fmt.Printf("\033[%sm%s\033[0m\n", color, strings.Repeat(char, length))
}

func PrintHeader(title string) {
	if !IsColorEnabled() {
		fmt.Println(title)
		return
	}
	
	fmt.Printf("\033[1;36m%s\033[0m\n", title)
}

func PrintSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !IsColorEnabled() {
		fmt.Println(msg)
		return
	}
	
	fmt.Printf("\033[32m[+] %s\033[0m\n", msg)
}

func PrintError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !IsColorEnabled() {
		fmt.Println(msg)
		return
	}
	
	fmt.Printf("\033[31m[!] %s\033[0m\n", msg)
}

func PrintWarning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !IsColorEnabled() {
		fmt.Println(msg)
		return
	}
	
	fmt.Printf("\033[33m[*] %s\033[0m\n", msg)
}

func PrintInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !IsColorEnabled() {
		fmt.Println(msg)
		return
	}
	
	fmt.Printf("\033[34m[*] %s\033[0m\n", msg)
}

func GetANSIColorCode(code int) string {
	sc := GetStatusCodeColor(code)
	return string(sc.Color)
}

func ParseColorCode(code string) Color {
	return Color(strings.TrimPrefix(code, "\033["))
}

func StripANSI(text string) string {
	result := text
	for strings.Contains(result, "\033[") {
		start := strings.Index(result, "\033[")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "m")
		if end == -1 {
			break
		}
		result = result[:start] + result[start+end+1:]
	}
	return result
}

func GetColorizedName() string {
	return "RCE HawkEye"
}

func FormatStatusLine(code int, length int, url string) string {
	statusStr := ColorizeStatusCode(code)
	lengthStr := ColorizeContentLength(length)
	urlStr := ColorizeURL(url)
	
	return fmt.Sprintf("  %s %s %s", statusStr, lengthStr, urlStr)
}

func FormatStatusLineWithDetails(code int, length int, url string, title string, tech []string) string {
	parts := []string{}
	
	parts = append(parts, "  "+ColorizeStatusCode(code))
	parts = append(parts, ColorizeContentLength(length))
	parts = append(parts, ColorizeURL(url))
	
	if title != "" {
		parts = append(parts, ColorizeTitle("["+title+"]"))
	}
	
	if len(tech) > 0 {
		techStr := strings.Join(tech, ",")
		parts = append(parts, ColorizeTechStack("["+techStr+"]"))
	}
	
	return strings.Join(parts, " ")
}

func init() {
	colorEnabled = true
	if runtime.GOOS == "windows" {
		enableWindowsANSI()
	}
}

func SetWindowsColorSupport(enabled bool) {
	if runtime.GOOS == "windows" {
		if enabled {
			enableWindowsANSI()
		}
		colorMutex.Lock()
		defer colorMutex.Unlock()
		colorEnabled = enabled
	}
}

func SprintColor(text string, color Color) string {
	return Colorize(text, color)
}

func SprintfColor(color Color, format string, args ...interface{}) string {
	return Colorize(fmt.Sprintf(format, args...), color)
}

func GetStatusCodeDescription(code int) string {
	if sc, ok := statusCodeColors[code]; ok {
		return sc.Description
	}
	
	switch {
	case code >= 200 && code < 300:
		return "Success"
	case code >= 300 && code < 400:
		return "Redirect"
	case code >= 400 && code < 500:
		return "Client Error"
	case code >= 500:
		return "Server Error"
	default:
		return "Unknown"
	}
}

func GetStatusCodeColorCode(code int) string {
	sc := GetStatusCodeColor(code)
	return string(sc.Color)
}
