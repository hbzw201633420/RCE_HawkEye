package techdetect

import (
	"regexp"
	"strings"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
)

type TechIndicator struct {
	TechStack      types.TechType
	Patterns       []string
	FileExtensions []string
	Paths          []string
	Headers        map[string]string
	Confidence     float64
}

type TechStackDetector struct {
	detectedTechs      map[types.TechType]bool
	detectedExtensions map[string]bool
	evidence           map[types.TechType][]string
}

func NewTechStackDetector() *TechStackDetector {
	return &TechStackDetector{
		detectedTechs:      make(map[types.TechType]bool),
		detectedExtensions: make(map[string]bool),
		evidence:           make(map[types.TechType][]string),
	}
}

var techIndicators = []TechIndicator{
	{
		TechStack:      types.TechTypePHP,
		Patterns:       []string{`\.php\d?$`, `\.phtml$`, `\.phps$`},
		FileExtensions: []string{".php", ".php3", ".php4", ".php5", ".phtml", ".phps"},
		Paths:          []string{"wp-admin", "wp-content", "wp-includes", "phpmyadmin", "adminer", "composer.json", "vendor", "laravel", "symfony", "codeigniter"},
		Headers:        map[string]string{"X-Powered-By": `PHP`},
		Confidence:     1.0,
	},
	{
		TechStack:      types.TechTypeJSPJava,
		Patterns:       []string{`\.jsp$`, `\.jspx$`, `\.jspa$`, `\.jsw$`, `\.jsv$`, `\.do$`},
		FileExtensions: []string{".jsp", ".jspx", ".jspa", ".jsw", ".jsv", ".do", ".action"},
		Paths:          []string{"WEB-INF", "META-INF", "struts", "spring", "tomcat", "weblogic", "web.xml", "pom.xml", "gradle", "maven"},
		Headers:        map[string]string{"X-Powered-By": `(JSP|Java|Servlet|Tomcat|JBoss|WebLogic)`},
		Confidence:     1.0,
	},
	{
		TechStack:      types.TechTypeASP,
		Patterns:       []string{`\.asp$`},
		FileExtensions: []string{".asp"},
		Paths:          []string{"global.asa", "iisadmin"},
		Headers:        map[string]string{"X-Powered-By": `ASP`, "Server": `IIS`},
		Confidence:     1.0,
	},
	{
		TechStack:      types.TechTypeASPXDotNet,
		Patterns:       []string{`\.aspx?$`, `\.ashx$`, `\.asmx$`, `\.asax$`, `\.svc$`},
		FileExtensions: []string{".aspx", ".ashx", ".asmx", ".asax", ".svc", ".axd"},
		Paths:          []string{"web.config", "bin/", "App_Code", "App_Data", "App_Themes", "Site.Master", "ViewState"},
		Headers:        map[string]string{"X-Powered-By": `ASP\.NET`, "X-AspNet-Version": `.*`},
		Confidence:     1.0,
	},
	{
		TechStack:      types.TechTypePython,
		Patterns:       []string{`\.py$`, `\.wsgi$`, `\.cgi$`},
		FileExtensions: []string{".py", ".wsgi", ".cgi", ".fcgi"},
		Paths:          []string{"django", "flask", "fastapi", "requirements.txt", "setup.py", "wsgi.py", "asgi.py", "manage.py", "settings.py", "gunicorn"},
		Headers:        map[string]string{"Server": `(gunicorn|uWSGI|Python)`},
		Confidence:     1.0,
	},
	{
		TechStack:      types.TechTypeNodeJS,
		Patterns:       []string{`\.js$`, `\.mjs$`, `\.cjs$`},
		FileExtensions: []string{".js", ".mjs", ".cjs", ".node"},
		Paths:          []string{"node_modules", "package.json", "npm", "yarn.lock", "package-lock.json", "express", "koa", "hapi", "next.js", "nuxt.js", "gatsby", "app.js", "server.js", "index.js", "main.js", ".nuxt", ".next"},
		Headers:        map[string]string{"X-Powered-By": `(Express|Next\.js|Nuxt|Node)`},
		Confidence:     1.0,
	},
	{
		TechStack:      types.TechTypeRuby,
		Patterns:       []string{`\.rb$`, `\.erb$`, `\.rhtml$`},
		FileExtensions: []string{".rb", ".erb", ".rhtml", ".rjs", ".rake"},
		Paths:          []string{"rails", "ruby", "Gemfile", "Gemfile.lock", "Rakefile", "config.ru", "app/controllers", "app/models", "app/views", "bin/rails"},
		Headers:        map[string]string{"X-Powered-By": `(Phusion Passenger|Rails|Ruby)`},
		Confidence:     1.0,
	},
	{
		TechStack:      types.TechTypeGo,
		Patterns:       []string{`\.go$`},
		FileExtensions: []string{".go"},
		Paths:          []string{"go.mod", "go.sum", "Gopkg.toml", "Gopkg.lock", "main.go"},
		Headers:        map[string]string{"Server": `(go|Go)`},
		Confidence:     1.0,
	},
	{
		TechStack:      types.TechTypePerl,
		Patterns:       []string{`\.pl$`, `\.pm$`, `\.cgi$`},
		FileExtensions: []string{".pl", ".pm", ".cgi", ".t"},
		Paths:          []string{"perl", "cpan", "Makefile.PL", "cpanfile"},
		Headers:        map[string]string{"Server": `(Perl|mod_perl)`},
		Confidence:     1.0,
	},
	{
		TechStack:      types.TechTypeLua,
		Patterns:       []string{`\.lua$`},
		FileExtensions: []string{".lua", ".wlua"},
		Paths:          []string{"nginx.conf", "openresty", "lapis", "moonscript"},
		Headers:        map[string]string{"Server": `(OpenResty|nginx)`},
		Confidence:     1.0,
	},
	{
		TechStack:      types.TechTypeColdFusion,
		Patterns:       []string{`\.cfm$`, `\.cfml$`, `\.cfc$`},
		FileExtensions: []string{".cfm", ".cfml", ".cfc"},
		Paths:          []string{"Application.cfc", "Application.cfm"},
		Headers:        map[string]string{"Server": `ColdFusion`},
		Confidence:     1.0,
	},
	{
		TechStack:      types.TechTypeCGI,
		Patterns:       []string{`\.cgi$`, `/cgi-bin/`},
		FileExtensions: []string{".cgi", ".fcgi"},
		Paths:          []string{"cgi-bin", "fcgi-bin"},
		Headers:        map[string]string{},
		Confidence:     1.0,
	},
}

func (d *TechStackDetector) DetectFromURLs(urls []string) []types.DetectedTech {
	d.detectedTechs = make(map[types.TechType]bool)
	d.detectedExtensions = make(map[string]bool)
	d.evidence = make(map[types.TechType][]string)

	for _, rawURL := range urls {
		d.analyzeURL(rawURL)
	}

	return d.buildResults()
}

func (d *TechStackDetector) DetectFromHeaders(headers map[string]string) []types.DetectedTech {
	for _, indicator := range techIndicators {
		for headerName, pattern := range indicator.Headers {
			headerValue, ok := headers[headerName]
			if !ok {
				continue
			}
			matched, _ := regexp.MatchString(pattern, headerValue)
			if matched {
				d.detectedTechs[indicator.TechStack] = true
				d.evidence[indicator.TechStack] = append(d.evidence[indicator.TechStack], "Header: "+headerName+"="+headerValue)
			}
		}
	}

	return d.buildResults()
}

func (d *TechStackDetector) analyzeURL(rawURL string) {
	urlLower := strings.ToLower(rawURL)

	var path string
	if idx := strings.Index(urlLower, "://"); idx != -1 {
		rest := urlLower[idx+3:]
		if idx2 := strings.Index(rest, "/"); idx2 != -1 {
			path = rest[idx2:]
		}
	} else {
		path = urlLower
	}

	for _, indicator := range techIndicators {
		for _, ext := range indicator.FileExtensions {
			if strings.HasSuffix(path, ext) {
				d.detectedTechs[indicator.TechStack] = true
				d.detectedExtensions[ext] = true
				d.evidence[indicator.TechStack] = append(d.evidence[indicator.TechStack], "Extension: "+ext+" in "+rawURL)
			}
		}

		for _, pattern := range indicator.Patterns {
			matched, _ := regexp.MatchString(pattern, path)
			if matched {
				d.detectedTechs[indicator.TechStack] = true
				d.evidence[indicator.TechStack] = append(d.evidence[indicator.TechStack], "Pattern: "+pattern+" in "+rawURL)
			}
		}

		for _, pathIndicator := range indicator.Paths {
			if strings.Contains(path, strings.ToLower(pathIndicator)) {
				d.detectedTechs[indicator.TechStack] = true
				d.evidence[indicator.TechStack] = append(d.evidence[indicator.TechStack], "Path: "+pathIndicator+" in "+rawURL)
			}
		}
	}
}

func (d *TechStackDetector) buildResults() []types.DetectedTech {
	var results []types.DetectedTech

	for tech := range d.detectedTechs {
		var indicator *TechIndicator
		for i := range techIndicators {
			if techIndicators[i].TechStack == tech {
				indicator = &techIndicators[i]
				break
			}
		}

		if indicator != nil {
			results = append(results, types.DetectedTech{
				TechStack:      tech,
				Confidence:     indicator.Confidence,
				Evidence:       d.evidence[tech],
				FileExtensions: indicator.FileExtensions,
			})
		}
	}

	return results
}

func (d *TechStackDetector) GetDetectedExtensions() map[string]bool {
	return d.detectedExtensions
}

func (d *TechStackDetector) GetTechStackNames() []string {
	var names []string
	for tech := range d.detectedTechs {
		names = append(names, string(tech))
	}
	return names
}

func GetExtensionsForTech(tech types.TechType) []string {
	for _, indicator := range techIndicators {
		if indicator.TechStack == tech {
			return indicator.FileExtensions
		}
	}
	return nil
}

func GetAllExtensions() map[string][]string {
	result := make(map[string][]string)
	for _, indicator := range techIndicators {
		result[string(indicator.TechStack)] = indicator.FileExtensions
	}
	return result
}
