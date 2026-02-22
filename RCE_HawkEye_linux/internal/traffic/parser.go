package traffic

import (
	"os"
	"regexp"
	"strings"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
)

type TrafficParser struct {
	requests []types.HttpRequest
}

func NewTrafficParser() *TrafficParser {
	return &TrafficParser{
		requests: make([]types.HttpRequest, 0),
	}
}

func (p *TrafficParser) ParseFile(filepath string) ([]types.HttpRequest, error) {
	content, err := readFile(filepath)
	if err != nil {
		return nil, err
	}

	p.requests = p.parseRawRequests(content)
	return p.requests, nil
}

func (p *TrafficParser) parseRawRequests(content string) []types.HttpRequest {
	var requests []types.HttpRequest

	rawRequests := p.splitRequests(content)

	for _, raw := range rawRequests {
		req := p.parseSingleRequest(raw)
		if req != nil {
			requests = append(requests, *req)
		}
	}

	return requests
}

func (p *TrafficParser) splitRequests(content string) []string {
	pattern := `(?:^|\n)(?=(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+)`
	re := regexp.MustCompile(pattern)
	parts := re.Split(content, -1)

	var requests []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			if matched, _ := regexp.MatchString(`^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+`, part); matched {
				requests = append(requests, part)
			}
		}
	}

	return requests
}

func (p *TrafficParser) parseSingleRequest(raw string) *types.HttpRequest {
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return nil
	}

	requestLine := strings.TrimSpace(lines[0])
	re := regexp.MustCompile(`^(\w+)\s+([^\s]+)\s+(HTTP/[\d.]+)?$`)
	matches := re.FindStringSubmatch(requestLine)
	if matches == nil {
		return nil
	}

	method := strings.ToUpper(matches[1])
	path := matches[2]
	version := matches[3]
	if version == "" {
		version = "HTTP/1.1"
	}

	headers := make(map[string]string)
	bodyStart := -1

	for i, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")

		if line == "" {
			bodyStart = i + 2
			break
		}

		if idx := strings.Index(line, ":"); idx != -1 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			headers[key] = value
		}
	}

	var body string
	if bodyStart > 0 && bodyStart < len(lines) {
		bodyLines := lines[bodyStart:]
		body = strings.TrimSpace(strings.Join(bodyLines, "\n"))
	}

	return &types.HttpRequest{
		Method:     method,
		Path:       path,
		Version:    version,
		Headers:    headers,
		Body:       body,
		RawRequest: raw,
	}
}

func (p *TrafficParser) GetRequests() []types.HttpRequest {
	return p.requests
}

func (p *TrafficParser) GetRequestsByMethod(method string) []types.HttpRequest {
	var result []types.HttpRequest
	for _, r := range p.requests {
		if strings.ToUpper(r.Method) == strings.ToUpper(method) {
			result = append(result, r)
		}
	}
	return result
}

func (p *TrafficParser) GetRequestsByPath(pattern string) []types.HttpRequest {
	var result []types.HttpRequest
	re := regexp.MustCompile(pattern)
	for _, r := range p.requests {
		if re.MatchString(r.Path) {
			result = append(result, r)
		}
	}
	return result
}

func readFile(filepath string) (string, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
