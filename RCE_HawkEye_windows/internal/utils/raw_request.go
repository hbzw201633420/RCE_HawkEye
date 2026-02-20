package utils

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type RawRequest struct {
	Method     string
	URL        string
	Host       string
	Path       string
	Headers    map[string]string
	Parameters map[string]string
	PostData   map[string]string
	Body       string
	HTTPVersion string
}

func ParseRawTrafficFile(filepath string) ([]*RawRequest, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("无法打开文件: %v", err)
	}
	defer file.Close()

	var requests []*RawRequest
	var lines []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}

	var requestLines [][]string
	var currentReqLines []string

	for _, line := range lines {
		if strings.HasPrefix(line, "GET ") || strings.HasPrefix(line, "POST ") ||
			strings.HasPrefix(line, "PUT ") || strings.HasPrefix(line, "DELETE ") ||
			strings.HasPrefix(line, "PATCH ") || strings.HasPrefix(line, "HEAD ") ||
			strings.HasPrefix(line, "OPTIONS ") {
			if len(currentReqLines) > 0 {
				requestLines = append(requestLines, currentReqLines)
			}
			currentReqLines = []string{line}
		} else {
			currentReqLines = append(currentReqLines, line)
		}
	}
	if len(currentReqLines) > 0 {
		requestLines = append(requestLines, currentReqLines)
	}

	for _, reqLines := range requestLines {
		req, err := parseRawRequest(reqLines)
		if err == nil && req != nil {
			requests = append(requests, req)
		}
	}

	if len(requests) == 0 {
		return nil, fmt.Errorf("未找到有效的HTTP请求")
	}

	return requests, nil
}

func parseRawRequest(lines []string) (*RawRequest, error) {
	if len(lines) == 0 {
		return nil, fmt.Errorf("空请求")
	}

	req := &RawRequest{
		Headers:    make(map[string]string),
		Parameters: make(map[string]string),
		PostData:   make(map[string]string),
	}

	firstLine := lines[0]
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("无效的请求行: %s", firstLine)
	}

	req.Method = parts[0]
	req.Path = parts[1]
	if len(parts) > 2 {
		req.HTTPVersion = parts[2]
	} else {
		req.HTTPVersion = "HTTP/1.1"
	}

	bodyStart := -1
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" || line == "\r" {
			bodyStart = i + 1
			break
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx > 0 {
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			req.Headers[key] = value

			if strings.ToLower(key) == "host" {
				req.Host = value
			}
		}
	}

	if bodyStart > 0 && bodyStart < len(lines) {
		bodyLines := lines[bodyStart:]
		req.Body = strings.Join(bodyLines, "\n")
	}

	if req.Host != "" {
		scheme := "http"
		if req.Headers["Authorization"] != "" || strings.Contains(req.Host, ":443") {
			scheme = "https"
		}
		req.URL = fmt.Sprintf("%s://%s%s", scheme, req.Host, req.Path)
	} else {
		req.URL = req.Path
	}

	if strings.Contains(req.Path, "?") {
		pathParts := strings.SplitN(req.Path, "?", 2)
		req.Path = pathParts[0]
		if len(pathParts) > 1 {
			queryParams := pathParts[1]
			params := strings.Split(queryParams, "&")
			for _, param := range params {
				kv := strings.SplitN(param, "=", 2)
				if len(kv) == 2 {
					decodedKey, _ := url.QueryUnescape(kv[0])
					decodedValue, _ := url.QueryUnescape(kv[1])
					req.Parameters[decodedKey] = decodedValue
				} else if len(kv) == 1 {
					decodedKey, _ := url.QueryUnescape(kv[0])
					req.Parameters[decodedKey] = ""
				}
			}
		}
	}

	if req.Method == "POST" && req.Body != "" {
		contentType := req.Headers["Content-Type"]
		if contentType == "" {
			contentType = req.Headers["content-type"]
		}

		if strings.Contains(contentType, "application/x-www-form-urlencoded") {
			params := strings.Split(req.Body, "&")
			for _, param := range params {
				kv := strings.SplitN(param, "=", 2)
				if len(kv) == 2 {
					decodedKey, _ := url.QueryUnescape(kv[0])
					decodedValue, _ := url.QueryUnescape(kv[1])
					req.PostData[decodedKey] = decodedValue
				} else if len(kv) == 1 {
					decodedKey, _ := url.QueryUnescape(kv[0])
					req.PostData[decodedKey] = ""
				}
			}
		} else if strings.Contains(contentType, "multipart/form-data") {
			boundaryRegex := regexp.MustCompile(`boundary=([^;]+)`)
			matches := boundaryRegex.FindStringSubmatch(contentType)
			if len(matches) > 1 {
				boundary := matches[1]
				req.PostData = parseMultipartData(req.Body, boundary)
			}
		} else if strings.Contains(contentType, "application/json") {
			req.PostData["_json_body"] = req.Body
		} else {
			params := strings.Split(req.Body, "&")
			for _, param := range params {
				kv := strings.SplitN(param, "=", 2)
				if len(kv) == 2 {
					decodedKey, _ := url.QueryUnescape(kv[0])
					decodedValue, _ := url.QueryUnescape(kv[1])
					req.PostData[decodedKey] = decodedValue
				}
			}
		}
	}

	return req, nil
}

func parseMultipartData(body, boundary string) map[string]string {
	params := make(map[string]string)
	
	parts := strings.Split(body, "--"+boundary)
	for _, part := range parts {
		if strings.TrimSpace(part) == "" || part == "--" || part == "--\r\n" {
			continue
		}

		nameRegex := regexp.MustCompile(`name="([^"]+)"`)
		matches := nameRegex.FindStringSubmatch(part)
		if len(matches) > 1 {
			name := matches[1]
			
			headerEnd := strings.Index(part, "\r\n\r\n")
			if headerEnd == -1 {
				headerEnd = strings.Index(part, "\n\n")
				if headerEnd != -1 {
					headerEnd += 2
				}
			} else {
				headerEnd += 4
			}

			if headerEnd != -1 && headerEnd < len(part) {
				value := part[headerEnd:]
				value = strings.TrimSuffix(value, "\r\n")
				value = strings.TrimSuffix(value, "\n")
				params[name] = value
			}
		}
	}

	return params
}

func ParseBurpSuiteFile(filepath string) ([]*RawRequest, error) {
	return ParseRawTrafficFile(filepath)
}

func ParseRawRequestFromString(raw string) (*RawRequest, error) {
	lines := strings.Split(raw, "\n")
	return parseRawRequest(lines)
}
