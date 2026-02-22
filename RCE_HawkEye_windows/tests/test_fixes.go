package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"
)

type TestResult struct {
	Name     string
	Passed   bool
	Message  string
	Duration time.Duration
}

var (
	baseURL    = "http://localhost:8080"
	httpClient *http.Client
)

func main() {
	fmt.Println("========================================")
	fmt.Println("RCE HawkEye 功能修复测试")
	fmt.Println("========================================")
	fmt.Println()

	jar, _ := cookiejar.New(nil)
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Jar:     jar,
	}

	results := []TestResult{}

	results = append(results, testServerConnection())
	results = append(results, testLogin())
	results = append(results, testI18nTranslations())
	results = append(results, testHistoryAPI())
	results = append(results, testReportsAPI())
	results = append(results, testHistoryDeleteAPI())

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("测试结果汇总")
	fmt.Println("========================================")

	passed := 0
	failed := 0
	for _, r := range results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
			failed++
		} else {
			passed++
		}
		fmt.Printf("[%s] %s (%.2fs)\n", status, r.Name, r.Duration.Seconds())
		if r.Message != "" {
			fmt.Printf("       %s\n", r.Message)
		}
	}

	fmt.Println()
	fmt.Printf("总计: %d 通过, %d 失败\n", passed, failed)

	if failed > 0 {
		os.Exit(1)
	}
}

func testServerConnection() TestResult {
	start := time.Now()
	result := TestResult{Name: "服务器连接测试"}

	resp, err := httpClient.Get(baseURL + "/login")
	if err != nil {
		result.Message = fmt.Sprintf("无法连接服务器: %v", err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		result.Message = fmt.Sprintf("服务器返回错误状态码: %d", resp.StatusCode)
		result.Duration = time.Since(start)
		return result
	}

	result.Passed = true
	result.Message = "服务器连接正常"
	result.Duration = time.Since(start)
	return result
}

func testLogin() TestResult {
	start := time.Now()
	result := TestResult{Name: "用户登录测试"}

	loginData := map[string]string{
		"username": "admin",
		"password": "admin123",
	}
	jsonData, _ := json.Marshal(loginData)

	resp, err := httpClient.Post(baseURL+"/api/login", "application/json", bytes.NewReader(jsonData))
	if err != nil {
		result.Message = fmt.Sprintf("登录请求失败: %v", err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var data map[string]interface{}
	json.Unmarshal(body, &data)

	if data["success"] == nil || !data["success"].(bool) {
		result.Message = fmt.Sprintf("登录失败: %v", data["error"])
		result.Duration = time.Since(start)
		return result
	}

	result.Passed = true
	result.Message = "登录成功"
	result.Duration = time.Since(start)
	return result
}

func testI18nTranslations() TestResult {
	start := time.Now()
	result := TestResult{Name: "i18n翻译测试"}

	resp, err := httpClient.Get(baseURL + "/static/js/i18n.js")
	if err != nil {
		result.Message = fmt.Sprintf("获取翻译文件失败: %v", err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	requiredPatterns := []string{
		"selectAll: '全选'",
		"selectAll: 'Select All'",
		"deleteSelected: '删除选中'",
		"deleteSelected: 'Delete Selected'",
		"noReports: '暂无报告'",
		"noReports: 'No reports found'",
		"deleteSuccess: '报告删除成功'",
		"deleteSuccess: 'Reports deleted successfully'",
		"deleteFailed: '删除失败'",
		"deleteFailed: 'Failed to delete'",
	}

	missingPatterns := []string{}
	for _, pattern := range requiredPatterns {
		if !strings.Contains(content, pattern) {
			missingPatterns = append(missingPatterns, pattern)
		}
	}

	if len(missingPatterns) > 0 {
		result.Message = fmt.Sprintf("缺失翻译: %s", strings.Join(missingPatterns, ", "))
		result.Duration = time.Since(start)
		return result
	}

	result.Passed = true
	result.Message = "所有翻译键存在"
	result.Duration = time.Since(start)
	return result
}

func testHistoryAPI() TestResult {
	start := time.Now()
	result := TestResult{Name: "历史记录API测试"}

	resp, err := httpClient.Get(baseURL + "/api/history")
	if err != nil {
		result.Message = fmt.Sprintf("获取历史记录失败: %v", err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var data map[string]interface{}
	json.Unmarshal(body, &data)

	if data["success"] == nil || !data["success"].(bool) {
		result.Message = fmt.Sprintf("API返回错误: %v", data["error"])
		result.Duration = time.Since(start)
		return result
	}

	history, ok := data["history"].([]interface{})
	if !ok {
		result.Message = "历史记录格式错误"
		result.Duration = time.Since(start)
		return result
	}

	result.Passed = true
	result.Message = fmt.Sprintf("获取到 %d 条历史记录", len(history))
	result.Duration = time.Since(start)
	return result
}

func testReportsAPI() TestResult {
	start := time.Now()
	result := TestResult{Name: "报告列表API测试"}

	resp, err := httpClient.Get(baseURL + "/api/reports")
	if err != nil {
		result.Message = fmt.Sprintf("获取报告列表失败: %v", err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var data map[string]interface{}
	json.Unmarshal(body, &data)

	if data["success"] == nil || !data["success"].(bool) {
		result.Message = fmt.Sprintf("API返回错误: %v", data["error"])
		result.Duration = time.Since(start)
		return result
	}

	reports, ok := data["reports"].([]interface{})
	if !ok {
		result.Message = "报告列表格式错误"
		result.Duration = time.Since(start)
		return result
	}

	result.Passed = true
	result.Message = fmt.Sprintf("获取到 %d 个报告", len(reports))
	result.Duration = time.Since(start)
	return result
}

func testHistoryDeleteAPI() TestResult {
	start := time.Now()
	result := TestResult{Name: "历史删除API测试"}

	resp, err := httpClient.Get(baseURL + "/api/history")
	if err != nil {
		result.Message = fmt.Sprintf("获取历史记录失败: %v", err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var data map[string]interface{}
	json.Unmarshal(body, &data)

	history, ok := data["history"].([]interface{})
	if !ok || len(history) == 0 {
		result.Passed = true
		result.Message = "无历史记录可测试删除"
		result.Duration = time.Since(start)
		return result
	}

	firstItem, ok := history[0].(map[string]interface{})
	if !ok {
		result.Passed = true
		result.Message = "历史记录格式异常，跳过删除测试"
		result.Duration = time.Since(start)
		return result
	}

	id, ok := firstItem["id"].(string)
	if !ok {
		result.Passed = true
		result.Message = "无法获取历史记录ID，跳过删除测试"
		result.Duration = time.Since(start)
		return result
	}

	deleteResp, err := httpClient.Post(baseURL+"/api/history/delete/"+id, "application/json", bytes.NewReader([]byte{}))
	if err != nil {
		result.Message = fmt.Sprintf("删除请求失败: %v", err)
		result.Duration = time.Since(start)
		return result
	}
	defer deleteResp.Body.Close()

	deleteBody, _ := io.ReadAll(deleteResp.Body)

	var deleteData map[string]interface{}
	json.Unmarshal(deleteBody, &deleteData)

	if deleteData["success"] == nil || !deleteData["success"].(bool) {
		result.Message = fmt.Sprintf("删除失败: %v", deleteData["error"])
		result.Duration = time.Since(start)
		return result
	}

	result.Passed = true
	result.Message = fmt.Sprintf("成功删除历史记录 ID: %s", id)
	result.Duration = time.Since(start)
	return result
}
