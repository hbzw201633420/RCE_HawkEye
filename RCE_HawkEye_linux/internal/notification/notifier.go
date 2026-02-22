package notification

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

type NotificationConfig struct {
	Enabled     bool   `json:"enabled"`
	WeChatKey   string `json:"wechat_key"`
	DingTalkKey string `json:"dingtalk_key"`
	EmailHost   string `json:"email_host"`
	EmailPort   int    `json:"email_port"`
	EmailUser   string `json:"email_user"`
	EmailPass   string `json:"email_pass"`
	EmailTo     string `json:"email_to"`
	EmailFrom   string `json:"email_from"`
}

type Notification struct {
	Title   string                 `json:"title"`
	Message string                 `json:"message"`
	Level   string                 `json:"level"`
	Data    map[string]interface{} `json:"data"`
}

type Notifier interface {
	Send(notification *Notification) error
	IsEnabled() bool
}

type WeChatNotifier struct {
	key string
}

func NewWeChatNotifier(key string) *WeChatNotifier {
	return &WeChatNotifier{key: key}
}

func (w *WeChatNotifier) IsEnabled() bool {
	return w.key != ""
}

func (w *WeChatNotifier) Send(n *Notification) error {
	if !w.IsEnabled() {
		return nil
	}

	var content strings.Builder
	content.WriteString(fmt.Sprintf("## %s\n\n", n.Title))
	content.WriteString(fmt.Sprintf("**级别**: %s\n\n", strings.ToUpper(n.Level)))
	content.WriteString(fmt.Sprintf("**时间**: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("**消息**: %s\n\n", n.Message))

	if len(n.Data) > 0 {
		content.WriteString("\n**详细信息**:\n")
		for k, v := range n.Data {
			content.WriteString(fmt.Sprintf("- %s: %v\n", k, v))
		}
	}

	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"content": content.String(),
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=%s", w.key)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if errmsg, ok := result["errmsg"]; ok && errmsg != "ok" {
		return fmt.Errorf("wechat notification failed: %v", result)
	}

	return nil
}

type DingTalkNotifier struct {
	webhook string
}

func NewDingTalkNotifier(webhook string) *DingTalkNotifier {
	return &DingTalkNotifier{webhook: webhook}
}

func (d *DingTalkNotifier) IsEnabled() bool {
	return d.webhook != ""
}

func (d *DingTalkNotifier) Send(n *Notification) error {
	if !d.IsEnabled() {
		return nil
	}

	var content strings.Builder
	content.WriteString(fmt.Sprintf("### %s\n\n", n.Title))
	content.WriteString(fmt.Sprintf("**级别**: %s\n\n", strings.ToUpper(n.Level)))
	content.WriteString(fmt.Sprintf("**时间**: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("**消息**: %s\n\n", n.Message))

	if len(n.Data) > 0 {
		content.WriteString("\n**详细信息**:\n")
		for k, v := range n.Data {
			content.WriteString(fmt.Sprintf("- %s: %v\n", k, v))
		}
	}

	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": n.Title,
			"text":  content.String(),
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(d.webhook, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if errcode, ok := result["errcode"]; ok && errcode.(float64) != 0 {
		return fmt.Errorf("dingtalk notification failed: %v", result)
	}

	return nil
}

type EmailNotifier struct {
	host     string
	port     int
	user     string
	password string
	from     string
	to       string
}

func NewEmailNotifier(host string, port int, user, password, from, to string) *EmailNotifier {
	return &EmailNotifier{
		host:     host,
		port:     port,
		user:     user,
		password: password,
		from:     from,
		to:       to,
	}
}

func (e *EmailNotifier) IsEnabled() bool {
	return e.host != "" && e.user != "" && e.to != ""
}

func (e *EmailNotifier) Send(n *Notification) error {
	if !e.IsEnabled() {
		return nil
	}

	subject := fmt.Sprintf("[RCE HawkEye] %s", n.Title)

	var body strings.Builder
	body.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	body.WriteString(fmt.Sprintf("From: %s\r\n", e.from))
	body.WriteString(fmt.Sprintf("To: %s\r\n", e.to))
	body.WriteString("MIME-Version: 1.0\r\n")
	body.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	body.WriteString("\r\n")

	body.WriteString(fmt.Sprintf("<html><body>"))
	body.WriteString(fmt.Sprintf("<h2>%s</h2>", n.Title))
	body.WriteString(fmt.Sprintf("<p><strong>级别:</strong> %s</p>", strings.ToUpper(n.Level)))
	body.WriteString(fmt.Sprintf("<p><strong>时间:</strong> %s</p>", time.Now().Format("2006-01-02 15:04:05")))
	body.WriteString(fmt.Sprintf("<p><strong>消息:</strong> %s</p>", n.Message))

	if len(n.Data) > 0 {
		body.WriteString("<h3>详细信息:</h3><ul>")
		for k, v := range n.Data {
			body.WriteString(fmt.Sprintf("<li><strong>%s:</strong> %v</li>", k, v))
		}
		body.WriteString("</ul>")
	}
	body.WriteString("</body></html>")

	auth := smtp.PlainAuth("", e.user, e.password, e.host)

	addr := fmt.Sprintf("%s:%d", e.host, e.port)

	client, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		config := &tls.Config{ServerName: e.host}
		if err = client.StartTLS(config); err != nil {
			return err
		}
	}

	if err = client.Auth(auth); err != nil {
		return err
	}

	if err = client.Mail(e.from); err != nil {
		return err
	}

	for _, to := range strings.Split(e.to, ",") {
		to = strings.TrimSpace(to)
		if err = client.Rcpt(to); err != nil {
			return err
		}
	}

	w, err := client.Data()
	if err != nil {
		return err
	}

	_, err = w.Write([]byte(body.String()))
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	return client.Quit()
}

type NotificationManager struct {
	config    *NotificationConfig
	wechat    *WeChatNotifier
	dingtalk  *DingTalkNotifier
	email     *EmailNotifier
}

func (m *NotificationManager) GetWeChat() *WeChatNotifier {
	return m.wechat
}

func (m *NotificationManager) GetDingTalk() *DingTalkNotifier {
	return m.dingtalk
}

func (m *NotificationManager) GetEmail() *EmailNotifier {
	return m.email
}

var (
	notifManager     *NotificationManager
	notifManagerOnce sync.Once
)

func GetManager() *NotificationManager {
	notifManagerOnce.Do(func() {
		notifManager = &NotificationManager{
			config: &NotificationConfig{},
		}
	})
	return notifManager
}

func (m *NotificationManager) Configure(config *NotificationConfig) {
	m.config = config
	m.wechat = NewWeChatNotifier(config.WeChatKey)
	m.dingtalk = NewDingTalkNotifier(config.DingTalkKey)
	m.email = NewEmailNotifier(
		config.EmailHost,
		config.EmailPort,
		config.EmailUser,
		config.EmailPass,
		config.EmailFrom,
		config.EmailTo,
	)
}

func (m *NotificationManager) SendAll(n *Notification) []error {
	var errors []error

	if m.wechat != nil && m.wechat.IsEnabled() {
		if err := m.wechat.Send(n); err != nil {
			errors = append(errors, fmt.Errorf("wechat: %w", err))
		}
	}

	if m.dingtalk != nil && m.dingtalk.IsEnabled() {
		if err := m.dingtalk.Send(n); err != nil {
			errors = append(errors, fmt.Errorf("dingtalk: %w", err))
		}
	}

	if m.email != nil && m.email.IsEnabled() {
		if err := m.email.Send(n); err != nil {
			errors = append(errors, fmt.Errorf("email: %w", err))
		}
	}

	return errors
}

func (m *NotificationManager) SendScanComplete(target string, vulnCount int, criticalCount int, highCount int, duration float64) {
	n := &Notification{
		Title:   "扫描完成",
		Message: fmt.Sprintf("目标 %s 扫描完成，发现 %d 个漏洞", target, vulnCount),
		Level:   "info",
		Data: map[string]interface{}{
			"目标":       target,
			"漏洞总数":     vulnCount,
			"严重漏洞":    criticalCount,
			"高危漏洞":    highCount,
			"扫描时长":    fmt.Sprintf("%.2f 秒", duration),
			"扫描完成时间": time.Now().Format("2006-01-02 15:04:05"),
		},
	}

	if criticalCount > 0 {
		n.Level = "critical"
	} else if highCount > 0 {
		n.Level = "high"
	}

	m.SendAll(n)
}

func (m *NotificationManager) SendVulnFound(target string, vulnType string, severity string, parameter string) {
	n := &Notification{
		Title:   "发现漏洞",
		Message: fmt.Sprintf("在 %s 发现 %s 漏洞", target, vulnType),
		Level:   severity,
		Data: map[string]interface{}{
			"目标":     target,
			"漏洞类型":   vulnType,
			"危险等级":   severity,
			"参数":     parameter,
			"发现时间": time.Now().Format("2006-01-02 15:04:05"),
		},
	}

	m.SendAll(n)
}

func (m *NotificationManager) SendError(title string, message string) {
	n := &Notification{
		Title:   title,
		Message: message,
		Level:   "error",
		Data: map[string]interface{}{
			"时间": time.Now().Format("2006-01-02 15:04:05"),
		},
	}

	m.SendAll(n)
}

func (m *NotificationManager) IsEnabled() bool {
	return m.config.Enabled
}

func (m *NotificationManager) GetConfig() *NotificationConfig {
	return m.config
}
