package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/hbzw/RCE_HawkEye_go/internal/types"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Domain DomainConfig `yaml:"domain"`
	Scan   ScanConfig   `yaml:"scan"`
}

type DomainConfig struct {
	AllowedDomains    []string `yaml:"allowed_domains"`
	BlockedDomains    []string `yaml:"blocked_domains"`
	RestrictToRoot    bool     `yaml:"restrict_to_root"`
	MaxDepth          int      `yaml:"max_depth"`
	MaxPages          int      `yaml:"max_pages"`
	ExcludeExtensions []string `yaml:"exclude_extensions"`
}

type ScanConfig struct {
	Timeout        int     `yaml:"timeout"`
	MaxConcurrent  int     `yaml:"max_concurrent"`
	DelayThreshold float64 `yaml:"delay_threshold"`
	UserAgent      string  `yaml:"user_agent"`
	ScanLevel      string  `yaml:"scan_level"`
}

type ConfigManager struct {
	configPath   string
	DomainConfig *DomainConfig
	ScanConfig   *ScanConfig
}

func NewConfigManager(configPath string) *ConfigManager {
	cm := &ConfigManager{
		configPath: configPath,
		DomainConfig: &DomainConfig{
			RestrictToRoot: true,
			MaxDepth:       2,
			MaxPages:       100,
			ExcludeExtensions: []string{
				".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg",
				".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
				".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
				".zip", ".rar", ".tar", ".gz", ".7z",
				".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",
				".ico", ".xml", ".json", ".rss", ".atom",
			},
		},
		ScanConfig: &ScanConfig{
			Timeout:        10,
			MaxConcurrent:  10,
			DelayThreshold: 4.0,
			UserAgent:      "RCE-HawkEye/1.1.0",
			ScanLevel:      "normal",
		},
	}

	if configPath != "" {
		cm.Load(configPath)
	}

	return cm
}

func (cm *ConfigManager) Load(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return err
	}

	if config.Domain.MaxDepth > 0 {
		cm.DomainConfig.MaxDepth = config.Domain.MaxDepth
	}
	if config.Domain.MaxPages > 0 {
		cm.DomainConfig.MaxPages = config.Domain.MaxPages
	}
	if len(config.Domain.AllowedDomains) > 0 {
		cm.DomainConfig.AllowedDomains = config.Domain.AllowedDomains
	}
	if len(config.Domain.BlockedDomains) > 0 {
		cm.DomainConfig.BlockedDomains = config.Domain.BlockedDomains
	}
	if len(config.Domain.ExcludeExtensions) > 0 {
		cm.DomainConfig.ExcludeExtensions = config.Domain.ExcludeExtensions
	}

	if config.Scan.Timeout > 0 {
		cm.ScanConfig.Timeout = config.Scan.Timeout
	}
	if config.Scan.MaxConcurrent > 0 {
		cm.ScanConfig.MaxConcurrent = config.Scan.MaxConcurrent
	}
	if config.Scan.DelayThreshold > 0 {
		cm.ScanConfig.DelayThreshold = config.Scan.DelayThreshold
	}
	if config.Scan.UserAgent != "" {
		cm.ScanConfig.UserAgent = config.Scan.UserAgent
	}
	if config.Scan.ScanLevel != "" {
		cm.ScanConfig.ScanLevel = config.Scan.ScanLevel
	}

	return nil
}

func (cm *ConfigManager) Save(configPath string) error {
	if configPath == "" {
		configPath = cm.configPath
	}

	if configPath == "" {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return err
	}

	config := Config{
		Domain: *cm.DomainConfig,
		Scan:   *cm.ScanConfig,
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}

func (cm *ConfigManager) SetAllowedDomains(domains []string) {
	cm.DomainConfig.AllowedDomains = domains
}

func (cm *ConfigManager) SetBlockedDomains(domains []string) {
	cm.DomainConfig.BlockedDomains = domains
}

func (cm *ConfigManager) GetAllowedDomains() []string {
	return cm.DomainConfig.AllowedDomains
}

func (cm *ConfigManager) GetBlockedDomains() []string {
	return cm.DomainConfig.BlockedDomains
}

func (d *DomainConfig) IsAllowed(urlStr string) bool {
	return true
}

func (d *DomainConfig) DomainMatches(domain, pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return strings.HasSuffix(domain, suffix) || domain == suffix[1:]
	}
	return domain == pattern
}

func (d *DomainConfig) AddAllowedDomain(domain string) {
	for _, existing := range d.AllowedDomains {
		if existing == domain {
			return
		}
	}
	d.AllowedDomains = append(d.AllowedDomains, domain)
}

func (d *DomainConfig) AddBlockedDomain(domain string) {
	for _, existing := range d.BlockedDomains {
		if existing == domain {
			return
		}
	}
	d.BlockedDomains = append(d.BlockedDomains, domain)
}

func (d *DomainConfig) RemoveAllowedDomain(domain string) {
	for i, existing := range d.AllowedDomains {
		if existing == domain {
			d.AllowedDomains = append(d.AllowedDomains[:i], d.AllowedDomains[i+1:]...)
			return
		}
	}
}

func (d *DomainConfig) RemoveBlockedDomain(domain string) {
	for i, existing := range d.BlockedDomains {
		if existing == domain {
			d.BlockedDomains = append(d.BlockedDomains[:i], d.BlockedDomains[i+1:]...)
			return
		}
	}
}

func (d *DomainConfig) ToTypesDomainConfig() *types.DomainConfig {
	return &types.DomainConfig{
		AllowedDomains:    d.AllowedDomains,
		BlockedDomains:    d.BlockedDomains,
		RestrictToRoot:    d.RestrictToRoot,
		MaxDepth:          d.MaxDepth,
		MaxPages:          d.MaxPages,
		ExcludeExtensions: d.ExcludeExtensions,
	}
}
