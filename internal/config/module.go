// config-------------------------------------
// @file      : module.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/7 19:48
// -------------------------------------------

package config

import (
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils"
	"log"
)

type SubdomainScanConfig struct {
	GoroutineCount int `yaml:"goroutineCount"` // Number of goroutines
}

type SubdomainSecurityConfig struct {
	GoroutineCount int `yaml:"goroutineCount"` // Number of goroutines
}

type AssetMappConfig struct {
	GoroutineCount int `yaml:"goroutineCount"` // Number of goroutines
}

type PortScanPreparationConfig struct {
	GoroutineCount int `yaml:"goroutineCount"` // Number of goroutines
}
type PortScanConfig struct {
	GoroutineCount int `yaml:"goroutineCount"` // Number of goroutines
}

type PortFingerprintConfig struct {
	GoroutineCount int `yaml:"goroutineCount"` // Number of goroutines
}

type AssetHandleConfig struct {
	GoroutineCount int `yaml:"goroutineCount"` // Number of goroutines
}

type URLScanConfig struct {
	GoroutineCount int `yaml:"goroutineCount"` // Number of goroutines
}

type URLSecurityConfig struct {
	GoroutineCount int `yaml:"goroutineCount"` // Number of goroutines
}

type WebCrawlerConfig struct {
	GoroutineCount int `yaml:"goroutineCount"` // Number of goroutines
}

type DirScanConfig struct {
	GoroutineCount int `yaml:"goroutineCount"` // Number of goroutines
}

type VulnerabilityScanConfig struct {
	GoroutineCount int `yaml:"goroutineCount"` // Number of goroutines
}

type ModulesConfigStruct struct {
	MaxGoroutineCount   int                       `yaml:"maxGoroutineCount"`
	SubdomainScan       SubdomainScanConfig       `yaml:"subdomainScan"`
	SubdomainSecurity   SubdomainSecurityConfig   `yaml:"subdomainSecurity"`
	AssetMapping        AssetMappConfig           `yaml:"assetMapping"`
	AssetHandle         AssetHandleConfig         `yaml:"assetHandle"`
	PortScanPreparation PortScanPreparationConfig `yaml:"portScanPreparation"`
	PortScan            PortScanConfig            `yaml:"portScan"`
	PortFingerprint     PortFingerprintConfig     `yaml:"portFingerprint"`
	URLScan             URLScanConfig             `yaml:"URLScan"`
	URLSecurity         URLSecurityConfig         `yaml:"URLSecurity"`
	WebCrawler          WebCrawlerConfig          `yaml:"webCrawler"`
	DirScan             DirScanConfig             `yaml:"dirScan"`
	VulnerabilityScan   VulnerabilityScanConfig   `yaml:"vulnerabilityScan"`
}

var ModulesConfigPath string
var ModulesConfig *ModulesConfigStruct

func ModulesInitialize() error {
	if err := utils.Tools.ReadYAMLFile(ModulesConfigPath, &ModulesConfig); err != nil {
		return err
	}
	return nil
}

func (cfg *ModulesConfigStruct) GetGoroutineCount(moduleName string) int {
	switch moduleName {
	case "task":
		return cfg.MaxGoroutineCount // This module uses the global max goroutines
	case "TargetHandler":
		return cfg.MaxGoroutineCount // This module uses the global max goroutines
	case "SubdomainScan":
		return cfg.SubdomainScan.GoroutineCount
	case "SubdomainSecurity":
		return cfg.SubdomainSecurity.GoroutineCount
	case "AssetMapping":
		return cfg.AssetMapping.GoroutineCount
	case "PortScanPreparation":
		return cfg.PortScanPreparation.GoroutineCount
	case "PortScan":
		return cfg.PortScan.GoroutineCount
	case "PortFingerprint":
		return cfg.PortFingerprint.GoroutineCount
	case "AssetHandle":
		return cfg.AssetHandle.GoroutineCount
	case "URLScan":
		return cfg.URLScan.GoroutineCount
	case "URLSecurity":
		return cfg.URLSecurity.GoroutineCount
	case "WebCrawler":
		return cfg.WebCrawler.GoroutineCount
	case "DirScan":
		return cfg.DirScan.GoroutineCount
	case "VulnerabilityScan":
		return cfg.VulnerabilityScan.GoroutineCount
	default:
		log.Printf(fmt.Sprintf("Module %v thread limit not found", moduleName))
		return 0 // Default value, means no matching module was found
	}
}
