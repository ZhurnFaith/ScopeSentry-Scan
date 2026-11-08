// Package main -----------------------------
// @file      : testConfig.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2023/12/11 20:15
// -------------------------------------------
package main

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

type Config struct {
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	ID      string `yaml:"id"`
	Enabled bool   `yaml:"enabled"`
}

func main() {
	scopeSentryConfigPath := filepath.Join("C:\\Users\\ThreatBook\\Desktop\\", "a.ymal")
	yamlFile, err := os.ReadFile(scopeSentryConfigPath)
	if err != nil {

	}

	// Create a Config object to hold the parsed configuration
	var config Config

	// Parse YAML content into the Config object with the yaml library
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {

	}

	// Print parsed configuration
	fmt.Printf("Config: %+v\n", config)

	// Iterate over rules and print each rule's info
	for _, rule := range config.Rules {
		fmt.Printf("Rule ID: %s, Enabled: %t\n", rule.ID, rule.Enabled)
	}
}
