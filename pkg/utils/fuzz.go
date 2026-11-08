// utils-------------------------------------
// @file      : fuzz.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2025/8/7 22:04
// -------------------------------------------

package utils

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

func GetKeyValue(key, id, tp, dnslog string) string {
	var sb strings.Builder
	sb.WriteString(key)
	sb.WriteByte('=')
	sb.WriteString("http://")
	sb.WriteString(id)
	sb.WriteByte('.')
	sb.WriteString(key)
	sb.WriteByte('.')
	sb.WriteString(tp)
	sb.WriteByte('.')
	sb.WriteString(dnslog)
	return url.QueryEscape(sb.String())
}

func GetJsonValue(key, id, dnslog string) string {
	var sb strings.Builder
	sb.WriteString("http://")
	sb.WriteString(id)
	sb.WriteByte('.')
	sb.WriteString(key)
	sb.WriteString(".3.")
	sb.WriteString(dnslog)
	return sb.String()
}

var cfg = HttpClientConfig{
	Timeout:             3 * time.Second,
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 50,
	IdleConnTimeout:     60 * time.Second,
	TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
	FollowRedirect:      false,
}

var client = GetNetHttpByConfig(cfg)

func FuzzGet(uri string, id string, header map[string]string, wg *sync.WaitGroup, testParam []string, dnslog string) {
	defer wg.Done()
	var builder strings.Builder
	for _, key := range testParam {
		if key == "" {
			continue
		}
		builder.WriteByte('&')
		builder.WriteString(GetKeyValue(key, id, "1", dnslog))

		if builder.Len() > 1000 {
			// Remove first '&'
			paramStr := builder.String()[1:]
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				FuzzHttpGetNoResWithCustomHeader(uri+"?"+p, header)
			}(paramStr)
			builder.Reset() // Reuse builder to avoid new allocations
		}
	}

	if builder.Len() > 0 {
		paramStr := builder.String()[1:]
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			FuzzHttpGetNoResWithCustomHeader(uri+"?"+p, header)
		}(paramStr)
	}
}

func FuzzPostJson(uri string, id string, header map[string]string, wg *sync.WaitGroup, testParam []string, dnslog string) {
	defer wg.Done()
	params := make(map[string]string)
	for _, key := range testParam {
		if key == "" {
			continue
		}
		params[key] = GetJsonValue(key, id, dnslog)
	}
	jsonData, err := json.Marshal(params)
	if err != nil {
		// Handle JSON serialization error
		fmt.Println("JSON serialization failed:", err)
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		FuzzHttpPostNoResWithCustomHeader(uri, jsonData, "json", header)
	}()
}

func FuzzPost(uri string, id string, header map[string]string, wg *sync.WaitGroup, testParam []string, dnslog string) {
	defer wg.Done()

	var builder strings.Builder

	for _, key := range testParam {
		if key == "" {
			continue
		}

		builder.WriteByte('&')
		builder.WriteString(GetKeyValue(key, id, "2", dnslog))

		// Send when parameter length exceeds the threshold
		if builder.Len() > 1024*1020 {
			paramStr := builder.String()[1:] // Remove first '&'
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				FuzzHttpPostNoResWithCustomHeader(uri, []byte(p), "url", header)
			}(paramStr)
			builder.Reset() // Reuse builder memory
		}
	}

	// Send remaining parameters
	if builder.Len() > 0 {
		paramStr := builder.String()[1:]
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			FuzzHttpPostNoResWithCustomHeader(uri, []byte(p), "url", header)
		}(paramStr)
	}
}

func FuzzHttpGetNoResWithCustomHeader(url string, header map[string]string) {
	err := client.HttpGetNoResWithCustomHeader(url, header)
	if err != nil {
	}
}

func FuzzHttpPostNoResWithCustomHeader(url string, body []byte, contentType string, customHeaders map[string]string) {
	err := client.HttpPostNoResWithCustomHeader(url, body, contentType, customHeaders)
	if err != nil {
	}
}
