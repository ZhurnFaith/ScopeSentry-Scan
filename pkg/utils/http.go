// utils-------------------------------------
// @file      : http.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2025/5/27 22:06
// -------------------------------------------

package utils

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// HttpClientConfig provide http.Client configuration options
type HttpClientConfig struct {
	Timeout             time.Duration
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	IdleConnTimeout     time.Duration
	TLSClientConfig     *tls.Config // TLS configuration can be customized (skip verification, custom CA, etc.)
	ProxyURL            string
	FollowRedirect      bool
}

// GetHttpClient return a configured http.Client
func GetHttpClient(cfg HttpClientConfig) *http.Client {
	var proxyFunc func(*http.Request) (*url.URL, error)

	if cfg.ProxyURL != "" {
		proxyURL, err := url.Parse(cfg.ProxyURL)
		if err == nil {
			proxyFunc = http.ProxyURL(proxyURL)
		} else {
			proxyFunc = nil
		}
	}

	transport := &http.Transport{
		Proxy:               proxyFunc,
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:     cfg.IdleConnTimeout,
		TLSClientConfig:     cfg.TLSClientConfig,
	}

	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
	}

	// ✅ if not following redirects, set CheckRedirect
	if !cfg.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

type Nethttp struct {
	Client *http.Client
}

var GlobalNetHttp *Nethttp

func InitializeNetHttp() {
	GlobalNetHttp = &Nethttp{}
	GlobalNetHttp.Client = GetHttpClient(HttpClientConfig{
		Timeout:             5 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 500,
		IdleConnTimeout:     60 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
	})
}

var (
	netHttpMap = make(map[string]*Nethttp)
	hmu        sync.Mutex
)

func getConfigKey(cfg HttpClientConfig) string {
	tlsSkipVerify := false
	if cfg.TLSClientConfig != nil {
		tlsSkipVerify = cfg.TLSClientConfig.InsecureSkipVerify
	}

	return fmt.Sprintf("p=%st=%dm=%dm=%di=%dt=%tf=%t",
		cfg.ProxyURL,
		int64(cfg.Timeout/time.Millisecond),
		cfg.MaxIdleConns,
		cfg.MaxIdleConnsPerHost,
		int64(cfg.IdleConnTimeout/time.Millisecond),
		tlsSkipVerify,
		cfg.FollowRedirect,
	)
}

// GetNetHttpByConfig get the Nethttp instance for the full configuration, cached for reuse
func GetNetHttpByConfig(cfg HttpClientConfig) *Nethttp {
	key := getConfigKey(cfg)

	hmu.Lock()
	defer hmu.Unlock()

	if instance, ok := netHttpMap[key]; ok {
		return instance
	}

	client := GetHttpClient(cfg)
	instance := &Nethttp{Client: client}

	netHttpMap[key] = instance
	return instance
}

func (n *Nethttp) HttpGetNoResWithCustomHeader(url string, customHeaders map[string]string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	for k, v := range customHeaders {
		req.Header.Set(k, v)
	}

	resp, err := n.Client.Do(req)
	if err != nil {
		//logger.SlogErrorLocal(fmt.Sprintf("HttpGetNoResWithCustomHeader func error: %v", err))
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (n *Nethttp) HttpPostNoResWithCustomHeader(url string, body []byte, contentType string, customHeaders map[string]string) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	if contentType == "json" {
		req.Header.Set("Content-Type", "application/json")
	} else {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	for k, v := range customHeaders {
		req.Header.Set(k, v)
	}

	resp, err := n.Client.Do(req)
	if err != nil {
		//logger.SlogErrorLocal(fmt.Sprintf("HttpPostNoResWithCustomHeader func error: %v", err))
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (n *Nethttp) HttpGetWithCustomHeader(uri string, customHeaders map[string]string) (types.HttpResponse, error) {
	// Create request
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return types.HttpResponse{}, err
	}

	// Add custom Header
	for k, v := range customHeaders {
		req.Header.Set(k, v)
	}
	// Send request
	resp, err := n.Client.Do(req)
	if err != nil {
		return types.HttpResponse{}, err
	}
	defer resp.Body.Close()

	tmp := types.HttpResponse{}
	tmp.Url = uri

	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			logger.SlogErrorLocal(fmt.Sprintf("gzip reader error: %v", err))
		} else {
			defer gzipReader.Close()
			reader = gzipReader
		}
	}

	// Limit max response body size (10MB)
	const maxBodySize = 10 * 1024 * 1024 // 10MB
	limitedReader := io.LimitReader(reader, maxBodySize)

	// Read response body
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		logger.SlogErrorLocal(fmt.Sprintf("HttpGetWithCustomHeader func error: %v", err))
		return types.HttpResponse{}, err
	}
	tmp.Body = string(bodyBytes)
	tmp.StatusCode = resp.StatusCode

	// Get redirect URL
	tmp.Redirect = resp.Header.Get("Location")

	// Settings Content-Length
	if resp.ContentLength >= 0 {
		tmp.ContentLength = int(resp.ContentLength)
	} else {
		tmp.ContentLength = len(bodyBytes)
	}
	return tmp, nil
}

func (n *Nethttp) HttpPostWithCustomHeader(uri string, requestBody []byte, ct string, customHeaders map[string]string) (error, HttpResponse) {
	// Create POST request
	req, err := http.NewRequest(http.MethodPost, uri, bytes.NewReader(requestBody))
	if err != nil {
		return err, HttpResponse{}
	}

	// Set default Content-Type (only when passed ct == "json")
	if ct == "json" {
		req.Header.Set("Content-Type", "application/json")
	}

	// Set custom Header
	for k, v := range customHeaders {
		req.Header.Set(k, v)
	}

	resp, err := n.Client.Do(req)
	if err != nil {
		logger.SlogErrorLocal(fmt.Sprintf("HttpPostWithCustomHeader func error: %v", err))
		return err, HttpResponse{}
	}
	defer resp.Body.Close()

	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			logger.SlogErrorLocal(fmt.Sprintf("gzip reader error: %v", err))
		} else {
			defer gzipReader.Close()
			reader = gzipReader
		}
	}

	// Limit max response body size (10MB)
	const maxBodySize = 10 * 1024 * 1024 // 10MB
	limitedReader := io.LimitReader(reader, maxBodySize)

	// Read response body
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return err, HttpResponse{}
	}

	// Extract response headers
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}

	res := HttpResponse{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       bodyBytes,
	}
	return nil, res
}
