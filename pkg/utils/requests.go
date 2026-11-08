// utils-------------------------------------
// @file      : requests.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/19 20:48
// -------------------------------------------

package utils

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/runner"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/valyala/fasthttp"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

type request struct {
}

var Requests *request

var HttpClient *fasthttp.Client
var Wappalyzer *wappalyzer.Wappalyze

type HttpResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

func InitializeRequests() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning) // increase the verbosity (optional)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	HttpClient = &fasthttp.Client{
		ReadTimeout:                   time.Second * 10,
		WriteTimeout:                  time.Second * 10,
		MaxIdleConnDuration:           time.Second * 10,
		NoDefaultUserAgentHeader:      true,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
		TLSConfig:                     tlsConfig,
		ReadBufferSize:                4 * 1024 * 1024,
		MaxResponseBodySize:           10 * 1024 * 1024,
		Dial: (&fasthttp.TCPDialer{
			Concurrency:      4096,
			DNSCacheDuration: time.Hour,
		}).Dial,
	}
	Requests = &request{}
	paralyze, err := wappalyzer.New()
	if err != nil {
		fmt.Printf("init wappalyzer error: %v", err)
	}
	Wappalyzer = paralyze
}

func (r *request) HttpGet(uri string) (types.HttpResponse, error) {
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	// Finally req and resp must be returned to the pool
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()
	req.Header.SetMethod(fasthttp.MethodGet)
	req.SetRequestURI(uri)
	if err := HttpClient.Do(req, resp); err != nil {
		return types.HttpResponse{}, err
	}
	tmp := types.HttpResponse{}
	tmp.Url = uri

	tmp.Body = string(resp.Body())
	tmp.StatusCode = resp.StatusCode()
	if location := resp.Header.Peek("location"); len(location) > 0 {
		tmp.Redirect = string(location)
	} else {
		rd := resp.Header.Peek("Location")
		if len(rd) > 0 {
			tmp.Redirect = string(rd)
		} else {
			tmp.Redirect = ""
		}
	}
	tmp.ContentLength = resp.Header.ContentLength()
	if tmp.ContentLength < 0 {
		tmp.ContentLength = len(resp.Body())
	}
	return tmp, nil
}
func (r *request) HttpGetByte(uri string) ([]byte, error) {
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	// Finally req and resp must be returned to the pool
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()
	req.Header.SetMethod(fasthttp.MethodGet)
	req.SetRequestURI(uri)
	if err := HttpClient.Do(req, resp); err != nil {
		return make([]byte, 0), err
	}
	tmp := resp.Body()
	return tmp, nil
}

func fixJSONNewlines(b []byte) []byte {
	var out []byte
	inString := false
	escaped := false

	for i := 0; i < len(b); i++ {
		c := b[i]

		if escaped {
			out = append(out, c)
			escaped = false
			continue
		}

		if c == '\\' {
			escaped = true
			out = append(out, c)
			continue
		}

		if c == '"' {
			inString = !inString
			out = append(out, c)
			continue
		}

		if inString && (c == '\n' || c == '\r') {
			// Escape newlines
			out = append(out, '\\', 'n')
			continue
		}

		out = append(out, c)
	}

	return out
}

func (r *request) HttpPost(uri string, requestBody []byte, ct string) (error, HttpResponse) {
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()
	req.Header.SetMethod(fasthttp.MethodPost)
	req.SetRequestURI(uri)
	if ct == "json" {
		req.Header.Set("Content-Type", "application/json")
		requestBody = fixJSONNewlines(requestBody)
	}
	req.SetBody(requestBody)

	if err := HttpClient.Do(req, resp); err != nil {
		return err, HttpResponse{}
	}
	headers := make(map[string]string)
	resp.Header.VisitAll(func(key, value []byte) {
		headers[string(key)] = string(value)
	})
	res := HttpResponse{
		StatusCode: resp.StatusCode(),
		Headers:    headers,
		Body:       append([]byte(nil), resp.Body()...),
	}
	return nil, res
}

func (r *request) HttpGetWithCustomHeader(uri string, customHeaders []string) (types.HttpResponse, error) {
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	// Finally req and resp must be returned to the pool
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()

	req.Header.SetMethod(fasthttp.MethodGet)
	req.SetRequestURI(uri)

	// Set custom headers
	for _, header := range customHeaders {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(parts[0], strings.TrimSpace(parts[1]))
		}
	}

	if err := HttpClient.Do(req, resp); err != nil {
		return types.HttpResponse{}, err
	}
	tmp := types.HttpResponse{}
	tmp.Url = uri
	// Define max response body size (100KB)
	const maxBodySize = 4 * 1024 * 1024

	// Truncate Body
	body := resp.Body()
	if len(body) > maxBodySize {
		body = body[:maxBodySize]
	}
	tmp.Body = string(body)
	tmp.StatusCode = resp.StatusCode()
	if location := resp.Header.Peek("location"); len(location) > 0 {
		tmp.Redirect = string(location)
	} else {
		rd := resp.Header.Peek("Location")
		if len(rd) > 0 {
			tmp.Redirect = string(rd)
		} else {
			tmp.Redirect = ""
		}
	}
	tmp.ContentLength = resp.Header.ContentLength()
	if tmp.ContentLength < 0 {
		tmp.ContentLength = len(resp.Body())
	}
	return tmp, nil
}

func (r *request) HttpGetByteWithCustomHeader(uri string, customHeaders []string) ([]byte, error) {
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	// Finally req and resp must be returned to the pool
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()

	req.Header.SetMethod(fasthttp.MethodGet)
	req.SetRequestURI(uri)

	// Set custom headers
	for _, header := range customHeaders {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(parts[0], strings.TrimSpace(parts[1]))
		}
	}

	if err := HttpClient.Do(req, resp); err != nil {
		return make([]byte, 0), err
	}
	tmp := resp.Body()
	return tmp, nil
}

func (r *request) HttpPostWithCustomHeader(uri string, requestBody []byte, ct string, customHeaders []string) (error, HttpResponse) {
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()
	req.Header.SetMethod(fasthttp.MethodPost)
	req.SetRequestURI(uri)

	// Set custom headers
	for _, header := range customHeaders {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(parts[0], strings.TrimSpace(parts[1]))
		}
	}

	if ct == "json" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBody(requestBody)

	if err := HttpClient.Do(req, resp); err != nil {
		return err, HttpResponse{}
	}
	headers := make(map[string]string)
	resp.Header.VisitAll(func(key, value []byte) {
		headers[string(key)] = string(value)
	})
	res := HttpResponse{
		StatusCode: resp.StatusCode(),
		Headers:    headers,
		Body:       append([]byte(nil), resp.Body()...),
	}
	return nil, res
}

func (r *request) HttpGetNoRes(uri string) error {
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()

	// Set request URI
	req.SetRequestURI(uri)

	req.Header.SetMethod(fasthttp.MethodGet)

	// Send request
	if err := HttpClient.Do(req, resp); err != nil {
		return err
	}
	// Discard the response body directly (or close it)
	resp.Reset()
	return nil
}

func (r *request) HttpPostNoRes(uri string, requestBody []byte, ct string) error {
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()
	req.Header.SetMethod(fasthttp.MethodPost)
	req.SetRequestURI(uri)
	if ct == "json" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBody(requestBody)

	if err := HttpClient.Do(req, resp); err != nil {
		return err
	}
	resp.Reset()
	return nil
}

func (r *request) HttpGetNoResWithCustomHeader(uri string, customHeaders []string) error {
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()

	// Set request URI
	req.SetRequestURI(uri)
	req.Header.SetMethod(fasthttp.MethodGet)

	// Set custom headers
	for _, header := range customHeaders {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(parts[0], strings.TrimSpace(parts[1]))
		}
	}

	// Send request
	if err := HttpClient.Do(req, resp); err != nil {
		return err
	}
	// Discard the response body directly (or close it)
	resp.Reset()
	return nil
}

func (r *request) HttpPostNoResWithCustomHeader(uri string, requestBody []byte, ct string, customHeaders []string) error {
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()
	req.Header.SetMethod(fasthttp.MethodPost)
	req.SetRequestURI(uri)

	// Set custom headers
	for _, header := range customHeaders {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(parts[0], strings.TrimSpace(parts[1]))
		}
	}

	if ct == "json" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBody(requestBody)

	if err := HttpClient.Do(req, resp); err != nil {
		return err
	}
	resp.Reset()
	return nil
}

var dialer = &net.Dialer{
	Timeout: 3 * time.Second,
}

func (r *request) TcpRecv(ip string, port uint16) ([]byte, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	response := make([]byte, 4096)
	err = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		return []byte{}, err
	}
	length, err := conn.Read(response)
	if err != nil {
		var netErr net.Error
		if (errors.As(err, &netErr) && netErr.Timeout()) ||
			errors.Is(err, syscall.ECONNREFUSED) { // timeout error or connection refused
			return []byte{}, err
		}
		return response[:length], nil
	}
	return response[:length], nil
}

func (r *request) Httpx(targets []string, resultCallback func(r types.AssetHttp), cdncheck string, screenshot bool, screenshotTimeout int, tLSProbe bool, followRedirects bool, ctx context.Context, executionTimeout int, bypassHeader bool) {
	// Set timeout context
	timeout := time.Duration(executionTimeout) * time.Minute // Set timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	rootDomain := ""
	customHeaders := []string{}
	if bypassHeader {
		if len(targets) != 0 {
			domain, err := Tools.GetRootDomain(targets[0])
			if err != nil {
				rootDomain = targets[0]
			} else {
				rootDomain = domain
			}
		}
		customHeaders = []string{
			"X-Forwarded-For-Original:127.0.0.1",
			"X-Forwarded-For:127.0.0.1",
			"X-Real-IP:127.0.0.1",
			"X-Forwarded-Host:127.0.0.1",
			"X-Forwarded-Proto:127.0.0.1",
			"Forwarded:127.0.0.1",
			"Via:127.0.0.1",
			"Client-IP:127.0.0.1",
			"True-Client-IP:127.0.0.1",
			"X-Originating-IP:127.0.0.1",
			"X-Client-IP:127.0.0.1",
			"Referer:" + rootDomain,
		}
	}

	options := runner.Options{
		CustomHeaders:             customHeaders,
		FollowRedirects:           followRedirects,
		MaxRedirects:              5,
		RandomAgent:               true,
		Methods:                   "GET",
		JSONOutput:                false,
		TLSProbe:                  tLSProbe,
		Threads:                   30,
		RateLimit:                 100,
		InputTargetHost:           targets,
		Favicon:                   true,
		ExtractTitle:              true,
		TechDetect:                true,
		OutputWebSocket:           true,
		OutputServerHeader:        true,
		OutputIP:                  true,
		OutputCName:               true,
		DisableStdin:              true,
		ResponseHeadersInStdout:   true,
		ResponseInStdout:          true,
		Base64ResponseInStdout:    false,
		Jarm:                      true,
		OutputCDN:                 cdncheck,
		Location:                  false,
		HostMaxErrors:             10,
		StoreResponse:             false,
		StoreChain:                false,
		MaxResponseBodySizeToRead: math.MaxInt32,
		Screenshot:                screenshot,
		ScreenshotTimeout:         time.Duration(screenshotTimeout) * time.Second,
		Timeout:                   10,
		Wappalyzer:                Wappalyzer,
		DisableStdout:             true,
		//InputFile: "./targetDomains.txt", // path to file containing the target domains list
		OnResult: func(r runner.Result) {
			// Check whether context is closed
			select {
			case <-ctx.Done():
				// If context is closed, return directly
				logger.SlogWarnLocal(fmt.Sprintf("Context closed before processing result for %s", r.Input))
				return
			default:
				// Continue processing results
				if r.Err != nil {
					logger.SlogDebugLocal(fmt.Sprintf("HttpxScan error %s: %s", r.Input, r.Err))
				} else {
					ah := Tools.HttpxResultToAssetHttp(r)
					//fmt.Printf("%s %s %d\n", r.Input, r.Host, r.StatusCode)
					resultCallback(ah)
				}
			}
		},
	}
	if err := options.ValidateOptions(); err != nil {
		logger.SlogErrorLocal(fmt.Sprintf("httpx options Validate error: %v", err))
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		logger.SlogErrorLocal(fmt.Sprintf("%v get error: %v", targets, err))
	}
	defer httpxRunner.Close()

	// Create a channel to signal task completion
	done := make(chan struct{})

	// Start a goroutine to run httpxRunner and notify the main program when done
	go func() {
		httpxRunner.RunEnumeration() // Run httpx scan
		close(done)                  // Close channel after scan completes to notify the main program
	}()

	select {
	case <-ctx.Done(): // Return after timeout
		logger.SlogWarnLocal(fmt.Sprintf("HttpxScan for %s timed out after %v", targets, timeout))
		return
	case <-done: // Continue after scan completes
		logger.SlogDebugLocal(fmt.Sprintf("HttpxScan for %s completed successfully", targets))
	}
}

// HttpGetWithRetry send an HTTP GET request with retries and proxy support.
// Parameters:
//   - requestURL: request URL
//   - timeout: timeout per request
//   - maxRetries: max retries
//   - retryInterval: wait interval between retries
//   - headers: request headers (e.g. User-Agent)
//   - proxyURL: proxy address, no proxy if empty
//
// Returns:
//   - *http.Response: return response body pointer on success
//   - error: if the request fails multiple times, return the last error
func (r *request) HttpGetWithRetry(requestURL string, timeout time.Duration, maxRetries int, retryInterval time.Duration, headers map[string]string, proxyURL string) (*http.Response, error) {
	// Configure Transport to control connection and response header timeouts
	var transport *http.Transport
	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			logger.SlogWarnLocal(fmt.Sprintf("Invalid proxy URL: %v", err))
			return nil, err
		}
		transport = &http.Transport{
			Proxy: http.ProxyURL(proxy),
			DialContext: (&net.Dialer{
				Timeout:   timeout, // Connection timeout
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   timeout, // TLS handshake timeout
			ResponseHeaderTimeout: timeout, // Max time to wait for response headers
		}
	} else {
		transport = &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   timeout, // Connection timeout
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   timeout, // TLS handshake timeout
			ResponseHeaderTimeout: timeout, // Max time to wait for response headers
		}
	}

	// Create HTTP client (no overall timeout)
	client := &http.Client{
		Transport: transport,
		Timeout:   0, // No total time limit, so body reads are not interrupted
	}

	var resp *http.Response
	var err error

	// Retry mechanism
	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, reqErr := http.NewRequest("GET", requestURL, nil)
		if reqErr != nil {
			return nil, reqErr
		}

		// Set request headers
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		// Send request
		resp, err = client.Do(req)
		if err == nil {
			return resp, nil
		}

		// Request failed, log and retry
		logger.SlogWarnLocal(fmt.Sprintf("[%v] GET attempt %d failed: %v", requestURL, attempt, err))
		if attempt < maxRetries {
			logger.SlogWarnLocal(fmt.Sprintf("Retrying GET %v after %v...", requestURL, retryInterval))
			time.Sleep(retryInterval)
		}
	}

	return nil, err
}

// HttpPostWithRetry send an HTTP POST request with retries and proxy support.
// Parameters:
//   - requestURL: request URL
//   - body: request body (JSON, form, etc.)
//   - timeout: timeout per request
//   - maxRetries: max retries
//   - retryInterval: wait interval between retries
//   - headers: request headers (usually Content-Type must be set)
//   - proxyURL: proxy address, no proxy if empty
//
// Returns:
//   - *http.Response: return response body pointer on success
//   - error: if the request fails multiple times, return the last error
func (r *request) HttpPostWithRetry(requestURL string, body io.Reader, timeout time.Duration, maxRetries int, retryInterval time.Duration, headers map[string]string, proxyURL string) (*http.Response, error) {
	// Configure Transport to control connection and response header timeouts
	var transport *http.Transport
	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			logger.SlogWarnLocal(fmt.Sprintf("Invalid proxy URL: %v", err))
			return nil, err
		}
		transport = &http.Transport{
			Proxy: http.ProxyURL(proxy),
			DialContext: (&net.Dialer{
				Timeout:   timeout, // TCP connection timeout
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
		}
	} else {
		transport = &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
		}
	}

	// Create HTTP client (no total request timeout)
	client := &http.Client{
		Transport: transport,
		Timeout:   0,
	}

	var resp *http.Response
	var err error

	// Retry mechanism
	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Note: body cannot be read twice, so for retries pass a reader that supports rereading (such as bytes.Buffer)
		req, reqErr := http.NewRequest("POST", requestURL, body)
		if reqErr != nil {
			return nil, reqErr
		}

		// Set request headers
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		// Send request
		resp, err = client.Do(req)
		if err == nil {
			return resp, nil
		}

		// Request failed, log and retry
		logger.SlogWarnLocal(fmt.Sprintf("[%v] POST attempt %d failed: %v", requestURL, attempt, err))
		if attempt < maxRetries {
			logger.SlogWarnLocal(fmt.Sprintf("Retrying POST %v after %v...", requestURL, retryInterval))
			time.Sleep(retryInterval)
		}
	}

	return nil, err
}
