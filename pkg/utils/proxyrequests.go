// utils-------------------------------------
// @file      : proxyrequests.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2025/2/20 23:21
// -------------------------------------------

package utils

import (
	"crypto/tls"
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"github.com/valyala/fasthttp"
	"net"
	"strings"
	"time"
)

type ProxyRequest struct {
	ProxyAddr string
	Client    *fasthttp.Client
}

var ProxyRequestsPool map[string]*ProxyRequest

type proxyRequest struct {
}

var ProxyRequests *proxyRequest

// InitializeProxyRequestsPool initialize proxy request management
func InitializeProxyRequestsPool() {
	ProxyRequestsPool = make(map[string]*ProxyRequest)
	ProxyRequests = &proxyRequest{}
}

// CreateClientWithProxy create an HTTP client with proxy
func CreateClientWithProxy(proxyAddr string) (*fasthttp.Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Skip certificate verification
	}

	// Set up HTTP client through proxy
	client := &fasthttp.Client{
		ReadTimeout:                   time.Second * 10,
		WriteTimeout:                  time.Second * 10,
		MaxIdleConnDuration:           time.Second * 10,
		NoDefaultUserAgentHeader:      true,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
		TLSConfig:                     tlsConfig,
		ReadBufferSize:                4 * 1024 * 1024,
		MaxResponseBodySize:           10 * 1024 * 1024,
		Dial: func(addr string) (net.Conn, error) {
			// Create proxied connection
			return net.Dial("tcp", proxyAddr)
		},
	}

	return client, nil
}

// GetProxyClient get client by proxy address, create one if none exists
func GetProxyClient(proxyAddr string) (*fasthttp.Client, error) {
	// If the client for this proxy was already created, return it
	if proxyRequest, exists := ProxyRequestsPool[proxyAddr]; exists {
		return proxyRequest.Client, nil
	}

	// Create new client
	client, err := CreateClientWithProxy(proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("Failed to create client with proxy: %v", err)
	}

	// Store this proxy and its client
	ProxyRequestsPool[proxyAddr] = &ProxyRequest{
		ProxyAddr: proxyAddr,
		Client:    client,
	}

	return client, nil
}
func (r *proxyRequest) HttpGetProxy(uri string, proxyAddr string) (types.HttpResponse, error) {
	client, err := GetProxyClient(proxyAddr)
	if err != nil {
		return types.HttpResponse{}, err
	}
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	// Finally req and resp must be returned to the pool
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()
	req.Header.SetMethod(fasthttp.MethodGet)
	req.SetRequestURI(uri)

	if err := client.Do(req, resp); err != nil {
		return types.HttpResponse{}, err
	}
	tmp := types.HttpResponse{}
	tmp.Url = uri
	// Define max response body size (10MB)
	const maxBodySize = 10 * 1024 * 1024

	// Truncate Body
	//body := resp.Body()
	//if len(body) > maxBodySize {
	//	body = body[:maxBodySize]
	//}
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
func (r *proxyRequest) HttpGetByteProxy(uri string, proxyAddr string) ([]byte, error) {
	client, err := GetProxyClient(proxyAddr)
	if err != nil {
		return []byte{}, err
	}
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	// Finally req and resp must be returned to the pool
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()
	req.Header.SetMethod(fasthttp.MethodGet)
	req.SetRequestURI(uri)
	if err := client.Do(req, resp); err != nil {
		return make([]byte, 0), err
	}
	tmp := resp.Body()
	return tmp, nil
}

func (r *proxyRequest) HttpPostProxy(uri string, requestBody []byte, ct string, proxyAddr string) (error, *fasthttp.Response) {
	client, err := GetProxyClient(proxyAddr)
	if err != nil {
		return err, nil
	}
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

	if err := client.Do(req, resp); err != nil {
		return err, nil
	}
	return nil, resp
}

func (r *proxyRequest) HttpGetWithCustomHeaderProxy(uri string, customHeaders []string, proxyAddr string) (types.HttpResponse, error) {
	client, err := GetProxyClient(proxyAddr)
	if err != nil {
		return types.HttpResponse{}, err
	}
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

	if err := client.Do(req, resp); err != nil {
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

func (r *proxyRequest) HttpGetByteWithCustomHeaderProxy(uri string, customHeaders []string, proxyAddr string) ([]byte, error) {
	client, err := GetProxyClient(proxyAddr)
	if err != nil {
		return make([]byte, 0), err
	}
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

	if err := client.Do(req, resp); err != nil {
		return make([]byte, 0), err
	}
	tmp := resp.Body()
	return tmp, nil
}

func (r *proxyRequest) HttpPostWithCustomHeaderProxy(uri string, requestBody []byte, ct string, customHeaders []string, proxyAddr string) (error, *fasthttp.Response) {
	client, err := GetProxyClient(proxyAddr)
	if err != nil {
		return err, nil
	}
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

	if err := client.Do(req, resp); err != nil {
		return err, nil
	}
	return nil, resp
}

func (r *proxyRequest) HttpGetNoResProxy(uri string, proxyAddr string) error {
	client, err := GetProxyClient(proxyAddr)
	if err != nil {
		return err
	}
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()

	// Set request URI
	req.SetRequestURI(uri)

	req.Header.SetMethod(fasthttp.MethodGet)

	// Send request
	if err := client.Do(req, resp); err != nil {
		return err
	}
	// Discard the response body directly (or close it)
	resp.Reset()
	return nil
}

func (r *proxyRequest) HttpPostNoResProxy(uri string, requestBody []byte, ct string, proxyAddr string) error {
	client, err := GetProxyClient(proxyAddr)
	if err != nil {
		return err
	}
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

	if err := client.Do(req, resp); err != nil {
		return err
	}
	resp.Reset()
	return nil
}

func (r *proxyRequest) HttpGetNoResWithCustomHeaderProxy(uri string, customHeaders []string, proxyAddr string) error {
	client, err := GetProxyClient(proxyAddr)
	if err != nil {
		return err
	}
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
	if err := client.Do(req, resp); err != nil {
		return err
	}
	// Discard the response body directly (or close it)
	resp.Reset()
	return nil
}

func (r *proxyRequest) HttpPostNoResWithCustomHeaderProxy(uri string, requestBody []byte, ct string, customHeaders []string, proxyAddr string) error {
	client, err := GetProxyClient(proxyAddr)
	if err != nil {
		return err
	}
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

	if err := client.Do(req, resp); err != nil {
		return err
	}
	resp.Reset()
	return nil
}
