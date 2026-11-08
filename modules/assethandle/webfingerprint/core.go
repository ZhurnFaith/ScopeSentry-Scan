// webfingerprint-------------------------------------
// @file      : core.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2025/12/27 21:51
// -------------------------------------------

package webfingerprint

import (
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// HTTPResponse HTTP response data
type HTTPResponse struct {
	URL        string
	StatusCode int
	RawHeaders string // Raw response header string (for matching)
	Body       string
	Title      string // Extracted from body title
}

// MatchContext match context
type MatchContext struct {
	Variables  map[string]string           // Variable storage
	Responses  map[string]*types.AssetHttp // Response cache (key is URL)
	HTTPClient *http.Client                // HTTP client
}

// LoadFingerprint load YAML fingerprint file
func LoadFingerprint(filepath string) (*types.Fingerprint, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read fingerprint file: %w", err)
	}

	// If there is no fingerprint wrapper, parse directly into the Fingerprint struct
	var fingerprint types.Fingerprint
	if err := yaml.Unmarshal(data, &fingerprint); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &fingerprint, nil
}

// parseHeaders parse raw headers string into map
func parseHeaders(rawHeaders string) map[string]string {
	headers := make(map[string]string)
	if rawHeaders == "" {
		return headers
	}

	lines := strings.Split(rawHeaders, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headers[key] = value
		}
	}

	return headers
}

// NewMatchContext create match context
func NewMatchContext() *MatchContext {
	return &MatchContext{
		Variables: make(map[string]string),
		Responses: make(map[string]*types.AssetHttp),
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// MatchFingerprint match fingerprint
func MatchFingerprint(fingerprint *types.Fingerprint, asset *types.AssetHttp) (bool, error) {
	ctx := NewMatchContext()

	// Rules are ORed, any matching rule is enough
	for _, rule := range fingerprint.Rules {
		matched, err := evaluateRule(rule, ctx, asset)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}

	return false, nil
}

// evaluateRule evaluate rules
func evaluateRule(rule types.Rule, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	// Create a new variable scope per rule (variables are not shared between rules)
	ctx.Variables = make(map[string]string)

	// Short-circuit evaluation optimization based on rule.Logic
	if rule.Logic == "AND" {
		// AND logic: return immediately on the first false false
		for _, condition := range rule.Conditions {
			result, err := evaluateCondition(condition, ctx, baseResponse)
			if err != nil {
				return false, err
			}
			if !result {
				return false, nil // Short-circuit: return on first failure false
			}
		}
		return true, nil // All conditions are met
	} else { // OR
		// OR logic: return immediately on the first true true
		for _, condition := range rule.Conditions {
			result, err := evaluateCondition(condition, ctx, baseResponse)
			if err != nil {
				return false, err
			}
			if result {
				return true, nil // Short-circuit: return on first match true
			}
		}
		return false, nil // None of the conditions are met
	}
}

// evaluateCondition evaluate conditions (recursively handle nested condition groups)
func evaluateCondition(condition types.Condition, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	// Check whether it is a nested condition group
	if isConditionGroup(condition) {
		return evaluateConditionGroup(condition, ctx, baseResponse)
	}

	// Normal conditions
	return evaluateNormalCondition(condition, ctx, baseResponse)
}

// isConditionGroup check whether it is a nested condition group
func isConditionGroup(condition types.Condition) bool {
	return condition.Logic != "" && condition.Location == ""
}

// evaluateConditionGroup evaluate nested condition group
func evaluateConditionGroup(condition types.Condition, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	// Short-circuit evaluation optimization based on logic
	if condition.Logic == "AND" {
		// AND logic: return immediately on the first false false
		for _, subCondition := range condition.Conditions {
			result, err := evaluateCondition(subCondition, ctx, baseResponse)
			if err != nil {
				return false, err
			}
			if !result {
				return false, nil // Short-circuit: return on first failure false
			}
		}
		return true, nil // All conditions are met
	} else { // OR
		// OR logic: return immediately on the first true true
		for _, subCondition := range condition.Conditions {
			result, err := evaluateCondition(subCondition, ctx, baseResponse)
			if err != nil {
				return false, err
			}
			if result {
				return true, nil // Short-circuit: return on first match true
			}
		}
		return false, nil // None of the conditions are met
	}
}

// evaluateNormalCondition evaluate regular condition
func evaluateNormalCondition(condition types.Condition, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	switch condition.MatchType {
	case "regex":
		return matchRegex(condition, ctx, baseResponse)
	case "contains":
		return matchContains(condition, ctx, baseResponse)
	case "not_contains":
		return matchNotContains(condition, ctx, baseResponse)
	case "extract":
		return matchExtract(condition, ctx, baseResponse)
	case "active":
		return matchActive(condition, ctx, baseResponse)
	default:
		return false, fmt.Errorf("unknown match_type: %s", condition.MatchType)
	}
}

// getDataByLocation get data by location
func getDataByLocation(location string, response *types.AssetHttp) string {
	switch location {
	case "body":
		return response.ResponseBody
	case "header":
		// Match against the raw headers string directly, without formatting
		return response.RawHeaders
	case "title":
		return response.Title
	default:
		return ""
	}
}

// formatHeaders format headers as string
func formatHeaders(headers map[string]string) string {
	var builder strings.Builder
	for key, value := range headers {
		builder.WriteString(key)
		builder.WriteString(": ")
		builder.WriteString(value)
		builder.WriteString("\n")
	}
	return builder.String()
}

// matchRegex regex match
func matchRegex(condition types.Condition, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	data := getDataByLocation(condition.Location, baseResponse)
	if data == "" {
		return false, nil
	}

	re, err := regexp.Compile(condition.Pattern)
	if err != nil {
		return false, fmt.Errorf("invalid regex pattern: %w", err)
	}

	return re.MatchString(data), nil
}

// matchContains string contains match
func matchContains(condition types.Condition, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	data := getDataByLocation(condition.Location, baseResponse)
	if data == "" {
		return false, nil
	}

	return strings.Contains(data, condition.Pattern), nil
}

// matchNotContains string does not contain match
func matchNotContains(condition types.Condition, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	data := getDataByLocation(condition.Location, baseResponse)
	if data == "" {
		return true, nil // If data is empty, treat as not contained
	}

	return !strings.Contains(data, condition.Pattern), nil
}

// matchExtract extract and save variables
func matchExtract(condition types.Condition, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	data := getDataByLocation(condition.Location, baseResponse)
	if data == "" {
		return false, nil
	}

	// Compile regular expression
	re, err := regexp.Compile(condition.Pattern)
	if err != nil {
		return false, fmt.Errorf("invalid regex pattern: %w", err)
	}

	// Execute match
	matches := re.FindStringSubmatch(data)
	if len(matches) <= condition.Group {
		return false, nil // No match or group does not exist
	}

	// Extract and save variables
	extractedValue := matches[condition.Group]
	ctx.Variables[condition.SaveAs] = extractedValue

	// If there are sub-conditions, evaluate them
	if len(condition.Conditions) > 0 {
		for _, subCondition := range condition.Conditions {
			result, err := evaluateCondition(subCondition, ctx, baseResponse)
			if err != nil {
				return false, err
			}
			if !result {
				return false, nil
			}
		}
	}

	return true, nil
}

// matchActive actively send HTTP request
func matchActive(condition types.Condition, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	// Confirm request URL
	var requestURL string
	if condition.DynamicPath != "" {
		// Replace variables
		path := replaceVariables(condition.DynamicPath, ctx.Variables)
		requestURL = baseURL(baseResponse.URL) + path
	} else if condition.Path != "" {
		requestURL = baseURL(baseResponse.URL) + condition.Path
	} else {
		return false, fmt.Errorf("active condition must have path or dynamic_path")
	}

	// Determine HTTP method
	method := condition.Method
	if method == "" {
		method = "GET"
	}

	// Check cache
	if cached, exists := ctx.Responses[requestURL]; exists {
		return evaluateActiveSubConditions(condition, cached, ctx), nil
	}

	// Send HTTP request
	response, err := sendHTTPRequest(ctx, method, requestURL)
	if err != nil {
		return false, fmt.Errorf("active request failed: %w", err)
	}

	// Cache response
	ctx.Responses[requestURL] = response

	// Evaluate sub-conditions (validation conditions)
	return evaluateActiveSubConditions(condition, response, ctx), nil
}

// evaluateActiveSubConditions evaluate sub-conditions of active requests
func evaluateActiveSubConditions(condition types.Condition, response *types.AssetHttp, ctx *MatchContext) bool {
	if len(condition.Conditions) == 0 {
		// No validation conditions, return as long as the request succeeds true
		return response.StatusCode >= 200 && response.StatusCode < 300
	}

	// Evaluate all sub-conditions
	for _, subCondition := range condition.Conditions {
		result, err := evaluateCondition(subCondition, ctx, response)
		if err != nil {
			return false
		}
		if !result {
			return false
		}
	}
	return true
}

// replaceVariables replace variables
func replaceVariables(template string, variables map[string]string) string {
	result := template
	for key, value := range variables {
		placeholder := "{{" + key + "}}"
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

// baseURL get basic URL
func baseURL(fullURL string) string {
	parsed, err := url.Parse(fullURL)
	if err != nil {
		return fullURL
	}
	return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
}

// sendHTTPRequest send HTTP request
func sendHTTPRequest(ctx *MatchContext, method, url string) (*types.AssetHttp, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	// Settings User-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := ctx.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Extract title
	title := extractTitle(string(body))

	// Format headers
	headers := make(map[string]string)
	var rawHeadersBuilder strings.Builder
	for key, values := range resp.Header {
		value := strings.Join(values, ", ")
		headers[key] = value
		// Build raw headers string format: "Key: Value\n"
		rawHeadersBuilder.WriteString(key)
		rawHeadersBuilder.WriteString(": ")
		rawHeadersBuilder.WriteString(value)
		rawHeadersBuilder.WriteString("\n")
	}
	rawHeaders := rawHeadersBuilder.String()

	return &types.AssetHttp{
		URL:          url,
		StatusCode:   resp.StatusCode,
		RawHeaders:   rawHeaders, // Save raw headers string
		ResponseBody: string(body),
		Title:        title,
	}, nil
}

// extractTitle extract from HTML body title
func extractTitle(body string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}
