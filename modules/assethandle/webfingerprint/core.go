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

// HTTPResponse HTTP响应数据
type HTTPResponse struct {
	URL        string
	StatusCode int
	RawHeaders string // 原始响应头字符串（用于匹配）
	Body       string
	Title      string // 从body中提取的title
}

// MatchContext 匹配上下文
type MatchContext struct {
	Variables  map[string]string           // 变量存储
	Responses  map[string]*types.AssetHttp // 响应缓存（key为URL）
	HTTPClient *http.Client                // HTTP客户端
}

// LoadFingerprint 加载YAML指纹文件
func LoadFingerprint(filepath string) (*types.Fingerprint, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read fingerprint file: %w", err)
	}

	// 如果没有fingerprint包装，直接解析为Fingerprint结构
	var fingerprint types.Fingerprint
	if err := yaml.Unmarshal(data, &fingerprint); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &fingerprint, nil
}

// parseHeaders 解析原始headers字符串为map
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

// NewMatchContext 创建匹配上下文
func NewMatchContext() *MatchContext {
	return &MatchContext{
		Variables: make(map[string]string),
		Responses: make(map[string]*types.AssetHttp),
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// MatchFingerprint 匹配指纹
func MatchFingerprint(fingerprint *types.Fingerprint, asset *types.AssetHttp) (bool, error) {
	ctx := NewMatchContext()

	// 规则之间是OR关系，任一规则匹配成功即可
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

// evaluateRule 评估规则
func evaluateRule(rule types.Rule, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	// 为每个规则创建新的变量作用域（规则之间变量不共享）
	ctx.Variables = make(map[string]string)

	// 根据rule.Logic进行短路求值优化
	if rule.Logic == "AND" {
		// AND逻辑：遇到第一个false就立即返回false
		for _, condition := range rule.Conditions {
			result, err := evaluateCondition(condition, ctx, baseResponse)
			if err != nil {
				return false, err
			}
			if !result {
				return false, nil // 短路：第一个不满足就返回false
			}
		}
		return true, nil // 所有条件都满足
	} else { // OR
		// OR逻辑：遇到第一个true就立即返回true
		for _, condition := range rule.Conditions {
			result, err := evaluateCondition(condition, ctx, baseResponse)
			if err != nil {
				return false, err
			}
			if result {
				return true, nil // 短路：第一个满足就返回true
			}
		}
		return false, nil // 所有条件都不满足
	}
}

// evaluateCondition 评估条件（递归处理嵌套条件组）
func evaluateCondition(condition types.Condition, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	// 判断是否为嵌套条件组
	if isConditionGroup(condition) {
		return evaluateConditionGroup(condition, ctx, baseResponse)
	}

	// 普通条件
	return evaluateNormalCondition(condition, ctx, baseResponse)
}

// isConditionGroup 判断是否为嵌套条件组
func isConditionGroup(condition types.Condition) bool {
	return condition.Logic != "" && condition.Location == ""
}

// evaluateConditionGroup 评估嵌套条件组
func evaluateConditionGroup(condition types.Condition, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	// 根据logic进行短路求值优化
	if condition.Logic == "AND" {
		// AND逻辑：遇到第一个false就立即返回false
		for _, subCondition := range condition.Conditions {
			result, err := evaluateCondition(subCondition, ctx, baseResponse)
			if err != nil {
				return false, err
			}
			if !result {
				return false, nil // 短路：第一个不满足就返回false
			}
		}
		return true, nil // 所有条件都满足
	} else { // OR
		// OR逻辑：遇到第一个true就立即返回true
		for _, subCondition := range condition.Conditions {
			result, err := evaluateCondition(subCondition, ctx, baseResponse)
			if err != nil {
				return false, err
			}
			if result {
				return true, nil // 短路：第一个满足就返回true
			}
		}
		return false, nil // 所有条件都不满足
	}
}

// evaluateNormalCondition 评估普通条件
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

// getDataByLocation 根据location获取数据
func getDataByLocation(location string, response *types.AssetHttp) string {
	switch location {
	case "body":
		return response.ResponseBody
	case "header":
		// 直接使用原始headers字符串进行匹配，不进行格式化
		return response.RawHeaders
	case "title":
		return response.Title
	default:
		return ""
	}
}

// formatHeaders 格式化headers为字符串
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

// matchRegex 正则表达式匹配
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

// matchContains 字符串包含匹配
func matchContains(condition types.Condition, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	data := getDataByLocation(condition.Location, baseResponse)
	if data == "" {
		return false, nil
	}

	return strings.Contains(data, condition.Pattern), nil
}

// matchNotContains 字符串不包含匹配
func matchNotContains(condition types.Condition, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	data := getDataByLocation(condition.Location, baseResponse)
	if data == "" {
		return true, nil // 如果数据为空，认为不包含
	}

	return !strings.Contains(data, condition.Pattern), nil
}

// matchExtract 提取并保存变量
func matchExtract(condition types.Condition, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	data := getDataByLocation(condition.Location, baseResponse)
	if data == "" {
		return false, nil
	}

	// 编译正则表达式
	re, err := regexp.Compile(condition.Pattern)
	if err != nil {
		return false, fmt.Errorf("invalid regex pattern: %w", err)
	}

	// 执行匹配
	matches := re.FindStringSubmatch(data)
	if len(matches) <= condition.Group {
		return false, nil // 未匹配或组不存在
	}

	// 提取并保存变量
	extractedValue := matches[condition.Group]
	ctx.Variables[condition.SaveAs] = extractedValue

	// 如果有子条件，评估子条件
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

// matchActive 主动发送HTTP请求
func matchActive(condition types.Condition, ctx *MatchContext, baseResponse *types.AssetHttp) (bool, error) {
	// 确定请求URL
	var requestURL string
	if condition.DynamicPath != "" {
		// 替换变量
		path := replaceVariables(condition.DynamicPath, ctx.Variables)
		requestURL = baseURL(baseResponse.URL) + path
	} else if condition.Path != "" {
		requestURL = baseURL(baseResponse.URL) + condition.Path
	} else {
		return false, fmt.Errorf("active condition must have path or dynamic_path")
	}

	// 确定HTTP方法
	method := condition.Method
	if method == "" {
		method = "GET"
	}

	// 检查缓存
	if cached, exists := ctx.Responses[requestURL]; exists {
		return evaluateActiveSubConditions(condition, cached, ctx), nil
	}

	// 发送HTTP请求
	response, err := sendHTTPRequest(ctx, method, requestURL)
	if err != nil {
		return false, fmt.Errorf("active request failed: %w", err)
	}

	// 缓存响应
	ctx.Responses[requestURL] = response

	// 评估子条件（验证条件）
	return evaluateActiveSubConditions(condition, response, ctx), nil
}

// evaluateActiveSubConditions 评估主动请求的子条件
func evaluateActiveSubConditions(condition types.Condition, response *types.AssetHttp, ctx *MatchContext) bool {
	if len(condition.Conditions) == 0 {
		// 没有验证条件，只要请求成功就返回true
		return response.StatusCode >= 200 && response.StatusCode < 300
	}

	// 评估所有子条件
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

// replaceVariables 替换变量
func replaceVariables(template string, variables map[string]string) string {
	result := template
	for key, value := range variables {
		placeholder := "{{" + key + "}}"
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

// baseURL 获取基础URL
func baseURL(fullURL string) string {
	parsed, err := url.Parse(fullURL)
	if err != nil {
		return fullURL
	}
	return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
}

// sendHTTPRequest 发送HTTP请求
func sendHTTPRequest(ctx *MatchContext, method, url string) (*types.AssetHttp, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	// 设置User-Agent
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

	// 提取title
	title := extractTitle(string(body))

	// 格式化headers
	headers := make(map[string]string)
	var rawHeadersBuilder strings.Builder
	for key, values := range resp.Header {
		value := strings.Join(values, ", ")
		headers[key] = value
		// 构建原始headers字符串格式: "Key: Value\n"
		rawHeadersBuilder.WriteString(key)
		rawHeadersBuilder.WriteString(": ")
		rawHeadersBuilder.WriteString(value)
		rawHeadersBuilder.WriteString("\n")
	}
	rawHeaders := rawHeadersBuilder.String()

	return &types.AssetHttp{
		URL:          url,
		StatusCode:   resp.StatusCode,
		RawHeaders:   rawHeaders, // 保存原始headers字符串
		ResponseBody: string(body),
		Title:        title,
	}, nil
}

// extractTitle 从HTML body中提取title
func extractTitle(body string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}
