// targetparser-------------------------------------
// @file      : targetparser.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/10 19:53
// -------------------------------------------

package targetparser

import (
	"errors"
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/interfaces"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/results"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils"
	"golang.org/x/net/idna"
	"net"
	"net/url"
	"regexp"
	"strings"
)

type Plugin struct {
	Name      string
	Module    string
	Parameter string
	PluginId  string
	Result    chan interface{}
	Custom    interface{}
	TaskId    string
	TaskName  string
}

func NewPlugin() *Plugin {
	return &Plugin{
		Name:     "TargetParser",
		Module:   "TargetHandler",
		PluginId: "7bbaec6487f51a9aafeff4720c7643f0",
	}
}

func (p *Plugin) SetTaskName(name string) {
	p.TaskName = name
}

func (p *Plugin) GetTaskName() string {
	return p.TaskName
}

func (p *Plugin) SetTaskId(id string) {
	p.TaskId = id
}
func (p *Plugin) UnInstall() error {
	return nil
}
func (p *Plugin) GetTaskId() string {
	return p.TaskId
}

func (p *Plugin) Log(msg string, tp ...string) {
	var logTp string
	if len(tp) > 0 {
		logTp = tp[0] // Use the parameters passed in
	} else {
		logTp = "i"
	}
	logger.PluginsLog(fmt.Sprintf("[Plugins %v] %v", p.GetName(), msg), logTp, p.GetModule(), p.GetPluginId())
}
func (p *Plugin) SetCustom(cu interface{}) {
	p.Custom = cu
}

func (p *Plugin) GetCustom() interface{} {
	return p.Custom
}

func (p *Plugin) SetPluginId(id string) {
	p.PluginId = id
}

func (p *Plugin) GetPluginId() string {
	return p.PluginId
}

func (p *Plugin) SetResult(ch chan interface{}) {
	p.Result = ch
}

func (p *Plugin) SetName(name string) {
	p.Name = name
}

func (p *Plugin) GetName() string {
	return p.Name
}

func (p *Plugin) SetModule(module string) {
	p.Module = module
}

func (p *Plugin) GetModule() string {
	return p.Module
}

// Check whether string is a valid domain
func isValidDomain(domain string) bool {
	// Domain regular expression (simplified)
	domainRegex := `^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`
	re := regexp.MustCompile(domainRegex)
	return re.MatchString(domain)
}

// Convert Chinese domain names to ASCII-compatible format
func toASCII(domain string) (string, error) {
	return idna.ToASCII(domain)
}

func (p *Plugin) Install() error {
	return nil
}

func (p *Plugin) Check() error {
	return nil
}

func (p *Plugin) SetParameter(args string) {
	p.Parameter = args
}

func (p *Plugin) GetParameter() string {
	return p.Parameter
}

var ipv6Regex = regexp.MustCompile(`^\[([0-9a-fA-F:]+)\]:(\d+)$`)

// Execute
//
//  1. IP address
//     Input: "192.168.1.1"
//     Output: "192.168.1.1"
//
//  2. URL with protocol (without port)
//     Input: "http://example.com"
//     Output: "example.com"
//
//  3. URL with protocol (with port)
//     Input: "http://example.com:8080"
//     Output: "example.com"
//     Output: "example.com:8080"
//
//  4. Wildcard domain
//     Input: "*.example.com"
//     Output: "*.example.com"
//     Input: "wda.*.example.com"
//     Output: "wda.*.example.com"
//
//  5. Valid domain without protocol
//     Input: "example.com"
//     Output: "example.com"
//
//  6. Chinese domain name
//     Input: "Example.com"
//     Output: "xn--fsq.com"
//
//  7. Invalid input, return directly
//     Input: "Example Company"
//     Output: "Invalid input: Example Company"
func (p *Plugin) Execute(input interface{}) (interface{}, error) {
	target, ok := input.(string)
	if !ok {
		logger.SlogError(fmt.Sprintf("%v error: %v input is not a string\n", p.Name, input))
		return nil, errors.New("input is not a string")
	}
	// Check whether it is an IP address
	if net.ParseIP(target) != nil {
		// If it is a plain IP address
		p.Result <- target
		return nil, nil
	}
	// Input starting with CIDR: is not distributed, it is sent directly to rustscan for scanning
	if strings.HasPrefix(target, "CIDR:") {
		tg := strings.Replace(target, "CIDR:", "", 1)
		tmpDominSkip := types.DomainSkip{Domain: tg, Skip: false, CIDR: true}
		p.Result <- tmpDominSkip
		return nil, nil
	}
	if strings.HasPrefix(target, "CMP:") {
		name := strings.Replace(target, "CMP:", "", 1)
		p.Result <- types.Company{Name: name}
		return nil, nil
	}
	if strings.HasPrefix(target, "ICP:") {
		name := strings.Replace(target, "ICP:", "", 1)
		p.Result <- types.ICP{ICP: name}
		return nil, nil
	}

	if strings.HasPrefix(target, "APP-ID:") {
		id := strings.Replace(target, "APP-ID:", "", 1)
		p.Result <- types.APP{
			BundleID: id,
		}
		return nil, nil
	}
	if strings.HasPrefix(target, "APP:") {
		name := strings.Replace(target, "APP:", "", 1)
		p.Result <- types.APP{
			Name: name,
		}
		return nil, nil
	}
	rootDomain, err := utils.Tools.GetRootDomain(target)
	if err == nil {
		if net.ParseIP(rootDomain) == nil {
			flag := results.Duplicate.RootDomain(rootDomain, p.TaskId)
			if flag {
				p.Result <- types.RootDomain{Domain: rootDomain}
			}
		}
	}

	// Try to parse URL
	parsedURL, err := url.Parse(target)
	if err == nil && parsedURL.Host != "" {
		host := parsedURL.Host
		rawHost := parsedURL.Host
		// Check whether there is a port number
		if strings.Contains(host, ":") {
			// Split hostname and port
			hostParts := strings.Split(host, ":")
			ipOrDomain := hostParts[0]
			//port := hostParts[1]
			rawHost = hostParts[0]
			p.Result <- ipOrDomain
			//// Check whether the host part is an IP address
			//if net.ParseIP(ipOrDomain) != nil {
			//	// Handle IP address + port
			//	p.Result <- ipOrDomain
			//	//p.Result <- ipOrDomain + ":" + port
			//} else {
			//	// Handle domain + port
			//	p.Result <- ipOrDomain
			//	//p.Result <- host
			//}
			hostPort := types.PortAlive{
				Host: ipOrDomain,
				IP:   "",
				Port: hostParts[1],
			}
			p.Result <- hostPort
		} else {
			// Check whether the host part is an IP address
			//if net.ParseIP(host) != nil {
			//	// Handle plain IP address
			//	p.Result <- host
			//} else {
			//	// Handle domain
			//	p.Result <- host
			//}
			p.Result <- host
		}
		path := parsedURL.Path
		// Check whether the path consists entirely of `/` compose
		if strings.Trim(path, "/") == "" {
		} else {
			tmp := types.AssetOther{
				Host:    rawHost,
				Port:    parsedURL.Port(),
				UrlPath: path,
				Type:    "http",
			}
			// Convert to []interface{}
			var interfaceList []interface{}
			interfaceList = append(interfaceList, tmp)
			p.Result <- interfaceList
		}
		return nil, nil
	}

	// Handle `*.domain.com` or other domains without protocol
	if strings.HasPrefix(target, "*.") || strings.Contains(target, ".*.") {
		p.Result <- target
		return nil, nil
	}
	// Handle ipv6
	if match := ipv6Regex.FindStringSubmatch(target); match != nil {
		result := types.PortAlive{
			Host: match[1],
			IP:   match[1], // IPv6 address
			Port: match[2], // Port
		}
		p.Result <- match[1]
		p.Result <- result
		return nil, nil
	}

	// Handle 127.0.0.1:666
	if strings.Contains(target, ":") {
		data := strings.Split(target, ":")
		if len(data) == 2 {
			result := types.PortAlive{
				Host: data[0],
				IP:   "",
				Port: data[1], // Port
			}
			p.Result <- data[0]
			p.Result <- result
			return nil, nil
		}
	}

	// Handle domains without protocol
	if isValidDomain(target) {
		asciiDomain, err := toASCII(target)
		if err == nil {
			p.Result <- asciiDomain
		} else {
			p.Result <- target
		}
	} else if net.ParseIP(target) != nil {
		p.Result <- target
	} else {
		// Handle invalid input
		logger.SlogInfoLocal(fmt.Sprintf("%v error Invalid input:%v ", p.Name, input))
	}

	return nil, nil
}

func (p *Plugin) Clone() interfaces.Plugin {
	return &Plugin{
		Name:     p.Name,
		Module:   p.Module,
		PluginId: p.PluginId,
		Custom:   p.Custom,
		TaskId:   p.TaskId,
	}
}
