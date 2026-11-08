// webfingerprint-------------------------------------
// @file      : webfingerprint.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/28 16:24
// -------------------------------------------

package webfingerprint

import (
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/global"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/interfaces"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"strings"
	"sync"
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
		Name:     "WebFingerprint",
		Module:   "AssetHandle",
		PluginId: "80718cc3fcb4827d942e6300184707e2",
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

func (p *Plugin) GetTaskId() string {
	return p.TaskId
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

func (p *Plugin) Install() error {
	return nil
}
func (p *Plugin) UnInstall() error {
	return nil
}

func (p *Plugin) Check() error {
	return nil
}

func (p *Plugin) SetParameter(args string) {
	p.Parameter = args
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

func (p *Plugin) GetParameter() string {
	return p.Parameter
}

func (p *Plugin) Execute(input interface{}) (interface{}, error) {
	httpResult, ok := input.(*types.AssetHttp)
	if !ok {
		// Means it is not an http asset, return directly
		return nil, nil
	}
	// Get the ACMatcher reference so global.WebFingers is not modified while the function runs
	if global.WebFingers == nil || global.WebFingers.ACMatcher == nil {
		logger.SlogErrorLocal("WebFinger ACMatcher is nil")
		return nil, nil
	}
	acMatcher := global.WebFingers.ACMatcher
	var mu sync.Mutex
	var matchFingers = []*types.Fingerprint{}
	// New version
	// Use Aho-Corasick for pre-matching
	acFingers := AcRun(httpResult.Title, httpResult.RawHeaders, httpResult.ResponseBody)
	matchFingers = append(matchFingers, acFingers...)
	// Add fingerprints that cannot use Aho-Corasick
	matchFingers = append(matchFingers, acMatcher.NonACFingerprints...)

	for _, fingerprint := range matchFingers {
		matchFlag, err := MatchFingerprint(fingerprint, httpResult)
		if err != nil {
			return nil, err
		}
		if matchFlag {
			mu.Lock()
			alreadyExists := false
			for _, tech := range httpResult.Technologies {
				if strings.ToLower(tech) == strings.ToLower(fingerprint.Name) {
					alreadyExists = true
					break
				}
			}
			if !alreadyExists {
				httpResult.Technologies = append(httpResult.Technologies, fingerprint.Name)
			}
			mu.Unlock()
		}
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

func popLastTwoBool(slice []bool) (bool, bool, []bool) {
	if len(slice) < 2 {
		return false, false, slice // If slice length is less than 2, return the original slice
	}

	// Get the last two elements
	lastIndex := len(slice) - 1
	last := slice[lastIndex]
	secondLast := slice[lastIndex-1]

	// Remove the last two elements with slicing
	slice = slice[:lastIndex-1]

	return secondLast, last, slice
}
