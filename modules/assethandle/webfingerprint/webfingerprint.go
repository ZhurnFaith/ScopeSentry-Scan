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
		logTp = tp[0] // 使用传入的参数
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
		// 说明不是http的资产，直接返回
		return nil, nil
	}
	// 获取 ACMatcher 引用，避免在函数执行过程中 global.WebFingers 被修改
	if global.WebFingers == nil || global.WebFingers.ACMatcher == nil {
		logger.SlogErrorLocal("WebFinger ACMatcher is nil")
		return nil, nil
	}
	acMatcher := global.WebFingers.ACMatcher
	var mu sync.Mutex
	var matchFingers = []*types.Fingerprint{}
	// 新版本
	// 使用ac自动机进行预匹配
	acFingers := AcRun(httpResult.Title, httpResult.RawHeaders, httpResult.ResponseBody)
	matchFingers = append(matchFingers, acFingers...)
	// 增加无法使用ac自动机的指纹
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
		return false, false, slice // 如果切片长度小于2，直接返回原切片
	}

	// 获取最后两个元素
	lastIndex := len(slice) - 1
	last := slice[lastIndex]
	secondLast := slice[lastIndex-1]

	// 使用切片操作去除最后两个元素
	slice = slice[:lastIndex-1]

	return secondLast, last, slice
}
