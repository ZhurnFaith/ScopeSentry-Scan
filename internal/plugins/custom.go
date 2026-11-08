// plugins-------------------------------------
// @file      : custom.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/11/15 21:10
// -------------------------------------------

package plugins

import (
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/global"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/interfaces"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/options"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/symbols"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/customplugin"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils"
	"github.com/cloudflare/cfssl/log"
	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

func GetCustomPlugin() ([]interfaces.Plugin, error) {
	var plugins []interfaces.Plugin
	utils.Tools.EnsureDir(global.PluginDir)
	// Walk the global.PluginDir directory with WalkDir
	err := filepath.WalkDir(global.PluginDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			log.Error(fmt.Sprintf("Error walking path", path, ":", err))
			return nil
		}

		// If it is a directory, get its name and traverse it
		if d.IsDir() {
		} else {
			dir := filepath.Dir(path)
			moduleName := filepath.Base(dir)

			filename := filepath.Base(path)
			extension := filepath.Ext(filename)              // Get file extension
			plgId := strings.TrimSuffix(filename, extension) // Strip extension
			plugin, err := LoadCustomPlugin(path, moduleName, plgId)
			if err != nil {
				log.Error(fmt.Sprintf("module %v plg load error: %v", moduleName, plgId, err))
				return nil // Return nil, continue iterating
			}
			plugins = append(plugins, plugin)
		}
		return nil
	})

	if err != nil {
		// If there is an error during iteration, return it
		return nil, fmt.Errorf("error walking the path %v: %v", global.PluginDir, err)
	}

	return plugins, nil
}

func LoadCustomPlugin(path string, modlue string, plgId string) (interfaces.Plugin, error) {
	logger.SlogInfoLocal(fmt.Sprintf("Load custom plugin: %v", path))
	// Initialize yaegi interpreter
	interp := interp.New(interp.Options{})
	// Load standard library and symbols
	err := interp.Use(stdlib.Symbols)
	if err != nil {
		return nil, err
	}
	err = interp.Use(symbols.WithLegacyAliases())
	if err != nil {
		return nil, err
	}
	err = interp.Use(map[string]map[string]reflect.Value{
		"os/exec": stdlib.Symbols["os/exec"],
	})
	_, err = interp.EvalPath(path)
	if err != nil {
		return nil, err
	}
	// Get Execute
	v, err := interp.Eval("plugin.Execute")
	if err != nil {
		return nil, err
	}
	executeFunc := v.Interface().(func(input interface{}, op options.PluginOption) (interface{}, error))

	v, err = interp.Eval("plugin.GetName")
	if err != nil {
		return nil, err
	}
	getNameFunc := v.Interface().(func() string)

	v, err = interp.Eval("plugin.Install")
	if err != nil {
		return nil, err
	}
	installFunc := v.Interface().(func() error)

	v, err = interp.Eval("plugin.Check")
	if err != nil {
		return nil, err
	}
	checkFunc := v.Interface().(func() error)

	v, err = interp.Eval("plugin.Uninstall")
	if err != nil {
		return nil, err
	}
	uninstallFunc := v.Interface().(func() error)

	v, err = interp.Eval("plugin.SetCustom")
	setCustomFunc := func(interface{}) {}
	if err != nil {
		// If the method does not exist, set setCustomFunc to nil
	} else {
		// If the method exists, get the function
		setCustomFunc = v.Interface().(func(interface{}))
	}
	plg := customplugin.NewPlugin(modlue, plgId, installFunc, checkFunc, executeFunc, uninstallFunc, getNameFunc, setCustomFunc)
	return plg, nil
}
