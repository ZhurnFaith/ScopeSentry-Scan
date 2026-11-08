// assetmapping-------------------------------------
// @file      : module.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/10 21:06
// -------------------------------------------

package assetmapping

import (
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/contextmanager"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/handler"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/interfaces"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/options"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/plugins"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/pool"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils"
	"sync"
	"time"
)

type Runner struct {
	Option     *options.TaskOptions
	NextModule interfaces.ModuleRunner
	Input      chan interface{}
}

func NewRunner(op *options.TaskOptions, nextModule interfaces.ModuleRunner) *Runner {
	return &Runner{
		Option:     op,
		NextModule: nextModule,
	}
}

func (r *Runner) ModuleRun() error {
	var allPluginWg sync.WaitGroup
	var resultWg sync.WaitGroup
	var nextModuleRun sync.WaitGroup
	// Create a shared result channel
	resultChan := make(chan interface{}, 500)
	go func() {
		nextModuleRun.Add(1)
		defer nextModuleRun.Done()
		err := r.NextModule.ModuleRun()
		if err != nil {
			logger.SlogError(fmt.Sprintf("Next module run error: %v", err))
		}
	}()
	// Result handling goroutine, reads plugin results asynchronously
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for {
			select {
			case <-contextmanager.GlobalContextManagers.GetContext(r.Option.ID).Done():
				r.NextModule.CloseInput()
				return
			case result, ok := <-resultChan:
				if !ok {
					// If resultChan is closed, exit the loop
					// This module is done, close the next module's input
					r.NextModule.CloseInput()
					return
				}
				// If asset mapping was not selected, http assets of type assetOther arrive here and are mapped without further checks
				r.NextModule.GetInput() <- result
				//if assetResult, ok := result.(types.AssetOther); ok {
				//	if assetResult.Type == "http" {
				//		// This may have been sent directly by the previous module
				//		httpxResultsHandler := func(ra types.AssetHttp) {
				//			r.NextModule.GetInput() <- ra
				//		}
				//		var url string
				//		if assetResult.Port != "" {
				//			url = assetResult.Host + ":" + assetResult.Port + assetResult.UrlPath
				//		} else {
				//			url = assetResult.Host + assetResult.UrlPath
				//		}
				//		utils.Requests.Httpx([]string{url}, httpxResultsHandler, "false", false, 10, false, true, contextmanager.GlobalContextManagers.GetContext(r.Option.ID), 10, false)
				//	} else {
				//		// If it is an asset of type other, send it directly to the next module
				//		r.NextModule.GetInput() <- result
				//	}
				//} else {
				//	// If it is not types.AssetOther it is types.AssetHttp, send it directly to the next module
				//	r.NextModule.GetInput() <- result
				//}
			}
		}
	}()

	var firstData bool
	firstData = false
	var start time.Time
	var end time.Time
	doneCalled := false
	for {
		//
		select {
		case <-contextmanager.GlobalContextManagers.GetContext(r.Option.ID).Done():
			allPluginWg.Wait()
			if !doneCalled {
				close(resultChan)
				resultWg.Wait()
				r.Option.ModuleRunWg.Done()
				doneCalled = true // Mark as called Done
			}
			nextModuleRun.Wait()
			return nil
		case data, ok := <-r.Input:
			if !ok {
				time.Sleep(3 * time.Second)
				allPluginWg.Wait()
				// Channel closed, end processing
				if firstData {
					end = time.Now()
					duration := end.Sub(start)
					handler.TaskHandle.ProgressEnd(r.GetName(), r.Option.Target, r.Option.ID, len(r.Option.AssetMapping), duration)
				}
				if !doneCalled {
					close(resultChan)
					resultWg.Wait()
					r.Option.ModuleRunWg.Done()
					doneCalled = true // Mark as called Done
				}
				logger.SlogInfoLocal(fmt.Sprintf("module %v target %v close resultChan", r.GetName(), r.Option.Target))
				nextModuleRun.Wait()
				return nil
			}
			//assets, ok := data.([]interface{})
			//if !ok {
			//	r.NextModule.GetInput() <- data
			//	continue
			//}
			switch data.(type) {
			case []interface{}:
			case types.Company:
			case types.ICP:
			case types.RootDomain:
				r.NextModule.GetInput() <- data
			default:
				r.NextModule.GetInput() <- data
				continue
			}
			if !firstData {
				start = time.Now()
				handler.TaskHandle.ProgressStart(r.GetName(), r.Option.Target, r.Option.ID, len(r.Option.AssetMapping))
				firstData = true
			}
			allPluginWg.Add(1)
			go func(assets interface{}) {
				defer allPluginWg.Done()
				//Incoming data can only be types.Asset
				if len(r.Option.AssetMapping) != 0 {
					// Call plugin
					for _, pluginId := range r.Option.AssetMapping {
						//var plgWg sync.WaitGroup
						var plgWg sync.WaitGroup
						plg, flag := plugins.GlobalPluginManager.GetPlugin(r.GetName(), pluginId)
						if flag {
							logger.SlogDebugLocal(fmt.Sprintf("%v plugin start execute", plg.GetName()))
							plgWg.Add(1)
							args, argsFlag := utils.Tools.GetParameter(r.Option.Parameters, r.GetName(), plg.GetPluginId())
							if argsFlag {
								plg.SetParameter(args)
							} else {
								plg.SetParameter("")
							}
							plg.SetResult(resultChan)
							plg.SetTaskId(r.Option.ID)
							plg.SetTaskName(r.Option.TaskName)
							// Unlike other modules, an array is passed here
							pluginFunc := func(assets interface{}) func() {
								return func() {
									defer plgWg.Done()
									select {
									case <-contextmanager.GlobalContextManagers.GetContext(r.Option.ID).Done():
										return
									default:
										_, err := plg.Execute(assets)
										if err != nil {
										}
									}
								}
							}(assets)
							err := pool.PoolManage.SubmitTask(r.GetName(), pluginFunc)
							if err != nil {
								plgWg.Done()
								logger.SlogError(fmt.Sprintf("task pool error: %v", err))
							}
							plgWg.Wait()
							logger.SlogDebugLocal(fmt.Sprintf("%v plugin end execute", plg.GetName()))
						} else {
							logger.SlogError(fmt.Sprintf("plugin %v not found", pluginId))
						}
					}
				} else {
					// If asset mapping is not enabled, send types.Asset to results and convert it there
					switch d := assets.(type) {
					case []interface{}:
						for _, asset := range d {
							resultChan <- asset
						}
					default:
						resultChan <- d
					}

				}
			}(data)

		}
	}
	return nil
}

func (r *Runner) SetInput(ch chan interface{}) {
	r.Input = ch
}

func (r *Runner) GetName() string {
	return "AssetMapping"
}

func (r *Runner) GetInput() chan interface{} {
	return r.Input
}

func (r *Runner) CloseInput() {
	close(r.Input)
}
