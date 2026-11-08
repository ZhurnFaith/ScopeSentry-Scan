// subdomainsecurity-------------------------------------
// @file      : module.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/10 21:06
// -------------------------------------------

package subdomainsecurity

import (
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/contextmanager"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/handler"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/interfaces"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/options"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/plugins"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/pool"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/results"
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

// ModuleRun subdomain security checks, e.g. subdomain takeover
func (r *Runner) ModuleRun() error {
	var allPluginWg sync.WaitGroup
	var resultWg sync.WaitGroup
	var nextModuleRun sync.WaitGroup
	// Create a shared result channel
	resultChan := make(chan interface{}, 1000)
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
			// There are only two kinds of results: types.SubTakeResult (subdomain takeover) and types.DomainResolve (domain resolution)
			select {
			case result, ok := <-resultChan:
				if !ok {
					// If resultChan is closed, exit the loop
					// This module is done, close the next module's input
					r.NextModule.CloseInput()
					return
				}
				if subdomainTakeoverResult, ok := result.(types.SubTakeResult); ok {
					// Subdomain takeover results, no need to send to the next module
					subdomainTakeoverResult.TaskName = r.Option.TaskName
					go results.Handler.SubdomainTakeover(&subdomainTakeoverResult)
					logger.SlogInfoLocal(fmt.Sprintf("Find subdomain takeover: %v - %v", subdomainTakeoverResult.Input, subdomainTakeoverResult.Value))
				} else {
					// DomainResolve send directly to the next module
					r.NextModule.GetInput() <- result
				}
			}
		}
	}()

	var firstData bool
	firstData = false
	var start time.Time
	var end time.Time
	doneCalled := false
	for {
		// Input is DNS info
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
				logger.SlogDebugLocal(fmt.Sprintf("%v shutdown: input begins closing", r.GetName()))
				allPluginWg.Wait()
				// Channel closed, end processing
				if firstData {
					end = time.Now()
					duration := end.Sub(start)
					handler.TaskHandle.ProgressEnd(r.GetName(), r.Option.Target, r.Option.ID, len(r.Option.SubdomainSecurity), duration)
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
			subdomain, ok := data.(types.SubdomainResult)
			if !ok {
				r.NextModule.GetInput() <- data
				continue
			}
			// Convert to DomainResolve and send to the next module
			tmp := types.DomainResolve{
				Domain: subdomain.Host,
				IP:     subdomain.IP,
			}
			r.NextModule.GetInput() <- tmp

			if !firstData {
				start = time.Now()
				handler.TaskHandle.ProgressStart(r.GetName(), r.Option.Target, r.Option.ID, len(r.Option.SubdomainSecurity))
				firstData = true
			}
			allPluginWg.Add(1)
			go func(data interface{}) {
				defer allPluginWg.Done()
				// If subdomain security scan is enabled
				if len(r.Option.SubdomainSecurity) != 0 {
					skipPluginFlag := true
					// Call plugin
					for _, pluginId := range r.Option.SubdomainSecurity {
						//var plgWg sync.WaitGroup
						var plgWg sync.WaitGroup
						plg, flag := plugins.GlobalPluginManager.GetPlugin(r.GetName(), pluginId)
						if flag {
							logger.SlogDebugLocal(fmt.Sprintf("%v plugin start execute: %v", plg.GetName(), data))
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
							pluginFunc := func(data interface{}) func() {
								return func() {
									defer plgWg.Done()
									select {
									case <-contextmanager.GlobalContextManagers.GetContext(r.Option.ID).Done():
										return
									default:
										_, err := plg.Execute(data)
										if err != nil {
										}
									}
								}
							}(data)
							err := pool.PoolManage.SubmitTask(r.GetName(), pluginFunc)
							if err != nil {
								plgWg.Done()
								logger.SlogError(fmt.Sprintf("task pool error: %v", err))
							}
							plgWg.Wait()
							logger.SlogDebugLocal(fmt.Sprintf("%v plugin end execute: %v", plg.GetName(), data))
						} else {
							// Plugin not found, skipping this plugin
							logger.SlogError(fmt.Sprintf("plugin %v not found", pluginId))
							// Send only once when none of the plugins found it
							if skipPluginFlag {
								resultChan <- data
								skipPluginFlag = false
							}
						}
					}
				} else {
					// Subdomain security scan not enabled, convert the data and send it to results
					// Already sent earlier
					//subdomain, ok = data.(types.SubdomainResult)
					//if ok {
					//	tmp := types.DomainResolve{
					//		Domain: subdomain.Host,
					//		IP:     subdomain.IP,
					//	}
					//	resultChan <- tmp
					//}
				}
			}(data)

		}
	}
}

func (r *Runner) SetInput(ch chan interface{}) {
	r.Input = ch
}

func (r *Runner) GetName() string {
	return "SubdomainSecurity"
}

func (r *Runner) GetInput() chan interface{} {
	return r.Input
}

func (r *Runner) CloseInput() {
	close(r.Input)
}
