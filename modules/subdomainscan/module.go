// subdomain-------------------------------------
// @file      : module.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/10 19:35
// -------------------------------------------

package subdomainscan

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
	"net"
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
			select {
			case result, ok := <-resultChan:
				if !ok {
					// If resultChan is closed, exit the loop
					// This module is done, close the next module's input
					r.NextModule.CloseInput()
					return
				}
				if subdomainResult, ok := result.(types.SubdomainResult); ok {
					subdomainResult.TaskName = r.Option.TaskName
					flag := results.Duplicate.SubdomainInTask(r.Option.ID, subdomainResult.Host, r.Option.IsRestart)
					if flag {
						if r.Option.Duplicates == "subdomain" && !r.Option.IsRestart {
							// Query mongodb for existing subdomains to deduplicate
							flag = results.Duplicate.SubdomainInMongoDb(&subdomainResult)
							if flag {
								// Subdomain not found in mongodb, store it and start scanning
								go results.Handler.Subdomain(&subdomainResult)
								// Send subdomain resolution results to the next module
								r.NextModule.GetInput() <- subdomainResult
							}
						} else {
							// Store in database and start scanning
							go results.Handler.Subdomain(&subdomainResult)
							// Send subdomain resolution results to the next module
							r.NextModule.GetInput() <- subdomainResult
						}
					} else {
						// Skip subdomains already scanned in the current task
						continue
					}
				} else {
					//fmt.Printf("get result begin:%v\n", result)
					// If the input is not types.SubdomainResult, it came straight from the previous module or this module is disabled, so send it to the next module
					target, ok := result.(string)
					if !ok {
						r.NextModule.GetInput() <- result
					} else {
						// Check whether this target has already been scanned in the current task by this or other nodes
						flag := results.Duplicate.SubdomainInTask(r.Option.ID, target, r.Option.IsRestart)
						if flag {
							if net.ParseIP(target) != nil {
								tmp := types.SubdomainResult{
									Host: target,
									IP:   []string{target},
								}
								r.NextModule.GetInput() <- tmp
							} else {
								resultDns := utils.DNS.QueryOne(target)
								resultDns.Host = target
								tmp := utils.DNS.DNSdataToSubdomainResult(resultDns)
								// Send downstream whether or not it resolves to an IP
								tmp.TaskName = r.Option.TaskName
								go results.Handler.Subdomain(&tmp)
								r.NextModule.GetInput() <- tmp
							}
						}
					}
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
		// The input can be one of two things: a domain, or ip
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
				if !doneCalled {
					close(resultChan)
					resultWg.Wait()
					r.Option.ModuleRunWg.Done()
					doneCalled = true // Mark as called Done
				}
				// Channel closed, end processing
				if firstData {
					end = time.Now()
					duration := end.Sub(start)
					handler.TaskHandle.ProgressEnd(r.GetName(), r.Option.Target, r.Option.ID, len(r.Option.SubdomainScan), duration)
				}
				logger.SlogInfoLocal(fmt.Sprintf("module %v target %v close resultChan", r.GetName(), r.Option.Target))
				nextModuleRun.Wait()
				return nil
			}
			//_, ok = data.(string)
			//if !ok {
			//	r.NextModule.GetInput() <- data
			//	continue
			//}
			if !firstData {
				start = time.Now()
				handler.TaskHandle.ProgressStart(r.GetName(), r.Option.Target, r.Option.ID, len(r.Option.SubdomainScan))
				firstData = true
			}
			allPluginWg.Add(1)
			go func(data interface{}) {
				defer allPluginWg.Done()
				// Send raw data to the next module so the original target is still mapped
				resultChan <- data
				t, _ := data.(string)
				if net.ParseIP(t) != nil {
					return
				}
				// If subdomain scan is enabled
				if len(r.Option.SubdomainScan) != 0 {
					// Skip plugin
					skipPluginFlag := true
					// Call plugin
					for _, pluginId := range r.Option.SubdomainScan {
						//var plgWg sync.WaitGroup
						var plgWg sync.WaitGroup
						plg, flag := plugins.GlobalPluginManager.GetPlugin(r.GetName(), pluginId)
						if flag {
							logger.SlogInfoLocal(fmt.Sprintf("%v plugin start execute: %v", plg.GetName(), data))
							plgWg.Add(1)
							args, argsFlag := utils.Tools.GetParameter(r.Option.Parameters, r.GetName(), plg.GetPluginId())
							if argsFlag {
								plg.SetParameter(args)
							} else {
								plg.SetParameter("")
							}
							//if r.Option.SubdomainFilename != "" {
							//	// If a subdomain dictionary is set, set the parameter for the plugin; ksubdomain requires a domain dictionary
							//	newParameter := plg.GetParameter() + " -subfile " + r.Option.SubdomainFilename
							//	plg.SetParameter(newParameter)
							//}
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
							logger.SlogInfoLocal(fmt.Sprintf("%v plugin end execute: %v", plg.GetName(), data))
						} else {
							// Plugin not found, skipping this plugin
							logger.SlogError(fmt.Sprintf("plugin %v not found, Skip this plugin", pluginId))
							// Send only once when none of the plugins found it
							if skipPluginFlag {
								resultChan <- data
								skipPluginFlag = false
							}
						}
					}
				}

			}(data)

		}
	}
}

func (r *Runner) SetInput(ch chan interface{}) {
	r.Input = ch
}

func (r *Runner) GetName() string {
	return "SubdomainScan"
}

func (r *Runner) GetInput() chan interface{} {
	return r.Input
}

func (r *Runner) CloseInput() {
	close(r.Input)
}
