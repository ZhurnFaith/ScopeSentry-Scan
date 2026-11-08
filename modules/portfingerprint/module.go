// portfingerprint-------------------------------------
// @file      : module.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/26 21:09
// -------------------------------------------

package portfingerprint

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
	"strconv"
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
	// Create a shared result channel
	resultChan := make(chan interface{}, 2000)
	go func() {
		err := r.NextModule.ModuleRun()
		if err != nil {
			logger.SlogError(fmt.Sprintf("Next module run error: %v", err))
		}
	}()
	// Result handling goroutine, reads plugin results asynchronously
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		var resultArray []interface{}
		for {
			select {
			case result, ok := <-resultChan:
				if !ok {
					if len(resultArray) > 0 {
						r.NextModule.GetInput() <- resultArray
					}
					time.Sleep(3 * time.Second)
					// If resultChan is closed, exit the loop
					// This module is done, close the next module's input
					r.NextModule.CloseInput()
					return
				}
				// Add result to array
				resultArray = append(resultArray, result)

				// If the array length exceeds 20, send to the next module and clear the array
				if len(resultArray) > 10 {
					r.NextModule.GetInput() <- resultArray
					resultArray = nil // Clear array
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
		select {
		case <-contextmanager.GlobalContextManagers.GetContext(r.Option.ID).Done():
			allPluginWg.Wait()
			if !doneCalled {
				close(resultChan)
				resultWg.Wait()
				r.Option.ModuleRunWg.Done()
				doneCalled = true // Mark as called Done
			}
			return nil
		case data, ok := <-r.Input:
			if !ok {
				time.Sleep(3 * time.Second)
				allPluginWg.Wait()
				// Channel closed, end processing
				if firstData {
					end = time.Now()
					duration := end.Sub(start)
					handler.TaskHandle.ProgressEnd(r.GetName(), r.Option.Target, r.Option.ID, len(r.Option.PortFingerprint), duration)
				}
				if !doneCalled {
					close(resultChan)
					resultWg.Wait()
					r.Option.ModuleRunWg.Done()
					doneCalled = true // Mark as called Done
				}
				logger.SlogInfoLocal(fmt.Sprintf("module %v target %v close resultChan", r.GetName(), r.Option.Target))
				return nil
			}
			_, ok = data.(types.PortAlive)
			if !ok {
				r.NextModule.GetInput() <- data
				continue
			}
			if !firstData {
				start = time.Now()
				handler.TaskHandle.ProgressStart(r.GetName(), r.Option.Target, r.Option.ID, len(r.Option.PortFingerprint))
				firstData = true
			}
			allPluginWg.Add(1)
			go func(data interface{}) {
				defer allPluginWg.Done()
				//Incoming data can only be types.PortAlive
				portAlive, _ := data.(types.PortAlive)
				var asset types.AssetOther
				asset = types.AssetOther{
					Host:    portAlive.Host,
					IP:      portAlive.IP,
					Port:    portAlive.Port,
					Service: "",
				}
				// An empty port here means it was sent directly without a port scan, so send it to the next module
				if asset.Port == "" {
					// If port is empty, only test the http service
					asset.Type = "http"
					resultChan <- asset
				} else {
					if len(r.Option.PortFingerprint) != 0 {
						// Call plugin
						for _, pluginId := range r.Option.PortFingerprint {
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
								}(&asset)
								err := pool.PoolManage.SubmitTask(r.GetName(), pluginFunc)
								if err != nil {
									plgWg.Done()
									logger.SlogError(fmt.Sprintf("task pool error: %v", err))
								}
								plgWg.Wait()
								if asset.Service != "" {
									// If the port's service is already identified, exit the loop and skip later plugins
									break
								}
								logger.SlogDebugLocal(fmt.Sprintf("%v plugin end execute: %v", plg.GetName(), data))
							} else {
								logger.SlogError(fmt.Sprintf("plugin %v not found", pluginId))
							}
						}
						// If no port service was detected, get the raw response
						if asset.Service == "" {
							asset.Type = "other"
							asset.Service = "unknown"
							portUint64, err := strconv.ParseUint(asset.Port, 10, 16)
							if err != nil {
								logger.SlogError(fmt.Sprintf("Port conversion error: %v", err))
							} else {
								rev, err := utils.Requests.TcpRecv(asset.Host, uint16(portUint64))
								if err == nil {
									rawResponse := string(rev)
									asset.Banner = utils.Tools.EscapeInvisibleKeepUnicode(rawResponse)
								} else {
									asset.Banner = ""
								}
							}
							resultChan <- asset
						} else {
							// Identified successfully
							resultChan <- asset
						}
					} else {
						// If port fingerprinting is not enabled, only do http mapping
						asset.Type = "http"
						resultChan <- asset
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
	return "PortFingerprint"
}

func (r *Runner) GetInput() chan interface{} {
	return r.Input
}

func (r *Runner) CloseInput() {
	close(r.Input)
}
