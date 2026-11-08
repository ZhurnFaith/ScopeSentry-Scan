// urlscan-------------------------------------
// @file      : module.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/10 21:05
// -------------------------------------------

package urlscan

import (
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/contextmanager"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/global"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/handler"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/interfaces"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/options"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/plugins"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/pool"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/results"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils"
	"os/exec"
	"path/filepath"
	"strings"
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
				// Input here is types.UrlResult; process it, store it in the database and send it to the next module
				// The original types.AssetOther and types.AssetHttp were already sent to the next module when input was read
				// This result has already been deduplicated in the plugin
				if urlResult, ok := result.(types.UrlResult); ok {
					urlResult.TaskName = r.Option.TaskName
					hash := utils.Tools.GenerateHash()
					urlResult.ResultId = hash
					if strings.Contains(urlResult.Output, "api") {
						urlResult.Tags = append(urlResult.Tags, "api")
					}
					if !urlResult.IsFile {
						// app file is not stored in the database url result
						go results.Handler.URL(&urlResult)
					}
					r.NextModule.GetInput() <- urlResult
				} else {
					if urlFileResult, ok := result.(types.UrlFile); ok {
						var uroWg sync.WaitGroup
						uroWg.Add(1)
						go func() {
							sem := utils.GetSemaphore("uro", int64(1))
							defer func() {
								uroWg.Done()
							}()

							err := sem.Acquire(contextmanager.GlobalContextManagers.GetContext(r.Option.ID), 1)
							if err != nil {
								logger.SlogWarnLocal(fmt.Sprintf("uro sem.Acquire get error: %v", err))
								return
							}
							defer sem.Release(1)
							flag := utils.Tools.CommandExists("uro")
							if flag {
								utils.Tools.DeleteFile(fmt.Sprintf("%v.dup", urlFileResult.Filepath))
								cmd := exec.Command("uro", "-i", urlFileResult.Filepath, "-o", fmt.Sprintf("%v.dup", urlFileResult.Filepath))
								// Run command and get output
								_, err := cmd.CombinedOutput()
								// If there is an error, print the error message
								if err != nil {
									logger.SlogErrorLocal(fmt.Sprintf("%v run uro error: %v\n", urlFileResult.Filepath, err))
								} else {
									urlFileResult.Filepath = fmt.Sprintf("%v.dup", urlFileResult.Filepath)
								}
							}
						}()
						uroWg.Wait()
						r.NextModule.GetInput() <- urlFileResult
					} else {
						r.NextModule.GetInput() <- result
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
					handler.TaskHandle.ProgressEnd(r.GetName(), r.Option.Target, r.Option.ID, len(r.Option.URLScan), duration)
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
			// Send raw data to the next module; input here is types.AssetOther, types.AssetHttp
			resultChan <- data

			if !firstData {
				start = time.Now()
				handler.TaskHandle.ProgressStart(r.GetName(), r.Option.Target, r.Option.ID, len(r.Option.URLScan))
				firstData = true
			}

			allPluginWg.Add(1)
			go func(data interface{}) {
				defer allPluginWg.Done()
				// If it is AssetOther, skip this module, only run for http assets
				httpData, ok := data.(types.AssetHttp)
				if !ok {
					return
				}
				// Deduplicate http assets within the current task

				filename := utils.Tools.HashXX64String(strings.Replace(strings.Replace(httpData.URL, "http://", "", -1), "https://", "", -1))
				//if !r.Option.IsStart {
				//	flag := results.Duplicate.DuplicateUrlFileKey(filename, r.Option.ID)
				//	if !flag {
				//		// Duplicate, already scanned
				//		return
				//	}
				//}
				flag := results.Duplicate.DuplicateUrlFileKey(filename, r.Option.ID)
				if !flag {
					// Duplicate, already scanned
					return
				}
				// Write raw urls to file
				urlFilePath := filepath.Join(global.TmpDir, filename)
				err := utils.Tools.WriteContentFileAppend(urlFilePath, httpData.URL+"\n")
				if err != nil {
				}

				if len(r.Option.URLScan) != 0 {
					// Call plugin
					for _, pluginId := range r.Option.URLScan {
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
							pluginFunc := func(data interface{}) func() {
								return func() {
									defer plgWg.Done()
									select {
									case <-contextmanager.GlobalContextManagers.GetContext(r.Option.ID).Done():
										return
									default:
										_, err := plg.Execute(data)
										if err == nil {
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
							logger.SlogDebugLocal(fmt.Sprintf("%v plugin end execute", plg.GetName()))
						} else {
							logger.SlogError(fmt.Sprintf("plugin %v not found", pluginId))
						}
					}
					// Call the url deduplication tool to deduplicate url data
					rootDomain, _ := utils.Tools.GetRootDomain(httpData.Host)

					// Send urlfile
					urlFile := types.UrlFile{
						Host:       httpData.Host,
						Filepath:   urlFilePath,
						RootDomain: rootDomain,
					}
					resultChan <- urlFile

				} else {
					rootDomain, _ := utils.Tools.GetRootDomain(httpData.Host)
					// If not enabled, convert http into a urlresult and send it to the next module to check the home page for sensitive info leaks
					r.NextModule.GetInput() <- types.UrlResult{
						Input:      httpData.URL,
						Output:     httpData.URL,
						OutputType: "httpx",
						ResultId:   utils.Tools.GenerateHash(),
						Body:       httpData.ResponseBody,
						Status:     httpData.StatusCode,
					}
					// Send urlfile
					urlFile := types.UrlFile{
						Host:       httpData.Host,
						Filepath:   urlFilePath,
						RootDomain: rootDomain,
					}
					resultChan <- urlFile
				}

			}(data)
		}
	}
}

func (r *Runner) SetInput(ch chan interface{}) {
	r.Input = ch
}

func (r *Runner) GetName() string {
	return "URLScan"
}

func (r *Runner) GetInput() chan interface{} {
	return r.Input
}

func (r *Runner) CloseInput() {
	close(r.Input)
}
