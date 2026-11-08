// assethandle-------------------------------------
// @file      : module.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/10 21:06
// -------------------------------------------

package assethandle

import (
	"fmt"
	"strings"
	"sync"
	"time"

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
	"go.mongodb.org/mongo-driver/bson"
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
	httpAssetHandle := func(dataTmp types.AssetHttp) {
		dataTmp.TaskName = []string{r.Option.TaskName}
		dataTmp.ResponseBodyHash = utils.Tools.HashXX64String(dataTmp.ResponseBody)
		flag, id, bsonData := results.Duplicate.AssetInMongodb(dataTmp.Host, dataTmp.Port)
		if flag {
			var oldAssetHttp types.AssetHttp
			data, _ := bson.Marshal(bsonData)
			_ = bson.Unmarshal(data, &oldAssetHttp)
			changeData := utils.Results.CompareAssetHttp(oldAssetHttp, dataTmp)
			if changeData.Timestamp != "" {
				// The asset changed, send the result to the changelog
				changeData.AssetId = id
				go results.Handler.AssetChangeLog(&changeData)
			}
			if dataTmp.Screenshot == "" {
				dataTmp.Screenshot = oldAssetHttp.Screenshot
			}
			t := ""
			if oldAssetHttp.Time == "" {
				t = dataTmp.Time
			} else {
				t = oldAssetHttp.Time
			}
			// Update the asset, set the latest scan time
			dataTmp.LastScanTime = dataTmp.Time
			dataTmp.Time = t
			dataTmp.Project = oldAssetHttp.Project
			dataTmp.RootDomain = oldAssetHttp.RootDomain
			dataTmp.TaskName = append(dataTmp.TaskName, oldAssetHttp.TaskName...)
			dataTmp.TaskName = utils.Tools.RemoveStringDuplicates(dataTmp.TaskName)
			dataTmp.Tags = append(dataTmp.Tags, oldAssetHttp.Tags...)
			dataTmp.Tags = utils.Tools.RemoveStringDuplicates(dataTmp.Tags)
			go func() {
				results.Handler.HttpIcon(dataTmp.FavIconMMH3, dataTmp.IconContent)
				dataTmp.IconContent = ""
				results.Handler.HttpBody(dataTmp.ResponseBodyHash, dataTmp.ResponseBody)
				dataTmp.ResponseBody = ""
				results.Handler.HttpScreenshot(dataTmp.ResponseBodyHash, dataTmp.Screenshot)
				dataTmp.Screenshot = ""
				results.Handler.AssetUpdate(id, dataTmp)
			}()
			// Asset unchanged, nothing to do
		} else {
			// Asset does not exist in database, insert directly.
			go func() {
				results.Handler.HttpIcon(dataTmp.FavIconMMH3, dataTmp.IconContent)
				dataTmp.IconContent = ""
				results.Handler.HttpBody(dataTmp.ResponseBodyHash, dataTmp.ResponseBody)
				dataTmp.ResponseBody = ""
				results.Handler.HttpScreenshot(dataTmp.ResponseBodyHash, dataTmp.Screenshot)
				dataTmp.Screenshot = ""
				results.Handler.AssetHttpInsert(&dataTmp)
			}()
		}

	}
	// Result handling goroutine, reads plugin results asynchronously
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		var assetOtherArray []types.AssetOther
		var assetHttpArray []types.AssetHttp
		for {
			select {
			case result, ok := <-resultChan:
				if !ok {
					// If resultChan is closed, exit the loop
					// This module is done, close the next module's input
					if len(assetOtherArray) > 0 {
						r.NextModule.GetInput() <- assetOtherArray
					}

					if len(assetHttpArray) > 0 {
						r.NextModule.GetInput() <- assetHttpArray
					}

					r.NextModule.CloseInput()
					return
				}
				r.NextModule.GetInput() <- result
				switch dataTmp := result.(type) {
				case types.AssetOther:
					if dataTmp.Type == "http" {
						tmp := types.AssetHttp{
							Host: dataTmp.Host,
							Port: dataTmp.Port,
							IP:   dataTmp.IP,
						}
						if r.Option.Type == "assetSource" || r.Option.Type == "asset" {
							if tmp.URL == "" {
								tmp.URL = dataTmp.Service + "://" + dataTmp.Host + ":" + dataTmp.Port
								tmp.URL = strings.ReplaceAll(strings.ReplaceAll(tmp.URL, ":80", ""), ":443", "")
							}
						}
						if len(r.Option.AssetMapping) != 0 {
							// If 0, httpx asset mapping is not enabled, so the task was created from assets
							httpAssetHandle(tmp)
						}
						assetHttpArray = append(assetHttpArray, tmp)
						continue
					}
					dataTmp.TaskName = []string{r.Option.TaskName}
					// Filter unknown
					if dataTmp.Service == "unknown" {
						if len(dataTmp.Banner) == 0 {
							logger.SlogInfoLocal(fmt.Sprintf("Unknown asset %v port %v ", dataTmp.Host, dataTmp.Port))
							dataTmp.LastScanTime = dataTmp.Time
							go results.Handler.AssetOtherInsert(&dataTmp)
							//utils.RunAnalyze(dataTmp.Host+":"+dataTmp.Port, httpAssetHandle)
							continue
						}
					}

					flag, id, bsonData := results.Duplicate.AssetInMongodb(dataTmp.Host, dataTmp.Port)
					if flag {
						// Asset exists in database, its info will be diff
						var oldAsset types.AssetOther
						data, _ := bson.Marshal(bsonData)
						_ = bson.Unmarshal(data, &oldAsset)
						changeData := utils.Results.CompareAssetOther(oldAsset, dataTmp)
						if changeData.Timestamp != "" {
							// The asset changed, send the result to the changelog
							changeData.AssetId = id
							go results.Handler.AssetChangeLog(&changeData)
							// Update the asset, set the latest scan time
						}
						dataTmp.LastScanTime = dataTmp.Time
						dataTmp.Time = oldAsset.Time
						dataTmp.Project = oldAsset.Project
						dataTmp.RootDomain = oldAsset.RootDomain
						dataTmp.TaskName = append(dataTmp.TaskName, oldAsset.TaskName...)
						dataTmp.TaskName = utils.Tools.RemoveStringDuplicates(dataTmp.TaskName)
						dataTmp.Tags = append(dataTmp.Tags, oldAsset.Tags...)
						dataTmp.Tags = utils.Tools.RemoveStringDuplicates(dataTmp.Tags)
						go results.Handler.AssetUpdate(id, dataTmp)
						// Asset unchanged, nothing to do
					} else {
						// Asset does not exist in database, insert directly.
						dataTmp.LastScanTime = dataTmp.Time
						go results.Handler.AssetOtherInsert(&dataTmp)
					}
					assetOtherArray = append(assetOtherArray, dataTmp)
					if len(assetOtherArray) > 10 {
						r.NextModule.GetInput() <- assetOtherArray
						assetOtherArray = nil
					}
				case types.AssetHttp:
					httpAssetHandle(dataTmp)
					assetHttpArray = append(assetHttpArray, dataTmp)
					if len(assetHttpArray) > 10 {
						r.NextModule.GetInput() <- assetHttpArray
						assetHttpArray = nil
					}
				case types.RootDomain:
					dataTmp.TaskName = r.Option.TaskName
					dataTmp.Time = utils.Tools.GetTimeNow()
					go results.Handler.RootDomain(&dataTmp)
				case types.APP:
					dataTmp.TaskName = r.Option.TaskName
					dataTmp.Time = utils.Tools.GetTimeNow()
					go results.Handler.APP(&dataTmp)
				case types.MP:
					dataTmp.TaskName = r.Option.TaskName
					dataTmp.Time = utils.Tools.GetTimeNow()
					go results.Handler.MP(&dataTmp)
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
					handler.TaskHandle.ProgressEnd(r.GetName(), r.Option.Target, r.Option.ID, len(r.Option.AssetHandle), duration)
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
			if !firstData {
				start = time.Now()
				handler.TaskHandle.ProgressStart(r.GetName(), r.Option.Target, r.Option.ID, len(r.Option.AssetHandle))
				firstData = true
			}
			allPluginWg.Add(1)
			go func(data interface{}) {
				defer allPluginWg.Done()
				var ty string
				var assetOther types.AssetOther
				var assetHttp types.AssetHttp
				var rootDomain types.RootDomain
				var app types.APP
				var mp types.MP
				switch a := data.(type) {
				case types.AssetOther:
					ty = "other"
					assetOther = a
				case types.AssetHttp:
					ty = "htttp"
					assetHttp = a
				case types.RootDomain:
					ty = "rootDomain"
					rootDomain = a
				case types.APP:
					ty = "app"
					app = a
				case types.MP:
					ty = "mp"
					mp = a
				default:
					r.NextModule.GetInput() <- data
					return
				}
				if len(r.Option.AssetHandle) != 0 {
					// Call plugin
					for _, pluginId := range r.Option.AssetHandle {
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
							var pluginFunc func()
							switch ty {
							case "other":
								pluginFunc = func(data interface{}) func() {
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
								}(&assetOther)
							case "htttp":
								pluginFunc = func(data interface{}) func() {
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
								}(&assetHttp)
							case "rootDomain":
								pluginFunc = func(data interface{}) func() {
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
								}(&rootDomain)
							case "app":
								pluginFunc = func(data interface{}) func() {
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
								}(&app)
							case "mp":
								pluginFunc = func(data interface{}) func() {
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
								}(&mp)
							}
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
				}
				// If this module is not enabled, or it is enabled and plugins have finished, send data to result handling

				switch ty {
				case "other":
					resultChan <- assetOther
				case "htttp":
					resultChan <- assetHttp
				case "rootDomain":
					resultChan <- rootDomain
				case "app":
					resultChan <- app
				case "mp":
					resultChan <- mp
				}
			}(data)
		}
	}
}

func (r *Runner) SetInput(ch chan interface{}) {
	r.Input = ch
}

func (r *Runner) GetName() string {
	return "AssetHandle"
}

func (r *Runner) GetInput() chan interface{} {
	return r.Input
}

func (r *Runner) CloseInput() {
	close(r.Input)
}
