// task-------------------------------------
// @file      : task.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/6 21:08
// -------------------------------------------

package task

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/bigcache"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/contextmanager"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/global"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/handler"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/options"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/pebbledb"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/pool"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/redis"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/runner"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/passivescan"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils"
	goRedis "github.com/redis/go-redis/v9"
	"os"
	"sync"
	"time"
)

func GetTask() {
	// Run locally cached tasks
	//RunPebbledbTask()
	// Get task from redis
	RunRedisTask()
}

// RunPebbledbTask run local cached tasks
func RunPebbledbTask(value []byte) {
	logger.SlogInfoLocal(fmt.Sprintf("get PebbleStore task: %v", string(value)))
	var runnerOption options.TaskOptions
	err := utils.Tools.JSONToStruct(value, &runnerOption)
	// Add global context to task
	contextmanager.GlobalContextManagers.AddContext(runnerOption.ID)
	// Set to the locally fetched task
	runnerOption.IsRestart = true
	if err != nil {
		logger.SlogErrorLocal(fmt.Sprintf("task JSONToStruct error: %v - %v", string(value), err))
		err = pebbledb.PebbleStore.Delete([]byte(fmt.Sprintf("task:%s", runnerOption.ID)))
		if err != nil {
			logger.SlogErrorLocal(fmt.Sprintf("PebbleStore delete error: %v", runnerOption.ID))
		}
		return
	}
	// Run task targets
	RunPebbleTarget(runnerOption)
	// Delete the task when it finishes; the update is deleted once in the redis task
	//err = pebbledb.PebbleStore.Delete([]byte(key))
	//if err != nil {
	//	logger.SlogErrorLocal(fmt.Sprintf("PebbleStore Delete %v error: %v", key, err))
	//}
	logger.SlogInfoLocal(fmt.Sprintf("PebbleStore task run end: %v", runnerOption.ID))
	//if len(keys) > 0 {
	//	// Print all with "task:" key-value pairs starting with
	//	for key, value := range keys {
	//
	//	}
	//	// Close nuclei engine
	//	handler.CloseNucleiEngine()
	//}
}

// RunRedisTask get task from redis
func RunRedisTask() {
	ticker := time.Tick(3 * time.Second)
	for {
		<-ticker
		TaskNodeName := "NodeTask:" + global.AppConfig.NodeName
		exists, err := redis.RedisClient.Exists(context.Background(), TaskNodeName)

		if err != nil {
			logger.SlogError(fmt.Sprintf("GetTask Error: %v", err))
			continue
		}
		if exists {
			var wg sync.WaitGroup

			taskInfo, err := redis.RedisClient.GetFirstFromList(context.Background(), TaskNodeName)
			if err != nil {
				logger.SlogError(fmt.Sprintf("GetTask info error: %v", err))
				continue
			}

			logger.SlogInfo(fmt.Sprintf("Get a new task: %v", taskInfo))
			var runnerOption options.TaskOptions
			err = json.Unmarshal([]byte(taskInfo), &runnerOption)
			if err != nil {
				logger.SlogError(fmt.Sprintf("Task parse error: %s", err))
				continue
			}
			// Run task initialization methods
			InitTaskOption(runnerOption)
			global.TaskName = runnerOption.TaskName

			taskKey := fmt.Sprintf("task:%v", runnerOption.ID)

			logger.SlogInfo(fmt.Sprintf("Task begin: %v %v", runnerOption.ID, runnerOption.TaskName))
			if runnerOption.Type == "page_monitoring" {
				// Run page monitoring
				go func() {
					for {
						targets, err := redis.RedisClient.BatchGetAndDelete(context.Background(), "TaskInfo:"+runnerOption.ID, 50)
						if len(targets) == 0 {
							break
						}
						if err != nil {
							// If err is not nil and is not redis.Nil, print the error
							if !errors.Is(err, goRedis.Nil) {
								logger.SlogError(fmt.Sprintf("GetRedisTask BatchGetAndDelete error: %v", err))
								// If getting the task fails, exit directly so local tasks are not deleted; after a restart, local tasks are fetched again
								os.Exit(0)
							}
							break
						}
						runner.PageMonitoringRunner(targets)
					}
				}()
			} else {
				// Enable passive scan
				passiveOptionCopy := runnerOption
				passivescan.SetPassiveScanChan(&passiveOptionCopy)

				cacheRunFlag := false
				// If the task exists locally, run the locally cached task in the background; this lets nodes resume after a crash. If the task was paused, local task info is deleted, so nothing runs here and pausing does not fail
				value, _ := pebbledb.PebbleStore.Get([]byte(taskKey))
				if value != nil {
					cacheRunFlag = true
					wg.Add(1)
					go func() {
						defer wg.Done()
						RunPebbledbTask(value)
					}()
					time.Sleep(5 * time.Second)
				}

				// Write task configuration locally
				runnerOption.IsRestart = false
				err = pebbledb.PebbleStore.Put([]byte(taskKey), []byte(taskInfo))
				if err != nil {
					logger.SlogError(fmt.Sprintf("PebbleStore.Put Task error: %s", err))
					continue
				}

				// Add global context to task
				contextmanager.GlobalContextManagers.AddContext(runnerOption.ID)
				// If the task resumed after a pause and there was no locally cached task before, run the locally cached targets first
				if runnerOption.IsStart && !cacheRunFlag {
					runnerOption.IsRestart = false
					wg.Add(1)
					go func() {
						defer wg.Done()
						logger.SlogInfoLocal(fmt.Sprintf("[stop to start]task start run pebbledb: %v", runnerOption.ID))
						RunPebbleTarget(runnerOption)
						logger.SlogInfoLocal(fmt.Sprintf("[stop to start]task end run pebbledb: %v", runnerOption.ID))
					}()
				}
			loop:
				for {
					select {
					case <-contextmanager.GlobalContextManagers.GetContext(runnerOption.ID).Done():
						break loop
					default:
						target, err := redis.RedisClient.PopFromListR(context.Background(), "TaskInfo:"+runnerOption.ID)
						if err != nil {
							// If err is not nil and is not redis.Nil, print the error
							if !errors.Is(err, goRedis.Nil) {
								logger.SlogError(fmt.Sprintf("GetRedisTask redis error: %v", err))
								// If getting the task fails, exit directly so local tasks are not deleted; after a restart, local tasks are fetched again
								os.Exit(0)
							}
							break loop
						}
						optionCopy := runnerOption
						optionCopy.Target = target
						taskFunc := func(op options.TaskOptions) func() {
							return func() {
								wg.Add(1)
								defer wg.Done()
								select {
								case <-contextmanager.GlobalContextManagers.GetContext(op.ID).Done():
									// Return directly if task canceled
									return
								default:
									err := runner.Run(op)
									if err != nil {
										// The task was canceled, return without deleting the target
										return
									} else {
										// Delete target after it finishes running
										DeletePebbleTarget(pebbledb.PebbleStore, []byte(op.ID+":"+op.Target))
									}
								}
							}
						}(optionCopy)
						// Write task targets locally
						err = pebbledb.PebbleStore.Put([]byte(fmt.Sprintf("%v:%v", runnerOption.ID, target)), []byte(""))
						if err != nil {
							logger.SlogError(fmt.Sprintf("PebbleStore.Put target error: %v", err))
						}
						// Submit task
						err = pool.PoolManage.SubmitTask("task", taskFunc)
						if err != nil {
							logger.SlogError(fmt.Sprintf("task pool error: %v", err))
							wg.Done()
						}
						// Prevent a single node from taking targets too fast and starving other nodes
						time.Sleep(3 * time.Second)
						logger.SlogInfoLocal(fmt.Sprintf("task target pool running goroutines: %v", pool.PoolManage.GetModuleRunningGoroutines("task")))
					}
				}
				time.Sleep(3 * time.Second)
				wg.Wait()
				passivescan.PassiveScanChanDone(runnerOption.ID)
				passivescan.PassiveScanWgMap[runnerOption.ID].Wait()
				// Delete task context
				contextmanager.GlobalContextManagers.DeleteContext(runnerOption.ID)
			}
			logger.SlogInfo(fmt.Sprintf("Task end: %v - %v", runnerOption.ID, runnerOption.TaskName))
			handler.CloseNucleiEngine()
			// Target finished, delete task info
			// Delete locally cached task info
			err = pebbledb.PebbleStore.Delete([]byte(taskKey))
			if err != nil {
				logger.SlogErrorLocal(fmt.Sprintf("PebbleStore Delete %v error: %v", taskKey, err))
			}
			// Reinitialize cache when task ends
			err = bigcache.Initialize()
			if err != nil {
				logger.SlogErrorLocal(fmt.Sprintf("bigcache Initialize error: %v", err))
			}
			// Show task info
			_ = handler.TaskHandle.PopTaskId(runnerOption.ID)
			// Close method run when task ends
			OptionClose()
			// Clear global variables
			CleanGlobal()
			// Clear file lock
			utils.Tools.ClearAllLocks()
			// Run task end methods
			logger.SlogInfo(fmt.Sprintf("Task clean end: %v", runnerOption.ID))
		}
	}
}

func CleanGlobal() {
	global.TmpCustomMapParameter = sync.Map{}
	global.TmpCustomParameter = nil
}
