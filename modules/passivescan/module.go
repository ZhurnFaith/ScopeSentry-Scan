// passivescan-------------------------------------
// @file      : module.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2025/2/8 19:30
// -------------------------------------------

package passivescan

import (
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/contextmanager"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/handler"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/interfaces"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/options"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/plugins"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"sync"
	"time"
)

type Runner struct {
	Option     *options.TaskOptions
	NextModule interfaces.ModuleRunner
	Input      chan interface{}
}

func NewRunner(op *options.TaskOptions, nextModule interfaces.ModuleRunner) *Runner { // Also changed to value type
	return &Runner{
		Option:     op,
		NextModule: nextModule,
	}
}

func (r *Runner) ModuleRun() error {
	defer PassiveScanWgMap[r.Option.ID].Done()

	var start time.Time
	var end time.Time
	var wg sync.WaitGroup
	handler.TaskHandle.ProgressStart(r.GetName(), r.Option.Target, r.Option.ID, len(r.Option.PassiveScan))
	start = time.Now()
	// Call plugin
	for _, pluginId := range r.Option.PassiveScan {
		plg, flag := plugins.GlobalPluginManager.GetPlugin(r.GetName(), pluginId)
		if flag {
			logger.SlogDebugLocal(fmt.Sprintf("%v plugin start execute", plg.GetName()))
			go func() {
				wg.Add(1)
				defer wg.Done()
				plg.SetTaskId(r.Option.ID)
				plg.SetTaskName(r.Option.TaskName)
				_, err := plg.Execute("")
				if err != nil {

				}
			}()
		} else {
			logger.SlogError(fmt.Sprintf("plugin %v not found", pluginId))
		}
	}
	closePlgFunc := func() {
		for _, pluginId := range r.Option.PassiveScan {
			plg, flag := plugins.GlobalPluginManager.GetPlugin(r.GetName(), pluginId)
			plg.SetTaskId(r.Option.ID)
			plg.SetTaskName(r.Option.TaskName)
			if flag {
				logger.SlogInfo(fmt.Sprintf("task %v close %v module %v plugin", r.Option.ID, r.GetName(), plg.GetName()))
				go func() {
					plg.SetCustom("close task")
				}()
			}
		}
		wg.Wait()
		end = time.Now()
		duration := end.Sub(start)
		handler.TaskHandle.ProgressEnd(r.GetName(), r.Option.Target, r.Option.ID, len(r.Option.PassiveScan), duration)
	}
	for {
		select {
		case <-contextmanager.GlobalContextManagers.GetContext(r.Option.ID).Done():
			closePlgFunc()
			return nil
		case data, ok := <-r.Input:
			if !ok {
				time.Sleep(3 * time.Second)
				closePlgFunc()
				return nil
			}
			// Pass the input data to the plugin via SetCustom; SetCustom is used for compatibility instead of adding a new function
			for _, pluginId := range r.Option.PassiveScan {
				plg, flag := plugins.GlobalPluginManager.GetPlugin(r.GetName(), pluginId)
				if flag {
					plg.SetTaskId(r.Option.ID)
					plg.SetTaskName(r.Option.TaskName)
					go func() {
						plg.SetCustom(data)
					}()
				}
			}

		}
	}
}

func (r *Runner) SetInput(ch chan interface{}) {
	r.Input = ch
}

func (r *Runner) GetName() string {
	return "PassiveScan"
}

func (r *Runner) GetInput() chan interface{} {
	return r.Input
}

func (r *Runner) CloseInput() {
	close(r.Input)
}

var TaskPassiveScanGlobal = make(map[string]chan interface{})
var mu sync.Mutex // Declare a mutex
var PassiveScanWgMap = make(map[string]*sync.WaitGroup)

func SetPassiveScanChan(op *options.TaskOptions) {
	mu.Lock()         // Acquire the lock to ensure only one goroutine can modify map
	defer mu.Unlock() // Release lock when function ends

	// Check whether id already exists
	if _, exists := TaskPassiveScanGlobal[op.ID]; !exists {
		logger.SlogInfo(fmt.Sprintf("passive scan begin: %v", op.ID))
		// If it does not exist, create a new chan and add it to the map
		vulnerabilityInputChan := make(chan interface{}, 2000)
		TaskPassiveScanGlobal[op.ID] = vulnerabilityInputChan
		passivescanModule := NewRunner(op, nil)
		passivescanModule.SetInput(vulnerabilityInputChan)
		if PassiveScanWgMap[op.ID] == nil {
			PassiveScanWgMap[op.ID] = &sync.WaitGroup{}
		}
		go func() {
			PassiveScanWgMap[op.ID].Add(1)
			err := passivescanModule.ModuleRun()
			if err != nil {

			}
		}()
	}
}

func PassiveScanChanDone(id string) {
	if _, exists := TaskPassiveScanGlobal[id]; exists {
		logger.SlogInfo(fmt.Sprintf("passive scan end: %v", id))
		close(TaskPassiveScanGlobal[id])
		delete(TaskPassiveScanGlobal, id)
	}
}
