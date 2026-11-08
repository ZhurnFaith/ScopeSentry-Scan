// main-------------------------------------
// @file      : restructure_cmd.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/6 22:00
// -------------------------------------------

package main

import (
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/bigcache"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/config"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/configupdater"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/contextmanager"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/global"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/handler"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/mongodb"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/node"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/notification"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/pebbledb"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/plugins"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/pool"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/redis"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/results"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/task"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils"
	"log"
	_ "net/http/pprof"
	"path/filepath"
	"sync"
	"time"
)

func main() {
	// Initialize system info
	config.Initialize()
	global.VERSION = "1.5"
	var err error
	// Initialize mongodb connection
	mongodb.Initialize()
	// Initialize redis connection
	redis.Initialize()
	// Initialize log module
	err = logger.NewLogger()
	if err != nil {
		log.Fatalf("Failed to init logger: %v", err)
	}
	// Initialize task counter
	handler.InitHandle()
	// Update configuration, load dictionaries
	configupdater.Initialize()
	// Initialize module configuration
	err = config.ModulesInitialize()
	if err != nil {
		log.Fatalf("Failed to init ModulesConfig: %v", err)
		return
	}
	// Initialize context manager
	contextmanager.NewContextManager()
	// Initialize tools
	utils.InitializeTools()
	utils.InitializeDnsTools()
	utils.InitializeRequests()
	utils.InitializeResults()
	// Initialize notification module
	notification.InitializeNotification()
	// Initialize goroutine pool
	pool.Initialize()
	// Initialize goroutine pools for each module
	pool.PoolManage.InitializeModulesPools(config.ModulesConfig)
	go pool.StartMonitoring()
	// Initialize memory cache
	err = bigcache.Initialize()
	if err != nil {
		logger.SlogErrorLocal(fmt.Sprintf("bigcache Initialize error: %v", err))
		return
	}
	// Initialize local persistent cache
	pebbledbSetting := pebbledb.Settings{
		DBPath:       filepath.Join(global.AbsolutePath, "data", "pebbledb"),
		CacheSize:    64 << 20,
		MaxOpenFiles: 500,
	}
	pebbledbOption := pebbledb.GetPebbleOptions(&pebbledbSetting)
	if !global.AppConfig.Debug {
		pebbledbOption.Logger = nil
	}
	pedb, err := pebbledb.NewPebbleDB(pebbledbOption, pebbledbSetting.DBPath)
	if err != nil {
		return
	}
	pebbledb.PebbleStore = pedb
	defer func(PebbleStore *pebbledb.PebbleDB) {
		_ = PebbleStore.Close()
	}(pebbledb.PebbleStore)

	// Initialize the result handling queue (normally this is done at task start and the queue is closed when the task finishes)
	results.InitializeResultQueue()
	defer results.Close()

	// Initialize global plugin manager
	plugins.GlobalPluginManager = plugins.NewPluginManager()
	err = plugins.GlobalPluginManager.InitializePlugins()
	if err != nil {
		log.Fatalf("Failed to init plugins: %v", err)
		return
	}
	// Performance monitoring
	//go pprof()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done() // Decrement counter to indicate task completion
		task.GetTask()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		node.Register()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		go configupdater.RefreshConfig()
	}()
	time.Sleep(10 * time.Second)
	wg.Wait()
}

//func pprof() {
//	if global.AppConfig.Debug {
//		go func() {
//			_ = http.ListenAndServe("0.0.0.0:6060", nil)
//		}()
//		//go DebugMem()
//		sigs := make(chan os.Signal, 1)
//		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
//
//		go func() {
//			sig := <-sigs
//			fmt.Println("Received termination signal:", sig)
//		}()
//	}
//}
