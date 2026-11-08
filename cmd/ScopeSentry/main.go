// Package ScopeSentry -----------------------------
// @file      : main.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2023/12/6 17:24
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
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

func main() {
	Banner()
	// Initialize system info
	config.Initialize()
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
	utils.InitializeNetHttp()
	utils.InitializeResults()
	utils.InitializeProxyRequestsPool()
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
	go pprof()
	//go printMemStats(5 * time.Second)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done() // Decrement counter to indicate task completion
		for {
			task.GetTask()
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			node.Register()
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			configupdater.RefreshConfig()
		}
	}()
	time.Sleep(10 * time.Second)
	wg.Wait()
}

func Banner() {
	banner := "   _____                         _____            _              \n  / ____|                       / ____|          | |             \n | (___   ___ ___  _ __   ___  | (___   ___ _ __ | |_ _ __ _   _ \n  \\___ \\ / __/ _ \\| '_ \\ / _ \\  \\___ \\ / _ \\ '_ \\| __| '__| | | |\n  ____) | (_| (_) | |_) |  __/  ____) |  __/ | | | |_| |  | |_| |\n |_____/ \\___\\___/| .__/ \\___| |_____/ \\___|_| |_|\\__|_|   \\__, |\n                  | |                                       __/ |\n                  |_|                                      |___/ "
	fmt.Println(banner)
}

func pprof() {
	if global.AppConfig.Debug {
		go func() {
			runtime.SetBlockProfileRate(1)
			_ = http.ListenAndServe("0.0.0.0:6060", nil)
		}()
		//go DebugMem()
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			sig := <-sigs
			fmt.Println("Received termination signal:", sig)
		}()
	}
}

func printMemStats(interval time.Duration) {
	if global.AppConfig.Debug {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)

			fmt.Printf("\n==== Memory Stats ====\n")
			fmt.Printf("Allocated:\t%.2f MB\n", float64(memStats.Alloc)/1024/1024)
			fmt.Printf("Total Alloc:\t%.2f MB\n", float64(memStats.TotalAlloc)/1024/1024)
			fmt.Printf("Sys:\t\t%.2f MB\n", float64(memStats.Sys)/1024/1024)
			fmt.Printf("Heap Alloc:\t%.2f MB\n", float64(memStats.HeapAlloc)/1024/1024)
			fmt.Printf("Heap Sys:\t%.2f MB\n", float64(memStats.HeapSys)/1024/1024)
			fmt.Printf("Heap Idle:\t%.2f MB\n", float64(memStats.HeapIdle)/1024/1024)
			fmt.Printf("Heap Inuse:\t%.2f MB\n", float64(memStats.HeapInuse)/1024/1024)
			fmt.Printf("Heap Released:\t%.2f MB\n", float64(memStats.HeapReleased)/1024/1024)
			fmt.Printf("Stack Sys:\t%.2f MB\n", float64(memStats.StackSys)/1024/1024)
			fmt.Printf("======================\n")
		}
	}
}

func goPringStack() {
	// Start a timer that prints stack traces every 5 seconds
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Start a goroutine to simulate the program running continuously
	go func() {
		for {
			time.Sleep(1 * time.Second)
			// Simulate some work
		}
	}()

	// Main goroutine keeps printing stack traces
	for {
		select {
		case <-ticker.C:
			printStack()
		}
	}
}

func printStack() {
	// Get stack trace
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, true)
	// Formatted output
	fmt.Printf("========== Stack Trace (Length: %d) ==========\n", n)
	fmt.Printf("%s\n", buf)
	fmt.Printf("===========================================\n")
}
