// main-------------------------------------
// @file      : testEhole.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/11/30 17:24
// -------------------------------------------

package main

import (
	"encoding/json"
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/bigcache"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/config"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/configupdater"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/contextmanager"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/global"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/handler"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/mongodb"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/notification"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/pebbledb"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/plugins"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/pool"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/redis"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/results"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

func main() {
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
	var assetsList []types.AssetHttp
	// Open file
	file, err := os.Open("ScopeSentry.asset.json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Read file content
	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}
	// Parse JSON data into struct
	err = json.Unmarshal(byteValue, &assetsList)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(assetsList))
	plg, _ := plugins.GlobalPluginManager.GetPlugin("AssetHandle", "4fb56e0137e9fda3e9c76e9446868fbb")
	plg.SetParameter("-finger 674ac1d1f11d1fdbe5dd6f01 -thread 30")
	for _, as := range assetsList {
		//fmt.Printf("%v", as)
		plg.Execute(&as)
	}
}
