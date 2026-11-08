// main-------------------------------------
// @file      : testSens.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/7/28 18:17
// -------------------------------------------

package main

import (
	"context"
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
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/urlsecurity/trufflehog"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils"
	"net/url"
	"path"
	"path/filepath"
	"time"
)

func main() {
	DebugInit()
	plg := trufflehog.NewPlugin()
	plg.Install()
	//data, _ := os.ReadFile("C:\\Users\\autumn\\Desktop\\PushSdk-8.3.68.0 (1).zip")
	//input := types.UrlResult{
	//	Output: "httpx://test.com",
	//	Body:   string(data),
	//	Status: 200,
	//}
	//plg.Execute(input)

	resultChan := make(chan string, 100)
	go func() {
		err := utils.Tools.ReadFileLineReader("C:\\Users\\autumn\\AppData\\Local\\JetBrains\\GoLand2023.3\\tmp\\GoLand\\ext\\katana\\NlxJtbZYo3wwIrW9", resultChan, context.Background())
		if err != nil {
			logger.SlogErrorLocal(fmt.Sprintf("ReadFileLineReader %v", err))
		}
	}()
	time.Sleep(2 * time.Second)
	var katanaResult types.KatanaResult
	for result := range resultChan {
		err := json.Unmarshal([]byte(result), &katanaResult)
		if err != nil {
			continue
		}
		var r types.UrlResult
		parsedURL, err := url.Parse(katanaResult.Request.URL)
		urlPath := ""
		if err != nil {
			urlPath = katanaResult.Request.URL
		} else {
			urlPath = parsedURL.Path
		}
		r.Ext = path.Ext(urlPath)
		r.Ext = path.Ext(parsedURL.Path)
		r.Input = "http://dwasdwadwa"
		r.Source = katanaResult.Request.Source
		r.Output = katanaResult.Request.URL
		r.OutputType = katanaResult.Request.Attribute
		r.Status = katanaResult.Response.StatusCode
		r.Length = len(katanaResult.Response.Body)
		r.Body = katanaResult.Response.Body
		r.Time = utils.Tools.GetTimeNow()
		if err != nil {
		}
		plg.Execute(r)
	}

}

func DebugInit() {
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
	}
	// Initialize task counter
	handler.InitHandle()
	// Update configuration, load dictionaries
	configupdater.Initialize()
	// Initialize module configuration
	err = config.ModulesInitialize()
	if err != nil {
		return
	}
	// Initialize context manager
	contextmanager.NewContextManager()
	// Initialize tools
	utils.InitializeTools()
	utils.InitializeDnsTools()
	utils.InitializeRequests()
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
		return
	}
}
