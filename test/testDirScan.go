// main-------------------------------------
// @file      : testDirScan.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/4/10 23:29
// -------------------------------------------

package main

//
//import (
//	"fmt"
//	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
//	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/dirScanMode/core"
//	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/dirScanMode/runner"
//	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/system"
//	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/util"
//	"net/http"
//	_ "net/http/pprof"
//	"path/filepath"
//)
//
//func main() {
//	//dirScanMode.GETRequest("https://hackerone.com")
//	// Open file
//	//if err != nil {
//	//}
//	//defer file.Close()
//	//
//	//// Create Scanner object
//	//scanner := bufio.NewScanner(file)
//	//var urls []string
//	//
//	//// Read file content line by line
//	//for scanner.Scan() {
//	//	line := scanner.Text()
//	//	// Store each line in an array
//	//	urls = append(urls, ""+line)
//	//}
//	//
//	//start := time.Now()
//	//fmt.Println(start)
//	//for _, url := range urls {
//	//	code := dirScanMode.GETRequest(url)
//	//	fmt.Printf("%s ---> %d\n", url, code)
//	//}
//	//end := time.Now()
//	//fmt.Println(end)
//	//duration := end.Sub(start)
//	//fmt.Println("Program uptime:", duration)
//	//util.DoGet("http://test:666/a.php")
//	go func() {
//		_ = http.ListenAndServe("0.0.0.0:6060", nil)
//	}()
//	system.Test()
//	system.UpdateDirDicConfig()
//	fmt.Println(system.GetTimeNow())
//	util.InitHttpClient()
//	dirDicConfigPath := filepath.Join(system.ConfigDir, "dirdict")
//	controller := runner.Controller{Targets: []string{"https://giftcards.abercrombie.com"}, Dictionary: dirDicConfigPath}
//	op := core.Options{Extensions: []string{"php", "aspx", "jsp", "html", "js"}, Thread: 100, MatchCallback: func(response types.HttpResponse) {
//		fmt.Printf("%v - %v - %v\n", response.Url, response.StatusCode, response.ContentLength)
//	}}
//	controller.Run(op)
//	fmt.Println(system.GetTimeNow())
//}
