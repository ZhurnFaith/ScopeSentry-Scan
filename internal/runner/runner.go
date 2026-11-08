// task-------------------------------------
// @file      : runner.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/9 21:47
// -------------------------------------------

package runner

import (
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/contextmanager"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/handler"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/options"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"
)

func Run(op options.TaskOptions) error {
	// Clear temporary files
	defer CleanTmp()
	var wg sync.WaitGroup
	var start time.Time
	var end time.Time
	start = time.Now()
	handler.TaskHandle.StartTask()
	handler.TaskHandle.ProgressStart("scan", op.Target, op.ID, 1)
	// Set PassiveScan's input
	op.ModuleRunWg = &wg
	switch op.Type {
	case "subdomainSource":
	case "assetSource":
	case "UrlScanSource":
	case "asset":
	case "subdomain":
	case "UrlScan":
	default:
		op.TargetHandler = append(op.TargetHandler, "7bbaec6487f51a9aafeff4720c7643f0")
	}
	process := modules.CreateScanProcess(&op)
	ch := make(chan interface{})
	process.SetInput(ch)
	go func() {
		err := process.ModuleRun()
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
	}()
	switch op.Type {
	case "subdomainSource", "subdomain":
		tmp := types.SubdomainResult{
			Type: "A",
			Host: op.Target,
		}
		op.InputChan["SubdomainSecurity"] <- tmp
	case "assetSource", "asset":
		var resultArray []interface{}
		scheme, domain, port, err := extractDomainAndPort(op.Target)
		if err != nil {
			logger.SlogError(fmt.Sprintf("task %v target %v scan type [%v] parse target error: %v", op.ID, op.Target, op.Type, err))
			break
		}
		tmp := types.AssetOther{
			Host:    domain,
			Port:    port,
			Service: scheme,
		}
		if strings.Contains(scheme, "http") {
			tmp.Type = "http"
		} else {
			tmp.Type = "other"
		}
		resultArray = append(resultArray, tmp)
		op.InputChan["AssetMapping"] <- resultArray
	case "UrlScanSource", "UrlScan":
		tmp := types.UrlResult{
			Output:   op.Target,
			ResultId: utils.Tools.CalculateMD5(op.Target),
		}
		op.InputChan["UrlSecurity"] <- tmp
	default:
		ch <- op.Target
	}
	close(ch)
	time.Sleep(10 * time.Second)
	wg.Wait()
	end = time.Now()
	duration := end.Sub(start)
	select {
	case <-contextmanager.GlobalContextManagers.GetContext(op.ID).Done():
		// Increment completed count
		handler.TaskHandle.EndTask()
		return fmt.Errorf("task Cancel")
	default:
		// Log module completion
		handler.TaskHandle.ProgressEnd("scan", op.Target, op.ID, 1, duration)
		// Record completion time and completed targets
		handler.TaskHandle.TaskEnd(op.Target, op.ID)
		// Increment completed count
		handler.TaskHandle.EndTask()
		return nil
	}
}

func extractDomainAndPort(inputURL string) (string, string, string, error) {
	// Parse URL
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return "", "", "", err
	}

	// Extract domain
	domain := parsedURL.Hostname()

	// Extract port, empty string means no port
	port := parsedURL.Port()

	// If no port is specified, return the default
	if port == "" {
		// Check the URL scheme; the common http default port is 80, https default port is 443
		switch parsedURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	return parsedURL.Scheme, domain, port, nil
}

func CleanTmp() {
	osType := runtime.GOOS
	if osType == "windows" {
		// Windows system handling
		//handleWindowsTemp()
	} else if osType == "linux" {
		// Linux system handling
		utils.Tools.HandleLinuxTemp()
	}
}

//func handleWindowsTemp() {
//	// Get current username
//	currentUser, err := user.Current()
//	if err != nil {
//		return
//	}
//	tempDir := fmt.Sprintf(`C:\Users\%s\AppData\Local\Temp`, currentUser.Username)
//
//	// Define PowerShell command
//	psCmd := fmt.Sprintf(`
//Get-ChildItem -Path "%s" -Directory |
//Where-Object {
//    ($_.Name -match '^\d{9}$') -or
//    ($_.Name -like 'ScopeSentry*') -or
//    ($_.Name -like '.org.chromium.Chromium*') -or
//    ($_.Name -like '*_badger') -or
//	($_.Name -like 'nuclei*') -or
//	($_.Name -like 'rod*')
//} |
//Remove-Item -Recurse -Force
//`, tempDir)
//
//	// Run PowerShell command
//	cmd := exec.Command("powershell", "-Command", psCmd)
//	_, err = cmd.CombinedOutput()
//	if err != nil {
//		fmt.Printf("Error running the PowerShell command: %v\n", err)
//		logger.SlogWarn("Clear temporary files C:\\Users\\{username}\\AppData\\Local\\Temp\\[^\\d{9}$, ScopeSentry*, .org.chromium.Chromium*, *_badger] failed, please clear them manually to avoid filling the disk,")
//		return
//	}
//}
