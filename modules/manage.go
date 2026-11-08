// modules-------------------------------------
// @file      : manage.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/10 21:51
// -------------------------------------------

package modules

import (
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/interfaces"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/options"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/assethandle"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/assetmapping"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/dirscan"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/portfingerprint"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/portscan"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/portscanpreparation"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/subdomainscan"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/subdomainsecurity"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/targethandler"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/urlscan"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/urlsecurity"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/vulnerabilityscan"
	"github.com/ZhurnFaith/ScopeSentry-Scan/modules/webcrawler"
)

func CreateScanProcess(op *options.TaskOptions) interfaces.ModuleRunner {
	// Initialize InputChan
	op.InputChan = make(map[string]chan interface{})

	// Vulnerability scan module
	op.ModuleRunWg.Add(1)
	vulnerabilityModule := vulnerabilityscan.NewRunner(op, nil)
	vulnerabilityInputChan := make(chan interface{}, 1000)
	vulnerabilityModule.SetInput(vulnerabilityInputChan)
	op.InputChan["Vulnerability"] = vulnerabilityInputChan

	// Directory scan module
	op.ModuleRunWg.Add(1)
	dirScanModule := dirscan.NewRunner(op, vulnerabilityModule)
	dirScanInputChan := make(chan interface{}, 1000)
	dirScanModule.SetInput(dirScanInputChan)
	op.InputChan["DirScan"] = dirScanInputChan

	// url security module
	op.ModuleRunWg.Add(1)
	urlSecurityModule := urlsecurity.NewRunner(op, dirScanModule)
	urlSecurityInputChan := make(chan interface{}, 1000)
	urlSecurityModule.SetInput(urlSecurityInputChan)
	op.InputChan["UrlSecurity"] = urlSecurityInputChan

	// Crawler module
	op.ModuleRunWg.Add(1)
	webCrawlerModule := webcrawler.NewRunner(op, urlSecurityModule)
	WebCrawlerInputChan := make(chan interface{}, 1000)
	webCrawlerModule.SetInput(WebCrawlerInputChan)
	op.InputChan["WebCrawler"] = WebCrawlerInputChan

	// url scan module
	op.ModuleRunWg.Add(1)
	urlScanModule := urlscan.NewRunner(op, webCrawlerModule)
	urlScanInputChan := make(chan interface{}, 1000)
	urlScanModule.SetInput(urlScanInputChan)
	op.InputChan["UrlScan"] = urlScanInputChan

	// Asset handling module
	op.ModuleRunWg.Add(1)
	assetHandleModule := assethandle.NewRunner(op, urlScanModule)
	assetHandleInputChan := make(chan interface{}, 500)
	assetHandleModule.SetInput(assetHandleInputChan)
	op.InputChan["AssetHandle"] = assetHandleInputChan

	// Asset mapping module
	op.ModuleRunWg.Add(1)
	assetMappingModule := assetmapping.NewRunner(op, assetHandleModule)
	assetMappingInputChan := make(chan interface{}, 500)
	assetMappingModule.SetInput(assetMappingInputChan)
	op.InputChan["AssetMapping"] = assetMappingInputChan

	// Port fingerprinting module
	op.ModuleRunWg.Add(1)
	portFingerprintModule := portfingerprint.NewRunner(op, assetMappingModule)
	portFingerprintInputChan := make(chan interface{}, 500)
	portFingerprintModule.SetInput(portFingerprintInputChan)
	op.InputChan["PortFingerprint"] = portFingerprintInputChan

	// Port scan module
	op.ModuleRunWg.Add(1)
	portScanModule := portscan.NewRunner(op, portFingerprintModule)
	portScanInputChan := make(chan interface{}, 500)
	portScanModule.SetInput(portScanInputChan)
	op.InputChan["PortScan"] = portScanInputChan

	// Port scan preprocessing module
	op.ModuleRunWg.Add(1)
	portScanPreparationModule := portscanpreparation.NewRunner(op, portScanModule)
	portScanPreparationInputChan := make(chan interface{}, 500)
	portScanPreparationModule.SetInput(portScanPreparationInputChan)
	op.InputChan["PortScanPreparation"] = portScanPreparationInputChan

	// Subdomain security module
	op.ModuleRunWg.Add(1)
	subdomainSecurityModule := subdomainsecurity.NewRunner(op, portScanPreparationModule)
	subdomainSecurityInputChan := make(chan interface{}, 500)
	subdomainSecurityModule.SetInput(subdomainSecurityInputChan)
	op.InputChan["SubdomainSecurity"] = subdomainSecurityInputChan

	// Subdomain scan module
	op.ModuleRunWg.Add(1)
	subdomainScanModule := subdomainscan.NewRunner(op, subdomainSecurityModule)
	subdomainScanInputChan := make(chan interface{}, 100)
	subdomainScanModule.SetInput(subdomainScanInputChan)
	op.InputChan["SubdomainScan"] = subdomainScanInputChan

	// Target handling module
	op.ModuleRunWg.Add(1)
	targetHandlerModule := targethandler.NewRunner(op, subdomainScanModule)
	return targetHandlerModule
}
