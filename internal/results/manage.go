// results-------------------------------------
// @file      : manage.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/17 20:59
// -------------------------------------------

package results

import (
	"time"
)

const (
	batchSize     = 60
	flushInterval = 30 * time.Second
)

type ResultQueue struct {
	Queue   chan interface{}
	CloseCh chan struct{}
}

var ResultQueues = make(map[string]*ResultQueue)

func InitializeResultQueue() {
	// Module list
	modules := []string{
		"SubdomainScan", "SubdomainSecurity",
		"AssetChangeLog", "URLScan",
		"WebCrawler", "VulnerabilityScan",
		"SensitiveResult", "DirScan", "PageMonitoring", "PageMonitoringBody", "SensitiveBody", "RootDomain", "APP", "MP",
	}
	// Initialize module queues and Goroutine
	for _, module := range modules {
		if module == "PageMonitoringUrl" {
			ResultQueues[module] = &ResultQueue{
				Queue:   make(chan interface{}, 3000),
				CloseCh: make(chan struct{}),
			}
		} else if module == "URLScan" {
			ResultQueues[module] = &ResultQueue{
				Queue:   make(chan interface{}, 3000),
				CloseCh: make(chan struct{}),
			}
		} else if module == "SensitiveResult" {
			ResultQueues[module] = &ResultQueue{
				Queue:   make(chan interface{}, 3000),
				CloseCh: make(chan struct{}),
			}
		} else if module == "SensitiveBody" {
			ResultQueues[module] = &ResultQueue{
				Queue:   make(chan interface{}, 15),
				CloseCh: make(chan struct{}),
			}
		} else {
			ResultQueues[module] = &ResultQueue{
				Queue:   make(chan interface{}, batchSize),
				CloseCh: make(chan struct{}),
			}
		}

		go processQueue(module, ResultQueues[module])
	}

	// Initialize deduplication module
	InitializeDuplicate()
	// Initialize result handling module
	InitializeHandler()
	// Initialize result insertion module
	InitializeResults()
}

func processQueue(module string, mq *ResultQueue) {
	ticker := time.NewTicker(flushInterval)
	if module == "URLScan" {
		ticker = time.NewTicker(60 * time.Second)
	}
	defer ticker.Stop()

	var buffer []interface{}

	for {
		select {
		case batch := <-mq.Queue:
			if batch != nil {
				buffer = append(buffer, batch)
				if len(buffer) >= batchSize-2 {
					flushBuffer(module, &buffer)
				}
			}
		case <-ticker.C:
			if len(buffer) > 0 {
				flushBuffer(module, &buffer)
			}
		case <-mq.CloseCh:
			// Handle shutdown signal
			if len(buffer) > 0 {
				flushBuffer(module, &buffer)
			}
			return
		}
	}
}

func flushBuffer(module string, buffer *[]interface{}) {
	if len(*buffer) == 0 {
		return
	}
	var name string
	if module == "SensitiveBody" {
		Results.Update(buffer, "SensitiveBody")
	} else if module == "RootDomain" {
		Results.Update(buffer, "RootDomain")
	} else if module == "VulnerabilityScan" {
		Results.InsertVulnerabilityScan(buffer)
	} else {
		switch module {
		case "SubdomainScan":
			name = "subdomain"
		case "SubdomainSecurity":
			name = "SubdomainTakerResult"
		case "AssetChangeLog":
			name = "AssetChangeLog"
		case "URLScan":
			name = "UrlScan"
		case "SensitiveResult":
			name = "SensitiveResult"
		case "WebCrawler":
			name = "crawler"
		case "DirScan":
			name = "DirScanResult"
		case "PageMonitoring":
			name = "PageMonitoring"
		case "PageMonitoringBody":
			name = "PageMonitoringBody"
		case "APP":
			name = "app"
		case "MP":
			name = "mp"
		}
		Results.Insert(name, buffer)
	}
	*buffer = nil
}

func Close() {
	for _, mq := range ResultQueues {
		close(mq.Queue)   // Close queue
		close(mq.CloseCh) // Send shutdown signal
	}
}
