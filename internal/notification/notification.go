// notification-------------------------------------
// @file      : notification.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/19 19:54
// -------------------------------------------

package notification

import (
	"encoding/json"
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/global"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils"
	"strings"
	"time"
)

const (
	batchSize     = 20
	flushInterval = 2 * time.Second // Take data from the queue every 2 seconds
)

type NotificationQueue struct {
	Queue chan string
}

var NotificationQueues = make(map[string]*NotificationQueue)

func InitializeNotification() {
	// Module list
	modules := []string{
		"SubdomainScan", "SubdomainSecurity",
		"AssetMapping", "PortScan", "URLScan",
		"URLSecurity", "DirScan", "WebCrawler", "VulnerabilityScan", "PageMonitor", "NewAssets",
	}
	// Initialize module queues and Goroutine
	for _, module := range modules {
		NotificationQueues[module] = &NotificationQueue{
			Queue: make(chan string, 50), // Cache queue size can be greater than batchSize
		}
		go processQueue(module, NotificationQueues[module])
	}
}

func processQueue(module string, mq *NotificationQueue) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		// Trigger processing logic every 2 seconds
		case <-ticker.C:
			processBatch(module, mq)
		}
	}
}

// processBatch take up to batchSize items from the queue for processing
func processBatch(module string, mq *NotificationQueue) {
	var buffer = ""
	num := 0
	// Try to take batchSize items, or all remaining items if fewer
	for i := 0; i < batchSize; i++ {
		select {
		case msg := <-mq.Queue:
			num += 1
			buffer += msg
		default:
			// If there is no more data in the queue, break the loop
			break
		}
	}

	if num > 0 {
		FlushBuffer(module, &buffer)
	}
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

// FlushBuffer simulate processing data in the queue
func FlushBuffer(module string, buffer *string) {
	*buffer = jsonEscape(*buffer)
	// Handle message
	*buffer = "[" + global.AppConfig.NodeName + "][" + module + "]results:\n" + *buffer
	for _, api := range global.NotificationApi {
		uri := strings.Replace(api.Url, "*msg*", *buffer, -1)
		if api.Method == "GET" {
			_, err := utils.Requests.HttpGet(uri)
			if err != nil {
				logger.SlogError(fmt.Sprintf("SendNotification %v HTTP Get Error: %v", uri, err))
			}
		} else {
			data := strings.Replace(api.Data, "*msg*", *buffer, -1)
			err, _ := utils.Requests.HttpPost(uri, []byte(data), api.ContentType)
			if err != nil {
				logger.SlogError(fmt.Sprintf("SendNotification %v HTTP Post Error: %v", uri, err))
			}
		}
	}
	// Clear buffer
	*buffer = ""
}
