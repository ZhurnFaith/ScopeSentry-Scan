// utils-------------------------------------
// @file      : semaphore.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2025/4/12 21:33
// -------------------------------------------

package utils

import (
	"golang.org/x/sync/semaphore"
	"sync"
)

var SemaphoreDict = make(map[string]*semaphore.Weighted)
var Mutex sync.Mutex

func GetSemaphore(tp string, limit int64) *semaphore.Weighted {
	Mutex.Lock()
	defer Mutex.Unlock()

	// If the map already has a semaphore for this tp, return it
	if sem, exists := SemaphoreDict[tp]; exists {
		return sem
	}

	// Otherwise create a new semaphore
	sem := semaphore.NewWeighted(limit)

	// Add the newly created semaphore to the map
	SemaphoreDict[tp] = sem
	return sem
}
