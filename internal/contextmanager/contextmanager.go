// contextmanager-------------------------------------
// @file      : contextmanager.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/11/7 21:29
// -------------------------------------------

package contextmanager

import (
	"context"
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"sync"
)

// ContextManager struct managing multiple contexts
type ContextManager struct {
	mu         sync.Mutex
	contexts   map[string]context.Context    // Store context
	cancels    map[string]context.CancelFunc // Store cancel function
	waitGroups map[string]*sync.WaitGroup    // Store per task WaitGroup
}

// Global map to store all ContextManagers by their IDs
var GlobalContextManagers *ContextManager

// NewContextManager create a new context manager
func NewContextManager() {
	GlobalContextManagers = &ContextManager{
		contexts:   make(map[string]context.Context),
		cancels:    make(map[string]context.CancelFunc),
		waitGroups: make(map[string]*sync.WaitGroup),
	}
}

// AddContext create and add a new context
func (cm *ContextManager) AddContext(taskID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// If taskID already exists, skip adding
	if _, exists := cm.contexts[taskID]; exists {
		// You can return directly here or run other handling logic
		return
	}
	// Create a new context and its cancel function
	ctx, cancel := context.WithCancel(context.Background())

	// Add to manager
	cm.contexts[taskID] = ctx
	cm.cancels[taskID] = cancel
	cm.waitGroups[taskID] = &sync.WaitGroup{}
}

// CancelContext cancel context of the specified task
func (cm *ContextManager) CancelContext(taskID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cancel, ok := cm.cancels[taskID]; ok {
		cancel()
		logger.SlogInfo(fmt.Sprintf("stop task success: %v", taskID))
	}
}

// CancelAllContexts cancel all contexts
func (cm *ContextManager) CancelAllContexts() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for _, cancel := range cm.cancels {
		cancel()
	}
}

// WaitForAll wait for all context-related tasks to complete
func (cm *ContextManager) WaitForAll() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var wg sync.WaitGroup
	for _, wgItem := range cm.waitGroups {
		wg.Add(1)
		go func(wgItem *sync.WaitGroup) {
			defer wg.Done()
			wgItem.Wait()
		}(wgItem)
	}
	wg.Wait()
}

// DeleteContext delete context of the specified task
func (cm *ContextManager) DeleteContext(taskID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Delete context, cancel function and WaitGroup
	if _, ok := cm.contexts[taskID]; ok {
		delete(cm.contexts, taskID)
		delete(cm.cancels, taskID)
		delete(cm.waitGroups, taskID)
		logger.SlogInfoLocal(fmt.Sprintf("Context %s deleted\n", taskID))
	} else {
		logger.SlogInfoLocal(fmt.Sprintf("Context %s not found\n", taskID))
	}
}

// GetContext get context of the specified task
func (cm *ContextManager) GetContext(taskID string) context.Context {
	// Acquire lock to protect context reads
	cm.mu.Lock()
	ctx, exists := cm.contexts[taskID]
	cm.mu.Unlock()

	// If the context does not exist, it needs to be created
	if !exists {
		// Do not call this while holding the lock when creating and adding a context AddContext
		cm.AddContext(taskID)
		// Acquire the lock again to get the newly created context
		cm.mu.Lock()
		ctx = cm.contexts[taskID]
		cm.mu.Unlock()
	}
	return ctx
}
