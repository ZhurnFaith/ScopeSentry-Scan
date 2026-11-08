// bigcache-------------------------------------
// @file      : bigcache.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/18 20:18
// -------------------------------------------

package bigcache

import (
	"context"
	"github.com/allegro/bigcache/v3"
	"time"
)

// BigCacheWrapper BigCache wrapper implementation
type BigCacheWrapper struct {
	cache *bigcache.BigCache
}

var BigCache *BigCacheWrapper

// NewBigCacheWrapper create a BigCache instance
func Initialize() error {
	config := bigcache.Config{
		LifeWindow:       10 * 365 * 24 * time.Hour, // Long cache lifetime
		Shards:           1024,
		MaxEntrySize:     500, // Max size per cache entry
		HardMaxCacheSize: 100, // Max cache size 100 MB
		Verbose:          true,
		CleanWindow:      5 * time.Minute,
	}
	bigCache, err := bigcache.New(context.Background(), config)
	if err != nil {
		return err
	}
	BigCache = &BigCacheWrapper{cache: bigCache}
	return nil
}

// Set store data in cache
func (b *BigCacheWrapper) Set(key string, value []byte) error {
	return b.cache.Set(key, value)
}

// Get get data from cache
func (b *BigCacheWrapper) Get(key string) ([]byte, error) {
	return b.cache.Get(key)
}

// Delete delete data from cache
func (b *BigCacheWrapper) Delete(key string) error {
	return b.cache.Delete(key)
}
