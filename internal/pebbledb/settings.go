// pebbledb-------------------------------------
// @file      : settings.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/6 21:30
// -------------------------------------------

package pebbledb

import (
	"github.com/cockroachdb/pebble"
)

// Settings configuration for PebbleDB
type Settings struct {
	DBPath       string
	CacheSize    int64 // Cache size
	MaxOpenFiles int   // Max open files
}

// GetPebbleOptions generate from Settings pebble.Options
func GetPebbleOptions(settings *Settings) *pebble.Options {
	return &pebble.Options{
		Cache:         pebble.NewCache(settings.CacheSize),
		MaxOpenFiles:  settings.MaxOpenFiles,
		LBaseMaxBytes: 64 << 20, // 64MB
		Levels: []pebble.LevelOptions{
			{Compression: pebble.NoCompression, TargetFileSize: 2 << 20}, // 2MB target file size
		},
	}
}
