// pebbledb-------------------------------------
// @file      : pebbledb.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/6 21:27
// -------------------------------------------

package pebbledb

import (
	"fmt"
	"github.com/cockroachdb/pebble"
)

type PebbleDB struct {
	db *pebble.DB
}

var PebbleStore *PebbleDB

// NewPebbleDB initialize PebbleDB instance
func NewPebbleDB(options *pebble.Options, dbPath string) (*PebbleDB, error) {
	db, err := pebble.Open(dbPath, options)
	if err != nil {
		return nil, err
	}
	return &PebbleDB{db: db}, nil
}

// Put store key-value pair in database
func (p *PebbleDB) Put(key, value []byte) error {
	return p.db.Set(key, value, pebble.Sync)
}

// Get get the value of the specified key from the database
func (p *PebbleDB) Get(key []byte) ([]byte, error) {
	value, closer, err := p.db.Get(key)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	return value, nil
}

// Delete delete key from database
func (p *PebbleDB) Delete(key []byte) error {
	return p.db.Delete(key, pebble.Sync)
}

// Close close database connection
func (p *PebbleDB) Close() error {
	return p.db.Close()
}

// BatchWrite batch write key-value pairs
func (p *PebbleDB) BatchWrite(pairs map[string]string) error {
	batch := p.db.NewBatch()
	defer batch.Close()

	for key, value := range pairs {
		if err := batch.Set([]byte(key), []byte(value), nil); err != nil {
			return err
		}
	}

	if err := batch.Commit(pebble.Sync); err != nil {
		return err
	}

	return nil
}

// Compact force database compaction to free space
func (p *PebbleDB) Compact() error {
	start := []byte("")               // Compress from the beginning
	end := []byte("zzzzzzzzzzzzzzzz") // Until after the max key
	// Call the Compact method to compact
	return p.db.Compact(start, end, true)
}

func (p *PebbleDB) GetKeysWithPrefix(prefix string) (map[string][]byte, error) {
	result := make(map[string][]byte)

	// Create iterator and set range
	lowerBound := []byte(prefix)          // Set lower bound to the specified prefix
	upperBound := []byte(prefix + "\xff") // Set upper bound to the specified prefix plus one character

	iter, _ := p.db.NewIter(&pebble.IterOptions{
		LowerBound: lowerBound,
		UpperBound: upperBound,
	})
	defer func(iter *pebble.Iterator) {
		err := iter.Close()
		if err != nil {
			fmt.Printf("GetKeysWithPrefix error: %v", err)
		}
	}(iter) // Ensure the iterator is closed when the function ends

	// Iterate over all matching keys
	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		value := iter.Value()
		result[string(key)] = value
	}

	if err := iter.Error(); err != nil {
		return nil, err
	}

	return result, nil
}
