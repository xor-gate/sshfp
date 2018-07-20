package sshfp

import (
	"fmt"

	"github.com/hashicorp/golang-lru"
)

// Cache for DNS SSHFP entries
type Cache interface {
	Add(e ...*Entry)
	Get(hostname string) (*Entry, bool)
	Remove(e *Entry)
}

// MemoryCache is a fixed with LRU cache
type MemoryCache struct {
	c *lru.Cache
}

// NewMemoryCache creates a new fixed with LRU cache of size
func NewMemoryCache(size int) (*MemoryCache, error) {
	c, err := lru.New(size)
	if err != nil {
		return nil, err
	}
	return &MemoryCache{c: c}, nil
}

// Add entry to the cache. When the entry property ExpiresAt is zero it never is evicted from the cache.
func (mc *MemoryCache) Add(e ...*Entry) {
	for _, entry := range e {
		fmt.Println("Add", entry.Hostname, entry)
		_ = mc.c.Add(entry.Hostname, entry)
	}
}

// Get entry from the cache
func (mc *MemoryCache) Get(hostname string) (*Entry, bool) {
	ce, ok := mc.c.Get(hostname)
	fmt.Println("Get", hostname, ce, ok)
	if !ok {
		return nil, false
	}

	e, ok := ce.(*Entry)
	return e, ok
}

// Remove entry from the cache
func (mc *MemoryCache) Remove(e *Entry) {
	mc.c.Remove(e)
}
