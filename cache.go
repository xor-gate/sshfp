package sshfp

import (
	"fmt"
	"time"

	"github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
)

// Entry is
type Entry struct {
	*dns.SSHFP
	ExpiresAt   time.Time
	Hostname    string
	Fingerprint []byte
}

// Cache for DNS SSHFP entries
type Cache interface {
	Add(e *Entry)
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

// Add entry to the cache
func (mc *MemoryCache) Add(e *Entry) {
	_ = mc.c.Add(e.Hostname, e)
	fmt.Println("Set", e)
}

// Get entry from the cache
func (mc *MemoryCache) Get(hostname string) (*Entry, bool) {
	ce, ok := mc.c.Get(hostname)
	e, ok := ce.(*Entry)
	fmt.Println("Get", e)
	return e, ok
}

// Remove entry from the cache
func (mc *MemoryCache) Remove(e *Entry) {
	mc.c.Remove(e)
}
