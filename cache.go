// Copyright 2018 sshfp authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package sshfp

import (
	"github.com/hashicorp/golang-lru"
)

// Cache for DNS SSHFP entries
type Cache interface {
	Add(e ...*Entry) error
	Get(hostname string) (*Entry, bool)
	Remove(e *Entry) error
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
func (mc *MemoryCache) Add(e ...*Entry) error {
	for _, entry := range e {
		_ = mc.c.Add(entry.Hostname, entry)
	}
	return nil
}

// Get entry from the cache
func (mc *MemoryCache) Get(hostname string) (*Entry, bool) {
	ce, ok := mc.c.Get(hostname)
	if !ok {
		return nil, false
	}

	e, ok := ce.(*Entry)
	return e, ok
}

// Remove entry from the cache
func (mc *MemoryCache) Remove(e *Entry) error {
	mc.c.Remove(e)
	return nil
}
