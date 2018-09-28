// Copyright 2018 sshfp authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package sshfp

// Cache for DNS SSHFP entries
type Cache interface {
	Add(e ...*Entry) error
	Get(hostname string, algo ...Algorithm) (Entries, bool)
	Remove(e *Entry) error
}

// MemoryCache is a in-memory cache
type MemoryCache struct {
	c map[string]Entries
}

// NewMemoryCache creates a new in-memory cache
func NewMemoryCache() (*MemoryCache, error) {
	return &MemoryCache{c: make(map[string]Entries)}, nil
}

func (mc *MemoryCache) add(hostname string, e *Entry) {
	entries, ok := mc.c[hostname]
	if !ok {
		entries = Entries{}
		mc.c[hostname] = entries
	}
	mc.c[hostname] = append(mc.c[hostname], e)
}

// Add entry to the cache
func (mc *MemoryCache) Add(e ...*Entry) error {
	for _, entry := range e {
		mc.add(entry.Hostname, entry)
	}
	return nil
}

// Get entries from the cache
func (mc *MemoryCache) Get(hostname string, algo ...Algorithm) (Entries, bool) {
	entries, ok := mc.c[hostname]
	if len(algo) == 1 {
		algorithm := uint8(algo[0])
		fentries := Entries{}
		for _, entry := range entries {
			if entry.Algorithm != algorithm {
				continue
			}
			fentries = append(fentries, entry)
		}
		entries = fentries
	}
	return entries, ok
}

// Remove entry from the cache
func (mc *MemoryCache) Remove(e *Entry) error {
	return nil
}
