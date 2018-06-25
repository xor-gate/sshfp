package sshfp

import (
	"fmt"
)

type Cache interface {
	Set(e *Entry)
	Get(hostname string) (*Entry, bool)
}

type MemoryCache struct {
	c map[string]*Entry
}

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{c: make(map[string]*Entry)}
}

func (mc *MemoryCache) Set(e *Entry) {
	mc.c[e.Hostname] = e
	fmt.Println("Set", e)
}

func (mc *MemoryCache) Get(hostname string) (*Entry, bool) {
	e, ok := mc.c[hostname]
	fmt.Println("Get", e)
	return e, ok
}
