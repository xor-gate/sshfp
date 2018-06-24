package sshfp

import (
	"fmt"
)

type Cache interface {
	Set()
	Get()
}

type MemoryCache struct {
}

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{}
}

func (mc *MemoryCache) Set() {
	fmt.Println("mc Set")
}

func (mc *MemoryCache) Get() {
	fmt.Println("mc Get")
}
