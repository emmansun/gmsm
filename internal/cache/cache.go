// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cache provides a weak map that associates the lifetime of
// values with the lifetime of keys.
package cache

import (
	"runtime"
	"sync"
	"weak"
)

type Cache[K, V any] struct {
	m sync.Map
}

// Get returns the result of new, for an associated key k.
//
// If Get was called with k before and didn't return an error, Get may return
// the same value it returned from the previous call if check returns true on
// it. If check returns false, Get will call new again and return the result.
//
// The cache is evicted some time after k becomes unreachable.
func (c *Cache[K, V]) Get(k *K, new func() (*V, error), check func(*V) bool) (*V, error) {
	p := weak.Make(k)
	if cached, ok := c.m.Load(p); ok {
		v := cached.(*V)
		if check(v) {
			return v, nil
		}
	}
	v, err := new()
	if err != nil {
		return nil, err
	}
	if _, present := c.m.Swap(p, v); !present {
		runtime.AddCleanup(k, c.evict, p)
	}
	return v, nil
}

func (c *Cache[K, V]) evict(p weak.Pointer[K]) {
	c.m.Delete(p)
}
