// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package diff

import "testing"

// WithValue sets *target to value and restores the previous value through
// Cleanup. Inside a Suite Run closure, restoration happens at the end of
// that execution; outside a Suite, it happens when the test finishes.
//
// Tests that mutate global dispatch state must not use t.Parallel or
// concurrent goroutines. Accelerated paths must be checked for availability
// before they are enabled, including in fuzz callbacks.
func WithValue[T any](t testing.TB, target *T, value T) {
	old := *target
	*target = value
	t.Cleanup(func() { *target = old })
}
