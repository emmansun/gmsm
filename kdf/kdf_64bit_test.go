//go:build !(arm || mips || s390x)

package kdf

import (
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

// TestKdfPanic tests that Kdf panics when keyLen is too large
func TestKdfPanic(t *testing.T) {
	// Test with a key length that would require >= 2^32-1 iterations
	maxIterations := (1 << 32) - 1
	tooLargeKeyLen := maxIterations * 32 // Assuming 32-byte hash output

	shouldPanic(t, func() {
		Kdf(sm3.New, []byte("test"), tooLargeKeyLen)
	})
}
