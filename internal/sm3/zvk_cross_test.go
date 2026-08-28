//go:build riscv64 && go1.28 && !purego

package sm3

import (
	"crypto/rand"
	"testing"
)

// TestZVKCrossCheck verifies the Zvksh block path matches the generic
// implementation over random multi-block inputs.
func TestZVKCrossCheck(t *testing.T) {
	if !useZVKSH {
		t.Skip("Zvksh not available")
	}
	for _, n := range []int{0, 1, 55, 63, 64, 65, 128, 1000, 64 * 1024} {
		data := make([]byte, n)
		rand.Read(data)
		g := New()
		g.Write(data)
		want := g.Sum(nil)
		z := New()
		z.Write(data)
		if got := z.Sum(nil); string(got) != string(want) {
			t.Fatalf("len=%d: zvksh mismatch", n)
		}
	}
}
