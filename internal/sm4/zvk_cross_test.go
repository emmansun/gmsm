//go:build riscv64 && go1.28 && !purego

package sm4

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestZVKCrossCheck verifies the Zvksed cipher (block, multi-block, key
// schedule) matches the generic implementation over random inputs.
func TestZVKCrossCheck(t *testing.T) {
	if !supportSM4 {
		t.Skip("Zvksed not available")
	}
	for _, n := range []int{1, 2, 3, 4, 5, 8, 9, 100} {
		key := make([]byte, 16)
		rand.Read(key)
		plain := make([]byte, n*BlockSize)
		rand.Read(plain)

		want, _ := newCipherGeneric(key)
		ct := make([]byte, len(plain))
		for i := 0; i < n; i++ {
			want.Encrypt(ct[i*16:], plain[i*16:])
		}

		got, _ := NewCipher(key)
		got2 := make([]byte, len(plain))
		if c, ok := got.(*sm4CipherAsm); ok {
			for off := 0; off < n; off += 4 {
				nb := min(4, n-off)
				if nb == 4 {
					c.EncryptBlocks(got2[off*16:], plain[off*16:])
				} else {
					for i := 0; i < nb; i++ {
						c.Encrypt(got2[(off+i)*16:], plain[(off+i)*16:])
					}
				}
			}
		} else {
			for i := 0; i < n; i++ {
				got.Encrypt(got2[i*16:], plain[i*16:])
			}
		}
		if !bytes.Equal(ct, got2) {
			t.Fatalf("n=%d: encrypt mismatch", n)
		}

		pt := make([]byte, len(plain))
		for i := 0; i < n; i++ {
			got.Decrypt(pt[i*16:], got2[i*16:])
		}
		if !bytes.Equal(plain, pt) {
			t.Fatalf("n=%d: decrypt roundtrip mismatch", n)
		}
	}
}
