package xts

import (
	"crypto/aes"
	"testing"
)

func BenchmarkDoubleTweak(b *testing.B) {
	var tweak [16]byte
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Failed()
	}
	block.Encrypt(tweak[:], tweak[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mul2(&tweak, false)
	}
}
