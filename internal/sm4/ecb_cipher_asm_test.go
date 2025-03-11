package sm4

import (
	"testing"

	"github.com/emmansun/gmsm/cipher"
)

func TestECBValidate(t *testing.T) {
	key := make([]byte, 16)
	src := make([]byte, 32)
	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	decrypter := cipher.NewECBDecrypter(c)
	// test len(src) == 0
	decrypter.CryptBlocks(nil, nil)

	// cipher: input not full blocks
	shouldPanic(t, func() {
		decrypter.CryptBlocks(src, src[1:])
	})
	// cipher: output smaller than input
	shouldPanic(t, func() {
		decrypter.CryptBlocks(src[1:], src)
	})
	// cipher: invalid buffer overlap
	shouldPanic(t, func() {
		decrypter.CryptBlocks(src[1:17], src[2:18])
	})
}
