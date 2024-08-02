//go:build (amd64 || arm64) && !purego

package sm4

import (
	"crypto/cipher"
	"testing"
)

// cbcMode is an interface for block ciphers using cipher block chaining.
type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

func TestSetIV(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	decrypter := cipher.NewCBCDecrypter(c, iv)
	cbc, ok := decrypter.(cbcMode)
	if !ok {
		t.Fatalf("it's not cbc")
	}
	shouldPanic(t, func() {
		cbc.SetIV(iv[1:])
	})
	cbc.SetIV(iv[:])
}

func TestCryptBlocks(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	src := make([]byte, 32)
	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	decrypter := cipher.NewCBCDecrypter(c, iv)
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
