package cipher_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/sm4"
)

var ecbSM4Tests = []struct {
	name string
	key  []byte
	in   []byte
}{
	{
		"1 block",
		[]byte("0123456789ABCDEF"),
		[]byte("exampleplaintext"),
	},
	{
		"2 same blocks",
		[]byte("0123456789ABCDEF"),
		[]byte("exampleplaintextexampleplaintext"),
	},
	{
		"2 different blocks",
		[]byte("0123456789ABCDEF"),
		[]byte("exampleplaintextfedcba9876543210"),
	},
	{
		"3 same blocks",
		[]byte("0123456789ABCDEF"),
		[]byte("exampleplaintextexampleplaintextexampleplaintext"),
	},
	{
		"4 same blocks",
		[]byte("0123456789ABCDEF"),
		[]byte("exampleplaintextexampleplaintextexampleplaintextexampleplaintext"),
	},
	{
		"5 same blocks",
		[]byte("0123456789ABCDEF"),
		[]byte("exampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintext"),
	},
	{
		"6 same blocks",
		[]byte("0123456789ABCDEF"),
		[]byte("exampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintext"),
	},
	{
		"7 same blocks",
		[]byte("0123456789ABCDEF"),
		[]byte("exampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintext"),
	},
	{
		"8 same blocks",
		[]byte("0123456789ABCDEF"),
		[]byte("exampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintext"),
	},
	{
		"9 same blocks",
		[]byte("0123456789ABCDEF"),
		[]byte("exampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintext"),
	},
	{
		"18 same blocks",
		[]byte("0123456789ABCDEF"),
		[]byte("exampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintextexampleplaintext"),
	},
}

func TestECBBasic(t *testing.T) {
	for _, test := range ecbSM4Tests {
		c, err := sm4.NewCipher(test.key)
		if err != nil {
			t.Errorf("%s: NewCipher(%d bytes) = %s", test.name, len(test.key), err)
			continue
		}
		encrypter := cipher.NewECBEncrypter(c)
		ciphertext := make([]byte, len(test.in))
		encrypter.CryptBlocks(ciphertext, test.in)

		plaintext := make([]byte, len(test.in))
		decrypter := cipher.NewECBDecrypter(c)
		decrypter.CryptBlocks(plaintext, ciphertext)
		if !bytes.Equal(test.in, plaintext) {
			t.Errorf("%s: ECB encrypt/decrypt failed, %s", test.name, string(plaintext))
		}
	}
}

func TestECBRandom(t *testing.T) {
	key := []byte("0123456789ABCDEF")
	plaintext := make([]byte, 464)
	ciphertext := make([]byte, 464)
	io.ReadFull(rand.Reader, plaintext)
	c, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	encrypter := cipher.NewECBEncrypter(c)
	encrypter.CryptBlocks(ciphertext, plaintext)
	result := make([]byte, 464)
	decrypter := cipher.NewECBDecrypter(c)
	decrypter.CryptBlocks(result, ciphertext)
	if !bytes.Equal(result, plaintext) {
		t.Error("ECB encrypt/decrypt failed")
	}
}

func shouldPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() { _ = recover() }()
	f()
	t.Errorf("should have panicked")
}

func TestECBValidate(t *testing.T) {
	key := make([]byte, 16)
	src := make([]byte, 32)
	c, err := sm4.NewCipher(key)
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
