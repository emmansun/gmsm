// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	internalsm4 "github.com/emmansun/gmsm/internal/sm4"
)

type testCapAEAD struct{}

func (testCapAEAD) NonceSize() int { return 12 }
func (testCapAEAD) Overhead() int  { return 16 }
func (testCapAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return append(dst, plaintext...)
}
func (testCapAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return append(dst, ciphertext...), nil
}

type testCapBlock struct{}

func (testCapBlock) BlockSize() int { return 16 }
func (testCapBlock) Encrypt(dst, src []byte) {
	copy(dst, src)
}
func (testCapBlock) Decrypt(dst, src []byte) {
	copy(dst, src)
}
func (testCapBlock) NewGCMSIV(newBlock func([]byte) (cipher.Block, error), key []byte) (cipher.AEAD, error) {
	return testCapAEAD{}, nil
}

type noCTRCapBlock struct{ cipher.Block }

func TestGCMSIVCapabilityDispatch(t *testing.T) {
	aead, err := NewGCMSIV(func(key []byte) (cipher.Block, error) {
		return testCapBlock{}, nil
	}, make([]byte, 16))
	if err != nil {
		t.Fatalf("NewGCMSIV failed: %v", err)
	}
	if _, ok := aead.(testCapAEAD); !ok {
		t.Fatal("expected capability-provided AEAD implementation")
	}
}

func BenchmarkGCMSIV_SealOpen1K(b *testing.B) {
	key := make([]byte, 16)
	key[0] = 1
	aad := make([]byte, 20)
	plaintext := make([]byte, 1024)

	aead, err := NewGCMSIV(aes.NewCipher, key)
	if err != nil {
		b.Fatalf("NewGCMSIV failed: %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var nonce [12]byte
		binary.LittleEndian.PutUint64(nonce[4:], uint64(i))

		ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
		if _, err := aead.Open(nil, nonce[:], ciphertext, aad); err != nil {
			b.Fatalf("Open failed: %v", err)
		}
	}
}

func BenchmarkGCMSIV_SM4_SealOpen1K(b *testing.B) {
	benchmarkGCMSIVSealOpen1KWithBlock(b, internalsm4.NewCipher)
}

func BenchmarkGCMSIV_SM4_Fallback_SealOpen1K(b *testing.B) {
	benchmarkGCMSIVSealOpen1KWithBlock(b, func(key []byte) (cipher.Block, error) {
		base, err := internalsm4.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return noCTRCapBlock{Block: base}, nil
	})
}

func benchmarkGCMSIVSealOpen1KWithBlock(b *testing.B, newBlock func([]byte) (cipher.Block, error)) {
	key := make([]byte, 16)
	key[0] = 1
	aad := make([]byte, 20)
	plaintext := make([]byte, 1024)

	aead, err := NewGCMSIV(newBlock, key)
	if err != nil {
		b.Fatalf("NewGCMSIV failed: %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var nonce [12]byte
		binary.LittleEndian.PutUint64(nonce[4:], uint64(i))

		ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
		if _, err := aead.Open(nil, nonce[:], ciphertext, aad); err != nil {
			b.Fatalf("Open failed: %v", err)
		}
	}
}
