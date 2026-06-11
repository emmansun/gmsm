// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cipher

import (
	"crypto/cipher"
	"testing"
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
