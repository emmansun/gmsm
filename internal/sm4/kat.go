// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm4

import (
	"crypto/subtle"
	"errors"
)

// KAT test vector from GB/T 32906-2016 Appendix A.
var (
	katKey = []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
	katPlaintext = []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
	katExpectedCipher = []byte{
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
	}
)

// KATEncryptDecrypt verifies SM4 encryption and decryption with the GB/T 32906-2016 standard vector.
func KATEncryptDecrypt() error {
	c, err := NewCipher(katKey)
	if err != nil {
		return errors.New("failed to create cipher: " + err.Error())
	}

	// Test encryption.
	dst := make([]byte, BlockSize)
	c.Encrypt(dst, katPlaintext)
	if subtle.ConstantTimeCompare(dst, katExpectedCipher) != 1 {
		return errors.New("encryption mismatch")
	}

	// Test decryption: decrypt the expected ciphertext back to plaintext.
	dec := make([]byte, BlockSize)
	c.Decrypt(dec, katExpectedCipher)
	if subtle.ConstantTimeCompare(dec, katPlaintext) != 1 {
		return errors.New("decryption mismatch")
	}

	return nil
}
