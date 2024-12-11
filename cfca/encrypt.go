// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cfca

import (
	"crypto/cipher"
	"errors"

	"github.com/emmansun/gmsm/padding"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

// NewSM4CBCBlockMode creates a new SM4-CBC block mode with the password.
func NewSM4CBCBlockMode(password []byte, isEncrypter bool) (cipher.BlockMode, error) {
	if len(password) == 0 {
		return nil, errors.New("cfca: invalid password")
	}
	ivkey := sm3.Kdf(password, 32)
	block, err := sm4.NewCipher(ivkey[16:])
	if err != nil {
		return nil, err
	}
	if isEncrypter {
		return cipher.NewCBCEncrypter(block, ivkey[:16]), nil
	}
	return cipher.NewCBCDecrypter(block, ivkey[:16]), nil
}

// EncryptBySM4CBC encrypts the data with the password using SM4-CBC algorithm.
// Corresponds to the cfca.sadk.util.encryptMessageBySM4 method.
func EncryptBySM4CBC(plaintext, password []byte) ([]byte, error) {
	mode, err := NewSM4CBCBlockMode(password, true)
	if err != nil {
		return nil, err
	}
	pkcs7 := padding.NewPKCS7Padding(uint(mode.BlockSize()))
	plaintext = pkcs7.Pad(plaintext)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// DecryptBySM4CBC decrypts the data with the password using SM4-CBC algorithm.
// Corresponds to the cfca.sadk.util.decryptMessageBySM4 method.
func DecryptBySM4CBC(ciphertext, password []byte) ([]byte, error) {
	mode, err := NewSM4CBCBlockMode(password, false)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	pkcs7 := padding.NewPKCS7Padding(uint(mode.BlockSize()))
	return pkcs7.Unpad(plaintext)
}
