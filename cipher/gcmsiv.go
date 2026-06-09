// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cipher

import (
	stdcipher "crypto/cipher"

	internalcipher "github.com/emmansun/gmsm/internal/cipher"
)

// NewGCMSIV returns an AEAD implementing the GCM-SIV mode.
// key is the key-generating key and cipherFunc creates a block cipher from raw key bytes.
func NewGCMSIV(cipherFunc CipherCreator, key []byte) (stdcipher.AEAD, error) {
	return internalcipher.NewGCMSIV(cipherFunc, key)
}
