// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

package sm3

func kdf(baseMD *digest, keyLen int, limit int) []byte {
	if limit < 4 {
		return kdfGeneric(baseMD, keyLen, limit)
	}

	if useAVX2 && limit >= 8 {
		return kdfBy8(baseMD, keyLen, limit)
	}

	return kdfBy4(baseMD, keyLen, limit)
}
