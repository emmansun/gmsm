// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

package sm3

var supportMult8 = supportLASX

func kdf(baseMD *digest, keyLen int, limit int) []byte {
	if !supportLSX || limit < 4 {
		return kdfGeneric(baseMD, keyLen, limit)
	}
	if supportLASX && limit >= 8 {
		return kdfBy8(baseMD, keyLen, limit)
	}
	return kdfBy4(baseMD, keyLen, limit)
}
