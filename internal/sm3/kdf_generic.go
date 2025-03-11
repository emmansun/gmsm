// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build purego || !(amd64 || arm64 || s390x || ppc64 || ppc64le)

package sm3

func kdf(baseMD *digest, keyLen int, limit int) []byte {
	return kdfGeneric(baseMD, keyLen, limit)
}
