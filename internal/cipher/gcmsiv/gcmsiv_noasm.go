// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build purego || !(amd64 || arm64)

package cipher

// computePolyval delegates to the pure-Go generic implementation on platforms
// without PCLMULQDQ support.
func computePolyval(authKey [16]byte, aad, plaintext []byte, lengthBlock [16]byte) (s [16]byte) {
	return computePolyvalGeneric(authKey, aad, plaintext, lengthBlock)
}
