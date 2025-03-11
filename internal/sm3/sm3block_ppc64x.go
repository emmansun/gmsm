// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

package sm3

//go:noescape
func blockASM(dig *digest, p []byte, buffer *uint32)

func block(dig *digest, p []byte) {
	var buffer [8]uint32 // 32 bytes buffer, avoid stack usage in asm code
	blockASM(dig, p, &buffer[0])
}
