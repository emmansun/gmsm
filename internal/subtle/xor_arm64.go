// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//go:build arm64 && !generic
// +build arm64,!generic

package subtle

// XORBytes xors the bytes in a and b. The destination should have enough
// space, otherwise XORBytes will panic. Returns the number of bytes xor'd.
func XORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return 0
	}
	if n > len(dst) {
		panic("subtle.XORBytes: dst too short")
	}

	xorBytes(&dst[0], &a[0], &b[0], n)
	return n
}

//go:noescape
func xorBytes(dst, a, b *byte, n int)
