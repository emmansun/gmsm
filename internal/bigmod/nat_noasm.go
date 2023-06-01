// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build purego || (!386 && !amd64 && !arm && !arm64 && !ppc64 && !ppc64le && !s390x)
// +build purego !386,!amd64,!arm,!arm64,!ppc64,!ppc64le,!s390x

package bigmod

import "unsafe"

// TODO: will use unsafe.Slice directly once upgrade golang sdk to 1.17+
func slice(ptr *uint, len int) []uint {
	return (*[len]uint)(unsafe.Pointer(ptr))[:]
}

func addMulVVW1024(z, x *uint, y uint) (c uint) {
	return addMulVVW(slice(z, 1024/_W), slice(x, 1024/_W), y)
}

func addMulVVW1536(z, x *uint, y uint) (c uint) {
	return addMulVVW(slice(z, 1536/_W), slice(x, 1536/_W), y)
}

func addMulVVW2048(z, x *uint, y uint) (c uint) {
	return addMulVVW(slice(z, 2048/_W), slice(x, 2048/_W), y)
}
