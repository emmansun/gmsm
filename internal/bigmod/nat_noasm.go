// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build purego || !(386 || amd64 || arm || arm64 || ppc64 || ppc64le || riscv64 || s390x)

package bigmod

import "unsafe"

// TODO: will use unsafe.Slice directly once upgrade golang sdk to 1.17+
func slice256(ptr *uint) []uint {
	return (*[256 / _W]uint)(unsafe.Pointer(ptr))[:]
}

func slice1024(ptr *uint) []uint {
	return (*[1024 / _W]uint)(unsafe.Pointer(ptr))[:]
}

func slice1536(ptr *uint) []uint {
	return (*[1536 / _W]uint)(unsafe.Pointer(ptr))[:]
}

func slice2048(ptr *uint) []uint {
	return (*[2048 / _W]uint)(unsafe.Pointer(ptr))[:]
}

func addMulVVW256(z, x *uint, y uint) (c uint) {
	return addMulVVW(slice256(z), slice256(x), y)
}

func addMulVVW1024(z, x *uint, y uint) (c uint) {
	return addMulVVW(slice1024(z), slice1024(x), y)
}

func addMulVVW1536(z, x *uint, y uint) (c uint) {
	return addMulVVW(slice1536(z), slice1536(x), y)
}

func addMulVVW2048(z, x *uint, y uint) (c uint) {
	return addMulVVW(slice2048(z), slice2048(x), y)
}
