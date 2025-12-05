// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// derived from crypto/internal/fips140/bigmod/nat_riscv64.s

//go:build !purego

#include "textflag.h"

// func addMulVVW256(z, x *uint, y uint) (c uint)
TEXT ·addMulVVW256(SB),$0-32
	MOVV	$4, R8
	JMP	addMulVVWx(SB)

// func addMulVVW1024(z, x *uint, y uint) (c uint)
TEXT ·addMulVVW1024(SB),$0-32
	MOVV	$16, R8
	JMP	addMulVVWx(SB)

// func addMulVVW1536(z, x *uint, y uint) (c uint)
TEXT ·addMulVVW1536(SB),$0-32
	MOVV	$24, R8
	JMP	addMulVVWx(SB)

// func addMulVVW2048(z, x *uint, y uint) (c uint)
TEXT ·addMulVVW2048(SB),$0-32
	MOVV	$32, R8
	JMP	addMulVVWx(SB)
