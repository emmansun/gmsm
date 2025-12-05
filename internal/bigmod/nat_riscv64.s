// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// func addMulVVW256(z, x *uint, y uint) (c uint)
TEXT ·addMulVVW256(SB),$0-32
	MOV	$4, X30
	JMP	addMulVVWx(SB)

// func addMulVVW1024(z, x *uint, y uint) (c uint)
TEXT ·addMulVVW1024(SB),$0-32
	MOV	$16, X30
	JMP	addMulVVWx(SB)

// func addMulVVW1536(z, x *uint, y uint) (c uint)
TEXT ·addMulVVW1536(SB),$0-32
	MOV	$24, X30
	JMP	addMulVVWx(SB)

// func addMulVVW2048(z, x *uint, y uint) (c uint)
TEXT ·addMulVVW2048(SB),$0-32
	MOV	$32, X30
	JMP	addMulVVWx(SB)
