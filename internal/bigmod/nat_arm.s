// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// func addMulVVW256(z, x *uint, y uint) (c uint)
TEXT ·addMulVVW256(SB), $0-16
	MOVW	$8, R5
	JMP		addMulVVWx(SB)

// func addMulVVW1024(z, x *uint, y uint) (c uint)
TEXT ·addMulVVW1024(SB), $0-16
	MOVW	$32, R5
	JMP		addMulVVWx(SB)

// func addMulVVW1536(z, x *uint, y uint) (c uint)
TEXT ·addMulVVW1536(SB), $0-16
	MOVW	$48, R5
	JMP		addMulVVWx(SB)

// func addMulVVW2048(z, x *uint, y uint) (c uint)
TEXT ·addMulVVW2048(SB), $0-16
	MOVW	$64, R5
	JMP		addMulVVWx(SB)
