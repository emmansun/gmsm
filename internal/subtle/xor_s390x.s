// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// func xorBytes(dst, a, b *byte, n int)
TEXT ·xorBytes(SB),NOSPLIT,$0-32
	MOVD	dst+0(FP), R1
	MOVD	a+8(FP), R2
	MOVD	b+16(FP), R3
	MOVD	n+24(FP), R4

	MOVD	$0, R5
	CMPBLT	R4, $16, less_than16

loop16b:
	VL 0(R2)(R5*1), V0
	VL 0(R3)(R5*1), V1
	VX V0, V1, V2
	VST V2, 0(R1)(R5*1)
	LAY	16(R5), R5
	SUB	$16, R4
	CMPBGE	R4, $16, loop16b

less_than16:
	CMPBLT	R4, $8, tail
	MOVD	0(R2)(R5*1), R7
	MOVD	0(R3)(R5*1), R8
	XOR	R7, R8
	MOVD	R8, 0(R1)(R5*1)
	LAY	8(R5), R5
	SUB	$8, R4

tail:
	CMPBEQ	R4, $0, done
	MOVB	0(R2)(R5*1), R7
	MOVB	0(R3)(R5*1), R8
	XOR	R7, R8
	MOVB	R8, 0(R1)(R5*1)
	LAY	1(R5), R5
	SUB	$1, R4
	BR	tail

done:
	RET
