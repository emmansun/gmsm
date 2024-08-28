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
	CMPBLT	R4, $64, less_than64

loop64b:
	VLM (R2)(R5*1), V0, V3
	VLM (R3)(R5*1), V4, V7
	VX V0, V4, V4
	VX V1, V5, V5
	VX V2, V6, V6
	VX V3, V7, V7
	VSTM V4, V7, (R1)(R5*1)
	LAY	64(R5), R5
	SUB	$64, R4
	CMPBGE	R4, $64, loop64b

less_than64:
	CMPBEQ	R4, $0, done // quick end
	CMPBLT	R4, $32, less_than32
	VLM (R2)(R5*1), V0, V1
	VLM (R3)(R5*1), V2, V3
	VX V0, V2, V2
	VX V1, V3, V3
	VSTM V2, V3, 0(R1)(R5*1)
	LAY	32(R5), R5
	SUB	$32, R4

less_than32:
	CMPBLT	R4, $16, less_than16
	VL 0(R2)(R5*1), V0
	VL 0(R3)(R5*1), V1
	VX V0, V1, V2
	VST V2, 0(R1)(R5*1)
	LAY	16(R5), R5
	SUB	$16, R4

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
