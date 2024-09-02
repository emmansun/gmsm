// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
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
	CMPBLT	R4, $64, tail

loop_64:
	VL 0(R2)(R5*1), V0
	VL 16(R2)(R5*1), V1
	VL 32(R2)(R5*1), V2
	VL 48(R2)(R5*1), V3
	VL 0(R3)(R5*1), V4
	VL 16(R3)(R5*1), V5
	VL 32(R3)(R5*1), V6
	VL 48(R3)(R5*1), V7
	VX V0, V4, V4
	VX V1, V5, V5
	VX V2, V6, V6
	VX V3, V7, V7
	VST V4, 0(R1)(R5*1)
	VST V5, 16(R1)(R5*1)
	VST V6, 32(R1)(R5*1)
	VST V7, 48(R1)(R5*1)
	LAY	64(R5), R5
	SUB	$64, R4
	CMPBGE	R4, $64, loop_64

tail:
	CMPBEQ	R4, $0, done
	CMPBLT	R4, $32, less_than32
	VL 0(R2)(R5*1), V0
	VL 16(R2)(R5*1), V1
	VL 0(R3)(R5*1), V2
	VL 16(R3)(R5*1), V3
	VX V0, V2, V2
	VX V1, V3, V3
	VST V2, 0(R1)(R5*1)
	VST V3, 16(R1)(R5*1)
	LAY	32(R5), R5
	SUB	$32, R4

less_than32:
	CMPBLT	R4, $16, less_than16
	VL 0(R2)(R5*1), V0
	VL 0(R3)(R5*1), V1
	VX V0, V1, V1
	VST V1, 0(R1)(R5*1)
	LAY	16(R5), R5
	SUB	$16, R4

less_than16:	
	CMPBLT	R4, $8, less_than8
	MOVD	0(R2)(R5*1), R7
	MOVD	0(R3)(R5*1), R8
	XOR	R7, R8
	MOVD	R8, 0(R1)(R5*1)
	LAY	8(R5), R5
	SUB	$8, R4

less_than8:
	CMPBLT	R4, $4, less_than4
	MOVWZ	0(R2)(R5*1), R7
	MOVWZ	0(R3)(R5*1), R8
	XOR	R7, R8
	MOVW	R8, 0(R1)(R5*1)
	LAY	4(R5), R5
	SUB	$4, R4

less_than4:
	CMPBLT	R4, $2, less_than2
	MOVHZ	0(R2)(R5*1), R7
	MOVHZ	0(R3)(R5*1), R8
	XOR	R7, R8
	MOVH	R8, 0(R1)(R5*1)
	LAY	2(R5), R5
	SUB	$2, R4

less_than2:
	CMPBEQ	R4, $0, done
	MOVB	0(R2)(R5*1), R7
	MOVB	0(R3)(R5*1), R8
	XOR	R7, R8
	MOVB	R8, 0(R1)(R5*1)

done:
	RET
