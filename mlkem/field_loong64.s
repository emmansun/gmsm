// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// polyAddAssignLASX computes dst[i] = fieldAdd(dst[i], src[i]) for all i in [0, 256).
// Uses LASX to process 16 int16 values (32 bytes) per vector, 2 vectors per iteration.
// func polyAddAssignLASX(dst, src *ringElement)
TEXT ·polyAddAssignLASX(SB), NOSPLIT, $0-16
	MOVV dst+0(FP), R4
	MOVV src+8(FP), R5

	// Broadcast q=3329 (0x0D01) to all 16 int16 lanes
	// 0x0D010D010D010D01 = 3329 repeated in each 16-bit position of a 64-bit word
	MOVV $0x0D010D010D010D01, R7
	XVMOVQ R7, X15.V4

	MOVV $8, R6  // loop counter: 8 iterations * 64 bytes = 512 bytes

poly_add_loop:
	// Load 2x 256-bit vectors = 32 coefficients
	XVMOVQ (R4), X0
	XVMOVQ 32(R4), X1
	XVMOVQ (R5), X2
	XVMOVQ 32(R5), X3

	// dst = dst + src
	XVADDH X2, X0, X0
	XVADDH X3, X1, X1

	// Conditional reduction: if dst >= q, subtract q
	// tmp = dst - q
	XVSUBH X15, X0, X4
	XVSUBH X15, X1, X5

	// mask = arithmetic right shift 15 (0xFFFF if tmp < 0, else 0)
	XVSRAH $15, X4, X6
	XVSRAH $15, X5, X7

	// fix = mask & q (q if tmp < 0, i.e., original was < q, so keep original)
	XVANDV X6, X15, X6
	XVANDV X7, X15, X7

	// result = tmp + fix (if tmp < 0: tmp + q = original; if tmp >= 0: tmp + 0 = dst - q)
	XVADDH X6, X4, X0
	XVADDH X7, X5, X1

	// Store results
	XVMOVQ X0, (R4)
	XVMOVQ X1, 32(R4)

	ADDV $64, R4
	ADDV $64, R5
	ADDV $-1, R6
	BNE R6, R0, poly_add_loop

	RET

// polySubAssignLASX computes dst[i] = fieldSub(dst[i], src[i]) for all i in [0, 256).
// fieldSub: x = uint16(a - b + q); return fieldReduceOnce(x)
// func polySubAssignLASX(dst, src *ringElement)
TEXT ·polySubAssignLASX(SB), NOSPLIT, $0-16
	MOVV dst+0(FP), R4
	MOVV src+8(FP), R5

	// Broadcast q=3329 (0x0D01) to all 16 int16 lanes
	MOVV $0x0D010D010D010D01, R7
	XVMOVQ R7, X15.V4

	MOVV $8, R6  // loop counter: 8 iterations * 64 bytes = 512 bytes

poly_sub_loop:
	// Load 2x 256-bit vectors = 32 coefficients
	XVMOVQ (R4), X0
	XVMOVQ 32(R4), X1
	XVMOVQ (R5), X2
	XVMOVQ 32(R5), X3

	// Compute dst + q - src
	XVADDH X15, X0, X0    // dst = dst + q
	XVSUBH X2, X0, X0     // dst = (dst + q) - src, result in [0, 2q)

	XVADDH X15, X1, X1    // dst = dst + q
	XVSUBH X3, X1, X1     // dst = (dst + q) - src

	// Conditional reduction: if dst >= q, subtract q
	// tmp = dst - q
	XVSUBH X15, X0, X4
	XVSUBH X15, X1, X5

	// mask = arithmetic right shift 15
	XVSRAH $15, X4, X6
	XVSRAH $15, X5, X7

	// fix = mask & q
	XVANDV X6, X15, X6
	XVANDV X7, X15, X7

	// result = tmp + fix
	XVADDH X6, X4, X0
	XVADDH X7, X5, X1

	// Store results
	XVMOVQ X0, (R4)
	XVMOVQ X1, 32(R4)

	ADDV $64, R4
	ADDV $64, R5
	ADDV $-1, R6
	BNE R6, R0, poly_sub_loop

	RET
