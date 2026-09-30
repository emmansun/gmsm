// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

#define res_ptr X10
#define a_ptr   X11
#define b_ptr   X12
#define mask    X14

// MOVCOND64 selects one 64-byte chunk branchlessly:
// res = a ^ ((a ^ b) & mask), where mask is all 1s if cond == 0, else all 0s.
// Requires: VSETIVLI $8, E64, M8 active, a_ptr/b_ptr/res_ptr valid.
// Uses aligned register groups V8-V15 (a) and V16-V23 (b); the result is stored from V8.
// Requires VLEN >= 128, consistent with the other RVV implementations in this module.
#define MOVCOND64() \
	VLE64V (a_ptr), V8; \
	VLE64V (b_ptr), V16; \
	VXORVV V16, V8, V16; \
	VANDVX mask, V16, V16; \
	VXORVV V8, V16, V8; \
	VSE64V V8, (res_ptr); \
	ADD $64, a_ptr, a_ptr; \
	ADD $64, b_ptr, b_ptr; \
	ADD $64, res_ptr, res_ptr

/* ---------------------------------------*/
// func gfpCopyRVV(res, a *gfP)
TEXT ·gfpCopyRVV(SB),NOSPLIT,$0
	MOV res+0(FP), res_ptr
	MOV in+8(FP), a_ptr

	VSETIVLI $4, E64, M4, TA, MA, X0
	VLE64V (a_ptr), V4
	VSE64V V4, (res_ptr)

	RET

/* ---------------------------------------*/
// func gfp2CopyRVV(res, a *gfP2)
TEXT ·gfp2CopyRVV(SB),NOSPLIT,$0
	MOV res+0(FP), res_ptr
	MOV in+8(FP), a_ptr

	VSETIVLI $8, E64, M4, TA, MA, X0
	VLE64V (a_ptr), V4
	VSE64V V4, (res_ptr)

	RET

/* ---------------------------------------*/
// func gfp4CopyRVV(res, a *gfP4)
TEXT ·gfp4CopyRVV(SB),NOSPLIT,$0
	MOV res+0(FP), res_ptr
	MOV in+8(FP), a_ptr

	VSETIVLI $16, E64, M8, TA, MA, X0
	VLE64V (a_ptr), V8
	VSE64V V8, (res_ptr)

	RET

/* ---------------------------------------*/
// func gfp6CopyRVV(res, a *gfP6)
TEXT ·gfp6CopyRVV(SB),NOSPLIT,$0
	MOV res+0(FP), res_ptr
	MOV in+8(FP), a_ptr

	VSETIVLI $16, E64, M8, TA, MA, X0
	VLE64V (a_ptr), V8
	VSE64V V8, (res_ptr)

	ADD $128, a_ptr, a_ptr
	ADD $128, res_ptr, res_ptr

	VSETIVLI $8, E64, M4, TA, MA, X0
	VLE64V (a_ptr), V4
	VSE64V V4, (res_ptr)

	RET

/* ---------------------------------------*/
// func gfp12CopyRVV(res, a *gfP12)
TEXT ·gfp12CopyRVV(SB),NOSPLIT,$0
	MOV res+0(FP), res_ptr
	MOV in+8(FP), a_ptr

	VSETIVLI $16, E64, M8, TA, MA, X0
	VLE64V (a_ptr), V8
	VSE64V V8, (res_ptr)

	ADD $128, a_ptr, a_ptr
	ADD $128, res_ptr, res_ptr

	VLE64V (a_ptr), V8
	VSE64V V8, (res_ptr)

	ADD $128, a_ptr, a_ptr
	ADD $128, res_ptr, res_ptr

	VLE64V (a_ptr), V8
	VSE64V V8, (res_ptr)

	RET

/* ---------------------------------------*/
// func gfP12MovCondRVV(res, a, b *gfP12, cond int)
// If cond == 0 res=b, else res=a
TEXT ·gfP12MovCondRVV(SB),NOSPLIT,$0
	MOV res+0(FP), res_ptr
	MOV a+8(FP), a_ptr
	MOV b+16(FP), b_ptr
	MOV cond+24(FP), X13

	SLTU X13, X0, mask
	SUB $1, mask, mask
	VSETIVLI $8, E64, M8, TA, MA, X0

	MOVCOND64()
	MOVCOND64()
	MOVCOND64()
	MOVCOND64()
	MOVCOND64()
	MOVCOND64()

	RET

/* ---------------------------------------*/
// func curvePointMovCondRVV(res, a, b *curvePoint, cond int)
// If cond == 0 res=b, else res=a
TEXT ·curvePointMovCondRVV(SB),NOSPLIT,$0
	MOV res+0(FP), res_ptr
	MOV a+8(FP), a_ptr
	MOV b+16(FP), b_ptr
	MOV cond+24(FP), X13

	SLTU X13, X0, mask
	SUB $1, mask, mask
	VSETIVLI $8, E64, M8, TA, MA, X0

	MOVCOND64()
	MOVCOND64()

	RET

/* ---------------------------------------*/
// func twistPointMovCondRVV(res, a, b *twistPoint, cond int)
// If cond == 0 res=b, else res=a
TEXT ·twistPointMovCondRVV(SB),NOSPLIT,$0
	MOV res+0(FP), res_ptr
	MOV a+8(FP), a_ptr
	MOV b+16(FP), b_ptr
	MOV cond+24(FP), X13

	SLTU X13, X0, mask
	SUB $1, mask, mask
	VSETIVLI $8, E64, M8, TA, MA, X0

	MOVCOND64()
	MOVCOND64()
	MOVCOND64()
	MOVCOND64()

	RET
