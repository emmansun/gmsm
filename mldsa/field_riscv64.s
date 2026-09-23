// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.26 && !purego

#include "textflag.h"

#define ZERO X0
#define RSP X2
#define Q X20
#define QNEGINV X21
#define ONE X22
#define RR X23

// MONT_MUL_HILO_VV computes:
//
//     dst = a*b*R^-1 mod q
//
// All vector operands use SEW=32.
//
// Constants:
//     Q       = 8380417
//     QNEGINV = 4236238847
//
// Clobbers:
//     lo, m
//
// The lo != 0 correction is required because this implementation
// computes high32(a*b) and high32(m*q) separately, so the carry from
// low32(a*b) + low32(m*q) is not included automatically.
#define MONT_MUL_HILO_VV(a, b, dst, lo, m) \
	VMULVV b, a, lo;                      \
	VMULHUVV b, a, dst;                   \
	VMULVX QNEGINV, lo, m;                \
	VMINUVX ONE, lo, lo;                  \
	VMULHUVX Q, m, m;                     \
	VADDVV lo, dst, dst;                  \
	VADDVV m, dst, dst;                   \
	REDUCE_ONCE_RVV(dst, lo)

// MONT_MUL_HILO_VX computes:
//
//     dst = a*b*R^-1 mod q
//
// a is a SEW=32, b is an unsigned 32-bit scalar in a GPR.
#define MONT_MUL_HILO_VX(a, b, dst, lo, m) \
	VMULVX b, a, lo;                      \
	VMULHUVX b, a, dst;                   \
	VMULVX QNEGINV, lo, m;                \
	VMINUVX ONE, lo, lo;                  \
	VMULHUVX Q, m, m;                     \
	VADDVV lo, dst, dst;                  \
	VADDVV m, dst, dst;                   \
	REDUCE_ONCE_RVV(dst, lo)
	
// Reduce x < 2q into [0,q).
#define REDUCE_ONCE_RVV(x, tmp) \
	VSUBVX Q, x, tmp;           \
	VSRAVI $31, tmp, x;         \
	VANDVX Q, x, x;             \
	VADDVV x, tmp, x

//func polyAddAssignRVV(dst, src *ringElement)
// polyAddAssignRVV computes dst[i] = fieldAdd(dst[i], src[i]) for all i in [0, 256).
TEXT ·polyAddAssignRVV(SB), NOSPLIT, $0-16
	MOV dst+0(FP), X11
	MOV src+8(FP), X12

	// Pinned constants.
	MOV $8380417, Q

	MOV $256, X13

	// With VLEN >= 128, E32/M4 gives VL in
	// {16, 32, 64, 128, 256}, all of which divide 256.	
	VSETVLI X13, E32, M4, TA, MA, X14

polyAddAssignRVV_loop:
	VLE32V		(X11), V4
	VLE32V		(X12), V8

	VADDVV V8, V4, V4
	REDUCE_ONCE_RVV(V4, V8)

	VSE32V		V4, (X11)
	SLL $2, X14, X15
	ADD	X15, X11, X11
	ADD	X15, X12, X12

	SUB	X14, X13, X13
	BNEZ	X13, polyAddAssignRVV_loop

	RET

//func polySubAssignRVV(dst, src *ringElement)
// polySubAssignRVV computes dst[i] = fieldSub(dst[i], src[i]) for all i in [0, 256).
TEXT ·polySubAssignRVV(SB), NOSPLIT, $0-16
	MOV dst+0(FP), X11
	MOV src+8(FP), X12

	// Pinned constants.
	MOV $8380417, Q

	MOV $256, X13

	// With VLEN >= 128, E32/M4 gives VL in
	// {16, 32, 64, 128, 256}, all of which divide 256.	
	VSETVLI X13, E32, M4, TA, MA, X14

polySubAssignRVV_loop:
	
	VLE32V		(X11), V4
	VLE32V		(X12), V8

	VSUBVV V8, V4, V4
	VSRAVI $31, V4, V16
	VANDVX Q, V16, V16
	VADDVV V16, V4, V4

	VSE32V		V4, (X11)
	SLL $2, X14, X15
	ADD	X15, X11, X11
	ADD	X15, X12, X12

	SUB	X14, X13, X13
	BNEZ	X13, polySubAssignRVV_loop
	RET

//func nttMulRVV(lhs, rhs, out *nttElement)
TEXT ·nttMulRVV(SB), NOSPLIT, $0-24
	MOV lhs+0(FP), X10
	MOV rhs+8(FP), X11
	MOV out+16(FP), X12

	// Pinned constants.
	MOV $8380417, Q
	MOV $4236238847, QNEGINV
	MOV $1, ONE

	MOV $256, X13

	VSETVLI X13, E32, M2, TA, MA, X14

nttMulRVV_loop:
	VLE32V		(X10), V2
	VLE32V		(X11), V4

	MONT_MUL_HILO_VV(V2, V4, V6, V8, V10)
	VSE32V		V6, (X12)

	SLL $2, X14, X15
	ADD	X15, X10, X10
	ADD	X15, X11, X11
	ADD	X15, X12, X12

	SUB	X14, X13, X13
	BNEZ	X13, nttMulRVV_loop

	RET

//func nttMulAccRVV(acc, lhs, rhs *nttElement)
TEXT ·nttMulAccRVV(SB), NOSPLIT, $0-24
	MOV lhs+8(FP), X10
	MOV rhs+16(FP), X11
	MOV acc+0(FP), X12

	// Pinned constants.
	MOV $8380417, Q
	MOV $4236238847, QNEGINV
	MOV $1, ONE

	MOV $256, X13

	VSETVLI X13, E32, M2, TA, MA, X14

nttMulAccRVV_loop:
	VLE32V		(X10), V2
	VLE32V		(X11), V4
	VLE32V		(X12), V6

	MONT_MUL_HILO_VV(V2, V4, V8, V10, V12)
	VADDVV V8, V6, V6
	REDUCE_ONCE_RVV(V6, V8)

	VSE32V		V6, (X12)

	SLL $2, X14, X15
	ADD	X15, X10, X10
	ADD	X15, X11, X11
	ADD	X15, X12, X12

	SUB	X14, X13, X13
	BNEZ	X13, nttMulAccRVV_loop

	RET
