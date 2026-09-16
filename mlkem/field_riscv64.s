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

// MONT_MUL_HILO_VV computes:
//
//     dst = a*b*R^-1 mod q
//
// All vector operands use E16/M1.
//
// Constants:
//     Q       = 3329
//     QNEGINV = 3327
//
// Clobbers:
//     lo, m
//
// The lo != 0 correction is required because this implementation
// computes high16(a*b) and high16(m*q) separately, so the carry from
// low16(a*b) + low16(m*q) is not included automatically.
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
// a is E16/M1, b is an unsigned 16-bit scalar in a GPR.
#define MONT_MUL_HILO_VX(a, b, dst, lo, m) \
	VMULVX b, a, lo;                      \
	VMULHUVX b, a, dst;                   \
	VMULVX QNEGINV, lo, m;                \
	VMINUVX ONE, lo, lo;                  \
	VMULHUVX Q, m, m;                     \
	VADDVV lo, dst, dst;                  \
	VADDVV m, dst, dst;                   \
	REDUCE_ONCE_RVV(dst, lo)

// Vector-vector Montgomery multiplication.
#define MONT_MUL_WIDE_VV(a, b, dst, tmp, product) \
	VWMULUVV b, a, product;                       \
	VNSRLWI $0, product, tmp;                     \
	VMULVX QNEGINV, tmp, tmp;                     \
	VWMACCUVX Q, tmp, product;                    \
	VNSRLWI $16, product, dst;                    \
	REDUCE_ONCE_RVV(dst, tmp)

// Vector-scalar Montgomery multiplication.
#define MONT_MUL_WIDE_VX(a, b, dst, tmp, product) \
	VWMULUVX b, a, product;                       \
	VNSRLWI $0, product, tmp;                     \
	VMULVX QNEGINV, tmp, tmp;                     \
	VWMACCUVX Q, tmp, product;                    \
	VNSRLWI $16, product, dst;                    \
	REDUCE_ONCE_RVV(dst, tmp)

// Reduce x < 2q into [0,q).
#define REDUCE_ONCE_RVV(x, tmp) \
	VSUBVX Q, x, tmp;           \
	VSRAVI $15, tmp, x;         \
	VANDVX Q, x, x;             \
	VADDVV x, tmp, x

// func internalNTTMulRVV(out, lhs, rhs *nttElement)
TEXT ·internalNTTMulRVV(SB), NOSPLIT, $0-24
	MOV out+0(FP), X10
	MOV lhs+8(FP), X11
	MOV rhs+16(FP), X12

	// Pinned constants.
	MOV $3329, Q
	MOV $3327, QNEGINV
	MOV $1, ONE

	MOV $·gammasMontgomery(SB), X13

	// There are 256 coefficients, with each RVV lane processing
	// one adjacent coefficient pair, hence 128 pair operations.
	MOV $128, X14

nttml_rvv_loop:
	// Each lane processes:
	//
	//   lhs[2*i+0], lhs[2*i+1]
	//   rhs[2*i+0], rhs[2*i+1]
	//   gammaTable[i]
	//
	VSETVLI X14, E16, M1, TA, MA, X15

	// V2 = lhs even: lhs[0], lhs[2], lhs[4], ...
	// V3 = lhs odd:  lhs[1], lhs[3], lhs[5], ...
	VLSEG2E16V (X11), V2

	// V4 = rhs even: rhs[0], rhs[2], rhs[4], ...
	// V5 = rhs odd:  rhs[1], rhs[3], rhs[5], ...
	VLSEG2E16V (X12), V4

	// V6 = gamma*R mod q
	VLE16V (X13), V6

	// Register allocation:
	//
	// V2,V3    lhs even/odd
	// V4,V5    rhs even/odd
	// V6       table gamma
	// V8,V9    intermediate products
	// V10,V11  final even/odd result pair
	// V12      Montgomery low temporary
	// V13      Montgomery m temporary
	// V14      reduce-once temporary

	// ------------------------------------------------------------
	// even = MontMul(a0,b0)
	//      + gamma*MontMul(a1,b1)
	// ------------------------------------------------------------

	MONT_MUL_HILO_VV(V2, V4, V10, V12, V13)
	MONT_MUL_HILO_VV(V3, V5, V9, V12, V13)
	MONT_MUL_HILO_VV(V9, V6, V9, V12, V13)

	VADDVV V9, V10, V10
	REDUCE_ONCE_RVV(V10, V14)

	// ------------------------------------------------------------
	// Cross products:
	//
	//   cross0 = MontMul(a0, b1)
	//   cross1 = MontMul(a1, b0)
	//   outOdd = cross0 + cross1
	// ------------------------------------------------------------

	MONT_MUL_HILO_VV(V2, V5, V8, V12, V13)
	MONT_MUL_HILO_VV(V3, V4, V9, V12, V13)

	VADDVV V9, V8, V11
	REDUCE_ONCE_RVV(V11, V14)

	// V10 = out[2*i+0]
	// V11 = out[2*i+1]
	VSSEG2E16V V10, (X10)

	// Each lane consumes one two-coefficient segment:
	//
	//   2 fields * sizeof(uint16) = 4 bytes.
	SLL $2, X15, X16

	ADD X16, X10, X10
	ADD X16, X11, X11
	ADD X16, X12, X12

	SLL $1, X15, X16
	ADD X16, X13, X13

	SUB X15, X14, X14
	BNEZ X14, nttml_rvv_loop

	RET
