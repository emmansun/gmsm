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

// func internalNTTMulAccRVV(acc, lhs, rhs *nttElement)
//
// Computes:
//
//     acc += lhs * rhs
//
// acc and the generated delta remain in the same Montgomery-scaled
// representation used by internalNTTMulRVV.
TEXT ·internalNTTMulAccRVV(SB), NOSPLIT, $0-24
	MOV acc+0(FP), X10
	MOV lhs+8(FP), X11
	MOV rhs+16(FP), X12

	// Pinned constants.
	MOV $3329, Q
	MOV $3327, QNEGINV
	MOV $1, ONE

	// gammasMontgomery[i] = gammas[i] * R mod q.
	MOV $·gammasMontgomery(SB), X13

	// Each lane processes one adjacent coefficient pair.
	//
	// 256 coefficients / 2 coefficients per pair = 128 pairs.
	MOV $128, X14

nttmlacc_rvv_loop:
	VSETVLI X14, E16, M1, TA, MA, X15

	// V2 = lhs even coefficients
	// V3 = lhs odd coefficients
	VLSEG2E16V (X11), V2

	// V4 = rhs even coefficients
	// V5 = rhs odd coefficients
	VLSEG2E16V (X12), V4

	// V6 = gamma * R mod q
	VLE16V (X13), V6

	// Register allocation:
	//
	// V2,V3    lhs even/odd
	// V4,V5    rhs even/odd
	// V6       gamma*R mod q
	// V8,V9    intermediate products
	// V10,V11  delta even/odd
	// V12      Montgomery low temporary
	// V13      Montgomery m temporary
	// V14      reduce-once temporary
	// V16,V17  accumulator even/odd

	// ------------------------------------------------------------
	// deltaEven =
	//     MontMul(a0, b0)
	//   + MontMul(MontMul(a1, b1), gamma*R)
	//
	// All terms have the same R^-1 scaling.
	// ------------------------------------------------------------

	MONT_MUL_HILO_VV(V2, V4, V10, V12, V13)
	MONT_MUL_HILO_VV(V3, V5, V9, V12, V13)
	MONT_MUL_HILO_VV(V9, V6, V9, V12, V13)

	VADDVV V9, V10, V10
	REDUCE_ONCE_RVV(V10, V14)

	// ------------------------------------------------------------
	// deltaOdd =
	//     MontMul(a0, b1)
	//   + MontMul(a1, b0)
	// ------------------------------------------------------------

	MONT_MUL_HILO_VV(V2, V5, V8, V12, V13)
	MONT_MUL_HILO_VV(V3, V4, V11, V12, V13)

	VADDVV V11, V8, V11
	REDUCE_ONCE_RVV(V11, V14)

	// ------------------------------------------------------------
	// acc += delta
	//
	// Contract:
	//     accEven, accOdd     < q
	//     deltaEven, deltaOdd < q
	//
	// Therefore each sum is < 2q and one conditional subtraction
	// is sufficient.
	// ------------------------------------------------------------

	// V16 = acc even
	// V17 = acc odd
	VLSEG2E16V (X10), V16

	VADDVV V10, V16, V16
	VADDVV V11, V17, V17

	REDUCE_ONCE_RVV(V16, V12)
	REDUCE_ONCE_RVV(V17, V13)

	// Interleave:
	//
	// acc[2*i+0] = V16[i]
	// acc[2*i+1] = V17[i]
	VSSEG2E16V V16, (X10)

	// One pair = two uint16 coefficients = four bytes.
	SLL $2, X15, X16

	ADD X16, X10, X10
	ADD X16, X11, X11
	ADD X16, X12, X12

	// One gamma uint16 per pair.
	SLL $1, X15, X17
	ADD X17, X13, X13

	SUB X15, X14, X14
	BNEZ X14, nttmlacc_rvv_loop

	RET

// func internalNTTMulAccKeyGenRVV(acc, lhs, rhs *nttElement)
//
// Computes:
//
//     acc += FromMontgomery(lhs * rhs)
//
// The NTT product is generated in the R^-1-scaled representation.
// Before accumulation, each coefficient is converted to the standard
// field representation with:
//
//     MontMul(delta, R^2 mod q)
//
// where R^2 mod q = 1353.
TEXT ·internalNTTMulAccKeyGenRVV(SB), NOSPLIT, $0-24
	MOV acc+0(FP), X10
	MOV lhs+8(FP), X11
	MOV rhs+16(FP), X12

	// Pinned constants.
	MOV $3329, Q
	MOV $3327, QNEGINV
	MOV $1, ONE
	MOV $1353, RR // R^2 mod q

	// gammasMontgomery[i] = gammas[i] * R mod q.
	MOV $·gammasMontgomery(SB), X13

	// Each lane processes one adjacent coefficient pair.
	//
	// 256 coefficients / 2 coefficients per pair = 128 pairs.
	MOV $128, X14

nttmlacc_kg_rvv_loop:
	VSETVLI X14, E16, M1, TA, MA, X15

	// V2 = lhs even coefficients
	// V3 = lhs odd coefficients
	VLSEG2E16V (X11), V2

	// V4 = rhs even coefficients
	// V5 = rhs odd coefficients
	VLSEG2E16V (X12), V4

	// V6 = gamma * R mod q
	VLE16V (X13), V6

	// Register allocation:
	//
	// V2,V3    lhs even/odd
	// V4,V5    rhs even/odd
	// V6       gamma*R mod q
	// V8,V9    intermediate products
	// V10,V11  delta even/odd
	// V12      Montgomery low temporary
	// V13      Montgomery m temporary
	// V14      reduce-once temporary
	// V16,V17  accumulator even/odd

	// ------------------------------------------------------------
	// deltaEven =
	//     MontMul(a0, b0)
	//   + MontMul(MontMul(a1, b1), gamma*R)
	//
	// Result:
	//     deltaEven =
	//       (a0*b0 + gamma*a1*b1) * R^-1 mod q
	// ------------------------------------------------------------

	MONT_MUL_HILO_VV(V2, V4, V10, V12, V13)
	MONT_MUL_HILO_VV(V3, V5, V9, V12, V13)
	MONT_MUL_HILO_VV(V9, V6, V9, V12, V13)

	VADDVV V9, V10, V10
	REDUCE_ONCE_RVV(V10, V14)

	// ------------------------------------------------------------
	// deltaOdd =
	//     MontMul(a0, b1)
	//   + MontMul(a1, b0)
	//
	// Result:
	//     deltaOdd =
	//       (a0*b1 + a1*b0) * R^-1 mod q
	// ------------------------------------------------------------

	MONT_MUL_HILO_VV(V2, V5, V8, V12, V13)
	MONT_MUL_HILO_VV(V3, V4, V11, V12, V13)

	VADDVV V11, V8, V11
	REDUCE_ONCE_RVV(V11, V14)

	// ------------------------------------------------------------
	// Convert delta from the R^-1-scaled representation to the
	// standard field representation:
	//
	//     MontMul(delta*R^-1, R^2) = delta
	// ------------------------------------------------------------

	MONT_MUL_HILO_VX(V10, RR, V10, V12, V13)
	MONT_MUL_HILO_VX(V11, RR, V11, V12, V13)

	// ------------------------------------------------------------
	// Accumulate in the standard field representation.
	//
	// Preconditions:
	//     acc   < q
	//     delta < q
	//
	// Therefore:
	//     acc + delta < 2q
	// ------------------------------------------------------------

	// V16 = acc even coefficients
	// V17 = acc odd coefficients
	VLSEG2E16V (X10), V16

	VADDVV V10, V16, V16
	VADDVV V11, V17, V17

	REDUCE_ONCE_RVV(V16, V12)
	REDUCE_ONCE_RVV(V17, V13)

	// Interleaved store:
	//
	// acc[2*i+0] = V16[i]
	// acc[2*i+1] = V17[i]
	VSSEG2E16V V16, (X10)

	// One coefficient pair occupies four bytes.
	SLL $2, X15, X18

	ADD X18, X10, X10
	ADD X18, X11, X11
	ADD X18, X12, X12

	// One uint16 gamma per pair.
	SLL $1, X15, X19
	ADD X19, X13, X13

	SUB X15, X14, X14
	BNEZ X14, nttmlacc_kg_rvv_loop

	RET
