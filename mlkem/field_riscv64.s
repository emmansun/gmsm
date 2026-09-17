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

// Input:
//     va = a
//     vb = b
//
// Output:
//     va = a+t mod q
//     vb = a-t mod q
#define NTT_BUTTERFLY(va, vb, zeta, vt, olda, lo, m, redtmp) \
	VMVVV va, olda;                                             \
	MONT_MUL_HILO_VX(vb, zeta, vt, lo, m);                     \
	VADDVV vt, olda, va;                                       \
	REDUCE_ONCE_RVV(va, redtmp);                               \
	VADDVX Q, olda, vb;                                        \
	VSUBVV vt, vb, vb;                                         \
	REDUCE_ONCE_RVV(vb, redtmp)

// Input:
//     va = a
//     vb = b
//
// Output:
//     va = a+b mod q
//     vb = zeta*(b-a) mod q
#define INVNTT_BUTTERFLY(va, vb, zeta, olda, diff, lo, m, redtmp) \
	VMVVV va, olda;                                               \
	VADDVV vb, olda, va;                                         \
	REDUCE_ONCE_RVV(va, redtmp);                                 \
	VADDVX Q, vb, diff;                                          \
	VSUBVV olda, diff, diff;                                     \
	REDUCE_ONCE_RVV(diff, redtmp);                               \
	MONT_MUL_HILO_VX(diff, zeta, vb, lo, m)

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

// func internalNTTRVV(f *ringElement)
TEXT ·internalNTTRVV(SB), NOSPLIT, $0-8
	MOV f+0(FP), X10

	// Pinned constants.
	MOV $3329, Q
	MOV $3327, QNEGINV
	MOV $1, ONE

	// Skip zetas[0], matching k=1.
	MOV $·zetasMontgomery(SB), X11
	ADD $2, X11, X11

	// Generic levels:
	//
	//	len = 128, 64, 32, 16, 8
	//
	// For len >= 8, unit-stride left/right loads remain reasonably
	// efficient. The final len=4 and len=2 levels use segmented
	// group-parallel kernels below.

	// len = 128
	MOV $128, X12

ntt_level_loop:
	// start = 0
	MOV $0, X13

ntt_start_loop:
	// Load one zeta multiplier for this start group.
	MOVHU (X11), X14
	ADD $2, X11, X11

	// leftPtr  = f + start*2
	// rightPtr = leftPtr + len*2
	SLL $1, X13, X15
	ADD X10, X15, X16

	SLL $1, X12, X17
	ADD X16, X17, X18

	// remaining = len
	MOV X12, X19

ntt_chunk_loop:
	// Strip-mine this butterfly row.
	VSETVLI X19, E16, M1, TA, MA, X15

	// V2 = a
	// V3 = b
	VLE16V (X16), V2
	VLE16V (X18), V3

	// Registers:
	//
	// V2 = left/result left
	// V3 = right/result right
	// V4 = t
	// V5 = old left
	// V6 = Montgomery lo
	// V7 = Montgomery m
	// V8 = reduce temporary

	VMVVV V2, V5

	// t = b * zeta mod q
	MONT_MUL_HILO_VX(V3, X14, V4, V6, V7)

	// left = oldLeft + t mod q
	VADDVV V4, V5, V2
	REDUCE_ONCE_RVV(V2, V8)

	// right = oldLeft - t mod q
	//
	// Compute oldLeft + q - t to avoid unsigned underflow.
	VADDVX Q, V5, V3
	VSUBVV V4, V3, V3
	REDUCE_ONCE_RVV(V3, V8)

	VSE16V V2, (X16)
	VSE16V V3, (X18)

	// Each lane consumes one uint16 from each side.
	SLL $1, X15, X17

	ADD X17, X16, X16
	ADD X17, X18, X18

	SUB X15, X19, X19
	BNEZ X19, ntt_chunk_loop

	// start += 2*len
	SLL $1, X12, X15
	ADD X15, X13, X13

	MOV $256, X15
	BLT X13, X15, ntt_start_loop

	// len >>= 1
	SRL $1, X12, X12

	MOV $8, X15
	BGE X12, X15, ntt_level_loop

// -----------------------------------------------------------------------------
// len = 4
//
// Memory layout for each 8-coefficient group:
//
//	[a0 a1 a2 a3 b0 b1 b2 b3]
//
// VLSEG8E16V transposes multiple groups into:
//
//	V2 = a0 of every group
//	V3 = a1 of every group
//	V4 = a2 of every group
//	V5 = a3 of every group
//	V6 = b0 of every group
//	V7 = b1 of every group
//	V8 = b2 of every group
//	V9 = b3 of every group
//
// Each lane therefore processes one independent butterfly group.
// There are 256/8 = 32 groups.
// -----------------------------------------------------------------------------

ntt_level4:
	MOV	X10, X16
	MOV	$32, X19

ntt_level4_loop:
	VSETVLI X19, E16, M1, TA, MA, X15

	// V10 = one zeta per group.
	VLE16V	(X11), V10

	// V2..V5 = left[0..3]
	// V6..V9 = right[0..3]
	VLSEG8E16V (X16), V2

	// Montgomery results:
	//	V11..V14 = t0..t3
	//
	// Shared Montgomery temporaries:
	//	V20, V21
	MONT_MUL_HILO_VV(V6, V10, V11, V20, V21)
	MONT_MUL_HILO_VV(V7, V10, V12, V20, V21)
	MONT_MUL_HILO_VV(V8, V10, V13, V20, V21)
	MONT_MUL_HILO_VV(V9, V10, V14, V20, V21)

	// right0 = left0 + q - t0
	VADDVX	Q, V2, V6
	VSUBVV	V11, V6, V6
	REDUCE_ONCE_RVV(V6, V20)

	// right1 = left1 + q - t1
	VADDVX	Q, V3, V7
	VSUBVV	V12, V7, V7
	REDUCE_ONCE_RVV(V7, V20)

	// right2 = left2 + q - t2
	VADDVX	Q, V4, V8
	VSUBVV	V13, V8, V8
	REDUCE_ONCE_RVV(V8, V20)

	// right3 = left3 + q - t3
	VADDVX	Q, V5, V9
	VSUBVV	V14, V9, V9
	REDUCE_ONCE_RVV(V9, V20)

	// left0 = left0 + t0
	VADDVV	V11, V2, V2
	REDUCE_ONCE_RVV(V2, V20)

	// left1 = left1 + t1
	VADDVV	V12, V3, V3
	REDUCE_ONCE_RVV(V3, V20)

	// left2 = left2 + t2
	VADDVV	V13, V4, V4
	REDUCE_ONCE_RVV(V4, V20)

	// left3 = left3 + t3
	VADDVV	V14, V5, V5
	REDUCE_ONCE_RVV(V5, V20)

	// Store:
	// [left0 left1 left2 left3 right0 right1 right2 right3]
	VSSEG8E16V V2, (X16)

	// zeta pointer += vl * sizeof(uint16)
	SLL	$1, X15, X17
	ADD	X17, X11, X11

	// coefficient pointer += vl * 8 * sizeof(uint16)
	//                     = vl * 16 bytes
	SLL	$4, X15, X17
	ADD	X17, X16, X16

	SUB	X15, X19, X19
	BNEZ	X19, ntt_level4_loop

// -----------------------------------------------------------------------------
// len = 2
//
// Each four-coefficient group:
//
//	[a0 a1 b0 b1]
//
// VLSEG4E16V produces:
//
//	V2 = a0 of every group
//	V3 = a1 of every group
//	V4 = b0 of every group
//	V5 = b1 of every group
//
// There are 256/4 = 64 groups.
// -----------------------------------------------------------------------------

ntt_level2:
	MOV	X10, X16
	MOV	$64, X19

ntt_level2_loop:
	VSETVLI X19, E16, M1, TA, MA, X15

	// One zeta per butterfly group.
	VLE16V	(X11), V10

	// V2,V3 = left
	// V4,V5 = right
	VLSEG4E16V (X16), V2

	// V11,V12 = t0,t1
	MONT_MUL_HILO_VV(V4, V10, V11, V20, V21)
	MONT_MUL_HILO_VV(V5, V10, V12, V20, V21)

	// right0 = left0 + q - t0
	VADDVX	Q, V2, V4
	VSUBVV	V11, V4, V4
	REDUCE_ONCE_RVV(V4, V20)

	// right1 = left1 + q - t1
	VADDVX	Q, V3, V5
	VSUBVV	V12, V5, V5
	REDUCE_ONCE_RVV(V5, V20)

	// left0 = left0 + t0
	VADDVV	V11, V2, V2
	REDUCE_ONCE_RVV(V2, V20)

	// left1 = left1 + t1
	VADDVV	V12, V3, V3
	REDUCE_ONCE_RVV(V3, V20)

	VSSEG4E16V V2, (X16)

	// zeta pointer += vl * 2
	SLL	$1, X15, X17
	ADD	X17, X11, X11

	// coefficient pointer += vl * 4 * sizeof(uint16)
	//                     = vl * 8 bytes
	SLL	$3, X15, X17
	ADD	X17, X16, X16

	SUB	X15, X19, X19
	BNEZ	X19, ntt_level2_loop

	RET

// func internalInverseNTTRVV(f *ringElement)
TEXT ·internalInverseNTTRVV(SB), NOSPLIT, $0-8
	MOV f+0(FP), X10

	MOV $3329, Q
	MOV $3327, QNEGINV
	MOV $1, ONE

	MOV $·zetasMontgomery(SB), X11
	ADD $254, X11, X11

	// len = 2
	MOV $2, X12

invntt_level_loop:
	MOV $0, X13

invntt_start_loop:
	MOVHU (X11), X14
	SUB $2, X11, X11

	SLL $1, X13, X15
	ADD X10, X15, X16

	SLL $1, X12, X17
	ADD X16, X17, X18

	MOV X12, X19

invntt_chunk_loop:
	VSETVLI X19, E16, M1, TA, MA, X15

	VLE16V (X16), V2
	VLE16V (X18), V3

	// V2 = a
	// V3 = b
	// V4 = old a
	// V5 = diff
	// V6 = Montgomery lo
	// V7 = Montgomery m
	// V8 = reduce temporary

	VMVVV V2, V4

	// a' = a+b mod q
	VADDVV V3, V4, V2
	REDUCE_ONCE_RVV(V2, V8)

	// diff = b-a mod q
	VADDVX Q, V3, V5
	VSUBVV V4, V5, V5
	REDUCE_ONCE_RVV(V5, V8)

	// b' = zeta*diff mod q
	MONT_MUL_HILO_VX(V5, X14, V3, V6, V7)

	VSE16V V2, (X16)
	VSE16V V3, (X18)

	SLL $1, X15, X17
	ADD X17, X16, X16
	ADD X17, X18, X18

	SUB X15, X19, X19
	BNEZ X19, invntt_chunk_loop

	SLL $1, X12, X15
	ADD X15, X13, X13

	MOV $256, X15
	BLT X13, X15, invntt_start_loop

	SLL $1, X12, X12

	MOV $128, X15
	BLE X12, X15, invntt_level_loop

	MOV $1441, X14

	MOV $256, X19
	MOV X10, X16

invntt_scale_loop:
	VSETVLI X19, E16, M1, TA, MA, X15

	VLE16V (X16), V2
	MONT_MUL_HILO_VX(V2, X14, V2, V6, V7)
	VSE16V V2, (X16)

	SLL $1, X15, X17
	ADD X17, X16, X16

	SUB X15, X19, X19
	BNEZ X19, invntt_scale_loop

	RET
