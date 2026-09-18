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
	MOV	f+0(FP), X10

	// Pinned Montgomery constants.
	MOV	$3329, Q
	MOV	$3327, QNEGINV
	MOV	$1, ONE

	// Inverse twiddles are stored in exact consumption order:
	//
	//	zetasMontgomery[127],
	//	zetasMontgomery[126],
	//	...
	//	zetasMontgomery[1].
	//
	// Therefore both scalar and vector paths advance X11 forward.
	MOV	$·zetasMontgomeryInverse(SB), X11

// -----------------------------------------------------------------------------
// len = 2
//
// Each four-coefficient group is:
//
//	[a0 a1 b0 b1]
//
// VLSEG4E16V transposes multiple groups into:
//
//	V2 = a0 across groups
//	V3 = a1 across groups
//	V4 = b0 across groups
//	V5 = b1 across groups
//
// Each vector lane processes one independent four-coefficient group.
// There are 256/4 = 64 groups.
//
// Inverse butterfly:
//
//	outA = a + b mod q
//	diff = b - a mod q
//	outB = MontMul(diff, zeta)
// -----------------------------------------------------------------------------

	MOV	X10, X16			// coefficient pointer
	MOV	$64, X19			// remaining groups

invntt_level2_loop:
	// Each lane represents one four-coefficient group.
	VSETVLI X19, E16, M1, TA, MA, X15

	// Load one inverse zeta per group.
	VLE16V	(X11), V10

	// V2,V3 = a0,a1
	// V4,V5 = b0,b1
	VLSEG4E16V (X16), V2

	// Preserve the original a values because a' overwrites V2,V3.
	VMVVV	V2, V6
	VMVVV	V3, V7

	// a0' = a0 + b0 mod q
	VADDVV	V4, V2, V2
	REDUCE_ONCE_RVV(V2, V20)

	// a1' = a1 + b1 mod q
	VADDVV	V5, V3, V3
	REDUCE_ONCE_RVV(V3, V20)

	// diff0 = b0 - oldA0 mod q
	//
	// Compute b0 + q - oldA0 to avoid uint16 underflow.
	VADDVX	Q, V4, V8
	VSUBVV	V6, V8, V8
	REDUCE_ONCE_RVV(V8, V20)

	// diff1 = b1 - oldA1 mod q
	VADDVX	Q, V5, V9
	VSUBVV	V7, V9, V9
	REDUCE_ONCE_RVV(V9, V20)

	// b0' = MontMul(diff0, zeta)
	// b1' = MontMul(diff1, zeta)
	MONT_MUL_HILO_VV(V8, V10, V4, V20, V21)
	MONT_MUL_HILO_VV(V9, V10, V5, V20, V21)

	// Store:
	//
	//	[a0' a1' b0' b1']
	VSSEG4E16V V2, (X16)

	// Advance inverse zeta pointer by vl uint16 values.
	SLL	$1, X15, X17
	ADD	X17, X11, X11

	// Advance coefficient pointer:
	//
	//	vl groups × 4 coefficients × 2 bytes
	//	= vl × 8 bytes.
	SLL	$3, X15, X17
	ADD	X17, X16, X16

	SUB	X15, X19, X19
	BNEZ	X19, invntt_level2_loop

	// len=2 consumed:
	//
	//	zetasMontgomeryInverse[0:64]
	//
	// X11 now points to zetasMontgomeryInverse[64].


// -----------------------------------------------------------------------------
// len = 4
//
// Each eight-coefficient group is:
//
//	[a0 a1 a2 a3 b0 b1 b2 b3]
//
// VLSEG8E16V transposes multiple groups into:
//
//	V2 = a0 across groups
//	V3 = a1 across groups
//	V4 = a2 across groups
//	V5 = a3 across groups
//	V6 = b0 across groups
//	V7 = b1 across groups
//	V8 = b2 across groups
//	V9 = b3 across groups
//
// Each lane processes one independent eight-coefficient group.
// There are 256/8 = 32 groups.
// -----------------------------------------------------------------------------

	MOV	X10, X16			// coefficient pointer
	MOV	$32, X19			// remaining groups

invntt_level4_loop:
	// E16/M1 is required here because NFIELDS=8 and LMUL=1.
	VSETVLI X19, E16, M1, TA, MA, X15

	// Load one inverse zeta per group.
	VLE16V	(X11), V10

	// V2..V5 = a0..a3
	// V6..V9 = b0..b3
	VLSEG8E16V (X16), V2

	// Preserve old a0..a3.
	VMVVV	V2, V11
	VMVVV	V3, V12
	VMVVV	V4, V13
	VMVVV	V5, V14

	// a0' = a0 + b0 mod q
	VADDVV	V6, V2, V2
	REDUCE_ONCE_RVV(V2, V20)

	// a1' = a1 + b1 mod q
	VADDVV	V7, V3, V3
	REDUCE_ONCE_RVV(V3, V20)

	// a2' = a2 + b2 mod q
	VADDVV	V8, V4, V4
	REDUCE_ONCE_RVV(V4, V20)

	// a3' = a3 + b3 mod q
	VADDVV	V9, V5, V5
	REDUCE_ONCE_RVV(V5, V20)

	// diff0 = b0 - oldA0 mod q
	VADDVX	Q, V6, V15
	VSUBVV	V11, V15, V15
	REDUCE_ONCE_RVV(V15, V20)

	// diff1 = b1 - oldA1 mod q
	VADDVX	Q, V7, V16
	VSUBVV	V12, V16, V16
	REDUCE_ONCE_RVV(V16, V20)

	// diff2 = b2 - oldA2 mod q
	VADDVX	Q, V8, V17
	VSUBVV	V13, V17, V17
	REDUCE_ONCE_RVV(V17, V20)

	// diff3 = b3 - oldA3 mod q
	VADDVX	Q, V9, V18
	VSUBVV	V14, V18, V18
	REDUCE_ONCE_RVV(V18, V20)

	// b0'..b3' = MontMul(diff0..diff3, zeta)
	MONT_MUL_HILO_VV(V15, V10, V6, V20, V21)
	MONT_MUL_HILO_VV(V16, V10, V7, V20, V21)
	MONT_MUL_HILO_VV(V17, V10, V8, V20, V21)
	MONT_MUL_HILO_VV(V18, V10, V9, V20, V21)

	// Store:
	//
	//	[a0' a1' a2' a3' b0' b1' b2' b3']
	VSSEG8E16V V2, (X16)

	// Advance inverse zeta pointer by vl uint16 values.
	SLL	$1, X15, X17
	ADD	X17, X11, X11

	// Advance coefficient pointer:
	//
	//	vl groups × 8 coefficients × 2 bytes
	//	= vl × 16 bytes.
	SLL	$4, X15, X17
	ADD	X17, X16, X16

	SUB	X15, X19, X19
	BNEZ	X19, invntt_level4_loop

	// len=4 consumed:
	//
	//	zetasMontgomeryInverse[64:96]
	//
	// X11 now points to zetasMontgomeryInverse[96].


// -----------------------------------------------------------------------------
// Generic levels:
//
//	len = 8, 16, 32, 64, 128
//
// For these levels, each butterfly row contains enough contiguous
// coefficients for the unit-stride strip-mined kernel.
// -----------------------------------------------------------------------------

	MOV	$8, X12

invntt_level_loop:
	MOV	$0, X13			// start = 0

invntt_start_loop:
	// One zeta per start group.
	MOVHU	(X11), X14
	ADD	$2, X11, X11

	// leftPtr = f + start*2
	SLL	$1, X13, X15
	ADD	X10, X15, X16

	// rightPtr = leftPtr + len*2
	SLL	$1, X12, X17
	ADD	X16, X17, X18

	MOV	X12, X19			// remaining = len

invntt_chunk_loop:
	// Strip-mine one inverse butterfly row.
	VSETVLI X19, E16, M1, TA, MA, X15

	VLE16V	(X16), V2			// a
	VLE16V	(X18), V3			// b

	// Preserve old a.
	VMVVV	V2, V4

	// a' = a + b mod q
	VADDVV	V3, V4, V2
	REDUCE_ONCE_RVV(V2, V8)

	// diff = b - a mod q
	//
	// Compute b + q - oldA to avoid uint16 underflow.
	VADDVX	Q, V3, V5
	VSUBVV	V4, V5, V5
	REDUCE_ONCE_RVV(V5, V8)

	// b' = zeta * diff mod q
	MONT_MUL_HILO_VX(V5, X14, V3, V6, V7)

	VSE16V	V2, (X16)
	VSE16V	V3, (X18)

	// Each lane consumes one uint16 from each side.
	SLL	$1, X15, X17
	ADD	X17, X16, X16
	ADD	X17, X18, X18

	SUB	X15, X19, X19
	BNEZ	X19, invntt_chunk_loop

	// start += 2*len
	SLL	$1, X12, X15
	ADD	X15, X13, X13

	MOV	$256, X15
	BLT	X13, X15, invntt_start_loop

	// len <<= 1
	SLL	$1, X12, X12

	MOV	$128, X15
	BLE	X12, X15, invntt_level_loop

	// All 127 inverse zetas have now been consumed:
	//
	//	len=2:   64
	//	len=4:   32
	//	len=8:   16
	//	len=16:   8
	//	len=32:   4
	//	len=64:   2
	//	len=128:  1
	//
	//	total: 127


// -----------------------------------------------------------------------------
// Final inverse scaling.
//
// 1441 is the Montgomery-domain scale used by the existing implementation.
// -----------------------------------------------------------------------------

	MOV	$1441, X14

	MOV	$256, X19
	MOV	X10, X16

invntt_scale_loop:
	VSETVLI X19, E16, M1, TA, MA, X15

	VLE16V	(X16), V2
	MONT_MUL_HILO_VX(V2, X14, V2, V6, V7)
	VSE16V	V2, (X16)

	SLL	$1, X15, X17
	ADD	X17, X16, X16

	SUB	X15, X19, X19
	BNEZ	X19, invntt_scale_loop

	RET

// DECOMPRESS_U10 computes:
//
//     x = round(x * q / 2^10)
//       = (x*q >> 10) + ((x*q >> 9) & 1)
//
// x is an unsigned 10-bit value.
//
// Since x < 1024 and q = 3329, x*q < 2^22. We split the 32-bit
// product into the low and high halves:
//
//     x*q = hi*2^16 + lo
//
// Therefore:
//
//     (x*q >> 10) = (hi << 6) | (lo >> 10)
//
// The rounding bit is bit 9 of lo.
//
// Parameters:
//     x    input/output vector, unsigned 16-bit lanes
//     lo   temporary vector
//     hi   temporary vector
//     rnd  temporary vector
#define DECOMPRESS_U10(x, lo, hi, rnd) \
	VMULVX    Q, x, lo;                \
	VMULHUVX  Q, x, hi;                \
	VSRLVI    $9, lo, rnd;             \
	VANDVI    $1, rnd, rnd;            \
	VSRLVI    $10, lo, lo;             \
	VSLLVI    $6, hi, hi;              \
	VORVV     hi, lo, x;               \
	VADDVV    rnd, x, x

// Each ringElement contains 256 uint16 coefficients.
//
// Every five input bytes encode four 10-bit coefficients:
//
//     y0 = b0       | (b1 & 0x03) << 8
//     y1 = b1 >> 2  | (b2 & 0x0f) << 6
//     y2 = b2 >> 4  | (b3 & 0x3f) << 4
//     y3 = b3 >> 6  | b4 << 2
//
// VLSEG5E8V loads:
//
//     V8  = b0[0], b0[1], ...
//     V9  = b1[0], b1[1], ...
//     V10 = b2[0], b2[1], ...
//     V11 = b3[0], b3[1], ...
//     V12 = b4[0], b4[1], ...
//
// VSSEG4E16V stores:
//
//     y0[0], y1[0], y2[0], y3[0],
//     y0[1], y1[1], y2[1], y3[1],
//     ...
TEXT ·decodeAndDecompressU10RVV(SB), NOSPLIT, $0-48
	MOV	dst_base+0(FP), X10
	MOV	dst_len+8(FP), X12
	MOV	c_base+24(FP), X11

	// There are 256 / 4 = 64 five-byte groups per ringElement.
	SLLI	$6, X12, X12
	BEQ	X12, X0, done

	MOV	$3329, Q

loop:
	// Use LMUL=MF2 for the five byte vectors. Widening each MF2
	// source produces one M1 vector containing uint16 lanes.
	//
	// X14 receives the actual VL.
	VSETVLI	X12, E8, MF2, TA, MA, X14

	// Load VL groups of five bytes.
	VLSEG5E8V	(X11), V8

	// Advance input by 5*VL bytes.
	SLLI	$2, X14, X15
	ADD	X14, X15, X15
	ADD	X15, X11, X11

	// Widen b0..b4 from uint8 MF2 to uint16 M1.
	//
	// Only four result vectors are needed. V12 is widened later
	// when constructing y3.
	VWADDUVX	X0, V8, V16
	VWADDUVX	X0, V9, V17
	VWADDUVX	X0, V10, V18
	VWADDUVX	X0, V11, V19
	VWADDUVX	X0, V12, V20

	// Keep the same VL and switch to uint16 M1 arithmetic.
	VSETVLI	X14, E16, M1, TA, MA, X0

	// Inputs at this point:
	//
	//     V16 = b0
	//     V17 = b1
	//     V18 = b2
	//     V19 = b3
	//     V20 = b4

	// Preserve the original byte vectors needed by more than one
	// decoded coefficient.

	// y0 = b0 | ((b1 & 0x03) << 8)
	VANDVI	$3, V17, V24
	VSLLVI	$8, V24, V24
	VORVV	V24, V16, V16

	// y1 = (b1 >> 2) | ((b2 & 0x0f) << 6)
	VSRLVI	$2, V17, V17
	VANDVI	$15, V18, V24
	VSLLVI	$6, V24, V24
	VORVV	V24, V17, V17

	// y2 = (b2 >> 4) | ((b3 & 0x3f) << 4)
	//
	// VANDVI cannot directly encode 63. Instead:
	//
	//     ((b3 << 10) >> 6) == (b3 & 0x3f) << 4
	VSRLVI	$4, V18, V18
	VSLLVI	$10, V19, V24
	VSRLVI	$6, V24, V24
	VORVV	V24, V18, V18

	// y3 = (b3 >> 6) | (b4 << 2)
	VSRLVI	$6, V19, V19
	VSLLVI	$2, V20, V24
	VORVV	V24, V19, V19

	// Decompress all four unsigned 10-bit vectors.
	//
	// V24-V26 are shared temporaries. Each macro invocation
	// completes before the next invocation starts.
	DECOMPRESS_U10(V16, V24, V25, V26)
	DECOMPRESS_U10(V17, V24, V25, V26)
	DECOMPRESS_U10(V18, V24, V25, V26)
	DECOMPRESS_U10(V19, V24, V25, V26)

	// Store four uint16 values for each encoded five-byte group:
	//
	//     V16[0], V17[0], V18[0], V19[0],
	//     V16[1], V17[1], V18[1], V19[1], ...
	VSSEG4E16V	V16, (X10)

	// Four uint16 values consume eight bytes per group.
	SLLI	$3, X14, X15
	ADD	X15, X10, X10

	SUB	X14, X12, X12
	BNE	X12, X0, loop

done:
	RET
