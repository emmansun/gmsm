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

// nttMatRowVecMulRVV computes dst = vec[0]*matRow[0] + vec[1]*matRow[1] + ... + vec[len-1]*matRow[len-1]
// where each element is a polynomial in NTT domain.
// For each RVV chunk of the polynomial, all len products are
// accumulated in a register before writing to dst once.
TEXT ·nttMatRowVecMulRVV(SB), NOSPLIT, $0-32
	MOV dst+0(FP), X12
	MOV vec+8(FP), X10
	MOV matRow+16(FP), X11
	MOV len+24(FP), X13
	
	// Pinned constants.
	MOV $8380417, Q
	MOV $4236238847, QNEGINV
	MOV $1, ONE

	MOV $256, X14
	VSETVLI X14, E32, M2, TA, MA, X15

	MOV $1024, X19  // element size in bytes: 256*4

mvmChunkLoop:
	MOV X10, X17  // X17 = current vec chunk
	MOV X11, X18  // X18 = current matRow chunk

	VLE32V		(X17), V2
	VLE32V		(X18), V4

	MONT_MUL_HILO_VV(V2, V4, V6, V10, V12)

	SUB $1, X13, X24
	BEQZ X24, mvmWrite  // len == 1: skip accumulate loop

mvmAccumulate:
	ADD X19, X17, X17  // move to next chunk of vec
	ADD X19, X18, X18  // move to next chunk of matRow

	VLE32V		(X17), V2
	VLE32V		(X18), V4

	MONT_MUL_HILO_VV(V2, V4, V8, V10, V12)
	// accumulate in register (no memory round-trip)
	VADDVV V8, V6, V6
	REDUCE_ONCE_RVV(V6, V8)

	SUB $1, X24, X24
	BNEZ X24, mvmAccumulate

mvmWrite:
	// Write accumulated result to dst only once per chunk
	VSE32V		V6, (X12)

	SLL $2, X15, X25
	ADD X25, X10, X10
	ADD X25, X11, X11
	ADD X25, X12, X12

	SUB X15, X14, X14
	BNEZ X14, mvmChunkLoop

	RET

// Input:
//     va = a
//     vb = b
//
// Output:
//     va = a+t mod q
//     vb = a-t mod q
#define NTT_BUTTERFLY_VZ(va, vb, vz, vt, lo, m) \
	MONT_MUL_HILO_VV(vb, vz, vt, lo, m);                       \
	VSUBVV vt, va, vb;                                         \
	VADDVV vt, va, va;                                         \
	REDUCE_ONCE_RVV(va, m);                                    \
	VSRAVI $31, vb, m;                                         \
	VANDVX Q, m, m;                                            \
	VADDVV m, vb, vb	

// Input:
//     va = a
//     vb = b
//
// Output:
//     va = a+t mod q
//     vb = a-t mod q
#define NTT_BUTTERFLY_XZ(va, vb, zeta, vt, lo, m) \
	MONT_MUL_HILO_VX(vb, zeta, vt, lo, m);                     \
	VSUBVV vt, va, vb;                                         \
	VADDVV vt, va, va;                                         \
	REDUCE_ONCE_RVV(va, m);                                    \
	VSRAVI $31, vb, m;                                         \
	VANDVX Q, m, m;                                            \
	VADDVV m, vb, vb

//func internalNTTRVV(f *ringElement)
TEXT ·internalNTTRVV(SB), NOSPLIT, $0-8
	MOV f+0(FP), X10

	// Pinned constants.
	MOV $8380417, Q
	MOV $4236238847, QNEGINV
	MOV $1, ONE

	// Skip zetasMontgomery[0], matching the generic k=1 start.
	MOV $·zetasMontgomery(SB), X11
	ADD $4, X11, X11

	// len = 128, 64, 32, 16, 8.
	MOV $128, X12

ntt_rvv_level_loop:
		MOV $0, X13

ntt_rvv_group_loop: 
			MOVWU (X11), X14
			ADD $4, X11, X11

			// left = f + start*4, right = left + len*4.
			SLL $2, X13, X15
			ADD X10, X15, X16 // left offset
			SLL $2, X12, X17
			ADD X16, X17, X18 // right offset
			MOV X12, X19

ntt_rvv_chunk_loop:
				VSETVLI X19, E32, M1, TA, MA, X15

				VLE32V (X16), V2
				VLE32V (X18), V3
				NTT_BUTTERFLY_XZ(V2, V3, X14, V4, V6, V7)
				VSE32V V2, (X16)
				VSE32V V3, (X18)

				SLL $2, X15, X17  // multiply chunk index by element size (4 bytes)
				ADD X17, X16, X16
				ADD X17, X18, X18
				SUB X15, X19, X19
				BNEZ X19, ntt_rvv_chunk_loop

			// start += 2*len.
			SLL $1, X12, X15
			ADD X15, X13, X13
			MOV $256, X15
			BLT X13, X15, ntt_rvv_group_loop

		SRL $1, X12, X12
		MOV $8, X15
		BGE X12, X15, ntt_rvv_level_loop

	// len = 4. Each group is [a0 a1 a2 a3 b0 b1 b2 b3].
	MOV X10, X16
	MOV $32, X19  // total groups for len=4 loop

ntt_rvv_len4_loop:
		VSETVLI X19, E32, M1, TA, MA, X15
		VLE32V (X11), V10
		VLSEG8E32V (X16), V2  // load 8 elements from memory into vector registers V2-V9

		NTT_BUTTERFLY_VZ(V2, V6, V10, V11, V20, V21)
		NTT_BUTTERFLY_VZ(V3, V7, V10, V12, V20, V21)
		NTT_BUTTERFLY_VZ(V4, V8, V10, V13, V20, V21)
		NTT_BUTTERFLY_VZ(V5, V9, V10, V14, V20, V21)

		VSSEG8E32V V2, (X16)
		SLL $2, X15, X17
		ADD X17, X11, X11  // advance the zeta pointer for the next chunk (len=4)
		SLL $5, X15, X17
		ADD X17, X16, X16  // advance the memory pointer for the next chunk (len=4)
		// decrement the remaining chunk count
		SUB X15, X19, X19
		BNEZ X19, ntt_rvv_len4_loop

	// len = 2. Each group is [a0 a1 b0 b1].
	MOV X10, X16
	MOV $64, X19  // total groups for len=2 loop

ntt_rvv_len2_loop:
		VSETVLI X19, E32, M1, TA, MA, X15
		VLE32V (X11), V10
		VLSEG4E32V (X16), V2

		NTT_BUTTERFLY_VZ(V2, V4, V10, V11, V20, V21)
		NTT_BUTTERFLY_VZ(V3, V5, V10, V12, V20, V21)

		VSSEG4E32V V2, (X16)
		SLL $2, X15, X17
		ADD X17, X11, X11  // advance the zeta pointer for the next chunk (len=2)
		SLL $4, X15, X17
		ADD X17, X16, X16  // advance the memory pointer for the next chunk (len=2)
		// decrement the remaining chunk count
		SUB X15, X19, X19
		BNEZ X19, ntt_rvv_len2_loop

	// len = 1. Each group is [a0 b0].
	MOV X10, X16
	MOV $128, X19  // total groups for len=1 loop

ntt_rvv_len1_loop:
		VSETVLI X19, E32, M1, TA, MA, X15
		VLE32V (X11), V10
		VLSEG2E32V (X16), V2

		NTT_BUTTERFLY_VZ(V2, V3, V10, V11, V20, V21)

		VSSEG2E32V V2, (X16)
		SLL $2, X15, X17
		ADD X17, X11, X11  // advance the zeta pointer for the next chunk (len=1)
		SLL $3, X15, X17
		ADD X17, X16, X16  // advance the memory pointer for the next chunk (len=1)
		// decrement the remaining chunk count (len=1)
		SUB X15, X19, X19
		BNEZ X19, ntt_rvv_len1_loop

	RET

// Input:
// va = a, where 0 <= a < q
// vb = b, where 0 <= b < q
//
// Output:
// va = (a+b) mod q
// vb = zeta*(b-a)*R^-1 mod q
//
// Output coefficients are canonical residues in [0,q).
//
// Clobbers:
// diff, lo, m
#define INVNTT_BUTTERFLY_XZ(va, vb, zeta, diff, lo, m) \
	VSUBVV va, vb, diff;                                          \
	VADDVV vb, va, va;                                            \
	REDUCE_ONCE_RVV(va, m);                                       \
	VSRAVI $31, diff, m;                                          \
	VANDVX Q, m, m;                                               \
	VADDVV m, diff, diff;                                         \
	MONT_MUL_HILO_VX(diff, zeta, vb, lo, m)

// Input:
// va = a, where 0 <= a < q
// vb = b, where 0 <= b < q
//
// Output:
// va = (a+b) mod q
// vb = zeta*(b-a)*R^-1 mod q
//
// Output coefficients are canonical residues in [0,q).
//
// Clobbers:
// diff, lo, m
#define INVNTT_BUTTERFLY_VZ(va, vb, vz, diff, lo, m) \
	VSUBVV va, vb, diff;                                          \
	VADDVV vb, va, va;                                            \
	REDUCE_ONCE_RVV(va, m);                                       \
	VSRAVI $31, diff, m;                                          \
	VANDVX Q, m, m;                                               \
	VADDVV m, diff, diff;                                         \
	MONT_MUL_HILO_VV(diff, vz, vb, lo, m)

// internalInverseNTTRVV computes the inverse NTT using RVV instructions.
TEXT ·internalInverseNTTRVV(SB), NOSPLIT, $0-8
	MOV	f+0(FP), X10

	// Pinned Montgomery constants.
	MOV	$8380417, Q
	MOV	$4236238847, QNEGINV
	MOV	$1, ONE

	// Inverse twiddles are stored in the exact order they are consumed:
	//
	//	zetasMontgomeryInverse[0],
	//	zetasMontgomeryInverse[1],
	//	...
	//	zetasMontgomeryInverse[255].
	MOV	$·zetasMontgomeryInverse(SB), X11

	// len = 2
	// len = 1
	MOV	X10, X16
	MOV	$128, X19

invntt_level1_loop:
	VSETVLI X19, E32, M1, TA, MA, X15
	VLE32V	(X11), V10
	VLSEG2E32V (X16), V2

	INVNTT_BUTTERFLY_VZ(V2, V3, V10, V8, V20, V21)

	VSSEG2E32V V2, (X16)

	SLL	$2, X15, X17
	ADD	X17, X11, X11

	SLL	$3, X15, X17
	ADD	X17, X16, X16

	SUB	X15, X19, X19
	BNEZ	X19, invntt_level1_loop

	MOV	X10, X16
	MOV	$64, X19

invntt_level2_loop:
	VSETVLI X19, E32, M1, TA, MA, X15
	VLE32V	(X11), V10
	VLSEG4E32V (X16), V2

	INVNTT_BUTTERFLY_VZ(V2, V4, V10, V8, V20, V21)
	INVNTT_BUTTERFLY_VZ(V3, V5, V10, V9, V20, V21)

	VSSEG4E32V V2, (X16)

	SLL	$2, X15, X17
	ADD	X17, X11, X11

	SLL	$4, X15, X17
	ADD	X17, X16, X16

	SUB	X15, X19, X19
	BNEZ	X19, invntt_level2_loop

	// len = 4
	MOV	X10, X16
	MOV	$32, X19

invntt_level4_loop:
	VSETVLI X19, E32, M1, TA, MA, X15
	VLE32V	(X11), V10
	VLSEG8E32V (X16), V2

	INVNTT_BUTTERFLY_VZ(V2, V6, V10, V15, V20, V21)
	INVNTT_BUTTERFLY_VZ(V3, V7, V10, V16, V20, V21)
	INVNTT_BUTTERFLY_VZ(V4, V8, V10, V17, V20, V21)
	INVNTT_BUTTERFLY_VZ(V5, V9, V10, V18, V20, V21)

	VSSEG8E32V V2, (X16)

	SLL	$2, X15, X17
	ADD	X17, X11, X11

	SLL	$5, X15, X17
	ADD	X17, X16, X16

	SUB	X15, X19, X19
	BNEZ	X19, invntt_level4_loop

	// Generic levels:
	//
	//	len = 8, 16, 32, 64, 128
	//
	// For these levels, one whole butterfly row is processed in a
	// strip-mined unit-stride loop.
	MOV	$8, X12

invntt_level_loop:
	MOV	$0, X13

invntt_start_loop:
	MOVWU	(X11), X14
	ADD	$4, X11, X11

	// leftPtr = f + start*4
	SLL	$2, X13, X15
	ADD	X10, X15, X16

	// rightPtr = leftPtr + len*4
	SLL	$2, X12, X17
	ADD	X16, X17, X18

	MOV	X12, X19

invntt_chunk_loop:
	VSETVLI X19, E32, M1, TA, MA, X15

	VLE32V	(X16), V2
	VLE32V	(X18), V3

	INVNTT_BUTTERFLY_XZ(V2, V3, X14, V5, V6, V7)

	VSE32V	V2, (X16)
	VSE32V	V3, (X18)

	SLL	$2, X15, X17
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

	// Final scale by invDegreeMontgomery = 41978.
	MOV	$41978, X14
	MOV	$256, X19
	MOV	X10, X16

invntt_scale_loop:
	VSETVLI X19, E32, M1, TA, MA, X15

	VLE32V	(X16), V2
	MONT_MUL_HILO_VX(V2, X14, V2, V6, V7)
	VSE32V	V2, (X16)

	SLL	$2, X15, X17
	ADD	X17, X16, X16

	SUB	X15, X19, X19
	BNEZ	X19, invntt_scale_loop

	RET

// func decomposeSubToR0Gamma32RVV(w, cs2 *fieldElement, out *int32)
TEXT ·decomposeSubToR0Gamma32RVV(SB), NOSPLIT, $0-24
	MOV	w+0(FP), X10
	MOV	cs2+8(FP), X11
	MOV	out+16(FP), X12

	MOV	$8380417, Q       // q
	MOV	$127, X14         // plus127
	MOV	$1025, X16        // decomposeMul1025
	MOV	$2097152, X17     // 2^21
	MOV	$15, X18          // decomposeMask15
	MOV	$523776, X19      // decompose2Gamma32 = 2*((q-1)/32)
	MOV	$4190208, X24     // qMinus1Div2
	MOV	$256, X13

decompose32_rvv_loop:
	VSETVLI	X13, E32, M1, TA, MA, X15

	// x = fieldSub(w, cs2).
	VLE32V	(X10), V2
	VLE32V	(X11), V3
	VSUBVV	V3, V2, V2
	VSRAVI	$31, V2, V4
	VANDVX	Q, V4, V4
	VADDVV	V4, V2, V2

	// r1 = ((((x + 127) >> 7) * 1025) + 2^21) >> 22; r1 &= 15.
	VADDVX	X14, V2, V5
	VSRAVI	$7, V5, V5
	VMULVX	X16, V5, V5
	VADDVX	X17, V5, V5
	VSRAVI	$22, V5, V5
	VANDVX	X18, V5, V5

	// r0 = x - r1*(2*gamma2), then center-lift around q/2.
	VMULVX	X19, V5, V6
	VSUBVV	V6, V2, V6
	VRSUBVX	X24, V6, V7
	VSRAVI	$31, V7, V7
	VANDVX	Q, V7, V7
	VSUBVV	V7, V6, V6
	VSE32V	V6, (X12)

	SLL	$2, X15, X25
	ADD	X25, X10, X10
	ADD	X25, X11, X11
	ADD	X25, X12, X12
	SUB	X15, X13, X13
	BNEZ	X13, decompose32_rvv_loop
	RET

// func decomposeSubToR0Gamma88RVV(w, cs2 *fieldElement, out *int32)
TEXT ·decomposeSubToR0Gamma88RVV(SB), NOSPLIT, $0-24
	MOV	w+0(FP), X10
	MOV	cs2+8(FP), X11
	MOV	out+16(FP), X12

	MOV	$8380417, Q       // q
	MOV	$127, X14         // plus127
	MOV	$11275, X16       // decomposeMul11275
	MOV	$8388608, X17     // 2^23
	MOV	$43, X18          // decomposeConst43
	MOV	$190464, X19      // decompose2Gamma88 = 2*((q-1)/88)
	MOV	$4190208, X24     // qMinus1Div2
	MOV	$256, X13

decompose88_rvv_loop:
	VSETVLI	X13, E32, M1, TA, MA, X15

	// x = fieldSub(w, cs2).
	VLE32V	(X10), V2
	VLE32V	(X11), V3
	VSUBVV	V3, V2, V2
	VSRAVI	$31, V2, V4
	VANDVX	Q, V4, V4
	VADDVV	V4, V2, V2

	// r1 = ((((x + 127) >> 7) * 11275) + 2^23) >> 24.
	VADDVX	X14, V2, V5
	VSRAVI	$7, V5, V5
	VMULVX	X16, V5, V5
	VADDVX	X17, V5, V5
	VSRAVI	$24, V5, V5

	// Clamp r1 == 44 to zero: r1 ^= ((43-r1) >> 31) & r1.
	VRSUBVX	X18, V5, V7
	VSRAVI	$31, V7, V7
	VANDVV	V5, V7, V7
	VXORVV	V7, V5, V5

	// r0 = x - r1*(2*gamma2), then center-lift around q/2.
	VMULVX	X19, V5, V6
	VSUBVV	V6, V2, V6
	VRSUBVX	X24, V6, V7
	VSRAVI	$31, V7, V7
	VANDVX	Q, V7, V7
	VSUBVV	V7, V6, V6
	VSE32V	V6, (X12)

	SLL	$2, X15, X25
	ADD	X25, X10, X10
	ADD	X25, X11, X11
	ADD	X25, X12, X12
	SUB	X15, X13, X13
	BNEZ	X13, decompose88_rvv_loop
	RET

// func useHintPolyGamma32RVV(h, r *fieldElement, out *fieldElement)
TEXT ·useHintPolyGamma32RVV(SB), NOSPLIT, $0-24
	MOV	h+0(FP), X10
	MOV	r+8(FP), X11
	MOV	out+16(FP), X12

	MOV	$8380417, Q       // q
	MOV	$127, X14         // plus127
	MOV	$1025, X16        // decomposeMul1025
	MOV	$2097152, X17     // 2^21
	MOV	$15, X18          // modulus mask
	MOV	$523776, X19      // 2*gamma2
	MOV	$4190208, X24     // qMinus1Div2
	MOV	$256, X13

usehint32_rvv_loop:
	VSETVLI X13, E32, M1, TA, MA, X15

	// Load h and r before storing, allowing exact output aliasing.
	VLE32V	(X10), V2
	VLE32V	(X11), V3

	// r1 = ((((r + 127) >> 7) * 1025) + 2^21) >> 22; r1 &= 15.
	VADDVX	X14, V3, V4
	VSRAVI	$7, V4, V4
	VMULVX	X16, V4, V4
	VADDVX	X17, V4, V4
	VSRAVI	$22, V4, V4
	VANDVX	X18, V4, V4

	// r0 = r - r1*(2*gamma2), then center-lift around q/2.
	VMULVX	X19, V4, V5
	VSUBVV	V5, V3, V5
	VRSUBVX	X24, V5, V6
	VSRAVI	$31, V6, V6
	VANDVX	Q, V6, V6
	VSUBVV	V6, V5, V5

	// delta = h ? (r0 > 0 ? 1 : 15) : 0.
	VRSUBVX	ZERO, V5, V6
	VSRAVI	$31, V6, V6       // posMask = 0xffffffff when r0 > 0
	VANDVI	$14, V6, V6
	VXORVI	$15, V6, V6       // deltaBase = 1 or 15
	VRSUBVX	ZERO, V2, V7     // hMask = 0 - h
	VANDVV	V7, V6, V6

	VADDVV	V6, V4, V4
	VANDVX	X18, V4, V4
	VSE32V	V4, (X12)

	SLL	$2, X15, X25
	ADD	X25, X10, X10
	ADD	X25, X11, X11
	ADD	X25, X12, X12
	SUB	X15, X13, X13
	BNEZ	X13, usehint32_rvv_loop
	RET

// func useHintPolyGamma88RVV(h, r *fieldElement, out *fieldElement)
TEXT ·useHintPolyGamma88RVV(SB), NOSPLIT, $0-24
	MOV	h+0(FP), X10
	MOV	r+8(FP), X11
	MOV	out+16(FP), X12

	MOV	$8380417, Q       // q
	MOV	$127, X14         // plus127
	MOV	$11275, X16       // decomposeMul11275
	MOV	$8388608, X17     // 2^23
	MOV	$43, X18          // modulus / high-bit limit
	MOV	$190464, X19      // 2*gamma2
	MOV	$4190208, X24     // qMinus1Div2
	MOV	$42, X23          // modulus / high-bit limit - 1
	MOV	$44, X5          // raw r1 clamp value
	MOV	$256, X13

usehint88_rvv_loop:
	VSETVLI X13, E32, M1, TA, MA, X15

	// Load h and r before storing, allowing exact output aliasing.
	VLE32V	(X10), V2
	VLE32V	(X11), V3

	// r1 = ((((r + 127) >> 7) * 11275) + 2^23) >> 24.
	VADDVX	X14, V3, V4
	VSRAVI	$7, V4, V4
	VMULVX	X16, V4, V4
	VADDVX	X17, V4, V4
	VSRAVI	$24, V4, V4

	// Clamp raw r1 == 44 to zero.
	VRSUBVX	X18, V4, V6
	VSRAVI	$31, V6, V6
	VANDVV	V4, V6, V6
	VXORVV	V6, V4, V4

	// r0 = r - r1*(2*gamma2), then center-lift around q/2.
	VMULVX	X19, V4, V5
	VSUBVV	V5, V3, V5
	VRSUBVX	X24, V5, V6
	VSRAVI	$31, V6, V6
	VANDVX	Q, V6, V6
	VSUBVV	V6, V5, V5

	// delta = h ? (r0 > 0 ? 1 : 43) : 0.
	VRSUBVX	ZERO, V5, V6
	VSRAVI	$31, V6, V6       // posMask = 0xffffffff when r0 > 0
	VANDVX	X23, V6, V6
	VXORVX	X18, V6, V6       // deltaBase = 1 or 43
	VRSUBVX	ZERO, V2, V7     // hMask = 0 - h
	VANDVV	V7, V6, V6

	VADDVV	V6, V4, V4
	VRSUBVX	X18, V4, V7
	VSRAVI	$31, V7, V7
	VANDVX	X5, V7, V7
	VSUBVV	V7, V4, V4
	VSE32V	V4, (X12)

	SLL	$2, X15, X25
	ADD	X25, X10, X10
	ADD	X25, X11, X11
	ADD	X25, X12, X12
	SUB	X15, X13, X13
	BNEZ	X13, usehint88_rvv_loop
	RET

// func makeHintPolyGamma32RVV(ct0, cs2, w, hint *fieldElement)
TEXT ·makeHintPolyGamma32RVV(SB), NOSPLIT, $0-32
	MOV	ct0+0(FP), X10
	MOV	cs2+8(FP), X11
	MOV	w+16(FP), X12
	MOV	hint+24(FP), X13

	MOV	$8380417, Q       // q
	MOV	$127, X14         // plus127
	MOV	$1025, X16        // decomposeMul1025
	MOV	$2097152, X17     // 2^21
	MOV	$15, X18          // modulus mask
	MOV	$256, X24

makehint32_rvv_loop:
	VSETVLI X24, E32, M1, TA, MA, X15

	// rPlusZ = fieldSub(w, cs2); r = fieldAdd(rPlusZ, ct0).
	VLE32V	(X10), V2
	VLE32V	(X11), V3
	VLE32V	(X12), V4
	VSUBVV	V3, V4, V4
	VSRAVI	$31, V4, V8
	VANDVX	Q, V8, V8
	VADDVV	V8, V4, V4
	VADDVV	V2, V4, V5
	REDUCE_ONCE_RVV(V5, V8)

	// HighBitsGamma32(rPlusZ).
	VADDVX	X14, V4, V6
	VSRLVI	$7, V6, V6
	VMULVX	X16, V6, V6
	VADDVX	X17, V6, V6
	VSRLVI	$22, V6, V6
	VANDVX	X18, V6, V6

	// HighBitsGamma32(r).
	VADDVX	X14, V5, V7
	VSRLVI	$7, V7, V7
	VMULVX	X16, V7, V7
	VADDVX	X17, V7, V7
	VSRLVI	$22, V7, V7
	VANDVX	X18, V7, V7

	// hint = HighBits(rPlusZ) != HighBits(r), converted to 0/1.
	VMSNEVV	V6, V7, V0
	VMVVI	$0, V8
	VMERGEVIM	$1, V8, V0, V8
	VSE32V	V8, (X13)

	SLL	$2, X15, X25
	ADD	X25, X10, X10
	ADD	X25, X11, X11
	ADD	X25, X12, X12
	ADD	X25, X13, X13
	SUB	X15, X24, X24
	BNEZ	X24, makehint32_rvv_loop
	RET

// func makeHintPolyGamma88RVV(ct0, cs2, w, hint *fieldElement)
TEXT ·makeHintPolyGamma88RVV(SB), NOSPLIT, $0-32
	MOV	ct0+0(FP), X10
	MOV	cs2+8(FP), X11
	MOV	w+16(FP), X12
	MOV	hint+24(FP), X13

	MOV	$8380417, Q       // q
	MOV	$127, X14         // plus127
	MOV	$11275, X16       // decomposeMul11275
	MOV	$8388608, X17     // 2^23
	MOV	$43, X18          // HighBits upper limit
	MOV	$256, X24

makehint88_rvv_loop:
	VSETVLI X24, E32, M1, TA, MA, X15

	// rPlusZ = fieldSub(w, cs2); r = fieldAdd(rPlusZ, ct0).
	VLE32V	(X10), V2
	VLE32V	(X11), V3
	VLE32V	(X12), V4
	VSUBVV	V3, V4, V4
	VSRAVI	$31, V4, V8
	VANDVX	Q, V8, V8
	VADDVV	V8, V4, V4
	VADDVV	V2, V4, V5
	REDUCE_ONCE_RVV(V5, V8)

	// HighBitsGamma88(rPlusZ), including raw r1 == 44 -> 0.
	VADDVX	X14, V4, V6
	VSRLVI	$7, V6, V6
	VMULVX	X16, V6, V6
	VADDVX	X17, V6, V6
	VSRLVI	$24, V6, V6
	VRSUBVX	X18, V6, V8
	VSRAVI	$31, V8, V8
	VANDVV	V6, V8, V8
	VXORVV	V8, V6, V6

	// HighBitsGamma88(r), including raw r1 == 44 -> 0.
	VADDVX	X14, V5, V7
	VSRLVI	$7, V7, V7
	VMULVX	X16, V7, V7
	VADDVX	X17, V7, V7
	VSRLVI	$24, V7, V7
	VRSUBVX	X18, V7, V8
	VSRAVI	$31, V8, V8
	VANDVV	V7, V8, V8
	VXORVV	V8, V7, V7

	// hint = HighBits(rPlusZ) != HighBits(r), converted to 0/1.
	VMSNEVV	V6, V7, V0
	VMVVI	$0, V8
	VMERGEVIM	$1, V8, V0, V8
	VSE32V	V8, (X13)

	SLL	$2, X15, X25
	ADD	X25, X10, X10
	ADD	X25, X11, X11
	ADD	X25, X12, X12
	ADD	X25, X13, X13
	SUB	X15, X24, X24
	BNEZ	X24, makehint88_rvv_loop
	RET

// func polyInfinityNormRVV(a *fieldElement) uint32
TEXT ·polyInfinityNormRVV(SB), NOSPLIT, $0-12
	MOV	a+0(FP), X10
	MOV	$8380417, Q
	MOV	$256, X13
	MOV	$0, X24

	// Reduce each chunk and keep the global maximum in X24.

poly_inf_norm_rvv_loop:
	VSETVLI X13, E32, M4, TA, MA, X14
	VLE32V	(X10), V4

	VRSUBVX	Q, V4, V8
	VMINUVV	V8, V4, V4
	VMVVI	$0, V16
	VREDMAXUVS	V16, V4, V20
	VMVXS	V20, X15
	SLTU	X24, X15, X16
	SUB	ZERO, X16, X16
	XOR	X24, X15, X17
	AND	X16, X17, X17
	XOR	X17, X24, X24

	SLL	$2, X14, X15
	ADD	X15, X10, X10
	SUB	X14, X13, X13
	BNEZ	X13, poly_inf_norm_rvv_loop

	MOVW	X24, ret+8(FP)
	RET

// func polyInfinityNormSignedRVV(a *int32) uint32
TEXT ·polyInfinityNormSignedRVV(SB), NOSPLIT, $0-12
	MOV	a+0(FP), X10
	MOV	$256, X13
	MOV	$0, X24

	// Reduce each chunk and keep the global maximum in X24.

poly_inf_norm_signed_rvv_loop:
	VSETVLI X13, E32, M4, TA, MA, X14
	VLE32V	(X10), V4

	// abs(x) = (x ^ (x >> 31)) - (x >> 31).
	VSRAVI	$31, V4, V8
	VXORVV	V8, V4, V4
	VSUBVV	V8, V4, V4
	VMVVI	$0, V16
	VREDMAXUVS	V16, V4, V20
	VMVXS	V20, X15
	SLTU	X24, X15, X16
	SUB	ZERO, X16, X16
	XOR	X24, X15, X17
	AND	X16, X17, X17
	XOR	X17, X24, X24

	SLL	$2, X14, X15
	ADD	X15, X10, X10
	SUB	X14, X13, X13
	BNEZ	X13, poly_inf_norm_signed_rvv_loop

	MOVW	X24, ret+8(FP)
	RET
