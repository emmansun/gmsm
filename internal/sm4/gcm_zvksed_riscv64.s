// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.27 && !purego

#include "textflag.h"

#define ZERO X0
#define RSP X2

#define B0 V1
#define B1 V2
#define B2 V3
#define B3 V4
#define B4 V5
#define B5 V6
#define B6 V7
#define B7 V8

#define ACC0 V9
#define ACC1 V10
#define ACCML V11
#define ACCMH V12

#define XPOLY X15
#define SHUFFLE_MASK V25
#define T0 V26
#define T1 V27
#define T2 V28
#define T3 V29

DATA gcmPoly<>+0x00(SB)/8, $0x0000000000000001
DATA gcmPoly<>+0x08(SB)/8, $0xc200000000000000
GLOBL gcmPoly<>(SB), (NOPTR+RODATA), $16

// VSM4R_VS performs vsm4r.vs Vd, Vs2
// OP-P(0x77) | funct6=101001,vm=1 → 0x53 | vs2[24:20] | vs1=10000 | funct3=010 | vd
#define VSM4R_VS(Vd, Vs2) \
	WORD $((0x53 << 25) | ((Vs2) << 20) | (0x10 << 15) | (2 << 12) | ((Vd) << 7) | 0x77)

#define stackaddress(index) ((index)*8+8)(RSP) // for RISCV64 stack usage, we CAN NOT overwrite the first 8 bytes space!

// func gcmSm4Init(productTable *[256]byte, rk []uint32)
TEXT ·gcmSm4Init(SB),NOSPLIT,$0
#define dst X10
#define RK X11

	MOV productTable+0(FP), dst
	MOV rk+8(FP), RK

	MOV $gcmPoly<>(SB), X12

	// Encrypt block 0, with the sm4 round keys to generate the hash key H
	VSETIVLI	$4, E32, M1, TA, MA, X0
	VXORVV V4, V4, V4

	VLE32V	(RK), V16
	ADD	$16, RK, X14
	VLE32V	(X14), V17
	ADD	$16, X14
	VLE32V	(X14), V18
	ADD	$16, X14
	VLE32V	(X14), V19
	ADD	$16, X14
	VLE32V	(X14), V20
	ADD	$16, X14
	VLE32V	(X14), V21
	ADD	$16, X14
	VLE32V	(X14), V22
	ADD	$16, X14
	VLE32V	(X14), V23

	VSM4R_VS(4, 16) // VSM4RVS	V16, V4
	VSM4R_VS(4, 17) // VSM4RVS	V17, V4
	VSM4R_VS(4, 18) // VSM4RVS	V18, V4
	VSM4R_VS(4, 19) // VSM4RVS	V19, V4
	VSM4R_VS(4, 20) // VSM4RVS	V20, V4
	VSM4R_VS(4, 21) // VSM4RVS	V21, V4
	VSM4R_VS(4, 22) // VSM4RVS	V22, V4
	VSM4R_VS(4, 23) // VSM4RVS	V23, V4

	// H * 2
	VSLLVI $1, V4, V2
	VSRLVI $31, V4, V3
	VSLIDE1UPVX ZERO, V3, V1
	VORVV V2, V1, V2
	VSRAVI $31, V4, V3  // V3[3] = 0xFFFFFFFF or 0x0
	VSLIDEDOWNVI $3, V3, V1 // V1[0] = V3[3]
	VMVXS V1, X15
	VLE32V (X12), V3
	VANDVX X15, V3, V3
	VORVV V2, V3, V1

	// Now prepare powers of H and pre-computations for them
	VSETIVLI	$2, E64, M1, TA, MA, X0
	VIDV V10               // V10 = [0, 1]
	VRSUBVI $1, V10, V10    // V10 = [1, 0]

	// Karatsuba pre-computations
	VRGATHERVV V10, V1, V2
	VXORVV V1, V2, V2

	ADD $240, dst, X14
	VSE64V V2, (X14)
	SUB $16, X14, X14
	VSE64V V1, (X14)

	MOV gcmPoly<>+0x08(SB), X15
	VMVVV V1, V3
	VMVVV V2, V4

initLoop:
		VCLMULVV V1, V3, V5    // LOW(V1 * V3) = [C0, D0]
		VCLMULHVV V1, V3, V6   // HIGH(V1 * V3) = [C1, D1]
		VCLMULVV V2, V4, V7    // LOW(V2 * V4) = [E0, F0]
		VCLMULHVV V2, V4, V8   // HIGH(V2 * V4) = [E1, F1]

		VXORVV V5, V6, V3        // [C0 ^ C1, D0 ^ D1]
		VXORVV V3, V7, V7        // [C0 ^ C1 ^ E0, D0 ^ D1 ^ F0]
		VSLIDEDOWNVI $1, V5, V4  // [D1, 0]
		VXORVV V4, V7, V7        // [C0 ^ C1 ^ E0 ^ D1, D0 ^ D1 ^ F0 ^ 0]
		VSLIDEUPVI $1, V7, V5    // [C0, C0 ^ C1 ^ E0 ^ D1]

		VSLIDEDOWNVI $1, V3, V3  // [D0 ^ D1, 0]
		VXORVV V3, V8, V8        // [D0 ^ D1 ^ E1, 0]
		VXORVV V6, V8, V8        // [D0 ^ D1 ^ E1 ^ C1, 0]
		VSLIDEDOWNVI $1, V6, V6  // [D1, 0]
		VSLIDEUPVI $1, V6, V8  // result = [V5, V8] = [C0, C0 ^ C1 ^ E0 ^ D1, D0 ^ D1 ^ E1 ^ C1, D1]

		// Fast reduction
		// 1st reduction
		VCLMULVX X15, V5, V3
		VCLMULHVX X15, V5, V4
		VSLIDEUPVI $1, V4, V3
		VRGATHERVV V10, V5, V4
		VXORVV V3, V4, V5
		// 2nd reduction
		VCLMULVX X15, V5, V3
		VCLMULHVX X15, V5, V4
		VSLIDEUPVI $1, V4, V3
		VRGATHERVV V10, V5, V4
		VXORVV V3, V4, V5
		VXORVV V5, V8, V3

		VRGATHERVV V10, V3, V4
		VXORVV V3, V4, V4

		SUB $16, X14, X14
		VSE64V V4, (X14)
		SUB $16, X14, X14
		VSE64V V3, (X14)

	BNE dst, X14, initLoop
	RET

// func gcmSm4Data(productTable *[256]byte, data []byte, T *[16]byte)
TEXT ·gcmSm4Data(SB),NOSPLIT,$0
#define pTbl X10
#define aut X11
#define tPtr X12
#define autLen X13

#define reduceRound(a) \
	VCLMULVX XPOLY, a, T0; \
	VCLMULHVX XPOLY, a, ACCMH; \
	VSLIDEUPVI $1, ACCMH, T0; \
	\
	VSLIDEDOWNVI $1, a, ACCMH; \
	VSLIDEUPVI $1, a, ACCMH; \
	VXORVV T0, ACCMH, a

#define mulRoundAAD(X ,i) \
	VREV8V X, T0; \
	VRGATHERVV SHUFFLE_MASK, T0, X; \
	VXORVV X, T0, T0; \
	\
	ADD $(16*(i*2)), pTbl, X14; \
	VLE64V (X14), T1; \
	VCLMULVV X, T1, T2; \
	VXORVV T2, ACC0, ACC0; \
	VCLMULHVV X, T1, T2;  \
	VXORVV T2, ACC1, ACC1; \
	\
	ADD $16, X14; \
	VLE64V (X14), T1; \
	VCLMULVV T0, T1, T2; \
	VXORVV T2, ACCML, ACCML; \
	VCLMULHVV T0, T1, T2;  \
	VXORVV T2, ACCMH, ACCMH

	MOV productTable+0(FP), pTbl
	MOV data_base+8(FP), aut
	MOV data_len+16(FP), autLen
	MOV T+32(FP), tPtr

	BEQZ autLen, dataBail

	VSETIVLI	$2, E64, M1, TA, MA, X0
	VLE64V (tPtr), ACC0                       // Load the original tag
	VIDV SHUFFLE_MASK                         // SHUFFLE_MASK = [0, 1]
	VRSUBVI $1, SHUFFLE_MASK, SHUFFLE_MASK    // SHUFFLE_MASK = [1, 0]
	MOV gcmPoly<>+0x08(SB), XPOLY

	MOV $13, X8
	BEQ autLen, X8, dataTLS
	MOV $128, X8
	BLT autLen, X8, startSinglesLoop
	JMP dataOctaLoop

dataTLS:
	ADD $224, pTbl, X8
	VLE64V (X8), T1
	ADD $16, X8, X8
	VLE64V (X8), T2
	MOV (aut), X9
	VMVSX X9, B0
	ADD $5, aut
	MOV (aut), X9
	SRL $24, X9
	VMVSX X9, B1
	VSLIDEUPVI $1, B1, B0
	XOR autLen, autLen
	JMP dataMul

dataOctaLoop:
		BLT autLen, X8, startSinglesLoop
		SUB $128, autLen, autLen

		VLE64V (aut), B0
		ADD $16, aut, aut
		VLE64V (aut), B1
		ADD $16, aut, aut
		VLE64V (aut), B2
		ADD $16, aut, aut
		VLE64V (aut), B3
		ADD $16, aut, aut
		VLE64V (aut), B4
		ADD $16, aut, aut
		VLE64V (aut), B5
		ADD $16, aut, aut
		VLE64V (aut), B6
		ADD $16, aut, aut
		VLE64V (aut), B7
		ADD $16, aut, aut

		VREV8V B0, T0
		VRGATHERVV SHUFFLE_MASK, T0, B0
		VXORVV ACC0, B0, B0

		VSLIDEDOWNVI $1, B0, T0
		VXORVV B0, T0, T0

		VLE64V (pTbl), T1
		ADD $16, pTbl, X9
		VLE64V (X9), T2

		VCLMULVV B0, T1, ACC0       // LOW(B0 * T1) = [C0, D0]
		VCLMULHVV B0, T1, ACC1      // HIGH(B0 * T1) = [C1, D1]
		VCLMULVV T0, T2, ACCML      // LOW(T0 * T2) = [E0, F0]
		VCLMULHVV T0, T2, ACCMH     // HIGH(T0 * T2) = [E1, F1]

		mulRoundAAD(B1, 1)
		mulRoundAAD(B2, 2)
		mulRoundAAD(B3, 3)
		mulRoundAAD(B4, 4)
		mulRoundAAD(B5, 5)
		mulRoundAAD(B6, 6)
		mulRoundAAD(B7, 7)

		VXORVV ACC0, ACC1, T0       // [C0 ^ C1, D0 ^ D1]
		VXORVV T0, ACCML, ACCML     // [C0 ^ C1 ^ E0, D0 ^ D1 ^ F0]
		VSLIDEDOWNVI $1, T0, T0     // [D0 ^ D1, 0]
		VXORVV T0, ACCMH, ACCMH     // [D0 ^ D1 ^ E1, *]

		VSLIDEDOWNVI $1, ACC0, T0   // [D1, 0]
		VXORVV T0, ACCML, ACCML     // [C0 ^ C1 ^ E0 ^ D1, *]
		VSLIDEUPVI $1, ACCML, ACC0	// [C0, C0 ^ C1 ^ E0 ^ D1]

		VSLIDEDOWNVI $1, ACC1, T0   // [D1, 0]
		VXORVV ACC1, ACCMH, ACC1    // [C1 ^ D0 ^ D1 ^ E1, *]
		VSLIDEUPVI $1, T0, ACC1     // [C1 ^ D0 ^ D1 ^ E1, D1] 

		// Fast reduction
		// 1st reduction
        reduceRound(ACC0)
		// 2nd reduction
        reduceRound(ACC0)
		VXORVV ACC0, ACC1, ACC0

	JMP dataOctaLoop

startSinglesLoop:
	ADD $224, pTbl, X8
	VLE64V (X8), T1
	ADD $16, X8, X8
	VLE64V (X8), T2

dataSinglesLoop:
		MOV $16, X8
		BLT autLen, X8, dataEnd
		SUB $16, autLen, autLen
		VLE64V (aut), B0
		ADD $16, aut, aut

dataMul:
		VREV8V B0, T0
		VRGATHERVV SHUFFLE_MASK, T0, B0
		VXORVV ACC0, B0, B0

		VSLIDEDOWNVI $1, B0, T0
		VXORVV B0, T0, T0

		VCLMULVV B0, T1, ACC0       // LOW(B0 * T1) = [C0, D0]
		VCLMULHVV B0, T1, ACC1      // HIGH(B0 * T1) = [C1, D1]
		VCLMULVV T0, T2, ACCML      // LOW(T0 * T2) = [E0, F0]
		VCLMULHVV T0, T2, ACCMH     // HIGH(T0 * T2) = [E1, F1]

		VXORVV ACC0, ACC1, T0       // [C0 ^ C1, D0 ^ D1]
		VXORVV T0, ACCML, ACCML     // [C0 ^ C1 ^ E0, D0 ^ D1 ^ F0]
		VSLIDEDOWNVI $1, T0, T0     // [D0 ^ D1, 0]
		VXORVV T0, ACCMH, ACCMH     // [D0 ^ D1 ^ E1, *]

		VSLIDEDOWNVI $1, ACC0, T0   // [D0, 0]
		VXORVV T0, ACCML, ACCML     // [C0 ^ C1 ^ E0 ^ D0, *]
		VSLIDEUPVI $1, ACCML, ACC0	// [C0, C0 ^ C1 ^ E0 ^ D0]

		VSLIDEDOWNVI $1, ACC1, T0   // [D1, 0]
		VXORVV ACC1, ACCMH, ACC1    // [C1 ^ D0 ^ D1 ^ E1, *]
		VSLIDEUPVI $1, T0, ACC1     // [C1 ^ D0 ^ D1 ^ E1, D1] 

		// Fast reduction
		// 1st reduction
		reduceRound(ACC0)
		// 2nd reduction
		reduceRound(ACC0)
		VXORVV ACC0, ACC1, ACC0

	JMP dataSinglesLoop

dataEnd:
	BEQZ autLen, dataBail
	VXORVV B0, B0, B0
	XOR X8, X8   // High 64 bits
	XOR X9, X9   // Low 64 bits
	XOR X14, X14 // Shift accumulator for partial byte loads
	MOV $8, X21

	BGE autLen, X21, dataLoadGT8

dataLoadLoopLess8:
		MOVBU (aut), X22
		SLL X14, X22, X22
		OR X22, X9, X9
		SUB $1, autLen, autLen
		ADD $1, aut, aut
		ADD $8, X14, X14
		BNEZ autLen, dataLoadLoopLess8

	JMP dataLoadDone

dataLoadGT8:
	MOV (aut), X9
	ADD $8, aut, aut
	SUB $8, autLen, autLen

dataLoadLoopHigh8:
		BEQZ autLen, dataLoadDone
		MOVBU (aut), X22
		SLL X14, X22, X22
		OR X22, X8, X8
		SUB $1, autLen, autLen
		ADD $1, aut, aut
		ADD $8, X14, X14

	JMP dataLoadLoopHigh8

dataLoadDone:
	VMVSX X9, B0
	VMVSX X8, B1
	VSLIDEUPVI $1, B1, B0

	JMP dataMul

dataBail:
	VSE64V ACC0, (tPtr)
	RET
#undef pTbl
#undef aut
#undef tPtr
#undef autLen

// func gcmSm4Finish(productTable *[256]byte, tagMask, T *[16]byte, pLen, dLen uint64)
TEXT ·gcmSm4Finish(SB),NOSPLIT,$0
#define pTbl X8
#define tMsk X9
#define tPtr X10
#define plen X11
#define dlen X12

	MOV productTable+0(FP), pTbl
	MOV tagMask+8(FP), tMsk
	MOV T+16(FP), tPtr
	MOV pLen+24(FP), plen
	MOV dLen+32(FP), dlen

	MOV gcmPoly<>+0x08(SB), XPOLY
	VSETIVLI	$2, E64, M1, TA, MA, X0
	VLE64V (tPtr), ACC0

	SLL $3, plen
	SLL $3, dlen
	VMVSX plen, B0
	VMVSX dlen, B1
	VSLIDEUPVI $1, B1, B0
	VXORVV ACC0, B0, B0

	ADD $224, pTbl, X13
	VLE64V (X13), T1
	ADD $16, X13, X13
	VLE64V (X13), T2

	VSLIDEDOWNVI $1, B0, T0
	VXORVV B0, T0, T0

	VCLMULVV B0, T1, ACC0       // LOW(B0 * T1) = [C0, D0]
	VCLMULHVV B0, T1, ACC1      // HIGH(B0 * T1) = [C1, D1]
	VCLMULVV T0, T2, ACCML      // LOW(T0 * T2) = [E0, F0]
	VCLMULHVV T0, T2, ACCMH     // HIGH(T0 * T2) = [E1, F1]

	VXORVV ACC0, ACC1, T0       // [C0 ^ C1, D0 ^ D1]
	VXORVV T0, ACCML, ACCML     // [C0 ^ C1 ^ E0, D0 ^ D1 ^ F0]
	VSLIDEDOWNVI $1, T0, T0     // [D0 ^ D1, 0]
	VXORVV T0, ACCMH, ACCMH     // [D0 ^ D1 ^ E1, *]

	VSLIDEDOWNVI $1, ACC0, T0   // [D0, 0]
	VXORVV T0, ACCML, ACCML     // [C0 ^ C1 ^ E0 ^ D0, *]
	VSLIDEUPVI $1, ACCML, ACC0	// [C0, C0 ^ C1 ^ E0 ^ D0]

	VSLIDEDOWNVI $1, ACC1, T0   // [D1, 0]
	VXORVV ACC1, ACCMH, ACC1    // [C1 ^ D0 ^ D1 ^ E1, *]
	VSLIDEUPVI $1, T0, ACC1     // [C1 ^ D0 ^ D1 ^ E1, D1] 

	reduceRound(ACC0)
	reduceRound(ACC0)
	VXORVV ACC0, ACC1, ACC0

	VREV8V ACC0, ACC0
	VSLIDEDOWNVI $1, ACC0, T0
	VSLIDEUPVI $1, ACC0, T0
	VLE64V (tMsk), T2
	VXORVV T2, T0, ACC0

	VSE64V ACC0, (tPtr)
	RET
#undef pTbl
#undef tMsk
#undef tPtr
#undef plen
#undef dlen

// func gcmSm4Enc(dst, src []byte, ctr *[16]byte, rk []uint32)
TEXT ·gcmSm4Enc(SB),0,$40-80
#define ctx X8
#define ctrPtr X9
#define ptx X10
#define rk X11
#define ptxLen X12
#define aluCTR X13

#define increment(i) ADDW $1, aluCTR

	MOV dst+0(FP), ctx
	MOV src_base+24(FP), ptx
	MOV src_len+32(FP), ptxLen
	MOV ctr+48(FP), ctrPtr
	MOV rk_base+56(FP), rk

	VSETIVLI	$4, E32, M1, TA, MA, X0
	// Load CTR first
	VLE32V	(ctrPtr), T0
	VREV8V	T0, T0
	VSLIDEDOWNVI $3, T0, T1 // T1[0] = T0[3]
	VMVXS T1, aluCTR

	// Prepare One Counters
	ADD $(8 + 0*16), RSP, X20
	VSE32V T0, (X20)
	ADD $16, X20
	increment(0)

	// round keys, shared by the 2-block and tail paths
	VLE32V	(rk), V8
	ADD	$16, rk, X21
	VLE32V	(X21), V10
	ADD	$16, X21
	VLE32V	(X21), V12
	ADD	$16, X21
	VLE32V	(X21), V14
	ADD	$16, X21
	VLE32V	(X21), V16
	ADD	$16, X21
	VLE32V	(X21), V18
	ADD	$16, X21
	VLE32V	(X21), V20
	ADD	$16, X21
	VLE32V	(X21), V22

	MOV $32, X21
	BLT ptxLen, X21, gcmSm4niEncSingle

	VSE32V T0, (X20)
	increment(1)
	VSETIVLI	$8, E32, M2, TA, MA, X0
	MOV	$·riscv64ZvksedRev(SB), X20
	VLE32V	(X20), V24	// reversal index (loop-invariant)

gcmSm4niEncDoublesLoop:
		// Load the 2 counters
		ADD $(8 + 0*16), RSP, X20
		VLE32V (X20), V4
		VREV8V	V4, V4
		VSM4R_VS(4, 8)  // VSM4RVS	V8, V4
		VSM4R_VS(4, 10) // VSM4RVS	V10, V4
		VSM4R_VS(4, 12) // VSM4RVS	V12, V4
		VSM4R_VS(4, 14) // VSM4RVS	V14, V4
		VSM4R_VS(4, 16) // VSM4RVS	V16, V4
		VSM4R_VS(4, 18) // VSM4RVS	V18, V4
		VSM4R_VS(4, 20) // VSM4RVS	V20, V4
		VSM4R_VS(4, 22) // VSM4RVS	V22, V4
		VRGATHERVV	V24, V4, V26
		VREV8V	V26, V26
		VLE32V (ptx), V4
		VXORVV V4, V26, V4
		VSE32V V4, (ctx)

		ADD $32, ptx, ptx
		ADD $32, ctx, ctx

		increment(0)
		SUB $32, ptxLen, ptxLen
		BLT ptxLen, X21, gcmSm4niEncSingle
		increment(1)

	JMP gcmSm4niEncDoublesLoop

gcmSm4niEncSingle:
	VSETIVLI	$4, E32, M1, TA, MA, X0
	MOV	$·riscv64ZvksedRev(SB), X20
	VLE32V	(X20), V24	// reversal index (loop-invariant)	
	MOV $16, X21
	BLT ptxLen, X21, gcmSm4niEncPartial
	
	// Load the 1 counters
	ADD $(8 + 0*16), RSP, X20
	VLE32V (X20), V4
	VREV8V	V4, V4
	VSM4R_VS(4, 8)  // VSM4RVS	V8, V4
	VSM4R_VS(4, 10) // VSM4RVS	V10, V4
	VSM4R_VS(4, 12) // VSM4RVS	V12, V4
	VSM4R_VS(4, 14) // VSM4RVS	V14, V4
	VSM4R_VS(4, 16) // VSM4RVS	V16, V4
	VSM4R_VS(4, 18) // VSM4RVS	V18, V4
	VSM4R_VS(4, 20) // VSM4RVS	V20, V4
	VSM4R_VS(4, 22) // VSM4RVS	V22, V4
	VRGATHERVV	V24, V4, V26
	VREV8V	V26, V26
	VLE32V (ptx), V4
	VXORVV V4, V26, V4
	VSE32V V4, (ctx)
	ADD $16, ptx, ptx
	ADD $16, ctx, ctx
	SUB $16, ptxLen, ptxLen
	increment(0)

gcmSm4niEncPartial:
	BEQZ ptxLen, encDone
	MOV ZERO, (8 + 1*16)(RSP)
	MOV ZERO, (8 + 1*16 + 8)(RSP)
	ADD $(8 + 1*16), RSP, X22

partialCopyIn:
		MOVBU (ptx), X20
		MOVB X20, (X22)
		ADD $1, X22, X22
		ADD $1, ptx, ptx
		SUB $1, ptxLen, ptxLen
		BNEZ ptxLen, partialCopyIn

partialDataReady:
	// Load the 1 counters
	ADD $(8 + 0*16), RSP, X20
	VLE32V (X20), V4
	VREV8V	V4, V4
	VSM4R_VS(4, 8)  // VSM4RVS	V8, V4
	VSM4R_VS(4, 10) // VSM4RVS	V10, V4
	VSM4R_VS(4, 12) // VSM4RVS	V12, V4
	VSM4R_VS(4, 14) // VSM4RVS	V14, V4
	VSM4R_VS(4, 16) // VSM4RVS	V16, V4
	VSM4R_VS(4, 18) // VSM4RVS	V18, V4
	VSM4R_VS(4, 20) // VSM4RVS	V20, V4
	VSM4R_VS(4, 22) // VSM4RVS	V22, V4
	VRGATHERVV	V24, V4, V26
	VREV8V	V26, V26
	ADD $16, X20, X20
	VLE32V (X20), V4
	VXORVV V4, V26, V4
	VSE32V V4, (ctx)  // // I assume there is always space, due to TAG in the end of the CT

encDone:
	RET

// func gcmSm4Dec(dst, src []byte, ctr *[16]byte, rk []uint32)
TEXT ·gcmSm4Dec(SB),0,$40-80
	MOV dst+0(FP), ptx
	MOV src_base+24(FP), ctx
	MOV src_len+32(FP), ptxLen
	MOV ctr+48(FP), ctrPtr
	MOV rk_base+56(FP), rk

	VSETIVLI	$4, E32, M1, TA, MA, X0
	// Load CTR first
	VLE32V	(ctrPtr), T0
	VREV8V	T0, T0
	VSLIDEDOWNVI $3, T0, T1 // T1[0] = T0[3]
	VMVXS T1, aluCTR

	// Prepare One Counters
	ADD $(8 + 0*16), RSP, X20
	VSE32V T0, (X20)
	ADD $16, X20
	increment(0)

	// round keys, shared by the 2-block and tail paths
	VLE32V	(rk), V8
	ADD	$16, rk, X21
	VLE32V	(X21), V10
	ADD	$16, X21
	VLE32V	(X21), V12
	ADD	$16, X21
	VLE32V	(X21), V14
	ADD	$16, X21
	VLE32V	(X21), V16
	ADD	$16, X21
	VLE32V	(X21), V18
	ADD	$16, X21
	VLE32V	(X21), V20
	ADD	$16, X21
	VLE32V	(X21), V22

	MOV $32, X21
	BLT ptxLen, X21, gcmSm4niDecSingle

	VSE32V T0, (X20)
	increment(1)
	VSETIVLI	$8, E32, M2, TA, MA, X0
	MOV	$·riscv64ZvksedRev(SB), X20
	VLE32V	(X20), V24	// reversal index (loop-invariant)

gcmSm4niDecDoublesLoop:
		// Load the 2 counters
		ADD $(8 + 0*16), RSP, X20
		VLE32V (X20), V4
		VREV8V	V4, V4
		VSM4R_VS(4, 8)  // VSM4RVS	V8, V4
		VSM4R_VS(4, 10) // VSM4RVS	V10, V4
		VSM4R_VS(4, 12) // VSM4RVS	V12, V4
		VSM4R_VS(4, 14) // VSM4RVS	V14, V4
		VSM4R_VS(4, 16) // VSM4RVS	V16, V4
		VSM4R_VS(4, 18) // VSM4RVS	V18, V4
		VSM4R_VS(4, 20) // VSM4RVS	V20, V4
		VSM4R_VS(4, 22) // VSM4RVS	V22, V4
		VRGATHERVV	V24, V4, V26
		VREV8V	V26, V26
		VLE32V (ctx), V4
		VXORVV V4, V26, V4
		VSE32V V4, (ptx)

		ADD $32, ptx, ptx
		ADD $32, ctx, ctx

		increment(0)
		SUB $32, ptxLen, ptxLen
		BLT ptxLen, X21, gcmSm4niDecSingle
		increment(1)

	JMP gcmSm4niDecDoublesLoop

gcmSm4niDecSingle:
	VSETIVLI	$4, E32, M1, TA, MA, X0
	MOV	$·riscv64ZvksedRev(SB), X20
	VLE32V	(X20), V24	// reversal index (loop-invariant)	
	MOV $16, X21
	BLT ptxLen, X21, gcmSm4niDecPartial
	
	// Load the 1 counters
	ADD $(8 + 0*16), RSP, X20
	VLE32V (X20), V4
	VREV8V	V4, V4
	VSM4R_VS(4, 8)  // VSM4RVS	V8, V4
	VSM4R_VS(4, 10) // VSM4RVS	V10, V4
	VSM4R_VS(4, 12) // VSM4RVS	V12, V4
	VSM4R_VS(4, 14) // VSM4RVS	V14, V4
	VSM4R_VS(4, 16) // VSM4RVS	V16, V4
	VSM4R_VS(4, 18) // VSM4RVS	V18, V4
	VSM4R_VS(4, 20) // VSM4RVS	V20, V4
	VSM4R_VS(4, 22) // VSM4RVS	V22, V4
	VRGATHERVV	V24, V4, V26
	VREV8V	V26, V26
	VLE32V (ctx), V4
	VXORVV V4, V26, V4
	VSE32V V4, (ptx)
	ADD $16, ptx, ptx
	ADD $16, ctx, ctx
	SUB $16, ptxLen, ptxLen
	increment(0)

gcmSm4niDecPartial:
	BEQZ ptxLen, decDone

	// Load the 1 counters
	ADD $(8 + 0*16), RSP, X20
	VLE32V (X20), V4
	VREV8V	V4, V4
	VSM4R_VS(4, 8)  // VSM4RVS	V8, V4
	VSM4R_VS(4, 10) // VSM4RVS	V10, V4
	VSM4R_VS(4, 12) // VSM4RVS	V12, V4
	VSM4R_VS(4, 14) // VSM4RVS	V14, V4
	VSM4R_VS(4, 16) // VSM4RVS	V16, V4
	VSM4R_VS(4, 18) // VSM4RVS	V18, V4
	VSM4R_VS(4, 20) // VSM4RVS	V20, V4
	VSM4R_VS(4, 22) // VSM4RVS	V22, V4
	VRGATHERVV	V24, V4, V26
	VREV8V	V26, V26
	VLE32V (ctx), V4     // I assume there is TAG attached to the ctx, and there is no read overflow
	VXORVV V4, V26, V4
	ADD $(8 + 1*16), RSP, X22
	VSE32V V4, (X22)

partialCopyOut:
		MOVBU (X22), X20
		MOVB X20, (ptx)
		ADD $1, X22, X22
		ADD $1, ptx, ptx
		SUB $1, ptxLen, ptxLen
		BNEZ ptxLen, partialCopyOut

decDone:
	RET
