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

// VSM4K_VI performs vsm4k.vi Vd, Vs2, imm5
// OP-P(0x77) | funct6=100001,vm=1 → 0x43 | vs2[24:20] | imm[19:15] | funct3=010 | vd[11:7]
#define VSM4K_VI(Vd, Vs2, Imm) \
	WORD $((0x43 << 25) | ((Vs2) << 20) | ((Imm) << 15) | (2 << 12) | ((Vd) << 7) | 0x77)

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
	ADD $224, dst, X14
	VRGATHERVV V10, V1, V2
	VSE64V V2, (X14)
	VXORVV V1, V2, V2
	ADD $16, X14, X14
	VSE64V V2, (X14)

	MOV gcmPoly<>+0x08(SB), X15
	VMVVV V1, V3
	VMVVV V2, V4

	ADD $16, dst, X13	

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

		SUB $48, X14, X14
		VRGATHERVV V10, V3, V4
		VSE64V V4, (X14)
		VXORVV V3, V4, V4
		ADD $16, X14, X14
		VSE64V V4, (X14)

	BNE X13, X14, initLoop
	RET

// func gcmSm4Data(productTable *[256]byte, data []byte, T *[16]byte)
TEXT ·gcmSm4Data(SB),NOSPLIT,$0
#define pTbl X10
#define aut X11
#define tPtr X12
#define autLen X13

// a remains in swapped-domain.
//
// T0     = low64(XPOLY * a)
// ACCML  = high64(XPOLY * a)
// ACCMH  = [high(a[1] * XPOLY), low(a[1] * XPOLY)]
//
// ACCML and ACCMH are scratch registers after product assembly.
#define reduceRound(a) \
	VCLMULVX XPOLY, a, T0; \
	VCLMULHVX XPOLY, a, ACCML; \
	VSLIDEDOWNVI $1, ACCML, ACCMH; \
	VSLIDEDOWNVI $1, T0, ACCML; \
	VSLIDEUPVI $1, ACCML, ACCMH; \
	VRGATHERVV SHUFFLE_MASK, a, T0; \
	VXORVV ACCMH, T0, a

#define mulRoundAAD(X ,i) \
	VREV8V X, X; \
	VRGATHERVV SHUFFLE_MASK, X, T0; \
	VXORVV X, T0, T0; \
	ADD $(16*(i*2)), pTbl, X14; \
	VLE64V (X14), T1; \
	VCLMULVV X, T1, T2; \
	VXORVV T2, ACC0, ACC0; \
	VCLMULHVV X, T1, T2;  \
	VXORVV T2, ACC1, ACC1; \ 
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
	VXORVV ACC0, ACC0, ACC0
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

		VREV8V B0, B0
		VXORVV ACC0, B0, B0

		// Karatsuba middle operand.
		VRGATHERVV SHUFFLE_MASK, B0, T0
		VXORVV B0, T0, T0

		VLE64V (pTbl), T1
		ADD $16, pTbl, X9
		VLE64V (X9), T2

		VCLMULVV B0, T1, ACC0       // LOW(B0 * T1) = [D0, C0]
		VCLMULHVV B0, T1, ACC1      // HIGH(B0 * T1) = [D1, C1]
		VCLMULVV T0, T2, ACCML      // LOW(T0 * T2) = [E0, F0]
		VCLMULHVV T0, T2, ACCMH     // HIGH(T0 * T2) = [E1, F1]

		mulRoundAAD(B1, 1)
		mulRoundAAD(B2, 2)
		mulRoundAAD(B3, 3)
		mulRoundAAD(B4, 4)
		mulRoundAAD(B5, 5)
		mulRoundAAD(B6, 6)
		mulRoundAAD(B7, 7)

		VXORVV ACC0, ACC1, T0       // [D0 ^ D1, C0 ^ C1]
		VXORVV T0, ACCML, ACCML     // [D0 ^ D1 ^ E0, C0 ^ C1 ^ E0]
		VXORVV T0, ACCMH, ACCMH     // [D0 ^ D1 ^ E1, C0 ^ C1 ^ E1]

		VSLIDEDOWNVI $1, ACCML, T0  // T0 = [C0 ^ C1 ^ E0, 0]
		VXORVV T0, ACC0, ACC0       // ACC0 = [D0 ^ C0 ^ C1 ^ E0, C0]

		VSLIDEDOWNVI $1, ACC1, T0   // T0 = [C1, 0]
		VXORVV T0, ACCMH, ACCMH     // ACCMH = [C1 ^ D0 ^ D1 ^ E1, C0 ^ E1]
		VSLIDEUPVI $1, ACCMH, ACC1  // ACC1 = [D1, C1 ^ D0 ^ D1 ^ E1]

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
		VREV8V B0, B0
		VXORVV ACC0, B0, B0        // ACC0 is also maintained in swapped-domain.

		VRGATHERVV SHUFFLE_MASK, B0, T0
		VXORVV B0, T0, T0

		VCLMULVV B0, T1, ACC0       // LOW(B0 * T1) = [D0, C0]
		VCLMULHVV B0, T1, ACC1      // HIGH(B0 * T1) = [D1, C1]
		VCLMULVV T0, T2, ACCML      // LOW(T0 * T2) = [E0, F0], E0 == F0
		VCLMULHVV T0, T2, ACCMH     // HIGH(T0 * T2) = [E1, F1], E1 == F1

		VXORVV ACC0, ACC1, T0       // [D0 ^ D1, C0 ^ C1]
		VXORVV T0, ACCML, ACCML     // [D0 ^ D1 ^ E0, C0 ^ C1 ^ E0]
		VXORVV T0, ACCMH, ACCMH     // [D0 ^ D1 ^ E1, C0 ^ C1 ^ E1]

		VSLIDEDOWNVI $1, ACCML, T0  // T0 = [C0 ^ C1 ^ E0, 0]
		VXORVV T0, ACC0, ACC0       // ACC0 = [D0 ^ C0 ^ C1 ^ E0, C0]

		VSLIDEDOWNVI $1, ACC1, T0   // T0 = [C1, 0]
		VXORVV T0, ACCMH, ACCMH     // ACCMH = [C1 ^ D0 ^ D1 ^ E1, C0 ^ E1]
		VSLIDEUPVI $1, ACCMH, ACC1  // ACC1 = [D1, C1 ^ D0 ^ D1 ^ E1]

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

// func gcmSm4Finish(productTable *[256]byte, tagMask, T *[16]byte, pLen, dLen uint64)
TEXT ·gcmSm4Finish(SB),NOSPLIT,$0
	RET
	
// func gcmSm4Enc(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)
TEXT ·gcmSm4Enc(SB),0,$256-96
	RET

// func gcmSm4Dec(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)
TEXT ·gcmSm4Dec(SB),0,$128-96
	RET
