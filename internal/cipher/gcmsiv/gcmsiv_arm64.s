// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

#define B0 V0
#define B1 V1
#define B2 V2
#define B3 V3
#define B4 V4
#define B5 V5
#define B6 V6
#define B7 V7

#define ACC0 V8
#define ACC1 V9
#define ACCM V10

#define T0 V11
#define T1 V12
#define T2 V13
#define T3 V14

#define POLY V15
#define ZERO V16

// func polyvalTableInitAsm(h *[16]byte, table *polyvalAsmTable)
TEXT ·polyvalTableInitAsm(SB), NOSPLIT, $0-16
#define pTbl R0
#define hPtr R1
#define I R2

	MOVD hPtr+0(FP), hPtr
	MOVD productTable+8(FP), pTbl
	
	VLD1 (hPtr), [B0.B16]

	// POLYVAL special handling
	MOVD	$0xE1, I
	LSL	$56, I
	VMOV	I, POLY.D[1]

	VMOV	B0.D[0], I
	LSL $63, I
	ASR $63, I
	VMOV	I, T1.D2
	VAND	POLY.B16, T1.B16, T1.B16
	VSHL $63, B0.D2, T2.D2
	VEXT	$8, ZERO.B16, T2.B16, T2.B16
	VSRI	$1, B0.D2, T2.D2
	VEOR	T1.B16, T2.B16, B0.B16
	
	VEXT	$8, B0.B16, B0.B16, B0.B16

	// Construct POLYVAL reduction polynomial in POLY: 0x0000000000000001_c200000000000000
	MOVD	$0xC2, I
	LSL	$56, I
	VMOV	I, POLY.D[0]
	MOVD	$1, I
	VMOV	I, POLY.D[1]
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	// Multiply by 2 modulo P
	VMOV	B0.D[0], I
	ASR	$63, I
	VMOV	I, T1.D[0]
	VMOV	I, T1.D[1]
	VAND	POLY.B16, T1.B16, T1.B16
	VUSHR	$63, B0.D2, T2.D2
	VEXT	$8, ZERO.B16, T2.B16, T2.B16
	VSLI	$1, B0.D2, T2.D2
	VEOR	T1.B16, T2.B16, B0.B16

	// Karatsuba pre-computation
	VEXT	$8, B0.B16, B0.B16, B1.B16
	VEOR	B0.B16, B1.B16, B1.B16

	ADD	$14*16, pTbl

	VST1	[B0.B16, B1.B16], (pTbl)
	SUB	$2*16, pTbl

	VMOV	B0.B16, B2.B16
	VMOV	B1.B16, B3.B16

	MOVD	$7, I

initLoop:
	// Compute powers of H
	SUBS	$1, I

	VPMULL	B0.D1, B2.D1, T1.Q1
	VPMULL2	B0.D2, B2.D2, T0.Q1
	VPMULL	B1.D1, B3.D1, T2.Q1
	VEOR	T0.B16, T2.B16, T2.B16
	VEOR	T1.B16, T2.B16, T2.B16
	VEXT	$8, ZERO.B16, T2.B16, T3.B16
	VEXT	$8, T2.B16, ZERO.B16, T2.B16
	VEOR	T2.B16, T0.B16, T0.B16
	VEOR	T3.B16, T1.B16, T1.B16
	VPMULL	POLY.D1, T0.D1, T2.Q1
	VEXT	$8, T0.B16, T0.B16, T0.B16
	VEOR	T2.B16, T0.B16, T0.B16
	VPMULL	POLY.D1, T0.D1, T2.Q1
	VEXT	$8, T0.B16, T0.B16, T0.B16
	VEOR	T2.B16, T0.B16, T0.B16
	VEOR	T1.B16, T0.B16, B2.B16
	VMOV	B2.B16, B3.B16
	VEXT	$8, B2.B16, B2.B16, B2.B16
	VEOR	B2.B16, B3.B16, B3.B16

	VST1	[B2.B16, B3.B16], (pTbl)
	SUB	$2*16, pTbl

	BNE	initLoop
	RET
#undef I
#undef hPtr
#undef pTbl	

// func polyvalBlocksUpdateAsm(table *polyvalAsmTable, y *[16]byte, blocks []byte)
TEXT ·polyvalBlocksUpdateAsm(SB), NOSPLIT, $0-40
#define pTbl R0
#define aut R1
#define tPtr R2
#define autLen R3
#define H0 R4
#define pTblSave R5

#define mulRound(X) \
	VLD1.P	32(pTbl), [T1.B16, T2.B16] \
	VEXT	$8, X.B16, X.B16, X.B16    \
	VEXT	$8, X.B16, X.B16, T0.B16   \
	VEOR	X.B16, T0.B16, T0.B16      \
	VPMULL	X.D1, T1.D1, T3.Q1         \
	VEOR	T3.B16, ACC1.B16, ACC1.B16 \
	VPMULL2	X.D2, T1.D2, T3.Q1         \
	VEOR	T3.B16, ACC0.B16, ACC0.B16 \
	VPMULL	T0.D1, T2.D1, T3.Q1        \
	VEOR	T3.B16, ACCM.B16, ACCM.B16

	MOVD	productTable+0(FP), pTbl
	MOVD	T+8(FP), tPtr
	MOVD	data_base+16(FP), aut
	MOVD	data_len+24(FP), autLen
	
	VLD1 (tPtr), [ACC0.B16]
	CBZ	autLen, polyvalUpdateDone

	MOVD	$0xC2, H0
	LSL	$56, H0
	VMOV	H0, POLY.D[0]
	MOVD	$1, H0
	VMOV	H0, POLY.D[1]
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16
	MOVD	pTbl, pTblSave

octetsLoop:
		CMP	$128, autLen
		BLT	startSinglesLoop
		SUB	$128, autLen

		VLD1.P	32(aut), [B0.B16, B1.B16]

		VLD1.P	32(pTbl), [T1.B16, T2.B16]
		//VREV64	B0.B16, B0.B16
		VEXT	$8, B0.B16, B0.B16, B0.B16
		VEOR	ACC0.B16, B0.B16, B0.B16
		VEXT	$8, B0.B16, B0.B16, T0.B16
		VEOR	B0.B16, T0.B16, T0.B16
		VPMULL	B0.D1, T1.D1, ACC1.Q1
		VPMULL2	B0.D2, T1.D2, ACC0.Q1
		VPMULL	T0.D1, T2.D1, ACCM.Q1

		mulRound(B1)
		VLD1.P  32(aut), [B2.B16, B3.B16]
		mulRound(B2)
		mulRound(B3)
		VLD1.P  32(aut), [B4.B16, B5.B16]
		mulRound(B4)
		mulRound(B5)
		VLD1.P  32(aut), [B6.B16, B7.B16]
		mulRound(B6)
		mulRound(B7)

		MOVD	pTblSave, pTbl
		reduce()
	B	octetsLoop

startSinglesLoop:

	ADD	$14*16, pTbl
	VLD1.P	(pTbl), [T1.B16, T2.B16]

singlesLoop:

		CMP	$16, autLen
		BLT	polyvalUpdateDone
		SUB	$16, autLen

		VLD1.P	16(aut), [B0.B16]
dataMul:
		//VREV64	B0.B16, B0.B16
		VEXT	$8, B0.B16, B0.B16, B0.B16
		VEOR	ACC0.B16, B0.B16, B0.B16

		VEXT	$8, B0.B16, B0.B16, T0.B16
		VEOR	B0.B16, T0.B16, T0.B16
		VPMULL	B0.D1, T1.D1, ACC1.Q1
		VPMULL2	B0.D2, T1.D2, ACC0.Q1
		VPMULL	T0.D1, T2.D1, ACCM.Q1

		reduce()

	B	singlesLoop

polyvalUpdateDone:
	VST1	[ACC0.B16], (tPtr)
	RET
