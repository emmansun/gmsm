// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

#define ZERO R0
#define RSP R3

#define B0 V0
#define T1 V1
#define T2 V2

#define POLY V3
#define ZERO_V V4

#define TW R5
#define GB R6
#define I R20

#define doubleTweak           \
	VSRLV $63, B0, T2         \
	VILVLV ZERO_V, T2, T2     \
	VSLLV $1, B0, T1          \
	VXORV T1, T2, T2          \
	\
	VSRAV $63, B0, T1		  \
	VILVHV T1, T1, T1         \
	VANDV POLY, T1, T1        \
	VXORV T1, T2, B0

#define gbDoubleTweak         \
	VSLLV $63, B0, T2         \
	VILVHV T2, ZERO_V, T2     \
	VSRLV $1, B0, T1          \
	VXORV T1, T2, T2          \
	\
	VMOVQ B0.V[0], I          \
	SLLV $63, I, I            \
	SRAV $63, I, I            \
	VMOVQ I, T1.V2            \
	VANDV POLY, T1, T1        \
	\
	VXORV T1, T2, B0

// func mul2Lsx(tweak *[blockSize]byte, isGB bool)
TEXT ·mul2Lsx(SB),NOSPLIT,$0
	MOVV tweak+0(FP), TW
	MOVB isGB+8(FP), GB

	VMOVQ (TW), B0

	VXORV	POLY, POLY, POLY
	VXORV	ZERO_V, ZERO_V, ZERO_V

	BNE GB, ZERO, gb_alg

	MOVV	$0x87, I
	VMOVQ	I, POLY.V[0]

	doubleTweak

	VMOVQ B0, (TW)
	RET

gb_alg:
	MOVV	$0xE1, I
	SLLV	$56, I
	VMOVQ	I, POLY.V[1]

	VSHUF4IB $0x1B, B0, B0
	VSHUF4IW $0x1B, B0, B0
	gbDoubleTweak
	VSHUF4IW $0x1B, B0, B0
	VSHUF4IB $0x1B, B0, B0

	VMOVQ B0, (TW)
	RET

// func doubleTweaksLsx(tweak *[blockSize]byte, tweaks []byte, isGB bool)
TEXT ·doubleTweaksLsx(SB),NOSPLIT,$0
	MOVV tweak+0(FP), TW
	MOVV tweaks+8(FP), R7
	MOVV tweaks_len+16(FP), R8
	MOVB isGB+32(FP), GB

	SRLV $4, R8, R8  // R8 = len / 16

	VMOVQ (TW), B0

	VXORV	POLY, POLY, POLY
	VXORV	ZERO_V, ZERO_V, ZERO_V

	BNE GB, ZERO, gb_alg

	MOVV	$0x87, I
	VMOVQ	I, POLY.V[0]

loop:
		VMOVQ B0, (R7)
		ADDV $16, R7, R7
		SUBV $1, R8, R8
		doubleTweak
		BNE R8, ZERO, loop
	VMOVQ B0, (TW)	
	RET

gb_alg:	
	MOVV	$0xE1, I
	SLLV	$56, I
	VMOVQ	I, POLY.V[1]

gb_alg_loop:	
		VMOVQ B0, (R7)
		ADDV $16, R7, R7
		SUBV $1, R8, R8
		VSHUF4IB $0x1B, B0, B0
		VSHUF4IW $0x1B, B0, B0
		gbDoubleTweak
		VSHUF4IW $0x1B, B0, B0
		VSHUF4IB $0x1B, B0, B0
		BNE R8, ZERO, gb_alg_loop
	VMOVQ B0, (TW)	
	RET
