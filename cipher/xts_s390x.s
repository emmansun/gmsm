// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

DATA xtsMask<>+0x00(SB)/8, $0x0f0e0d0c0b0a0908 // byte swap BE -> LE
DATA xtsMask<>+0x08(SB)/8, $0x0706050403020100
GLOBL xtsMask<>(SB), (NOPTR+RODATA), $16

#define BSWAP V0
#define POLY V1
#define B0 V2
#define T0 V3
#define T1 V4
#define CPOOL R3

#define doubleTweak(B0, BSWAP, POLY, T0, T1) \
	VPERM B0, B0, BSWAP, B0  \// BE -> LE
	\ // Multiply by 2
	VESRAF $31, B0, T0 \
	VREPF $0, T0, T0  \
	VN POLY, T0, T0    \    // T0 for reduction
	VREPIB $1, T1      \
	VSL T1, B0, T1     \
	VX T1, T0, B0      \
	\
	VPERM B0, B0, BSWAP, B0

#define gbDoubleTweak(B0, POLY, T0, T1) \
	VESLF $31, B0, T0   \
	VESRAF $31, T0, T0  \
	VREPF $3, T0, T0   \
	VN POLY, T0, T0     \ // T0 for reduction
	\
	VREPIB $1, T1       \
	VSRL T1, B0, T1     \
	VX T1, T0, B0

// func mul2(tweak *[blockSize]byte, isGB bool)
TEXT ·mul2(SB),NOSPLIT,$0
	MOVD tweak+0(FP), R1
	MOVB isGB+8(FP), R2

	CMPBEQ R2, $1, gb_alg

	MOVD $xtsMask<>+0x00(SB), CPOOL
	VL  (CPOOL), BSWAP
	
	// Load polynomial for reduction
	VZERO POLY
	VLEIB $15, $0x87, POLY

	// Load tweak
	VL 0(R1), B0
	doubleTweak(B0, BSWAP, POLY, T0, T1)
	VST B0, 0(R1)

gb_alg:
	// Load polynomial for reduction
	VZERO POLY
	VLEIB $0, $0xe1, POLY

	// Load tweak
	VL 0(R1), B0
	gbDoubleTweak(B0, POLY, T0, T1)
	VST B0, 0(R1)

	RET

// func doubleTweaks(tweak *[blockSize]byte, tweaks []byte, isGB bool)
TEXT ·doubleTweaks(SB),NOSPLIT,$0
	MOVD tweak+0(FP), R1
	MOVD tweaks+8(FP), R2
	MOVD tweaks_len+16(FP), R3
	MOVB isGB+32(FP), R4

	AND	$-16, R3
	LAY	(R2)(R3*1), R5

	VL 0(R1), B0

	CMPBEQ R4, $1, gb_alg

	MOVD $xtsMask<>+0x00(SB), CPOOL
	VL  (CPOOL), BSWAP
	
	// Load polynomial for reduction
	VZERO POLY
	VLEIB $15, $0x87, POLY

loop:
	VST B0, 0(R2)

	doubleTweak(B0, BSWAP, POLY, T0, T1)

	LA	16(R2), R2
	CMPBLT	R2, R5, loop

	VST B0, 0(R1)
	RET

gb_alg:	
	// Load polynomial for reduction
	VZERO POLY
	VLEIB $0, $0xe1, POLY

gb_alg_loop:
	VST B0, 0(R2)

	gbDoubleTweak(B0, POLY, T0, T1)

	LA	16(R2), R2
	CMPBLT	R2, R5, gb_alg_loop

	VST B0, 0(R1)
	RET
