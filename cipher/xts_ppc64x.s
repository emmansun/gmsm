// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"

DATA xtsMask<>+0x00(SB)/8, $0x0f0e0d0c0b0a0908 // byte swap BE -> LE
DATA xtsMask<>+0x08(SB)/8, $0x0706050403020100
DATA xtsMask<>+0x10(SB)/8, $0x0000000000000000
DATA xtsMask<>+0x18(SB)/8, $0x0000000000000087
DATA xtsMask<>+0x20(SB)/8, $0xe100000000000000
DATA xtsMask<>+0x28(SB)/8, $0x0000000000000000
GLOBL xtsMask<>(SB), (NOPTR+RODATA), $48

#define ESPERM  V21  // Endian swapping permute into BE

#define POLY V0
#define B0 V1
#define T0 V2
#define T1 V3
#define CPOOL R7

#define doubleTweak(B0, POLY, T0, T1) \
	\ // Multiply by 2
	VSPLTB $0, B0, T0    \
	VSPLTISB $7, T1      \
	VSRAB    T0, T1, T0  \
	VAND    POLY, T0, T0 \// T0 for reduction
	\
	VSPLTISB $1, T1      \
	VSL B0, T1, T1       \
	VXOR T0, T1, B0

#define gbDoubleTweak(B0, POLY, T0, T1) \
	VSPLTB $15, B0, T0   \
	VSPLTISB $7, T1      \
	VSLB T0, T1, T0      \
	VSRAB T0, T1, T0     \
	VAND POLY, T0, T0    \ // T0 for reduction
	VSPLTISB $1, T1      \
	VSR B0, T1, B0       \
	VXOR T0, B0, B0

// func mul2(tweak *[blockSize]byte, isGB bool)
TEXT ·mul2(SB),NOSPLIT,$0
	MOVD tweak+0(FP), R3
	MOVBZ isGB+8(FP), R4

	MOVD $xtsMask<>(SB), CPOOL

	CMPW R4, $1
	BEQ gb_alg
	
	// Load polynomial for reduction
	MOVD $16, R5
	LXVD2X (CPOOL)(R5), POLY

	// Load tweak
	LXVD2X (R3), B0
#ifdef GOARCH_ppc64le
	XXPERMDI B0, B0, $2, B0
	doubleTweak(B0, POLY, T0, T1)
	XXPERMDI B0, B0, $2, B0
#else
	LXVD2X (CPOOL), ESPERM
	
	VPERM B0, B0, ESPERM, B0
	doubleTweak(B0, POLY, T0, T1)
	VPERM B0, B0, ESPERM, B0
#endif
	STXVD2X B0, (R3)

	RET

gb_alg:	
	// Load polynomial for reduction
	MOVD $32, R5
	LXVD2X (CPOOL)(R5), POLY

	// Load tweak
	LXVD2X (R3), B0
#ifdef GOARCH_ppc64le
	LVX (CPOOL), ESPERM
	VPERM B0, B0, ESPERM, B0
	gbDoubleTweak(B0, POLY, T0, T1)
	VPERM B0, B0, ESPERM, B0
#else
	gbDoubleTweak(B0, POLY, T0, T1)
#endif
	STXVD2X B0, (R3)
	RET

// func doubleTweaks(tweak *[blockSize]byte, tweaks []byte, isGB bool)
TEXT ·doubleTweaks(SB),NOSPLIT,$0
	MOVD tweak+0(FP), R3
	MOVD tweaks+8(FP), R4
	MOVD tweaks_len+16(FP), R5
	MOVBZ isGB+32(FP), R6

	MOVD $xtsMask<>(SB), CPOOL

	// Load tweak
	LXVD2X (R3), B0

	CMPW R6, $1
	BEQ gb_alg

	SRD	$4, R5
	MOVD R5, CTR

#ifndef GOARCH_ppc64le
	LXVD2X (CPOOL), ESPERM
#endif	
	// Load polynomial for reduction
	MOVD $16, R5
	LXVD2X (CPOOL)(R5), POLY

loop:
		STXVD2X B0, (R4)
		ADD $16, R4

#ifdef GOARCH_ppc64le
		XXPERMDI B0, B0, $2, B0
		doubleTweak(B0, POLY, T0, T1)
		XXPERMDI B0, B0, $2, B0
#else
		VPERM B0, B0, ESPERM, B0
		doubleTweak(B0, POLY, T0, T1)
		VPERM B0, B0, ESPERM, B0
#endif

		BDNZ	loop

	STXVD2X B0, (R3)
	RET

gb_alg:	
	SRD	$4, R5
	MOVD R5, CTR

	// Load polynomial for reduction
	MOVD $32, R5
	LXVD2X (CPOOL)(R5), POLY

#ifdef GOARCH_ppc64le
	LVX (CPOOL), ESPERM
#endif

gbLoop:
	STXVD2X B0, (R4)
	ADD $16, R4

#ifdef GOARCH_ppc64le
		VPERM B0, B0, ESPERM, B0
		gbDoubleTweak(B0, POLY, T0, T1)
		VPERM B0, B0, ESPERM, B0
#else
		gbDoubleTweak(B0, POLY, T0, T1)
#endif

		BDNZ	gbLoop

	STXVD2X B0, (R3)
	RET
