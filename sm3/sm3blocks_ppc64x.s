// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"

// For P9 instruction emulation
#define ESPERMW  V21 // Endian swapping permute into BE
#define TMP2    V22  // Temporary for P8_STXVB16X/P8_STXVB16X

DATA ·mask+0x00(SB)/8, $0x0c0d0e0f08090a0b // Permute for vector doubleword endian swap
DATA ·mask+0x08(SB)/8, $0x0405060700010203
DATA ·mask+0x10(SB)/8, $0x0001020310111213 // Permute for transpose matrix
DATA ·mask+0x18(SB)/8, $0x0405060714151617
DATA ·mask+0x20(SB)/8, $0x08090a0b18191a1b
DATA ·mask+0x28(SB)/8, $0x0c0d0e0f1c1d1e1f
DATA ·mask+0x30(SB)/8, $0x0001020304050607
DATA ·mask+0x38(SB)/8, $0x1011121314151617
DATA ·mask+0x40(SB)/8, $0x08090a0b0c0d0e0f
DATA ·mask+0x48(SB)/8, $0x18191a1b1c1d1e1f
GLOBL ·mask(SB), RODATA, $80

#ifdef GOARCH_ppc64le
#define NEEDS_ESPERM

#define LOADWORDS(RA,RB,VT) \
	LXVD2X	(RA+RB), VT \
	VPERM	VT, VT, ESPERMW, VT

#define STOREWORDS(VS,RA,RB) \
	VPERM	VS, VS, ESPERMW, TMP2 \
	STXVD2X	TMP2, (RA+RB)

#else
#define LOADWORDS(RA,RB,VT)  LXVD2X	(RA+RB), VT
#define STOREWORDS(VS,RA,RB) STXVD2X	VS, (RA+RB)	
#endif // defined(GOARCH_ppc64le)

#define TRANSPOSE_MATRIX(T0, T1, T2, T3, M0, M1, M2, M3, TMP0, TMP1, TMP2, TMP3) \
	VPERM T0, T1, M0, TMP0; \
	VPERM T2, T3, M0, TMP1; \
	VPERM T0, T1, M1, TMP2; \
	VPERM T2, T3, M1, TMP3; \
	VPERM TMP0, TMP1, M2, T0; \
	VPERM TMP0, TMP1, M3, T1; \
	VPERM TMP2, TMP3, M2, T2; \
	VPERM TMP2, TMP3, M3, T3

// transposeMatrix(dig **[8]uint32)
TEXT ·transposeMatrix(SB),NOSPLIT,$0
	MOVD	dig+0(FP), R3
	MOVD 	$8, R5
	MOVD 	$16, R6
	MOVD 	$24, R7
	MOVD 	$32, R8
	MOVD 	$48, R9

#ifdef NEEDS_ESPERM
	MOVD	$·mask(SB), R4
	LVX	(R4), ESPERMW
	ADD	$0x10, R4
#else
	MOVD	$·mask+0x10(SB), R4
#endif
	LXVD2X 	(R0)(R4), V8
	LXVD2X 	(R6)(R4), V9
	LXVD2X 	(R8)(R4), V10
	LXVD2X 	(R9)(R4), V11

	MOVD 	(R0)(R3), R4
	LOADWORDS(R4, R0, V0)
	LOADWORDS(R4, R6, V4)
	MOVD 	(R5)(R3), R4
	LOADWORDS(R4, R0, V1)
	LOADWORDS(R4, R6, V5)
	MOVD 	(R6)(R3), R4
	LOADWORDS(R4, R0, V2)
	LOADWORDS(R4, R6, V6)
	MOVD 	(R7)(R3), R4
	LOADWORDS(R4, R0, V3)
	LOADWORDS(R4, R6, V7)


	TRANSPOSE_MATRIX(V0, V1, V2, V3, V8, V9, V10, V11, V12, V13, V14, V15)
	TRANSPOSE_MATRIX(V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15)

	MOVD 	(R0)(R3), R4
	STOREWORDS(V0, R4, R0)
	STOREWORDS(V4, R4, R6)
	MOVD 	(R5)(R3), R4
	STOREWORDS(V1, R4, R0)
	STOREWORDS(V5, R4, R6)
	MOVD 	(R6)(R3), R4
	STOREWORDS(V2, R4, R0)
	STOREWORDS(V6, R4, R6)
	MOVD 	(R7)(R3), R4
	STOREWORDS(V3, R4, R0)
	STOREWORDS(V7, R4, R6)

	RET
