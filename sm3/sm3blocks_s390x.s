// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

DATA mask<>+0x00(SB)/8, $0x0001020310111213
DATA mask<>+0x08(SB)/8, $0x0405060714151617
DATA mask<>+0x10(SB)/8, $0x08090a0b18191a1b
DATA mask<>+0x18(SB)/8, $0x0c0d0e0f1c1d1e1f
DATA mask<>+0x20(SB)/8, $0x0001020304050607
DATA mask<>+0x28(SB)/8, $0x1011121314151617
DATA mask<>+0x30(SB)/8, $0x08090a0b0c0d0e0f
DATA mask<>+0x38(SB)/8, $0x18191a1b1c1d1e1f
GLOBL mask<>(SB), 8, $64

#define TRANSPOSE_MATRIX(T0, T1, T2, T3, M1, M2, M3, M4, TMP0, TMP1, TMP2, TMP3) \
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
	MOVD	dig+0(FP), R1

	MOVD 	(R1), R2
	VL 0(R2), V0
	VL 16(R2), V4
	MOVD 	8(R1), R2
	VL 0(R2), V1
	VL 16(R2), V5
	MOVD 	16(R1), R2
	VL 0(R2), V2
	VL 16(R2), V6
	MOVD 	24(R1), R2
	VL 0(R2), V3
	VL 16(R2), V7

	MOVD $mask<>+0x00(SB), R2
	VLM 0(R2), V8, V11

	TRANSPOSE_MATRIX(V0, V1, V2, V3, V8, V9, V10, V11, V12, V13, V14, V15)
	TRANSPOSE_MATRIX(V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15)

	MOVD 	(R1), R2
	VST V0, 0(R2)
	VST V4, 16(R2)
	MOVD 	8(R1), R2
	VST V1, 0(R2)
	VST V5, 16(R2)
	MOVD 	16(R1), R2
	VST V2, 0(R2)
	VST V6, 16(R2)
	MOVD 	24(R1), R2
	VST V3, 0(R2)
	VST V7, 16(R2)
	RET
