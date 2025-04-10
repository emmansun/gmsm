// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"

#define REVERSE_WORDS V19
#define M1L V20
#define M1H V21
#define M2L V22
#define M2H V23
// For instruction emulation
#define ESPERMW  V31 // Endian swapping permute into BE

#define TMP0 V10
#define TMP1 V11
#define TMP2 V12
#define TMP3 V13

#include "aesni_macros_ppc64x.s"

// func encryptSm4Ecb(xk *uint32, dst, src []byte)
TEXT ·encryptSm4Ecb(SB),NOSPLIT,$0
#define dstPtr R3
#define srcPtr R4
#define rk R5
#define srcLen R6
	// prepare/load constants
#ifdef NEEDS_PERMW
	MOVD	$·rcon(SB), R4
	LVX	(R4), ESPERMW
#endif
	MOVD	$·rcon+0x10(SB), R4
	LOAD_CONSTS(R4, R3)

	MOVD xk+0(FP), rk
	MOVD dst+8(FP), dstPtr
	MOVD src+32(FP), srcPtr
	MOVD src_len+40(FP), srcLen

	MOVD $16, R7
	MOVD $32, R8
	MOVD $48, R10
	MOVD $64, R11
	MOVD $80, R12
	MOVD $96, R14
	MOVD $112, R15

	CMP srcLen, $128
	BLT block64

preloop128:
	SRD	$7, srcLen, R9	// Set up loop counter
	MOVD	R9, CTR
	ANDCC	$127, srcLen, R9	// Check for tailing bytes for later
	PCALIGN $16

block128:
	// Case for >= 128 bytes
	PPC64X_LXVW4X(srcPtr, R0, V0)
	PPC64X_LXVW4X(srcPtr, R7, V1)
	PPC64X_LXVW4X(srcPtr, R8, V2)
	PPC64X_LXVW4X(srcPtr, R10, V3)
	PPC64X_LXVW4X(srcPtr, R11, V4)
	PPC64X_LXVW4X(srcPtr, R12, V5)
	PPC64X_LXVW4X(srcPtr, R14, V6)
	PPC64X_LXVW4X(srcPtr, R15, V7)
	PRE_TRANSPOSE_MATRIX(V0, V1, V2, V3)
	PRE_TRANSPOSE_MATRIX(V4, V5, V6, V7)

	LXVW4X (rk)(R0), V8
	PROCESS_8BLOCKS_4ROUND
	LXVW4X (rk)(R7), V8
	PROCESS_8BLOCKS_4ROUND
	LXVW4X (rk)(R8), V8
	PROCESS_8BLOCKS_4ROUND
	LXVW4X (rk)(R10), V8
	PROCESS_8BLOCKS_4ROUND
	LXVW4X (rk)(R11), V8
	PROCESS_8BLOCKS_4ROUND
	LXVW4X (rk)(R12), V8
	PROCESS_8BLOCKS_4ROUND
	LXVW4X (rk)(R14), V8
	PROCESS_8BLOCKS_4ROUND
	LXVW4X (rk)(R15), V8
	PROCESS_8BLOCKS_4ROUND

	TRANSPOSE_MATRIX(V0, V1, V2, V3)
	TRANSPOSE_MATRIX(V4, V5, V6, V7)

	PPC64X_STXVW4X(V0, dstPtr, R0)
	PPC64X_STXVW4X(V1, dstPtr, R7)
	PPC64X_STXVW4X(V2, dstPtr, R8)
	PPC64X_STXVW4X(V3, dstPtr, R10)
	PPC64X_STXVW4X(V4, dstPtr, R11)
	PPC64X_STXVW4X(V5, dstPtr, R12)
	PPC64X_STXVW4X(V6, dstPtr, R14)
	PPC64X_STXVW4X(V7, dstPtr, R15)

	ADD $128, srcPtr
	ADD $128, dstPtr
	BDNZ	block128
	BC	12,2,LR		// BEQLR, fast return
	MOVD	R9, srcLen

block64:
	CMP srcLen, $64
	BLT lessThan64
	PPC64X_LXVW4X(srcPtr, R0, V0)
	PPC64X_LXVW4X(srcPtr, R7, V1)
	PPC64X_LXVW4X(srcPtr, R8, V2)
	PPC64X_LXVW4X(srcPtr, R10, V3)
	PRE_TRANSPOSE_MATRIX(V0, V1, V2, V3)
	LXVW4X (rk)(R0), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R7), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R8), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R10), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R11), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R12), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R14), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R15), V8
	PROCESS_4BLOCKS_4ROUND
	TRANSPOSE_MATRIX(V0, V1, V2, V3)
	PPC64X_STXVW4X(V0, dstPtr, R0)
	PPC64X_STXVW4X(V1, dstPtr, R7)
	PPC64X_STXVW4X(V2, dstPtr, R8)
	PPC64X_STXVW4X(V3, dstPtr, R10)
	ADD $64, srcPtr
	ADD $64, dstPtr
	ADD $-64, srcLen

lessThan64:
	CMPU srcLen, $48, CR1
	CMPU srcLen, $32, CR2
	CMPU srcLen, $16, CR3
	BEQ CR1, block48
	BEQ CR2, block32
	BEQ CR3, block16
	RET

block48:
	PPC64X_LXVW4X(srcPtr, R0, V0)
	PPC64X_LXVW4X(srcPtr, R7, V1)
	PPC64X_LXVW4X(srcPtr, R8, V2)
	PRE_TRANSPOSE_MATRIX(V0, V1, V2, V3)
	LXVW4X (rk)(R0), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R7), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R8), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R10), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R11), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R12), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R14), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R15), V8
	PROCESS_4BLOCKS_4ROUND
	TRANSPOSE_MATRIX(V0, V1, V2, V3)
	PPC64X_STXVW4X(V0, dstPtr, R0)
	PPC64X_STXVW4X(V1, dstPtr, R7)
	PPC64X_STXVW4X(V2, dstPtr, R8)
	RET

block32:
	PPC64X_LXVW4X(srcPtr, R0, V0)
	PPC64X_LXVW4X(srcPtr, R7, V1)
	PRE_TRANSPOSE_MATRIX(V0, V1, V2, V3)
	LXVW4X (rk)(R0), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R7), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R8), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R10), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R11), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R12), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R14), V8
	PROCESS_4BLOCKS_4ROUND
	LXVW4X (rk)(R15), V8
	PROCESS_4BLOCKS_4ROUND
	TRANSPOSE_MATRIX(V0, V1, V2, V3)
	PPC64X_STXVW4X(V0, dstPtr, R0)
	PPC64X_STXVW4X(V1, dstPtr, R7)
	RET

block16:
	PPC64X_LXVW4X(srcPtr, R0, V0)
	VSLDOI $4, V0, V0, V1
	VSLDOI $4, V1, V1, V2
	VSLDOI $4, V2, V2, V3
	LXVW4X (rk)(R0), V8
	PROCESS_SINGLEBLOCK_4ROUND
	LXVW4X (rk)(R7), V8
	PROCESS_SINGLEBLOCK_4ROUND
	LXVW4X (rk)(R8), V8
	PROCESS_SINGLEBLOCK_4ROUND
	LXVW4X (rk)(R10), V8
	PROCESS_SINGLEBLOCK_4ROUND
	LXVW4X (rk)(R11), V8
	PROCESS_SINGLEBLOCK_4ROUND
	LXVW4X (rk)(R12), V8
	PROCESS_SINGLEBLOCK_4ROUND
	LXVW4X (rk)(R14), V8
	PROCESS_SINGLEBLOCK_4ROUND
	LXVW4X (rk)(R15), V8
	PROCESS_SINGLEBLOCK_4ROUND
	VSLDOI $4, V3, V3, V3
	VSLDOI $4, V3, V2, V2
	VSLDOI $4, V2, V1, V1
	VSLDOI $4, V1, V0, V0
	PPC64X_STXVW4X(V0, dstPtr, R0)
	RET
