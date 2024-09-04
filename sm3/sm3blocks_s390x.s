// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"
#include "go_asm.h"
#include "sm3_const_asm.s"

DATA mask<>+0x00(SB)/8, $0x0001020310111213
DATA mask<>+0x08(SB)/8, $0x0405060714151617
DATA mask<>+0x10(SB)/8, $0x08090a0b18191a1b
DATA mask<>+0x18(SB)/8, $0x0c0d0e0f1c1d1e1f
DATA mask<>+0x20(SB)/8, $0x0001020304050607
DATA mask<>+0x28(SB)/8, $0x1011121314151617
DATA mask<>+0x30(SB)/8, $0x08090a0b0c0d0e0f
DATA mask<>+0x38(SB)/8, $0x18191a1b1c1d1e1f
GLOBL mask<>(SB), 8, $64

#define a V0
#define e V1
#define b V2
#define f V3
#define c V4
#define g V5
#define d V6
#define h V7
#define M0 V8
#define M1 V9
#define M2 V10
#define M3 V11
#define TMP0 V12
#define TMP1 V13
#define TMP2 V14
#define TMP3 V15
#define TMP4 V16
#define aSave V24
#define bSave V25
#define cSave V26
#define dSave V27
#define eSave V28
#define fSave V29
#define gSave V30
#define hSave V31

#define TRANSPOSE_MATRIX(T0, T1, T2, T3, M0, M1, M2, M3, TMP0, TMP1, TMP2, TMP3) \
	VPERM T0, T1, M0, TMP0; \
	VPERM T2, T3, M0, TMP1; \
	VPERM T0, T1, M1, TMP2; \
	VPERM T2, T3, M1, TMP3; \
	VPERM TMP0, TMP1, M2, T0; \
	VPERM TMP0, TMP1, M3, T1; \
	VPERM TMP2, TMP3, M2, T2; \
	VPERM TMP2, TMP3, M3, T3

// r = s <<< n
#define PROLD(s, r, n) \
	VERLLF $n, s, r

#define loadWordByIndex(W, i) \
	VL (16*i)(statePtr), W

// one word is 16 bytes
#define prepare4Words \
	VL (srcPtr1)(srcPtrPtr*1), V16; \
	VL (srcPtr2)(srcPtrPtr*1), V17; \
	VL (srcPtr3)(srcPtrPtr*1), V18; \
	VL (srcPtr4)(srcPtrPtr*1), V19; \
	TRANSPOSE_MATRIX(V16, V17, V18, V19, M0, M1, M2, M3, TMP0, TMP1, TMP2, TMP3); \
	VSTM V16, V19, (wordPtr); \
	LAY 16(srcPtrPtr), srcPtrPtr; \
	ADD $64, wordPtr

#define ROUND_00_11(index, const, a, b, c, d, e, f, g, h) \
	PROLD(a, TMP0, 12)               \
	VLR TMP0, TMP1                   \
	VLREPF (index*4)(R3), TMP2       \
	VAF TMP2, TMP1, TMP1             \
	VAF e, TMP1, TMP1                \
	PROLD(TMP1, TMP2, 7)             \ // TMP2 = SS1
	VX TMP2, TMP1, TMP0			     \ // TMP0 = SS2
	VX a, b, TMP1                    \
	VX c, TMP1, TMP1				 \
	VAF TMP1, d, TMP1                \ // TMP1 = (a XOR b XOR c) + d
	loadWordByIndex(TMP3, index)     \
	loadWordByIndex(TMP4, index+4)   \
	VX TMP3, TMP4, TMP4              \
	VAF TMP4, TMP1, TMP1             \ // TMP1 = (a XOR b XOR c) + d + (Wt XOR Wt+4)
	VAF TMP1, TMP0, TMP1			 \ // TMP1 = TT1
	VAF h, TMP3, TMP3				 \
	VAF TMP3, TMP2, TMP3			 \ // Wt + h + SS1
	VX e, f, TMP4 				     \
	VX g, TMP4, TMP4				 \
	VAF TMP4, TMP3, TMP3			 \ // TT2 = (e XOR f XOR g) + Wt + h + SS1
	VLR b, TMP4 					 \
	PROLD(TMP4, b, 9)                \ // b = b <<< 9
	VLR TMP1, h					     \ // h = TT1
	VLR f, TMP4 					 \
	PROLD(TMP4, f, 19)               \ // f = f <<< 19
	PROLD(TMP3, TMP4, 9)             \ // TMP4 = TT2 <<< 9
	PROLD(TMP4, TMP0, 8)             \ // TMP0 = TT2 <<< 17
	VX TMP3, TMP4, TMP4 			 \ // TMP4 = TT2 XOR (TT2 <<< 9)
	VX TMP4, TMP0, d                 \ // d = TT2 XOR (TT2 <<< 9) XOR (TT2 <<< 17)

#define MESSAGE_SCHEDULE(index) \
	loadWordByIndex(TMP0, index+1)    \ // Wj-3
	PROLD(TMP0, TMP1, 15)             \
	loadWordByIndex(TMP0, index-12)   \ // Wj-16
	VX TMP0, TMP1, TMP0               \
	loadWordByIndex(TMP1, index-5)    \ // Wj-9
	VX TMP0, TMP1, TMP0               \
	PROLD(TMP0, TMP1, 15)             \
	PROLD(TMP1, TMP2, 8)              \
	VX TMP1, TMP0, TMP0               \
	VX TMP2, TMP0, TMP0               \ // P1
	loadWordByIndex(TMP1, index-9)    \ // Wj-13
	PROLD(TMP1, TMP2, 7)              \
	VX TMP2, TMP0, TMP0               \
	loadWordByIndex(TMP1, index-2)    \ // Wj-6
	VX TMP1, TMP0, TMP1               \
	VST TMP1, (wordPtr)               \
	ADD $16, wordPtr                  \

#define ROUND_12_15(index, const, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index)                               \
	ROUND_00_11(index, const, a, b, c, d, e, f, g, h)     \

#define ROUND_16_63(index, const, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index)          \ // TMP1 is Wt+4 now, Pls do not use it
	PROLD(a, TMP0, 12)               \
	VLR TMP0, TMP4                   \
	VLREPF (index*4)(R3), TMP2       \
	VAF TMP2, TMP0, TMP0             \
	VAF e, TMP0, TMP0                \
	PROLD(TMP0, TMP2, 7)             \ // TMP2 = SS1
	VX TMP2, TMP4, TMP0              \ // TMP0 = SS2
	VO a, b, TMP3                    \
	VN a, b, TMP4                    \
	VN c, TMP3, TMP3                 \
	VO TMP4, TMP3, TMP4              \ // (a AND b) OR (a AND c) OR (b AND c)
	VAF TMP4, d, TMP4                \ // (a AND b) OR (a AND c) OR (b AND c) + d
	loadWordByIndex(TMP3, index)     \ // Wj
	VX TMP3, TMP1, TMP1              \ // Wj XOR Wj+4
	VAF TMP4, TMP1, TMP4             \ // (a AND b) OR (a AND c) OR (b AND c) + d + (Wt XOR Wt+4)
	VAF TMP4, TMP0, TMP4             \ // TT1
	VAF h, TMP3, TMP3                \ // Wt + h
	VAF TMP2, TMP3, TMP3             \ // Wt + h + SS1
	VX f, g, TMP1                    \
	VN TMP1, e, TMP1                 \
	VX g, TMP1, TMP1                 \ // (f XOR g) AND e XOR g
	VAF TMP3, TMP1, TMP3             \ // TT2
	VLR b, TMP1                      \
	PROLD(TMP1, b, 9)                \ // b = b <<< 9
	VLR TMP4, h                      \ // h = TT1
	VLR f, TMP1                      \
	PROLD(TMP1, f, 19)               \ // f = f <<< 19
	PROLD(TMP3, TMP1, 9)             \ // TMP1 = TT2 <<< 9
	PROLD(TMP1, TMP0, 8)             \ // TMP0 = TT2 <<< 17
	VX TMP3, TMP1, TMP1              \ // TMP1 = TT2 XOR (TT2 <<< 9)
	VX TMP1, TMP0, d                 \ // d = TT2 XOR (TT2 <<< 9) XOR (TT2 <<< 17)

// func copyResultsBy4(dig *uint32, dst *byte)
TEXT ·copyResultsBy4(SB),NOSPLIT,$0
#define digPtr R3
#define dstPtr R4
	MOVD	dig+0(FP), digPtr
	MOVD	dst+8(FP), dstPtr

	// load state
	VLM (digPtr), V0, V7
	VSTM V0, V7, (dstPtr)

	RET
#undef digPtr
#undef dstPtr

// blockMultBy4(dig **[8]uint32, p **byte, buffer *byte, blocks int)
TEXT ·blockMultBy4(SB), NOSPLIT, $0
#define digPtr R11
#define srcPtrPtr R1
#define statePtr R2
#define blockCount R5
#define srcPtr1 R6
#define srcPtr2 R7
#define srcPtr3 R8
#define srcPtr4 R9
#define wordPtr R10
	MOVD	dig+0(FP), digPtr
	MOVD	p+8(FP), srcPtrPtr
	MOVD	buffer+16(FP), statePtr
	MOVD	blocks+24(FP), blockCount

	// load state
	MOVD 0(digPtr), R4
	VLM (R4), a, e
	MOVD 8(digPtr), R4
	VLM (R4), b, f
	MOVD 16(digPtr), R4
	VLM (R4), c, g
	MOVD 24(digPtr), R4
	VLM (R4), d, h

	MOVD $mask<>+0x00(SB), R4
	VLM (R4), M0, M3

	TRANSPOSE_MATRIX(a, b, c, d, M0, M1, M2, M3, TMP0, TMP1, TMP2, TMP3)
	TRANSPOSE_MATRIX(e, f, g, h, M0, M1, M2, M3, TMP0, TMP1, TMP2, TMP3)

	MOVD (srcPtrPtr), srcPtr1
	MOVD 8(srcPtrPtr), srcPtr2
	MOVD 16(srcPtrPtr), srcPtr3
	MOVD 24(srcPtrPtr), srcPtr4
	MOVD $0, srcPtrPtr

	MOVD $·_K+0(SB), R3

loop:
	// save state
	VLR a, aSave
	VLR b, bSave
	VLR c, cSave
	VLR d, dSave
	VLR e, eSave
	VLR f, fSave
	VLR g, gSave
	VLR h, hSave

	// reset wordPtr
	MOVD statePtr, wordPtr

	// load message block
	prepare4Words
	prepare4Words
	prepare4Words
	prepare4Words

	ROUND_00_11(0, T0, a, b, c, d, e, f, g, h)
	ROUND_00_11(1, T1, h, a, b, c, d, e, f, g)
	ROUND_00_11(2, T2, g, h, a, b, c, d, e, f)
	ROUND_00_11(3, T3, f, g, h, a, b, c, d, e)
	ROUND_00_11(4, T4, e, f, g, h, a, b, c, d)
	ROUND_00_11(5, T5, d, e, f, g, h, a, b, c)
	ROUND_00_11(6, T6, c, d, e, f, g, h, a, b)
	ROUND_00_11(7, T7, b, c, d, e, f, g, h, a)
	ROUND_00_11(8, T8, a, b, c, d, e, f, g, h)
	ROUND_00_11(9, T9, h, a, b, c, d, e, f, g)
	ROUND_00_11(10, T10, g, h, a, b, c, d, e, f)
	ROUND_00_11(11, T11, f, g, h, a, b, c, d, e)

	ROUND_12_15(12, T12, e, f, g, h, a, b, c, d)
	ROUND_12_15(13, T13, d, e, f, g, h, a, b, c)
	ROUND_12_15(14, T14, c, d, e, f, g, h, a, b)
	ROUND_12_15(15, T15, b, c, d, e, f, g, h, a)

	ROUND_16_63(16, T16, a, b, c, d, e, f, g, h)
	ROUND_16_63(17, T17, h, a, b, c, d, e, f, g)
	ROUND_16_63(18, T18, g, h, a, b, c, d, e, f)
	ROUND_16_63(19, T19, f, g, h, a, b, c, d, e)
	ROUND_16_63(20, T20, e, f, g, h, a, b, c, d)
	ROUND_16_63(21, T21, d, e, f, g, h, a, b, c)
	ROUND_16_63(22, T22, c, d, e, f, g, h, a, b)
	ROUND_16_63(23, T23, b, c, d, e, f, g, h, a)
	ROUND_16_63(24, T24, a, b, c, d, e, f, g, h)
	ROUND_16_63(25, T25, h, a, b, c, d, e, f, g)
	ROUND_16_63(26, T26, g, h, a, b, c, d, e, f)
	ROUND_16_63(27, T27, f, g, h, a, b, c, d, e)
	ROUND_16_63(28, T28, e, f, g, h, a, b, c, d)
	ROUND_16_63(29, T29, d, e, f, g, h, a, b, c)
	ROUND_16_63(30, T30, c, d, e, f, g, h, a, b)
	ROUND_16_63(31, T31, b, c, d, e, f, g, h, a)
	ROUND_16_63(32, T32, a, b, c, d, e, f, g, h)
	ROUND_16_63(33, T33, h, a, b, c, d, e, f, g)
	ROUND_16_63(34, T34, g, h, a, b, c, d, e, f)
	ROUND_16_63(35, T35, f, g, h, a, b, c, d, e)
	ROUND_16_63(36, T36, e, f, g, h, a, b, c, d)
	ROUND_16_63(37, T37, d, e, f, g, h, a, b, c)
	ROUND_16_63(38, T38, c, d, e, f, g, h, a, b)
	ROUND_16_63(39, T39, b, c, d, e, f, g, h, a)
	ROUND_16_63(40, T40, a, b, c, d, e, f, g, h)
	ROUND_16_63(41, T41, h, a, b, c, d, e, f, g)
	ROUND_16_63(42, T42, g, h, a, b, c, d, e, f)
	ROUND_16_63(43, T43, f, g, h, a, b, c, d, e)
	ROUND_16_63(44, T44, e, f, g, h, a, b, c, d)
	ROUND_16_63(45, T45, d, e, f, g, h, a, b, c)
	ROUND_16_63(46, T46, c, d, e, f, g, h, a, b)
	ROUND_16_63(47, T47, b, c, d, e, f, g, h, a)
	ROUND_16_63(48, T16, a, b, c, d, e, f, g, h)
	ROUND_16_63(49, T17, h, a, b, c, d, e, f, g)
	ROUND_16_63(50, T18, g, h, a, b, c, d, e, f)
	ROUND_16_63(51, T19, f, g, h, a, b, c, d, e)
	ROUND_16_63(52, T20, e, f, g, h, a, b, c, d)
	ROUND_16_63(53, T21, d, e, f, g, h, a, b, c)
	ROUND_16_63(54, T22, c, d, e, f, g, h, a, b)
	ROUND_16_63(55, T23, b, c, d, e, f, g, h, a)
	ROUND_16_63(56, T24, a, b, c, d, e, f, g, h)
	ROUND_16_63(57, T25, h, a, b, c, d, e, f, g)
	ROUND_16_63(58, T26, g, h, a, b, c, d, e, f)
	ROUND_16_63(59, T27, f, g, h, a, b, c, d, e)
	ROUND_16_63(60, T28, e, f, g, h, a, b, c, d)
	ROUND_16_63(61, T29, d, e, f, g, h, a, b, c)
	ROUND_16_63(62, T30, c, d, e, f, g, h, a, b)
	ROUND_16_63(63, T31, b, c, d, e, f, g, h, a)

	VX a, aSave, a
	VX b, bSave, b
	VX c, cSave, c
	VX d, dSave, d
	VX e, eSave, e
	VX f, fSave, f
	VX g, gSave, g
	VX h, hSave, h

	SUB $1, blockCount
	CMPBGT blockCount, $0, loop

	TRANSPOSE_MATRIX(a, b, c, d, M0, M1, M2, M3, TMP0, TMP1, TMP2, TMP3)
	TRANSPOSE_MATRIX(e, f, g, h, M0, M1, M2, M3, TMP0, TMP1, TMP2, TMP3)

	MOVD 	0(digPtr), R4
	VSTM a, e, (R4)
	MOVD 	8(digPtr), R4
	VSTM b, f, (R4)
	MOVD 	16(digPtr), R4
	VSTM c, g, (R4)
	MOVD 	24(digPtr), R4
	VSTM d, h, (R4)

	RET
