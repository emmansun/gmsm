// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

#define a V0
#define e V1
#define b V2
#define f V3
#define c V4
#define g V5
#define d V6
#define h V7
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

#define TRANSPOSE_MATRIX(T0, T1, T2, T3, TMP0, TMP1, TMP2, TMP3) \
	VMRHF T0, T1, TMP0;     \
	VMRHF T2, T3, TMP1;     \
	VMRLF T0, T1, TMP2;     \
	VMRLF T2, T3, TMP3;     \
	VPDI $0x2, TMP0, TMP1, T0; \
	VPDI $0x7, TMP0, TMP1, T1; \
	VPDI $0x2, TMP2, TMP3, T2; \
	VPDI $0x7, TMP2, TMP3, T3

// r = s <<< n
#define PROLD(s, r, n) \
	VERLLF $n, s, r

#define loadWordByIndex(W, i) \
	VL (16*(i))(statePtr), W

// one word is 16 bytes
#define prepare4Words \
	VL (srcPtr1)(srcPtrPtr*1), V16; \
	VL (srcPtr2)(srcPtrPtr*1), V17; \
	VL (srcPtr3)(srcPtrPtr*1), V18; \
	VL (srcPtr4)(srcPtrPtr*1), V19; \
	TRANSPOSE_MATRIX(V16, V17, V18, V19, TMP0, TMP1, TMP2, TMP3); \
	VSTM V16, V19, (wordPtr); \
	LAY 16(srcPtrPtr), srcPtrPtr; \
	ADD $64, wordPtr

#define ROUND_00_11(index, a, b, c, d, e, f, g, h) \
	PROLD(a, TMP0, 12)               \
	VLR TMP0, TMP1                   \
	VLREPF (index*4)(kPtr), TMP2     \ // It seems that the VREPIF instruction is not supported yet.
	VAF TMP2, TMP0, TMP0             \
	VAF e, TMP0, TMP0                \
	PROLD(TMP0, TMP2, 7)             \ // TMP2 = SS1
	VX TMP2, TMP1, TMP0              \ // TMP0 = SS2
	VX a, b, TMP1                    \
	VX c, TMP1, TMP1                 \
	VAF TMP1, d, TMP1                \ // TMP1 = (a XOR b XOR c) + d
	loadWordByIndex(TMP3, index)     \
	loadWordByIndex(TMP4, index+4)   \
	VX TMP3, TMP4, TMP4              \
	VAF TMP4, TMP1, TMP1             \ // TMP1 = (a XOR b XOR c) + d + (Wt XOR Wt+4)
	VAF TMP1, TMP0, TMP1             \ // TMP1 = TT1
	VAF h, TMP3, TMP3                \
	VAF TMP3, TMP2, TMP3             \ // Wt + h + SS1
	VX e, f, TMP4                    \
	VX g, TMP4, TMP4                 \
	VAF TMP4, TMP3, TMP3             \ // TT2 = (e XOR f XOR g) + Wt + h + SS1
	VLR b, TMP4                      \
	PROLD(TMP4, b, 9)                \ // b = b <<< 9
	VLR TMP1, h                      \ // h = TT1
	VLR f, TMP4                      \
	PROLD(TMP4, f, 19)               \ // f = f <<< 19
	PROLD(TMP3, TMP4, 9)             \ // TMP4 = TT2 <<< 9
	PROLD(TMP4, TMP0, 8)             \ // TMP0 = TT2 <<< 17
	VX TMP3, TMP4, TMP4              \ // TMP4 = TT2 XOR (TT2 <<< 9)
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

#define ROUND_12_15(index, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index)                        \
	ROUND_00_11(index, a, b, c, d, e, f, g, h)     \

#define ROUND_16_63(index, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index)          \ // TMP1 is Wt+4 now, Pls do not use it
	PROLD(a, TMP0, 12)               \
	VLR TMP0, TMP4                   \
	VLREPF (index*4)(kPtr), TMP2     \ // It seems that the VREPIF instruction is not supported yet.
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

	VLM (digPtr), V0, V7
	VSTM V0, V7, (dstPtr)

	RET
#undef digPtr
#undef dstPtr

// Used general purpose registers R1-R11.
// blockMultBy4(dig **[8]uint32, p **byte, buffer *byte, blocks int)
TEXT ·blockMultBy4(SB), NOSPLIT, $0
#define digPtr R11
#define srcPtrPtr R1
#define statePtr R2
#define kPtr R3
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

	TRANSPOSE_MATRIX(a, b, c, d, TMP0, TMP1, TMP2, TMP3)
	TRANSPOSE_MATRIX(e, f, g, h, TMP0, TMP1, TMP2, TMP3)

	MOVD (srcPtrPtr), srcPtr1
	MOVD 8(srcPtrPtr), srcPtr2
	MOVD 16(srcPtrPtr), srcPtr3
	MOVD 24(srcPtrPtr), srcPtr4
	MOVD $0, srcPtrPtr

	MOVD $·_K+0(SB), kPtr

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

	ROUND_00_11(0, a, b, c, d, e, f, g, h)
	ROUND_00_11(1, h, a, b, c, d, e, f, g)
	ROUND_00_11(2, g, h, a, b, c, d, e, f)
	ROUND_00_11(3, f, g, h, a, b, c, d, e)
	ROUND_00_11(4, e, f, g, h, a, b, c, d)
	ROUND_00_11(5, d, e, f, g, h, a, b, c)
	ROUND_00_11(6, c, d, e, f, g, h, a, b)
	ROUND_00_11(7, b, c, d, e, f, g, h, a)
	ROUND_00_11(8, a, b, c, d, e, f, g, h)
	ROUND_00_11(9, h, a, b, c, d, e, f, g)
	ROUND_00_11(10, g, h, a, b, c, d, e, f)
	ROUND_00_11(11, f, g, h, a, b, c, d, e)

	ROUND_12_15(12, e, f, g, h, a, b, c, d)
	ROUND_12_15(13, d, e, f, g, h, a, b, c)
	ROUND_12_15(14, c, d, e, f, g, h, a, b)
	ROUND_12_15(15, b, c, d, e, f, g, h, a)

	ROUND_16_63(16, a, b, c, d, e, f, g, h)
	ROUND_16_63(17, h, a, b, c, d, e, f, g)
	ROUND_16_63(18, g, h, a, b, c, d, e, f)
	ROUND_16_63(19, f, g, h, a, b, c, d, e)
	ROUND_16_63(20, e, f, g, h, a, b, c, d)
	ROUND_16_63(21, d, e, f, g, h, a, b, c)
	ROUND_16_63(22, c, d, e, f, g, h, a, b)
	ROUND_16_63(23, b, c, d, e, f, g, h, a)
	ROUND_16_63(24, a, b, c, d, e, f, g, h)
	ROUND_16_63(25, h, a, b, c, d, e, f, g)
	ROUND_16_63(26, g, h, a, b, c, d, e, f)
	ROUND_16_63(27, f, g, h, a, b, c, d, e)
	ROUND_16_63(28, e, f, g, h, a, b, c, d)
	ROUND_16_63(29, d, e, f, g, h, a, b, c)
	ROUND_16_63(30, c, d, e, f, g, h, a, b)
	ROUND_16_63(31, b, c, d, e, f, g, h, a)
	ROUND_16_63(32, a, b, c, d, e, f, g, h)
	ROUND_16_63(33, h, a, b, c, d, e, f, g)
	ROUND_16_63(34, g, h, a, b, c, d, e, f)
	ROUND_16_63(35, f, g, h, a, b, c, d, e)
	ROUND_16_63(36, e, f, g, h, a, b, c, d)
	ROUND_16_63(37, d, e, f, g, h, a, b, c)
	ROUND_16_63(38, c, d, e, f, g, h, a, b)
	ROUND_16_63(39, b, c, d, e, f, g, h, a)
	ROUND_16_63(40, a, b, c, d, e, f, g, h)
	ROUND_16_63(41, h, a, b, c, d, e, f, g)
	ROUND_16_63(42, g, h, a, b, c, d, e, f)
	ROUND_16_63(43, f, g, h, a, b, c, d, e)
	ROUND_16_63(44, e, f, g, h, a, b, c, d)
	ROUND_16_63(45, d, e, f, g, h, a, b, c)
	ROUND_16_63(46, c, d, e, f, g, h, a, b)
	ROUND_16_63(47, b, c, d, e, f, g, h, a)
	ROUND_16_63(48, a, b, c, d, e, f, g, h)
	ROUND_16_63(49, h, a, b, c, d, e, f, g)
	ROUND_16_63(50, g, h, a, b, c, d, e, f)
	ROUND_16_63(51, f, g, h, a, b, c, d, e)
	ROUND_16_63(52, e, f, g, h, a, b, c, d)
	ROUND_16_63(53, d, e, f, g, h, a, b, c)
	ROUND_16_63(54, c, d, e, f, g, h, a, b)
	ROUND_16_63(55, b, c, d, e, f, g, h, a)
	ROUND_16_63(56, a, b, c, d, e, f, g, h)
	ROUND_16_63(57, h, a, b, c, d, e, f, g)
	ROUND_16_63(58, g, h, a, b, c, d, e, f)
	ROUND_16_63(59, f, g, h, a, b, c, d, e)
	ROUND_16_63(60, e, f, g, h, a, b, c, d)
	ROUND_16_63(61, d, e, f, g, h, a, b, c)
	ROUND_16_63(62, c, d, e, f, g, h, a, b)
	ROUND_16_63(63, b, c, d, e, f, g, h, a)

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

	TRANSPOSE_MATRIX(a, b, c, d, TMP0, TMP1, TMP2, TMP3)
	TRANSPOSE_MATRIX(e, f, g, h, TMP0, TMP1, TMP2, TMP3)

	MOVD 	0(digPtr), R4
	VSTM a, e, (R4)
	MOVD 	8(digPtr), R4
	VSTM b, f, (R4)
	MOVD 	16(digPtr), R4
	VSTM c, g, (R4)
	MOVD 	24(digPtr), R4
	VSTM d, h, (R4)

	RET
