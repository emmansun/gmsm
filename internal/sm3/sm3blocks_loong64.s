// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

#define ZERO R0
#define RSP R3
#define REG_KT R31

#define a V0
#define e V1
#define b V2
#define f V3
#define c V4
#define g V5
#define d V6
#define h V7

#define tmp1 V8
#define tmp2 V9
#define tmp3 V10
#define tmp4 V11

#define ZERO_VECTOR V23
#define aSave V24
#define bSave V25
#define cSave V26
#define dSave V27
#define eSave V28
#define fSave V29
#define gSave V30
#define hSave V31

// input: from high to low
// t0 = t0.S3, t0.S2, t0.S1, t0.S0
// t1 = t1.S3, t1.S2, t1.S1, t1.S0
// t2 = t2.S3, t2.S2, t2.S1, t2.S0
// t3 = t3.S3, t3.S2, t3.S1, t3.S0
// output: from high to low
// t0 = t3.S0, t2.S0, t1.S0, t0.S0
// t1 = t3.S1, t2.S1, t1.S1, t0.S1
// t2 = t3.S2, t2.S2, t1.S2, t0.S2
// t3 = t3.S3, t2.S3, t1.S3, t0.S3
#define TRANSPOSE_MATRIX(t0, t1, t2, t3, RTMP0, RTMP1, RTMP2, RTMP3) \
	VILVLW t0, t1, RTMP0; /* RTMP0 = {t1.S1, t0.S1, t1.S0, t0.S0} */ \
	VILVLW t2, t3, RTMP1; /* RTMP0 = {t3.S1, t2.S1, t3.S0, t2.S0} */ \
	VILVHW t0, t1, RTMP2; /* RTMP2 = {t1.S3, t0.S3, t1.S2, t0.S2} */ \
	VILVHW t2, t3, RTMP3; /* RTMP3 = {t3.S3, t2.S3, t3.S2, t2.S2} */ \
	VILVLV RTMP0, RTMP1, t0; /* t0 = {t3.S0, t2.S0, t1.S0, t0.S0} */ \
	VILVHV RTMP0, RTMP1, t1; /* t1 = {t3.S1, t2.S1, t1.S1, t0.S1} */ \
	VILVLV RTMP2, RTMP3, t2; /* t2 = {t3.S2, t2.S2, t1.S2, t0.S2} */ \
	VILVHV RTMP2, RTMP3, t3; /* t3 = {t3.S3, t2.S3, t1.S3, t0.S3} */

#define prepare4Words(index) \
    VMOVQ (index*16)(srcPtr1), V12; \
    VMOVQ (index*16)(srcPtr2), V13; \
    VMOVQ (index*16)(srcPtr3), V14; \
    VMOVQ (index*16)(srcPtr4), V15; \
	TRANSPOSE_MATRIX(V12, V13, V14, V15, tmp1, tmp2, tmp3, tmp4); \
    VSHUF4IB $0x1B, V12, V12; \
    VSHUF4IB $0x1B, V13, V13; \
    VSHUF4IB $0x1B, V14, V14; \
    VSHUF4IB $0x1B, V15, V15; \
    VMOVQ V12, (0*16)(wordPtr); \
    VMOVQ V13, (1*16)(wordPtr); \
    VMOVQ V14, (2*16)(wordPtr); \
    VMOVQ V15, (3*16)(wordPtr); \
    ADDV $64, wordPtr, wordPtr

#define loadWordByIndex(W, i) \
    VMOVQ (16*(i))(wordStart), W \

#define LOAD_T(index, T) \
    VMOVQ (index*4)(REG_KT), T.W4

#define ROUND_00_11(index, a, b, c, d, e, f, g, h) \
	VROTRW $(32-12), a, V12; \
	LOAD_T(index, tmp1); \
	VADDW tmp1, V12, V13; \
	VADDW e, V13, V13; \
	VROTRW $(32-7), V13, V14; \  // ss1
	VXORV V12, V14, V12; \       // ss2
	VXORV a, b, V13; \
	VXORV c, V13, V13; \
	VADDW d, V13, V13; \     // tt1 part1
	loadWordByIndex(tmp3, index); \
	loadWordByIndex(tmp4, index+4)    \
	VXORV tmp3, tmp4, tmp4; \   // Wt XOR Wt+4
	VADDW h, tmp3, tmp3; \      // tt2 part1: h + Wt
	VADDW tmp4, V13, V13; \ 
	VADDW V12, V13, h; \      // tt1
	VADDW V14, tmp3, tmp3; \
	VXORV e, f, tmp4; \
	VXORV g, tmp4, tmp4; \
	VADDW tmp4, tmp3, tmp3;      // tt2
	VROTRW $(32-9), b, b; \
	VROTRW $(32-19), f, f; \
	; \ // P0(tt2)
	VROTRW $(32-9), tmp3, tmp4; \
	VXORV tmp3, tmp4, tmp4; \
	VROTRW $(32-17), tmp3, tmp3; \
	VXORV tmp3, tmp4, d

#define MESSAGE_SCHEDULE(index) \
	loadWordByIndex(tmp3, index+1)    \ // Wj-3
	VROTRW $(32-15), tmp3, tmp4; \    // ROTL15(Wj-3)
	loadWordByIndex(tmp3, index-12)   \ // Wj-16
	VXORV tmp3, tmp4, tmp4; \        // x part1
	loadWordByIndex(tmp3, index-5)    \ // Wj-9
	VXORV tmp3, tmp4, tmp4; \        // x
	VROTRW $(32-15), tmp4, tmp3; \     // ROT
	VXORV tmp3, tmp4, tmp3; \      // p1(x) part1
	VROTRW $(32-23), tmp4, tmp4; \    // ROTL23(x)
	VXORV tmp4, tmp3, tmp3; \      // p1(x)
	loadWordByIndex(tmp4, index-9)    \ // Wj-13
	VROTRW $(32-7), tmp4, tmp4; \     // ROTL7(Wj-13)
	VXORV tmp4, tmp3, tmp3; \      // p1(x) XOR ROTL7(Wj-13)
	loadWordByIndex(tmp4, index-2)    \ // Wj-6
	VXORV tmp3, tmp4, tmp4; \      // Wj
	VMOVQ tmp4, (wordPtr); \
	ADDV $16, wordPtr, wordPtr

#define ROUND_12_15(index, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index)                               \
	ROUND_00_11(index, a, b, c, d, e, f, g, h)     \

#define ROUND_16_63(index, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index)          \ // tmp4 is Wt+4 now, Pls do not use it
	VROTRW $(32-12), a, V12; \
	LOAD_T(index, tmp1); \
	VADDW tmp1, V12, V13; \
	VADDW e, V13, V13; \
	VROTRW $(32-7), V13, V14; \  // ss1
	VXORV V12, V14, V12; \       // ss2
	VORV a, b, tmp3; \
	VANDV a, b, V13; \
	VANDV tmp3, c, tmp3; \
	VXORV V13, tmp3, V13; \   // ff2
	VADDW d, V13, V13; \     // tt1 part1
	loadWordByIndex(tmp3, index); \
	VXORV tmp3, tmp4, tmp4; \   // Wt XOR Wt+4
	VADDW h, tmp3, tmp3; \      // tt2 part1: h + Wt
	VADDW tmp4, V13, V13; \ 
	VADDW V12, V13, h; \      // tt1
	VADDW V14, tmp3, tmp3; \  // ss1 + h + Wt
	VXORV f, g, tmp4; \
	VANDV e, tmp4, tmp4; \
	VXORV g, tmp4, tmp4; \   // gg2
	VADDW tmp4, tmp3, tmp3;   // tt2
	VROTRW $(32-9), b, b; \
	VROTRW $(32-19), f, f; \
	; \ // P0(tt2)
	VROTRW $(32-9), tmp3, tmp4; \
	VXORV tmp3, tmp4, tmp4; \
	VROTRW $(32-17), tmp3, tmp3; \
	VXORV tmp3, tmp4, d

// blockMultBy4(dig **[8]uint32, p **byte, buffer *byte, blocks int)
TEXT ·blockMultBy4(SB), NOSPLIT, $0
#define digPtr R5
#define srcPtrPtr R6
#define blockCount R7
#define wordStart R8
#define srcPtr1 R9
#define srcPtr2 R10
#define srcPtr3 R11
#define srcPtr4 R12
#define wordPtr R13
	MOVV	dig+0(FP), digPtr
	MOVV	p+8(FP), srcPtrPtr
	MOVV	buffer+16(FP), wordStart
	MOVV	blocks+24(FP), blockCount

	// load state
	MOVV (0*8)(digPtr), R20
    VMOVQ (0*16)(R20), a
    VMOVQ (1*16)(R20), e
    MOVV (1*8)(digPtr), R20
    VMOVQ (0*16)(R20), b
    VMOVQ (1*16)(R20), f
    MOVV (2*8)(digPtr), R20
    VMOVQ (0*16)(R20), c
    VMOVQ (1*16)(R20), g
    MOVV (3*8)(digPtr), R20
    VMOVQ (0*16)(R20), d
    VMOVQ (1*16)(R20), h

	// transpose state
	TRANSPOSE_MATRIX(a, b, c, d, tmp1, tmp2, tmp3, tmp4)
	TRANSPOSE_MATRIX(e, f, g, h, tmp1, tmp2, tmp3, tmp4)

    MOVV	(0*8)(srcPtrPtr), srcPtr1
    MOVV	(1*8)(srcPtrPtr), srcPtr2
    MOVV	(2*8)(srcPtrPtr), srcPtr3
    MOVV	(3*8)(srcPtrPtr), srcPtr4
    
    VXORV ZERO_VECTOR, ZERO_VECTOR, ZERO_VECTOR
    MOVV	$·_K(SB), REG_KT		// const table

loop:
    // loong64 can't move from vector register to vector register directly now.
    VXORV a, ZERO_VECTOR, aSave
    VXORV b, ZERO_VECTOR, bSave
    VXORV c, ZERO_VECTOR, cSave
    VXORV d, ZERO_VECTOR, dSave
    VXORV e, ZERO_VECTOR, eSave
    VXORV f, ZERO_VECTOR, fSave
    VXORV g, ZERO_VECTOR, gSave
    VXORV h, ZERO_VECTOR, hSave

    // reset wordPtr
	MOVV wordStart, wordPtr

	// load message block
	prepare4Words(0)
	prepare4Words(1)
	prepare4Words(2)
	prepare4Words(3)

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

    VXORV aSave, a, a
    VXORV bSave, b, b
    VXORV cSave, c, c
    VXORV dSave, d, d
    VXORV eSave, e, e
    VXORV fSave, f, f
    VXORV gSave, g, g
    VXORV hSave, h, h

	ADDV $64, srcPtr1, srcPtr1
	ADDV $64, srcPtr2, srcPtr2
	ADDV $64, srcPtr3, srcPtr3
	ADDV $64, srcPtr4, srcPtr4

    SUBV $1, blockCount, blockCount
    BNE blockCount, loop

	// transpose state
	TRANSPOSE_MATRIX(a, b, c, d, tmp1, tmp2, tmp3, tmp4)
	TRANSPOSE_MATRIX(e, f, g, h, tmp1, tmp2, tmp3, tmp4)

    // store state
    MOVV	(0*8)(digPtr), R20
    VMOVQ a, (0*16)(R20)
    VMOVQ e, (1*16)(R20)
    MOVV	(1*8)(digPtr), R20
    VMOVQ b, (0*16)(R20)
    VMOVQ f, (1*16)(R20)
    MOVV	(2*8)(digPtr), R20
    VMOVQ c, (0*16)(R20)
    VMOVQ g, (1*16)(R20)
    MOVV	(3*8)(digPtr), R20
    VMOVQ d, (0*16)(R20)
    VMOVQ h, (1*16)(R20)

    RET


#undef digPtr
#undef a
#undef b
#undef c
#undef d
#undef e
#undef f
#undef g
#undef h

#define a V0
#define b V1
#define c V2
#define d V3
#define e V4
#define f V5
#define g V6
#define h V7
// func copyResultsBy4(dig *uint32, dst *byte)
TEXT ·copyResultsBy4(SB),NOSPLIT,$0
#define digPtr R4
#define dstPtr R5
	MOVV	dig+0(FP), digPtr
	MOVV	dst+8(FP), dstPtr

	// load state
    VMOVQ (0*16)(digPtr), a
    VMOVQ (1*16)(digPtr), b
    VMOVQ (2*16)(digPtr), c
    VMOVQ (3*16)(digPtr), d
    VMOVQ (4*16)(digPtr), e
    VMOVQ (5*16)(digPtr), f
    VMOVQ (6*16)(digPtr), g
    VMOVQ (7*16)(digPtr), h

    VSHUF4IB $0x1B, a, a
    VSHUF4IB $0x1B, b, b
    VSHUF4IB $0x1B, c, c
    VSHUF4IB $0x1B, d, d
    VSHUF4IB $0x1B, e, e
    VSHUF4IB $0x1B, f, f
    VSHUF4IB $0x1B, g, g
    VSHUF4IB $0x1B, h, h

    VMOVQ a, (0*16)(dstPtr)
    VMOVQ b, (1*16)(dstPtr)
    VMOVQ c, (2*16)(dstPtr)
    VMOVQ d, (3*16)(dstPtr)
    VMOVQ e, (4*16)(dstPtr)
    VMOVQ f, (5*16)(dstPtr)
    VMOVQ g, (6*16)(dstPtr)
    VMOVQ h, (7*16)(dstPtr)
	RET
