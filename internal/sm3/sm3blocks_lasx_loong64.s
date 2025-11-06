// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

#define ZERO R0
#define RSP R3
#define REG_KT R31

#define a X0
#define e X1
#define b X2
#define f X3
#define c X4
#define g X5
#define d X6
#define h X7

#define tmp1 X8
#define tmp2 X9
#define tmp3 X10
#define tmp4 X11

#define ZERO_VECTOR X23
#define aSave X24
#define bSave X25
#define cSave X26
#define dSave X27
#define eSave X28
#define fSave X29
#define gSave X30
#define hSave X31

// input: from high to low
// t0 = t0.W7, t0.W6, t0.W5, t0.W4 t0.W3, t0.W2, t0.W1, t0.W0
// t1 = t1.W7, t1.W6, t1.W5, t1.W4 t1.W3, t1.W2, t1.W1, t1.W0
// t2 = t2.W7, t2.W6, t2.W5, t2.W4 t2.W3, t2.W2, t2.W1, t2.W0
// t3 = t3.W7, t3.W6, t3.W5, t3.W4 t3.W3, t3.W2, t3.W1, t3.W0
// t4 = t4.W7, t4.W6, t4.W5, t4.W4 t4.W3, t4.W2, t4.W1, t4.W0
// t5 = t5.W7, t5.W6, t5.W5, t5.W4 t5.W3, t5.W2, t5.W1, t5.W0
// t6 = t6.W7, t6.W6, t6.W5, t6.W4 t6.W3, t6.W2, t6.W1, t6.W0
// t7 = t7.W7, t7.W6, t7.W5, t7.W4 t7.W3, t7.W2, t7.W1, t7.W0
// output: from high to low
// t0 = t0.W7, t0.W6, t0.W5, t0.W4 t0.W3, t0.W2, t0.W1, t0.W0
// t1 = t1.W7, t1.W6, t1.W5, t1.W4 t1.W3, t1.W2, t1.W1, t1.W0
// t2 = t2.W7, t2.W6, t2.W5, t2.W4 t2.W3, t2.W2, t2.W1, t2.W0
// t3 = t3.W7, t3.W6, t3.W5, t3.W4 t3.W3, t3.W2, t3.W1, t3.W0
// t4 = t4.W7, t4.W6, t4.W5, t4.W4 t4.W3, t4.W2, t4.W1, t4.W0
// t5 = t5.W7, t5.W6, t5.W5, t5.W4 t5.W3, t5.W2, t5.W1, t5.W0
// t6 = t6.W7, t6.W6, t6.W5, t6.W4 t6.W3, t6.W2, t6.W1, t6.W0
// t7 = t7.W7, t7.W6, t7.W5, t7.W4 t7.W3, t7.W2, t7.W1, t7.W0
// This is a temp solution for transpose 8x8 matrix
#define TRANSPOSE_MATRIX(t0, t1, t2, t3, t4, t5, t6, t7, RTMP0, RTMP1, RTMP2, RTMP3) \
	XVILVHW t0, t1, RTMP3; /* RTMP3 = {t1.S7, t0.S7, t1.S6, t0.S6, t1.S3, t0.S3, t1.S2, t0.S2} */ \
	XVILVLW t0, t1, t0;    /* t0    = {t1.S5, t0.S5, t1.S4, t0.S4, t1.S1, t0.S1, t1.S0, t0.S0} */ \
	XVILVLW t2, t3, RTMP2; /* RTMP2 = {t3.S5, t2.S4, t3.S5, t2.S4, t3.S1, t2.S1, t3.S0, t2.S0} */ \
	XVILVHW t2, t3, t2;    /* t2    = {t3.S7, t2.S7, t3.S6, t2.S6, t3.S3, t2.S3, t3.S2, t2.S2} */ \
	XVILVLV t0, RTMP2, RTMP0; /* RTMP0 = {t3.S4, t2.S4, t1.S4, t0.S4, t3.S0, t2.S0, t1.S0, t0.S0} */ \
	XVILVHV t0, RTMP2, RTMP1; /* RTMP1 = {t3.S5, t2.S5, t1.S5, t0.S5, t3.S1, t2.S1, t1.S1, t0.S1} */ \
	XVILVLV RTMP3, t2, RTMP2; /* RTMP2 = {t3.S6, t2.S6, t1.S6, t0.S6, t3.S2, t2.S2, t1.S2, t0.S2} */ \
	XVILVHV RTMP3, t2, RTMP3; /* RTMP3 = {t3.S7, t2.S7, t1.S7, t0.S7, t3.S3, t2.S3, t1.S3, t0.S3} */ \
	; \
	XVILVHW t4, t5, t0; /* t0 = {t5.S7, t4.S7, t5.S6, t4.S6, t5.S3, t4.S3, t5.S2, t4.S2} */ \
	XVILVLW t4, t5, t4; /* t4 = {t5.S5, t4.S4, t5.S5, t4.S4, t5.S1, t4.S1, t5.S0, t4.S0} */ \
	XVILVLW t6, t7, t1; /* t1 = {t7.S5, t6.S4, t7.S5, t6.S4, t7.S1, t6.S1, t7.S0, t6.S0} */ \
	XVILVHW t6, t7, t6; /* t6 = {t7.S7, t6.S7, t7.S6, t6.S6, t7.S3, t6.S3, t7.S2, t6.S2} */ \
	XVILVHV t4, t1, t5; /* t5 = {t7.S5, t6.S5, t5.S5, t4.S5, t7.S1, t6.S1, t5.S1, t4.S1} */ \
	XVILVLV t4, t1, t4; /* t4 = {t7.S4, t6.S4, t5.S4, t4.S4, t7.S0, t6.S0, t5.S0, t4.S0} */ \
	XVILVHV t0, t6, t7; /* t7 = {t7.S7, t6.S7, t5.S7, t4.S7, t7.S3, t6.S3, t5.S3, t4.S3} */ \
	XVILVLV t0, t6, t6; /* t6 = {t7.S6, t6.S6, t5.S6, t4.S6, t7.S2, t6.S2, t5.S2, t4.S2} */ \
	; \ // below are temp solution to move data back to t0~t7, we need instruction like VPERM2I128
	XVMOVQ RTMP0, t0.Q2; \
	XVMOVQ t4.V[0], R20; \
	XVMOVQ t4.V[1], R21; \
	XVMOVQ R20, t0.V[2]; \
	XVMOVQ R21, t0.V[3]; \
	; \
	XVMOVQ RTMP1, t1.Q2; \
	XVMOVQ t5.V[0], R20; \
	XVMOVQ t5.V[1], R21; \
	XVMOVQ R20, t1.V[2]; \
	XVMOVQ R21, t1.V[3]; \
	; \
	XVMOVQ RTMP2, t2.Q2; \
	XVMOVQ t6.V[0], R20; \
	XVMOVQ t6.V[1], R21; \
	XVMOVQ R20, t2.V[2]; \
	XVMOVQ R21, t2.V[3]; \
	; \
	XVMOVQ RTMP3, t3.Q2; \
	XVMOVQ t7.V[0], R20; \
	XVMOVQ t7.V[1], R21; \
	XVMOVQ R20, t3.V[2]; \
	XVMOVQ R21, t3.V[3]; \
	; \
	XVMOVQ RTMP0.V[2], R20; \
	XVMOVQ RTMP0.V[3], R21; \
	XVMOVQ R20, t4.V[0]; \
	XVMOVQ R21, t4.V[1]; \
	; \
	XVMOVQ RTMP1.V[2], R20; \
	XVMOVQ RTMP1.V[3], R21; \
	XVMOVQ R20, t5.V[0]; \
	XVMOVQ R21, t5.V[1]; \
	; \
	XVMOVQ RTMP2.V[2], R20; \
	XVMOVQ RTMP2.V[3], R21; \
	XVMOVQ R20, t6.V[0]; \
	XVMOVQ R21, t6.V[1]; \
	; \
	XVMOVQ RTMP3.V[2], R20; \
	XVMOVQ RTMP3.V[3], R21; \
	XVMOVQ R20, t7.V[0]; \
	XVMOVQ R21, t7.V[1]

#define TRANSPOSE_MATRIX1 \
	XVILVHW a, b, tmp4; /* tmp4 = {b.S7, a.S7, b.S6, a.S6, b.S3, a.S3, b.S2, a.S2} */ \
	XVILVLW a, b, a;    /* a    = {b.S5, a.S5, b.S4, a.S4, b.S1, a.S1, b.S0, a.S0} */ \
	XVILVLW c, d, tmp3; /* tmp3 = {d.S5, c.S4, d.S5, c.S4, d.S1, c.S1, d.S0, c.S0} */ \
	XVILVHW c, d, c;    /* c    = {d.S7, c.S7, d.S6, c.S6, d.S3, c.S3, d.S2, c.S2} */ \
	XVILVLV a, tmp3, tmp1; /* tmp1 = {d.S4, c.S4, b.S4, a.S4, d.S0, c.S0, b.S0, a.S0} */ \
	XVILVHV a, tmp3, tmp2; /* tmp2 = {d.S5, c.S5, b.S5, a.S5, d.S1, c.S1, b.S1, a.S1} */ \
	XVILVLV tmp4, c, tmp3; /* tmp3 = {d.S6, c.S6, b.S6, a.S6, d.S2, c.S2, b.S2, a.S2} */ \
	XVILVHV tmp4, c, tmp4; /* tmp4 = {d.S7, c.S7, b.S7, a.S7, d.S3, c.S3, b.S3, a.S3} */ \
	; \
	XVILVHW e, f, a; /* a = {f.S7, e.S7, f.S6, e.S6, f.S3, e.S3, f.S2, e.S2} */ \
	XVILVLW e, f, e; /* e = {f.S5, e.S4, f.S5, e.S4, f.S1, e.S1, f.S0, e.S0} */ \
	XVILVLW g, h, b; /* b = {h.S5, g.S4, h.S5, g.S4, h.S1, g.S1, h.S0, g.S0} */ \
	XVILVHW g, h, g; /* g = {h.S7, g.S7, h.S6, g.S6, h.S3, g.S3, h.S2, g.S2} */ \
	XVILVHV e, b, f; /* f = {h.S5, g.S5, f.S5, e.S5, h.S1, g.S1, f.S1, e.S1} */ \
	XVILVLV e, b, e; /* e = {h.S4, g.S4, f.S4, e.S4, h.S0, g.S0, f.S0, e.S0} */ \
	XVILVHV a, g, h; /* h = {h.S7, g.S7, f.S7, e.S7, h.S3, g.S3, f.S3, e.S3} */ \
	XVILVLV a, g, g; /* g = {h.S6, g.S6, f.S6, e.S6, h.S2, g.S2, f.S2, e.S2} */ \
	; \ // below are temp solution to move data back to a~h
	XVMOVQ tmp1, a.Q2; \
	WORD $0x77ec0820   \ // XVPERMIQ $0x2, e, a
	; \
	XVMOVQ tmp2, b.Q2; \
	WORD $0x77ec0862   \ // XVPERMIQ $0x2, f, b
	; \
	XVMOVQ tmp3, c.Q2; \
	WORD $0x77ec08a4   \ // XVPERMIQ $0x2, g, c
	; \
	XVMOVQ tmp4, d.Q2; \
	WORD $0x77ec08e6   \ // XVPERMIQ $0x2, h, d
	; \
	WORD $0x77ecc501   \ // XVPERMIQ $0x31, tmp1, e
	WORD $0x77ecc523   \ // XVPERMIQ $0x31, tmp2, f
	WORD $0x77ecc545   \ // XVPERMIQ $0x31, tmp3, g
	WORD $0x77ecc567   \ // XVPERMIQ $0x31, tmp4, h

#define prepare8Words(index) \
	XVMOVQ (index*32)(srcPtr1), X12; \
	XVMOVQ (index*32)(srcPtr2), X13; \
	XVMOVQ (index*32)(srcPtr3), X14; \
	XVMOVQ (index*32)(srcPtr4), X15; \
	XVMOVQ (index*32)(srcPtr5), X16; \
	XVMOVQ (index*32)(srcPtr6), X17; \
	XVMOVQ (index*32)(srcPtr7), X18; \
	XVMOVQ (index*32)(srcPtr8), X19; \
	TRANSPOSE_MATRIX(X12, X13, X14, X15, X16, X17, X18, X19, tmp1, tmp2, tmp3, tmp4); \
	XVSHUF4IB $0x1B, X12, X12; \
	XVSHUF4IB $0x1B, X13, X13; \
	XVSHUF4IB $0x1B, X14, X14; \
	XVSHUF4IB $0x1B, X15, X15; \
	XVSHUF4IB $0x1B, X16, X16; \
	XVSHUF4IB $0x1B, X17, X17; \
	XVSHUF4IB $0x1B, X18, X18; \
	XVSHUF4IB $0x1B, X19, X19; \	
	XVMOVQ X12, (0*32)(wordPtr); \
	XVMOVQ X13, (1*32)(wordPtr); \
	XVMOVQ X14, (2*32)(wordPtr); \
	XVMOVQ X15, (3*32)(wordPtr); \
	XVMOVQ X16, (4*32)(wordPtr); \
	XVMOVQ X17, (5*32)(wordPtr); \
	XVMOVQ X18, (6*32)(wordPtr); \
	XVMOVQ X19, (7*32)(wordPtr); \	
	ADDV $256, wordPtr, wordPtr

#define loadWordByIndex(W, i) \
	XVMOVQ (32*(i))(wordStart), W \

#define loadWordBackward(W, i) \
	XVMOVQ (-32*(i))(wordPtr), W \

#define LOAD_T(index, T) \
	MOVW (index*4)(REG_KT), R20 \
	XVMOVQ R20, T.W8

#define ROUND_00_11(index, a, b, c, d, e, f, g, h) \
	XVROTRW $(32-12), a, X12; \
	LOAD_T(index, tmp1); \
	XVADDW tmp1, X12, X13; \
	XVADDW e, X13, X13; \
	XVROTRW $(32-7), X13, X14; \  // ss1
	XVXORV X12, X14, X12; \       // ss2
	;\ // FF1
	XVXORV a, b, X13; \
	XVXORV c, X13, X13; \
	XVADDW d, X13, X13; \     // tt1 part1
	loadWordByIndex(tmp3, index); \
	loadWordByIndex(tmp4, index+4)    \
	XVXORV tmp3, tmp4, tmp4; \   // Wt XOR Wt+4
	XVADDW h, tmp3, tmp3; \      // tt2 part1: h + Wt
	XVADDW tmp4, X13, X13; \ 
	XVADDW X12, X13, h; \      // tt1
	XVADDW X14, tmp3, tmp3; \
	; \ // GG1
	XVXORV e, f, tmp4; \
	XVXORV g, tmp4, tmp4; \
	XVADDW tmp4, tmp3, tmp3; \      // tt2
	XVROTRW $(32-9), b, b; \
	XVROTRW $(32-19), f, f; \
	; \ // P0(tt2)
	XVROTRW $(32-9), tmp3, tmp4; \
	XVXORV tmp3, tmp4, tmp4; \
	XVROTRW $(32-17), tmp3, tmp3; \
	XVXORV tmp3, tmp4, d

#define MESSAGE_SCHEDULE(index) \
	loadWordBackward(tmp3, 3)    \ // Wj-3
	XVROTRW $(32-15), tmp3, tmp4; \    // ROTL15(Wj-3)
	loadWordBackward(tmp3, 16)   \ // Wj-16
	XVXORV tmp3, tmp4, tmp4; \        // x part1
	loadWordBackward(tmp3, 9)    \ // Wj-9
	XVXORV tmp3, tmp4, tmp4; \        // x
	XVROTRW $(32-15), tmp4, tmp3; \     // ROTL(15, x)
	XVXORV tmp3, tmp4, tmp3; \      // x XOR ROTL(15, x)
	XVROTRW $(32-23), tmp4, tmp4; \    // ROTL23(x)
	XVXORV tmp4, tmp3, tmp3; \      // p1(x)
	loadWordBackward(tmp4, 13)    \ // Wj-13
	XVROTRW $(32-7), tmp4, tmp4; \     // ROTL7(Wj-13)
	XVXORV tmp4, tmp3, tmp3; \      // p1(x) XOR ROTL7(Wj-13)
	loadWordBackward(tmp4, 6)    \ // Wj-6
	XVXORV tmp3, tmp4, tmp4; \      // Wj
	XVMOVQ tmp4, (wordPtr); \
	ADDV $32, wordPtr, wordPtr

#define ROUND_12_15(index, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index)                               \
	ROUND_00_11(index, a, b, c, d, e, f, g, h)     \

#define ROUND_16_63(index, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index)          \ // tmp4 is Wt+4 now, Pls do not use it
	XVROTRW $(32-12), a, X12; \
	LOAD_T(index, tmp1); \
	XVADDW tmp1, X12, X13; \
	XVADDW e, X13, X13; \
	XVROTRW $(32-7), X13, X14; \  // ss1
	XVXORV X12, X14, X12; \       // ss2
	;\ // FF2
	XVORV a, b, tmp3; \
	XVANDV a, b, X13; \
	XVANDV tmp3, c, tmp3; \
	XVORV X13, tmp3, X13; \   // ff2
	XVADDW d, X13, X13; \     // tt1 part1
	loadWordBackward(tmp3, 5); \
	XVXORV tmp3, tmp4, tmp4; \   // Wt XOR Wt+4
	XVADDW h, tmp3, tmp3; \      // tt2 part1: h + Wt
	XVADDW tmp4, X13, X13; \ 
	XVADDW X12, X13, h; \      // tt1
	XVADDW X14, tmp3, tmp3; \  // ss1 + h + Wt
	XVXORV f, g, tmp4; \
	XVANDV e, tmp4, tmp4; \
	XVXORV g, tmp4, tmp4; \   // gg2
	XVADDW tmp4, tmp3, tmp3; \  // tt2
	XVROTRW $(32-9), b, b; \
	XVROTRW $(32-19), f, f; \
	; \ // P0(tt2)
	XVROTRW $(32-9), tmp3, tmp4; \
	XVXORV tmp3, tmp4, tmp4; \
	XVROTRW $(32-17), tmp3, tmp3; \
	XVXORV tmp3, tmp4, d

// transposeMatrix8x8(dig **[8]uint32)
TEXT ·transposeMatrix8x8(SB),NOSPLIT,$0
	MOVV dig+0(FP), R5
	// load state
	MOVV (0*8)(R5), R6
	XVMOVQ (0*32)(R6), a
	MOVV (1*8)(R5), R6
	XVMOVQ (0*32)(R6), b
	MOVV (2*8)(R5), R6
	XVMOVQ (0*32)(R6), c
	MOVV (3*8)(R5), R6
	XVMOVQ (0*32)(R6), d
	MOVV (4*8)(R5), R6
	XVMOVQ (0*32)(R6), e
	MOVV (5*8)(R5), R6
	XVMOVQ (0*32)(R6), f
	MOVV (6*8)(R5), R6
	XVMOVQ (0*32)(R6), g
	MOVV (7*8)(R5), R6
	XVMOVQ (0*32)(R6), h

	TRANSPOSE_MATRIX1

	// store state
	MOVV (0*8)(R5), R6
	XVMOVQ a, (0*32)(R6)
	MOVV (1*8)(R5), R6
	XVMOVQ b, (0*32)(R6)
	MOVV (2*8)(R5), R6
	XVMOVQ c, (0*32)(R6)
	MOVV (3*8)(R5), R6
	XVMOVQ d, (0*32)(R6)
	MOVV (4*8)(R5), R6
	XVMOVQ e, (0*32)(R6)
	MOVV (5*8)(R5), R6
	XVMOVQ f, (0*32)(R6)
	MOVV (6*8)(R5), R6
	XVMOVQ g, (0*32)(R6)
	MOVV (7*8)(R5), R6
	XVMOVQ h, (0*32)(R6)
	RET

// blockMultBy8(dig **[8]uint32, p *[]byte, buffer *byte, blocks int)
TEXT ·blockMultBy8(SB),NOSPLIT,$0
#define digPtr R5
#define srcPtrPtr R6
#define blockCount R7
#define wordStart R8
#define srcPtr1 R9
#define srcPtr2 R10
#define srcPtr3 R11
#define srcPtr4 R12
#define srcPtr5 R13
#define srcPtr6 R14
#define srcPtr7 R15
#define srcPtr8 R16
#define wordPtr R17

	MOVV	dig+0(FP), digPtr
	MOVV	p+8(FP), srcPtrPtr
	MOVV	buffer+16(FP), wordStart
	MOVV	blocks+24(FP), blockCount

	// load state
	MOVV (0*8)(digPtr), R20
	XVMOVQ (0*32)(R20), a
	MOVV (1*8)(digPtr), R20
	XVMOVQ (0*32)(R20), b
	MOVV (2*8)(digPtr), R20
	XVMOVQ (0*32)(R20), c
	MOVV (3*8)(digPtr), R20
	XVMOVQ (0*32)(R20), d
	MOVV (4*8)(digPtr), R20
	XVMOVQ (0*32)(R20), e
	MOVV (5*8)(digPtr), R20
	XVMOVQ (0*32)(R20), f
	MOVV (6*8)(digPtr), R20
	XVMOVQ (0*32)(R20), g
	MOVV (7*8)(digPtr), R20
	XVMOVQ (0*32)(R20), h

	// transpose state
	TRANSPOSE_MATRIX(a, b, c, d, e, f, g, h, tmp1, tmp2, tmp3, tmp4)

	MOVV	(0*8)(srcPtrPtr), srcPtr1
	MOVV	(1*8)(srcPtrPtr), srcPtr2
	MOVV	(2*8)(srcPtrPtr), srcPtr3
	MOVV	(3*8)(srcPtrPtr), srcPtr4
	MOVV	(4*8)(srcPtrPtr), srcPtr5
	MOVV	(5*8)(srcPtrPtr), srcPtr6
	MOVV	(6*8)(srcPtrPtr), srcPtr7
	MOVV	(7*8)(srcPtrPtr), srcPtr8

	XVXORV ZERO_VECTOR, ZERO_VECTOR, ZERO_VECTOR
	MOVV	$·_K(SB), REG_KT		// const table

loop:
	// loong64 can't move from vector register to vector register directly now.
	XVXORV a, ZERO_VECTOR, aSave
	XVXORV b, ZERO_VECTOR, bSave
	XVXORV c, ZERO_VECTOR, cSave
	XVXORV d, ZERO_VECTOR, dSave
	XVXORV e, ZERO_VECTOR, eSave
	XVXORV f, ZERO_VECTOR, fSave
	XVXORV g, ZERO_VECTOR, gSave
	XVXORV h, ZERO_VECTOR, hSave

	// reset wordPtr
	MOVV wordStart, wordPtr

	// load message block
	prepare8Words(0)
	prepare8Words(1)

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

	XVXORV aSave, a, a
	XVXORV bSave, b, b
	XVXORV cSave, c, c
	XVXORV dSave, d, d
	XVXORV eSave, e, e
	XVXORV fSave, f, f
	XVXORV gSave, g, g
	XVXORV hSave, h, h

	ADDV $64, srcPtr1, srcPtr1
	ADDV $64, srcPtr2, srcPtr2
	ADDV $64, srcPtr3, srcPtr3
	ADDV $64, srcPtr4, srcPtr4
	ADDV $64, srcPtr5, srcPtr5
	ADDV $64, srcPtr6, srcPtr6
	ADDV $64, srcPtr7, srcPtr7
	ADDV $64, srcPtr8, srcPtr8

	SUBV $1, blockCount, blockCount
	BNE blockCount, loop

	// transpose state
	TRANSPOSE_MATRIX(a, b, c, d, e, f, g, h, tmp1, tmp2, tmp3, tmp4)

	// store state
	MOVV	(0*8)(digPtr), R20
	XVMOVQ a, (0*32)(R20)
	MOVV	(1*8)(digPtr), R20
	XVMOVQ b, (0*32)(R20)
	MOVV	(2*8)(digPtr), R20
	XVMOVQ c, (0*32)(R20)
	MOVV	(3*8)(digPtr), R20
	XVMOVQ d, (0*32)(R20)
	MOVV	(4*8)(digPtr), R20
	XVMOVQ e, (0*32)(R20)
	MOVV	(5*8)(digPtr), R20
	XVMOVQ f, (0*32)(R20)
	MOVV	(6*8)(digPtr), R20
	XVMOVQ g, (0*32)(R20)
	MOVV	(7*8)(digPtr), R20
	XVMOVQ h, (0*32)(R20)

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

#define a X0
#define b X1
#define c X2
#define d X3
#define e X4
#define f X5
#define g X6
#define h X7
// func copyResultsBy8(dig *uint32, dst *byte)
TEXT ·copyResultsBy8(SB),NOSPLIT,$0
#define digPtr R4
#define dstPtr R5
	MOVV	dig+0(FP), digPtr
	MOVV	dst+8(FP), dstPtr

	// load state
	XVMOVQ (0*32)(digPtr), a
	XVMOVQ (1*32)(digPtr), b
	XVMOVQ (2*32)(digPtr), c
	XVMOVQ (3*32)(digPtr), d
	XVMOVQ (4*32)(digPtr), e
	XVMOVQ (5*32)(digPtr), f
	XVMOVQ (6*32)(digPtr), g
	XVMOVQ (7*32)(digPtr), h

	XVSHUF4IB $0x1B, a, a
	XVSHUF4IB $0x1B, b, b
	XVSHUF4IB $0x1B, c, c
	XVSHUF4IB $0x1B, d, d
	XVSHUF4IB $0x1B, e, e
	XVSHUF4IB $0x1B, f, f
	XVSHUF4IB $0x1B, g, g
	XVSHUF4IB $0x1B, h, h

	XVMOVQ a, (0*32)(dstPtr)
	XVMOVQ b, (1*32)(dstPtr)
	XVMOVQ c, (2*32)(dstPtr)
	XVMOVQ d, (3*32)(dstPtr)
	XVMOVQ e, (4*32)(dstPtr)
	XVMOVQ f, (5*32)(dstPtr)
	XVMOVQ g, (6*32)(dstPtr)
	XVMOVQ h, (7*32)(dstPtr)

	RET
