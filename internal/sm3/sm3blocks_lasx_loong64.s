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

	TRANSPOSE_MATRIX(a, b, c, d, e, f, g, h, tmp1, tmp2, tmp3, tmp4)

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
	RET

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
