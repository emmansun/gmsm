//go:build !purego

#include "textflag.h"

// shuffle byte order from LE to BE
DATA flip_mask<>+0x00(SB)/8, $0x0405060700010203
DATA flip_mask<>+0x08(SB)/8, $0x0c0d0e0f08090a0b
GLOBL flip_mask<>(SB), RODATA, $16

// left rotations of 32-bit words by 8-bit increments
DATA r08_mask<>+0x00(SB)/8, $0x0605040702010003
DATA r08_mask<>+0x08(SB)/8, $0x0E0D0C0F0A09080B
GLOBL r08_mask<>(SB), 8, $16

// Transpose matrix with PUNPCKHDQ/PUNPCKLDQ/PUNPCKHQDQ/PUNPCKLQDQ instructions.
// input: from high to low
// r0 = [w3, w2, w1, w0]
// r1 = [w7, w6, w5, w4]
// r2 = [w11, w10, w9, w8]
// r3 = [w15, w14, w13, w12]
// r: 32/64 temp register
// tmp1: 128 bits temp register
// tmp2: 128 bits temp register
//
// output: from high to low
// r0 = [w12, w8, w4, w0]
// r1 = [w13, w9, w5, w1]
// r2 = [w14, w10, w6, w2]
// r3 = [w15, w11, w7, w3]
//
// SSE2/MMX instructions:
//	MOVOU r0, tmp2;
//	PUNPCKHDQ r1, tmp2;
//	PUNPCKLDQ	r1, r0; 
//	MOVOU r2, tmp1; 
//	PUNPCKLDQ r3, tmp1; 
//	PUNPCKHDQ r3, r2; 
//	MOVOU r0, r1; 
//	PUNPCKHQDQ tmp1, r1; 
//	PUNPCKLQDQ tmp1, r0; 
//	MOVOU tmp2, r3; 
//	PUNPCKHQDQ r2, r3; 
//	PUNPCKLQDQ r2, tmp2; 
//	MOVOU tmp2, r2
#define SSE_TRANSPOSE_MATRIX(r0, r1, r2, r3, tmp1, tmp2) \
	MOVOU r0, tmp2;      \
	PUNPCKHLQ r1, tmp2;  \
	PUNPCKLLQ	r1, r0;  \
	MOVOU r2, tmp1;      \
	PUNPCKLLQ r3, tmp1;  \
	PUNPCKHLQ r3, r2;    \
	MOVOU r0, r1;        \
	PUNPCKHQDQ tmp1, r1; \
	PUNPCKLQDQ tmp1, r0; \
	MOVOU tmp2, r3;      \
	PUNPCKHQDQ r2, r3;   \
	PUNPCKLQDQ r2, tmp2; \
	MOVOU tmp2, r2

#define a X0
#define b X1
#define c X2
#define d X3
#define e X4
#define f X5
#define g X6
#define h X7

#define tmp1 X8
#define tmp2 X9

#define storeState(R) \
	MOVOU a, (R) \
	MOVOU b, 16(R) \
	MOVOU c, 32(R) \
	MOVOU d, 48(R) \
	MOVOU e, 64(R) \
	MOVOU f, 80(R) \
	MOVOU g, 96(R) \
	MOVOU h, 112(R)

#define storeWord(W, j) MOVOU W, (128+(j)*16)(BX)
#define loadWord(W, i) MOVOU (128+(i)*16)(BX), W

#define SSE_REV32(a, b, c, d) \
	PSHUFB flip_mask<>(SB), a; \
	PSHUFB flip_mask<>(SB), b; \
	PSHUFB flip_mask<>(SB), c; \
	PSHUFB flip_mask<>(SB), d

#define prepare4Words(i) \
	MOVOU (i*16)(R8), X10; \
	MOVOU (i*16)(R9), X11; \
	MOVOU (i*16)(R10), X12; \
	MOVOU (i*16)(R11), X13; \
	; \
	SSE_TRANSPOSE_MATRIX(X10, X11, X12, X13, tmp1, tmp2); \
	SSE_REV32(X10, X11, X12, X13); \
	; \
	storeWord(X10, 4*i+0); \
	storeWord(X11, 4*i+1); \
	storeWord(X12, 4*i+2); \
	storeWord(X13, 4*i+3)

#define LOAD_T(index, T) \
	MOVL (index*4)(AX), T;    \
	PSHUFD $0, T, T

// r <<< n, SSE version
#define PROLD(r, n) \
	MOVOU r, tmp1; \
	PSLLL $n, r; \
	PSRLL $(32-n), tmp1; \
	POR tmp1, r

#define SSE_SS1SS2(index, a, e, TMP, SS1, SS2) \
	MOVOU a, SS1; \
	PROLD(SS1, 12); \
	MOVOU SS1, SS2; \ // a <<< 12
	LOAD_T(index, TMP); \
	PADDL TMP, SS1; \
	PADDL e, SS1; \
	PROLD(SS1, 7); \ // SS1
	PXOR SS1, SS2; \ // SS2

#define SSE_FF0(X, Y, Z, DST) \
	MOVOU X, DST; \
	PXOR Y, DST; \
	PXOR Z, DST

#define SSE_FF1(X, Y, Z, TMP, DST) \
	MOVOU X, DST; \
	POR Y, DST; \
	MOVOU X, TMP; \
	PAND Y, TMP; \
	PAND Z, DST; \
	POR TMP, DST; \ // (a AND b) OR (a AND c) OR (b AND c)

#define SSE_GG0(X, Y, Z, DST) \
	SSE_FF0(X, Y, Z, DST)

// DST = (Y XOR Z) AND X XOR Z
#define SSE_GG1(X, Y, Z, DST) \
	MOVOU Y, DST; \
	PXOR Z, DST; \
	PAND X, DST; \
	PXOR Z, DST

#define SSE_COPY_RESULT(b, d, f, h, TT1, TT2) \
	PROLD(b, 9); \
	MOVOU TT1, h; \
	PROLD(f, 19); \
	MOVOU TT2, TT1; \
	PROLD(TT1, 9); \
	PXOR TT1, TT2; \ // tt2 XOR ROTL(9, tt2)
	PSHUFB r08_mask<>(SB), TT1; \ // ROTL(17, tt2)
	PXOR TT2, TT1; \ // tt2 XOR ROTL(9, tt2) XOR ROTL(17, tt2)
	MOVOU TT1, d

#define ROUND_00_11(index, a, b, c, d, e, f, g, h) \
	SSE_SS1SS2(index, a, e, tmp2, X12, X13); \
	SSE_FF0(a, b, c, X14); \
	PADDL d, X14; \ // (a XOR b XOR c) + d 
	loadWord(X10, index); \
	loadWord(X11, index+4); \
	PXOR X10, X11; \ //Wt XOR Wt+4
	PADDL X11, X14; \ // (a XOR b XOR c) + d + Wt XOR Wt+4
	PADDL X14, X13; \ // TT1
	PADDL h, X10; \ // Wt + h
	PADDL X12, X10; \ // Wt + h + SS1
	SSE_GG0(e, f, g, X11); \
	PADDL X11, X10; \ // TT2 = (e XOR f XOR g) + Wt + h + SS1
	; \ // copy result
	SSE_COPY_RESULT(b, d, f, h, X13, X10)

#define MESSAGE_SCHEDULE(index) \
	loadWord(X10, index+1); \ // Wj-3
	PROLD(X10, 15); \
	loadWord(X11, index-12); \ // Wj-16
	PXOR X11, X10; \
	loadWord(X11, index-5); \ // Wj-9
	PXOR X11, X10; \
	MOVOU X10, X11; \
	PROLD(X11, 15); \
	PXOR X11, X10; \
	PSHUFB r08_mask<>(SB), X11; \
	PXOR X11, X10; \ // P1
	loadWord(X11, index-9); \ // Wj-13
	PROLD(X11, 7); \
	PXOR X11, X10; \
	loadWord(X11, index-2); \ // Wj-6
	PXOR X10, X11; \
	storeWord(X11, index+4)

#define ROUND_12_15(index, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index); \
	ROUND_00_11(index, a, b, c, d, e, f, g, h)

#define ROUND_16_63(index, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index); \ // X11 is Wt+4 now, Pls do not use it
	SSE_SS1SS2(index, a, e, tmp2, X12, X13); \
	; \
	SSE_FF1(a, b, c, X10, X14); \
	PADDL d, X14; \ // (a AND b) OR (a AND c) OR (b AND c) + d
	loadWord(X10, index); \
	PXOR X10, X11; \ //Wt XOR Wt+4
	PADDL X11, X14; \ // (a AND b) OR (a AND c) OR (b AND c) + d + Wt XOR Wt+4
	PADDL X14, X13; \ // TT1
	; \
	PADDL h, X10; \ // Wt + h
	PADDL X12, X10; \ // Wt + h + SS1
	SSE_GG1(e, f, g, X11); \
	PADDL X11, X10; \ // TT2 = (e XOR f XOR g) + Wt + h + SS1
	; \ // copy result
	SSE_COPY_RESULT(b, d, f, h, X13, X10)

// transpose matrix function, AVX version
// parameters:
// - r0: 128 bits register as input/output data
// - r1: 128 bits register as input/output data
// - r2: 128 bits register as input/output data
// - r3: 128 bits register as input/output data
// - tmp1: 128 bits temp register
// - tmp2: 128 bits temp register
#define TRANSPOSE_MATRIX(r0, r1, r2, r3, tmp1, tmp2) \
	VPUNPCKHDQ r1, r0, tmp2;                 \ // tmp2 =  tmp2 = [w07, w03, w06, w02]
	VPUNPCKLDQ r1, r0, r0;                   \ // r0 =      r0 = [w05, w01, w04, w00]
	VPUNPCKLDQ r3, r2, tmp1;                 \ // tmp1 =  tmp1 = [w13, w09, w12, w08]
	VPUNPCKHDQ r3, r2, r2;                   \ // r2 =      r2 = [w15, w11, w14, w10] 
	VPUNPCKHQDQ tmp1, r0, r1;                \ // r1 =      r1 = [w13, w09, w05, w01]
	VPUNPCKLQDQ tmp1, r0, r0;                \ // r0 =      r0 = [w12, w08, w04, w00]
	VPUNPCKHQDQ r2, tmp2, r3;                \ // r3 =      r3 = [w15, w11, w07, w03]
	VPUNPCKLQDQ r2, tmp2, r2                   // r2 =      r2 = [w14, w10, w06, w02]

#define avxStoreWord(W, j) VMOVDQU W, (128+(j)*16)(BX)
#define avxLoadWord(W, i) VMOVDQU (128+(i)*16)(BX), W

#define avxStoreState(R) \
	VMOVDQU a, (0*16)(R) \
	VMOVDQU b, (1*16)(R) \
	VMOVDQU c, (2*16)(R) \
	VMOVDQU d, (3*16)(R) \
	VMOVDQU e, (4*16)(R) \
	VMOVDQU f, (5*16)(R) \
	VMOVDQU g, (6*16)(R) \
	VMOVDQU h, (7*16)(R)

#define AVX_REV32(a, b, c, d) \
	VPSHUFB flip_mask<>(SB), a, a; \
	VPSHUFB flip_mask<>(SB), b, b; \
	VPSHUFB flip_mask<>(SB), c, c; \
	VPSHUFB flip_mask<>(SB), d, d

#define avxPrepare4Words(i) \
	VMOVDQU (i*16)(R8), X10; \
	VMOVDQU (i*16)(R9), X11; \
	VMOVDQU (i*16)(R10), X12; \
	VMOVDQU (i*16)(R11), X13; \
	; \
	TRANSPOSE_MATRIX(X10, X11, X12, X13, tmp1, tmp2); \
	AVX_REV32(X10, X11, X12, X13); \
	; \
	avxStoreWord(X10, 4*i+0); \
	avxStoreWord(X11, 4*i+1); \
	avxStoreWord(X12, 4*i+2); \
	avxStoreWord(X13, 4*i+3)

#define AVX_LOAD_T(index, T) \
	MOVL (index*4)(AX), T;    \
	VPSHUFD $0, T, T

// r <<< n
#define VPROLD(r, n) \
	VPSLLD $(n), r, tmp1; \
	VPSRLD $(32-n), r, r; \
	VPOR tmp1, r, r

// d = r <<< n
#define VPROLD2(r, d, n) \
	VPSLLD $(n), r, tmp1; \
	VPSRLD $(32-n), r, d; \
	VPOR tmp1, d, d

#define AVX_SS1SS2(index, a, e, SS1, SS2) \
	VPROLD2(a, SS2, 12); \ // a <<< 12
	AVX_LOAD_T(index, SS1); \
	VPADDD SS1, SS2, SS1; \
	VPADDD e, SS1, SS1; \
	VPROLD(SS1, 7); \ // SS1
	VPXOR SS1, SS2, SS2

// DST = X XOR Y XOR Z
#define AVX_FF0(X, Y, Z, DST) \
	VPXOR X, Y, DST; \
	VPXOR Z, DST, DST

// DST = (X AND Y) OR (X AND Z) OR (Y AND Z)
#define AVX_FF1(X, Y, Z, TMP, DST) \
	VPOR X, Y, DST; \
	VPAND X, Y, TMP; \
	VPAND Z, DST, DST; \
	VPOR TMP, DST, DST

// DST = X XOR Y XOR Z
#define AVX_GG0(X, Y, Z, DST) \
	AVX_FF0(X, Y, Z, DST)

// DST = (Y XOR Z) AND X XOR Z
#define AVX_GG1(X, Y, Z, DST) \
	VPXOR Y, Z, DST; \
	VPAND X, DST, DST; \ 
	VPXOR Z, DST, DST

#define AVX_COPY_RESULT(b, d, f, h, TT1, TT2) \
	VPROLD(b, 9); \
	VMOVDQU TT1, h; \
	VPROLD(f, 19); \
	VPROLD2(TT2, TT1, 9); \ // tt2 <<< 9
	VPXOR TT2, TT1, TT2; \ // tt2 XOR ROTL(9, tt2)
	VPSHUFB r08_mask<>(SB), TT1, TT1; \ // ROTL(17, tt2)
	VPXOR TT2, TT1, d

#define AVX_ROUND_00_11(index, a, b, c, d, e, f, g, h) \
	AVX_SS1SS2(index, a, e, X12, X13); \
	; \
	AVX_FF0(a, b, c, X14); \
	VPADDD d, X14, X14; \ // (a XOR b XOR c) + d 
	avxLoadWord(X10, index); \
	avxLoadWord(X11, index+4); \
	VPXOR X10, X11, X11; \ //Wt XOR Wt+4
	VPADDD X11, X14, X14; \ // (a XOR b XOR c) + d + Wt XOR Wt+4
	VPADDD X14, X13, X13; \ // TT1
	VPADDD h, X10, X10; \ // Wt + h
	VPADDD X12, X10, X10; \ // Wt + h + SS1
	AVX_GG0(e, f, g, X11); \
	VPADDD X11, X10, X10; \ // TT2 = (e XOR f XOR g) + Wt + h + SS1
	; \ // copy result
	AVX_COPY_RESULT(b, d, f, h, X13, X10)

#define AVX_MESSAGE_SCHEDULE(index) \
	avxLoadWord(X10, index+1); \ // Wj-3
	VPROLD(X10, 15); \
	VPXOR (128+(index-12)*16)(BX), X10, X10; \ // Wj-16
	VPXOR (128+(index-5)*16)(BX), X10, X10; \ // Wj-9
	; \ // P1
	VPROLD2(X10, X11, 15); \
	VPXOR X11, X10, X10; \
	VPSHUFB r08_mask<>(SB), X11, X11; \
	VPXOR X11, X10, X10; \ // P1
	avxLoadWord(X11, index-9); \ // Wj-13
	VPROLD(X11, 7); \
	VPXOR X11, X10, X10; \
	VPXOR (128+(index-2)*16)(BX), X10, X11; \
	avxStoreWord(X11, index+4)

#define AVX_ROUND_12_15(index, a, b, c, d, e, f, g, h) \
	AVX_MESSAGE_SCHEDULE(index); \
	AVX_ROUND_00_11(index, a, b, c, d, e, f, g, h)

#define AVX_ROUND_16_63(index, a, b, c, d, e, f, g, h) \
	AVX_MESSAGE_SCHEDULE(index); \ // X11 is Wt+4 now, Pls do not use it
	AVX_SS1SS2(index, a, e, X12, X13); \
	; \
	AVX_FF1(a, b, c, X10, X14); \
	VPADDD d, X14, X14; \ // (a AND b) OR (a AND c) OR (b AND c) + d
	avxLoadWord(X10, index); \
	VPXOR X10, X11, X11; \ //Wt XOR Wt+4
	VPADDD X11, X14, X14; \ // (a AND b) OR (a AND c) OR (b AND c) + d + Wt XOR Wt+4
	VPADDD X14, X13, X13; \ // TT1
	; \
	VPADDD h, X10, X10; \ // Wt + h
	VPADDD X12, X10, X10; \ // Wt + h + SS1
	AVX_GG1(e, f, g, X11); \
	VPADDD X11, X10, X10; \ // TT2 = (e XOR f XOR g) + Wt + h + SS1
	; \ // copy result
	AVX_COPY_RESULT(b, d, f, h, X13, X10)

// blockMultBy4(dig **[8]uint32, p *[]byte, buffer *byte, blocks int)
TEXT ·blockMultBy4(SB),NOSPLIT,$0
	MOVQ	dig+0(FP), DI
	MOVQ	p+8(FP), SI
	MOVQ	buffer+16(FP), BX
	MOVQ	blocks+24(FP), DX

	CMPB ·useAVX(SB), $1
	JE   avx

	// load state
	MOVQ (DI), R8
	MOVOU (0*16)(R8), a
	MOVOU (1*16)(R8), e
	MOVQ 8(DI), R8
	MOVOU (0*16)(R8), b
	MOVOU (1*16)(R8), f
	MOVQ 16(DI), R8
	MOVOU (0*16)(R8), c
	MOVOU (1*16)(R8), g
	MOVQ 24(DI), R8
	MOVOU (0*16)(R8), d
	MOVOU (1*16)(R8), h

	// transpose state
	SSE_TRANSPOSE_MATRIX(a, b, c, d, tmp1, tmp2)
	SSE_TRANSPOSE_MATRIX(e, f, g, h, tmp1, tmp2)

	// store state to temporary buffer
	storeState(BX)

	MOVQ $·_K+0(SB), AX
	MOVQ (SI), R8
	MOVQ 8(SI), R9
	MOVQ 16(SI), R10
	MOVQ 24(SI), R11

loop:	
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

	MOVOU (0*16)(BX), tmp1
	PXOR tmp1, a
	MOVOU (1*16)(BX), tmp1
	PXOR tmp1, b
	MOVOU (2*16)(BX), tmp1
	PXOR tmp1, c
	MOVOU (3*16)(BX), tmp1
	PXOR tmp1, d
	MOVOU (4*16)(BX), tmp1
	PXOR tmp1, e
	MOVOU (5*16)(BX), tmp1
	PXOR tmp1, f
	MOVOU (6*16)(BX), tmp1
	PXOR tmp1, g
	MOVOU (7*16)(BX), tmp1
	PXOR tmp1, h

	DECQ DX
	JZ end
	
	storeState(BX)
	LEAQ 64(R8), R8
	LEAQ 64(R9), R9
	LEAQ 64(R10), R10
	LEAQ 64(R11), R11
	JMP loop

end:
	// transpose state
	SSE_TRANSPOSE_MATRIX(a, b, c, d, tmp1, tmp2)
	SSE_TRANSPOSE_MATRIX(e, f, g, h, tmp1, tmp2)

	MOVQ (DI), R8
	MOVOU a, (0*16)(R8)
	MOVOU e, (1*16)(R8)
	MOVQ 8(DI), R8
	MOVOU b, (0*16)(R8)
	MOVOU f, (1*16)(R8)
	MOVQ 16(DI), R8
	MOVOU c, (0*16)(R8)
	MOVOU g, (1*16)(R8)
	MOVQ 24(DI), R8
	MOVOU d, (0*16)(R8)
	MOVOU h, (1*16)(R8)

	RET

avx:
	// load state
	MOVQ (DI), R8
	VMOVDQU (0*16)(R8), a
	VMOVDQU (1*16)(R8), e
	MOVQ 8(DI), R8
	VMOVDQU (0*16)(R8), b
	VMOVDQU (1*16)(R8), f
	MOVQ 16(DI), R8
	VMOVDQU (0*16)(R8), c
	VMOVDQU (1*16)(R8), g
	MOVQ 24(DI), R8
	VMOVDQU (0*16)(R8), d
	VMOVDQU (1*16)(R8), h

	// transpose state
	TRANSPOSE_MATRIX(a, b, c, d, tmp1, tmp2)
	TRANSPOSE_MATRIX(e, f, g, h, tmp1, tmp2)

	avxStoreState(BX)

	MOVQ $·_K+0(SB), AX
	MOVQ (SI), R8
	MOVQ 8(SI), R9
	MOVQ 16(SI), R10
	MOVQ 24(SI), R11

avxLoop:
	// load message block
	avxPrepare4Words(0)
	avxPrepare4Words(1)
	avxPrepare4Words(2)
	avxPrepare4Words(3)

	AVX_ROUND_00_11(0, a, b, c, d, e, f, g, h)
	AVX_ROUND_00_11(1, h, a, b, c, d, e, f, g)
	AVX_ROUND_00_11(2, g, h, a, b, c, d, e, f)
	AVX_ROUND_00_11(3, f, g, h, a, b, c, d, e)
	AVX_ROUND_00_11(4, e, f, g, h, a, b, c, d)
	AVX_ROUND_00_11(5, d, e, f, g, h, a, b, c)
	AVX_ROUND_00_11(6, c, d, e, f, g, h, a, b)
	AVX_ROUND_00_11(7, b, c, d, e, f, g, h, a)
	AVX_ROUND_00_11(8, a, b, c, d, e, f, g, h)
	AVX_ROUND_00_11(9, h, a, b, c, d, e, f, g)
	AVX_ROUND_00_11(10, g, h, a, b, c, d, e, f)
	AVX_ROUND_00_11(11, f, g, h, a, b, c, d, e)

	AVX_ROUND_12_15(12, e, f, g, h, a, b, c, d)
	AVX_ROUND_12_15(13, d, e, f, g, h, a, b, c)
	AVX_ROUND_12_15(14, c, d, e, f, g, h, a, b)
	AVX_ROUND_12_15(15, b, c, d, e, f, g, h, a)

	AVX_ROUND_16_63(16, a, b, c, d, e, f, g, h)
	AVX_ROUND_16_63(17, h, a, b, c, d, e, f, g)
	AVX_ROUND_16_63(18, g, h, a, b, c, d, e, f)
	AVX_ROUND_16_63(19, f, g, h, a, b, c, d, e)
	AVX_ROUND_16_63(20, e, f, g, h, a, b, c, d)
	AVX_ROUND_16_63(21, d, e, f, g, h, a, b, c)
	AVX_ROUND_16_63(22, c, d, e, f, g, h, a, b)
	AVX_ROUND_16_63(23, b, c, d, e, f, g, h, a)
	AVX_ROUND_16_63(24, a, b, c, d, e, f, g, h)
	AVX_ROUND_16_63(25, h, a, b, c, d, e, f, g)
	AVX_ROUND_16_63(26, g, h, a, b, c, d, e, f)
	AVX_ROUND_16_63(27, f, g, h, a, b, c, d, e)
	AVX_ROUND_16_63(28, e, f, g, h, a, b, c, d)
	AVX_ROUND_16_63(29, d, e, f, g, h, a, b, c)
	AVX_ROUND_16_63(30, c, d, e, f, g, h, a, b)
	AVX_ROUND_16_63(31, b, c, d, e, f, g, h, a)
	AVX_ROUND_16_63(32, a, b, c, d, e, f, g, h)
	AVX_ROUND_16_63(33, h, a, b, c, d, e, f, g)
	AVX_ROUND_16_63(34, g, h, a, b, c, d, e, f)
	AVX_ROUND_16_63(35, f, g, h, a, b, c, d, e)
	AVX_ROUND_16_63(36, e, f, g, h, a, b, c, d)
	AVX_ROUND_16_63(37, d, e, f, g, h, a, b, c)
	AVX_ROUND_16_63(38, c, d, e, f, g, h, a, b)
	AVX_ROUND_16_63(39, b, c, d, e, f, g, h, a)
	AVX_ROUND_16_63(40, a, b, c, d, e, f, g, h)
	AVX_ROUND_16_63(41, h, a, b, c, d, e, f, g)
	AVX_ROUND_16_63(42, g, h, a, b, c, d, e, f)
	AVX_ROUND_16_63(43, f, g, h, a, b, c, d, e)
	AVX_ROUND_16_63(44, e, f, g, h, a, b, c, d)
	AVX_ROUND_16_63(45, d, e, f, g, h, a, b, c)
	AVX_ROUND_16_63(46, c, d, e, f, g, h, a, b)
	AVX_ROUND_16_63(47, b, c, d, e, f, g, h, a)
	AVX_ROUND_16_63(48, a, b, c, d, e, f, g, h)
	AVX_ROUND_16_63(49, h, a, b, c, d, e, f, g)
	AVX_ROUND_16_63(50, g, h, a, b, c, d, e, f)
	AVX_ROUND_16_63(51, f, g, h, a, b, c, d, e)
	AVX_ROUND_16_63(52, e, f, g, h, a, b, c, d)
	AVX_ROUND_16_63(53, d, e, f, g, h, a, b, c)
	AVX_ROUND_16_63(54, c, d, e, f, g, h, a, b)
	AVX_ROUND_16_63(55, b, c, d, e, f, g, h, a)
	AVX_ROUND_16_63(56, a, b, c, d, e, f, g, h)
	AVX_ROUND_16_63(57, h, a, b, c, d, e, f, g)
	AVX_ROUND_16_63(58, g, h, a, b, c, d, e, f)
	AVX_ROUND_16_63(59, f, g, h, a, b, c, d, e)
	AVX_ROUND_16_63(60, e, f, g, h, a, b, c, d)
	AVX_ROUND_16_63(61, d, e, f, g, h, a, b, c)
	AVX_ROUND_16_63(62, c, d, e, f, g, h, a, b)
	AVX_ROUND_16_63(63, b, c, d, e, f, g, h, a)

	VPXOR (0*16)(BX), a, a
	VPXOR (1*16)(BX), b, b
	VPXOR (2*16)(BX), c, c
	VPXOR (3*16)(BX), d, d
	VPXOR (4*16)(BX), e, e
	VPXOR (5*16)(BX), f, f
	VPXOR (6*16)(BX), g, g
	VPXOR (7*16)(BX), h, h

	DECQ DX
	JZ avxEnd

	// store current state
	avxStoreState(BX)

	LEAQ 64(R8), R8
	LEAQ 64(R9), R9
	LEAQ 64(R10), R10
	LEAQ 64(R11), R11
	JMP avxLoop

avxEnd:
	// transpose state
	TRANSPOSE_MATRIX(a, b, c, d, tmp1, tmp2)
	TRANSPOSE_MATRIX(e, f, g, h, tmp1, tmp2)

	MOVQ (DI), R8
	VMOVDQU a, (0*16)(R8)
	VMOVDQU e, (1*16)(R8)
	MOVQ 8(DI), R8
	VMOVDQU b, (0*16)(R8)
	VMOVDQU f, (1*16)(R8)
	MOVQ 16(DI), R8
	VMOVDQU c, (0*16)(R8)
	VMOVDQU g, (1*16)(R8)
	MOVQ 24(DI), R8
	VMOVDQU d, (0*16)(R8)
	VMOVDQU h, (1*16)(R8)

	RET

// func copyResultsBy4(dig *uint32, dst *byte)
TEXT ·copyResultsBy4(SB),NOSPLIT,$0
	MOVQ	dig+0(FP), DI
	MOVQ	dst+8(FP), SI

	CMPB ·useAVX(SB), $1
	JE   avx

	// load state
	MOVOU (0*16)(DI), a
	MOVOU (1*16)(DI), b
	MOVOU (2*16)(DI), c
	MOVOU (3*16)(DI), d
	MOVOU (4*16)(DI), e
	MOVOU (5*16)(DI), f
	MOVOU (6*16)(DI), g
	MOVOU (7*16)(DI), h
	
	SSE_REV32(a, b, c, d)
	SSE_REV32(e, f, g, h)
	storeState(SI)

	RET

avx:
	// load state
	VMOVDQU (0*16)(DI), a
	VMOVDQU (1*16)(DI), b
	VMOVDQU (2*16)(DI), c
	VMOVDQU (3*16)(DI), d
	VMOVDQU (4*16)(DI), e
	VMOVDQU (5*16)(DI), f
	VMOVDQU (6*16)(DI), g
	VMOVDQU (7*16)(DI), h

	AVX_REV32(a, b, c, d)
	AVX_REV32(e, f, g, h)

	avxStoreState(SI)

	RET
