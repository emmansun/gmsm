//go:build !purego

#include "textflag.h"

// shuffle byte order from LE to BE
DATA flip_mask<>+0x00(SB)/8, $0x0405060700010203
DATA flip_mask<>+0x08(SB)/8, $0x0c0d0e0f08090a0b
GLOBL flip_mask<>(SB), RODATA, $16

DATA T256_4<>+0x00(SB)/8, $0x79cc451979cc4519
DATA T256_4<>+0x08(SB)/8, $0x79cc451979cc4519
DATA T256_4<>+0x10(SB)/8, $0xf3988a32f3988a32
DATA T256_4<>+0x18(SB)/8, $0xf3988a32f3988a32
DATA T256_4<>+0x20(SB)/8, $0xe7311465e7311465
DATA T256_4<>+0x28(SB)/8, $0xe7311465e7311465
DATA T256_4<>+0x30(SB)/8, $0xce6228cbce6228cb
DATA T256_4<>+0x38(SB)/8, $0xce6228cbce6228cb
DATA T256_4<>+0x40(SB)/8, $0x9cc451979cc45197
DATA T256_4<>+0x48(SB)/8, $0x9cc451979cc45197
DATA T256_4<>+0x50(SB)/8, $0x3988a32f3988a32f
DATA T256_4<>+0x58(SB)/8, $0x3988a32f3988a32f
DATA T256_4<>+0x60(SB)/8, $0x7311465e7311465e
DATA T256_4<>+0x68(SB)/8, $0x7311465e7311465e
DATA T256_4<>+0x70(SB)/8, $0xe6228cbce6228cbc
DATA T256_4<>+0x78(SB)/8, $0xe6228cbce6228cbc
DATA T256_4<>+0x80(SB)/8, $0xcc451979cc451979
DATA T256_4<>+0x88(SB)/8, $0xcc451979cc451979
DATA T256_4<>+0x90(SB)/8, $0x988a32f3988a32f3
DATA T256_4<>+0x98(SB)/8, $0x988a32f3988a32f3
DATA T256_4<>+0xa0(SB)/8, $0x311465e7311465e7
DATA T256_4<>+0xa8(SB)/8, $0x311465e7311465e7
DATA T256_4<>+0xb0(SB)/8, $0x6228cbce6228cbce
DATA T256_4<>+0xb8(SB)/8, $0x6228cbce6228cbce
DATA T256_4<>+0xc0(SB)/8, $0xc451979cc451979c
DATA T256_4<>+0xc8(SB)/8, $0xc451979cc451979c
DATA T256_4<>+0xd0(SB)/8, $0x88a32f3988a32f39
DATA T256_4<>+0xd8(SB)/8, $0x88a32f3988a32f39
DATA T256_4<>+0xe0(SB)/8, $0x11465e7311465e73
DATA T256_4<>+0xe8(SB)/8, $0x11465e7311465e73
DATA T256_4<>+0xf0(SB)/8, $0x228cbce6228cbce6
DATA T256_4<>+0xf8(SB)/8, $0x228cbce6228cbce6
DATA T256_4<>+0x0100(SB)/8, $0x9d8a7a879d8a7a87
DATA T256_4<>+0x0108(SB)/8, $0x9d8a7a879d8a7a87
DATA T256_4<>+0x0110(SB)/8, $0x3b14f50f3b14f50f
DATA T256_4<>+0x0118(SB)/8, $0x3b14f50f3b14f50f
DATA T256_4<>+0x0120(SB)/8, $0x7629ea1e7629ea1e
DATA T256_4<>+0x0128(SB)/8, $0x7629ea1e7629ea1e
DATA T256_4<>+0x0130(SB)/8, $0xec53d43cec53d43c
DATA T256_4<>+0x0138(SB)/8, $0xec53d43cec53d43c
DATA T256_4<>+0x0140(SB)/8, $0xd8a7a879d8a7a879
DATA T256_4<>+0x0148(SB)/8, $0xd8a7a879d8a7a879
DATA T256_4<>+0x0150(SB)/8, $0xb14f50f3b14f50f3
DATA T256_4<>+0x0158(SB)/8, $0xb14f50f3b14f50f3
DATA T256_4<>+0x0160(SB)/8, $0x629ea1e7629ea1e7
DATA T256_4<>+0x0168(SB)/8, $0x629ea1e7629ea1e7
DATA T256_4<>+0x0170(SB)/8, $0xc53d43cec53d43ce
DATA T256_4<>+0x0178(SB)/8, $0xc53d43cec53d43ce
DATA T256_4<>+0x0180(SB)/8, $0x8a7a879d8a7a879d
DATA T256_4<>+0x0188(SB)/8, $0x8a7a879d8a7a879d
DATA T256_4<>+0x0190(SB)/8, $0x14f50f3b14f50f3b
DATA T256_4<>+0x0198(SB)/8, $0x14f50f3b14f50f3b
DATA T256_4<>+0x01a0(SB)/8, $0x29ea1e7629ea1e76
DATA T256_4<>+0x01a8(SB)/8, $0x29ea1e7629ea1e76
DATA T256_4<>+0x01b0(SB)/8, $0x53d43cec53d43cec
DATA T256_4<>+0x01b8(SB)/8, $0x53d43cec53d43cec
DATA T256_4<>+0x01c0(SB)/8, $0xa7a879d8a7a879d8
DATA T256_4<>+0x01c8(SB)/8, $0xa7a879d8a7a879d8
DATA T256_4<>+0x01d0(SB)/8, $0x4f50f3b14f50f3b1
DATA T256_4<>+0x01d8(SB)/8, $0x4f50f3b14f50f3b1
DATA T256_4<>+0x01e0(SB)/8, $0x9ea1e7629ea1e762
DATA T256_4<>+0x01e8(SB)/8, $0x9ea1e7629ea1e762
DATA T256_4<>+0x01f0(SB)/8, $0x3d43cec53d43cec5
DATA T256_4<>+0x01f8(SB)/8, $0x3d43cec53d43cec5
DATA T256_4<>+0x0200(SB)/8, $0x7a879d8a7a879d8a
DATA T256_4<>+0x0208(SB)/8, $0x7a879d8a7a879d8a
DATA T256_4<>+0x0210(SB)/8, $0xf50f3b14f50f3b14
DATA T256_4<>+0x0218(SB)/8, $0xf50f3b14f50f3b14
DATA T256_4<>+0x0220(SB)/8, $0xea1e7629ea1e7629
DATA T256_4<>+0x0228(SB)/8, $0xea1e7629ea1e7629
DATA T256_4<>+0x0230(SB)/8, $0xd43cec53d43cec53
DATA T256_4<>+0x0238(SB)/8, $0xd43cec53d43cec53
DATA T256_4<>+0x0240(SB)/8, $0xa879d8a7a879d8a7
DATA T256_4<>+0x0248(SB)/8, $0xa879d8a7a879d8a7
DATA T256_4<>+0x0250(SB)/8, $0x50f3b14f50f3b14f
DATA T256_4<>+0x0258(SB)/8, $0x50f3b14f50f3b14f
DATA T256_4<>+0x0260(SB)/8, $0xa1e7629ea1e7629e
DATA T256_4<>+0x0268(SB)/8, $0xa1e7629ea1e7629e
DATA T256_4<>+0x0270(SB)/8, $0x43cec53d43cec53d
DATA T256_4<>+0x0278(SB)/8, $0x43cec53d43cec53d
DATA T256_4<>+0x0280(SB)/8, $0x879d8a7a879d8a7a
DATA T256_4<>+0x0288(SB)/8, $0x879d8a7a879d8a7a
DATA T256_4<>+0x0290(SB)/8, $0x0f3b14f50f3b14f5
DATA T256_4<>+0x0298(SB)/8, $0x0f3b14f50f3b14f5
DATA T256_4<>+0x02a0(SB)/8, $0x1e7629ea1e7629ea
DATA T256_4<>+0x02a8(SB)/8, $0x1e7629ea1e7629ea
DATA T256_4<>+0x02b0(SB)/8, $0x3cec53d43cec53d4
DATA T256_4<>+0x02b8(SB)/8, $0x3cec53d43cec53d4
DATA T256_4<>+0x02c0(SB)/8, $0x79d8a7a879d8a7a8
DATA T256_4<>+0x02c8(SB)/8, $0x79d8a7a879d8a7a8
DATA T256_4<>+0x02d0(SB)/8, $0xf3b14f50f3b14f50
DATA T256_4<>+0x02d8(SB)/8, $0xf3b14f50f3b14f50
DATA T256_4<>+0x02e0(SB)/8, $0xe7629ea1e7629ea1
DATA T256_4<>+0x02e8(SB)/8, $0xe7629ea1e7629ea1
DATA T256_4<>+0x02f0(SB)/8, $0xcec53d43cec53d43
DATA T256_4<>+0x02f8(SB)/8, $0xcec53d43cec53d43
GLOBL T256_4<>(SB), RODATA, $3072 // 48 * 4 * 16

// Transpose matrix without PUNPCKHDQ/PUNPCKLDQ/PUNPCKHQDQ/PUNPCKLQDQ instructions, bad performance!
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

#define storeState \
	MOVOU a, (BX) \
	MOVOU b, 16(BX) \
	MOVOU c, 32(BX) \
	MOVOU d, 48(BX) \
	MOVOU e, 64(BX) \
	MOVOU f, 80(BX) \
	MOVOU g, 96(BX) \
	MOVOU h, 112(BX)

// xorm (mem), reg
// Xor reg to mem using reg-mem xor and store
#define xorm(P1, P2) \
	MOVOU P1, tmp1; \
	PXOR tmp1, P2; \
	MOVOU P2, P1
	
#define store4Words(W, j) MOVOU W, (128+(j)*16)(BX)
#define load4Words(W, i) MOVOU (128+(i)*16)(BX), W

#define prepareFirst16Words(i) \
	MOVOU (i*16)(R8), X10; \
	MOVOU (i*16)(R9), X11; \
	MOVOU (i*16)(R10), X12; \
	MOVOU (i*16)(R11), X13; \
	; \
	SSE_TRANSPOSE_MATRIX(X10, X11, X12, X13, tmp1, tmp2); \
	MOVOU flip_mask<>(SB), tmp1; \
	PSHUFB tmp1, X10; \
	PSHUFB tmp1, X11; \
	PSHUFB tmp1, X12; \
	PSHUFB tmp1, X13; \
	; \
	store4Words(X10, 4*i+0); \
	store4Words(X11, 4*i+1); \
	store4Words(X12, 4*i+2); \
	store4Words(X13, 4*i+3)

// r <<< n, SSE version
#define PROLD(r, n) \
	MOVOU r, tmp1; \
	PSLLL $n, r; \
	PSRLL $(32-n), tmp1; \
	POR tmp1, r

#define ROUND_00_11(index, a, b, c, d, e, f, g, h) \
	MOVOU a, X12; \
	PROLD(X12, 12); \
	MOVOU X12, X13; \ // a <<< 12
	MOVOU (index*16)(AX), tmp2; \
	PADDL tmp2, X12; \
	PADDL e, X12; \
	PROLD(X12, 7); \ // SS1
	PXOR X12, X13; \ // SS2
	MOVOU b, X14; \
	PXOR a, X14; \
	PXOR c, X14; \ // (a XOR b XOR c)
	PADDL d, X14; \ // (a XOR b XOR c) + d 
	load4Words(X10, index); \
	load4Words(X11, index+4); \
	PXOR X10, X11; \ //Wt XOR Wt+4
	PADDL X11, X14; \ // (a XOR b XOR c) + d + Wt XOR Wt+4
	PADDL X14, X13; \ // TT1
	PADDL h, X10; \ // Wt + h
	PADDL X12, X10; \ // Wt + h + SS1
	MOVOU e, X11; \
	PXOR f, X11; \
	PXOR g, X11; \ // (e XOR f XOR g)
	PADDL X11, X10; \ // TT2 = (e XOR f XOR g) + Wt + h + SS1
	; \ // copy result
	PROLD(b, 9); \
	MOVOU X13, h; \
	PROLD(f, 19); \
	MOVOU X10, X13; \
	PROLD(X13, 9); \
	PXOR X10, X13; \ // tt2 XOR ROTL(9, tt2)
	PROLD(X10, 17); \
	PXOR X10, X13; \ // tt2 XOR ROTL(9, tt2) XOR ROTL(17, tt2)
	MOVOU X13, d

#define MESSAGE_SCHEDULE(index) \
	load4Words(X10, index+1); \ // Wj-3
	PROLD(X10, 15); \
	load4Words(X11, index-12); \ // Wj-16
	PXOR X11, X10; \
	load4Words(X11, index-5); \ // Wj-9
	PXOR X11, X10; \
	MOVOU X10, X11; \
	PROLD(X11, 15); \
	PXOR X11, X10; \
	PROLD(X11, 8); \
	PXOR X11, X10; \ // P1
	load4Words(X11, index-9); \ // Wj-13
	PROLD(X11, 7); \
	PXOR X11, X10; \
	load4Words(X11, index-2); \ // Wj-6
	PXOR X10, X11; \
	store4Words(X11, index+4)

#define ROUND_12_15(index, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index); \
	ROUND_00_11(index, a, b, c, d, e, f, g, h)

#define ROUND_16_63(index, cIndex, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index); \ // X11 is Wt+4 now, Pls do not use it
	MOVOU a, X12; \
	PROLD(X12, 12); \
	MOVOU X12, X13; \ // a <<< 12
	MOVOU (cIndex*16)(AX), tmp2; \
	PADDL tmp2, X12; \
	PADDL e, X12; \
	PROLD(X12, 7); \ // SS1
	PXOR X12, X13; \ // SS2
	; \
	MOVOU a, X14; \
	POR b, X14; \
	MOVOU a, X10; \
	PAND b, X10; \
	PAND c, X14; \
	POR X10, X14; \ // (a AND b) OR (a AND c) OR (b AND c)
	PADDL d, X14; \ // (a AND b) OR (a AND c) OR (b AND c) + d
	load4Words(X10, index); \
	PXOR X10, X11; \ //Wt XOR Wt+4
	PADDL X11, X14; \ // (a AND b) OR (a AND c) OR (b AND c) + d + Wt XOR Wt+4
	PADDL X14, X13; \ // TT1
	; \
	PADDL h, X10; \ // Wt + h
	PADDL X12, X10; \ // Wt + h + SS1
	MOVOU f, X11; \
	PXOR g, X11; \
	PAND e, X11; \ // (f XOR g) AND e XOR g
	PXOR g, X11; \
	PADDL X11, X10; \ // TT2 = (e XOR f XOR g) + Wt + h + SS1
	; \ // copy result
	PROLD(b, 9); \
	MOVOU X13, h; \
	PROLD(f, 19); \
	MOVOU X10, X13; \
	PROLD(X13, 9); \
	PXOR X10, X13; \ // tt2 XOR ROTL(9, tt2)
	PROLD(X10, 17); \
	PXOR X10, X13; \ // tt2 XOR ROTL(9, tt2) XOR ROTL(17, tt2)
	MOVOU X13, d	

// transpose matrix function, AVX/AVX2 version
// parameters:
// - r0: 128/256 bits register as input/output data
// - r1: 128/256 bits register as input/output data
// - r2: 128/256 bits register as input/output data
// - r3: 128/256 bits register as input/output data
// - tmp1: 128/256 bits temp register
// - tmp2: 128/256 bits temp register
#define TRANSPOSE_MATRIX(r0, r1, r2, r3, tmp1, tmp2) \
	VPUNPCKHDQ r1, r0, tmp2;                 \ // tmp2 =  [w15, w7, w14, w6, w11, w3, w10, w2]          tmp2 = [w7, w3, w6, w2]
	VPUNPCKLDQ r1, r0, r0;                   \ // r0 =    [w13, w5, w12, w4, w9, w1, w8, w0]              r0 = [w5, w1, w4, w0]
	VPUNPCKLDQ r3, r2, tmp1;                 \ // tmp1 =  [w29, w21, w28, w20, w25, w17, w24, w16]      tmp1 = [w13, w9, w12, w8]
	VPUNPCKHDQ r3, r2, r2;                   \ // r2 =    [w31, w27, w30, w22, w27, w19, w26, w18]        r2 = [w15, w11, w14, w10] 
	VPUNPCKHQDQ tmp1, r0, r1;                \ // r1 =    [w29, w21, w13, w5, w25, w17, w9, w1]           r1 = [w13, w9, w5, w1]
	VPUNPCKLQDQ tmp1, r0, r0;                \ // r0 =    [w28, w20, w12, w4, w24, w16, w8, w0]           r0 = [w12, w8, w4, w0]
	VPUNPCKHQDQ r2, tmp2, r3;                \ // r3 =    [w31, w27, w15, w7, w27, w19, w11, w3]          r3 = [w15, w11, w7, w3]
	VPUNPCKLQDQ r2, tmp2, r2                   // r2 =    [w30, w22, w14, w6, w26, w18, w10, w2]          r2 = [w14, w10, w6, w2]

// avxXorm (mem), reg
// Xor reg to mem using reg-mem xor and store
#define avxXorm(P1, P2) \
	VPXOR P1, P2, P2; \
	VMOVDQU P2, P1
	
#define avxStore4Words(W, j) VMOVDQU W, (128+(j)*16)(BX)
#define avxLoad4Words(W, i) VMOVDQU (128+(i)*16)(BX), W

#define avxPrepareFirst16Words(i) \
	VMOVDQU (i*16)(R8), X10; \
	VMOVDQU (i*16)(R9), X11; \
	VMOVDQU (i*16)(R10), X12; \
	VMOVDQU (i*16)(R11), X13; \
	; \
	TRANSPOSE_MATRIX(X10, X11, X12, X13, tmp1, tmp2); \
	VPSHUFB flip_mask<>(SB), X10, X10; \
	VPSHUFB flip_mask<>(SB), X11, X11; \
	VPSHUFB flip_mask<>(SB), X12, X12; \
	VPSHUFB flip_mask<>(SB), X13, X13; \
	; \
	avxStore4Words(X10, 4*i+0); \
	avxStore4Words(X11, 4*i+1); \
	avxStore4Words(X12, 4*i+2); \
	avxStore4Words(X13, 4*i+3)

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

#define AVX_ROUND_00_11(index, a, b, c, d, e, f, g, h) \
	VPROLD2(a, X13, 12); \ // a <<< 12
	VPADDD (index*16)(AX), X13, X12; \
	VPADDD e, X12, X12; \
	VPROLD(X12, 7); \ // SS1
	VPXOR X12, X13, X13; \ // SS2
	; \
	VPXOR a, b, X14; \
	VPXOR c, X14, X14; \ // (a XOR b XOR c)
	VPADDD d, X14, X14; \ // (a XOR b XOR c) + d 
	avxLoad4Words(X10, index); \
	avxLoad4Words(X11, index+4); \
	VPXOR X10, X11, X11; \ //Wt XOR Wt+4
	VPADDD X11, X14, X14; \ // (a XOR b XOR c) + d + Wt XOR Wt+4
	VPADDD X14, X13, X13; \ // TT1
	VPADDD h, X10, X10; \ // Wt + h
	VPADDD X12, X10, X10; \ // Wt + h + SS1
	VPXOR e, f, X11; \
	VPXOR g, X11, X11; \ // (e XOR f XOR g)
	VPADDD X11, X10, X10; \ // TT2 = (e XOR f XOR g) + Wt + h + SS1
	; \ // copy result
	VPROLD(b, 9); \
	VMOVDQU X13, h; \
	VPROLD(f, 19); \
	VPROLD2(X10, X13, 9); \ // tt2 <<< 9
	VPXOR X10, X13, X13; \ // tt2 XOR ROTL(9, tt2)
	VPROLD(X10, 17); \ // tt2 <<< 17
	VPXOR X10, X13, d

#define AVX_MESSAGE_SCHEDULE(index) \
	avxLoad4Words(X10, index+1); \ // Wj-3
	VPROLD(X10, 15); \
	VPXOR (128+(index-12)*16)(BX), X10, X10; \ // Wj-16
	VPXOR (128+(index-5)*16)(BX), X10, X10; \ // Wj-9
	; \ // P1
	VPROLD2(X10, X11, 15); \
	VPXOR X11, X10, X10; \
	VPROLD(X11, 8); \
	VPXOR X11, X10, X10; \ // P1
	avxLoad4Words(X11, index-9); \ // Wj-13
	VPROLD(X11, 7); \
	VPXOR X11, X10, X10; \
	VPXOR (128+(index-2)*16)(BX), X10, X11; \
	avxStore4Words(X11, index+4)

#define AVX_ROUND_12_15(index, a, b, c, d, e, f, g, h) \
	AVX_MESSAGE_SCHEDULE(index); \
	AVX_ROUND_00_11(index, a, b, c, d, e, f, g, h)

#define AVX_ROUND_16_63(index, cIndex, a, b, c, d, e, f, g, h) \
	AVX_MESSAGE_SCHEDULE(index); \ // X11 is Wt+4 now, Pls do not use it
	VPROLD2(a, X13, 12); \ // a <<< 12
	VPADDD (cIndex*16)(AX), X13, X12; \
	VPADDD e, X12, X12; \
	VPROLD(X12, 7); \ // SS1
	VPXOR X12, X13, X13; \ // SS2
	; \
	VPOR a, b, X14; \
	VPAND a, b, X10; \
	VPAND c, X14, X14; \
	VPOR X10, X14, X14; \ // (a AND b) OR (a AND c) OR (b AND c)
	VPADDD d, X14, X14; \ // (a AND b) OR (a AND c) OR (b AND c) + d
	avxLoad4Words(X10, index); \
	VPXOR X10, X11, X11; \ //Wt XOR Wt+4
	VPADDD X11, X14, X14; \ // (a AND b) OR (a AND c) OR (b AND c) + d + Wt XOR Wt+4
	VPADDD X14, X13, X13; \ // TT1
	; \
	VPADDD h, X10, X10; \ // Wt + h
	VPADDD X12, X10, X10; \ // Wt + h + SS1
	VPXOR f, g, X11; \
	VPAND e, X11, X11; \ 
	VPXOR g, X11, X11; \ // (f XOR g) AND e XOR g
	VPADDD X11, X10, X10; \ // TT2 = (e XOR f XOR g) + Wt + h + SS1
	; \ // copy result
	VPROLD(b, 9); \
	VMOVDQU X13, h; \
	VPROLD(f, 19); \
	VPROLD2(X10, X13, 9); \ // tt2 <<< 9
	VPXOR X10, X13, X13; \ // tt2 XOR ROTL(9, tt2)
	VPROLD(X10, 17); \ // tt2 <<< 17
	VPXOR X10, X13, d

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
	storeState

	MOVQ $T256_4<>(SB), AX
	MOVQ (SI), R8
	MOVQ 8(SI), R9
	MOVQ 16(SI), R10
	MOVQ 24(SI), R11

loop:	
	// load message block
	prepareFirst16Words(0)
	prepareFirst16Words(1)
	prepareFirst16Words(2)
	prepareFirst16Words(3)

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

	ROUND_16_63(16, 16, a, b, c, d, e, f, g, h)
	ROUND_16_63(17, 17, h, a, b, c, d, e, f, g)
	ROUND_16_63(18, 18, g, h, a, b, c, d, e, f)
	ROUND_16_63(19, 19, f, g, h, a, b, c, d, e)
	ROUND_16_63(20, 20, e, f, g, h, a, b, c, d)
	ROUND_16_63(21, 21, d, e, f, g, h, a, b, c)
	ROUND_16_63(22, 22, c, d, e, f, g, h, a, b)
	ROUND_16_63(23, 23, b, c, d, e, f, g, h, a)
	ROUND_16_63(24, 24, a, b, c, d, e, f, g, h)
	ROUND_16_63(25, 25, h, a, b, c, d, e, f, g)
	ROUND_16_63(26, 26, g, h, a, b, c, d, e, f)
	ROUND_16_63(27, 27, f, g, h, a, b, c, d, e)
	ROUND_16_63(28, 28, e, f, g, h, a, b, c, d)
	ROUND_16_63(29, 29, d, e, f, g, h, a, b, c)
	ROUND_16_63(30, 30, c, d, e, f, g, h, a, b)
	ROUND_16_63(31, 31, b, c, d, e, f, g, h, a)
	ROUND_16_63(32, 32, a, b, c, d, e, f, g, h)
	ROUND_16_63(33, 33, h, a, b, c, d, e, f, g)
	ROUND_16_63(34, 34, g, h, a, b, c, d, e, f)
	ROUND_16_63(35, 35, f, g, h, a, b, c, d, e)
	ROUND_16_63(36, 36, e, f, g, h, a, b, c, d)
	ROUND_16_63(37, 37, d, e, f, g, h, a, b, c)
	ROUND_16_63(38, 38, c, d, e, f, g, h, a, b)
	ROUND_16_63(39, 39, b, c, d, e, f, g, h, a)
	ROUND_16_63(40, 40, a, b, c, d, e, f, g, h)
	ROUND_16_63(41, 41, h, a, b, c, d, e, f, g)
	ROUND_16_63(42, 42, g, h, a, b, c, d, e, f)
	ROUND_16_63(43, 43, f, g, h, a, b, c, d, e)
	ROUND_16_63(44, 44, e, f, g, h, a, b, c, d)
	ROUND_16_63(45, 45, d, e, f, g, h, a, b, c)
	ROUND_16_63(46, 46, c, d, e, f, g, h, a, b)
	ROUND_16_63(47, 47, b, c, d, e, f, g, h, a)
	ROUND_16_63(48, 16, a, b, c, d, e, f, g, h)
	ROUND_16_63(49, 17, h, a, b, c, d, e, f, g)
	ROUND_16_63(50, 18, g, h, a, b, c, d, e, f)
	ROUND_16_63(51, 19, f, g, h, a, b, c, d, e)
	ROUND_16_63(52, 20, e, f, g, h, a, b, c, d)
	ROUND_16_63(53, 21, d, e, f, g, h, a, b, c)
	ROUND_16_63(54, 22, c, d, e, f, g, h, a, b)
	ROUND_16_63(55, 23, b, c, d, e, f, g, h, a)
	ROUND_16_63(56, 24, a, b, c, d, e, f, g, h)
	ROUND_16_63(57, 25, h, a, b, c, d, e, f, g)
	ROUND_16_63(58, 26, g, h, a, b, c, d, e, f)
	ROUND_16_63(59, 27, f, g, h, a, b, c, d, e)
	ROUND_16_63(60, 28, e, f, g, h, a, b, c, d)
	ROUND_16_63(61, 29, d, e, f, g, h, a, b, c)
	ROUND_16_63(62, 30, c, d, e, f, g, h, a, b)
	ROUND_16_63(63, 31, b, c, d, e, f, g, h, a)

	xorm(  0(BX), a)
	xorm( 16(BX), b)
	xorm( 32(BX), c)
	xorm( 48(BX), d)
	xorm( 64(BX), e)
	xorm( 80(BX), f)
	xorm( 96(BX), g)
	xorm(112(BX), h)

	LEAQ 64(R8), R8
	LEAQ 64(R9), R9
	LEAQ 64(R10), R10
	LEAQ 64(R11), R11

	DECQ DX
	JNZ loop

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

	VMOVDQU a, (BX)
	VMOVDQU b, 16(BX)
	VMOVDQU c, 32(BX)
	VMOVDQU d, 48(BX)
	VMOVDQU e, 64(BX)
	VMOVDQU f, 80(BX)
	VMOVDQU g, 96(BX)
	VMOVDQU h, 112(BX)

	MOVQ $T256_4<>(SB), AX
	MOVQ (SI), R8
	MOVQ 8(SI), R9
	MOVQ 16(SI), R10
	MOVQ 24(SI), R11

avxLoop:
	// load message block
	avxPrepareFirst16Words(0)
	avxPrepareFirst16Words(1)
	avxPrepareFirst16Words(2)
	avxPrepareFirst16Words(3)

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

	AVX_ROUND_16_63(16, 16, a, b, c, d, e, f, g, h)
	AVX_ROUND_16_63(17, 17, h, a, b, c, d, e, f, g)
	AVX_ROUND_16_63(18, 18, g, h, a, b, c, d, e, f)
	AVX_ROUND_16_63(19, 19, f, g, h, a, b, c, d, e)
	AVX_ROUND_16_63(20, 20, e, f, g, h, a, b, c, d)
	AVX_ROUND_16_63(21, 21, d, e, f, g, h, a, b, c)
	AVX_ROUND_16_63(22, 22, c, d, e, f, g, h, a, b)
	AVX_ROUND_16_63(23, 23, b, c, d, e, f, g, h, a)
	AVX_ROUND_16_63(24, 24, a, b, c, d, e, f, g, h)
	AVX_ROUND_16_63(25, 25, h, a, b, c, d, e, f, g)
	AVX_ROUND_16_63(26, 26, g, h, a, b, c, d, e, f)
	AVX_ROUND_16_63(27, 27, f, g, h, a, b, c, d, e)
	AVX_ROUND_16_63(28, 28, e, f, g, h, a, b, c, d)
	AVX_ROUND_16_63(29, 29, d, e, f, g, h, a, b, c)
	AVX_ROUND_16_63(30, 30, c, d, e, f, g, h, a, b)
	AVX_ROUND_16_63(31, 31, b, c, d, e, f, g, h, a)
	AVX_ROUND_16_63(32, 32, a, b, c, d, e, f, g, h)
	AVX_ROUND_16_63(33, 33, h, a, b, c, d, e, f, g)
	AVX_ROUND_16_63(34, 34, g, h, a, b, c, d, e, f)
	AVX_ROUND_16_63(35, 35, f, g, h, a, b, c, d, e)
	AVX_ROUND_16_63(36, 36, e, f, g, h, a, b, c, d)
	AVX_ROUND_16_63(37, 37, d, e, f, g, h, a, b, c)
	AVX_ROUND_16_63(38, 38, c, d, e, f, g, h, a, b)
	AVX_ROUND_16_63(39, 39, b, c, d, e, f, g, h, a)
	AVX_ROUND_16_63(40, 40, a, b, c, d, e, f, g, h)
	AVX_ROUND_16_63(41, 41, h, a, b, c, d, e, f, g)
	AVX_ROUND_16_63(42, 42, g, h, a, b, c, d, e, f)
	AVX_ROUND_16_63(43, 43, f, g, h, a, b, c, d, e)
	AVX_ROUND_16_63(44, 44, e, f, g, h, a, b, c, d)
	AVX_ROUND_16_63(45, 45, d, e, f, g, h, a, b, c)
	AVX_ROUND_16_63(46, 46, c, d, e, f, g, h, a, b)
	AVX_ROUND_16_63(47, 47, b, c, d, e, f, g, h, a)
	AVX_ROUND_16_63(48, 16, a, b, c, d, e, f, g, h)
	AVX_ROUND_16_63(49, 17, h, a, b, c, d, e, f, g)
	AVX_ROUND_16_63(50, 18, g, h, a, b, c, d, e, f)
	AVX_ROUND_16_63(51, 19, f, g, h, a, b, c, d, e)
	AVX_ROUND_16_63(52, 20, e, f, g, h, a, b, c, d)
	AVX_ROUND_16_63(53, 21, d, e, f, g, h, a, b, c)
	AVX_ROUND_16_63(54, 22, c, d, e, f, g, h, a, b)
	AVX_ROUND_16_63(55, 23, b, c, d, e, f, g, h, a)
	AVX_ROUND_16_63(56, 24, a, b, c, d, e, f, g, h)
	AVX_ROUND_16_63(57, 25, h, a, b, c, d, e, f, g)
	AVX_ROUND_16_63(58, 26, g, h, a, b, c, d, e, f)
	AVX_ROUND_16_63(59, 27, f, g, h, a, b, c, d, e)
	AVX_ROUND_16_63(60, 28, e, f, g, h, a, b, c, d)
	AVX_ROUND_16_63(61, 29, d, e, f, g, h, a, b, c)
	AVX_ROUND_16_63(62, 30, c, d, e, f, g, h, a, b)
	AVX_ROUND_16_63(63, 31, b, c, d, e, f, g, h, a)

	avxXorm(  0(BX), a)
	avxXorm( 16(BX), b)
	avxXorm( 32(BX), c)
	avxXorm( 48(BX), d)
	avxXorm( 64(BX), e)
	avxXorm( 80(BX), f)
	avxXorm( 96(BX), g)
	avxXorm(112(BX), h)

	LEAQ 64(R8), R8
	LEAQ 64(R9), R9
	LEAQ 64(R10), R10
	LEAQ 64(R11), R11

	DECQ DX
	JNZ avxLoop

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
