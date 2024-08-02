//go:build !purego

#include "textflag.h"

// shuffle byte order from LE to BE
DATA flip_mask<>+0x00(SB)/8, $0x0405060700010203
DATA flip_mask<>+0x08(SB)/8, $0x0c0d0e0f08090a0b
DATA flip_mask<>+0x10(SB)/8, $0x0405060700010203
DATA flip_mask<>+0x18(SB)/8, $0x0c0d0e0f08090a0b
GLOBL flip_mask<>(SB), 8, $32

// left rotations of 32-bit words by 8-bit increments
DATA r08_mask<>+0x00(SB)/8, $0x0605040702010003
DATA r08_mask<>+0x08(SB)/8, $0x0E0D0C0F0A09080B
DATA r08_mask<>+0x10(SB)/8, $0x0605040702010003
DATA r08_mask<>+0x18(SB)/8, $0x0E0D0C0F0A09080B
GLOBL r08_mask<>(SB), 8, $32

#define a Y0
#define b Y1
#define c Y2
#define d Y3
#define e Y4
#define f Y5
#define g Y6
#define h Y7
#define TMP1 Y8
#define TMP2 Y9
#define TMP3 Y10
#define TMP4 Y11

#define srcPtr1 CX
#define srcPtr2 R8
#define srcPtr3 R9
#define srcPtr4 R10
#define srcPtr5 R11
#define srcPtr6 R12
#define srcPtr7 R13
#define srcPtr8 R14

// transpose matrix function, AVX2 version
// parameters:
// - r0: 256 bits register as input/output data
// - r1: 256 bits register as input/output data
// - r2: 256 bits register as input/output data
// - r3: 256 bits register as input/output data
// - r4: 256 bits register as input/output data
// - r5: 256 bits register as input/output data
// - r6: 256 bits register as input/output data
// - r7: 256 bits register as input/output data
// - tmp1: 256 bits temp register
// - tmp2: 256 bits temp register
// - tmp3: 256 bits temp register
// - tmp4: 256 bits temp register
#define TRANSPOSE_MATRIX(r0, r1, r2, r3, r4, r5, r6, r7, tmp1, tmp2, tmp3, tmp4) \
	; \ // [r0, r1, r2, r3] => [tmp3, tmp4, tmp2, tmp1]
	VPUNPCKHDQ r1, r0, tmp4;                 \ // tmp4 =  [w15, w7, w14, w6, w11, w3, w10, w2]
	VPUNPCKLDQ r1, r0, r0;                   \ // r0 =    [w13, w5, w12, w4, w9, w1, w8, w0]
	VPUNPCKLDQ r3, r2, tmp3;                 \ // tmp3 =  [w29, w21, w28, w20, w25, w17, w24, w16]
	VPUNPCKHDQ r3, r2, r2;                   \ // r2 =    [w31, w27, w30, w22, w27, w19, w26, w18]
	VPUNPCKHQDQ tmp3, r0, tmp2;                \ // tmp2 =    [w29, w21, w13, w5, w25, w17, w9, w1]
	VPUNPCKLQDQ tmp3, r0, tmp1;                \ // tmp1 =    [w28, w20, w12, w4, w24, w16, w8, w0]
	VPUNPCKHQDQ r2, tmp4, tmp3;                \ // tmp3 =    [w31, w23, w15, w7, w27, w19, w11, w3]
	VPUNPCKLQDQ r2, tmp4, tmp4;                \ // tmp4 =    [w30, w22, w14, w6, w26, w18, w10, w2]
	; \ // [r4, r5, r6, r7] => [r4, r5, r6, r7]
	VPUNPCKHDQ r5, r4, r1;                 \ // r1 =  [w47, w39, w46, w38, w43, w35, w42, w34]
	VPUNPCKLDQ r5, r4, r4;                   \ // r4 =    [w45, w37, w44, w36, w41, w33, w40, w32]
	VPUNPCKLDQ r7, r6, r0;                 \ // r0 =  [w61, w53, w60, w52, w57, w49, w56, w48]
	VPUNPCKHDQ r7, r6, r6;                   \ // r6 =    [w63, w59, w52, w54, w59, w51, w58, w50]
	VPUNPCKHQDQ r0, r4, r5;                \ // r5 =    [w61, w53, w45, w37, w57, w49, w41, w33]
	VPUNPCKLQDQ r0, r4, r4;                \ // r4 =    [w60, w52, w44, w36, w56, w48, w40, w32]
	VPUNPCKHQDQ r6, r1, r7;                \ // r7 =    [w63, w55, w47, w39, w59, w51, w43, w35]
	VPUNPCKLQDQ r6, r1, r6;                \ // r6 =    [w62, w54, w46, w38, w58, w50, w42, w34]
	; \ // [tmp3, tmp4, tmp2, tmp1], [r4, r5, r6, r7] => [r0, r1, r2, r3, r4, r5, r6, r7]
	VPERM2I128 $0x20, r4, tmp1, r0;              \ // r0 =    [w56, w48, w40, w32, w24, w16, w8, w0]
	VPERM2I128 $0x20, r5, tmp2, r1;              \ // r1 =    [w57, w49, w41, w33, w25, w17, w9, w1]
	VPERM2I128 $0x20, r6, tmp4, r2;              \ // r2 =    [w58, w50, w42, w34, w26, w18, w10, w2]
	VPERM2I128 $0x20, r7, tmp3, r3;              \ // r3 =    [w59, w51, w43, w35, w27, w19, w11, w3]
	VPERM2I128 $0x31, r4, tmp1, r4;              \ // r4 =    [w60, w52, w44, w36, w28, w20, w12, w4]
	VPERM2I128 $0x31, r5, tmp2, r5;              \ // r5 =    [w61, w53, w45, w37, w29, w21, w13, w5]
	VPERM2I128 $0x31, r6, tmp4, r6;              \ // r6 =    [w62, w54, w46, w38, w30, w22, w14, w6]
	VPERM2I128 $0x31, r7, tmp3, r7;              \ // r7 =    [w63, w55, w47, w39, w31, w23, w15, w7]

// store 256 bits
#define storeWord(W, j) VMOVDQU W, (256+(j)*32)(BX)
// load 256 bits
#define loadWord(W, i) VMOVDQU (256+(i)*32)(BX), W

#define REV32(a, b, c, d, e, f, g, h) \
	VPSHUFB flip_mask<>(SB), a, a; \
	VPSHUFB flip_mask<>(SB), b, b; \
	VPSHUFB flip_mask<>(SB), c, c; \
	VPSHUFB flip_mask<>(SB), d, d; \
	VPSHUFB flip_mask<>(SB), e, e; \
	VPSHUFB flip_mask<>(SB), f, f; \
	VPSHUFB flip_mask<>(SB), g, g; \
	VPSHUFB flip_mask<>(SB), h, h

#define prepare8Words(i) \
	VMOVDQU (i*32)(srcPtr1), a; \
	VMOVDQU (i*32)(srcPtr2), b; \
	VMOVDQU (i*32)(srcPtr3), c; \
	VMOVDQU (i*32)(srcPtr4), d; \
	VMOVDQU (i*32)(srcPtr5), e; \
	VMOVDQU (i*32)(srcPtr6), f; \
	VMOVDQU (i*32)(srcPtr7), g; \
	VMOVDQU (i*32)(srcPtr8), h; \    
	; \
	TRANSPOSE_MATRIX(a, b, c, d, e, f, g, h, TMP1, TMP2, TMP3, TMP4); \
	REV32(a, b, c, d, e, f, g, h); \
	; \
	storeWord(a, 8*i+0); \
	storeWord(b, 8*i+1); \
	storeWord(c, 8*i+2); \
	storeWord(d, 8*i+3); \
	storeWord(e, 8*i+4); \
	storeWord(f, 8*i+5); \
	storeWord(g, 8*i+6); \
	storeWord(h, 8*i+7)

#define saveState(R) \
	VMOVDQU a, (0*32)(R); \
	VMOVDQU b, (1*32)(R); \
	VMOVDQU c, (2*32)(R); \
	VMOVDQU d, (3*32)(R); \
	VMOVDQU e, (4*32)(R); \
	VMOVDQU f, (5*32)(R); \
	VMOVDQU g, (6*32)(R); \
	VMOVDQU h, (7*32)(R)

#define loadState(R) \
	VMOVDQU (0*32)(R), a; \
	VMOVDQU (1*32)(R), b; \
	VMOVDQU (2*32)(R), c; \
	VMOVDQU (3*32)(R), d; \
	VMOVDQU (4*32)(R), e; \
	VMOVDQU (5*32)(R), f; \
	VMOVDQU (6*32)(R), g; \
	VMOVDQU (7*32)(R), h

// r <<< n
#define VPROLD(r, n) \
	VPSLLD $(n), r, TMP1; \
	VPSRLD $(32-n), r, r; \
	VPOR TMP1, r, r

// d = r <<< n
#define VPROLD2(r, d, n) \
	VPSLLD $(n), r, TMP1; \
	VPSRLD $(32-n), r, d; \
	VPOR TMP1, d, d

#define LOAD_T(index, T) \
	VPBROADCASTD (index*4)(AX), T

// DST = X XOR Y XOR Z
#define FF0(X, Y, Z, DST) \
	VPXOR X, Y, DST; \
	VPXOR Z, DST, DST

// DST = (X AND Y) OR (X AND Z) OR (Y AND Z)
#define FF1(X, Y, Z, TMP, DST) \
	VPOR X, Y, DST; \
	VPAND X, Y, TMP; \
	VPAND Z, DST, DST; \
	VPOR TMP, DST, DST

// DST = X XOR Y XOR Z
#define GG0(X, Y, Z, DST) \
	FF0(X, Y, Z, DST)

// DST = (Y XOR Z) AND X XOR Z
#define GG1(X, Y, Z, DST) \
	VPXOR Y, Z, DST; \
	VPAND X, DST, DST; \ 
	VPXOR Z, DST, DST

#define SS1SS2(index, a, e, SS1, SS2) \
	VPROLD2(a, SS2, 12); \ // a <<< 12
	LOAD_T(index, SS1);   \ // const
	VPADDD SS1, SS2, SS1; \
	VPADDD e, SS1, SS1; \
	VPROLD(SS1, 7); \ // SS1
	VPXOR SS1, SS2, SS2; \ // SS2

#define COPY_RESULT(b, d, f, h, TT1, TT2) \
	VPROLD(b, 9); \
	VMOVDQU TT1, h; \ // TT1
	VPROLD(f, 19); \
	VPROLD2(TT2, TT1, 9); \ // tt2 <<< 9
	VPXOR TT2, TT1, TT2; \ // tt2 XOR ROTL(9, tt2)
	VPSHUFB r08_mask<>(SB), TT1, TT1; \ // ROTL(17, tt2)
	VPXOR TT1, TT2, d

#define ROUND_00_11(index, a, b, c, d, e, f, g, h) \
	SS1SS2(index, a, e, Y12, Y13); \
	; \
	FF0(a, b, c, Y14); \
	VPADDD d, Y14, Y14; \ // (a XOR b XOR c) + d 
	loadWord(Y10, index); \
	loadWord(Y11, index+4); \
	VPXOR Y10, Y11, Y11; \ //Wt XOR Wt+4
	VPADDD Y11, Y14, Y14; \ // (a XOR b XOR c) + d + Wt XOR Wt+4
	VPADDD Y14, Y13, Y13; \ // TT1
	VPADDD h, Y10, Y10; \ // Wt + h
	VPADDD Y12, Y10, Y10; \ // Wt + h + SS1
	GG0(e, f, g, Y11); \
	VPADDD Y11, Y10, Y10; \ // TT2 = (e XOR f XOR g) + Wt + h + SS1
	; \ // copy result
	COPY_RESULT(b, d, f, h, Y13, Y10)

#define MESSAGE_SCHEDULE(index) \
	loadWord(Y10, index+1); \ // Wj-3
	VPROLD(Y10, 15); \
	VPXOR (256+(index-12)*32)(BX), Y10, Y10; \ // Wj-16
	VPXOR (256+(index-5)*32)(BX), Y10, Y10; \ // Wj-9
	; \ // P1
	VPROLD2(Y10, Y11, 15); \
	VPXOR Y11, Y10, Y10; \
	VPSHUFB r08_mask<>(SB), Y11, Y11; \
	VPXOR Y11, Y10, Y10; \ // P1
	loadWord(Y11, index-9); \ // Wj-13
	VPROLD(Y11, 7); \
	VPXOR Y11, Y10, Y10; \
	VPXOR (256+(index-2)*32)(BX), Y10, Y11; \
	storeWord(Y11, index+4)

#define ROUND_12_15(index, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index); \
	ROUND_00_11(index, a, b, c, d, e, f, g, h)

#define ROUND_16_63(index, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index); \ // Y11 is Wt+4 now, Pls do not use it
	SS1SS2(index, a, e, Y12, Y13); \
	; \
	FF1(a, b, c, Y10, Y14); \ // (a AND b) OR (a AND c) OR (b AND c)
	VPADDD d, Y14, Y14; \ // (a AND b) OR (a AND c) OR (b AND c) + d
	loadWord(Y10, index); \
	VPXOR Y10, Y11, Y11; \ //Wt XOR Wt+4
	VPADDD Y11, Y14, Y14; \ // (a AND b) OR (a AND c) OR (b AND c) + d + Wt XOR Wt+4
	VPADDD Y14, Y13, Y13; \ // TT1
	; \
	VPADDD h, Y10, Y10; \ // Wt + h
	VPADDD Y12, Y10, Y10; \ // Wt + h + SS1
	GG1(e, f, g, Y11); \
	VPADDD Y11, Y10, Y10; \ // TT2 = (e XOR f XOR g) + Wt + h + SS1
	; \ // copy result
	COPY_RESULT(b, d, f, h, Y13, Y10)

// transposeMatrix8x8(dig **[8]uint32)
TEXT ·transposeMatrix8x8(SB),NOSPLIT,$0
	MOVQ	dig+0(FP), DI

	// load state
	MOVQ (DI), R8
	VMOVDQU (R8), a
	MOVQ 8(DI), R8
	VMOVDQU (R8), b
	MOVQ 16(DI), R8
	VMOVDQU (R8), c
	MOVQ 24(DI), R8
	VMOVDQU (R8), d
	MOVQ 32(DI), R8
	VMOVDQU (R8), e
	MOVQ 40(DI), R8
	VMOVDQU (R8), f
	MOVQ 48(DI), R8
	VMOVDQU (R8), g
	MOVQ 56(DI), R8
	VMOVDQU (R8), h

	TRANSPOSE_MATRIX(a, b, c, d, e, f, g, h, TMP1, TMP2, TMP3, TMP4)

	// save state
	MOVQ (DI), R8
	VMOVDQU a, (R8)
	MOVQ 8(DI), R8
	VMOVDQU b, (R8)
	MOVQ 16(DI), R8
	VMOVDQU c, (R8)
	MOVQ 24(DI), R8
	VMOVDQU d, (R8)
	MOVQ 32(DI), R8
	VMOVDQU e, (R8)
	MOVQ 40(DI), R8
	VMOVDQU f, (R8)
	MOVQ 48(DI), R8
	VMOVDQU g, (R8)
	MOVQ 56(DI), R8
	VMOVDQU h, (R8)

	VZEROUPPER

	RET

// blockMultBy8(dig **[8]uint32, p *[]byte, buffer *byte, blocks int)
TEXT ·blockMultBy8(SB),NOSPLIT,$0
	MOVQ	dig+0(FP), DI
	MOVQ	p+8(FP), SI
	MOVQ	buffer+16(FP), BX
	MOVQ	blocks+24(FP), DX

	// load state
	MOVQ (DI), R8
	VMOVDQU (R8), a
	MOVQ 8(DI), R8
	VMOVDQU (R8), b
	MOVQ 16(DI), R8
	VMOVDQU (R8), c
	MOVQ 24(DI), R8
	VMOVDQU (R8), d
	MOVQ 32(DI), R8
	VMOVDQU (R8), e
	MOVQ 40(DI), R8
	VMOVDQU (R8), f
	MOVQ 48(DI), R8
	VMOVDQU (R8), g
	MOVQ 56(DI), R8
	VMOVDQU (R8), h

	TRANSPOSE_MATRIX(a, b, c, d, e, f, g, h, TMP1, TMP2, TMP3, TMP4)

	saveState(BX)

	MOVQ $·_K+0(SB), AX
	MOVQ (0*8)(SI), srcPtr1
	MOVQ (1*8)(SI), srcPtr2
	MOVQ (2*8)(SI), srcPtr3
	MOVQ (3*8)(SI), srcPtr4
	MOVQ (4*8)(SI), srcPtr5
	MOVQ (5*8)(SI), srcPtr6
	MOVQ (6*8)(SI), srcPtr7
	MOVQ (7*8)(SI), srcPtr8

loop:
	prepare8Words(0)
	prepare8Words(1)

	// Need to load state again due to YMM registers are used in prepare8Words
	loadState(BX)

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

	VPXOR (0*32)(BX), a, a
	VPXOR (1*32)(BX), b, b
	VPXOR (2*32)(BX), c, c
	VPXOR (3*32)(BX), d, d
	VPXOR (4*32)(BX), e, e
	VPXOR (5*32)(BX), f, f
	VPXOR (6*32)(BX), g, g
	VPXOR (7*32)(BX), h, h

	DECQ DX
	JZ end

	saveState(BX)
	LEAQ 64(srcPtr1), srcPtr1
	LEAQ 64(srcPtr2), srcPtr2
	LEAQ 64(srcPtr3), srcPtr3
	LEAQ 64(srcPtr4), srcPtr4
	LEAQ 64(srcPtr5), srcPtr5
	LEAQ 64(srcPtr6), srcPtr6
	LEAQ 64(srcPtr7), srcPtr7
	LEAQ 64(srcPtr8), srcPtr8

	JMP loop

end:
	TRANSPOSE_MATRIX(a, b, c, d, e, f, g, h, TMP1, TMP2, TMP3, TMP4)

	// save state
	MOVQ (DI), R8
	VMOVDQU a, (R8)
	MOVQ 8(DI), R8
	VMOVDQU b, (R8)
	MOVQ 16(DI), R8
	VMOVDQU c, (R8)
	MOVQ 24(DI), R8
	VMOVDQU d, (R8)
	MOVQ 32(DI), R8
	VMOVDQU e, (R8)
	MOVQ 40(DI), R8
	VMOVDQU f, (R8)
	MOVQ 48(DI), R8
	VMOVDQU g, (R8)
	MOVQ 56(DI), R8
	VMOVDQU h, (R8)

	VZEROUPPER
	RET

// func copyResultsBy8(dig *uint32, dst *byte)
TEXT ·copyResultsBy8(SB),NOSPLIT,$0
	MOVQ	dig+0(FP), DI
	MOVQ	dst+8(FP), SI

	loadState(DI)
	REV32(a, b, c, d, e, f, g, h)
	saveState(SI)

	VZEROUPPER
	RET
