//go:build amd64 && !purego

#include "textflag.h"

#define B0 X0
#define B1 X1
#define B2 X2
#define B3 X3
#define B4 X4
#define B5 X5
#define B6 X6
#define B7 X7

#define TW X10

#define T0 X11
#define T1 X12
#define T2 X13
#define POLY X14
#define NIBBLE_MASK Y13
#define X_NIBBLE_MASK X13
#define BSWAP X15
#define DWBSWAP Y15

DATA gcmPoly<>+0x00(SB)/8, $0x0000000000000087
DATA gcmPoly<>+0x08(SB)/8, $0x0000000000000000

DATA gbGcmPoly<>+0x00(SB)/8, $0x0000000000000000
DATA gbGcmPoly<>+0x08(SB)/8, $0xe100000000000000

GLOBL gcmPoly<>(SB), (NOPTR+RODATA), $16
GLOBL gbGcmPoly<>(SB), (NOPTR+RODATA), $16

#include "aesni_macros_amd64.s"

#define mul2GBInline        \
	PSHUFB BSWAP, TW;       \
	\// TW * 2
	MOVOU TW, T0;           \
 	PSHUFD $0, TW, T1;      \
	PSRLQ $1, TW;           \
	PSLLQ $63, T0;          \
	PSRLDQ $8, T0;          \
	POR T0, TW;             \
	\// reduction
	PSLLL $31, T1;          \
	PSRAL $31, T1;          \
	PAND POLY, T1;          \
	PXOR T1, TW;            \
	PSHUFB BSWAP, TW

#define avxMul2GBInline        \
	VPSHUFB BSWAP, TW, TW;       \
	\// TW * 2
	VPSLLQ $63, TW, T0;     \      
 	VPSHUFD $0, TW, T1;     \
	VPSRLQ $1, TW, TW;      \
	VPSRLDQ $8, T0, T0;     \
	VPOR T0, TW, TW;        \
	\// reduction
	VPSLLD $31, T1, T1;     \
	VPSRAD $31, T1, T1;     \
	VPAND POLY, T1, T1;     \
	VPXOR T1, TW, TW;       \
	VPSHUFB BSWAP, TW, TW

#define prepareGB4Tweaks \
	MOVOU TW, (16*0)(SP); \
	mul2GBInline;           \ 
	MOVOU TW, (16*1)(SP); \ 
	mul2GBInline;           \
	MOVOU TW, (16*2)(SP); \
	mul2GBInline;           \
	MOVOU TW, (16*3)(SP); \
	mul2GBInline

#define prepareGB8Tweaks \
	prepareGB4Tweaks;       \
	MOVOU TW, (16*4)(SP); \
	mul2GBInline;           \
	MOVOU TW, (16*5)(SP); \
	mul2GBInline;           \
	MOVOU TW, (16*6)(SP); \
	mul2GBInline;           \
	MOVOU TW, (16*7)(SP); \
	mul2GBInline

#define avxPrepareGB4Tweaks \
	VMOVDQU TW, (16*0)(SP); \
	avxMul2GBInline;           \ 
	VMOVDQU TW, (16*1)(SP); \ 
	avxMul2GBInline;           \
	VMOVDQU TW, (16*2)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*3)(SP); \
	avxMul2GBInline

#define avxPrepareGB8Tweaks \
	avxPrepareGB4Tweaks;       \
	VMOVDQU TW, (16*4)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*5)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*6)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*7)(SP); \
	avxMul2GBInline

#define avxPrepareGB16Tweaks \
	avxPrepareGB8Tweaks;       \
	VMOVDQU TW, (16*8)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*9)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*10)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*11)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*12)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*13)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*14)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*15)(SP); \
	avxMul2GBInline

#define mul2Inline        \
	PSHUFD $0xff, TW, T0; \
	MOVOU TW, T1;         \         
	PSRAL $31, T0;        \
	PAND POLY, T0;        \        
	PSRLL $31, T1;        \
	PSLLDQ $4, T1;        \
	PSLLL $1, TW;         \
	PXOR T0, TW;          \
	PXOR T1, TW

#define avxMul2Inline        \
	VPSHUFD $0xff, TW, T0; \
	VPSRLD $31, TW, T1;    \       
	VPSRAD $31, T0, T0;    \
	VPAND POLY, T0, T0;    \        
	VPSLLDQ $4, T1, T1;    \
	VPSLLD $1, TW, TW;     \
	VPXOR T0, TW, TW;      \
	VPXOR T1, TW, TW

#define prepare4Tweaks \
	MOVOU TW, (16*0)(SP); \
	mul2Inline;           \ 
	MOVOU TW, (16*1)(SP); \ 
	mul2Inline;           \
	MOVOU TW, (16*2)(SP); \
	mul2Inline;           \
	MOVOU TW, (16*3)(SP); \
	mul2Inline

#define prepare8Tweaks \
	prepare4Tweaks;       \
	MOVOU TW, (16*4)(SP); \
	mul2Inline;           \
	MOVOU TW, (16*5)(SP); \
	mul2Inline;           \
	MOVOU TW, (16*6)(SP); \
	mul2Inline;           \
	MOVOU TW, (16*7)(SP); \
	mul2Inline

#define avxPrepare4Tweaks \
	VMOVDQU TW, (16*0)(SP); \
	avxMul2Inline;           \ 
	VMOVDQU TW, (16*1)(SP); \ 
	avxMul2Inline;           \
	VMOVDQU TW, (16*2)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*3)(SP); \
	avxMul2Inline

#define avxPrepare8Tweaks \
	prepare4Tweaks;       \
	VMOVDQU TW, (16*4)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*5)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*6)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*7)(SP); \
	avxMul2Inline

#define avxPrepare16Tweaks \
	prepare8Tweaks;       \
	VMOVDQU TW, (16*8)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*9)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*10)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*11)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*12)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*13)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*14)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*15)(SP); \
	avxMul2Inline

#define sseLoad4Blocks \
	MOVOU (16*0)(DX), B0; \
	MOVOU (16*0)(SP), T0; \ 
	PXOR T0, B0; \
	MOVOU (16*1)(DX), B1; \
	MOVOU (16*1)(SP), T0; \
	PXOR T0, B1; \
	MOVOU (16*2)(DX), B2; \
	MOVOU (16*2)(SP), T0; \
	PXOR T0, B2; \
	MOVOU (16*3)(DX), B3; \
	MOVOU (16*3)(SP), T0; \
	PXOR T0, B3

#define sseStore4Blocks \
	MOVOU (16*0)(SP), T0; \
	PXOR T0, B0; \
	MOVOU B0, (16*0)(CX); \
	MOVOU (16*1)(SP), T0; \
	PXOR T0, B1; \
	MOVOU B1, (16*1)(CX); \
	MOVOU (16*2)(SP), T0; \
	PXOR T0, B2; \
	MOVOU B2, (16*2)(CX); \
	MOVOU (16*3)(SP), T0; \
	PXOR T0, B3; \
	MOVOU B3, (16*3)(CX)

#define sseLoad8Blocks \
	sseLoad4Blocks;  \
	MOVOU (16*4)(DX), B4;  \
	MOVOU (16*4)(SP), T0;  \ 
	PXOR T0, B4;           \
	MOVOU (16*5)(DX), B5;  \
	MOVOU (16*5)(SP), T0;  \ 
	PXOR T0, B5;           \
	MOVOU (16*6)(DX), B6;  \
	MOVOU (16*6)(SP), T0;  \ 
	PXOR T0, B6;           \
	MOVOU (16*7)(DX), B7;  \
	MOVOU (16*7)(SP), T0;  \
	PXOR T0, B7

#define sseStore8Blocks \
	sseStore4Blocks; \
	MOVOU (16*4)(SP), T0; \ 
	PXOR T0, B4; \
	MOVOU B4, (16*4)(CX); \
	MOVOU (16*5)(SP), T0; \
	PXOR T0, B5; \
	MOVOU B5, (16*5)(CX); \
	MOVOU (16*6)(SP), T0; \
	PXOR T0, B6; \
	MOVOU B6, (16*6)(CX); \
	MOVOU (16*7)(SP), T0; \
	PXOR T0, B7; \
	MOVOU B7, (16*7)(CX)

#define avxLoad4Blocks \
	VMOVDQU (16*0)(DX), B0; \
	VPXOR (16*0)(SP), B0, B0; \
	VMOVDQU (16*1)(DX), B1; \
	VPXOR (16*1)(SP), B1, B1; \
	VMOVDQU (16*2)(DX), B2; \
	VPXOR (16*2)(SP), B2, B2; \
	VMOVDQU (16*3)(DX), B3; \
	VPXOR (16*3)(SP), B3, B3

#define avxStore4Blocks \
	VPXOR (16*0)(SP), B0, B0; \
	VMOVDQU B0, (16*0)(CX); \
	VPXOR (16*1)(SP), B1, B1; \
	VMOVDQU B1, (16*1)(CX); \
	VPXOR (16*2)(SP), B2, B2; \
	VMOVDQU B2, (16*2)(CX); \
	VPXOR (16*3)(SP), B3, B3; \
	VMOVDQU B3, (16*3)(CX)

#define avxLoad8Blocks \
	avxLoad4Blocks; \
	VMOVDQU (16*4)(DX), B4; \
	VPXOR (16*4)(SP), B4, B4; \
	VMOVDQU (16*5)(DX), B5; \
	VPXOR (16*5)(SP), B5, B5; \
	VMOVDQU (16*6)(DX), B6; \
	VPXOR (16*6)(SP), B6, B6; \
	VMOVDQU (16*7)(DX), B7; \
	VPXOR (16*7)(SP), B7, B7

#define avxStore8Blocks \
	avxStore4Blocks; \
	VPXOR (16*4)(SP), B4, B4; \
	VMOVDQU B4, (16*4)(CX); \
	VPXOR (16*5)(SP), B5, B5; \
	VMOVDQU B5, (16*5)(CX); \
	VPXOR (16*6)(SP), B6, B6; \
	VMOVDQU B6, (16*6)(CX); \
	VPXOR (16*7)(SP), B7, B7; \
	VMOVDQU B7, (16*7)(CX)

#define avx2Load8Blocks \
	VMOVDQU (32*0)(DX), Y0; \
	VPXOR (32*0)(SP), Y0, Y0; \
	VMOVDQU (32*1)(DX), Y1; \
	VPXOR (32*1)(SP), Y1, Y1; \
	VMOVDQU (32*2)(DX), Y2; \
	VPXOR (32*2)(SP), Y2, Y2; \
	VMOVDQU (32*3)(DX), Y3; \
	VPXOR (32*3)(SP), Y3, Y3

#define avx2Load16Blocks \
	avx2Load8Blocks; \
	VMOVDQU (32*4)(DX), Y4; \
	VPXOR (32*4)(SP), Y4, Y4; \
	VMOVDQU (32*5)(DX), Y5; \
	VPXOR (32*5)(SP), Y5, Y5; \
	VMOVDQU (32*6)(DX), Y6; \
	VPXOR (32*6)(SP), Y6, Y6; \
	VMOVDQU (32*7)(DX), Y7; \
	VPXOR (32*7)(SP), Y7, Y7

#define avx2LE2BE8Blocks \
	VBROADCASTI128 flip_mask<>(SB), Y11; \
	VPSHUFB Y11, Y0, Y0; \
	VPSHUFB Y11, Y1, Y1; \
	VPSHUFB Y11, Y2, Y2; \
	VPSHUFB Y11, Y3, Y3; \

#define avx2LE2BE16Blocks \
	avx2LE2BE8Blocks; \
	VPSHUFB Y11, Y4, Y4; \
	VPSHUFB Y11, Y5, Y5; \
	VPSHUFB Y11, Y6, Y6; \
	VPSHUFB Y11, Y7, Y7

#define avx2Store8Blocks \
	VPXOR (32*0)(SP), Y0, Y0; \
	VMOVDQU Y0, (32*0)(CX); \
	VPXOR (32*1)(SP), Y1, Y1; \
	VMOVDQU Y1, (32*1)(CX); \
	VPXOR (32*2)(SP), Y2, Y2; \
	VMOVDQU Y2, (32*2)(CX); \
	VPXOR (32*3)(SP), Y3, Y3; \
	VMOVDQU Y3, (32*3)(CX); \

#define avx2Store16Blocks \
	avx2Store8Blocks; \
	VPXOR (32*4)(SP), Y4, Y4; \
	VMOVDQU Y4, (32*4)(CX); \
	VPXOR (32*5)(SP), Y5, Y5; \
	VMOVDQU Y5, (32*5)(CX); \
	VPXOR (32*6)(SP), Y6, Y6; \
	VMOVDQU Y6, (32*6)(CX); \
	VPXOR (32*7)(SP), Y7, Y7; \
	VMOVDQU Y7, (32*7)(CX)

#define avx2ByteSwap8Blocks \
	VPSHUFB DWBSWAP, Y0, Y0; \
	VPSHUFB DWBSWAP, Y1, Y1; \
	VPSHUFB DWBSWAP, Y2, Y2; \
	VPSHUFB DWBSWAP, Y3, Y3; \

#define avx2ByteSwap16Blocks \
	avx2ByteSwap8Blocks; \
  	VPSHUFB DWBSWAP, Y4, Y4; \
	VPSHUFB DWBSWAP, Y5, Y5; \
	VPSHUFB DWBSWAP, Y6, Y6; \
	VPSHUFB DWBSWAP, Y7, Y7

// func encryptSm4Xts(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)
TEXT ·encryptSm4Xts(SB),0,$256-64
	MOVQ xk+0(FP), AX
	MOVQ tweak+8(FP), BX
	MOVQ dst+16(FP), CX
	MOVQ src+40(FP), DX
	MOVQ src_len+48(FP), DI

	CMPB ·useAVX2(SB), $1
	JE   avx2XtsSm4Enc

	CMPB ·useAVX(SB), $1
	JE   avxXtsSm4Enc

	MOVOU gcmPoly<>(SB), POLY

	MOVOU (0*16)(BX), TW

xtsSm4EncOctets:
	CMPQ DI, $128
	JB xtsSm4EncNibbles
	SUBQ $128, DI

	// prepare tweaks
	prepare8Tweaks
	// load 8 blocks for encryption
	sseLoad8Blocks

	SM4_8BLOCKS(AX, X8, T0, T1, T2, B0, B1, B2, B3, B4, B5, B6, B7)

	sseStore8Blocks

	LEAQ 128(DX), DX
	LEAQ 128(CX), CX

	JMP xtsSm4EncOctets

xtsSm4EncNibbles:
	CMPQ DI, $64
	JB xtsSm4EncSingles
	SUBQ $64, DI

	// prepare tweaks
	prepare4Tweaks
	// load 4 blocks for encryption
	sseLoad4Blocks

	SM4_4BLOCKS(AX, B4, T0, T1, T2, B0, B1, B2, B3)

	sseStore4Blocks

	LEAQ 64(DX), DX
	LEAQ 64(CX), CX

xtsSm4EncSingles:
	CMPQ DI, $16
	JB xtsSm4EncTail
	SUBQ $16, DI

	// load 1 block for encryption
	MOVOU (16*0)(DX), B0
	
	PXOR TW, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	PXOR TW, B0
	MOVOU B0, (16*0)(CX)
	mul2Inline

	LEAQ 16(DX), DX
	LEAQ 16(CX), CX

	JMP xtsSm4EncSingles

xtsSm4EncTail:
	TESTQ DI, DI
	JE xtsSm4EncDone

	LEAQ -16(CX), R8
	MOVOU (16*0)(R8), B0
	MOVOU B0, (16*0)(SP)

	CMPQ DI, $8
	JB   loop_1b
	SUBQ  $8, DI
	MOVQ (DX)(DI*1), R9
	MOVQ (SP)(DI*1), R10
	MOVQ R9, (SP)(DI*1)
	MOVQ R10, (CX)(DI*1)

	TESTQ DI, DI
	JE xtsSm4EncTailEnc

loop_1b:
	SUBQ  $1, DI
	MOVB (DX)(DI*1), R9
	MOVB (SP)(DI*1), R10
	MOVB R9, (SP)(DI*1)
	MOVB R10, (CX)(DI*1)
	TESTQ DI, DI
	JNE   loop_1b

xtsSm4EncTailEnc:
	MOVOU (16*0)(SP), B0
	PXOR TW, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	PXOR TW, B0
	MOVOU B0, (16*0)(R8)

xtsSm4EncDone:
	MOVOU TW, (16*0)(BX)
	RET

avxXtsSm4Enc:
	VMOVDQU gcmPoly<>(SB), POLY
	VMOVDQU (0*16)(BX), TW

avxXtsSm4EncOctets:
	CMPQ DI, $128
	JB avxXtsSm4EncNibbles
	SUBQ $128, DI

	// prepare tweaks
	avxPrepare8Tweaks
	// load 8 blocks for encryption
	avxLoad8Blocks

	AVX_SM4_8BLOCKS(AX, X8, T0, T1, T2, B0, B1, B2, B3, B4, B5, B6, B7)

	avxStore8Blocks

	LEAQ 128(DX), DX
	LEAQ 128(CX), CX

	JMP avxXtsSm4EncOctets

avxXtsSm4EncNibbles:
	CMPQ DI, $64
	JB avxXtsSm4EncSingles
	SUBQ $64, DI

	// prepare tweaks
	avxPrepare4Tweaks
	// load 4 blocks for encryption
	avxLoad4Blocks

	AVX_SM4_4BLOCKS(AX, B4, T0, T1, T2, B0, B1, B2, B3)

	avxStore4Blocks

	LEAQ 64(DX), DX
	LEAQ 64(CX), CX

avxXtsSm4EncSingles:
	CMPQ DI, $16
	JB avxXtsSm4EncTail
	SUBQ $16, DI

	// load 1 block for encryption
	VMOVDQU (16*0)(DX), B0
	
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	avxMul2Inline

	LEAQ 16(DX), DX
	LEAQ 16(CX), CX

	JMP avxXtsSm4EncSingles

avxXtsSm4EncTail:
	TESTQ DI, DI
	JE avxXtsSm4EncDone

	LEAQ -16(CX), R8
	VMOVDQU (16*0)(R8), B0
	VMOVDQU B0, (16*0)(SP)

	CMPQ DI, $8
	JB   avx_loop_1b
	SUBQ  $8, DI
	MOVQ (DX)(DI*1), R9
	MOVQ (SP)(DI*1), R10
	MOVQ R9, (SP)(DI*1)
	MOVQ R10, (CX)(DI*1)

	TESTQ DI, DI
	JE avxXtsSm4EncTailEnc

avx_loop_1b:
	SUBQ  $1, DI
	MOVB (DX)(DI*1), R9
	MOVB (SP)(DI*1), R10
	MOVB R9, (SP)(DI*1)
	MOVB R10, (CX)(DI*1)
	TESTQ DI, DI
	JNE   avx_loop_1b

avxXtsSm4EncTailEnc:
	VMOVDQU (16*0)(SP), B0
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(R8)

avxXtsSm4EncDone:
	VMOVDQU TW, (16*0)(BX)
	RET

avx2XtsSm4Enc:
	VMOVDQU gcmPoly<>(SB), POLY
	VMOVDQU (0*16)(BX), TW
	VBROADCASTI128 nibble_mask<>(SB), NIBBLE_MASK
	VBROADCASTI128 bswap_mask<>(SB), DWBSWAP

avx2XtsSm4Enc16Blocks:
	CMPQ DI, $256
	JB avx2XtsSm4EncOctets
	SUBQ $256, DI

	// prepare tweaks
	avxPrepare16Tweaks
	// load 16 blocks for encryption
	avx2Load16Blocks
	// Apply Byte Flip Mask: LE -> BE
	avx2LE2BE16Blocks
	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)
	TRANSPOSE_MATRIX(Y4, Y5, Y6, Y7, Y8, Y9)

	AVX2_SM4_16BLOCKS(AX, Y8, Y9, X8, X9, Y11, Y12, Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7)

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)
	TRANSPOSE_MATRIX(Y4, Y5, Y6, Y7, Y8, Y9)
	avx2ByteSwap16Blocks
	avx2Store16Blocks

	LEAQ 256(DX), DX
	LEAQ 256(CX), CX
	JMP avx2XtsSm4Enc16Blocks

avx2XtsSm4EncOctets:
	CMPQ DI, $128
	JB avx2XtsSm4EncNibbles
	SUBQ $128, DI

	// prepare tweaks
	avxPrepare8Tweaks
	// load 8 blocks for encryption
	avx2Load8Blocks
	// Apply Byte Flip Mask: LE -> BE
	avx2LE2BE8Blocks
	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)

	AVX2_SM4_8BLOCKS(AX, Y8, Y9, X8, X9, Y7, Y0, Y1, Y2, Y3)

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)
	avx2ByteSwap8Blocks
	avx2Store8Blocks

	LEAQ 128(DX), DX
	LEAQ 128(CX), CX

avx2XtsSm4EncNibbles:
	CMPQ DI, $64
	JB avx2XtsSm4EncSingles
	SUBQ $64, DI

	// prepare tweaks
	avxPrepare4Tweaks

	// load 4 blocks for encryption
	avxLoad4Blocks

	AVX_SM4_4BLOCKS(AX, B4, T0, T1, T2, B0, B1, B2, B3)

	avxStore4Blocks

	LEAQ 64(DX), DX
	LEAQ 64(CX), CX

avx2XtsSm4EncSingles:
	CMPQ DI, $16
	JB avx2XtsSm4EncTail
	SUBQ $16, DI

	// load 1 block for encryption
	VMOVDQU (16*0)(DX), B0
	
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	avxMul2Inline

	LEAQ 16(DX), DX
	LEAQ 16(CX), CX

	JMP avx2XtsSm4EncSingles

avx2XtsSm4EncTail:
	TESTQ DI, DI
	JE avx2XtsSm4EncDone

	LEAQ -16(CX), R8
	VMOVDQU (16*0)(R8), B0
	VMOVDQU B0, (16*0)(SP)

	CMPQ DI, $8
	JB   avx2_loop_1b
	SUBQ  $8, DI
	MOVQ (DX)(DI*1), R9
	MOVQ (SP)(DI*1), R10
	MOVQ R9, (SP)(DI*1)
	MOVQ R10, (CX)(DI*1)

	TESTQ DI, DI
	JE avx2XtsSm4EncTailEnc

avx2_loop_1b:
	SUBQ  $1, DI
	MOVB (DX)(DI*1), R9
	MOVB (SP)(DI*1), R10
	MOVB R9, (SP)(DI*1)
	MOVB R10, (CX)(DI*1)
	TESTQ DI, DI
	JNE   avx2_loop_1b

avx2XtsSm4EncTailEnc:
	VMOVDQU (16*0)(SP), B0
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(R8)

avx2XtsSm4EncDone:
	VMOVDQU TW, (16*0)(BX)
	VZEROUPPER
	RET

// func encryptSm4XtsGB(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)
TEXT ·encryptSm4XtsGB(SB),0,$256-64
	MOVQ xk+0(FP), AX
	MOVQ tweak+8(FP), BX
	MOVQ dst+16(FP), CX
	MOVQ src+40(FP), DX
	MOVQ src_len+48(FP), DI

	CMPB ·useAVX2(SB), $1
	JE   avx2XtsSm4Enc

	CMPB ·useAVX(SB), $1
	JE   avxXtsSm4Enc

	MOVOU gbGcmPoly<>(SB), POLY
	MOVOU bswap_mask<>(SB), BSWAP
	MOVOU (0*16)(BX), TW

xtsSm4EncOctets:
	CMPQ DI, $128
	JB xtsSm4EncNibbles
	SUBQ $128, DI

	// prepare tweaks
	prepareGB8Tweaks
	// load 8 blocks for encryption
	sseLoad8Blocks

	SM4_8BLOCKS(AX, X8, T0, T1, T2, B0, B1, B2, B3, B4, B5, B6, B7)

	sseStore8Blocks

	LEAQ 128(DX), DX
	LEAQ 128(CX), CX

	JMP xtsSm4EncOctets

xtsSm4EncNibbles:
	CMPQ DI, $64
	JB xtsSm4EncSingles
	SUBQ $64, DI

	// prepare tweaks
	prepareGB4Tweaks
	// load 4 blocks for encryption
	sseLoad4Blocks

	SM4_4BLOCKS(AX, B4, T0, T1, T2, B0, B1, B2, B3)

	sseStore4Blocks

	LEAQ 64(DX), DX
	LEAQ 64(CX), CX

xtsSm4EncSingles:
	CMPQ DI, $16
	JB xtsSm4EncTail
	SUBQ $16, DI

	// load 1 block for encryption
	MOVOU (16*0)(DX), B0
	
	PXOR TW, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	PXOR TW, B0
	MOVOU B0, (16*0)(CX)
	mul2GBInline

	LEAQ 16(DX), DX
	LEAQ 16(CX), CX

	JMP xtsSm4EncSingles

xtsSm4EncTail:
	TESTQ DI, DI
	JE xtsSm4EncDone

	LEAQ -16(CX), R8
	MOVOU (16*0)(R8), B0
	MOVOU B0, (16*0)(SP)

	CMPQ DI, $8
	JB   loop_1b
	SUBQ  $8, DI
	MOVQ (DX)(DI*1), R9
	MOVQ (SP)(DI*1), R10
	MOVQ R9, (SP)(DI*1)
	MOVQ R10, (CX)(DI*1)

	TESTQ DI, DI
	JE xtsSm4EncTailEnc

loop_1b:
	SUBQ  $1, DI
	MOVB (DX)(DI*1), R9
	MOVB (SP)(DI*1), R10
	MOVB R9, (SP)(DI*1)
	MOVB R10, (CX)(DI*1)
	TESTQ DI, DI
	JNE   loop_1b

xtsSm4EncTailEnc:
	MOVOU (16*0)(SP), B0
	PXOR TW, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	PXOR TW, B0
	MOVOU B0, (16*0)(R8)

xtsSm4EncDone:
	MOVOU TW, (16*0)(BX)
	RET

avxXtsSm4Enc:
	VMOVDQU gbGcmPoly<>(SB), POLY
	VMOVDQU bswap_mask<>(SB), BSWAP
	VMOVDQU (0*16)(BX), TW

avxXtsSm4EncOctets:
	CMPQ DI, $128
	JB avxXtsSm4EncNibbles
	SUBQ $128, DI

	// prepare tweaks
	avxPrepareGB8Tweaks
	// load 8 blocks for encryption
	avxLoad8Blocks

	AVX_SM4_8BLOCKS(AX, X8, T0, T1, T2, B0, B1, B2, B3, B4, B5, B6, B7)

	avxStore8Blocks

	LEAQ 128(DX), DX
	LEAQ 128(CX), CX

	JMP avxXtsSm4EncOctets

avxXtsSm4EncNibbles:
	CMPQ DI, $64
	JB avxXtsSm4EncSingles
	SUBQ $64, DI

	// prepare tweaks
	avxPrepareGB4Tweaks
	// load 4 blocks for encryption
	avxLoad4Blocks

	AVX_SM4_4BLOCKS(AX, B4, T0, T1, T2, B0, B1, B2, B3)

	avxStore4Blocks

	LEAQ 64(DX), DX
	LEAQ 64(CX), CX

avxXtsSm4EncSingles:
	CMPQ DI, $16
	JB avxXtsSm4EncTail
	SUBQ $16, DI

	// load 1 block for encryption
	VMOVDQU (16*0)(DX), B0
	
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	avxMul2GBInline

	LEAQ 16(DX), DX
	LEAQ 16(CX), CX

	JMP avxXtsSm4EncSingles

avxXtsSm4EncTail:
	TESTQ DI, DI
	JE avxXtsSm4EncDone

	LEAQ -16(CX), R8
	VMOVDQU (16*0)(R8), B0
	VMOVDQU B0, (16*0)(SP)

	CMPQ DI, $8
	JB   avx_loop_1b
	SUBQ  $8, DI
	MOVQ (DX)(DI*1), R9
	MOVQ (SP)(DI*1), R10
	MOVQ R9, (SP)(DI*1)
	MOVQ R10, (CX)(DI*1)

	TESTQ DI, DI
	JE avxXtsSm4EncTailEnc

avx_loop_1b:
	SUBQ  $1, DI
	MOVB (DX)(DI*1), R9
	MOVB (SP)(DI*1), R10
	MOVB R9, (SP)(DI*1)
	MOVB R10, (CX)(DI*1)
	TESTQ DI, DI
	JNE   avx_loop_1b

avxXtsSm4EncTailEnc:
	VMOVDQU (16*0)(SP), B0
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(R8)

avxXtsSm4EncDone:
	VMOVDQU TW, (16*0)(BX)
	RET

avx2XtsSm4Enc:
	VMOVDQU gbGcmPoly<>(SB), POLY
	VMOVDQU (0*16)(BX), TW
	VBROADCASTI128 nibble_mask<>(SB), NIBBLE_MASK
	VBROADCASTI128 bswap_mask<>(SB), DWBSWAP

avx2XtsSm4Enc16Blocks:
	CMPQ DI, $256
	JB avx2XtsSm4EncOctets
	SUBQ $256, DI

	// prepare tweaks
	avxPrepareGB16Tweaks
	// load 16 blocks for encryption
	avx2Load16Blocks
	// Apply Byte Flip Mask: LE -> BE
	avx2LE2BE16Blocks
	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)
	TRANSPOSE_MATRIX(Y4, Y5, Y6, Y7, Y8, Y9)

	AVX2_SM4_16BLOCKS(AX, Y8, Y9, X8, X9, Y11, Y12, Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7)

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)
	TRANSPOSE_MATRIX(Y4, Y5, Y6, Y7, Y8, Y9)
	avx2ByteSwap16Blocks
	avx2Store16Blocks

	LEAQ 256(DX), DX
	LEAQ 256(CX), CX
	JMP avx2XtsSm4Enc16Blocks

avx2XtsSm4EncOctets:
	CMPQ DI, $128
	JB avx2XtsSm4EncNibbles
	SUBQ $128, DI

	// prepare tweaks
	avxPrepareGB8Tweaks
	// load 8 blocks for encryption
	avx2Load8Blocks
	// Apply Byte Flip Mask: LE -> BE
	avx2LE2BE8Blocks
	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)

	AVX2_SM4_8BLOCKS(AX, Y8, Y9, X8, X9, Y7, Y0, Y1, Y2, Y3)

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)
	avx2ByteSwap8Blocks
	avx2Store8Blocks

	LEAQ 128(DX), DX
	LEAQ 128(CX), CX

avx2XtsSm4EncNibbles:
	CMPQ DI, $64
	JB avx2XtsSm4EncSingles
	SUBQ $64, DI

	// prepare tweaks
	avxPrepareGB4Tweaks
	// load 4 blocks for encryption
	avxLoad4Blocks

	AVX_SM4_4BLOCKS(AX, B4, T0, T1, T2, B0, B1, B2, B3)

	avxStore4Blocks

	LEAQ 64(DX), DX
	LEAQ 64(CX), CX

avx2XtsSm4EncSingles:
	CMPQ DI, $16
	JB avx2XtsSm4EncTail
	SUBQ $16, DI

	// load 1 block for encryption
	VMOVDQU (16*0)(DX), B0
	
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	avxMul2GBInline

	LEAQ 16(DX), DX
	LEAQ 16(CX), CX

	JMP avx2XtsSm4EncSingles

avx2XtsSm4EncTail:
	TESTQ DI, DI
	JE avx2XtsSm4EncDone

	LEAQ -16(CX), R8
	VMOVDQU (16*0)(R8), B0
	VMOVDQU B0, (16*0)(SP)

	CMPQ DI, $8
	JB   avx2_loop_1b
	SUBQ  $8, DI
	MOVQ (DX)(DI*1), R9
	MOVQ (SP)(DI*1), R10
	MOVQ R9, (SP)(DI*1)
	MOVQ R10, (CX)(DI*1)

	TESTQ DI, DI
	JE avx2XtsSm4EncTailEnc

avx2_loop_1b:
	SUBQ  $1, DI
	MOVB (DX)(DI*1), R9
	MOVB (SP)(DI*1), R10
	MOVB R9, (SP)(DI*1)
	MOVB R10, (CX)(DI*1)
	TESTQ DI, DI
	JNE   avx2_loop_1b

avx2XtsSm4EncTailEnc:
	VMOVDQU (16*0)(SP), B0
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(R8)

avx2XtsSm4EncDone:
	VMOVDQU TW, (16*0)(BX)
	VZEROUPPER
	RET

// func decryptSm4Xts(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)
TEXT ·decryptSm4Xts(SB),0,$256-64
	MOVQ xk+0(FP), AX
	MOVQ tweak+8(FP), BX
	MOVQ dst+16(FP), CX
	MOVQ src+40(FP), DX
	MOVQ src_len+48(FP), DI

	CMPB ·useAVX2(SB), $1
	JE   avx2XtsSm4Dec

	CMPB ·useAVX(SB), $1
	JE   avxXtsSm4Dec

	MOVOU gcmPoly<>(SB), POLY
	MOVOU (0*16)(BX), TW

xtsSm4DecOctets:
	CMPQ DI, $128
	JB xtsSm4DecNibbles
	SUBQ $128, DI

	// prepare tweaks
	prepare8Tweaks
	// load 8 blocks for decryption
	sseLoad8Blocks

	SM4_8BLOCKS(AX, X8, T0, T1, T2, B0, B1, B2, B3, B4, B5, B6, B7)

	sseStore8Blocks

	LEAQ 128(DX), DX
	LEAQ 128(CX), CX

	JMP xtsSm4DecOctets

xtsSm4DecNibbles:
	CMPQ DI, $64
	JB xtsSm4DecSingles
	SUBQ $64, DI

	// prepare tweaks
	prepare4Tweaks
	// load 4 blocks for decryption
	sseLoad4Blocks

	SM4_4BLOCKS(AX, B4, T0, T1, T2, B0, B1, B2, B3)

	sseStore4Blocks

	LEAQ 64(DX), DX
	LEAQ 64(CX), CX

xtsSm4DecSingles:
	CMPQ DI, $32
	JB xtsSm4DecTail
	SUBQ $16, DI

	// load 1 block for decryption
	MOVOU (16*0)(DX), B0
	
	PXOR TW, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	PXOR TW, B0
	MOVOU B0, (16*0)(CX)
	mul2Inline

	LEAQ 16(DX), DX
	LEAQ 16(CX), CX

	JMP xtsSm4DecSingles

xtsSm4DecTail:
	TESTQ DI, DI
	JE xtsSm4DecDone

	CMPQ DI, $16
	JE xtsSm4DecLastBlock

	// length > 16
	// load 1 block for decryption
	MOVOU (16*0)(DX), B0
	MOVOU TW, B5
	mul2Inline
	PXOR TW, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	PXOR TW, B0
	MOVOU B0, (16*0)(CX)
	MOVOU B5, TW

	SUBQ $16, DI
	LEAQ 16(DX), DX
	LEAQ 16(CX), CX
	LEAQ -16(CX), R8
	MOVOU B0, (16*0)(SP)

	CMPQ DI, $8
	JB   loop_1b
	SUBQ  $8, DI
	MOVQ (DX)(DI*1), R9
	MOVQ (SP)(DI*1), R10
	MOVQ R9, (SP)(DI*1)
	MOVQ R10, (CX)(DI*1)

	TESTQ DI, DI
	JE xtsSm4DecTailDec

loop_1b:
	SUBQ  $1, DI
	MOVB (DX)(DI*1), R9
	MOVB (SP)(DI*1), R10
	MOVB R9, (SP)(DI*1)
	MOVB R10, (CX)(DI*1)
	TESTQ DI, DI
	JNE   loop_1b

xtsSm4DecTailDec:
	MOVOU (16*0)(SP), B0
	PXOR TW, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	PXOR TW, B0
	MOVOU B0, (16*0)(R8)
	JMP xtsSm4DecDone

xtsSm4DecLastBlock:
	MOVOU (16*0)(DX), B0
	PXOR TW, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	PXOR TW, B0
	MOVOU B0, (16*0)(CX)
	mul2Inline

xtsSm4DecDone:
	MOVOU TW, (16*0)(BX)
	RET

avxXtsSm4Dec:
	VMOVDQU gcmPoly<>(SB), POLY
	VMOVDQU (0*16)(BX), TW

avxXtsSm4DecOctets:
	CMPQ DI, $128
	JB avxXtsSm4DecNibbles
	SUBQ $128, DI

	// prepare tweaks
	avxPrepare8Tweaks

	// load 8 blocks for decryption
	avxLoad8Blocks

	AVX_SM4_8BLOCKS(AX, X8, T0, T1, T2, B0, B1, B2, B3, B4, B5, B6, B7)

	avxStore8Blocks

	LEAQ 128(DX), DX
	LEAQ 128(CX), CX

	JMP avxXtsSm4DecOctets

avxXtsSm4DecNibbles:
	CMPQ DI, $64
	JB avxXtsSm4DecSingles
	SUBQ $64, DI

	// prepare tweaks
	avxPrepare4Tweaks
	// load 4 blocks for decryption
	avxLoad4Blocks

	AVX_SM4_4BLOCKS(AX, B4, T0, T1, T2, B0, B1, B2, B3)

	avxStore4Blocks

	LEAQ 64(DX), DX
	LEAQ 64(CX), CX

avxXtsSm4DecSingles:
	CMPQ DI, $32
	JB avxXtsSm4DecTail
	SUBQ $16, DI

	// load 1 block for decryption
	VMOVDQU (16*0)(DX), B0
	
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	avxMul2Inline

	LEAQ 16(DX), DX
	LEAQ 16(CX), CX

	JMP avxXtsSm4DecSingles

avxXtsSm4DecTail:
	TESTQ DI, DI
	JE avxXtsSm4DecDone

	CMPQ DI, $16
	JE avxXtsSm4DecLastBlock

	// length > 16
	// load 1 block for decryption
	VMOVDQU (16*0)(DX), B0
	VMOVDQU TW, B5
	avxMul2Inline
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	VMOVDQU B5, TW

	SUBQ $16, DI
	LEAQ 16(DX), DX
	LEAQ 16(CX), CX
	LEAQ -16(CX), R8
	VMOVDQU B0, (16*0)(SP)

	CMPQ DI, $8
	JB   avx_loop_1b
	SUBQ  $8, DI
	MOVQ (DX)(DI*1), R9
	MOVQ (SP)(DI*1), R10
	MOVQ R9, (SP)(DI*1)
	MOVQ R10, (CX)(DI*1)

	TESTQ DI, DI
	JE avxXtsSm4DecTailDec

avx_loop_1b:
	SUBQ  $1, DI
	MOVB (DX)(DI*1), R9
	MOVB (SP)(DI*1), R10
	MOVB R9, (SP)(DI*1)
	MOVB R10, (CX)(DI*1)
	TESTQ DI, DI
	JNE   avx_loop_1b

avxXtsSm4DecTailDec:
	VMOVDQU (16*0)(SP), B0
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(R8)
	JMP avxXtsSm4DecDone

avxXtsSm4DecLastBlock:
	VMOVDQU (16*0)(DX), B0
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	avxMul2Inline

avxXtsSm4DecDone:
	VMOVDQU TW, (16*0)(BX)
	RET

avx2XtsSm4Dec:
	VMOVDQU gcmPoly<>(SB), POLY
	VMOVDQU (0*16)(BX), TW
	VBROADCASTI128 nibble_mask<>(SB), NIBBLE_MASK
	VBROADCASTI128 bswap_mask<>(SB), DWBSWAP

avx2XtsSm4Dec16Blocks:
	CMPQ DI, $256
	JB avx2XtsSm4DecOctets
	SUBQ $256, DI

	// prepare tweaks
	avxPrepare16Tweaks
	// load 16 blocks for encryption
	avx2Load16Blocks
	// Apply Byte Flip Mask: LE -> BE
	avx2LE2BE16Blocks
	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)
	TRANSPOSE_MATRIX(Y4, Y5, Y6, Y7, Y8, Y9)

	AVX2_SM4_16BLOCKS(AX, Y8, Y9, X8, X9, Y11, Y12, Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7)

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)
	TRANSPOSE_MATRIX(Y4, Y5, Y6, Y7, Y8, Y9)
	avx2ByteSwap16Blocks
	avx2Store16Blocks

	LEAQ 256(DX), DX
	LEAQ 256(CX), CX

	JMP avx2XtsSm4Dec16Blocks

avx2XtsSm4DecOctets:
	CMPQ DI, $128
	JB avx2XtsSm4DecNibbles
	SUBQ $128, DI

	// prepare tweaks
	avxPrepare8Tweaks
	// load 8 blocks for encryption
	avx2Load8Blocks
	// Apply Byte Flip Mask: LE -> BE
	avx2LE2BE8Blocks
	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)

	AVX2_SM4_8BLOCKS(AX, Y8, Y9, X8, X9, Y7, Y0, Y1, Y2, Y3)

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)
	avx2ByteSwap8Blocks
	avx2Store8Blocks

	LEAQ 128(DX), DX
	LEAQ 128(CX), CX

avx2XtsSm4DecNibbles:
	CMPQ DI, $64
	JB avxXtsSm4DecSingles
	SUBQ $64, DI

	// prepare tweaks
	avxPrepare4Tweaks
	// load 4 blocks for decryption
	avxLoad4Blocks

	AVX_SM4_4BLOCKS(AX, B4, T0, T1, T2, B0, B1, B2, B3)

	avxStore4Blocks

	LEAQ 64(DX), DX
	LEAQ 64(CX), CX

avx2XtsSm4DecSingles:
	CMPQ DI, $32
	JB avx2XtsSm4DecTail
	SUBQ $16, DI

	// load 1 block for decryption
	VMOVDQU (16*0)(DX), B0
	
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	avxMul2Inline

	LEAQ 16(DX), DX
	LEAQ 16(CX), CX

	JMP avx2XtsSm4DecSingles

avx2XtsSm4DecTail:
	TESTQ DI, DI
	JE avx2XtsSm4DecDone

	CMPQ DI, $16
	JE avx2XtsSm4DecLastBlock

	// length > 16
	// load 1 block for decryption
	VMOVDQU (16*0)(DX), B0
	VMOVDQU TW, B5
	avxMul2Inline
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	VMOVDQU B5, TW

	SUBQ $16, DI
	LEAQ 16(DX), DX
	LEAQ 16(CX), CX
	LEAQ -16(CX), R8
	VMOVDQU B0, (16*0)(SP)

	CMPQ DI, $8
	JB   avx2_loop_1b
	SUBQ  $8, DI
	MOVQ (DX)(DI*1), R9
	MOVQ (SP)(DI*1), R10
	MOVQ R9, (SP)(DI*1)
	MOVQ R10, (CX)(DI*1)

	TESTQ DI, DI
	JE avx2XtsSm4DecTailDec

avx2_loop_1b:
	SUBQ  $1, DI
	MOVB (DX)(DI*1), R9
	MOVB (SP)(DI*1), R10
	MOVB R9, (SP)(DI*1)
	MOVB R10, (CX)(DI*1)
	TESTQ DI, DI
	JNE   avx2_loop_1b

avx2XtsSm4DecTailDec:
	VMOVDQU (16*0)(SP), B0
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(R8)
	JMP avx2XtsSm4DecDone

avx2XtsSm4DecLastBlock:
	VMOVDQU (16*0)(DX), B0
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	avxMul2Inline

avx2XtsSm4DecDone:
	VMOVDQU TW, (16*0)(BX)
	VZEROUPPER
	RET

// func decryptSm4XtsGB(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)
TEXT ·decryptSm4XtsGB(SB),0,$256-64
	MOVQ xk+0(FP), AX
	MOVQ tweak+8(FP), BX
	MOVQ dst+16(FP), CX
	MOVQ src+40(FP), DX
	MOVQ src_len+48(FP), DI

	CMPB ·useAVX2(SB), $1
	JE   avx2XtsSm4Dec

	CMPB ·useAVX(SB), $1
	JE   avxXtsSm4Dec

	MOVOU gbGcmPoly<>(SB), POLY
	MOVOU bswap_mask<>(SB), BSWAP
	MOVOU (0*16)(BX), TW

xtsSm4DecOctets:
	CMPQ DI, $128
	JB xtsSm4DecNibbles
	SUBQ $128, DI

	// prepare tweaks
	prepareGB8Tweaks
	// load 8 blocks for decryption
	sseLoad8Blocks

	SM4_8BLOCKS(AX, X8, T0, T1, T2, B0, B1, B2, B3, B4, B5, B6, B7)

	sseStore8Blocks

	LEAQ 128(DX), DX
	LEAQ 128(CX), CX

	JMP xtsSm4DecOctets

xtsSm4DecNibbles:
	CMPQ DI, $64
	JB xtsSm4DecSingles
	SUBQ $64, DI

	// prepare tweaks
	prepareGB4Tweaks
	// load 4 blocks for decryption
	sseLoad4Blocks

	SM4_4BLOCKS(AX, B4, T0, T1, T2, B0, B1, B2, B3)

	sseStore4Blocks

	LEAQ 64(DX), DX
	LEAQ 64(CX), CX

xtsSm4DecSingles:
	CMPQ DI, $32
	JB xtsSm4DecTail
	SUBQ $16, DI

	// load 1 block for decryption
	MOVOU (16*0)(DX), B0
	
	PXOR TW, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	PXOR TW, B0
	MOVOU B0, (16*0)(CX)
	mul2GBInline

	LEAQ 16(DX), DX
	LEAQ 16(CX), CX

	JMP xtsSm4DecSingles

xtsSm4DecTail:
	TESTQ DI, DI
	JE xtsSm4DecDone

	CMPQ DI, $16
	JE xtsSm4DecLastBlock

	// length > 16
	// load 1 block for decryption
	MOVOU (16*0)(DX), B0
	MOVOU TW, B5
	mul2GBInline
	PXOR TW, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	PXOR TW, B0
	MOVOU B0, (16*0)(CX)
	MOVOU B5, TW

	SUBQ $16, DI
	LEAQ 16(DX), DX
	LEAQ 16(CX), CX
	LEAQ -16(CX), R8
	MOVOU B0, (16*0)(SP)

	CMPQ DI, $8
	JB   loop_1b
	SUBQ  $8, DI
	MOVQ (DX)(DI*1), R9
	MOVQ (SP)(DI*1), R10
	MOVQ R9, (SP)(DI*1)
	MOVQ R10, (CX)(DI*1)

	TESTQ DI, DI
	JE xtsSm4DecTailDec

loop_1b:
	SUBQ  $1, DI
	MOVB (DX)(DI*1), R9
	MOVB (SP)(DI*1), R10
	MOVB R9, (SP)(DI*1)
	MOVB R10, (CX)(DI*1)
	TESTQ DI, DI
	JNE   loop_1b

xtsSm4DecTailDec:
	MOVOU (16*0)(SP), B0
	PXOR TW, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	PXOR TW, B0
	MOVOU B0, (16*0)(R8)
	JMP xtsSm4DecDone

xtsSm4DecLastBlock:
	MOVOU (16*0)(DX), B0
	PXOR TW, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	PXOR TW, B0
	MOVOU B0, (16*0)(CX)
	mul2GBInline

xtsSm4DecDone:
	MOVOU TW, (16*0)(BX)
	RET

avxXtsSm4Dec:
	VMOVDQU gbGcmPoly<>(SB), POLY
	VMOVDQU bswap_mask<>(SB), BSWAP	
	VMOVDQU (0*16)(BX), TW

avxXtsSm4DecOctets:
	CMPQ DI, $128
	JB avxXtsSm4DecNibbles
	SUBQ $128, DI

	// prepare tweaks
	avxPrepareGB8Tweaks
	// load 8 blocks for decryption
	avxLoad8Blocks

	AVX_SM4_8BLOCKS(AX, X8, T0, T1, T2, B0, B1, B2, B3, B4, B5, B6, B7)

	avxStore8Blocks

	LEAQ 128(DX), DX
	LEAQ 128(CX), CX

	JMP avxXtsSm4DecOctets

avxXtsSm4DecNibbles:
	CMPQ DI, $64
	JB avxXtsSm4DecSingles
	SUBQ $64, DI

	// prepare tweaks
	avxPrepareGB4Tweaks
	// load 4 blocks for decryption
	avxLoad4Blocks

	AVX_SM4_4BLOCKS(AX, B4, T0, T1, T2, B0, B1, B2, B3)

	avxStore4Blocks

	LEAQ 64(DX), DX
	LEAQ 64(CX), CX

avxXtsSm4DecSingles:
	CMPQ DI, $32
	JB avxXtsSm4DecTail
	SUBQ $16, DI

	// load 1 block for decryption
	VMOVDQU (16*0)(DX), B0
	
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	avxMul2GBInline

	LEAQ 16(DX), DX
	LEAQ 16(CX), CX

	JMP avxXtsSm4DecSingles

avxXtsSm4DecTail:
	TESTQ DI, DI
	JE avxXtsSm4DecDone

	CMPQ DI, $16
	JE avxXtsSm4DecLastBlock

	// length > 16
	// load 1 block for decryption
	VMOVDQU (16*0)(DX), B0
	VMOVDQU TW, B5
	avxMul2GBInline
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	VMOVDQU B5, TW

	SUBQ $16, DI
	LEAQ 16(DX), DX
	LEAQ 16(CX), CX
	LEAQ -16(CX), R8
	VMOVDQU B0, (16*0)(SP)

	CMPQ DI, $8
	JB   avx_loop_1b
	SUBQ  $8, DI
	MOVQ (DX)(DI*1), R9
	MOVQ (SP)(DI*1), R10
	MOVQ R9, (SP)(DI*1)
	MOVQ R10, (CX)(DI*1)

	TESTQ DI, DI
	JE avxXtsSm4DecTailDec

avx_loop_1b:
	SUBQ  $1, DI
	MOVB (DX)(DI*1), R9
	MOVB (SP)(DI*1), R10
	MOVB R9, (SP)(DI*1)
	MOVB R10, (CX)(DI*1)
	TESTQ DI, DI
	JNE   avx_loop_1b

avxXtsSm4DecTailDec:
	VMOVDQU (16*0)(SP), B0
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(R8)
	JMP avxXtsSm4DecDone

avxXtsSm4DecLastBlock:
	VMOVDQU (16*0)(DX), B0
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	avxMul2GBInline

avxXtsSm4DecDone:
	VMOVDQU TW, (16*0)(BX)
	RET

avx2XtsSm4Dec:
	VMOVDQU gbGcmPoly<>(SB), POLY
	VMOVDQU (0*16)(BX), TW
	VBROADCASTI128 nibble_mask<>(SB), NIBBLE_MASK
	VBROADCASTI128 bswap_mask<>(SB), DWBSWAP

avx2XtsSm4Dec16Blocks:
	CMPQ DI, $256
	JB avx2XtsSm4DecOctets
	SUBQ $256, DI

	// prepare tweaks
	avxPrepareGB16Tweaks
	// load 16 blocks for encryption
	avx2Load16Blocks
	// Apply Byte Flip Mask: LE -> BE
	avx2LE2BE16Blocks
	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)
	TRANSPOSE_MATRIX(Y4, Y5, Y6, Y7, Y8, Y9)

	AVX2_SM4_16BLOCKS(AX, Y8, Y9, X8, X9, Y11, Y12, Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7)

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)
	TRANSPOSE_MATRIX(Y4, Y5, Y6, Y7, Y8, Y9)
	avx2ByteSwap16Blocks
	avx2Store16Blocks

	LEAQ 256(DX), DX
	LEAQ 256(CX), CX

	JMP avx2XtsSm4Dec16Blocks

avx2XtsSm4DecOctets:
	CMPQ DI, $128
	JB avx2XtsSm4DecNibbles
	SUBQ $128, DI

	// prepare tweaks
	avxPrepareGB8Tweaks
	// load 8 blocks for encryption
	avx2Load8Blocks
	// Apply Byte Flip Mask: LE -> BE
	avx2LE2BE8Blocks
	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)

	AVX2_SM4_8BLOCKS(AX, Y8, Y9, X8, X9, Y7, Y0, Y1, Y2, Y3)

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(Y0, Y1, Y2, Y3, Y8, Y9)
	avx2ByteSwap8Blocks
	avx2Store8Blocks

	LEAQ 128(DX), DX
	LEAQ 128(CX), CX

avx2XtsSm4DecNibbles:
	CMPQ DI, $64
	JB avxXtsSm4DecSingles
	SUBQ $64, DI

	// prepare tweaks
	avxPrepareGB4Tweaks
	// load 4 blocks for decryption
	avxLoad4Blocks

	AVX_SM4_4BLOCKS(AX, B4, T0, T1, T2, B0, B1, B2, B3)

	avxStore4Blocks

	LEAQ 64(DX), DX
	LEAQ 64(CX), CX

avx2XtsSm4DecSingles:
	CMPQ DI, $32
	JB avx2XtsSm4DecTail
	SUBQ $16, DI

	// load 1 block for decryption
	VMOVDQU (16*0)(DX), B0
	
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	avxMul2Inline

	LEAQ 16(DX), DX
	LEAQ 16(CX), CX

	JMP avx2XtsSm4DecSingles

avx2XtsSm4DecTail:
	TESTQ DI, DI
	JE avx2XtsSm4DecDone

	CMPQ DI, $16
	JE avx2XtsSm4DecLastBlock

	// length > 16
	// load 1 block for decryption
	VMOVDQU (16*0)(DX), B0
	VMOVDQU TW, B5
	avxMul2GBInline
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	VMOVDQU B5, TW

	SUBQ $16, DI
	LEAQ 16(DX), DX
	LEAQ 16(CX), CX
	LEAQ -16(CX), R8
	VMOVDQU B0, (16*0)(SP)

	CMPQ DI, $8
	JB   avx2_loop_1b
	SUBQ  $8, DI
	MOVQ (DX)(DI*1), R9
	MOVQ (SP)(DI*1), R10
	MOVQ R9, (SP)(DI*1)
	MOVQ R10, (CX)(DI*1)

	TESTQ DI, DI
	JE avx2XtsSm4DecTailDec

avx2_loop_1b:
	SUBQ  $1, DI
	MOVB (DX)(DI*1), R9
	MOVB (SP)(DI*1), R10
	MOVB R9, (SP)(DI*1)
	MOVB R10, (CX)(DI*1)
	TESTQ DI, DI
	JNE   avx2_loop_1b

avx2XtsSm4DecTailDec:
	VMOVDQU (16*0)(SP), B0
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(R8)
	JMP avx2XtsSm4DecDone

avx2XtsSm4DecLastBlock:
	VMOVDQU (16*0)(DX), B0
	VPXOR TW, B0, B0
	SM4_SINGLE_BLOCK(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	VPXOR TW, B0, B0
	VMOVDQU B0, (16*0)(CX)
	avxMul2GBInline

avx2XtsSm4DecDone:
	VMOVDQU TW, (16*0)(BX)
	VZEROUPPER
	RET
