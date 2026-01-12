// This SM4 implementation referenced https://github.com/mjosaarinen/sm4ni/blob/master/sm4ni.c
//go:build !purego

#include "textflag.h"

#define t0 X0
#define t1 X1
#define t2 X2
#define t3 X3

#define x X8
#define y X9
#define XTMP6 X10
#define XTMP7 X11

// shuffle byte order from LE to BE
DATA ·flip_mask+0x00(SB)/8, $0x0405060700010203
DATA ·flip_mask+0x08(SB)/8, $0x0c0d0e0f08090a0b
GLOBL ·flip_mask(SB), RODATA, $16

// shuffle byte and word order
DATA ·bswap_mask+0x00(SB)/8, $0x08090a0b0c0d0e0f
DATA ·bswap_mask+0x08(SB)/8, $0x0001020304050607
GLOBL ·bswap_mask(SB), RODATA, $16

//nibble mask
DATA ·nibble_mask+0x00(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA ·nibble_mask+0x08(SB)/8, $0x0F0F0F0F0F0F0F0F
GLOBL ·nibble_mask(SB), RODATA, $16

// inverse shift rows
DATA ·inverse_shift_rows+0x00(SB)/8, $0x0B0E0104070A0D00
DATA ·inverse_shift_rows+0x08(SB)/8, $0x0306090C0F020508
DATA ·inverse_shift_rows+0x10(SB)/8, $0x0B0E0104070A0D00
DATA ·inverse_shift_rows+0x18(SB)/8, $0x0306090C0F020508
GLOBL ·inverse_shift_rows(SB), RODATA, $32

// Affine transform 1 (low and high nibbles)
DATA ·m1_low+0x00(SB)/8, $0x0A7FC3B6D5A01C69
DATA ·m1_low+0x08(SB)/8, $0x3045F98CEF9A2653
DATA ·m1_low+0x10(SB)/8, $0x0A7FC3B6D5A01C69
DATA ·m1_low+0x18(SB)/8, $0x3045F98CEF9A2653
GLOBL ·m1_low(SB), RODATA, $32

DATA ·m1_high+0x00(SB)/8, $0xC35BF46CAF379800
DATA ·m1_high+0x08(SB)/8, $0x68F05FC7049C33AB
DATA ·m1_high+0x10(SB)/8, $0xC35BF46CAF379800
DATA ·m1_high+0x18(SB)/8, $0x68F05FC7049C33AB
GLOBL ·m1_high(SB), RODATA, $32

// Affine transform 2 (low and high nibbles)
DATA ·m2_low+0x00(SB)/8, $0x9A950A05FEF16E61
DATA ·m2_low+0x08(SB)/8, $0x0E019E916A65FAF5
DATA ·m2_low+0x10(SB)/8, $0x9A950A05FEF16E61
DATA ·m2_low+0x18(SB)/8, $0x0E019E916A65FAF5
GLOBL ·m2_low(SB), RODATA, $32

DATA ·m2_high+0x00(SB)/8, $0x892D69CD44E0A400
DATA ·m2_high+0x08(SB)/8, $0x2C88CC68E14501A5
DATA ·m2_high+0x10(SB)/8, $0x892D69CD44E0A400
DATA ·m2_high+0x18(SB)/8, $0x2C88CC68E14501A5
GLOBL ·m2_high(SB), RODATA, $32

// left rotations of 32-bit words by 8-bit increments
DATA ·r08_mask+0x00(SB)/8, $0x0605040702010003
DATA ·r08_mask+0x08(SB)/8, $0x0E0D0C0F0A09080B
DATA ·r08_mask+0x10(SB)/8, $0x0605040702010003
DATA ·r08_mask+0x18(SB)/8, $0x0E0D0C0F0A09080B
GLOBL ·r08_mask(SB), RODATA, $32

#include "aesni_macros_amd64.s"

// SM4 TAO L2 function, used for key expand
// parameters:
// -  x: 128 bits register as TAO_L1 input/output data
// -  y: 128 bits temp register
// -  tmp1: 128 bits temp register
// -  tmp2: 128 bits temp register
#define SM4_TAO_L2(x, y, tmp1, tmp2)    \
	SM4_SBOX(x, y, tmp1);              \
	;                                  \ //####################  4 parallel L2 linear transforms ##################//
	MOVOU x, y;                        \
	MOVOU x, tmp1;                     \
	PSLLL $13, tmp1;                   \
	PSRLL $19, y;                      \
	POR tmp1, y;                       \ //y = X roll 13  
	PSLLL $10, tmp1;                   \
	MOVOU x, tmp2;                     \
	PSRLL $9, tmp2;                    \
	POR tmp1, tmp2;                    \ //tmp2 = x roll 23
	PXOR tmp2, y;                      \
	PXOR y, x                        

// SM4 expand round function
// t0 ^= tao_l2(t1^t2^t3^ck) and store t0.S[0] to enc/dec
// parameters:
// - index: round key index immediate number
// -  x: 128 bits temp register
// -  y: 128 bits temp register
// - t0: 128 bits register for data
// - t1: 128 bits register for data
// - t2: 128 bits register for data
// - t3: 128 bits register for data
#define SM4_EXPANDKEY_ROUND(index, x, y, t0, t1, t2, t3) \
	MOVL (index * 4)(BX)(CX*1), x;                         \
	PXOR t1, x;                                            \
	PXOR t2, x;                                            \
	PXOR t3, x;                                            \
	SM4_TAO_L2(x, y, XTMP6, XTMP7);                        \
	PXOR x, t0;                                            \
	MOVL t0, R8;                                           \ // _mm_cvtsi128_si32
	MOVL R8, (index * 4)(DX)(CX*1);                        \
	MOVL R8, (12 - index * 4)(DI)(SI*1)

#define XDWORD0 Y4
#define XDWORD1 Y5
#define XDWORD2 Y6
#define XDWORD3 Y7

#define XWORD0 X4
#define XWORD1 X5
#define XWORD2 X6
#define XWORD3 X7

#define XDWORD4 Y10
#define XDWORD5 Y11
#define XDWORD6 Y12
#define XDWORD7 Y14

#define XWORD4 X10
#define XWORD5 X11
#define XWORD6 X12
#define XWORD7 X14

#define XDWTMP0 Y0
#define XDWTMP1 Y1
#define XDWTMP2 Y2

#define XWTMP0 X0
#define XWTMP1 X1
#define XWTMP2 X2

#define NIBBLE_MASK Y3
#define X_NIBBLE_MASK X3

#define BYTE_FLIP_MASK 	Y13 // mask to convert LE -> BE
#define X_BYTE_FLIP_MASK 	X13 // mask to convert LE -> BE

#define XDWORD Y8
#define YDWORD Y9

#define XWORD X8
#define YWORD X9

// func expandKeyAsm(key *byte, ck, enc, dec *uint32, inst int)
TEXT ·expandKeyAsm(SB),NOSPLIT,$0
	MOVQ key+0(FP), AX
	MOVQ  ck+8(FP), BX
	MOVQ  enc+16(FP), DX
	MOVQ  dec+24(FP), DI

	MOVUPS 0(AX), t0
	PSHUFB ·flip_mask(SB), t0
	PXOR ·fk(SB), t0
	PSHUFD $1, t0, t1
	PSHUFD $2, t0, t2
	PSHUFD $3, t0, t3

	XORL CX, CX
	MOVL $112, SI

loop:
		SM4_EXPANDKEY_ROUND(0, x, y, t0, t1, t2, t3)
		SM4_EXPANDKEY_ROUND(1, x, y, t1, t2, t3, t0)
		SM4_EXPANDKEY_ROUND(2, x, y, t2, t3, t0, t1)
		SM4_EXPANDKEY_ROUND(3, x, y, t3, t0, t1, t2)

		ADDL $16, CX
		SUBL $16, SI
		CMPL CX, $4*32
		JB loop

expand_end:  
	RET 

// func encryptBlocksAsm(xk *uint32, dst, src []byte, inst int)
TEXT ·encryptBlocksAsm(SB),NOSPLIT,$0
	MOVQ xk+0(FP), AX
	MOVQ dst+8(FP), BX
	MOVQ src+32(FP), DX
	MOVQ src_len+40(FP), DI

	CMPB ·useAVX2(SB), $1
	JE   avx2

non_avx2_start:
	CMPQ DI, $128
	JEQ sse_8blocks

	MOVOU 0(DX), XWORD0
	MOVOU 16(DX), XWORD1
	MOVOU 32(DX), XWORD2
	MOVOU 48(DX), XWORD3

	SM4_4BLOCKS(AX, XWORD, YWORD, XWTMP0, XWTMP1, XWORD0, XWORD1, XWORD2, XWORD3)
	
	MOVOU XWORD0, 0(BX)
	MOVOU XWORD1, 16(BX)
	MOVOU XWORD2, 32(BX)
	MOVOU XWORD3, 48(BX)

	RET

sse_8blocks:
	MOVOU 0(DX), XWORD0
	MOVOU 16(DX), XWORD1
	MOVOU 32(DX), XWORD2
	MOVOU 48(DX), XWORD3
	MOVOU 64(DX), XWORD4
	MOVOU 80(DX), XWORD5
	MOVOU 96(DX), XWORD6
	MOVOU 112(DX), XWORD7

	SM4_8BLOCKS(AX, XWORD, YWORD, XWTMP0, XWTMP1, XWORD0, XWORD1, XWORD2, XWORD3, XWORD4, XWORD5, XWORD6, XWORD7)
	
	MOVOU XWORD0, 0(BX)
	MOVOU XWORD1, 16(BX)
	MOVOU XWORD2, 32(BX)
	MOVOU XWORD3, 48(BX)
	MOVOU XWORD4, 64(BX)
	MOVOU XWORD5, 80(BX)
	MOVOU XWORD6, 96(BX)
	MOVOU XWORD7, 112(BX)	
done_sm4:
	RET

avx2:
	VBROADCASTI128 ·nibble_mask(SB), NIBBLE_MASK
	
	CMPQ DI, $256
	JEQ avx2_16blocks

avx2_8blocks:
	VMOVDQU 0(DX), XDWORD0
	VMOVDQU 32(DX), XDWORD1
	VMOVDQU 64(DX), XDWORD2
	VMOVDQU 96(DX), XDWORD3
	VBROADCASTI128 ·flip_mask(SB), BYTE_FLIP_MASK

	// Apply Byte Flip Mask: LE -> BE
	VPSHUFB BYTE_FLIP_MASK, XDWORD0, XDWORD0
	VPSHUFB BYTE_FLIP_MASK, XDWORD1, XDWORD1
	VPSHUFB BYTE_FLIP_MASK, XDWORD2, XDWORD2
	VPSHUFB BYTE_FLIP_MASK, XDWORD3, XDWORD3

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(XDWORD0, XDWORD1, XDWORD2, XDWORD3, XDWTMP1, XDWTMP2)

	AVX2_SM4_8BLOCKS(AX, XDWORD, YDWORD, XWORD, YWORD, XDWTMP0, XDWORD0, XDWORD1, XDWORD2, XDWORD3)

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(XDWORD0, XDWORD1, XDWORD2, XDWORD3, XDWTMP1, XDWTMP2)

	VBROADCASTI128 ·bswap_mask(SB), BYTE_FLIP_MASK
	VPSHUFB BYTE_FLIP_MASK, XDWORD0, XDWORD0
	VPSHUFB BYTE_FLIP_MASK, XDWORD1, XDWORD1
	VPSHUFB BYTE_FLIP_MASK, XDWORD2, XDWORD2
	VPSHUFB BYTE_FLIP_MASK, XDWORD3, XDWORD3
  
	VMOVDQU XDWORD0, 0(BX)
	VMOVDQU XDWORD1, 32(BX)
	VMOVDQU XDWORD2, 64(BX)
	VMOVDQU XDWORD3, 96(BX)

	VZEROUPPER
	RET

avx2_16blocks:
	VMOVDQU 0(DX), XDWORD0
	VMOVDQU 32(DX), XDWORD1
	VMOVDQU 64(DX), XDWORD2
	VMOVDQU 96(DX), XDWORD3
	VMOVDQU 128(DX), XDWORD4
	VMOVDQU 160(DX), XDWORD5
	VMOVDQU 192(DX), XDWORD6
	VMOVDQU 224(DX), XDWORD7

	VBROADCASTI128 ·flip_mask(SB), BYTE_FLIP_MASK

	// Apply Byte Flip Mask: LE -> BE
	VPSHUFB BYTE_FLIP_MASK, XDWORD0, XDWORD0
	VPSHUFB BYTE_FLIP_MASK, XDWORD1, XDWORD1
	VPSHUFB BYTE_FLIP_MASK, XDWORD2, XDWORD2
	VPSHUFB BYTE_FLIP_MASK, XDWORD3, XDWORD3
	VPSHUFB BYTE_FLIP_MASK, XDWORD4, XDWORD4
	VPSHUFB BYTE_FLIP_MASK, XDWORD5, XDWORD5
	VPSHUFB BYTE_FLIP_MASK, XDWORD6, XDWORD6
	VPSHUFB BYTE_FLIP_MASK, XDWORD7, XDWORD7

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(XDWORD0, XDWORD1, XDWORD2, XDWORD3, XDWTMP1, XDWTMP2)
	TRANSPOSE_MATRIX(XDWORD4, XDWORD5, XDWORD6, XDWORD7, XDWTMP1, XDWTMP2)

	AVX2_SM4_16BLOCKS(AX, XDWORD, YDWORD, XWORD, YWORD, XDWTMP0, XDWTMP1, XDWORD0, XDWORD1, XDWORD2, XDWORD3, XDWORD4, XDWORD5, XDWORD6, XDWORD7)

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(XDWORD0, XDWORD1, XDWORD2, XDWORD3, XDWTMP1, XDWTMP2)
	TRANSPOSE_MATRIX(XDWORD4, XDWORD5, XDWORD6, XDWORD7, XDWTMP1, XDWTMP2)

	VBROADCASTI128 ·bswap_mask(SB), BYTE_FLIP_MASK
	VPSHUFB BYTE_FLIP_MASK, XDWORD0, XDWORD0
	VPSHUFB BYTE_FLIP_MASK, XDWORD1, XDWORD1
	VPSHUFB BYTE_FLIP_MASK, XDWORD2, XDWORD2
	VPSHUFB BYTE_FLIP_MASK, XDWORD3, XDWORD3
  	VPSHUFB BYTE_FLIP_MASK, XDWORD4, XDWORD4
	VPSHUFB BYTE_FLIP_MASK, XDWORD5, XDWORD5
	VPSHUFB BYTE_FLIP_MASK, XDWORD6, XDWORD6
	VPSHUFB BYTE_FLIP_MASK, XDWORD7, XDWORD7

	VMOVDQU XDWORD0, 0(BX)
	VMOVDQU XDWORD1, 32(BX)
	VMOVDQU XDWORD2, 64(BX)
	VMOVDQU XDWORD3, 96(BX)
	VMOVDQU XDWORD4, 128(BX)
	VMOVDQU XDWORD5, 160(BX)
	VMOVDQU XDWORD6, 192(BX)
	VMOVDQU XDWORD7, 224(BX)	

avx2_sm4_done:
	VZEROUPPER
	RET

// func encryptBlockAsm(xk *uint32, dst, src *byte, inst int)
// Requires: SSSE3
TEXT ·encryptBlockAsm(SB),NOSPLIT,$0
	MOVQ xk+0(FP), AX
	MOVQ dst+8(FP), BX
	MOVQ src+16(FP), DX
  
	MOVUPS (DX), t0
	PSHUFB ·flip_mask(SB), t0
	PSHUFD $1, t0, t1
	PSHUFD $2, t0, t2
	PSHUFD $3, t0, t3

	XORL CX, CX

loop:
		MOVUPS (AX)(CX*1), XTMP7
		MOVOU XTMP7, x
		SM4_SINGLE_ROUND(x, y, XTMP6, t0, t1, t2, t3)
		PSHUFD $1, XTMP7, x
		SM4_SINGLE_ROUND(x, y, XTMP6, t1, t2, t3, t0)
		PSHUFD $2, XTMP7, x
		SM4_SINGLE_ROUND(x, y, XTMP6, t2, t3, t0, t1)
		PSHUFD $3, XTMP7, x
		SM4_SINGLE_ROUND(x, y, XTMP6, t3, t0, t1, t2)

		ADDL $16, CX
		CMPL CX, $4*32
		JB loop

	PUNPCKLLQ t2, t3
	PUNPCKLLQ t0, t1
	PUNPCKLQDQ t1, t3
	PSHUFB ·flip_mask(SB), t3
	MOVUPS t3, (BX)

done_sm4:
	RET
