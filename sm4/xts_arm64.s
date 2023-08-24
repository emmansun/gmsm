//go:build arm64 && !purego
// +build arm64,!purego

#include "textflag.h"

#define B0 V0
#define B1 V1
#define B2 V2
#define B3 V3
#define B4 V4
#define B5 V5
#define B6 V6
#define B7 V7

#define T0 V8
#define T1 V9
#define T2 V10
#define T3 V11
#define T4 V12
#define T5 V13
#define T6 V14
#define T7 V15

#define POLY V16
#define ZERO V17
#define TW V18

#define K0 V19
#define K1 V20
#define K2 V21
#define K3 V22

#define NIBBLE_MASK V23
#define INVERSE_SHIFT_ROWS V24
#define M1L V25
#define M1H V26 
#define M2L V27 
#define M2H V28
#define R08_MASK V29 
#define R16_MASK V30
#define R24_MASK V31

#include "aesni_macros_arm64.s"

#define mul2Inline        \
	VMOV	TW.D[1], I;                     \
	ASR	$63, I;                             \
	VMOV	I, K0.D2;                       \
	VAND	POLY.B16, K0.B16, K0.B16;       \
	\
	VUSHR	$63, TW.D2, K1.D2;              \
	VEXT	$8, K1.B16, ZERO.B16, K1.B16;   \
	VSHL	$1, TW.D2, TW.D2;               \
	VEOR	K0.B16, TW.B16, TW.B16;         \
	VEOR	K1.B16, TW.B16, TW.B16

#define mul2GBInline        \
	VREV64 TW.B16, TW.B16;                  \
	VEXT	$8, TW.B16, TW.B16, TW.B16;     \
	\
	VMOV	TW.D[0], I;                     \
	LSL $63, I;                             \
	ASR $63, I;                             \
	VMOV	I, K0.D2;                       \
	VAND	POLY.B16, K0.B16, K0.B16;       \
	\
	VSHL $63, TW.D2, K1.D2;                 \
	VEXT	$8, ZERO.B16, K1.B16, K1.B16;   \
	VUSHR	$1, TW.D2, TW.D2;               \
	VEOR	K0.B16, TW.B16, TW.B16;         \
	VEOR	K1.B16, TW.B16, TW.B16;         \
	\
	VEXT	$8, TW.B16, TW.B16, TW.B16;     \
	VREV64 TW.B16, TW.B16

#define prepare4Tweaks \
	VMOV TW.B16, T0.B16;   \
	mul2Inline;            \
	VMOV TW.B16, T1.B16;   \
	mul2Inline;            \
	VMOV TW.B16, T2.B16;   \
	mul2Inline;            \
	VMOV TW.B16, T3.B16;   \
	mul2Inline

#define prepare8Tweaks \
	prepare4Tweaks;        \
	VMOV TW.B16, T4.B16;   \
	mul2Inline;            \
	VMOV TW.B16, T5.B16;   \
	mul2Inline;            \
	VMOV TW.B16, T6.B16;   \
	mul2Inline;            \
	VMOV TW.B16, T7.B16;   \
	mul2Inline

#define prepareGB4Tweaks \
	VMOV TW.B16, T0.B16;     \
	mul2GBInline;            \
	VMOV TW.B16, T1.B16;     \
	mul2GBInline;            \
	VMOV TW.B16, T2.B16;     \
	mul2GBInline;            \
	VMOV TW.B16, T3.B16;     \
	mul2GBInline

#define prepareGB8Tweaks \
	prepareGB4Tweaks;        \
	VMOV TW.B16, T4.B16;     \
	mul2GBInline;            \
	VMOV TW.B16, T5.B16;     \
	mul2GBInline;            \
	VMOV TW.B16, T6.B16;     \
	mul2GBInline;            \
	VMOV TW.B16, T7.B16;     \
	mul2GBInline

#define load8blocks \
	VLD1.P 64(srcPtr), [B0.S4, B1.S4, B2.S4, B3.S4]; \
	VEOR T0.B16, B0.B16, B0.B16; \
	VEOR T1.B16, B1.B16, B1.B16; \
	VEOR T2.B16, B2.B16, B2.B16; \
	VEOR T3.B16, B3.B16, B3.B16; \
	\
	VLD1.P 64(srcPtr), [B4.S4, B5.S4, B6.S4, B7.S4]; \
	VEOR T4.B16, B4.B16, B4.B16; \
	VEOR T5.B16, B5.B16, B5.B16; \
	VEOR T6.B16, B6.B16, B6.B16; \
	VEOR T7.B16, B7.B16, B7.B16; \
	\
	VREV32 B0.B16, B0.B16; \
	VREV32 B1.B16, B1.B16; \
	VREV32 B2.B16, B2.B16; \
	VREV32 B3.B16, B3.B16; \
	VREV32 B4.B16, B4.B16; \
	VREV32 B5.B16, B5.B16; \
	VREV32 B6.B16, B6.B16; \
	VREV32 B7.B16, B7.B16; \
	\
	PRE_TRANSPOSE_MATRIX(B0, B1, B2, B3, K0, K1, K2, K3); \
	PRE_TRANSPOSE_MATRIX(B4, B5, B6, B7, K0, K1, K2, K3)

#define store8blocks \
	VREV32 B0.B16, B0.B16; \
	VREV32 B1.B16, B1.B16; \
	VREV32 B2.B16, B2.B16; \
	VREV32 B3.B16, B3.B16; \
	TRANSPOSE_MATRIX(B0, B1, B2, B3, K0, K1, K2, K3); \
	VREV32 B4.B16, B4.B16; \
	VREV32 B5.B16, B5.B16; \
	VREV32 B6.B16, B6.B16; \
	VREV32 B7.B16, B7.B16; \
	TRANSPOSE_MATRIX(B4, B5, B6, B7, K0, K1, K2, K3); \
	\
	VEOR T0.B16, B0.B16, B0.B16; \
	VEOR T1.B16, B1.B16, B1.B16; \
	VEOR T2.B16, B2.B16, B2.B16; \
	VEOR T3.B16, B3.B16, B3.B16; \
	VEOR T4.B16, B4.B16, B4.B16; \
	VEOR T5.B16, B5.B16, B5.B16; \
	VEOR T6.B16, B6.B16, B6.B16; \
	VEOR T7.B16, B7.B16, B7.B16; \
	\
	VST1.P [B0.S4, B1.S4, B2.S4, B3.S4], 64(dstPtr); \
	VST1.P [B4.S4, B5.S4, B6.S4, B7.S4], 64(dstPtr)

#define load4blocks \
	VLD1.P 64(srcPtr), [B0.S4, B1.S4, B2.S4, B3.S4]; \
	VEOR T0.B16, B0.B16, B0.B16; \
	VEOR T1.B16, B1.B16, B1.B16; \
	VEOR T2.B16, B2.B16, B2.B16; \
	VEOR T3.B16, B3.B16, B3.B16; \
	\
	VREV32 B0.B16, B0.B16; \
	VREV32 B1.B16, B1.B16; \
	VREV32 B2.B16, B2.B16; \
	VREV32 B3.B16, B3.B16; \
	PRE_TRANSPOSE_MATRIX(B0, B1, B2, B3, K0, K1, K2, K3)

#define store4blocks \
	VREV32 B0.B16, B0.B16; \
	VREV32 B1.B16, B1.B16; \
	VREV32 B2.B16, B2.B16; \
	VREV32 B3.B16, B3.B16; \
	TRANSPOSE_MATRIX(B0, B1, B2, B3, K0, K1, K2, K3); \
	\
	VEOR T0.B16, B0.B16, B0.B16; \
	VEOR T1.B16, B1.B16, B1.B16; \
	VEOR T2.B16, B2.B16, B2.B16; \
	VEOR T3.B16, B3.B16, B3.B16; \
	\
	VST1.P [B0.S4, B1.S4, B2.S4, B3.S4], 64(dstPtr)

#define loadOneBlock \
	VLD1.P 16(srcPtr), [B0.S4]; \
	VEOR TW.B16, B0.B16, B0.B16; \
	\
	VREV32 B0.B16, B0.B16; \
	VMOV B0.S[1], B1.S[0]; \
	VMOV B0.S[2], B2.S[0]; \
	VMOV B0.S[3], B3.S[0]

#define storeOneBlock \
	VMOV B2.S[0], B3.S[1]; \
	VMOV B1.S[0], B3.S[2]; \
	VMOV B0.S[0], B3.S[3]; \
	VREV32 B3.B16, B3.B16; \
	\
	VEOR TW.B16, B3.B16, B3.B16; \
	VST1.P [B3.S4], 16(dstPtr)

#define dstPtr R2
#define srcPtr R3
#define rk R0
#define twPtr R1
#define srcPtrLen R4
#define I R5
#define rkSave R6

// func encryptSm4Xts(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)
TEXT ·encryptSm4Xts(SB),0,$128-64
	LOAD_SM4_AESNI_CONSTS()
	MOVD xk+0(FP), rk
	MOVD tweak+8(FP), twPtr
	MOVD dst+16(FP), dstPtr
	MOVD src+40(FP), srcPtr
	MOVD src_len+48(FP), srcPtrLen

	VEOR	POLY.B16, POLY.B16, POLY.B16
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	MOVD	$0x87, I
	VMOV	I, POLY.D[0]

	MOVD rk, rkSave
	VLD1 (twPtr), [TW.B16]

xtsSm4EncOctets:
	CMP	$128, srcPtrLen
	BLT	xtsSm4EncNibbles
	SUB	$128, srcPtrLen

	prepare8Tweaks
	load8blocks
	MOVD rkSave, rk
	EOR R13, R13

encOctetsEnc8Blocks:
			SM4_8BLOCKS_ROUND(rk, R19, K0, K1, K2, K3, B0, B1, B2, B3, B4, B5, B6, B7)
			SM4_8BLOCKS_ROUND(rk, R19, K0, K1, K2, K3, B1, B2, B3, B0, B5, B6, B7, B4)
			SM4_8BLOCKS_ROUND(rk, R19, K0, K1, K2, K3, B2, B3, B0, B1, B6, B7, B4, B5)
			SM4_8BLOCKS_ROUND(rk, R19, K0, K1, K2, K3, B3, B0, B1, B2, B7, B4, B5, B6)

		ADD $1, R13
		CMP $8, R13
		BNE encOctetsEnc8Blocks

	store8blocks
	B	xtsSm4EncOctets

xtsSm4EncNibbles:
	CMP	$64, srcPtrLen
	BLT	xtsSm4EncSingles
	SUB	$64, srcPtrLen

	prepare4Tweaks
	load4blocks
	MOVD rkSave, rk
	EOR R13, R13

encNibblesEnc4Blocks:
		SM4_ROUND(rk, R19, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, R19, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, R19, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, R19, K0, K1, K2, B3, B0, B1, B2)

		ADD $1, R13
		CMP $8, R13
		BNE encNibblesEnc4Blocks
	
	store4blocks

xtsSm4EncSingles:
	CMP	$16, srcPtrLen
	BLT	xtsSm4EncDone
	SUB	$16, srcPtrLen

	loadOneBlock

	MOVD rkSave, rk
	EOR R13, R13

encSinglesEnc4Blocks:	
		SM4_ROUND(rk, R19, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, R19, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, R19, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, R19, K0, K1, K2, B3, B0, B1, B2)
		ADD $1, R13
		CMP $8, R13
		BNE encSinglesEnc4Blocks

	storeOneBlock
	mul2Inline
	B	xtsSm4EncSingles

xtsSm4EncDone:
	VST1 [TW.B16], (twPtr)
	RET

// func encryptSm4XtsGB(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)
TEXT ·encryptSm4XtsGB(SB),0,$128-64
	RET

// func decryptSm4Xts(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)
TEXT ·decryptSm4Xts(SB),0,$128-64
	RET

// func decryptSm4XtsGB(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)
TEXT ·decryptSm4XtsGB(SB),0,$128-64
	RET
