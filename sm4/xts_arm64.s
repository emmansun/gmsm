//go:build !purego

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

#include "aesni_macros_arm64.s"
#include "xts_macros_arm64.s"

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
	BLT	xtsSm4EncTail
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

xtsSm4EncTail:
	CBZ	srcPtrLen, xtsSm4EncDone
	SUB $16, dstPtr, R7
	MOVD R7, R9
	MOVD RSP, R8
	VLD1 (R7), [B0.B16]
	VST1 [B0.B16], (R8)

	TBZ	$3, srcPtrLen, less_than8
	MOVD.P 8(srcPtr), R11
	MOVD.P R11, 8(R8)
	MOVD.P 8(R7), R12
	MOVD.P R12, 8(dstPtr)

less_than8:
	TBZ	$2, srcPtrLen, less_than4
	MOVWU.P 4(srcPtr), R11
	MOVWU.P R11, 4(R8)
	MOVWU.P 4(R7), R12
	MOVWU.P R12, 4(dstPtr)

less_than4:
	TBZ	$1, srcPtrLen, less_than2
	MOVHU.P 2(srcPtr), R11
	MOVHU.P R11, 2(R8)
	MOVHU.P 2(R7), R12
	MOVHU.P R12, 2(dstPtr)

less_than2:
	TBZ	$0, srcPtrLen, xtsSm4EncTailEnc
	MOVBU (srcPtr), R11
	MOVBU R11, (R8)
	MOVBU (R7), R12
	MOVBU R12, (dstPtr)

xtsSm4EncTailEnc:
	VLD1 (RSP), [B0.B16]
	VEOR TW.B16, B0.B16, B0.B16
	VREV32 B0.B16, B0.B16
	VMOV B0.S[1], B1.S[0]
	VMOV B0.S[2], B2.S[0]
	VMOV B0.S[3], B3.S[0]

	MOVD rkSave, rk
	EOR R13, R13

tailEncLoop:
		SM4_ROUND(rk, R19, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, R19, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, R19, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, R19, K0, K1, K2, B3, B0, B1, B2)
		ADD $1, R13
		CMP $8, R13
		BNE tailEncLoop

	VMOV B2.S[0], B3.S[1]
	VMOV B1.S[0], B3.S[2]
	VMOV B0.S[0], B3.S[3]
	VREV32 B3.B16, B3.B16

	VEOR TW.B16, B3.B16, B3.B16
	VST1 [B3.B16], (R9)

xtsSm4EncDone:
	VST1 [TW.B16], (twPtr)
	RET

// func encryptSm4XtsGB(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)
TEXT ·encryptSm4XtsGB(SB),0,$128-64
	LOAD_SM4_AESNI_CONSTS()
	MOVD xk+0(FP), rk
	MOVD tweak+8(FP), twPtr
	MOVD dst+16(FP), dstPtr
	MOVD src+40(FP), srcPtr
	MOVD src_len+48(FP), srcPtrLen

	VEOR	POLY.B16, POLY.B16, POLY.B16
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	MOVD	$0xE1, I
	LSL	$56, I
	VMOV	I, POLY.D[1]

	MOVD rk, rkSave
	VLD1 (twPtr), [TW.B16]

xtsSm4EncOctets:
	CMP	$128, srcPtrLen
	BLT	xtsSm4EncNibbles
	SUB	$128, srcPtrLen

	prepareGB8Tweaks
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

	prepareGB4Tweaks
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
	BLT	xtsSm4EncTail
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
	mul2GBInline
	B	xtsSm4EncSingles

xtsSm4EncTail:
	CBZ	srcPtrLen, xtsSm4EncDone
	SUB $16, dstPtr, R7
	MOVD R7, R9
	MOVD RSP, R8
	VLD1 (R7), [B0.B16]
	VST1 [B0.B16], (R8)

	TBZ	$3, srcPtrLen, less_than8
	MOVD.P 8(srcPtr), R11
	MOVD.P R11, 8(R8)
	MOVD.P 8(R7), R12
	MOVD.P R12, 8(dstPtr)

less_than8:
	TBZ	$2, srcPtrLen, less_than4
	MOVWU.P 4(srcPtr), R11
	MOVWU.P R11, 4(R8)
	MOVWU.P 4(R7), R12
	MOVWU.P R12, 4(dstPtr)

less_than4:
	TBZ	$1, srcPtrLen, less_than2
	MOVHU.P 2(srcPtr), R11
	MOVHU.P R11, 2(R8)
	MOVHU.P 2(R7), R12
	MOVHU.P R12, 2(dstPtr)

less_than2:
	TBZ	$0, srcPtrLen, xtsSm4EncTailEnc
	MOVBU (srcPtr), R11
	MOVBU R11, (R8)
	MOVBU (R7), R12
	MOVBU R12, (dstPtr)

xtsSm4EncTailEnc:
	VLD1 (RSP), [B0.B16]
	VEOR TW.B16, B0.B16, B0.B16
	VREV32 B0.B16, B0.B16
	VMOV B0.S[1], B1.S[0]
	VMOV B0.S[2], B2.S[0]
	VMOV B0.S[3], B3.S[0]

	MOVD rkSave, rk
	EOR R13, R13

tailEncLoop:
		SM4_ROUND(rk, R19, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, R19, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, R19, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, R19, K0, K1, K2, B3, B0, B1, B2)
		ADD $1, R13
		CMP $8, R13
		BNE tailEncLoop

	VMOV B2.S[0], B3.S[1]
	VMOV B1.S[0], B3.S[2]
	VMOV B0.S[0], B3.S[3]
	VREV32 B3.B16, B3.B16

	VEOR TW.B16, B3.B16, B3.B16
	VST1 [B3.B16], (R9)

xtsSm4EncDone:
	VST1 [TW.B16], (twPtr)
	RET

// func decryptSm4Xts(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)
TEXT ·decryptSm4Xts(SB),0,$128-64
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

xtsSm4DecOctets:
	CMP	$128, srcPtrLen
	BLT	xtsSm4DecNibbles
	SUB	$128, srcPtrLen

	prepare8Tweaks
	load8blocks
	MOVD rkSave, rk
	EOR R13, R13

decOctetsDec8Blocks:
			SM4_8BLOCKS_ROUND(rk, R19, K0, K1, K2, K3, B0, B1, B2, B3, B4, B5, B6, B7)
			SM4_8BLOCKS_ROUND(rk, R19, K0, K1, K2, K3, B1, B2, B3, B0, B5, B6, B7, B4)
			SM4_8BLOCKS_ROUND(rk, R19, K0, K1, K2, K3, B2, B3, B0, B1, B6, B7, B4, B5)
			SM4_8BLOCKS_ROUND(rk, R19, K0, K1, K2, K3, B3, B0, B1, B2, B7, B4, B5, B6)

		ADD $1, R13
		CMP $8, R13
		BNE decOctetsDec8Blocks

	store8blocks
	B	xtsSm4DecOctets

xtsSm4DecNibbles:
	CMP	$64, srcPtrLen
	BLT	xtsSm4DecSingles
	SUB	$64, srcPtrLen

	prepare4Tweaks
	load4blocks
	MOVD rkSave, rk
	EOR R13, R13

decNibblesDec4Blocks:
		SM4_ROUND(rk, R19, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, R19, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, R19, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, R19, K0, K1, K2, B3, B0, B1, B2)

		ADD $1, R13
		CMP $8, R13
		BNE decNibblesDec4Blocks
	
	store4blocks

xtsSm4DecSingles:
	CMP	$32, srcPtrLen
	BLT	xtsSm4DecTail
	SUB	$16, srcPtrLen

	loadOneBlock

	MOVD rkSave, rk
	EOR R13, R13

decSinglesDec4Blocks:	
		SM4_ROUND(rk, R19, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, R19, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, R19, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, R19, K0, K1, K2, B3, B0, B1, B2)
		ADD $1, R13
		CMP $8, R13
		BNE decSinglesDec4Blocks

	storeOneBlock
	mul2Inline

	B	xtsSm4DecSingles

xtsSm4DecTail:
	CBZ	srcPtrLen, xtsSm4DecDone
	
	CMP	$16, srcPtrLen
	BEQ xtsSm4DecLastBlock

	VMOV TW.B16, B4.B16
	mul2Inline
	loadOneBlock
	MOVD rkSave, rk
	EOR R13, R13

decLastCompleteBlockLoop:	
		SM4_ROUND(rk, R19, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, R19, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, R19, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, R19, K0, K1, K2, B3, B0, B1, B2)
		ADD $1, R13
		CMP $8, R13
		BNE decLastCompleteBlockLoop
	storeOneBlock
	VMOV B4.B16, TW.B16
	VST1 [B3.B16], (RSP)

	SUB $16, dstPtr, R7
	MOVD R7, R9
	MOVD RSP, R8

	TBZ	$3, srcPtrLen, less_than8
	MOVD.P 8(srcPtr), R11
	MOVD.P R11, 8(R8)
	MOVD.P 8(R7), R12
	MOVD.P R12, 8(dstPtr)

less_than8:
	TBZ	$2, srcPtrLen, less_than4
	MOVWU.P 4(srcPtr), R11
	MOVWU.P R11, 4(R8)
	MOVWU.P 4(R7), R12
	MOVWU.P R12, 4(dstPtr)

less_than4:
	TBZ	$1, srcPtrLen, less_than2
	MOVHU.P 2(srcPtr), R11
	MOVHU.P R11, 2(R8)
	MOVHU.P 2(R7), R12
	MOVHU.P R12, 2(dstPtr)

less_than2:
	TBZ	$0, srcPtrLen, xtsSm4DecTailDec
	MOVBU (srcPtr), R11
	MOVBU R11, (R8)
	MOVBU (R7), R12
	MOVBU R12, (dstPtr)

xtsSm4DecTailDec:
	VLD1 (RSP), [B0.B16]
	VEOR TW.B16, B0.B16, B0.B16
	VREV32 B0.B16, B0.B16
	VMOV B0.S[1], B1.S[0]
	VMOV B0.S[2], B2.S[0]
	VMOV B0.S[3], B3.S[0]

	MOVD rkSave, rk
	EOR R13, R13

tailDecLoop:
		SM4_ROUND(rk, R19, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, R19, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, R19, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, R19, K0, K1, K2, B3, B0, B1, B2)
		ADD $1, R13
		CMP $8, R13
		BNE tailDecLoop

	VMOV B2.S[0], B3.S[1]
	VMOV B1.S[0], B3.S[2]
	VMOV B0.S[0], B3.S[3]
	VREV32 B3.B16, B3.B16

	VEOR TW.B16, B3.B16, B3.B16
	VST1 [B3.B16], (R9)

	B xtsSm4DecDone

xtsSm4DecLastBlock:
	loadOneBlock

	MOVD rkSave, rk
	EOR R13, R13

decLastBlockLoop:	
		SM4_ROUND(rk, R19, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, R19, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, R19, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, R19, K0, K1, K2, B3, B0, B1, B2)
		ADD $1, R13
		CMP $8, R13
		BNE decLastBlockLoop

	storeOneBlock
	mul2Inline

xtsSm4DecDone:
	VST1 [TW.B16], (twPtr)
	RET

// func decryptSm4XtsGB(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)
TEXT ·decryptSm4XtsGB(SB),0,$128-64
	LOAD_SM4_AESNI_CONSTS()
	MOVD xk+0(FP), rk
	MOVD tweak+8(FP), twPtr
	MOVD dst+16(FP), dstPtr
	MOVD src+40(FP), srcPtr
	MOVD src_len+48(FP), srcPtrLen

	VEOR	POLY.B16, POLY.B16, POLY.B16
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	MOVD	$0xE1, I
	LSL	$56, I
	VMOV	I, POLY.D[1]

	MOVD rk, rkSave
	VLD1 (twPtr), [TW.B16]

xtsSm4DecOctets:
	CMP	$128, srcPtrLen
	BLT	xtsSm4DecNibbles
	SUB	$128, srcPtrLen

	prepareGB8Tweaks
	load8blocks
	MOVD rkSave, rk
	EOR R13, R13

decOctetsDec8Blocks:
			SM4_8BLOCKS_ROUND(rk, R19, K0, K1, K2, K3, B0, B1, B2, B3, B4, B5, B6, B7)
			SM4_8BLOCKS_ROUND(rk, R19, K0, K1, K2, K3, B1, B2, B3, B0, B5, B6, B7, B4)
			SM4_8BLOCKS_ROUND(rk, R19, K0, K1, K2, K3, B2, B3, B0, B1, B6, B7, B4, B5)
			SM4_8BLOCKS_ROUND(rk, R19, K0, K1, K2, K3, B3, B0, B1, B2, B7, B4, B5, B6)

		ADD $1, R13
		CMP $8, R13
		BNE decOctetsDec8Blocks

	store8blocks
	B	xtsSm4DecOctets

xtsSm4DecNibbles:
	CMP	$64, srcPtrLen
	BLT	xtsSm4DecSingles
	SUB	$64, srcPtrLen

	prepareGB4Tweaks
	load4blocks
	MOVD rkSave, rk
	EOR R13, R13

decNibblesDec4Blocks:
		SM4_ROUND(rk, R19, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, R19, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, R19, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, R19, K0, K1, K2, B3, B0, B1, B2)

		ADD $1, R13
		CMP $8, R13
		BNE decNibblesDec4Blocks
	
	store4blocks

xtsSm4DecSingles:
	CMP	$32, srcPtrLen
	BLT	xtsSm4DecTail
	SUB	$16, srcPtrLen

	loadOneBlock

	MOVD rkSave, rk
	EOR R13, R13

decSinglesDec4Blocks:	
		SM4_ROUND(rk, R19, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, R19, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, R19, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, R19, K0, K1, K2, B3, B0, B1, B2)
		ADD $1, R13
		CMP $8, R13
		BNE decSinglesDec4Blocks

	storeOneBlock
	mul2GBInline

	B	xtsSm4DecSingles

xtsSm4DecTail:
	CBZ	srcPtrLen, xtsSm4DecDone
	
	CMP	$16, srcPtrLen
	BEQ xtsSm4DecLastBlock

	VMOV TW.B16, B4.B16
	mul2GBInline
	loadOneBlock
	MOVD rkSave, rk
	EOR R13, R13

decLastCompleteBlockLoop:	
		SM4_ROUND(rk, R19, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, R19, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, R19, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, R19, K0, K1, K2, B3, B0, B1, B2)
		ADD $1, R13
		CMP $8, R13
		BNE decLastCompleteBlockLoop
	storeOneBlock
	VMOV B4.B16, TW.B16
	VST1 [B3.B16], (RSP)

	SUB $16, dstPtr, R7
	MOVD R7, R9
	MOVD RSP, R8

	TBZ	$3, srcPtrLen, less_than8
	MOVD.P 8(srcPtr), R11
	MOVD.P R11, 8(R8)
	MOVD.P 8(R7), R12
	MOVD.P R12, 8(dstPtr)

less_than8:
	TBZ	$2, srcPtrLen, less_than4
	MOVWU.P 4(srcPtr), R11
	MOVWU.P R11, 4(R8)
	MOVWU.P 4(R7), R12
	MOVWU.P R12, 4(dstPtr)

less_than4:
	TBZ	$1, srcPtrLen, less_than2
	MOVHU.P 2(srcPtr), R11
	MOVHU.P R11, 2(R8)
	MOVHU.P 2(R7), R12
	MOVHU.P R12, 2(dstPtr)

less_than2:
	TBZ	$0, srcPtrLen, xtsSm4DecTailDec
	MOVBU (srcPtr), R11
	MOVBU R11, (R8)
	MOVBU (R7), R12
	MOVBU R12, (dstPtr)

xtsSm4DecTailDec:
	VLD1 (RSP), [B0.B16]
	VEOR TW.B16, B0.B16, B0.B16
	VREV32 B0.B16, B0.B16
	VMOV B0.S[1], B1.S[0]
	VMOV B0.S[2], B2.S[0]
	VMOV B0.S[3], B3.S[0]

	MOVD rkSave, rk
	EOR R13, R13

tailDecLoop:
		SM4_ROUND(rk, R19, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, R19, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, R19, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, R19, K0, K1, K2, B3, B0, B1, B2)
		ADD $1, R13
		CMP $8, R13
		BNE tailDecLoop

	VMOV B2.S[0], B3.S[1]
	VMOV B1.S[0], B3.S[2]
	VMOV B0.S[0], B3.S[3]
	VREV32 B3.B16, B3.B16

	VEOR TW.B16, B3.B16, B3.B16
	VST1 [B3.B16], (R9)

	B xtsSm4DecDone

xtsSm4DecLastBlock:
	loadOneBlock

	MOVD rkSave, rk
	EOR R13, R13

decLastBlockLoop:	
		SM4_ROUND(rk, R19, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, R19, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, R19, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, R19, K0, K1, K2, B3, B0, B1, B2)
		ADD $1, R13
		CMP $8, R13
		BNE decLastBlockLoop

	storeOneBlock
	mul2GBInline

xtsSm4DecDone:
	VST1 [TW.B16], (twPtr)
	RET
