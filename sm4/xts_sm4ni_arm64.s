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

#define POLY V8
#define ZERO V9
#define TW V10

#define T0 V11
#define T1 V12
#define T2 V13
#define T3 V14
#define T4 V15
#define T5 V16
#define T6 V17
#define T7 V18

#define RK0 V19
#define RK1 V20
#define RK2 V21
#define RK3 V22
#define RK4 V23
#define RK5 V24
#define RK6 V25
#define RK7 V26

#define K0 V27
#define K1 V28

#include "sm4ni_macros_arm64.s"
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
	VREV32 B7.B16, B7.B16

#define store8blocks \
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

#define dstPtr R2
#define srcPtr R3
#define rk R0
#define twPtr R1
#define srcPtrLen R4
#define I R5

// func encryptSm4NiXts(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)
TEXT ·encryptSm4NiXts(SB),0,$128-64
	MOVD xk+0(FP), rk
	MOVD tweak+8(FP), twPtr
	MOVD dst+16(FP), dstPtr
	MOVD src+40(FP), srcPtr
	MOVD src_len+48(FP), srcPtrLen

	VEOR	POLY.B16, POLY.B16, POLY.B16
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	MOVD	$0x87, I
	VMOV	I, POLY.D[0]

	// For SM4 round keys are stored in: RK0 .. RK7
	VLD1.P	64(rk), [RK0.S4, RK1.S4, RK2.S4, RK3.S4]
	VLD1.P	64(rk), [RK4.S4, RK5.S4, RK6.S4, RK7.S4]

	VLD1 (twPtr), [TW.B16]

xtsSm4EncOctets:
	CMP	$128, srcPtrLen
	BLT	xtsSm4EncSingles
	SUB	$128, srcPtrLen
	prepare8Tweaks
	load8blocks
	sm4eEnc8blocks()
	store8blocks

	B	xtsSm4EncOctets

xtsSm4EncSingles:
	CMP	$16, srcPtrLen
	BLT	xtsSm4EncTail
	SUB	$16, srcPtrLen

	VLD1.P 16(srcPtr), [B0.S4]
	VEOR TW.B16, B0.B16, B0.B16
	VREV32 B0.B16, B0.B16
	sm4eEnc1block()
	VEOR TW.B16, B0.B16, B0.B16
	VST1.P [B0.S4], 16(dstPtr)

	mul2Inline
	B xtsSm4EncSingles

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
	sm4eEnc1block()
	VEOR TW.B16, B0.B16, B0.B16
	VST1 [B0.B16], (R9)

xtsSm4EncDone:
	VST1 [TW.B16], (twPtr)
	RET

// func encryptSm4NiXtsGB(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)
TEXT ·encryptSm4NiXtsGB(SB),0,$128-64
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

	// For SM4 round keys are stored in: RK0 .. RK7
	VLD1.P	64(rk), [RK0.S4, RK1.S4, RK2.S4, RK3.S4]
	VLD1.P	64(rk), [RK4.S4, RK5.S4, RK6.S4, RK7.S4]

	VLD1 (twPtr), [TW.B16]

xtsSm4EncOctets:
	CMP	$128, srcPtrLen
	BLT	xtsSm4EncSingles
	SUB	$128, srcPtrLen
	prepareGB8Tweaks
	load8blocks
	sm4eEnc8blocks()
	store8blocks

	B	xtsSm4EncOctets

xtsSm4EncSingles:
	CMP	$16, srcPtrLen
	BLT	xtsSm4EncTail
	SUB	$16, srcPtrLen

	VLD1.P 16(srcPtr), [B0.S4]
	VEOR TW.B16, B0.B16, B0.B16
	VREV32 B0.B16, B0.B16
	sm4eEnc1block()
	VEOR TW.B16, B0.B16, B0.B16
	VST1.P [B0.S4], 16(dstPtr)

	mul2GBInline
	B xtsSm4EncSingles

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
	sm4eEnc1block()
	VEOR TW.B16, B0.B16, B0.B16
	VST1 [B0.B16], (R9)

xtsSm4EncDone:
	VST1 [TW.B16], (twPtr)
    RET

// func decryptSm4NiXts(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)
TEXT ·decryptSm4NiXts(SB),0,$128-64
	MOVD xk+0(FP), rk
	MOVD tweak+8(FP), twPtr
	MOVD dst+16(FP), dstPtr
	MOVD src+40(FP), srcPtr
	MOVD src_len+48(FP), srcPtrLen

	VEOR	POLY.B16, POLY.B16, POLY.B16
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	MOVD	$0x87, I
	VMOV	I, POLY.D[0]

	// For SM4 round keys are stored in: RK0 .. RK7
	VLD1.P	64(rk), [RK0.S4, RK1.S4, RK2.S4, RK3.S4]
	VLD1.P	64(rk), [RK4.S4, RK5.S4, RK6.S4, RK7.S4]

	VLD1 (twPtr), [TW.B16]

xtsSm4DecOctets:
	CMP	$128, srcPtrLen
	BLT	xtsSm4DecSingles
	SUB	$128, srcPtrLen

	prepare8Tweaks
	load8blocks
	sm4eEnc8blocks()
	store8blocks

	B xtsSm4DecOctets

xtsSm4DecSingles:
	CMP	$32, srcPtrLen
	BLT	xtsSm4DecTail
	SUB	$16, srcPtrLen

	VLD1.P 16(srcPtr), [B0.S4]
	VEOR TW.B16, B0.B16, B0.B16
	VREV32 B0.B16, B0.B16
	sm4eEnc1block()
	VEOR TW.B16, B0.B16, B0.B16
	VST1.P [B0.S4], 16(dstPtr)

	mul2Inline
	B xtsSm4DecSingles

xtsSm4DecTail:
	CBZ	srcPtrLen, xtsSm4DecDone
	
	CMP	$16, srcPtrLen
	BEQ xtsSm4DecLastBlock

	VMOV TW.B16, B4.B16
	mul2Inline
	VLD1.P 16(srcPtr), [B0.S4]
	VEOR TW.B16, B0.B16, B0.B16
	VREV32 B0.B16, B0.B16
	sm4eEnc1block()
	VEOR TW.B16, B0.B16, B0.B16
	VST1.P [B0.S4], 16(dstPtr)
	VMOV B4.B16, TW.B16
	VST1 [B0.B16], (RSP)

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
	sm4eEnc1block()
	VEOR TW.B16, B0.B16, B0.B16
	VST1 [B0.B16], (R9)

	B xtsSm4DecDone

xtsSm4DecLastBlock:
	VLD1.P 16(srcPtr), [B0.S4]
	VEOR TW.B16, B0.B16, B0.B16
	VREV32 B0.B16, B0.B16
	sm4eEnc1block()
	VEOR TW.B16, B0.B16, B0.B16
	VST1.P [B0.S4], 16(dstPtr)
	mul2Inline

xtsSm4DecDone:
	VST1 [TW.B16], (twPtr)
    RET

// func decryptSm4NiXtsGB(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)
TEXT ·decryptSm4NiXtsGB(SB),0,$128-64
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

	// For SM4 round keys are stored in: RK0 .. RK7
	VLD1.P	64(rk), [RK0.S4, RK1.S4, RK2.S4, RK3.S4]
	VLD1.P	64(rk), [RK4.S4, RK5.S4, RK6.S4, RK7.S4]

	VLD1 (twPtr), [TW.B16]

xtsSm4DecOctets:
	CMP	$128, srcPtrLen
	BLT	xtsSm4DecSingles
	SUB	$128, srcPtrLen

	prepareGB8Tweaks
	load8blocks
	sm4eEnc8blocks()
	store8blocks

	B xtsSm4DecOctets

xtsSm4DecSingles:
	CMP	$32, srcPtrLen
	BLT	xtsSm4DecTail
	SUB	$16, srcPtrLen

	VLD1.P 16(srcPtr), [B0.S4]
	VEOR TW.B16, B0.B16, B0.B16
	VREV32 B0.B16, B0.B16
	sm4eEnc1block()
	VEOR TW.B16, B0.B16, B0.B16
	VST1.P [B0.S4], 16(dstPtr)

	mul2GBInline
	B xtsSm4DecSingles

xtsSm4DecTail:
	CBZ	srcPtrLen, xtsSm4DecDone
	
	CMP	$16, srcPtrLen
	BEQ xtsSm4DecLastBlock

	VMOV TW.B16, B4.B16
	mul2GBInline
	VLD1.P 16(srcPtr), [B0.S4]
	VEOR TW.B16, B0.B16, B0.B16
	VREV32 B0.B16, B0.B16
	sm4eEnc1block()
	VEOR TW.B16, B0.B16, B0.B16
	VST1.P [B0.S4], 16(dstPtr)
	VMOV B4.B16, TW.B16
	VST1 [B0.B16], (RSP)

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
	sm4eEnc1block()
	VEOR TW.B16, B0.B16, B0.B16
	VST1 [B0.B16], (R9)

	B xtsSm4DecDone

xtsSm4DecLastBlock:
	VLD1.P 16(srcPtr), [B0.S4]
	VEOR TW.B16, B0.B16, B0.B16
	VREV32 B0.B16, B0.B16
	sm4eEnc1block()
	VEOR TW.B16, B0.B16, B0.B16
	VST1.P [B0.S4], 16(dstPtr)
	mul2GBInline

xtsSm4DecDone:
	VST1 [TW.B16], (twPtr)
    RET
