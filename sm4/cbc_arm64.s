//go:build !purego

#include "textflag.h"

#define x V0
#define y V1
#define t0 V2
#define t1 V3
#define t2 V4
#define t3 V5
#define XTMP6 V6
#define XTMP7 V7
#define t4 V10
#define t5 V11
#define t6 V12
#define t7 V13
#define IV V18

#define ZERO V16
#define NIBBLE_MASK V20
#define INVERSE_SHIFT_ROWS V21
#define M1L V22
#define M1H V23 
#define M2L V24 
#define M2H V25
#define R08_MASK V26 
#define FK_MASK V27

#include "aesni_macros_arm64.s"

#define dstPtr R1
#define srcPtr R2
#define rk R3
#define rkSave R4
#define srcPtrLen R5

// func decryptBlocksChain(xk *uint32, dst, src []byte, iv *byte)
TEXT ·decryptBlocksChain(SB),NOSPLIT,$0
	LOAD_SM4_AESNI_CONSTS()
	VEOR ZERO.B16, ZERO.B16, ZERO.B16

	MOVD xk+0(FP), rk
	MOVD dst+8(FP), dstPtr
	MOVD src+32(FP), srcPtr
	MOVD src_len+40(FP), srcPtrLen
	MOVD iv+56(FP), R6
	MOVD rk, rkSave
	VLD1 (R6), [IV.B16]

	ADD srcPtr, srcPtrLen, R10
	SUB $16, R10, R10
	VLD1 (R10), [V15.S4]

cbcSm4Octets:
	CMP	$128, srcPtrLen
	BLE	cbcSm4Nibbles
	SUB	$128, srcPtrLen
	MOVD rkSave, rk
	ADD srcPtr, srcPtrLen, R10
	SUB $16, R10, R11
	ADD dstPtr, srcPtrLen, R12

	VLD1.P 64(R10), [t0.S4, t1.S4, t2.S4, t3.S4]
	VLD1.P 64(R10), [t4.S4, t5.S4, t6.S4, t7.S4]
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	VREV32 t2.B16, t2.B16
	VREV32 t3.B16, t3.B16
	VREV32 t4.B16, t4.B16
	VREV32 t5.B16, t5.B16
	VREV32 t6.B16, t6.B16
	VREV32 t7.B16, t7.B16

	PRE_TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)
	PRE_TRANSPOSE_MATRIX(t4, t5, t6, t7, x, y, XTMP6, XTMP7)
	EOR R0, R0

cbc8BlocksLoop:
		SM4_8BLOCKS_ROUND(rk, R19, x, y, XTMP6, XTMP7, t0, t1, t2, t3, t4, t5, t6, t7)
		SM4_8BLOCKS_ROUND(rk, R19, x, y, XTMP6, XTMP7, t1, t2, t3, t0, t5, t6, t7, t4)
		SM4_8BLOCKS_ROUND(rk, R19, x, y, XTMP6, XTMP7, t2, t3, t0, t1, t6, t7, t4, t5)
		SM4_8BLOCKS_ROUND(rk, R19, x, y, XTMP6, XTMP7, t3, t0, t1, t2, t7, t4, t5, t6)

		ADD $16, R0
		CMP $128, R0
		BNE cbc8BlocksLoop

	TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)
	TRANSPOSE_MATRIX(t4, t5, t6, t7, x, y, XTMP6, XTMP7)
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	VREV32 t2.B16, t2.B16
	VREV32 t3.B16, t3.B16
	VREV32 t4.B16, t4.B16
	VREV32 t5.B16, t5.B16
	VREV32 t6.B16, t6.B16
	VREV32 t7.B16, t7.B16

	VLD1.P 64(R11), [V6.S4, V7.S4, V8.S4, V9.S4]
	VEOR V6.B16, t0.B16, t0.B16
	VEOR V7.B16, t1.B16, t1.B16
	VEOR V8.B16, t2.B16, t2.B16
	VEOR V9.B16, t3.B16, t3.B16

	VLD1.P 64(R11), [V6.S4, V7.S4, V8.S4, V9.S4]
	VEOR V6.B16, t4.B16, t4.B16
	VEOR V7.B16, t5.B16, t5.B16
	VEOR V8.B16, t6.B16, t6.B16
	VEOR V9.B16, t7.B16, t7.B16

	VST1.P [t0.S4, t1.S4, t2.S4, t3.S4], 64(R12)
	VST1.P [t4.S4, t5.S4, t6.S4, t7.S4], 64(R12)

	B cbcSm4Octets

cbcSm4Nibbles:
	CMP	$64, srcPtrLen
	BLE	cbcSm4Single
	SUB	$64, srcPtrLen
	MOVD rkSave, rk
	ADD srcPtr, srcPtrLen, R10
	SUB $16, R10, R11
	ADD dstPtr, srcPtrLen, R12

	VLD1 (R10), [t0.S4, t1.S4, t2.S4, t3.S4]
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	VREV32 t2.B16, t2.B16
	VREV32 t3.B16, t3.B16
	PRE_TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)

	EOR R0, R0

cbc4BlocksLoop:
		SM4_ROUND(rk, R19, x, y, XTMP6, t0, t1, t2, t3)
		SM4_ROUND(rk, R19, x, y, XTMP6, t1, t2, t3, t0)
		SM4_ROUND(rk, R19, x, y, XTMP6, t2, t3, t0, t1)
		SM4_ROUND(rk, R19, x, y, XTMP6, t3, t0, t1, t2)

		ADD $16, R0
		CMP $128, R0
		BNE cbc4BlocksLoop

	TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	VREV32 t2.B16, t2.B16
	VREV32 t3.B16, t3.B16

	VLD1 (R11), [V6.S4, V7.S4, V8.S4, V9.S4]
	VEOR V6.B16, t0.B16, t0.B16
	VEOR V7.B16, t1.B16, t1.B16
	VEOR V8.B16, t2.B16, t2.B16
	VEOR V9.B16, t3.B16, t3.B16

	VST1 [t0.S4, t1.S4, t2.S4, t3.S4], (R12)

cbcSm4Single:
	MOVD rkSave, rk
	EOR R0, R0

	CMP $16, srcPtrLen
	BEQ cbcSm4Single16

	CMP $32, srcPtrLen
	BEQ cbcSm4Single32

	CMP $48, srcPtrLen
	BEQ cbcSm4Single48

	// 4 blocks
	VLD1 (srcPtr), [t0.S4, t1.S4, t2.S4, t3.S4]
	VMOV t0.B16, V6.B16
	VMOV t1.B16, V7.B16
	VMOV t2.B16, V8.B16
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	VREV32 t2.B16, t2.B16
	VREV32 t3.B16, t3.B16
	PRE_TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)

cbc4BlocksLoop64:
		SM4_ROUND(rk, R19, x, y, XTMP6, t0, t1, t2, t3)
		SM4_ROUND(rk, R19, x, y, XTMP6, t1, t2, t3, t0)
		SM4_ROUND(rk, R19, x, y, XTMP6, t2, t3, t0, t1)
		SM4_ROUND(rk, R19, x, y, XTMP6, t3, t0, t1, t2)

		ADD $16, R0
		CMP $128, R0
		BNE cbc4BlocksLoop64

	TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	VREV32 t2.B16, t2.B16
	VREV32 t3.B16, t3.B16

	VEOR IV.B16, t0.B16, t0.B16
	VEOR V6.B16, t1.B16, t1.B16
	VEOR V7.B16, t2.B16, t2.B16
	VEOR V8.B16, t3.B16, t3.B16

	VST1 [t0.S4, t1.S4, t2.S4, t3.S4], (dstPtr)

	B cbcSm4Done

cbcSm4Single16:
	VLD1 (srcPtr), [t0.S4]
	VREV32 t0.B16, t0.B16
	VMOV t0.S[1], t1.S[0]
	VMOV t0.S[2], t2.S[0]
	VMOV t0.S[3], t3.S[0]

cbc4BlocksLoop16:
		SM4_ROUND(rk, R19, x, y, XTMP6, t0, t1, t2, t3)
		SM4_ROUND(rk, R19, x, y, XTMP6, t1, t2, t3, t0)
		SM4_ROUND(rk, R19, x, y, XTMP6, t2, t3, t0, t1)
		SM4_ROUND(rk, R19, x, y, XTMP6, t3, t0, t1, t2)

		ADD $16, R0
		CMP $128, R0
		BNE cbc4BlocksLoop16

	VMOV t2.S[0], t3.S[1]
	VMOV t1.S[0], t3.S[2]
	VMOV t0.S[0], t3.S[3]
	VREV32 t3.B16, t3.B16

	VEOR IV.B16, t3.B16, t3.B16

	VST1 [t3.S4], (dstPtr)

	B cbcSm4Done

cbcSm4Single32:
	VLD1 (srcPtr), [t0.S4, t1.S4]
	VMOV t0.B16, V6.B16
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	PRE_TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)

cbc4BlocksLoop32:
		SM4_ROUND(rk, R19, x, y, XTMP6, t0, t1, t2, t3)
		SM4_ROUND(rk, R19, x, y, XTMP6, t1, t2, t3, t0)
		SM4_ROUND(rk, R19, x, y, XTMP6, t2, t3, t0, t1)
		SM4_ROUND(rk, R19, x, y, XTMP6, t3, t0, t1, t2)

		ADD $16, R0
		CMP $128, R0
		BNE cbc4BlocksLoop32

	TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16

	VEOR IV.B16, t0.B16, t0.B16
	VEOR V6.B16, t1.B16, t1.B16

	VST1 [t0.S4, t1.S4], (dstPtr)
	B cbcSm4Done

cbcSm4Single48:
	VLD1 (srcPtr), [t0.S4, t1.S4, t2.S4]
	VMOV t0.B16, V6.B16
	VMOV t1.B16, V7.B16
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	VREV32 t2.B16, t2.B16
	PRE_TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)

cbc4BlocksLoop48:
		SM4_ROUND(rk, R19, x, y, XTMP6, t0, t1, t2, t3)
		SM4_ROUND(rk, R19, x, y, XTMP6, t1, t2, t3, t0)
		SM4_ROUND(rk, R19, x, y, XTMP6, t2, t3, t0, t1)
		SM4_ROUND(rk, R19, x, y, XTMP6, t3, t0, t1, t2)

		ADD $16, R0
		CMP $128, R0
		BNE cbc4BlocksLoop48

	TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	VREV32 t2.B16, t2.B16

	VEOR IV.B16, t0.B16, t0.B16
	VEOR V6.B16, t1.B16, t1.B16
	VEOR V7.B16, t2.B16, t2.B16

	VST1 [t0.S4, t1.S4, t2.S4], (dstPtr)

cbcSm4Done:
	VST1 [V15.S4], (R6)
	RET
