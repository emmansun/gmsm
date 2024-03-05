//go:build !purego

#include "textflag.h"

#define x V0
#define y V1
#define t0 V2
#define t1 V3
#define t2 V4
#define t3 V5
#define ZERO V16
#define NIBBLE_MASK V20
#define INVERSE_SHIFT_ROWS V21
#define M1L V22
#define M1H V23 
#define M2L V24 
#define M2H V25
#define R08_MASK V26 
#define FK_MASK V27
#define XTMP6 V6
#define XTMP7 V7
#define t4 V10
#define t5 V11
#define t6 V12
#define t7 V13

#include "aesni_macros_arm64.s"

// func encryptSm4Ecb(xk *uint32, dst, src []byte)
TEXT ·encryptSm4Ecb(SB),NOSPLIT,$0
#define dstPtr R1
#define srcPtr R2
#define rk R3
#define rkSave R4
#define srcPtrLen R5
	LOAD_SM4_AESNI_CONSTS()
	VEOR ZERO.B16, ZERO.B16, ZERO.B16

	MOVD xk+0(FP), rk
	MOVD dst+8(FP), dstPtr
	MOVD src+32(FP), srcPtr
	MOVD src_len+40(FP), srcPtrLen
	MOVD rk, rkSave

ecbSm4Octets:
	CMP	$128, srcPtrLen
	BLT	ecbSm4Nibbles
	SUB	$128, srcPtrLen
	MOVD rkSave, rk

	VLD1.P 64(srcPtr), [t0.S4, t1.S4, t2.S4, t3.S4]
	VLD1.P 64(srcPtr), [t4.S4, t5.S4, t6.S4, t7.S4]
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

ecb8BlocksLoop:
		SM4_8BLOCKS_ROUND(rk, R6, x, y, XTMP6, XTMP7, t0, t1, t2, t3, t4, t5, t6, t7)
		SM4_8BLOCKS_ROUND(rk, R6, x, y, XTMP6, XTMP7, t1, t2, t3, t0, t5, t6, t7, t4)
		SM4_8BLOCKS_ROUND(rk, R6, x, y, XTMP6, XTMP7, t2, t3, t0, t1, t6, t7, t4, t5)
		SM4_8BLOCKS_ROUND(rk, R6, x, y, XTMP6, XTMP7, t3, t0, t1, t2, t7, t4, t5, t6)

		ADD $16, R0
		CMP $128, R0
		BNE ecb8BlocksLoop

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

	VST1.P [t0.S4, t1.S4, t2.S4, t3.S4], 64(dstPtr)
	VST1.P [t4.S4, t5.S4, t6.S4, t7.S4], 64(dstPtr)

	B ecbSm4Octets

ecbSm4Nibbles:
	CMP	$64, srcPtrLen
	BLT	ecbSm4Single
	SUB	$64, srcPtrLen
	MOVD rkSave, rk

	VLD1.P 64(srcPtr), [t0.S4, t1.S4, t2.S4, t3.S4]
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	VREV32 t2.B16, t2.B16
	VREV32 t3.B16, t3.B16
	PRE_TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)

	EOR R0, R0

ecb4BlocksLoop:
		SM4_ROUND(rk, R6, x, y, XTMP6, t0, t1, t2, t3)
		SM4_ROUND(rk, R6, x, y, XTMP6, t1, t2, t3, t0)
		SM4_ROUND(rk, R6, x, y, XTMP6, t2, t3, t0, t1)
		SM4_ROUND(rk, R6, x, y, XTMP6, t3, t0, t1, t2)

		ADD $16, R0
		CMP $128, R0
		BNE ecb4BlocksLoop

	TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	VREV32 t2.B16, t2.B16
	VREV32 t3.B16, t3.B16
	VST1.P [t0.S4, t1.S4, t2.S4, t3.S4], 64(dstPtr)

ecbSm4Single:
	CBZ	srcPtrLen, ecbSm4Done
	MOVD rkSave, rk
	EOR R0, R0

	CMP $32, srcPtrLen
	BEQ ecbSm4Single32

	CMP $48, srcPtrLen
	BEQ ecbSm4Single48

ecbSm4Single16:
	VLD1.P 16(srcPtr), [t0.S4]
	VREV32 t0.B16, t0.B16
	VMOV t0.S[1], t1.S[0]
	VMOV t0.S[2], t2.S[0]
	VMOV t0.S[3], t3.S[0]

encryptBlocksLoop1:
		SM4_ROUND(rk, R6, x, y, XTMP6, t0, t1, t2, t3)
		SM4_ROUND(rk, R6, x, y, XTMP6, t1, t2, t3, t0)
		SM4_ROUND(rk, R6, x, y, XTMP6, t2, t3, t0, t1)
		SM4_ROUND(rk, R6, x, y, XTMP6, t3, t0, t1, t2)

		ADD $16, R0
		CMP $128, R0
		BNE encryptBlocksLoop1

	VMOV t2.S[0], t3.S[1]
	VMOV t1.S[0], t3.S[2]
	VMOV t0.S[0], t3.S[3]
	VREV32 t3.B16, t3.B16
	VST1.P [t3.S4], 16(dstPtr)

	B ecbSm4Done

ecbSm4Single32:
	VLD1.P 32(srcPtr), [t0.S4, t1.S4]
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	PRE_TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)

encryptBlocksLoop2:
		SM4_ROUND(rk, R6, x, y, XTMP6, t0, t1, t2, t3)
		SM4_ROUND(rk, R6, x, y, XTMP6, t1, t2, t3, t0)
		SM4_ROUND(rk, R6, x, y, XTMP6, t2, t3, t0, t1)
		SM4_ROUND(rk, R6, x, y, XTMP6, t3, t0, t1, t2)

		ADD $16, R0
		CMP $128, R0
		BNE encryptBlocksLoop2

	TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	VST1.P [t0.S4, t1.S4], 32(dstPtr)

	B ecbSm4Done

ecbSm4Single48:
	VLD1.P 48(srcPtr), [t0.S4, t1.S4, t2.S4]
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	VREV32 t2.B16, t2.B16
    PRE_TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)

encryptBlocksLoop3:
		SM4_ROUND(rk, R6, x, y, XTMP6, t0, t1, t2, t3)
		SM4_ROUND(rk, R6, x, y, XTMP6, t1, t2, t3, t0)
		SM4_ROUND(rk, R6, x, y, XTMP6, t2, t3, t0, t1)
		SM4_ROUND(rk, R6, x, y, XTMP6, t3, t0, t1, t2)

		ADD $16, R0
		CMP $128, R0
		BNE encryptBlocksLoop3

	TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	VREV32 t2.B16, t2.B16
	VST1.P [t0.S4, t1.S4, t2.S4], 48(dstPtr)
ecbSm4Done:
	RET
