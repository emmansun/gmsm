//go:build arm64 && !purego
// +build arm64,!purego

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
#define R16_MASK V27
#define R24_MASK V28
#define FK_MASK V29
#define XTMP6 V6
#define IV V7

#include "aesni_arm64.h"

// func encryptBlocksChain(xk *uint32, dst, src []byte, iv *byte)
TEXT ·encryptBlocksChain(SB),NOSPLIT,$0
#define ctx R1
#define ptx R3
#define ptxLen R4
#define rkSave R8

	LOAD_SM4_AESNI_CONSTS()

	MOVD xk+0(FP), rkSave
	MOVD dst+8(FP), ctx
	MOVD src+32(FP), ptx
	MOVD src_len+40(FP), ptxLen
	MOVD iv+56(FP), R5

	VEOR ZERO.B16, ZERO.B16, ZERO.B16
	VLD1 (R5), [IV.B16]

loopSrc:
		CMP	$16, ptxLen
		BLT	done_sm4
		SUB	$16, ptxLen

		VLD1.P (ptx), [t0.S4]
		VEOR IV.B16, t0.B16, t0.B16
		VREV32 t0.B16, t0.B16
		VMOV t0.S[1], t1.S[0]
		VMOV t0.S[2], t2.S[0]
		VMOV t0.S[3], t3.S[0]

		EOR R2, R2
		MOVD rkSave, R0

encryptBlockLoop:
			SM4_ROUND(R0, R19, x, y, XTMP6, t0, t1, t2, t3)
			SM4_ROUND(R0, R19, x, y, XTMP6, t1, t2, t3, t0)
			SM4_ROUND(R0, R19, x, y, XTMP6, t2, t3, t0, t1)
			SM4_ROUND(R0, R19, x, y, XTMP6, t3, t0, t1, t2)

			ADD $16, R2
			CMP $128, R2
			BNE encryptBlockLoop

		VMOV t2.S[0], t3.S[1]
		VMOV t1.S[0], t3.S[2]
		VMOV t0.S[0], t3.S[3]
		VREV32 t3.B16, t3.B16

		VST1.P [t3.B16], (ctx)
		VMOV t3.B16, IV.B16

		B loopSrc

done_sm4:
	VST1 [IV.B16], (R5)
	RET

#undef ctx
#undef ptx
#undef ptxLen
#undef rkSave

// func decryptBlocksChain(xk *uint32, dst, src []byte, iv *byte)
TEXT ·decryptBlocksChain(SB),NOSPLIT,$0
	LOAD_SM4_AESNI_CONSTS()

	MOVD xk+0(FP), R8
	MOVD dst+8(FP), R9
	MOVD src+32(FP), R10
	MOVD src_len+40(FP), R12
	MOVD iv+56(FP), R11


	VLD1 (R10), [t0.S4, t1.S4, t2.S4, t3.S4]
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	VREV32 t2.B16, t2.B16
	VREV32 t3.B16, t3.B16
	PRE_TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)

	VEOR ZERO.B16, ZERO.B16, ZERO.B16
	EOR R0, R0

encryptBlocksLoop:
		SM4_ROUND(R8, R19, x, y, XTMP6, t0, t1, t2, t3)
		SM4_ROUND(R8, R19, x, y, XTMP6, t1, t2, t3, t0)
		SM4_ROUND(R8, R19, x, y, XTMP6, t2, t3, t0, t1)
		SM4_ROUND(R8, R19, x, y, XTMP6, t3, t0, t1, t2)

		ADD $16, R0
		CMP $128, R0
		BNE encryptBlocksLoop

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

	VST1 [t0.S4, t1.S4, t2.S4, t3.S4], (R9)
	RET
