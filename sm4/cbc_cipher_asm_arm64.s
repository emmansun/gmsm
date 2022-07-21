//go:build arm64 && !generic
// +build arm64,!generic

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

#define SM4_ROUND(RK, x, y, z, t0, t1, t2, t3)  \ 
	MOVW.P 4(RK), R19;                                \
	VMOV R19, x.S4;                                   \
	VEOR t1.B16, x.B16, x.B16;                        \
	VEOR t2.B16, x.B16, x.B16;                        \
	VEOR t3.B16, x.B16, x.B16;                        \
	SM4_TAO_L1(x, y, z);                              \
	VEOR x.B16, t0.B16, t0.B16

#define load_global_data_1() \
	LDP nibble_mask<>(SB), (R0, R1)         \
	VMOV R0, NIBBLE_MASK.D[0]               \
	VMOV R1, NIBBLE_MASK.D[1]               \
	LDP m1_low<>(SB), (R0, R1)              \
	VMOV R0, M1L.D[0]                       \
	VMOV R1, M1L.D[1]                       \
	LDP m1_high<>(SB), (R0, R1)             \
	VMOV R0, M1H.D[0]                       \
	VMOV R1, M1H.D[1]                       \
	LDP m2_low<>(SB), (R0, R1)              \
	VMOV R0, M2L.D[0]                       \
	VMOV R1, M2L.D[1]                       \
	LDP m2_high<>(SB), (R0, R1)             \
	VMOV R0, M2H.D[0]                       \
	VMOV R1, M2H.D[1]                       \
	LDP fk_mask<>(SB), (R0, R1)             \
	VMOV R0, FK_MASK.D[0]                   \
	VMOV R1, FK_MASK.D[1]                   \
	LDP inverse_shift_rows<>(SB), (R0, R1)  \
	VMOV R0, INVERSE_SHIFT_ROWS.D[0]        \
	VMOV R1, INVERSE_SHIFT_ROWS.D[1]  

#define load_global_data_2() \
	load_global_data_1()         \
	LDP r08_mask<>(SB), (R0, R1) \
	VMOV R0, R08_MASK.D[0]       \
	VMOV R1, R08_MASK.D[1]       \
	LDP r16_mask<>(SB), (R0, R1) \
	VMOV R0, R16_MASK.D[0]       \
	VMOV R1, R16_MASK.D[1]       \
	LDP r24_mask<>(SB), (R0, R1) \
	VMOV R0, R24_MASK.D[0]       \
	VMOV R1, R24_MASK.D[1]

// func encryptBlocksChain(xk *uint32, dst, src []byte, iv *byte)
TEXT ·encryptBlocksChain(SB),NOSPLIT,$0
#define ctx R1
#define ptx R3
#define ptxLen R4
#define rkSave R8

    load_global_data_2()

	MOVD xk+0(FP), rkSave
	MOVD dst+8(FP), ctx
	MOVD src+32(FP), ptx
	MOVD src_len+40(FP), ptxLen
	MOVD iv+56(FP), R5
    
    VEOR ZERO.B16, ZERO.B16, ZERO.B16

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
	SM4_ROUND(R0, x, y, XTMP6, t0, t1, t2, t3)
	SM4_ROUND(R0, x, y, XTMP6, t1, t2, t3, t0)
	SM4_ROUND(R0, x, y, XTMP6, t2, t3, t0, t1)
	SM4_ROUND(R0, x, y, XTMP6, t3, t0, t1, t2)

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
