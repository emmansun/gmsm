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
#define XTMP7 V7

#include "aesni_arm64.h"

#define SM4_TAO_L2(x, y)         \
	SM4_SBOX(x, y, XTMP6);                      \
	;                                           \ //####################  4 parallel L2 linear transforms ##################//
	VSHL $13, x.S4, XTMP6.S4;                   \
	VUSHR $19, x.S4, y.S4;                      \
	VORR XTMP6.B16, y.B16, y.B16;               \
	VSHL $23, x.S4, XTMP6.S4;                   \
	VUSHR $9, x.S4, XTMP7.S4;                   \
	VORR XTMP6.B16, XTMP7.B16, XTMP7.B16;       \
	VEOR XTMP7.B16, y.B16, y.B16;               \
	VEOR x.B16, y.B16, x.B16

#define SM4_EXPANDKEY_ROUND(x, y, t0, t1, t2, t3) \
	MOVW.P 4(R9), R19;                               \
	VMOV R19, x.S[0];                                \
	VEOR t1.B16, x.B16, x.B16;                       \
	VEOR t2.B16, x.B16, x.B16;                       \
	VEOR t3.B16, x.B16, x.B16;                       \
	SM4_TAO_L2(x, y);                                \
	VEOR x.B16, t0.B16, t0.B16;                      \
	VMOV t0.S[0], R2;                                \
	MOVW.P R2, 4(R10);                               \
	MOVW.P R2, -4(R11)

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

#define SM4EKEY_EXPORT_KEYS() \
	VMOV V9.S[3], V10.S[0]            \
	VMOV V9.S[2], V10.S[1]            \
	VMOV V9.S[1], V10.S[2]            \
	VMOV V9.S[0], V10.S[3]            \
	VMOV V8.S[3], V11.S[0]            \
	VMOV V8.S[2], V11.S[1]            \
	VMOV V8.S[1], V11.S[2]            \
	VMOV V8.S[0], V11.S[3]            \
	VST1.P	[V8.S4, V9.S4], 32(R10)   \
	VST1	[V10.S4, V11.S4], (R11)   \
	SUB  $32, R11, R11

#define SM4E_ROUND() \
	VLD1.P 16(R10), [V8.B16]    \
	VREV32 V8.B16, V8.B16       \
	WORD $0xcec08408            \ //SM4E V8.4S, V0.4S
	WORD $0xcec08428            \ //SM4E V8.4S, V1.4S
	WORD $0xcec08448            \ //SM4E V8.4S, V2.4S
	WORD $0xcec08468            \ //SM4E V8.4S, V3.4S
	WORD $0xcec08488            \ //SM4E V8.4S, V4.4S
	WORD $0xcec084a8            \ //SM4E V8.4S, V5.4S
	WORD $0xcec084c8            \ //SM4E V8.4S, V6.4S
	WORD $0xcec084e8            \ //SM4E V8.4S, V7.4S
	VREV64	V8.S4, V8.S4               \ 
	VEXT $8, V8.B16, V8.B16, V8.B16    \	
	VREV32 V8.B16, V8.B16              \
	VST1.P  [V8.B16], 16(R9)

// func expandKeyAsm(key *byte, ck, enc, dec *uint32, inst int)
TEXT ·expandKeyAsm(SB),NOSPLIT,$0
	MOVD key+0(FP), R8
	MOVD ck+8(FP), R9
	MOVD enc+16(FP), R10
	MOVD dec+24(FP), R11
	MOVD inst+32(FP), R12

	CMP $1, R12
	BEQ sm4ekey

	load_global_data_1()
	
	VLD1 (R8), [t0.B16]
	VREV32 t0.B16, t0.B16
	VEOR t0.B16, FK_MASK.B16, t0.B16
	VMOV t0.S[1], t1.S[0]
	VMOV t0.S[2], t2.S[0]
	VMOV t0.S[3], t3.S[0]

	EOR R0, R0
	ADD $124, R11
	VEOR ZERO.B16, ZERO.B16, ZERO.B16

ksLoop:
		SM4_EXPANDKEY_ROUND(x, y, t0, t1, t2, t3)
		SM4_EXPANDKEY_ROUND(x, y, t1, t2, t3, t0)
		SM4_EXPANDKEY_ROUND(x, y, t2, t3, t0, t1)
		SM4_EXPANDKEY_ROUND(x, y, t3, t0, t1, t2)

		ADD $16, R0 
		CMP $128, R0
		BNE ksLoop
	RET 

sm4ekey:
	LDP fk_mask<>(SB), (R0, R1)
	VMOV R0, FK_MASK.D[0]             
	VMOV R1, FK_MASK.D[1]
	VLD1 (R8), [V9.B16]
	VREV32 V9.B16, V9.B16
	VEOR FK_MASK.B16, V9.B16, V9.B16
	ADD $96, R11

	VLD1.P	64(R9), [V0.S4, V1.S4, V2.S4, V3.S4]
	WORD $0xce60c928          //SM4EKEY V8.4S, V9.4S, V0.4S
	WORD $0xce61c909          //SM4EKEY V9.4S, V8.4S, V1.4S
	SM4EKEY_EXPORT_KEYS()

	WORD $0xce62c928          //SM4EKEY V8.4S, V9.4S, V2.4S
	WORD $0xce63c909          //SM4EKEY V9.4S, V8.4S, V3.4S
	SM4EKEY_EXPORT_KEYS()

	VLD1.P	64(R9), [V0.S4, V1.S4, V2.S4, V3.S4]
	WORD $0xce60c928          //SM4EKEY V8.4S, V9.4S, V0.4S
	WORD $0xce61c909          //SM4EKEY V9.4S, V8.4S, V1.4S
	SM4EKEY_EXPORT_KEYS()

	WORD $0xce62c928          //SM4EKEY V8.4S, V9.4S, V2.4S
	WORD $0xce63c909          //SM4EKEY V9.4S, V8.4S, V3.4S
	SM4EKEY_EXPORT_KEYS()
	RET

// func encryptBlocksAsm(xk *uint32, dst, src []byte, inst int)
TEXT ·encryptBlocksAsm(SB),NOSPLIT,$0
	MOVD xk+0(FP), R8
	MOVD dst+8(FP), R9
	MOVD src+32(FP), R10
	MOVD src_len+40(FP), R12
	MOVD inst+56(FP), R11

	CMP $1, R11
	BEQ sm4niblocks

	VLD1 (R10), [t0.S4, t1.S4, t2.S4, t3.S4]
	VREV32 t0.B16, t0.B16
	VREV32 t1.B16, t1.B16
	VREV32 t2.B16, t2.B16
	VREV32 t3.B16, t3.B16
	PRE_TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y, XTMP6, XTMP7)

	load_global_data_2()

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

	VST1 [t0.S4, t1.S4, t2.S4, t3.S4], (R9)
	RET

sm4niblocks:
	VLD1.P  64(R8), [V0.S4, V1.S4, V2.S4, V3.S4]
	VLD1.P  64(R8), [V4.S4, V5.S4, V6.S4, V7.S4]

sm4niblockloop:  
		SM4E_ROUND()
		SUB	$16, R12, R12                                  // message length - 16bytes, then compare with 16bytes
		CBNZ	R12, sm4niblockloop  
	RET

// func encryptBlockAsm(xk *uint32, dst, src *byte, inst int)
TEXT ·encryptBlockAsm(SB),NOSPLIT,$0
	MOVD xk+0(FP), R8
	MOVD dst+8(FP), R9
	MOVD src+16(FP), R10
	MOVD inst+24(FP), R11

	CMP $1, R11
	BEQ sm4niblock

	VLD1 (R10), [t0.S4]
	VREV32 t0.B16, t0.B16
	VMOV t0.S[1], t1.S[0]
	VMOV t0.S[2], t2.S[0]
	VMOV t0.S[3], t3.S[0]

	load_global_data_2()

	VEOR ZERO.B16, ZERO.B16, ZERO.B16
	EOR R0, R0

encryptBlockLoop:
		SM4_ROUND(R8, R19, x, y, XTMP6, t0, t1, t2, t3)
		SM4_ROUND(R8, R19, x, y, XTMP6, t1, t2, t3, t0)
		SM4_ROUND(R8, R19, x, y, XTMP6, t2, t3, t0, t1)
		SM4_ROUND(R8, R19, x, y, XTMP6, t3, t0, t1, t2)

		ADD $16, R0
		CMP $128, R0
		BNE encryptBlockLoop

	VMOV t2.S[0], t3.S[1]
	VMOV t1.S[0], t3.S[2]
	VMOV t0.S[0], t3.S[3]
	VREV32 t3.B16, t3.B16
	VST1 [t3.B16], (R9)
	RET

sm4niblock:
	VLD1 (R10), [V8.B16]
	VREV32 V8.B16, V8.B16
	VLD1.P	64(R8), [V0.S4, V1.S4, V2.S4, V3.S4]
	WORD $0xcec08408          //SM4E V8.4S, V0.4S
	WORD $0xcec08428          //SM4E V8.4S, V1.4S
	WORD $0xcec08448          //SM4E V8.4S, V2.4S
	WORD $0xcec08468          //SM4E V8.4S, V3.4S
	VLD1.P	64(R8), [V0.S4, V1.S4, V2.S4, V3.S4]
	WORD $0xcec08408          //SM4E V8.4S, V0.4S
	WORD $0xcec08428          //SM4E V8.4S, V1.4S
	WORD $0xcec08448          //SM4E V8.4S, V2.4S
	WORD $0xcec08468          //SM4E V8.4S, V3.4S
	VREV64	V8.S4, V8.S4
	VEXT $8, V8.B16, V8.B16, V8.B16
	VREV32 V8.B16, V8.B16
	VST1	[V8.B16], (R9)
	RET  
