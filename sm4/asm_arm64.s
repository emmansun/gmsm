//go:build !purego

#include "textflag.h"

#define t0 V0
#define t1 V1
#define t2 V2
#define t3 V3
#define t4 V4
#define t5 V5
#define t6 V6
#define t7 V7
#define x V8
#define y V9
#define XTMP6 V10
#define XTMP7 V11
#define M1L V20
#define M1H V21
#define M2L V22
#define M2H V23
#define R08_MASK V24
#define INVERSE_SHIFT_ROWS V25
#define FK_MASK V26
#define NIBBLE_MASK V27
#define ZERO V28

DATA ·rcon+0x00(SB)/8, $0x0A7FC3B6D5A01C69 // m1l
DATA ·rcon+0x08(SB)/8, $0x3045F98CEF9A2653
DATA ·rcon+0x10(SB)/8, $0xC35BF46CAF379800 // m1h
DATA ·rcon+0x18(SB)/8, $0x68F05FC7049C33AB
DATA ·rcon+0x20(SB)/8, $0x9A950A05FEF16E61 // m2l
DATA ·rcon+0x28(SB)/8, $0x0E019E916A65FAF5
DATA ·rcon+0x30(SB)/8, $0x892D69CD44E0A400 // m2h
DATA ·rcon+0x38(SB)/8, $0x2C88CC68E14501A5
DATA ·rcon+0x40(SB)/8, $0x0605040702010003 // left rotations of 32-bit words by 8-bit increments
DATA ·rcon+0x48(SB)/8, $0x0E0D0C0F0A09080B  
DATA ·rcon+0x50(SB)/8, $0x0B0E0104070A0D00 // inverse shift rows
DATA ·rcon+0x58(SB)/8, $0x0306090C0F020508 
DATA ·rcon+0x60(SB)/8, $0x56aa3350a3b1bac6 // fk
DATA ·rcon+0x68(SB)/8, $0xb27022dc677d9197
GLOBL ·rcon(SB), RODATA, $112

#include "aesni_macros_arm64.s"

#define SM4_TAO_L2(x, y)         \
	SM4_SBOX(x, y, XTMP6);                      \
	;                                           \ //####################  4 parallel L2 linear transforms ##################//
	VSHL $13, x.S4, y.S4;                       \
	VSRI $19, x.S4, y.S4;                       \
	VSHL $23, x.S4, XTMP6.S4;                   \
	VSRI $9, x.S4, XTMP6.S4;                    \
	VEOR XTMP6.B16, y.B16, y.B16;               \
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

#define LOAD_SM4KEY_AESNI_CONSTS() \
	MOVW $0x0F0F0F0F, R0                                 \
	VDUP R0, NIBBLE_MASK.S4                              \
	MOVD $·rcon(SB), R0                                  \
	VLD1.P 64(R0), [M1L.B16, M1H.B16, M2L.B16, M2H.B16]  \
	VLD1 (R0), [R08_MASK.B16, INVERSE_SHIFT_ROWS.B16, FK_MASK.B16]

#define SM4EKEY_EXPORT_KEYS() \
	VREV64	V8.S4, V11.S4                 \ 
	VEXT $8, V11.B16, V11.B16, V11.B16    \	
	VREV64	V9.S4, V10.S4                 \ 
	VEXT $8, V10.B16, V10.B16, V10.B16    \	
	VST1.P	[V8.S4, V9.S4], 32(R10)       \
	VST1	[V10.S4, V11.S4], (R11)       \
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
	VREV64	V8.B16, V8.B16             \ 
	VEXT $8, V8.B16, V8.B16, V8.B16    \	
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

	LOAD_SM4KEY_AESNI_CONSTS()
	
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
	MOVD $·rcon+0x60(SB), R0
	VLD1 (R0), [FK_MASK.B16]
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

	LOAD_SM4_AESNI_CONSTS()

	CMP $128, R12
	BEQ double_enc

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

	VST1 [t0.S4, t1.S4, t2.S4, t3.S4], (R9)
	RET

double_enc:
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

	VEOR ZERO.B16, ZERO.B16, ZERO.B16
	EOR R0, R0

encrypt8BlocksLoop:
		SM4_8BLOCKS_ROUND(R8, R19, x, y, XTMP6, XTMP7, t0, t1, t2, t3, t4, t5, t6, t7)
		SM4_8BLOCKS_ROUND(R8, R19, x, y, XTMP6, XTMP7, t1, t2, t3, t0, t5, t6, t7, t4)
		SM4_8BLOCKS_ROUND(R8, R19, x, y, XTMP6, XTMP7, t2, t3, t0, t1, t6, t7, t4, t5)
		SM4_8BLOCKS_ROUND(R8, R19, x, y, XTMP6, XTMP7, t3, t0, t1, t2, t7, t4, t5, t6)

		ADD $16, R0
		CMP $128, R0
		BNE encrypt8BlocksLoop

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

	VST1.P [t0.S4, t1.S4, t2.S4, t3.S4], 64(R9)
	VST1.P [t4.S4, t5.S4, t6.S4, t7.S4], 64(R9)

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

	LOAD_SM4_AESNI_CONSTS()

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
	VREV64	V8.B16, V8.B16
	VEXT $8, V8.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R9)
	RET  
