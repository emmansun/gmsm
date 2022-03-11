#include "textflag.h"

//nibble mask
DATA nibble_mask<>+0x00(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA nibble_mask<>+0x08(SB)/8, $0x0F0F0F0F0F0F0F0F
GLOBL nibble_mask<>(SB), (NOPTR+RODATA), $16

// inverse shift rows
DATA inverse_shift_rows<>+0x00(SB)/8, $0x0B0E0104070A0D00
DATA inverse_shift_rows<>+0x08(SB)/8, $0x0306090C0F020508 
GLOBL inverse_shift_rows<>(SB), (NOPTR+RODATA), $16

// Affine transform 1 (low and high hibbles)
DATA m1_low<>+0x00(SB)/8, $0x0A7FC3B6D5A01C69
DATA m1_low<>+0x08(SB)/8, $0x3045F98CEF9A2653
GLOBL m1_low<>(SB), (NOPTR+RODATA), $16

DATA m1_high<>+0x00(SB)/8, $0xC35BF46CAF379800
DATA m1_high<>+0x08(SB)/8, $0x68F05FC7049C33AB  
GLOBL m1_high<>(SB), (NOPTR+RODATA), $16

// Affine transform 2 (low and high hibbles)
DATA m2_low<>+0x00(SB)/8, $0x9A950A05FEF16E61
DATA m2_low<>+0x08(SB)/8, $0x0E019E916A65FAF5
GLOBL m2_low<>(SB), (NOPTR+RODATA), $16

DATA m2_high<>+0x00(SB)/8, $0x892D69CD44E0A400
DATA m2_high<>+0x08(SB)/8, $0x2C88CC68E14501A5
GLOBL m2_high<>(SB), (NOPTR+RODATA), $16

// left rotations of 32-bit words by 8-bit increments
DATA r08_mask<>+0x00(SB)/8, $0x0605040702010003
DATA r08_mask<>+0x08(SB)/8, $0x0E0D0C0F0A09080B  
GLOBL r08_mask<>(SB), (NOPTR+RODATA), $16

DATA r16_mask<>+0x00(SB)/8, $0x0504070601000302
DATA r16_mask<>+0x08(SB)/8, $0x0D0C0F0E09080B0A   
GLOBL r16_mask<>(SB), (NOPTR+RODATA), $16

DATA r24_mask<>+0x00(SB)/8, $0x0407060500030201
DATA r24_mask<>+0x08(SB)/8, $0x0C0F0E0D080B0A09  
GLOBL r24_mask<>(SB), (NOPTR+RODATA), $16

#define B0 V0
#define B1 V1
#define B2 V2
#define B3 V3
#define B4 V4
#define B5 V5
#define B6 V6
#define B7 V7

#define ACC0 V8
#define ACC1 V9
#define ACCM V10

#define T0 V11
#define T1 V12
#define T2 V13
#define T3 V14

#define POLY V15
#define ZERO V16
#define INC V17
#define CTR V18

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

#define reduce() \
	VEOR	ACC0.B16, ACCM.B16, ACCM.B16     \
	VEOR	ACC1.B16, ACCM.B16, ACCM.B16     \
	VEXT	$8, ZERO.B16, ACCM.B16, T0.B16   \
	VEXT	$8, ACCM.B16, ZERO.B16, ACCM.B16 \
	VEOR	ACCM.B16, ACC0.B16, ACC0.B16     \
	VEOR	T0.B16, ACC1.B16, ACC1.B16       \
	VPMULL	POLY.D1, ACC0.D1, T0.Q1          \
	VEXT	$8, ACC0.B16, ACC0.B16, ACC0.B16 \
	VEOR	T0.B16, ACC0.B16, ACC0.B16       \
	VPMULL	POLY.D1, ACC0.D1, T0.Q1          \
	VEOR	T0.B16, ACC1.B16, ACC1.B16       \
	VEXT	$8, ACC1.B16, ACC1.B16, ACC1.B16 \
	VEOR	ACC1.B16, ACC0.B16, ACC0.B16     \

// func gcmSm4Finish(productTable *[256]byte, tagMask, T *[16]byte, pLen, dLen uint64)
TEXT ·gcmSm4Finish(SB),NOSPLIT,$0    
#define pTbl R0
#define tMsk R1
#define tPtr R2
#define plen R3
#define dlen R4

	MOVD	$0xC2, R1
	LSL	$56, R1
	MOVD	$1, R0
	VMOV	R1, POLY.D[0]
	VMOV	R0, POLY.D[1]
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	MOVD	productTable+0(FP), pTbl
	MOVD	tagMask+8(FP), tMsk
	MOVD	T+16(FP), tPtr
	MOVD	pLen+24(FP), plen
	MOVD	dLen+32(FP), dlen

	VLD1	(tPtr), [ACC0.B16]
	VLD1	(tMsk), [B1.B16]

	LSL	$3, plen
	LSL	$3, dlen

	VMOV	dlen, B0.D[0]
	VMOV	plen, B0.D[1]

	ADD	$14*16, pTbl
	VLD1.P	(pTbl), [T1.B16, T2.B16]

	VEOR	ACC0.B16, B0.B16, B0.B16

	VEXT	$8, B0.B16, B0.B16, T0.B16
	VEOR	B0.B16, T0.B16, T0.B16
	VPMULL	B0.D1, T1.D1, ACC1.Q1
	VPMULL2	B0.D2, T1.D2, ACC0.Q1
	VPMULL	T0.D1, T2.D1, ACCM.Q1

	reduce()

	VREV64	ACC0.B16, ACC0.B16
	VEOR	B1.B16, ACC0.B16, ACC0.B16

	VST1	[ACC0.B16], (tPtr)
	RET
#undef pTbl
#undef tMsk
#undef tPtr
#undef plen
#undef dlen

#define PRE_TRANSPOSE_MATRIX(t0, t1, t2, t3, K) \
	VMOV t0.B16, K.B16                         \
	VMOV t1.S[0], t0.S[1]                      \
	VMOV t2.S[0], t0.S[2]                      \
	VMOV t3.S[0], t0.S[3]                      \
	VMOV K.S[1], t1.S[0]                       \
	VMOV K.S[2], t2.S[0]                       \
	VMOV K.S[3], t3.S[0]                       \
	VMOV t1.D[1], K.D[1]                       \
	VMOV t2.S[1], t1.S[2]                      \
	VMOV t3.S[1], t1.S[3]                      \
	VMOV K.S[2], t2.S[1]                       \
	VMOV K.S[3], t3.S[1]                       \
	VMOV t2.S[3], K.S[3]                       \
	VMOV t3.S[2], t2.S[3]                      \
	VMOV K.S[3], t3.S[2]

#define TRANSPOSE_MATRIX(t0, t1, t2, t3, K) \
	VMOV t0.B16, K.B16                        \
	VMOV t3.S[0], t0.S[0]                     \   
	VMOV t2.S[0], t0.S[1]                     \
	VMOV t1.S[0], t0.S[2]                     \
	VMOV K0.S[0], t0.S[3]                     \   
	VMOV t3.S[1], t1.S[0]                     \
	VMOV t3.S[2], t2.S[0]                     \
	VMOV t3.S[3], t3.S[0]                     \
	VMOV t2.S[3], t3.S[1]                     \
	VMOV t1.S[3], t3.S[2]                     \
	VMOV K.S[3], t3.S[3]                      \
	VMOV K.S[2], t2.S[3]                      \
	VMOV K.S[1], t1.S[3]                      \
	VMOV t1.B16, K.B16                        \
	VMOV t2.S[1], t1.S[1]                     \
	VMOV K.S[1], t1.S[2]                      \
	VMOV t2.S[2], t2.S[1]                     \
	VMOV K.S[2], t2.S[2]

#define LOAD_SM4_AESNI_CONSTS() \
  LDP nibble_mask<>(SB), (R20, R21)          \
  VMOV R20, NIBBLE_MASK.D[0]                 \
  VMOV R21, NIBBLE_MASK.D[1]                 \
  LDP m1_low<>(SB), (R20, R21)               \
  VMOV R20, M1L.D[0]                         \
  VMOV R21, M1L.D[1]                         \
  LDP m1_high<>(SB), (R20, R21)              \
  VMOV R20, M1H.D[0]                         \
  VMOV R21, M1H.D[1]                         \
  LDP m2_low<>(SB), (R20, R21)               \
  VMOV R20, M2L.D[0]                         \
  VMOV R21, M2L.D[1]                         \
  LDP m2_high<>(SB), (R20, R21)              \
  VMOV R20, M2H.D[0]                         \
  VMOV R21, M2H.D[1]                         \
  LDP inverse_shift_rows<>(SB), (R20, R21)   \
  VMOV R20, INVERSE_SHIFT_ROWS.D[0]          \
  VMOV R21, INVERSE_SHIFT_ROWS.D[1]          \
  LDP r08_mask<>(SB), (R20, R21)             \
  VMOV R20, R08_MASK.D[0]                    \
  VMOV R21, R08_MASK.D[1]                    \
  LDP r16_mask<>(SB), (R20, R21)             \
  VMOV R20, R16_MASK.D[0]                    \
  VMOV R21, R16_MASK.D[1]                    \
  LDP r24_mask<>(SB), (R20, R21)             \
  VMOV R20, R24_MASK.D[0]                    \
  VMOV R21, R24_MASK.D[1]

#define SM4_SBOX(x, y, z) \
  ;                                              \
  VAND x.B16, NIBBLE_MASK.B16, z.B16;            \
  VTBL z.B16, [M1L.B16], y.B16;                  \
  VUSHR $4, x.D2, x.D2;                          \
  VAND x.B16, NIBBLE_MASK.B16, z.B16;            \
  VTBL z.B16, [M1H.B16], z.B16;                  \
  VEOR y.B16, z.B16, x.B16;                      \
  VTBL INVERSE_SHIFT_ROWS.B16, [x.B16], x.B16;   \
  AESE ZERO.B16, x.B16;                          \	
  VAND x.B16, NIBBLE_MASK.B16, z.B16;            \
  VTBL z.B16, [M2L.B16], y.B16;                  \
  VUSHR $4, x.D2, x.D2;                          \
  VAND x.B16, NIBBLE_MASK.B16, z.B16;            \
  VTBL z.B16, [M2H.B16], z.B16;                  \
  VEOR y.B16, z.B16, x.B16

#define SM4_TAO_L1(x, y, z)         \
	SM4_SBOX(x, y, z);                                   \
	VTBL R08_MASK.B16, [x.B16], y.B16;                   \
	VEOR y.B16, x.B16, y.B16;                            \
	VTBL R16_MASK.B16, [x.B16], z.B16;                   \
	VEOR z.B16, y.B16, y.B16;                            \
	VSHL $2, y.S4, z.S4;                                 \
	VUSHR $30, y.S4, y.S4;                               \
	VORR y.B16, z.B16, y.B16;                            \
	VTBL R24_MASK.B16, [x.B16], z.B16;                   \
	VEOR z.B16, x.B16, x.B16;                            \
	VEOR y.B16, x.B16, x.B16

#define SM4_ROUND(RK, x, y, z, t0, t1, t2, t3)  \ 
	MOVW.P 4(RK), R19;                                \
	VMOV R19, x.S4;                                   \
	VEOR t1.B16, x.B16, x.B16;                        \
	VEOR t2.B16, x.B16, x.B16;                        \
	VEOR t3.B16, x.B16, x.B16;                        \
	SM4_TAO_L1(x, y, z);                              \
	VEOR x.B16, t0.B16, t0.B16

// func gcmSm4Init(productTable *[256]byte, rk []uint32)
TEXT ·gcmSm4Init(SB),NOSPLIT,$0
#define pTbl R0
#define RK R1
#define I R2

	MOVD productTable+0(FP), pTbl
	MOVD rk+8(FP), RK

	MOVD	$0xC2, I
	LSL	$56, I
	VMOV	I, POLY.D[0]
	MOVD	$1, I
	VMOV	I, POLY.D[1]
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	// Encrypt block 0 with the SM4 keys to generate the hash key H
	LOAD_SM4_AESNI_CONSTS()
	VEOR	B0.B16, B0.B16, B0.B16
	VEOR	B1.B16, B1.B16, B1.B16
	VEOR	B2.B16, B2.B16, B2.B16
	VEOR	B3.B16, B3.B16, B3.B16
	EOR R3, R3

sm4InitEncLoop:	
	SM4_ROUND(RK, K0, K1, K2, B0, B1, B2, B3)
	SM4_ROUND(RK, K0, K1, K2, B1, B2, B3, B0)
	SM4_ROUND(RK, K0, K1, K2, B2, B3, B0, B1)
	SM4_ROUND(RK, K0, K1, K2, B3, B0, B1, B2)

	ADD $1, R3
	CMP $8, R3
	BNE sm4InitEncLoop

	VMOV B0.S[0], B0.S[2]
	VMOV B1.S[0], B0.S[3]
	VMOV B2.S[0], B0.S[0]
	VMOV B3.S[0], B0.S[1]

	// Multiply by 2 modulo P
	VMOV	B0.D[0], I
	ASR	$63, I
	VMOV	I, T1.D[0]
	VMOV	I, T1.D[1]
	VAND	POLY.B16, T1.B16, T1.B16
	VUSHR	$63, B0.D2, T2.D2
	VEXT	$8, ZERO.B16, T2.B16, T2.B16
	VSHL	$1, B0.D2, B0.D2
	VEOR	T1.B16, B0.B16, B0.B16
	VEOR	T2.B16, B0.B16, B0.B16 // Can avoid this when VSLI is available

	// Karatsuba pre-computation
	VEXT	$8, B0.B16, B0.B16, B1.B16
	VEOR	B0.B16, B1.B16, B1.B16

	ADD	$14*16, pTbl

	VST1	[B0.B16, B1.B16], (pTbl)
	SUB	$2*16, pTbl

	VMOV	B0.B16, B2.B16
	VMOV	B1.B16, B3.B16

	MOVD	$7, I

initLoop:
	// Compute powers of H
	SUBS	$1, I

	VPMULL	B0.D1, B2.D1, T1.Q1
	VPMULL2	B0.D2, B2.D2, T0.Q1
	VPMULL	B1.D1, B3.D1, T2.Q1
	VEOR	T0.B16, T2.B16, T2.B16
	VEOR	T1.B16, T2.B16, T2.B16
	VEXT	$8, ZERO.B16, T2.B16, T3.B16
	VEXT	$8, T2.B16, ZERO.B16, T2.B16
	VEOR	T2.B16, T0.B16, T0.B16
	VEOR	T3.B16, T1.B16, T1.B16
	VPMULL	POLY.D1, T0.D1, T2.Q1
	VEXT	$8, T0.B16, T0.B16, T0.B16
	VEOR	T2.B16, T0.B16, T0.B16
	VPMULL	POLY.D1, T0.D1, T2.Q1
	VEXT	$8, T0.B16, T0.B16, T0.B16
	VEOR	T2.B16, T0.B16, T0.B16
	VEOR	T1.B16, T0.B16, B2.B16
	VMOV	B2.B16, B3.B16
	VEXT	$8, B2.B16, B2.B16, B2.B16
	VEOR	B2.B16, B3.B16, B3.B16

	VST1	[B2.B16, B3.B16], (pTbl)
	SUB	$2*16, pTbl

	BNE	initLoop
	RET
#undef I
#undef RK
#undef pTbl	

// func gcmSm4Data(productTable *[256]byte, data []byte, T *[16]byte)
TEXT ·gcmSm4Data(SB),NOSPLIT,$0
#define pTbl R0
#define aut R1
#define tPtr R2
#define autLen R3
#define H0 R4
#define pTblSave R5

#define mulRound(X) \
	VLD1.P	32(pTbl), [T1.B16, T2.B16] \
	VREV64	X.B16, X.B16               \
	VEXT	$8, X.B16, X.B16, T0.B16   \
	VEOR	X.B16, T0.B16, T0.B16      \
	VPMULL	X.D1, T1.D1, T3.Q1         \
	VEOR	T3.B16, ACC1.B16, ACC1.B16 \
	VPMULL2	X.D2, T1.D2, T3.Q1         \
	VEOR	T3.B16, ACC0.B16, ACC0.B16 \
	VPMULL	T0.D1, T2.D1, T3.Q1        \
	VEOR	T3.B16, ACCM.B16, ACCM.B16

	MOVD	productTable+0(FP), pTbl
	MOVD	data_base+8(FP), aut
	MOVD	data_len+16(FP), autLen
	MOVD	T+32(FP), tPtr

	//VEOR	ACC0.B16, ACC0.B16, ACC0.B16
	VLD1 (tPtr), [ACC0.B16]
	CBZ	autLen, dataBail

	MOVD	$0xC2, H0
	LSL	$56, H0
	VMOV	H0, POLY.D[0]
	MOVD	$1, H0
	VMOV	H0, POLY.D[1]
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16
	MOVD	pTbl, pTblSave

	CMP	$13, autLen
	BEQ	dataTLS
	CMP	$128, autLen
	BLT	startSinglesLoop
	B	octetsLoop

dataTLS:
	ADD	$14*16, pTbl
	VLD1.P	(pTbl), [T1.B16, T2.B16]
	VEOR	B0.B16, B0.B16, B0.B16

	MOVD	(aut), H0
	VMOV	H0, B0.D[0]
	MOVW	8(aut), H0
	VMOV	H0, B0.S[2]
	MOVB	12(aut), H0
	VMOV	H0, B0.B[12]

	MOVD	$0, autLen
	B	dataMul

octetsLoop:
		CMP	$128, autLen
		BLT	startSinglesLoop
		SUB	$128, autLen

		VLD1.P	32(aut), [B0.B16, B1.B16]

		VLD1.P	32(pTbl), [T1.B16, T2.B16]
		VREV64	B0.B16, B0.B16
		VEOR	ACC0.B16, B0.B16, B0.B16
		VEXT	$8, B0.B16, B0.B16, T0.B16
		VEOR	B0.B16, T0.B16, T0.B16
		VPMULL	B0.D1, T1.D1, ACC1.Q1
		VPMULL2	B0.D2, T1.D2, ACC0.Q1
		VPMULL	T0.D1, T2.D1, ACCM.Q1

		mulRound(B1)
		VLD1.P  32(aut), [B2.B16, B3.B16]
		mulRound(B2)
		mulRound(B3)
		VLD1.P  32(aut), [B4.B16, B5.B16]
		mulRound(B4)
		mulRound(B5)
		VLD1.P  32(aut), [B6.B16, B7.B16]
		mulRound(B6)
		mulRound(B7)

		MOVD	pTblSave, pTbl
		reduce()
	B	octetsLoop

startSinglesLoop:

	ADD	$14*16, pTbl
	VLD1.P	(pTbl), [T1.B16, T2.B16]

singlesLoop:

		CMP	$16, autLen
		BLT	dataEnd
		SUB	$16, autLen

		VLD1.P	16(aut), [B0.B16]
dataMul:
		VREV64	B0.B16, B0.B16
		VEOR	ACC0.B16, B0.B16, B0.B16

		VEXT	$8, B0.B16, B0.B16, T0.B16
		VEOR	B0.B16, T0.B16, T0.B16
		VPMULL	B0.D1, T1.D1, ACC1.Q1
		VPMULL2	B0.D2, T1.D2, ACC0.Q1
		VPMULL	T0.D1, T2.D1, ACCM.Q1

		reduce()

	B	singlesLoop

dataEnd:

	CBZ	autLen, dataBail
	VEOR	B0.B16, B0.B16, B0.B16
	ADD	autLen, aut

dataLoadLoop:
		MOVB.W	-1(aut), H0
		VEXT	$15, B0.B16, ZERO.B16, B0.B16
		VMOV	H0, B0.B[0]
		SUBS	$1, autLen
		BNE	dataLoadLoop
	B	dataMul

dataBail:
	VST1	[ACC0.B16], (tPtr)
	RET

#undef pTbl
#undef aut
#undef tPtr
#undef autLen
#undef H0
#undef pTblSave

// func gcmSm4Enc(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)
TEXT ·gcmSm4Enc(SB),NOSPLIT,$0
#define pTbl R0
#define dstPtr R1
#define ctrPtr R2
#define srcPtr R3
#define rk R4
#define tPtr R5
#define srcPtrLen R6
#define aluCTR R7
#define aluTMP R8
#define H0 R9
#define H1 R10
#define pTblSave R11
#define rkSave R12
#define mulRoundSingleWithoutRev(X) \
	VEOR	ACC0.B16, X.B16, X.B16    \
	VEXT	$8, X.B16, X.B16, T0.B16  \
	VEOR	X.B16, T0.B16, T0.B16     \
	VPMULL	X.D1, T1.D1, ACC1.Q1    \
	VPMULL2	X.D2, T1.D2, ACC0.Q1    \
	VPMULL	T0.D1, T2.D1, ACCM.Q1   \
	reduce()                        \

#define mulRoundSingle(X) \
	VREV64	X.B16, X.B16            \
	mulRoundSingleWithoutRev(X)     \

	MOVD	productTable+0(FP), pTbl
	MOVD	dst+8(FP), dstPtr
	MOVD	src_base+32(FP), srcPtr
	MOVD	src_len+40(FP), srcPtrLen
	MOVD	ctr+56(FP), ctrPtr
	MOVD	T+64(FP), tPtr
	MOVD	rk_base+72(FP), rk
	
	MOVD	$0xC2, H1
	LSL	$56, H1
	MOVD	$1, H0
	VMOV	H1, POLY.D[0]
	VMOV	H0, POLY.D[1]
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	MOVD	pTbl, pTblSave
	MOVD rk, rkSave
	// Current tag, after AAD
	VLD1	(tPtr), [ACC0.B16]
	VEOR	ACC1.B16, ACC1.B16, ACC1.B16
	VEOR	ACCM.B16, ACCM.B16, ACCM.B16
	// Prepare initial counter, and the increment vector
	VLD1	(ctrPtr), [CTR.B16]
	VEOR	INC.B16, INC.B16, INC.B16
	MOVD	$1, H0
	VMOV	H0, INC.S[3]
	VREV32	CTR.B16, CTR.B16
	VADD	CTR.S4, INC.S4, CTR.S4
	// Skip to <8 blocks loop
	CMP	$128, srcPtrLen

	LOAD_SM4_AESNI_CONSTS()

	BLT	encNibblesLoop
	// There are at least 8 blocks to encrypt

encOctetsLoop:
		SUB	$128, srcPtrLen
		// Prepare 8 counters
		VMOV	CTR.B16, B0.B16
		VADD	B0.S4, INC.S4, B1.S4
		VADD	B1.S4, INC.S4, B2.S4
		VADD	B2.S4, INC.S4, B3.S4
		VADD	B3.S4, INC.S4, B4.S4
		VADD	B4.S4, INC.S4, B5.S4
		VADD	B5.S4, INC.S4, B6.S4
		VADD	B6.S4, INC.S4, B7.S4
		VADD	B7.S4, INC.S4, CTR.S4

		// encryption first 4 blocks
		PRE_TRANSPOSE_MATRIX(B0, B1, B2, B3, K0)
		EOR R13, R13
		MOVD	rkSave, rk

encOctetsEnc4Blocks1:	
			SM4_ROUND(rk, K0, K1, K2, B0, B1, B2, B3)
			SM4_ROUND(rk, K0, K1, K2, B1, B2, B3, B0)
			SM4_ROUND(rk, K0, K1, K2, B2, B3, B0, B1)
			SM4_ROUND(rk, K0, K1, K2, B3, B0, B1, B2)

		ADD $1, R13
		CMP $8, R13
		BNE encOctetsEnc4Blocks1
		VREV32 B0.B16, B0.B16
		VREV32 B1.B16, B1.B16
		VREV32 B2.B16, B2.B16
		VREV32 B3.B16, B3.B16
		TRANSPOSE_MATRIX(B0, B1, B2, B3, K0)
		// encryption first 4 blocks
		PRE_TRANSPOSE_MATRIX(B4, B5, B6, B7, K0)
		MOVD	rkSave, rk

encOctetsEnc4Blocks2:	
			SM4_ROUND(rk, K0, K1, K2, B4, B5, B6, B7)
			SM4_ROUND(rk, K0, K1, K2, B5, B6, B7, B4)
			SM4_ROUND(rk, K0, K1, K2, B6, B7, B4, B5)
			SM4_ROUND(rk, K0, K1, K2, B7, B4, B5, B6)

		ADD $1, R13
		CMP $16, R13
		BNE encOctetsEnc4Blocks2
		VREV32 B4.B16, B4.B16
		VREV32 B5.B16, B5.B16
		VREV32 B6.B16, B6.B16
		VREV32 B7.B16, B7.B16
		TRANSPOSE_MATRIX(B4, B5, B6, B7, K0)

		// XOR plaintext and store ciphertext
		VLD1.P	32(srcPtr), [T1.B16, T2.B16]
		VEOR	B0.B16, T1.B16, B0.B16
		VEOR	B1.B16, T2.B16, B1.B16
		VST1.P  [B0.B16, B1.B16], 32(dstPtr)
		VLD1.P	32(srcPtr), [T1.B16, T2.B16]
		VEOR	B2.B16, T1.B16, B2.B16
		VEOR	B3.B16, T2.B16, B3.B16
		VST1.P  [B2.B16, B3.B16], 32(dstPtr)
		VLD1.P	32(srcPtr), [T1.B16, T2.B16]
		VEOR	B4.B16, T1.B16, B4.B16
		VEOR	B5.B16, T2.B16, B5.B16
		VST1.P  [B4.B16, B5.B16], 32(dstPtr)
		VLD1.P	32(srcPtr), [T1.B16, T2.B16]
		VEOR	B6.B16, T1.B16, B6.B16
		VEOR	B7.B16, T2.B16, B7.B16
		VST1.P  [B6.B16, B7.B16], 32(dstPtr)

		VLD1.P	32(pTbl), [T1.B16, T2.B16]
		VREV64	B0.B16, B0.B16
		VEOR	ACC0.B16, B0.B16, B0.B16
		VEXT	$8, B0.B16, B0.B16, T0.B16
		VEOR	B0.B16, T0.B16, T0.B16
		VPMULL	B0.D1, T1.D1, ACC1.Q1
		VPMULL2	B0.D2, T1.D2, ACC0.Q1
		VPMULL	T0.D1, T2.D1, ACCM.Q1

		mulRound(B1)
		mulRound(B2)
		mulRound(B3)
		mulRound(B4)
		mulRound(B5)
		mulRound(B6)
		mulRound(B7)
		MOVD	pTblSave, pTbl
		reduce()

		CMP	$128, srcPtrLen
		BGE	encOctetsLoop

encNibblesLoop:
	CBZ	srcPtrLen, encDone
	ADD	$14*16, pTbl
	// Preload H and its Karatsuba precomp
	VLD1.P	(pTbl), [T1.B16, T2.B16]

	CMP	$64, srcPtrLen
	BLT	encStartSingles
	SUB	$64, srcPtrLen

	// Prepare 4 counters
	VMOV	CTR.B16, B0.B16
	VADD	B0.S4, INC.S4, B1.S4
	VADD	B1.S4, INC.S4, B2.S4
	VADD	B2.S4, INC.S4, B3.S4
	VADD	B3.S4, INC.S4, CTR.S4

	// encryption first 4 blocks
	PRE_TRANSPOSE_MATRIX(B0, B1, B2, B3, K0)
	EOR R13, R13
	MOVD	rkSave, rk

encNibblesEnc4Blocks:	
		SM4_ROUND(rk, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, K0, K1, K2, B3, B0, B1, B2)

	ADD $1, R13
	CMP $8, R13
	BNE encNibblesEnc4Blocks
	VREV32 B0.B16, B0.B16
	VREV32 B1.B16, B1.B16
	VREV32 B2.B16, B2.B16
	VREV32 B3.B16, B3.B16
	TRANSPOSE_MATRIX(B0, B1, B2, B3, K0)

	// XOR plaintext and store ciphertext
	VLD1.P	32(srcPtr), [K1.B16, K2.B16]
	VEOR	B0.B16, K1.B16, B0.B16
	VEOR	B1.B16, K2.B16, B1.B16
	VST1.P  [B0.B16, B1.B16], 32(dstPtr)
	VLD1.P	32(srcPtr), [K1.B16, K2.B16]
	VEOR	B2.B16, K1.B16, B2.B16
	VEOR	B3.B16, K2.B16, B3.B16
	VST1.P  [B2.B16, B3.B16], 32(dstPtr)

	mulRoundSingle(B0)
	mulRoundSingle(B1)
	mulRoundSingle(B2)
	mulRoundSingle(B3)

encStartSingles:
	CBZ	srcPtrLen, encDone

	// Prepare 4 counters
	VMOV	CTR.B16, B0.B16
	VADD	B0.S4, INC.S4, B1.S4
	VADD	B1.S4, INC.S4, B2.S4
	VADD	B2.S4, INC.S4, B3.S4
	VADD	B3.S4, INC.S4, CTR.S4

	// encryption first 4 blocks
	PRE_TRANSPOSE_MATRIX(B0, B1, B2, B3, K0)
	EOR R13, R13
	MOVD	rkSave, rk

encSinglesEnc4Blocks:	
		SM4_ROUND(rk, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, K0, K1, K2, B3, B0, B1, B2)

	ADD $1, R13
	CMP $8, R13
	BNE encSinglesEnc4Blocks
	VREV32 B0.B16, B0.B16
	VREV32 B1.B16, B1.B16
	VREV32 B2.B16, B2.B16
	VREV32 B3.B16, B3.B16
	TRANSPOSE_MATRIX(B0, B1, B2, B3, K0)

	VMOV B0.B16, K0.B16
	CMP	$16, srcPtrLen
	BLT	encTail
	SUB	$16, srcPtrLen
	VLD1.P	16(srcPtr), [K1.B16]
	VEOR	K0.B16, K1.B16, K0.B16		
	VST1.P  [K0.B16], 16(dstPtr)
	mulRoundSingle(K0)

	VMOV B1.B16, K0.B16
	CMP	$16, srcPtrLen
	BLT	encTail
	SUB	$16, srcPtrLen
	VLD1.P	16(srcPtr), [K1.B16]
	VEOR	K0.B16, K1.B16, K0.B16		
	VST1.P  [K0.B16], 16(dstPtr)
	mulRoundSingle(K0)

	VMOV B2.B16, K0.B16
	CMP	$16, srcPtrLen
	BLT	encTail
	SUB	$16, srcPtrLen
	VLD1.P	16(srcPtr), [K1.B16]
	VEOR	K0.B16, K1.B16, K0.B16		
	VST1.P  [K0.B16], 16(dstPtr)
	mulRoundSingle(K0)

	VMOV B3.B16, K0.B16
	CMP	$16, srcPtrLen
	BLT	encTail
	SUB	$16, srcPtrLen
	VLD1.P	16(srcPtr), [K1.B16]
	VEOR	K0.B16, K1.B16, K0.B16		
	VST1.P  [K0.B16], 16(dstPtr)
	mulRoundSingle(K0)

encTail:
	CBZ	srcPtrLen, encDone
	VEOR	T0.B16, T0.B16, T0.B16
	VEOR	T3.B16, T3.B16, T3.B16
	MOVD	$0, H1
	SUB	$1, H1
	ADD	srcPtrLen, srcPtr

	TBZ	$3, srcPtrLen, ld4
	MOVD.W	-8(srcPtr), H0
	VMOV	H0, T0.D[0]
	VMOV	H1, T3.D[0]
ld4:
	TBZ	$2, srcPtrLen, ld2
	MOVW.W	-4(srcPtr), H0
	VEXT	$12, T0.B16, ZERO.B16, T0.B16
	VEXT	$12, T3.B16, ZERO.B16, T3.B16
	VMOV	H0, T0.S[0]
	VMOV	H1, T3.S[0]
ld2:
	TBZ	$1, srcPtrLen, ld1
	MOVH.W	-2(srcPtr), H0
	VEXT	$14, T0.B16, ZERO.B16, T0.B16
	VEXT	$14, T3.B16, ZERO.B16, T3.B16
	VMOV	H0, T0.H[0]
	VMOV	H1, T3.H[0]
ld1:
	TBZ	$0, srcPtrLen, ld0
	MOVB.W	-1(srcPtr), H0
	VEXT	$15, T0.B16, ZERO.B16, T0.B16
	VEXT	$15, T3.B16, ZERO.B16, T3.B16
	VMOV	H0, T0.B[0]
	VMOV	H1, T3.B[0]
ld0:
	MOVD	ZR, srcPtrLen
	VEOR	T0.B16, K0.B16, K0.B16
	VAND	T3.B16, K0.B16, K0.B16
	VST1.P  [K0.B16], 16(dstPtr)
	mulRoundSingle(K0)

encDone:
	VST1	[ACC0.B16], (tPtr)
	RET

// func gcmSm4Dec(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)
TEXT ·gcmSm4Dec(SB),NOSPLIT,$0
	MOVD	productTable+0(FP), pTbl
	MOVD	dst+8(FP), dstPtr
	MOVD	src_base+32(FP), srcPtr
	MOVD	src_len+40(FP), srcPtrLen
	MOVD	ctr+56(FP), ctrPtr
	MOVD	T+64(FP), tPtr
	MOVD	rk_base+72(FP), rk

	MOVD	$0xC2, H1
	LSL	$56, H1
	MOVD	$1, H0
	VMOV	H1, POLY.D[0]
	VMOV	H0, POLY.D[1]
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	MOVD	pTbl, pTblSave
	MOVD rk, rkSave
	// Current tag, after AAD
	VLD1	(tPtr), [ACC0.B16]
	VEOR	ACC1.B16, ACC1.B16, ACC1.B16
	VEOR	ACCM.B16, ACCM.B16, ACCM.B16
	// Prepare initial counter, and the increment vector
	VLD1	(ctrPtr), [CTR.B16]
	VEOR	INC.B16, INC.B16, INC.B16
	MOVD	$1, H0
	VMOV	H0, INC.S[3]
	VREV32	CTR.B16, CTR.B16
	VADD	CTR.S4, INC.S4, CTR.S4

	// Skip to <8 blocks loop
	CMP	$128, srcPtrLen

	LOAD_SM4_AESNI_CONSTS()

	BLT	decNibblesLoop
	// There are at least 8 blocks to encrypt

decOctetsLoop:
		SUB	$128, srcPtrLen

		VMOV	CTR.B16, B0.B16
		VADD	B0.S4, INC.S4, B1.S4
		VADD	B1.S4, INC.S4, B2.S4
		VADD	B2.S4, INC.S4, B3.S4
		VADD	B3.S4, INC.S4, B4.S4
		VADD	B4.S4, INC.S4, B5.S4
		VADD	B5.S4, INC.S4, B6.S4
		VADD	B6.S4, INC.S4, B7.S4
		VADD	B7.S4, INC.S4, CTR.S4

		// encryption first 4 blocks
		PRE_TRANSPOSE_MATRIX(B0, B1, B2, B3, K0)
		EOR R13, R13
		MOVD	rkSave, rk

decOctetsEnc4Blocks1:	
			SM4_ROUND(rk, K0, K1, K2, B0, B1, B2, B3)
			SM4_ROUND(rk, K0, K1, K2, B1, B2, B3, B0)
			SM4_ROUND(rk, K0, K1, K2, B2, B3, B0, B1)
			SM4_ROUND(rk, K0, K1, K2, B3, B0, B1, B2)

		ADD $1, R13
		CMP $8, R13
		BNE decOctetsEnc4Blocks1
		VREV32 B0.B16, T1.B16
		VREV32 B1.B16, T2.B16
		VREV32 B2.B16, B2.B16
		VREV32 B3.B16, B3.B16
		TRANSPOSE_MATRIX(T1, T2, B2, B3, K0)

		// encryption first 4 blocks
		PRE_TRANSPOSE_MATRIX(B4, B5, B6, B7, K0)
		MOVD	rkSave, rk

decOctetsEnc4Blocks2:	
			SM4_ROUND(rk, K0, K1, K2, B4, B5, B6, B7)
			SM4_ROUND(rk, K0, K1, K2, B5, B6, B7, B4)
			SM4_ROUND(rk, K0, K1, K2, B6, B7, B4, B5)
			SM4_ROUND(rk, K0, K1, K2, B7, B4, B5, B6)

		ADD $1, R13
		CMP $16, R13
		BNE decOctetsEnc4Blocks2
		VREV32 B4.B16, B4.B16
		VREV32 B5.B16, B5.B16
		VREV32 B6.B16, B6.B16
		VREV32 B7.B16, B7.B16
		TRANSPOSE_MATRIX(B4, B5, B6, B7, K0)

		VLD1.P	32(srcPtr), [B0.B16, B1.B16]
		VEOR	B0.B16, T1.B16, T1.B16
		VEOR	B1.B16, T2.B16, T2.B16
		VST1.P  [T1.B16, T2.B16], 32(dstPtr)

		VLD1.P	32(pTbl), [T1.B16, T2.B16]
		VREV64	B0.B16, B0.B16
		VEOR	ACC0.B16, B0.B16, B0.B16
		VEXT	$8, B0.B16, B0.B16, T0.B16
		VEOR	B0.B16, T0.B16, T0.B16
		VPMULL	B0.D1, T1.D1, ACC1.Q1
		VPMULL2	B0.D2, T1.D2, ACC0.Q1
		VPMULL	T0.D1, T2.D1, ACCM.Q1
		mulRound(B1)

		VLD1.P	32(srcPtr), [B0.B16, B1.B16]
		VEOR	B2.B16, B0.B16, T1.B16
		VEOR	B3.B16, B1.B16, T2.B16
		VST1.P  [T1.B16, T2.B16], 32(dstPtr)
		mulRound(B0)
		mulRound(B1)

		VLD1.P	32(srcPtr), [B0.B16, B1.B16]
		VEOR	B4.B16, B0.B16, T1.B16
		VEOR	B5.B16, B1.B16, T2.B16
		VST1.P  [T1.B16, T2.B16], 32(dstPtr)
		mulRound(B0)
		mulRound(B1)

		VLD1.P	32(srcPtr), [B0.B16, B1.B16]
		VEOR	B6.B16, B0.B16, T1.B16
		VEOR	B7.B16, B1.B16, T2.B16
		VST1.P  [T1.B16, T2.B16], 32(dstPtr)
		mulRound(B0)
		mulRound(B1)

		MOVD	pTblSave, pTbl
		reduce()

		CMP	$128, srcPtrLen
		BGE	decOctetsLoop

decNibblesLoop:
	CBZ	srcPtrLen, decDone
	ADD	$14*16, pTbl
	// Preload H and its Karatsuba precomp
	VLD1.P	(pTbl), [T1.B16, T2.B16]
	CMP	$64, srcPtrLen
	BLT	decStartSingles
	SUB	$64, srcPtrLen

	// Prepare 4 counters
	VMOV	CTR.B16, B0.B16
	VADD	B0.S4, INC.S4, B1.S4
	VADD	B1.S4, INC.S4, B2.S4
	VADD	B2.S4, INC.S4, B3.S4
	VADD	B3.S4, INC.S4, CTR.S4

	// encryption first 4 blocks
	PRE_TRANSPOSE_MATRIX(B0, B1, B2, B3, K0)
	EOR R13, R13
	MOVD	rkSave, rk

decNibblesEnc4Blocks:	
		SM4_ROUND(rk, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, K0, K1, K2, B3, B0, B1, B2)

	ADD $1, R13
	CMP $8, R13
	BNE decNibblesEnc4Blocks
	VREV32 B0.B16, B0.B16
	VREV32 B1.B16, B1.B16
	VREV32 B2.B16, B2.B16
	VREV32 B3.B16, B3.B16
	TRANSPOSE_MATRIX(B0, B1, B2, B3, K0)

	// XOR plaintext and store ciphertext
	VLD1.P	32(srcPtr), [K1.B16, K2.B16]
	VREV64	K1.B16, B4.B16
	VREV64	K2.B16, B5.B16
	VEOR	B0.B16, K1.B16, B0.B16
	VEOR	B1.B16, K2.B16, B1.B16
	VST1.P  [B0.B16, B1.B16], 32(dstPtr)
	VLD1.P	32(srcPtr), [K1.B16, K2.B16]
	VREV64	K1.B16, B6.B16
	VREV64	K2.B16, B7.B16
	VEOR	B2.B16, K1.B16, B2.B16
	VEOR	B3.B16, K2.B16, B3.B16
	VST1.P  [B2.B16, B3.B16], 32(dstPtr)
	mulRoundSingleWithoutRev(B4)
	mulRoundSingleWithoutRev(B5)
	mulRoundSingleWithoutRev(B6)
	mulRoundSingleWithoutRev(B7)

decStartSingles:
	CBZ	srcPtrLen, decDone

	// Prepare 4 counters
	VMOV	CTR.B16, B0.B16
	VADD	B0.S4, INC.S4, B1.S4
	VADD	B1.S4, INC.S4, B2.S4
	VADD	B2.S4, INC.S4, B3.S4
	VADD	B3.S4, INC.S4, CTR.S4

	// encryption first 4 blocks
	PRE_TRANSPOSE_MATRIX(B0, B1, B2, B3, K0)
	EOR R13, R13
	MOVD	rkSave, rk

decSinglesEnc4Blocks:	
		SM4_ROUND(rk, K0, K1, K2, B0, B1, B2, B3)
		SM4_ROUND(rk, K0, K1, K2, B1, B2, B3, B0)
		SM4_ROUND(rk, K0, K1, K2, B2, B3, B0, B1)
		SM4_ROUND(rk, K0, K1, K2, B3, B0, B1, B2)

	ADD $1, R13
	CMP $8, R13
	BNE decSinglesEnc4Blocks
	VREV32 B0.B16, B0.B16
	VREV32 B1.B16, B1.B16
	VREV32 B2.B16, B2.B16
	VREV32 B3.B16, B3.B16
	TRANSPOSE_MATRIX(B0, B1, B2, B3, K0)

	VMOV B0.B16, K0.B16
	CMP	$16, srcPtrLen
	BLT	decTail
	SUB	$16, srcPtrLen
	VLD1.P	16(srcPtr), [K1.B16]
	VREV64	K1.B16, B5.B16
	VEOR	K0.B16, K1.B16, K0.B16		
	VST1.P  [K0.B16], 16(dstPtr)
	mulRoundSingleWithoutRev(B5)

	VMOV B1.B16, K0.B16
	CMP	$16, srcPtrLen
	BLT	decTail
	SUB	$16, srcPtrLen
	VLD1.P	16(srcPtr), [K1.B16]
	VREV64	K1.B16, B5.B16
	VEOR	K0.B16, K1.B16, K0.B16		
	VST1.P  [K0.B16], 16(dstPtr)
	mulRoundSingleWithoutRev(B5)

	VMOV B2.B16, K0.B16
	CMP	$16, srcPtrLen
	BLT	decTail
	SUB	$16, srcPtrLen
	VLD1.P	16(srcPtr), [K1.B16]
	VREV64	K1.B16, B5.B16
	VEOR	K0.B16, K1.B16, K0.B16		
	VST1.P  [K0.B16], 16(dstPtr)
	mulRoundSingleWithoutRev(B5)

	VMOV B3.B16, K0.B16
	CMP	$16, srcPtrLen
	BLT	decTail
	SUB	$16, srcPtrLen
	VLD1.P	16(srcPtr), [K1.B16]
	VREV64	K1.B16, B5.B16
	VEOR	K0.B16, K1.B16, K0.B16		
	VST1.P  [K0.B16], 16(dstPtr)
	mulRoundSingleWithoutRev(B5)

decTail:
	CBZ	srcPtrLen, decDone
	// Assuming it is safe to load past dstPtr due to the presence of the tag
	VLD1	(srcPtr), [B5.B16]

	VEOR	B5.B16, K0.B16, B0.B16

	VEOR	T3.B16, T3.B16, T3.B16
	MOVD	$0, H1
	SUB	$1, H1

	TBZ	$3, srcPtrLen, decLd4
	VMOV	B0.D[0], H0
	MOVD.P	H0, 8(dstPtr)
	VMOV	H1, T3.D[0]
	VEXT	$8, ZERO.B16, B0.B16, B0.B16

decLd4:
	TBZ	$2, srcPtrLen, decLd2
	VMOV	B0.S[0], H0
	MOVW.P	H0, 4(dstPtr)
	VEXT	$12, T3.B16, ZERO.B16, T3.B16
	VMOV	H1, T3.S[0]
	VEXT	$4, ZERO.B16, B0.B16, B0.B16
decLd2:
	TBZ	$1, srcPtrLen, decLd1
	VMOV	B0.H[0], H0
	MOVH.P	H0, 2(dstPtr)
	VEXT	$14, T3.B16, ZERO.B16, T3.B16
	VMOV	H1, T3.H[0]
	VEXT	$2, ZERO.B16, B0.B16, B0.B16
decLd1:
	TBZ	$0, srcPtrLen, decLd0
	VMOV	B0.B[0], H0
	MOVB.P	H0, 1(dstPtr)
	VEXT	$15, T3.B16, ZERO.B16, T3.B16
	VMOV	H1, T3.B[0]
decLd0:

	VAND	T3.B16, B5.B16, B5.B16
	VREV64	B5.B16, B5.B16

	VEOR	ACC0.B16, B5.B16, B5.B16
	VEXT	$8, B5.B16, B5.B16, T0.B16
	VEOR	B5.B16, T0.B16, T0.B16
	VPMULL	B5.D1, T1.D1, ACC1.Q1
	VPMULL2	B5.D2, T1.D2, ACC0.Q1
	VPMULL	T0.D1, T2.D1, ACCM.Q1
	reduce()

decDone:
	VST1	[ACC0.B16], (tPtr)
	RET
