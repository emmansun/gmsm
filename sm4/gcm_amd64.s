// This is an optimized implementation of AES-GCM using AES-NI and CLMUL-NI
// The implementation uses some optimization as described in:
// [1] Gueron, S., Kounavis, M.E.: Intel® Carry-Less Multiplication
//     Instruction and its Usage for Computing the GCM Mode rev. 2.02
// [2] Gueron, S., Krasnov, V.: Speeding up Counter Mode in Software and
//     Hardware
//go:build amd64 && !purego
// +build amd64,!purego

#include "textflag.h"

#define B0 X0
#define B1 X1
#define B2 X2
#define B3 X3
#define B4 X4
#define B5 X5
#define B6 X6
#define B7 X7

#define DWB0 Y0
#define DWB1 Y2
#define DWB2 Y4
#define DWB3 Y6

#define XDWORD Y1
#define YDWORD Y3
#define XDWTMP0 Y5

#define ACC0 X8
#define ACC1 X9
#define ACCM X10

#define T0 X11
#define T1 X12
#define T2 X13
#define POLY X14
#define BSWAP X15
#define DWBSWAP Y15
#define NIBBLE_MASK Y7
#define X_NIBBLE_MASK X7

DATA gcmPoly<>+0x00(SB)/8, $0x0000000000000001
DATA gcmPoly<>+0x08(SB)/8, $0xc200000000000000

DATA andMask<>+0x00(SB)/8, $0x00000000000000ff
DATA andMask<>+0x08(SB)/8, $0x0000000000000000
DATA andMask<>+0x10(SB)/8, $0x000000000000ffff
DATA andMask<>+0x18(SB)/8, $0x0000000000000000
DATA andMask<>+0x20(SB)/8, $0x0000000000ffffff
DATA andMask<>+0x28(SB)/8, $0x0000000000000000
DATA andMask<>+0x30(SB)/8, $0x00000000ffffffff
DATA andMask<>+0x38(SB)/8, $0x0000000000000000
DATA andMask<>+0x40(SB)/8, $0x000000ffffffffff
DATA andMask<>+0x48(SB)/8, $0x0000000000000000
DATA andMask<>+0x50(SB)/8, $0x0000ffffffffffff
DATA andMask<>+0x58(SB)/8, $0x0000000000000000
DATA andMask<>+0x60(SB)/8, $0x00ffffffffffffff
DATA andMask<>+0x68(SB)/8, $0x0000000000000000
DATA andMask<>+0x70(SB)/8, $0xffffffffffffffff
DATA andMask<>+0x78(SB)/8, $0x0000000000000000
DATA andMask<>+0x80(SB)/8, $0xffffffffffffffff
DATA andMask<>+0x88(SB)/8, $0x00000000000000ff
DATA andMask<>+0x90(SB)/8, $0xffffffffffffffff
DATA andMask<>+0x98(SB)/8, $0x000000000000ffff
DATA andMask<>+0xa0(SB)/8, $0xffffffffffffffff
DATA andMask<>+0xa8(SB)/8, $0x0000000000ffffff
DATA andMask<>+0xb0(SB)/8, $0xffffffffffffffff
DATA andMask<>+0xb8(SB)/8, $0x00000000ffffffff
DATA andMask<>+0xc0(SB)/8, $0xffffffffffffffff
DATA andMask<>+0xc8(SB)/8, $0x000000ffffffffff
DATA andMask<>+0xd0(SB)/8, $0xffffffffffffffff
DATA andMask<>+0xd8(SB)/8, $0x0000ffffffffffff
DATA andMask<>+0xe0(SB)/8, $0xffffffffffffffff
DATA andMask<>+0xe8(SB)/8, $0x00ffffffffffffff

GLOBL gcmPoly<>(SB), (NOPTR+RODATA), $16
GLOBL andMask<>(SB), (NOPTR+RODATA), $240

#include "aesni_macros_amd64.s"

// func gcmSm4Finish(productTable *[256]byte, tagMask, T *[16]byte, pLen, dLen uint64)
TEXT ·gcmSm4Finish(SB),NOSPLIT,$0
#define pTbl DI
#define tMsk SI
#define tPtr DX
#define plen AX
#define dlen CX

	MOVQ productTable+0(FP), pTbl
	MOVQ tagMask+8(FP), tMsk
	MOVQ T+16(FP), tPtr
	MOVQ pLen+24(FP), plen
	MOVQ dLen+32(FP), dlen

	MOVOU (tPtr), ACC0
	MOVOU (tMsk), T2

	MOVOU bswap_mask<>(SB), BSWAP
	MOVOU gcmPoly<>(SB), POLY

	SHLQ $3, plen
	SHLQ $3, dlen

	MOVQ plen, B0
	PINSRQ $1, dlen, B0

	PXOR ACC0, B0

	MOVOU (16*14)(pTbl), ACC0
	MOVOU (16*15)(pTbl), ACCM
	MOVOU ACC0, ACC1

	PCLMULQDQ $0x00, B0, ACC0
	PCLMULQDQ $0x11, B0, ACC1
	PSHUFD $78, B0, T0
	PXOR B0, T0
	PCLMULQDQ $0x00, T0, ACCM

	PXOR ACC0, ACCM
	PXOR ACC1, ACCM
	MOVOU ACCM, T0
	PSRLDQ $8, ACCM
	PSLLDQ $8, T0
	PXOR ACCM, ACC1
	PXOR T0, ACC0

	MOVOU POLY, T0
	PCLMULQDQ $0x01, ACC0, T0
	PSHUFD $78, ACC0, ACC0
	PXOR T0, ACC0

	MOVOU POLY, T0
	PCLMULQDQ $0x01, ACC0, T0
	PSHUFD $78, ACC0, ACC0
	PXOR T0, ACC0

	PXOR ACC1, ACC0

	PSHUFB BSWAP, ACC0
	PXOR T2, ACC0
	MOVOU ACC0, (tPtr)

	RET

#undef pTbl
#undef tMsk
#undef tPtr
#undef plen
#undef dlen

// func gcmSm4Init(productTable *[256]byte, rk []uint32)
TEXT ·gcmSm4Init(SB),NOSPLIT,$0
#define dst DI
#define RK SI

	MOVQ productTable+0(FP), dst
	MOVQ rk+8(FP), RK

	MOVOU gcmPoly<>(SB), POLY

	// Encrypt block 0, with the sm4 round keys to generate the hash key H
	PXOR B0, B0
	PXOR B1, B1
	PXOR B2, B2
	PXOR B3, B3
	XORL CX, CX

sm4InitEncLoop:
	SM4_SINGLE_ROUND(0, RK, CX, T0, T1, T2, B3, B2, B1, B0)
	SM4_SINGLE_ROUND(1, RK, CX, T0, T1, T2, B2, B1, B0, B3)
	SM4_SINGLE_ROUND(2, RK, CX, T0, T1, T2, B1, B0, B3, B2)
	SM4_SINGLE_ROUND(3, RK, CX, T0, T1, T2, B0, B3, B2, B1)

	ADDL $16, CX
	CMPL CX, $4*32
	JB sm4InitEncLoop

	PALIGNR $4, B3, B3
	PALIGNR $4, B3, B2
	PALIGNR $4, B2, B1
	PALIGNR $4, B1, B0

	// H * 2
	PSHUFD $0xff, B0, T0
	MOVOU B0, T1
	PSRAL $31, T0
	PAND POLY, T0
	PSRLL $31, T1
	PSLLDQ $4, T1
	PSLLL $1, B0
	PXOR T0, B0
	PXOR T1, B0
	// Karatsuba pre-computations
	MOVOU B0, (16*14)(dst)
	PSHUFD $78, B0, B1
	PXOR B0, B1
	MOVOU B1, (16*15)(dst)

	MOVOU B0, B2
	MOVOU B1, B3
	// Now prepare powers of H and pre-computations for them
	MOVQ $7, AX

initLoop:
		MOVOU B2, T0
		MOVOU B2, T1
		MOVOU B3, T2
		PCLMULQDQ $0x00, B0, T0
		PCLMULQDQ $0x11, B0, T1
		PCLMULQDQ $0x00, B1, T2

		PXOR T0, T2
		PXOR T1, T2
		MOVOU T2, B4
		PSLLDQ $8, B4
		PSRLDQ $8, T2
		PXOR B4, T0
		PXOR T2, T1

		MOVOU POLY, B2
		PCLMULQDQ $0x01, T0, B2
		PSHUFD $78, T0, T0
		PXOR B2, T0
		MOVOU POLY, B2
		PCLMULQDQ $0x01, T0, B2
		PSHUFD $78, T0, T0
		PXOR T0, B2
		PXOR T1, B2

		MOVOU B2, (16*12)(dst)
		PSHUFD $78, B2, B3
		PXOR B2, B3
		MOVOU B3, (16*13)(dst)

		DECQ AX
		LEAQ (-16*2)(dst), dst
	JNE initLoop

	RET

#undef RK
#undef dst

// func gcmSm4Data(productTable *[256]byte, data []byte, T *[16]byte)
TEXT ·gcmSm4Data(SB),NOSPLIT,$0
#define pTbl DI
#define aut SI
#define tPtr CX
#define autLen DX

#define reduceRound(a) 	MOVOU POLY, T0;	PCLMULQDQ $0x01, a, T0; PSHUFD $78, a, a; PXOR T0, a
#define avxReduceRound(a) 	VPCLMULQDQ $0x01, a, POLY, T0; VPSHUFD $78, a, a; VPXOR T0, a, a
#define mulRoundAAD(X ,i) \
	MOVOU (16*(i*2))(pTbl), T1;\
	MOVOU T1, T2;\
	PCLMULQDQ $0x00, X, T1;\
	PXOR T1, ACC0;\
	PCLMULQDQ $0x11, X, T2;\
	PXOR T2, ACC1;\
	PSHUFD $78, X, T1;\
	PXOR T1, X;\
	MOVOU (16*(i*2+1))(pTbl), T1;\
	PCLMULQDQ $0x00, X, T1;\
	PXOR T1, ACCM

	MOVQ productTable+0(FP), pTbl
	MOVQ data_base+8(FP), aut
	MOVQ data_len+16(FP), autLen
	MOVQ T+32(FP), tPtr

	PXOR ACC0, ACC0
	// MOVOU (tPtr), ACC0 // originally we passed in tag initial value
	MOVOU bswap_mask<>(SB), BSWAP
	MOVOU gcmPoly<>(SB), POLY

	TESTQ autLen, autLen
	JEQ dataBail

	CMPQ autLen, $13	// optimize the TLS case
	JE dataTLS
	CMPQ autLen, $128
	JB startSinglesLoop
	JMP dataOctaLoop

dataTLS:
	MOVOU (16*14)(pTbl), T1
	MOVOU (16*15)(pTbl), T2
	PXOR B0, B0
	MOVQ (aut), B0
	PINSRD $2, 8(aut), B0
	PINSRB $12, 12(aut), B0
	XORQ autLen, autLen
	JMP dataMul

dataOctaLoop:
		CMPQ autLen, $128
		JB startSinglesLoop
		SUBQ $128, autLen

		MOVOU (16*0)(aut), X0
		MOVOU (16*1)(aut), X1
		MOVOU (16*2)(aut), X2
		MOVOU (16*3)(aut), X3
		MOVOU (16*4)(aut), X4
		MOVOU (16*5)(aut), X5
		MOVOU (16*6)(aut), X6
		MOVOU (16*7)(aut), X7
		LEAQ (16*8)(aut), aut
		PSHUFB BSWAP, X0
		PSHUFB BSWAP, X1
		PSHUFB BSWAP, X2
		PSHUFB BSWAP, X3
		PSHUFB BSWAP, X4
		PSHUFB BSWAP, X5
		PSHUFB BSWAP, X6
		PSHUFB BSWAP, X7
		PXOR ACC0, X0

		MOVOU (16*0)(pTbl), ACC0
		MOVOU (16*1)(pTbl), ACCM
		MOVOU ACC0, ACC1
		PSHUFD $78, X0, T1
		PXOR X0, T1
		PCLMULQDQ $0x00, X0, ACC0
		PCLMULQDQ $0x11, X0, ACC1
		PCLMULQDQ $0x00, T1, ACCM

		mulRoundAAD(X1, 1)
		mulRoundAAD(X2, 2)
		mulRoundAAD(X3, 3)
		mulRoundAAD(X4, 4)
		mulRoundAAD(X5, 5)
		mulRoundAAD(X6, 6)
		mulRoundAAD(X7, 7)

		PXOR ACC0, ACCM
		PXOR ACC1, ACCM
		MOVOU ACCM, T0
		PSRLDQ $8, ACCM
		PSLLDQ $8, T0
		PXOR ACCM, ACC1
		PXOR T0, ACC0
		reduceRound(ACC0)
		reduceRound(ACC0)
		PXOR ACC1, ACC0
	JMP dataOctaLoop

startSinglesLoop:
	MOVOU (16*14)(pTbl), T1
	MOVOU (16*15)(pTbl), T2

dataSinglesLoop:

		CMPQ autLen, $16
		JB dataEnd
		SUBQ $16, autLen

		MOVOU (aut), B0
dataMul:
		PSHUFB BSWAP, B0
		PXOR ACC0, B0

		MOVOU T1, ACC0
		MOVOU T2, ACCM
		MOVOU T1, ACC1

		PSHUFD $78, B0, T0
		PXOR B0, T0
		PCLMULQDQ $0x00, B0, ACC0
		PCLMULQDQ $0x11, B0, ACC1
		PCLMULQDQ $0x00, T0, ACCM

		PXOR ACC0, ACCM
		PXOR ACC1, ACCM
		MOVOU ACCM, T0
		PSRLDQ $8, ACCM
		PSLLDQ $8, T0
		PXOR ACCM, ACC1
		PXOR T0, ACC0

		MOVOU POLY, T0
		PCLMULQDQ $0x01, ACC0, T0
		PSHUFD $78, ACC0, ACC0
		PXOR T0, ACC0

		MOVOU POLY, T0
		PCLMULQDQ $0x01, ACC0, T0
		PSHUFD $78, ACC0, ACC0
		PXOR T0, ACC0
		PXOR ACC1, ACC0

		LEAQ 16(aut), aut

	JMP dataSinglesLoop

dataEnd:

	TESTQ autLen, autLen
	JEQ dataBail

	PXOR B0, B0
	LEAQ -1(aut)(autLen*1), aut

dataLoadLoop:

		PSLLDQ $1, B0
		PINSRB $0, (aut), B0

		LEAQ -1(aut), aut
		DECQ autLen
		JNE dataLoadLoop

	JMP dataMul

dataBail:
	MOVOU ACC0, (tPtr)
	RET

#undef pTbl
#undef aut
#undef tPtr
#undef autLen


// func gcmSm4Enc(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)
TEXT ·gcmSm4Enc(SB),0,$256-96
#define pTbl DI
#define ctx DX
#define ctrPtr CX
#define ptx SI
#define rk AX
#define tPtr R8
#define ptxLen R9
#define aluCTR R10
#define aluTMP R11

#define increment(i) ADDL $1, aluCTR; MOVL aluCTR, (3*4 + 8*16 + i*16)(SP)

#define mulRound(i) \
	MOVOU (16*i)(SP), T0;\
	MOVOU (16*(i*2))(pTbl), T1;\
	MOVOU T1, T2;\
	PCLMULQDQ $0x00, T0, T1;\
	PXOR T1, ACC0;\
	PCLMULQDQ $0x11, T0, T2;\
	PXOR T2, ACC1;\
	PSHUFD $78, T0, T1;\
	PXOR T1, T0;\
	MOVOU (16*(i*2+1))(pTbl), T1;\
	PCLMULQDQ $0x00, T0, T1;\
	PXOR T1, ACCM

#define gcmEncDataStep(B) \
	PSHUFB BSWAP, B; \
	PXOR ACC0, B; \
	MOVOU T2, ACC0; \
	MOVOU T2, ACC1; \
	MOVOU (16*15)(pTbl), ACCM; \
	PSHUFD $78, B, T0; \
	PXOR B, T0; \
	PCLMULQDQ $0x00, B, ACC0; \
	PCLMULQDQ $0x11, B, ACC1; \
	PCLMULQDQ $0x00, T0, ACCM; \
	PXOR ACC0, ACCM; \
	PXOR ACC1, ACCM; \
	MOVOU ACCM, T0; \
	PSRLDQ $8, ACCM; \
	PSLLDQ $8, T0; \
	PXOR ACCM, ACC1; \
	PXOR T0, ACC0; \
	reduceRound(ACC0); \
	reduceRound(ACC0); \
	PXOR ACC1, ACC0

#define avxMulRound(i) \
	VMOVDQU (16*i)(SP), T0;\
	VMOVDQU (16*(i*2))(pTbl), T2;\
	VPCLMULQDQ $0x00, T0, T2, T1;\
	VPXOR T1, ACC0, ACC0;\
	VPCLMULQDQ $0x11, T0, T2, T2;\
	VPXOR T2, ACC1, ACC1;\
	VPSHUFD $78, T0, T1;\
	VPXOR T1, T0, T0;\
	VMOVDQU (16*(i*2+1))(pTbl), T1;\
	VPCLMULQDQ $0x00, T0, T1, T1;\
	VPXOR T1, ACCM, ACCM

#define avxGcmEncDataStep(B) \
	VPSHUFB BSWAP, B, B; \
	VPXOR ACC0, B, B; \
	VMOVDQU (16*15)(pTbl), ACCM; \
	VPSHUFD $78, B, T0; \
	VPXOR B, T0, T0; \
	VPCLMULQDQ $0x00, B, T2, ACC0; \
	VPCLMULQDQ $0x11, B, T2, ACC1; \
	VPCLMULQDQ $0x00, T0, ACCM, ACCM; \
	VPXOR ACC0, ACCM, ACCM; \
	VPXOR ACC1, ACCM, ACCM; \
	VPSLLDQ $8, ACCM, T0; \
	VPSRLDQ $8, ACCM, ACCM; \
	VPXOR ACCM, ACC1, ACC1; \
	VPXOR T0, ACC0, ACC0; \
	avxReduceRound(ACC0); \
	avxReduceRound(ACC0); \
	VPXOR ACC1, ACC0, ACC0

	MOVQ productTable+0(FP), pTbl
	MOVQ dst+8(FP), ctx
	MOVQ src_base+32(FP), ptx
	MOVQ src_len+40(FP), ptxLen
	MOVQ ctr+56(FP), ctrPtr
	MOVQ T+64(FP), tPtr
	MOVQ rk_base+72(FP), rk

	CMPB ·useAVX2(SB), $1
	JE   avx2GcmSm4Enc

	CMPB ·useAVX(SB), $1
	JE   avxGcmSm4Enc

	MOVOU bswap_mask<>(SB), BSWAP
	MOVOU gcmPoly<>(SB), POLY

	MOVOU (tPtr), ACC0
	PXOR ACC1, ACC1
	PXOR ACCM, ACCM
	MOVOU (ctrPtr), T0
	PSHUFB flip_mask<>(SB), T0
	PEXTRD $3, T0, aluCTR

	MOVOU T0, (8*16 + 0*16)(SP)
	increment(0)
	MOVOU T0, (8*16 + 1*16)(SP)
	increment(1)
	MOVOU T0, (8*16 + 2*16)(SP)
	increment(2)
	MOVOU T0, (8*16 + 3*16)(SP)
	increment(3)

	CMPQ ptxLen, $128
	JB gcmSm4EncNibbles
	SUBQ $128, ptxLen

	// We have at least 8 blocks to encrypt, prepare the rest of the counters
	MOVOU T0, (8*16 + 4*16)(SP)
	increment(4)
	MOVOU T0, (8*16 + 5*16)(SP)
	increment(5)
	MOVOU T0, (8*16 + 6*16)(SP)
	increment(6)
	MOVOU T0, (8*16 + 7*16)(SP)
	increment(7)

	// load 8 ctrs for encryption
	MOVOU (8*16 + 0*16)(SP), B0
	MOVOU (8*16 + 1*16)(SP), B1
	MOVOU (8*16 + 2*16)(SP), B2
	MOVOU (8*16 + 3*16)(SP), B3
	MOVOU (8*16 + 4*16)(SP), B4
	MOVOU (8*16 + 5*16)(SP), B5
	MOVOU (8*16 + 6*16)(SP), B6
	MOVOU (8*16 + 7*16)(SP), B7

	SM4_8BLOCKS_WO_BS(rk, ACC1, T0, T1, T2, B0, B1, B2, B3, B4, B5, B6, B7)
	increment(0)

	// XOR plaintext
	MOVOU (16*0)(ptx), T0
	PXOR T0, B0
	increment(1)
	MOVOU (16*1)(ptx), T0
	PXOR T0, B1
	increment(2)
	MOVOU (16*2)(ptx), T0
	PXOR T0, B2
	increment(3)
	MOVOU (16*3)(ptx), T0
	PXOR T0, B3
	increment(4)
	MOVOU (16*4)(ptx), T0
	PXOR T0, B4
	increment(5)
	MOVOU (16*5)(ptx), T0
	PXOR T0, B5
	increment(6)
	MOVOU (16*6)(ptx), T0
	PXOR T0, B6
	increment(7)
	MOVOU (16*7)(ptx), T0
	PXOR T0, B7

	// Store ciphertext
	MOVOU B0, (16*0)(ctx)
	PSHUFB BSWAP, B0
	PXOR ACC0, B0
	MOVOU B1, (16*1)(ctx)
	PSHUFB BSWAP, B1
	MOVOU B2, (16*2)(ctx)
	PSHUFB BSWAP, B2
	MOVOU B3, (16*3)(ctx)
	PSHUFB BSWAP, B3
	MOVOU B4, (16*4)(ctx)
	PSHUFB BSWAP, B4
	MOVOU B5, (16*5)(ctx)
	PSHUFB BSWAP, B5
	MOVOU B6, (16*6)(ctx)
	PSHUFB BSWAP, B6
	MOVOU B7, (16*7)(ctx)
	PSHUFB BSWAP, B7

	MOVOU B0, (16*0)(SP)
	MOVOU B1, (16*1)(SP)
	MOVOU B2, (16*2)(SP)
	MOVOU B3, (16*3)(SP)
	MOVOU B4, (16*4)(SP)
	MOVOU B5, (16*5)(SP)
	MOVOU B6, (16*6)(SP)
	MOVOU B7, (16*7)(SP)

	LEAQ 128(ptx), ptx
	LEAQ 128(ctx), ctx

gcmSm4EncOctetsLoop:
		CMPQ ptxLen, $128
		JB gcmSm4EncOctetsEnd
		SUBQ $128, ptxLen

		MOVOU (8*16 + 0*16)(SP), B0
		MOVOU (8*16 + 1*16)(SP), B1
		MOVOU (8*16 + 2*16)(SP), B2
		MOVOU (8*16 + 3*16)(SP), B3
		MOVOU (8*16 + 4*16)(SP), B4
		MOVOU (8*16 + 5*16)(SP), B5
		MOVOU (8*16 + 6*16)(SP), B6
		MOVOU (8*16 + 7*16)(SP), B7

		MOVOU (16*0)(SP), T0
		PSHUFD $78, T0, T1
		PXOR T0, T1

		MOVOU (16*0)(pTbl), ACC0
		MOVOU (16*1)(pTbl), ACCM
		MOVOU ACC0, ACC1

		PCLMULQDQ $0x00, T1, ACCM
		PCLMULQDQ $0x00, T0, ACC0
		PCLMULQDQ $0x11, T0, ACC1

		mulRound(1)
		increment(0)
		mulRound(2)
		increment(1)
		mulRound(3)
		increment(2)
	 	mulRound(4)
		increment(3)
		mulRound(5)
		increment(4)
		mulRound(6)
		increment(5)
	 	mulRound(7)
		increment(6)
		
		PXOR ACC0, ACCM
		PXOR ACC1, ACCM
		MOVOU ACCM, T0
		PSRLDQ $8, ACCM
		PSLLDQ $8, T0
		PXOR ACCM, ACC1
		PXOR T0, ACC0
		
		increment(7)
		reduceRound(ACC0)
		reduceRound(ACC0)
		PXOR ACC1, ACC0
		
		SM4_8BLOCKS_WO_BS(rk, ACC1, T0, T1, T2, B0, B1, B2, B3, B4, B5, B6, B7)

		PXOR (16*0)(ptx), B0
		PXOR (16*1)(ptx), B1
		PXOR (16*2)(ptx), B2
		PXOR (16*3)(ptx), B3
		PXOR (16*4)(ptx), B4
		PXOR (16*5)(ptx), B5
		PXOR (16*6)(ptx), B6
		PXOR (16*7)(ptx), B7

		MOVOU B0, (16*0)(ctx)
		PSHUFB BSWAP, B0
		PXOR ACC0, B0
		MOVOU B1, (16*1)(ctx)
		PSHUFB BSWAP, B1
		MOVOU B2, (16*2)(ctx)
		PSHUFB BSWAP, B2
		MOVOU B3, (16*3)(ctx)
		PSHUFB BSWAP, B3
		MOVOU B4, (16*4)(ctx)
		PSHUFB BSWAP, B4
		MOVOU B5, (16*5)(ctx)
		PSHUFB BSWAP, B5
		MOVOU B6, (16*6)(ctx)
		PSHUFB BSWAP, B6
		MOVOU B7, (16*7)(ctx)
		PSHUFB BSWAP, B7

		MOVOU B0, (16*0)(SP)
		MOVOU B1, (16*1)(SP)
		MOVOU B2, (16*2)(SP)
		MOVOU B3, (16*3)(SP)
		MOVOU B4, (16*4)(SP)
		MOVOU B5, (16*5)(SP)
		MOVOU B6, (16*6)(SP)
		MOVOU B7, (16*7)(SP)

		LEAQ 128(ptx), ptx
		LEAQ 128(ctx), ctx

		JMP gcmSm4EncOctetsLoop

gcmSm4EncOctetsEnd:
	MOVOU (16*0)(SP), T0
	MOVOU (16*0)(pTbl), ACC0
	MOVOU (16*1)(pTbl), ACCM
	MOVOU ACC0, ACC1
	PSHUFD $78, T0, T1
	PXOR T0, T1
	PCLMULQDQ $0x00, T0, ACC0
	PCLMULQDQ $0x11, T0, ACC1
	PCLMULQDQ $0x00, T1, ACCM

	mulRound(1)
	mulRound(2)
	mulRound(3)
	mulRound(4)
	mulRound(5)
	mulRound(6)
	mulRound(7)

	PXOR ACC0, ACCM
	PXOR ACC1, ACCM
	MOVOU ACCM, T0
	PSRLDQ $8, ACCM
	PSLLDQ $8, T0
	PXOR ACCM, ACC1
	PXOR T0, ACC0

	reduceRound(ACC0)
	reduceRound(ACC0)
	PXOR ACC1, ACC0

	TESTQ ptxLen, ptxLen
	JE gcmSm4EncDone

	SUBQ $4, aluCTR

gcmSm4EncNibbles:
	CMPQ ptxLen, $64
	JBE gcmSm4EncSingles
	SUBQ $64, ptxLen

	MOVOU (8*16 + 0*16)(SP), B0
	MOVOU (8*16 + 1*16)(SP), B1
	MOVOU (8*16 + 2*16)(SP), B2
	MOVOU (8*16 + 3*16)(SP), B3
	
	SM4_4BLOCKS_WO_BS(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	PXOR (16*0)(ptx), B0
	PXOR (16*1)(ptx), B1
	PXOR (16*2)(ptx), B2
	PXOR (16*3)(ptx), B3

	MOVOU B0, (16*0)(ctx)
	MOVOU B1, (16*1)(ctx)
	MOVOU B2, (16*2)(ctx)
	MOVOU B3, (16*3)(ctx)

	MOVOU (16*14)(pTbl), T2
	increment(0)
	gcmEncDataStep(B0)
	increment(1)
	gcmEncDataStep(B1)
	increment(2)
	gcmEncDataStep(B2)
	increment(3)
	gcmEncDataStep(B3)

	LEAQ 64(ptx), ptx
	LEAQ 64(ctx), ctx

gcmSm4EncSingles:
	TESTQ ptxLen, ptxLen
	JE gcmSm4EncDone
	MOVOU (8*16 + 0*16)(SP), B0
	MOVOU (8*16 + 1*16)(SP), B1
	MOVOU (8*16 + 2*16)(SP), B2
	MOVOU (8*16 + 3*16)(SP), B3
	
	SM4_4BLOCKS_WO_BS(AX, B4, T0, T1, T2, B0, B1, B2, B3)
	MOVOU B0, (16*0)(SP)
	MOVOU B1, (16*1)(SP)
	MOVOU B2, (16*2)(SP)
	MOVOU B3, (16*3)(SP)

	MOVOU (16*14)(pTbl), T2
	MOVQ SP, BP

gcmSm4EncSinglesLoop:
		CMPQ ptxLen, $16
		JB gcmSm4EncTail
		SUBQ $16, ptxLen
		MOVOU (16*0)(BP), B0
		MOVOU (ptx), T0
		PXOR T0, B0
		MOVOU B0, (ctx)
		gcmEncDataStep(B0)
		LEAQ (16*1)(ptx), ptx
		LEAQ (16*1)(ctx), ctx
		ADDQ $16, BP
	JMP gcmSm4EncSinglesLoop		

gcmSm4EncTail:
	TESTQ ptxLen, ptxLen
	JE gcmSm4EncDone
	MOVOU (16*0)(BP), B0
	MOVOU B0, T0

	LEAQ -1(ptx)(ptxLen*1), ptx

	MOVQ ptxLen, aluTMP
	SHLQ $4, aluTMP

	LEAQ andMask<>(SB), aluCTR
	MOVOU -16(aluCTR)(aluTMP*1), T1
	PXOR B0, B0
ptxLoadLoop:
		PSLLDQ $1, B0
		PINSRB $0, (ptx), B0
		LEAQ -1(ptx), ptx
		DECQ ptxLen
	JNE ptxLoadLoop

	PXOR T0, B0
	PAND T1, B0
	MOVOU B0, (ctx)	// I assume there is always space, due to TAG in the end of the CT
	gcmEncDataStep(B0)

gcmSm4EncDone:
	MOVOU ACC0, (tPtr)
	RET

avxGcmSm4Enc:
	VMOVDQU bswap_mask<>(SB), BSWAP
	VMOVDQU gcmPoly<>(SB), POLY

	VMOVDQU (tPtr), ACC0
	VPXOR ACC1, ACC1, ACC1
	VPXOR ACCM, ACCM, ACCM
	VMOVDQU (ctrPtr), T0
	VPSHUFB flip_mask<>(SB), T0, T0
	VPEXTRD $3, T0, aluCTR

	VMOVDQU T0, (8*16 + 0*16)(SP)
	increment(0)
	VMOVDQU T0, (8*16 + 1*16)(SP)
	increment(1)
	VMOVDQU T0, (8*16 + 2*16)(SP)
	increment(2)
	VMOVDQU T0, (8*16 + 3*16)(SP)
	increment(3)

	CMPQ ptxLen, $128
	JB avxGcmSm4EncNibbles
	SUBQ $128, ptxLen

	// We have at least 8 blocks to encrypt, prepare the rest of the counters
	VMOVDQU T0, (8*16 + 4*16)(SP)
	increment(4)
	VMOVDQU T0, (8*16 + 5*16)(SP)
	increment(5)
	VMOVDQU T0, (8*16 + 6*16)(SP)
	increment(6)
	VMOVDQU T0, (8*16 + 7*16)(SP)
	increment(7)

	// load 8 ctrs for encryption
	VMOVDQU (8*16 + 0*16)(SP), B0
	VMOVDQU (8*16 + 1*16)(SP), B1
	VMOVDQU (8*16 + 2*16)(SP), B2
	VMOVDQU (8*16 + 3*16)(SP), B3
	VMOVDQU (8*16 + 4*16)(SP), B4
	VMOVDQU (8*16 + 5*16)(SP), B5
	VMOVDQU (8*16 + 6*16)(SP), B6
	VMOVDQU (8*16 + 7*16)(SP), B7

	AVX_SM4_8BLOCKS_WO_BS(rk, ACC1, T0, T1, T2, B0, B1, B2, B3, B4, B5, B6, B7)
	increment(0)
	
	// XOR plaintext
	VPXOR (16*0)(ptx), B0, B0
	VPXOR (16*1)(ptx), B1, B1
	increment(1)
	VPXOR (16*2)(ptx), B2, B2
	VPXOR (16*3)(ptx), B3, B3
	increment(2)
	VPXOR (16*4)(ptx), B4, B4
	VPXOR (16*5)(ptx), B5, B5
	increment(3)
	VPXOR (16*6)(ptx), B6, B6
	VPXOR (16*7)(ptx), B7, B7	
	// Store ciphertext
	VMOVDQU B0, (16*0)(ctx)
	VPSHUFB BSWAP, B0, B0
	increment(4)
	VMOVDQU B1, (16*1)(ctx)
	VPSHUFB BSWAP, B1, B1
	increment(5)
	VMOVDQU B2, (16*2)(ctx)
	VPSHUFB BSWAP, B2, B2
	increment(6)
	VMOVDQU B3, (16*3)(ctx)
	VPSHUFB BSWAP, B3, B3
	increment(7)
	VMOVDQU B4, (16*4)(ctx)
	VPSHUFB BSWAP, B4, B4
	VMOVDQU B5, (16*5)(ctx)
	VPSHUFB BSWAP, B5, B5
	VMOVDQU B6, (16*6)(ctx)
	VPSHUFB BSWAP, B6, B6
	VMOVDQU B7, (16*7)(ctx)
	VPSHUFB BSWAP, B7, B7

	VPXOR ACC0, B0, B0

	VMOVDQU B0, (16*0)(SP)
	VMOVDQU B1, (16*1)(SP)
	VMOVDQU B2, (16*2)(SP)
	VMOVDQU B3, (16*3)(SP)
	VMOVDQU B4, (16*4)(SP)
	VMOVDQU B5, (16*5)(SP)
	VMOVDQU B6, (16*6)(SP)
	VMOVDQU B7, (16*7)(SP)

	LEAQ 128(ptx), ptx
	LEAQ 128(ctx), ctx	

avxGcmSm4EncOctetsLoop:
		CMPQ ptxLen, $128
		JB avxGcmSm4EncOctetsEnd
		SUBQ $128, ptxLen

		// load 8 ctrs for encryption
		VMOVDQU (8*16 + 0*16)(SP), B0
		VMOVDQU (8*16 + 1*16)(SP), B1
		VMOVDQU (8*16 + 2*16)(SP), B2
		VMOVDQU (8*16 + 3*16)(SP), B3
		VMOVDQU (8*16 + 4*16)(SP), B4
		VMOVDQU (8*16 + 5*16)(SP), B5
		VMOVDQU (8*16 + 6*16)(SP), B6
		VMOVDQU (8*16 + 7*16)(SP), B7

		VMOVDQU (16*0)(SP), T0
		VPSHUFD $78, T0, T1
		VPXOR T0, T1, T1

		VMOVDQU (16*0)(pTbl), ACC1
		VMOVDQU (16*1)(pTbl), ACCM

		VPCLMULQDQ $0x00, T1, ACCM, ACCM
		VPCLMULQDQ $0x00, T0, ACC1, ACC0
		VPCLMULQDQ $0x11, T0, ACC1, ACC1

		avxMulRound(1)
		increment(0)
		avxMulRound(2)
		increment(1)
		avxMulRound(3)
		increment(2)
	 	avxMulRound(4)
		increment(3)
		avxMulRound(5)
		increment(4)
		avxMulRound(6)
		increment(5)
	 	avxMulRound(7)
		increment(6)
		VPXOR ACC0, ACCM, ACCM
		VPXOR ACC1, ACCM, ACCM
		VPSLLDQ $8, ACCM, T0
		VPSRLDQ $8, ACCM, ACCM
		
		VPXOR ACCM, ACC1, ACC1
		VPXOR T0, ACC0, ACC0

		increment(7)
		avxReduceRound(ACC0)
		avxReduceRound(ACC0)
		VPXOR ACC1, ACC0, ACC0

		AVX_SM4_8BLOCKS_WO_BS(rk, ACC1, T0, T1, T2, B0, B1, B2, B3, B4, B5, B6, B7)
		// XOR plaintext
		VPXOR (16*0)(ptx), B0, B0
		VPXOR (16*1)(ptx), B1, B1
		VPXOR (16*2)(ptx), B2, B2
		VPXOR (16*3)(ptx), B3, B3
		VPXOR (16*4)(ptx), B4, B4
		VPXOR (16*5)(ptx), B5, B5
		VPXOR (16*6)(ptx), B6, B6
		VPXOR (16*7)(ptx), B7, B7

		// Store ciphertext
		VMOVDQU B0, (16*0)(ctx)
		VPSHUFB BSWAP, B0, B0
		VMOVDQU B1, (16*1)(ctx)
		VPSHUFB BSWAP, B1, B1
		VMOVDQU B2, (16*2)(ctx)
		VPSHUFB BSWAP, B2, B2
		VMOVDQU B3, (16*3)(ctx)
		VPSHUFB BSWAP, B3, B3
		VMOVDQU B4, (16*4)(ctx)
		VPSHUFB BSWAP, B4, B4
		VMOVDQU B5, (16*5)(ctx)
		VPSHUFB BSWAP, B5, B5
		VMOVDQU B6, (16*6)(ctx)
		VPSHUFB BSWAP, B6, B6
		VMOVDQU B7, (16*7)(ctx)
		VPSHUFB BSWAP, B7, B7

		VPXOR ACC0, B0, B0
		VMOVDQU B0, (16*0)(SP)
		VMOVDQU B1, (16*1)(SP)
		VMOVDQU B2, (16*2)(SP)
		VMOVDQU B3, (16*3)(SP)
		VMOVDQU B4, (16*4)(SP)
		VMOVDQU B5, (16*5)(SP)
		VMOVDQU B6, (16*6)(SP)
		VMOVDQU B7, (16*7)(SP)

		LEAQ 128(ptx), ptx
		LEAQ 128(ctx), ctx	

		JMP avxGcmSm4EncOctetsLoop

avxGcmSm4EncOctetsEnd:
	VMOVDQU (16*0)(SP), T0
	VMOVDQU (16*0)(pTbl), ACC0
	VMOVDQU (16*1)(pTbl), ACCM
	VMOVDQU ACC0, ACC1
	VPSHUFD $78, T0, T1
	VPXOR T0, T1, T1
	VPCLMULQDQ $0x00, T0, ACC0, ACC0
	VPCLMULQDQ $0x11, T0, ACC1, ACC1
	VPCLMULQDQ $0x00, T1, ACCM, ACCM

	avxMulRound(1)
	avxMulRound(2)
	avxMulRound(3)
	avxMulRound(4)
	avxMulRound(5)
	avxMulRound(6)
	avxMulRound(7)

	VPXOR ACC0, ACCM, ACCM
	VPXOR ACC1, ACCM, ACCM
	VPSLLDQ $8, ACCM, T0
	VPSRLDQ $8, ACCM, ACCM
	
	VPXOR ACCM, ACC1, ACC1
	VPXOR T0, ACC0, ACC0

	avxReduceRound(ACC0)
	avxReduceRound(ACC0)
	VPXOR ACC1, ACC0, ACC0

	TESTQ ptxLen, ptxLen
	JE avxGcmSm4EncDone

	SUBQ $4, aluCTR

avxGcmSm4EncNibbles:
	CMPQ ptxLen, $64
	JBE avxGcmSm4EncSingles
	SUBQ $64, ptxLen
	
	// load 4 ctrs for encryption
	VMOVDQU (8*16 + 0*16)(SP), B0
	VMOVDQU (8*16 + 1*16)(SP), B1
	VMOVDQU (8*16 + 2*16)(SP), B2
	VMOVDQU (8*16 + 3*16)(SP), B3

	AVX_SM4_4BLOCKS_WO_BS(rk, B6, B7, T1, T2, B0, B1, B2, B3)
	// XOR plaintext
	VPXOR (16*0)(ptx), B0, B0
	VPXOR (16*1)(ptx), B1, B1
	VPXOR (16*2)(ptx), B2, B2
	VPXOR (16*3)(ptx), B3, B3	

	// Store ciphertext
	VMOVDQU B0, (16*0)(ctx)
	VMOVDQU B1, (16*1)(ctx)
	VMOVDQU B2, (16*2)(ctx)
	VMOVDQU B3, (16*3)(ctx)

	VMOVDQU (16*14)(pTbl), T2
	increment(0)
	avxGcmEncDataStep(B0)
	increment(1)
	avxGcmEncDataStep(B1)
	increment(2)
	avxGcmEncDataStep(B2)
	increment(3)
	avxGcmEncDataStep(B3)
	
	LEAQ 64(ptx), ptx
	LEAQ 64(ctx), ctx

avxGcmSm4EncSingles:
	TESTQ ptxLen, ptxLen
	JE avxGcmSm4EncDone

	VMOVDQU (8*16 + 0*16)(SP), B0
	VMOVDQU (8*16 + 1*16)(SP), B1
	VMOVDQU (8*16 + 2*16)(SP), B2
	VMOVDQU (8*16 + 3*16)(SP), B3

	AVX_SM4_4BLOCKS_WO_BS(rk, B6, B7, T1, T2, B0, B1, B2, B3)
	VMOVDQU B0, (16*0)(SP)
	VMOVDQU B1, (16*1)(SP)
	VMOVDQU B2, (16*2)(SP)
	VMOVDQU B3, (16*3)(SP)

	VMOVDQU (16*14)(pTbl), T2
	MOVQ SP, BP

avxGcmSm4EncSinglesLoop:
		CMPQ ptxLen, $16
		JB avxGcmSm4EncTail
		SUBQ $16, ptxLen
		VMOVDQU (16*0)(BP), B0
		VMOVDQU (ptx), T0
		VPXOR T0, B0, B0
		VMOVDQU B0, (ctx)
		avxGcmEncDataStep(B0)
		LEAQ (16*1)(ptx), ptx
		LEAQ (16*1)(ctx), ctx
		ADDQ $16, BP
	JMP avxGcmSm4EncSinglesLoop

avxGcmSm4EncTail:
	TESTQ ptxLen, ptxLen
	JE avxGcmSm4EncDone
	VMOVDQU (16*0)(BP), B0
	VMOVDQU B0, T0

	LEAQ -1(ptx)(ptxLen*1), ptx

	MOVQ ptxLen, aluTMP
	SHLQ $4, aluTMP

	LEAQ andMask<>(SB), aluCTR
	VMOVDQU -16(aluCTR)(aluTMP*1), T1
	VPXOR B0, B0, B0

avxPtxLoadLoop:
		VPSLLDQ $1, B0, B0
		VPINSRB $0, (ptx), B0, B0
		LEAQ -1(ptx), ptx
		DECQ ptxLen
	JNE avxPtxLoadLoop

	VPXOR T0, B0, B0
	VPAND T1, B0, B0
	VMOVDQU B0, (ctx)	// I assume there is always space, due to TAG in the end of the CT
	avxGcmEncDataStep(B0)

avxGcmSm4EncDone:
	VMOVDQU ACC0, (tPtr)
	RET

avx2GcmSm4Enc:
	VMOVDQU bswap_mask<>(SB), BSWAP
	VMOVDQU gcmPoly<>(SB), POLY

	VMOVDQU (tPtr), ACC0
	VPXOR ACC1, ACC1, ACC1
	VPXOR ACCM, ACCM, ACCM
	VMOVDQU (ctrPtr), T0
	VPSHUFB flip_mask<>(SB), T0, T0
	VPEXTRD $3, T0, aluCTR

	VINSERTI128 $1, T0, Y11, Y11
	VMOVDQU Y11, (8*16 + 0*32)(SP)
	increment(0)
	increment(1)
	VMOVDQU Y11, (8*16 + 1*32)(SP)
	increment(2)
	increment(3)

	CMPQ ptxLen, $128
	JB avx2GcmSm4EncNibbles
	SUBQ $128, ptxLen

	// We have at least 8 blocks to encrypt, prepare the rest of the counters
	VMOVDQU Y11, (8*16 + 2*32)(SP)
	increment(4)
	increment(5)
	VMOVDQU Y11, (8*16 + 3*32)(SP)
	increment(6)
	increment(7)

	VBROADCASTI128 bswap_mask<>(SB), DWBSWAP
	// load 8 ctrs for encryption
	VMOVDQU (4*32 + 0*32)(SP), DWB0
	VMOVDQU (4*32 + 1*32)(SP), DWB1
	VMOVDQU (4*32 + 2*32)(SP), DWB2
	VMOVDQU (4*32 + 3*32)(SP), DWB3

	increment(0)
	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(DWB0, DWB1, DWB2, DWB3, XDWORD, YDWORD)
	
	VBROADCASTI128 nibble_mask<>(SB), NIBBLE_MASK
	increment(1)
	AVX2_SM4_8BLOCKS(rk, XDWORD, YDWORD, X1, X3, XDWTMP0, DWB0, DWB1, DWB2, DWB3)
	increment(2)
	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(DWB0, DWB1, DWB2, DWB3, XDWORD, YDWORD)
	
	VPSHUFB DWBSWAP, DWB0, DWB0
	VPSHUFB DWBSWAP, DWB1, DWB1
	increment(3)
	VPSHUFB DWBSWAP, DWB2, DWB2
	VPSHUFB DWBSWAP, DWB3, DWB3
	increment(4)
	
	// XOR plaintext
	VMOVDQU (32*0)(ptx), XDWTMP0
	VPXOR XDWTMP0, DWB0, DWB0
	VMOVDQU (32*1)(ptx), XDWTMP0
	VPXOR XDWTMP0, DWB1, DWB1
	increment(5)
	VMOVDQU (32*2)(ptx), XDWTMP0
	VPXOR XDWTMP0, DWB2, DWB2
	VMOVDQU (32*3)(ptx), XDWTMP0
	VPXOR XDWTMP0, DWB3, DWB3
	increment(6)
	
	// Store ciphertext
	VMOVDQU DWB0, (32*0)(ctx)
	VPSHUFB DWBSWAP, DWB0, DWB0
	VMOVDQU DWB1, (32*1)(ctx)
	VPSHUFB DWBSWAP, DWB1, DWB1
	VMOVDQU DWB2, (32*2)(ctx)
	VPSHUFB DWBSWAP, DWB2, DWB2
	VMOVDQU DWB3, (32*3)(ctx)
	VPSHUFB DWBSWAP, DWB3, DWB3
	increment(7)
	//VPXOR XDWTMP0, XDWTMP0, XDWTMP0
	//VINSERTI128 $0, ACC0, XDWTMP0, XDWTMP0
	//VPXOR XDWTMP0, DWB0, DWB0
	PXOR ACC0, B0  // Can't call VPXOR here
	VMOVDQU DWB0, (32*0)(SP)
	VMOVDQU DWB1, (32*1)(SP)
	VMOVDQU DWB2, (32*2)(SP)
	VMOVDQU DWB3, (32*3)(SP)

	LEAQ 128(ptx), ptx
	LEAQ 128(ctx), ctx

avx2GcmSm4EncOctetsLoop:
		CMPQ ptxLen, $128
		JB avx2GcmSm4EncOctetsEnd
		SUBQ $128, ptxLen

		// load 8 ctrs for encryption
		VMOVDQU (4*32 + 0*32)(SP), DWB0
		VMOVDQU (4*32 + 1*32)(SP), DWB1
		VMOVDQU (4*32 + 2*32)(SP), DWB2
		VMOVDQU (4*32 + 3*32)(SP), DWB3

		VMOVDQU (16*0)(SP), T0
		VPSHUFD $78, T0, T1
		VPXOR T0, T1, T1

		VMOVDQU (16*0)(pTbl), ACC1
		VMOVDQU (16*1)(pTbl), ACCM

		VPCLMULQDQ $0x00, T1, ACCM, ACCM
		VPCLMULQDQ $0x00, T0, ACC1, ACC0
		VPCLMULQDQ $0x11, T0, ACC1, ACC1

		// Transpose matrix 4 x 4 32bits word
		TRANSPOSE_MATRIX(DWB0, DWB1, DWB2, DWB3, XDWORD, YDWORD)

		AVX2_SM4_8BLOCKS(rk, XDWORD, YDWORD, X1, X3, XDWTMP0, DWB0, DWB1, DWB2, DWB3)

		// Transpose matrix 4 x 4 32bits word
		TRANSPOSE_MATRIX(DWB0, DWB1, DWB2, DWB3, XDWORD, YDWORD)

		VPSHUFB DWBSWAP, DWB0, DWB0
		VPSHUFB DWBSWAP, DWB1, DWB1
		VPSHUFB DWBSWAP, DWB2, DWB2
		VPSHUFB DWBSWAP, DWB3, DWB3

		avxMulRound(1)
		increment(0)
		avxMulRound(2)
		increment(1)
		avxMulRound(3)
		increment(2)
	 	avxMulRound(4)
		increment(3)
		avxMulRound(5)
		increment(4)
		avxMulRound(6)
		increment(5)
	 	avxMulRound(7)
		increment(6)
		
		VPXOR ACC0, ACCM, ACCM
		VPXOR ACC1, ACCM, ACCM
		VPSLLDQ $8, ACCM, T0
		VPSRLDQ $8, ACCM, ACCM
		
		VPXOR ACCM, ACC1, ACC1
		VPXOR T0, ACC0, ACC0

		increment(7)
		avxReduceRound(ACC0)
		avxReduceRound(ACC0)
		VPXOR ACC1, ACC0, ACC0

		// XOR plaintext
		VPXOR (32*0)(ptx), DWB0, DWB0
		VPXOR (32*1)(ptx), DWB1, DWB1
		VPXOR (32*2)(ptx), DWB2, DWB2
		VPXOR (32*3)(ptx), DWB3, DWB3

		// Store ciphertext
		VMOVDQU DWB0, (32*0)(ctx)
		VPSHUFB DWBSWAP, DWB0, DWB0
		VMOVDQU DWB1, (32*1)(ctx)
		VPSHUFB DWBSWAP, DWB1, DWB1
		VMOVDQU DWB2, (32*2)(ctx)
		VPSHUFB DWBSWAP, DWB2, DWB2
		VMOVDQU DWB3, (32*3)(ctx)
		VPSHUFB DWBSWAP, DWB3, DWB3

		//VPXOR XDWTMP0, XDWTMP0, XDWTMP0
		//VINSERTI128 $0, ACC0, XDWTMP0, XDWTMP0
		//VPXOR XDWTMP0, DWB0, DWB0
		PXOR ACC0, B0  // Can't call VPXOR here
		VMOVDQU DWB0, (32*0)(SP)
		VMOVDQU DWB1, (32*1)(SP)
		VMOVDQU DWB2, (32*2)(SP)
		VMOVDQU DWB3, (32*3)(SP)

		LEAQ 128(ptx), ptx
		LEAQ 128(ctx), ctx

		JMP avx2GcmSm4EncOctetsLoop

avx2GcmSm4EncOctetsEnd:
	VMOVDQU (16*0)(SP), T0
	VMOVDQU (16*0)(pTbl), ACC0
	VMOVDQU (16*1)(pTbl), ACCM
	VMOVDQU ACC0, ACC1
	VPSHUFD $78, T0, T1
	VPXOR T0, T1, T1
	VPCLMULQDQ $0x00, T0, ACC0, ACC0
	VPCLMULQDQ $0x11, T0, ACC1, ACC1
	VPCLMULQDQ $0x00, T1, ACCM, ACCM

	avxMulRound(1)
	avxMulRound(2)
	avxMulRound(3)
	avxMulRound(4)
	avxMulRound(5)
	avxMulRound(6)
	avxMulRound(7)

	VPXOR ACC0, ACCM, ACCM
	VPXOR ACC1, ACCM, ACCM
	VPSLLDQ $8, ACCM, T0
	VPSRLDQ $8, ACCM, ACCM
	
	VPXOR ACCM, ACC1, ACC1
	VPXOR T0, ACC0, ACC0

	avxReduceRound(ACC0)
	avxReduceRound(ACC0)
	VPXOR ACC1, ACC0, ACC0

	TESTQ ptxLen, ptxLen
	JE avx2GcmSm4EncDone

	SUBQ $4, aluCTR

avx2GcmSm4EncNibbles:
	CMPQ ptxLen, $64
	JBE avx2GcmSm4EncSingles
	SUBQ $64, ptxLen

	VMOVDQU (8*16 + 0*16)(SP), B0
	VMOVDQU (8*16 + 1*16)(SP), B1
	VMOVDQU (8*16 + 2*16)(SP), B2
	VMOVDQU (8*16 + 3*16)(SP), B3
	
	AVX_SM4_4BLOCKS_WO_BS(rk, B4, B5, B6, B7, B0, B1, B2, B3)

	VPXOR (16*0)(ptx), B0, B0
	VPXOR (16*1)(ptx), B1, B1
	VPXOR (16*2)(ptx), B2, B2
	VPXOR (16*3)(ptx), B3, B3

	VMOVDQU B0, (16*0)(ctx)
	VMOVDQU B1, (16*1)(ctx)
	VMOVDQU B2, (16*2)(ctx)
	VMOVDQU B3, (16*3)(ctx)

	VMOVDQU (16*14)(pTbl), T2
	avxGcmEncDataStep(B0)
	increment(0)
	avxGcmEncDataStep(B1)
	increment(1)
	avxGcmEncDataStep(B2)
	increment(2)
	avxGcmEncDataStep(B3)
	increment(3)

	LEAQ 64(ptx), ptx
	LEAQ 64(ctx), ctx

avx2GcmSm4EncSingles:
	TESTQ ptxLen, ptxLen
	JE avx2GcmSm4EncDone

	VMOVDQU (8*16 + 0*16)(SP), B0
	VMOVDQU (8*16 + 1*16)(SP), B1
	VMOVDQU (8*16 + 2*16)(SP), B2
	VMOVDQU (8*16 + 3*16)(SP), B3

	AVX_SM4_4BLOCKS_WO_BS(rk, B4, B5, B6, B7, B0, B1, B2, B3)

	VMOVDQU B0, (16*0)(SP)
	VMOVDQU B1, (16*1)(SP)
	VMOVDQU B2, (16*2)(SP)
	VMOVDQU B3, (16*3)(SP)

	VMOVDQU (16*14)(pTbl), T2
	MOVQ SP, BP

avx2GcmSm4EncSinglesLoop:
		CMPQ ptxLen, $16
		JB avx2GcmSm4EncTail
		SUBQ $16, ptxLen
		VMOVDQU (16*0)(BP), B0
		VMOVDQU (ptx), T0
		VPXOR T0, B0, B0
		VMOVDQU B0, (ctx)
		avxGcmEncDataStep(B0)
		LEAQ (16*1)(ptx), ptx
		LEAQ (16*1)(ctx), ctx
		ADDQ $16, BP
	JMP avx2GcmSm4EncSinglesLoop

avx2GcmSm4EncTail:
	TESTQ ptxLen, ptxLen
	JE avx2GcmSm4EncDone
	VMOVDQU (16*0)(BP), B0
	VMOVDQU B0, T0

	LEAQ -1(ptx)(ptxLen*1), ptx

	MOVQ ptxLen, aluTMP
	SHLQ $4, aluTMP

	LEAQ andMask<>(SB), aluCTR
	VMOVDQU -16(aluCTR)(aluTMP*1), T1
	VPXOR B0, B0, B0

avx2PtxLoadLoop:
		VPSLLDQ $1, B0, B0
		VPINSRB $0, (ptx), B0, B0
		LEAQ -1(ptx), ptx
		DECQ ptxLen
	JNE avx2PtxLoadLoop

	VPXOR T0, B0, B0
	VPAND T1, B0, B0
	VMOVDQU B0, (ctx)	// I assume there is always space, due to TAG in the end of the CT
	avxGcmEncDataStep(B0)

avx2GcmSm4EncDone:
	VMOVDQU ACC0, (tPtr)
	VZEROUPPER
	RET

#undef increment

// func gcmSm4Dec(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)
TEXT ·gcmSm4Dec(SB),0,$128-96
#define increment(i) ADDL $1, aluCTR; MOVL aluCTR, (3*4 + i*16)(SP)

#define decMulRound(i) \
	MOVOU (16*i)(ctx), T0;\
	PSHUFB BSWAP, T0;\
	internalDecMulRound(i)

#define internalDecMulRound(i) \
	MOVOU (16*(i*2))(pTbl), T1;\
	MOVOU T1, T2;\
	PCLMULQDQ $0x00, T0, T1;\
	PXOR T1, ACC0;\
	PSHUFD $78, T0, T1;\
	PCLMULQDQ $0x11, T0, T2;\
	PXOR T1, T0;\
	PXOR T2, ACC1;\
	MOVOU (16*(i*2+1))(pTbl), T2;\
	PCLMULQDQ $0x00, T2, T0;\
	PXOR T0, ACCM

#define decGhashRound(i) \
		MOVOU (16*i)(ctx), B0; \
		internalDecGhashRound()

#define internalDecGhashRound() \
		PSHUFB BSWAP, B0; \
		PXOR ACC0, B0; \
		MOVOU T2, ACC0; \
		MOVOU T2, ACC1; \
		MOVOU (16*15)(pTbl), ACCM; \
		PCLMULQDQ $0x00, B0, ACC0; \
		PCLMULQDQ $0x11, B0, ACC1; \
		PSHUFD $78, B0, T0; \
		PXOR B0, T0; \
		PCLMULQDQ $0x00, T0, ACCM; \
		PXOR ACC0, ACCM; \
		PXOR ACC1, ACCM; \
		MOVOU ACCM, T0; \
		PSRLDQ $8, ACCM; \
		PSLLDQ $8, T0; \
		PXOR ACCM, ACC1; \
		PXOR T0, ACC0; \
		reduceRound(ACC0); \
		reduceRound(ACC0); \
		PXOR ACC1, ACC0

#define avxDecMulRound(i) \
	VMOVDQU (16*i)(ctx), T0;\
	VPSHUFB BSWAP, T0, T0;\
	VMOVDQU (16*(i*2))(pTbl), T2;\
	VPCLMULQDQ $0x00, T0, T2, T1;\
	VPXOR T1, ACC0, ACC0;\
	VPSHUFD $78, T0, T1;\
	VPCLMULQDQ $0x11, T0, T2, T2;\
	VPXOR T1, T0, T0;\
	VPXOR T2, ACC1, ACC1;\
	VMOVDQU (16*(i*2+1))(pTbl), T2;\
	VPCLMULQDQ $0x00, T2, T0, T0;\
	VPXOR T0, ACCM, ACCM

#define internalAvxDecGhashRound() \
		VPSHUFB BSWAP, B0, B0; \
		VPXOR ACC0, B0, B0; \
		VMOVDQU (16*15)(pTbl), ACCM; \
		VPCLMULQDQ $0x00, B0, T2, ACC0; \
		VPCLMULQDQ $0x11, B0, T2, ACC1; \
		VPSHUFD $78, B0, T0; \
		VPXOR B0, T0, T0; \
		VPCLMULQDQ $0x00, T0, ACCM, ACCM; \
		VPXOR ACC0, ACCM, ACCM; \
		VPXOR ACC1, ACCM, ACCM; \
		VPSLLDQ $8, ACCM, T0; \
		VPSRLDQ $8, ACCM, ACCM; \
		VPXOR ACCM, ACC1, ACC1; \
		VPXOR T0, ACC0, ACC0; \
		avxReduceRound(ACC0); \
		avxReduceRound(ACC0); \
		VPXOR ACC1, ACC0, ACC0

	MOVQ productTable+0(FP), pTbl
	MOVQ dst+8(FP), ptx
	MOVQ src_base+32(FP), ctx
	MOVQ src_len+40(FP), ptxLen
	MOVQ ctr+56(FP), ctrPtr
	MOVQ T+64(FP), tPtr
	MOVQ rk_base+72(FP), rk

	CMPB ·useAVX2(SB), $1
	JE   avx2GcmSm4Dec

	CMPB ·useAVX(SB), $1
	JE   avxGcmSm4Dec

	MOVOU bswap_mask<>(SB), BSWAP
	MOVOU gcmPoly<>(SB), POLY

	MOVOU (tPtr), ACC0
	PXOR ACC1, ACC1
	PXOR ACCM, ACCM
	MOVOU (ctrPtr), T0
	PSHUFB flip_mask<>(SB), T0
	PEXTRD $3, T0, aluCTR

	MOVOU T0, (0*16)(SP)
	increment(0)
	MOVOU T0, (1*16)(SP)
	increment(1)
	MOVOU T0, (2*16)(SP)
	increment(2)
	MOVOU T0, (3*16)(SP)
	increment(3)

	CMPQ ptxLen, $128
	JB gcmSm4DecNibbles

	// We have at least 8 blocks to dencrypt, prepare the rest of the counters
	MOVOU T0, (4*16)(SP)
	increment(4)
	MOVOU T0, (5*16)(SP)
	increment(5)
	MOVOU T0, (6*16)(SP)
	increment(6)
	MOVOU T0, (7*16)(SP)
	increment(7)

gcmSm4DecOctetsLoop:
		CMPQ ptxLen, $128
		JB gcmSm4DecEndOctets
		SUBQ $128, ptxLen

		MOVOU (0*16)(SP), B0
		MOVOU (1*16)(SP), B1
		MOVOU (2*16)(SP), B2
		MOVOU (3*16)(SP), B3
		MOVOU (4*16)(SP), B4
		MOVOU (5*16)(SP), B5
		MOVOU (6*16)(SP), B6
		MOVOU (7*16)(SP), B7

		MOVOU (16*0)(ctx), T0
		PSHUFB BSWAP, T0
		PXOR ACC0, T0
		PSHUFD $78, T0, T1
		PXOR T0, T1

		MOVOU (16*0)(pTbl), ACC0
		MOVOU (16*1)(pTbl), ACCM
		MOVOU ACC0, ACC1

		PCLMULQDQ $0x00, T1, ACCM
		PCLMULQDQ $0x00, T0, ACC0
		PCLMULQDQ $0x11, T0, ACC1

		decMulRound(1)
		increment(0)
		decMulRound(2)
		increment(1)
		decMulRound(3)
		increment(2)
	 	decMulRound(4)
		increment(3)
		decMulRound(5)
		increment(4)
		decMulRound(6)
		increment(5)
	 	decMulRound(7)
		increment(6)
		increment(7)

		PXOR ACC0, ACCM
		PXOR ACC1, ACCM
		MOVOU ACCM, T0
		PSRLDQ $8, ACCM
		PSLLDQ $8, T0
		PXOR ACCM, ACC1
		PXOR T0, ACC0

		reduceRound(ACC0)
		reduceRound(ACC0)
		PXOR ACC1, ACC0

		SM4_8BLOCKS_WO_BS(rk, ACC1, T0, T1, T2, B0, B1, B2, B3, B4, B5, B6, B7)

		PXOR (16*0)(ctx), B0
		PXOR (16*1)(ctx), B1
		PXOR (16*2)(ctx), B2
		PXOR (16*3)(ctx), B3
		PXOR (16*4)(ctx), B4
		PXOR (16*5)(ctx), B5
		PXOR (16*6)(ctx), B6
		PXOR (16*7)(ctx), B7

		MOVOU B0, (16*0)(ptx)
		MOVOU B1, (16*1)(ptx)
		MOVOU B2, (16*2)(ptx)
		MOVOU B3, (16*3)(ptx)
		MOVOU B4, (16*4)(ptx)
		MOVOU B5, (16*5)(ptx)
		MOVOU B6, (16*6)(ptx)
		MOVOU B7, (16*7)(ptx)

		LEAQ 128(ptx), ptx
		LEAQ 128(ctx), ctx

		JMP gcmSm4DecOctetsLoop

gcmSm4DecEndOctets:
	SUBQ $4, aluCTR

gcmSm4DecNibbles:
	CMPQ ptxLen, $64
	JBE gcmSm4DecSingles
	SUBQ $64, ptxLen

	MOVOU (0*16)(SP), B4
	MOVOU (1*16)(SP), B5
	MOVOU (2*16)(SP), B6
	MOVOU (3*16)(SP), B7

	SM4_4BLOCKS_WO_BS(rk, B0, T0, T1, T2, B4, B5, B6, B7)
	MOVOU (16*14)(pTbl), T2

	MOVOU (16*0)(ctx), B0
	PXOR B0, B4
	internalDecGhashRound()
	increment(0)
	MOVOU (16*1)(ctx), B0
	PXOR B0, B5
	internalDecGhashRound()
	increment(1)
	MOVOU (16*2)(ctx), B0
	PXOR B0, B6
	internalDecGhashRound()
	increment(2)
	MOVOU (16*3)(ctx), B0
	PXOR B0, B7
	internalDecGhashRound()
	increment(3)

	MOVOU B4, (16*0)(ptx)
	MOVOU B5, (16*1)(ptx)
	MOVOU B6, (16*2)(ptx)
	MOVOU B7, (16*3)(ptx)

	LEAQ 64(ptx), ptx
	LEAQ 64(ctx), ctx

gcmSm4DecSingles:
	TESTQ ptxLen, ptxLen
	JE gcmSm4DecDone
	MOVOU (0*16)(SP), B0
	MOVOU (1*16)(SP), B1
	MOVOU (2*16)(SP), B2
	MOVOU (3*16)(SP), B3
	
	SM4_4BLOCKS_WO_BS(rk, B4, T0, T1, T2, B0, B1, B2, B3)
	MOVOU B0, (16*4)(SP)
	MOVOU B1, (16*5)(SP)
	MOVOU B2, (16*6)(SP)
	MOVOU B3, (16*7)(SP)

	MOVOU (16*14)(pTbl), T2
	MOVQ SP, BP
	ADDQ $64, BP

gcmSm4DecSinglesLoop:
		CMPQ ptxLen, $16
		JB gcmSm4DecTail
		SUBQ $16, ptxLen

		MOVOU (16*0)(BP), B1
		MOVOU (ctx), T0
		PXOR T0, B1
		
		decGhashRound(0)
		MOVOU B1, (ptx)

		LEAQ (16*1)(ptx), ptx
		LEAQ (16*1)(ctx), ctx
		ADDQ $16, BP
	JMP gcmSm4DecSinglesLoop		

gcmSm4DecTail:
	TESTQ ptxLen, ptxLen
	JE gcmSm4DecDone

	MOVQ ptxLen, aluTMP
	SHLQ $4, aluTMP
	LEAQ andMask<>(SB), aluCTR
	MOVOU -16(aluCTR)(aluTMP*1), T1

	MOVOU (ctx), B0	// I assume there is TAG attached to the ctx, and there is no read overflow
	PAND T1, B0

	MOVOU B0, T1
	internalDecGhashRound()

	MOVOU (16*0)(BP), B0
	PXOR T1, B0

ptxStoreLoop:
		PEXTRB $0, B0, (ptx)
		PSRLDQ $1, B0
		LEAQ 1(ptx), ptx
		DECQ ptxLen

	JNE ptxStoreLoop

gcmSm4DecDone:
	MOVOU ACC0, (tPtr)
	RET

avxGcmSm4Dec:
	VMOVDQU bswap_mask<>(SB), BSWAP
	VMOVDQU gcmPoly<>(SB), POLY

	VMOVDQU (tPtr), ACC0
	VPXOR ACC1, ACC1, ACC1
	VPXOR ACCM, ACCM, ACCM
	VMOVDQU (ctrPtr), T0
	VPSHUFB flip_mask<>(SB), T0, T0
	VPEXTRD $3, T0, aluCTR

	VMOVDQU T0, (0*16)(SP)
	increment(0)
	VMOVDQU T0, (1*16)(SP)
	increment(1)
	VMOVDQU T0, (2*16)(SP)
	increment(2)
	VMOVDQU T0, (3*16)(SP)
	increment(3)

	CMPQ ptxLen, $128
	JB avxGcmSm4DecNibbles

	// We have at least 8 blocks to dencrypt, prepare the rest of the counters
	VMOVDQU T0, (4*16)(SP)
	increment(4)
	VMOVDQU T0, (5*16)(SP)
	increment(5)
	VMOVDQU T0, (6*16)(SP)
	increment(6)
	VMOVDQU T0, (7*16)(SP)
	increment(7)

avxGcmSm4DecOctetsLoop:
		CMPQ ptxLen, $128
		JB avxGcmSm4DecEndOctets
		SUBQ $128, ptxLen

		VMOVDQU (0*16)(SP), B0
		VMOVDQU (1*16)(SP), B1
		VMOVDQU (2*16)(SP), B2
		VMOVDQU (3*16)(SP), B3
		VMOVDQU (4*16)(SP), B4
		VMOVDQU (5*16)(SP), B5
		VMOVDQU (6*16)(SP), B6
		VMOVDQU (7*16)(SP), B7

		VMOVDQU (16*0)(ctx), T0
		VPSHUFB BSWAP, T0, T0
		VPXOR ACC0, T0, T0
		VPSHUFD $78, T0, T1
		VPXOR T0, T1, T1

		VMOVDQU (16*0)(pTbl), ACC1
		VMOVDQU (16*1)(pTbl), ACCM

		VPCLMULQDQ $0x00, T1, ACCM, ACCM
		VPCLMULQDQ $0x00, T0, ACC1, ACC0
		VPCLMULQDQ $0x11, T0, ACC1, ACC1

		avxDecMulRound(1)
		increment(0)
		avxDecMulRound(2)
		increment(1)
		avxDecMulRound(3)
		increment(2)
	 	avxDecMulRound(4)
		increment(3)
		avxDecMulRound(5)
		increment(4)
		avxDecMulRound(6)
		increment(5)
	 	avxDecMulRound(7)
		increment(6)
		
		VPXOR ACC0, ACCM, ACCM
		VPXOR ACC1, ACCM, ACCM

		VPSLLDQ $8, ACCM, T0
		VPSRLDQ $8, ACCM, ACCM

		VPXOR ACCM, ACC1, ACC1
		VPXOR T0, ACC0, ACC0

		increment(7)
		avxReduceRound(ACC0)
		avxReduceRound(ACC0)
		VPXOR ACC1, ACC0, ACC0

		AVX_SM4_8BLOCKS_WO_BS(rk, ACC1, T0, T1, T2, B0, B1, B2, B3, B4, B5, B6, B7)

		VPXOR (16*0)(ctx), B0, B0
		VPXOR (16*1)(ctx), B1, B1
		VPXOR (16*2)(ctx), B2, B2
		VPXOR (16*3)(ctx), B3, B3
		VPXOR (16*4)(ctx), B4, B4
		VPXOR (16*5)(ctx), B5, B5
		VPXOR (16*6)(ctx), B6, B6
		VPXOR (16*7)(ctx), B7, B7

		VMOVDQU B0, (16*0)(ptx)
		VMOVDQU B1, (16*1)(ptx)
		VMOVDQU B2, (16*2)(ptx)
		VMOVDQU B3, (16*3)(ptx)
		VMOVDQU B4, (16*4)(ptx)
		VMOVDQU B5, (16*5)(ptx)
		VMOVDQU B6, (16*6)(ptx)
		VMOVDQU B7, (16*7)(ptx)

		LEAQ 128(ptx), ptx
		LEAQ 128(ctx), ctx

		JMP avxGcmSm4DecOctetsLoop

avxGcmSm4DecEndOctets:
	SUBQ $4, aluCTR

avxGcmSm4DecNibbles:
	CMPQ ptxLen, $64
	JBE avxGcmSm4DecSingles
	SUBQ $64, ptxLen

	VMOVDQU (0*16)(SP), B4
	VMOVDQU (1*16)(SP), B5
	VMOVDQU (2*16)(SP), B6
	VMOVDQU (3*16)(SP), B7

	AVX_SM4_4BLOCKS_WO_BS(rk, B0, B1, T1, T2, B4, B5, B6, B7)

	VMOVDQU (16*14)(pTbl), T2
	VMOVDQU (16*0)(ctx), B0
	VPXOR B0, B4, B4
	internalAvxDecGhashRound()
	increment(0)

	VMOVDQU (16*1)(ctx), B0
	VPXOR B0, B5, B5
	internalAvxDecGhashRound()
	increment(1)

	VMOVDQU (16*2)(ctx), B0
	VPXOR B0, B6, B6
	internalAvxDecGhashRound()
	increment(2)

	VMOVDQU (16*3)(ctx), B0
	VPXOR B0, B7, B7
	internalAvxDecGhashRound()
	increment(3)

	VMOVDQU B4, (16*0)(ptx)
	VMOVDQU B5, (16*1)(ptx)
	VMOVDQU B6, (16*2)(ptx)
	VMOVDQU B7, (16*3)(ptx)

	LEAQ 64(ptx), ptx
	LEAQ 64(ctx), ctx

avxGcmSm4DecSingles:
	TESTQ ptxLen, ptxLen
	JE avxGcmSm4DecDone

	VMOVDQU (0*16)(SP), B0
	VMOVDQU (1*16)(SP), B1
	VMOVDQU (2*16)(SP), B2
	VMOVDQU (3*16)(SP), B3
	
	AVX_SM4_4BLOCKS_WO_BS(rk, B7, B6, B5, B4, B0, B1, B2, B3)
	VMOVDQU B0, (16*4)(SP)
	VMOVDQU B1, (16*5)(SP)
	VMOVDQU B2, (16*6)(SP)
	VMOVDQU B3, (16*7)(SP)

	VMOVDQU (16*14)(pTbl), T2
	MOVQ SP, BP
	ADDQ $64, BP

avxGcmSm4DecSinglesLoop:
		CMPQ ptxLen, $16
		JB avxGcmSm4DecTail
		SUBQ $16, ptxLen

		VMOVDQU (16*0)(BP), T0
		VMOVDQU (ctx), B0
		VPXOR T0, B0, T0
		VMOVDQU T0, (ptx)

		internalAvxDecGhashRound()

		LEAQ (16*1)(ptx), ptx
		LEAQ (16*1)(ctx), ctx
		ADDQ $16, BP
	JMP avxGcmSm4DecSinglesLoop

avxGcmSm4DecTail:
	TESTQ ptxLen, ptxLen
	JE avxGcmSm4DecDone

	MOVQ ptxLen, aluTMP
	SHLQ $4, aluTMP
	LEAQ andMask<>(SB), aluCTR
	VMOVDQU -16(aluCTR)(aluTMP*1), T1

	VMOVDQU (ctx), B0	// I assume there is TAG attached to the ctx, and there is no read overflow
	VPAND T1, B0, B0

	VMOVDQU B0, T1
	internalAvxDecGhashRound()

	VMOVDQU (16*0)(BP), B0
	VPXOR T1, B0, B0

avxPtxStoreLoop:
		VPEXTRB $0, B0, (ptx)
		VPSRLDQ $1, B0, B0
		LEAQ 1(ptx), ptx
		DECQ ptxLen

	JNE avxPtxStoreLoop

avxGcmSm4DecDone:
	VMOVDQU ACC0, (tPtr)
	RET

avx2GcmSm4Dec:
	VMOVDQU bswap_mask<>(SB), BSWAP
	VMOVDQU gcmPoly<>(SB), POLY

	VMOVDQU (tPtr), ACC0
	VPXOR ACC1, ACC1, ACC1
	VPXOR ACCM, ACCM, ACCM
	VMOVDQU (ctrPtr), T0
	VPSHUFB flip_mask<>(SB), T0, T0
	VPEXTRD $3, T0, aluCTR

	VINSERTI128 $1, T0, Y11, Y11
	VMOVDQU Y11, (0*32)(SP)
	increment(0)
	increment(1)
	VMOVDQU Y11, (1*32)(SP)
	increment(2)
	increment(3)

	CMPQ ptxLen, $128
	JB avx2GcmSm4DecNibbles

	// We have at least 8 blocks to dencrypt, prepare the rest of the counters
	VMOVDQU Y11, (2*32)(SP)
	increment(4)
	increment(5)
	VMOVDQU Y11, (3*32)(SP)
	increment(6)
	increment(7)

	VBROADCASTI128 bswap_mask<>(SB), DWBSWAP
	VBROADCASTI128 nibble_mask<>(SB), NIBBLE_MASK

avx2GcmSm4DecOctetsLoop:
		CMPQ ptxLen, $128
		JB avx2GcmSm4DecEndOctets
		SUBQ $128, ptxLen

		// load 8 ctrs for encryption
		VMOVDQU (0*32)(SP), DWB0
		VMOVDQU (1*32)(SP), DWB1
		VMOVDQU (2*32)(SP), DWB2
		VMOVDQU (3*32)(SP), DWB3

		VMOVDQU (16*0)(ctx), T0
		VPSHUFB BSWAP, T0, T0
		VPXOR ACC0, T0, T0
		VPSHUFD $78, T0, T1
		VPXOR T0, T1, T1

		VMOVDQU (16*0)(pTbl), ACC1
		VMOVDQU (16*1)(pTbl), ACCM

		VPCLMULQDQ $0x00, T1, ACCM, ACCM
		VPCLMULQDQ $0x00, T0, ACC1, ACC0
		VPCLMULQDQ $0x11, T0, ACC1, ACC1

		avxDecMulRound(1)
		increment(0)
		avxDecMulRound(2)
		increment(1)
		avxDecMulRound(3)
		increment(2)
	 	avxDecMulRound(4)
		increment(3)
		avxDecMulRound(5)
		increment(4)
		avxDecMulRound(6)
		increment(5)
	 	avxDecMulRound(7)
		increment(6)
		
		VPXOR ACC0, ACCM, ACCM
		VPXOR ACC1, ACCM, ACCM
		VPSLLDQ $8, ACCM, T0
		VPSRLDQ $8, ACCM, ACCM
		
		VPXOR ACCM, ACC1, ACC1
		VPXOR T0, ACC0, ACC0
		increment(7)

		avxReduceRound(ACC0)
		avxReduceRound(ACC0)
		VPXOR ACC1, ACC0, ACC0

		// Transpose matrix 4 x 4 32bits word
		TRANSPOSE_MATRIX(DWB0, DWB1, DWB2, DWB3, XDWORD, YDWORD)

		AVX2_SM4_8BLOCKS(rk, XDWORD, YDWORD, X1, X3, XDWTMP0, DWB0, DWB1, DWB2, DWB3)

		// Transpose matrix 4 x 4 32bits word
		TRANSPOSE_MATRIX(DWB0, DWB1, DWB2, DWB3, XDWORD, YDWORD)

		VPSHUFB DWBSWAP, DWB0, DWB0
		VPSHUFB DWBSWAP, DWB1, DWB1
		VPSHUFB DWBSWAP, DWB2, DWB2
		VPSHUFB DWBSWAP, DWB3, DWB3

		VPXOR (32*0)(ctx), DWB0, DWB0
		VPXOR (32*1)(ctx), DWB1, DWB1
		VPXOR (32*2)(ctx), DWB2, DWB2
		VPXOR (32*3)(ctx), DWB3, DWB3

		VMOVDQU DWB0, (32*0)(ptx)
		VMOVDQU DWB1, (32*1)(ptx)
		VMOVDQU DWB2, (32*2)(ptx)
		VMOVDQU DWB3, (32*3)(ptx)
		
		LEAQ 128(ptx), ptx
		LEAQ 128(ctx), ctx

		JMP avx2GcmSm4DecOctetsLoop

avx2GcmSm4DecEndOctets:
	SUBQ $4, aluCTR

avx2GcmSm4DecNibbles:
	CMPQ ptxLen, $64
	JBE avx2GcmSm4DecSingles
	SUBQ $64, ptxLen

	VMOVDQU (0*16)(SP), B4
	VMOVDQU (1*16)(SP), B1
	VMOVDQU (2*16)(SP), B2
	VMOVDQU (3*16)(SP), B3
	
	AVX_SM4_4BLOCKS_WO_BS(rk, B0, B5, B6, B7, B4, B1, B2, B3)

	VMOVDQU (16*14)(pTbl), T2
	VMOVDQU (16*0)(ctx), B0
	VPXOR B0, B4, B4
	increment(0)
	internalAvxDecGhashRound()

	VMOVDQU (16*1)(ctx), B0
	VPXOR B0, B1, B1
	increment(1)
	internalAvxDecGhashRound()

	VMOVDQU (16*2)(ctx), B0
	VPXOR B0, B2, B2
	increment(2)
	internalAvxDecGhashRound()

	VMOVDQU (16*3)(ctx), B0
	VPXOR B0, B3, B3
	increment(3)
	internalAvxDecGhashRound()

	VMOVDQU B4, (16*0)(ptx)
	VMOVDQU B1, (16*1)(ptx)
	VMOVDQU B2, (16*2)(ptx)
	VMOVDQU B3, (16*3)(ptx)

	LEAQ 64(ptx), ptx
	LEAQ 64(ctx), ctx

avx2GcmSm4DecSingles:
	TESTQ ptxLen, ptxLen
	JE avx2GcmSm4DecDone

	VMOVDQU (0*16)(SP), B0
	VMOVDQU (1*16)(SP), B1
	VMOVDQU (2*16)(SP), B2
	VMOVDQU (3*16)(SP), B3

	AVX_SM4_4BLOCKS_WO_BS(rk, B4, B5, B6, B7, B0, B1, B2, B3)

	VMOVDQU B0, (16*4)(SP)
	VMOVDQU B1, (16*5)(SP)
	VMOVDQU B2, (16*6)(SP)
	VMOVDQU B3, (16*7)(SP)

	VMOVDQU (16*14)(pTbl), T2
	MOVQ SP, BP
	ADDQ $64, BP

avx2GcmSm4DecSinglesLoop:
		CMPQ ptxLen, $16
		JB avx2GcmSm4DecTail
		SUBQ $16, ptxLen

		VMOVDQU (16*0)(BP), T0
		VMOVDQU (ctx), B0
		VPXOR T0, B0, T0
		VMOVDQU T0, (ptx)

		internalAvxDecGhashRound()
		LEAQ (16*1)(ptx), ptx
		LEAQ (16*1)(ctx), ctx
		ADDQ $16, BP
	JMP avx2GcmSm4DecSinglesLoop

avx2GcmSm4DecTail:
	TESTQ ptxLen, ptxLen
	JE avx2GcmSm4DecDone

	MOVQ ptxLen, aluTMP
	SHLQ $4, aluTMP
	LEAQ andMask<>(SB), aluCTR
	VMOVDQU -16(aluCTR)(aluTMP*1), T1 // Fetch and-mask according ptxLen

	VMOVDQU (ctx), B0	// I assume there is TAG attached to the ctx, and there is no read overflow
	VPAND T1, B0, B0  // Just keep ptxLen bytes, others will be zero

	VMOVDQU B0, T1
	internalAvxDecGhashRound()
	VMOVDQU (16*0)(BP), B0
	VPXOR T1, B0, B0

avx2PtxStoreLoop:
		VPEXTRB $0, B0, (ptx)
		VPSRLDQ $1, B0, B0
		LEAQ 1(ptx), ptx
		DECQ ptxLen

	JNE avx2PtxStoreLoop

avx2GcmSm4DecDone:
	VMOVDQU ACC0, (tPtr)
	VZEROUPPER	
	RET

// func gcmSm4niEnc(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)
TEXT ·gcmSm4niEnc(SB),NOSPLIT,$0
	RET

// func gcmSm4niDec(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)
TEXT ·gcmSm4niDec(SB),NOSPLIT,$0
	RET
