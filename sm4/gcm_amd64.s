// This is an optimized implementation of AES-GCM using AES-NI and CLMUL-NI
// The implementation uses some optimization as described in:
// [1] Gueron, S., Kounavis, M.E.: Intel® Carry-Less Multiplication
//     Instruction and its Usage for Computing the GCM Mode rev. 2.02
// [2] Gueron, S., Krasnov, V.: Speeding up Counter Mode in Software and
//     Hardware

#include "textflag.h"

#define B0 X0
#define B1 X1
#define B2 X2
#define B3 X3
#define B4 X4
#define B5 X5
#define B6 X6
#define B7 X7

#define ACC0 X8
#define ACC1 X9
#define ACCM X10

#define T0 X11
#define T1 X12
#define T2 X13
#define POLY X14
#define BSWAP X15

DATA bswapMask<>+0x00(SB)/8, $0x08090a0b0c0d0e0f
DATA bswapMask<>+0x08(SB)/8, $0x0001020304050607

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

GLOBL bswapMask<>(SB), (NOPTR+RODATA), $16
GLOBL gcmPoly<>(SB), (NOPTR+RODATA), $16
GLOBL andMask<>(SB), (NOPTR+RODATA), $240

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

	MOVOU bswapMask<>(SB), BSWAP
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

// func precomputeTableAsm(productTable *[256]byte, src *[16]byte)
TEXT ·precomputeTableAsm(SB),NOSPLIT,$0
#define dst DI
#define SRC SI

	MOVQ productTable+0(FP), dst
	MOVQ src+8(FP), SRC

	MOVOU bswapMask<>(SB), BSWAP
	MOVOU gcmPoly<>(SB), POLY

  MOVOU (16*0)(SRC), B0
  PSHUFB BSWAP, B0

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

#undef SRC
#undef dst

// func gcmSm4Data(productTable *[256]byte, data []byte, T *[16]byte)
TEXT ·gcmSm4Data(SB),NOSPLIT,$0
#define pTbl DI
#define aut SI
#define tPtr CX
#define autLen DX

#define reduceRound(a) 	MOVOU POLY, T0;	PCLMULQDQ $0x01, a, T0; PSHUFD $78, a, a; PXOR T0, a
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

	//PXOR ACC0, ACC0
  MOVOU (tPtr), ACC0
	MOVOU bswapMask<>(SB), BSWAP
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
