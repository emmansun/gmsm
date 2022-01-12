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

// shuffle byte order from LE to BE
DATA flipMask<>+0x00(SB)/8, $0x0405060700010203
DATA flipMask<>+0x08(SB)/8, $0x0c0d0e0f08090a0b

//nibble mask
DATA nibbleMask<>+0x00(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA nibbleMask<>+0x08(SB)/8, $0x0F0F0F0F0F0F0F0F

// inverse shift rows
DATA inverseShiftRows<>+0x00(SB)/8, $0x0B0E0104070A0D00
DATA inverseShiftRows<>+0x08(SB)/8, $0x0306090C0F020508 

// Affine transform 1 (low and high hibbles)
DATA m1Low<>+0x00(SB)/8, $0x9197E2E474720701
DATA m1Low<>+0x08(SB)/8, $0xC7C1B4B222245157

DATA m1High<>+0x00(SB)/8, $0xE240AB09EB49A200
DATA m1High<>+0x08(SB)/8, $0xF052B91BF95BB012  

// Affine transform 2 (low and high hibbles)
DATA m2Low<>+0x00(SB)/8, $0x5B67F2CEA19D0834
DATA m2Low<>+0x08(SB)/8, $0xEDD14478172BBE82

DATA m2High<>+0x00(SB)/8, $0xAE7201DD73AFDC00
DATA m2High<>+0x08(SB)/8, $0x11CDBE62CC1063BF

// left rotations of 32-bit words by 8-bit increments
DATA r08Mask<>+0x00(SB)/8, $0x0605040702010003
DATA r08Mask<>+0x08(SB)/8, $0x0E0D0C0F0A09080B 

DATA r16Mask<>+0x00(SB)/8, $0x0504070601000302
DATA r16Mask<>+0x08(SB)/8, $0x0D0C0F0E09080B0A   

DATA r24Mask<>+0x00(SB)/8, $0x0407060500030201
DATA r24Mask<>+0x08(SB)/8, $0x0C0F0E0D080B0A09  

DATA fkMask<>+0x00(SB)/8, $0x56aa3350a3b1bac6
DATA fkMask<>+0x08(SB)/8, $0xb27022dc677d9197

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

GLOBL flipMask<>(SB), (NOPTR+RODATA), $16
GLOBL nibbleMask<>(SB), (NOPTR+RODATA), $16
GLOBL inverseShiftRows<>(SB), (NOPTR+RODATA), $16
GLOBL m1Low<>(SB), (NOPTR+RODATA), $16
GLOBL m1High<>(SB), (NOPTR+RODATA), $16
GLOBL m2Low<>(SB), (NOPTR+RODATA), $16
GLOBL m2High<>(SB), (NOPTR+RODATA), $16
GLOBL r08Mask<>(SB), (NOPTR+RODATA), $16
GLOBL r16Mask<>(SB), (NOPTR+RODATA), $16
GLOBL r24Mask<>(SB), (NOPTR+RODATA), $16
GLOBL fkMask<>(SB), (NOPTR+RODATA), $16
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

#define SM4_SBOX(x, y, z) \
  ;                                   \ //#############################  inner affine ############################//
  MOVOU x, z;                         \
  PAND nibbleMask<>(SB), z;           \ //y = _mm_and_si128(x, c0f); 
  MOVOU m1Low<>(SB), y;               \
  PSHUFB z, y;                        \ //y = _mm_shuffle_epi8(m1l, y);
  PSRLQ $4, x;                        \ //x = _mm_srli_epi64(x, 4); 
  PAND nibbleMask<>(SB), x;           \ //x = _mm_and_si128(x, c0f);
  MOVOU m1High<>(SB), z;              \
  PSHUFB x, z;                        \ //x = _mm_shuffle_epi8(m1h, x);
  MOVOU  z, x;                        \ //x = _mm_shuffle_epi8(m1h, x);
  PXOR y, x;                          \ //x = _mm_shuffle_epi8(m1h, x) ^ y;
  ;                                   \ // inverse ShiftRows
  PSHUFB inverseShiftRows<>(SB), x;   \ //x = _mm_shuffle_epi8(x, shr); 
  AESENCLAST nibbleMask<>(SB), x;     \ // AESNI instruction
  ;                                   \ //#############################  outer affine ############################//
  MOVOU  x, z;                        \
  PANDN nibbleMask<>(SB), z;          \ //z = _mm_andnot_si128(x, c0f);
  MOVOU m2Low<>(SB), y;               \ 
  PSHUFB z, y;                        \ //y = _mm_shuffle_epi8(m2l, z)
  PSRLQ $4, x;                        \ //x = _mm_srli_epi64(x, 4);
  PAND nibbleMask<>(SB), x;           \ //x = _mm_and_si128(x, c0f); 
  MOVOU m2High<>(SB), z;              \
  PSHUFB x, z;                        \
  MOVOU  z, x;                        \ //x = _mm_shuffle_epi8(m2h, x)
  PXOR y, x                             //x = _mm_shuffle_epi8(m2h, x) ^ y; 

#define SM4_TAO_L1(x, y, z)         \
  SM4_SBOX(x, y, z);                     \
  ;                                   \ //####################  4 parallel L1 linear transforms ##################//
  MOVOU x, y;                         \
  PSHUFB r08Mask<>(SB), y;            \ //y = _mm_shuffle_epi8(x, r08)
  PXOR x, y;                          \ //y = x xor _mm_shuffle_epi8(x, r08)
  MOVOU x, z;                         \
  PSHUFB r16Mask<>(SB), z;            \ 
  PXOR z, y;                          \ //y = x xor _mm_shuffle_epi8(x, r08) xor _mm_shuffle_epi8(x, r16)
  MOVOU y, z;                         \
  PSLLL $2, z;                        \
  PSRLL $30, y;                       \
  POR z, y;                           \ //y = _mm_slli_epi32(y, 2) ^ _mm_srli_epi32(y, 30);  
  MOVOU x, z;                         \
  PSHUFB r24Mask<>(SB), z;            \
  PXOR y, x;                          \ //x = x xor y
  PXOR z, x                             //x = x xor y xor _mm_shuffle_epi8(x, r24);

#define SM4_SINGLE_ROUND(index, RK, IND, x, y, z, t0, t1, t2, t3)  \ 
  PINSRD $0, (index * 4)(RK)(IND*1), x;             \
  PXOR t1, x;                                       \
  PXOR t2, x;                                       \
  PXOR t3, x;                                       \
  SM4_TAO_L1(x, y, z);                              \
  PXOR x, t0

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
  SM4_SINGLE_ROUND(0, RK, CX, T0, T1, T2, B0, B1, B2, B3)
  SM4_SINGLE_ROUND(1, RK, CX, T0, T1, T2, B1, B2, B3, B0)
  SM4_SINGLE_ROUND(2, RK, CX, T0, T1, T2, B2, B3, B0, B1)
  SM4_SINGLE_ROUND(3, RK, CX, T0, T1, T2, B3, B0, B1, B2)

  ADDL $16, CX
  CMPL CX, $4*32
  JB sm4InitEncLoop

	PEXTRD $0, B1, R8
	PINSRD $1, R8, B0
	PEXTRD $0, B2, R8
	PINSRD $2, R8, B0
	PEXTRD $0, B3, R8
	PINSRD $3, R8, B0

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
