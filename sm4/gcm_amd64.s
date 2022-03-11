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

#define DWB0 Y0
#define DWB1 Y2
#define DWB2 Y4
#define DWB3 Y6

#define XDWORD Y1
#define YDWORD Y3
#define XDWTMP0 Y5
#define XDWTMP1 Y7

#define ACC0 X8
#define ACC1 X9
#define ACCM X10

#define T0 X11
#define T1 X12
#define T2 X13
#define POLY X14
#define BSWAP X15
#define DWBSWAP Y15
#define NIBBLE_MASK Y11
#define X_NIBBLE_MASK X11

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
DATA m1Low<>+0x00(SB)/8, $0x0A7FC3B6D5A01C69
DATA m1Low<>+0x08(SB)/8, $0x3045F98CEF9A2653

DATA m1High<>+0x00(SB)/8, $0xC35BF46CAF379800
DATA m1High<>+0x08(SB)/8, $0x68F05FC7049C33AB  

// Affine transform 2 (low and high hibbles)
DATA m2Low<>+0x00(SB)/8, $0x9A950A05FEF16E61
DATA m2Low<>+0x08(SB)/8, $0x0E019E916A65FAF5

DATA m2High<>+0x00(SB)/8, $0x892D69CD44E0A400
DATA m2High<>+0x08(SB)/8, $0x2C88CC68E14501A5

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

#define SM4_ROUND(index, RK, IND, x, y, z, t0, t1, t2, t3)  \ 
  PINSRD $0, (index * 4)(RK)(IND*1), x;           \
  PSHUFD $0, x, x;                                \
  PXOR t1, x;                                     \
  PXOR t2, x;                                     \
  PXOR t3, x;                                     \
  SM4_TAO_L1(x, y, z);                            \
  PXOR x, t0

//	MOVOU r0, tmp2;
//	PUNPCKHDQ r1, tmp2;
//	PUNPCKLDQ	r1, r0; 
//	MOVOU r2, tmp1; 
//	PUNPCKLDQ r3, tmp1; 
//	PUNPCKHDQ r3, r2; 
//	MOVOU r0, r1; 
//	PUNPCKHQDQ tmp1, r1; 
//	PUNPCKLQDQ tmp1, r0; 
//	MOVOU tmp2, r3; 
//	PUNPCKHQDQ r2, r3; 
//	PUNPCKLQDQ r2, tmp2; 
//	MOVOU tmp2, r2
#define SSE_TRANSPOSE_MATRIX(r, r0, r1, r2, r3, tmp1, tmp2) \
  PEXTRD $2, r0, r; \
  PINSRD $0, r, tmp2;  \
  PEXTRD $2, r1, r; \
  PINSRD $1, r, tmp2;  \  
  ; \
  PEXTRD $3, r0, r; \
  PINSRD $2, r, tmp2;  \
  PEXTRD $3, r1, r; \
  PINSRD $3, r, tmp2;  \   // tmp2 = [w7, w3, w6, w2]
  ; \
  PEXTRD $1, r0, r; \
  PINSRD $2, r, r0;  \
  PEXTRD $0, r1, r; \
  PINSRD $1, r, r0;  \
  PEXTRD $1, r1, r; \
  PINSRD $3, r, r0;  \ //   r0 = [w5, w1, w4, w0] 
  ; \
  PEXTRD $0, r2, r; \
  PINSRD $0, r, tmp1;  \
  PEXTRD $0, r3, r; \
  PINSRD $1, r, tmp1;  \
  PEXTRD $1, r2, r; \
  PINSRD $2, r, tmp1;  \
  PEXTRD $1, r3, r; \
  PINSRD $3, r, tmp1;  \ // tmp1 = [w13, w9, w12, w8]
  ; \
  PEXTRD $2, r2, r; \
  PINSRD $0, r, r2;  \
  PEXTRD $2, r3, r; \
  PINSRD $1, r, r2;  \
  PEXTRD $3, r2, r; \
  PINSRD $2, r, r2;  \
  PEXTRD $3, r3, r; \
  PINSRD $3, r, r2;  \ //   r2 = [w15, w11, w14, w10] 
  ; \
	MOVOU r0, r1; \
  PEXTRQ $1, r1, r; \
  PINSRQ $0, r, r1; \
  PEXTRQ $1, tmp1, r; \ 
  PINSRQ $1, r, r1; \ //  r1 = [w13, w9, w5, w1]
  ; \
  PEXTRQ $0, tmp1, r; \ 
  PINSRQ $1, r, r0; \ //  r0 = [w12, w8, w4, w0]
  ; \
	MOVOU tmp2, r3; \
  PEXTRQ $1, r3, r; \
  PINSRQ $0, r, r3; \
  PEXTRQ $1, r2, r; \
  PINSRQ $1, r, r3; \ //  r3 = [w15, w11, w7, w3]
  ; \
  PEXTRQ $0, r2, r; \
  PINSRQ $1, r, r2; \
  PEXTRQ $0, tmp2, r; \
  PINSRQ $0, r, r2

#define SM4_4BLOCKS(RK, IND, x, y, z, t0, t1, t2, t3)  \ 
	PSHUFB flipMask<>(SB), t0; \
	PSHUFB flipMask<>(SB), t1; \
	PSHUFB flipMask<>(SB), t2; \
	PSHUFB flipMask<>(SB), t3; \
	SSE_TRANSPOSE_MATRIX(R12, t0, t1, t2, t3, x, y);          \
	XORL IND, IND;                                            \
	SM4_ROUND(0, RK, IND, x, y, z, t0, t1, t2, t3);           \
	SM4_ROUND(1, RK, IND, x, y, z, t1, t2, t3, t0);           \
	SM4_ROUND(2, RK, IND, x, y, z, t2, t3, t0, t1);           \
	SM4_ROUND(3, RK, IND, x, y, z, t3, t0, t1, t2);           \
	ADDL $16, IND;                                            \
	SM4_ROUND(0, RK, IND, x, y, z, t0, t1, t2, t3);           \
	SM4_ROUND(1, RK, IND, x, y, z, t1, t2, t3, t0);           \
	SM4_ROUND(2, RK, IND, x, y, z, t2, t3, t0, t1);           \
	SM4_ROUND(3, RK, IND, x, y, z, t3, t0, t1, t2);           \
	ADDL $16, IND;                                            \
	SM4_ROUND(0, RK, IND, x, y, z, t0, t1, t2, t3);           \
	SM4_ROUND(1, RK, IND, x, y, z, t1, t2, t3, t0);           \
	SM4_ROUND(2, RK, IND, x, y, z, t2, t3, t0, t1);           \
	SM4_ROUND(3, RK, IND, x, y, z, t3, t0, t1, t2);           \
	ADDL $16, IND;                                            \
	SM4_ROUND(0, RK, IND, x, y, z, t0, t1, t2, t3);           \
	SM4_ROUND(1, RK, IND, x, y, z, t1, t2, t3, t0);           \
	SM4_ROUND(2, RK, IND, x, y, z, t2, t3, t0, t1);           \
	SM4_ROUND(3, RK, IND, x, y, z, t3, t0, t1, t2);           \
	ADDL $16, IND;                                            \
	SM4_ROUND(0, RK, IND, x, y, z, t0, t1, t2, t3);           \
	SM4_ROUND(1, RK, IND, x, y, z, t1, t2, t3, t0);           \
	SM4_ROUND(2, RK, IND, x, y, z, t2, t3, t0, t1);           \
	SM4_ROUND(3, RK, IND, x, y, z, t3, t0, t1, t2);           \
	ADDL $16, IND;                                            \
	SM4_ROUND(0, RK, IND, x, y, z, t0, t1, t2, t3);           \
	SM4_ROUND(1, RK, IND, x, y, z, t1, t2, t3, t0);           \
	SM4_ROUND(2, RK, IND, x, y, z, t2, t3, t0, t1);           \
	SM4_ROUND(3, RK, IND, x, y, z, t3, t0, t1, t2);           \
	ADDL $16, IND;                                            \
	SM4_ROUND(0, RK, IND, x, y, z, t0, t1, t2, t3);           \
	SM4_ROUND(1, RK, IND, x, y, z, t1, t2, t3, t0);           \
	SM4_ROUND(2, RK, IND, x, y, z, t2, t3, t0, t1);           \
	SM4_ROUND(3, RK, IND, x, y, z, t3, t0, t1, t2);           \
	ADDL $16, IND;                                            \
	SM4_ROUND(0, RK, IND, x, y, z, t0, t1, t2, t3);           \
	SM4_ROUND(1, RK, IND, x, y, z, t1, t2, t3, t0);           \
	SM4_ROUND(2, RK, IND, x, y, z, t2, t3, t0, t1);           \
	SM4_ROUND(3, RK, IND, x, y, z, t3, t0, t1, t2);           \
	SSE_TRANSPOSE_MATRIX(R12, t0, t1, t2, t3, x, y);          \
	PSHUFB BSWAP, t3; \
	PSHUFB BSWAP, t2; \
	PSHUFB BSWAP, t1; \
	PSHUFB BSWAP, t0

#define TRANSPOSE_MATRIX(r0, r1, r2, r3, tmp1, tmp2) \
  VPUNPCKHDQ r1, r0, tmp2;                 \ // tmp2 =  [w15, w7, w14, w6, w11, w3, w10, w2]          tmp2 = [w7, w3, w6, w2]
  VPUNPCKLDQ r1, r0, r0;                   \ // r0 =    [w13, w5, w12, w4, w9, w1, w8, w0]              r0 = [w5, w1, w4, w0]
  VPUNPCKLDQ r3, r2, tmp1;                 \ // tmp1 =  [w29, w21, w28, w20, w25, w17, w24, w16]      tmp1 = [w13, w9, w12, w8]
  VPUNPCKHDQ r3, r2, r2;                   \ // r2 =    [w31, w27, w30, w22, w27, w19, w26, w18]        r2 = [w15, w11, w14, w10] 
  VPUNPCKHQDQ tmp1, r0, r1;                \ // r1 =    [w29, w21, w13, w5, w25, w17, w9, w1]           r1 = [w13, w9, w5, w1]
  VPUNPCKLQDQ tmp1, r0, r0;                \ // r0 =    [w28, w20, w12, w4, w24, w16, w8, w0]           r0 = [w12, w8, w4, w0]
  VPUNPCKHQDQ r2, tmp2, r3;                \ // r3 =    [w31, w27, w15, w7, w27, w19, w11, w3]          r3 = [w15, w11, w7, w3]
  VPUNPCKLQDQ r2, tmp2, r2                   // r2 =    [w30, w22, w14, w6, w26, w18, w10, w2]          r2 = [w14, w10, w6, w2]

#define AVX2_SM4_SBOX(x, y, xw, yw, tmp) \
  VPAND NIBBLE_MASK, x, tmp;                       \
  VBROADCASTI128 m1Low<>(SB), y;                   \
  VPSHUFB tmp, y, y;                               \
  VPSRLQ $4, x, x;                                 \
  VPAND NIBBLE_MASK, x, x;                         \
  VBROADCASTI128 m1High<>(SB), tmp;                \
  VPSHUFB x, tmp, x;                               \
  VPXOR y, x, x;                                   \
  VBROADCASTI128 inverseShiftRows<>(SB), tmp;      \
  VPSHUFB tmp, x, x;                               \
  VEXTRACTI128 $1, x, yw                           \
  VAESENCLAST X_NIBBLE_MASK, xw, xw;               \
  VAESENCLAST X_NIBBLE_MASK, yw, yw;               \
  VINSERTI128 $1, yw, x, x;                        \
  VPANDN NIBBLE_MASK, x, tmp;                      \
  VBROADCASTI128 m2Low<>(SB), y;                   \
  VPSHUFB tmp, y, y;                               \
  VPSRLQ $4, x, x;                                 \
  VPAND NIBBLE_MASK, x, x;                         \
  VBROADCASTI128 m2High<>(SB), tmp;                \
  VPSHUFB x, tmp, x;                               \
  VPXOR y, x, x

#define AVX2_SM4_TAO_L1(x, y, xw, yw, tmp) \
  AVX2_SM4_SBOX(x, y, xw, yw, tmp);          \
  VBROADCASTI128 r08Mask<>(SB), tmp;         \
  VPSHUFB tmp, x, y;                         \
  VPXOR x, y, y;                             \        
  VBROADCASTI128 r16Mask<>(SB), tmp;         \
  VPSHUFB tmp, x, tmp;                       \
  VPXOR tmp, y, y;                           \
  VPSLLD $2, y, tmp;                         \
  VPSRLD $30, y, y;                          \
  VPXOR tmp, y, y;                           \
  VBROADCASTI128 r24Mask<>(SB), tmp;         \
  VPSHUFB tmp, x, tmp;                       \
  VPXOR y, x, x;                             \
  VPXOR x, tmp, x

#define AVX2_SM4_ROUND(index, RK, IND, x, y, xw, yw, tmp, t0, t1, t2, t3)  \ 
  VPBROADCASTD (index * 4)(RK)(IND*1), x;            \
  VPXOR t1, x, x;                                    \
  VPXOR t2, x, x;                                    \
  VPXOR t3, x, x;                                    \
  AVX2_SM4_TAO_L1(x, y, xw, yw, tmp);         \  
  VPXOR x, t0, t0

#define AVX_SM4_SBOX(x, y, tmp) \
  VPAND X_NIBBLE_MASK, x, tmp;                       \
  VMOVDQU m1Low<>(SB), y;                            \
  VPSHUFB tmp, y, y;                                 \
  VPSRLQ $4, x, x;                                   \
  VPAND X_NIBBLE_MASK, x, x;                         \
  VMOVDQU m1High<>(SB), tmp;                         \
  VPSHUFB x, tmp, x;                                 \
  VPXOR y, x, x;                                     \
  VMOVDQU inverseShiftRows<>(SB), tmp;               \
  VPSHUFB tmp, x, x;                                 \
  VAESENCLAST X_NIBBLE_MASK, x, x;                   \
  VPANDN X_NIBBLE_MASK, x, tmp;                      \
  VMOVDQU m2Low<>(SB), y;                            \
  VPSHUFB tmp, y, y;                                 \
  VPSRLQ $4, x, x;                                   \
  VPAND X_NIBBLE_MASK, x, x;                         \
  VMOVDQU m2High<>(SB), tmp;                         \
  VPSHUFB x, tmp, x;                                 \
  VPXOR y, x, x

#define AVX_SM4_TAO_L1(x, y, tmp) \
  AVX_SM4_SBOX(x, y, tmp);                \
  VMOVDQU r08Mask<>(SB), tmp;             \
  VPSHUFB tmp, x, y;                      \
  VPXOR x, y, y;                          \        
  VMOVDQU r16Mask<>(SB), tmp;             \
  VPSHUFB tmp, x, tmp;                    \
  VPXOR tmp, y, y;                        \
  VPSLLD $2, y, tmp;                      \
  VPSRLD $30, y, y;                       \
  VPXOR tmp, y, y;                        \
  VMOVDQU r24Mask<>(SB), tmp;             \
  VPSHUFB tmp, x, tmp;                    \
  VPXOR y, x, x;                          \
  VPXOR x, tmp, x

#define AVX_SM4_ROUND(index, RK, IND, x, y, tmp, t0, t1, t2, t3)  \ 
  VPBROADCASTD (index * 4)(RK)(IND*1), x;                 \
  VPXOR t1, x, x;                                         \
  VPXOR t2, x, x;                                         \
  VPXOR t3, x, x;                                         \
  AVX_SM4_TAO_L1(x, y, tmp);                              \  
  VPXOR x, t0, t0

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

#define increment(i) ADDL $1, aluCTR; MOVL aluCTR, aluTMP; BSWAPL aluTMP; MOVL aluTMP, (3*4 + 8*16 + i*16)(SP)

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

	MOVQ productTable+0(FP), pTbl
	MOVQ dst+8(FP), ctx
	MOVQ src_base+32(FP), ptx
	MOVQ src_len+40(FP), ptxLen
	MOVQ ctr+56(FP), ctrPtr
	MOVQ T+64(FP), tPtr
	MOVQ rk_base+72(FP), rk

	CMPB ·useAVX2(SB), $1
	JE   avx2GcmSm4Enc

	MOVOU bswapMask<>(SB), BSWAP
	MOVOU gcmPoly<>(SB), POLY

	MOVOU (tPtr), ACC0
	PXOR ACC1, ACC1
	PXOR ACCM, ACCM
	MOVOU (ctrPtr), T0
	MOVL (3*4)(ctrPtr), aluCTR
	
	BSWAPL aluCTR
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

	SM4_4BLOCKS(rk, BX, T0, T1, T2, B0, B1, B2, B3)
	increment(0)
	increment(1)
	increment(2)
	increment(3)
	SM4_4BLOCKS(rk, BX, T0, T1, T2, B4, B5, B6, B7)
	increment(4)
	increment(5)
	increment(6)
	increment(7)	

	// XOR plaintext
	MOVOU (16*0)(ptx), T0
	PXOR T0, B0
	MOVOU (16*1)(ptx), T0
	PXOR T0, B1
	MOVOU (16*2)(ptx), T0
	PXOR T0, B2
	MOVOU (16*3)(ptx), T0
	PXOR T0, B3
	MOVOU (16*4)(ptx), T0
	PXOR T0, B4
	MOVOU (16*5)(ptx), T0
	PXOR T0, B5
	MOVOU (16*6)(ptx), T0
	PXOR T0, B6
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

		SM4_4BLOCKS(rk, BX, T0, T1, T2, B0, B1, B2, B3)
		mulRound(1)
		increment(0)
		mulRound(2)
		increment(1)
		mulRound(3)
		increment(2)
	 	mulRound(4)
		increment(3)
		SM4_4BLOCKS(rk, BX, T0, T1, T2, B4, B5, B6, B7)
		mulRound(5)
		increment(4)
		mulRound(6)
		increment(5)
	 	mulRound(7)
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
		
		MOVOU (16*0)(ptx), T0
		PXOR T0, B0
		MOVOU (16*1)(ptx), T0
		PXOR T0, B1
		MOVOU (16*2)(ptx), T0
		PXOR T0, B2
		MOVOU (16*3)(ptx), T0
		PXOR T0, B3
		MOVOU (16*4)(ptx), T0
		PXOR T0, B4
		MOVOU (16*5)(ptx), T0
		PXOR T0, B5
		MOVOU (16*6)(ptx), T0
		PXOR T0, B6
		MOVOU (16*7)(ptx), T0
		PXOR T0, B7

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
	
	SM4_4BLOCKS(AX, BX, T0, T1, T2, B0, B1, B2, B3)
	MOVOU (16*0)(ptx), T0
	PXOR T0, B0
	MOVOU (16*1)(ptx), T0
	PXOR T0, B1
	MOVOU (16*2)(ptx), T0
	PXOR T0, B2
	MOVOU (16*3)(ptx), T0
	PXOR T0, B3

	MOVOU B0, (16*0)(ctx)
	MOVOU B1, (16*1)(ctx)
	MOVOU B2, (16*2)(ctx)
	MOVOU B3, (16*3)(ctx)

	MOVOU (16*14)(pTbl), T2
	gcmEncDataStep(B0)
	gcmEncDataStep(B1)
	gcmEncDataStep(B2)
	gcmEncDataStep(B3)
	increment(0)
	increment(1)
	increment(2)
	increment(3)

	LEAQ 64(ptx), ptx
	LEAQ 64(ctx), ctx

gcmSm4EncSingles:
	TESTQ ptxLen, ptxLen
	JE gcmSm4EncDone
	MOVOU (8*16 + 0*16)(SP), B0
	MOVOU (8*16 + 1*16)(SP), B1
	MOVOU (8*16 + 2*16)(SP), B2
	MOVOU (8*16 + 3*16)(SP), B3
	
	SM4_4BLOCKS(AX, BX, T0, T1, T2, B0, B1, B2, B3)
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

avx2GcmSm4Enc:
	VMOVDQU bswapMask<>(SB), BSWAP
	VMOVDQU gcmPoly<>(SB), POLY

	VMOVDQU (tPtr), ACC0
	VPXOR ACC1, ACC1, ACC1
	VPXOR ACCM, ACCM, ACCM
	VMOVDQU (ctrPtr), T0
	MOVL (3*4)(ctrPtr), aluCTR
	
	BSWAPL aluCTR
	VMOVDQU T0, (8*16 + 0*16)(SP)
	increment(0)
	VMOVDQU T0, (8*16 + 1*16)(SP)
	increment(1)
	VMOVDQU T0, (8*16 + 2*16)(SP)
	increment(2)
	VMOVDQU T0, (8*16 + 3*16)(SP)
	increment(3)

	CMPQ ptxLen, $128
	JB avx2GcmSm4EncNibbles
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
	VMOVDQU (4*32 + 0*32)(SP), DWB0
	VMOVDQU (4*32 + 1*32)(SP), DWB1
	VMOVDQU (4*32 + 2*32)(SP), DWB2
	VMOVDQU (4*32 + 3*32)(SP), DWB3

	VBROADCASTI128 flipMask<>(SB), XDWTMP0
	// Apply Byte Flip Mask: LE -> BE
	VPSHUFB XDWTMP0, DWB0, DWB0
	VPSHUFB XDWTMP0, DWB1, DWB1
	VPSHUFB XDWTMP0, DWB2, DWB2
	VPSHUFB XDWTMP0, DWB3, DWB3

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(DWB0, DWB1, DWB2, DWB3, XDWTMP0, XDWTMP1)
	XORL BX, BX
	VBROADCASTI128 nibbleMask<>(SB), NIBBLE_MASK

avx2GcmSm4Enc8Loop1:
	AVX2_SM4_ROUND(0, rk, BX, XDWORD, YDWORD, X1, X3, XDWTMP1, DWB0, DWB1, DWB2, DWB3) 
	AVX2_SM4_ROUND(1, rk, BX, XDWORD, YDWORD, X1, X3, XDWTMP1, DWB1, DWB2, DWB3, DWB0) 
	AVX2_SM4_ROUND(2, rk, BX, XDWORD, YDWORD, X1, X3, XDWTMP1, DWB2, DWB3, DWB0, DWB1) 
	AVX2_SM4_ROUND(3, rk, BX, XDWORD, YDWORD, X1, X3, XDWTMP1, DWB3, DWB0, DWB1, DWB2) 

	ADDL $16, BX
	CMPL BX, $4*32
	JB avx2GcmSm4Enc8Loop1

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(DWB0, DWB1, DWB2, DWB3, XDWTMP0, XDWTMP1)

	VBROADCASTI128 bswapMask<>(SB), DWBSWAP
	VPSHUFB DWBSWAP, DWB0, DWB0
	VPSHUFB DWBSWAP, DWB1, DWB1
	VPSHUFB DWBSWAP, DWB2, DWB2
	VPSHUFB DWBSWAP, DWB3, DWB3

	increment(0)
	increment(1)
	increment(2)
	increment(3)
	increment(4)
	increment(5)
	increment(6)
	increment(7)

	// XOR plaintext
	VMOVDQU (32*0)(ptx), XDWTMP0
	VPXOR XDWTMP0, DWB0, DWB0
	VMOVDQU (32*1)(ptx), XDWTMP0
	VPXOR XDWTMP0, DWB1, DWB1
	VMOVDQU (32*2)(ptx), XDWTMP0
	VPXOR XDWTMP0, DWB2, DWB2
	VMOVDQU (32*3)(ptx), XDWTMP0
	VPXOR XDWTMP0, DWB3, DWB3

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

avx2GcmSm4EncOctetsLoop:
		CMPQ ptxLen, $128
		JB avx2GcmSm4EncOctetsEnd
		SUBQ $128, ptxLen

		// load 8 ctrs for encryption
		VMOVDQU (4*32 + 0*32)(SP), DWB0
		VMOVDQU (4*32 + 1*32)(SP), DWB1
		VMOVDQU (4*32 + 2*32)(SP), DWB2
		VMOVDQU (4*32 + 3*32)(SP), DWB3

		VBROADCASTI128 flipMask<>(SB), XDWTMP0
		// Apply Byte Flip Mask: LE -> BE
		VPSHUFB XDWTMP0, DWB0, DWB0
		VPSHUFB XDWTMP0, DWB1, DWB1
		VPSHUFB XDWTMP0, DWB2, DWB2
		VPSHUFB XDWTMP0, DWB3, DWB3

		VMOVDQU (16*0)(SP), T0
		VPSHUFD $78, T0, T1
		VPXOR T0, T1, T1

		VMOVDQU (16*0)(pTbl), ACC0
		VMOVDQU (16*1)(pTbl), ACCM
		VMOVDQU ACC0, ACC1

		PCLMULQDQ $0x00, T1, ACCM
		PCLMULQDQ $0x00, T0, ACC0
		PCLMULQDQ $0x11, T0, ACC1

		// Transpose matrix 4 x 4 32bits word
		TRANSPOSE_MATRIX(DWB0, DWB1, DWB2, DWB3, XDWTMP0, XDWTMP1)
		XORL BX, BX
		VBROADCASTI128 nibbleMask<>(SB), NIBBLE_MASK

avx2GcmSm4Enc8Loop2:
			AVX2_SM4_ROUND(0, rk, BX, XDWORD, YDWORD, X1, X3, XDWTMP1, DWB0, DWB1, DWB2, DWB3) 
			AVX2_SM4_ROUND(1, rk, BX, XDWORD, YDWORD, X1, X3, XDWTMP1, DWB1, DWB2, DWB3, DWB0) 
			AVX2_SM4_ROUND(2, rk, BX, XDWORD, YDWORD, X1, X3, XDWTMP1, DWB2, DWB3, DWB0, DWB1) 
			AVX2_SM4_ROUND(3, rk, BX, XDWORD, YDWORD, X1, X3, XDWTMP1, DWB3, DWB0, DWB1, DWB2) 

  		ADDL $16, BX
  		CMPL BX, $4*32
		JB avx2GcmSm4Enc8Loop2

		// Transpose matrix 4 x 4 32bits word
		TRANSPOSE_MATRIX(DWB0, DWB1, DWB2, DWB3, XDWTMP0, XDWTMP1)

		VBROADCASTI128 bswapMask<>(SB), DWBSWAP
		VPSHUFB DWBSWAP, DWB0, DWB0
		VPSHUFB DWBSWAP, DWB1, DWB1
		VPSHUFB DWBSWAP, DWB2, DWB2
		VPSHUFB DWBSWAP, DWB3, DWB3

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
		increment(7)
		VPXOR ACC0, ACCM, ACCM
		VPXOR ACC1, ACCM, ACCM
		VPSLLDQ $8, ACCM, T0
		VPSRLDQ $8, ACCM, ACCM
		
		VPXOR ACCM, ACC1, ACC1
		VPXOR T0, ACC0, ACC0

		reduceRound(ACC0)
		reduceRound(ACC0)
		VPXOR ACC1, ACC0, ACC0

		// XOR plaintext
		VMOVDQU (32*0)(ptx), XDWTMP0
		VPXOR XDWTMP0, DWB0, DWB0
		VMOVDQU (32*1)(ptx), XDWTMP0
		VPXOR XDWTMP0, DWB1, DWB1
		VMOVDQU (32*2)(ptx), XDWTMP0
		VPXOR XDWTMP0, DWB2, DWB2
		VMOVDQU (32*3)(ptx), XDWTMP0
		VPXOR XDWTMP0, DWB3, DWB3

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

	VPXOR ACC0, ACCM, ACCM
	VPXOR ACC1, ACCM, ACCM
	VPSLLDQ $8, ACCM, T0
	VPSRLDQ $8, ACCM, ACCM
	
	VPXOR ACCM, ACC1, ACC1
	VPXOR T0, ACC0, ACC0

	reduceRound(ACC0)
	reduceRound(ACC0)
	VPXOR ACC1, ACC0, ACC0

	TESTQ ptxLen, ptxLen
	JE avx2GcmSm4EncDone

	SUBQ $4, aluCTR

avx2GcmSm4EncNibbles:
	VMOVDQU flipMask<>(SB), B7
	CMPQ ptxLen, $64
	JBE avx2GcmSm4EncSingles
	SUBQ $64, ptxLen

	VMOVDQU (8*16 + 0*16)(SP), B0
	VMOVDQU (8*16 + 1*16)(SP), B1
	VMOVDQU (8*16 + 2*16)(SP), B2
	VMOVDQU (8*16 + 3*16)(SP), B3
	
	VPSHUFB B7, B0, B0
	VPSHUFB B7, B1, B1
	VPSHUFB B7, B2, B2
	VPSHUFB B7, B3, B3

	TRANSPOSE_MATRIX(B0, B1, B2, B3, T0, T1)
	XORL BX, BX	
	VMOVDQU nibbleMask<>(SB), X_NIBBLE_MASK

avx2GcmSm4Enc4Loop2:
	AVX_SM4_ROUND(0, rk, BX, B4, B5, B6, B0, B1, B2, B3)
	AVX_SM4_ROUND(1, rk, BX, B4, B5, B6, B1, B2, B3, B0)
	AVX_SM4_ROUND(2, rk, BX, B4, B5, B6, B2, B3, B0, B1)
	AVX_SM4_ROUND(3, rk, BX, B4, B5, B6, B3, B0, B1, B2)

	ADDL $16, BX
	CMPL BX, $4*32
	JB avx2GcmSm4Enc4Loop2

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(B0, B1, B2, B3, B4, B5)
	VPSHUFB BSWAP, B0, B0
	VPSHUFB BSWAP, B1, B1
	VPSHUFB BSWAP, B2, B2
	VPSHUFB BSWAP, B3, B3

	VMOVDQU (16*0)(ptx), T0
	VPXOR T0, B0, B0
	VMOVDQU (16*1)(ptx), T0
	VPXOR T0, B1, B1
	VMOVDQU (16*2)(ptx), T0
	VPXOR T0, B2, B2
	VMOVDQU (16*3)(ptx), T0
	VPXOR T0, B3, B3

	VMOVDQU B0, (16*0)(ctx)
	VMOVDQU B1, (16*1)(ctx)
	VMOVDQU B2, (16*2)(ctx)
	VMOVDQU B3, (16*3)(ctx)

	VMOVDQU (16*14)(pTbl), T2
	gcmEncDataStep(B0)
	gcmEncDataStep(B1)
	gcmEncDataStep(B2)
	gcmEncDataStep(B3)
	increment(0)
	increment(1)
	increment(2)
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

	VPSHUFB B7, B0, B0
	VPSHUFB B7, B1, B1
	VPSHUFB B7, B2, B2
	VPSHUFB B7, B3, B3

	TRANSPOSE_MATRIX(B0, B1, B2, B3, T0, T1)
	XORL BX, BX
	VMOVDQU nibbleMask<>(SB), X_NIBBLE_MASK

avx2GcmSm4Enc4Loop1:
	AVX_SM4_ROUND(0, rk, BX, B4, B5, B6, B0, B1, B2, B3)
	AVX_SM4_ROUND(1, rk, BX, B4, B5, B6, B1, B2, B3, B0)
	AVX_SM4_ROUND(2, rk, BX, B4, B5, B6, B2, B3, B0, B1)
	AVX_SM4_ROUND(3, rk, BX, B4, B5, B6, B3, B0, B1, B2)

	ADDL $16, BX
	CMPL BX, $4*32
	JB avx2GcmSm4Enc4Loop1

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(B0, B1, B2, B3, B4, B5)
	VPSHUFB BSWAP, B0, B0
	VPSHUFB BSWAP, B1, B1
	VPSHUFB BSWAP, B2, B2
	VPSHUFB BSWAP, B3, B3

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
		gcmEncDataStep(B0)
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
		PSLLDQ $1, B0
		PINSRB $0, (ptx), B0
		LEAQ -1(ptx), ptx
		DECQ ptxLen
	JNE avx2PtxLoadLoop

	VPXOR T0, B0, B0
	VPAND T1, B0, B0
	VMOVDQU B0, (ctx)	// I assume there is always space, due to TAG in the end of the CT
	gcmEncDataStep(B0)

avx2GcmSm4EncDone:
	VMOVDQU ACC0, (tPtr)
	VZEROUPPER
	RET

#undef increment

// func gcmSm4Dec(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)
TEXT ·gcmSm4Dec(SB),0,$128-96
#define increment(i) ADDL $1, aluCTR; MOVL aluCTR, aluTMP; BSWAPL aluTMP; MOVL aluTMP, (3*4 + i*16)(SP)

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

	MOVQ productTable+0(FP), pTbl
	MOVQ dst+8(FP), ptx
	MOVQ src_base+32(FP), ctx
	MOVQ src_len+40(FP), ptxLen
	MOVQ ctr+56(FP), ctrPtr
	MOVQ T+64(FP), tPtr
	MOVQ rk_base+72(FP), rk

	CMPB ·useAVX2(SB), $1
	JE   avx2GcmSm4Dec

	MOVOU bswapMask<>(SB), BSWAP
	MOVOU gcmPoly<>(SB), POLY

	MOVOU (tPtr), ACC0
	PXOR ACC1, ACC1
	PXOR ACCM, ACCM
	MOVOU (ctrPtr), T0
	MOVL (3*4)(ctrPtr), aluCTR
	BSWAPL aluCTR

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

		SM4_4BLOCKS(rk, BX, T0, T1, T2, B0, B1, B2, B3)
		decMulRound(1)
		increment(0)
		decMulRound(2)
		increment(1)
		decMulRound(3)
		increment(2)
	 	decMulRound(4)
		increment(3)
		SM4_4BLOCKS(rk, BX, T0, T1, T2, B4, B5, B6, B7)
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

		MOVOU (16*0)(ctx), T0
		PXOR T0, B0
		MOVOU (16*1)(ctx), T0
		PXOR T0, B1
		MOVOU (16*2)(ctx), T0
		PXOR T0, B2
		MOVOU (16*3)(ctx), T0
		PXOR T0, B3
		MOVOU (16*4)(ctx), T0
		PXOR T0, B4
		MOVOU (16*5)(ctx), T0
		PXOR T0, B5
		MOVOU (16*6)(ctx), T0
		PXOR T0, B6
		MOVOU (16*7)(ctx), T0
		PXOR T0, B7

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

	MOVOU (0*16)(SP), B0
	MOVOU (1*16)(SP), B1
	MOVOU (2*16)(SP), B2
	MOVOU (3*16)(SP), B3

	SM4_4BLOCKS(rk, BX, T0, T1, T2, B0, B1, B2, B3)
	MOVOU (16*14)(pTbl), T2
	MOVOU (16*0)(ctx), T0
	PXOR T0, B0
	MOVOU (16*1)(ctx), T0
	PXOR T0, B1
	MOVOU (16*2)(ctx), T0
	PXOR T0, B2
	MOVOU (16*3)(ctx), T0
	PXOR T0, B3

	MOVOU B0, (16*0)(ptx)
	MOVOU B1, (16*1)(ptx)
	MOVOU B2, (16*2)(ptx)
	MOVOU B3, (16*3)(ptx)

	
	decGhashRound(0)
	increment(0)
	decGhashRound(1)
	increment(1)
	decGhashRound(2)
	increment(2)
	decGhashRound(3)
	increment(3)

	LEAQ 64(ptx), ptx
	LEAQ 64(ctx), ctx

gcmSm4DecSingles:
	TESTQ ptxLen, ptxLen
	JE gcmSm4DecDone
	MOVOU (0*16)(SP), B0
	MOVOU (1*16)(SP), B1
	MOVOU (2*16)(SP), B2
	MOVOU (3*16)(SP), B3
	
	SM4_4BLOCKS(rk, BX, T0, T1, T2, B0, B1, B2, B3)
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

		MOVOU (16*0)(BP), B0
		MOVOU (ctx), T0
		PXOR T0, B0
		MOVOU B0, (ptx)

		decGhashRound(0)
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
	PSHUFB BSWAP, B0
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

	reduceRound(ACC0)
	reduceRound(ACC0)
	PXOR ACC1, ACC0

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

avx2GcmSm4Dec:
	VMOVDQU bswapMask<>(SB), BSWAP
	VMOVDQU gcmPoly<>(SB), POLY

	VMOVDQU (tPtr), ACC0
	VPXOR ACC1, ACC1, ACC1
	VPXOR ACCM, ACCM, ACCM
	VMOVDQU (ctrPtr), T0
	MOVL (3*4)(ctrPtr), aluCTR
	BSWAPL aluCTR

	VMOVDQU T0, (0*16)(SP)
	increment(0)
	VMOVDQU T0, (1*16)(SP)
	increment(1)
	VMOVDQU T0, (2*16)(SP)
	increment(2)
	VMOVDQU T0, (3*16)(SP)
	increment(3)

	CMPQ ptxLen, $128
	JB avx2GcmSm4DecNibbles

	// We have at least 8 blocks to dencrypt, prepare the rest of the counters
	VMOVDQU T0, (4*16)(SP)
	increment(4)
	VMOVDQU T0, (5*16)(SP)
	increment(5)
	VMOVDQU T0, (6*16)(SP)
	increment(6)
	VMOVDQU T0, (7*16)(SP)
	increment(7)

avx2GcmSm4DecOctetsLoop:
		CMPQ ptxLen, $128
		JB avx2GcmSm4DecEndOctets
		SUBQ $128, ptxLen

		// load 8 ctrs for encryption
		VMOVDQU (0*32)(SP), DWB0
		VMOVDQU (1*32)(SP), DWB1
		VMOVDQU (2*32)(SP), DWB2
		VMOVDQU (3*32)(SP), DWB3

		VBROADCASTI128 flipMask<>(SB), XDWTMP0
		// Apply Byte Flip Mask: LE -> BE
		VPSHUFB XDWTMP0, DWB0, DWB0
		VPSHUFB XDWTMP0, DWB1, DWB1
		VPSHUFB XDWTMP0, DWB2, DWB2
		VPSHUFB XDWTMP0, DWB3, DWB3

		VMOVDQU (16*0)(ctx), T0
		VPSHUFB BSWAP, T0, T0
		VPXOR ACC0, T0, T0
		VPSHUFD $78, T0, T1
		VPXOR T0, T1, T1

		VMOVDQU (16*0)(pTbl), ACC0
		VMOVDQU (16*1)(pTbl), ACCM
		VMOVDQU ACC0, ACC1

		PCLMULQDQ $0x00, T1, ACCM
		PCLMULQDQ $0x00, T0, ACC0
		PCLMULQDQ $0x11, T0, ACC1


		// Transpose matrix 4 x 4 32bits word
		TRANSPOSE_MATRIX(DWB0, DWB1, DWB2, DWB3, XDWTMP0, XDWTMP1)
		XORL BX, BX
		VBROADCASTI128 nibbleMask<>(SB), NIBBLE_MASK

avx2GcmSm4Dec8Loop2:
			AVX2_SM4_ROUND(0, rk, BX, XDWORD, YDWORD, X1, X3, XDWTMP1, DWB0, DWB1, DWB2, DWB3) 
			AVX2_SM4_ROUND(1, rk, BX, XDWORD, YDWORD, X1, X3, XDWTMP1, DWB1, DWB2, DWB3, DWB0) 
			AVX2_SM4_ROUND(2, rk, BX, XDWORD, YDWORD, X1, X3, XDWTMP1, DWB2, DWB3, DWB0, DWB1) 
			AVX2_SM4_ROUND(3, rk, BX, XDWORD, YDWORD, X1, X3, XDWTMP1, DWB3, DWB0, DWB1, DWB2) 

			ADDL $16, BX
			CMPL BX, $4*32
		JB avx2GcmSm4Dec8Loop2

		// Transpose matrix 4 x 4 32bits word
		TRANSPOSE_MATRIX(DWB0, DWB1, DWB2, DWB3, XDWTMP0, XDWTMP1)

		VBROADCASTI128 bswapMask<>(SB), DWBSWAP
		VPSHUFB DWBSWAP, DWB0, DWB0
		VPSHUFB DWBSWAP, DWB1, DWB1
		VPSHUFB DWBSWAP, DWB2, DWB2
		VPSHUFB DWBSWAP, DWB3, DWB3

		VMOVDQU (32*0)(ctx), XDWTMP0
		VPXOR XDWTMP0, DWB0, DWB0
		VPSHUFB DWBSWAP, XDWTMP0, XDWTMP0
		VEXTRACTI128 $1, XDWTMP0, T0
		internalDecMulRound(1)
		increment(0)

		VMOVDQU (32*1)(ctx), XDWTMP0
		VPXOR XDWTMP0, DWB1, DWB1
		VPSHUFB DWBSWAP, XDWTMP0, XDWTMP0
		VEXTRACTI128 $0, XDWTMP0, T0
		internalDecMulRound(2)
		increment(1)
		VEXTRACTI128 $1, XDWTMP0, T0
		internalDecMulRound(3)
		increment(2)

		VMOVDQU (32*2)(ctx), XDWTMP0
		VPXOR XDWTMP0, DWB2, DWB2
		VPSHUFB DWBSWAP, XDWTMP0, XDWTMP0
		VEXTRACTI128 $0, XDWTMP0, T0
		internalDecMulRound(4)
		increment(3)
		VEXTRACTI128 $1, XDWTMP0, T0
		internalDecMulRound(5)
		increment(4)

		VMOVDQU (32*3)(ctx), XDWTMP0
		VPXOR XDWTMP0, DWB3, DWB3
		VPSHUFB DWBSWAP, XDWTMP0, XDWTMP0
		VEXTRACTI128 $0, XDWTMP0, T0
		internalDecMulRound(6)
		increment(5)
		VEXTRACTI128 $1, XDWTMP0, T0
		internalDecMulRound(7)
		increment(6)
		increment(7)

		VMOVDQU DWB0, (32*0)(ptx)
		VMOVDQU DWB1, (32*1)(ptx)
		VMOVDQU DWB2, (32*2)(ptx)
		VMOVDQU DWB3, (32*3)(ptx)

		VPXOR ACC0, ACCM, ACCM
		VPXOR ACC1, ACCM, ACCM
		VPSLLDQ $8, ACCM, T0
		VPSRLDQ $8, ACCM, ACCM
		
		VPXOR ACCM, ACC1, ACC1
		VPXOR T0, ACC0, ACC0

		reduceRound(ACC0)
		reduceRound(ACC0)
		VPXOR ACC1, ACC0, ACC0

		LEAQ 128(ptx), ptx
		LEAQ 128(ctx), ctx

		JMP avx2GcmSm4DecOctetsLoop

avx2GcmSm4DecEndOctets:
	SUBQ $4, aluCTR

avx2GcmSm4DecNibbles:
	VMOVDQU flipMask<>(SB), B7 // DO NOT CHANGE B7
	CMPQ ptxLen, $64
	JBE avx2GcmSm4DecSingles
	SUBQ $64, ptxLen

	VMOVDQU (0*16)(SP), B0
	VMOVDQU (1*16)(SP), B1
	VMOVDQU (2*16)(SP), B2
	VMOVDQU (3*16)(SP), B3
	
	VPSHUFB B7, B0, B0
	VPSHUFB B7, B1, B1
	VPSHUFB B7, B2, B2
	VPSHUFB B7, B3, B3

	TRANSPOSE_MATRIX(B0, B1, B2, B3, T0, T1)
	XORL BX, BX	
	VMOVDQU nibbleMask<>(SB), X_NIBBLE_MASK

avx2GcmSm4Dec4Loop2:
	AVX_SM4_ROUND(0, rk, BX, B4, B5, B6, B0, B1, B2, B3)
	AVX_SM4_ROUND(1, rk, BX, B4, B5, B6, B1, B2, B3, B0)
	AVX_SM4_ROUND(2, rk, BX, B4, B5, B6, B2, B3, B0, B1)
	AVX_SM4_ROUND(3, rk, BX, B4, B5, B6, B3, B0, B1, B2)

	ADDL $16, BX
	CMPL BX, $4*32
	JB avx2GcmSm4Dec4Loop2

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(B0, B1, B2, B3, B4, B5)
	VPSHUFB BSWAP, B0, B4
	VPSHUFB BSWAP, B1, B1
	VPSHUFB BSWAP, B2, B2
	VPSHUFB BSWAP, B3, B3

	VMOVDQU (16*14)(pTbl), T2
	VMOVDQU (16*0)(ctx), B0
	VPXOR B0, B4, B4
	internalDecGhashRound()

	VMOVDQU (16*1)(ctx), B0
	VPXOR B0, B1, B1
	internalDecGhashRound()

	VMOVDQU (16*2)(ctx), B0
	VPXOR B0, B2, B2
	internalDecGhashRound()

	VMOVDQU (16*3)(ctx), B0
	VPXOR B0, B3, B3
	internalDecGhashRound()

	VMOVDQU B4, (16*0)(ptx)
	VMOVDQU B1, (16*1)(ptx)
	VMOVDQU B2, (16*2)(ptx)
	VMOVDQU B3, (16*3)(ptx)

	increment(0)
	increment(1)
	increment(2)
	increment(3)

	LEAQ 64(ptx), ptx
	LEAQ 64(ctx), ctx

avx2GcmSm4DecSingles:
	TESTQ ptxLen, ptxLen
	JE avx2GcmSm4DecDone

	VMOVDQU (0*16)(SP), B0
	VMOVDQU (1*16)(SP), B1
	VMOVDQU (2*16)(SP), B2
	VMOVDQU (3*16)(SP), B3

	VPSHUFB B7, B0, B0
	VPSHUFB B7, B1, B1
	VPSHUFB B7, B2, B2
	VPSHUFB B7, B3, B3

	TRANSPOSE_MATRIX(B0, B1, B2, B3, T0, T1)
	
	XORL BX, BX	
	VMOVDQU nibbleMask<>(SB), X_NIBBLE_MASK

avx2GcmSm4Dec4Loop1:
	AVX_SM4_ROUND(0, rk, BX, B4, B5, B6, B0, B1, B2, B3)
	AVX_SM4_ROUND(1, rk, BX, B4, B5, B6, B1, B2, B3, B0)
	AVX_SM4_ROUND(2, rk, BX, B4, B5, B6, B2, B3, B0, B1)
	AVX_SM4_ROUND(3, rk, BX, B4, B5, B6, B3, B0, B1, B2)

	ADDL $16, BX
	CMPL BX, $4*32
	JB avx2GcmSm4Dec4Loop1

	// Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(B0, B1, B2, B3, B4, B5)
	VPSHUFB BSWAP, B0, B0
	VPSHUFB BSWAP, B1, B1
	VPSHUFB BSWAP, B2, B2
	VPSHUFB BSWAP, B3, B3

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

		internalDecGhashRound()
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
	internalDecGhashRound()
	VMOVDQU (16*0)(BP), B0
	VPXOR T1, B0, B0

avx2PtxStoreLoop:
		PEXTRB $0, B0, (ptx)
		PSRLDQ $1, B0
		LEAQ 1(ptx), ptx
		DECQ ptxLen

	JNE avx2PtxStoreLoop

avx2GcmSm4DecDone:
	VMOVDQU ACC0, (tPtr)
	VZEROUPPER	
	RET
