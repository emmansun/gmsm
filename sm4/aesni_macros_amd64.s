// shuffle byte order from LE to BE
DATA flip_mask<>+0x00(SB)/8, $0x0405060700010203
DATA flip_mask<>+0x08(SB)/8, $0x0c0d0e0f08090a0b
GLOBL flip_mask<>(SB), 8, $16

// shuffle byte and word order
DATA bswap_mask<>+0x00(SB)/8, $0x08090a0b0c0d0e0f
DATA bswap_mask<>+0x08(SB)/8, $0x0001020304050607
GLOBL bswap_mask<>(SB), 8, $16

//nibble mask
DATA nibble_mask<>+0x00(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA nibble_mask<>+0x08(SB)/8, $0x0F0F0F0F0F0F0F0F
GLOBL nibble_mask<>(SB), 8, $16

// inverse shift rows
DATA inverse_shift_rows<>+0x00(SB)/8, $0x0B0E0104070A0D00
DATA inverse_shift_rows<>+0x08(SB)/8, $0x0306090C0F020508
GLOBL inverse_shift_rows<>(SB), 8, $16

// Affine transform 1 (low and high hibbles)
DATA m1_low<>+0x00(SB)/8, $0x0A7FC3B6D5A01C69
DATA m1_low<>+0x08(SB)/8, $0x3045F98CEF9A2653
GLOBL m1_low<>(SB), 8, $16

DATA m1_high<>+0x00(SB)/8, $0xC35BF46CAF379800
DATA m1_high<>+0x08(SB)/8, $0x68F05FC7049C33AB
GLOBL m1_high<>(SB), 8, $16

// Affine transform 2 (low and high hibbles)
DATA m2_low<>+0x00(SB)/8, $0x9A950A05FEF16E61
DATA m2_low<>+0x08(SB)/8, $0x0E019E916A65FAF5
GLOBL m2_low<>(SB), 8, $16

DATA m2_high<>+0x00(SB)/8, $0x892D69CD44E0A400
DATA m2_high<>+0x08(SB)/8, $0x2C88CC68E14501A5
GLOBL m2_high<>(SB), 8, $16

// left rotations of 32-bit words by 8-bit increments
DATA r08_mask<>+0x00(SB)/8, $0x0605040702010003
DATA r08_mask<>+0x08(SB)/8, $0x0E0D0C0F0A09080B
GLOBL r08_mask<>(SB), 8, $16

DATA fk_mask<>+0x00(SB)/8, $0x56aa3350a3b1bac6
DATA fk_mask<>+0x08(SB)/8, $0xb27022dc677d9197
GLOBL fk_mask<>(SB), 8, $16

// inverse shift rows
DATA inverse_shift_rows256<>+0x00(SB)/8, $0x0B0E0104070A0D00
DATA inverse_shift_rows256<>+0x08(SB)/8, $0x0306090C0F020508
DATA inverse_shift_rows256<>+0x10(SB)/8, $0x0B0E0104070A0D00
DATA inverse_shift_rows256<>+0x18(SB)/8, $0x0306090C0F020508
GLOBL inverse_shift_rows256<>(SB), 8, $32

DATA r08_mask256<>+0x00(SB)/8, $0x0605040702010003
DATA r08_mask256<>+0x08(SB)/8, $0x0E0D0C0F0A09080B
DATA r08_mask256<>+0x10(SB)/8, $0x0605040702010003
DATA r08_mask256<>+0x18(SB)/8, $0x0E0D0C0F0A09080B
GLOBL r08_mask256<>(SB), 8, $32

// Transpose matrix without PUNPCKHDQ/PUNPCKLDQ/PUNPCKHQDQ/PUNPCKLQDQ instructions, bad performance!
// input: from high to low
// r0 = [w3, w2, w1, w0]
// r1 = [w7, w6, w5, w4]
// r2 = [w11, w10, w9, w8]
// r3 = [w15, w14, w13, w12]
// r: 32/64 temp register
// tmp1: 128 bits temp register
// tmp2: 128 bits temp register
//
// output: from high to low
// r0 = [w12, w8, w4, w0]
// r1 = [w13, w9, w5, w1]
// r2 = [w14, w10, w6, w2]
// r3 = [w15, w11, w7, w3]
//
// SSE2/MMX instructions:
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
#define SSE_TRANSPOSE_MATRIX(r0, r1, r2, r3, tmp1, tmp2) \
	MOVOU r0, tmp2;      \
	PUNPCKHLQ r1, tmp2;  \
	PUNPCKLLQ	r1, r0;  \
	MOVOU r2, tmp1;      \
	PUNPCKLLQ r3, tmp1;  \
	PUNPCKHLQ r3, r2;    \
	MOVOU r0, r1;        \
	PUNPCKHQDQ tmp1, r1; \
	PUNPCKLQDQ tmp1, r0; \
	MOVOU tmp2, r3;      \
	PUNPCKHQDQ r2, r3;   \
	PUNPCKLQDQ r2, tmp2; \
	MOVOU tmp2, r2

// SM4 sbox function
// parameters:
// -  x: 128 bits register as sbox input/output data
// -  y: 128 bits temp register
// -  z: 128 bits temp register
#define SM4_SBOX(x, y, z) \
	;                                   \ //#############################  inner affine ############################//
	MOVOU x, z;                         \
	PAND nibble_mask<>(SB), z;          \ //y = _mm_and_si128(x, c0f); 
	MOVOU m1_low<>(SB), y;              \
	PSHUFB z, y;                        \ //y = _mm_shuffle_epi8(m1l, y);
	PSRLQ $4, x;                        \ //x = _mm_srli_epi64(x, 4); 
	PAND nibble_mask<>(SB), x;          \ //x = _mm_and_si128(x, c0f);
	MOVOU m1_high<>(SB), z;             \
	PSHUFB x, z;                        \ //x = _mm_shuffle_epi8(m1h, x);
	MOVOU  z, x;                        \ //x = _mm_shuffle_epi8(m1h, x);
	PXOR y, x;                          \ //x = _mm_shuffle_epi8(m1h, x) ^ y;
	;                                   \ // inverse ShiftRows
	PSHUFB inverse_shift_rows<>(SB), x; \ //x = _mm_shuffle_epi8(x, shr); 
	AESENCLAST nibble_mask<>(SB), x;    \ // AESNI instruction
	;                                   \ //#############################  outer affine ############################//
	MOVOU  x, z;                        \
	PANDN nibble_mask<>(SB), z;         \ //z = _mm_andnot_si128(x, c0f);
	MOVOU m2_low<>(SB), y;              \ 
	PSHUFB z, y;                        \ //y = _mm_shuffle_epi8(m2l, z)
	PSRLQ $4, x;                        \ //x = _mm_srli_epi64(x, 4);
	PAND nibble_mask<>(SB), x;          \ //x = _mm_and_si128(x, c0f); 
	MOVOU m2_high<>(SB), z;             \
	PSHUFB x, z;                        \
	MOVOU  z, x;                        \ //x = _mm_shuffle_epi8(m2h, x)
	PXOR y, x                             //x = _mm_shuffle_epi8(m2h, x) ^ y; 

// SM4 TAO L1 function
// parameters:
// -  x: 128 bits register as TAO_L1 input/output data
// -  y: 128 bits temp register
// -  z: 128 bits temp register
#define SM4_TAO_L1(x, y, z)         \
	SM4_SBOX(x, y, z);                  \
	;                                   \ //####################  4 parallel L1 linear transforms ##################//
	MOVOU x, y;                         \
	PSHUFB r08_mask<>(SB), y;           \ //y = x <<< 8
	MOVOU y, z;                         \
	PSHUFB r08_mask<>(SB), z;           \ //z = x <<< 16
	PXOR x, y;                          \ //y = x ^ (x <<< 8)
	PXOR z, y;                          \ //y = x ^ (x <<< 8) ^ (x <<< 16)
	PSHUFB r08_mask<>(SB), z;           \ //z = x <<< 24
	PXOR z, x;                          \ //x = x ^ (x <<< 24)
	MOVOU y, z;                         \
	PSLLL $2, z;                        \
	PSRLL $30, y;                       \
	POR z, y;                           \ // y = (x <<< 2) ^ (x <<< 10) ^ (x <<< 18)
	PXOR y, x

// SM4 single round function, handle 16 bytes data
// t0 ^= tao_l1(t1^t2^t3^xk)
// used R19 as temp 32/64 bits register
// parameters:
// - index: round key index immediate number
// - RK: round key register
// - IND: round key index base register
// -  x: 128 bits temp register
// -  y: 128 bits temp register
// -  z: 128 bits temp register
// - t0: 128 bits register for data as result
// - t1: 128 bits register for data
// - t2: 128 bits register for data
// - t3: 128 bits register for data
#define SM4_SINGLE_ROUND(index, RK, IND, x, y, z, t0, t1, t2, t3)  \ 
	MOVL (index * 4)(RK)(IND*1), x;                   \
	PXOR t1, x;                                       \
	PXOR t2, x;                                       \
	PXOR t3, x;                                       \
	SM4_TAO_L1(x, y, z);                              \
	PXOR x, t0

// SM4 round function, handle 64 bytes data
// t0 ^= tao_l1(t1^t2^t3^xk)
// parameters:
// - index: round key index immediate number
// - RK: round key register
// - IND: round key index base register
// -  x: 128 bits temp register
// -  y: 128 bits temp register
// -  z: 128 bits temp register
// - t0: 128 bits register for data as result
// - t1: 128 bits register for data
// - t2: 128 bits register for data
// - t3: 128 bits register for data
#define SM4_ROUND(index, RK, IND, x, y, z, t0, t1, t2, t3)  \ 
	MOVL (index * 4)(RK)(IND*1), x;                 \
	PSHUFD $0, x, x;                                \
	PXOR t1, x;                                     \
	PXOR t2, x;                                     \
	PXOR t3, x;                                     \
	SM4_TAO_L1(x, y, z);                            \
	PXOR x, t0

#define SM4_ONE_ROUND_SSE(x, y, z, t0, t1, t2, t3)  \
	PXOR t1, x;                                     \
	PXOR t2, x;                                     \
	PXOR t3, x;                                     \
	SM4_TAO_L1(x, y, z);                            \
	PXOR x, t0                                      \

#define SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3) \
	PSHUFD $0, rk128, x;                                   \
	SM4_ONE_ROUND_SSE(x, y, z, t0, t1, t2, t3);            \
	PSHUFD $0x55, rk128, x;                                \
	SM4_ONE_ROUND_SSE(x, y, z, t1, t2, t3, t0);            \
	PSHUFD $0xAA, rk128, x;                                \
	SM4_ONE_ROUND_SSE(x, y, z, t2, t3, t0, t1);            \
	PSHUFD $0xFF, rk128, x;                                \
	SM4_ONE_ROUND_SSE(x, y, z, t3, t0, t1, t2);            \

// Requires: SSSE3
#define SM4_SINGLE_BLOCK(RK, rk128, x, y, z, t0, t1, t2, t3) \
	PSHUFB flip_mask<>(SB), t0;                            \
	PSHUFD $1, t0, t1;                                     \
	PSHUFD $2, t0, t2;                                     \
	PSHUFD $3, t0, t3;                                     \
	MOVOU (0*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	MOVOU (1*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	MOVOU (2*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	MOVOU (3*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	MOVOU (4*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	MOVOU (5*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	MOVOU (6*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	MOVOU (7*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	PALIGNR $4, t3, t3;                                    \
	PALIGNR $4, t3, t2;                                    \
	PALIGNR $4, t2, t1;                                    \
	PALIGNR $4, t1, t0;                                    \
	PSHUFB flip_mask<>(SB), t0

#define SM4_4BLOCKS(RK, rk128, x, y, z, t0, t1, t2, t3)  \ 
	PSHUFB flip_mask<>(SB), t0; \
	PSHUFB flip_mask<>(SB), t1; \
	PSHUFB flip_mask<>(SB), t2; \
	PSHUFB flip_mask<>(SB), t3; \
	SM4_4BLOCKS_WO_BS(RK, rk128, x, y, z, t0, t1, t2, t3)

#define SM4_4BLOCKS_WO_BS(RK, rk128, x, y, z, t0, t1, t2, t3)  \ 
	SSE_TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y);            \
	MOVOU (0*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	MOVOU (1*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	MOVOU (2*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	MOVOU (3*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	MOVOU (4*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	MOVOU (5*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	MOVOU (6*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	MOVOU (7*16)(RK), rk128;                               \
	SM4_4BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3);   \
	SSE_TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y);          \
	PSHUFB bswap_mask<>(SB), t3; \
	PSHUFB bswap_mask<>(SB), t2; \
	PSHUFB bswap_mask<>(SB), t1; \
	PSHUFB bswap_mask<>(SB), t0

#define SM4_8BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7) \
	PSHUFD $0, rk128, x;                                   \
	SM4_ONE_ROUND_SSE(x, y, z, t0, t1, t2, t3);            \
	PSHUFD $0, rk128, x;                                   \
	SM4_ONE_ROUND_SSE(x, y, z, t4, t5, t6, t7);            \
	PSHUFD $0x55, rk128, x;                                \
	SM4_ONE_ROUND_SSE(x, y, z, t1, t2, t3, t0);            \
	PSHUFD $0x55, rk128, x;                                \
	SM4_ONE_ROUND_SSE(x, y, z, t5, t6, t7, t4);            \
	PSHUFD $0xAA, rk128, x;                                \
	SM4_ONE_ROUND_SSE(x, y, z, t2, t3, t0, t1);            \
	PSHUFD $0xAA, rk128, x;                                \
	SM4_ONE_ROUND_SSE(x, y, z, t6, t7, t4, t5);            \
	PSHUFD $0xFF, rk128, x;                                \
	SM4_ONE_ROUND_SSE(x, y, z, t3, t0, t1, t2);            \
	PSHUFD $0xFF, rk128, x;                                \
	SM4_ONE_ROUND_SSE(x, y, z, t7, t4, t5, t6);            \

#define SM4_8BLOCKS(RK, rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7)  \ 
	PSHUFB flip_mask<>(SB), t0; \
	PSHUFB flip_mask<>(SB), t1; \
	PSHUFB flip_mask<>(SB), t2; \
	PSHUFB flip_mask<>(SB), t3; \
	PSHUFB flip_mask<>(SB), t4; \
	PSHUFB flip_mask<>(SB), t5; \
	PSHUFB flip_mask<>(SB), t6; \
	PSHUFB flip_mask<>(SB), t7; \	
	SM4_8BLOCKS_WO_BS(RK, rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7)

#define SM4_8BLOCKS_WO_BS(RK, rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7)  \ 
	SSE_TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y);          \
	SSE_TRANSPOSE_MATRIX(t4, t5, t6, t7, x, y);          \
	MOVOU (0*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \
	MOVOU (1*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \
	MOVOU (2*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \
	MOVOU (3*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \
	MOVOU (4*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \
	MOVOU (5*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \
	MOVOU (6*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \
	MOVOU (7*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \
	SSE_TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y);            \
	SSE_TRANSPOSE_MATRIX(t4, t5, t6, t7, x, y);            \
	PSHUFB bswap_mask<>(SB), t3; \
	PSHUFB bswap_mask<>(SB), t2; \
	PSHUFB bswap_mask<>(SB), t1; \
	PSHUFB bswap_mask<>(SB), t0; \
	PSHUFB bswap_mask<>(SB), t7; \
	PSHUFB bswap_mask<>(SB), t6; \
	PSHUFB bswap_mask<>(SB), t5; \
	PSHUFB bswap_mask<>(SB), t4

// SM4 sbox function, AVX version
// parameters:
// -  x: 128 bits register as sbox input/output data
// -  y: 128 bits temp register
// - tmp: 128 bits temp register
#define AVX_SM4_SBOX(x, y, tmp) \
	VPAND nibble_mask<>(SB), x, tmp;                   \
	VMOVDQU m1_low<>(SB), y;                           \
	VPSHUFB tmp, y, y;                                 \
	VPSRLQ $4, x, x;                                   \
	VPAND nibble_mask<>(SB), x, x;                     \
	VMOVDQU m1_high<>(SB), tmp;                        \
	VPSHUFB x, tmp, x;                                 \
	VPXOR y, x, x;                                     \
	VPSHUFB inverse_shift_rows<>(SB), x, x;            \
	VAESENCLAST nibble_mask<>(SB), x, x;               \
	VPANDN nibble_mask<>(SB), x, tmp;                  \
	VMOVDQU m2_low<>(SB), y;                           \
	VPSHUFB tmp, y, y;                                 \
	VPSRLQ $4, x, x;                                   \
	VPAND nibble_mask<>(SB), x, x;                     \
	VMOVDQU m2_high<>(SB), tmp;                        \
	VPSHUFB x, tmp, x;                                 \
	VPXOR y, x, x

// SM4 TAO L1 function, AVX version
// parameters:
// -  x: 128 bits register as sbox input/output data
// -  y: 128 bits temp register
// - tmp: 128 bits temp register
#define AVX_SM4_TAO_L1(x, y, tmp) \
	AVX_SM4_SBOX(x, y, tmp);   \
	VPSHUFB r08_mask<>(SB), x, y;           \ // y = x <<< 8
	VPSHUFB r08_mask<>(SB), y, tmp;         \ // tmp = x <<< 16
	VPXOR x, y, y;                          \ // y = x ^ (x <<< 8)
	VPXOR tmp, y, y;                        \ // y = x ^ (x <<< 8) ^ (x <<< 16)
	VPSHUFB r08_mask<>(SB), tmp, tmp;       \ // tmp = x <<< 24
	VPXOR x, tmp, x;                        \ // x = x ^ (x <<< 24)
	VPSLLD $2, y, tmp;                      \
	VPSRLD $30, y, y;                       \
	VPOR tmp, y, y;                         \ // y = (x <<< 2) ^ (x <<< 10) ^ (x <<< 18)
	VPXOR y, x, x

// transpose matrix function, AVX/AVX2 version
// parameters:
// - r0: 128/256 bits register as input/output data
// - r1: 128/256 bits register as input/output data
// - r2: 128/256 bits register as input/output data
// - r3: 128/256 bits register as input/output data
// - tmp1: 128/256 bits temp register
// - tmp2: 128/256 bits temp register
#define TRANSPOSE_MATRIX(r0, r1, r2, r3, tmp1, tmp2) \
	VPUNPCKHDQ r1, r0, tmp2;                 \ // tmp2 =  [w15, w7, w14, w6, w11, w3, w10, w2]          tmp2 = [w7, w3, w6, w2]
	VPUNPCKLDQ r1, r0, r0;                   \ // r0 =    [w13, w5, w12, w4, w9, w1, w8, w0]              r0 = [w5, w1, w4, w0]
	VPUNPCKLDQ r3, r2, tmp1;                 \ // tmp1 =  [w29, w21, w28, w20, w25, w17, w24, w16]      tmp1 = [w13, w9, w12, w8]
	VPUNPCKHDQ r3, r2, r2;                   \ // r2 =    [w31, w27, w30, w22, w27, w19, w26, w18]        r2 = [w15, w11, w14, w10] 
	VPUNPCKHQDQ tmp1, r0, r1;                \ // r1 =    [w29, w21, w13, w5, w25, w17, w9, w1]           r1 = [w13, w9, w5, w1]
	VPUNPCKLQDQ tmp1, r0, r0;                \ // r0 =    [w28, w20, w12, w4, w24, w16, w8, w0]           r0 = [w12, w8, w4, w0]
	VPUNPCKHQDQ r2, tmp2, r3;                \ // r3 =    [w31, w27, w15, w7, w27, w19, w11, w3]          r3 = [w15, w11, w7, w3]
	VPUNPCKLQDQ r2, tmp2, r2                   // r2 =    [w30, w22, w14, w6, w26, w18, w10, w2]          r2 = [w14, w10, w6, w2]

// SM4 round function, AVX version, handle 128 bits
// t0 ^= tao_l1(t1^t2^t3^xk)
// parameters:
// - index: round key index immediate number
// - x: 128 bits temp register
// - y: 128 bits temp register
// - t0: 128 bits register for data as result
// - t1: 128 bits register for data
// - t2: 128 bits register for data
// - t3: 128 bits register for data
#define AVX_SM4_ROUND(index, RK, IND, x, y, tmp, t0, t1, t2, t3)  \ 
	MOVL (index * 4)(RK)(IND*1), x;                    \
	VPSHUFD $0, x, x;                                  \
	VPXOR t1, x, x;                                    \
	VPXOR t2, x, x;                                    \
	VPXOR t3, x, x;                                    \
	AVX_SM4_TAO_L1(x, y, tmp);                         \  
	VPXOR x, t0, t0


#define SM4_ONE_ROUND_AVX(x, y, z, t0, t1, t2, t3)  \
	VPXOR t1, x, x;                                    \
	VPXOR t2, x, x;                                    \
	VPXOR t3, x, x;                                    \
	AVX_SM4_TAO_L1(x, y, z);                           \
	VPXOR x, t0, t0                                    \

#define SM4_4BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3) \
	VPSHUFD $0, rk128, x;                                   \
	SM4_ONE_ROUND_AVX(x, y, z, t0, t1, t2, t3);             \
	VPSHUFD $0x55, rk128, x;                                \
	SM4_ONE_ROUND_AVX(x, y, z, t1, t2, t3, t0);             \
	VPSHUFD $0xAA, rk128, x;                                \
	SM4_ONE_ROUND_AVX(x, y, z, t2, t3, t0, t1);             \
	VPSHUFD $0xFF, rk128, x;                                \
	SM4_ONE_ROUND_AVX(x, y, z, t3, t0, t1, t2);             \

#define AVX_SM4_4BLOCKS(RK, rk128, x, y, z, t0, t1, t2, t3) \
	VPSHUFB flip_mask<>(SB), t0, t0                              \
	VPSHUFB flip_mask<>(SB), t1, t1                              \  
	VPSHUFB flip_mask<>(SB), t2, t2                              \
	VPSHUFB flip_mask<>(SB), t3, t3                              \
	;                                              \
	AVX_SM4_4BLOCKS_WO_BS(RK, rk128, x, y, z, t0, t1, t2, t3)

#define AVX_SM4_4BLOCKS_WO_BS(RK, rk128, x, y, z, t0, t1, t2, t3) \
	TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y)         \
	VMOVDQU (0*16)(RK), rk128;                                 \
	SM4_4BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3);   \
	VMOVDQU (1*16)(RK), rk128;                                 \
	SM4_4BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3);   \
	VMOVDQU (2*16)(RK), rk128;                                 \
	SM4_4BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3);   \
	VMOVDQU (3*16)(RK), rk128;                                 \
	SM4_4BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3);   \
	VMOVDQU (4*16)(RK), rk128;                                 \
	SM4_4BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3);   \
	VMOVDQU (5*16)(RK), rk128;                                 \
	SM4_4BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3);   \
	VMOVDQU (6*16)(RK), rk128;                                 \
	SM4_4BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3);   \
	VMOVDQU (7*16)(RK), rk128;                                 \
	SM4_4BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3);   \
	; \ // Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y)                     \
	VPSHUFB bswap_mask<>(SB), t0, t0                           \
	VPSHUFB bswap_mask<>(SB), t1, t1                           \
	VPSHUFB bswap_mask<>(SB), t2, t2                           \
	VPSHUFB bswap_mask<>(SB), t3, t3                           \

#define SM4_8BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7) \
	VPSHUFD $0, rk128, x;                                   \
	SM4_ONE_ROUND_AVX(x, y, z, t0, t1, t2, t3);             \
	VPSHUFD $0, rk128, x;                                   \
	SM4_ONE_ROUND_AVX(x, y, z, t4, t5, t6, t7);             \
	VPSHUFD $0x55, rk128, x;                                \
	SM4_ONE_ROUND_AVX(x, y, z, t1, t2, t3, t0);             \
	VPSHUFD $0x55, rk128, x;                                \
	SM4_ONE_ROUND_AVX(x, y, z, t5, t6, t7, t4);             \
	VPSHUFD $0xAA, rk128, x;                                \
	SM4_ONE_ROUND_AVX(x, y, z, t2, t3, t0, t1);             \
	VPSHUFD $0xAA, rk128, x;                                \
	SM4_ONE_ROUND_AVX(x, y, z, t6, t7, t4, t5);             \
	VPSHUFD $0xFF, rk128, x;                                \
	SM4_ONE_ROUND_AVX(x, y, z, t3, t0, t1, t2);             \
	VPSHUFD $0xFF, rk128, x;                                \
	SM4_ONE_ROUND_AVX(x, y, z, t7, t4, t5, t6);             \

#define AVX_SM4_8BLOCKS(RK, rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7) \
	VPSHUFB flip_mask<>(SB), t0, t0                              \
	VPSHUFB flip_mask<>(SB), t1, t1                              \
	VPSHUFB flip_mask<>(SB), t2, t2                              \
	VPSHUFB flip_mask<>(SB), t3, t3                              \
	VPSHUFB flip_mask<>(SB), t4, t4                              \
	VPSHUFB flip_mask<>(SB), t5, t5                              \
	VPSHUFB flip_mask<>(SB), t6, t6                              \
	VPSHUFB flip_mask<>(SB), t7, t7                              \	
	;                                              \
	AVX_SM4_8BLOCKS_WO_BS(RK, rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7)

#define AVX_SM4_8BLOCKS_WO_BS(RK, rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7) \
	TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y)         \
	TRANSPOSE_MATRIX(t4, t5, t6, t7, x, y)         \
	VMOVDQU (0*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \
	VMOVDQU (1*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \
	VMOVDQU (2*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \
	VMOVDQU (3*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \
	VMOVDQU (4*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \
	VMOVDQU (5*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \
	VMOVDQU (6*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \
	VMOVDQU (7*16)(RK), rk128;                               \
	SM4_8BLOCKS_4ROUNDS_AVX(rk128, x, y, z, t0, t1, t2, t3, t4, t5, t6, t7);                                   \		
	; \ // Transpose matrix 4 x 4 32bits word
	TRANSPOSE_MATRIX(t0, t1, t2, t3, x, y)                        \
	TRANSPOSE_MATRIX(t4, t5, t6, t7, x, y)                        \
	VPSHUFB bswap_mask<>(SB), t0, t0                                         \
	VPSHUFB bswap_mask<>(SB), t1, t1                                         \
	VPSHUFB bswap_mask<>(SB), t2, t2                                         \
	VPSHUFB bswap_mask<>(SB), t3, t3                                         \
	VPSHUFB bswap_mask<>(SB), t4, t4                                         \
	VPSHUFB bswap_mask<>(SB), t5, t5                                         \
	VPSHUFB bswap_mask<>(SB), t6, t6                                         \
	VPSHUFB bswap_mask<>(SB), t7, t7                                         \

// SM4 sbox function, AVX2 version
// parameters:
// -  x: 256 bits register as sbox input/output data
// -  y: 256 bits temp register
// -  z: 256 bits temp register
// - xw: 128 bits temp register
// - yw: 128 bits temp register
// - xNibbleMask: 128 bits register stored nibble mask, should be loaded earlier.
// - yNibbleMask: 256 bits register stored nibble mask, should be loaded earlier.
#define AVX2_SM4_SBOX(x, y, z, xw, yw, xNibbleMask, yNibbleMask) \
	VPAND yNibbleMask, x, z;                       \
	VBROADCASTI128 m1_low<>(SB), y;                \
	VPSHUFB z, y, y;                               \
	VPSRLQ $4, x, x;                               \
	VPAND yNibbleMask, x, x;                       \
	VBROADCASTI128 m1_high<>(SB), z;               \
	VPSHUFB x, z, x;                               \
	VPXOR y, x, x;                                 \
	VPSHUFB inverse_shift_rows256<>(SB), x, x;     \
	VEXTRACTI128 $1, x, yw                         \
	VAESENCLAST xNibbleMask, xw, xw;               \
	VAESENCLAST xNibbleMask, yw, yw;               \
	VINSERTI128 $1, yw, x, x;                      \
	VPANDN yNibbleMask, x, z;                      \
	VBROADCASTI128 m2_low<>(SB), y;                \
	VPSHUFB z, y, y;                               \
	VPSRLQ $4, x, x;                               \
	VPAND yNibbleMask, x, x;                       \
	VBROADCASTI128 m2_high<>(SB), z;               \
	VPSHUFB x, z, x;                               \
	VPXOR y, x, x

// SM4 TAO L1 function, AVX2 version
// parameters:
// -  x: 256 bits register as sbox input/output data
// -  y: 256 bits temp register
// -  z: 256 bits temp register
// - xw: 128 bits temp register, x's related low 128 bits register!
// - yw: 128 bits temp register, y's related low 128 bits register!
// - xNibbleMask: 128 bits register stored nibble mask, should be loaded earlier.
// - yNibbleMask: 256 bits register stored nibble mask, should be loaded earlier.
#define AVX2_SM4_TAO_L1(x, y, z, xw, yw, xNibbleMask, yNibbleMask) \
	AVX2_SM4_SBOX(x, y, z, xw, yw, xNibbleMask, yNibbleMask);      \
	VPSHUFB r08_mask256<>(SB), x, y;         \ // y = x <<< 8
	VPSHUFB r08_mask256<>(SB), y, z;         \ // z = x <<< 16
	VPXOR x, y, y;                           \ // y = x ^ (x <<< 8)
	VPXOR z, y, y;                           \ // y = x ^ (x <<< 8) ^ (x <<< 16)
	VPSHUFB r08_mask256<>(SB), z, z;         \ // z = x <<< 24
	VPXOR x, z, x;                           \ // x = x ^ (x <<< 24)
	VPSLLD $2, y, z;                         \
	VPSRLD $30, y, y;                        \
	VPOR z, y, y;                            \ // y = (x <<< 2) ^ (x <<< 10) ^ (x <<< 18)
	VPXOR y, x, x

// SM4 round function, AVX2 version, handle 256 bits
// t0 ^= tao_l1(t1^t2^t3^xk)
// parameters:
// - index: round key index immediate number
// - x: 256 bits temp register, MUST use XDWORD!
// - y: 256 bits temp register, MUST use YDWORD!
// - t0: 256 bits register for data as result
// - t1: 256 bits register for data
// - t2: 256 bits register for data
// - t3: 256 bits register for data
#define AVX2_SM4_ROUND(index, RK, IND, x, y, xw, yw, tmp, t0, t1, t2, t3)  \ 
	VPBROADCASTD (index * 4)(RK)(IND*1), x;                                  \
	VPXOR t1, x, x;                                                          \
	VPXOR t2, x, x;                                                          \
	VPXOR t3, x, x;                                                          \
	AVX2_SM4_TAO_L1(x, y, tmp, xw, yw, X_NIBBLE_MASK, NIBBLE_MASK);          \  
	VPXOR x, t0, t0

// SM4 round function, AVX2 version, handle 256 bits
// t0 ^= tao_l1(t1^t2^t3^xk)
// parameters:
// - index: round key index immediate number
// - x: 256 bits temp register, MUST use XDWORD!
// - y: 256 bits temp register, MUST use YDWORD!
// - t0: 256 bits register for data as result
// - t1: 256 bits register for data
// - t2: 256 bits register for data
// - t3: 256 bits register for data
#define AVX2_SM4_ROUND2(index, RK, x, y, xw, yw, tmp, t0, t1, t2, t3)  \ 
	VPBROADCASTD (index * 4)(RK), x;                                  \
	VPXOR t1, x, x;                                                          \
	VPXOR t2, x, x;                                                          \
	VPXOR t3, x, x;                                                          \
	AVX2_SM4_TAO_L1(x, y, tmp, xw, yw, X_NIBBLE_MASK, NIBBLE_MASK);          \  
	VPXOR x, t0, t0

// SM4 round function, AVX version, handle 128 bits
// t0 ^= tao_l1(t1^t2^t3^xk)
// parameters:
// - index: round key index immediate number
// - x: 128 bits temp register
// - y: 128 bits temp register
// - t0: 128 bits register for data as result
// - t1: 128 bits register for data
// - t2: 128 bits register for data
// - t3: 128 bits register for data
#define AVX2_SM4_ROUND_4BLOCKS(index, RK, IND, x, y, tmp, t0, t1, t2, t3)  \ 
	VPBROADCASTD (index * 4)(RK)(IND*1), x;            \
	VPXOR t1, x, x;                                    \
	VPXOR t2, x, x;                                    \
	VPXOR t3, x, x;                                    \
	AVX_SM4_TAO_L1(x, y, tmp);                         \  
	VPXOR x, t0, t0

#define AVX2_SM4_8BLOCKS(RK, x, y, xw, yw, tmp, t0, t1, t2, t3)	\
	AVX2_SM4_ROUND2(0, RK, x, y, xw, yw, tmp, t0, t1, t2, t3); \
	AVX2_SM4_ROUND2(1, RK, x, y, xw, yw, tmp, t1, t2, t3, t0); \
	AVX2_SM4_ROUND2(2, RK, x, y, xw, yw, tmp, t2, t3, t0, t1); \
	AVX2_SM4_ROUND2(3, RK, x, y, xw, yw, tmp, t3, t0, t1, t2); \
	AVX2_SM4_ROUND2(4, RK, x, y, xw, yw, tmp, t0, t1, t2, t3); \
	AVX2_SM4_ROUND2(5, RK, x, y, xw, yw, tmp, t1, t2, t3, t0); \
	AVX2_SM4_ROUND2(6, RK, x, y, xw, yw, tmp, t2, t3, t0, t1); \
	AVX2_SM4_ROUND2(7, RK, x, y, xw, yw, tmp, t3, t0, t1, t2); \
	AVX2_SM4_ROUND2(8, RK, x, y, xw, yw, tmp, t0, t1, t2, t3); \
	AVX2_SM4_ROUND2(9, RK, x, y, xw, yw, tmp, t1, t2, t3, t0); \
	AVX2_SM4_ROUND2(10, RK, x, y, xw, yw, tmp, t2, t3, t0, t1); \
	AVX2_SM4_ROUND2(11, RK, x, y, xw, yw, tmp, t3, t0, t1, t2); \
	AVX2_SM4_ROUND2(12, RK, x, y, xw, yw, tmp, t0, t1, t2, t3); \
	AVX2_SM4_ROUND2(13, RK, x, y, xw, yw, tmp, t1, t2, t3, t0); \
	AVX2_SM4_ROUND2(14, RK, x, y, xw, yw, tmp, t2, t3, t0, t1); \
	AVX2_SM4_ROUND2(15, RK, x, y, xw, yw, tmp, t3, t0, t1, t2); \
	AVX2_SM4_ROUND2(16, RK, x, y, xw, yw, tmp, t0, t1, t2, t3); \
	AVX2_SM4_ROUND2(17, RK, x, y, xw, yw, tmp, t1, t2, t3, t0); \
	AVX2_SM4_ROUND2(18, RK, x, y, xw, yw, tmp, t2, t3, t0, t1); \
	AVX2_SM4_ROUND2(19, RK, x, y, xw, yw, tmp, t3, t0, t1, t2); \
	AVX2_SM4_ROUND2(20, RK, x, y, xw, yw, tmp, t0, t1, t2, t3); \
	AVX2_SM4_ROUND2(21, RK, x, y, xw, yw, tmp, t1, t2, t3, t0); \
	AVX2_SM4_ROUND2(22, RK, x, y, xw, yw, tmp, t2, t3, t0, t1); \
	AVX2_SM4_ROUND2(23, RK, x, y, xw, yw, tmp, t3, t0, t1, t2); \
	AVX2_SM4_ROUND2(24, RK, x, y, xw, yw, tmp, t0, t1, t2, t3); \
	AVX2_SM4_ROUND2(25, RK, x, y, xw, yw, tmp, t1, t2, t3, t0); \
	AVX2_SM4_ROUND2(26, RK, x, y, xw, yw, tmp, t2, t3, t0, t1); \
	AVX2_SM4_ROUND2(27, RK, x, y, xw, yw, tmp, t3, t0, t1, t2); \
	AVX2_SM4_ROUND2(28, RK, x, y, xw, yw, tmp, t0, t1, t2, t3); \
	AVX2_SM4_ROUND2(29, RK, x, y, xw, yw, tmp, t1, t2, t3, t0); \
	AVX2_SM4_ROUND2(30, RK, x, y, xw, yw, tmp, t2, t3, t0, t1); \
	AVX2_SM4_ROUND2(31, RK, x, y, xw, yw, tmp, t3, t0, t1, t2)

// SM4 round function, AVX2 version, handle 256 bits
// t0 ^= tao_l1(t1^t2^t3^xk)
// parameters:
// - index: round key index immediate number
// - x: 256 bits temp register, MUST use XDWORD!
// - y: 256 bits temp register, MUST use YDWORD!
// - t0: 256 bits register for data as result
// - t1: 256 bits register for data
// - t2: 256 bits register for data
// - t3: 256 bits register for data
#define AVX2_SM4_16BLOCKS_ROUND(index, RK, x, y, xw, yw, tmp, tmp1, t0, t1, t2, t3, t4, t5, t6, t7)  \ 
	VPBROADCASTD (index * 4)(RK), tmp1;                                         \
	VPXOR t1, tmp1, x;                                                          \
	VPXOR t2, x, x;                                                             \
	VPXOR t3, x, x;                                                             \
	AVX2_SM4_TAO_L1(x, y, tmp, xw, yw, X_NIBBLE_MASK, NIBBLE_MASK);             \  
	VPXOR x, t0, t0;                                                            \
	;\
	VPXOR t5, tmp1, x;                                                          \
	VPXOR t6, x, x;                                                             \
	VPXOR t7, x, x;                                                             \
	AVX2_SM4_TAO_L1(x, y, tmp, xw, yw, X_NIBBLE_MASK, NIBBLE_MASK);             \  
	VPXOR x, t4, t4;                                                            \

#define AVX2_SM4_16BLOCKS(RK, x, y, xw, yw, tmp, tmp1, t0, t1, t2, t3, t4, t5, t6, t7)	\
	AVX2_SM4_16BLOCKS_ROUND(0, RK, x, y, xw, yw, tmp, tmp1, t0, t1, t2, t3, t4, t5, t6, t7); \
	AVX2_SM4_16BLOCKS_ROUND(1, RK, x, y, xw, yw, tmp, tmp1, t1, t2, t3, t0, t5, t6, t7, t4); \
	AVX2_SM4_16BLOCKS_ROUND(2, RK, x, y, xw, yw, tmp, tmp1, t2, t3, t0, t1, t6, t7, t4, t5); \
	AVX2_SM4_16BLOCKS_ROUND(3, RK, x, y, xw, yw, tmp, tmp1, t3, t0, t1, t2, t7, t4, t5, t6); \
	AVX2_SM4_16BLOCKS_ROUND(4, RK, x, y, xw, yw, tmp, tmp1, t0, t1, t2, t3, t4, t5, t6, t7); \
	AVX2_SM4_16BLOCKS_ROUND(5, RK, x, y, xw, yw, tmp, tmp1, t1, t2, t3, t0, t5, t6, t7, t4); \
	AVX2_SM4_16BLOCKS_ROUND(6, RK, x, y, xw, yw, tmp, tmp1, t2, t3, t0, t1, t6, t7, t4, t5); \
	AVX2_SM4_16BLOCKS_ROUND(7, RK, x, y, xw, yw, tmp, tmp1, t3, t0, t1, t2, t7, t4, t5, t6); \
	AVX2_SM4_16BLOCKS_ROUND(8, RK, x, y, xw, yw, tmp, tmp1, t0, t1, t2, t3, t4, t5, t6, t7); \
	AVX2_SM4_16BLOCKS_ROUND(9, RK, x, y, xw, yw, tmp, tmp1, t1, t2, t3, t0, t5, t6, t7, t4); \
	AVX2_SM4_16BLOCKS_ROUND(10, RK, x, y, xw, yw, tmp, tmp1, t2, t3, t0, t1, t6, t7, t4, t5); \
	AVX2_SM4_16BLOCKS_ROUND(11, RK, x, y, xw, yw, tmp, tmp1, t3, t0, t1, t2, t7, t4, t5, t6); \
	AVX2_SM4_16BLOCKS_ROUND(12, RK, x, y, xw, yw, tmp, tmp1, t0, t1, t2, t3, t4, t5, t6, t7); \
	AVX2_SM4_16BLOCKS_ROUND(13, RK, x, y, xw, yw, tmp, tmp1, t1, t2, t3, t0, t5, t6, t7, t4); \
	AVX2_SM4_16BLOCKS_ROUND(14, RK, x, y, xw, yw, tmp, tmp1, t2, t3, t0, t1, t6, t7, t4, t5); \
	AVX2_SM4_16BLOCKS_ROUND(15, RK, x, y, xw, yw, tmp, tmp1, t3, t0, t1, t2, t7, t4, t5, t6); \
	AVX2_SM4_16BLOCKS_ROUND(16, RK, x, y, xw, yw, tmp, tmp1, t0, t1, t2, t3, t4, t5, t6, t7); \
	AVX2_SM4_16BLOCKS_ROUND(17, RK, x, y, xw, yw, tmp, tmp1, t1, t2, t3, t0, t5, t6, t7, t4); \
	AVX2_SM4_16BLOCKS_ROUND(18, RK, x, y, xw, yw, tmp, tmp1, t2, t3, t0, t1, t6, t7, t4, t5); \
	AVX2_SM4_16BLOCKS_ROUND(19, RK, x, y, xw, yw, tmp, tmp1, t3, t0, t1, t2, t7, t4, t5, t6); \
	AVX2_SM4_16BLOCKS_ROUND(20, RK, x, y, xw, yw, tmp, tmp1, t0, t1, t2, t3, t4, t5, t6, t7); \
	AVX2_SM4_16BLOCKS_ROUND(21, RK, x, y, xw, yw, tmp, tmp1, t1, t2, t3, t0, t5, t6, t7, t4); \
	AVX2_SM4_16BLOCKS_ROUND(22, RK, x, y, xw, yw, tmp, tmp1, t2, t3, t0, t1, t6, t7, t4, t5); \
	AVX2_SM4_16BLOCKS_ROUND(23, RK, x, y, xw, yw, tmp, tmp1, t3, t0, t1, t2, t7, t4, t5, t6); \
	AVX2_SM4_16BLOCKS_ROUND(24, RK, x, y, xw, yw, tmp, tmp1, t0, t1, t2, t3, t4, t5, t6, t7); \
	AVX2_SM4_16BLOCKS_ROUND(25, RK, x, y, xw, yw, tmp, tmp1, t1, t2, t3, t0, t5, t6, t7, t4); \
	AVX2_SM4_16BLOCKS_ROUND(26, RK, x, y, xw, yw, tmp, tmp1, t2, t3, t0, t1, t6, t7, t4, t5); \
	AVX2_SM4_16BLOCKS_ROUND(27, RK, x, y, xw, yw, tmp, tmp1, t3, t0, t1, t2, t7, t4, t5, t6); \
	AVX2_SM4_16BLOCKS_ROUND(28, RK, x, y, xw, yw, tmp, tmp1, t0, t1, t2, t3, t4, t5, t6, t7); \
	AVX2_SM4_16BLOCKS_ROUND(29, RK, x, y, xw, yw, tmp, tmp1, t1, t2, t3, t0, t5, t6, t7, t4); \
	AVX2_SM4_16BLOCKS_ROUND(30, RK, x, y, xw, yw, tmp, tmp1, t2, t3, t0, t1, t6, t7, t4, t5); \
	AVX2_SM4_16BLOCKS_ROUND(31, RK, x, y, xw, yw, tmp, tmp1, t3, t0, t1, t2, t7, t4, t5, t6)
