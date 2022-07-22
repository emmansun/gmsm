// shuffle byte order from LE to BE
DATA flip_mask<>+0x00(SB)/8, $0x0405060700010203
DATA flip_mask<>+0x08(SB)/8, $0x0c0d0e0f08090a0b
GLOBL flip_mask<>(SB), RODATA, $16

// shuffle byte and word order
DATA bswap_mask<>+0x00(SB)/8, $0x08090a0b0c0d0e0f
DATA bswap_mask<>+0x08(SB)/8, $0x0001020304050607
GLOBL bswap_mask<>(SB), RODATA, $16

//nibble mask
DATA nibble_mask<>+0x00(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA nibble_mask<>+0x08(SB)/8, $0x0F0F0F0F0F0F0F0F
GLOBL nibble_mask<>(SB), RODATA, $16

// inverse shift rows
DATA inverse_shift_rows<>+0x00(SB)/8, $0x0B0E0104070A0D00
DATA inverse_shift_rows<>+0x08(SB)/8, $0x0306090C0F020508 
GLOBL inverse_shift_rows<>(SB), RODATA, $16

// Affine transform 1 (low and high hibbles)
DATA m1_low<>+0x00(SB)/8, $0x0A7FC3B6D5A01C69
DATA m1_low<>+0x08(SB)/8, $0x3045F98CEF9A2653
GLOBL m1_low<>(SB), RODATA, $16

DATA m1_high<>+0x00(SB)/8, $0xC35BF46CAF379800
DATA m1_high<>+0x08(SB)/8, $0x68F05FC7049C33AB  
GLOBL m1_high<>(SB), RODATA, $16

// Affine transform 2 (low and high hibbles)
DATA m2_low<>+0x00(SB)/8, $0x9A950A05FEF16E61
DATA m2_low<>+0x08(SB)/8, $0x0E019E916A65FAF5
GLOBL m2_low<>(SB), RODATA, $16

DATA m2_high<>+0x00(SB)/8, $0x892D69CD44E0A400
DATA m2_high<>+0x08(SB)/8, $0x2C88CC68E14501A5
GLOBL m2_high<>(SB), RODATA, $16

// left rotations of 32-bit words by 8-bit increments
DATA r08_mask<>+0x00(SB)/8, $0x0605040702010003
DATA r08_mask<>+0x08(SB)/8, $0x0E0D0C0F0A09080B  
GLOBL r08_mask<>(SB), RODATA, $16

DATA r16_mask<>+0x00(SB)/8, $0x0504070601000302
DATA r16_mask<>+0x08(SB)/8, $0x0D0C0F0E09080B0A   
GLOBL r16_mask<>(SB), RODATA, $16

DATA r24_mask<>+0x00(SB)/8, $0x0407060500030201
DATA r24_mask<>+0x08(SB)/8, $0x0C0F0E0D080B0A09  
GLOBL r24_mask<>(SB), RODATA, $16

DATA fk_mask<>+0x00(SB)/8, $0x56aa3350a3b1bac6
DATA fk_mask<>+0x08(SB)/8, $0xb27022dc677d9197
GLOBL fk_mask<>(SB), RODATA, $16

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
	PINSRD $3, r, tmp2;  \ // tmp2 = [w7, w3, w6, w2]
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

#define SM4_TAO_L1(x, y, z)         \
	SM4_SBOX(x, y, z);                  \
	;                                   \ //####################  4 parallel L1 linear transforms ##################//
	MOVOU x, y;                         \
	PSHUFB r08_mask<>(SB), y;           \ //y = _mm_shuffle_epi8(x, r08)
	PXOR x, y;                          \ //y = x xor _mm_shuffle_epi8(x, r08)
	MOVOU x, z;                         \
	PSHUFB r16_mask<>(SB), z;           \
	PXOR z, y;                          \ //y = x xor _mm_shuffle_epi8(x, r08) xor _mm_shuffle_epi8(x, r16)
	MOVOU y, z;                         \
	PSLLL $2, z;                        \
	PSRLL $30, y;                       \
	POR z, y;                           \ //y = _mm_slli_epi32(y, 2) ^ _mm_srli_epi32(y, 30);  
	MOVOU x, z;                         \
	PSHUFB r24_mask<>(SB), z;           \
	PXOR y, x;                          \ //x = x xor y
	PXOR z, x                             //x = x xor y xor _mm_shuffle_epi8(x, r24);

#define AVX_SM4_SBOX(x, y, X_NIBBLE_MASK, tmp) \
	VPAND X_NIBBLE_MASK, x, tmp;                       \
	VMOVDQU m1_low<>(SB), y;                           \
	VPSHUFB tmp, y, y;                                 \
	VPSRLQ $4, x, x;                                   \
	VPAND X_NIBBLE_MASK, x, x;                         \
	VMOVDQU m1_high<>(SB), tmp;                        \
	VPSHUFB x, tmp, x;                                 \
	VPXOR y, x, x;                                     \
	VMOVDQU inverse_shift_rows<>(SB), tmp;             \
	VPSHUFB tmp, x, x;                                 \
	VAESENCLAST X_NIBBLE_MASK, x, x;                   \
	VPANDN X_NIBBLE_MASK, x, tmp;                      \
	VMOVDQU m2_low<>(SB), y;                           \
	VPSHUFB tmp, y, y;                                 \
	VPSRLQ $4, x, x;                                   \
	VPAND X_NIBBLE_MASK, x, x;                         \
	VMOVDQU m2_high<>(SB), tmp;                        \
	VPSHUFB x, tmp, x;                                 \
	VPXOR y, x, x

#define AVX_SM4_TAO_L1(x, y, X_NIBBLE_MASK, tmp) \
	AVX_SM4_SBOX(x, y, X_NIBBLE_MASK, tmp); \
	VMOVDQU r08_mask<>(SB), tmp;            \
	VPSHUFB tmp, x, y;                      \
	VPXOR x, y, y;                          \
	VMOVDQU r16_mask<>(SB), tmp;            \
	VPSHUFB tmp, x, tmp;                    \
	VPXOR tmp, y, y;                        \
	VPSLLD $2, y, tmp;                      \
	VPSRLD $30, y, y;                       \
	VPXOR tmp, y, y;                        \
	VMOVDQU r24_mask<>(SB), tmp;            \
	VPSHUFB tmp, x, tmp;                    \
	VPXOR y, x, x;                          \
	VPXOR x, tmp, x

#define TRANSPOSE_MATRIX(r0, r1, r2, r3, tmp1, tmp2) \
	VPUNPCKHDQ r1, r0, tmp2;                 \ // tmp2 =  [w15, w7, w14, w6, w11, w3, w10, w2]          tmp2 = [w7, w3, w6, w2]
	VPUNPCKLDQ r1, r0, r0;                   \ // r0 =    [w13, w5, w12, w4, w9, w1, w8, w0]              r0 = [w5, w1, w4, w0]
	VPUNPCKLDQ r3, r2, tmp1;                 \ // tmp1 =  [w29, w21, w28, w20, w25, w17, w24, w16]      tmp1 = [w13, w9, w12, w8]
	VPUNPCKHDQ r3, r2, r2;                   \ // r2 =    [w31, w27, w30, w22, w27, w19, w26, w18]        r2 = [w15, w11, w14, w10] 
	VPUNPCKHQDQ tmp1, r0, r1;                \ // r1 =    [w29, w21, w13, w5, w25, w17, w9, w1]           r1 = [w13, w9, w5, w1]
	VPUNPCKLQDQ tmp1, r0, r0;                \ // r0 =    [w28, w20, w12, w4, w24, w16, w8, w0]           r0 = [w12, w8, w4, w0]
	VPUNPCKHQDQ r2, tmp2, r3;                \ // r3 =    [w31, w27, w15, w7, w27, w19, w11, w3]          r3 = [w15, w11, w7, w3]
	VPUNPCKLQDQ r2, tmp2, r2                   // r2 =    [w30, w22, w14, w6, w26, w18, w10, w2]          r2 = [w14, w10, w6, w2]

#define AVX2_SM4_SBOX(x, y, xw, yw, xNibbleMask, yNibbleMask, tmp) \
	VPAND yNibbleMask, x, tmp;                       \
	VBROADCASTI128 m1_low<>(SB), y;                  \
	VPSHUFB tmp, y, y;                               \
	VPSRLQ $4, x, x;                                 \
	VPAND yNibbleMask, x, x;                         \
	VBROADCASTI128 m1_high<>(SB), tmp;               \
	VPSHUFB x, tmp, x;                               \
	VPXOR y, x, x;                                   \
	VBROADCASTI128 inverse_shift_rows<>(SB), tmp;    \
	VPSHUFB tmp, x, x;                               \
	VEXTRACTI128 $1, x, yw                           \
	VAESENCLAST xNibbleMask, xw, xw;                 \
	VAESENCLAST xNibbleMask, yw, yw;                 \
	VINSERTI128 $1, yw, x, x;                        \
	VPANDN yNibbleMask, x, tmp;                      \
	VBROADCASTI128 m2_low<>(SB), y;                  \
	VPSHUFB tmp, y, y;                               \
	VPSRLQ $4, x, x;                                 \
	VPAND yNibbleMask, x, x;                         \
	VBROADCASTI128 m2_high<>(SB), tmp;               \
	VPSHUFB x, tmp, x;                               \
	VPXOR y, x, x

#define AVX2_SM4_TAO_L1(x, y, xw, yw, xNibbleMask, yNibbleMask, tmp) \
	AVX2_SM4_SBOX(x, y, xw, yw, xNibbleMask, yNibbleMask, tmp);      \
	VBROADCASTI128 r08_mask<>(SB), tmp;        \
	VPSHUFB tmp, x, y;                         \
	VPXOR x, y, y;                             \
	VBROADCASTI128 r16_mask<>(SB), tmp;        \
	VPSHUFB tmp, x, tmp;                       \
	VPXOR tmp, y, y;                           \
	VPSLLD $2, y, tmp;                         \
	VPSRLD $30, y, y;                          \
	VPXOR tmp, y, y;                           \
	VBROADCASTI128 r24_mask<>(SB), tmp;        \
	VPSHUFB tmp, x, tmp;                       \
	VPXOR y, x, x;                             \
	VPXOR x, tmp, x
