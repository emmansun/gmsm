// Referenced Intel(R) Multi-Buffer Crypto for IPsec
// https://github.com/intel/intel-ipsec-mb/
// https://gist.github.com/emmansun/15d2fce6659ab97ffaf7ab66e278caee
//go:build !purego

#include "textflag.h"

DATA Top3_bits_of_the_byte<>+0x00(SB)/8, $0xe0e0e0e0e0e0e0e0
DATA Top3_bits_of_the_byte<>+0x08(SB)/8, $0xe0e0e0e0e0e0e0e0
GLOBL Top3_bits_of_the_byte<>(SB), RODATA, $16

DATA Bottom5_bits_of_the_byte<>+0x00(SB)/8, $0x1f1f1f1f1f1f1f1f
DATA Bottom5_bits_of_the_byte<>+0x08(SB)/8, $0x1f1f1f1f1f1f1f1f
GLOBL Bottom5_bits_of_the_byte<>(SB), RODATA, $16

DATA Low_nibble_mask<>+0x00(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA Low_nibble_mask<>+0x08(SB)/8, $0x0F0F0F0F0F0F0F0F
GLOBL Low_nibble_mask<>(SB), RODATA, $16

DATA P1<>+0x00(SB)/8, $0x0A020F0F0E000F09
DATA P1<>+0x08(SB)/8, $0x090305070C000400
GLOBL P1<>(SB), RODATA, $16

DATA P2<>+0x00(SB)/8, $0x040C000705060D08
DATA P2<>+0x08(SB)/8, $0x0209030F0A0E010B
GLOBL P2<>(SB), RODATA, $16

DATA P3<>+0x00(SB)/8, $0x0F0A0D00060A0602
DATA P3<>+0x08(SB)/8, $0x0D0C0900050D0303
GLOBL P3<>(SB), RODATA, $16

DATA Aes_to_Zuc_mul_low_nibble<>+0x00(SB)/8, $0x1D1C9F9E83820100
DATA Aes_to_Zuc_mul_low_nibble<>+0x08(SB)/8, $0x3938BBBAA7A62524
GLOBL Aes_to_Zuc_mul_low_nibble<>(SB), RODATA, $16

DATA Aes_to_Zuc_mul_high_nibble<>+0x00(SB)/8, $0xA174A97CDD08D500
DATA Aes_to_Zuc_mul_high_nibble<>+0x08(SB)/8, $0x3DE835E04194499C
GLOBL Aes_to_Zuc_mul_high_nibble<>(SB), RODATA, $16

DATA Comb_matrix_mul_low_nibble<>+0x00(SB)/8, $0xCFDB6571BEAA1400
DATA Comb_matrix_mul_low_nibble<>+0x08(SB)/8, $0x786CD2C6091DA3B7
GLOBL Comb_matrix_mul_low_nibble<>(SB), RODATA, $16

DATA Comb_matrix_mul_high_nibble<>+0x00(SB)/8, $0x638CFA1523CCBA55
DATA Comb_matrix_mul_high_nibble<>+0x08(SB)/8, $0x3FD0A6497F90E609
GLOBL Comb_matrix_mul_high_nibble<>(SB), RODATA, $16

DATA Shuf_mask<>+0x00(SB)/8, $0x0B0E0104070A0D00
DATA Shuf_mask<>+0x08(SB)/8, $0x0306090C0F020508
GLOBL Shuf_mask<>(SB), RODATA, $16

DATA Cancel_aes<>+0x00(SB)/8, $0x6363636363636363
DATA Cancel_aes<>+0x08(SB)/8, $0x6363636363636363
GLOBL Cancel_aes<>(SB), RODATA, $16

DATA CombMatrix<>+0x00(SB)/8, $0x3C1A99B2AD1ED43A
DATA CombMatrix<>+0x08(SB)/8, $0x3C1A99B2AD1ED43A
GLOBL CombMatrix<>(SB), RODATA, $16

DATA mask_S0<>+0x00(SB)/8, $0xff00ff00ff00ff00
DATA mask_S0<>+0x08(SB)/8, $0xff00ff00ff00ff00
GLOBL mask_S0<>(SB), RODATA, $16

DATA mask_S1<>+0x00(SB)/8, $0x00ff00ff00ff00ff
DATA mask_S1<>+0x08(SB)/8, $0x00ff00ff00ff00ff
GLOBL mask_S1<>(SB), RODATA, $16

// shuffle byte order from LE to BE
DATA flip_mask<>+0x00(SB)/8, $0x0405060700010203
DATA flip_mask<>+0x08(SB)/8, $0x0c0d0e0f08090a0b
GLOBL flip_mask<>(SB), RODATA, $16

// ZUC S1 GFNI matrices: S1(x) = m2 · GF_AES_Inv(m1 · x) ⊕ 0x55
// Verified against ZUC S1 table (c1=0, c2=0x55). Use pair #3.
// Source: github.com/emmansun/simd/blob/main/amd64/sse/sse_gfni_test.go
DATA zuc_gfni_s1_m1<>+0x00(SB)/8, $0x95124E5A9E18ACC6
DATA zuc_gfni_s1_m1<>+0x08(SB)/8, $0x95124E5A9E18ACC6
GLOBL zuc_gfni_s1_m1<>(SB), RODATA, $16

DATA zuc_gfni_s1_m2<>+0x00(SB)/8, $0xC305CBCC771ADAF1
DATA zuc_gfni_s1_m2<>+0x08(SB)/8, $0xC305CBCC771ADAF1
GLOBL zuc_gfni_s1_m2<>(SB), RODATA, $16

#define OFFSET_FR1      (16*4)
#define OFFSET_FR2      (17*4)
#define OFFSET_BRC_X0   (18*4)
#define OFFSET_BRC_X1   (19*4)
#define OFFSET_BRC_X2   (20*4)
#define OFFSET_BRC_X3   (21*4)

#define SHLDL(a, b, n) \  // NO SHLDL in GOLANG now
	SHLL n, a          \
	SHRL n, b          \  
	ORL  b, a

// Rotate left 5 bits in each byte, within an XMM register, SSE version.
#define Rotl_5_SSE(XDATA, XTMP0)               \
	MOVOU XDATA, XTMP0                         \
	PSLLL $5, XTMP0                            \
	PSRLL $3, XDATA                            \
	PAND Top3_bits_of_the_byte<>(SB), XTMP0    \
	PAND Bottom5_bits_of_the_byte<>(SB), XDATA \
	POR XTMP0, XDATA

// Compute 16 S0 box values from 16 bytes, SSE version.
#define S0_comput_SSE(IN_OUT, XTMP1, XTMP2)    \
	MOVOU IN_OUT, XTMP1                        \
	\
	PSRLQ $4, XTMP1                            \  // x1
	PAND Low_nibble_mask<>(SB), XTMP1          \ 
	PAND Low_nibble_mask<>(SB), IN_OUT         \  // x2
	\
	MOVOU P1<>(SB), XTMP2                      \
	PSHUFB IN_OUT, XTMP2                       \ // P1[x2]
	PXOR XTMP1, XTMP2                          \ // q = x1 ^ P1[x2], XTMP1 free
	\
	MOVOU P2<>(SB), XTMP1                      \
	PSHUFB XTMP2, XTMP1                        \ // P2[q]
	PXOR IN_OUT, XTMP1                         \ // r = x2 ^ P2[q]; IN_OUT free
	\
	MOVOU P3<>(SB), IN_OUT                     \
	PSHUFB XTMP1, IN_OUT                       \ // P3[r]
	PXOR XTMP2, IN_OUT                         \ // s = q ^ P3[r], XTMP2 free
	\ // s << 4 (since high nibble of each byte is 0, no masking is required)
	PSLLQ $4, IN_OUT                           \
	POR XTMP1, IN_OUT                          \ // t = (s << 4) | r
	Rotl_5_SSE(IN_OUT, XTMP1)

// Perform 8x8 matrix multiplication using lookup tables with partial results
// for high and low nible of each input byte, SSE versiion.
#define MUL_PSHUFB_SSE(XIN, XLO, XHI_OUT, XTMP)        \
	\ // Get low nibble of input data
	MOVOU XIN, XTMP                                    \
	PAND Low_nibble_mask<>(SB), XTMP                   \
	\ // Get low nibble of output
	PSHUFB XTMP, XLO                                   \
	\ // Get high nibble of input data
	PSRLQ $4, XIN                                      \
	PAND Low_nibble_mask<>(SB), XIN                    \
	\ // Get high nibble of output
	PSHUFB XIN, XHI_OUT                                \
	\ // XOR high and low nibbles to get full bytes
	PXOR XLO, XHI_OUT

// Compute 16 S1 box values from 16 bytes, stored in XMM register
#define S1_comput_SSE(XIN_OUT, XTMP1, XTMP2, XTMP3)    \
	MOVOU Aes_to_Zuc_mul_low_nibble<>(SB), XTMP1       \
	MOVOU Aes_to_Zuc_mul_high_nibble<>(SB), XTMP2      \
	MUL_PSHUFB_SSE(XIN_OUT, XTMP1, XTMP2, XTMP3)       \
	\
	PSHUFB Shuf_mask<>(SB), XTMP2                      \
	AESENCLAST Cancel_aes<>(SB), XTMP2                 \
	\
	MOVOU Comb_matrix_mul_low_nibble<>(SB), XTMP1      \
	MOVOU Comb_matrix_mul_high_nibble<>(SB), XIN_OUT   \
	MUL_PSHUFB_SSE(XTMP2, XTMP1, XIN_OUT, XTMP3)

// Rotate left 5 bits in each byte, within an XMM register, AVX version.
#define Rotl_5_AVX(XDATA, XTMP0)                       \
	VPSLLD $5, XDATA, XTMP0                            \
	VPSRLD $3, XDATA, XDATA                            \
	VPAND Top3_bits_of_the_byte<>(SB), XTMP0, XTMP0    \
	VPAND Bottom5_bits_of_the_byte<>(SB), XDATA, XDATA \
	VPOR XTMP0, XDATA, XDATA

// Compute 16 S0 box values from 16 bytes, AVX version.
#define S0_comput_AVX(IN_OUT, XTMP1, XTMP2)      \
	VPSRLQ $4, IN_OUT, XTMP1                     \ // x1
	VPAND Low_nibble_mask<>(SB), XTMP1, XTMP1    \
	VPAND Low_nibble_mask<>(SB), IN_OUT, IN_OUT  \ // x2
	\
	VMOVDQU P1<>(SB), XTMP2                      \
	VPSHUFB IN_OUT, XTMP2, XTMP2                 \ // P1[x2]
	VPXOR XTMP1, XTMP2, XTMP2                    \ // q = x1 ^ P1[x2] ; XTMP1 free
	\
	VMOVDQU P2<>(SB), XTMP1                      \
	VPSHUFB XTMP2, XTMP1, XTMP1                  \ // P2[q]
	VPXOR IN_OUT, XTMP1, XTMP1                   \ // r = x2 ^ P2[q] ; IN_OUT free
	\
	VMOVDQU P3<>(SB), IN_OUT                     \
	VPSHUFB XTMP1, IN_OUT, IN_OUT                \ // P3[r]
	VPXOR XTMP2, IN_OUT, IN_OUT                  \ // s = q ^ P3[r] ; XTMP2 free
	\ // s << 4 (since high nibble of each byte is 0, no masking is required)
	VPSLLQ $4, IN_OUT, IN_OUT                    \
	VPOR XTMP1, IN_OUT, IN_OUT                   \ // t = (s << 4) | r
	Rotl_5_AVX(IN_OUT, XTMP1)

// Perform 8x8 matrix multiplication using lookup tables with partial results
// for high and low nible of each input byte, AVX version.
#define MUL_PSHUFB_AVX(XIN, XLO, XHI_OUT, XTMP)        \
	\ // Get low nibble of input data
	VPAND Low_nibble_mask<>(SB), XIN, XTMP             \
	\ // Get low nibble of output
	VPSHUFB XTMP, XLO, XLO                             \
	\ // Get high nibble of input data
	VPSRLQ $4, XIN, XTMP                               \
	VPAND Low_nibble_mask<>(SB), XTMP, XTMP            \
	\ // Get high nibble of output
	VPSHUFB XTMP, XHI_OUT, XHI_OUT                     \
	\ // XOR high and low nibbles to get full bytes
	VPXOR XLO, XHI_OUT, XHI_OUT

// Compute 16 S1 box values from 16 bytes, stored in XMM register
#define S1_comput_AVX(XIN_OUT, XTMP1, XTMP2, XTMP3)       \
	\ // gf2p8affineqb  XIN_OUT, [rel Aes_to_Zuc], 0x00
	VMOVDQU Aes_to_Zuc_mul_low_nibble<>(SB), XTMP1        \
	VMOVDQU Aes_to_Zuc_mul_high_nibble<>(SB), XTMP2       \
	MUL_PSHUFB_AVX(XIN_OUT, XTMP1, XTMP2, XTMP3)          \
	\
	VPSHUFB Shuf_mask<>(SB), XTMP2, XTMP2                 \
	VAESENCLAST Cancel_aes<>(SB), XTMP2, XTMP2            \
	\ // gf2p8affineqb  XIN_OUT, [rel CombMatrix], 0x55
	VMOVDQU Comb_matrix_mul_low_nibble<>(SB), XTMP1       \
	VMOVDQU Comb_matrix_mul_high_nibble<>(SB), XIN_OUT    \
	MUL_PSHUFB_AVX(XTMP2, XTMP1, XIN_OUT, XTMP3)

// Compute 16 S1 box values from 16 bytes using GFNI (2 instructions).
// XIN_OUT: input/output XMM register
// XTMP1: temporary XMM register (clobbered)
// Equivalent to S1_comput_AVX but uses GF2P8AFFINEQB + GF2P8AFFINEINVQB.
#define S1_comput_GFNI(XIN_OUT, XTMP1) \
	VMOVDQU zuc_gfni_s1_m1<>(SB), XTMP1;              \
	VGF2P8AFFINEQB $0x00, XTMP1, XIN_OUT, XIN_OUT;    \
	VMOVDQU zuc_gfni_s1_m2<>(SB), XTMP1;              \
	VGF2P8AFFINEINVQB $0x55, XTMP1, XIN_OUT, XIN_OUT

#define F_R1 R9
#define F_R2 R10
#define BRC_X0 R11
#define BRC_X1 R12
#define BRC_X2 R13
#define BRC_X3 R14

// Non-Linear function F, GFNI version.
// Same as NONLIN_FUN_AVX but uses GFNI for S1 computation.
#define NONLIN_FUN_GFNI                      \
	NONLIN_FUN                               \
	VMOVQ DX, X0                             \
	VMOVDQA X0, X1                           \ 
	S0_comput_AVX(X1, X2, X3)                \
	S1_comput_GFNI(X0, X2)                   \
	\
	VPAND mask_S1<>(SB), X0, X0              \
	VPAND mask_S0<>(SB), X1, X1              \ 
	VPXOR X1, X0, X0                         \ 
	\
	MOVL X0, F_R1                            \ // F_R1
	VPEXTRD $1, X0, F_R2

#define ROUND_GFNI(idx)            \
	BITS_REORG(idx)               \
	NONLIN_FUN_GFNI               \
	XORL BRC_X3, AX               \
	MOVL AX, (idx*4)(DI)          \
	XORQ AX, AX                   \
	LFSR_UPDT(idx)

#define ROUND_REV32_GFNI(idx)      \
	BITS_REORG(idx)               \
	NONLIN_FUN_GFNI               \
	XORL BRC_X3, AX               \
	BSWAPL AX                     \
	MOVL AX, (idx*4)(DI)          \
	XORQ AX, AX                   \
	LFSR_UPDT(idx)

// BITS_REORG(idx)
//
// params
//      %1 - round number
// uses
//      AX, BX, CX, DX
// return 
//      updates R11, R12, R13, R14
//
#define BITS_REORG(idx)                      \
	MOVL (((15 + idx) % 16)*4)(SI), BRC_X0   \
	MOVL (((14 + idx) % 16)*4)(SI), AX       \
	MOVL (((11 + idx) % 16)*4)(SI), BRC_X1   \
	MOVL (((9 + idx) % 16)*4)(SI), BX        \
	MOVL (((7 + idx) % 16)*4)(SI), BRC_X2    \ 
	MOVL (((5 + idx) % 16)*4)(SI), CX        \
	MOVL (((2 + idx) % 16)*4)(SI), BRC_X3    \
	MOVL (((0 + idx) % 16)*4)(SI), DX        \
	SHRL $15, BRC_X0                         \
	SHLL $16, AX                             \
	SHLL $1, BX                              \
	SHLL $1, CX                              \
	SHLL $1, DX                              \
	SHLDL(BRC_X0, AX, $16)                   \
	SHLDL(BRC_X1, BX, $16)                   \
	SHLDL(BRC_X2, CX, $16)                   \
	SHLDL(BRC_X3, DX, $16)                      

// LFSR_UPDT calculates the next state word and places/overwrites it to lfsr[idx % 16]
// 
// params
//      %1 - round number
// uses
//      AX as input (ZERO or W), BX, CX, DX, R8
#define LFSR_UPDT(idx)                       \
	MOVL (((0 + idx) % 16)*4)(SI), BX        \
	MOVL (((4 + idx) % 16)*4)(SI), CX        \
	MOVL (((10 + idx) % 16)*4)(SI), DX       \
	MOVL (((13 + idx) % 16)*4)(SI), R8       \
	\ // Calculate 64-bit LFSR feedback
	ADDQ BX, AX                              \
	SHLQ $8, BX                              \
	SHLQ $20, CX                             \
	SHLQ $21, DX                             \
	SHLQ $17, R8                             \
	ADDQ BX, AX                              \
	ADDQ CX, AX                              \
	ADDQ DX, AX                              \
	ADDQ R8, AX                              \
	MOVL (((15 + idx) % 16)*4)(SI), R8       \
	SHLQ $15, R8                             \
	ADDQ R8, AX                              \
	\ // Reduce it to 31-bit value
	MOVQ AX, BX                              \
	ANDQ $0x7FFFFFFF, AX                     \
	SHRQ $31, BX                             \
	ADDQ BX, AX                              \
	\
	MOVQ AX, BX                              \
	SUBQ $0x7FFFFFFF, AX                     \
	CMOVQCS BX, AX                           \
	\ // LFSR_S16 = (LFSR_S15++) = AX
	MOVL AX, (((0 + idx) % 16)*4)(SI)

#define NONLIN_FUN                           \
	MOVL BRC_X0, AX                          \
	XORL F_R1, AX                            \ // F_R1 xor BRC_X1
	ADDL F_R2, AX                            \ // W = (F_R1 xor BRC_X1) + F_R2
	ADDL BRC_X1, F_R1                        \ // W1= F_R1 + BRC_X1
	XORL BRC_X2, F_R2                        \ // W2= F_R2 ^ BRC_X2
	\
	MOVL F_R1, DX                            \
	MOVL F_R2, CX                            \
	SHLDL(DX, CX, $16)                       \ // P = (W1 << 16) | (W2 >> 16)
	SHLDL(F_R2, F_R1, $16)                   \ // Q = (W2 << 16) | (W1 >> 16)
	MOVL DX, BX                              \ // start L1 
	MOVL DX, CX                              \
	ROLL $2, BX                              \
	ROLL $24, CX                             \
	XORL CX, DX                              \
	XORL BX, DX                              \
	ROLL $8, BX                              \
	XORL BX, DX                              \
	ROLL $8, BX                              \
	XORL BX, DX                              \ // U = L1(P) = EDX, hi(RDX)=0
	MOVL F_R2, BX                            \  
	MOVL F_R2, CX                            \
	ROLL $8, BX                              \
	XORL BX, F_R2                            \
	ROLL $14, CX                             \
	XORL CX, F_R2                            \
	ROLL $8, CX                              \
	XORL CX, F_R2                            \
	ROLL $8, CX                              \
	XORL CX, F_R2                            \ // V = L2(Q) = R11D, hi(R11)=0
	SHLQ $32, F_R2                           \ // DX = V || U
	XORQ F_R2, DX                             

// Non-Linear function F, SSE version.
// uses
//      AX, BX, CX, DX, R8
//      X0, X1, X2, X3, X4
// return 
//      W in AX
//      updated F_R1, F_R2  
#define NONLIN_FUN_SSE                       \
	NONLIN_FUN                               \
	MOVQ DX, X0                              \
	MOVOU X0, X1                             \ 
	S0_comput_SSE(X1, X2, X3)                \
	S1_comput_SSE(X0, X2, X3, X4)            \
	\
	PAND mask_S1<>(SB), X0                   \
	PAND mask_S0<>(SB), X1                   \ 
	PXOR X1, X0                              \ 
	\
	MOVL X0, F_R1                            \ // F_R1
	PEXTRD $1, X0, F_R2

// RESTORE_LFSR_0, appends the first 4 bytes to last (SSE, PALIGNR).
// PALIGNR $N, src, dst  =>  src[N..15] || dst[0..N-1]
// Back-to-front so each src register is still original when read.
#define RESTORE_LFSR_0                       \
	MOVUPS (0)(SI), X0                       \ // [s0..s3]
	MOVUPS (16)(SI), X1                      \ // [s4..s7]
	MOVUPS (32)(SI), X2                      \ // [s8..s11]
	MOVUPS (48)(SI), X3                      \ // [s12..s15]
	MOVAPS X0, X4                            \ // backup [s0..s3]
	PALIGNR $4, X3, X4                       \ // X4 = [s13,s14,s15,s0]
	PALIGNR $4, X2, X3                       \ // X3 = [s9,s10,s11,s12]
	PALIGNR $4, X1, X2                       \ // X2 = [s5,s6,s7,s8]
	PALIGNR $4, X0, X1                       \ // X1 = [s1,s2,s3,s4]
	MOVUPS X1, (0)(SI)                       \
	MOVUPS X2, (16)(SI)                      \
	MOVUPS X3, (32)(SI)                      \
	MOVUPS X4, (48)(SI)

// RESTORE_LFSR_2, appends the first 8 bytes to last (SSE, PALIGNR).
#define RESTORE_LFSR_2                       \
	MOVUPS (0)(SI), X0                       \ // [s0..s3]
	MOVUPS (16)(SI), X1                      \ // [s4..s7]
	MOVUPS (32)(SI), X2                      \ // [s8..s11]
	MOVUPS (48)(SI), X3                      \ // [s12..s15]
	MOVAPS X0, X4                            \ // backup [s0..s3]
	PALIGNR $8, X3, X4                       \ // X4 = [s14,s15,s0,s1]
	PALIGNR $8, X2, X3                       \ // X3 = [s10,s11,s12,s13]
	PALIGNR $8, X1, X2                       \ // X2 = [s6,s7,s8,s9]
	PALIGNR $8, X0, X1                       \ // X1 = [s2,s3,s4,s5]
	MOVUPS X1, (0)(SI)                       \
	MOVUPS X2, (16)(SI)                      \
	MOVUPS X3, (32)(SI)                      \
	MOVUPS X4, (48)(SI)

// RESTORE_LFSR_4, appends the first 16 bytes to last.
#define RESTORE_LFSR_4                       \
	MOVUPS (0)(SI), X0                       \ // first 16 bytes
	MOVUPS (16)(SI), X1                      \
	MOVUPS (32)(SI), X2                      \
	MOVUPS (48)(SI), X3                      \ // last 16 bytes
	\
	MOVUPS X1, (0)(SI)                       \
	MOVUPS X2, (16)(SI)                      \
	MOVUPS X3, (32)(SI)                      \
	MOVUPS X0, (48)(SI)

// RESTORE_LFSR_8, appends the first 32 bytes to last.
#define RESTORE_LFSR_8                       \
	MOVUPS (0)(SI), X0                       \
	MOVUPS (16)(SI), X1                      \
	MOVUPS (32)(SI), X2                      \
	MOVUPS (48)(SI), X3                      \
	\
	MOVUPS X2, (0)(SI)                       \
	MOVUPS X3, (16)(SI)                      \
	MOVUPS X0, (32)(SI)                      \
	MOVUPS X1, (48)(SI)

// VPALIGNR $N, src2, src1, dst  =>  src2[N..15] || src1[0..N-1]
// AVX variants use VEX-encoded moves to avoid AVX-SSE transition penalties.

// RESTORE_LFSR_0_AVX, appends the first 4 bytes to last (AVX, VPALIGNR).
#define RESTORE_LFSR_0_AVX                   \
	VMOVDQU (0)(SI), X0                      \ // [s0..s3]
	VMOVDQU (16)(SI), X1                     \ // [s4..s7]
	VMOVDQU (32)(SI), X2                     \ // [s8..s11]
	VMOVDQU (48)(SI), X3                     \ // [s12..s15]
	VMOVDQA X0, X4                           \ // backup [s0..s3]
	VPALIGNR $4, X3, X4, X4                  \ // X4 = [s13,s14,s15,s0]
	VPALIGNR $4, X2, X3, X3                  \ // X3 = [s9,s10,s11,s12]
	VPALIGNR $4, X1, X2, X2                  \ // X2 = [s5,s6,s7,s8]
	VPALIGNR $4, X0, X1, X1                  \ // X1 = [s1,s2,s3,s4]
	VMOVDQU X1, (0)(SI)                      \
	VMOVDQU X2, (16)(SI)                     \
	VMOVDQU X3, (32)(SI)                     \
	VMOVDQU X4, (48)(SI)

// RESTORE_LFSR_2_AVX, appends the first 8 bytes to last (AVX, VPALIGNR).
#define RESTORE_LFSR_2_AVX                   \
	VMOVDQU (0)(SI), X0                      \ // [s0..s3]
	VMOVDQU (16)(SI), X1                     \ // [s4..s7]
	VMOVDQU (32)(SI), X2                     \ // [s8..s11]
	VMOVDQU (48)(SI), X3                     \ // [s12..s15]
	VMOVDQA X0, X4                           \ // backup [s0..s3]
	VPALIGNR $8, X3, X4, X4                  \ // X4 = [s14,s15,s0,s1]
	VPALIGNR $8, X2, X3, X3                  \ // X3 = [s10,s11,s12,s13]
	VPALIGNR $8, X1, X2, X2                  \ // X2 = [s6,s7,s8,s9]
	VPALIGNR $8, X0, X1, X1                  \ // X1 = [s2,s3,s4,s5]
	VMOVDQU X1, (0)(SI)                      \
	VMOVDQU X2, (16)(SI)                     \
	VMOVDQU X3, (32)(SI)                     \
	VMOVDQU X4, (48)(SI)

// RESTORE_LFSR_4_AVX, appends the first 16 bytes to last (AVX, VMOVDQU).
#define RESTORE_LFSR_4_AVX                   \
	VMOVDQU (0)(SI), X0                      \
	VMOVDQU (16)(SI), X1                     \
	VMOVDQU (32)(SI), X2                     \
	VMOVDQU (48)(SI), X3                     \
	VMOVDQU X1, (0)(SI)                      \
	VMOVDQU X2, (16)(SI)                     \
	VMOVDQU X3, (32)(SI)                     \
	VMOVDQU X0, (48)(SI)

// RESTORE_LFSR_8_AVX, appends the first 32 bytes to last (AVX, VMOVDQU).
#define RESTORE_LFSR_8_AVX                   \
	VMOVDQU (0)(SI), X0                      \
	VMOVDQU (16)(SI), X1                     \
	VMOVDQU (32)(SI), X2                     \
	VMOVDQU (48)(SI), X3                     \
	VMOVDQU X2, (0)(SI)                      \
	VMOVDQU X3, (16)(SI)                     \
	VMOVDQU X0, (32)(SI)                     \
	VMOVDQU X1, (48)(SI)

// Non-Linear function F, AVX version.
// uses
//      AX, BX, CX, DX, R8
//      X0, X1, X2, X3, X4
// return 
//      W in AX
//      updated F_R1, F_R2
#define NONLIN_FUN_AVX                       \
	NONLIN_FUN                               \
	VMOVQ DX, X0                             \
	VMOVDQA X0, X1                           \ 
	S0_comput_AVX(X1, X2, X3)                \
	S1_comput_AVX(X0, X2, X3, X4)            \
	\
	VPAND mask_S1<>(SB), X0, X0              \
	VPAND mask_S0<>(SB), X1, X1              \ 
	VPXOR X1, X0, X0                         \ 
	\
	MOVL X0, F_R1                            \ // F_R1
	VPEXTRD $1, X0, F_R2   

#define LOAD_STATE                           \
	MOVL OFFSET_FR1(SI), F_R1                \
	MOVL OFFSET_FR2(SI), F_R2                \
	MOVL OFFSET_BRC_X0(SI), BRC_X0           \
	MOVL OFFSET_BRC_X1(SI), BRC_X1           \
	MOVL OFFSET_BRC_X2(SI), BRC_X2           \
	MOVL OFFSET_BRC_X3(SI), BRC_X3

#define SAVE_STATE                           \
	MOVL F_R1, OFFSET_FR1(SI)                \
	MOVL F_R2, OFFSET_FR2(SI)                \
	MOVL BRC_X0, OFFSET_BRC_X0(SI)           \
	MOVL BRC_X1, OFFSET_BRC_X1(SI)           \
	MOVL BRC_X2, OFFSET_BRC_X2(SI)           \
	MOVL BRC_X3, OFFSET_BRC_X3(SI)

// func genKeywordAsm(s *zucState32) uint32
TEXT ·genKeywordAsm(SB),NOSPLIT,$0
	MOVQ pState+0(FP), SI

	LOAD_STATE

	BITS_REORG(0)
	CMPB ·useGFNI(SB), $1
	JE   gfni
	CMPB ·useAVX(SB), $1
	JE   avx

sse:
	NONLIN_FUN_SSE

	// (BRC_X3 xor W) as result
	XORL BRC_X3, AX
	MOVL AX, ret+8(FP)

	// LFSRWithWorkMode
	XORQ AX, AX
	LFSR_UPDT(0)

	SAVE_STATE
	RESTORE_LFSR_0

	RET

avx:
	NONLIN_FUN_AVX

	// (BRC_X3 xor W) as result
	XORL BRC_X3, AX
	MOVL AX, ret+8(FP)

	// LFSRWithWorkMode
	XORQ AX, AX
	LFSR_UPDT(0)

	SAVE_STATE
	RESTORE_LFSR_0_AVX

	RET

gfni:
	NONLIN_FUN_GFNI

	// (BRC_X3 xor W) as result
	XORL BRC_X3, AX
	MOVL AX, ret+8(FP)

	// LFSRWithWorkMode
	XORQ AX, AX
	LFSR_UPDT(0)

	SAVE_STATE
	RESTORE_LFSR_0_AVX

	RET

#define ROUND_SSE(idx)            \
	BITS_REORG(idx)               \
	NONLIN_FUN_SSE                \
	XORL BRC_X3, AX               \
	MOVL AX, (idx*4)(DI)          \
	XORQ AX, AX                   \
	LFSR_UPDT(idx)

#define ROUND_AVX(idx)            \
	BITS_REORG(idx)               \
	NONLIN_FUN_AVX                \
	XORL BRC_X3, AX               \
	MOVL AX, (idx*4)(DI)          \
	XORQ AX, AX                   \
	LFSR_UPDT(idx)

#define ROUND_REV32_SSE(idx)      \
	BITS_REORG(idx)               \
	NONLIN_FUN_SSE                \
	XORL BRC_X3, AX               \
	BSWAPL AX                     \
	MOVL AX, (idx*4)(DI)          \
	XORQ AX, AX                   \
	LFSR_UPDT(idx)

#define ROUND_REV32_AVX(idx)      \
	BITS_REORG(idx)               \
	NONLIN_FUN_AVX                \
	XORL BRC_X3, AX               \
	BSWAPL AX                     \
	MOVL AX, (idx*4)(DI)          \
	XORQ AX, AX                   \
	LFSR_UPDT(idx)

// func genKeyStreamAsm(keyStream []uint32, pState *zucState32)
TEXT ·genKeyStreamAsm(SB),NOSPLIT,$0
	MOVQ ks+0(FP), DI
	MOVQ ks_len+8(FP), BP
	MOVQ pState+24(FP), SI

	LOAD_STATE

	CMPB ·useGFNI(SB), $1
	JE   gfniZucSixteens
	CMPB ·useAVX(SB), $1
	JE   avxZucSixteens

sseZucSixteens:
	CMPQ BP, $16
	JB sseZucOctet
	SUBQ $16, BP
	ROUND_SSE(0)
	ROUND_SSE(1)
	ROUND_SSE(2)
	ROUND_SSE(3)
	ROUND_SSE(4)
	ROUND_SSE(5)
	ROUND_SSE(6)
	ROUND_SSE(7)
	ROUND_SSE(8)
	ROUND_SSE(9)
	ROUND_SSE(10)
	ROUND_SSE(11)
	ROUND_SSE(12)
	ROUND_SSE(13)
	ROUND_SSE(14)
	ROUND_SSE(15)
	LEAQ 64(DI), DI
	JMP sseZucSixteens

sseZucOctet:
	CMPQ BP, $8
	JB sseZucNibble
	SUBQ $8, BP
	ROUND_SSE(0)
	ROUND_SSE(1)
	ROUND_SSE(2)
	ROUND_SSE(3)
	ROUND_SSE(4)
	ROUND_SSE(5)
	ROUND_SSE(6)
	ROUND_SSE(7)
	LEAQ 32(DI), DI
	RESTORE_LFSR_8

sseZucNibble:
	CMPQ BP, $4
	JB sseZucDouble
	SUBQ $4, BP
	ROUND_SSE(0)
	ROUND_SSE(1)
	ROUND_SSE(2)
	ROUND_SSE(3)
	LEAQ 16(DI), DI
	RESTORE_LFSR_4

sseZucDouble:
	CMPQ BP, $2
	JB sseZucSingle
	SUBQ $2, BP
	ROUND_SSE(0)
	ROUND_SSE(1)
	LEAQ 8(DI), DI
	RESTORE_LFSR_2

sseZucSingle:
	TESTQ BP, BP
	JE sseZucRet
	ROUND_SSE(0)
	RESTORE_LFSR_0

sseZucRet:
	SAVE_STATE
	RET

avxZucSixteens:
	CMPQ BP, $16
	JB avxZucOctet
	SUBQ $16, BP
	ROUND_AVX(0)
	ROUND_AVX(1)
	ROUND_AVX(2)
	ROUND_AVX(3)
	ROUND_AVX(4)
	ROUND_AVX(5)
	ROUND_AVX(6)
	ROUND_AVX(7)
	ROUND_AVX(8)
	ROUND_AVX(9)
	ROUND_AVX(10)
	ROUND_AVX(11)
	ROUND_AVX(12)
	ROUND_AVX(13)
	ROUND_AVX(14)
	ROUND_AVX(15)
	LEAQ 64(DI), DI
	JMP avxZucSixteens

avxZucOctet:
	CMPQ BP, $8
	JB avxZucNibble
	SUBQ $8, BP
	ROUND_AVX(0)
	ROUND_AVX(1)
	ROUND_AVX(2)
	ROUND_AVX(3)
	ROUND_AVX(4)
	ROUND_AVX(5)
	ROUND_AVX(6)
	ROUND_AVX(7)
	LEAQ 32(DI), DI
	RESTORE_LFSR_8_AVX

avxZucNibble:
	CMPQ BP, $4
	JB avxZucDouble
	SUBQ $4, BP
	ROUND_AVX(0)
	ROUND_AVX(1)
	ROUND_AVX(2)
	ROUND_AVX(3)
	LEAQ 16(DI), DI
	RESTORE_LFSR_4_AVX

avxZucDouble:
	CMPQ BP, $2
	JB avxZucSingle
	SUBQ $2, BP
	ROUND_AVX(0)
	ROUND_AVX(1)
	LEAQ 8(DI), DI
	RESTORE_LFSR_2_AVX

avxZucSingle:
	TESTQ BP, BP
	JE avxZucRet
	ROUND_AVX(0)
	RESTORE_LFSR_0_AVX

avxZucRet:
	SAVE_STATE
	RET

gfniZucSixteens:
	CMPQ BP, $16
	JB gfniZucOctet
	SUBQ $16, BP
	ROUND_GFNI(0)
	ROUND_GFNI(1)
	ROUND_GFNI(2)
	ROUND_GFNI(3)
	ROUND_GFNI(4)
	ROUND_GFNI(5)
	ROUND_GFNI(6)
	ROUND_GFNI(7)
	ROUND_GFNI(8)
	ROUND_GFNI(9)
	ROUND_GFNI(10)
	ROUND_GFNI(11)
	ROUND_GFNI(12)
	ROUND_GFNI(13)
	ROUND_GFNI(14)
	ROUND_GFNI(15)
	LEAQ 64(DI), DI
	JMP gfniZucSixteens

gfniZucOctet:
	CMPQ BP, $8
	JB gfniZucNibble
	SUBQ $8, BP
	ROUND_GFNI(0)
	ROUND_GFNI(1)
	ROUND_GFNI(2)
	ROUND_GFNI(3)
	ROUND_GFNI(4)
	ROUND_GFNI(5)
	ROUND_GFNI(6)
	ROUND_GFNI(7)
	LEAQ 32(DI), DI
	RESTORE_LFSR_8_AVX

gfniZucNibble:
	CMPQ BP, $4
	JB gfniZucDouble
	SUBQ $4, BP
	ROUND_GFNI(0)
	ROUND_GFNI(1)
	ROUND_GFNI(2)
	ROUND_GFNI(3)
	LEAQ 16(DI), DI
	RESTORE_LFSR_4_AVX

gfniZucDouble:
	CMPQ BP, $2
	JB gfniZucSingle
	SUBQ $2, BP
	ROUND_GFNI(0)
	ROUND_GFNI(1)
	LEAQ 8(DI), DI
	RESTORE_LFSR_2_AVX

gfniZucSingle:
	TESTQ BP, BP
	JE gfniZucRet
	ROUND_GFNI(0)
	RESTORE_LFSR_0_AVX

gfniZucRet:
	SAVE_STATE
	RET

// func genKeyStreamRev32Asm(keyStream []byte, pState *zucState32)
TEXT ·genKeyStreamRev32Asm(SB),NOSPLIT,$0
	MOVQ ks+0(FP), DI
	MOVQ ks_len+8(FP), BP
	MOVQ pState+24(FP), SI

	SHRQ $2, BP

	LOAD_STATE

	CMPB ·useGFNI(SB), $1
	JE   gfniZucSixteens
	CMPB ·useAVX(SB), $1
	JE   avxZucSixteens

sseZucSixteens:
	CMPQ BP, $16
	JB sseZucOctet
	SUBQ $16, BP
	ROUND_REV32_SSE(0)
	ROUND_REV32_SSE(1)
	ROUND_REV32_SSE(2)
	ROUND_REV32_SSE(3)
	ROUND_REV32_SSE(4)
	ROUND_REV32_SSE(5)
	ROUND_REV32_SSE(6)
	ROUND_REV32_SSE(7)
	ROUND_REV32_SSE(8)
	ROUND_REV32_SSE(9)
	ROUND_REV32_SSE(10)
	ROUND_REV32_SSE(11)
	ROUND_REV32_SSE(12)
	ROUND_REV32_SSE(13)
	ROUND_REV32_SSE(14)
	ROUND_REV32_SSE(15)
	LEAQ 64(DI), DI
	JMP sseZucSixteens

sseZucOctet:
	CMPQ BP, $8
	JB sseZucNibble
	SUBQ $8, BP
	ROUND_REV32_SSE(0)
	ROUND_REV32_SSE(1)
	ROUND_REV32_SSE(2)
	ROUND_REV32_SSE(3)
	ROUND_REV32_SSE(4)
	ROUND_REV32_SSE(5)
	ROUND_REV32_SSE(6)
	ROUND_REV32_SSE(7)
	LEAQ 32(DI), DI
	RESTORE_LFSR_8

sseZucNibble:
	CMPQ BP, $4
	JB sseZucDouble
	SUBQ $4, BP
	ROUND_REV32_SSE(0)
	ROUND_REV32_SSE(1)
	ROUND_REV32_SSE(2)
	ROUND_REV32_SSE(3)
	LEAQ 16(DI), DI
	RESTORE_LFSR_4

sseZucDouble:
	CMPQ BP, $2
	JB sseZucSingle
	SUBQ $2, BP
	ROUND_REV32_SSE(0)
	ROUND_REV32_SSE(1)
	LEAQ 8(DI), DI
	RESTORE_LFSR_2

sseZucSingle:
	TESTQ BP, BP
	JE sseZucRet
	ROUND_REV32_SSE(0)
	RESTORE_LFSR_0

sseZucRet:
	SAVE_STATE
	RET

avxZucSixteens:
	CMPQ BP, $16
	JB avxZucOctet
	SUBQ $16, BP
	ROUND_REV32_AVX(0)
	ROUND_REV32_AVX(1)
	ROUND_REV32_AVX(2)
	ROUND_REV32_AVX(3)
	ROUND_REV32_AVX(4)
	ROUND_REV32_AVX(5)
	ROUND_REV32_AVX(6)
	ROUND_REV32_AVX(7)
	ROUND_REV32_AVX(8)
	ROUND_REV32_AVX(9)
	ROUND_REV32_AVX(10)
	ROUND_REV32_AVX(11)
	ROUND_REV32_AVX(12)
	ROUND_REV32_AVX(13)
	ROUND_REV32_AVX(14)
	ROUND_REV32_AVX(15)
	LEAQ 64(DI), DI
	JMP avxZucSixteens

avxZucOctet:
	CMPQ BP, $8
	JB avxZucNibble
	SUBQ $8, BP
	ROUND_REV32_AVX(0)
	ROUND_REV32_AVX(1)
	ROUND_REV32_AVX(2)
	ROUND_REV32_AVX(3)
	ROUND_REV32_AVX(4)
	ROUND_REV32_AVX(5)
	ROUND_REV32_AVX(6)
	ROUND_REV32_AVX(7)
	LEAQ 32(DI), DI
	RESTORE_LFSR_8_AVX

avxZucNibble:
	CMPQ BP, $4
	JB avxZucDouble
	SUBQ $4, BP
	ROUND_REV32_AVX(0)
	ROUND_REV32_AVX(1)
	ROUND_REV32_AVX(2)
	ROUND_REV32_AVX(3)
	LEAQ 16(DI), DI
	RESTORE_LFSR_4_AVX

avxZucDouble:
	CMPQ BP, $2
	JB avxZucSingle
	SUBQ $2, BP
	ROUND_REV32_AVX(0)
	ROUND_REV32_AVX(1)
	LEAQ 8(DI), DI
	RESTORE_LFSR_2_AVX

avxZucSingle:
	TESTQ BP, BP
	JE avxZucRet
	ROUND_REV32_AVX(0)
	RESTORE_LFSR_0_AVX

avxZucRet:
	SAVE_STATE
	RET

gfniZucSixteens:
	CMPQ BP, $16
	JB gfniZucOctet
	SUBQ $16, BP
	ROUND_REV32_GFNI(0)
	ROUND_REV32_GFNI(1)
	ROUND_REV32_GFNI(2)
	ROUND_REV32_GFNI(3)
	ROUND_REV32_GFNI(4)
	ROUND_REV32_GFNI(5)
	ROUND_REV32_GFNI(6)
	ROUND_REV32_GFNI(7)
	ROUND_REV32_GFNI(8)
	ROUND_REV32_GFNI(9)
	ROUND_REV32_GFNI(10)
	ROUND_REV32_GFNI(11)
	ROUND_REV32_GFNI(12)
	ROUND_REV32_GFNI(13)
	ROUND_REV32_GFNI(14)
	ROUND_REV32_GFNI(15)
	LEAQ 64(DI), DI
	JMP gfniZucSixteens

gfniZucOctet:
	CMPQ BP, $8
	JB gfniZucNibble
	SUBQ $8, BP
	ROUND_REV32_GFNI(0)
	ROUND_REV32_GFNI(1)
	ROUND_REV32_GFNI(2)
	ROUND_REV32_GFNI(3)
	ROUND_REV32_GFNI(4)
	ROUND_REV32_GFNI(5)
	ROUND_REV32_GFNI(6)
	ROUND_REV32_GFNI(7)
	LEAQ 32(DI), DI
	RESTORE_LFSR_8_AVX

gfniZucNibble:
	CMPQ BP, $4
	JB gfniZucDouble
	SUBQ $4, BP
	ROUND_REV32_GFNI(0)
	ROUND_REV32_GFNI(1)
	ROUND_REV32_GFNI(2)
	ROUND_REV32_GFNI(3)
	LEAQ 16(DI), DI
	RESTORE_LFSR_4_AVX

gfniZucDouble:
	CMPQ BP, $2
	JB gfniZucSingle
	SUBQ $2, BP
	ROUND_REV32_GFNI(0)
	ROUND_REV32_GFNI(1)
	LEAQ 8(DI), DI
	RESTORE_LFSR_2_AVX

gfniZucSingle:
	TESTQ BP, BP
	JE gfniZucRet
	ROUND_REV32_GFNI(0)
	RESTORE_LFSR_0_AVX

gfniZucRet:
	SAVE_STATE
	RET
