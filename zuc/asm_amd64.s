// Referenced https://github.com/intel/intel-ipsec-mb/
//go:build amd64 && !generic
// +build amd64,!generic

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

DATA High_nibble_mask<>+0x00(SB)/8, $0xF0F0F0F0F0F0F0F0
DATA High_nibble_mask<>+0x08(SB)/8, $0xF0F0F0F0F0F0F0F0
GLOBL High_nibble_mask<>(SB), RODATA, $16

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

DATA Comb_matrix_mul_low_nibble<>+0x00(SB)/8, $0x9A8E3024EBFF4155
DATA Comb_matrix_mul_low_nibble<>+0x08(SB)/8, $0x2D3987935C48F6E2
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

DATA Const_comb_matrix<>+0x00(SB)/8, $0x5555555555555555
DATA Const_comb_matrix<>+0x08(SB)/8, $0x5555555555555555
GLOBL Const_comb_matrix<>(SB), RODATA, $16

DATA CombMatrix<>+0x00(SB)/8, $0x3C1A99B2AD1ED43A
DATA CombMatrix<>+0x08(SB)/8, $0x3C1A99B2AD1ED43A
GLOBL CombMatrix<>(SB), RODATA, $16

DATA mask_S0<>+0x00(SB)/8, $0xff00ff00ff00ff00
DATA mask_S0<>+0x08(SB)/8, $0xff00ff00ff00ff00
GLOBL mask_S0<>(SB), RODATA, $16

DATA mask_S1<>+0x00(SB)/8, $0x00ff00ff00ff00ff
DATA mask_S1<>+0x08(SB)/8, $0x00ff00ff00ff00ff
GLOBL mask_S1<>(SB), RODATA, $16

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

#define Rotl_5_SSE(XDATA, XTMP0)               \
    MOVOU XDATA, XTMP0                         \
    PSLLQ $5, XTMP0                            \ // should use pslld
    PSRLQ $3, XDATA                            \ // should use psrld
    PAND Top3_bits_of_the_byte<>(SB), XTMP0    \
    PAND Bottom5_bits_of_the_byte<>(SB), XDATA \
    POR XTMP0, XDATA

#define S0_comput_SSE(IN_OUT, XTMP1, XTMP2)    \
    MOVOU IN_OUT, XTMP1                        \
    \
    PAND Low_nibble_mask<>(SB), IN_OUT         \ 
    \
    PAND High_nibble_mask<>(SB), XTMP1         \ 
    PSRLQ $4, XTMP1                            \
    \
    MOVOU P1<>(SB), XTMP2                      \
    PSHUFB IN_OUT, XTMP2                       \
    PXOR XTMP1, XTMP2                          \
    \
    MOVOU P2<>(SB), XTMP1                      \
    PSHUFB XTMP2, XTMP1                        \
    PXOR IN_OUT, XTMP1                         \
    \
    MOVOU P3<>(SB), IN_OUT                     \
    PSHUFB XTMP1, IN_OUT                       \
    PXOR XTMP2, IN_OUT                         \
    \
    PSLLQ $4, IN_OUT                           \
    POR XTMP1, IN_OUT                          \
    Rotl_5_SSE(IN_OUT, XTMP1)

// Perform 8x8 matrix multiplication using lookup tables with partial results
// for high and low nible of each input byte
#define MUL_PSHUFB_SSE(XIN, XLO, XHI_OUT, XTMP)        \
    MOVOU Low_nibble_mask<>(SB), XTMP                  \
    PAND XIN, XTMP                                     \
    \
    PSHUFB XTMP, XLO                                   \
    \
    MOVOU High_nibble_mask<>(SB), XTMP                 \
    PAND XIN, XTMP                                     \
    PSRLQ $4, XTMP                                     \
    \
    PSHUFB XTMP, XHI_OUT                               \
    \
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
    MOVOU Comb_matrix_mul_low_nibble<>(SB), XTMP1       \
    MOVOU Comb_matrix_mul_high_nibble<>(SB), XIN_OUT    \
    MUL_PSHUFB_SSE(XTMP2, XTMP1, XIN_OUT, XTMP3)        \
    PXOR Const_comb_matrix<>(SB), XIN_OUT


#define Rotl_5_AVX(XDATA, XTMP0)                       \
    VPSLLD $5, XDATA, XTMP0                            \
    VPSRLD $3, XDATA, XDATA                            \
    VPAND Top3_bits_of_the_byte<>(SB), XTMP0, XTMP0    \
    VPAND Bottom5_bits_of_the_byte<>(SB), XDATA, XDATA \
    VPOR XTMP0, XDATA, XDATA

#define S0_comput_AVX(IN_OUT, XTMP1, XTMP2)    \
    VPAND High_nibble_mask<>(SB), IN_OUT, XTMP1  \
    VPSRLQ $4, XTMP1, XTMP1                      \
    \
    VPAND Low_nibble_mask<>(SB), IN_OUT, IN_OUT  \
    \
    VMOVDQU P1<>(SB), XTMP2                      \
    VPSHUFB IN_OUT, XTMP2, XTMP2                 \
    VPXOR XTMP1, XTMP2, XTMP2                    \
    \
    VMOVDQU P2<>(SB), XTMP1                      \
    VPSHUFB XTMP2, XTMP1, XTMP1                  \
    VPXOR IN_OUT, XTMP1, XTMP1                   \
    \
    VMOVDQU P3<>(SB), IN_OUT                     \
    VPSHUFB XTMP1, IN_OUT, IN_OUT                \
    VPXOR XTMP2, IN_OUT, IN_OUT                  \
    \
    VPSLLQ $4, IN_OUT, IN_OUT                    \
    VPOR XTMP1, IN_OUT, IN_OUT                   \
    Rotl_5_AVX(IN_OUT, XTMP1)

// Perform 8x8 matrix multiplication using lookup tables with partial results
// for high and low nible of each input byte
#define MUL_PSHUFB_AVX(XIN, XLO, XHI_OUT, XTMP)        \
    VPAND Low_nibble_mask<>(SB), XIN, XTMP             \
    VPSHUFB XTMP, XLO, XLO                             \
    VPAND High_nibble_mask<>(SB), XIN, XTMP            \
    VPSRLQ $4, XTMP, XTMP                              \
    VPSHUFB XTMP, XHI_OUT, XHI_OUT                     \
    VPXOR XLO, XHI_OUT, XHI_OUT

// Compute 16 S1 box values from 16 bytes, stored in XMM register
#define S1_comput_AVX(XIN_OUT, XTMP1, XTMP2, XTMP3)       \
    VMOVDQU Aes_to_Zuc_mul_low_nibble<>(SB), XTMP1        \
    VMOVDQU Aes_to_Zuc_mul_high_nibble<>(SB), XTMP2       \
    MUL_PSHUFB_AVX(XIN_OUT, XTMP1, XTMP2, XTMP3)          \
    VPSHUFB Shuf_mask<>(SB), XTMP2, XTMP2                 \
    VAESENCLAST Cancel_aes<>(SB), XTMP2, XTMP2            \
    VMOVDQU Comb_matrix_mul_low_nibble<>(SB), XTMP1       \
    VMOVDQU Comb_matrix_mul_high_nibble<>(SB), XIN_OUT    \
    MUL_PSHUFB_AVX(XTMP2, XTMP1, XIN_OUT, XTMP3)          \
    VPXOR Const_comb_matrix<>(SB), XIN_OUT, XIN_OUT     
    

// BITS_REORG(idx)
// params
//      %1 - round number
// uses
//      AX, BX, CX, DX
// return 
//      R12, R13, R14, R15
#define BITS_REORG(idx)                      \
    MOVL (((15 + idx) % 16)*4)(SI), R12      \
    MOVL (((14 + idx) % 16)*4)(SI), AX       \
    MOVL (((11 + idx) % 16)*4)(SI), R13      \
    MOVL (((9 + idx) % 16)*4)(SI), BX        \
    MOVL (((7 + idx) % 16)*4)(SI), R14       \ 
    MOVL (((5 + idx) % 16)*4)(SI), CX        \
    MOVL (((2 + idx) % 16)*4)(SI), R15       \
    MOVL (((0 + idx) % 16)*4)(SI), DX        \
    SHRL $15, R12                            \
    SHLL $16, AX                             \
    SHLL $1, BX                              \
    SHLL $1, CX                              \
    SHLL $1, DX                              \
    SHLDL(R12, AX, $16)                      \
    SHLDL(R13, BX, $16)                      \
    SHLDL(R14, CX, $16)                      \
    SHLDL(R15, DX, $16)                      

#define LFSR_UPDT(idx)                       \
    MOVL (((0 + idx) % 16)*4)(SI), BX        \
    MOVL (((4 + idx) % 16)*4)(SI), CX        \
    MOVL (((10 + idx) % 16)*4)(SI), DX       \
    MOVL (((13 + idx) % 16)*4)(SI), R8       \
    MOVL (((15 + idx) % 16)*4)(SI), R9       \
    ADDQ BX, AX                              \
    SHLQ $8, BX                              \
    SHLQ $20, CX                             \
    SHLQ $21, DX                             \
    SHLQ $17, R8                             \
    SHLQ $15, R9                             \
    ADDQ BX, AX                              \
    ADDQ CX, AX                              \
    ADDQ DX, AX                              \
    ADDQ R8, AX                              \
    ADDQ R9, AX                              \
    \
    MOVQ AX, BX                              \
    ANDQ $0x7FFFFFFF, AX                     \
    SHRQ $31, BX                             \
    ADDQ BX, AX                              \
    \
    MOVQ AX, BX                              \
    SUBQ $0x7FFFFFFF, AX                     \
    CMOVQCS BX, AX                           \
    \
    MOVL AX, (((0 + idx) % 16)*4)(SI)

#define NONLIN_FUN()                         \
    MOVL R12, AX                             \
    XORL R10, AX                             \
    ADDL R11, AX                             \
    ADDL R13, R10                            \ // W1= F_R1 + BRC_X1
    XORL R14, R11                            \ // W2= F_R2 ^ BRC_X2
    \
    MOVL R10, DX                             \
    MOVL R11, CX                             \
    SHLDL(DX, CX, $16)                       \ // P = (W1 << 16) | (W2 >> 16)
    SHLDL(R11, R10, $16)                     \ // Q = (W2 << 16) | (W1 >> 16)
    MOVL DX, BX                              \  
    MOVL DX, CX                              \
    MOVL DX, R8                              \
    MOVL DX, R9                              \
    ROLL $2, BX                              \
    ROLL $10, CX                             \
    ROLL $18, R8                             \
    ROLL $24, R9                             \
    XORL BX, DX                              \
    XORL CX, DX                              \
    XORL R8, DX                              \
    XORL R9, DX                              \ // U = L1(P) = EDX, hi(RDX)=0
    MOVL R11, BX                             \  
    MOVL R11, CX                             \
    MOVL R11, R8                             \
    MOVL R11, R9                             \
    ROLL $8, BX                              \
    ROLL $14, CX                             \
    ROLL $22, R8                             \
    ROLL $30, R9                             \
    XORL BX, R11                             \
    XORL CX, R11                             \
    XORL R8, R11                             \
    XORL R9, R11                             \ // V = L2(Q) = R11D, hi(R11)=0
    SHLQ $32, R11                            \
    XORQ R11, DX                             

#define NONLIN_FUN_SSE()                     \
    NONLIN_FUN()                             \
    MOVQ DX, X0                              \
    MOVOU X0, X1                             \ 
    S0_comput_SSE(X1, X2, X3)                \
    S1_comput_SSE(X0, X2, X3, X4)            \
    \
    PAND mask_S1<>(SB), X0                   \
    PAND mask_S0<>(SB), X1                   \ 
    PXOR X1, X0                              \ 
    \
    MOVL X0, R10                             \ // F_R1
    PEXTRD $1, X0, R11

#define RESTORE_LFSR_0()                     \
    MOVL (0*4)(SI), AX                       \
    MOVUPS (4)(SI), X0                       \ 
    MOVUPS (20)(SI), X1                      \ 
    MOVUPS (36)(SI), X2                      \
    MOVQ (52)(SI), BX                        \
    MOVL (60)(SI), CX                        \
    \
    MOVUPS X0, (SI)                          \  
    MOVUPS X1, (16)(SI)                      \  
    MOVUPS X2, (32)(SI)                      \
    MOVQ BX, (48)(SI)                        \
    MOVL CX, (56)(SI)                        \
    MOVL AX, (60)(SI) 

#define RESTORE_LFSR_2()                     \
    MOVQ (0)(SI), AX                         \
    MOVUPS (8)(SI), X0                       \ 
    MOVUPS (24)(SI), X1                      \ 
    MOVUPS (40)(SI), X2                      \
    MOVQ (56)(SI), BX                        \
    \
    MOVUPS X0, (SI)                          \  
    MOVUPS X1, (16)(SI)                      \  
    MOVUPS X2, (32)(SI)                      \
    MOVQ BX, (48)(SI)                        \
    MOVQ AX, (56)(SI)

#define RESTORE_LFSR_4()                     \
    MOVUPS (0)(SI), X0                       \
    MOVUPS (16)(SI), X1                      \
    MOVUPS (32)(SI), X2                      \
    MOVUPS (48)(SI), X3                      \
    \
    MOVUPS X1, (0)(SI)                       \
    MOVUPS X2, (16)(SI)                      \
    MOVUPS X3, (32)(SI)                      \
    MOVUPS X0, (48)(SI)

#define RESTORE_LFSR_8()                     \
    MOVUPS (0)(SI), X0                       \
    MOVUPS (16)(SI), X1                      \
    MOVUPS (32)(SI), X2                      \
    MOVUPS (48)(SI), X3                      \
    \
    MOVUPS X2, (0)(SI)                       \
    MOVUPS X3, (16)(SI)                      \
    MOVUPS X0, (32)(SI)                      \
    MOVUPS X1, (48)(SI)

#define NONLIN_FUN_AVX()                     \
    NONLIN_FUN()                             \
    VMOVQ DX, X0                             \
    VMOVDQA X0, X1                           \ 
    S0_comput_AVX(X1, X2, X3)                \
    S1_comput_AVX(X0, X2, X3, X4)            \
    \
    VPAND mask_S1<>(SB), X0, X0              \
    VPAND mask_S0<>(SB), X1, X1              \ 
    VPXOR X1, X0, X0                         \ 
    \
    MOVL X0, R10                             \ // F_R1
    VPEXTRD $1, X0, R11   

#define LOAD_STATE()                         \
    MOVL OFFSET_FR1(SI), R10                 \
    MOVL OFFSET_FR2(SI), R11                 \
    MOVL OFFSET_BRC_X0(SI), R12              \
    MOVL OFFSET_BRC_X1(SI), R13              \
    MOVL OFFSET_BRC_X2(SI), R14              \
    MOVL OFFSET_BRC_X3(SI), R15

#define SAVE_STATE()                         \
    MOVL R10, OFFSET_FR1(SI)                 \
    MOVL R11, OFFSET_FR2(SI)                 \
    MOVL R12, OFFSET_BRC_X0(SI)              \
    MOVL R13, OFFSET_BRC_X1(SI)              \
    MOVL R14, OFFSET_BRC_X2(SI)              \
    MOVL R15, OFFSET_BRC_X3(SI)

// func genKeywordAsm(s *zucState32) uint32
TEXT ·genKeywordAsm(SB),NOSPLIT,$0
    MOVQ pState+0(FP), SI
    
    LOAD_STATE()

    BITS_REORG(0)
	CMPB ·useAVX(SB), $1
	JE   avx

sse:
    NONLIN_FUN_SSE()

    XORL R15, AX
    MOVL AX, ret+8(FP)
    XORQ AX, AX
    LFSR_UPDT(0)
    SAVE_STATE()
    RESTORE_LFSR_0()

    RET

avx:
    NONLIN_FUN_AVX()

    XORL R15, AX
    MOVL AX, ret+8(FP)
    XORQ AX, AX
    LFSR_UPDT(0)
    SAVE_STATE()
    RESTORE_LFSR_0()

    VZEROUPPER
    RET

#define ROUND_SSE(idx)            \
    BITS_REORG(idx)               \
    NONLIN_FUN_SSE()              \
    XORL R15, AX                  \
    MOVL AX, (idx*4)(DI)          \
    XORQ AX, AX                   \
    LFSR_UPDT(idx)

#define ROUND_AVX(idx)            \
    BITS_REORG(idx)               \
    NONLIN_FUN_AVX()              \
    XORL R15, AX                  \
    MOVL AX, (idx*4)(DI)          \
    XORQ AX, AX                   \
    LFSR_UPDT(idx)

// func genKeyStreamAsm(keyStream []uint32, pState *zucState32)
TEXT ·genKeyStreamAsm(SB),NOSPLIT,$0
    MOVQ ks+0(FP), DI
    MOVQ ks_len+8(FP), BP
    MOVQ pState+24(FP), SI

    LOAD_STATE()

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
    RESTORE_LFSR_8()
sseZucNibble:
    CMPQ BP, $4
    JB sseZucDouble
    SUBQ $4, BP
    ROUND_SSE(0)
    ROUND_SSE(1)
    ROUND_SSE(2)
    ROUND_SSE(3)
    LEAQ 16(DI), DI
    RESTORE_LFSR_4()
sseZucDouble:
    CMPQ BP, $2
    JB sseZucSingle
    SUBQ $2, BP
    ROUND_SSE(0)
    ROUND_SSE(1)
    LEAQ 8(DI), DI
    RESTORE_LFSR_2()
sseZucSingle:
    TESTQ BP, BP
    JE sseZucRet
    ROUND_SSE(0)
    RESTORE_LFSR_0()
sseZucRet:
    SAVE_STATE()
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
    RESTORE_LFSR_8()
avxZucNibble:
    CMPQ BP, $4
    JB avxZucDouble
    SUBQ $4, BP
    ROUND_AVX(0)
    ROUND_AVX(1)
    ROUND_AVX(2)
    ROUND_AVX(3)
    LEAQ 16(DI), DI
    RESTORE_LFSR_4()
avxZucDouble:
    CMPQ BP, $2
    JB avxZucSingle
    SUBQ $2, BP
    ROUND_AVX(0)
    ROUND_AVX(1)
    LEAQ 8(DI), DI
    RESTORE_LFSR_2()
avxZucSingle:
    TESTQ BP, BP
    JE avxZucRet
    ROUND_AVX(0)
    RESTORE_LFSR_0()
avxZucRet:
    SAVE_STATE()
    VZEROUPPER
    RET
