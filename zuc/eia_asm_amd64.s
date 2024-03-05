// Referenced Intel(R) Multi-Buffer Crypto for IPsec
// https://github.com/intel/intel-ipsec-mb/
//go:build !purego

#include "textflag.h"

DATA bit_reverse_table_l<>+0x00(SB)/8, $0x0e060a020c040800
DATA bit_reverse_table_l<>+0x08(SB)/8, $0x0f070b030d050901
GLOBL bit_reverse_table_l<>(SB), RODATA, $16

DATA bit_reverse_table_h<>+0x00(SB)/8, $0xe060a020c0408000
DATA bit_reverse_table_h<>+0x08(SB)/8, $0xf070b030d0509010
GLOBL bit_reverse_table_h<>(SB), RODATA, $16

DATA bit_reverse_and_table<>+0x00(SB)/8, $0x0f0f0f0f0f0f0f0f
DATA bit_reverse_and_table<>+0x08(SB)/8, $0x0f0f0f0f0f0f0f0f
GLOBL bit_reverse_and_table<>(SB), RODATA, $16

DATA shuf_mask_dw0_0_dw1_0<>+0x00(SB)/8, $0xffffffff03020100
DATA shuf_mask_dw0_0_dw1_0<>+0x08(SB)/8, $0xffffffff07060504
GLOBL shuf_mask_dw0_0_dw1_0<>(SB), RODATA, $16

DATA shuf_mask_dw2_0_dw3_0<>+0x00(SB)/8, $0xffffffff0b0a0908
DATA shuf_mask_dw2_0_dw3_0<>+0x08(SB)/8, $0xffffffff0f0e0d0c
GLOBL shuf_mask_dw2_0_dw3_0<>(SB), RODATA, $16

#define XTMP1 X1
#define XTMP2 X2
#define XTMP3 X3
#define XTMP4 X4
#define XTMP5 X5
#define XTMP6 X6
#define XDATA X7
#define XDIGEST X8
#define KS_L X9
#define KS_M1 X10
#define KS_M2 X11
#define KS_H X12

// func eia3Round16B(t *uint32, keyStream *uint32, p *byte, tagSize int)
TEXT ·eia3Round16B(SB),NOSPLIT,$0
	MOVQ t+0(FP), AX
	MOVQ ks+8(FP), BX
	MOVQ p+16(FP), CX
	MOVQ tagSize+24(FP), DX

	CMPB ·useAVX(SB), $1
	JE   avx

	// Reverse data bytes
	MOVUPS (0)(CX), XDATA
	MOVOU bit_reverse_and_table<>(SB), XTMP4
	MOVOU XDATA, XTMP2
	PAND  XTMP4, XTMP2

	PANDN XDATA, XTMP4
	PSRLQ $4, XTMP4

	MOVOU bit_reverse_table_h<>(SB), XTMP3
	PSHUFB XTMP2, XTMP3

	MOVOU bit_reverse_table_l<>(SB), XTMP1
	PSHUFB XTMP4, XTMP1

	PXOR XTMP1, XTMP3  // XTMP3 - bit reverse data bytes

	// ZUC authentication part, 4x32 data bits
	// setup KS
	MOVUPS (0*4)(BX), XTMP1
	MOVUPS (2*4)(BX), XTMP2
	PSHUFD $0x61, XTMP1, KS_L  // KS bits [63:32 31:0 95:64 63:32]
	PSHUFD $0x61, XTMP2, KS_M1 // KS bits [127:96 95:64 159:128 127:96]

	// setup DATA
	MOVOU XTMP3, XTMP1
	PSHUFB shuf_mask_dw0_0_dw1_0<>(SB), XTMP1
	MOVOU XTMP1, XTMP2 // XTMP1/2 - Data bits [31:0 0s 63:32 0s]

	PSHUFB shuf_mask_dw2_0_dw3_0<>(SB), XTMP3
	MOVOU XTMP3, XDIGEST // XDIGEST/XTMP3 - Data bits [95:64 0s 127:96 0s]

	// clmul
	// xor the results from 4 32-bit words together
	// Calculate lower 32 bits of tag
	PCLMULQDQ $0x00, KS_L, XTMP1
	PCLMULQDQ $0x11, KS_L, XTMP2
	PCLMULQDQ $0x00, KS_M1, XDIGEST
	PCLMULQDQ $0x11, KS_M1, XTMP3

	// XOR all products and move 32-bits to lower 32 bits
	PXOR XTMP1, XTMP2
	PXOR XTMP3, XDIGEST
	PXOR XTMP2, XDIGEST
	PSRLDQ $4, XDIGEST

	// Update tag
	MOVL XDIGEST, R10
	XORL R10, (AX)

	// Copy last 16 bytes of KS to the front
	MOVUPS (4*4)(BX), XTMP1
	MOVUPS XTMP1, (0*4)(BX)

	RET

avx:
	VMOVDQU (0)(CX), XDATA

	// Reverse data bytes
	VMOVDQU bit_reverse_and_table<>(SB), XTMP1 
	VPAND XTMP1, XDATA, XTMP2
	VPANDN XDATA, XTMP1, XTMP3
	VPSRLD $4, XTMP3, XTMP3

	VMOVDQU bit_reverse_table_h<>(SB), XTMP1
	VPSHUFB XTMP2, XTMP1, XTMP4
	VMOVDQU bit_reverse_table_l<>(SB), XTMP1
	VPSHUFB XTMP3, XTMP1, XTMP1
	VPOR XTMP1, XTMP4, XTMP4
	
	// ZUC authentication part, 4x32 data bits
	// setup KS
	VPSHUFD $0x61, (0*4)(BX), KS_L  // KS bits [63:32 31:0 95:64 63:32]
	VPSHUFD $0x61, (2*4)(BX), KS_M1  // KS bits [63:32 31:0 95:64 63:32]

	// setup DATA
	// Data bytes [31:0 0s 63:32 0s]
	VPSHUFB shuf_mask_dw0_0_dw1_0<>(SB), XTMP4, XTMP1
	// Data bytes [95:64 0s 127:96 0s]
	VPSHUFB shuf_mask_dw2_0_dw3_0<>(SB), XTMP4, XTMP2

	// clmul
	// xor the results from 4 32-bit words together
	// Calculate lower 32 bits of tag
	VPCLMULQDQ $0x00, KS_L, XTMP1, XTMP3
	VPCLMULQDQ $0x11, KS_L, XTMP1, XTMP4
	VPCLMULQDQ $0x00, KS_M1, XTMP2, XTMP5
	VPCLMULQDQ $0x11, KS_M1, XTMP2, XTMP6

	VPXOR XTMP3, XTMP4, XTMP3
	VPXOR XTMP5, XTMP6, XTMP5
	VPXOR XTMP3, XTMP5, XDIGEST

	VMOVQ XDIGEST, R10
	SHRQ $32, R10
	XORL R10, (AX)

	// Copy last 16 bytes of KS to the front
	VMOVDQU (4*4)(BX), XTMP1
	VMOVDQU XTMP1, (0*4)(BX)

	VZEROUPPER
	RET
