//go:build !purego

#include "textflag.h"

DATA eia_const<>+0x00(SB)/8, $0x0e060a020c040800 // bit_reverse_table low
DATA eia_const<>+0x08(SB)/8, $0x0f070b030d050901
DATA eia_const<>+0x10(SB)/8, $0xe060a020c0408000 // bit_reverse_table high
DATA eia_const<>+0x18(SB)/8, $0xf070b030d0509010
DATA eia_const<>+0x20(SB)/8, $0xffffffff03020100 // SHUF_MASK_DW0_DW1
DATA eia_const<>+0x28(SB)/8, $0xffffffff07060504
DATA eia_const<>+0x30(SB)/8, $0xffffffff0b0a0908 // SHUF_MASK_DW2_DW3
DATA eia_const<>+0x38(SB)/8, $0xffffffff0f0e0d0c
GLOBL eia_const<>(SB), RODATA, $64

#define AX R2
#define BX R3
#define CX R4
#define DX R5

#define XTMP1 V1
#define XTMP2 V2
#define XTMP3 V3
#define XTMP4 V4
#define XTMP5 V5
#define XTMP6 V6
#define XDATA V7
#define XDIGEST V8
#define KS_L V9
#define KS_M1 V10
#define KS_M2 V11
#define KS_H V12
#define BIT_REV_AND_TAB V20
#define BIT_REV_TAB_L V21
#define BIT_REV_TAB_H V22
#define SHUF_MASK_DW0_DW1 V23
#define SHUF_MASK_DW2_DW3 V24

#define LOAD_GLOBAL_DATA() \
	MOVD $eia_const<>(SB), R0                                                                              \
	VLD1 (R0), [BIT_REV_TAB_L.B16, BIT_REV_TAB_H.B16, SHUF_MASK_DW0_DW1.B16, SHUF_MASK_DW2_DW3.B16]       \
	MOVW $0x0F0F0F0F, R0                                                                                  \
	VDUP R0, BIT_REV_AND_TAB.S4

#define BIT_REVERSE(XDATA, XTMP1, XTMP2) \
	VAND BIT_REV_AND_TAB.B16, XDATA.B16, XTMP2.B16 \
	VUSHR $4, XDATA.B16, XTMP1.B16                 \
	VTBL XTMP2.B16, [BIT_REV_TAB_H.B16], XTMP2.B16 \
	VTBL XTMP1.B16, [BIT_REV_TAB_L.B16], XTMP1.B16 \
	VEOR XTMP1.B16, XTMP2.B16, XDATA.B16                        

// func eiaRoundTag4(t *uint32, keyStream *uint32, p *byte)
TEXT ·eiaRoundTag4(SB),NOSPLIT,$0
	MOVD t+0(FP), AX
	MOVD ks+8(FP), BX
	MOVD p+16(FP), CX

	LOAD_GLOBAL_DATA()

	// Reverse data bytes
	VLD1 (CX), [XDATA.B16]
	BIT_REVERSE(XDATA, XTMP1, XTMP2)

	// ZUC authentication part, 4x32 data bits
	// setup KS
	VLD1 (BX), [XTMP1.B16, XTMP2.B16]
	VST1 [XTMP2.B16], (BX) // Copy last 16 bytes of KS to the front
	// TODO: Any better solution???
	VDUP XTMP1.S[1], KS_L.S4
	VMOV XTMP1.S[0], KS_L.S[1]
	VMOV XTMP1.S[2], KS_L.S[2] // KS bits [63:32 31:0 95:64 63:32]
	VDUP XTMP1.S[3], KS_M1.S4
	VMOV XTMP1.S[2], KS_M1.S[1]
	VMOV XTMP2.S[0], KS_M1.S[2] // KS bits [127:96 95:64 159:128 127:96]

	// setup DATA
	VTBL SHUF_MASK_DW0_DW1.B16, [XDATA.B16], XTMP1.B16 // XTMP1 - Data bits [31:0 0s 63:32 0s]
	VTBL SHUF_MASK_DW2_DW3.B16, [XDATA.B16], XTMP2.B16 // XTMP2 - Data bits [95:64 0s 127:96 0s]

	// clmul
	// xor the results from 4 32-bit words together
	// Calculate lower 32 bits of tag
	VPMULL KS_L.D1, XTMP1.D1, XTMP3.Q1
	VPMULL2 KS_L.D2, XTMP1.D2, XTMP4.Q1
	VPMULL KS_M1.D1, XTMP2.D1, XTMP5.Q1
	VPMULL2 KS_M1.D2, XTMP2.D2, XTMP6.Q1

	VEOR XTMP3.B16, XTMP4.B16, XTMP3.B16
	VEOR XTMP5.B16, XTMP6.B16, XTMP5.B16
	VEOR XTMP3.B16, XTMP5.B16, XDIGEST.B16

	VMOV XDIGEST.S[1], R10
	MOVW (AX), R11
	EORW R10, R11
	MOVW R11, (AX)

	RET

// func eia256RoundTag8(t *uint32, keyStream *uint32, p *byte)
TEXT ·eia256RoundTag8(SB),NOSPLIT,$0
	MOVD t+0(FP), AX
	MOVD ks+8(FP), BX
	MOVD p+16(FP), CX

	LOAD_GLOBAL_DATA()

	// Reverse data bytes
	VLD1 (CX), [XDATA.B16]
	BIT_REVERSE(XDATA, XTMP1, XTMP2)

	// ZUC authentication part, 4x32 data bits
	// setup KS
	VLD1 (BX), [XTMP1.B16, XTMP2.B16]
	VST1 [XTMP2.B16], (BX) // Copy last 16 bytes of KS to the front
	// TODO: Any better solution???
	VMOVQ $0x0302010007060504, $0x070605040b0a0908, XTMP4
	VTBL XTMP4.B16, [XTMP1.B16], KS_L.B16 // KS bits [63:32 31:0 95:64 63:32]
	VTBL XTMP4.B16, [XTMP2.B16], KS_M2.B16 // KS bits [191:160 159:128 223:192 191:160]
	VDUP XTMP1.S[3], KS_M1.S4
	VMOV XTMP1.S[2], KS_M1.S[1]
	VMOV XTMP2.S[0], KS_M1.S[2] // KS bits [127:96 95:64 159:128 127:96]
	
	// setup DATA
	VTBL SHUF_MASK_DW0_DW1.B16, [XDATA.B16], XTMP1.B16 // XTMP1 - Data bits [31:0 0s 63:32 0s]
	VTBL SHUF_MASK_DW2_DW3.B16, [XDATA.B16], XTMP2.B16 // XTMP2 - Data bits [95:64 0s 127:96 0s]

	// clmul
	// xor the results from 4 32-bit words together

	// Calculate lower 32 bits of tag
	VPMULL KS_L.D1, XTMP1.D1, XTMP3.Q1
	VPMULL2 KS_L.D2, XTMP1.D2, XTMP4.Q1
	VPMULL KS_M1.D1, XTMP2.D1, XTMP5.Q1
	VPMULL2 KS_M1.D2, XTMP2.D2, XTMP6.Q1

	VEOR XTMP3.B16, XTMP4.B16, XTMP3.B16
	VEOR XTMP5.B16, XTMP6.B16, XTMP5.B16
	VEOR XTMP3.B16, XTMP5.B16, XTMP3.B16

	// Move previous result to low 32 bits and XOR with previous digest
	VMOV XTMP3.S[1], XDIGEST.S[0]

	// Prepare data and calculate bits 63-32 of tag
	VEXT	$8, KS_L.B16, KS_L.B16, XTMP5.B16
	VPMULL XTMP5.D1, XTMP1.D1, XTMP3.Q1
	VEXT	$8, XTMP1.B16, XTMP1.B16, XTMP5.B16
	VPMULL KS_M1.D1, XTMP5.D1, XTMP4.Q1
	VEXT	$8, KS_M1.B16, KS_M1.B16, XTMP1.B16
	VPMULL XTMP1.D1, XTMP2.D1, XTMP5.Q1
	VEXT	$8, XTMP2.B16, XTMP2.B16, XTMP1.B16
	VPMULL KS_M2.D1, XTMP1.D1, XTMP6.Q1

	VEOR XTMP3.B16, XTMP4.B16, XTMP3.B16
	VEOR XTMP5.B16, XTMP6.B16, XTMP5.B16
	VEOR XTMP3.B16, XTMP5.B16, XTMP3.B16

	VMOV XTMP3.S[1], XDIGEST.S[1]

	VMOV XDIGEST.D[0], R10
	MOVD (AX), R11
	EOR R10, R11
	MOVD R11, (AX)

	RET

// func eia256RoundTag16(t *uint32, keyStream *uint32, p *byte)
TEXT ·eia256RoundTag16(SB),NOSPLIT,$0
	MOVD t+0(FP), AX
	MOVD ks+8(FP), BX
	MOVD p+16(FP), CX

	LOAD_GLOBAL_DATA()

	// Reverse data bytes
	VLD1 (CX), [XDATA.B16]
	BIT_REVERSE(XDATA, XTMP1, XTMP2)

	// ZUC authentication part, 4x32 data bits
	// setup KS
	VLD1 (BX), [XTMP1.B16, XTMP2.B16]
	VST1 [XTMP2.B16], (BX) // Copy last 16 bytes of KS to the front
	// TODO: Any better solution??? We can use VTBL, but there are no performance imprvoement if we can't reuse MASK constant
	VMOVQ $0x0302010007060504, $0x070605040b0a0908, XTMP4
	VTBL XTMP4.B16, [XTMP1.B16], KS_L.B16  // KS bits [63:32 31:0 95:64 63:32]
	VTBL XTMP4.B16, [XTMP2.B16], KS_M2.B16 // KS bits [191:160 159:128 223:192 191:160]
	VMOVQ $0x0b0a09080f0e0d0c, $0x0b0a09080f0e0d0c, XTMP4
	VTBL XTMP4.B16, [XTMP2.B16], KS_H.B16  // KS bits [255:224 223:192 255:224 223:192]
	VDUP XTMP1.S[3], KS_M1.S4
	VMOV XTMP1.S[2], KS_M1.S[1]
	VMOV XTMP2.S[0], KS_M1.S[2] // KS bits [127:96 95:64 159:128 127:96]

	// setup DATA
	VTBL SHUF_MASK_DW0_DW1.B16, [XDATA.B16], XTMP1.B16 // XTMP1 - Data bits [31:0 0s 63:32 0s]
	VTBL SHUF_MASK_DW2_DW3.B16, [XDATA.B16], XTMP2.B16 // XTMP2 - Data bits [95:64 0s 127:96 0s]

	// clmul
	// xor the results from 4 32-bit words together

	// Calculate lower 32 bits of tag
	VPMULL KS_L.D1, XTMP1.D1, XTMP3.Q1
	VPMULL2 KS_L.D2, XTMP1.D2, XTMP4.Q1
	VPMULL KS_M1.D1, XTMP2.D1, XTMP5.Q1
	VPMULL2 KS_M1.D2, XTMP2.D2, XTMP6.Q1

	VEOR XTMP3.B16, XTMP4.B16, XTMP3.B16
	VEOR XTMP5.B16, XTMP6.B16, XTMP5.B16
	VEOR XTMP3.B16, XTMP5.B16, XTMP3.B16

	// Move previous result to low 32 bits and XOR with previous digest
	VMOV XTMP3.S[1], XDIGEST.S[0]

	// Prepare data and calculate bits 63-32 of tag
	VEXT	$8, KS_L.B16, KS_L.B16, XTMP5.B16
	VPMULL XTMP5.D1, XTMP1.D1, XTMP3.Q1
	VEXT	$8, XTMP1.B16, XTMP1.B16, XTMP5.B16
	VPMULL KS_M1.D1, XTMP5.D1, XTMP4.Q1
	VEXT	$8, KS_M1.B16, KS_M1.B16, XTMP6.B16
	VPMULL XTMP6.D1, XTMP2.D1, XTMP5.Q1
	VEXT	$8, XTMP2.B16, XTMP2.B16, KS_L.B16
	VPMULL KS_M2.D1, KS_L.D1, XTMP6.Q1

	// XOR all the products and keep only 32-63 bits
	VEOR XTMP3.B16, XTMP4.B16, XTMP3.B16
	VEOR XTMP5.B16, XTMP6.B16, XTMP5.B16
	VEOR XTMP3.B16, XTMP5.B16, XTMP3.B16

	VMOV XTMP3.S[1], XDIGEST.S[1]

	// Prepare data and calculate bits 95-64 of tag
	VPMULL KS_M1.D1, XTMP1.D1, XTMP3.Q1
	VPMULL2 KS_M1.D2, XTMP1.D2, XTMP4.Q1
	VPMULL KS_M2.D1, XTMP2.D1, XTMP5.Q1
	VPMULL2 KS_M2.D2, XTMP2.D2, XTMP6.Q1

	// XOR all the products and move bits 63-32 to bits 95-64
	VEOR XTMP3.B16, XTMP4.B16, XTMP3.B16
	VEOR XTMP5.B16, XTMP6.B16, XTMP5.B16
	VEOR XTMP3.B16, XTMP5.B16, XTMP3.B16

	VMOV XTMP3.S[1], XDIGEST.S[2]

	// Prepare data and calculate bits 127-96 of tag
	VEXT	$8, KS_M1.B16, KS_M1.B16, XTMP5.B16
	VPMULL XTMP5.D1, XTMP1.D1, XTMP3.Q1
	VEXT	$8, XTMP1.B16, XTMP1.B16, XTMP5.B16
	VPMULL KS_M2.D1, XTMP5.D1, XTMP4.Q1
	VEXT	$8, KS_M2.B16, KS_M2.B16, XTMP6.B16
	VPMULL XTMP6.D1, XTMP2.D1, XTMP5.Q1
	VEXT	$8, XTMP2.B16, XTMP2.B16, KS_L.B16
	VPMULL KS_H.D1, KS_L.D1, XTMP6.Q1

	// XOR all the products and move bits 63-32 to bits 127-96
	VEOR XTMP3.B16, XTMP4.B16, XTMP3.B16
	VEOR XTMP5.B16, XTMP6.B16, XTMP5.B16
	VEOR XTMP3.B16, XTMP5.B16, XTMP3.B16

	VMOV XTMP3.S[1], XDIGEST.S[3]

	VLD1 (AX), [XTMP1.B16]
	VEOR XTMP1.B16, XDIGEST.B16, XDIGEST.B16
	VST1 [XDIGEST.B16], (AX)

	RET
