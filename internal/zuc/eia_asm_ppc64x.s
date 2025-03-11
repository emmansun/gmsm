// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"

DATA eia_const<>+0x00(SB)/8, $0x0706050403020100 // Permute for vector doubleword endian swap
DATA eia_const<>+0x08(SB)/8, $0x0f0e0d0c0b0a0908
DATA eia_const<>+0x10(SB)/8, $0x0008040c020a060e // bit_reverse_table_l
DATA eia_const<>+0x18(SB)/8, $0x0109050d030b070f // bit_reverse_table_l
DATA eia_const<>+0x20(SB)/8, $0x0000000010111213 // data mask
DATA eia_const<>+0x28(SB)/8, $0x0000000014151617 // data mask
DATA eia_const<>+0x30(SB)/8, $0x0000000018191a1b // data mask
DATA eia_const<>+0x38(SB)/8, $0x000000001c1d1e1f // data mask
DATA eia_const<>+0x40(SB)/8, $0x0405060708090a0b // ks mask
DATA eia_const<>+0x48(SB)/8, $0x0001020304050607 // ks mask
GLOBL eia_const<>(SB), RODATA, $80

#define XTMP1 V0
#define XTMP2 V1
#define XTMP3 V2
#define XTMP4 V3
#define XTMP5 V4
#define XTMP6 V5
#define XDATA V6
#define XDIGEST V7
#define KS_L V8
#define KS_M1 V9
#define KS_M2 V10
#define KS_H V11
#define BIT_REV_TAB_L V12
#define BIT_REV_TAB_H V13
#define ZERO V15
#define PTR R7

#define BIT_REVERSE(addr, IN, OUT, XTMP) \
	LXVD2X (addr)(R0), BIT_REV_TAB_L     \
	VSPLTISB $4, XTMP                    \
	VSLB  BIT_REV_TAB_L, XTMP, BIT_REV_TAB_H  \
	VPERMXOR BIT_REV_TAB_L, BIT_REV_TAB_H, IN, OUT

// func eiaRoundTag4(t *uint32, keyStream *uint32, p *byte)
TEXT ·eiaRoundTag4(SB),NOSPLIT,$0
	MOVD t+0(FP), R3
	MOVD ks+8(FP), R4
	MOVD p+16(FP), R5

#ifndef GOARCH_ppc64le
	MOVD	$eia_const<>(SB), PTR
	LVX	(PTR), XTMP1
	ADD	$0x10, PTR
#else
	MOVD	$eia_const<>+0x10(SB), PTR
#endif

	LXVD2X (R5)(R0), XDATA
#ifndef GOARCH_ppc64le
	VPERM XDATA, XDATA, XTMP1, XDATA
#endif

	BIT_REVERSE(PTR, XDATA, XTMP3, XTMP2)

	// ZUC authentication part, 4x32 data bits
	// setup data
	VSPLTISB $0, XTMP2
	MOVD $0x10, R8
	LXVD2X (PTR)(R8), XTMP4
	VPERM XTMP2, XTMP3, XTMP4, XTMP1
	MOVD $0x20, R8
	LXVD2X (PTR)(R8), XTMP4
	VPERM XTMP2, XTMP3, XTMP4, XTMP2

	// setup KS
	LXVW4X (R4), KS_L
	MOVD $8, R8
	LXVW4X (R8)(R4), KS_M1
	// load ks mask
	MOVD $0x30, R8
	LXVD2X (PTR)(R8), XTMP4
	VPERM KS_L, KS_L, XTMP4, KS_L
	VPERM KS_M1, KS_M1, XTMP4, KS_M1

	// clmul
	// xor the results from 4 32-bit words together
	// Calculate lower 32 bits of tag
	VPMSUMD XTMP1, KS_L, XTMP3
	VPMSUMD XTMP2, KS_M1, XTMP4
	VXOR XTMP3, XTMP4, XTMP3
	VSPLTW $2, XTMP3, XDIGEST

	// Update tag
	MFVSRWZ XDIGEST, R8
	MOVWZ (R3), R6
	XOR R6, R8, R6 
	MOVW R6, (R3)

	// Copy last 16 bytes of KS to the front
	MOVD $16, R8
	LXVD2X (R8)(R4), XTMP1
	STXVD2X XTMP1, (R4)(R0)

	RET

// func eia256RoundTag8(t *uint32, keyStream *uint32, p *byte)
TEXT ·eia256RoundTag8(SB),NOSPLIT,$0
	MOVD t+0(FP), R3
	MOVD ks+8(FP), R4
	MOVD p+16(FP), R5

#ifndef GOARCH_ppc64le
	MOVD	$eia_const<>(SB), PTR
	LVX	(PTR), XTMP1
	ADD	$0x10, PTR
#else
	MOVD	$eia_const<>+0x10(SB), PTR
#endif

	LXVD2X (R5)(R0), XDATA
#ifndef GOARCH_ppc64le
	VPERM XDATA, XDATA, XTMP1, XDATA
#endif

	BIT_REVERSE(PTR, XDATA, XTMP3, XTMP2)
	
	// ZUC authentication part, 4x32 data bits
	// setup data
	VSPLTISB $0, ZERO
	MOVD $0x10, R8
	LXVD2X (PTR)(R8), XTMP4
	VPERM ZERO, XTMP3, XTMP4, XTMP1
	MOVD $0x20, R8
	LXVD2X (PTR)(R8), XTMP4
	VPERM ZERO, XTMP3, XTMP4, XTMP2

	// setup KS
	LXVW4X (R4), KS_L
	MOVD $8, R8
	LXVW4X (R8)(R4), KS_M1
	MOVD $16, R8
	LXVW4X (R8)(R4), KS_M2
	MOVD $0x30, R8
	LXVD2X (PTR)(R8), XTMP4
	VPERM KS_L, KS_L, XTMP4, KS_L
	VPERM KS_M1, KS_M1, XTMP4, KS_M1
	VPERM KS_M2, KS_M2, XTMP4, KS_M2

	// clmul
	// xor the results from 4 32-bit words together
	// Calculate lower 32 bits of tag
	VPMSUMD XTMP1, KS_L, XTMP3
	VPMSUMD XTMP2, KS_M1, XTMP4
	VXOR XTMP3, XTMP4, XTMP3
	VSPLTW $2, XTMP3, XDIGEST

	// Calculate upper 32 bits of tag
	VSLDOI $8, KS_M1, KS_L, KS_L
	VPMSUMD XTMP1, KS_L, XTMP3
	VSLDOI $8, KS_M2, KS_M1, KS_M1
	VPMSUMD XTMP2, KS_M1, XTMP4
	VXOR XTMP3, XTMP4, XTMP3
	VSPLTW $2, XTMP3, XTMP3

	// Update tag
#ifdef GOARCH_ppc64le
	VSLDOI $12, XTMP3, XDIGEST, XDIGEST
#else
	VSLDOI $12, XDIGEST, XTMP3, XDIGEST
#endif
	MFVSRD XDIGEST, R8
	MOVD (R3), R6
	XOR R6, R8, R6
	MOVD R6, (R3)

	// Copy last 16 bytes of KS to the front
	MOVD $16, R8
	LXVD2X (R8)(R4), XTMP1
	STXVD2X XTMP1, (R4)(R0)

	RET

// func eia256RoundTag16(t *uint32, keyStream *uint32, p *byte)
TEXT ·eia256RoundTag16(SB),NOSPLIT,$0
	MOVD t+0(FP), R3
	MOVD ks+8(FP), R4
	MOVD p+16(FP), R5

#ifndef GOARCH_ppc64le
	MOVD	$eia_const<>(SB), PTR
	LVX	(PTR), XTMP1
	ADD	$0x10, PTR
#else
	MOVD	$eia_const<>+0x10(SB), PTR
#endif

	LXVD2X (R5)(R0), XDATA
#ifndef GOARCH_ppc64le
	VPERM XDATA, XDATA, XTMP1, XDATA
#endif

	BIT_REVERSE(PTR, XDATA, XTMP3, XTMP2)

	// ZUC authentication part, 4x32 data bits
	// setup data
	VSPLTISB $0, ZERO
	MOVD $0x10, R8
	LXVD2X (PTR)(R8), XTMP4
	VPERM ZERO, XTMP3, XTMP4, XTMP1
	MOVD $0x20, R8
	LXVD2X (PTR)(R8), XTMP4
	VPERM ZERO, XTMP3, XTMP4, XTMP2

	// setup KS
	LXVW4X (R4), KS_L
	MOVD $8, R8
	LXVW4X (R8)(R4), KS_M1
	MOVD $16, R8
	LXVW4X (R8)(R4), KS_M2
	VOR KS_M2, KS_M2, KS_H
	MOVD $0x30, R8
	LXVD2X (PTR)(R8), XTMP4
	VPERM KS_L, KS_L, XTMP4, KS_L
	VPERM KS_M1, KS_M1, XTMP4, KS_M1
	VPERM KS_M2, KS_M2, XTMP4, KS_M2

	// clmul
	// xor the results from 4 32-bit words together
	// Calculate lower 32 bits of tag
	VPMSUMD XTMP1, KS_L, XTMP3
	VPMSUMD XTMP2, KS_M1, XTMP4
	VXOR XTMP3, XTMP4, XTMP3
	VSLDOI $12, XTMP3, XTMP3, XDIGEST

	// Calculate upper 32 bits of tag
	VSLDOI $8, KS_M1, KS_L, KS_L
	VPMSUMD XTMP1, KS_L, XTMP3
	VSLDOI $8, KS_M2, KS_M1, XTMP5
	VPMSUMD XTMP2, XTMP5, XTMP4
	VXOR XTMP3, XTMP4, XTMP3
	VSLDOI $8, XTMP3, XTMP3, XTMP3
	VSLDOI $4, XDIGEST, XTMP3, XDIGEST

	// calculate bits 95-64 of tag
	VPMSUMD XTMP1, KS_M1, XTMP3
	VPMSUMD XTMP2, KS_M2, XTMP4
	VXOR XTMP3, XTMP4, XTMP3
	VSLDOI $8, XTMP3, XTMP3, XTMP3
	VSLDOI $4, XDIGEST, XTMP3, XDIGEST

	// calculate bits 127-96 of tag
	VSLDOI $8, KS_M2, KS_M1, KS_M1
	VPMSUMD XTMP1, KS_M1, XTMP3
	VSLDOI $8, KS_H, KS_M2, KS_M2
	VPMSUMD XTMP2, KS_M2, XTMP4
	VXOR XTMP3, XTMP4, XTMP3
	VSLDOI $8, XTMP3, XTMP3, XTMP3
	VSLDOI $4, XDIGEST, XTMP3, XDIGEST

	// Update tag
	LXVW4X (R3)(R0), XTMP1
	VXOR XTMP1, XDIGEST, XDIGEST
	STXVW4X XDIGEST, (R3)

	// Copy last 16 bytes of KS to the front
	MOVD $16, R8
	LXVD2X (R8)(R4), XTMP1
	STXVD2X XTMP1, (R4)(R0)

	RET
