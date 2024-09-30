// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"

DATA ·rcon+0x00(SB)/8, $0x0706050403020100 // Permute for vector doubleword endian swap
DATA ·rcon+0x08(SB)/8, $0x0f0e0d0c0b0a0908
DATA ·rcon+0x10(SB)/8, $0x0f0f0f0f0f0f0f0f // bit_reverse_and_table
DATA ·rcon+0x18(SB)/8, $0x0f0f0f0f0f0f0f0f
DATA ·rcon+0x20(SB)/8, $0x0008040c020a060e // bit_reverse_table_l
DATA ·rcon+0x28(SB)/8, $0x0109050d030b070f // bit_reverse_table_l
DATA ·rcon+0x30(SB)/8, $0x0000000010111213 // data mask
DATA ·rcon+0x38(SB)/8, $0x0000000014151617 // data mask
DATA ·rcon+0x40(SB)/8, $0x0000000018191a1b // data mask
DATA ·rcon+0x48(SB)/8, $0x000000001c1d1e1f // data mask
DATA ·rcon+0x50(SB)/8, $0x0405060708090a0b // ks mask
DATA ·rcon+0x58(SB)/8, $0x0001020304050607 // ks mask
GLOBL ·rcon(SB), RODATA, $96

#define XTMP1 V0
#define XTMP2 V1
#define XTMP3 V2
#define XTMP4 V3
#define XDATA V6
#define XDIGEST V7
#define KS_L V8
#define KS_M1 V9
#define BIT_REV_TAB_L V12
#define BIT_REV_TAB_H V13
#define BIT_REV_AND_TAB V14

#define PTR R7

// func eia3Round16B(t *uint32, keyStream *uint32, p *byte, tagSize int)
TEXT ·eia3Round16B(SB),NOSPLIT,$0
	MOVD t+0(FP), R3
	MOVD ks+8(FP), R4
	MOVD p+16(FP), R5

#ifndef GOARCH_ppc64le
	MOVD	$·rcon(SB), PTR // PTR points to rcon addr
	LVX	(PTR), XTMP1
	ADD	$0x10, PTR
#else
	MOVD	$·rcon+0x10(SB), PTR // PTR points to rcon addr (skipping permute vector)
#endif

	LXVD2X (R5)(R0), XDATA
#ifndef GOARCH_ppc64le
	VPERM XDATA, XDATA, XTMP1, XDATA
#endif

	LXVD2X (PTR)(R0), BIT_REV_AND_TAB
	VAND	BIT_REV_AND_TAB, XDATA, XTMP3
	VSPLTISB $4, XTMP2;
	VSRB	XDATA, XTMP2, XTMP1
	VAND	BIT_REV_AND_TAB, XTMP1, XTMP1

	MOVD	$0x10, R8
	LXVD2X (PTR)(R8), BIT_REV_TAB_L
	VSLB  BIT_REV_TAB_L, XTMP2, BIT_REV_TAB_H
	VPERM BIT_REV_TAB_L, BIT_REV_TAB_L, XTMP1, XTMP1
	VPERM BIT_REV_TAB_H, BIT_REV_TAB_H, XTMP3, XTMP3
	VXOR XTMP1, XTMP3, XTMP3 // XTMP3 - bit reverse data bytes

	// ZUC authentication part, 4x32 data bits
	// setup data
	VSPLTISB $0, XTMP2
	MOVD $0x20, R8
	LXVD2X (PTR)(R8), XTMP4
	VPERM XTMP2, XTMP3, XTMP4, XTMP1
	MOVD $0x30, R8
	LXVD2X (PTR)(R8), XTMP4
	VPERM XTMP2, XTMP3, XTMP4, XTMP2

	// setup KS
	LXVW4X (R4), KS_L
	MOVD $8, R8
	LXVW4X (R8)(R4), KS_M1
	MOVD $0x40, R8
	LXVD2X (PTR)(R8), XTMP1
	VPERM KS_L, KS_L, XTMP1, KS_L
	VPERM KS_M1, KS_M1, XTMP1, KS_M1

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
