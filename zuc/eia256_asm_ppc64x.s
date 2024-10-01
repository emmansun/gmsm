// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"

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
#define BIT_REV_AND_TAB V14
#define ZERO V15
#define PTR R7

// func eia256RoundTag8(t *uint32, keyStream *uint32, p *byte)
TEXT ·eia256RoundTag8(SB),NOSPLIT,$0
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
	VSRW	XDATA, XTMP2, XTMP1
	VAND	BIT_REV_AND_TAB, XTMP1, XTMP1

	MOVD	$0x10, R8
	LXVD2X (PTR)(R8), BIT_REV_TAB_L
	VSLB  BIT_REV_TAB_L, XTMP2, BIT_REV_TAB_H
	VPERM BIT_REV_TAB_L, BIT_REV_TAB_L, XTMP1, XTMP1
	VPERM BIT_REV_TAB_H, BIT_REV_TAB_H, XTMP3, XTMP3
	VXOR XTMP1, XTMP3, XTMP3 // XTMP3 - bit reverse data bytes

	// ZUC authentication part, 4x32 data bits
	// setup data
	VSPLTISB $0, ZERO
	MOVD $0x20, R8
	LXVD2X (PTR)(R8), XTMP4
	VPERM ZERO, XTMP3, XTMP4, XTMP1
	MOVD $0x30, R8
	LXVD2X (PTR)(R8), XTMP4
	VPERM ZERO, XTMP3, XTMP4, XTMP2

	// setup KS
	LXVW4X (R4), KS_L
	MOVD $8, R8
	LXVW4X (R8)(R4), KS_M1
	MOVD $16, R8
	LXVW4X (R8)(R4), KS_M2
	MOVD $0x40, R8
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
	VSPLTW $2, XTMP3, XTMP3, XTMP3
	VSLDOI $12, XDIGEST, XTMP3, XDIGEST

	// Update tag
	MFVSRD XDIGEST, R8
#ifdef GOARCH_ppc64le
	MOVDBR (R3), R6
	XOR R6, R8, R6
	MOVDBR R6, (R3)
#else
	MOVD (R3), R6
	XOR R6, R8, R6
	MOVD R6, (R3)
#endif

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
	VSRW	XDATA, XTMP2, XTMP1
	VAND	BIT_REV_AND_TAB, XTMP1, XTMP1

	MOVD	$0x10, R8
	LXVD2X (PTR)(R8), BIT_REV_TAB_L
	VSLB  BIT_REV_TAB_L, XTMP2, BIT_REV_TAB_H
	VPERM BIT_REV_TAB_L, BIT_REV_TAB_L, XTMP1, XTMP1
	VPERM BIT_REV_TAB_H, BIT_REV_TAB_H, XTMP3, XTMP3
	VXOR XTMP1, XTMP3, XTMP3 // XTMP3 - bit reverse data bytes

	// ZUC authentication part, 4x32 data bits
	// setup data
	VSPLTISB $0, ZERO
	MOVD $0x20, R8
	LXVD2X (PTR)(R8), XTMP4
	VPERM ZERO, XTMP3, XTMP4, XTMP1
	MOVD $0x30, R8
	LXVD2X (PTR)(R8), XTMP4
	VPERM ZERO, XTMP3, XTMP4, XTMP2

	// setup KS
	LXVW4X (R4), KS_L
	MOVD $8, R8
	LXVW4X (R8)(R4), KS_M1
	MOVD $16, R8
	LXVW4X (R8)(R4), KS_M2
	VOR KS_M2, KS_M2, KS_H
	MOVD $0x40, R8
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
