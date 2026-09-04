// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

#define ZERO X0
#define RSP X2

// func mul2Asm(tweak *[blockSize]byte)
TEXT ·mul2Asm(SB),NOSPLIT,$0
	MOV tweak+0(FP), X10
	VSETIVLI	$2, E64, M1, TA, MA, X0
	VLE64V (X10), V1

	// Multiply by 2 in GF(2^128) with the polynomial x^128 + x^7 + x^2 + x + 1
	VSLLVI $1, V1, V2
	VSRLVI $63, V1, V3
	VSLIDE1UPVX ZERO, V3, V4
	VORVV V2, V4, V2

	// Generate mask for reduction: if the most significant bit of the original tweak was 1, we need to XOR with the polynomial.
	VSLIDEDOWNVI $1, V3, V5
	VMSNEVI $0, V5, V0

	MOV $0x87, X11
	VMVSX X11, V6
	VXORVV V2, V6, V0, V2

	VSE64V V2, (X10)
	RET
