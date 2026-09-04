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
	VSETIVLI	$4, E32, M1, TA, MA, X0
	VLE32V (X10), V1

	// Multiply by 2 in GF(2^128) with the polynomial x^128 + x^7 + x^2 + x + 1
	VSLLVI $1, V1, V2
	VSRLVI $31, V1, V3
	VSLIDE1UPVX ZERO, V3, V4
	VORVV V2, V4, V2

	// Generate mask for reduction: if the most significant bit of the original tweak was 1, we need to XOR with the polynomial.
	VSRAVI $31, V1, V3
	VSLIDEDOWNVI $3, V3, V5

	MOV $0x87, X11
	VANDVX X11, V5, V5
	VXORVV V2, V5, V2

	VSE32V V2, (X10)
	RET

// func doubleTweaksAsm(tweak *[blockSize]byte, tweaks []byte)
TEXT ·doubleTweaksAsm(SB),NOSPLIT,$0
	MOV tweak+0(FP), X10
	MOV tweaks+8(FP), X11
	MOV tweaks_len+16(FP), X12

	SRL $4, X12
	BEQ X12, ZERO, end

	VSETIVLI	$4, E32, M1, TA, MA, X0
	// Prepare the polynomial for reduction
	MOV $0x87, X13

	VLE32V (X10), V1

loop:
	VSE32V V1, (X11)
	ADD $16, X11

	// Multiply by 2 in GF(2^128) with the polynomial x^128 + x^7 + x^2 + x + 1
	VSLLVI $1, V1, V2
	VSRLVI $31, V1, V3
	VSLIDE1UPVX ZERO, V3, V4
	VORVV V2, V4, V2

	// Generate mask for reduction: if the most significant bit of the original tweak was 1, we need to XOR with the polynomial.
	VSRAVI $31, V2, V3
	VSLIDEDOWNVI $3, V3, V5
	
	VANDVX X13, V5, V5
	VXORVV V2, V5, V1

	SUB $1, X12
	BNE X12, ZERO, loop

	VSE32V V1, (X10)
end: 
	RET
