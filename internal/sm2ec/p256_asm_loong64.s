// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

#define res_ptr R29
#define x_ptr R30
#define y_ptr R31

#define acc0 R8
#define acc1 R9
#define acc2 R10
#define acc3 R11
#define acc4 R12
#define acc5 R13

/* ---------------------------------------*/
// func p256OrdLittleToBig(res *[32]byte, in *p256OrdElement)
TEXT ·p256OrdLittleToBig(SB),NOSPLIT,$0
	JMP ·p256BigToLittle(SB)
/* ---------------------------------------*/
// func p256OrdBigToLittle(res *p256OrdElement, in *[32]byte)
TEXT ·p256OrdBigToLittle(SB),NOSPLIT,$0
	JMP ·p256BigToLittle(SB)
/* ---------------------------------------*/
// func p256LittleToBig(res *[32]byte, in *p256Element)
TEXT ·p256LittleToBig(SB),NOSPLIT,$0
	JMP ·p256BigToLittle(SB)
/* ---------------------------------------*/
// func p256BigToLittle(res *p256Element, in *[32]byte)
TEXT ·p256BigToLittle(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV in+8(FP), x_ptr

	MOVV (8*0)(x_ptr), acc0
	MOVV (8*1)(x_ptr), acc1
	MOVV (8*2)(x_ptr), acc2
	MOVV (8*3)(x_ptr), acc3

	REVBV acc0, acc0
	REVBV acc1, acc1
	REVBV acc2, acc2
	REVBV acc3, acc3

	MOVV acc3, (8*0)(res_ptr)
	MOVV acc2, (8*1)(res_ptr)
	MOVV acc1, (8*2)(res_ptr)
	MOVV acc0, (8*3)(res_ptr)

	RET
