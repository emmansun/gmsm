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
#define t0 R14
#define t1 R15
#define t2 R16
#define t3 R17

DATA p256p<>+0x00(SB)/8, $0xffffffffffffffff
DATA p256p<>+0x08(SB)/8, $0xffffffff00000000
DATA p256p<>+0x10(SB)/8, $0xffffffffffffffff
DATA p256p<>+0x18(SB)/8, $0xfffffffeffffffff
DATA p256ordK0<>+0x00(SB)/8, $0x327f9e8872350975
DATA p256ord<>+0x00(SB)/8, $0x53bbf40939d54123
DATA p256ord<>+0x08(SB)/8, $0x7203df6b21c6052b
DATA p256ord<>+0x10(SB)/8, $0xffffffffffffffff
DATA p256ord<>+0x18(SB)/8, $0xfffffffeffffffff
DATA p256one<>+0x00(SB)/8, $0x0000000000000001
DATA p256one<>+0x08(SB)/8, $0x00000000ffffffff
DATA p256one<>+0x10(SB)/8, $0x0000000000000000
DATA p256one<>+0x18(SB)/8, $0x0000000100000000
GLOBL p256p<>(SB), RODATA, $32
GLOBL p256ordK0<>(SB), RODATA, $8
GLOBL p256ord<>(SB), RODATA, $32
GLOBL p256one<>(SB), RODATA, $32

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

/* ---------------------------------------*/
// func p256NegCond(val *p256Element, cond int)
TEXT ·p256NegCond(SB),NOSPLIT,$0
	MOVV val+0(FP), res_ptr
	MOVV cond+8(FP), t0
	// acc = poly
	MOVV $-1, acc0
	MOVV p256p<>+0x08(SB), acc1
	MOVV $-1, acc2
	MOVV p256p<>+0x18(SB), acc3
	// Load the original value
	MOVV (8*0)(res_ptr), acc4
	MOVV (8*1)(res_ptr), x_ptr
	MOVV (8*2)(res_ptr), y_ptr
	MOVV (8*3)(res_ptr), acc5

	// Speculatively subtract
	SUBV acc4, acc0
	SGTU x_ptr, acc1, t1
	SUBV x_ptr, acc1
	SUBV y_ptr, acc2
	SGTU t1, acc2, t2
	SUBV t1, acc2
	SUBV acc5, acc3
	SUBV t2, acc3

	MASKNEZ t0, acc4, acc4
	MASKEQZ t0, acc0, acc0
	OR acc4, acc0

	MASKNEZ t0, x_ptr, x_ptr
	MASKEQZ t0, acc1, acc1
	OR x_ptr, acc1

	MASKNEZ t0, y_ptr, y_ptr
	MASKEQZ t0, acc2, acc2
	OR y_ptr, acc2

	MASKNEZ t0, acc5, acc5
	MASKEQZ t0, acc3, acc3
	OR acc5, acc3

	MOVV acc0, (8*0)(res_ptr)
	MOVV acc1, (8*1)(res_ptr)
	MOVV acc2, (8*2)(res_ptr)
	MOVV acc3, (8*3)(res_ptr)

	RET
