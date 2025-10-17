// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// X4 is TP（Thread Pointer), so we can't use it as a general purpose register.
#define ZERO X0
#define RSP X2
#define res_ptr X5
#define x_ptr X6
#define y_ptr X7
#define a_ptr x_ptr
#define b_ptr y_ptr

#define acc0 X8
#define acc1 X9
#define acc2 X10
#define acc3 X11

#define acc4 X12
#define acc5 X13
#define acc6 X14
#define acc7 X15

#define t0 X16
#define t1 X17
#define t2 X18
#define t3 X19

#define hlp0 X20
#define hlp1 res_ptr

#define x0 X21
#define x1 X22
#define x2 X23
#define x3 X24
#define y0 X25
#define y1 X26
#define y2 X28
#define y3 X29

#define const0 X31

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
	MOV res+0(FP), res_ptr
	MOV in+8(FP), x_ptr

	MOV (8*0)(x_ptr), acc0
	MOV (8*1)(x_ptr), acc1
	MOV (8*2)(x_ptr), acc2
	MOV (8*3)(x_ptr), acc3

	REV8 acc0, acc0
	REV8 acc1, acc1
	REV8 acc2, acc2
	REV8 acc3, acc3

	MOV acc3, (8*0)(res_ptr)
	MOV acc2, (8*1)(res_ptr)
	MOV acc1, (8*2)(res_ptr)
	MOV acc0, (8*3)(res_ptr)

	RET
