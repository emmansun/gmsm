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

/* ---------------------------------------*/
// func p256NegCond(val *p256Element, cond int)
TEXT ·p256NegCond(SB),NOSPLIT,$0
	MOVV val+0(FP), res_ptr
	MOVV cond+8(FP), t0

	// acc = poly
	MOV $-1, acc0
	MOV p256p<>+0x08(SB), acc1
	MOV $-1, acc2
	MOV p256p<>+0x18(SB), acc3
	// Load the original value
	MOV (8*0)(res_ptr), acc4
	MOV (8*1)(res_ptr), x_ptr
	MOV (8*2)(res_ptr), y_ptr
	MOV (8*3)(res_ptr), acc5

	// Speculatively subtract
	SUB acc4, acc0
	SLTU x_ptr, acc1, t1
	SUB x_ptr, acc1
	SUB y_ptr, acc2
	SLTU t1, acc2, t2
	SUB t1, acc2
	SUB acc5, acc3
	SUB t2, acc3

	SLTU t0, ZERO, t0
	SUB $1, t0, t0        // mask = -cond
	XOR $-1, t0, t1        // t1 = ~mask

	AND acc4, t0, acc4
	AND acc0, t1, acc0
	OR acc4, acc0, acc0
	AND x_ptr, t0, x_ptr
	AND acc1, t1, acc1
	OR x_ptr, acc1, acc1
	AND y_ptr, t0, y_ptr
	AND acc2, t1, acc2
	OR y_ptr, acc2, acc2
	AND acc5, t0, acc5
	AND acc3, t1, acc3
	OR acc5, acc3, acc3

	MOV acc0, (8*0)(res_ptr)
	MOV acc1, (8*1)(res_ptr)
	MOV acc2, (8*2)(res_ptr)
	MOV acc3, (8*3)(res_ptr)

	RET

/* ---------------------------------------*/
// func p256MovCond(res, a, b *SM2P256Point, cond int)
TEXT ·p256MovCond(SB),NOSPLIT,$0
	MOV res+0(FP), res_ptr
	MOV a+8(FP), x_ptr
	MOV b+16(FP), y_ptr
	MOV cond+24(FP), t0

	SLTU t0, ZERO, t0
	SUB $1, t0, t0        // mask = -cond
	XOR $-1, t0, t1        // t1 = ~mask

	// Load a.x
	MOV (8*0)(x_ptr), acc0
	MOV (8*1)(x_ptr), acc1
	MOV (8*2)(x_ptr), acc2
	MOV (8*3)(x_ptr), acc3

	// Load b.x
	MOV (8*0)(y_ptr), acc4
	MOV (8*1)(y_ptr), acc5
	MOV (8*2)(y_ptr), acc6
	MOV (8*3)(y_ptr), acc7

	// Conditional move
	AND acc4, t0, acc4
	AND acc0, t1, acc0
	OR acc4, acc0, acc0
	AND acc5, t0, acc5
	AND acc1, t1, acc1
	OR acc5, acc1, acc1
	AND acc6, t0, acc6
	AND acc2, t1, acc2
	OR acc6, acc2, acc2
	AND acc7, t0, acc7
	AND acc3, t1, acc3
	OR acc7, acc3, acc3
	
	// Store res.x
	MOV acc0, (8*0)(res_ptr)
	MOV acc1, (8*1)(res_ptr)
	MOV acc2, (8*2)(res_ptr)
	MOV acc3, (8*3)(res_ptr)

	// Load a.y
	MOV (8*4)(x_ptr), acc0
	MOV (8*5)(x_ptr), acc1
	MOV (8*6)(x_ptr), acc2
	MOV (8*7)(x_ptr), acc3

	// Load b.y
	MOV (8*4)(y_ptr), acc4
	MOV (8*5)(y_ptr), acc5
	MOV (8*6)(y_ptr), acc6
	MOV (8*7)(y_ptr), acc7

	// Conditional move
	AND acc4, t0, acc4
	AND acc0, t1, acc0
	OR acc4, acc0, acc0
	AND acc5, t0, acc5
	AND acc1, t1, acc1
	OR acc5, acc1, acc1
	AND acc6, t0, acc6
	AND acc2, t1, acc2
	OR acc6, acc2, acc2
	AND acc7, t0, acc7
	AND acc3, t1, acc3
	OR acc7, acc3, acc3

	// Store res.y
	MOV acc0, (8*4)(res_ptr)
	MOV acc1, (8*5)(res_ptr)
	MOV acc2, (8*6)(res_ptr)
	MOV acc3, (8*7)(res_ptr)

	MOV (8*8)(x_ptr), acc0
	MOV (8*9)(x_ptr), acc1
	MOV (8*10)(x_ptr), acc2
	MOV (8*11)(x_ptr), acc3

	MOV (8*8)(y_ptr), acc4
	MOV (8*9)(y_ptr), acc5
	MOV (8*10)(y_ptr), acc6
	MOV (8*11)(y_ptr), acc7

	// Conditional move
	AND acc4, t0, acc4
	AND acc0, t1, acc0
	OR acc4, acc0, acc0
	AND acc5, t0, acc5
	AND acc1, t1, acc1
	OR acc5, acc1, acc1
	AND acc6, t0, acc6
	AND acc2, t1, acc2
	OR acc6, acc2, acc2
	AND acc7, t0, acc7
	AND acc3, t1, acc3
	OR acc7, acc3, acc3

	// Store res.z
	MOV acc0, (8*8)(res_ptr)
	MOV acc1, (8*9)(res_ptr)
	MOV acc2, (8*10)(res_ptr)
	MOV acc3, (8*11)(res_ptr)

	RET
