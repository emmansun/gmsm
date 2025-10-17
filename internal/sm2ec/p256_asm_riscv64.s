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
	MOV val+0(FP), res_ptr
	MOV cond+8(FP), t0

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

/* ---------------------------------------*/
// (y3, y2, y1, y0) = (x3, x2, x1, x0) * (y3, y2, y1, y0)
TEXT sm2P256MulInternal<>(SB),NOSPLIT,$0
	// y[0] * x
	MUL y0, x0, acc0
	MULHU	y0, x0, acc4
	MUL y0, x1, acc1
	MULHU y0, x1, acc5
	MUL y0, x2, acc2
	MULHU y0, x2, acc6
	MUL y0, x3, acc3
	MULHU y0, x3, acc7

	// ADDS acc4, acc1
	ADD acc1, acc4, acc1
	SLTU acc4, acc1, t0
	// ADCS acc5, acc2
	ADD t0, acc5, acc5    // no carry
	ADD acc2, acc5, acc2
	SLTU acc5, acc2, t0
	// ADCS acc6, acc3
	ADD t0, acc6, acc6    // no carry
	ADD acc3, acc6, acc3
	SLTU acc6, acc3, t0
	// ADC $0, acc7, acc4
	ADD t0, acc7, acc4    // no carry
	// First reduction step
	SLL $32, acc0, t0
	SRL $32, acc0, t1

	// SUBS t0, acc1
	SLTU t0, acc1, t2
	SUB t0, acc1
	// SUBCS t1, acc2
	ADD t2, t1, hlp0        // no carry
	SLTU hlp0, acc2, t2
	SUB hlp0, acc2
	// SUBCS t0, acc3
	ADD t2, t0, t2        // no carry
	SLTU t2, acc3, hlp0
	SUB t2, acc3, acc3
	// SUBC t1, acc0, t2
	SUB t1, acc0, t2      // no borrow
	SUB hlp0, t2, t2      // no borrow

	// ADDS acc0, acc1
	ADD acc0, acc1, acc1
	SLTU acc0, acc1, t0
	// ADCS $0, acc2
	ADD t0, acc2, acc2
	SLTU t0, acc2, t1
	// ADCS $0, acc3
	ADD t1, acc3, acc3
	SLTU t1, acc3, t0
	// ADC $0, t2, acc0
	ADD t0, t2, acc0      // (acc1, acc2, acc3, acc0) is the result

	// y[1] * x
	MUL y1, x0, t0
	// ADDS t0, acc1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t2
	MULHU y1, x0, t1

	MUL y1, x1, t0
	// ADCS t0, acc2
	ADD t0, acc2, acc2
	SLTU t0, acc2, t3
	ADD t2, acc2, acc2
	SLTU t2, acc2, hlp0
	OR t3, hlp0, t2
	MULHU y1, x1, y0

	MUL y1, x2, t0
	// ADCS t0, acc3
	ADD t0, acc3, acc3
	SLTU t0, acc3, t3
	ADD t2, acc3, acc3
	SLTU t2, acc3, hlp0
	OR t3, hlp0, t2
	MULHU y1, x2, acc6

	MUL y1, x3, t0
	// ADCS t0, acc4
	ADD t0, acc4, acc4
	SLTU t0, acc4, t3
	ADD t2, acc4, acc4
	SLTU t2, acc4, hlp0
	OR t3, hlp0, acc5
	MULHU y1, x3, acc7

	// ADDS	t1, acc2
	ADD t1, acc2, acc2
	SLTU t1, acc2, t2
	// ADCS	y0, acc3
	ADD y0, acc3, acc3
	SLTU y0, acc3, t3
	ADD t2, acc3, acc3
	SLTU t2, acc3, hlp0
	OR t3, hlp0, t2
	// ADCS	acc6, acc4
	ADD acc6, acc4, acc4
	SLTU acc6, acc4, t3
	ADD t2, acc4, acc4
	SLTU t2, acc4, hlp0
	OR t3, hlp0, t2
	// ADC	acc7, acc5
	ADD t2, acc5, acc5
	ADD acc7, acc5, acc5

	// Second reduction step
	SLL $32, acc1, t0
	SRL $32, acc1, t1

	// SUBS t0, acc2
	SLTU t0, acc2, t2
	SUB t0, acc2
	// SUBCS t1, acc3
	ADD t2, t1, t3        // no carry
	SLTU t3, acc3, t2
	SUB t3, acc3
	// SUBCS t0, acc0
	ADD t2, t0, t2        // no carry
	SLTU t2, acc0, t3
	SUB t2, acc0, acc0
	// SUBC t1, acc1, t2
	SUB t1, acc1, t2      // no borrow
	SUB t3, t2, t2        // no borrow

	// ADDS acc1, acc2
	ADD acc1, acc2, acc2
	SLTU acc1, acc2, t0
	// ADCS $0, acc3
	ADD t0, acc3, acc3
	SLTU t0, acc3, t1
	// ADCS $0, acc0
	ADD t1, acc0, acc0
	SLTU t1, acc0, t0
	// ADC $0, t2, acc1
	ADD t0, t2, acc1      // (acc2, acc3, acc0, acc1) is the result

	// y[2] * x
	MUL y2, x0, t0
	// ADDS t0, acc2
	ADD t0, acc2, acc2
	SLTU t0, acc2, t2
	MULHU y2, x0, t1

	MUL y2, x1, t0
	// ADCS t0, acc3
	ADD t0, acc3, acc3
	SLTU t0, acc3, t3
	ADD t2, acc3, acc3
	SLTU t2, acc3, hlp0
	OR t3, hlp0, t2
	MULHU y2, x1, y0

	MUL y2, x2, t0
	// ADCS t0, acc0
	ADD t0, acc0, acc0
	SLTU t0, acc0, t3
	ADD t2, acc0, acc0
	SLTU t2, acc0, hlp0
	OR t3, hlp0, t2
	MULHU y2, x2, y1

	MUL y2, x3, t0
	// ADCS t0, acc1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t3
	ADD t2, acc1, acc1
	SLTU t2, acc1, hlp0
	OR t3, hlp0, acc6
	MULHU y2, x3, acc7

	// ADDS	t1, acc3
	ADD t1, acc3, acc3
	SLTU t1, acc3, t2
	// ADCS	y0, acc4
	ADD y0, acc4, acc4
	SLTU y0, acc4, t3
	ADD t2, acc4, acc4
	SLTU t2, acc4, hlp0
	OR t3, hlp0, t2
	// ADCS	y1, acc5
	ADD y1, acc5, acc5
	SLTU y1, acc5, t3
	ADD t2, acc5, acc5
	SLTU t2, acc5, hlp0
	OR t3, hlp0, t2
	// ADC	acc7, acc6
	ADD t2, acc6, acc6
	ADD acc7, acc6, acc6

	// Third reduction step
	SLL $32, acc2, t0
	SRL $32, acc2, t1

	// SUBS t0, acc3
	SLTU t0, acc3, t2
	SUB t0, acc3
	// SUBCS t1, acc0
	ADD t2, t1, t3        // no carry
	SLTU t3, acc0, t2
	SUB t3, acc0
	// SUBCS t0, acc1
	ADD t2, t0, t2        // no carry
	SLTU t2, acc1, t3
	SUB t2, acc1, acc1	
	// SUBC t1, acc2, t2
	SUB t1, acc2, t2      // no borrow
	SUB t3, t2, t2        // no borrow

	// ADDS acc2, acc3
	ADD acc2, acc3, acc3
	SLTU acc2, acc3, t0
	// ADCS $0, acc0
	ADD t0, acc0, acc0
	SLTU t0, acc0, t1
	// ADCS $0, acc1
	ADD t1, acc1, acc1
	SLTU t1, acc1, t0
	// ADC $0, t2, acc2
	ADD t0, t2, acc2      // (acc3, acc0, acc1, acc2) is the result

	// y[2] * x
	MUL y3, x0, t0
	// ADDS t0, acc3
	ADD t0, acc3, acc3
	SLTU t0, acc3, t2
	MULHU y3, x0, t1

	MUL y3, x1, t0
	// ADCS t0, acc4
	ADD t0, acc4, acc4
	SLTU t0, acc4, t3
	ADD t2, acc4, acc4
	SLTU t2, acc4, hlp0
	OR t3, hlp0, t2
	MULHU y3, x1, y0

	MUL y3, x2, t0
	// ADCS t0, acc5
	ADD t0, acc5, acc5
	SLTU t0, acc5, t3
	ADD t2, acc5, acc5	
	SLTU t2, acc5, hlp0
	OR t3, hlp0, t2
	MULHU y3, x2, y1

	MUL y3, x3, t0
	// ADCS t0, acc6
	ADD t0, acc6, acc6
	SLTU t0, acc6, t3
	ADD t2, acc6, acc6
	SLTU t2, acc6, hlp0
	OR t3, hlp0, acc7
	MULHU y3, x3, t0

	// ADDS	t1, acc4
	ADD t1, acc4, acc4
	SLTU t1, acc4, t2
	// ADCS	y0, acc5
	ADD y0, acc5, acc5
	SLTU y0, acc5, t3
	ADD t2, acc5, acc5
	SLTU t2, acc5, hlp0
	OR t3, hlp0, t2
	// ADCS	y1, acc6
	ADD y1, acc6, acc6
	SLTU y1, acc6, t3
	ADD t2, acc6, acc6
	SLTU t2, acc6, hlp0
	OR t3, hlp0, t2
	// ADC	t0, acc7
	ADD t2, acc7, acc7
	ADD t0, acc7, acc7

	// Fourth reduction step
	SLL $32, acc3, t0
	SRL $32, acc3, t1

	// SUBS t0, acc0
	SLTU t0, acc0, t2
	SUB t0, acc0
	// SUBCS t1, acc1
	ADD t2, t1, t3        // no carry
	SLTU t3, acc1, t2
	SUB t3, acc1
	// SUBCS t0, acc2
	ADD t2, t0, t2        // no carry
	SLTU t2, acc2, t3
	SUB t2, acc2, acc2
	// SUBC t1, acc3, t2
	SUB t1, acc3, t2      // no borrow
	SUB t3, t2, t2        // no borrow

	// ADDS acc3, acc0
	ADD acc3, acc0, acc0
	SLTU acc3, acc0, t0
	// ADCS $0, acc1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t1
	// ADCS $0, acc2
	ADD t1, acc2, acc2
	SLTU t1, acc2, t0
	// ADC $0, t2, acc3
	ADD t0, t2, acc3      // (acc0, acc1, acc2, acc3) is the result

	// Add bits [511:256] of the mul result
	ADD acc4, acc0, y0
	SLTU acc4, y0, t0
	ADD acc5, acc1, y1
	SLTU acc5, y1, t1
	ADD t0, y1, y1
	SLTU t0, y1, t2
	OR t1, t2, t0
	ADD acc6, acc2, y2
	SLTU acc6, y2, t1
	ADD t0, y2, y2
	SLTU t0, y2, t2
	OR t1, t2, t0
	ADD acc7, acc3, y3
	SLTU acc7, y3, t1
	ADD t0, y3, y3
	SLTU t0, y3, t2
	OR t1, t2, t0

	// Final reduction
	ADD $1, y0, acc4
	SLTU y0, acc4, t1
	ADD const0, t1, t1           // no carry
	ADD y1, t1, acc5
	SLTU y1, acc5, t3
	ADD t3, y2, acc6
	SLTU y2, acc6, hlp0
	ADD $1, hlp0, hlp0           // no carry
	ADD hlp0, const0, t2         // no carry
	ADD y3, t2, acc7
	SLTU y3, acc7, hlp0
	OR t0, hlp0, t0

	SUB $1, t0, t0        // mask = -cond
	XOR $-1, t0, t1        // t1 = ~mask

	AND t0, y0, y0
	AND t1, acc4, acc4
	OR acc4, y0

	AND t0, y1, y1
	AND t1, acc5, acc5
	OR acc5, y1

	AND t0, y2, y2
	AND t1, acc6, acc6
	OR acc6, y2

	AND t0, y3, y3
	AND t1, acc7, acc7
	OR acc7, y3

	RET

/* ---------------------------------------*/
// func p256Mul(res, in1, in2 *p256Element)
TEXT ·p256Mul(SB),NOSPLIT,$0
	MOV res+0(FP), res_ptr
	MOV in1+8(FP), x_ptr
	MOV in2+16(FP), y_ptr

	MOV p256one<>+0x08(SB), const0

	MOV (8*0)(x_ptr), x0
	MOV (8*1)(x_ptr), x1
	MOV (8*2)(x_ptr), x2
	MOV (8*3)(x_ptr), x3

	MOV (8*0)(y_ptr), y0
	MOV (8*1)(y_ptr), y1
	MOV (8*2)(y_ptr), y2
	MOV (8*3)(y_ptr), y3

	CALL sm2P256MulInternal<>(SB)

	MOV y0, (8*0)(res_ptr)
	MOV y1, (8*1)(res_ptr)
	MOV y2, (8*2)(res_ptr)
	MOV y3, (8*3)(res_ptr)

	RET
