// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.
// Required riscv64 architecture extensions: Zbb (Bitmanip), M (Multiply/Divide)
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

#define const0 X30
#define const1 X31
#define const2 t2
#define const3 t3

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
DATA p256orderone<>+0x00(SB)/8, $0xac440bf6c62abedd
DATA p256orderone<>+0x08(SB)/8, $0x8dfc2094de39fad4
GLOBL p256p<>(SB), RODATA, $32
GLOBL p256ordK0<>(SB), RODATA, $8
GLOBL p256ord<>(SB), RODATA, $32
GLOBL p256one<>(SB), RODATA, $32
GLOBL p256orderone<>(SB), RODATA, $16

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

	REV8 acc0, acc0  // 28.4.2: Bitwise Rotation (Zbb)
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
	ADD hlp0, const1, t2         // no carry
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
	ADD $1, const0, const1

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

/* ---------------------------------------*/
// (y3, y2, y1, y0) = (x3, x2, x1, x0) ^ 2
TEXT sm2P256SqrInternal<>(SB),NOSPLIT,$0
	// x[1:] * x[0]
	MUL x0, x1, acc1
	MULHU x0, x1, acc2

	MUL x0, x2, t0
	// ADDS t0, acc2
	ADD t0, acc2, acc2
	SLTU t0, acc2, t1
	MULHU x0, x2, acc3

	MUL x0, x3, t0
	// ADCS t0, acc3
	ADD t1, acc3, acc3  // no carry
	ADD t0, acc3, acc3
	SLTU t0, acc3, t1
	MULHU x0, x3, acc4
	ADD t1, acc4, acc4  // no carry

	// x[2:] * x[1]
	MUL x1, x2, t0
	// ADDS t0, acc3
	ADD t0, acc3, acc3
	SLTU t0, acc3, t2
	MULHU x1, x2, t1
	// ADCS t1, acc4
	ADD t1, acc4, acc4
	SLTU t1, acc4, t3
	ADD t2, acc4, acc4
	SLTU t2, acc4, hlp0
	// ADC $0, acc5
	OR t3, hlp0, acc5

	MUL x1, x3, t0
	// ADCS t0, acc4
	ADD t0, acc4, acc4
	SLTU t0, acc4, t2
	MULHU x1, x3, t1
	// ADC	t1, acc5
	ADD t1, t2, t2       // no carry
	ADD t2, acc5, acc5   // no carry

	// x[3] * x[2]
	MUL x2, x3, t0
	// ADDS t0, acc5
	ADD t0, acc5, acc5
	SLTU t0, acc5, t1
	MULHU x2, x3, acc6
	// ADC	$0, acc6
	ADD t1, acc6, acc6   // no carry

	// *2
	SRL $63, acc1, t0
	SLL $1, acc1, acc1
	SRL $63, acc2, t1
	SLL $1, acc2, acc2
	ADD t0, acc2, acc2
	SRL $63, acc3, t2
	SLL $1, acc3, acc3
	ADD t1, acc3, acc3
	SRL $63, acc4, t3
	SLL $1, acc4, acc4
	ADD t2, acc4, acc4
	SRL $63, acc5, hlp0
	SLL $1, acc5, acc5
	ADD t3, acc5, acc5
	SRL $63, acc6, acc7
	SLL $1, acc6, acc6
	ADD hlp0, acc6, acc6

	// Missing products
	MUL x0, x0, acc0
	MULHU x0, x0, t0
	// ADDS t0, acc1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t1
	MUL x1, x1, t0
	// ADCS t0, acc2
	ADD t0, t1, t1       // no carry
	ADD t1, acc2, acc2
	SLTU t1, acc2, t2
	MULHU x1, x1, t0
	// ADCS t0, acc3
	ADD t0, t2, t2	      // no carry
	ADD t2, acc3, acc3
	SLTU t2, acc3, t1
	MUL x2, x2, t0
	// ADCS t0, acc4
	ADD t0, t1, t1       // no carry
	ADD t1, acc4, acc4
	SLTU t1, acc4, t2
	MULHU x2, x2, t0
	// ADCS t0, acc5
	ADD t0, t2, t2       // no carry
	ADD t2, acc5, acc5
	SLTU t2, acc5, t1
	MUL x3, x3, t0
	// ADCS t0, acc6
	ADD t0, t1, t1       // no carry
	ADD t1, acc6, acc6
	SLTU t1, acc6, t2
	MULHU x3, x3, t0
	// ADC	t0, acc7
	ADD t0, t2, t2       // no carry
	ADD t2, acc7, acc7   // (acc0, acc1, acc2, acc3, acc4, acc5, acc6, acc7) is the result
	
	// First reduction step
	SLL $32, acc0, t0
	SRL $32, acc0, t1

	// SUBS t0, acc1
	SLTU t0, acc1, t2
	SUB t0, acc1, acc1
	// SBCS t1, acc2
	ADD t2, t1, t2       // no carry
	SLTU t2, acc2, t3
	SUB t2, acc2, acc2
	// SBCS t0, acc3
	ADD t3, t0, t3       // no carry
	SLTU t3, acc3, t2
	SUB t3, acc3, acc3
	// SBC t1, acc0
	ADD t2, t1, t2       // no carry
	SUB t2, acc0, y0     // no borrow

	// ADDS acc0, acc1, acc1
	ADD acc0, acc1, acc1
	SLTU acc0, acc1, t0
	// ADCS $0, acc2
	ADD t0, acc2, acc2
	SLTU t0, acc2, t1
	// ADCS $0, acc3
	ADD t1, acc3, acc3
	SLTU t1, acc3, t0
	// ADC $0, y0, acc0
	ADD t0, y0, acc0

	// Second reduction step
	SLL $32, acc1, t0
	SRL $32, acc1, t1

	// SUBS t0, acc2
	SLTU t0, acc2, t2
	SUB t0, acc2, acc2
	// SBCS t1, acc3
	ADD t2, t1, t3       // no carry
	SLTU t3, acc3, t2
	SUB t3, acc3, acc3
	// SBCS t0, acc0
	ADD t2, t0, t2       // no carry
	SLTU t2, acc0, t3
	SUB t2, acc0, acc0
	// SBC t1, acc1
	ADD t3, t1, t2       // no carry
	SUB t2, acc1, y0     // no borrow

	// ADDS acc1, acc2
	ADD acc1, acc2, acc2
	SLTU acc1, acc2, t0
	// ADCS $0, acc3
	ADD t0, acc3, acc3
	SLTU t0, acc3, t1
	// ADCS $0, acc0
	ADD t1, acc0, acc0
	SLTU t1, acc0, t0
	// ADC $0, y0, acc1
	ADD t0, y0, acc1

	// Third reduction step
	SLL $32, acc2, t0
	SRL $32, acc2, t1

	// SUBS t0, acc3
	SLTU t0, acc3, t2
	SUB t0, acc3, acc3
	// SBCS t1, acc0
	ADD t2, t1, t3       // no carry
	SLTU t3, acc0, t2
	SUB t3, acc0, acc0
	// SBCS t0, acc1
	ADD t2, t0, t2       // no carry
	SLTU t2, acc1, t3
	SUB t2, acc1, acc1
	// SBC t1, acc2
	ADD t3, t1, t2       // no carry
	SUB t2, acc2, y0     // no borrow

	// ADDS acc2, acc3
	ADD acc2, acc3, acc3
	SLTU acc2, acc3, t0
	// ADCS $0, acc0
	ADD t0, acc0, acc0
	SLTU t0, acc0, t1
	// ADCS $0, acc1
	ADD t1, acc1, acc1
	SLTU t1, acc1, t0
	// ADC $0, y0, acc2
	ADD t0, y0, acc2

	// Last reduction step
	SLL $32, acc3, t0
	SRL $32, acc3, t1

	// SUBS t0, acc0
	SLTU t0, acc0, t2
	SUB t0, acc0, acc0
	// SBCS t1, acc1
	ADD t2, t1, t3       // no carry
	SLTU t3, acc1, t2
	SUB t3, acc1, acc1
	// SBCS t0, acc2
	ADD t2, t0, t2       // no carry
	SLTU t2, acc2, t3
	SUB t2, acc2, acc2
	// SBC t1, acc3
	ADD t3, t1, t2       // no carry
	SUB t2, acc3, y0     // no borrow

	// ADDS acc3, acc0
	ADD acc3, acc0, acc0
	SLTU acc3, acc0, t0
	// ADCS $0, acc1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t1
	// ADCS $0, acc2
	ADD t1, acc2, acc2
	SLTU t1, acc2, t0
	// ADC $0, y0, acc3
	ADD t0, y0, acc3

	// Add bits [511:256] of the sqr result
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
	ADD const0, t1, t1             // no carry
	ADD y1, t1, acc5
	SLTU y1, acc5, t3
	ADD t3, y2, acc6
	SLTU y2, acc6, hlp0
	ADD hlp0, const1, t2         // no carry
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
// func p256Sqr(res, in *p256Element, n int)
TEXT ·p256Sqr(SB),NOSPLIT,$0
	MOV res+0(FP), res_ptr
	MOV in+8(FP), x_ptr
	MOV n+16(FP), y_ptr

	MOV (8*0)(x_ptr), x0
	MOV (8*1)(x_ptr), x1
	MOV (8*2)(x_ptr), x2
	MOV (8*3)(x_ptr), x3

	MOV p256one<>+0x08(SB), const0
	ADD $1, const0, const1
	
sqrLoop:
		SUB $1, y_ptr
		CALL	sm2P256SqrInternal<>(SB)
		MOV y0, x0
		MOV y1, x1
		MOV y2, x2
		MOV y3, x3
		BNE y_ptr, ZERO, sqrLoop

	MOV y0, (8*0)(res_ptr)
	MOV y1, (8*1)(res_ptr)
	MOV y2, (8*2)(res_ptr)
	MOV y3, (8*3)(res_ptr)

	RET

/* ---------------------------------------*/
// func p256FromMont(res, in *p256Element)
TEXT ·p256FromMont(SB),NOSPLIT,$0
	MOV res+0(FP), res_ptr
	MOV in+8(FP), x_ptr

	MOV (8*0)(x_ptr), acc0
	MOV (8*1)(x_ptr), acc1
	MOV (8*2)(x_ptr), acc2
	MOV (8*3)(x_ptr), acc3
	// Only reduce, no multiplications are needed
	// First reduction step
	SLL $32, acc0, t0
	SRL $32, acc0, t1

	// SUBS t0, acc1
	SLTU t0, acc1, t2
	SUB t0, acc1, acc1
	// SBCS t1, acc2
	ADD t2, t1, t2       // no carry
	SLTU t2, acc2, t3
	SUB t2, acc2, acc2
	// SBCS t0, acc3
	ADD t3, t0, t3       // no carry
	SLTU t3, acc3, t2
	SUB t3, acc3, acc3
	// SBC t1, acc0
	ADD t2, t1, t2       // no carry
	SUB t2, acc0, y0     // no borrow

	// ADDS acc0, acc1, acc1
	ADD acc0, acc1, acc1
	SLTU acc0, acc1, t0
	// ADCS $0, acc2
	ADD t0, acc2, acc2
	SLTU t0, acc2, t1
	// ADCS $0, acc3
	ADD t1, acc3, acc3
	SLTU t1, acc3, t0
	// ADC $0, y0, acc0
	ADD t0, y0, acc0

	// Second reduction step
	SLL $32, acc1, t0
	SRL $32, acc1, t1

	// SUBS t0, acc2
	SLTU t0, acc2, t2
	SUB t0, acc2, acc2
	// SBCS t1, acc3
	ADD t2, t1, t3       // no carry
	SLTU t3, acc3, t2
	SUB t3, acc3, acc3
	// SBCS t0, acc0
	ADD t2, t0, t2       // no carry
	SLTU t2, acc0, t3
	SUB t2, acc0, acc0
	// SBC t1, acc1
	ADD t3, t1, t2       // no carry
	SUB t2, acc1, y0     // no borrow

	// ADDS acc1, acc2
	ADD acc1, acc2, acc2
	SLTU acc1, acc2, t0
	// ADCS $0, acc3
	ADD t0, acc3, acc3
	SLTU t0, acc3, t1
	// ADCS $0, acc0
	ADD t1, acc0, acc0
	SLTU t1, acc0, t0
	// ADC $0, y0, acc1
	ADD t0, y0, acc1

	// Third reduction step
	SLL $32, acc2, t0
	SRL $32, acc2, t1

	// SUBS t0, acc3
	SLTU t0, acc3, t2
	SUB t0, acc3, acc3
	// SBCS t1, acc0
	ADD t2, t1, t3       // no carry
	SLTU t3, acc0, t2
	SUB t3, acc0, acc0
	// SBCS t0, acc1
	ADD t2, t0, t2       // no carry
	SLTU t2, acc1, t3
	SUB t2, acc1, acc1
	// SBC t1, acc2
	ADD t3, t1, t2       // no carry
	SUB t2, acc2, y0     // no borrow

	// ADDS acc2, acc3
	ADD acc2, acc3, acc3
	SLTU acc2, acc3, t0
	// ADCS $0, acc0
	ADD t0, acc0, acc0
	SLTU t0, acc0, t1
	// ADCS $0, acc1
	ADD t1, acc1, acc1
	SLTU t1, acc1, t0
	// ADC $0, y0, acc2
	ADD t0, y0, acc2

	// Last reduction step
	SLL $32, acc3, t0
	SRL $32, acc3, t1

	// SUBS t0, acc0
	SLTU t0, acc0, t2
	SUB t0, acc0, acc0
	// SBCS t1, acc1
	ADD t2, t1, t3       // no carry
	SLTU t3, acc1, t2
	SUB t3, acc1, acc1
	// SBCS t0, acc2
	ADD t2, t0, t2       // no carry
	SLTU t2, acc2, t3
	SUB t2, acc2, acc2
	// SBC t1, acc3
	ADD t3, t1, t2       // no carry
	SUB t2, acc3, y0     // no borrow

	// ADDS acc3, acc0
	ADD acc3, acc0, acc0
	SLTU acc3, acc0, t0
	// ADCS $0, acc1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t1
	// ADCS $0, acc2
	ADD t1, acc2, acc2
	SLTU t1, acc2, t0
	// ADC $0, y0, acc3
	ADD t0, y0, acc3

	// Final reduction
	ADD $1, acc0, acc4
	SLTU acc0, acc4, t1
	MOV p256one<>+0x08(SB), t2
	ADD t2, t1, t1         // no carry
	ADD acc1, t1, acc5
	SLTU acc1, acc5, t3
	ADD t3, acc2, acc6
	SLTU acc2, acc6, hlp0
	ADD $1, t2, t2
	ADD hlp0, t2, t2         // no carry
	ADD acc3, t2, acc7
	SLTU acc3, acc7, t0

	SUB $1, t0, t0        // mask = -cond
	XOR $-1, t0, t1        // t1 = ~mask

	AND t0, acc0, acc0
	AND t1, acc4, acc4
	OR acc4, acc0

	AND t0, acc1, acc1
	AND t1, acc5, acc5
	OR acc5, acc1

	AND t0, acc2, acc2
	AND t1, acc6, acc6
	OR acc6, acc2

	AND t0, acc3, acc3
	AND t1, acc7, acc7
	OR acc7, acc3

	MOV acc0, (8*0)(res_ptr)
	MOV acc1, (8*1)(res_ptr)
	MOV acc2, (8*2)(res_ptr)
	MOV acc3, (8*3)(res_ptr)
	RET

/* ---------------------------------------*/
//func p256OrdReduce(s *p256OrdElement)
TEXT ·p256OrdReduce(SB),NOSPLIT,$0
	MOV s+0(FP), res_ptr

	MOV (8*0)(res_ptr), acc0
	MOV (8*1)(res_ptr), acc1
	MOV (8*2)(res_ptr), acc2
	MOV (8*3)(res_ptr), acc3

	MOV p256ord<>+0x00(SB), x0
	MOV p256ord<>+0x08(SB), x1
	MOV p256ord<>+0x10(SB), x2
	MOV p256ord<>+0x18(SB), x3

	SLTU x0, acc0, t0
	SUB x0, acc0, y0
	// SBCS x1, acc1
	ADD t0, x1, t1        // no carry
	SLTU t1, acc1, t2
	SUB t1, acc1, y1
	// SBCS x2, acc2
	SLTU x2, acc2, t3
	SUB x2, acc2, y2
	SLTU t2, y2, t0
	SUB t2, y2, y2
	OR t3, t0, t2
	// SBCS x3, acc3
	SLTU x3, acc3, t3
	SUB x3, acc3, y3
	SLTU t2, y3, t0
	SUB t2, y3, y3
	OR t3, t0, t0

	SUB $1, t0, t0        // mask = -cond
	XOR $-1, t0, t1        // t1 = ~mask

	AND t0, y0, y0
	AND t1, acc0, acc0
	OR acc0, y0

	AND t0, y1, y1
	AND t1, acc1, acc1
	OR acc1, y1

	AND t0, y2, y2
	AND t1, acc2, acc2
	OR acc2, y2

	AND t0, y3, y3
	AND t1, acc3, acc3
	OR acc3, y3

	MOV y0, (8*0)(res_ptr)
	MOV y1, (8*1)(res_ptr)
	MOV y2, (8*2)(res_ptr)
	MOV y3, (8*3)(res_ptr)

	RET

/* ---------------------------------------*/
// func p256Select(res *SM2P256Point, table *p256Table, idx, limit int)
TEXT ·p256Select(SB),NOSPLIT,$0
	MOV	limit+24(FP), x_ptr
	MOV	idx+16(FP), const0
	MOV	table+8(FP), y_ptr
	MOV	res+0(FP), res_ptr

	MOV    $0, x0
	MOV    $0, x1
	MOV    $0, x2
	MOV    $0, x3
	MOV    $0, y0
	MOV    $0, y1
	MOV    $0, y2
	MOV    $0, y3
	MOV    $0, t0
	MOV    $0, t1
	MOV    $0, t2
	MOV    $0, t3

	MOV	$0, acc5

loop_select:
		ADD $1, acc5, acc5
		XOR  acc5, const0, hlp0
		SLTU hlp0, ZERO, hlp0
		SUB $1, hlp0, hlp0   // mask = -cond

		MOV    (8*0)(y_ptr), acc0
		MOV    (8*1)(y_ptr), acc1
		MOV    (8*2)(y_ptr), acc2
		MOV    (8*3)(y_ptr), acc3
		AND hlp0, acc0, acc0
		AND hlp0, acc1, acc1
		AND hlp0, acc2, acc2
		AND hlp0, acc3, acc3
		OR   acc0, x0, x0
		OR   acc1, x1, x1
		OR   acc2, x2, x2
		OR   acc3, x3, x3

		MOV    (8*4)(y_ptr), acc0
		MOV    (8*5)(y_ptr), acc1
		MOV    (8*6)(y_ptr), acc2
		MOV    (8*7)(y_ptr), acc3
		AND hlp0, acc0, acc0
		AND hlp0, acc1, acc1
		AND hlp0, acc2, acc2
		AND hlp0, acc3, acc3
		OR   acc0, y0, y0
		OR   acc1, y1, y1
		OR   acc2, y2, y2
		OR   acc3, y3, y3

		MOV    (8*8)(y_ptr), acc0
		MOV    (8*9)(y_ptr), acc1
		MOV    (8*10)(y_ptr), acc2
		MOV    (8*11)(y_ptr), acc3
		AND hlp0, acc0, acc0
		AND hlp0, acc1, acc1
		AND hlp0, acc2, acc2
		AND hlp0, acc3, acc3
		OR   acc0, t0, t0
		OR   acc1, t1, t1
		OR   acc2, t2, t2
		OR   acc3, t3, t3
		ADD $96, y_ptr, y_ptr

		BNE acc5, x_ptr, loop_select

	MOV    x0, (8*0)(res_ptr)
	MOV    x1, (8*1)(res_ptr)
	MOV    x2, (8*2)(res_ptr)
	MOV    x3, (8*3)(res_ptr)
	MOV    y0, (8*4)(res_ptr)
	MOV    y1, (8*5)(res_ptr)
	MOV    y2, (8*6)(res_ptr)
	MOV    y3, (8*7)(res_ptr)
	MOV    t0, (8*8)(res_ptr)
	MOV    t1, (8*9)(res_ptr)
	MOV    t2, (8*10)(res_ptr)
	MOV    t3, (8*11)(res_ptr)

	RET

/* ---------------------------------------*/
// func p256SelectAffine(res *p256AffinePoint, table *p256AffineTable, idx int)
TEXT ·p256SelectAffine(SB),NOSPLIT,$0
	MOV	idx+16(FP), t0
	MOV	table+8(FP), t1
	MOV	res+0(FP), res_ptr

basic_path:
	XOR	x0, x0, x0
	XOR	x1, x1, x1
	XOR	x2, x2, x2
	XOR	x3, x3, x3
	XOR	y0, y0, y0
	XOR	y1, y1, y1
	XOR	y2, y2, y2
	XOR	y3, y3, y3

	MOV	$0, t2
	MOV	$32, const0

loop_select:
		ADD $1, t2, t2
		XOR  t2, t0, hlp0
		SLTU hlp0, ZERO, hlp0
		SUB $1, hlp0, hlp0   // mask = -cond

		MOV    (8*0)(t1), acc0
		MOV    (8*1)(t1), acc1
		MOV    (8*2)(t1), acc2
		MOV    (8*3)(t1), acc3
		AND hlp0, acc0, acc0
		AND hlp0, acc1, acc1
		AND hlp0, acc2, acc2
		AND hlp0, acc3, acc3
		OR   acc0, x0, x0
		OR   acc1, x1, x1
		OR   acc2, x2, x2
		OR   acc3, x3, x3

		MOV    (8*4)(t1), acc0
		MOV    (8*5)(t1), acc1
		MOV    (8*6)(t1), acc2
		MOV    (8*7)(t1), acc3
		AND hlp0, acc0, acc0
		AND hlp0, acc1, acc1
		AND hlp0, acc2, acc2
		AND hlp0, acc3, acc3
		OR   acc0, y0, y0
		OR   acc1, y1, y1
		OR   acc2, y2, y2
		OR   acc3, y3, y3
		ADD $64, t1, t1

		BNE t2, const0, loop_select
	MOV    x0, (8*0)(res_ptr)
	MOV    x1, (8*1)(res_ptr)
	MOV    x2, (8*2)(res_ptr)
	MOV    x3, (8*3)(res_ptr)
	MOV    y0, (8*4)(res_ptr)
	MOV    y1, (8*5)(res_ptr)
	MOV    y2, (8*6)(res_ptr)
	MOV    y3, (8*7)(res_ptr)		
	RET

/* ---------------------------------------*/
// (x3, x2, x1, x0) = (y3, y2, y1, y0) - (x3, x2, x1, x0)	
TEXT sm2P256Subinternal<>(SB),NOSPLIT,$0
	SLTU x0, y0, t0
	SUB x0, y0, acc0
	// SBCS x1, y1
	SLTU x1, y1, t1
	SUB x1, y1, acc1
	SLTU t0, acc1, t2
	SUB t0, acc1, acc1
	OR t1, t2, t0
	// SBCS x2, y2
	SLTU x2, y2, t1
	SUB x2, y2, acc2
	SLTU t0, acc2, t2
	SUB t0, acc2, acc2
	OR t1, t2, t0
	// SBCS x3, y3
	SLTU x3, y3, t1
	SUB x3, y3, acc3
	SLTU t0, acc3, t2
	SUB t0, acc3, acc3
	OR t1, t2, t0

	SLL $63, t0, t0
	SRA $63, t0, t0    // mask = -cond

	AND $1, t0, t1
	AND t0, const0, t3
	AND t0, const1, t2

	SLTU t1, acc0, hlp0
	SUB t1, acc0, x0
	ADD hlp0, t3, t3       // no carry
	SLTU t3, acc1, t1
	SUB t3, acc1, x1
	SLTU t1, acc2, hlp0
	SUB t1, acc2, x2
	ADD hlp0, t2, t1       // no carry
	SUB t1, acc3, x3

	RET

/* ---------------------------------------*/
// (x3, x2, x1, x0) = 2(y3, y2, y1, y0)
#define p256MulBy2Inline       \
	SRL $63, y0, t0;  \
	SLL $1, y0, x0;  \
	SRL $63, y1, t1;  \
	SLL $1, y1, x1;  \
	ADD t0, x1, x1;  \
	SRL $63, y2, t2;  \
	SLL $1, y2, x2;  \
	ADD t1, x2, x2;  \
	SRL $63, y3, t3;  \
	SLL $1, y3, x3;  \
	ADD t2, x3, x3;  \
	;\
	ADD $1, x0, acc4;  \
	SLTU x0, acc4, t0;  \
	ADD const0, t0, t0;  \
	ADD x1, t0, acc5;  \
	SLTU x1, acc5, t0;  \
	ADD t0, x2, acc6;  \
	SLTU x2, acc6, t0;  \
	ADD const1, t0, t0;  \
	ADD x3, t0, acc7;  \
	SLTU x3, acc7, t0;  \
	OR t0, t3, t0;  \
	;\
	SUB $1, t0, t0;  \
	XOR $-1, t0, t1;  \
	AND t0, x0, x0;  \
	AND t1, acc4, acc4;  \
	OR acc4, x0;  \
	AND t0, x1, x1;	\
	AND t1, acc5, acc5;  \
	OR acc5, x1;  \
	AND t0, x2, x2;  \
	AND t1, acc6, acc6;  \
	OR acc6, x2;  \
	AND t0, x3, x3;  \
	AND t1, acc7, acc7;  \
	OR acc7, x3

// (x3, x2, x1, x0) = (x3, x2, x1, x0) + (y3, y2, y1, y0)
#define p256AddInline          \
	ADD x0, y0, x0;  \
	SLTU y0, x0, t0;  \
	ADD x1, y1, x1;  \
	SLTU y1, x1, t1;  \
	ADD t0, x1, x1;  \
	SLTU t0, x1, t2;  \
	OR t1, t2, t0;  \
	ADD x2, y2, x2;  \
	SLTU y2, x2, t1;  \
	ADD t0, x2, x2;  \
	SLTU t0, x2, t2;  \
	OR t1, t2, t0;  \
	ADD x3, y3, x3;  \
	SLTU y3, x3, t1;  \
	ADD t0, x3, x3;  \
	SLTU t0, x3, t2;  \
	OR t1, t2, t2;  \
	;\
	ADD $1, x0, acc4;  \
	SLTU x0, acc4, t0;  \
	ADD const0, t0, t0;  \
	ADD x1, t0, acc5;  \
	SLTU x1, acc5, t0;  \
	ADD t0, x2, acc6;  \
	SLTU x2, acc6, t0;  \
	ADD const1, t0, t0;  \
	ADD x3, t0, acc7;  \
	SLTU x3, acc7, t0;  \
	OR t0, t2, t0;  \
	;\
	SUB $1, t0, t0;  \
	XOR $-1, t0, t1;  \
	;\
	AND t0, x0, x0;  \
	AND t1, acc4, acc4;  \
	OR acc4, x0;  \
	;\
	AND t0, x1, x1;  \
	AND t1, acc5, acc5;  \
	OR acc5, x1;  \
	;\
	AND t0, x2, x2;  \
	AND t1, acc6, acc6;  \
	OR acc6, x2;  \
	;\
	AND t0, x3, x3;  \
	AND t1, acc7, acc7;  \
	OR acc7, x3

// (y3, y2, y1, y0) = (y3, y2, y1, y0) / 2
#define p256DivideBy2 \
	SLL $63, y0, t0;  \
	SRA $63, t0, t0;  \
	AND $1, t0, acc1;  \
	AND const0, t0, acc2;  \
	AND const1, t0, acc3;  \
	;\
	SLTU acc1, y0, t1;  \
	SUB acc1, y0, y0;  \
	ADD t1, acc2, acc2;  \
	SRL $1, y0, y0;  \
	SLTU acc2, y1, t1;  \
	SUB acc2, y1, y1;  \
	SLTU t1, y2, t2;  \
	SUB t1, y2, y2;  \
	SLL $63, y1, t1;  \
	OR  t1, y0; \
	SRL $1, y1, y1;  \
	ADD t2, acc3, acc3;  \
	SLL $63, y2, t2;  \
	OR  t2, y1; \
	SRL $1, y2, y2;  \
	SUB acc3, y3, t1;  \
	SLL $63, t1, t2;  \
	OR  t2, y2; \
	SLTU y3, acc3, t2;  \
	AND t0, t2, t2;  \
	SLL $63, t2, t2;  \
	SRL $1, t1, y3;  \
	OR  t2, y3

/* ---------------------------------------*/
#define x1in(off) (off)(a_ptr)
#define y1in(off) (off + 32)(a_ptr)
#define z1in(off) (off + 64)(a_ptr)
#define x2in(off) (off)(b_ptr)
#define z2in(off) (off + 64)(b_ptr)
#define x3out(off) (off)(res_ptr)
#define y3out(off) (off + 32)(res_ptr)
#define z3out(off) (off + 64)(res_ptr)
#define LDx(src) MOV src(0), x0; MOV src(8), x1; MOV src(16), x2; MOV src(24), x3
#define LDy(src) MOV src(0), y0; MOV src(8), y1; MOV src(16), y2; MOV src(24), y3
#define STx(src) MOV x0, src(0); MOV x1, src(8); MOV x2, src(16); MOV x3, src(24)
#define STy(src) MOV y0, src(0); MOV y1, src(8); MOV y2, src(16); MOV y3, src(24)
/* ---------------------------------------*/
#define y2in(off)  (32*0 + 8 + off)(RSP)
#define s2(off)    (32*1 + 8 + off)(RSP)
#define z1sqr(off) (32*2 + 8 + off)(RSP)
#define h(off)	   (32*3 + 8 + off)(RSP)
#define r(off)	   (32*4 + 8 + off)(RSP)
#define hsqr(off)  (32*5 + 8 + off)(RSP)
#define rsqr(off)  (32*6 + 8 + off)(RSP)
#define hcub(off)  (32*7 + 8 + off)(RSP)

#define z2sqr(off) (32*8 + 8 + off)(RSP)
#define s1(off) (32*9 + 8 + off)(RSP)
#define u1(off) (32*10 + 8 + off)(RSP)
#define u2(off) (32*11 + 8 + off)(RSP)

/* ---------------------------------------*/
// func p256PointAddAffineAsm(res, in1 *SM2P256Point, in2 *p256AffinePoint, sign, sel, zero int)
TEXT ·p256PointAddAffineAsm(SB),0,$264-48
	MOV	in1+8(FP), a_ptr
	MOV	in2+16(FP), b_ptr
	MOV	sign+24(FP), hlp0
	MOV	sel+32(FP), hlp1
	MOV	zero+40(FP), t2

	SLTU hlp0, ZERO, hlp0
	SLTU hlp1, ZERO, hlp1
	SLTU t2, ZERO, t2
	SLL $1, t2, t2
	OR t2, hlp1, hlp1

	MOV p256one<>+0x08(SB), const0
	ADD $1, const0, const1

	// Negate y2in based on sign
	MOV (8*4)(b_ptr), y0
	MOV (8*5)(b_ptr), y1
	MOV (8*6)(b_ptr), y2
	MOV (8*7)(b_ptr), y3
	// (acc0, acc1, acc2, acc3) = - (y3, y2, y1, y0)
	SLTU y0, ZERO, t3
	SUB y0, ZERO, acc0
	SLTU y1, ZERO, t2
	SUB y1, ZERO, acc1
	SLTU t3, acc1, t1
	SUB t3, acc1, acc1
	OR t2, t1, t3
	SLTU y2, ZERO, t2
	SUB y2, ZERO, acc2
	SLTU t3, acc2, t1
	SUB t3, acc2, acc2
	OR t2, t1, t3
	SLTU y3, ZERO, t2
	SUB y3, ZERO, acc3
	SLTU t3, acc3, t1
	SUB t3, acc3, acc3
	OR t2, t1, t3

	SLL $63, t3, t3
	SRA $63, t3, t3    // mask = -cond
	AND $1, t3, acc4
	AND const0, t3, acc5
	AND const1, t3, acc7

	SLTU acc4, acc0, t3
	SUB acc4, acc0, acc0
	ADD t3, acc5, acc5       // no carry
	SLTU acc5, acc1, t3
	SUB acc5, acc1, acc1
	SLTU t3, acc2, t1
	SUB t3, acc2, acc2
	ADD t1, acc7, t3       // no carry
	SUB t3, acc3, acc3
	// If condition is 0, keep original value
	SUB $1, hlp0, hlp0    // mask = -cond
	XOR $-1, hlp0, t0    // t0 = ~mask
	AND hlp0, y0, y0
	AND t0, acc0, acc0
	AND hlp0, y1, y1
	AND t0, acc1, acc1
	AND hlp0, y2, y2
	AND t0, acc2, acc2
	AND hlp0, y3, y3
	AND t0, acc3, acc3
	OR acc0, y0
	OR acc1, y1
	OR acc2, y2
	OR acc3, y3
	// Store result
	STy(y2in)

	// Begin point add
	LDx(z1in)
	CALL	sm2P256SqrInternal<>(SB)    // z1ˆ2
	STy(z1sqr)

	LDx(x2in)
	CALL	sm2P256MulInternal<>(SB)    // x2 * z1ˆ2

	LDx(x1in)
	CALL	sm2P256Subinternal<>(SB)    // h = u2 - u1
	STx(h)

	LDy(z1in)
	CALL	sm2P256MulInternal<>(SB)    // z3 = h * z1

	// iff select == 0, z3 = z1
	MOV (8*8)(a_ptr), acc0
	MOV (8*9)(a_ptr), acc1
	MOV (8*10)(a_ptr), acc2
	MOV (8*11)(a_ptr), acc3
	AND $1, hlp1, t0
	SUB $1, t0, t0    // mask = -cond
	XOR $-1, t0, t1        // t1 = ~mask
	AND t0, acc0, acc0
	AND t1, y0, y0
	OR acc0, y0
	AND t0, acc1, acc1
	AND t1, y1, y1
	OR acc1, y1
	AND t0, acc2, acc2
	AND t1, y2, y2
	OR acc2, y2
	AND t0, acc3, acc3
	AND t1, y3, y3
	OR acc3, y3
	// iff zero == 0, z3 = 1
	MOV $1, acc0
	MOV const0, acc1
	MOV $0, acc2
	MOV const1, acc3
	SRL $1, hlp1, t0
	SUB $1, t0, t0
	XOR $-1, t0, t1
	AND t0, acc0, acc0
	AND t1, y0, y0
	OR acc0, y0
	AND t0, acc1, acc1
	AND t1, y1, y1
	OR acc1, y1
	AND t0, acc2, acc2
	AND t1, y2, y2
	OR acc2, y2
	AND t0, acc3, acc3
	AND t1, y3, y3
	OR acc3, y3
	LDx(z1in)
	// store z3
	MOV res+0(FP), t0
	MOV y0, (8*8)(t0)
	MOV y1, (8*9)(t0)
	MOV y2, (8*10)(t0)
	MOV y3, (8*11)(t0)

	LDy(z1sqr)
	CALL	sm2P256MulInternal<>(SB)    // z1 ^ 3

	LDx(y2in)
	CALL	sm2P256MulInternal<>(SB)    // s2 = y2 * z1ˆ3
	STy(s2)

	LDx(y1in)
	CALL	sm2P256Subinternal<>(SB)    // r = s2 - s1
	STx(r)

	CALL	sm2P256SqrInternal<>(SB)    // rsqr = rˆ2
	STy	(rsqr)

	LDx(h)
	CALL	sm2P256SqrInternal<>(SB)    // hsqr = hˆ2
	STy(hsqr)

	CALL	sm2P256MulInternal<>(SB)    // hcub = hˆ3
	STy(hcub)

	LDx(y1in)
	CALL	sm2P256MulInternal<>(SB)    // y1 * hˆ3
	STy(s2)

	MOV hsqr(0*8), x0
	MOV hsqr(1*8), x1
	MOV hsqr(2*8), x2
	MOV hsqr(3*8), x3
	MOV (8*0)(a_ptr), y0
	MOV (8*1)(a_ptr), y1
	MOV (8*2)(a_ptr), y2
	MOV (8*3)(a_ptr), y3
	CALL	sm2P256MulInternal<>(SB)    // hsqr * u1
	MOV y0, h(0*8)
	MOV y1, h(1*8)
	MOV y2, h(2*8)
	MOV y3, h(3*8)

	p256MulBy2Inline               // u1 * hˆ2 * 2, inline

	LDy(rsqr)
	CALL	sm2P256Subinternal<>(SB)    // rˆ2 - u1 * hˆ2 * 2

	MOV x0, y0 
	MOV x1, y1
	MOV x2, y2
	MOV x3, y3
	LDx(hcub)
	CALL	sm2P256Subinternal<>(SB)

	MOV (8*0)(a_ptr), acc0             // load x1
	MOV (8*1)(a_ptr), acc1
	MOV (8*2)(a_ptr), acc2
	MOV (8*3)(a_ptr), acc3
	// iff select == 0, x3 = x1
	AND $1, hlp1, t0
	SUB $1, t0, t0
	XOR $-1, t0, t1        // t1 = ~mask
	AND t0, acc0, acc0
	AND t1, x0, x0
	AND t0, acc1, acc1
	AND t1, x1, x1
	AND t0, acc2, acc2
	AND t1, x2, x2
	AND t0, acc3, acc3
	AND t1, x3, x3
	OR acc0, x0
	OR acc1, x1
	OR acc2, x2
	OR acc3, x3
	MOV (8*0)(b_ptr), acc0            // load x2
	MOV (8*1)(b_ptr), acc1
	MOV (8*2)(b_ptr), acc2
	MOV (8*3)(b_ptr), acc3
	// iff zero == 0, x3 = x2
	SRL $1, hlp1, t0
	SUB $1, t0, t0
	XOR $-1, t0, t1        // t1 = ~mask
	AND t0, acc0, acc0
	AND t1, x0, x0
	AND t0, acc1, acc1
	AND t1, x1, x1
	AND t0, acc2, acc2
	AND t1, x2, x2
	AND t0, acc3, acc3
	AND t1, x3, x3
	OR acc0, x0
	OR acc1, x1
	OR acc2, x2
	OR acc3, x3
	// store x3
	MOV res+0(FP), t0
	MOV x0, (8*0)(t0)
	MOV x1, (8*1)(t0)
	MOV x2, (8*2)(t0)
	MOV x3, (8*3)(t0)

	MOV h(0*8), y0 
	MOV h(1*8), y1
	MOV h(2*8), y2
	MOV h(3*8), y3
	CALL	sm2P256Subinternal<>(SB)

	MOV r(0*8), y0 
	MOV r(1*8), y1
	MOV r(2*8), y2
	MOV r(3*8), y3
	CALL	sm2P256MulInternal<>(SB)

	MOV s2(0*8), x0 
	MOV s2(1*8), x1
	MOV s2(2*8), x2
	MOV s2(3*8), x3
	CALL	sm2P256Subinternal<>(SB)

	MOV (8*4)(a_ptr), acc0            // load y1
	MOV (8*5)(a_ptr), acc1
	MOV (8*6)(a_ptr), acc2
	MOV (8*7)(a_ptr), acc3
	// iff select == 0, y3 = y1
	AND $1, hlp1, t0
	SUB $1, t0, t0
	XOR $-1, t0, t1        // t1 = ~mask
	AND t0, acc0, acc0
	AND t1, x0, x0
	AND t0, acc1, acc1
	AND t1, x1, x1
	AND t0, acc2, acc2
	AND t1, x2, x2
	AND t0, acc3, acc3
	AND t1, x3, x3
	OR acc0, x0
	OR acc1, x1
	OR acc2, x2
	OR acc3, x3
	MOV y2in(0*8), acc0                // load y2
	MOV y2in(1*8), acc1
	MOV y2in(2*8), acc2
	MOV y2in(3*8), acc3
	// iff zero == 0, y3 = y2
	SRL $1, hlp1, t0
	SUB $1, t0, t0
	XOR $-1, t0, t1        // t1 = ~mask
	AND t0, acc0, acc0
	AND t1, x0, x0
	AND t0, acc1, acc1
	AND t1, x1, x1
	AND t0, acc2, acc2
	AND t1, x2, x2
	AND t0, acc3, acc3
	AND t1, x3, x3
	OR acc0, x0
	OR acc1, x1
	OR acc2, x2
	OR acc3, x3
	// store y3
	MOV res+0(FP), t0
	MOV x0, (8*4)(t0)
	MOV x1, (8*5)(t0)
	MOV x2, (8*6)(t0)
	MOV x3, (8*7)(t0)

	RET

#define s(off)	(32*0 + 8 + off)(RSP)
#define m(off)	(32*1 + 8 + off)(RSP)
#define zsqr(off) (32*2 + 8 + off)(RSP)
#define tmp(off)  (32*3 + 8 + off)(RSP)

//func p256PointDoubleAsm(res, in *SM2P256Point)
TEXT ·p256PointDoubleAsm(SB),NOSPLIT,$136-16
	MOV	res+0(FP), res_ptr
	MOV	in+8(FP), a_ptr

	MOV p256one<>+0x08(SB), const0
	ADD $1, const0, const1

	// Begin point double
	MOV (8*8)(a_ptr), x0              // load z 
	MOV (8*9)(a_ptr), x1
	MOV (8*10)(a_ptr), x2
	MOV (8*11)(a_ptr), x3
	CALL	sm2P256SqrInternal<>(SB)    // z1ˆ2
	MOV y0, zsqr(0*8)                  // store z^2
	MOV y1, zsqr(1*8)
	MOV y2, zsqr(2*8)
	MOV y3, zsqr(3*8)

	MOV (8*0)(a_ptr), x0               // load x
	MOV (8*1)(a_ptr), x1
	MOV (8*2)(a_ptr), x2
	MOV (8*3)(a_ptr), x3
	p256AddInline
	STx(m)

	LDx(z1in)
	LDy(y1in)
	CALL	sm2P256MulInternal<>(SB)
	p256MulBy2Inline
	STx(z3out)

	LDy(x1in)
	LDx(zsqr)
	CALL	sm2P256Subinternal<>(SB)
	LDy(m)
	CALL	sm2P256MulInternal<>(SB)

	// Multiply by 3
	p256MulBy2Inline
	p256AddInline
	STx(m)

	LDy(y1in)
	p256MulBy2Inline
	CALL	sm2P256SqrInternal<>(SB)
	STy(s)
	MOV	y0, x0
	MOV	y1, x1
	MOV	y2, x2
	MOV	y3, x3
	CALL	sm2P256SqrInternal<>(SB)

	// Divide by 2
	p256DivideBy2

	STy(y3out)

	LDx(x1in)
	LDy(s)
	CALL	sm2P256MulInternal<>(SB)
	STy(s)
	p256MulBy2Inline
	STx(tmp)

	LDx(m)
	CALL	sm2P256SqrInternal<>(SB)
	LDx(tmp)
	CALL	sm2P256Subinternal<>(SB)

	STx(x3out)

	LDy(s)
	CALL	sm2P256Subinternal<>(SB)

	LDy(m)
	CALL	sm2P256MulInternal<>(SB)

	LDx(y3out)
	CALL	sm2P256Subinternal<>(SB)
	STx(y3out)

	RET

#define p256PointDoubleRound() \
	LDx(z3out)                       \ // load z
	CALL	sm2P256SqrInternal<>(SB) \
	MOV y0, zsqr(0*8)          \ // store z^2
	MOV y1, zsqr(1*8)          \
	MOV y2, zsqr(2*8)          \
	MOV y3, zsqr(3*8)          \
	\
	LDx(x3out)                       \// load x
	p256AddInline                    \
	STx(m)                           \
	\
	LDx(z3out)                       \ // load z
	LDy(y3out)                       \ // load y
	CALL	sm2P256MulInternal<>(SB) \
	p256MulBy2Inline                 \
	STx(z3out)                       \ // store result z
	\
	LDy(x3out)                       \ // load x
	LDx(zsqr)                        \
	CALL	sm2P256Subinternal<>(SB) \
	LDy(m)                           \
	CALL	sm2P256MulInternal<>(SB) \
	\
	\// Multiply by 3
	p256MulBy2Inline                 \
	p256AddInline                    \
	STx(m)                           \
	\
	LDy(y3out)                       \  // load y
	p256MulBy2Inline                 \
	CALL	sm2P256SqrInternal<>(SB) \
	STy(s)                           \
	MOV	y0, x0                   \
	MOV	y1, x1                   \
	MOV	y2, x2                   \
	MOV	y3, x3                   \
	CALL	sm2P256SqrInternal<>(SB) \
	\
	\// Divide by 2
	p256DivideBy2                    \
	STy(y3out)                       \                
	\
	LDx(x3out)                       \  // load x
	LDy(s)                           \
	CALL	sm2P256MulInternal<>(SB) \
	STy(s)                           \
	p256MulBy2Inline                 \
	STx(tmp)                         \
	\
	LDx(m)                           \
	CALL	sm2P256SqrInternal<>(SB) \
	LDx(tmp)                         \
	CALL	sm2P256Subinternal<>(SB) \
	\
	STx(x3out)                       \
	\
	LDy(s)                           \
	CALL	sm2P256Subinternal<>(SB) \
	\
	LDy(m)                           \
	CALL	sm2P256MulInternal<>(SB) \
	\
	LDx(y3out)                       \
	CALL	sm2P256Subinternal<>(SB) \
	STx(y3out)                       \


/* ---------------------------------------*/
//func p256PointDouble6TimesAsm(res, in *SM2P256Point)
TEXT ·p256PointDouble6TimesAsm(SB),NOSPLIT,$136-16
	MOV	res+0(FP), res_ptr
	MOV	in+8(FP), a_ptr

	MOV p256one<>+0x08(SB), const0
	ADD $1, const0, const1

	// Begin point double
	MOV (8*8)(a_ptr), x0 
	MOV (8*9)(a_ptr), x1
	MOV (8*10)(a_ptr), x2
	MOV (8*11)(a_ptr), x3
	CALL	sm2P256SqrInternal<>(SB)    // z1ˆ2
	MOV y0, zsqr(0*8)                  // store z^2
	MOV y1, zsqr(1*8)
	MOV y2, zsqr(2*8)
	MOV y3, zsqr(3*8)

	MOV (8*0)(a_ptr), x0               // load x
	MOV (8*1)(a_ptr), x1
	MOV (8*2)(a_ptr), x2
	MOV (8*3)(a_ptr), x3
	p256AddInline
	STx(m)

	LDx(z1in)
	LDy(y1in)
	CALL	sm2P256MulInternal<>(SB)
	p256MulBy2Inline
	STx(z3out)

	LDy(x1in)
	LDx(zsqr)
	CALL	sm2P256Subinternal<>(SB)
	LDy(m)
	CALL	sm2P256MulInternal<>(SB)

	// Multiply by 3
	p256MulBy2Inline
	p256AddInline
	STx(m)

	LDy(y1in)
	p256MulBy2Inline
	CALL	sm2P256SqrInternal<>(SB)
	STy(s)
	MOV	y0, x0
	MOV	y1, x1
	MOV	y2, x2
	MOV	y3, x3
	CALL	sm2P256SqrInternal<>(SB)

	// Divide by 2
	p256DivideBy2

	STy(y3out)

	LDx(x1in)
	LDy(s)
	CALL	sm2P256MulInternal<>(SB)
	STy(s)
	p256MulBy2Inline
	STx(tmp)

	LDx(m)
	CALL	sm2P256SqrInternal<>(SB)
	LDx(tmp)
	CALL	sm2P256Subinternal<>(SB)

	STx(x3out)

	LDy(s)
	CALL	sm2P256Subinternal<>(SB)

	LDy(m)
	CALL	sm2P256MulInternal<>(SB)

	LDx(y3out)
	CALL	sm2P256Subinternal<>(SB)
	STx(y3out)

	// Begin point double rounds 2 - 6
	p256PointDoubleRound()
	p256PointDoubleRound()
	p256PointDoubleRound()
	p256PointDoubleRound()
	p256PointDoubleRound()

	RET

/* ---------------------------------------*/
#undef y2in
#undef x3out
#undef y3out
#undef z3out
#define y2in(off) (off + 32)(b_ptr)
#define x3out(off) (off)(b_ptr)
#define y3out(off) (off + 32)(b_ptr)
#define z3out(off) (off + 64)(b_ptr)
// func p256PointAddAsm(res, in1, in2 *SM2P256Point) int
TEXT ·p256PointAddAsm(SB),0,$392-32
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
	// Move input to stack in order to free registers
	MOV	in1+8(FP), a_ptr
	MOV	in2+16(FP), b_ptr

	MOV p256one<>+0x08(SB), const0
	ADD $1, const0, const1

	// Begin point add
	LDx(z2in)
	CALL	sm2P256SqrInternal<>(SB)    // z2^2
	STy(z2sqr)

	CALL	sm2P256MulInternal<>(SB)    // z2^3

	LDx(y1in)
	CALL	sm2P256MulInternal<>(SB)    // s1 = z2ˆ3*y1
	STy(s1)

	LDx(z1in)
	CALL	sm2P256SqrInternal<>(SB)    // z1^2
	STy(z1sqr)

	CALL	sm2P256MulInternal<>(SB)    // z1^3

	LDx(y2in)
	CALL	sm2P256MulInternal<>(SB)    // s2 = z1ˆ3*y2

	LDx(s1)
	CALL	sm2P256Subinternal<>(SB)    // r = s2 - s1
	STx(r)

	// Check if zero mod p256
	OR x0, x1, acc0
	OR x2, x3, acc1
	OR acc0, acc1, acc1
	SLTU acc1, ZERO, acc1
	XOR $1, acc1, hlp0   // hlp0 = (if zero then 1 else 0)

	MOV $-1, acc0
	MOV p256p<>+0x08(SB), acc1
	MOV p256p<>+0x18(SB), acc3

	XOR acc0, x0, acc4
	XOR acc1, x1, acc5
	XOR acc0, x2, acc6
	XOR acc3, x3, acc7
	OR acc4, acc5, acc4
	OR acc6, acc7, acc7
	OR acc4, acc7, acc7
	SLTU acc7, ZERO, acc7
	XOR $1, acc7, res_ptr    // res_ptr = (if zero then 1 else 0)
	OR hlp0, res_ptr, res_ptr

	LDx(z2sqr)
	LDy(x1in)
	CALL	sm2P256MulInternal<>(SB)    // u1 = x1 * z2ˆ2
	STy(u1)

	LDx(z1sqr)
	LDy(x2in)
	CALL	sm2P256MulInternal<>(SB)    // u2 = x2 * z1ˆ2
	STy(u2)

	LDx(u1)
	CALL	sm2P256Subinternal<>(SB)    // h = u2 - u1
	STx(h)

	// Check if zero mod p256
	OR x0, x1, acc0
	OR x2, x3, acc1
	OR acc0, acc1, acc1
	SLTU acc1, ZERO, acc1
	XOR $1, acc1, hlp0   // hlp0 = (if zero then 1 else 0)

	MOV $-1, acc0
	MOV p256p<>+0x08(SB), acc1
	MOV p256p<>+0x18(SB), acc3

	XOR acc0, x0, acc4
	XOR acc1, x1, acc5
	XOR acc0, x2, acc6
	XOR acc3, x3, acc7
	OR acc4, acc5, acc4
	OR acc6, acc7, acc7
	OR acc4, acc7, acc7
	SLTU acc7, ZERO, acc7
	XOR $1, acc7, t0    // t0 = (if zero then 1 else 0)
	OR hlp0, t0, hlp0

	AND hlp0, res_ptr, res_ptr

	LDx(r)
	CALL	sm2P256SqrInternal<>(SB)    // rsqr = rˆ2
	STy(rsqr)

	LDx(h)
	CALL	sm2P256SqrInternal<>(SB)    // hsqr = hˆ2
	STy(hsqr)

	LDx(h)
	CALL	sm2P256MulInternal<>(SB)    // hcub = hˆ3
	STy(hcub)

	LDx(s1)
	CALL	sm2P256MulInternal<>(SB)
	STy(s2)

	LDx(z1in)
	LDy(z2in)
	CALL	sm2P256MulInternal<>(SB)    // z1 * z2
	LDx(h)
	CALL	sm2P256MulInternal<>(SB)    // z1 * z2 * h
	MOV	res+0(FP), b_ptr
	STy(z3out)

	LDx(hsqr)
	LDy(u1)
	CALL	sm2P256MulInternal<>(SB)    // hˆ2 * u1
	STy(u2)

	p256MulBy2Inline               // u1 * hˆ2 * 2, inline
	LDy(rsqr)
	CALL	sm2P256Subinternal<>(SB)    // rˆ2 - u1 * hˆ2 * 2

	MOV	x0, y0
	MOV	x1, y1
	MOV	x2, y2
	MOV	x3, y3
	LDx(hcub)
	CALL	sm2P256Subinternal<>(SB)
	STx(x3out)

	LDy(u2)
	CALL	sm2P256Subinternal<>(SB)

	LDy(r)
	CALL	sm2P256MulInternal<>(SB)

	LDx(s2)
	CALL	sm2P256Subinternal<>(SB)
	STx(y3out)

	MOV	res_ptr, ret+24(FP)

	RET
