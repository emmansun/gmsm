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

// res = a + b + carryIn
// carryOut = 0 or 1
// a and res CAN'T be the same register
// carryIn and carryOut CAN be the same register
#define ADCS(carryIn, a, b, res, carryOut, carryTmp) \
	ADD a, b, res                       \
	SLTU a, res, carryTmp                \
	ADDV carryIn, res, res               \
	SLTU carryIn, res, carryOut          \
	OR carryTmp, carryOut, carryOut

// res = a + b
// carryOut = 0 or 1
// a and res CAN'T be the same register
#define ADDS(a, b, res, carryOut) \
	ADD a, b, res                       \
	SLTU a, res, carryOut

// res = a + b + carryIn
#define ADC(carryIn, a, b, res) \
	ADD a, b, res                       \
	ADD carryIn, res, res

// res = b - a - borrowIn
// borrowOut = 0 or 1
// borrowIn and borrowOut CAN be the same register
#define SBCS(borrowIn, a, b, res, borrowOut, borrowTmp1, borrowTmp2) \
	SLTU a, b, borrowTmp1                 \
	SUB a, b, res                        \
	SLTU borrowIn, res, borrowTmp2        \
	SUB borrowIn, res, res               \
	OR borrowTmp1, borrowTmp2, borrowOut

#define SUBS(a, b, res, borrowOut) \
	SLTU a, b, borrowOut                 \
	SUB a, b, res

#define storeBlock(a0,a1,a2,a3, r) \
	MOV a0,  0+r \
	MOV a1,  8+r \
	MOV a2, 16+r \
	MOV a3, 24+r

#define loadBlock(r, a0,a1,a2,a3) \
	MOV  0+r, a0 \
	MOV  8+r, a1 \
	MOV 16+r, a2 \
	MOV 24+r, a3

#define loadModulus(p0,p1,p2,p3) \
	MOV ·p2+0(SB), p0 \
	MOV ·p2+8(SB), p1 \
	MOV ·p2+16(SB), p2 \
	MOV ·p2+24(SB), p3

// func gfpNeg(c, a *gfP)
TEXT ·gfpNeg(SB), NOSPLIT, $0-16
	MOV a+8(FP), a_ptr
	loadBlock(0(a_ptr), x0, x1, x2, x3)
	loadModulus(const0, const1, const2, const3)

	SUBS(x0, const0, x0, t0)
	// SBCS x1, const1, x1
	SBCS(t0, x1, const1, x1, t0, t1, hlp0)
	// SBCS x2, const2, x2
	SBCS(t0, x2, const2, x2, t0, t1, hlp0)
	// SUBCS x3, const3, x3
	ADD t0, x3, x3
	SUB x3, const3, x3 // last one no need to check carry

	XOR const0, x0, t0
	XOR const1, x1, t1
	OR t1, t0
	XOR const2, x2, t1
	OR t1, t0
	XOR const3, x3, t1
	OR t1, t0

	SLTU t0, ZERO, t0
	SUB t0, ZERO, t0

	AND t0, x0, x0
	AND t0, x1, x1
	AND t0, x2, x2
	AND t0, x3, x3
	
	MOV c+0(FP), res_ptr
	storeBlock(x0, x1, x2, x3, 0(res_ptr))

	RET

#define gfpCarry(x0, x1, x2, x3, carry, const0, const1, const2, const3) \
	\ // (acc3, acc2, acc1, acc0) = (x3, x2, x1, x0) - p
	SUBS(const0, x0, acc0, t0)               \
	SBCS(t0, const1, x1, acc1, t0, t1, hlp0) \
	SBCS(t0, const2, x2, acc2, t0, t1, hlp0) \
	SBCS(t0, const3, x3, acc3, t0, t1, hlp0) \
	\
	SLTU t0, carry, t0                 \ // if there are borrowings, t0 = 1 else 0
	SUB $1, t0, t0                     \ // mask = -cond
	XOR $-1, t0, t1                    \ // if there are borrowings, t0 = 0 and t1 = -1 else t0 = -1 and t1 = 0	
	\
	AND t1, x0, x0                     \
	AND t0, acc0, acc0                 \
	OR acc0, x0, x0                    \
	AND t1, x1, x1                     \
	AND t0, acc1, acc1                 \
	OR acc1, x1, x1                    \
	AND t1, x2, x2                     \
	AND t0, acc2, acc2                 \
	OR acc2, x2, x2                    \
	AND t1, x3, x3                     \
	AND t0, acc3, acc3                 \
	OR acc3, x3, x3

// func gfpAdd(c, a, b *gfP)
TEXT ·gfpAdd(SB), NOSPLIT, $0-24
	MOV a+8(FP), a_ptr
	MOV b+16(FP), b_ptr

	loadBlock(0(a_ptr), x0, x1, x2, x3)
	loadBlock(0(b_ptr), y0, y1, y2, y3)

	ADDS(y0, x0, x0, t0)
	ADCS(t0, y1, x1, x1, t0, t1)
	ADCS(t0, y2, x2, x2, t0, t1)
	ADCS(t0, y3, x3, x3, acc5, t1)

	// reducation
	loadModulus(const0, const1, const2, const3)
	gfpCarry(x0, x1, x2, x3, acc5, const0, const1, const2, const3)

	MOV c+0(FP), res_ptr
	storeBlock(x0, x1, x2, x3, 0(res_ptr))
	RET

// func gfpDouble(c, a *gfP)
TEXT ·gfpDouble(SB), NOSPLIT, $0-16
	MOV a+8(FP), a_ptr
	
	loadBlock(0(a_ptr), x0, x1, x2, x3)
	SRL $63, x0, t0
	SLL $1, x0, x0
	SRL $63, x1, t1
	SLL $1, x1, x1
	ADD t0, x1, x1
	SRL $63, x2, t0
	SLL $1, x2, x2
	ADD t1, x2, x2
	SRL $63, x3, acc5
	SLL $1, x3, x3
	ADD t0, x3, x3

	// reducation
	loadModulus(const0, const1, const2, const3)
	gfpCarry(x0, x1, x2, x3, acc5, const0, const1, const2, const3)

	MOV c+0(FP), res_ptr
	storeBlock(x0, x1, x2, x3, 0(res_ptr))	
	RET

// func gfpTriple(c, a *gfP)
TEXT ·gfpTriple(SB), NOSPLIT, $0-16
	MOV a+8(FP), a_ptr

	loadBlock(0(a_ptr), x0, x1, x2, x3)
	// double first
	SRL $63, x0, t0
	SLL $1, x0, y0
	SRL $63, x1, t1
	SLL $1, x1, y1
	ADD t0, y1, y1
	SRL $63, x2, t0
	SLL $1, x2, y2
	ADD t1, y2, y2
	SRL $63, x3, acc5
	SLL $1, x3, y3
	ADD t0, y3, y3

	// reducation
	loadModulus(const0, const1, const2, const3)
	gfpCarry(y0, y1, y2, y3, acc5, const0, const1, const2, const3)

	// add once more
	ADDS(y0, x0, x0, t0)
	ADCS(t0, y1, x1, x1, t0, t1)
	ADCS(t0, y2, x2, x2, t0, t1)
	ADCS(t0, y3, x3, x3, acc5, t1)
	gfpCarry(x0, x1, x2, x3, acc5, const0, const1, const2, const3)

	MOV c+0(FP), res_ptr
	storeBlock(x0, x1, x2, x3, 0(res_ptr))
	RET

// func gfpSub(c, a, b *gfP)
TEXT ·gfpSub(SB), NOSPLIT, $0-24
	MOV a+8(FP), a_ptr
	MOV b+16(FP), b_ptr

	loadBlock(0(b_ptr), x0, x1, x2, x3)
	loadBlock(0(a_ptr), y0, y1, y2, y3)

	SUBS(x0, y0, acc0, t0)
	// SBCS x1, y1
	SBCS(t0, x1, y1, acc1, t0, t1, hlp0)
	// SBCS x2, y2
	SBCS(t0, x2, y2, acc2, t0, t1, hlp0)
	// SBCS x3, y3
	SBCS(t0, x3, y3, acc3, t0, t1, hlp0)

	// reduction
	loadModulus(const0, const1, const2, const3)

	SUB $1, t0, t0
	XOR $-1, t0, t0
	AND t0, const0, const0
	AND t0, const1, const1
	AND t0, const2, const2
	AND t0, const3, const3

	ADD const0, acc0, x0
	SLTU const0, x0, t0
	ADD const1, acc1, x1
	SLTU const1, x1, t1
	ADD t0, x1, x1
	SLTU t0, x1, hlp0
	OR hlp0, t1, t0
	ADD const2, acc2, x2
	SLTU const2, x2, t1
	ADD t0, x2, x2
	SLTU t0, x2, hlp0
	OR hlp0, t1, t0
	ADD const3, acc3, x3
	SLTU const3, x3, t1
	ADD t0, x3, x3

	MOV c+0(FP), res_ptr
	storeBlock(x0, x1, x2, x3, 0(res_ptr))
	RET

// func gfpMul(c, a, b *gfP)
TEXT ·gfpMul(SB), NOSPLIT, $0
	MOV a+8(FP), a_ptr
	MOV b+16(FP), b_ptr
	MOV ·np+0x00(SB), hlp1

	loadBlock(0(a_ptr), x0, x1, x2, x3)
	loadBlock(0(b_ptr), y0, y1, y2, y3)
	loadModulus(const0, const1, const2, const3)

	// y[0] * x
	MUL y0, x0, acc0
	MULHU y0, x0, acc4
	MUL y0, x1, acc1
	MULHU y0, x1, acc5
	MUL y0, x2, acc2
	MULHU y0, x2, acc6
	MUL y0, x3, acc3
	MULHU y0, x3, acc7

	// ADDS acc4, acc1
	ADD acc4, acc1, acc1
	SLTU acc4, acc1, t0
	// ADCS acc5, acc2
	ADD t0, acc5, acc5 // no carry
	ADD acc5, acc2, acc2
	SLTU acc5, acc2, t0
	// ADCS acc6, acc3
	ADD t0, acc6, acc6 // no carry
	ADD acc6, acc3, acc3
	SLTU acc6, acc3, t0
	// ADCS acc7, 0
	ADD t0, acc7, acc4 // no carry

	// First reduction step
	MUL acc0, hlp1, hlp0
	// MUL const0, hlp0, t0
	MUL const0, hlp0, t0
	// ADDS t0, acc0
	ADD t0, acc0, acc0 // acc0 is free now
	SLTU t0, acc0, t1
	MULHU const0, hlp0, y0
	
	// MUL const1, hlp0, t0
	MUL const1, hlp0, t0
	// ADCS t0, acc1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t0
	ADD t1, acc1, acc1
	SLTU t1, acc1, t1
	OR t0, t1
	MULHU const1, hlp0, acc0

	// MUL const2, hlp0, t0
	MUL const2, hlp0, t0
	// ADCS t0, acc2
	ADD t0, acc2, acc2
	SLTU t0, acc2, t0
	ADD t1, acc2, acc2
	SLTU t1, acc2, t1
	OR t0, t1
	MULHU const2, hlp0, a_ptr

	// MUL const3, hlp0, t0
	MUL const3, hlp0, t0
	// ADCS t0, acc3
	ADD t0, acc3, acc3
	SLTU t0, acc3, t0
	ADD t1, acc3, acc3
	SLTU t1, acc3, t1
	OR t0, t1
	MULHU const3, hlp0, hlp0
	ADD t1, acc4, acc4

	// ADDS y0, acc1
	ADD y0, acc1, acc1
	SLTU y0, acc1, t0
	// ADCS acc0, acc2
	ADD acc0, acc2, acc2
	SLTU acc0, acc2, t1
	ADD t0, acc2, acc2
	SLTU t0, acc2, t0
	OR t1, t0
	// ADCS a_ptr, acc3
	ADD a_ptr, acc3, acc3
	SLTU a_ptr, acc3, t1
	ADD t0, acc3, acc3
	SLTU t0, acc3, t0
	OR t1, t0
	// ADCS hlp0, ZERO, acc0
	ADD t0, hlp0, acc0

	// y[1] * x
	MUL y1, x0, t0
	// ADDS t0, acc1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t0
	MULHU y1, x0, y0

	MUL y1, x1, t1
	// ADCS t1, acc2
	ADD t1, acc2, acc2
	SLTU t1, acc2, hlp0
	ADD t0, acc2, acc2
	SLTU t0, acc2, t0
	OR hlp0, t0, t0
	MULHU y1, x1, acc6

	MUL y1, x2, t1
	// ADCS t1, acc3
	ADD t1, acc3, acc3
	SLTU t1, acc3, hlp0
	ADD t0, acc3, acc3
	SLTU t0, acc3, t0
	OR hlp0, t0, t0
	MULHU y1, x2, acc7

	MUL y1, x3, t1
	// ADCS t1, acc0
	ADD t1, acc0, acc0
	SLTU t1, acc0, hlp0
	ADD t0, acc0, acc0
	SLTU t0, acc0, t0
	OR hlp0, t0, acc5
	MULHU y1, x3, y1

	// ADDS y0, acc2
	ADD y0, acc2, acc2
	SLTU y0, acc2, t0
	// ADCS acc6, acc3
	ADD acc6, acc3, acc3
	SLTU acc6, acc3, t1
	ADD t0, acc3, acc3
	SLTU t0, acc3, t0
	OR t1, t0, t0
	// ADCS acc7, acc4
	ADD acc7, acc4, acc4
	SLTU acc7, acc4, t1
	ADD t0, acc4, acc4
	SLTU t0, acc4, t0
	OR t1, t0, t0
	// ADCS y1, acc5
	ADD y1, acc5, acc5
	ADD t0, acc5, acc5

	// Second reduction step
	MUL acc1, hlp1, hlp0
	// MUL const0, hlp0, t0
	MUL const0, hlp0, t0
	// ADDS t0, acc1
	ADD t0, acc1, acc1 // acc1 is free now
	SLTU t0, acc1, t1
	MULHU const0, hlp0, y0

	// MUL const1, hlp0, t0
	MUL const1, hlp0, t0
	// ADCS t0, acc2
	ADD t0, acc2, acc2
	SLTU t0, acc2, t0
	ADD t1, acc2, acc2
	SLTU t1, acc2, t1
	OR t0, t1
	MULHU const1, hlp0, y1

	// MUL const2, hlp0, t0
	MUL const2, hlp0, t0
	// ADCS t0, acc3
	ADD t0, acc3, acc3
	SLTU t0, acc3, t0
	ADD t1, acc3, acc3
	SLTU t1, acc3, t1
	OR t0, t1
	MULHU const2, hlp0, acc1

	// MUL const3, hlp0, t0
	MUL const3, hlp0, t0
	// ADCS t0, acc0
	ADD t0, acc0, acc0
	SLTU t0, acc0, t0
	ADD t1, acc0, acc0
	SLTU t1, acc0, t1
	OR t0, t1
	MULHU const3, hlp0, hlp0
	ADD t1, acc5, acc5

	// ADDS y0, acc2
	ADD y0, acc2, acc2
	SLTU y0, acc2, t0
	// ADCS y1, acc3
	ADD y1, acc3, acc3
	SLTU y1, acc3, t1
	ADD t0, acc3, acc3
	SLTU t0, acc3, t0
	OR t1, t0
	// ADCS acc1, acc0
	ADD acc1, acc0, acc0
	SLTU acc1, acc0, t1
	ADD t0, acc0, acc0
	SLTU t0, acc0, t0
	OR t1, t0
	// ADCS hlp0, ZERO, acc1
	ADD t0, hlp0, acc1

	// y[2] * x
	MUL y2, x0, t0
	// ADDS t0, acc2
	ADD t0, acc2, acc2
	SLTU t0, acc2, t0
	MULHU y2, x0, y0

	MUL y2, x1, t1
	// ADCS t1, acc3
	ADD t1, acc3, acc3
	SLTU t1, acc3, hlp0
	ADD t0, acc3, acc3
	SLTU t0, acc3, t0
	OR hlp0, t0, t0
	MULHU y2, x1, y1

	MUL y2, x2, t1
	// ADCS t1, acc4
	ADD t1, acc4, acc4
	SLTU t1, acc4, hlp0
	ADD t0, acc4, acc4
	SLTU t0, acc4, t0
	OR hlp0, t0, t0
	MULHU y2, x2, acc7

	MUL y2, x3, t1
	// ADCS t1, acc5
	ADD t1, acc5, acc5
	SLTU t1, acc5, hlp0
	ADD t0, acc5, acc5
	SLTU t0, acc5, t0
	OR hlp0, t0, acc6
	MULHU y2, x3, y2

	// ADDS y0, acc3
	ADD y0, acc3, acc3
	SLTU y0, acc3, t0
	// ADCS y1, acc4
	ADD y1, acc4, acc4
	SLTU y1, acc4, t1
	ADD t0, acc4, acc4
	SLTU t0, acc4, t0
	OR t1, t0, t0
	// ADCS acc7, acc5
	ADD acc7, acc5, acc5
	SLTU acc7, acc5, t1
	ADD t0, acc5, acc5
	SLTU t0, acc5, t0
	OR t1, t0, t0
	// ADCS y2, acc6
	ADD y2, acc6, acc6
	ADD t0, acc6, acc6

	// Third reduction step
	MUL acc2, hlp1, hlp0
	// MUL const0, hlp0, t0
	MUL const0, hlp0, t0
	// ADDS t0, acc2
	ADD t0, acc2, acc2 // acc2 is free now
	SLTU t0, acc2, t1
	MULHU const0, hlp0, y0

	// MUL const1, hlp0, t0
	MUL const1, hlp0, t0
	// ADCS t0, acc3
	ADD t0, acc3, acc3
	SLTU t0, acc3, t0
	ADD t1, acc3, acc3
	SLTU t1, acc3, t1
	OR t0, t1
	MULHU const1, hlp0, y1

	// MUL const2, hlp0, t0
	MUL const2, hlp0, t0
	// ADCS t0, acc0
	ADD t0, acc0, acc0
	SLTU t0, acc0, t0
	ADD t1, acc0, acc0
	SLTU t1, acc0, t1
	OR t0, t1
	MULHU const2, hlp0, y2

	// MUL const3, hlp0, t0
	MUL const3, hlp0, t0
	// ADCS t0, acc1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t0
	ADD t1, acc1, acc1
	SLTU t1, acc1, t1
	OR t0, t1
	MULHU const3, hlp0, hlp0
	ADD t1, acc6, acc6

	// ADDS y0, acc3
	ADD y0, acc3, acc3
	SLTU y0, acc3, t0
	// ADCS y1, acc0
	ADD y1, acc0, acc0
	SLTU y1, acc0, t1
	ADD t0, acc0, acc0
	SLTU t0, acc0, t0
	OR t1, t0
	// ADCS y2, acc1
	ADD y2, acc1, acc1
	SLTU y2, acc1, t1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t0
	OR t1, t0
	// ADC hlp0, ZERO, acc2
	ADD t0, hlp0, acc2

	// y[3] * x
	MUL y3, x0, t0
	// ADDS t0, acc3
	ADD t0, acc3, acc3
	SLTU t0, acc3, t0
	MULHU y3, x0, y0

	MUL y3, x1, t1
	// ADCS t1, acc4
	ADD t1, acc4, acc4
	SLTU t1, acc4, hlp0
	ADD t0, acc4, acc4
	SLTU t0, acc4, t0
	OR hlp0, t0, t0
	MULHU y3, x1, y1

	MUL y3, x2, t1
	// ADCS t1, acc5
	ADD t1, acc5, acc5
	SLTU t1, acc5, hlp0
	ADD t0, acc5, acc5
	SLTU t0, acc5, t0
	OR hlp0, t0, t0
	MULHU y3, x2, y2

	MUL y3, x3, t1
	// ADCS t1, acc6
	ADD t1, acc6, acc6
	SLTU t1, acc6, hlp0
	ADD t0, acc6, acc6
	SLTU t0, acc6, t0
	OR hlp0, t0, acc7
	MULHU y3, x3, y3

	// ADDS y0, acc4
	ADD y0, acc4, acc4
	SLTU y0, acc4, t0
	// ADCS y1, acc5
	ADD y1, acc5, acc5
	SLTU y1, acc5, t1
	ADD t0, acc5, acc5
	SLTU t0, acc5, t0
	OR t1, t0, t0
	// ADCS y2, acc6
	ADD y2, acc6, acc6
	SLTU y2, acc6, t1
	ADD t0, acc6, acc6
	SLTU t0, acc6, t0
	OR t1, t0, t0
	// ADCS y3, acc7
	ADD y3, acc7, acc7
	ADD t0, acc7, acc7

	// Last reduction step
	MUL acc3, hlp1, hlp0
	// MUL const0, hlp0, t0
	MUL const0, hlp0, t0
	// ADDS t0, acc3
	ADD t0, acc3, acc3 // acc3 is free now
	SLTU t0, acc3, t1
	MULHU const0, hlp0, y0

	// MUL const1, hlp0, t0
	MUL const1, hlp0, t0
	// ADCS t0, acc0
	ADD t0, acc0, acc0
	SLTU t0, acc0, t0
	ADD t1, acc0, acc0
	SLTU t1, acc0, t1
	OR t0, t1
	MULHU const1, hlp0, y1

	// MUL const2, hlp0, t0
	MUL const2, hlp0, t0
	// ADCS t0, acc1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t0
	ADD t1, acc1, acc1
	SLTU t1, acc1, t1
	OR t0, t1
	MULHU const2, hlp0, y2

	// MUL const3, hlp0, t0
	MUL const3, hlp0, t0
	// ADCS t0, acc2
	ADD t0, acc2, acc2
	SLTU t0, acc2, t0
	ADD t1, acc2, acc2
	SLTU t1, acc2, t1
	OR t0, t1
	MULHU const3, hlp0, hlp0
	ADD t1, acc7, acc7

	// ADDS y0, acc0
	ADD y0, acc0, acc0
	SLTU y0, acc0, t0
	// ADCS y1, acc1
	ADD y1, acc1, acc1
	SLTU y1, acc1, t1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t0
	OR t1, t0
	// ADCS y2, acc2
	ADD y2, acc2, acc2
	SLTU y2, acc2, t1
	ADD t0, acc2, acc2
	SLTU t0, acc2, t0
	OR t1, t0
	// ADC hlp0, ZERO, acc3
	ADD t0, hlp0, acc3

	ADD acc4, acc0, x0
	SLTU acc4, x0, t0
	ADD acc5, acc1, x1
	SLTU acc5, x1, t1
	ADD t0, x1, x1
	SLTU t0, x1, t0
	OR t1, t0, t0
	ADD acc6, acc2, x2
	SLTU acc6, x2, t1
	ADD t0, x2, x2
	SLTU t0, x2, t0
	OR t1, t0, t0
	ADD acc7, acc3, x3
	SLTU acc7, x3, t1
	ADD t0, x3, x3
	SLTU t0, x3, acc5
	OR t1, acc5, acc5

	// final reduction
	gfpCarry(x0, x1, x2, x3, acc5, const0, const1, const2, const3)

	MOV c+0(FP), res_ptr
	storeBlock(x0, x1, x2, x3, 0(res_ptr))

	RET

// func gfpSqr(res, in *gfP, n int)
TEXT ·gfpSqr(SB), NOSPLIT, $0
	MOV in+8(FP), a_ptr
	MOV n+16(FP), b_ptr
	MOV ·np+0x00(SB), hlp1

	loadBlock(0(a_ptr), x0, x1, x2, x3)
	loadModulus(const0, const1, const2, const3)

sqrLoop:
		SUB	$1, b_ptr

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
		SLTU t0, acc3, t0
		MULHU x1, x2, t1
		// ADCS t1, acc4
		ADD t1, acc4, acc4
		SLTU t1, acc4, t1
		ADD t0, acc4, acc4
		SLTU t0, acc4, t0
		// ADC $0, acc5
		OR t0, t1, acc5

		MUL x1, x3, t0
		// ADCS t0, acc4
		ADD t0, acc4, acc4
		SLTU t0, acc4, t0
		MULHU x1, x3, t1
		// ADC	t1, acc5
		ADD t1, t0, t0       // no carry
		ADD t0, acc5, acc5   // no carry

		// x[3] * x[2]
		MUL x2, x3, t0
		// ADDS t0, acc5
		ADD t0, acc5, acc5
		SLTU t0, acc5, t1
		MULHU x2, x3, acc6
		// ADC	$0, acc6
		ADD t1, acc6, acc6   // no carry

		// *2
		// ALSLV is NOT supported in go 1.25
		SRL $63, acc1, t0
		SLL $1, acc1, acc1
		SRL $63, acc2, t1
		// ALSLV $1, t0, acc2, acc2
		SLL $1, acc2, acc2
		ADD t0, acc2, acc2
		SRL $63, acc3, t0
		// ALSLV $1, t1, acc3, acc3
		SLL $1, acc3, acc3
		ADD t1, acc3, acc3
		SRL $63, acc4, t1
		// ALSLV $1, t0, acc4, acc4
		SLL $1, acc4, acc4
		ADD t0, acc4, acc4
		SRL $63, acc5, t0
		// ALSLV $1, t1, acc5, acc5
		SLL $1, acc5, acc5
		ADD t1, acc5, acc5
		SRL $63, acc6, acc7
		// ALSLV $1, t0, acc6, acc6
		SLL $1, acc6, acc6
		ADD t0, acc6, acc6

		// Missing products
		MUL x0, x0, acc0
		MULHU x0, x0, t0
		// ADDS t0, acc1
		ADD t0, acc1, acc1
		SLTU t0, acc1, t1
		MUL x1, x1, t0
		// ADCS t0, acc2
		ADD t0, t1, t1         // no carry
		ADD t1, acc2, acc2
		SLTU t1, acc2, t1
		MULHU x1, x1, t0
		// ADCS t0, acc3
		ADD t0, t1, t0	    // no carry
		ADD t0, acc3, acc3
		SLTU t0, acc3, t1
		MUL x2, x2, t0
		// ADCS t0, acc4
		ADD t0, t1, t0         // no carry
		ADD t0, acc4, acc4
		SLTU t0, acc4, t1
		MULHU x2, x2, t0
		// ADCS t0, acc5
		ADD t0, t1, t0     // no carry
		ADD t0, acc5, acc5
		SLTU t0, acc5, t1
		MUL x3, x3, t0
		// ADCS t0, acc6
		ADD t0, t1, t0         // no carry
		ADD t0, acc6, acc6
		SLTU t0, acc6, t1
		MULHU x3, x3, t0
		// ADC	t0, acc7
		ADD t0, t1, t0     // no carry
		ADD t0, acc7, acc7   // (acc0, acc1, acc2, acc3, acc4, acc5, acc6, acc7) is the result

		// First reduction step
		MUL acc0, hlp1, hlp0
		// MUL	const0, hlp0, t0
		MUL hlp0, const0, t0
		// ADDS t0, acc0
		ADD t0, acc0, acc0
		SLTU t0, acc0, t1
		MULHU hlp0, const0, y0

		// MUL const1, hlp0, t0
		MUL hlp0, const1, t0
		// ADCS t0, acc1
		ADD t0, acc1, acc1
		SLTU t0, acc1, t0
		ADD t1, acc1, acc1
		SLTU t1, acc1, t1
		OR t0, t1, t1
		MULHU hlp0, const1, y1

		// MUL const2, hlp0, t0
		MUL hlp0, const2, t0
		// ADCS t0, acc2
		ADD t0, acc2, acc2
		SLTU t0, acc2, t0
		ADD t1, acc2, acc2
		SLTU t1, acc2, t1
		OR t0, t1, t1
		MULHU hlp0, const2, y2

		// MUL const3, hlp0, t0
		MUL hlp0, const3, t0
		// ADCS t0, acc3
		ADD t0, acc3, acc3
		SLTU t0, acc3, t0
		ADD t1, acc3, acc3
		SLTU t1, acc3, t1
		OR t0, t1, t1
		MULHU hlp0, const3, acc0
		ADD t1, acc0, acc0         // no carry

		ADD y0, acc1, acc1
		SLTU y0, acc1, t0
		ADD y1, acc2, acc2
		SLTU y1, acc2, t1
		ADD t0, acc2, acc2
		SLTU t0, acc2, t0
		OR t1, t0, t0
		ADD y2, acc3, acc3
		SLTU y2, acc3, t1
		ADD t0, acc3, acc3
		SLTU t0, acc3, t0
		OR t1, t0, t0
		ADD t0, acc0, acc0

		// Second reduction step
		MUL acc1, hlp1, hlp0
		// MUL	const0, hlp0, t0
		MUL hlp0, const0, t0
		// ADDS t0, acc1
		ADD t0, acc1, acc1
		SLTU t0, acc1, t1
		MULHU hlp0, const0, y0

		// MUL const1, hlp0, t0
		MUL hlp0, const1, t0
		// ADCS t0, acc2
		ADD t0, acc2, acc2
		SLTU t0, acc2, t0
		ADD t1, acc2, acc2
		SLTU t1, acc2, t1
		OR t0, t1, t1
		MULHU hlp0, const1, y1

		// MUL const2, hlp0, t0
		MUL hlp0, const2, t0
		// ADCS t0, acc3
		ADD t0, acc3, acc3
		SLTU t0, acc3, t0
		ADD t1, acc3, acc3
		SLTU t1, acc3, t1
		OR t0, t1, t1
		MULHU hlp0, const2, y2

		// MUL const3, hlp0, t0
		MUL hlp0, const3, t0
		// ADCS t0, acc0
		ADD t0, acc0, acc0
		SLTU t0, acc0, t0
		ADD t1, acc0, acc0
		SLTU t1, acc0, t1
		OR t0, t1, t1
		MULHU hlp0, const3, acc1
		ADD t1, acc1, acc1       // no carry

		ADD y0, acc2, acc2
		SLTU y0, acc2, t0
		ADD y1, acc3, acc3
		SLTU y1, acc3, t1
		ADD t0, acc3, acc3
		SLTU t0, acc3, t0
		OR t1, t0, t0
		ADD y2, acc0, acc0
		SLTU y2, acc0, t1
		ADD t0, acc0, acc0
		SLTU t0, acc0, t0
		OR t1, t0, t0
		ADD t0, acc1, acc1

		// Third reduction step
		MUL acc2, hlp1, hlp0
		// MUL	const0, hlp0, t0
		MUL hlp0, const0, t0
		// ADDS t0, acc2
		ADD t0, acc2, acc2
		SLTU t0, acc2, t1
		MULHU hlp0, const0, y0

		// MUL const1, hlp0, t0
		MUL hlp0, const1, t0
		// ADCS t0, acc3
		ADD t0, acc3, acc3
		SLTU t0, acc3, t0
		ADD t1, acc3, acc3
		SLTU t1, acc3, t1
		OR t0, t1, t1
		MULHU hlp0, const1, y1

		// MUL const2, hlp0, t0
		MUL hlp0, const2, t0
		// ADCS t0, acc0
		ADD t0, acc0, acc0
		SLTU t0, acc0, t0
		ADD t1, acc0, acc0
		SLTU t1, acc0, t1
		OR t0, t1, t1
		MULHU hlp0, const2, y2

		// MUL const3, hlp0, t0
		MUL hlp0, const3, t0
		// ADCS t0, acc1
		ADD t0, acc1, acc1
		SLTU t0, acc1, t0
		ADD t1, acc1, acc1
		SLTU t1, acc1, t1
		OR t0, t1, t1
		MULHU hlp0, const3, acc2
		ADD t1, acc2, acc2       // no carry

		ADD y0, acc3, acc3
		SLTU y0, acc3, t0
		ADD y1, acc0, acc0
		SLTU y1, acc0, t1
		ADD t0, acc0, acc0
		SLTU t0, acc0, t0
		OR t1, t0, t0
		ADD y2, acc1, acc1
		SLTU y2, acc1, t1
		ADD t0, acc1, acc1
		SLTU t0, acc1, t0
		OR t1, t0, t0
		ADD t0, acc2, acc2

		// Last reduction step
		MUL acc3, hlp1, hlp0
		// MUL	const0, hlp0, t0
		MUL hlp0, const0, t0
		// ADDS t0, acc3
		ADD t0, acc3, acc3
		SLTU t0, acc3, t1
		MULHU hlp0, const0, y0

		// MUL const1, hlp0, t0
		MUL hlp0, const1, t0
		// ADCS t0, acc0
		ADD t0, acc0, acc0
		SLTU t0, acc0, t0
		ADD t1, acc0, acc0
		SLTU t1, acc0, t1
		OR t0, t1, t1
		MULHU hlp0, const1, y1

		// MUL const2, hlp0, t0
		MUL hlp0, const2, t0
		// ADCS t0, acc1
		ADD t0, acc1, acc1
		SLTU t0, acc1, t0
		ADD t1, acc1, acc1
		SLTU t1, acc1, t1
		OR t0, t1, t1
		MULHU hlp0, const2, y2

		// MUL const3, hlp0, t0
		MUL hlp0, const3, t0
		// ADCS t0, acc2
		ADD t0, acc2, acc2
		SLTU t0, acc2, t0
		ADD t1, acc2, acc2
		SLTU t1, acc2, t1
		OR t0, t1, t1
		MULHU hlp0, const3, acc3
		ADD t1, acc3, acc3       // no carry

		ADD y0, acc0, acc0
		SLTU y0, acc0, t0
		ADD y1, acc1, acc1
		SLTU y1, acc1, t1
		ADD t0, acc1, acc1
		SLTU t0, acc1, t0
		OR t1, t0, t0
		ADD y2, acc2, acc2
		SLTU y2, acc2, t1
		ADD t0, acc2, acc2
		SLTU t0, acc2, t0
		OR t1, t0, t0
		ADD t0, acc3, acc3

		ADD acc4, acc0, x0
		SLTU acc4, x0, t0
		ADD acc5, acc1, x1
		SLTU acc5, x1, t1
		ADD t0, x1, x1
		SLTU t0, x1, t0
		OR t1, t0, t0
		ADD acc6, acc2, x2
		SLTU acc6, x2, t1
		ADD t0, x2, x2
		SLTU t0, x2, t0
		OR t1, t0, t0
		ADD acc7, acc3, x3
		SLTU acc7, x3, t1
		ADD t0, x3, x3
		SLTU t0, x3, acc5
		OR t1, acc5, acc5

		// final reduction
		gfpCarry(x0, x1, x2, x3, acc5, const0, const1, const2, const3)
		BNE b_ptr, ZERO, sqrLoop

	MOV res+0(FP), res_ptr
	storeBlock(x0, x1, x2, x3, 0(res_ptr))
	RET

/* ---------------------------------------*/
// func gfpFromMont(res, in *gfP)
TEXT ·gfpFromMont(SB), NOSPLIT, $0
	MOV in+8(FP), a_ptr
	MOV ·np+0x00(SB), hlp1

	loadBlock(0(a_ptr), acc0, acc1, acc2, acc3)
	loadModulus(const0, const1, const2, const3)

	// Only reduce, no multiplications are needed
	// First reduction step
	MUL acc0, hlp1, hlp0
	// MUL	const0, hlp0, t0
	MUL hlp0, const0, t0
	// ADDS t0, acc0
	ADD t0, acc0, acc0
	SLTU t0, acc0, t1
	MULHU hlp0, const0, y0

	// MUL const1, hlp0, t0
	MUL hlp0, const1, t0
	// ADCS t0, acc1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t0
	ADD t1, acc1, acc1
	SLTU t1, acc1, t1
	OR t0, t1, t1
	MULHU hlp0, const1, y1

	// MUL const2, hlp0, t0
	MUL hlp0, const2, t0
	// ADCS t0, acc2
	ADD t0, acc2, acc2
	SLTU t0, acc2, t0
	ADD t1, acc2, acc2
	SLTU t1, acc2, t1
	OR t0, t1, t1
	MULHU hlp0, const2, y2

	// MUL const3, hlp0, t0
	MUL hlp0, const3, t0
	// ADCS t0, acc3
	ADD t0, acc3, acc3
	SLTU t0, acc3, t0
	ADD t1, acc3, acc3
	SLTU t1, acc3, t1
	OR t0, t1, t1
	MULHU hlp0, const3, acc0
	ADD t1, acc0, acc0       // no carry

	ADD y0, acc1, acc1
	SLTU y0, acc1, t0
	ADD y1, acc2, acc2
	SLTU y1, acc2, t1
	ADD t0, acc2, acc2
	SLTU t0, acc2, t0
	OR t1, t0, t0
	ADD y2, acc3, acc3
	SLTU y2, acc3, t1
	ADD t0, acc3, acc3
	SLTU t0, acc3, t0
	OR t1, t0, t0
	ADD t0, acc0, acc0

	// Second reduction step
	MUL acc1, hlp1, hlp0
	// MUL	const0, hlp0, t0
	MUL hlp0, const0, t0
	// ADDS t0, acc1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t1
	MULHU hlp0, const0, y0

	// MUL const1, hlp0, t0
	MUL hlp0, const1, t0
	// ADCS t0, acc2
	ADD t0, acc2, acc2
	SLTU t0, acc2, t0
	ADD t1, acc2, acc2
	SLTU t1, acc2, t1
	OR t0, t1, t1
	MULHU hlp0, const1, y1

	// MUL const2, hlp0, t0
	MUL hlp0, const2, t0
	// ADCS t0, acc3
	ADD t0, acc3, acc3
	SLTU t0, acc3, t0
	ADD t1, acc3, acc3
	SLTU t1, acc3, t1
	OR t0, t1, t1
	MULHU hlp0, const2, y2

	// MUL const3, hlp0, t0
	MUL hlp0, const3, t0
	// ADCS t0, acc0
	ADD t0, acc0, acc0
	SLTU t0, acc0, t0
	ADD t1, acc0, acc0
	SLTU t1, acc0, t1
	OR t0, t1, t1
	MULHU hlp0, const3, acc1
	ADD t1, acc1, acc1       // no carry

	ADD y0, acc2, acc2
	SLTU y0, acc2, t0
	ADD y1, acc3, acc3
	SLTU y1, acc3, t1
	ADD t0, acc3, acc3
	SLTU t0, acc3, t0
	OR t1, t0, t0
	ADD y2, acc0, acc0
	SLTU y2, acc0, t1
	ADD t0, acc0, acc0
	SLTU t0, acc0, t0
	OR t1, t0, t0
	ADD t0, acc1, acc1

	// Third reduction step
	MUL acc2, hlp1, hlp0
	// MUL	const0, hlp0, t0
	MUL hlp0, const0, t0
	// ADDS t0, acc2
	ADD t0, acc2, acc2
	SLTU t0, acc2, t1
	MULHU hlp0, const0, y0

	// MUL const1, hlp0, t0
	MUL hlp0, const1, t0
	// ADCS t0, acc3
	ADD t0, acc3, acc3
	SLTU t0, acc3, t0
	ADD t1, acc3, acc3
	SLTU t1, acc3, t1
	OR t0, t1, t1
	MULHU hlp0, const1, y1

	// MUL const2, hlp0, t0
	MUL hlp0, const2, t0
	// ADCS t0, acc0
	ADD t0, acc0, acc0
	SLTU t0, acc0, t0
	ADD t1, acc0, acc0
	SLTU t1, acc0, t1
	OR t0, t1, t1
	MULHU hlp0, const2, y2

	// MUL const3, hlp0, t0
	MUL hlp0, const3, t0
	// ADCS t0, acc1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t0
	ADD t1, acc1, acc1
	SLTU t1, acc1, t1
	OR t0, t1, t1
	MULHU hlp0, const3, acc2
	ADD t1, acc2, acc2       // no carry

	ADD y0, acc3, acc3
	SLTU y0, acc3, t0
	ADD y1, acc0, acc0
	SLTU y1, acc0, t1
	ADD t0, acc0, acc0
	SLTU t0, acc0, t0
	OR t1, t0, t0
	ADD y2, acc1, acc1
	SLTU y2, acc1, t1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t0
	OR t1, t0, t0
	ADD t0, acc2, acc2

	// Last reduction step
	MUL acc3, hlp1, hlp0
	// MUL	const0, hlp0, t0
	MUL hlp0, const0, t0
	// ADDS t0, acc3
	ADD t0, acc3, acc3
	SLTU t0, acc3, t1
	MULHU hlp0, const0, y0

	// MUL const1, hlp0, t0
	MUL hlp0, const1, t0
	// ADCS t0, acc0
	ADD t0, acc0, acc0
	SLTU t0, acc0, t0
	ADD t1, acc0, acc0
	SLTU t1, acc0, t1
	OR t0, t1, t1
	MULHU hlp0, const1, y1

	// MUL const2, hlp0, t0
	MUL hlp0, const2, t0
	// ADCS t0, acc1
	ADD t0, acc1, acc1
	SLTU t0, acc1, t0
	ADD t1, acc1, acc1
	SLTU t1, acc1, t1
	OR t0, t1, t1
	MULHU hlp0, const2, y2

	// MUL const3, hlp0, t0
	MUL hlp0, const3, t0
	// ADCS t0, acc2
	ADD t0, acc2, acc2
	SLTU t0, acc2, t0
	ADD t1, acc2, acc2
	SLTU t1, acc2, t1
	OR t0, t1, t1
	MULHU hlp0, const3, acc3
	ADD t1, acc3, acc3       // no carry

	ADD y0, acc0, x0
	SLTU y0, x0, t0
	ADD y1, acc1, x1
	SLTU y1, x1, t1
	ADD t0, x1, x1
	SLTU t0, x1, t0
	OR t1, t0, t0
	ADD y2, acc2, x2
	SLTU y2, x2, t1
	ADD t0, x2, x2
	SLTU t0, x2, t0
	OR t1, t0, t0
	ADD t0, acc3, x3

	gfpCarry(x0, x1, x2, x3, ZERO, const0, const1, const2, const3)

	MOV res+0(FP), res_ptr
	storeBlock(x0, x1, x2, x3, 0(res_ptr))

	RET

/* ---------------------------------------*/
// func gfpUnmarshal(res *gfP, in *[32]byte)
TEXT ·gfpUnmarshal(SB), NOSPLIT, $0
	JMP	·gfpMarshal(SB)

/* ---------------------------------------*/
// func gfpMarshal(res *[32]byte, in *gfP)
TEXT ·gfpMarshal(SB),NOSPLIT,$0
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
