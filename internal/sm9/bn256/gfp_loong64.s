// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

#define ZERO R0
#define RSP R3
#define res_ptr R4
#define x_ptr R5
#define y_ptr R6
#define a_ptr x_ptr
#define b_ptr y_ptr

#define acc0 R7
#define acc1 R8
#define acc2 R9
#define acc3 R10

#define acc4 R11
#define acc5 R12
#define acc6 R13
#define acc7 R14

#define t0 R15
#define t1 R16
#define t2 R17
#define t3 R18

#define hlp0 R19
#define hlp1 res_ptr

#define x0 R20
#define x1 R21
#define x2 R23
#define x3 R24
#define y0 R25
#define y1 R26
#define y2 R27
#define y3 R31

#define const0 R28
#define const1 R29
#define const2 t2
#define const3 t3

#define storeBlock(a0,a1,a2,a3, r) \
	MOVV a0,  0+r \
	MOVV a1,  8+r \
	MOVV a2, 16+r \
	MOVV a3, 24+r

#define loadBlock(r, a0,a1,a2,a3) \
	MOVV  0+r, a0 \
	MOVV  8+r, a1 \
	MOVV 16+r, a2 \
	MOVV 24+r, a3

#define loadModulus(p0,p1,p2,p3) \
	MOVV ·p2+0(SB), p0 \
	MOVV ·p2+8(SB), p1 \
	MOVV ·p2+16(SB), p2 \
	MOVV ·p2+24(SB), p3

// func gfpNeg(c, a *gfP)
TEXT ·gfpNeg(SB), NOSPLIT, $0-16
	MOVV a+8(FP), a_ptr
	loadBlock(0(a_ptr), x0, x1, x2, x3)
	loadModulus(const0, const1, const2, const3)

	SGTU x0, const0, t0
	SUBV x0, const0, x0
	// SUBCS x1, const1, x1
	SGTU x1, const1, t1
	SUBV x1, const1, x1
	SGTU t0, x1, hlp0
	SUBV t0, x1, x1
	OR hlp0, t1, t0
	// SUBCS x2, const2, x2
	SGTU x2, const2, t1
	SUBV x2, const2, x2
	SGTU t0, x2, hlp0
	SUBV t0, x2, x2
	OR hlp0, t1, t0
	// SUBCS x3, const3, x3
	ADDV t0, x3, x3
	SUBV x3, const3, x3 // last one no need to check carry

	XOR const0, x0, t0
	XOR const1, x1, t1
	OR t1, t0
	XOR const2, x2, t1
	OR t1, t0
	XOR const3, x3, t1
	OR t1, t0

	MASKEQZ t0, x0, x0
	MASKEQZ t0, x1, x1
	MASKEQZ t0, x2, x2
	MASKEQZ t0, x3, x3
	
	MOVV c+0(FP), res_ptr
	storeBlock(x0, x1, x2, x3, 0(res_ptr))

	RET

#define gfpCarry(x0, x1, x2, x3, carry, const0, const1, const2, const3) \
	\ // (acc3, acc2, acc1, acc0) = (x3, x2, x1, x0) - p
	SGTU const0, x0, t0                \
	SUBV const0, x0, acc0              \
	SGTU const1, x1, t1                \
	SUBV const1, x1, acc1              \ 
	SGTU t0, acc1, hlp0                \
	SUBV t0, acc1, acc1                \
	OR hlp0, t1, t0                    \
	SGTU const2, x2, t1                \
	SUBV const2, x2, acc2              \
	SGTU t0, acc2, hlp0                \
	SUBV t0, acc2, acc2                \ 
	OR hlp0, t1, t0                    \ 
	SGTU const3, x3, t1                \
	SUBV const3, x3, acc3              \
	SGTU t0, acc3, hlp0                \
	SUBV t0, acc3, acc3                \
	OR hlp0, t1, t0                    \
	\
	SGTU t0, carry, t0                 \
	\
	MASKEQZ t0, x0, x0                 \
	MASKNEZ t0, acc0, acc0             \
	OR acc0, x0, x0                    \
	MASKEQZ t0, x1, x1                 \
	MASKNEZ t0, acc1, acc1             \
	OR acc1, x1, x1                    \
	MASKEQZ t0, x2, x2                 \
	MASKNEZ t0, acc2, acc2             \
	OR acc2, x2, x2                    \
	MASKEQZ t0, x3, x3                 \
	MASKNEZ t0, acc3, acc3             \
	OR acc3, x3, x3

// func gfpAdd(c, a, b *gfP)
TEXT ·gfpAdd(SB), NOSPLIT, $0-24
	MOVV a+8(FP), a_ptr
	MOVV b+16(FP), b_ptr
	MOVV c+0(FP), res_ptr

	loadBlock(0(a_ptr), x0, x1, x2, x3)
	loadBlock(0(b_ptr), y0, y1, y2, y3)

	ADDV x0, y0, x0
	SGTU y0, x0, t0

	ADDV x1, y1, x1
	SGTU y1, x1, t1
	ADDV t0, x1, x1
	SGTU t0, x1, hlp0
	OR hlp0, t1, t0

	ADDV x2, y2, x2
	SGTU y2, x2, t1
	ADDV t0, x2, x2
	SGTU t0, x2, hlp0
	OR hlp0, t1, t0

	ADDV x3, y3, x3
	SGTU y3, x3, t1
	ADDV t0, x3, x3
	SGTU t0, x3, hlp0
	OR hlp0, t1, acc5

	// reducation
	loadModulus(const0, const1, const2, const3)
	gfpCarry(x0, x1, x2, x3, acc5, const0, const1, const2, const3)

	storeBlock(x0, x1, x2, x3, 0(res_ptr))
	RET

// func gfpDouble(c, a *gfP)
TEXT ·gfpDouble(SB), NOSPLIT, $0-16
	MOVV a+8(FP), a_ptr
	MOVV c+0(FP), res_ptr

	loadBlock(0(a_ptr), x0, x1, x2, x3)
	SRLV $63, x0, t0
	SLLV $1, x0, x0
	SRLV $63, x1, t1
	SLLV $1, x1, x1
	ADDV t0, x1, x1
	SRLV $63, x2, t0
	SLLV $1, x2, x2
	ADDV t1, x2, x2
	SRLV $63, x3, acc5
	SLLV $1, x3, x3
	ADDV t0, x3, x3

	// reducation
	loadModulus(const0, const1, const2, const3)
	gfpCarry(x0, x1, x2, x3, acc5, const0, const1, const2, const3)

	storeBlock(x0, x1, x2, x3, 0(res_ptr))	
	RET

// func gfpTriple(c, a *gfP)
TEXT ·gfpTriple(SB), NOSPLIT, $0-16
	MOVV a+8(FP), a_ptr
	MOVV c+0(FP), res_ptr

	loadBlock(0(a_ptr), x0, x1, x2, x3)
	// double first
	SRLV $63, x0, t0
	SLLV $1, x0, y0
	SRLV $63, x1, t1
	SLLV $1, x1, y1
	ADDV t0, y1, y1
	SRLV $63, x2, t0
	SLLV $1, x2, y2
	ADDV t1, y2, y2
	SRLV $63, x3, acc5
	SLLV $1, x3, y3
	ADDV t0, y3, y3

	// reducation
	loadModulus(const0, const1, const2, const3)
	gfpCarry(y0, y1, y2, y3, acc5, const0, const1, const2, const3)

	// add once more
	ADDV x0, y0, x0
	SGTU y0, x0, t0
	ADDV x1, y1, x1
	SGTU y1, x1, t1
	ADDV t0, x1, x1
	SGTU t0, x1, hlp0
	OR hlp0, t1, t0
	ADDV x2, y2, x2
	SGTU y2, x2, t1
	ADDV t0, x2, x2
	SGTU t0, x2, hlp0
	OR hlp0, t1, t0
	ADDV x3, y3, x3
	SGTU y3, x3, t1
	ADDV t0, x3, x3
	SGTU t0, x3, hlp0
	OR hlp0, t1, acc5
	gfpCarry(y0, y1, y2, y3, acc5, const0, const1, const2, const3)
	storeBlock(x0, x1, x2, x3, 0(res_ptr))
	RET

// func gfpSub(c, a, b *gfP)
TEXT ·gfpSub(SB), NOSPLIT, $0-24
	MOVV a+8(FP), a_ptr
	MOVV b+16(FP), b_ptr
	MOVV c+0(FP), res_ptr

	loadBlock(0(b_ptr), x0, x1, x2, x3)
	loadBlock(0(a_ptr), y0, y1, y2, y3)

	SGTU x0, y0, t0
	SUBV x0, y0, acc0
	// SBCS x1, y1
	SGTU x1, y1, t1
	SUBV x1, y1, acc1
	SGTU t0, acc1, hlp0
	SUBV t0, acc1, acc1
	OR t1, hlp0, t0
	// SBCS x2, y2
	SGTU x2, y2, t1
	SUBV x2, y2, acc2
	SGTU t0, acc2, hlp0
	SUBV t0, acc2, acc2
	OR t1, hlp0, t0
	// SBCS x3, y3
	SGTU x3, y3, t1
	SUBV x3, y3, acc3
	SGTU t0, acc3, hlp0
	SUBV t0, acc3, acc3
	OR t1, hlp0, t0

	// reduction
	loadModulus(const0, const1, const2, const3)
	MASKEQZ t0, const0, const0
	MASKEQZ t0, const1, const1
	MASKEQZ t0, const2, const2
	MASKEQZ t0, const3, const3

	ADDV const0, acc0, x0
	SGTU const0, x0, t0
	ADDV const1, acc1, x1
	SGTU const1, x1, t1
	ADDV t0, x1, x1
	SGTU t0, x1, hlp0
	OR hlp0, t1, t0
	ADDV const2, acc2, x2
	SGTU const2, x2, t1
	ADDV t0, x2, x2
	SGTU t0, x2, hlp0
	OR hlp0, t1, t0
	ADDV const3, acc3, x3
	SGTU const3, x3, t1
	ADDV t0, x3, x3

	storeBlock(x0, x1, x2, x3, 0(res_ptr))
	RET

// func gfpMul(c, a, b *gfP)
TEXT ·gfpMul(SB), NOSPLIT, $0
	MOVV a+8(FP), a_ptr
	MOVV b+16(FP), b_ptr
	MOVV ·np+0x00(SB), hlp1

	loadBlock(0(a_ptr), x0, x1, x2, x3)
	loadBlock(0(b_ptr), y0, y1, y2, y3)
	loadModulus(const0, const1, const2, const3)

	// y[0] * x
	MULV y0, x0, acc0
	MULHVU y0, x0, acc4
	MULV y0, x1, acc1
	MULHVU y0, x1, acc5
	MULV y0, x2, acc2
	MULHVU y0, x2, acc6
	MULV y0, x3, acc3
	MULHVU y0, x3, acc7

	// ADDS acc4, acc1
	ADDV acc4, acc1, acc1
	SGTU acc4, acc1, t0
	// ADCS acc5, acc2
	ADDV t0, acc5, acc5 // no carry
	ADDV acc5, acc2, acc2
	SGTU acc5, acc2, t0
	// ADCS acc6, acc3
	ADDV t0, acc6, acc6 // no carry
	ADDV acc6, acc3, acc3
	SGTU acc6, acc3, t0
	// ADCS acc7, 0
	ADDV t0, acc7, acc4 // no carry

	// First reduction step
	MULV acc0, hlp1, hlp0
	// MUL const0, hlp0, t0
	MULV const0, hlp0, t0
	// ADDS t0, acc0
	ADDV t0, acc0, acc0 // acc0 is free now
	SGTU t0, acc0, t1
	MULHVU const0, hlp0, y0
	
	// MUL const1, hlp0, t0
	MULV const1, hlp0, t0
	// ADCS t0, acc1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t0
	ADDV t1, acc1, acc1
	SGTU t1, acc1, t1
	OR t0, t1
	MULHVU const1, hlp0, acc0

	// MUL const2, hlop, t0
	MULV const2, hlp0, t0
	// ADCS t0, acc2
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t0
	ADDV t1, acc2, acc2
	SGTU t1, acc2, t1
	OR t0, t1
	MULHVU const2, hlp0, a_ptr

	// MUL const3, hlop, t0
	MULV const3, hlp0, t0
	// ADCS t0, acc3
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t0
	ADDV t1, acc3, acc3
	SGTU t1, acc3, t1
	OR t0, t1
	MULHVU const2, hlp0, hlp0
	ADDV t1, acc4, acc4

	// ADDS y0, acc1
	ADDV y0, acc1, acc1
	SGTU y0, acc1, t0
	// ADCS acc0, acc2
	ADDV acc0, acc2, acc2
	SGTU acc0, acc2, t1
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t0
	OR t1, t0
	// ADCS a_ptr, acc3
	ADDV a_ptr, acc3, acc3
	SGTU a_ptr, acc3, t1
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t0
	OR t1, t0
	// ADCS hlp0, ZERO, acc0
	ADDV t0, hlp0, acc0

	// y[1] * x
	MULV y1, x0, t0
	// ADDS t0, acc1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t0
	MULHVU y1, x0, y0

	MULV y1, x1, t1
	// ADCS t1, acc2
	ADDV t1, acc2, acc2
	SGTU t1, acc2, hlp0
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t0
	OR hlp0, t0, t0
	MULHVU y1, x1, acc6

	MULV y1, x2, t1
	// ADCS t1, acc3
	ADDV t1, acc3, acc3
	SGTU t1, acc3, hlp0
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t0
	OR hlp0, t0, t0
	MULHVU y1, x2, acc7

	MULV y1, x3, t1
	// ADCS t1, acc0
	ADDV t1, acc0, acc0
	SGTU t1, acc0, hlp0
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t0
	OR hlp0, t0, acc5
	MULHVU y1, x3, y1

	// ADDS y0, acc2
	ADDV y0, acc2, acc2
	SGTU y0, acc2, t0
	// ADCS acc6, acc3
	ADDV acc6, acc3, acc3
	SGTU acc6, acc3, t1
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t0
	OR t1, t0, t0
	// ADCS acc7, acc4
	ADDV acc7, acc4, acc4
	SGTU acc7, acc4, t1
	ADDV t0, acc4, acc4
	SGTU t0, acc4, t0
	OR t1, t0, t0
	// ADCS y1, acc5
	ADDV y1, acc5, acc5
	ADDV t0, acc5, acc5

	// Second reduction step
	MULV acc1, hlp1, hlp0
	// MUL const0, hlop, t0
	MULV const0, hlp0, t0
	// ADDS t0, acc1
	ADDV t0, acc1, acc1 // acc1 is free now
	SGTU t0, acc1, t1
	MULHVU const0, hlp0, y0

	// MUL const1, hlop, t0
	MULV const1, hlp0, t0
	// ADCS t0, acc2
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t0
	ADDV t1, acc2, acc2
	SGTU t1, acc2, t1
	OR t0, t1
	MULHVU const1, hlp0, y1

	// MUL const2, hlop, t0
	MULV const2, hlp0, t0
	// ADCS t0, acc3
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t0
	ADDV t1, acc3, acc3
	SGTU t1, acc3, t1
	OR t0, t1
	MULHVU const2, hlp0, acc1

	// MUL const3, hlop, t0
	MULV const3, hlp0, t0
	// ADCS t0, acc0
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t0
	ADDV t1, acc0, acc0
	SGTU t1, acc0, t1
	OR t0, t1
	MULHVU const3, hlp0, hlp0
	ADDV t1, acc5, acc5

	// ADDS y0, acc2
	ADDV y0, acc2, acc2
	SGTU y0, acc2, t0
	// ADCS y1, acc3
	ADDV y1, acc3, acc3
	SGTU y1, acc3, t1
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t0
	OR t1, t0
	// ADCS acc1, acc0
	ADDV acc1, acc0, acc0
	SGTU acc1, acc0, t1
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t0
	OR t1, t0
	// ADCS hlp0, ZERO, acc1
	ADDV t0, hlp0, acc1

	// y[2] * x
	MULV y2, x0, t0
	// ADDS t0, acc2
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t0
	MULHVU y2, x0, y0

	MULV y2, x1, t1
	// ADCS t1, acc3
	ADDV t1, acc3, acc3
	SGTU t1, acc3, hlp0
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t0
	OR hlp0, t0, t0
	MULHVU y2, x1, y1

	MULV y2, x2, t1
	// ADCS t1, acc4
	ADDV t1, acc4, acc4
	SGTU t1, acc4, hlp0
	ADDV t0, acc4, acc4
	SGTU t0, acc4, t0
	OR hlp0, t0, t0
	MULHVU y2, x2, acc7

	MULV y2, x3, t1
	// ADCS t1, acc5
	ADDV t1, acc5, acc5
	SGTU t1, acc5, hlp0
	ADDV t0, acc5, acc5
	SGTU t0, acc5, t0
	OR hlp0, t0, acc6
	MULHVU y2, x3, y2

	// ADDS y0, acc3
	ADDV y0, acc3, acc3
	SGTU y0, acc3, t0
	// ADCS y1, acc4
	ADDV y1, acc4, acc4
	SGTU y1, acc4, t1
	ADDV t0, acc4, acc4
	SGTU t0, acc4, t0
	OR t1, t0, t0
	// ADCS acc7, acc5
	ADDV acc7, acc5, acc5
	SGTU acc7, acc5, t1
	ADDV t0, acc5, acc5
	SGTU t0, acc5, t0
	OR t1, t0, t0
	// ADCS y2, acc6
	ADDV y2, acc6, acc6
	ADDV t0, acc6, acc6

	// Third reduction step
	MULV acc2, hlp1, hlp0
	// MUL const0, hlp0, t0
	MULV const0, hlp0, t0
	// ADDS t0, acc2
	ADDV t0, acc2, acc2 // acc2 is free now
	SGTU t0, acc2, t1
	MULHVU const0, hlp0, y0

	// MUL const1, hlp0, t0
	MULV const1, hlp0, t0
	// ADCS t0, acc3
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t0
	ADDV t1, acc3, acc3
	SGTU t1, acc3, t1
	OR t0, t1
	MULHVU const1, hlp0, y1

	// MUL const2, hlp0, t0
	MULV const2, hlp0, t0
	// ADCS t0, acc0
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t0
	ADDV t1, acc0, acc0
	SGTU t1, acc0, t1
	OR t0, t1
	MULHVU const2, hlp0, y2

	// MUL const3, hlp0, t0
	MULV const3, hlp0, t0
	// ADCS t0, acc1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t0
	ADDV t1, acc1, acc1
	SGTU t1, acc1, t1
	OR t0, t1
	MULHVU const3, hlp0, hlp0
	ADDV t1, acc6, acc6

	// ADDS y0, acc3
	ADDV y0, acc3, acc3
	SGTU y0, acc3, t0
	// ADCS y1, acc0
	ADDV y1, acc0, acc0
	SGTU y1, acc0, t1
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t0
	OR t1, t0
	// ADCS y2, acc1
	ADDV y2, acc1, acc1
	SGTU y2, acc1, t1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t0
	OR t1, t0
	// ADC hlp0, ZERO, acc2
	ADDV t0, hlp0, acc2

	// y[3] * x
	MULV y3, x0, t0
	// ADDS t0, acc3
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t0
	MULHVU y3, x0, y0

	MULV y3, x1, t1
	// ADCS t1, acc4
	ADDV t1, acc4, acc4
	SGTU t1, acc4, hlp0
	ADDV t0, acc4, acc4
	SGTU t0, acc4, t0
	OR hlp0, t0, t0
	MULHVU y3, x1, y1

	MULV y3, x2, t1
	// ADCS t1, acc5
	ADDV t1, acc5, acc5
	SGTU t1, acc5, hlp0
	ADDV t0, acc5, acc5
	SGTU t0, acc5, t0
	OR hlp0, t0, t0
	MULHVU y3, x2, y2

	MULV y3, x3, t1
	// ADCS t1, acc6
	ADDV t1, acc6, acc6
	SGTU t1, acc6, hlp0
	ADDV t0, acc6, acc6
	SGTU t0, acc6, t0
	OR hlp0, t0, acc7
	MULHVU y3, x3, y3

	// ADDS y0, acc4
	ADDV y0, acc4, acc4
	SGTU y0, acc4, t0
	// ADCS y1, acc5
	ADDV y1, acc5, acc5
	SGTU y1, acc5, t1
	ADDV t0, acc5, acc5
	SGTU t0, acc5, t0
	OR t1, t0, t0
	// ADCS y2, acc6
	ADDV y2, acc6, acc6
	SGTU y2, acc6, t1
	ADDV t0, acc6, acc6
	SGTU t0, acc6, t0
	OR t1, t0, t0
	// ADCS y3, acc7
	ADDV y3, acc7, acc7
	ADDV t0, acc7, acc7

	// Last reduction step
	MULV acc3, hlp1, hlp0
	// MUL const0, hlp0, t0
	MULV const0, hlp0, t0
	// ADDS t0, acc3
	ADDV t0, acc3, acc3 // acc3 is free now
	SGTU t0, acc3, t1
	MULHVU const0, hlp0, y0

	// MUL const1, hlp0, t0
	MULV const1, hlp0, t0
	// ADCS t0, acc0
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t0
	ADDV t1, acc0, acc0
	SGTU t1, acc0, t1
	OR t0, t1
	MULHVU const1, hlp0, y1

	// MUL const2, hlp0, t0
	MULV const2, hlp0, t0
	// ADCS t0, acc1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t0
	ADDV t1, acc1, acc1
	SGTU t1, acc1, t1
	OR t0, t1
	MULHVU const2, hlp0, y2

	// MUL const3, hlp0, t0
	MULV const3, hlp0, t0
	// ADCS t0, acc2
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t0
	ADDV t1, acc2, acc2
	SGTU t1, acc2, t1
	OR t0, t1
	MULHVU const3, hlp0, hlp0
	ADDV t1, acc7, acc7

	// ADDS y0, acc0
	ADDV y0, acc0, acc0
	SGTU y0, acc0, t0
	// ADCS y1, acc1
	ADDV y1, acc1, acc1
	SGTU y1, acc1, t1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t0
	OR t1, t0
	// ADCS y2, acc2
	ADDV y2, acc2, acc2
	SGTU y2, acc2, t1
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t0
	OR t1, t0
	// ADC hlp0, ZERO, acc3
	ADDV t0, hlp0, acc3

	ADDV acc4, acc0, x0
	SGTU acc4, x0, t0
	ADDV acc5, acc1, x1
	SGTU acc5, x1, t1
	ADDV t0, x1, x1
	SGTU t0, x1, t0
	OR t1, t0, t0
	ADDV acc6, acc2, x2
	SGTU acc6, x2, t1
	ADDV t0, x2, x2
	SGTU t0, x2, t0
	OR t1, t0, t0
	ADDV acc7, acc3, x3
	SGTU acc7, x3, t1
	ADDV t0, x3, x3
	SGTU t0, x3, acc5
	OR t1, acc5, acc5

	// final reduction
	gfpCarry(x0, x1, x2, x3, acc5, const0, const1, const2, const3)

	MOVV c+0(FP), res_ptr
	storeBlock(x0, x1, x2, x3, 0(res_ptr))

	RET

// func gfpSqr(res, in *gfP, n int)
TEXT ·gfpSqr(SB), NOSPLIT, $0
	MOVV in+8(FP), a_ptr
	MOVV n+16(FP), b_ptr
	MOVV ·np+0x00(SB), hlp1

	loadBlock(0(a_ptr), x0, x1, x2, x3)
	loadModulus(const0, const1, const2, const3)

sqrLoop:
		SUBV	$1, b_ptr

		// x[1:] * x[0]
		MULV x0, x1, acc1
		MULHVU x0, x1, acc2

		MULV x0, x2, t0
		// ADDS t0, acc2
		ADDV t0, acc2, acc2
		SGTU t0, acc2, t1
		MULHVU x0, x2, acc3

		MULV x0, x3, t0
		// ADCS t0, acc3
		ADDV t1, acc3, acc3  // no carry
		ADDV t0, acc3, acc3
		SGTU t0, acc3, t1
		MULHVU x0, x3, acc4
		ADDV t1, acc4, acc4  // no carry

		// x[2:] * x[1]
		MULV x1, x2, t0
		// ADDS t0, acc3
		ADDV t0, acc3, acc3
		SGTU t0, acc3, t0
		MULHVU x1, x2, t1
		// ADCS t1, acc4
		ADDV t1, acc4, acc4
		SGTU t1, acc4, t1
		ADDV t0, acc4, acc4
		SGTU t0, acc4, t0
		// ADC $0, acc5
		OR t0, t1, acc5

		MULV x1, x3, t0
		// ADCS t0, acc4
		ADDV t0, acc4, acc4
		SGTU t0, acc4, t0
		MULHVU x1, x3, t1
		// ADC	t1, acc5
		ADDV t1, t0, t0       // no carry
		ADDV t0, acc5, acc5   // no carry

		// x[3] * x[2]
		MULV x2, x3, t0
		// ADDS t0, acc5
		ADDV t0, acc5, acc5
		SGTU t0, acc5, t1
		MULHVU x2, x3, acc6
		// ADC	$0, acc6
		ADDV t1, acc6, acc6   // no carry

		// *2
		// ALSLV is NOT supported in go 1.25
		SRLV $63, acc1, t0
		SLLV $1, acc1, acc1
		SRLV $63, acc2, t1
		// ALSLV $1, t0, acc2, acc2
		SLLV $1, acc2, acc2
		ADDV t0, acc2, acc2
		SRLV $63, acc3, t0
		// ALSLV $1, t1, acc3, acc3
		SLLV $1, acc3, acc3
		ADDV t1, acc3, acc3
		SRLV $63, acc4, t1
		// ALSLV $1, t0, acc4, acc4
		SLLV $1, acc4, acc4
		ADDV t0, acc4, acc4
		SRLV $63, acc5, t0
		// ALSLV $1, t1, acc5, acc5
		SLLV $1, acc5, acc5
		ADDV t1, acc5, acc5
		SRLV $63, acc6, acc7
		// ALSLV $1, t0, acc6, acc6
		SLLV $1, acc6, acc6
		ADDV t0, acc6, acc6

		// Missing products
		MULV x0, x0, acc0
		MULHVU x0, x0, t0
		// ADDS t0, acc1
		ADDV t0, acc1, acc1
		SGTU t0, acc1, t1
		MULV x1, x1, t0
		// ADCS t0, acc2
		ADDV t0, t1, t1         // no carry
		ADDV t1, acc2, acc2
		SGTU t1, acc2, t1
		MULHVU x1, x1, t0
		// ADCS t0, acc3
		ADDV t0, t1, t0	    // no carry
		ADDV t0, acc3, acc3
		SGTU t0, acc3, t1
		MULV x2, x2, t0
		// ADCS t0, acc4
		ADDV t0, t1, t0         // no carry
		ADDV t0, acc4, acc4
		SGTU t0, acc4, t1
		MULHVU x2, x2, t0
		// ADCS t0, acc5
		ADDV t0, t1, t0     // no carry
		ADDV t0, acc5, acc5
		SGTU t0, acc5, t1
		MULV x3, x3, t0
		// ADCS t0, acc6
		ADDV t0, t1, t0         // no carry
		ADDV t0, acc6, acc6
		SGTU t0, acc6, t1
		MULHVU x3, x3, t0
		// ADC	t0, acc7
		ADDV t0, t1, t0     // no carry
		ADDV t0, acc7, acc7   // (acc0, acc1, acc2, acc3, acc4, acc5, acc6, acc7) is the result

		// First reduction step
		MULV acc0, hlp1, hlp0
		// MUL	const0, hlp0, t0
		MULV hlp0, const0, t0
		// ADDS t0, acc0
		ADDV t0, acc0, acc0
		SGTU t0, acc0, t1
		MULHVU hlp0, const0, y0

		// MUL const1, hlp0, t0
		MULV hlp0, const1, t0
		// ADCS t0, acc1
		ADDV t0, acc1, acc1
		SGTU t0, acc1, t0
		ADDV t1, acc1, acc1
		SGTU t1, acc1, t1
		OR t0, t1, t1
		MULHVU hlp0, const1, y1

		// MUL const2, hlp0, t0
		MULV hlp0, const2, t0
		// ADCS t0, acc2
		ADDV t0, acc2, acc2
		SGTU t0, acc2, t0
		ADDV t1, acc2, acc2
		SGTU t1, acc2, t1
		OR t0, t1, t1
		MULHVU hlp0, const2, y2

		// MUL const3, hlp0, t0
		MULV hlp0, const3, t0
		// ADCS t0, acc3
		ADDV t0, acc3, acc3
		SGTU t0, acc3, t0
		ADDV t1, acc3, acc3
		SGTU t1, acc3, t1
		OR t0, t1, t1
		MULHVU hlp0, const3, acc0
		ADDV t1, acc0, acc0         // no carry

		ADDV y0, acc1, acc1
		SGTU y0, acc1, t0
		ADDV y1, acc2, acc2
		SGTU y1, acc2, t1
		ADDV t0, acc2, acc2
		SGTU t0, acc2, t0
		OR t1, t0, t0
		ADDV y2, acc3, acc3
		SGTU y2, acc3, t1
		ADDV t0, acc3, acc3
		SGTU t0, acc3, t0
		OR t1, t0, t0
		ADDV t0, acc0, acc0

		// Second reduction step
		MULV acc1, hlp1, hlp0
		// MUL	const0, hlp0, t0
		MULV hlp0, const0, t0
		// ADDS t0, acc1
		ADDV t0, acc1, acc1
		SGTU t0, acc1, t1
		MULHVU hlp0, const0, y0

		// MUL const1, hlp0, t0
		MULV hlp0, const1, t0
		// ADCS t0, acc2
		ADDV t0, acc2, acc2
		SGTU t0, acc2, t0
		ADDV t1, acc2, acc2
		SGTU t1, acc2, t1
		OR t0, t1, t1
		MULHVU hlp0, const1, y1

		// MUL const2, hlp0, t0
		MULV hlp0, const2, t0
		// ADCS t0, acc3
		ADDV t0, acc3, acc3
		SGTU t0, acc3, t0
		ADDV t1, acc3, acc3
		SGTU t1, acc3, t1
		OR t0, t1, t1
		MULHVU hlp0, const2, y2

		// MUL const3, hlp0, t0
		MULV hlp0, const3, t0
		// ADCS t0, acc0
		ADDV t0, acc0, acc0
		SGTU t0, acc0, t0
		ADDV t1, acc0, acc0
		SGTU t1, acc0, t1
		OR t0, t1, t1
		MULHVU hlp0, const3, acc1
		ADDV t1, acc1, acc1       // no carry

		ADDV y0, acc2, acc2
		SGTU y0, acc2, t0
		ADDV y1, acc3, acc3
		SGTU y1, acc3, t1
		ADDV t0, acc3, acc3
		SGTU t0, acc3, t0
		OR t1, t0, t0
		ADDV y2, acc0, acc0
		SGTU y2, acc0, t1
		ADDV t0, acc0, acc0
		SGTU t0, acc0, t0
		OR t1, t0, t0
		ADDV t0, acc1, acc1

		// Third reduction step
		MULV acc2, hlp1, hlp0
		// MUL	const0, hlp0, t0
		MULV hlp0, const0, t0
		// ADDS t0, acc2
		ADDV t0, acc2, acc2
		SGTU t0, acc2, t1
		MULHVU hlp0, const0, y0

		// MUL const1, hlp0, t0
		MULV hlp0, const1, t0
		// ADCS t0, acc3
		ADDV t0, acc3, acc3
		SGTU t0, acc3, t0
		ADDV t1, acc3, acc3
		SGTU t1, acc3, t1
		OR t0, t1, t1
		MULHVU hlp0, const1, y1

		// MUL const2, hlp0, t0
		MULV hlp0, const2, t0
		// ADCS t0, acc0
		ADDV t0, acc0, acc0
		SGTU t0, acc0, t0
		ADDV t1, acc0, acc0
		SGTU t1, acc0, t1
		OR t0, t1, t1
		MULHVU hlp0, const2, y2

		// MUL const3, hlp0, t0
		MULV hlp0, const3, t0
		// ADCS t0, acc1
		ADDV t0, acc1, acc1
		SGTU t0, acc1, t0
		ADDV t1, acc1, acc1
		SGTU t1, acc1, t1
		OR t0, t1, t1
		MULHVU hlp0, const3, acc2
		ADDV t1, acc2, acc2       // no carry

		ADDV y0, acc3, acc3
		SGTU y0, acc3, t0
		ADDV y1, acc0, acc0
		SGTU y1, acc0, t1
		ADDV t0, acc0, acc0
		SGTU t0, acc0, t0
		OR t1, t0, t0
		ADDV y2, acc1, acc1
		SGTU y2, acc1, t1
		ADDV t0, acc1, acc1
		SGTU t0, acc1, t0
		OR t1, t0, t0
		ADDV t0, acc2, acc2

		// Last reduction step
		MULV acc3, hlp1, hlp0
		// MUL	const0, hlp0, t0
		MULV hlp0, const0, t0
		// ADDS t0, acc3
		ADDV t0, acc3, acc3
		SGTU t0, acc3, t1
		MULHVU hlp0, const0, y0

		// MUL const1, hlp0, t0
		MULV hlp0, const1, t0
		// ADCS t0, acc0
		ADDV t0, acc0, acc0
		SGTU t0, acc0, t0
		ADDV t1, acc0, acc0
		SGTU t1, acc0, t1
		OR t0, t1, t1
		MULHVU hlp0, const1, y1

		// MUL const2, hlp0, t0
		MULV hlp0, const2, t0
		// ADCS t0, acc1
		ADDV t0, acc1, acc1
		SGTU t0, acc1, t0
		ADDV t1, acc1, acc1
		SGTU t1, acc1, t1
		OR t0, t1, t1
		MULHVU hlp0, const2, y2

		// MUL const3, hlp0, t0
		MULV hlp0, const3, t0
		// ADCS t0, acc2
		ADDV t0, acc2, acc2
		SGTU t0, acc2, t0
		ADDV t1, acc2, acc2
		SGTU t1, acc2, t1
		OR t0, t1, t1
		MULHVU hlp0, const3, acc3
		ADDV t1, acc3, acc3       // no carry

		ADDV y0, acc0, acc0
		SGTU y0, acc0, t0
		ADDV y1, acc1, acc1
		SGTU y1, acc1, t1
		ADDV t0, acc1, acc1
		SGTU t0, acc1, t0
		OR t1, t0, t0
		ADDV y2, acc2, acc2
		SGTU y2, acc2, t1
		ADDV t0, acc2, acc2
		SGTU t0, acc2, t0
		OR t1, t0, t0
		ADDV t0, acc3, acc3

		ADDV acc4, acc0, x0
		SGTU acc4, x0, t0
		ADDV acc5, acc1, x1
		SGTU acc5, x1, t1
		ADDV t0, x1, x1
		SGTU t0, x1, t0
		OR t1, t0, t0
		ADDV acc6, acc2, x2
		SGTU acc6, x2, t1
		ADDV t0, x2, x2
		SGTU t0, x2, t0
		OR t1, t0, t0
		ADDV acc7, acc3, x3
		SGTU acc7, x3, t1
		ADDV t0, x3, x3
		SGTU t0, x3, acc5
		OR t1, acc5, acc5

		// final reduction
		gfpCarry(x0, x1, x2, x3, acc5, const0, const1, const2, const3)
		BNE b_ptr, sqrLoop

	MOVV res+0(FP), res_ptr
	storeBlock(x0, x1, x2, x3, 0(res_ptr))
	RET

/* ---------------------------------------*/
// func gfpFromMont(res, in *gfP)
TEXT ·gfpFromMont(SB), NOSPLIT, $0
	MOVV in+8(FP), a_ptr
	MOVV ·np+0x00(SB), hlp1

	loadBlock(0(a_ptr), acc0, acc1, acc2, acc3)
	loadModulus(const0, const1, const2, const3)

	// Only reduce, no multiplications are needed
	// First reduction step
	MULV acc0, hlp1, hlp0
	// MUL	const0, hlp0, t0
	MULV hlp0, const0, t0
	// ADDS t0, acc0
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t1
	MULHVU hlp0, const0, y0

	// MUL const1, hlp0, t0
	MULV hlp0, const1, t0
	// ADCS t0, acc1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t0
	ADDV t1, acc1, acc1
	SGTU t1, acc1, t1
	OR t0, t1, t1
	MULHVU hlp0, const1, y1

	// MUL const2, hlp0, t0
	MULV hlp0, const2, t0
	// ADCS t0, acc2
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t0
	ADDV t1, acc2, acc2
	SGTU t1, acc2, t1
	OR t0, t1, t1
	MULHVU hlp0, const2, y2

	// MUL const3, hlp0, t0
	MULV hlp0, const3, t0
	// ADCS t0, acc3
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t0
	ADDV t1, acc3, acc3
	SGTU t1, acc3, t1
	OR t0, t1, t1
	MULHVU hlp0, const3, acc0
	ADDV t1, acc0, acc0       // no carry

	ADDV y0, acc1, acc1
	SGTU y0, acc1, t0
	ADDV y1, acc2, acc2
	SGTU y1, acc2, t1
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t0
	OR t1, t0, t0
	ADDV y2, acc3, acc3
	SGTU y2, acc3, t1
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t0
	OR t1, t0, t0
	ADDV t0, acc0, acc0

	// Second reduction step
	MULV acc1, hlp1, hlp0
	// MUL	const0, hlp0, t0
	MULV hlp0, const0, t0
	// ADDS t0, acc1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t1
	MULHVU hlp0, const0, y0

	// MUL const1, hlp0, t0
	MULV hlp0, const1, t0
	// ADCS t0, acc2
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t0
	ADDV t1, acc2, acc2
	SGTU t1, acc2, t1
	OR t0, t1, t1
	MULHVU hlp0, const1, y1

	// MUL const2, hlp0, t0
	MULV hlp0, const2, t0
	// ADCS t0, acc3
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t0
	ADDV t1, acc3, acc3
	SGTU t1, acc3, t1
	OR t0, t1, t1
	MULHVU hlp0, const2, y2

	// MUL const3, hlp0, t0
	MULV hlp0, const3, t0
	// ADCS t0, acc0
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t0
	ADDV t1, acc0, acc0
	SGTU t1, acc0, t1
	OR t0, t1, t1
	MULHVU hlp0, const3, acc1
	ADDV t1, acc1, acc1       // no carry

	ADDV y0, acc2, acc2
	SGTU y0, acc2, t0
	ADDV y1, acc3, acc3
	SGTU y1, acc3, t1
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t0
	OR t1, t0, t0
	ADDV y2, acc0, acc0
	SGTU y2, acc0, t1
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t0
	OR t1, t0, t0
	ADDV t0, acc1, acc1

	// Third reduction step
	MULV acc2, hlp1, hlp0
	// MUL	const0, hlp0, t0
	MULV hlp0, const0, t0
	// ADDS t0, acc2
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t1
	MULHVU hlp0, const0, y0

	// MUL const1, hlp0, t0
	MULV hlp0, const1, t0
	// ADCS t0, acc3
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t0
	ADDV t1, acc3, acc3
	SGTU t1, acc3, t1
	OR t0, t1, t1
	MULHVU hlp0, const1, y1

	// MUL const2, hlp0, t0
	MULV hlp0, const2, t0
	// ADCS t0, acc0
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t0
	ADDV t1, acc0, acc0
	SGTU t1, acc0, t1
	OR t0, t1, t1
	MULHVU hlp0, const2, y2

	// MUL const3, hlp0, t0
	MULV hlp0, const3, t0
	// ADCS t0, acc1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t0
	ADDV t1, acc1, acc1
	SGTU t1, acc1, t1
	OR t0, t1, t1
	MULHVU hlp0, const3, acc2
	ADDV t1, acc2, acc2       // no carry

	ADDV y0, acc3, acc3
	SGTU y0, acc3, t0
	ADDV y1, acc0, acc0
	SGTU y1, acc0, t1
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t0
	OR t1, t0, t0
	ADDV y2, acc1, acc1
	SGTU y2, acc1, t1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t0
	OR t1, t0, t0
	ADDV t0, acc2, acc2

	// Last reduction step
	MULV acc3, hlp1, hlp0
	// MUL	const0, hlp0, t0
	MULV hlp0, const0, t0
	// ADDS t0, acc3
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t1
	MULHVU hlp0, const0, y0

	// MUL const1, hlp0, t0
	MULV hlp0, const1, t0
	// ADCS t0, acc0
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t0
	ADDV t1, acc0, acc0
	SGTU t1, acc0, t1
	OR t0, t1, t1
	MULHVU hlp0, const1, y1

	// MUL const2, hlp0, t0
	MULV hlp0, const2, t0
	// ADCS t0, acc1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t0
	ADDV t1, acc1, acc1
	SGTU t1, acc1, t1
	OR t0, t1, t1
	MULHVU hlp0, const2, y2

	// MUL const3, hlp0, t0
	MULV hlp0, const3, t0
	// ADCS t0, acc2
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t0
	ADDV t1, acc2, acc2
	SGTU t1, acc2, t1
	OR t0, t1, t1
	MULHVU hlp0, const3, acc3
	ADDV t1, acc3, acc3       // no carry

	ADDV y0, acc0, x0
	SGTU y0, x0, t0
	ADDV y1, acc1, x1
	SGTU y1, x1, t1
	ADDV t0, x1, x1
	SGTU t0, x1, t0
	OR t1, t0, t0
	ADDV y2, acc2, x2
	SGTU y2, x2, t1
	ADDV t0, x2, x2
	SGTU t0, x2, t0
	OR t1, t0, t0
	ADDV t0, acc3, x3

	gfpCarry(x0, x1, x2, x3, ZERO, const0, const1, const2, const3)

	MOVV res+0(FP), res_ptr
	storeBlock(x0, x1, x2, x3, 0(res_ptr))

	RET

/* ---------------------------------------*/
// func gfpUnmarshal(res *gfP, in *[32]byte)
TEXT ·gfpUnmarshal(SB), NOSPLIT, $0
	JMP	·gfpMarshal(SB)

/* ---------------------------------------*/
// func gfpMarshal(res *[32]byte, in *gfP)
TEXT ·gfpMarshal(SB),NOSPLIT,$0
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
