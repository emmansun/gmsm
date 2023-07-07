//go:build arm64 && !purego
// +build arm64,!purego

#include "textflag.h"

#define res_ptr R0
#define a_ptr R1
#define b_ptr R2

#define acc0 R3
#define acc1 R4
#define acc2 R5
#define acc3 R6

#define acc4 R7
#define acc5 R8
#define acc6 R9
#define acc7 R10
#define t0 R11
#define t1 R12
#define t2 R13
#define t3 R14
#define const0 R15
#define const1 R16

#define hlp0 R17
#define hlp1 res_ptr

#define x0 R19
#define x1 R20
#define x2 R21
#define x3 R22
#define y0 R23
#define y1 R24
#define y2 R25
#define y3 R26

#define const2 t2
#define const3 t3

#define storeBlock(a0,a1,a2,a3, r) \
	MOVD a0,  0+r \
	MOVD a1,  8+r \
	MOVD a2, 16+r \
	MOVD a3, 24+r

#define loadBlock(r, a0,a1,a2,a3) \
	MOVD  0+r, a0 \
	MOVD  8+r, a1 \
	MOVD 16+r, a2 \
	MOVD 24+r, a3

#define loadModulus(p0,p1,p2,p3) \
	MOVD ·p2+0(SB), p0 \
	MOVD ·p2+8(SB), p1 \
	MOVD ·p2+16(SB), p2 \
	MOVD ·p2+24(SB), p3

TEXT ·gfpNeg(SB),0,$0-16
	MOVD a+8(FP), R0
	loadBlock(0(R0), R1,R2,R3,R4)
	loadModulus(R5,R6,R7,R8)

	SUBS R1, R5, R1
	SBCS R2, R6, R2
	SBCS R3, R7, R3
	SBCS R4, R8, R4

	SUBS R5, R1, R5
	SBCS R6, R2, R6
	SBCS R7, R3, R7
	SBCS R8, R4, R8

	CSEL CS, R5, R1, R1
	CSEL CS, R6, R2, R2
	CSEL CS, R7, R3, R3
	CSEL CS, R8, R4, R4

	MOVD c+0(FP), R0
	storeBlock(R1,R2,R3,R4, 0(R0))
	RET

TEXT ·gfpAdd(SB),0,$0-24
	MOVD a+8(FP), R0
	loadBlock(0(R0), R1,R2,R3,R4)
	MOVD b+16(FP), R0
	loadBlock(0(R0), R5,R6,R7,R8)
	loadModulus(R9,R10,R11,R12)
	MOVD ZR, R0

	ADDS R5, R1
	ADCS R6, R2
	ADCS R7, R3
	ADCS R8, R4
	ADCS ZR, R0

	SUBS  R9, R1, R5
	SBCS R10, R2, R6
	SBCS R11, R3, R7
	SBCS R12, R4, R8
	SBCS  ZR, R0, R0

	CSEL CS, R5, R1, R1
	CSEL CS, R6, R2, R2
	CSEL CS, R7, R3, R3
	CSEL CS, R8, R4, R4

	MOVD c+0(FP), R0
	storeBlock(R1,R2,R3,R4, 0(R0))
	RET

TEXT ·gfpSub(SB),0,$0-24
	MOVD a+8(FP), R0
	loadBlock(0(R0), R1,R2,R3,R4)
	MOVD b+16(FP), R0
	loadBlock(0(R0), R5,R6,R7,R8)
	loadModulus(R9,R10,R11,R12)

	SUBS R5, R1
	SBCS R6, R2
	SBCS R7, R3
	SBCS R8, R4

	CSEL CS, ZR,  R9,  R9
	CSEL CS, ZR, R10, R10
	CSEL CS, ZR, R11, R11
	CSEL CS, ZR, R12, R12

	ADDS  R9, R1
	ADCS R10, R2
	ADCS R11, R3
	ADCS R12, R4

	MOVD c+0(FP), R0
	storeBlock(R1,R2,R3,R4, 0(R0))
	RET

TEXT ·gfpMul(SB),NOSPLIT,$0
	MOVD	in1+8(FP), a_ptr
	MOVD	in2+16(FP), b_ptr

	MOVD	·np+0x00(SB), hlp1
	LDP	·p2+0x00(SB), (const0, const1)
	LDP	·p2+0x10(SB), (const2, const3)

	LDP	0*16(a_ptr), (x0, x1)
	LDP	1*16(a_ptr), (x2, x3)
	LDP	0*16(b_ptr), (y0, y1)
	LDP	1*16(b_ptr), (y2, y3)

	// y[0] * x
	MUL	y0, x0, acc0
	UMULH	y0, x0, acc1

	MUL	y0, x1, t0
	ADDS	t0, acc1
	UMULH	y0, x1, acc2

	MUL	y0, x2, t0
	ADCS	t0, acc2
	UMULH	y0, x2, acc3

	MUL	y0, x3, t0
	ADCS	t0, acc3
	UMULH	y0, x3, acc4
	ADC	$0, acc4
	// First reduction step
	MUL	acc0, hlp1, hlp0

	MUL	const0, hlp0, t0
	ADDS	t0, acc0, acc0
	UMULH	const0, hlp0, t1

	MUL	const1, hlp0, t0
	ADCS	t0, acc1, acc1
	UMULH	const1, hlp0, y0

	MUL	const2, hlp0, t0
	ADCS	t0, acc2, acc2
	UMULH	const2, hlp0, acc0

	MUL	const3, hlp0, t0
	ADCS	t0, acc3, acc3

	UMULH	const3, hlp0, hlp0
	ADC	$0, acc4

	ADDS	t1, acc1, acc1
	ADCS	y0, acc2, acc2
	ADCS	acc0, acc3, acc3
	ADC	$0, hlp0, acc0
	// y[1] * x
	MUL	y1, x0, t0
	ADDS	t0, acc1
	UMULH	y1, x0, t1

	MUL	y1, x1, t0
	ADCS	t0, acc2
	UMULH	y1, x1, hlp0

	MUL	y1, x2, t0
	ADCS	t0, acc3
	UMULH	y1, x2, y0

	MUL	y1, x3, t0
	ADCS	t0, acc4
	UMULH	y1, x3, y1
	ADC	$0, ZR, acc5

	ADDS	t1, acc2
	ADCS	hlp0, acc3
	ADCS	y0, acc4
	ADC	y1, acc5
	// Second reduction step
	MUL	acc1, hlp1, hlp0

	MUL	const0, hlp0, t0
	ADDS	t0, acc1, acc1
	UMULH	const0, hlp0, t1

	MUL	const1, hlp0, t0
	ADCS	t0, acc2, acc2
	UMULH	const1, hlp0, y0

	MUL	const2, hlp0, t0
	ADCS	t0, acc3, acc3
	UMULH	const2, hlp0, acc1

	MUL	const3, hlp0, t0
	ADCS	t0, acc0, acc0

	UMULH	const3, hlp0, hlp0
	ADC	$0, acc5

	ADDS	t1, acc2, acc2
	ADCS	y0, acc3, acc3
	ADCS	acc1, acc0, acc0
	ADC	$0, hlp0, acc1
	// y[2] * x
	MUL	y2, x0, t0
	ADDS	t0, acc2
	UMULH	y2, x0, t1

	MUL	y2, x1, t0
	ADCS	t0, acc3
	UMULH	y2, x1, hlp0

	MUL	y2, x2, t0
	ADCS	t0, acc4
	UMULH	y2, x2, y0

	MUL	y2, x3, t0
	ADCS	t0, acc5
	UMULH	y2, x3, y1
	ADC	$0, ZR, acc6

	ADDS	t1, acc3
	ADCS	hlp0, acc4
	ADCS	y0, acc5
	ADC	y1, acc6
	// Third reduction step
	MUL	acc2, hlp1, hlp0

	MUL	const0, hlp0, t0
	ADDS	t0, acc2, acc2
	UMULH	const0, hlp0, t1

	MUL	const1, hlp0, t0
	ADCS	t0, acc3, acc3
	UMULH	const1, hlp0, y0

	MUL	const2, hlp0, t0
	ADCS	t0, acc0, acc0
	UMULH	const2, hlp0, acc2

	MUL	const3, hlp0, t0
	ADCS	t0, acc1, acc1

	UMULH	const3, hlp0, hlp0
	ADC	$0, acc6

	ADDS	t1, acc3, acc3
	ADCS	y0, acc0, acc0
	ADCS	acc2, acc1, acc1
	ADC	$0, hlp0, acc2
	// y[3] * x
	MUL	y3, x0, t0
	ADDS	t0, acc3
	UMULH	y3, x0, t1

	MUL	y3, x1, t0
	ADCS	t0, acc4
	UMULH	y3, x1, hlp0

	MUL	y3, x2, t0
	ADCS	t0, acc5
	UMULH	y3, x2, y0

	MUL	y3, x3, t0
	ADCS	t0, acc6
	UMULH	y3, x3, y1
	ADC	$0, ZR, acc7

	ADDS	t1, acc4
	ADCS	hlp0, acc5
	ADCS	y0, acc6
	ADC	y1, acc7
	// Last reduction step
	MUL	acc3, hlp1, hlp0

	MUL	const0, hlp0, t0
	ADDS	t0, acc3, acc3
	UMULH	const0, hlp0, t1

	MUL	const1, hlp0, t0
	ADCS	t0, acc0, acc0
	UMULH	const1, hlp0, y0

	MUL	const2, hlp0, t0
	ADCS	t0, acc1, acc1
	UMULH	const2, hlp0, acc3

	MUL	const3, hlp0, t0
	ADCS	t0, acc2, acc2

	UMULH	const3, hlp0, hlp0
	ADC	$0, acc7

	ADDS	t1, acc0, acc0
	ADCS	y0, acc1, acc1
	ADCS	acc3, acc2, acc2
	ADC	$0, hlp0, acc3

	ADDS	acc4, acc0, acc0
	ADCS	acc5, acc1, acc1
	ADCS	acc6, acc2, acc2
	ADCS	acc7, acc3, acc3
	ADC	$0, ZR, acc4

	SUBS	const0, acc0, t0
	SBCS	const1, acc1, t1
	SBCS	const2, acc2, t2
	SBCS	const3, acc3, t3
	SBCS	$0, acc4, acc4

	CSEL	CS, t0, acc0, acc0
	CSEL	CS, t1, acc1, acc1
	CSEL	CS, t2, acc2, acc2
	CSEL	CS, t3, acc3, acc3

	MOVD	res+0(FP), res_ptr
	STP	(acc0, acc1), 0*16(res_ptr)
	STP	(acc2, acc3), 1*16(res_ptr)

	RET

// func gfpSqr(res, in *gfP, n int)
TEXT ·gfpSqr(SB),NOSPLIT,$0
	MOVD	in+8(FP), a_ptr
	MOVD	n+16(FP), b_ptr

	MOVD	·np+0x00(SB), hlp1
	LDP	·p2+0x00(SB), (const0, const1)
	LDP	·p2+0x10(SB), (const2, const3)

	LDP	0*16(a_ptr), (x0, x1)
	LDP	1*16(a_ptr), (x2, x3)

ordSqrLoop:
	SUB	$1, b_ptr

	// x[1:] * x[0]
	MUL	x0, x1, acc1
	UMULH	x0, x1, acc2

	MUL	x0, x2, t0
	ADDS	t0, acc2, acc2
	UMULH	x0, x2, acc3

	MUL	x0, x3, t0
	ADCS	t0, acc3, acc3
	UMULH	x0, x3, acc4
	ADC	$0, acc4, acc4
	// x[2:] * x[1]
	MUL	x1, x2, t0
	ADDS	t0, acc3
	UMULH	x1, x2, t1
	ADCS	t1, acc4
	ADC	$0, ZR, acc5

	MUL	x1, x3, t0
	ADDS	t0, acc4
	UMULH	x1, x3, t1
	ADC	t1, acc5
	// x[3] * x[2]
	MUL	x2, x3, t0
	ADDS	t0, acc5
	UMULH	x2, x3, acc6
	ADC	$0, acc6

	MOVD	$0, acc7
	// *2
	ADDS	acc1, acc1
	ADCS	acc2, acc2
	ADCS	acc3, acc3
	ADCS	acc4, acc4
	ADCS	acc5, acc5
	ADCS	acc6, acc6
	ADC	$0, acc7
	// Missing products
	MUL	x0, x0, acc0
	UMULH	x0, x0, t0
	ADDS	t0, acc1, acc1

	MUL	x1, x1, t0
	ADCS	t0, acc2, acc2
	UMULH	x1, x1, t1
	ADCS	t1, acc3, acc3

	MUL	x2, x2, t0
	ADCS	t0, acc4, acc4
	UMULH	x2, x2, t1
	ADCS	t1, acc5, acc5

	MUL	x3, x3, t0
	ADCS	t0, acc6, acc6
	UMULH	x3, x3, t1
	ADC	t1, acc7, acc7
	// First reduction step
	MUL	acc0, hlp1, hlp0

	MUL	const0, hlp0, t0
	ADDS	t0, acc0, acc0
	UMULH	const0, hlp0, t1

	MUL	const1, hlp0, t0
	ADCS	t0, acc1, acc1
	UMULH	const1, hlp0, y0

	MUL	const2, hlp0, t0
	ADCS	t0, acc2, acc2
	UMULH	const2, hlp0, acc0

	MUL	const3, hlp0, t0
	ADCS	t0, acc3, acc3

	UMULH	const3, hlp0, hlp0
	ADC	$0, hlp0

	ADDS	t1, acc1, acc1
	ADCS	y0, acc2, acc2
	ADCS	acc0, acc3, acc3
	ADC	$0, hlp0, acc0
	// Second reduction step
	MUL	acc1, hlp1, hlp0

	MUL	const0, hlp0, t0
	ADDS	t0, acc1, acc1
	UMULH	const0, hlp0, t1

	MUL	const1, hlp0, t0
	ADCS	t0, acc2, acc2
	UMULH	const1, hlp0, y0

	MUL	const2, hlp0, t0
	ADCS	t0, acc3, acc3
	UMULH	const2, hlp0, acc1

	MUL	const3, hlp0, t0
	ADCS	t0, acc0, acc0

	UMULH	const3, hlp0, hlp0
	ADC	$0, hlp0

	ADDS	t1, acc2, acc2
	ADCS	y0, acc3, acc3
	ADCS	acc1, acc0, acc0
	ADC	$0, hlp0, acc1
	// Third reduction step
	MUL	acc2, hlp1, hlp0

	MUL	const0, hlp0, t0
	ADDS	t0, acc2, acc2
	UMULH	const0, hlp0, t1

	MUL	const1, hlp0, t0
	ADCS	t0, acc3, acc3
	UMULH	const1, hlp0, y0

	MUL	const2, hlp0, t0
	ADCS	t0, acc0, acc0
	UMULH	const2, hlp0, acc2

	MUL	const3, hlp0, t0
	ADCS	t0, acc1, acc1

	UMULH	const3, hlp0, hlp0
	ADC	$0, hlp0

	ADDS	t1, acc3, acc3
	ADCS	y0, acc0, acc0
	ADCS	acc2, acc1, acc1
	ADC	$0, hlp0, acc2

	// Last reduction step
	MUL	acc3, hlp1, hlp0

	MUL	const0, hlp0, t0
	ADDS	t0, acc3, acc3
	UMULH	const0, hlp0, t1

	MUL	const1, hlp0, t0
	ADCS	t0, acc0, acc0
	UMULH	const1, hlp0, y0

	MUL	const2, hlp0, t0
	ADCS	t0, acc1, acc1
	UMULH	const2, hlp0, acc3

	MUL	const3, hlp0, t0
	ADCS	t0, acc2, acc2

	UMULH	const3, hlp0, hlp0
	ADC	$0, acc7

	ADDS	t1, acc0, acc0
	ADCS	y0, acc1, acc1
	ADCS	acc3, acc2, acc2
	ADC	$0, hlp0, acc3

	ADDS	acc4, acc0, acc0
	ADCS	acc5, acc1, acc1
	ADCS	acc6, acc2, acc2
	ADCS	acc7, acc3, acc3
	ADC	$0, ZR, acc4

	SUBS	const0, acc0, y0
	SBCS	const1, acc1, y1
	SBCS	const2, acc2, y2
	SBCS	const3, acc3, y3
	SBCS	$0, acc4, acc4

	CSEL	CS, y0, acc0, x0
	CSEL	CS, y1, acc1, x1
	CSEL	CS, y2, acc2, x2
	CSEL	CS, y3, acc3, x3

	CBNZ	b_ptr, ordSqrLoop

	MOVD	res+0(FP), res_ptr
	STP	(x0, x1), 0*16(res_ptr)
	STP	(x2, x3), 1*16(res_ptr)

	RET

/* ---------------------------------------*/
// func gfpFromMont(res, in *gfP)
TEXT ·gfpFromMont(SB),NOSPLIT,$0
	MOVD	in+8(FP), a_ptr

	MOVD	·np+0x00(SB), hlp1
	LDP	·p2+0x00(SB), (const0, const1)
	LDP	·p2+0x10(SB), (const2, const3)

	LDP	0*16(a_ptr), (acc0, acc1)
	LDP	1*16(a_ptr), (acc2, acc3)
	// Only reduce, no multiplications are needed
	// First reduction step
	MUL	acc0, hlp1, hlp0

	MUL	const0, hlp1, t0
	ADDS	t0, acc0, acc0
	UMULH	const0, hlp0, t1

	MUL	const1, hlp0, t0
	ADCS	t0, acc1, acc1
	UMULH	const1, hlp0, y0

	MUL	const2, hlp0, t0
	ADCS	t0, acc2, acc2
	UMULH	const2, hlp0, acc0

	MUL	const3, hlp0, t0
	ADCS	t0, acc3, acc3

	UMULH	const3, hlp0, hlp0
	ADC	$0, hlp0

	ADDS	t1, acc1, acc1
	ADCS	y0, acc2, acc2
	ADCS	acc0, acc3, acc3
	ADC	$0, hlp0, acc0
	// Second reduction step
	MUL	acc1, hlp1, hlp0

	MUL	const0, hlp1, t0
	ADDS	t0, acc1, acc1
	UMULH	const0, hlp0, t1

	MUL	const1, hlp0, t0
	ADCS	t0, acc2, acc2
	UMULH	const1, hlp0, y0

	MUL	const2, hlp0, t0
	ADCS	t0, acc3, acc3
	UMULH	const2, hlp0, acc1

	MUL	const3, hlp0, t0
	ADCS	t0, acc0, acc0

	UMULH	const3, hlp0, hlp0
	ADC	$0, hlp0

	ADDS	t1, acc2, acc2
	ADCS	y0, acc3, acc3
	ADCS	acc1, acc0, acc0
	ADC	$0, hlp0, acc1
	// Third reduction step
	MUL	acc2, hlp1, hlp0

	MUL	const0, hlp1, t0
	ADDS	t0, acc2, acc2
	UMULH	const0, hlp0, t1

	MUL	const1, hlp0, t0
	ADCS	t0, acc3, acc3
	UMULH	const1, hlp0, y0

	MUL	const2, hlp0, t0
	ADCS	t0, acc0, acc0
	UMULH	const2, hlp0, acc2

	MUL	const3, hlp0, t0
	ADCS	t0, acc1, acc1

	UMULH	const3, hlp0, hlp0
	ADC	$0, hlp0

	ADDS	t1, acc3, acc3
	ADCS	y0, acc0, acc0
	ADCS	acc2, acc1, acc1
	ADC	$0, hlp0, acc2

	// Last reduction step
	MUL	acc3, hlp1, hlp0

	MUL	const0, hlp1, t0
	ADDS	t0, acc3, acc3
	UMULH	const0, hlp0, t1

	MUL	const1, hlp0, t0
	ADCS	t0, acc0, acc0
	UMULH	const1, hlp0, y0

	MUL	const2, hlp0, t0
	ADCS	t0, acc1, acc1
	UMULH	const2, hlp0, acc3

	MUL	const3, hlp0, t0
	ADCS	t0, acc2, acc2

	UMULH	const3, hlp0, hlp0
	ADC	$0, hlp0

	ADDS	t1, acc0, acc0
	ADCS	y0, acc1, acc1
	ADCS	acc3, acc2, acc2
	ADC	$0, hlp0, acc3

	SUBS	const0, acc0, y0
	SBCS	const1, acc1, y1
	SBCS	const2, acc2, y2
	SBCS	const3, acc3, y3

	CSEL	CS, y0, acc0, x0
	CSEL	CS, y1, acc1, x1
	CSEL	CS, y2, acc2, x2
	CSEL	CS, y3, acc3, x3

	MOVD	res+0(FP), res_ptr
	STP	(x0, x1), 0*16(res_ptr)
	STP	(x2, x3), 1*16(res_ptr)

	RET

/* ---------------------------------------*/
// func gfpUnmarshal(res *gfP, in *[32]byte)
TEXT ·gfpUnmarshal(SB),NOSPLIT,$0
	JMP	·gfpMarshal(SB)

/* ---------------------------------------*/
// func gfpMarshal(res *[32]byte, in *gfP)
TEXT ·gfpMarshal(SB),NOSPLIT,$0
	MOVD	res+0(FP), res_ptr
	MOVD	in+8(FP), a_ptr

	LDP	0*16(a_ptr), (acc0, acc1)
	LDP	1*16(a_ptr), (acc2, acc3)

	REV	acc0, acc0
	REV	acc1, acc1
	REV	acc2, acc2
	REV	acc3, acc3

	STP	(acc3, acc2), 0*16(res_ptr)
	STP	(acc1, acc0), 1*16(res_ptr)
	RET
