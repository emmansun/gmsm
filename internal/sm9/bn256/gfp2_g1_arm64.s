//go:build !purego

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
#define const0 R13
#define const1 R14
#define const2 R15
#define const3 R16

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

/* ---------------------------------------*/
// (x3, x2, x1, x0) = (y3, y2, y1, y0) - (x3, x2, x1, x0)
TEXT gfpSubInternal(SB),NOSPLIT,$0
	SUBS	x0, y0, acc0
	SBCS	x1, y1, acc1
	SBCS	x2, y2, acc2
	SBCS	x3, y3, acc3
	SBC	$0, ZR, t0

	ADDS	const0, acc0, acc4
	ADCS	const1, acc1, acc5
	ADCS	const2, acc2, acc6
	ADC	    const3, acc3, acc7

	ANDS	$1, t0
	CSEL	EQ, acc0, acc4, x0
	CSEL	EQ, acc1, acc5, x1
	CSEL	EQ, acc2, acc6, x2
	CSEL	EQ, acc3, acc7, x3

	RET

/* ---------------------------------------*/
// (y3, y2, y1, y0) = (x3, x2, x1, x0) * (y3, y2, y1, y0)
TEXT gfpMulInternal(SB),NOSPLIT,$0
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
	UMULH	y1, x1, y0

	MUL	y1, x2, t0
	ADCS	t0, acc3
	UMULH	y1, x2, hlp0

	MUL	y1, x3, t0
	ADCS	t0, acc4
	UMULH	y1, x3, y1
	ADC	$0, ZR, acc5

	ADDS	t1, acc2
	ADCS	y0, acc3
	ADCS	hlp0, acc4
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
	UMULH	y2, x1, y0

	MUL	y2, x2, t0
	ADCS	t0, acc4
	UMULH	y2, x2, y1

	MUL	y2, x3, t0
	ADCS	t0, acc5
	UMULH	y2, x3, hlp0
	ADC	$0, ZR, acc6

	ADDS	t1, acc3
	ADCS	y0, acc4
	ADCS	y1, acc5
	ADC	hlp0, acc6
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
	UMULH	y3, x1, y0

	MUL	y3, x2, t0
	ADCS	t0, acc5
	UMULH	y3, x2, y1

	MUL	y3, x3, t0
	ADCS	t0, acc6
	UMULH	y3, x3, hlp0
	ADC	$0, ZR, acc7

	ADDS	t1, acc4
	ADCS	y0, acc5
	ADCS	y1, acc6
	ADC	hlp0, acc7
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

	// Add bits [511:256] of the mul result
	ADDS	acc4, acc0, acc0
	ADCS	acc5, acc1, acc1
	ADCS	acc6, acc2, acc2
	ADCS	acc7, acc3, acc3
	ADC	$0, ZR, acc4

	SUBS	const0, acc0, t0
	SBCS	const1, acc1, t1
	SBCS	const2, acc2, acc6
	SBCS	const3, acc3, acc7
	SBCS	$0, acc4, acc4

	CSEL	CS, t0, acc0, y0
	CSEL	CS, t1, acc1, y1
	CSEL	CS, acc6, acc2, y2
	CSEL	CS, acc7, acc3, y3
    
    RET

/* ---------------------------------------*/
// (y3, y2, y1, y0) = (x3, x2, x1, x0) ^ 2
TEXT gfpSqrInternal(SB),NOSPLIT,$0
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
	ADCS	t1, acc7, acc7
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
	// Add bits [511:256] of the sqr result
	ADDS	acc4, acc0, acc0
	ADCS	acc5, acc1, acc1
	ADCS	acc6, acc2, acc2
	ADCS	acc7, acc3, acc3
	ADC	$0, ZR, acc4

	SUBS	const0, acc0, t0
	SBCS	const1, acc1, t1
	SBCS	const2, acc2, acc6
	SBCS	const3, acc3, acc7
	SBCS	$0, acc4, acc4

	CSEL	CS, t0, acc0, y0
	CSEL	CS, t1, acc1, y1
	CSEL	CS, acc6, acc2, y2
	CSEL	CS, acc7, acc3, y3
    RET

/* ---------------------------------------*/
// (x3, x2, x1, x0) = 2(y3, y2, y1, y0)
#define gfpMulBy2Inline       \
	ADDS	y0, y0, x0;    \
	ADCS	y1, y1, x1;    \
	ADCS	y2, y2, x2;    \
	ADCS	y3, y3, x3;    \
	ADC	$0, ZR, hlp0;  \
	SUBS	const0, x0, acc0;   \
	SBCS	const1, x1, acc1;\
	SBCS	const2, x2, acc2;    \
	SBCS	const3, x3, acc3;\
	SBCS	$0, hlp0, hlp0;\
	CSEL	CC, x0, acc0, x0;\
	CSEL	CC, x1, acc1, x1;\
	CSEL	CC, x2, acc2, x2;\
	CSEL	CC, x3, acc3, x3;    

// (y3, y2, y1, y0) = 2(y3, y2, y1, y0)
#define gfpMulBy2Inline2       \
	ADDS	y0, y0, x0;    \
	ADCS	y1, y1, x1;    \
	ADCS	y2, y2, x2;    \
	ADCS	y3, y3, x3;    \
	ADC	$0, ZR, hlp0;  \
	SUBS	const0, x0, acc0;   \
	SBCS	const1, x1, acc1;\
	SBCS	const2, x2, acc2;    \
	SBCS	const3, x3, acc3;\
	SBCS	$0, hlp0, hlp0;\
	CSEL	CC, x0, acc0, y0;\
	CSEL	CC, x1, acc1, y1;\
	CSEL	CC, x2, acc2, y2;\
	CSEL	CC, x3, acc3, y3;    

/* ---------------------------------------*/
// (x3, x2, x1, x0) = (x3, x2, x1, x0) + (y3, y2, y1, y0)
#define gfpAddInline          \
	ADDS	y0, x0, x0;    \
	ADCS	y1, x1, x1;    \
	ADCS	y2, x2, x2;    \
	ADCS	y3, x3, x3;    \
	ADC	$0, ZR, hlp0;  \
	SUBS	const0, x0, acc0;   \
	SBCS	const1, x1, acc1;\
	SBCS	const2, x2, acc2;    \
	SBCS	const3, x3, acc3;\
	SBCS	$0, hlp0, hlp0;\
	CSEL	CC, x0, acc0, x0;\
	CSEL	CC, x1, acc1, x1;\
	CSEL	CC, x2, acc2, x2;\
	CSEL	CC, x3, acc3, x3;

/* ---------------------------------------*/
#define x1in(off) (off)(a_ptr)
#define y1in(off) (off + 32)(a_ptr)
#define z1in(off) (off + 64)(a_ptr)
#define x2in(off) (off)(b_ptr)
#define y2in(off) (off + 32)(b_ptr)
#define z2in(off) (off + 64)(b_ptr)
#define x3out(off) (off)(res_ptr)
#define y3out(off) (off + 32)(res_ptr)
#define z3out(off) (off + 64)(res_ptr)
#define LDx(src) LDP src(0), (x0, x1); LDP src(16), (x2, x3)
#define LDy(src) LDP src(0), (y0, y1); LDP src(16), (y2, y3)
#define STx(src) STP (x0, x1), src(0); STP (x2, x3), src(16)
#define STy(src) STP (y0, y1), src(0); STP (y2, y3), src(16)
#define y2x      MOVD y0, x0; MOVD y1, x1; MOVD y2, x2; MOVD y3, x3
#define x2y      MOVD x0, y0; MOVD x1, y1; MOVD x2, y2; MOVD x3, y3

/* ---------------------------------------*/
#define tmp0(off)	(32*0 + 8 + off)(RSP)
#define tmp1(off)	(32*1 + 8 + off)(RSP)
#define tmp2(off) (32*2 + 8 + off)(RSP)

// func gfp2Mul(c, a, b *gfP2)
TEXT ·gfp2Mul(SB),NOSPLIT,$104-24
	MOVD	in1+8(FP), a_ptr
	MOVD	in2+16(FP), b_ptr

	MOVD	·np+0x00(SB), hlp1
	LDP	·p2+0x00(SB), (const0, const1)
	LDP	·p2+0x10(SB), (const2, const3)
	
	LDx (y1in)
	LDy (y2in)
	CALL gfpMulInternal(SB)
	STy (tmp0)

	LDx (x1in)
	LDy (x2in)
	CALL gfpMulInternal(SB)
	STy (tmp1)

	LDx (x1in)
	LDy (y1in)
	gfpAddInline
	STx (tmp2)

	LDx (x2in)
	LDy (y2in)
	gfpAddInline
	LDy (tmp2)
	CALL gfpMulInternal(SB)

	LDx (tmp0)
	CALL gfpSubInternal(SB)
	x2y
	LDx (tmp1)
	CALL gfpSubInternal(SB)
	MOVD	res+0(FP), res_ptr  // not use hlp1 any more
	STx (x3out)

	LDy (tmp1)
	gfpMulBy2Inline
	LDy (tmp0)
	CALL gfpSubInternal(SB)
	STx (y3out)

	RET

// func gfp2MulU(c, a, b *gfP2)
TEXT ·gfp2MulU(SB),NOSPLIT,$104-24
	MOVD	in1+8(FP), a_ptr
	MOVD	in2+16(FP), b_ptr

	MOVD	·np+0x00(SB), hlp1
	LDP	·p2+0x00(SB), (const0, const1)
	LDP	·p2+0x10(SB), (const2, const3)

	LDx (y1in)
	LDy (y2in)
	CALL gfpMulInternal(SB)
	STy (tmp0)

	LDx (x1in)
	LDy (x2in)
	CALL gfpMulInternal(SB)
	STy (tmp1)

	LDx (x1in)
	LDy (y1in)
	gfpAddInline
	STx (tmp2)

	LDx (x2in)
	LDy (y2in)
	gfpAddInline
	LDy (tmp2)
	CALL gfpMulInternal(SB)

	LDx (tmp0)
	CALL gfpSubInternal(SB)
	x2y
	LDx (tmp1)
	CALL gfpSubInternal(SB)
	x2y
	gfpMulBy2Inline
	MOVD	$0, y0 
	MOVD	$0, y1 
	MOVD	$0, y2 
	MOVD	$0, y3
	CALL gfpSubInternal(SB)
	MOVD	res+0(FP), res_ptr    // not use hlp1 any more
	STx (y3out)

	LDy (tmp1)
	gfpMulBy2Inline
	LDy (tmp0)
	CALL gfpSubInternal(SB)
	STx (x3out)

	RET

// func gfp2MulU1(c, a *gfP2)
TEXT ·gfp2MulU1(SB),NOSPLIT,$0-16
	MOVD	res+0(FP), b_ptr
	MOVD	in1+8(FP), a_ptr

	LDP	·p2+0x00(SB), (const0, const1)
	LDP	·p2+0x10(SB), (const2, const3)

	LDy (x1in)
	gfpMulBy2Inline
	MOVD	$0, y0 
	MOVD	$0, y1 
	MOVD	$0, y2 
	MOVD	$0, y3
	CALL gfpSubInternal(SB)
	
	ADD $32, a_ptr, a_ptr
	VLD1 (a_ptr), [V0.B16, V1.B16]
	VST1 [V0.B16, V1.B16], (b_ptr)
	STx (y2in)

	RET

// func gfp2Square(c, a *gfP2)
TEXT ·gfp2Square(SB),NOSPLIT,$72-16
	MOVD	res+0(FP), b_ptr
	MOVD	in1+8(FP), a_ptr

	MOVD	·np+0x00(SB), hlp1
	LDP	·p2+0x00(SB), (const0, const1)
	LDP	·p2+0x10(SB), (const2, const3)

	LDx (y1in)
	LDy (x1in)
	gfpAddInline
	STx (tmp0)
	gfpMulBy2Inline
	LDy (y1in)
	CALL gfpSubInternal(SB)
	LDy (tmp0)
	CALL gfpMulInternal(SB)
	STy (tmp0)

	LDx (y1in)
	LDy (x1in)
	CALL gfpMulInternal(SB)
	//STy (tmp1)
	LDx (tmp0)
	gfpAddInline
	STx (y2in)

	//LDy (tmp1)
	gfpMulBy2Inline
	STx (x2in)

	RET

// func gfp2SquareU(c, a *gfP2)
TEXT ·gfp2SquareU(SB),NOSPLIT,$72-16
	MOVD	res+0(FP), b_ptr
	MOVD	in1+8(FP), a_ptr

	MOVD	·np+0x00(SB), hlp1
	LDP	·p2+0x00(SB), (const0, const1)
	LDP	·p2+0x10(SB), (const2, const3)

	LDx (y1in)
	LDy (x1in)
	gfpAddInline
	STx (tmp0)
	gfpMulBy2Inline
	LDy (y1in)
	CALL gfpSubInternal(SB)
	LDy (tmp0)
	CALL gfpMulInternal(SB)
	STy (tmp0)

	LDx (y1in)
	LDy (x1in)
	CALL gfpMulInternal(SB)
	//STy (tmp1)
	LDx (tmp0)
	gfpAddInline
	STx (x2in)

	//LDy (tmp1)
	gfpMulBy2Inline2
	gfpMulBy2Inline
	MOVD	$0, y0 
	MOVD	$0, y1 
	MOVD	$0, y2 
	MOVD	$0, y3
	CALL gfpSubInternal(SB)
	STx (y2in)

	RET

/* ---------------------------------------*/
#undef tmp2
#define x3t(off) (32*2 + 8 + off)(RSP)
#define y3t(off) (32*3 + 8 + off)(RSP)
#define z3t(off) (32*4 + 8 + off)(RSP)

// func curvePointDoubleComplete(c, a *curvePoint)
TEXT ·curvePointDoubleComplete(SB),NOSPLIT,$168-16
	MOVD	res+0(FP), b_ptr
	MOVD	in1+8(FP), a_ptr

	MOVD	·np+0x00(SB), hlp1
	LDP	·p2+0x00(SB), (const0, const1)
	LDP	·p2+0x10(SB), (const2, const3)

	LDx (y1in)
	CALL gfpSqrInternal(SB) // t0 := Y^2
	STy (tmp0)

	gfpMulBy2Inline2        // Z3 := t0 + t0
	gfpMulBy2Inline2        // Z3 := Z3 + Z3
	gfpMulBy2Inline         // Z3 := Z3 + Z3
	STx (z3t)
	
	LDx (z1in)
	CALL gfpSqrInternal(SB) // t2 := Z^2
	STy (tmp1)
	gfpMulBy2Inline2
	gfpMulBy2Inline2
	gfpMulBy2Inline2
	gfpMulBy2Inline2
	LDx (tmp1)
	CALL gfpSubInternal(SB) // t2 := 3b * t2 = 3bZ^2
	STx (tmp1)
	LDy (z3t)
	CALL gfpMulInternal(SB) // X3 := t2 * Z3
	STy (x3t)

	LDx (tmp0)
	LDy (tmp1)
	gfpAddInline            // Y3 := t0 + t2
	STx (y3t)
	gfpMulBy2Inline
	gfpAddInline            // t2 := t2 + t2 + t2
	STx (tmp1)
	LDy (tmp0)
	CALL gfpSubInternal(SB) // t0 := t0 - t2
	STx (tmp0)    
	LDy (y3t)
	CALL gfpMulInternal(SB) // Y3 := t0 * Y3
	LDx (x3t)
	gfpAddInline            // Y3 := X3 + Y3
	STx (y3t)

	LDx (y1in)
	LDy (z1in)
	CALL gfpMulInternal(SB) // t1 := YZ
	LDx (z3t)
	CALL gfpMulInternal(SB) // Z3 := t1 * Z3
	STy (z2in)              // Store Z3

	LDx (x1in)
	LDy (y1in)
	CALL gfpMulInternal(SB) // t1 := XY
	LDx (tmp0)
	CALL gfpMulInternal(SB) // X3 := t0 * t1
	gfpMulBy2Inline         // X3 := X3 + X3
	STx (x2in)              // Store X3
	// Store Y3
	LDx (y3t)
	STx (y2in)

	RET

/* ---------------------------------------*/
#undef x3t
#undef y3t
#undef z3t

#define tmp2(off) (32*2 + 8 + off)(RSP)
#define tmp3(off) (32*3 + 8 + off)(RSP)
#define tmp4(off) (32*4 + 8 + off)(RSP)
#define x3t(off) (32*5 + 8 + off)(RSP)
#define y3t(off) (32*6 + 8 + off)(RSP)
#define z3t(off) (32*7 + 8 + off)(RSP)

// func curvePointAddComplete(c, a, b *curvePoint)
TEXT ·curvePointAddComplete(SB),0,$264-24
	MOVD	in1+8(FP), a_ptr
	MOVD	in2+16(FP), b_ptr

	MOVD	·np+0x00(SB), hlp1
	LDP	·p2+0x00(SB), (const0, const1)
	LDP	·p2+0x10(SB), (const2, const3)

	LDx (x1in)
	LDy (x2in)
	CALL gfpMulInternal(SB)         // t0 := X1X2
	STy (tmp0)
	LDx (y1in)
	LDy (y2in)
	CALL gfpMulInternal(SB)         // t1 := Y1Y2
	STy (tmp1)
	LDx (z1in)
	LDy (z2in)
	CALL gfpMulInternal(SB)         // t2 := Z1Z2
	STy (tmp2)

	LDx (x1in)
	LDy (y1in)
	gfpAddInline                    // t3 := X1 + Y1
	STx (tmp3)

	LDx (x2in)
	LDy (y2in)
	gfpAddInline                    // t4 := X2 + Y2
	LDy (tmp3)
	CALL gfpMulInternal(SB)         // t3 := t3 * t4 = (X1 + Y1) * (X2 + Y2)
	STy (tmp3)

	LDx (tmp0)
	LDy (tmp1)
	gfpAddInline                    // t4 := t0 + t1
	LDy (tmp3)
	CALL gfpSubInternal(SB)         // t3 := t3 - t4 = X1Y2 + X2Y1
	STx (tmp3)

	LDx (y1in)
	LDy (z1in)
	gfpAddInline                    // t4 := Y1 + Z1
	STx (tmp4)

	LDx (y2in)
	LDy (z2in)
	gfpAddInline                    // t3 := Y2 + Z2
	LDy (tmp4)
	CALL gfpMulInternal(SB)         // t4 := t4 * X3 = (Y1 + Z1)(Y2 + Z2)
	STy (tmp4)

	LDx (tmp1)
	LDy (tmp2)
	gfpAddInline                    // X3 := t1 + t2
	LDy (tmp4)
	CALL gfpSubInternal(SB)         // t4 := t4 - X3 = Y1Z2 + Y2Z1
	STx (tmp4)

	LDx (x1in)
	LDy (z1in)
	gfpAddInline                    // X3 := X1 + Z1
	STx (x3t)

	LDx (x2in)
	LDy (z2in)
	gfpAddInline                    // Y3 := X2 + Z2
	LDy (x3t)
	CALL gfpMulInternal(SB)         // X3 := X3 * Y3
	STy (x3t)

	LDx (tmp0)
	LDy (tmp2)
	gfpAddInline                    // Y3 := t0 + t2
	LDy (x3t)
	CALL gfpSubInternal(SB)         // Y3 := X3 - Y3 = X1Z2 + X2Z1
	STx (y3t)

	LDy (tmp0)
	gfpMulBy2Inline
	gfpAddInline                    // t0 := t0 + t0 + t0 = 3X1X2
	STx (tmp0)

	LDy (tmp2)
	gfpMulBy2Inline2
	gfpMulBy2Inline2
	gfpMulBy2Inline2
	gfpMulBy2Inline2
	LDx (tmp2)
	CALL gfpSubInternal(SB)        // t2 := 3b * t2 = 3bZ1Z2
	STx (tmp2)

	LDy (tmp1)
	gfpAddInline                   // Z3 := t1 + t2 = Y1Y2 + 3bZ1Z2
	STx (z3t)

	LDx (tmp2)
	CALL gfpSubInternal(SB)        // t1 := t1 - t2 = Y1Y2 - 3bZ1Z2
	STx (tmp1)

	LDy (y3t)
	gfpMulBy2Inline2
	gfpMulBy2Inline2
	gfpMulBy2Inline2
	gfpMulBy2Inline2
	LDx (y3t)
	CALL gfpSubInternal(SB)        // Y3 = 3b * Y3 = 3b(X1Z2 + X2Z1)
	STx (y3t)

	LDy (tmp4)
	CALL gfpMulInternal(SB)        // X3 := t4 * Y3 = 3b(X1Z2 + X2Z1)(Y1Z2 + Y2Z1)
	STy (x3t)

	MOVD res+0(FP), b_ptr

	LDx (tmp3)
	LDy (tmp1)
	CALL gfpMulInternal(SB)        // t2 := t3 * t1 = (X1Y2 + X2Y1)(Y1Y2 - 3bZ1Z2)
	LDx (x3t)
	CALL gfpSubInternal(SB)        // X3 := t2 - X3 = (X1Y2 + X2Y1)(Y1Y2 - 3bZ1Z2) - 3b(Y1Z2 + Y2Z1)(X1Z2 + X2Z1)
	STx (x2in)

	LDy (y3t)
	LDx (tmp0)
	CALL gfpMulInternal(SB)        // Y3 := Y3 * t0 = 9bX1X2(X1Z2 + X2Z1)
	STy (y3t)

	LDx (tmp1)
	LDy (z3t)
	CALL gfpMulInternal(SB)        // t1 := t1 * Z3 = (Y1Y2 + 3bZ1Z2)(Y1Y2 - 3bZ1Z2)
	LDx (y3t)
	gfpAddInline                   // Y3 := t1 + Y3 = (Y1Y2 + 3bZ1Z2)(Y1Y2 - 3bZ1Z2) + 9bX1X2(X1Z2 + X2Z1)
	STx (y2in)

	LDx (tmp0)
	LDy (tmp3)
	CALL gfpMulInternal(SB)        // t0 := t0 * t3 = 3X1X2(X1Y2 + X2Y1)
	STy (tmp0)

	LDx (tmp4)
	LDy (z3t)
	CALL gfpMulInternal(SB)        // Z3 := Z3 * t4 = (Y1Z2 + Y2Z1)(Y1Y2 + 3bZ1Z2)
	LDx (tmp0)
	gfpAddInline                   // Z3 := Z3 + t0 = (Y1Z2 + Y2Z1)(Y1Y2 + 3bZ1Z2) + 3X1X2(X1Y2 + X2Y1)
	STx (z2in)

	RET
