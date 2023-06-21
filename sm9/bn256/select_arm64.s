//go:build arm64 && !purego
// +build arm64,!purego

#include "textflag.h"

#define res_ptr R0
#define a_ptr R1
#define b_ptr R2

/* ---------------------------------------*/
// func gfP12MovCond(res, a, b *gfP12, cond int)
// If cond == 0 res=b, else res=a
TEXT ·gfP12MovCond(SB),NOSPLIT,$0
	MOVD	res+0(FP), res_ptr
	MOVD	a+8(FP), a_ptr
	MOVD	b+16(FP), b_ptr
	MOVD	cond+24(FP), R3

	CMP	$0, R3
	// Two remarks:
	// 1) Will want to revisit NEON, when support is better
	// 2) CSEL might not be constant time on all ARM processors
	LDP	0*16(a_ptr), (R4, R5)
	LDP	1*16(a_ptr), (R6, R7)
	LDP	2*16(a_ptr), (R8, R9)
	LDP	0*16(b_ptr), (R16, R17)
	LDP	1*16(b_ptr), (R19, R20)
	LDP	2*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 0*16(res_ptr)
	STP	(R6, R7), 1*16(res_ptr)
	STP	(R8, R9), 2*16(res_ptr)

	LDP	3*16(a_ptr), (R4, R5)
	LDP	4*16(a_ptr), (R6, R7)
	LDP	5*16(a_ptr), (R8, R9)
	LDP	3*16(b_ptr), (R16, R17)
	LDP	4*16(b_ptr), (R19, R20)
	LDP	5*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 3*16(res_ptr)
	STP	(R6, R7), 4*16(res_ptr)
	STP	(R8, R9), 5*16(res_ptr)

	LDP	6*16(a_ptr), (R4, R5)
	LDP	7*16(a_ptr), (R6, R7)
	LDP	8*16(a_ptr), (R8, R9)
	LDP	6*16(b_ptr), (R16, R17)
	LDP	7*16(b_ptr), (R19, R20)
	LDP	8*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 6*16(res_ptr)
	STP	(R6, R7), 7*16(res_ptr)
	STP	(R8, R9), 8*16(res_ptr)

	LDP	9*16(a_ptr), (R4, R5)
	LDP	10*16(a_ptr), (R6, R7)
	LDP	11*16(a_ptr), (R8, R9)
	LDP	9*16(b_ptr), (R16, R17)
	LDP	10*16(b_ptr), (R19, R20)
	LDP	11*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 9*16(res_ptr)
	STP	(R6, R7), 10*16(res_ptr)
	STP	(R8, R9), 11*16(res_ptr)

	LDP	12*16(a_ptr), (R4, R5)
	LDP	13*16(a_ptr), (R6, R7)
	LDP	14*16(a_ptr), (R8, R9)
	LDP	12*16(b_ptr), (R16, R17)
	LDP	13*16(b_ptr), (R19, R20)
	LDP	14*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 12*16(res_ptr)
	STP	(R6, R7), 13*16(res_ptr)
	STP	(R8, R9), 14*16(res_ptr)

	LDP	15*16(a_ptr), (R4, R5)
	LDP	16*16(a_ptr), (R6, R7)
	LDP	17*16(a_ptr), (R8, R9)
	LDP	15*16(b_ptr), (R16, R17)
	LDP	16*16(b_ptr), (R19, R20)
	LDP	17*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 15*16(res_ptr)
	STP	(R6, R7), 16*16(res_ptr)
	STP	(R8, R9), 17*16(res_ptr)

	LDP	18*16(a_ptr), (R4, R5)
	LDP	19*16(a_ptr), (R6, R7)
	LDP	20*16(a_ptr), (R8, R9)
	LDP	18*16(b_ptr), (R16, R17)
	LDP	19*16(b_ptr), (R19, R20)
	LDP	20*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 18*16(res_ptr)
	STP	(R6, R7), 19*16(res_ptr)
	STP	(R8, R9), 20*16(res_ptr)

	LDP	21*16(a_ptr), (R4, R5)
	LDP	22*16(a_ptr), (R6, R7)
	LDP	23*16(a_ptr), (R8, R9)
	LDP	21*16(b_ptr), (R16, R17)
	LDP	22*16(b_ptr), (R19, R20)
	LDP	23*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 21*16(res_ptr)
	STP	(R6, R7), 22*16(res_ptr)
	STP	(R8, R9), 23*16(res_ptr)

	RET

/* ---------------------------------------*/
// func curvePointMovCond(res, a, b *curvePoint, cond int)
// If cond == 0 res=b, else res=a
TEXT ·curvePointMovCond(SB),NOSPLIT,$0
	MOVD	res+0(FP), res_ptr
	MOVD	a+8(FP), a_ptr
	MOVD	b+16(FP), b_ptr
	MOVD	cond+24(FP), R3

	CMP	$0, R3
	// Two remarks:
	// 1) Will want to revisit NEON, when support is better
	// 2) CSEL might not be constant time on all ARM processors
	LDP	0*16(a_ptr), (R4, R5)
	LDP	1*16(a_ptr), (R6, R7)
	LDP	2*16(a_ptr), (R8, R9)
	LDP	0*16(b_ptr), (R16, R17)
	LDP	1*16(b_ptr), (R19, R20)
	LDP	2*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 0*16(res_ptr)
	STP	(R6, R7), 1*16(res_ptr)
	STP	(R8, R9), 2*16(res_ptr)

	LDP	3*16(a_ptr), (R4, R5)
	LDP	4*16(a_ptr), (R6, R7)
	LDP	5*16(a_ptr), (R8, R9)
	LDP	3*16(b_ptr), (R16, R17)
	LDP	4*16(b_ptr), (R19, R20)
	LDP	5*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 3*16(res_ptr)
	STP	(R6, R7), 4*16(res_ptr)
	STP	(R8, R9), 5*16(res_ptr)

	LDP	6*16(a_ptr), (R4, R5)
	LDP	7*16(a_ptr), (R6, R7)
	LDP	6*16(b_ptr), (R16, R17)
	LDP	7*16(b_ptr), (R19, R20)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	STP	(R4, R5), 6*16(res_ptr)
	STP	(R6, R7), 7*16(res_ptr)

	RET

/* ---------------------------------------*/
// func twistPointMovCond(res, a, b *twistPoint, cond int)
// If cond == 0 res=b, else res=a
TEXT ·twistPointMovCond(SB),NOSPLIT,$0
	MOVD	res+0(FP), res_ptr
	MOVD	a+8(FP), a_ptr
	MOVD	b+16(FP), b_ptr
	MOVD	cond+24(FP), R3

	CMP	$0, R3
	// Two remarks:
	// 1) Will want to revisit NEON, when support is better
	// 2) CSEL might not be constant time on all ARM processors
	LDP	0*16(a_ptr), (R4, R5)
	LDP	1*16(a_ptr), (R6, R7)
	LDP	2*16(a_ptr), (R8, R9)
	LDP	0*16(b_ptr), (R16, R17)
	LDP	1*16(b_ptr), (R19, R20)
	LDP	2*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 0*16(res_ptr)
	STP	(R6, R7), 1*16(res_ptr)
	STP	(R8, R9), 2*16(res_ptr)

	LDP	3*16(a_ptr), (R4, R5)
	LDP	4*16(a_ptr), (R6, R7)
	LDP	5*16(a_ptr), (R8, R9)
	LDP	3*16(b_ptr), (R16, R17)
	LDP	4*16(b_ptr), (R19, R20)
	LDP	5*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 3*16(res_ptr)
	STP	(R6, R7), 4*16(res_ptr)
	STP	(R8, R9), 5*16(res_ptr)

	LDP	6*16(a_ptr), (R4, R5)
	LDP	7*16(a_ptr), (R6, R7)
	LDP	8*16(a_ptr), (R8, R9)
	LDP	6*16(b_ptr), (R16, R17)
	LDP	7*16(b_ptr), (R19, R20)
	LDP	8*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 6*16(res_ptr)
	STP	(R6, R7), 7*16(res_ptr)
	STP	(R8, R9), 8*16(res_ptr)

	LDP	9*16(a_ptr), (R4, R5)
	LDP	10*16(a_ptr), (R6, R7)
	LDP	11*16(a_ptr), (R8, R9)
	LDP	9*16(b_ptr), (R16, R17)
	LDP	10*16(b_ptr), (R19, R20)
	LDP	11*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 9*16(res_ptr)
	STP	(R6, R7), 10*16(res_ptr)
	STP	(R8, R9), 11*16(res_ptr)

	LDP	12*16(a_ptr), (R4, R5)
	LDP	13*16(a_ptr), (R6, R7)
	LDP	14*16(a_ptr), (R8, R9)
	LDP	12*16(b_ptr), (R16, R17)
	LDP	13*16(b_ptr), (R19, R20)
	LDP	14*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 12*16(res_ptr)
	STP	(R6, R7), 13*16(res_ptr)
	STP	(R8, R9), 14*16(res_ptr)

	LDP	15*16(a_ptr), (R4, R5)
	LDP	15*16(b_ptr), (R16, R17)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	STP	(R4, R5), 15*16(res_ptr)

	RET
