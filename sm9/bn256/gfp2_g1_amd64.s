//go:build amd64 && !purego
// +build amd64,!purego

#include "textflag.h"

/* ---------------------------------------*/
#define mul0 AX
#define mul1 DX
#define acc0 BX
#define acc1 CX
#define acc2 R8
#define acc3 R9
#define acc4 R10
#define acc5 R11
#define acc6 R12
#define acc7 R13
#define t0 R14
#define t1 R15
#define t2 DI
#define t3 SI
#define hlp BP
/* ---------------------------------------*/
// (acc7, acc6, acc5, acc4) = (acc7, acc6, acc5, acc4) - (t3, t2, t1, t0)
TEXT gfpSubInternal(SB),NOSPLIT,$0
	XORQ mul0, mul0
	SUBQ t0, acc4
	SBBQ t1, acc5
	SBBQ t2, acc6
	SBBQ t3, acc7
	SBBQ $0, mul0

	MOVQ acc4, acc0
	MOVQ acc5, acc1
	MOVQ acc6, acc2
	MOVQ acc7, acc3

	ADDQ ·p2+0(SB), acc4
	ADCQ ·p2+8(SB), acc5
	ADCQ ·p2+16(SB), acc6
	ADCQ ·p2+24(SB), acc7
	ANDQ $1, mul0

	// CMOVQEQ: Move if equal (ZF == 1)
	CMOVQEQ acc0, acc4
	CMOVQEQ acc1, acc5
	CMOVQEQ acc2, acc6
	CMOVQEQ acc3, acc7

	RET

/* ---------------------------------------*/
// (acc7, acc6, acc5, acc4) = (acc7, acc6, acc5, acc4) * (t3, t2, t1, t0)
// t0, t1 will be overwrited after this function call
TEXT gfpMulInternal(SB),NOSPLIT,$8
	CMPB ·supportADX(SB), $0
	JE   noAdxMul

	// [t3, t2, t1, t0] * acc4
	MOVQ acc4, mul1
	MULXQ t0, acc0, acc1

	MULXQ t1, mul0, acc2
	ADDQ mul0, acc1

	MULXQ t2, mul0, acc3
	ADCQ mul0, acc2

	MULXQ t3, mul0, acc4
	ADCQ mul0, acc3
	ADCQ $0, acc4

	// [t3, t2, t1, t0] * acc5
	MOVQ acc5, mul1
	MULXQ t0, mul0, hlp
	ADDQ mul0, acc1
	ADCQ hlp, acc2

	MULXQ t1, mul0, hlp
	ADCQ $0, hlp
	ADDQ mul0, acc2
	ADCQ hlp, acc3

	MULXQ t2, mul0, hlp
	ADCQ $0, hlp
	ADDQ mul0, acc3
	ADCQ hlp, acc4

	MULXQ t3, mul0, acc5
	ADCQ $0, acc5
	ADDQ mul0, acc4
	ADCQ $0, acc5

	// [t3, t2, t1, t0] * acc5
	MOVQ acc6, mul1
	MULXQ t0, mul0, hlp
	ADDQ mul0, acc2
	ADCQ hlp, acc3

	MULXQ t1, mul0, hlp
	ADCQ $0, hlp
	ADDQ mul0, acc3
	ADCQ hlp, acc4

	MULXQ t2, mul0, hlp
	ADCQ $0, hlp
	ADDQ mul0, acc4
	ADCQ hlp, acc5

	MULXQ t3, mul0, acc6
	ADCQ $0, acc6
	ADDQ mul0, acc5
	ADCQ $0, acc6

	// [t3, t2, t1, t0] * acc7
	MOVQ acc7, mul1
	MULXQ t0, mul0, hlp
	ADDQ mul0, acc3
	ADCQ hlp, acc4

	MULXQ t1, mul0, hlp
	ADCQ $0, hlp
	ADDQ mul0, acc4
	ADCQ hlp, acc5

	MULXQ t2, mul0, hlp
	ADCQ $0, hlp
	ADDQ mul0, acc5
	ADCQ hlp, acc6

	MULXQ t3, mul0, acc7
	ADCQ $0, acc7
	ADDQ mul0, acc6
	ADCQ $0, acc7

	// T = [acc7, acc6, acc5, acc4, acc3, acc2, acc1, acc0]
	// First reduction step
	XORQ t1, t1
	MOVQ acc0, mul1
	MULXQ ·np+0x00(SB), mul1, mul0

	MULXQ ·p2+0x00(SB), mul0, t0
	ADOXQ mul0, acc0               // (carry1, acc0) = acc0 + t0 * ord0

	MULXQ ·p2+0x08(SB), mul0, hlp
	ADCXQ t0, mul0
	ADOXQ mul0, acc1

	MULXQ ·p2+0x10(SB), mul0, t0
	ADCXQ hlp, mul0
	ADOXQ mul0, acc2
	
	MULXQ ·p2+0x18(SB), mul0, acc0
	ADCXQ t0, mul0
	ADOXQ mul0, acc3
	ADCXQ t1, acc0
	ADOXQ t1, acc0

	// Second reduction step
	MOVQ acc1, mul1
	MULXQ ·np+0x00(SB), mul1, mul0

	MULXQ ·p2+0x00(SB), mul0, t0
	ADOXQ mul0, acc1

	MULXQ ·p2+0x08(SB), mul0, hlp
	ADCXQ t0, mul0
	ADOXQ mul0, acc2

	MULXQ ·p2+0x10(SB), mul0, t0
	ADCXQ hlp, mul0
	ADOXQ mul0, acc3

	MULXQ ·p2+0x18(SB), mul0, acc1
	ADCXQ t0, mul0
	ADOXQ mul0, acc0
	ADCXQ t1, acc1
	ADOXQ t1, acc1

	// Third reduction step
	MOVQ acc2, mul1
	MULXQ ·np+0x00(SB), mul1, mul0

	MULXQ ·p2+0x00(SB), mul0, t0
	ADOXQ mul0, acc2

	MULXQ ·p2+0x08(SB), mul0, hlp
	ADCXQ t0, mul0
	ADOXQ mul0, acc3

	MULXQ ·p2+0x10(SB), mul0, t0
	ADCXQ hlp, mul0
	ADOXQ mul0, acc0

	MULXQ ·p2+0x18(SB), mul0, acc2
	ADCXQ t0, mul0
	ADOXQ mul0, acc1
	ADCXQ t1, acc2
	ADOXQ t1, acc2

	// Last reduction step
	MOVQ acc3, mul1
	MULXQ ·np+0x00(SB), mul1, mul0

	MULXQ ·p2+0x00(SB), mul0, t0
	ADOXQ mul0, acc3

	MULXQ ·p2+0x08(SB), mul0, hlp
	ADCXQ t0, mul0
	ADOXQ mul0, acc0

	MULXQ ·p2+0x10(SB), mul0, t0
	ADCXQ hlp, mul0
	ADOXQ mul0, acc1

	MULXQ ·p2+0x18(SB), mul0, acc3
	ADCXQ t0, mul0
	ADOXQ mul0, acc2
	ADCXQ t1, acc3
	ADOXQ t1, acc3

	MOVQ $0, hlp
	// Add bits [511:256] of the result
	ADDQ acc0, acc4
	ADCQ acc1, acc5
	ADCQ acc2, acc6
	ADCQ acc3, acc7
	ADCQ $0, hlp
	// Copy result
	MOVQ acc4, acc0
	MOVQ acc5, acc1
	MOVQ acc6, acc2
	MOVQ acc7, acc3
	// Subtract p
	SUBQ ·p2+0(SB), acc4
	SBBQ ·p2+8(SB), acc5
	SBBQ ·p2+16(SB), acc6
	SBBQ ·p2+24(SB), acc7
	SBBQ $0, hlp
	// If the result of the subtraction is negative, restore the previous result
	CMOVQCS acc0, acc4
	CMOVQCS acc1, acc5
	CMOVQCS acc2, acc6
	CMOVQCS acc3, acc7

	RET

noAdxMul:
	// [t3, t2, t1, t0] * acc4
	MOVQ acc4, mul0
	MULQ t0
	MOVQ mul0, acc0
	MOVQ mul1, acc1

	MOVQ acc4, mul0
	MULQ t1
	ADDQ mul0, acc1
	ADCQ $0, mul1
	MOVQ mul1, acc2

	MOVQ acc4, mul0
	MULQ t2
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, acc3

	MOVQ acc4, mul0
	MULQ t3
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, acc4

	// [t3, t2, t1, t0] * acc5
	MOVQ acc5, mul0
	MULQ t0
	ADDQ mul0, acc1
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc5, mul0
	MULQ t1
	ADDQ hlp, acc2
	ADCQ $0, mul1
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc5, mul0
	MULQ t2
	ADDQ hlp, acc3
	ADCQ $0, mul1
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc5, mul0
	MULQ t3
	ADDQ hlp, acc4
	ADCQ $0, mul1
	ADDQ mul0, acc4
	ADCQ $0, mul1
	MOVQ mul1, acc5

	// [t3, t2, t1, t0] * acc6
	MOVQ acc6, mul0
	MULQ t0
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc6, mul0
	MULQ t1
	ADDQ hlp, acc3
	ADCQ $0, mul1
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc6, mul0
	MULQ t2
	ADDQ hlp, acc4
	ADCQ $0, mul1
	ADDQ mul0, acc4
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc6, mul0
	MULQ t3
	ADDQ hlp, acc5
	ADCQ $0, mul1
	ADDQ mul0, acc5
	ADCQ $0, mul1
	MOVQ mul1, acc6

	// [t3, t2, t1, t0] * acc7
	MOVQ acc7, mul0
	MULQ t0
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc7, mul0
	MULQ t1
	ADDQ hlp, acc4
	ADCQ $0, mul1
	ADDQ mul0, acc4
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc7, mul0
	MULQ t2
	ADDQ hlp, acc5
	ADCQ $0, mul1
	ADDQ mul0, acc5
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc7, mul0
	MULQ t3
	ADDQ hlp, acc6
	ADCQ $0, mul1
	ADDQ mul0, acc6
	ADCQ $0, mul1
	MOVQ mul1, acc7
	// T = [acc7, acc6, acc5, acc4, acc3, acc2, acc1, acc0]
	// First reduction step
	MOVQ acc0, mul0
	MULQ ·np+0x00(SB)
	MOVQ mul0, hlp

	MOVQ ·p2+0x00(SB), mul0
	MULQ hlp
	ADDQ mul0, acc0
	ADCQ $0, mul1
	MOVQ mul1, t0
	XORQ acc0, acc0

	MOVQ ·p2+0x08(SB), mul0
	MULQ hlp
	ADDQ t0, acc1
	ADCQ $0, mul1
	ADDQ mul0, acc1
	ADCQ $0, mul1
	MOVQ mul1, t0

	MOVQ ·p2+0x10(SB), mul0
	MULQ hlp
	ADDQ t0, acc2
	ADCQ $0, mul1
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, t0

	MOVQ ·p2+0x18(SB), mul0
	MULQ hlp
	ADDQ t0, acc3
	ADCQ $0, mul1
	ADDQ mul0, acc3
	ADCQ mul1, acc0

	// Second reduction step
	MOVQ acc1, mul0
	MULQ ·np+0x00(SB)
	MOVQ mul0, hlp

	MOVQ ·p2+0x00(SB), mul0
	MULQ hlp
	ADDQ mul0, acc1
	ADCQ $0, mul1
	MOVQ mul1, t0
	XORQ acc1, acc1

	MOVQ ·p2+0x08(SB), mul0
	MULQ hlp
	ADDQ t0, acc2
	ADCQ $0, mul1
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, t0

	MOVQ ·p2+0x10(SB), mul0
	MULQ hlp
	ADDQ t0, acc3
	ADCQ $0, mul1
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, t0

	MOVQ ·p2+0x18(SB), mul0
	MULQ hlp
	ADDQ t0, acc0
	ADCQ $0, mul1
	ADDQ mul0, acc0
	ADCQ mul1, acc1

	// Third reduction step
	MOVQ acc2, mul0
	MULQ ·np+0x00(SB)
	MOVQ mul0, hlp

	MOVQ ·p2+0x00(SB), mul0
	MULQ hlp
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, t0
	XORQ acc2, acc2

	MOVQ ·p2+0x08(SB), mul0
	MULQ hlp
	ADDQ t0, acc3
	ADCQ $0, mul1
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, t0

	MOVQ ·p2+0x10(SB), mul0
	MULQ hlp
	ADDQ t0, acc0
	ADCQ $0, mul1
	ADDQ mul0, acc0
	ADCQ $0, mul1
	MOVQ mul1, t0

	MOVQ ·p2+0x18(SB), mul0
	MULQ hlp
	ADDQ t0, acc1
	ADCQ $0, mul1
	ADDQ mul0, acc1
	ADCQ mul1, acc2

	// Last reduction step
	MOVQ acc3, mul0
	MULQ ·np+0x00(SB)
	MOVQ mul0, hlp

	MOVQ ·p2+0x00(SB), mul0
	MULQ hlp
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, t0
	XORQ acc3, acc3

	MOVQ ·p2+0x08(SB), mul0
	MULQ hlp
	ADDQ t0, acc0
	ADCQ $0, mul1
	ADDQ mul0, acc0
	ADCQ $0, mul1
	MOVQ mul1, t0

	MOVQ ·p2+0x10(SB), mul0
	MULQ hlp
	ADDQ t0, acc1
	ADCQ $0, mul1
	ADDQ mul0, acc1
	ADCQ $0, mul1
	MOVQ mul1, t0

	MOVQ ·p2+0x18(SB), mul0
	MULQ hlp
	ADDQ t0, acc2
	ADCQ $0, mul1
	ADDQ mul0, acc2
	ADCQ mul1, acc3

	MOVQ $0, hlp
	// Add bits [511:256] of the result
	ADDQ acc0, acc4
	ADCQ acc1, acc5
	ADCQ acc2, acc6
	ADCQ acc3, acc7
	ADCQ $0, hlp
	// Copy result
	MOVQ acc4, acc0
	MOVQ acc5, acc1
	MOVQ acc6, acc2
	MOVQ acc7, acc3
	// Subtract p
	SUBQ ·p2+0(SB), acc4
	SBBQ ·p2+8(SB), acc5
	SBBQ ·p2+16(SB), acc6
	SBBQ ·p2+24(SB), acc7
	SBBQ $0, hlp
	// If the result of the subtraction is negative, restore the previous result
	CMOVQCS acc0, acc4
	CMOVQCS acc1, acc5
	CMOVQCS acc2, acc6
	CMOVQCS acc3, acc7

	RET

/* ---------------------------------------*/
// (acc7, acc6, acc5, acc4) = (acc7, acc6, acc5, acc4) ^ 2
TEXT gfpSqrInternal(SB),NOSPLIT,$8
	CMPB ·supportADX(SB), $0
	JE   noAdxSqr

	XORQ t3, t3

	// [acc7, acc6, acc5] * acc4
	MOVQ acc4, mul1
	MULXQ acc5, acc1, acc2

	MULXQ acc6, mul0, acc3
	ADOXQ mul0, acc2

	MULXQ acc7, mul0, t0
	ADOXQ mul0, acc3
	ADOXQ t3, t0

	// [acc7, acc6] * acc5
	MOVQ acc5, mul1
	MULXQ acc6, mul0, hlp
	ADOXQ mul0, acc3

	MULXQ acc7, mul0, t1
	ADCXQ hlp, mul0
	ADOXQ mul0, t0
	ADCXQ t3, t1

	// acc7 * acc6
	MOVQ acc6, mul1
	MULXQ acc7, mul0, t2
	ADOXQ mul0, t1
	ADOXQ t3, t2
	
	// *2
	ADOXQ acc1, acc1
	ADOXQ acc2, acc2
	ADOXQ acc3, acc3
	ADOXQ t0, t0
	ADOXQ t1, t1
	ADOXQ t2, t2
	ADOXQ t3, t3

	// Missing products
	MOVQ acc4, mul1
	MULXQ mul1, acc0, acc4 
	ADCXQ acc4, acc1

	MOVQ acc5, mul1
	MULXQ mul1, mul0, acc4
	ADCXQ mul0, acc2
	ADCXQ acc4, acc3

	MOVQ acc6, mul1
	MULXQ mul1, mul0, acc4
	ADCXQ mul0, t0
	ADCXQ acc4, t1

	MOVQ acc7, mul1
	MULXQ mul1, mul0, acc4
	ADCXQ mul0, t2
	ADCXQ acc4, t3

	// T = [t3, t2, t1, t0, acc3, acc2, acc1, acc0]
	// First reduction step
	XORQ acc5, acc5
	MOVQ acc0, mul1
	MULXQ ·np+0x00(SB), mul1, mul0

	MULXQ ·p2+0x00(SB), mul0, acc4
	ADOXQ mul0, acc0               // (carry1, acc0) = acc0 + acc5 * ord0

	MULXQ ·p2+0x08(SB), mul0, hlp
	ADCXQ acc4, mul0
	ADOXQ mul0, acc1

	MULXQ ·p2+0x10(SB), mul0, acc4
	ADCXQ hlp, mul0
	ADOXQ mul0, acc2
	
	MULXQ ·p2+0x18(SB), mul0, acc0
	ADCXQ acc4, mul0
	ADOXQ mul0, acc3
	ADCXQ acc5, acc0
	ADOXQ acc5, acc0

	// Second reduction step
	MOVQ acc1, mul1
	MULXQ ·np+0x00(SB), mul1, mul0

	MULXQ ·p2+0x00(SB), mul0, acc4
	ADOXQ mul0, acc1

	MULXQ ·p2+0x08(SB), mul0, hlp
	ADCXQ acc4, mul0
	ADOXQ mul0, acc2

	MULXQ ·p2+0x10(SB), mul0, acc4
	ADCXQ hlp, mul0
	ADOXQ mul0, acc3

	MULXQ ·p2+0x18(SB), mul0, acc1
	ADCXQ acc4, mul0
	ADOXQ mul0, acc0
	ADCXQ acc5, acc1
	ADOXQ acc5, acc1

	// Third reduction step
	MOVQ acc2, mul1
	MULXQ ·np+0x00(SB), mul1, mul0

	MULXQ ·p2+0x00(SB), mul0, acc4
	ADOXQ mul0, acc2

	MULXQ ·p2+0x08(SB), mul0, hlp
	ADCXQ acc4, mul0
	ADOXQ mul0, acc3

	MULXQ ·p2+0x10(SB), mul0, acc4
	ADCXQ hlp, mul0
	ADOXQ mul0, acc0

	MULXQ ·p2+0x18(SB), mul0, acc2
	ADCXQ acc4, mul0
	ADOXQ mul0, acc1
	ADCXQ acc5, acc2
	ADOXQ acc5, acc2

	// Last reduction step
	MOVQ acc3, mul1
	MULXQ ·np+0x00(SB), mul1, mul0

	MULXQ ·p2+0x00(SB), mul0, acc4
	ADOXQ mul0, acc3

	MULXQ ·p2+0x08(SB), mul0, hlp
	ADCXQ acc4, mul0
	ADOXQ mul0, acc0

	MULXQ ·p2+0x10(SB), mul0, acc4
	ADCXQ hlp, mul0
	ADOXQ mul0, acc1

	MULXQ ·p2+0x18(SB), mul0, acc3
	ADCXQ acc4, mul0
	ADOXQ mul0, acc2
	ADCXQ acc5, acc3
	ADOXQ acc5, acc3

	MOVQ $0, hlp
	// Add bits [511:256] of the result
	ADDQ acc0, t0
	ADCQ acc1, t1
	ADCQ acc2, t2
	ADCQ acc3, t3
	ADCQ $0, hlp
	// Copy result
	MOVQ t0, acc4
	MOVQ t1, acc5
	MOVQ t2, acc6
	MOVQ t3, acc7
	// Subtract p
	SUBQ ·p2+0(SB), acc4
	SBBQ ·p2+8(SB), acc5
	SBBQ ·p2+16(SB), acc6
	SBBQ ·p2+24(SB), acc7
	SBBQ $0, hlp
	// If the result of the subtraction is negative, restore the previous result
	CMOVQCS t0, acc4
	CMOVQCS t1, acc5
	CMOVQCS t2, acc6
	CMOVQCS t3, acc7

	RET

noAdxSqr:
	MOVQ acc4, mul0
	MULQ acc5
	MOVQ mul0, acc1
	MOVQ mul1, acc2

	MOVQ acc4, mul0
	MULQ acc6
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, acc3

	MOVQ acc4, mul0
	MULQ acc7
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, t0

	MOVQ acc5, mul0
	MULQ acc6
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc5, mul0
	MULQ acc7
	ADDQ hlp, t0
	ADCQ $0, mul1
	ADDQ mul0, t0
	ADCQ $0, mul1
	MOVQ mul1, t1

	MOVQ acc6, mul0
	MULQ acc7
	ADDQ mul0, t1
	ADCQ $0, mul1
	MOVQ mul1, t2
	XORQ t3, t3
	// *2
	ADDQ acc1, acc1
	ADCQ acc2, acc2
	ADCQ acc3, acc3
	ADCQ t0, t0
	ADCQ t1, t1
	ADCQ t2, t2
	ADCQ $0, t3
	// Missing products
	MOVQ acc4, mul0
	MULQ mul0
	MOVQ mul0, acc0
	MOVQ DX, acc4

	MOVQ acc5, mul0
	MULQ mul0
	ADDQ acc4, acc1
	ADCQ mul0, acc2
	ADCQ $0, DX
	MOVQ DX, acc4

	MOVQ acc6, mul0
	MULQ mul0
	ADDQ acc4, acc3
	ADCQ mul0, t0
	ADCQ $0, DX
	MOVQ DX, acc4

	MOVQ acc7, mul0
	MULQ mul0
	ADDQ acc4, t1
	ADCQ mul0, t2
	ADCQ DX, t3
	// T = [t3, t2, t1, t0, acc3, acc2, acc1, acc0]
	// First reduction step
	MOVQ acc0, mul0
	MULQ ·np+0x00(SB)
	MOVQ mul0, hlp

	MOVQ ·p2+0x00(SB), mul0
	MULQ hlp
	ADDQ mul0, acc0
	ADCQ $0, mul1
	MOVQ mul1, acc5
	XORQ acc0, acc0

	MOVQ ·p2+0x08(SB), mul0
	MULQ hlp
	ADDQ acc5, acc1
	ADCQ $0, mul1
	ADDQ mul0, acc1
	ADCQ $0, mul1
	MOVQ mul1, acc5

	MOVQ ·p2+0x10(SB), mul0
	MULQ hlp
	ADDQ acc5, acc2
	ADCQ $0, mul1
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, acc5

	MOVQ ·p2+0x18(SB), mul0
	MULQ hlp
	ADDQ acc5, acc3
	ADCQ $0, mul1
	ADDQ mul0, acc3
	ADCQ mul1, acc0

	// Second reduction step
	MOVQ acc1, mul0
	MULQ ·np+0x00(SB)
	MOVQ mul0, hlp

	MOVQ ·p2+0x00(SB), mul0
	MULQ hlp
	ADDQ mul0, acc1
	ADCQ $0, mul1
	MOVQ mul1, acc5
	XORQ acc1, acc1

	MOVQ ·p2+0x08(SB), mul0
	MULQ hlp
	ADDQ acc5, acc2
	ADCQ $0, mul1
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, acc5

	MOVQ ·p2+0x10(SB), mul0
	MULQ hlp
	ADDQ acc5, acc3
	ADCQ $0, mul1
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, acc5

	MOVQ ·p2+0x18(SB), mul0
	MULQ hlp
	ADDQ acc5, acc0
	ADCQ $0, mul1
	ADDQ mul0, acc0
	ADCQ mul1, acc1

	// Third reduction step
	MOVQ acc2, mul0
	MULQ ·np+0x00(SB)
	MOVQ mul0, hlp

	MOVQ ·p2+0x00(SB), mul0
	MULQ hlp
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, acc5
	XORQ acc2, acc2

	MOVQ ·p2+0x08(SB), mul0
	MULQ hlp
	ADDQ acc5, acc3
	ADCQ $0, mul1
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, acc5

	MOVQ ·p2+0x10(SB), mul0
	MULQ hlp
	ADDQ acc5, acc0
	ADCQ $0, mul1
	ADDQ mul0, acc0
	ADCQ $0, mul1
	MOVQ mul1, acc5

	MOVQ ·p2+0x18(SB), mul0
	MULQ hlp
	ADDQ acc5, acc1
	ADCQ $0, mul1
	ADDQ mul0, acc1
	ADCQ mul1, acc2

	// Last reduction step
	MOVQ acc3, mul0
	MULQ ·np+0x00(SB)
	MOVQ mul0, hlp

	MOVQ ·p2+0x00(SB), mul0
	MULQ hlp
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, acc5
	XORQ acc3, acc3

	MOVQ ·p2+0x08(SB), mul0
	MULQ hlp
	ADDQ acc5, acc0
	ADCQ $0, mul1
	ADDQ mul0, acc0
	ADCQ $0, mul1
	MOVQ mul1, acc5

	MOVQ ·p2+0x10(SB), mul0
	MULQ hlp
	ADDQ acc5, acc1
	ADCQ $0, mul1
	ADDQ mul0, acc1
	ADCQ $0, mul1
	MOVQ mul1, acc5

	MOVQ ·p2+0x18(SB), mul0
	MULQ hlp
	ADDQ acc5, acc2
	ADCQ $0, mul1
	ADDQ mul0, acc2
	ADCQ mul1, acc3

	MOVQ $0, hlp
	// Add bits [511:256] of the result
	ADDQ acc0, t0
	ADCQ acc1, t1
	ADCQ acc2, t2
	ADCQ acc3, t3
	ADCQ $0, hlp
	// Copy result
	MOVQ t0, acc4
	MOVQ t1, acc5
	MOVQ t2, acc6
	MOVQ t3, acc7
	// Subtract p
	SUBQ ·p2+0(SB), acc4
	SBBQ ·p2+8(SB), acc5
	SBBQ ·p2+16(SB), acc6
	SBBQ ·p2+24(SB), acc7
	SBBQ $0, hlp
	// If the result of the subtraction is negative, restore the previous result
	CMOVQCS t0, acc4
	CMOVQCS t1, acc5
	CMOVQCS t2, acc6
	CMOVQCS t3, acc7

	RET

/* ---------------------------------------*/
// (t3, t2, t1, t0) = 2(acc7, acc6, acc5, acc4)
#define gfpMulBy2Inline \
	XORQ mul0, mul0;\
	ADDQ acc4, acc4;\
	ADCQ acc5, acc5;\
	ADCQ acc6, acc6;\
	ADCQ acc7, acc7;\
	ADCQ $0, mul0;\
	MOVQ acc4, t0;\
	MOVQ acc5, t1;\
	MOVQ acc6, t2;\
	MOVQ acc7, t3;\
	SUBQ ·p2+0(SB), t0;\
	SBBQ ·p2+8(SB), t1;\
	SBBQ ·p2+16(SB), t2;\
	SBBQ ·p2+24(SB), t3;\
	SBBQ $0, mul0;\
	CMOVQCS acc4, t0;\ // CMOVQCS: Move if below (CF == 1)
	CMOVQCS acc5, t1;\
	CMOVQCS acc6, t2;\
	CMOVQCS acc7, t3;

/* ---------------------------------------*/
// (t3, t2, t1, t0) = (acc7, acc6, acc5, acc4) + (t3, t2, t1, t0)
#define gfpAddInline \
	XORQ mul0, mul0;\
	ADDQ t0, acc4;\
	ADCQ t1, acc5;\
	ADCQ t2, acc6;\
	ADCQ t3, acc7;\
	ADCQ $0, mul0;\
	MOVQ acc4, t0;\
	MOVQ acc5, t1;\
	MOVQ acc6, t2;\
	MOVQ acc7, t3;\
	SUBQ ·p2+0(SB), t0;\
	SBBQ ·p2+8(SB), t1;\
	SBBQ ·p2+16(SB), t2;\
	SBBQ ·p2+24(SB), t3;\
	SBBQ $0, mul0;\
	CMOVQCS acc4, t0;\
	CMOVQCS acc5, t1;\
	CMOVQCS acc6, t2;\
	CMOVQCS acc7, t3;

/* ---------------------------------------*/
#define LDacc(src) MOVQ src(8*0), acc4; MOVQ src(8*1), acc5; MOVQ src(8*2), acc6; MOVQ src(8*3), acc7
#define LDt(src)   MOVQ src(8*0), t0; MOVQ src(8*1), t1; MOVQ src(8*2), t2; MOVQ src(8*3), t3
#define ST(dst)    MOVQ acc4, dst(8*0); MOVQ acc5, dst(8*1); MOVQ acc6, dst(8*2); MOVQ acc7, dst(8*3)
#define STt(dst)   MOVQ t0, dst(8*0); MOVQ t1, dst(8*1); MOVQ t2, dst(8*2); MOVQ t3, dst(8*3)
#define acc2t      MOVQ acc4, t0; MOVQ acc5, t1; MOVQ acc6, t2; MOVQ acc7, t3
#define t2acc      MOVQ t0, acc4; MOVQ t1, acc5; MOVQ t2, acc6; MOVQ t3, acc7

/* ---------------------------------------*/
#define axin(off) (32*0 + off)(SP)
#define ayin(off) (32*1 + off)(SP)
#define bxin(off) (32*2 + off)(SP)
#define byin(off) (32*3 + off)(SP)
#define tmp0(off) (32*4 + off)(SP)
#define tmp1(off) (32*5 + off)(SP)
#define cxout(off) (32*6 + off)(SP)
#define rptr	  (32*7)(SP)

TEXT ·gfp2Mul(SB),NOSPLIT,$256-24
	// Move input to stack in order to free registers
	MOVQ res+0(FP), CX
	MOVQ in1+8(FP), AX
	MOVQ in2+16(FP), BX

	MOVOU (16*0)(AX), X0
	MOVOU (16*1)(AX), X1
	MOVOU (16*2)(AX), X2
	MOVOU (16*3)(AX), X3

	MOVOU X0, axin(16*0)
	MOVOU X1, axin(16*1)
	MOVOU X2, ayin(16*0)
	MOVOU X3, ayin(16*1)

	MOVOU (16*0)(BX), X0
	MOVOU (16*1)(BX), X1
	MOVOU (16*2)(BX), X2
	MOVOU (16*3)(BX), X3

	MOVOU X0, bxin(16*0)
	MOVOU X1, bxin(16*1)
	MOVOU X2, byin(16*0)
	MOVOU X3, byin(16*1)

	// Store pointer to result
	MOVQ CX, rptr

	LDacc (ayin)
	LDt (byin)
	CALL gfpMulInternal(SB)
	ST (tmp0)

	LDacc (axin)
	LDt (bxin)
	CALL gfpMulInternal(SB)
	ST (tmp1)

	LDacc (axin)
	LDt (ayin)
	gfpAddInline
	STt (cxout)

	LDacc (bxin)
	LDt (byin)
	gfpAddInline

	LDacc (cxout)
	CALL gfpMulInternal(SB)
	LDt (tmp0)
	CALL gfpSubInternal(SB)
	LDt (tmp1)
	CALL gfpSubInternal(SB)

	// Store x	
	MOVQ rptr, AX
	MOVQ acc4, (16*0 + 8*0)(AX)
	MOVQ acc5, (16*0 + 8*1)(AX)
	MOVQ acc6, (16*0 + 8*2)(AX)
	MOVQ acc7, (16*0 + 8*3)(AX)

	LDacc (tmp0)
	//LDt (tmp1)
	CALL gfpSubInternal(SB)
	CALL gfpSubInternal(SB)
	MOVQ rptr, AX
	///////////////////////
	MOVQ $0, rptr	
	// Store y
	MOVQ acc4, (16*2 + 8*0)(AX)
	MOVQ acc5, (16*2 + 8*1)(AX)
	MOVQ acc6, (16*2 + 8*2)(AX)
	MOVQ acc7, (16*2 + 8*3)(AX)

	RET

TEXT ·gfp2MulU(SB),NOSPLIT,$256-24
	// Move input to stack in order to free registers
	MOVQ res+0(FP), CX
	MOVQ in1+8(FP), AX
	MOVQ in2+16(FP), BX

	MOVOU (16*0)(AX), X0
	MOVOU (16*1)(AX), X1
	MOVOU (16*2)(AX), X2
	MOVOU (16*3)(AX), X3

	MOVOU X0, axin(16*0)
	MOVOU X1, axin(16*1)
	MOVOU X2, ayin(16*0)
	MOVOU X3, ayin(16*1)

	MOVOU (16*0)(BX), X0
	MOVOU (16*1)(BX), X1
	MOVOU (16*2)(BX), X2
	MOVOU (16*3)(BX), X3

	MOVOU X0, bxin(16*0)
	MOVOU X1, bxin(16*1)
	MOVOU X2, byin(16*0)
	MOVOU X3, byin(16*1)

	// Store pointer to result
	MOVQ CX, rptr

	LDacc (ayin)
	LDt (byin)
	CALL gfpMulInternal(SB)
	ST (tmp0)

	LDacc (axin)
	LDt (bxin)
	CALL gfpMulInternal(SB)
	ST (tmp1)

	LDacc (axin)
	LDt (ayin)
	gfpAddInline
	STt (cxout)

	LDacc (bxin)
	LDt (byin)
	gfpAddInline

	LDacc (cxout)
	CALL gfpMulInternal(SB)
	LDt (tmp0)
	CALL gfpSubInternal(SB)
	LDt (tmp1)
	CALL gfpSubInternal(SB)
	gfpMulBy2Inline
	XORQ acc4, acc4
	XORQ acc5, acc5
	XORQ acc6, acc6
	XORQ acc7, acc7
	CALL gfpSubInternal(SB)

	// Store y
	MOVQ rptr, AX
	MOVQ acc4, (16*2 + 8*0)(AX)
	MOVQ acc5, (16*2 + 8*1)(AX)
	MOVQ acc6, (16*2 + 8*2)(AX)
	MOVQ acc7, (16*2 + 8*3)(AX)

	LDacc (tmp0)
	LDt (tmp1)
	CALL gfpSubInternal(SB)
	CALL gfpSubInternal(SB)
	MOVQ rptr, AX
	///////////////////////
	MOVQ $0, rptr	
	// Store x
	MOVQ acc4, (16*0 + 8*0)(AX)
	MOVQ acc5, (16*0 + 8*1)(AX)
	MOVQ acc6, (16*0 + 8*2)(AX)
	MOVQ acc7, (16*0 + 8*3)(AX)

	RET

#undef axin
#undef ayin
#undef bxin
#undef byin
#undef tmp0
#undef tmp1
#undef cxout
#undef rptr

#define axin(off) (32*0 + off)(SP)
#define ayin(off) (32*1 + off)(SP)
#define cxout(off) (32*2 + off)(SP)
#define cyout(off) (32*3 + off)(SP)
#define rptr	  (32*4)(SP)

TEXT ·gfp2Square(SB),NOSPLIT,$160-16
	// Move input to stack in order to free registers
	MOVQ res+0(FP), AX
	MOVQ in1+8(FP), BX

	MOVOU (16*0)(BX), X0
	MOVOU (16*1)(BX), X1
	MOVOU (16*2)(BX), X2
	MOVOU (16*3)(BX), X3

	MOVOU X0, axin(16*0)
	MOVOU X1, axin(16*1)
	MOVOU X2, ayin(16*0)
	MOVOU X3, ayin(16*1)

	// Store pointer to result
	MOVQ AX, rptr
	
	LDacc (axin)
	LDt (ayin)
	gfpAddInline
	STt (cyout)

	LDacc (axin)
	gfpMulBy2Inline
	STt (cxout)

	LDacc (ayin)
	CALL gfpSubInternal(SB)
	ST (cxout)

	LDt (cyout)
	CALL gfpMulInternal(SB)
	ST (cyout)

	LDacc (axin)
	LDt (ayin)
	CALL gfpMulInternal(SB)
	ST (cxout)

	LDt (cyout)
	gfpAddInline
	// Store y
	MOVQ rptr, AX
	MOVQ t0, (16*2 + 8*0)(AX)
	MOVQ t1, (16*2 + 8*1)(AX)
	MOVQ t2, (16*2 + 8*2)(AX)
	MOVQ t3, (16*2 + 8*3)(AX)

	LDacc (cxout)
	gfpMulBy2Inline
	// Store x
	MOVQ rptr, AX
	///////////////////////
	MOVQ $0, rptr	
	MOVQ t0, (16*0 + 8*0)(AX)
	MOVQ t1, (16*0 + 8*1)(AX)
	MOVQ t2, (16*0 + 8*2)(AX)
	MOVQ t3, (16*0 + 8*3)(AX)

	RET

TEXT ·gfp2SquareU(SB),NOSPLIT,$160-16
	// Move input to stack in order to free registers
	MOVQ res+0(FP), AX
	MOVQ in1+8(FP), BX

	MOVOU (16*0)(BX), X0
	MOVOU (16*1)(BX), X1
	MOVOU (16*2)(BX), X2
	MOVOU (16*3)(BX), X3

	MOVOU X0, axin(16*0)
	MOVOU X1, axin(16*1)
	MOVOU X2, ayin(16*0)
	MOVOU X3, ayin(16*1)

	// Store pointer to result
	MOVQ AX, rptr
	
	LDacc (axin)
	LDt (ayin)
	gfpAddInline
	STt (cxout)

	LDacc (axin)
	gfpMulBy2Inline
	STt (cyout)

	LDacc (ayin)
	CALL gfpSubInternal(SB)
	ST (cyout)

	LDt (cxout)
	CALL gfpMulInternal(SB)
	ST (cxout)

	LDacc (axin)
	LDt (ayin)
	CALL gfpMulInternal(SB)
	ST (cyout)

	LDt (cxout)
	gfpAddInline

	// Store x
	MOVQ rptr, AX
	MOVQ t0, (16*0 + 8*0)(AX)
	MOVQ t1, (16*0 + 8*1)(AX)
	MOVQ t2, (16*0 + 8*2)(AX)
	MOVQ t3, (16*0 + 8*3)(AX)

	LDacc (cyout)
	gfpMulBy2Inline
	t2acc
	gfpMulBy2Inline
	XORQ acc4, acc4
	XORQ acc5, acc5
	XORQ acc6, acc6
	XORQ acc7, acc7
	CALL gfpSubInternal(SB)

	// Store y
	MOVQ rptr, AX
	///////////////////////
	MOVQ $0, rptr	
	MOVQ acc4, (16*2 + 8*0)(AX)
	MOVQ acc5, (16*2 + 8*1)(AX)
	MOVQ acc6, (16*2 + 8*2)(AX)
	MOVQ acc7, (16*2 + 8*3)(AX)

	RET

#undef axin
#undef ayin
#undef cxout
#undef cyout
#undef rptr

/* ---------------------------------------*/
#define xin(off) (32*0 + off)(SP)
#define yin(off) (32*1 + off)(SP)
#define zin(off) (32*2 + off)(SP)

#define xout(off) (32*3 + off)(SP)
#define yout(off) (32*4 + off)(SP)
#define zout(off) (32*5 + off)(SP)
#define tmp0(off) (32*6 + off)(SP)
#define tmp2(off) (32*7 + off)(SP)
#define rptr	  (32*8)(SP)

// func curvePointDoubleComplete(c, a *curvePoint)
TEXT ·curvePointDoubleComplete(SB),NOSPLIT,$288-16
	MOVQ res+0(FP), AX
	MOVQ in+8(FP), BX

	MOVOU (16*0)(BX), X0
	MOVOU (16*1)(BX), X1
	MOVOU (16*2)(BX), X2
	MOVOU (16*3)(BX), X3
	MOVOU (16*4)(BX), X4
	MOVOU (16*5)(BX), X5
	
	MOVOU X0, xin(16*0)
	MOVOU X1, xin(16*1)
	MOVOU X2, yin(16*0)
	MOVOU X3, yin(16*1)
	MOVOU X4, zin(16*0)
	MOVOU X5, zin(16*1)

	// Store pointer to result
	MOVQ AX, rptr

	LDacc (yin)
	CALL gfpSqrInternal(SB) // t0 := Y^2
	ST (tmp0)

	gfpMulBy2Inline // Z3 := t0 + t0
	t2acc
	gfpMulBy2Inline // Z3 := Z3 + Z3
	t2acc
	gfpMulBy2Inline // Z3 := Z3 + Z3
	STt (zout)	

	LDacc (zin)
	CALL gfpSqrInternal(SB) // t2 := Z^2
	ST (tmp2)
	gfpMulBy2Inline
	t2acc
	gfpMulBy2Inline
	t2acc
	gfpMulBy2Inline
	t2acc
	gfpMulBy2Inline
	t2acc
	LDt (tmp2)
	CALL gfpSubInternal(SB)  // t2 := 3b * t2
	ST (tmp2)
	LDt (zout)
	CALL gfpMulInternal(SB) // X3 := Z3 * t2
	ST (xout)

	LDacc (tmp0)
	LDt (tmp2)
	gfpAddInline // Y3 := t0 + t2
	STt (yout)

	LDacc (yin)
	LDt (zin)
	CALL gfpMulInternal(SB) // t1 := YZ
	LDt (zout)
	CALL gfpMulInternal(SB) // Z3 := t1 * Z3
	MOVQ rptr, AX
	// Store Z
	MOVQ acc4, (16*4 + 8*0)(AX)
	MOVQ acc5, (16*4 + 8*1)(AX)
	MOVQ acc6, (16*4 + 8*2)(AX)
	MOVQ acc7, (16*4 + 8*3)(AX)	

	LDacc (tmp2) 
	gfpMulBy2Inline
	LDacc (tmp2)
	gfpAddInline // t2 := t2 + t2 + t2
	LDacc (tmp0)
	CALL gfpSubInternal(SB) // t0 := t0 - t2
	ST (tmp0)
	LDt (yout)
	CALL gfpMulInternal(SB) // Y3 = t0 * Y3
	LDt (xout)
	gfpAddInline // Y3 := X3 + Y3
	MOVQ rptr, AX
	// Store y
	MOVQ t0, (16*2 + 8*0)(AX)
	MOVQ t1, (16*2 + 8*1)(AX)
	MOVQ t2, (16*2 + 8*2)(AX)
	MOVQ t3, (16*2 + 8*3)(AX)

	LDacc (xin)
	LDt (yin)
	CALL gfpMulInternal(SB) // t1 := XY
	LDt (tmp0)
	CALL gfpMulInternal(SB) // X3 := t0 * t1
	gfpMulBy2Inline         // X3 := X3 + X3
	MOVQ rptr, AX
	MOVQ $0, rptr
	// Store x
	MOVQ t0, (16*0 + 8*0)(AX)
	MOVQ t1, (16*0 + 8*1)(AX)
	MOVQ t2, (16*0 + 8*2)(AX)
	MOVQ t3, (16*0 + 8*3)(AX)

	RET

#undef xin
#undef yin
#undef zin
#undef xout
#undef yout
#undef zout
#undef tmp0
#undef tmp2
#undef rptr

// gfpIsZero returns 1 in AX if [acc4..acc7] represents zero and zero
// otherwise. It writes to [acc4..acc7], t0 and t1.
TEXT gfpIsZero(SB),NOSPLIT,$0
	// AX contains a flag that is set if the input is zero.
	XORQ AX, AX
	MOVQ $1, t1

	// Check whether [acc4..acc7] are all zero.
	MOVQ acc4, t0
	ORQ acc5, t0
	ORQ acc6, t0
	ORQ acc7, t0

	// Set the zero flag if so. (CMOV of a constant to a register doesn't
	// appear to be supported in Go. Thus t1 = 1.)
	CMOVQEQ t1, AX

	// XOR [acc4..acc7] with P and compare with zero again.
	XORQ ·p2+0(SB), acc4
	XORQ ·p2+8(SB), acc5
	XORQ ·p2+16(SB), acc6
	XORQ ·p2+24(SB), acc7
	ORQ acc5, acc4
	ORQ acc6, acc4
	ORQ acc7, acc4

	// Set the zero flag if so.
	CMOVQEQ t1, AX
	RET

/* ---------------------------------------*/
/*
#define x1in(off) (32*0 + off)(SP)
#define y1in(off) (32*1 + off)(SP)
#define z1in(off) (32*2 + off)(SP)
#define x2in(off) (32*3 + off)(SP)
#define y2in(off) (32*4 + off)(SP)
#define z2in(off) (32*5 + off)(SP)

#define xout(off) (32*6 + off)(SP)
#define yout(off) (32*7 + off)(SP)
#define zout(off) (32*8 + off)(SP)

#define u1(off)    (32*9 + off)(SP)
#define u2(off)    (32*10 + off)(SP)
#define s1(off)    (32*11 + off)(SP)
#define s2(off)    (32*12 + off)(SP)
#define z1sqr(off) (32*13 + off)(SP)
#define z2sqr(off) (32*14 + off)(SP)
#define h(off)     (32*15 + off)(SP)
#define r(off)     (32*16 + off)(SP)
#define hsqr(off)  (32*17 + off)(SP)
#define rsqr(off)  (32*18 + off)(SP)
#define hcub(off)  (32*19 + off)(SP)
#define rptr       (32*20)(SP)
#define points_eq  (32*20+8)(SP)

#define curvePointAddInline \
	\// Begin point add
	LDacc (z2in)                 \
	CALL gfpSqrInternal(SB)	 \// z2ˆ2
	ST (z2sqr)                   \
	LDt (z2in)                   \
	CALL gfpMulInternal(SB)	 \// z2ˆ3
	LDt (y1in)                   \
	CALL gfpMulInternal(SB)	 \// s1 = z2ˆ3*y1
	ST (s1)                      \
	\
	LDacc (z1in)                 \ 
	CALL gfpSqrInternal(SB)	 \// z1ˆ2
	ST (z1sqr)                   \
	LDt (z1in)                   \
	CALL gfpMulInternal(SB)	 \// z1ˆ3
	LDt (y2in)                   \
	CALL gfpMulInternal(SB)	 \// s2 = z1ˆ3*y2
	ST (s2)                      \ 
	\
	LDt (s1)                     \
	CALL gfpSubInternal(SB)	 \// r = s2 - s1
	ST (r)                       \
	CALL gfpIsZero(SB)       \
	MOVQ AX, points_eq           \
	\
	LDacc (z2sqr)                \
	LDt (x1in)                   \
	CALL gfpMulInternal(SB)	 \// u1 = x1 * z2ˆ2
	ST (u1)                      \
	LDacc (z1sqr)                \
	LDt (x2in)                   \ 
	CALL gfpMulInternal(SB)	 \// u2 = x2 * z1ˆ2
	ST (u2)                      \
	\
	LDt (u1)                     \ 
	CALL gfpSubInternal(SB)	 \// h = u2 - u1
	ST (h)                       \
	CALL gfpIsZero(SB)       \
	ANDQ points_eq, AX           \
	MOVQ AX, points_eq           \
	\
	LDacc (r)                    \
	CALL gfpSqrInternal(SB)	 \// rsqr = rˆ2
	ST (rsqr)                    \
	\
	LDacc (h)                    \
	CALL gfpSqrInternal(SB)	 \// hsqr = hˆ2
	ST (hsqr)                    \
	\
	LDt (h)                      \
	CALL gfpMulInternal(SB)	 \// hcub = hˆ3
	ST (hcub)                    \
	\
	LDt (s1)                     \
	CALL gfpMulInternal(SB)  \
	ST (s2)                      \
	\
	LDacc (z1in)                 \
	LDt (z2in)                   \
	CALL gfpMulInternal(SB)	 \// z1 * z2
	LDt (h)                      \
	CALL gfpMulInternal(SB)	 \// z1 * z2 * h
	ST (zout)                    \
	\
	LDacc (hsqr)                 \
	LDt (u1)                     \
	CALL gfpMulInternal(SB)	 \// hˆ2 * u1
	ST (u2)                      \
	\
	gfpMulBy2Inline	         \// u1 * hˆ2 * 2, inline
	LDacc (rsqr)                 \
	CALL gfpSubInternal(SB)	 \// rˆ2 - u1 * hˆ2 * 2
	\
	LDt (hcub)                   \
	CALL gfpSubInternal(SB)  \
	ST (xout)                    \
	\
	MOVQ acc4, t0                \
	MOVQ acc5, t1                \
	MOVQ acc6, t2                \
	MOVQ acc7, t3                \
	LDacc (u2)                   \
	CALL gfpSubInternal(SB)  \
	\
	LDt (r)                      \
	CALL gfpMulInternal(SB)  \
	\
	LDt (s2)                     \
	CALL gfpSubInternal(SB)  \
	ST (yout)                    \

// func curvePointAdd(c, a, b *curvePoint) int
TEXT ·curvePointAdd(SB),0,$680-32
	// Move input to stack in order to free registers
	MOVQ res+0(FP), AX
	MOVQ in1+8(FP), BX
	MOVQ in2+16(FP), CX

	MOVOU (16*0)(BX), X0
	MOVOU (16*1)(BX), X1
	MOVOU (16*2)(BX), X2
	MOVOU (16*3)(BX), X3
	MOVOU (16*4)(BX), X4
	MOVOU (16*5)(BX), X5

	MOVOU X0, x1in(16*0)
	MOVOU X1, x1in(16*1)
	MOVOU X2, y1in(16*0)
	MOVOU X3, y1in(16*1)
	MOVOU X4, z1in(16*0)
	MOVOU X5, z1in(16*1)

	MOVOU (16*0)(CX), X0
	MOVOU (16*1)(CX), X1
	MOVOU (16*2)(CX), X2
	MOVOU (16*3)(CX), X3
	MOVOU (16*4)(CX), X4
	MOVOU (16*5)(CX), X5

	MOVOU X0, x2in(16*0)
	MOVOU X1, x2in(16*1)
	MOVOU X2, y2in(16*0)
	MOVOU X3, y2in(16*1)
	MOVOU X4, z2in(16*0)
	MOVOU X5, z2in(16*1)
	// Store pointer to result
	MOVQ AX, rptr

	curvePointAddInline

	MOVOU xout(16*0), X0
	MOVOU xout(16*1), X1
	MOVOU yout(16*0), X2
	MOVOU yout(16*1), X3
	MOVOU zout(16*0), X4
	MOVOU zout(16*1), X5
	// Finally output the result
	MOVQ rptr, AX
	MOVQ $0, rptr
	MOVOU X0, (16*0)(AX)
	MOVOU X1, (16*1)(AX)
	MOVOU X2, (16*2)(AX)
	MOVOU X3, (16*3)(AX)
	MOVOU X4, (16*4)(AX)
	MOVOU X5, (16*5)(AX)

	MOVQ points_eq, AX
	MOVQ AX, ret+24(FP)

	RET
*/
