//go:build amd64 && !purego
// +build amd64,!purego

#include "textflag.h"

#define res_ptr DI
#define x_ptr SI
#define y_ptr CX

#define acc0 R8
#define acc1 R9
#define acc2 R10
#define acc3 R11
#define acc4 R12
#define acc5 R13
#define t0 R14
#define t1 R15

#define storeBlock(a0,a1,a2,a3, r) \
	MOVQ a0,  0+r \
	MOVQ a1,  8+r \
	MOVQ a2, 16+r \
	MOVQ a3, 24+r

#define loadBlock(r, a0,a1,a2,a3) \
	MOVQ  0+r, a0 \
	MOVQ  8+r, a1 \
	MOVQ 16+r, a2 \
	MOVQ 24+r, a3

#define gfpCarry(a0,a1,a2,a3, b0,b1,b2,b3,b4) \
	\ // b = a-p
	MOVQ a0, b0 \
	MOVQ a1, b1 \
	MOVQ a2, b2 \
	MOVQ a3, b3 \
	\
	SUBQ ·p2+0(SB), b0 \
	SBBQ ·p2+8(SB), b1 \
	SBBQ ·p2+16(SB), b2 \
	SBBQ ·p2+24(SB), b3 \
	SBBQ $0, b4 \
	\
	\ // if b is negative then return a
	\ // else return b
	CMOVQCC b0, a0 \
	CMOVQCC b1, a1 \
	CMOVQCC b2, a2 \
	CMOVQCC b3, a3

#define gfpCarryWithoutCarry(a0,a1,a2,a3, b0,b1,b2,b3) \
	\ // b = a-p
	MOVQ a0, b0 \
	MOVQ a1, b1 \
	MOVQ a2, b2 \
	MOVQ a3, b3 \
	\
	SUBQ ·p2+0(SB), b0 \
	SBBQ ·p2+8(SB), b1 \
	SBBQ ·p2+16(SB), b2 \
	SBBQ ·p2+24(SB), b3 \
	\
	\ // if b is negative then return a
	\ // else return b
	CMOVQCC b0, a0 \
	CMOVQCC b1, a1 \
	CMOVQCC b2, a2 \
	CMOVQCC b3, a3

TEXT ·gfpNeg(SB),0,$0-16
	MOVQ ·p2+0(SB), R8
	MOVQ ·p2+8(SB), R9
	MOVQ ·p2+16(SB), R10
	MOVQ ·p2+24(SB), R11

	MOVQ a+8(FP), DI
	SUBQ 0(DI), R8
	SBBQ 8(DI), R9
	SBBQ 16(DI), R10
	SBBQ 24(DI), R11

	gfpCarryWithoutCarry(R8,R9,R10,R11, R12,R13,R14,CX)

	MOVQ c+0(FP), DI
	storeBlock(R8,R9,R10,R11, 0(DI))
	RET

TEXT ·gfpAdd(SB),0,$0-24
	MOVQ a+8(FP), DI
	MOVQ b+16(FP), SI

	loadBlock(0(DI), R8,R9,R10,R11)
	MOVQ $0, R12

	ADDQ  0(SI), R8
	ADCQ  8(SI), R9
	ADCQ 16(SI), R10
	ADCQ 24(SI), R11
	ADCQ $0, R12

	gfpCarry(R8,R9,R10,R11, R13,R14,CX,AX,R12)

	MOVQ c+0(FP), DI
	storeBlock(R8,R9,R10,R11, 0(DI))
	RET

TEXT ·gfpDouble(SB),0,$0-16
	MOVQ a+0(FP), DI
	MOVQ b+8(FP), SI

	loadBlock(0(SI), R8,R9,R10,R11)
	XORQ R12, R12

	ADDQ  R8, R8
	ADCQ  R9, R9
	ADCQ  R10, R10
	ADCQ  R11, R11
	ADCQ  $0, R12

	gfpCarry(R8,R9,R10,R11, R13,R14,CX,AX,R12)

	storeBlock(R8,R9,R10,R11, 0(DI))
	RET

TEXT ·gfpTriple(SB),0,$0-16
	MOVQ a+0(FP), DI
	MOVQ b+8(FP), SI

	loadBlock(0(SI), R8,R9,R10,R11)
	XORQ R12, R12

	ADDQ  R8, R8
	ADCQ  R9, R9
	ADCQ  R10, R10
	ADCQ  R11, R11
	ADCQ $0, R12

	gfpCarry(R8,R9,R10,R11, R13,R14,CX,AX,R12)

	XORQ R12, R12
	ADDQ  0(SI), R8
	ADCQ  8(SI), R9
	ADCQ 16(SI), R10
	ADCQ 24(SI), R11
	ADCQ $0, R12

	gfpCarry(R8,R9,R10,R11, R13,R14,CX,AX,R12)

	storeBlock(R8,R9,R10,R11, 0(DI))
	RET

TEXT ·gfpSub(SB),0,$0-24
	MOVQ a+8(FP), DI
	MOVQ b+16(FP), SI

	loadBlock(0(DI), R8,R9,R10,R11)

	MOVQ ·p2+0(SB), R12
	MOVQ ·p2+8(SB), R13
	MOVQ ·p2+16(SB), R14
	MOVQ ·p2+24(SB), CX
	MOVQ $0, AX

	SUBQ  0(SI), R8
	SBBQ  8(SI), R9
	SBBQ 16(SI), R10
	SBBQ 24(SI), R11

	CMOVQCC AX, R12
	CMOVQCC AX, R13
	CMOVQCC AX, R14
	CMOVQCC AX, CX

	ADDQ R12, R8
	ADCQ R13, R9
	ADCQ R14, R10
	ADCQ CX, R11

	MOVQ c+0(FP), DI
	storeBlock(R8,R9,R10,R11, 0(DI))
	RET

TEXT ·gfpMul(SB),0,$0-24
	MOVQ in1+8(FP), x_ptr
	MOVQ in2+16(FP), y_ptr
	
	CMPB ·supportADX(SB), $0
	JE   noAdxMul

	XORQ acc5, acc5
	XORQ res_ptr, res_ptr
	// x * y[0]
	MOVQ (8*0)(y_ptr), DX
	MULXQ (8*0)(x_ptr), acc0, acc1 

	MULXQ (8*1)(x_ptr), AX, acc2
	ADCXQ AX, acc1

	MULXQ (8*2)(x_ptr), AX, acc3
	ADCXQ AX, acc2

	MULXQ (8*3)(x_ptr), AX, acc4
	ADCXQ AX, acc3
	ADCXQ acc5, acc4

	// First reduction step
	MOVQ acc0, DX
	MULXQ ·np+0x00(SB), DX, AX

	MULXQ ·p2+0x00(SB), AX, t0
	ADOXQ AX, acc0

	MULXQ ·p2+0x08(SB), AX, t1
	ADCXQ t0, AX
	ADOXQ AX, acc1

	MULXQ ·p2+0x10(SB), AX, t0
	ADCXQ t1, AX
	ADOXQ AX, acc2

	MULXQ ·p2+0x18(SB), AX, t1
	ADCXQ t0, AX
	ADOXQ AX, acc3

	ADCXQ res_ptr, t1
	ADOXQ t1, acc4
	ADOXQ res_ptr, acc5
	XORQ acc0, acc0

	// x * y[1]
	MOVQ (8*1)(y_ptr), DX
	MULXQ (8*0)(x_ptr), AX, t0
	ADOXQ AX, acc1

	MULXQ (8*1)(x_ptr), AX, t1 
	ADCXQ t0, AX
	ADOXQ AX, acc2

	MULXQ (8*2)(x_ptr), AX, t0
	ADCXQ t1, AX
	ADOXQ AX, acc3

	MULXQ (8*3)(x_ptr), AX, t1
	ADCXQ t0, AX
	ADOXQ AX, acc4

	ADCXQ acc0, t1
	ADOXQ t1, acc5
	ADOXQ res_ptr, acc0

	// Second reduction step
	MOVQ acc1, DX
	MULXQ ·np+0x00(SB), DX, AX

	MULXQ ·p2+0x00(SB), AX, t0
	ADOXQ AX, acc1

	MULXQ ·p2+0x08(SB), AX, t1
	ADCXQ t0, AX
	ADOXQ AX, acc2

	MULXQ ·p2+0x10(SB), AX, t0
	ADCXQ t1, AX
	ADOXQ AX, acc3

	MULXQ ·p2+0x18(SB), AX, t1
	ADCXQ t0, AX
	ADOXQ AX, acc4

	ADCXQ res_ptr, t1
	ADOXQ t1, acc5
	ADOXQ res_ptr, acc0
	XORQ acc1, acc1

	// x * y[2]
	MOVQ (8*2)(y_ptr), DX
	MULXQ (8*0)(x_ptr), AX, t0
	ADOXQ AX, acc2

	MULXQ (8*1)(x_ptr), AX, t1 
	ADCXQ t0, AX
	ADOXQ AX, acc3

	MULXQ (8*2)(x_ptr), AX, t0
	ADCXQ t1, AX
	ADOXQ AX, acc4

	MULXQ (8*3)(x_ptr), AX, t1
	ADCXQ t0, AX
	ADOXQ AX, acc5

	ADCXQ res_ptr, t1
	ADOXQ t1, acc0
	ADOXQ res_ptr, acc1

	// Third reduction step
	MOVQ acc2, DX
	MULXQ ·np+0x00(SB), DX, AX

	MULXQ ·p2+0x00(SB), AX, t0
	ADOXQ AX, acc2

	MULXQ ·p2+0x08(SB), AX, t1
	ADCXQ t0, AX
	ADOXQ AX, acc3

	MULXQ ·p2+0x10(SB), AX, t0
	ADCXQ t1, AX
	ADOXQ AX, acc4

	MULXQ ·p2+0x18(SB), AX, t1
	ADCXQ t0, AX
	ADOXQ AX, acc5

	ADCXQ res_ptr, t1
	ADOXQ t1, acc0
	ADOXQ res_ptr, acc1
	XORQ acc2, acc2

	// x * y[3]
	MOVQ (8*3)(y_ptr), DX
	MULXQ (8*0)(x_ptr), AX, t0
	ADOXQ AX, acc3

	MULXQ (8*1)(x_ptr), AX, t1 
	ADCXQ t0, AX
	ADOXQ AX, acc4

	MULXQ (8*2)(x_ptr), AX, t0 
	ADCXQ t1, AX
	ADOXQ AX, acc5

	MULXQ (8*3)(x_ptr), AX, t1
	ADCXQ t0, AX
	ADOXQ AX, acc0

	ADCXQ res_ptr, t1
	ADOXQ t1, acc1
	ADOXQ res_ptr, acc2

	// Last reduction step
	MOVQ acc3, DX
	MULXQ ·np+0x00(SB), DX, AX

	MULXQ ·p2+0x00(SB), AX, t0
	ADOXQ AX, acc3

	MULXQ ·p2+0x08(SB), AX, t1
	ADCXQ t0, AX
	ADOXQ AX, acc4

	MULXQ ·p2+0x10(SB), AX, t0
	ADCXQ t1, AX
	ADOXQ AX, acc5

	MULXQ ·p2+0x18(SB), AX, t1
	ADCXQ t0, AX
	ADOXQ AX, acc0

	ADCXQ res_ptr, t1
	ADOXQ t1, acc1
	ADOXQ res_ptr, acc2
	// Copy result [255:0]
	gfpCarry(acc4,acc5,acc0,acc1, x_ptr,acc3,t0,t1,acc2)
	MOVQ res+0(FP), res_ptr
	storeBlock(acc4,acc5,acc0,acc1, 0(res_ptr))
	RET

noAdxMul:
	// x * y[0]
	MOVQ (8*0)(y_ptr), t0

	MOVQ (8*0)(x_ptr), AX
	MULQ t0
	MOVQ AX, acc0
	MOVQ DX, acc1

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, acc2

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, acc3

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, acc4
	XORQ acc5, acc5
	// First reduction step
	MOVQ acc0, AX
	MULQ ·np+0x00(SB)
	MOVQ AX, t0

	MOVQ ·p2+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc0
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc1
	ADCQ $0, DX
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ DX, acc4
	ADCQ $0, acc5
	// x * y[1]
	MOVQ (8*1)(y_ptr), t0

	MOVQ (8*0)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ DX, acc5
	ADCQ $0, acc0
	// Second reduction step
	MOVQ acc1, AX
	MULQ ·np+0x00(SB)
	MOVQ AX, t0

	MOVQ ·p2+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ DX, acc5
	ADCQ $0, acc0
	// x * y[2]
	MOVQ (8*2)(y_ptr), t0

	MOVQ (8*0)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc5
	ADCQ $0, DX
	ADDQ AX, acc5
	ADCQ DX, acc0
	ADCQ $0, acc1
	// Third reduction step
	MOVQ acc2, AX
	MULQ ·np+0x00(SB)
	MOVQ AX, t0

	MOVQ ·p2+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc5
	ADCQ $0, DX
	ADDQ AX, acc5
	ADCQ DX, acc0
	ADCQ $0, acc1
	// x * y[3]
	MOVQ (8*3)(y_ptr), t0

	MOVQ (8*0)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc5
	ADCQ $0, DX
	ADDQ AX, acc5
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc0
	ADCQ $0, DX
	ADDQ AX, acc0
	ADCQ DX, acc1
	ADCQ $0, acc2
	// Last reduction step
	MOVQ acc3, AX
	MULQ ·np+0x00(SB)
	MOVQ AX, t0

	MOVQ ·p2+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc5
	ADCQ $0, DX
	ADDQ AX, acc5
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc0
	ADCQ $0, DX
	ADDQ AX, acc0
	ADCQ DX, acc1
	ADCQ $0, acc2
	// Copy result [255:0]
	gfpCarry(acc4,acc5,acc0,acc1, x_ptr,acc3,t0,t1,acc2)
	MOVQ res+0(FP), res_ptr
	storeBlock(acc4,acc5,acc0,acc1, 0(res_ptr))

	RET

// func gfpSqr(res, in *gfP, n int)
TEXT ·gfpSqr(SB),NOSPLIT,$0
	MOVQ res+0(FP), res_ptr
	MOVQ in+8(FP), x_ptr
	MOVQ n+16(FP), BX

	CMPB ·supportADX(SB), $0
	JE   gfpSqrLoop

gfpSqrLoopAdx:
	XORQ acc0, acc0
	XORQ y_ptr, y_ptr
	// y[1:] * y[0]
	MOVQ (8*0)(x_ptr), DX
	MULXQ (8*1)(x_ptr), acc1, acc2 

	MULXQ (8*2)(x_ptr), AX, acc3
	ADOXQ AX, acc2

	MULXQ (8*3)(x_ptr), AX, acc4
	ADOXQ AX, acc3
	ADOXQ y_ptr, acc4

	// y[2:] * y[1]
	MOVQ (8*1)(x_ptr), DX
	MULXQ (8*2)(x_ptr), AX, t1
	ADOXQ AX, acc3

	MULXQ (8*3)(x_ptr), AX, acc5
	ADCXQ t1, AX
	ADOXQ AX, acc4
	ADCXQ y_ptr, acc5

	// y[3] * y[2]
	MOVQ (8*2)(x_ptr), DX
	MULXQ (8*3)(x_ptr), AX, y_ptr 
	ADOXQ AX, acc5
	ADOXQ acc0, y_ptr

	XORQ t1, t1
	// *2
	ADOXQ acc1, acc1
	ADOXQ acc2, acc2
	ADOXQ acc3, acc3
	ADOXQ acc4, acc4
	ADOXQ acc5, acc5
	ADOXQ y_ptr, y_ptr
	ADOXQ acc0, t1
	
	// Missing products
	MOVQ (8*0)(x_ptr), DX
	MULXQ DX, acc0, t0
	ADCXQ t0, acc1

	MOVQ (8*1)(x_ptr), DX
	MULXQ DX, AX, t0
	ADCXQ AX, acc2
	ADCXQ t0, acc3

	MOVQ (8*2)(x_ptr), DX
	MULXQ DX, AX, t0 
	ADCXQ AX, acc4
	ADCXQ t0, acc5

	MOVQ (8*3)(x_ptr), DX
	MULXQ DX, AX, x_ptr
	ADCXQ AX, y_ptr
	ADCXQ t1, x_ptr

	// First reduction step
	MOVQ acc0, DX
	MULXQ ·np+0x00(SB), DX, AX

	MULXQ ·p2+0x00(SB), AX, t0
	ADOXQ AX, acc0               // (carry1, acc0) = acc0 + t0 * ord0

	MULXQ ·p2+0x08(SB), AX, t1
	ADCXQ t0, AX
	ADOXQ AX, acc1

	MULXQ ·p2+0x10(SB), AX, t0
	ADCXQ t1, AX
	ADOXQ AX, acc2
	
	MULXQ ·p2+0x18(SB), AX, acc0
	ADCXQ t0, AX
	ADOXQ AX, acc3
	MOVQ $0, t0
	ADCXQ t0, acc0
	ADOXQ t0, acc0

	// Second reduction step
	MOVQ acc1, DX
	MULXQ ·np+0x00(SB), DX, AX

	MULXQ ·p2+0x00(SB), AX, t0
	ADOXQ AX, acc1

	MULXQ ·p2+0x08(SB), AX, t1
	ADCXQ t0, AX
	ADOXQ AX, acc2

	MULXQ ·p2+0x10(SB), AX, t0
	ADCXQ t1, AX
	ADOXQ AX, acc3

	MULXQ ·p2+0x18(SB), AX, acc1
	ADCXQ t0, AX
	ADOXQ AX, acc0
	MOVQ $0, t0
	ADCXQ t0, acc1
	ADOXQ t0, acc1

	// Third reduction step
	MOVQ acc2, DX
	MULXQ ·np+0x00(SB), DX, AX

	MULXQ ·p2+0x00(SB), AX, t0
	ADOXQ AX, acc2

	MULXQ ·p2+0x08(SB), AX, t1
	ADCXQ t0, AX
	ADOXQ AX, acc3

	MULXQ ·p2+0x10(SB), AX, t0
	ADCXQ t1, AX
	ADOXQ AX, acc0

	MULXQ ·p2+0x18(SB), AX, acc2
	ADCXQ t0, AX
	ADOXQ AX, acc1
	MOVQ $0, t0
	ADCXQ t0, acc2
	ADOXQ t0, acc2

	// Last reduction step
	MOVQ acc3, DX
	MULXQ ·np+0x00(SB), DX, AX

	MULXQ ·p2+0x00(SB), AX, t0
	ADOXQ AX, acc3

	MULXQ ·p2+0x08(SB), AX, t1
	ADCXQ t0, AX
	ADOXQ AX, acc0

	MULXQ ·p2+0x10(SB), AX, t0
	ADCXQ t1, AX
	ADOXQ AX, acc1

	MULXQ ·p2+0x18(SB), AX, acc3
	ADCXQ t0, AX
	ADOXQ AX, acc2
	MOVQ $0, t0
	ADCXQ t0, acc3
	ADOXQ t0, acc3

	XORQ t1, t1
	// Add bits [511:256] of the sqr result
	ADCXQ acc4, acc0
	ADCXQ acc5, acc1
	ADCXQ y_ptr, acc2
	ADCXQ x_ptr, acc3
	ADCXQ t1, t0
	
	gfpCarry(acc0,acc1,acc2,acc3, acc4,acc5,y_ptr,t1,t0)
	storeBlock(acc0,acc1,acc2,acc3, 0(res_ptr))

	MOVQ res_ptr, x_ptr
	DECQ BX
	JNE gfpSqrLoopAdx

	RET

gfpSqrLoop:

	// y[1:] * y[0]
	MOVQ (8*0)(x_ptr), t0

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	MOVQ AX, acc1
	MOVQ DX, acc2

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, acc3

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, acc4
	// y[2:] * y[1]
	MOVQ (8*1)(x_ptr), t0

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, acc5
	// y[3] * y[2]
	MOVQ (8*2)(x_ptr), t0

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc5
	ADCQ $0, DX
	MOVQ DX, y_ptr
	XORQ t1, t1
	// *2
	ADDQ acc1, acc1
	ADCQ acc2, acc2
	ADCQ acc3, acc3
	ADCQ acc4, acc4
	ADCQ acc5, acc5
	ADCQ y_ptr, y_ptr
	ADCQ $0, t1
	// Missing products
	MOVQ (8*0)(x_ptr), AX
	MULQ AX
	MOVQ AX, acc0
	MOVQ DX, t0

	MOVQ (8*1)(x_ptr), AX
	MULQ AX
	ADDQ t0, acc1
	ADCQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t0

	MOVQ (8*2)(x_ptr), AX
	MULQ AX
	ADDQ t0, acc3
	ADCQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t0

	MOVQ (8*3)(x_ptr), AX
	MULQ AX
	ADDQ t0, acc5
	ADCQ AX, y_ptr
	ADCQ DX, t1
	MOVQ t1, x_ptr
	// T = [acc0, acc1, acc2, acc3, acc4, acc5, y_ptr, x_ptr]
	// First reduction step
	MOVQ acc0, AX
	MULQ ·np+0x00(SB)
	MOVQ AX, t0     // Y

	// Calculate next T = T+Y*P
	MOVQ ·p2+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc0   // acc0 is free now
	ADCQ $0, DX
	MOVQ DX, t1     // carry
	XORQ acc0, acc0

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc1
	ADCQ $0, DX
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ DX, acc0

	// Second reduction step
	MOVQ acc1, AX
	MULQ ·np+0x00(SB)
	MOVQ AX, t0     // Y

	// Calculate next T = T+Y*P
	MOVQ ·p2+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc1   // acc1 is free now
	ADCQ $0, DX
	MOVQ DX, t1     // carry
	XORQ acc1, acc1

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc0
	ADCQ $0, DX
	ADDQ AX, acc0
	ADCQ DX, acc1

	// Third reduction step
	MOVQ acc2, AX
	MULQ ·np+0x00(SB)
	MOVQ AX, t0     // Y

	// Calculate next T = T+Y*P
	MOVQ ·p2+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc2   // acc2 is free now
	ADCQ $0, DX
	MOVQ DX, t1     // carry
	XORQ acc2, acc2

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc0
	ADCQ $0, DX
	ADDQ AX, acc0
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc1
	ADCQ $0, DX
	ADDQ AX, acc1
	ADCQ DX, acc2

	// Last reduction step
	MOVQ acc3, AX
	MULQ ·np+0x00(SB)
	MOVQ AX, t0     // Y

	// Calculate next T = T+Y*P
	MOVQ ·p2+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc3   // acc3 is free now
	ADCQ $0, DX
	MOVQ DX, t1     // carry
	XORQ acc3, acc3

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc0
	ADCQ $0, DX
	ADDQ AX, acc0
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc1
	ADCQ $0, DX
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ DX, acc3

	XORQ t0, t0
	// Add bits [511:256] of the sqr result
	ADDQ acc4, acc0
	ADCQ acc5, acc1
	ADCQ y_ptr, acc2
	ADCQ x_ptr, acc3
	ADCQ $0, t0
	
	gfpCarry(acc0,acc1,acc2,acc3, acc4,acc5,y_ptr,t1,t0)
	storeBlock(acc0,acc1,acc2,acc3, 0(res_ptr))
	MOVQ res_ptr, x_ptr
	DECQ BX
	JNE gfpSqrLoop

	RET

/* ---------------------------------------*/
// func gfpFromMont(res, in *gfP)
TEXT ·gfpFromMont(SB),NOSPLIT,$0
	MOVQ res+0(FP), res_ptr
	MOVQ in+8(FP), x_ptr

	MOVQ (8*0)(x_ptr), acc0
	MOVQ (8*1)(x_ptr), acc1
	MOVQ (8*2)(x_ptr), acc2
	MOVQ (8*3)(x_ptr), acc3
	XORQ acc4, acc4

	// Only reduce, no multiplications are needed
	// First reduction step
	MOVQ acc0, AX
	MULQ ·np+0x00(SB)
	MOVQ AX, t0     // Y

	// Calculate next T = T+Y*P
	MOVQ ·p2+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc0   // acc0 is free now
	ADCQ $0, DX
	MOVQ DX, t1     // carry
	XORQ acc0, acc0

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc1
	ADCQ $0, DX
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ DX, acc4
	XORQ acc5, acc5

	// Second reduction step
	MOVQ acc1, AX
	MULQ ·np+0x00(SB)
	MOVQ AX, t0     // Y

	// Calculate next T = T+Y*P
	MOVQ ·p2+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc1   // acc1 is free now
	ADCQ $0, DX
	MOVQ DX, t1     // carry
	XORQ acc1, acc1

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ DX, acc5

	// Third reduction step
	MOVQ acc2, AX
	MULQ ·np+0x00(SB)
	MOVQ AX, t0     // Y

	// Calculate next T = T+Y*P
	MOVQ ·p2+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc2   // acc2 is free now
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc5
	ADCQ $0, DX
	ADDQ AX, acc5
	ADCQ DX, acc0

	// Last reduction step
	MOVQ acc3, AX
	MULQ ·np+0x00(SB)
	MOVQ AX, t0     // Y

	// Calculate next T = T+Y*P
	MOVQ ·p2+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc3   // acc3 is free now
	ADCQ $0, DX
	MOVQ DX, t1     // carry
	XORQ acc3, acc3

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc5
	ADCQ $0, DX
	ADDQ AX, acc5
	ADCQ $0, DX
	MOVQ DX, t1     // carry

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc0
	ADCQ $0, DX
	ADDQ AX, acc0
	ADCQ DX, acc1

	gfpCarryWithoutCarry(acc4, acc5, acc0, acc1, x_ptr, acc3, t0, t1)
	storeBlock(acc4,acc5,acc0,acc1, 0(res_ptr))
	RET

/* ---------------------------------------*/
// func gfpUnmarshal(res *gfP, in *[32]byte)
TEXT ·gfpUnmarshal(SB),NOSPLIT,$0
	JMP ·gfpMarshal(SB)

/* ---------------------------------------*/
// func gfpMarshal(res *[32]byte, in *gfP)
TEXT ·gfpMarshal(SB),NOSPLIT,$0
	MOVQ res+0(FP), res_ptr
	MOVQ in+8(FP), x_ptr

	MOVQ (8*0)(x_ptr), acc0
	MOVQ (8*1)(x_ptr), acc1
	MOVQ (8*2)(x_ptr), acc2
	MOVQ (8*3)(x_ptr), acc3

	BSWAPQ acc0
	BSWAPQ acc1
	BSWAPQ acc2
	BSWAPQ acc3

	MOVQ acc3, (8*0)(res_ptr)
	MOVQ acc2, (8*1)(res_ptr)
	MOVQ acc1, (8*2)(res_ptr)
	MOVQ acc0, (8*3)(res_ptr)

	RET
