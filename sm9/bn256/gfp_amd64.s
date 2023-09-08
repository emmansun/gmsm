//go:build amd64 && !purego && !plugin
// +build amd64,!purego,!plugin

#include "textflag.h"
#include "gfp_macros_amd64.s"
#define t1 R15

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
