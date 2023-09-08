//go:build amd64 && !purego
// +build amd64,!purego

#include "textflag.h"

#include "gfp_macros_amd64.s"

TEXT ·gfpNeg(SB),NOSPLIT,$0-16
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

TEXT ·gfpAdd(SB),NOSPLIT,$0-24
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

TEXT ·gfpDouble(SB),NOSPLIT,$0-16
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

TEXT ·gfpTriple(SB),NOSPLIT,$0-16
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

TEXT ·gfpSub(SB),NOSPLIT,$0-24
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

TEXT ·gfpMul(SB),NOSPLIT,$0-24
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

	MULXQ ·p2+0x08(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc1

	MULXQ ·p2+0x10(SB), AX, t0
	ADCXQ BX, AX
	ADOXQ AX, acc2

	MULXQ ·p2+0x18(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc3

	ADCXQ res_ptr, BX
	ADOXQ BX, acc4
	ADOXQ res_ptr, acc5
	XORQ acc0, acc0

	// x * y[1]
	MOVQ (8*1)(y_ptr), DX
	MULXQ (8*0)(x_ptr), AX, t0
	ADOXQ AX, acc1

	MULXQ (8*1)(x_ptr), AX, BX 
	ADCXQ t0, AX
	ADOXQ AX, acc2

	MULXQ (8*2)(x_ptr), AX, t0
	ADCXQ BX, AX
	ADOXQ AX, acc3

	MULXQ (8*3)(x_ptr), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc4

	ADCXQ acc0, BX
	ADOXQ BX, acc5
	ADOXQ res_ptr, acc0

	// Second reduction step
	MOVQ acc1, DX
	MULXQ ·np+0x00(SB), DX, AX

	MULXQ ·p2+0x00(SB), AX, t0
	ADOXQ AX, acc1

	MULXQ ·p2+0x08(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc2

	MULXQ ·p2+0x10(SB), AX, t0
	ADCXQ BX, AX
	ADOXQ AX, acc3

	MULXQ ·p2+0x18(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc4

	ADCXQ res_ptr, BX
	ADOXQ BX, acc5
	ADOXQ res_ptr, acc0
	XORQ acc1, acc1

	// x * y[2]
	MOVQ (8*2)(y_ptr), DX
	MULXQ (8*0)(x_ptr), AX, t0
	ADOXQ AX, acc2

	MULXQ (8*1)(x_ptr), AX, BX 
	ADCXQ t0, AX
	ADOXQ AX, acc3

	MULXQ (8*2)(x_ptr), AX, t0
	ADCXQ BX, AX
	ADOXQ AX, acc4

	MULXQ (8*3)(x_ptr), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc5

	ADCXQ res_ptr, BX
	ADOXQ BX, acc0
	ADOXQ res_ptr, acc1

	// Third reduction step
	MOVQ acc2, DX
	MULXQ ·np+0x00(SB), DX, AX

	MULXQ ·p2+0x00(SB), AX, t0
	ADOXQ AX, acc2

	MULXQ ·p2+0x08(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc3

	MULXQ ·p2+0x10(SB), AX, t0
	ADCXQ BX, AX
	ADOXQ AX, acc4

	MULXQ ·p2+0x18(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc5

	ADCXQ res_ptr, BX
	ADOXQ BX, acc0
	ADOXQ res_ptr, acc1
	XORQ acc2, acc2

	// x * y[3]
	MOVQ (8*3)(y_ptr), DX
	MULXQ (8*0)(x_ptr), AX, t0
	ADOXQ AX, acc3

	MULXQ (8*1)(x_ptr), AX, BX 
	ADCXQ t0, AX
	ADOXQ AX, acc4

	MULXQ (8*2)(x_ptr), AX, t0 
	ADCXQ BX, AX
	ADOXQ AX, acc5

	MULXQ (8*3)(x_ptr), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc0

	ADCXQ res_ptr, BX
	ADOXQ BX, acc1
	ADOXQ res_ptr, acc2

	// Last reduction step
	MOVQ acc3, DX
	MULXQ ·np+0x00(SB), DX, AX

	MULXQ ·p2+0x00(SB), AX, t0
	ADOXQ AX, acc3

	MULXQ ·p2+0x08(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc4

	MULXQ ·p2+0x10(SB), AX, t0
	ADCXQ BX, AX
	ADOXQ AX, acc5

	MULXQ ·p2+0x18(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc0

	ADCXQ res_ptr, BX
	ADOXQ BX, acc1
	ADOXQ res_ptr, acc2
	// Copy result [255:0]
	gfpCarry(acc4,acc5,acc0,acc1, x_ptr,acc3,t0,BX,acc2)
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
	MOVQ DX, BX

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ BX, acc1
	ADCQ $0, DX
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ BX, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ BX, acc3
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
	MOVQ DX, BX

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	ADDQ BX, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ BX, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ BX, acc4
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
	MOVQ DX, BX

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ BX, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ BX, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ BX, acc4
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
	MOVQ DX, BX

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	ADDQ BX, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ BX, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ BX, acc5
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
	MOVQ DX, BX

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ BX, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ BX, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ BX, acc5
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
	MOVQ DX, BX

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	ADDQ BX, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ BX, acc5
	ADCQ $0, DX
	ADDQ AX, acc5
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ BX, acc0
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
	MOVQ DX, BX

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ BX, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ BX, acc5
	ADCQ $0, DX
	ADDQ AX, acc5
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ BX, acc0
	ADCQ $0, DX
	ADDQ AX, acc0
	ADCQ DX, acc1
	ADCQ $0, acc2
	// Copy result [255:0]
	gfpCarry(acc4,acc5,acc0,acc1, x_ptr,acc3,t0,BX,acc2)
	MOVQ res+0(FP), res_ptr
	storeBlock(acc4,acc5,acc0,acc1, 0(res_ptr))

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
	MOVQ DX, BX     // carry
	XORQ acc0, acc0

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ BX, acc1
	ADCQ $0, DX
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, BX     // carry

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ BX, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, BX     // carry

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ BX, acc3
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
	MOVQ DX, BX     // carry
	XORQ acc1, acc1

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ BX, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, BX     // carry

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ BX, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, BX     // carry

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ BX, acc4
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
	MOVQ DX, BX     // carry

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ BX, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, BX     // carry

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ BX, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, BX     // carry

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ BX, acc5
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
	MOVQ DX, BX     // carry
	XORQ acc3, acc3

	MOVQ ·p2+0x08(SB), AX
	MULQ t0
	ADDQ BX, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, BX     // carry

	MOVQ ·p2+0x10(SB), AX
	MULQ t0
	ADDQ BX, acc5
	ADCQ $0, DX
	ADDQ AX, acc5
	ADCQ $0, DX
	MOVQ DX, BX     // carry

	MOVQ ·p2+0x18(SB), AX
	MULQ t0
	ADDQ BX, acc0
	ADCQ $0, DX
	ADDQ AX, acc0
	ADCQ DX, acc1

	gfpCarryWithoutCarry(acc4, acc5, acc0, acc1, x_ptr, acc3, t0, BX)
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
