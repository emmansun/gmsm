//go:build !purego

#include "textflag.h"

#include "p256_macros_amd64.s"

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
/* ---------------------------------------*/
// func p256MovCond(res, a, b *SM2P256Point, cond int)
TEXT ·p256MovCond(SB),NOSPLIT,$0
	MOVQ res+0(FP), res_ptr
	MOVQ a+8(FP), x_ptr
	MOVQ b+16(FP), y_ptr
	MOVQ cond+24(FP), X12

	CMPB ·supportAVX2+0(SB), $0x01
	JEQ  move_avx2
	
	PXOR X13, X13
	PSHUFD $0, X12, X12
	PCMPEQL X13, X12

	MOVOU X12, X0
	MOVOU (16*0)(x_ptr), X6
	PANDN X6, X0

	MOVOU X12, X1
	MOVOU (16*1)(x_ptr), X7
	PANDN X7, X1

	MOVOU X12, X2
	MOVOU (16*2)(x_ptr), X8
	PANDN X8, X2

	MOVOU X12, X3
	MOVOU (16*3)(x_ptr), X9
	PANDN X9, X3

	MOVOU X12, X4
	MOVOU (16*4)(x_ptr), X10
	PANDN X10, X4

	MOVOU X12, X5
	MOVOU (16*5)(x_ptr), X11
	PANDN X11, X5

	MOVOU (16*0)(y_ptr), X6
	MOVOU (16*1)(y_ptr), X7
	MOVOU (16*2)(y_ptr), X8
	MOVOU (16*3)(y_ptr), X9
	MOVOU (16*4)(y_ptr), X10
	MOVOU (16*5)(y_ptr), X11

	PAND X12, X6
	PAND X12, X7
	PAND X12, X8
	PAND X12, X9
	PAND X12, X10
	PAND X12, X11

	PXOR X6, X0
	PXOR X7, X1
	PXOR X8, X2
	PXOR X9, X3
	PXOR X10, X4
	PXOR X11, X5

	MOVOU X0, (16*0)(res_ptr)
	MOVOU X1, (16*1)(res_ptr)
	MOVOU X2, (16*2)(res_ptr)
	MOVOU X3, (16*3)(res_ptr)
	MOVOU X4, (16*4)(res_ptr)
	MOVOU X5, (16*5)(res_ptr)

	RET

move_avx2:
	VPXOR Y13, Y13, Y13
	VPBROADCASTD X12, Y12
	VPCMPEQD Y13, Y12, Y12

	VPANDN (32*0)(x_ptr), Y12, Y0 
	VPANDN (32*1)(x_ptr), Y12, Y1
	VPANDN (32*2)(x_ptr), Y12, Y2

	VPAND (32*0)(y_ptr), Y12, Y3
	VPAND (32*1)(y_ptr), Y12, Y4
	VPAND (32*2)(y_ptr), Y12, Y5

	VPXOR Y3, Y0, Y0
	VPXOR Y4, Y1, Y1
	VPXOR Y5, Y2, Y2

	VMOVDQU Y0, (32*0)(res_ptr)
	VMOVDQU Y1, (32*1)(res_ptr)
	VMOVDQU Y2, (32*2)(res_ptr)

	VZEROUPPER
	RET

/* ---------------------------------------*/
// func p256NegCond(val *p256Element, cond int)
TEXT ·p256NegCond(SB),NOSPLIT,$0
	MOVQ val+0(FP), res_ptr
	MOVQ cond+8(FP), t0
	// acc = poly
	MOVQ $-1, acc0
	MOVQ p256p<>+0x08(SB), acc1
	MOVQ $-1, acc2
	MOVQ p256p<>+0x18(SB), acc3
	// Load the original value
	MOVQ (8*0)(res_ptr), acc4
	MOVQ (8*1)(res_ptr), x_ptr
	MOVQ (8*2)(res_ptr), y_ptr
	MOVQ (8*3)(res_ptr), acc5
	// Speculatively subtract
	SUBQ acc4, acc0
	SBBQ x_ptr, acc1
	SBBQ y_ptr, acc2
	SBBQ acc5, acc3
	// If condition is 0, keep original value
	TESTQ t0, t0
	CMOVQEQ acc4, acc0
	CMOVQEQ x_ptr, acc1
	CMOVQEQ y_ptr, acc2
	CMOVQEQ acc5, acc3
	// Store result
	MOVQ acc0, (8*0)(res_ptr)
	MOVQ acc1, (8*1)(res_ptr)
	MOVQ acc2, (8*2)(res_ptr)
	MOVQ acc3, (8*3)(res_ptr)

	RET

/* ---------------------------------------*/
// func p256Mul(res, in1, in2 *p256Element)
TEXT ·p256Mul(SB),NOSPLIT,$0
	MOVQ in1+8(FP), x_ptr
	MOVQ in2+16(FP), y_ptr

	CMPB ·supportBMI2+0(SB), $0x01
	JEQ  mulBMI2

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
	MOVQ acc0, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ AX, acc1
	SBBQ DX, acc2
	SBBQ AX, acc3
	MOVQ acc0, AX
	SBBQ DX, acc0

	ADDQ AX, acc1
	ADCQ $0, acc2
	ADCQ $0, acc3
	ADCQ acc0, acc4
	ADCQ $0, acc5
	
	XORQ acc0, acc0
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
	MOVQ acc1, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ AX, acc2
	SBBQ DX, acc3
	SBBQ AX, acc4
	MOVQ acc1, AX
	SBBQ DX, acc1

	ADDQ AX, acc2
	ADCQ $0, acc3
	ADCQ $0, acc4
	ADCQ acc1, acc5
	ADCQ $0, acc0
	
	XORQ acc1, acc1
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
	MOVQ acc2, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ AX, acc3
	SBBQ DX, acc4
	SBBQ AX, acc5
	MOVQ acc2, AX
	SBBQ DX, acc2

	ADDQ AX, acc3
	ADCQ $0, acc4
	ADCQ $0, acc5
	ADCQ acc2, acc0
	ADCQ $0, acc1
	
	XORQ acc2, acc2
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
	MOVQ acc3, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ AX, acc4
	SBBQ DX, acc5
	SBBQ AX, acc0
	MOVQ acc3, AX
	SBBQ DX, acc3

	ADDQ AX, acc4
	ADCQ $0, acc5
	ADCQ $0, acc0
	ADCQ acc3, acc1
	ADCQ $0, acc2
	
	MOVQ res+0(FP), res_ptr
	p256PrimReduce(acc4, acc5, acc0, acc1, acc2, x_ptr, acc3, t0, BX, res_ptr)
	RET

mulBMI2:
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
	MOVQ acc0, AX
	MOVQ acc0, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ AX, acc1
	SBBQ DX, acc2
	SBBQ AX, acc3
	MOVQ acc0, AX
	SBBQ DX, acc0

	ADOXQ AX, acc1
	ADOXQ res_ptr, acc2
	ADOXQ res_ptr, acc3
	ADOXQ acc0, acc4
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
	MOVQ acc1, AX
	MOVQ acc1, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ AX, acc2
	SBBQ DX, acc3
	SBBQ AX, acc4
	MOVQ acc1, AX
	SBBQ DX, acc1

	ADOXQ AX, acc2
	ADOXQ res_ptr, acc3
	ADOXQ res_ptr, acc4
	ADOXQ acc1, acc5
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
	MOVQ acc2, AX
	MOVQ acc2, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ AX, acc3
	SBBQ DX, acc4
	SBBQ AX, acc5
	MOVQ acc2, AX
	SBBQ DX, acc2

	ADOXQ AX, acc3
	ADOXQ res_ptr, acc4
	ADOXQ res_ptr, acc5
	ADOXQ acc2, acc0
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
	MOVQ acc3, AX
	MOVQ acc3, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ AX, acc4
	SBBQ DX, acc5
	SBBQ AX, acc0
	MOVQ acc3, AX
	SBBQ DX, acc3

	ADOXQ AX, acc4
	ADOXQ res_ptr, acc5
	ADOXQ res_ptr, acc0
	ADOXQ acc3, acc1
	ADOXQ res_ptr, acc2
	
	MOVQ res+0(FP), res_ptr
	p256PrimReduce(acc4, acc5, acc0, acc1, acc2, x_ptr, acc3, t0, BX, res_ptr)
	RET

/* ---------------------------------------*/
// func p256FromMont(res, in *p256Element)
TEXT ·p256FromMont(SB),NOSPLIT,$0
	MOVQ res+0(FP), res_ptr
	MOVQ in+8(FP), x_ptr

	MOVQ (8*0)(x_ptr), acc0
	MOVQ (8*1)(x_ptr), acc1
	MOVQ (8*2)(x_ptr), acc2
	MOVQ (8*3)(x_ptr), acc3
	XORQ acc4, acc4

	// Only reduce, no multiplications are needed
	// First stage
	MOVQ acc0, AX
	MOVQ acc0, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ AX, acc1
	SBBQ DX, acc2
	SBBQ AX, acc3
	MOVQ acc0, AX
	SBBQ DX, acc0

	ADDQ AX, acc1
	ADCQ $0, acc2
	ADCQ $0, acc3
	ADCQ acc0, acc4
	
	XORQ acc5, acc5
	// Second stage
	MOVQ acc1, AX
	MOVQ acc1, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ AX, acc2
	SBBQ DX, acc3
	SBBQ AX, acc4
	MOVQ acc1, AX
	SBBQ DX, acc5

	ADDQ AX, acc2
	ADCQ $0, acc3
	ADCQ $0, acc4
	ADCQ acc1, acc5
	
	XORQ acc0, acc0
	// Third stage
	MOVQ acc2, AX
	MOVQ acc2, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ AX, acc3
	SBBQ DX, acc4
	SBBQ AX, acc5
	MOVQ acc2, AX
	SBBQ DX, acc2

	ADDQ AX, acc3
	ADCQ $0, acc4
	ADCQ $0, acc5
	ADCQ acc2, acc0
	
	XORQ acc1, acc1
	// Last stage
	MOVQ acc3, AX
	MOVQ acc3, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ AX, acc4
	SBBQ DX, acc5
	SBBQ AX, acc0
	MOVQ acc3, AX
	SBBQ DX, acc3

	ADDQ AX, acc4
	ADCQ $0, acc5
	ADCQ $0, acc0
	ADCQ acc3, acc1
	
	MOVQ acc4, x_ptr
	MOVQ acc5, acc3
	MOVQ acc0, t0
	MOVQ acc1, BX

	SUBQ $-1, acc4
	SBBQ p256p<>+0x08(SB), acc5
	SBBQ $-1, acc0
	SBBQ p256p<>+0x018(SB), acc1

	CMOVQCS x_ptr, acc4
	CMOVQCS acc3, acc5
	CMOVQCS t0, acc0
	CMOVQCS BX, acc1

	MOVQ acc4, (8*0)(res_ptr)
	MOVQ acc5, (8*1)(res_ptr)
	MOVQ acc0, (8*2)(res_ptr)
	MOVQ acc1, (8*3)(res_ptr)

	RET
/* ---------------------------------------*/
// func p256Select(res *SM2P256Point, table *p256Table, idx, limit int)
TEXT ·p256Select(SB),NOSPLIT,$0
	//MOVQ idx+16(FP),AX
	MOVQ table+8(FP),DI
	MOVQ res+0(FP),DX

	CMPB ·supportAVX2+0(SB), $0x01
	JEQ  select_avx2

	PXOR X15, X15	// X15 = 0
	PCMPEQL X14, X14 // X14 = -1
	PSUBL X14, X15   // X15 = 1
	MOVL idx+16(FP), X14
	PSHUFD $0, X14, X14

	PXOR X0, X0
	PXOR X1, X1
	PXOR X2, X2
	PXOR X3, X3
	PXOR X4, X4
	PXOR X5, X5
	MOVQ limit+24(FP),AX

	MOVOU X15, X13

loop_select:

		MOVOU X13, X12
		PADDL X15, X13
		PCMPEQL X14, X12

		MOVOU (16*0)(DI), X6
		MOVOU (16*1)(DI), X7
		MOVOU (16*2)(DI), X8
		MOVOU (16*3)(DI), X9
		MOVOU (16*4)(DI), X10
		MOVOU (16*5)(DI), X11
		ADDQ $(16*6), DI

		PAND X12, X6
		PAND X12, X7
		PAND X12, X8
		PAND X12, X9
		PAND X12, X10
		PAND X12, X11

		PXOR X6, X0
		PXOR X7, X1
		PXOR X8, X2
		PXOR X9, X3
		PXOR X10, X4
		PXOR X11, X5

		DECQ AX
		JNE loop_select

	MOVOU X0, (16*0)(DX)
	MOVOU X1, (16*1)(DX)
	MOVOU X2, (16*2)(DX)
	MOVOU X3, (16*3)(DX)
	MOVOU X4, (16*4)(DX)
	MOVOU X5, (16*5)(DX)

	RET

select_avx2:
	VPXOR Y15, Y15, Y15
	VPCMPEQD Y14, Y14, Y14
	VPSUBD Y14, Y15, Y15     // Y15 = 1 
	VPBROADCASTD idx+16(FP), Y14

	MOVQ limit+24(FP),AX
	VMOVDQU Y15, Y13

	VPXOR Y0, Y0, Y0
	VPXOR Y1, Y1, Y1
	VPXOR Y2, Y2, Y2

loop_select_avx2:
		VPCMPEQD Y14, Y13, Y12
		VPADDD Y15, Y13, Y13

		VPAND (32*0)(DI), Y12, Y3
		VPAND (32*1)(DI), Y12, Y4
		VPAND (32*2)(DI), Y12, Y5

		ADDQ $(32*3), DI

		VPXOR Y3, Y0, Y0
		VPXOR Y4, Y1, Y1
		VPXOR Y5, Y2, Y2

		DECQ AX
		JNE loop_select_avx2
	
	VMOVDQU Y0, (32*0)(DX)
	VMOVDQU Y1, (32*1)(DX)
	VMOVDQU Y2, (32*2)(DX)
	VZEROUPPER
	RET

/* ---------------------------------------*/
// func p256SelectAffine(res *p256AffinePoint, table *p256AffineTable, idx int)
TEXT ·p256SelectAffine(SB),NOSPLIT,$0
	MOVQ idx+16(FP),AX
	MOVQ table+8(FP),DI
	MOVQ res+0(FP),DX

	CMPB ·supportAVX2+0(SB), $0x01
	JEQ  select_base_avx2

	PXOR X15, X15	 // X15 = 0
	PCMPEQL X14, X14 // X14 = -1
	PSUBL X14, X15   // X15 = 1
	MOVL idx+16(FP), X14  // x14 = idx
	PSHUFD $0, X14, X14

	MOVQ $16, AX
	MOVOU X15, X13

	PXOR X0, X0
	PXOR X1, X1
	PXOR X2, X2
	PXOR X3, X3

loop_select_base:

		MOVOU X13, X12
		PADDL X15, X13
		PCMPEQL X14, X12

		MOVOU (16*0)(DI), X4
		MOVOU (16*1)(DI), X5
		MOVOU (16*2)(DI), X6
		MOVOU (16*3)(DI), X7

		MOVOU (16*4)(DI), X8
		MOVOU (16*5)(DI), X9
		MOVOU (16*6)(DI), X10
		MOVOU (16*7)(DI), X11

		ADDQ $(16*8), DI

		PAND X12, X4
		PAND X12, X5
		PAND X12, X6
		PAND X12, X7

		MOVOU X13, X12
		PADDL X15, X13
		PCMPEQL X14, X12

		PAND X12, X8
		PAND X12, X9
		PAND X12, X10
		PAND X12, X11

		PXOR X4, X0
		PXOR X5, X1
		PXOR X6, X2
		PXOR X7, X3

		PXOR X8, X0
		PXOR X9, X1
		PXOR X10, X2
		PXOR X11, X3

		DECQ AX
		JNE loop_select_base

	MOVOU X0, (16*0)(DX)
	MOVOU X1, (16*1)(DX)
	MOVOU X2, (16*2)(DX)
	MOVOU X3, (16*3)(DX)

	RET

select_base_avx2:
	VPXOR Y15, Y15, Y15
	VPCMPEQD Y14, Y14, Y14
	VPSUBD Y14, Y15, Y15
	VPBROADCASTD idx+16(FP), Y14

	MOVQ $16, AX
	VMOVDQU Y15, Y13
	VPXOR Y0, Y0, Y0
	VPXOR Y1, Y1, Y1

loop_select_base_avx2:
		VPCMPEQD Y14, Y13, Y12
		VPADDD Y15, Y13, Y13

		VPAND (32*0)(DI), Y12, Y2
		VPAND (32*1)(DI), Y12, Y3

		VPCMPEQD Y14, Y13, Y12
		VPADDD Y15, Y13, Y13

		VPAND (32*2)(DI), Y12, Y4
		VPAND (32*3)(DI), Y12, Y5

		ADDQ $(32*4), DI

		VPXOR Y2, Y0, Y0
		VPXOR Y3, Y1, Y1

		VPXOR Y4, Y0, Y0
		VPXOR Y5, Y1, Y1

		DECQ AX
		JNE loop_select_base_avx2

	VMOVDQU Y0, (32*0)(DX)
	VMOVDQU Y1, (32*1)(DX)
	VZEROUPPER
	RET

//func p256OrdReduce(s *p256OrdElement)
TEXT ·p256OrdReduce(SB),NOSPLIT,$0
	MOVQ s+0(FP), res_ptr
	MOVQ (8*0)(res_ptr), acc0
	MOVQ (8*1)(res_ptr), acc1
	MOVQ (8*2)(res_ptr), acc2
	MOVQ (8*3)(res_ptr), acc3
	XORQ acc4, acc4
	p256OrdReduceInline(acc0, acc1, acc2, acc3, acc4, acc5, x_ptr, y_ptr, t0, res_ptr)
	RET

// func p256OrdMul(res, in1, in2 *p256OrdElement)
TEXT ·p256OrdMul(SB),NOSPLIT,$0
	MOVQ in1+8(FP), x_ptr
	MOVQ in2+16(FP), y_ptr
	CMPB ·supportBMI2+0(SB), $0x01
	JEQ  ordMulBMI2

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
	MULQ p256ordK0<>(SB)
	MOVQ AX, t0

	MOVQ p256ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc0
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ t0, acc0
	MOVQ t0, AX
	MOVQ t0, DX
	SHLQ $32, AX
	SHRQ $32, DX
		
	SUBQ t0, acc2
	SBBQ AX, acc3
	SBBQ DX, acc0

	MOVQ p256ord<>+0x08(SB), AX
	MULQ t0
	ADDQ BX, acc1
	ADCQ $0, DX
	ADDQ AX, acc1
	ADCQ DX, acc2
	ADCQ $0, acc3
	ADCQ acc0, acc4
	ADCQ $0, acc5

	XORQ acc0, acc0  // It seems this line is optional.
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
	MULQ p256ordK0<>(SB)
	MOVQ AX, t0

	MOVQ p256ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ t0, acc1
	MOVQ t0, AX
	MOVQ t0, DX
	SHLQ $32, AX
	SHRQ $32, DX
		
	SUBQ t0, acc3
	SBBQ AX, acc4
	SBBQ DX, acc1

	MOVQ p256ord<>+0x08(SB), AX
	MULQ t0
	ADDQ BX, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ DX, acc3
	ADCQ $0, acc4
	ADCQ acc1, acc5
	ADCQ $0, acc0

	XORQ acc1, acc1  // It seems this line is optional.
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
	MULQ p256ordK0<>(SB)
	MOVQ AX, t0

	MOVQ p256ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ t0, acc2
	MOVQ t0, AX
	MOVQ t0, DX
	SHLQ $32, AX
	SHRQ $32, DX
		
	SUBQ t0, acc4
	SBBQ AX, acc5
	SBBQ DX, acc2

	MOVQ p256ord<>+0x08(SB), AX
	MULQ t0
	ADDQ BX, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ DX, acc4
	ADCQ $0, acc5
	ADCQ acc2, acc0
	ADCQ $0, acc1

	XORQ acc2, acc2  // It seems this line is optional.
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
	MULQ p256ordK0<>(SB)
	MOVQ AX, t0

	MOVQ p256ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, BX

	MOVQ t0, acc3
	MOVQ t0, AX
	MOVQ t0, DX
	SHLQ $32, AX
	SHRQ $32, DX
	
	SUBQ t0, acc5
	SBBQ AX, acc0
	SBBQ DX, acc3
	
	MOVQ p256ord<>+0x08(SB), AX
	MULQ t0
	ADDQ BX, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ DX, acc5
	ADCQ $0, acc0
	ADCQ acc3, acc1
	ADCQ $0, acc2

	MOVQ res+0(FP), res_ptr
	p256OrdReduceInline(acc4, acc5, acc0, acc1, acc2, x_ptr, acc3, t0, BX, res_ptr)

	RET

ordMulBMI2:
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
	MULXQ p256ordK0<>(SB), DX, AX 

	MULXQ p256ord<>+0x00(SB), AX, t0
	ADOXQ AX, acc0

	MULXQ p256ord<>+0x08(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc1

	MULXQ p256ord<>+0x10(SB), AX, t0
	ADCXQ BX, AX
	ADOXQ AX, acc2

	MULXQ p256ord<>+0x18(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc3

	ADCXQ res_ptr, BX
	ADOXQ BX, acc4
	ADOXQ res_ptr, acc5
	XORQ acc0, acc0  // It seems this line is optional.

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
	MULXQ p256ordK0<>(SB), DX, AX

	MULXQ p256ord<>+0x00(SB), AX, t0
	ADOXQ AX, acc1

	MULXQ p256ord<>+0x08(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc2

	MULXQ p256ord<>+0x10(SB), AX, t0
	ADCXQ BX, AX
	ADOXQ AX, acc3

	MULXQ p256ord<>+0x18(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc4

	ADCXQ res_ptr, BX
	ADOXQ BX, acc5
	ADOXQ res_ptr, acc0
	XORQ acc1, acc1  // It seems this line is optional.

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
	MULXQ p256ordK0<>(SB), DX, AX

	MULXQ p256ord<>+0x00(SB), AX, t0
	ADOXQ AX, acc2

	MULXQ p256ord<>+0x08(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc3

	MULXQ p256ord<>+0x10(SB), AX, t0
	ADCXQ BX, AX
	ADOXQ AX, acc4

	MULXQ p256ord<>+0x18(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc5

	ADCXQ res_ptr, BX
	ADOXQ BX, acc0
	ADOXQ res_ptr, acc1
	XORQ acc2, acc2  // It seems this line is optional.

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
	MULXQ p256ordK0<>(SB), DX, AX

	MULXQ p256ord<>+0x00(SB), AX, t0
	ADOXQ AX, acc3

	MULXQ p256ord<>+0x08(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc4

	MULXQ p256ord<>+0x10(SB), AX, t0
	ADCXQ BX, AX
	ADOXQ AX, acc5

	MULXQ p256ord<>+0x18(SB), AX, BX
	ADCXQ t0, AX
	ADOXQ AX, acc0

	ADCXQ res_ptr, BX
	ADOXQ BX, acc1
	ADOXQ res_ptr, acc2

	MOVQ res+0(FP), res_ptr
	p256OrdReduceInline(acc4, acc5, acc0, acc1, acc2, x_ptr, acc3, t0, BX, res_ptr)

	RET
