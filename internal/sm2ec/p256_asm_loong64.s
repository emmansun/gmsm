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
#define hlp1 R30

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

DATA p256p<>+0x00(SB)/8, $0xffffffffffffffff
DATA p256p<>+0x08(SB)/8, $0xffffffff00000000
DATA p256p<>+0x10(SB)/8, $0xffffffffffffffff
DATA p256p<>+0x18(SB)/8, $0xfffffffeffffffff
DATA p256ordK0<>+0x00(SB)/8, $0x327f9e8872350975
DATA p256ord<>+0x00(SB)/8, $0x53bbf40939d54123
DATA p256ord<>+0x08(SB)/8, $0x7203df6b21c6052b
DATA p256ord<>+0x10(SB)/8, $0xffffffffffffffff
DATA p256ord<>+0x18(SB)/8, $0xfffffffeffffffff
DATA p256one<>+0x00(SB)/8, $0x0000000000000001
DATA p256one<>+0x08(SB)/8, $0x00000000ffffffff
DATA p256one<>+0x10(SB)/8, $0x0000000000000000
DATA p256one<>+0x18(SB)/8, $0x0000000100000000
GLOBL p256p<>(SB), RODATA, $32
GLOBL p256ordK0<>(SB), RODATA, $8
GLOBL p256ord<>(SB), RODATA, $32
GLOBL p256one<>(SB), RODATA, $32

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

/* ---------------------------------------*/
// func p256MovCond(res, a, b *SM2P256Point, cond int)
TEXT ·p256MovCond(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV a+8(FP), x_ptr
	MOVV b+16(FP), y_ptr
	MOVV cond+24(FP), t0

	MOVV ·supportLSX+0(SB), t1
	BEQ  t1, ZERO, basic_path

	MOVV ·supportLASX+0(SB), t1
	BEQ  t1, ZERO, lsx_path

	XVMOVQ t0, X0.V4
	XVXORV X1, X1, X1
	XVSEQV X0, X1, X0

	XVMOVQ (32*0)(x_ptr), X1
	XVMOVQ (32*1)(x_ptr), X2
	XVMOVQ (32*2)(x_ptr), X3

	XVANDNV X1, X0, X1
	XVANDNV X2, X0, X2
	XVANDNV X3, X0, X3

	XVMOVQ (32*0)(y_ptr), X4
	XVMOVQ (32*1)(y_ptr), X5
	XVMOVQ (32*2)(y_ptr), X6

	XVANDV X4, X0, X4
	XVANDV X5, X0, X5
	XVANDV X6, X0, X6

	XVORV X1, X4, X1
	XVORV X2, X5, X2
	XVORV X3, X6, X3

	XVMOVQ X1, (32*0)(res_ptr)
	XVMOVQ X2, (32*1)(res_ptr)
	XVMOVQ X3, (32*2)(res_ptr)

	RET

lsx_path:
	VMOVQ t0, V0.V2
	VXORV V1, V1, V1
	VSEQV V0, V1, V0

	VMOVQ (16*0)(x_ptr), V1
	VMOVQ (16*1)(x_ptr), V2
	VMOVQ (16*2)(x_ptr), V3
	VMOVQ (16*3)(x_ptr), V4
	VMOVQ (16*4)(x_ptr), V5
	VMOVQ (16*5)(x_ptr), V6
	VANDNV V1, V0, V1
	VANDNV V2, V0, V2
	VANDNV V3, V0, V3
	VANDNV V4, V0, V4
	VANDNV V5, V0, V5
	VANDNV V6, V0, V6

	VMOVQ (16*0)(y_ptr), V7
	VMOVQ (16*1)(y_ptr), V8
	VMOVQ (16*2)(y_ptr), V9
	VMOVQ (16*3)(y_ptr), V10
	VMOVQ (16*4)(y_ptr), V11
	VMOVQ (16*5)(y_ptr), V12
	VANDV V7, V0, V7
	VANDV V8, V0, V8
	VANDV V9, V0, V9
	VANDV V10, V0, V10
	VANDV V11, V0, V11
	VANDV V12, V0, V12

	VORV V1, V7, V1
	VORV V2, V8, V2
	VORV V3, V9, V3
	VORV V4, V10, V4
	VORV V5, V11, V5
	VORV V6, V12, V6

	VMOVQ V1, (16*0)(res_ptr)
	VMOVQ V2, (16*1)(res_ptr)
	VMOVQ V3, (16*2)(res_ptr)
	VMOVQ V4, (16*3)(res_ptr)
	VMOVQ V5, (16*4)(res_ptr)
	VMOVQ V6, (16*5)(res_ptr)

	RET

basic_path:
	// Load a.x
	MOVV (8*0)(x_ptr), acc0
	MOVV (8*1)(x_ptr), acc1
	MOVV (8*2)(x_ptr), acc2
	MOVV (8*3)(x_ptr), acc3

	// Load b.x
	MOVV (8*0)(y_ptr), t1
	MOVV (8*1)(y_ptr), t2
	MOVV (8*2)(y_ptr), t3
	MOVV (8*3)(y_ptr), hlp0

	// Conditional move
	MASKNEZ t0, t1, t1
	MASKEQZ t0, acc0, acc0
	OR t1, acc0

	MASKNEZ t0, t2, t2
	MASKEQZ t0, acc1, acc1
	OR t2, acc1

	MASKNEZ t0, t3, t3
	MASKEQZ t0, acc2, acc2
	OR t3, acc2

	MASKNEZ t0, hlp0, hlp0
	MASKEQZ t0, acc3, acc3
	OR hlp0, acc3

	// Store result
	MOVV acc0, (8*0)(res_ptr)
	MOVV acc1, (8*1)(res_ptr)
	MOVV acc2, (8*2)(res_ptr)
	MOVV acc3, (8*3)(res_ptr)

	// Load a.y
	MOVV (8*4)(x_ptr), acc0
	MOVV (8*5)(x_ptr), acc1
	MOVV (8*6)(x_ptr), acc2
	MOVV (8*7)(x_ptr), acc3

	// Load b.y
	MOVV (8*4)(y_ptr), t1
	MOVV (8*5)(y_ptr), t2
	MOVV (8*6)(y_ptr), t3
	MOVV (8*7)(y_ptr), hlp0

	// Conditional move
	MASKNEZ t0, t1, t1
	MASKEQZ t0, acc0, acc0
	OR t1, acc0

	MASKNEZ t0, t2, t2
	MASKEQZ t0, acc1, acc1
	OR t2, acc1

	MASKNEZ t0, t3, t3
	MASKEQZ t0, acc2, acc2
	OR t3, acc2

	MASKNEZ t0, hlp0, hlp0
	MASKEQZ t0, acc3, acc3
	OR hlp0, acc3

	// Store result
	MOVV acc0, (8*4)(res_ptr)
	MOVV acc1, (8*5)(res_ptr)
	MOVV acc2, (8*6)(res_ptr)
	MOVV acc3, (8*7)(res_ptr)

	// Load a.z
	MOVV (8*8)(x_ptr), acc0
	MOVV (8*9)(x_ptr), acc1
	MOVV (8*10)(x_ptr), acc2
	MOVV (8*11)(x_ptr), acc3

	// Load b.z
	MOVV (8*8)(y_ptr), t1
	MOVV (8*9)(y_ptr), t2
	MOVV (8*10)(y_ptr), t3
	MOVV (8*11)(y_ptr), hlp0

	// Conditional move
	MASKNEZ t0, t1, t1
	MASKEQZ t0, acc0, acc0
	OR t1, acc0

	MASKNEZ t0, t2, t2
	MASKEQZ t0, acc1, acc1
	OR t2, acc1

	MASKNEZ t0, t3, t3
	MASKEQZ t0, acc2, acc2
	OR t3, acc2

	MASKNEZ t0, hlp0, hlp0
	MASKEQZ t0, acc3, acc3
	OR hlp0, acc3

	// Store result
	MOVV acc0, (8*8)(res_ptr)
	MOVV acc1, (8*9)(res_ptr)
	MOVV acc2, (8*10)(res_ptr)
	MOVV acc3, (8*11)(res_ptr)
	RET

/* ---------------------------------------*/
// func p256NegCond(val *p256Element, cond int)
TEXT ·p256NegCond(SB),NOSPLIT,$0
	MOVV val+0(FP), res_ptr
	MOVV cond+8(FP), t0
	// acc = poly
	MOVV $-1, acc0
	MOVV p256p<>+0x08(SB), acc1
	MOVV $-1, acc2
	MOVV p256p<>+0x18(SB), acc3
	// Load the original value
	MOVV (8*0)(res_ptr), acc4
	MOVV (8*1)(res_ptr), x_ptr
	MOVV (8*2)(res_ptr), y_ptr
	MOVV (8*3)(res_ptr), acc5

	// Speculatively subtract
	SUBV acc4, acc0
	SGTU x_ptr, acc1, t1
	SUBV x_ptr, acc1
	SUBV y_ptr, acc2
	SGTU t1, acc2, t2
	SUBV t1, acc2
	SUBV acc5, acc3
	SUBV t2, acc3

	MASKNEZ t0, acc4, acc4
	MASKEQZ t0, acc0, acc0
	OR acc4, acc0

	MASKNEZ t0, x_ptr, x_ptr
	MASKEQZ t0, acc1, acc1
	OR x_ptr, acc1

	MASKNEZ t0, y_ptr, y_ptr
	MASKEQZ t0, acc2, acc2
	OR y_ptr, acc2

	MASKNEZ t0, acc5, acc5
	MASKEQZ t0, acc3, acc3
	OR acc5, acc3

	MOVV acc0, (8*0)(res_ptr)
	MOVV acc1, (8*1)(res_ptr)
	MOVV acc2, (8*2)(res_ptr)
	MOVV acc3, (8*3)(res_ptr)

	RET

/* ---------------------------------------*/
// func p256FromMont(res, in *p256Element)
TEXT ·p256FromMont(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV in+8(FP), x_ptr

	MOVV (8*0)(x_ptr), acc0
	MOVV (8*1)(x_ptr), acc1
	MOVV (8*2)(x_ptr), acc2
	MOVV (8*3)(x_ptr), acc3
	// Only reduce, no multiplications are needed
	// First reduction step
	SLLV $32, acc0, t0
	SRLV $32, acc0, t1

	// SUBS t0, acc1
	SGTU t0, acc1, t2
	SUBV t0, acc1, acc1
	// SBCS t1, acc2
	ADDV t2, t1, t2       // no carry
	SGTU t2, acc2, t3
	SUBV t2, acc2, acc2
	// SBCS t0, acc3
	ADDV t3, t0, t3       // no carry
	SGTU t3, acc3, t2
	SUBV t3, acc3, acc3
	// SBC t1, acc0
	ADDV t2, t1, t2       // no carry
	SUBV t2, acc0, y0     // no borrow

	// ADDS acc0, acc1, acc1
	ADDV acc0, acc1, acc1
	SGTU acc0, acc1, t0
	// ADCS $0, acc2
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t1
	// ADCS $0, acc3
	ADDV t1, acc3, acc3
	SGTU t1, acc3, t0
	// ADC $0, y0, acc0
	ADDV t0, y0, acc0

	// Second reduction step
	SLLV $32, acc1, t0
	SRLV $32, acc1, t1

	// SUBS t0, acc2
	SGTU t0, acc2, t2
	SUBV t0, acc2, acc2
	// SBCS t1, acc3
	ADDV t2, t1, t3       // no carry
	SGTU t3, acc3, t2
	SUBV t3, acc3, acc3
	// SBCS t0, acc0
	ADDV t2, t0, t2       // no carry
	SGTU t2, acc0, t3
	SUBV t2, acc0, acc0
	// SBC t1, acc1
	ADDV t3, t1, t2       // no carry
	SUBV t2, acc1, y0     // no borrow

	// ADDS acc1, acc2
	ADDV acc1, acc2, acc2
	SGTU acc1, acc2, t0
	// ADCS $0, acc3
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t1
	// ADCS $0, acc0
	ADDV t1, acc0, acc0
	SGTU t1, acc0, t0
	// ADC $0, y0, acc1
	ADDV t0, y0, acc1

	// Third reduction step
	SLLV $32, acc2, t0
	SRLV $32, acc2, t1

	// SUBS t0, acc3
	SGTU t0, acc3, t2
	SUBV t0, acc3, acc3
	// SBCS t1, acc0
	ADDV t2, t1, t3       // no carry
	SGTU t3, acc0, t2
	SUBV t3, acc0, acc0
	// SBCS t0, acc1
	ADDV t2, t0, t2       // no carry
	SGTU t2, acc1, t3
	SUBV t2, acc1, acc1
	// SBC t1, acc2
	ADDV t3, t1, t2       // no carry
	SUBV t2, acc2, y0     // no borrow

	// ADDS acc2, acc3
	ADDV acc2, acc3, acc3
	SGTU acc2, acc3, t0
	// ADCS $0, acc0
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t1
	// ADCS $0, acc1
	ADDV t1, acc1, acc1
	SGTU t1, acc1, t0
	// ADC $0, y0, acc2
	ADDV t0, y0, acc2

	// Last reduction step
	SLLV $32, acc3, t0
	SRLV $32, acc3, t1

	// SUBS t0, acc0
	SGTU t0, acc0, t2
	SUBV t0, acc0, acc0
	// SBCS t1, acc1
	ADDV t2, t1, t3       // no carry
	SGTU t3, acc1, t2
	SUBV t3, acc1, acc1
	// SBCS t0, acc2
	ADDV t2, t0, t2       // no carry
	SGTU t2, acc2, t3
	SUBV t2, acc2, acc2
	// SBC t1, acc3
	ADDV t3, t1, t2       // no carry
	SUBV t2, acc3, y0     // no borrow

	// ADDS acc3, acc0
	ADDV acc3, acc0, acc0
	SGTU acc3, acc0, t0
	// ADCS $0, acc1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t1
	// ADCS $0, acc2
	ADDV t1, acc2, acc2
	SGTU t1, acc2, t0
	// ADC $0, y0, acc3
	ADDV t0, y0, acc3

	// Final reduction
	ADDV $1, acc0, acc4
	SGTU acc0, acc4, t1
	MOVV p256one<>+0x08(SB), t2
	ADDV t2, t1, t1         // no carry
	ADDV acc1, t1, acc5
	SGTU acc1, acc5, t3
	ADDV t3, acc2, acc6
	SGTU acc2, acc6, hlp0
	ADDV $1, t2, t2
	ADDV hlp0, t2, t2         // no carry
	ADDV acc3, t2, acc7
	SGTU acc3, acc7, t0

	MASKNEZ t0, acc0, acc0
	MASKEQZ t0, acc4, acc4
	OR acc4, acc0

	MASKNEZ t0, acc1, acc1
	MASKEQZ t0, acc5, acc5
	OR acc5, acc1

	MASKNEZ t0, acc2, acc2
	MASKEQZ t0, acc6, acc6
	OR acc6, acc2

	MASKNEZ t0, acc3, acc3
	MASKEQZ t0, acc7, acc7
	OR acc7, acc3

	MOVV acc0, (8*0)(res_ptr)
	MOVV acc1, (8*1)(res_ptr)
	MOVV acc2, (8*2)(res_ptr)
	MOVV acc3, (8*3)(res_ptr)
	RET

/* ---------------------------------------*/
// func p256Sqr(res, in *p256Element, n int)
TEXT ·p256Sqr(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV in+8(FP), x_ptr
	MOVV n+16(FP), y_ptr

	MOVV (8*0)(x_ptr), x0
	MOVV (8*1)(x_ptr), x1
	MOVV (8*2)(x_ptr), x2
	MOVV (8*3)(x_ptr), x3

	MOVV p256one<>+0x08(SB), const0
	ADDV $1, const0, const1
	
sqrLoop:
		SUBV $1, y_ptr
		CALL	sm2P256SqrInternal<>(SB)
		MOVV y0, x0
		MOVV y1, x1
		MOVV y2, x2
		MOVV y3, x3
		BNE y_ptr, sqrLoop

	MOVV y0, (8*0)(res_ptr)
	MOVV y1, (8*1)(res_ptr)
	MOVV y2, (8*2)(res_ptr)
	MOVV y3, (8*3)(res_ptr)

	RET
/* ---------------------------------------*/
// (y3, y2, y1, y0) = (x3, x2, x1, x0) ^ 2
TEXT sm2P256SqrInternal<>(SB),NOSPLIT,$0
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
	SGTU t0, acc3, t2
	MULHVU x1, x2, t1
	// ADCS t1, acc4
	ADDV t1, acc4, acc4
	SGTU t1, acc4, t3
	ADDV t2, acc4, acc4
	SGTU t2, acc4, hlp0
	// ADC $0, acc5
	OR t3, hlp0, acc5

	MULV x1, x3, t0
	// ADCS t0, acc4
	ADDV t0, acc4, acc4
	SGTU t0, acc4, t2
	MULHVU x1, x3, t1
	// ADC	t1, acc5
	ADDV t1, t2, t2       // no carry
	ADDV t2, acc5, acc5   // no carry

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
	SRLV $63, acc3, t2
	// ALSLV $1, t1, acc3, acc3
	SLLV $1, acc3, acc3
	ADDV t1, acc3, acc3
	SRLV $63, acc4, t3
	// ALSLV $1, t2, acc4, acc4
	SLLV $1, acc4, acc4
	ADDV t2, acc4, acc4
	SRLV $63, acc5, hlp0
	// ALSLV $1, t3, acc5, acc5
	SLLV $1, acc5, acc5
	ADDV t3, acc5, acc5
	SRLV $63, acc6, acc7
	// ALSLV $1, hlp0, acc6, acc6
	SLLV $1, acc6, acc6
	ADDV hlp0, acc6, acc6

	// Missing products
	MULV x0, x0, acc0
	MULHVU x0, x0, t0
	// ADDS t0, acc1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t1
	MULV x1, x1, t0
	// ADCS t0, acc2
	ADDV t0, t1, t1       // no carry
	ADDV t1, acc2, acc2
	SGTU t1, acc2, t2
	MULHVU x1, x1, t0
	// ADCS t0, acc3
	ADDV t0, t2, t2	      // no carry
	ADDV t2, acc3, acc3
	SGTU t2, acc3, t1
	MULV x2, x2, t0
	// ADCS t0, acc4
	ADDV t0, t1, t1       // no carry
	ADDV t1, acc4, acc4
	SGTU t1, acc4, t2
	MULHVU x2, x2, t0
	// ADCS t0, acc5
	ADDV t0, t2, t2       // no carry
	ADDV t2, acc5, acc5
	SGTU t2, acc5, t1
	MULV x3, x3, t0
	// ADCS t0, acc6
	ADDV t0, t1, t1       // no carry
	ADDV t1, acc6, acc6
	SGTU t1, acc6, t2
	MULHVU x3, x3, t0
	// ADC	t0, acc7
	ADDV t0, t2, t2       // no carry
	ADDV t2, acc7, acc7   // (acc0, acc1, acc2, acc3, acc4, acc5, acc6, acc7) is the result
	
	// First reduction step
	SLLV $32, acc0, t0
	SRLV $32, acc0, t1

	// SUBS t0, acc1
	SGTU t0, acc1, t2
	SUBV t0, acc1, acc1
	// SBCS t1, acc2
	ADDV t2, t1, t2       // no carry
	SGTU t2, acc2, t3
	SUBV t2, acc2, acc2
	// SBCS t0, acc3
	ADDV t3, t0, t3       // no carry
	SGTU t3, acc3, t2
	SUBV t3, acc3, acc3
	// SBC t1, acc0
	ADDV t2, t1, t2       // no carry
	SUBV t2, acc0, y0     // no borrow

	// ADDS acc0, acc1, acc1
	ADDV acc0, acc1, acc1
	SGTU acc0, acc1, t0
	// ADCS $0, acc2
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t1
	// ADCS $0, acc3
	ADDV t1, acc3, acc3
	SGTU t1, acc3, t0
	// ADC $0, y0, acc0
	ADDV t0, y0, acc0

	// Second reduction step
	SLLV $32, acc1, t0
	SRLV $32, acc1, t1

	// SUBS t0, acc2
	SGTU t0, acc2, t2
	SUBV t0, acc2, acc2
	// SBCS t1, acc3
	ADDV t2, t1, t3       // no carry
	SGTU t3, acc3, t2
	SUBV t3, acc3, acc3
	// SBCS t0, acc0
	ADDV t2, t0, t2       // no carry
	SGTU t2, acc0, t3
	SUBV t2, acc0, acc0
	// SBC t1, acc1
	ADDV t3, t1, t2       // no carry
	SUBV t2, acc1, y0     // no borrow

	// ADDS acc1, acc2
	ADDV acc1, acc2, acc2
	SGTU acc1, acc2, t0
	// ADCS $0, acc3
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t1
	// ADCS $0, acc0
	ADDV t1, acc0, acc0
	SGTU t1, acc0, t0
	// ADC $0, y0, acc1
	ADDV t0, y0, acc1

	// Third reduction step
	SLLV $32, acc2, t0
	SRLV $32, acc2, t1

	// SUBS t0, acc3
	SGTU t0, acc3, t2
	SUBV t0, acc3, acc3
	// SBCS t1, acc0
	ADDV t2, t1, t3       // no carry
	SGTU t3, acc0, t2
	SUBV t3, acc0, acc0
	// SBCS t0, acc1
	ADDV t2, t0, t2       // no carry
	SGTU t2, acc1, t3
	SUBV t2, acc1, acc1
	// SBC t1, acc2
	ADDV t3, t1, t2       // no carry
	SUBV t2, acc2, y0     // no borrow

	// ADDS acc2, acc3
	ADDV acc2, acc3, acc3
	SGTU acc2, acc3, t0
	// ADCS $0, acc0
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t1
	// ADCS $0, acc1
	ADDV t1, acc1, acc1
	SGTU t1, acc1, t0
	// ADC $0, y0, acc2
	ADDV t0, y0, acc2

	// Last reduction step
	SLLV $32, acc3, t0
	SRLV $32, acc3, t1

	// SUBS t0, acc0
	SGTU t0, acc0, t2
	SUBV t0, acc0, acc0
	// SBCS t1, acc1
	ADDV t2, t1, t3       // no carry
	SGTU t3, acc1, t2
	SUBV t3, acc1, acc1
	// SBCS t0, acc2
	ADDV t2, t0, t2       // no carry
	SGTU t2, acc2, t3
	SUBV t2, acc2, acc2
	// SBC t1, acc3
	ADDV t3, t1, t2       // no carry
	SUBV t2, acc3, y0     // no borrow

	// ADDS acc3, acc0
	ADDV acc3, acc0, acc0
	SGTU acc3, acc0, t0
	// ADCS $0, acc1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t1
	// ADCS $0, acc2
	ADDV t1, acc2, acc2
	SGTU t1, acc2, t0
	// ADC $0, y0, acc3
	ADDV t0, y0, acc3

	// Add bits [511:256] of the sqr result
	ADDV acc4, acc0, y0
	SGTU acc4, y0, t0
	ADDV acc5, acc1, y1
	SGTU acc5, y1, t1
	ADDV t0, y1, y1
	SGTU t0, y1, t2
	OR t1, t2, t0
	ADDV acc6, acc2, y2
	SGTU acc6, y2, t1
	ADDV t0, y2, y2
	SGTU t0, y2, t2
	OR t1, t2, t0
	ADDV acc7, acc3, y3
	SGTU acc7, y3, t1
	ADDV t0, y3, y3
	SGTU t0, y3, t2
	OR t1, t2, t0

	// Final reduction
	ADDV $1, y0, acc4
	SGTU y0, acc4, t1
	ADDV const0, t1, t1             // no carry
	ADDV y1, t1, acc5
	SGTU y1, acc5, t3
	ADDV t3, y2, acc6
	SGTU y2, acc6, hlp0
	ADDV hlp0, const1, t2         // no carry
	ADDV y3, t2, acc7
	SGTU y3, acc7, hlp0
	OR t0, hlp0, t0

	MASKNEZ t0, y0, y0
	MASKEQZ t0, acc4, acc4
	OR acc4, y0

	MASKNEZ t0, y1, y1
	MASKEQZ t0, acc5, acc5
	OR acc5, y1

	MASKNEZ t0, y2, y2
	MASKEQZ t0, acc6, acc6
	OR acc6, y2

	MASKNEZ t0, y3, y3
	MASKEQZ t0, acc7, acc7
	OR acc7, y3

	RET

/* ---------------------------------------*/
// (y3, y2, y1, y0) = (x3, x2, x1, x0) * (y3, y2, y1, y0)
TEXT sm2P256MulInternal<>(SB),NOSPLIT,$0
	// y[0] * x
	MULV y0, x0, acc0
	MULHVU	y0, x0, acc4
	MULV y0, x1, acc1
	MULHVU y0, x1, acc5
	MULV y0, x2, acc2
	MULHVU y0, x2, acc6
	MULV y0, x3, acc3
	MULHVU y0, x3, acc7

	// ADDS acc4, acc1
	ADDV acc1, acc4, acc1
	SGTU acc4, acc1, t0
	// ADCS acc5, acc2
	ADDV t0, acc5, acc5    // no carry
	ADDV acc2, acc5, acc2
	SGTU acc5, acc2, t0
	// ADCS acc6, acc3
	ADDV t0, acc6, acc6    // no carry
	ADDV acc3, acc6, acc3
	SGTU acc6, acc3, t0
	// ADC $0, acc7, acc4
	ADDV t0, acc7, acc4    // no carry
	// First reduction step
	SLLV $32, acc0, t0
	SRLV $32, acc0, t1

	// SUBS t0, acc1
	SGTU t0, acc1, t2
	SUBV t0, acc1
	// SUBCS t1, acc2
	ADDV t2, t1, t3        // no carry
	SGTU t3, acc2, t2
	SUBV t3, acc2
	// SUBCS t0, acc3
	ADDV t2, t0, t2        // no carry
	SGTU t2, acc3, t3
	SUBV t2, acc3, acc3
	// SUBC t1, acc0, t2
	SUBV t1, acc0, t2      // no borrow
	SUBV t3, t2, t2        // no borrow

	// ADDS acc0, acc1
	ADDV acc0, acc1, acc1
	SGTU acc0, acc1, t0
	// ADCS $0, acc2
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t1
	// ADCS $0, acc3
	ADDV t1, acc3, acc3
	SGTU t1, acc3, t0
	// ADC $0, t2, acc0
	ADDV t0, t2, acc0      // (acc1, acc2, acc3, acc0) is the result

	// y[1] * x
	MULV y1, x0, t0
	// ADDS t0, acc1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t2
	MULHVU y1, x0, t1

	MULV y1, x1, t0
	// ADCS t0, acc2
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t3
	ADDV t2, acc2, acc2
	SGTU t2, acc2, hlp0
	OR t3, hlp0, t2
	MULHVU y1, x1, y0

	MULV y1, x2, t0
	// ADCS t0, acc3
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t3
	ADDV t2, acc3, acc3
	SGTU t2, acc3, hlp0
	OR t3, hlp0, t2
	MULHVU y1, x2, acc6

	MULV y1, x3, t0
	// ADCS t0, acc4
	ADDV t0, acc4, acc4
	SGTU t0, acc4, t3
	ADDV t2, acc4, acc4
	SGTU t2, acc4, hlp0
	OR t3, hlp0, acc5
	MULHVU y1, x3, acc7

	// ADDS	t1, acc2
	ADDV t1, acc2, acc2
	SGTU t1, acc2, t2
	// ADCS	y0, acc3
	ADDV y0, acc3, acc3
	SGTU y0, acc3, t3
	ADDV t2, acc3, acc3
	SGTU t2, acc3, hlp0
	OR t3, hlp0, t2
	// ADCS	acc6, acc4
	ADDV acc6, acc4, acc4
	SGTU acc6, acc4, t3
	ADDV t2, acc4, acc4
	SGTU t2, acc4, hlp0
	OR t3, hlp0, t2
	// ADC	acc7, acc5
	ADDV t2, acc5, acc5
	ADDV acc7, acc5, acc5

	// Second reduction step
	SLLV $32, acc1, t0
	SRLV $32, acc1, t1

	// SUBS t0, acc2
	SGTU t0, acc2, t2
	SUBV t0, acc2
	// SUBCS t1, acc3
	ADDV t2, t1, t3        // no carry
	SGTU t3, acc3, t2
	SUBV t3, acc3
	// SUBCS t0, acc0
	ADDV t2, t0, t2        // no carry
	SGTU t2, acc0, t3
	SUBV t2, acc0, acc0
	// SUBC t1, acc1, t2
	SUBV t1, acc1, t2      // no borrow
	SUBV t3, t2, t2        // no borrow

	// ADDS acc1, acc2
	ADDV acc1, acc2, acc2
	SGTU acc1, acc2, t0
	// ADCS $0, acc3
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t1
	// ADCS $0, acc0
	ADDV t1, acc0, acc0
	SGTU t1, acc0, t0
	// ADC $0, t2, acc1
	ADDV t0, t2, acc1      // (acc2, acc3, acc0, acc1) is the result

	// y[2] * x
	MULV y2, x0, t0
	// ADDS t0, acc2
	ADDV t0, acc2, acc2
	SGTU t0, acc2, t2
	MULHVU y2, x0, t1

	MULV y2, x1, t0
	// ADCS t0, acc3
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t3
	ADDV t2, acc3, acc3
	SGTU t2, acc3, hlp0
	OR t3, hlp0, t2
	MULHVU y2, x1, y0

	MULV y2, x2, t0
	// ADCS t0, acc0
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t3
	ADDV t2, acc0, acc0
	SGTU t2, acc0, hlp0
	OR t3, hlp0, t2
	MULHVU y2, x2, y1

	MULV y2, x3, t0
	// ADCS t0, acc1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t3
	ADDV t2, acc1, acc1
	SGTU t2, acc1, hlp0
	OR t3, hlp0, acc6
	MULHVU y2, x3, acc7

	// ADDS	t1, acc3
	ADDV t1, acc3, acc3
	SGTU t1, acc3, t2
	// ADCS	y0, acc4
	ADDV y0, acc4, acc4
	SGTU y0, acc4, t3
	ADDV t2, acc4, acc4
	SGTU t2, acc4, hlp0
	OR t3, hlp0, t2
	// ADCS	y1, acc5
	ADDV y1, acc5, acc5
	SGTU y1, acc5, t3
	ADDV t2, acc5, acc5
	SGTU t2, acc5, hlp0
	OR t3, hlp0, t2
	// ADC	acc7, acc6
	ADDV t2, acc6, acc6
	ADDV acc7, acc6, acc6

	// Third reduction step
	SLLV $32, acc2, t0
	SRLV $32, acc2, t1

	// SUBS t0, acc3
	SGTU t0, acc3, t2
	SUBV t0, acc3
	// SUBCS t1, acc0
	ADDV t2, t1, t3        // no carry
	SGTU t3, acc0, t2
	SUBV t3, acc0
	// SUBCS t0, acc1
	ADDV t2, t0, t2        // no carry
	SGTU t2, acc1, t3
	SUBV t2, acc1, acc1	
	// SUBC t1, acc2, t2
	SUBV t1, acc2, t2      // no borrow
	SUBV t3, t2, t2        // no borrow

	// ADDS acc2, acc3
	ADDV acc2, acc3, acc3
	SGTU acc2, acc3, t0
	// ADCS $0, acc0
	ADDV t0, acc0, acc0
	SGTU t0, acc0, t1
	// ADCS $0, acc1
	ADDV t1, acc1, acc1
	SGTU t1, acc1, t0
	// ADC $0, t2, acc2
	ADDV t0, t2, acc2      // (acc3, acc0, acc1, acc2) is the result

	// y[2] * x
	MULV y3, x0, t0
	// ADDS t0, acc3
	ADDV t0, acc3, acc3
	SGTU t0, acc3, t2
	MULHVU y3, x0, t1

	MULV y3, x1, t0
	// ADCS t0, acc4
	ADDV t0, acc4, acc4
	SGTU t0, acc4, t3
	ADDV t2, acc4, acc4
	SGTU t2, acc4, hlp0
	OR t3, hlp0, t2
	MULHVU y3, x1, y0

	MULV y3, x2, t0
	// ADCS t0, acc5
	ADDV t0, acc5, acc5
	SGTU t0, acc5, t3
	ADDV t2, acc5, acc5	
	SGTU t2, acc5, hlp0
	OR t3, hlp0, t2
	MULHVU y3, x2, y1

	MULV y3, x3, t0
	// ADCS t0, acc6
	ADDV t0, acc6, acc6
	SGTU t0, acc6, t3
	ADDV t2, acc6, acc6
	SGTU t2, acc6, hlp0
	OR t3, hlp0, acc7
	MULHVU y3, x3, t0

	// ADDS	t1, acc4
	ADDV t1, acc4, acc4
	SGTU t1, acc4, t2
	// ADCS	y0, acc5
	ADDV y0, acc5, acc5
	SGTU y0, acc5, t3
	ADDV t2, acc5, acc5
	SGTU t2, acc5, hlp0
	OR t3, hlp0, t2
	// ADCS	y1, acc6
	ADDV y1, acc6, acc6
	SGTU y1, acc6, t3
	ADDV t2, acc6, acc6
	SGTU t2, acc6, hlp0
	OR t3, hlp0, t2
	// ADC	t0, acc7
	ADDV t2, acc7, acc7
	ADDV t0, acc7, acc7

	// Fourth reduction step
	SLLV $32, acc3, t0
	SRLV $32, acc3, t1

	// SUBS t0, acc0
	SGTU t0, acc0, t2
	SUBV t0, acc0
	// SUBCS t1, acc1
	ADDV t2, t1, t3        // no carry
	SGTU t3, acc1, t2
	SUBV t3, acc1
	// SUBCS t0, acc2
	ADDV t2, t0, t2        // no carry
	SGTU t2, acc2, t3
	SUBV t2, acc2, acc2
	// SUBC t1, acc3, t2
	SUBV t1, acc3, t2      // no borrow
	SUBV t3, t2, t2        // no borrow

	// ADDS acc3, acc0
	ADDV acc3, acc0, acc0
	SGTU acc3, acc0, t0
	// ADCS $0, acc1
	ADDV t0, acc1, acc1
	SGTU t0, acc1, t1
	// ADCS $0, acc2
	ADDV t1, acc2, acc2
	SGTU t1, acc2, t0
	// ADC $0, t2, acc3
	ADDV t0, t2, acc3      // (acc0, acc1, acc2, acc3) is the result

	// Add bits [511:256] of the mul result
	ADDV acc4, acc0, y0
	SGTU acc4, y0, t0
	ADDV acc5, acc1, y1
	SGTU acc5, y1, t1
	ADDV t0, y1, y1
	SGTU t0, y1, t2
	OR t1, t2, t0
	ADDV acc6, acc2, y2
	SGTU acc6, y2, t1
	ADDV t0, y2, y2
	SGTU t0, y2, t2
	OR t1, t2, t0
	ADDV acc7, acc3, y3
	SGTU acc7, y3, t1
	ADDV t0, y3, y3
	SGTU t0, y3, t2
	OR t1, t2, t0

	// Final reduction
	ADDV $1, y0, acc4
	SGTU y0, acc4, t1
	ADDV const0, t1, t1             // no carry
	ADDV y1, t1, acc5
	SGTU y1, acc5, t3
	ADDV t3, y2, acc6
	SGTU y2, acc6, hlp0
	ADDV hlp0, const1, t2         // no carry
	ADDV y3, t2, acc7
	SGTU y3, acc7, hlp0
	OR t0, hlp0, t0

	MASKNEZ t0, y0, y0
	MASKEQZ t0, acc4, acc4
	OR acc4, y0

	MASKNEZ t0, y1, y1
	MASKEQZ t0, acc5, acc5
	OR acc5, y1

	MASKNEZ t0, y2, y2
	MASKEQZ t0, acc6, acc6
	OR acc6, y2

	MASKNEZ t0, y3, y3
	MASKEQZ t0, acc7, acc7
	OR acc7, y3

	RET

/* ---------------------------------------*/
// func p256Mul(res, in1, in2 *p256Element)
TEXT ·p256Mul(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV in1+8(FP), x_ptr
	MOVV in2+16(FP), y_ptr

	MOVV p256one<>+0x08(SB), const0
	ADDV $1, const0, const1

	MOVV (8*0)(x_ptr), x0
	MOVV (8*1)(x_ptr), x1
	MOVV (8*2)(x_ptr), x2
	MOVV (8*3)(x_ptr), x3

	MOVV (8*0)(y_ptr), y0
	MOVV (8*1)(y_ptr), y1
	MOVV (8*2)(y_ptr), y2
	MOVV (8*3)(y_ptr), y3

	CALL sm2P256MulInternal<>(SB)

	MOVV y0, (8*0)(res_ptr)
	MOVV y1, (8*1)(res_ptr)
	MOVV y2, (8*2)(res_ptr)
	MOVV y3, (8*3)(res_ptr)

	RET

/* ---------------------------------------*/
// func p256OrdSqr(res, in *p256OrdElement, n int)
TEXT ·p256OrdSqr(SB),NOSPLIT,$0
	RET

/* ---------------------------------------*/
// func p256OrdMul(res, in1, in2 *p256OrdElement)
TEXT ·p256OrdMul(SB),NOSPLIT,$0
	RET

/* ---------------------------------------*/
//func p256OrdReduce(s *p256OrdElement)
TEXT ·p256OrdReduce(SB),NOSPLIT,$0
	MOVV s+0(FP), res_ptr

	MOVV (8*0)(res_ptr), acc0
	MOVV (8*1)(res_ptr), acc1
	MOVV (8*2)(res_ptr), acc2
	MOVV (8*3)(res_ptr), acc3

	MOVV p256ord<>+0x00(SB), x0
	MOVV p256ord<>+0x08(SB), x1
	MOVV p256ord<>+0x10(SB), x2
	MOVV p256ord<>+0x18(SB), x3

	SGTU x0, acc0, t0
	SUBV x0, acc0, y0
	// SBCS x1, acc1
	ADDV t0, x1, t1        // no carry
	SGTU t1, acc1, t2
	SUBV t1, acc1, y1
	// SBCS x2, acc2
	SGTU x2, acc2, t3
	SUBV x2, acc2, y2
	SGTU t2, y2, t0
	SUBV t2, y2, y2
	OR t3, t0, t2
	// SBCS x3, acc3
	SGTU x3, acc3, t3
	SUBV x3, acc3, y3
	SGTU t2, y3, t0
	SUBV t2, y3, y3
	OR t3, t0, t0

	MASKNEZ t0, y0, y0
	MASKEQZ t0, acc0, acc0
	OR acc0, y0

	MASKNEZ t0, y1, y1
	MASKEQZ t0, acc1, acc1
	OR acc1, y1

	MASKNEZ t0, y2, y2
	MASKEQZ t0, acc2, acc2
	OR acc2, y2

	MASKNEZ t0, y3, y3
	MASKEQZ t0, acc3, acc3
	OR acc3, y3

	MOVV y0, (8*0)(res_ptr)
	MOVV y1, (8*1)(res_ptr)
	MOVV y2, (8*2)(res_ptr)
	MOVV y3, (8*3)(res_ptr)

	RET

/* ---------------------------------------*/
// func p256Select(res *SM2P256Point, table *p256Table, idx, limit int)
TEXT ·p256Select(SB),NOSPLIT,$0
	MOVV	limit+24(FP), x_ptr
	MOVV	idx+16(FP), const0
	MOVV	table+8(FP), y_ptr
	MOVV	res+0(FP), res_ptr

	MOVV    $0, x0
	MOVV    $0, x1
	MOVV    $0, x2
	MOVV    $0, x3
	MOVV    $0, y0
	MOVV    $0, y1
	MOVV    $0, y2
	MOVV    $0, y3
	MOVV    $0, t0
	MOVV    $0, t1
	MOVV    $0, t2
	MOVV    $0, t3

	MOVV	$0, const1

loop_select:
		ADDV $1, const1, const1
		XOR  const1, const0, hlp0

		MOVV    (8*0)(y_ptr), acc0
		MOVV    (8*1)(y_ptr), acc1
		MOVV    (8*2)(y_ptr), acc2
		MOVV    (8*3)(y_ptr), acc3
		MASKNEZ hlp0, acc0, acc0
		MASKNEZ hlp0, acc1, acc1
		MASKNEZ hlp0, acc2, acc2
		MASKNEZ hlp0, acc3, acc3
		OR   acc0, x0, x0
		OR   acc1, x1, x1
		OR   acc2, x2, x2
		OR   acc3, x3, x3

		ADDVU $32, y_ptr, y_ptr
		MOVV    (8*0)(y_ptr), acc0
		MOVV    (8*1)(y_ptr), acc1
		MOVV    (8*2)(y_ptr), acc2
		MOVV    (8*3)(y_ptr), acc3
		MASKNEZ hlp0, acc0, acc0
		MASKNEZ hlp0, acc1, acc1
		MASKNEZ hlp0, acc2, acc2
		MASKNEZ hlp0, acc3, acc3
		OR   acc0, y0, y0
		OR   acc1, y1, y1
		OR   acc2, y2, y2
		OR   acc3, y3, y3

		ADDVU $32, y_ptr, y_ptr
		MOVV    (8*0)(y_ptr), acc0
		MOVV    (8*1)(y_ptr), acc1
		MOVV    (8*2)(y_ptr), acc2
		MOVV    (8*3)(y_ptr), acc3
		MASKNEZ hlp0, acc0, acc0
		MASKNEZ hlp0, acc1, acc1
		MASKNEZ hlp0, acc2, acc2
		MASKNEZ hlp0, acc3, acc3
		OR   acc0, t0, t0
		OR   acc1, t1, t1
		OR   acc2, t2, t2
		OR   acc3, t3, t3

		BNE const1, x_ptr, loop_select

	MOVV    x0, (8*0)(res_ptr)
	MOVV    x1, (8*1)(res_ptr)
	MOVV    x2, (8*2)(res_ptr)
	MOVV    x3, (8*3)(res_ptr)
	MOVV    y0, (8*4)(res_ptr)
	MOVV    y1, (8*5)(res_ptr)
	MOVV    y2, (8*6)(res_ptr)
	MOVV    y3, (8*7)(res_ptr)
	MOVV    t0, (8*8)(res_ptr)
	MOVV    t1, (8*9)(res_ptr)
	MOVV    t2, (8*10)(res_ptr)
	MOVV    t3, (8*11)(res_ptr)

	RET

/* ---------------------------------------*/
// func p256SelectAffine(res *p256AffinePoint, table *p256AffineTable, idx int)
TEXT ·p256SelectAffine(SB),NOSPLIT,$0
	MOVD	idx+16(FP), t0
	MOVD	table+8(FP), t1
	MOVD	res+0(FP), res_ptr

	XOR	x0, x0, x0
	XOR	x1, x1, x1
	XOR	x2, x2, x2
	XOR	x3, x3, x3
	XOR	y0, y0, y0
	XOR	y1, y1, y1
	XOR	y2, y2, y2
	XOR	y3, y3, y3

	MOVV	$0, t2
	MOVV	$32, const0

loop_select:
		ADDV $1, t2, t2
		XOR  t2, t0, hlp0

		MOVV    (8*0)(t1), acc0
		MOVV    (8*1)(t1), acc1
		MOVV    (8*2)(t1), acc2
		MOVV    (8*3)(t1), acc3
		MASKNEZ hlp0, acc0, acc0
		MASKNEZ hlp0, acc1, acc1
		MASKNEZ hlp0, acc2, acc2
		MASKNEZ hlp0, acc3, acc3
		OR   acc0, x0, x0
		OR   acc1, x1, x1
		OR   acc2, x2, x2
		OR   acc3, x3, x3

		ADDVU $32, t1, t1
		MOVV    (8*0)(t1), acc0
		MOVV    (8*1)(t1), acc1
		MOVV    (8*2)(t1), acc2
		MOVV    (8*3)(t1), acc3
		MASKNEZ hlp0, acc0, acc0
		MASKNEZ hlp0, acc1, acc1
		MASKNEZ hlp0, acc2, acc2
		MASKNEZ hlp0, acc3, acc3
		OR   acc0, y0, y0
		OR   acc1, y1, y1
		OR   acc2, y2, y2
		OR   acc3, y3, y3

		BNE t2, const0, loop_select
	MOVV    x0, (8*0)(res_ptr)
	MOVV    x1, (8*1)(res_ptr)
	MOVV    x2, (8*2)(res_ptr)
	MOVV    x3, (8*3)(res_ptr)
	MOVV    y0, (8*4)(res_ptr)
	MOVV    y1, (8*5)(res_ptr)
	MOVV    y2, (8*6)(res_ptr)
	MOVV    y3, (8*7)(res_ptr)		
	RET

/* ---------------------------------------*/
// func p256Sub(res, in1, in2 *p256Element)
TEXT ·p256Sub(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV in1+8(FP), x_ptr
	MOVV in2+16(FP), y_ptr
	MOVV (8*0)(x_ptr), y0
	MOVV (8*1)(x_ptr), y1
	MOVV (8*2)(x_ptr), y2
	MOVV (8*3)(x_ptr), y3

	MOVV (8*0)(y_ptr), x0
	MOVV (8*1)(y_ptr), x1
	MOVV (8*2)(y_ptr), x2
	MOVV (8*3)(y_ptr), x3

	MOVV p256one<>+0x08(SB), const0
	ADDV $1, const0, const1

	CALL sm2P256Subinternal<>(SB)

	MOVV x0, (8*0)(res_ptr)
	MOVV x1, (8*1)(res_ptr)
	MOVV x2, (8*2)(res_ptr)
	MOVV x3, (8*3)(res_ptr)
	RET

/* ---------------------------------------*/
// (x3, x2, x1, x0) = (y3, y2, y1, y0) - (x3, x2, x1, x0)	
TEXT sm2P256Subinternal<>(SB),NOSPLIT,$0
	SGTU x0, y0, t0
	SUBV x0, y0, acc0
	// SBCS x1, y1
	SGTU x1, y1, t1
	SUBV x1, y1, acc1
	SGTU t0, acc1, t2
	SUBV t0, acc1, acc1
	OR t1, t2, t0
	// SBCS x2, y2
	SGTU x2, y2, t1
	SUBV x2, y2, acc2
	SGTU t0, acc2, t2
	SUBV t0, acc2, acc2
	OR t1, t2, t0
	// SBCS x3, y3
	SGTU x3, y3, t1
	SUBV x3, y3, acc3
	SGTU t0, acc3, t2
	SUBV t0, acc3, acc3
	OR t1, t2, t0

	MOVV $1, t1
	MASKEQZ t0, t1, t1
	MASKEQZ t0, const0, t3
	MASKEQZ t0, const1, t2

	SGTU t1, acc0, hlp0
	SUBV t1, acc0, x0
	ADDV hlp0, t3, t3       // no carry
	SGTU t3, acc1, t1
	SUBV t3, acc1, x1
	SGTU t1, acc2, hlp0
	SUBV t1, acc2, x2
	ADDV hlp0, t2, t1       // no carry
	SUBV t1, acc3, x3

	RET

/* ---------------------------------------*/
// (x3, x2, x1, x0) = 2(y3, y2, y1, y0)
#define p256MulBy2Inline       \
	SRLV $63, y0, t0;  \
	SLLV $1, y0, x0;  \
	SRLV $63, y1, t1;  \
	SLLV $1, y1, x1;  \
	ADDV t0, x1, x1;  \
	SRLV $63, y2, t2;  \
	SLLV $1, y2, x2;  \
	ADDV t1, x2, x2;  \
	SRLV $63, y3, t3;  \
	SLLV $1, y3, x3;  \
	ADDV t2, x3, x3;  \
	;\
	ADDV $1, x0, acc4;  \
	SGTU x0, acc4, t0;  \
	ADDV const0, t0, t0;  \
	ADDV x1, t0, acc5;  \
	SGTU x1, acc5, t0;  \
	ADDV t0, x2, acc6;  \
	SGTU x2, acc6, t0;  \
	ADDV const1, t0, t0;  \
	ADDV x3, t0, acc7;  \
	SGTU x3, acc7, t0;  \
	OR t0, t3, t0;  \
	MASKNEZ t0, x0, x0;  \
	MASKEQZ t0, acc4, acc4;  \
	OR acc4, x0;  \
	MASKNEZ t0, x1, x1;  \
	MASKEQZ t0, acc5, acc5;  \
	OR acc5, x1;  \
	MASKNEZ t0, x2, x2;  \
	MASKEQZ t0, acc6, acc6;  \
	OR acc6, x2;  \
	MASKNEZ t0, x3, x3;  \
	MASKEQZ t0, acc7, acc7;  \
	OR acc7, x3

/* ---------------------------------------*/
// func p256MulBy2(res, in *p256Element)
TEXT ·p256MulBy2(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV in+8(FP), x_ptr
	MOVV (8*0)(x_ptr), y0
	MOVV (8*1)(x_ptr), y1
	MOVV (8*2)(x_ptr), y2
	MOVV (8*3)(x_ptr), y3
	MOVV p256one<>+0x08(SB), const0
	ADDV $1, const0, const1
	p256MulBy2Inline
	MOVV x0, (8*0)(res_ptr)
	MOVV x1, (8*1)(res_ptr)
	MOVV x2, (8*2)(res_ptr)
	MOVV x3, (8*3)(res_ptr)
	RET

/* ---------------------------------------*/
#define x1in(off) (off)(a_ptr)
#define y1in(off) (off + 32)(a_ptr)
#define z1in(off) (off + 64)(a_ptr)
#define x2in(off) (off)(b_ptr)
#define z2in(off) (off + 64)(b_ptr)
#define x3out(off) (off)(res_ptr)
#define y3out(off) (off + 32)(res_ptr)
#define z3out(off) (off + 64)(res_ptr)
#define LDx(src) MOVV src(0), x0; MOVV src(8) x1; MOVV src(16), x2; MOVV src(24), x3
#define LDy(src) MOVV src(0), y0; MOVV src(8) y1; MOVV src(16), y2; MOVV src(24), y3
#define STx(src) MOVV x0, src(0); MOVV x1, src(8); MOVV x2, src(16); MOVV x3, src(24)
#define STy(src) MOVV y0, src(0); MOVV y1, src(8); MOVV y2, src(16); MOVV y3, src(24)
/* ---------------------------------------*/
#define y2in(off)  (32*0 + 8 + off)(RSP)
#define s2(off)    (32*1 + 8 + off)(RSP)
#define z1sqr(off) (32*2 + 8 + off)(RSP)
#define h(off)	   (32*3 + 8 + off)(RSP)
#define r(off)	   (32*4 + 8 + off)(RSP)
#define hsqr(off)  (32*5 + 8 + off)(RSP)
#define rsqr(off)  (32*6 + 8 + off)(RSP)
#define hcub(off)  (32*7 + 8 + off)(RSP)

#define z2sqr(off) (32*8 + 8 + off)(RSP)
#define s1(off) (32*9 + 8 + off)(RSP)
#define u1(off) (32*10 + 8 + off)(RSP)
#define u2(off) (32*11 + 8 + off)(RSP)

/* ---------------------------------------*/
// func p256PointAddAffineAsm(res, in1 *SM2P256Point, in2 *p256AffinePoint, sign, sel, zero int)
TEXT ·p256PointAddAffineAsm(SB),0,$264-48
	MOVV	in1+8(FP), a_ptr
	MOVV	in2+16(FP), b_ptr
	MOVV	sign+24(FP), hlp0
	MOVV	sel+32(FP), hlp1
	MOVV	zero+40(FP), res_ptr

	MOVV p256one<>+0x08(SB), const0
	ADDV $1, const0, const1

	// Negate y2in based on sign
	MOVV (8*0)(b_ptr), y0
	MOVV (8*1)(b_ptr), y1
	MOVV (8*2)(b_ptr), y2
	MOVV (8*3)(b_ptr), y3
	// (acc0, acc1, acc2, acc3) = - (y3, y2, y1, y0)
	SGTU y0, ZERO, t3
	SUBV y0, ZERO, acc0
	SGTU y1, ZERO, t4
	SUBV y1, ZERO, acc1
	SGTU t3, acc1, t1
	SUBV t3, acc1, acc1
	OR t4, t1, t3
	SGTU y2, ZERO, t4
	SUBV y2, ZERO, acc2
	SGTU t3, acc2, t1
	SUBV t3, acc2, acc2
	OR t4, t1, t3
	SGTU y3, ZERO, t4
	SUBV y3, ZERO, acc3
	SGTU t3, acc3, t1
	SUBV t3, acc3, acc3
	OR t4, t1, t3

	MOVV $1, acc4
	MASKEQZ t3, acc4, acc4
	MASKEQZ t3, const0, acc5
	MASKEQZ t3, const1, acc7

	SGTU acc4, acc0, t3
	SUBV acc4, acc0, acc0
	ADDV t3, acc5, acc5       // no carry
	SGTU acc5, acc1, t3
	SUBV acc5, acc1, acc1
	SGTU t3, acc2, t1
	SUBV t3, acc2, acc2
	ADDV t1, acc7, t3       // no carry
	SUBV t3, acc3, acc3
	// If condition is 0, keep original value
	MASKEQZ hlp0, acc0, acc0
	MASKNEZ hlp0, y0, y0
	MASKEQZ hlp0, acc1, acc1
	MASKNEZ hlp0, y1, y1
	MASKEQZ hlp0, acc2, acc2
	MASKNEZ hlp0, y2, y2
	MASKEQZ hlp0, acc3, acc3
	MASKNEZ hlp0, y3, y3
	OR acc0, y0
	OR acc1, y1
	OR acc2, y2
	OR acc3, y3
	// Store result
	STy(y2in)

	// Begin point add
	LDx(z1in)
	CALL	sm2P256SqrInternal<>(SB)    // z1ˆ2
	STy(z1sqr)

	LDx(x2in)
	CALL	sm2P256MulInternal<>(SB)    // x2 * z1ˆ2

	LDx(x1in)
	CALL	sm2P256Subinternal<>(SB)    // h = u2 - u1
	STx(h)

	LDy(z1in)
	CALL	p256MulInternal<>(SB)    // z3 = h * z1

	// iff select == 0, z3 = z1
	MOVV (8*8)(a_ptr), acc0
	MOVV (8*9)(a_ptr), acc1
	MOVV (8*10)(a_ptr), acc2
	MOVV (8*11)(a_ptr), acc3
	MASKEQZ hlp1, y0, y0
	MASKNEZ hlp1, acc0, acc0
	MASKEQZ hlp1, y1, y1
	MASKNEZ hlp1, acc1, acc1
	MASKEQZ hlp1, y2, y2
	MASKNEZ hlp1, acc2, acc2
	MASKEQZ hlp1, y3, y3
	MASKNEZ hlp1, acc3, acc3
	OR acc0, y0
	OR acc1, y1
	OR acc2, y2
	OR acc3, y3
	// iff zero == 0, z3 = 1
	MOVV $1, acc0
	MOVV const0, acc1
	MOVV $0, acc2
	MOVV const1, acc3
	MASKEQZ res_ptr, y0, y0
	MASKNEZ res_ptr, acc0, acc0
	MASKEQZ res_ptr, y1, y1
	MASKNEZ res_ptr, acc1, acc1
	MASKEQZ res_ptr, y2, y2
	MASKNEZ res_ptr, acc2, acc2
	MASKEQZ res_ptr, y3, y3
	MASKNEZ res_ptr, acc3, acc3
	OR acc0, y0
	OR acc1, y1
	OR acc2, y2
	OR acc3, y3
	LDx(z1in)
	// store z3
	MOVV res+0(FP), t0
	MOVV y0, (8*8)(t0)
	MOVV y1, (8*9)(t0)
	MOVV y2, (8*10)(t0)
	MOVV y3, (8*11)(t0)

	LDy(z1sqr)
	CALL	p256MulInternal<>(SB)    // z1 ^ 3

	LDx(y2in)
	CALL	p256MulInternal<>(SB)    // s2 = y2 * z1ˆ3
	STy(s2)

	LDx(y1in)
	CALL	p256SubInternal<>(SB)    // r = s2 - s1
	STx(r)

	CALL	p256SqrInternal<>(SB)    // rsqr = rˆ2
	STy	(rsqr)

	LDx(h)
	CALL	p256SqrInternal<>(SB)    // hsqr = hˆ2
	STy(hsqr)

	CALL	p256MulInternal<>(SB)    // hcub = hˆ3
	STy(hcub)

	LDx(y1in)
	CALL	p256MulInternal<>(SB)    // y1 * hˆ3
	STy(s2)

	MOVV hsqr(0*8), x0
	MOVV hsqr(1*8), x1
	MOVV hsqr(2*8), x2
	MOVV hsqr(3*8), x3
	CALL	p256MulInternal<>(SB)    // hsqr * u1
	MOVV y0, h(0*8)
	MOVV y1, h(1*8)
	MOVV y2, h(2*8)
	MOVV y3, h(3*8)

	p256MulBy2Inline               // u1 * hˆ2 * 2, inline

	LDy(rsqr)
	CALL	p256SubInternal<>(SB)    // rˆ2 - u1 * hˆ2 * 2

	MOVV x0, y0 
	MOVV x1, y1
	MOVV x2, y2
	MOVV x3, y3
	LDy(hcub)
	CALL	p256SubInternal<>(SB)

	MOVV (8*0)(a_ptr), acc0
	MOVV (8*1)(a_ptr), acc1
	MOVV (8*2)(a_ptr), acc2
	MOVV (8*3)(a_ptr), acc3
	// iff select == 0, x3 = x1
	MASKEQZ hlp1, x0, x0 
	MASKNEZ hlp1, acc0, acc0
	MASKEQZ hlp1, x1, x1
	MASKNEZ hlp1, acc1, acc1
	MASKEQZ hlp1, x2, x2
	MASKNEZ hlp1, acc2, acc2
	MASKEQZ hlp1, x3, x3
	MASKNEZ hlp1, acc3, acc3
	OR acc0, x0
	OR acc1, x1
	OR acc2, x2
	OR acc3, x3
	MOVV (8*0)(b_ptr), acc0
	MOVV (8*1)(b_ptr), acc1
	MOVV (8*2)(b_ptr), acc2
	MOVV (8*3)(b_ptr), acc3
	// iff zero == 0, x3 = x2
	MASKEQZ res_ptr, x0, x0
	MASKNEZ res_ptr, acc0, acc0
	MASKEQZ res_ptr, x1, x1
	MASKNEZ res_ptr, acc1, acc1
	MASKEQZ res_ptr, x2, x2
	MASKNEZ res_ptr, acc2, acc2
	MASKEQZ res_ptr, x3, x3
	MASKNEZ res_ptr, acc3, acc3
	OR acc0, x0
	OR acc1, x1
	OR acc2, x2
	OR acc3, x3
	// store x3
	MOVV res+0(FP), t0
	MOVV x0, (8*0)(t0)
	MOVV x1, (8*1)(t0)
	MOVV x2, (8*2)(t0)
	MOVV x3, (8*3)(t0)

	MOVV h(0*8), y0 
	MOVV h(1*8), y1
	MOVV h(2*8), y2
	MOVV h(3*8), y3
	CALL	p256SubInternal<>(SB)

	MOVV r(0*8), y0 
	MOVV r(1*8), y1
	MOVV r(2*8), y2
	MOVV r(3*8), y3
	CALL	p256MulInternal<>(SB)

	MOVV s2(0*8), x0 
	MOVV s2(1*8), x1
	MOVV s2(2*8), x2
	MOVV s2(3*8), x3
	CALL	p256SubInternal<>(SB)

	MOVV (8*4)(a_ptr), acc0
	MOVV (8*5)(a_ptr), acc1
	MOVV (8*6)(a_ptr), acc2
	MOVV (8*7)(a_ptr), acc3
	// iff select == 0, y3 = y1
	MASKEQZ hlp1, x0, x0
	MASKNEZ hlp1, acc0, acc0
	MASKEQZ hlp1, x1, x1
	MASKNEZ hlp1, acc1, acc1
	MASKEQZ hlp1, x2, x2
	MASKNEZ hlp1, acc2, acc2
	MASKEQZ hlp1, x3, x3
	MASKNEZ hlp1, acc3, acc3
	OR acc0, x0
	OR acc1, x1
	OR acc2, x2
	OR acc3, x3
	MOVV y2in(0*8), acc0
	MOVV y2in(1*8), acc1
	MOVV y2in(2*8), acc2
	MOVV y2in(3*8), acc3
	// iff zero == 0, y3 = y2
	MASKEQZ res_ptr, x0, x0
	MASKNEZ res_ptr, acc0, acc0
	MASKEQZ res_ptr, x1, x1
	MASKNEZ res_ptr, acc1, acc1
	MASKEQZ res_ptr, x2, x2
	MASKNEZ res_ptr, acc2, acc2
	MASKEQZ res_ptr, x3, x3
	MASKNEZ res_ptr, acc3, acc3
	OR acc0, x0
	OR acc1, x1
	OR acc2, x2
	OR acc3, x3
	// store y3
	MOVV res+0(FP), t0
	MOVV x0, (8*4)(t0)
	MOVV x1, (8*5)(t0)
	MOVV x2, (8*6)(t0)
	MOVV x3, (8*7)(t0)

	RET

// (x3, x2, x1, x0) = (x3, x2, x1, x0) + (y3, y2, y1, y0)
#define p256AddInline          \
	ADDV x0, y0, x0;  \
	SGTU y0, x0, t0;  \
	ADDV x1, y1, x1;  \
	SGTU y1, x1, t1;  \
	ADDV t0, x1, x1;  \
	SGTU t0, x1, t2;  \
	OR t1, t2, t0;  \
	ADDV x2, y2, x2;  \
	SGTU y2, x2, t1;  \
	ADDV t0, x2, x2;  \
	SGTU t0, x2, t2;  \
	OR t1, t2, t0;  \
	ADDV x3, y3, x3;  \
	SGTU y3, x3, t1;  \
	ADDV t0, x3, x3;  \
	SGTU t0, x3, t2;  \
	OR t1, t2, t2;  \
	;\
	ADDV $1, x0, acc4;  \
	SGTU x0, acc4, t0;  \
	ADDV const0, t0, t0;  \
	ADDV x1, t0, acc5;  \
	SGTU x1, acc5, t0;  \
	ADDV t0, x2, acc6;  \
	SGTU x2, acc6, t0;  \
	ADDV const1, t0, t0;  \
	ADDV x3, t0, acc7;  \
	SGTU x3, acc7, t0;  \
	OR t0, t2, t0;  \
	MASKNEZ t0, x0, x0;  \
	MASKEQZ t0, acc4, acc4;  \
	OR acc4, x0;  \
	MASKNEZ t0, x1, x1;  \
	MASKEQZ t0, acc5, acc5;  \
	OR acc5, x1;  \
	MASKNEZ t0, x2, x2;  \
	MASKEQZ t0, acc6, acc6;  \
	OR acc6, x2;  \
	MASKNEZ t0, x3, x3;  \
	MASKEQZ t0, acc7, acc7;  \
	OR acc7, x3


/* ---------------------------------------*/
// func p256Add(res, in1, in2 *p256Element)
TEXT ·p256Add(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV in1+8(FP), x_ptr
	MOVV in2+16(FP), y_ptr
	MOVV (8*0)(x_ptr), y0
	MOVV (8*1)(x_ptr), y1
	MOVV (8*2)(x_ptr), y2
	MOVV (8*3)(x_ptr), y3

	MOVV (8*0)(y_ptr), x0
	MOVV (8*1)(y_ptr), x1
	MOVV (8*2)(y_ptr), x2
	MOVV (8*3)(y_ptr), x3

	MOVV p256one<>+0x08(SB), const0
	ADDV $1, const0, const1

	p256AddInline

	MOVV x0, (8*0)(res_ptr)
	MOVV x1, (8*1)(res_ptr)
	MOVV x2, (8*2)(res_ptr)
	MOVV x3, (8*3)(res_ptr)
	RET

// (y3, y2, y1, y0) = (y3, y2, y1, y0) / 2
#define p256DivideBy2 \
	MOVV $1, acc1;  \
	AND t1, y0, t0;  \
	MASKEQZ t0, acc1, acc1
	MASKEQZ t0, const0, acc2;  \
	MASKEQZ t0, const1, acc3;  \
	SGTU acc1, y0, t1;  \
	SUBV acc1, y0, y0;  \
	ADDV t1, acc2, acc2;  \
	SRLV $1, y0, y0;  \
	SGTU acc2, y1, t1;  \
	SUBV acc2, y1, y1;  \
	SGTU t1, y2, t2;  \
	SUBV t1, y2, y2;  \
	BSTRINSV $63, y1, $63, y0;  \
	SRLV $1, y1, y1;  \
	ADDV t2, acc3, acc3;  \
	BSTRINSV $63, y2, $63, y1;  \
	SRLV $1, y2, y2;  \
	SUBV acc3, y3, t1;  \
	SGTU y3, acc3, t2;  \
	BSTRINSV $63, t1, $63, y2;  \
	SRLV $1, t1, y3;  \
	MASKEQZ t0, t2, t2;  \
	BSTRINSV $63, t2, $63, y3

/* ---------------------------------------*/
// func p256DivBy2(res, in *p256Element)
TEXT ·p256DivBy2(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV in+8(FP), x_ptr
	MOVV (8*0)(x_ptr), y0
	MOVV (8*1)(x_ptr), y1
	MOVV (8*2)(x_ptr), y2
	MOVV (8*3)(x_ptr), y3
	MOVV p256one<>+0x08(SB), const0
	ADDV $1, const0, const1
	p256DivideBy2
	MOVV y0, (8*0)(res_ptr)
	MOVV y1, (8*1)(res_ptr)
	MOVV y2, (8*2)(res_ptr)
	MOVV y3, (8*3)(res_ptr)
	RET

#define s(off)	(32*0 + 8 + off)(RSP)
#define m(off)	(32*1 + 8 + off)(RSP)
#define zsqr(off) (32*2 + 8 + off)(RSP)
#define tmp(off)  (32*3 + 8 + off)(RSP)

//func p256PointDoubleAsm(res, in *SM2P256Point)
TEXT ·p256PointDoubleAsm(SB),NOSPLIT,$136-16
	MOVV	res+0(FP), res_ptr
	MOVV	in+8(FP), a_ptr

	MOVV p256one<>+0x08(SB), const0
	ADDV $1, const0, const1

	// Begin point double
	MOVV (8*8)(a_ptr), x0 
	MOVV (8*9)(a_ptr), x1
	MOVV (8*10)(a_ptr), x2
	MOVV (8*11)(a_ptr), x3
	CALL	sm2P256SqrInternal<>(SB)    // z1ˆ2
	MOVV y0, zsqr(0*8)                  // store z^2
	MOVV y1, zsqr(1*8)
	MOVV y2, zsqr(2*8)
	MOVV y3, zsqr(3*8)

	MOVV (8*0)(a_ptr), x0               // load x
	MOVV (8*1)(a_ptr), x1
	MOVV (8*2)(a_ptr), x2
	MOVV (8*3)(a_ptr), x3
	p256AddInline
	STx(m)

	LDx(z1in)
	LDy(y1in)
	CALL	sm2P256MulInternal<>(SB)
	p256MulBy2Inline
	STx(z3out)

	LDy(x1in)
	LDx(zsqr)
	CALL	sm2P256Subinternal<>(SB)
	LDy(m)
	CALL	sm2P256MulInternal<>(SB)

	// Multiply by 3
	p256MulBy2Inline
	p256AddInline
	STx(m)

	LDy(y1in)
	p256MulBy2Inline
	CALL	sm2P256SqrInternal<>(SB)
	STy(s)
	MOVV	y0, x0
	MOVV	y1, x1
	MOVV	y2, x2
	MOVV	y3, x3
	CALL	sm2P256SqrInternal<>(SB)

	// Divide by 2
	p256DivideBy2

	STy(y3out)

	LDx(x1in)
	LDy(s)
	CALL	sm2P256MulInternal<>(SB)
	STy(s)
	p256MulBy2Inline
	STx(tmp)

	LDx(m)
	CALL	sm2P256SqrInternal<>(SB)
	LDx(tmp)
	CALL	sm2P256Subinternal<>(SB)

	STx(x3out)

	LDy(s)
	CALL	sm2P256Subinternal<>(SB)

	LDy(m)
	CALL	sm2P256MulInternal<>(SB)

	LDx(y3out)
	CALL	sm2P256Subinternal<>(SB)
	STx(y3out)

	RET

#define p256PointDoubleRound() \
	LDx(z3out)                       \ // load z
	CALL	sm2P256SqrInternal<>(SB) \
	MOVV y0, zsqr(0*8)          \ // store z^2
	MOVV y1, zsqr(1*8)          \
	MOVV y2, zsqr(2*8)          \
	MOVV y3, zsqr(3*8)          \
	\
	LDx(x3out)                       \// load x
	p256AddInline                    \
	STx(m)                           \
	\
	LDx(z3out)                       \ // load z
	LDy(y3out)                       \ // load y
	CALL	sm2P256MulInternal<>(SB) \
	p256MulBy2Inline                 \
	STx(z3out)                       \ // store result z
	\
	LDy(x3out)                       \ // load x
	LDx(zsqr)                        \
	CALL	sm2P256Subinternal<>(SB) \
	LDy(m)                           \
	CALL	sm2P256MulInternal<>(SB) \
	\
	\// Multiply by 3
	p256MulBy2Inline                 \
	p256AddInline                    \
	STx(m)                           \
	\
	LDy(y3out)                       \  // load y
	p256MulBy2Inline                 \
	CALL	sm2P256SqrInternal<>(SB) \
	STy(s)                           \
	MOVV	y0, x0                   \
	MOVV	y1, x1                   \
	MOVV	y2, x2                   \
	MOVV	y3, x3                   \
	CALL	sm2P256SqrInternal<>(SB) \
	\
	\// Divide by 2
	p256DivideBy2                    \
	STy(y3out)                       \                
	\
	LDx(x3out)                       \  // load x
	LDy(s)                           \
	CALL	sm2P256MulInternal<>(SB) \
	STy(s)                           \
	p256MulBy2Inline                 \
	STx(tmp)                         \
	\
	LDx(m)                           \
	CALL	sm2P256SqrInternal<>(SB) \
	LDx(tmp)                         \
	CALL	sm2P256Subinternal<>(SB) \
	\
	STx(x3out)                       \
	\
	LDy(s)                           \
	CALL	sm2P256Subinternal<>(SB) \
	\
	LDy(m)                           \
	CALL	sm2P256MulInternal<>(SB) \
	\
	LDx(y3out)                       \
	CALL	sm2P256Subinternal<>(SB) \
	STx(y3out)                       \


/* ---------------------------------------*/
//func p256PointDouble6TimesAsm(res, in *SM2P256Point)
TEXT ·p256PointDouble6TimesAsm(SB),NOSPLIT,$136-16
	MOVV	res+0(FP), res_ptr
	MOVV	in+8(FP), a_ptr

	MOVV p256one<>+0x08(SB), const0
	ADDV $1, const0, const1

	// Begin point double
	MOVV (8*8)(a_ptr), x0 
	MOVV (8*9)(a_ptr), x1
	MOVV (8*10)(a_ptr), x2
	MOVV (8*11)(a_ptr), x3
	CALL	sm2P256SqrInternal<>(SB)    // z1ˆ2
	MOVV y0, zsqr(0*8)                  // store z^2
	MOVV y1, zsqr(1*8)
	MOVV y2, zsqr(2*8)
	MOVV y3, zsqr(3*8)

	MOVV (8*0)(a_ptr), x0               // load x
	MOVV (8*1)(a_ptr), x1
	MOVV (8*2)(a_ptr), x2
	MOVV (8*3)(a_ptr), x3
	p256AddInline
	STx(m)

	LDx(z1in)
	LDy(y1in)
	CALL	sm2P256MulInternal<>(SB)
	p256MulBy2Inline
	STx(z3out)

	LDy(x1in)
	LDx(zsqr)
	CALL	sm2P256Subinternal<>(SB)
	LDy(m)
	CALL	sm2P256MulInternal<>(SB)

	// Multiply by 3
	p256MulBy2Inline
	p256AddInline
	STx(m)

	LDy(y1in)
	p256MulBy2Inline
	CALL	sm2P256SqrInternal<>(SB)
	STy(s)
	MOVV	y0, x0
	MOVV	y1, x1
	MOVV	y2, x2
	MOVV	y3, x3
	CALL	sm2P256SqrInternal<>(SB)

	// Divide by 2
	p256DivideBy2

	STy(y3out)

	LDx(x1in)
	LDy(s)
	CALL	sm2P256MulInternal<>(SB)
	STy(s)
	p256MulBy2Inline
	STx(tmp)

	LDx(m)
	CALL	sm2P256SqrInternal<>(SB)
	LDx(tmp)
	CALL	sm2P256Subinternal<>(SB)

	STx(x3out)

	LDy(s)
	CALL	sm2P256Subinternal<>(SB)

	LDy(m)
	CALL	sm2P256MulInternal<>(SB)

	LDx(y3out)
	CALL	sm2P256Subinternal<>(SB)
	STx(y3out)

	// Begin point double rounds 2 - 6
	p256PointDoubleRound()
	p256PointDoubleRound()
	p256PointDoubleRound()
	p256PointDoubleRound()
	p256PointDoubleRound()

	RET

/* ---------------------------------------*/
#undef y2in
#undef x3out
#undef y3out
#undef z3out
#define y2in(off) (off + 32)(b_ptr)
#define x3out(off) (off)(b_ptr)
#define y3out(off) (off + 32)(b_ptr)
#define z3out(off) (off + 64)(b_ptr)
// func p256PointAddAsm(res, in1, in2 *SM2P256Point) int
TEXT ·p256PointAddAsm(SB),0,$392-32
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
	// Move input to stack in order to free registers
	MOVV	in1+8(FP), a_ptr
	MOVV	in2+16(FP), b_ptr

	MOVV p256one<>+0x08(SB), const0
	ADDV $1, const0, const1

	// Begin point add
	LDx(z2in)
	CALL	sm2P256SqrInternal<>(SB)    // z2^2
	STy(z2sqr)

	CALL	sm2P256MulInternal<>(SB)    // z2^3

	LDx(y1in)
	CALL	sm2P256MulInternal<>(SB)    // s1 = z2ˆ3*y1
	STy(s1)

	LDx(z1in)
	CALL	sm2P256SqrInternal<>(SB)    // z1^2
	STy(z1sqr)

	CALL	sm2P256MulInternal<>(SB)    // z1^3

	LDx(y2in)
	CALL	sm2P256MulInternal<>(SB)    // s2 = z1ˆ3*y2

	LDx(s1)
	CALL	sm2P256Subinternal<>(SB)    // r = s2 - s1
	STx(r)

	// Check if zero mod p256
	OR x0, x1, acc0
	OR x2, x3, acc1
	OR acc0, acc1, acc1
	SGTU acc1, ZERO, hlp0

	MOVV $-1, acc0
	MOVV p256p<>+0x08(SB), acc1
	MOVV p256p<>+0x18(SB), acc3

	XOR acc0, x0, acc4
	XOR acc1, x1, acc5
	XOR acc0, x2, acc6
	XOR acc3, x3, acc7
	OR acc4, acc5, acc4
	OR acc6, acc7, acc7
	OR acc4, acc7, acc7
	SGTU acc7, ZERO, res_ptr
	OR hlp0, res_ptr, res_ptr

	LDx(z2sqr)
	LDy(x1in)
	CALL	sm2P256MulInternal<>(SB)    // u1 = x1 * z2ˆ2
	STy(u1)

	LDx(z1sqr)
	LDy(x2in)
	CALL	sm2P256MulInternal<>(SB)    // u2 = x2 * z1ˆ2
	STy(u2)

	LDx(u1)
	CALL	sm2P256Subinternal<>(SB)    // h = u2 - u1
	STx(h)

	// Check if zero mod p256
	OR x0, x1, acc0
	OR x2, x3, acc1
	OR acc0, acc1, acc1
	SGTU acc1, ZERO, hlp0

	MOVV $-1, acc0
	MOVV p256p<>+0x08(SB), acc1
	MOVV p256p<>+0x18(SB), acc3

	XOR acc0, x0, acc4
	XOR acc1, x1, acc5
	XOR acc0, x2, acc6
	XOR acc3, x3, acc7
	OR acc4, acc5, acc4
	OR acc6, acc7, acc7
	OR acc4, acc7, acc7
	SGTU acc7, ZERO, t0
	OR hlp0, t0, hlp0

	AND hlp0, res_ptr, res_ptr

	LDx(r)
	CALL	sm2P256SqrInternal<>(SB)    // rsqr = rˆ2
	STy(rsqr)

	LDx(h)
	CALL	sm2P256SqrInternal<>(SB)    // hsqr = hˆ2
	STy(hsqr)

	LDx(h)
	CALL	sm2P256MulInternal<>(SB)    // hcub = hˆ3
	STy(hcub)

	LDx(s1)
	CALL	sm2P256MulInternal<>(SB)
	STy(s2)

	LDx(z1in)
	LDy(z2in)
	CALL	sm2P256MulInternal<>(SB)    // z1 * z2
	LDx(h)
	CALL	sm2P256MulInternal<>(SB)    // z1 * z2 * h
	MOVV	res+0(FP), b_ptr
	STy(z3out)

	LDx(hsqr)
	LDy(u1)
	CALL	sm2P256MulInternal<>(SB)    // hˆ2 * u1
	STy(u2)

	p256MulBy2Inline               // u1 * hˆ2 * 2, inline
	LDy(rsqr)
	CALL	sm2P256Subinternal<>(SB)    // rˆ2 - u1 * hˆ2 * 2

	MOVV	x0, y0
	MOVV	x1, y1
	MOVV	x2, y2
	MOVV	x3, y3
	LDx(hcub)
	CALL	sm2P256Subinternal<>(SB)
	STx(x3out)

	LDy(u2)
	CALL	sm2P256Subinternal<>(SB)

	LDy(r)
	CALL	sm2P256MulInternal<>(SB)

	LDx(s2)
	CALL	sm2P256Subinternal<>(SB)
	STx(y3out)

	MOVV	res_ptr, ret+24(FP)

	RET
