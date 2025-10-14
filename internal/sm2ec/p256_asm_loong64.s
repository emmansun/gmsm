// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

#define ZERO R0
#define res_ptr R4
#define x_ptr R5
#define y_ptr R6

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
	RET

/* ---------------------------------------*/
// func p256SelectAffine(res *p256AffinePoint, table *p256AffineTable, idx int)
TEXT ·p256SelectAffine(SB),NOSPLIT,$0
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
