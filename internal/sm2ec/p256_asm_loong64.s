// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.25 && !purego

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
#define t0 R13
#define t1 R14
#define t2 R15
#define t3 R16
#define t4 R17

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
	MOVV (8*3)(y_ptr), t4

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

	MASKNEZ t0, t4, t4
	MASKEQZ t0, acc3, acc3
	OR t4, acc3

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
	MOVV (8*7)(y_ptr), t4

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

	MASKNEZ t0, t4, t4
	MASKEQZ t0, acc3, acc3
	OR t4, acc3

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
	MOVV (8*11)(y_ptr), t4

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

	MASKNEZ t0, t4, t4
	MASKEQZ t0, acc3, acc3
	OR t4, acc3

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
