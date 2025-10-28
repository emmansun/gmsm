// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

#define ZERO R0
#define res_ptr R4
#define a_ptr R5
#define b_ptr R6

/* ---------------------------------------*/
// func gfpCopy(res, a *gfP)
TEXT ·gfpCopy(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV a+8(FP), a_ptr

	MOVV ·supportLSX+0(SB), R7
	BEQ  R7, ZERO, basic_path

	MOVV ·supportLASX+0(SB), R7
	BEQ  R7, ZERO, lsx_path

	// LASX path
	XVMOVQ (a_ptr), X0
	XVMOVQ X0, (res_ptr)
	RET

lsx_path:
	VMOVQ (a_ptr), V0
	VMOVQ 16(a_ptr), V1
	VMOVQ V0, (res_ptr)
	VMOVQ V1, 16(res_ptr)
	RET

basic_path:
	MOVV (0*8)(a_ptr), R7
	MOVV (1*8)(a_ptr), R8
	MOVV (2*8)(a_ptr), R9
	MOVV (3*8)(a_ptr), R10
	MOVV R7, (0*8)(res_ptr)
	MOVV R8, (1*8)(res_ptr)
	MOVV R9, (2*8)(res_ptr)
	MOVV R10, (3*8)(res_ptr)

	RET


/* ---------------------------------------*/
// func gfp2Copy(res, a *gfP2)
TEXT ·gfp2Copy(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV a+8(FP), a_ptr

	MOVV ·supportLSX+0(SB), R7
	BEQ  R7, ZERO, basic_path

	MOVV ·supportLASX+0(SB), R7
	BEQ  R7, ZERO, lsx_path

	// LASX path
	XVMOVQ (a_ptr), X0
	XVMOVQ 32(a_ptr), X1
	XVMOVQ X0, (res_ptr)
	XVMOVQ X1, 32(res_ptr)
	RET

lsx_path:
	VMOVQ (a_ptr), V0
	VMOVQ 16(a_ptr), V1
	VMOVQ 32(a_ptr), V2
	VMOVQ 48(a_ptr), V3
	VMOVQ V0, (res_ptr)
	VMOVQ V1, 16(res_ptr)
	VMOVQ V2, 32(res_ptr)
	VMOVQ V3, 48(res_ptr)
	RET

basic_path:
	MOVV (0*8)(a_ptr), R7
	MOVV (1*8)(a_ptr), R8
	MOVV (2*8)(a_ptr), R9
	MOVV (3*8)(a_ptr), R10
	MOVV R7, (0*8)(res_ptr)
	MOVV R8, (1*8)(res_ptr)
	MOVV R9, (2*8)(res_ptr)
	MOVV R10, (3*8)(res_ptr)
	MOVV (4*8)(a_ptr), R7
	MOVV (5*8)(a_ptr), R8
	MOVV (6*8)(a_ptr), R9
	MOVV (7*8)(a_ptr), R10
	MOVV R7, (4*8)(res_ptr)
	MOVV R8, (5*8)(res_ptr)
	MOVV R9, (6*8)(res_ptr)
	MOVV R10, (7*8)(res_ptr)
	RET

/* ---------------------------------------*/
// func gfp4Copy(res, a *gfP4)
TEXT ·gfp4Copy(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV a+8(FP), a_ptr

	MOVV ·supportLSX+0(SB), R7
	BEQ  R7, ZERO, basic_path

	MOVV ·supportLASX+0(SB), R7
	BEQ  R7, ZERO, lsx_path

	// LASX path
	XVMOVQ (a_ptr), X0
	XVMOVQ 32(a_ptr), X1
	XVMOVQ 64(a_ptr), X2
	XVMOVQ 96(a_ptr), X3
	XVMOVQ X0, (res_ptr)
	XVMOVQ X1, 32(res_ptr)
	XVMOVQ X2, 64(res_ptr)
	XVMOVQ X3, 96(res_ptr)
	RET

lsx_path:
	VMOVQ (a_ptr), V0
	VMOVQ 16(a_ptr), V1
	VMOVQ 32(a_ptr), V2
	VMOVQ 48(a_ptr), V3
	VMOVQ 64(a_ptr), V4
	VMOVQ 80(a_ptr), V5
	VMOVQ 96(a_ptr), V6
	VMOVQ 112(a_ptr), V7
	VMOVQ V0, (res_ptr)
	VMOVQ V1, 16(res_ptr)
	VMOVQ V2, 32(res_ptr)
	VMOVQ V3, 48(res_ptr)
	VMOVQ V4, 64(res_ptr)
	VMOVQ V5, 80(res_ptr)
	VMOVQ V6, 96(res_ptr)
	VMOVQ V7, 112(res_ptr)
	RET

basic_path:
	MOVV (0*8)(a_ptr), R7
	MOVV (1*8)(a_ptr), R8
	MOVV (2*8)(a_ptr), R9
	MOVV (3*8)(a_ptr), R10
	MOVV R7, (0*8)(res_ptr)
	MOVV R8, (1*8)(res_ptr)
	MOVV R9, (2*8)(res_ptr)
	MOVV R10, (3*8)(res_ptr)
	MOVV (4*8)(a_ptr), R7
	MOVV (5*8)(a_ptr), R8
	MOVV (6*8)(a_ptr), R9
	MOVV (7*8)(a_ptr), R10
	MOVV R7, (4*8)(res_ptr)
	MOVV R8, (5*8)(res_ptr)
	MOVV R9, (6*8)(res_ptr)
	MOVV R10, (7*8)(res_ptr)
	MOVV (8*8)(a_ptr), R7
	MOVV (9*8)(a_ptr), R8
	MOVV (10*8)(a_ptr), R9
	MOVV (11*8)(a_ptr), R10
	MOVV R7, (8*8)(res_ptr)
	MOVV R8, (9*8)(res_ptr)
	MOVV R9, (10*8)(res_ptr)
	MOVV R10, (11*8)(res_ptr)
	MOVV (12*8)(a_ptr), R7
	MOVV (13*8)(a_ptr), R8
	MOVV (14*8)(a_ptr), R9
	MOVV (15*8)(a_ptr), R10
	MOVV R7, (12*8)(res_ptr)
	MOVV R8, (13*8)(res_ptr)
	MOVV R9, (14*8)(res_ptr)
	MOVV R10, (15*8)(res_ptr)
	RET

/* ---------------------------------------*/
// func gfp6Copy(res, a *gfP6)
TEXT ·gfp6Copy(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV a+8(FP), a_ptr

	MOVV ·supportLSX+0(SB), R7
	BEQ  R7, ZERO, basic_path

	MOVV ·supportLASX+0(SB), R7
	BEQ  R7, ZERO, lsx_path

	// LASX path
	XVMOVQ (a_ptr), X0
	XVMOVQ 32(a_ptr), X1
	XVMOVQ 64(a_ptr), X2
	XVMOVQ 96(a_ptr), X3
	XVMOVQ 128(a_ptr), X4
	XVMOVQ 160(a_ptr), X5
	XVMOVQ X0, (res_ptr)
	XVMOVQ X1, 32(res_ptr)
	XVMOVQ X2, 64(res_ptr)
	XVMOVQ X3, 96(res_ptr)
	XVMOVQ X4, 128(res_ptr)
	XVMOVQ X5, 160(res_ptr)
	RET

lsx_path:
	VMOVQ (a_ptr), V0
	VMOVQ 16(a_ptr), V1
	VMOVQ 32(a_ptr), V2
	VMOVQ 48(a_ptr), V3
	VMOVQ 64(a_ptr), V4
	VMOVQ 80(a_ptr), V5
	VMOVQ 96(a_ptr), V6
	VMOVQ 112(a_ptr), V7
	VMOVQ 128(a_ptr), V8
	VMOVQ 144(a_ptr), V9
	VMOVQ 160(a_ptr), V10
	VMOVQ 176(a_ptr), V11
	VMOVQ V0, (res_ptr)
	VMOVQ V1, 16(res_ptr)
	VMOVQ V2, 32(res_ptr)
	VMOVQ V3, 48(res_ptr)
	VMOVQ V4, 64(res_ptr)
	VMOVQ V5, 80(res_ptr)
	VMOVQ V6, 96(res_ptr)
	VMOVQ V7, 112(res_ptr)
	VMOVQ V8, 128(res_ptr)
	VMOVQ V9, 144(res_ptr)
	VMOVQ V10, 160(res_ptr)
	VMOVQ V11, 176(res_ptr)
	RET

basic_path:
	MOVV $6, R7
basic_path_loop:	
		MOVV (0*8)(a_ptr), R8
		MOVV (1*8)(a_ptr), R9
		MOVV (2*8)(a_ptr), R10
		MOVV (3*8)(a_ptr), R11
		MOVV R8, (0*8)(res_ptr)
		MOVV R9, (1*8)(res_ptr)
		MOVV R10, (2*8)(res_ptr)
		MOVV R11, (3*8)(res_ptr)
		ADDV $32, a_ptr
		ADDV $32, res_ptr
		SUBV $1, R7
		BNE  R7, basic_path_loop
	RET

/* ---------------------------------------*/
// func gfp12Copy(res, a *gfP12)
TEXT ·gfp12Copy(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV a+8(FP), a_ptr

	MOVV ·supportLSX+0(SB), R7
	BEQ  R7, ZERO, basic_path

	MOVV ·supportLASX+0(SB), R7
	BEQ  R7, ZERO, lsx_path

	// LASX path
	XVMOVQ (a_ptr), X0
	XVMOVQ 32(a_ptr), X1
	XVMOVQ 64(a_ptr), X2
	XVMOVQ 96(a_ptr), X3
	XVMOVQ 128(a_ptr), X4
	XVMOVQ 160(a_ptr), X5
	XVMOVQ 192(a_ptr), X6
	XVMOVQ 224(a_ptr), X7
	XVMOVQ 256(a_ptr), X8
	XVMOVQ 288(a_ptr), X9
	XVMOVQ 320(a_ptr), X10
	XVMOVQ 352(a_ptr), X11
	XVMOVQ X0, (res_ptr)
	XVMOVQ X1, 32(res_ptr)
	XVMOVQ X2, 64(res_ptr)
	XVMOVQ X3, 96(res_ptr)
	XVMOVQ X4, 128(res_ptr)
	XVMOVQ X5, 160(res_ptr)
	XVMOVQ X6, 192(res_ptr)
	XVMOVQ X7, 224(res_ptr)
	XVMOVQ X8, 256(res_ptr)
	XVMOVQ X9, 288(res_ptr)
	XVMOVQ X10, 320(res_ptr)
	XVMOVQ X11, 352(res_ptr)
	RET

lsx_path:
	VMOVQ (a_ptr), V0
	VMOVQ 16(a_ptr), V1
	VMOVQ 32(a_ptr), V2
	VMOVQ 48(a_ptr), V3
	VMOVQ 64(a_ptr), V4
	VMOVQ 80(a_ptr), V5
	VMOVQ 96(a_ptr), V6
	VMOVQ 112(a_ptr), V7
	VMOVQ V0, (res_ptr)
	VMOVQ V1, 16(res_ptr)
	VMOVQ V2, 32(res_ptr)
	VMOVQ V3, 48(res_ptr)
	VMOVQ V4, 64(res_ptr)
	VMOVQ V5, 80(res_ptr)
	VMOVQ V6, 96(res_ptr)
	VMOVQ V7, 112(res_ptr)
	VMOVQ 128(a_ptr), V0
	VMOVQ 144(a_ptr), V1
	VMOVQ 160(a_ptr), V2
	VMOVQ 176(a_ptr), V3
	VMOVQ 192(a_ptr), V4
	VMOVQ 208(a_ptr), V5
	VMOVQ 224(a_ptr), V6
	VMOVQ 240(a_ptr), V7
	VMOVQ V0, 128(res_ptr)
	VMOVQ V1, 144(res_ptr)
	VMOVQ V2, 160(res_ptr)
	VMOVQ V3, 176(res_ptr)
	VMOVQ V4, 192(res_ptr)
	VMOVQ V5, 208(res_ptr)
	VMOVQ V6, 224(res_ptr)
	VMOVQ V7, 240(res_ptr)
	VMOVQ 256(a_ptr), V0
	VMOVQ 272(a_ptr), V1
	VMOVQ 288(a_ptr), V2
	VMOVQ 304(a_ptr), V3
	VMOVQ 320(a_ptr), V4
	VMOVQ 336(a_ptr), V5
	VMOVQ 352(a_ptr), V6
	VMOVQ 368(a_ptr), V7
	VMOVQ V0, 256(res_ptr)
	VMOVQ V1, 272(res_ptr)
	VMOVQ V2, 288(res_ptr)
	VMOVQ V3, 304(res_ptr)
	VMOVQ V4, 320(res_ptr)
	VMOVQ V5, 336(res_ptr)
	VMOVQ V6, 352(res_ptr)
	VMOVQ V7, 368(res_ptr)

	RET

basic_path:
	MOVV $12, R7
basic_path_loop:	
		MOVV (0*8)(a_ptr), R8
		MOVV (1*8)(a_ptr), R9
		MOVV (2*8)(a_ptr), R10
		MOVV (3*8)(a_ptr), R11
		MOVV R8, (0*8)(res_ptr)
		MOVV R9, (1*8)(res_ptr)
		MOVV R10, (2*8)(res_ptr)
		MOVV R11, (3*8)(res_ptr)
		ADDV $32, a_ptr
		ADDV $32, res_ptr
		SUBV $1, R7
		BNE  R7, basic_path_loop
	RET

/* ---------------------------------------*/
// func gfP12MovCond(res, a, b *gfP12, cond int)
// If cond == 0 res=b, else res=a
TEXT ·gfP12MovCond(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV a+8(FP), a_ptr
	MOVV b+16(FP), b_ptr
	MOVV cond+24(FP), R31

	MOVV ·supportLSX+0(SB), R7
	BEQ  R7, ZERO, basic_path

	MOVV ·supportLASX+0(SB), R7
	BEQ  R7, ZERO, lsx_path

	// LASX path
	XVMOVQ R31, X0.V4
	XVXORV X1, X1, X1
	XVSEQV X0, X1, X0

	XVMOVQ (32*0)(a_ptr), X1
	XVMOVQ (32*1)(a_ptr), X2
	XVMOVQ (32*2)(a_ptr), X3
	XVMOVQ (32*3)(a_ptr), X4
	XVMOVQ (32*4)(a_ptr), X5
	XVMOVQ (32*5)(a_ptr), X6
	XVMOVQ (32*6)(a_ptr), X7
	XVMOVQ (32*7)(a_ptr), X8
	XVMOVQ (32*8)(a_ptr), X9
	XVMOVQ (32*9)(a_ptr), X10
	XVMOVQ (32*10)(a_ptr), X11
	XVMOVQ (32*11)(a_ptr), X12

	XVANDNV X1, X0, X1
	XVANDNV X2, X0, X2
	XVANDNV X3, X0, X3
	XVANDNV X4, X0, X4
	XVANDNV X5, X0, X5
	XVANDNV X6, X0, X6
	XVANDNV X7, X0, X7
	XVANDNV X8, X0, X8
	XVANDNV X9, X0, X9
	XVANDNV X10, X0, X10
	XVANDNV X11, X0, X11
	XVANDNV X12, X0, X12

	XVMOVQ (32*0)(b_ptr), X13
	XVMOVQ (32*1)(b_ptr), X14
	XVMOVQ (32*2)(b_ptr), X15
	XVMOVQ (32*3)(b_ptr), X16
	XVMOVQ (32*4)(b_ptr), X17
	XVMOVQ (32*5)(b_ptr), X18
	XVMOVQ (32*6)(b_ptr), X19
	XVMOVQ (32*7)(b_ptr), X20
	XVMOVQ (32*8)(b_ptr), X21
	XVMOVQ (32*9)(b_ptr), X22
	XVMOVQ (32*10)(b_ptr), X23
	XVMOVQ (32*11)(b_ptr), X24

	XVANDV X13, X0, X13
	XVANDV X14, X0, X14
	XVANDV X15, X0, X15
	XVANDV X16, X0, X16
	XVANDV X17, X0, X17
	XVANDV X18, X0, X18
	XVANDV X19, X0, X19
	XVANDV X20, X0, X20
	XVANDV X21, X0, X21
	XVANDV X22, X0, X22
	XVANDV X23, X0, X23
	XVANDV X24, X0, X24

	XVORV X1, X13, X1
	XVORV X2, X14, X2
	XVORV X3, X15, X3
	XVORV X4, X16, X4
	XVORV X5, X17, X5
	XVORV X6, X18, X6
	XVORV X7, X19, X7
	XVORV X8, X20, X8
	XVORV X9, X21, X9
	XVORV X10, X22, X10
	XVORV X11, X23, X11
	XVORV X12, X24, X12

	XVMOVQ X1, (32*0)(res_ptr)
	XVMOVQ X2, (32*1)(res_ptr)
	XVMOVQ X3, (32*2)(res_ptr)
	XVMOVQ X4, (32*3)(res_ptr)
	XVMOVQ X5, (32*4)(res_ptr)
	XVMOVQ X6, (32*5)(res_ptr)
	XVMOVQ X7, (32*6)(res_ptr)
	XVMOVQ X8, (32*7)(res_ptr)
	XVMOVQ X9, (32*8)(res_ptr)
	XVMOVQ X10, (32*9)(res_ptr)
	XVMOVQ X11, (32*10)(res_ptr)
	XVMOVQ X12, (32*11)(res_ptr)
	RET

lsx_path:
	VMOVQ R31, V0.V2
	VXORV V1, V1, V1
	VSEQV V0, V1, V0

	VMOVQ (16*0)(a_ptr), V1
	VMOVQ (16*1)(a_ptr), V2
	VMOVQ (16*2)(a_ptr), V3
	VMOVQ (16*3)(a_ptr), V4
	VMOVQ (16*4)(a_ptr), V5
	VMOVQ (16*5)(a_ptr), V6
	VMOVQ (16*6)(a_ptr), V7
	VMOVQ (16*7)(a_ptr), V8

	VANDNV V1, V0, V1
	VANDNV V2, V0, V2
	VANDNV V3, V0, V3
	VANDNV V4, V0, V4
	VANDNV V5, V0, V5
	VANDNV V6, V0, V6
	VANDNV V7, V0, V7
	VANDNV V8, V0, V8

	VMOVQ (16*0)(b_ptr), V9
	VMOVQ (16*1)(b_ptr), V10
	VMOVQ (16*2)(b_ptr), V11
	VMOVQ (16*3)(b_ptr), V12
	VMOVQ (16*4)(b_ptr), V13
	VMOVQ (16*5)(b_ptr), V14
	VMOVQ (16*6)(b_ptr), V15
	VMOVQ (16*7)(b_ptr), V16

	VANDV V9, V0, V9
	VANDV V10, V0, V10
	VANDV V11, V0, V11
	VANDV V12, V0, V12
	VANDV V13, V0, V13
	VANDV V14, V0, V14
	VANDV V15, V0, V15
	VANDV V16, V0, V16

	VORV V1, V9, V1
	VORV V2, V10, V2
	VORV V3, V11, V3
	VORV V4, V12, V4
	VORV V5, V13, V5
	VORV V6, V14, V6
	VORV V7, V15, V7
	VORV V8, V16, V8

	VMOVQ V1, (16*0)(res_ptr)
	VMOVQ V2, (16*1)(res_ptr)
	VMOVQ V3, (16*2)(res_ptr)
	VMOVQ V4, (16*3)(res_ptr)
	VMOVQ V5, (16*4)(res_ptr)
	VMOVQ V6, (16*5)(res_ptr)
	VMOVQ V7, (16*6)(res_ptr)
	VMOVQ V8, (16*7)(res_ptr)

	VMOVQ (8*16)(a_ptr), V1
	VMOVQ (9*16)(a_ptr), V2
	VMOVQ (10*16)(a_ptr), V3
	VMOVQ (11*16)(a_ptr), V4
	VMOVQ (12*16)(a_ptr), V5
	VMOVQ (13*16)(a_ptr), V6
	VMOVQ (14*16)(a_ptr), V7
	VMOVQ (15*16)(a_ptr), V8

	VANDNV V1, V0, V1
	VANDNV V2, V0, V2
	VANDNV V3, V0, V3
	VANDNV V4, V0, V4
	VANDNV V5, V0, V5
	VANDNV V6, V0, V6
	VANDNV V7, V0, V7
	VANDNV V8, V0, V8

	VMOVQ (8*16)(b_ptr), V9
	VMOVQ (9*16)(b_ptr), V10
	VMOVQ (10*16)(b_ptr), V11
	VMOVQ (11*16)(b_ptr), V12
	VMOVQ (12*16)(b_ptr), V13
	VMOVQ (13*16)(b_ptr), V14
	VMOVQ (14*16)(b_ptr), V15
	VMOVQ (15*16)(b_ptr), V16

	VANDV V9, V0, V9
	VANDV V10, V0, V10
	VANDV V11, V0, V11
	VANDV V12, V0, V12
	VANDV V13, V0, V13
	VANDV V14, V0, V14
	VANDV V15, V0, V15
	VANDV V16, V0, V16

	VORV V1, V9, V1
	VORV V2, V10, V2
	VORV V3, V11, V3
	VORV V4, V12, V4
	VORV V5, V13, V5
	VORV V6, V14, V6
	VORV V7, V15, V7
	VORV V8, V16, V8

	VMOVQ V1, (8*16)(res_ptr)
	VMOVQ V2, (9*16)(res_ptr)
	VMOVQ V3, (10*16)(res_ptr)
	VMOVQ V4, (11*16)(res_ptr)
	VMOVQ V5, (12*16)(res_ptr)
	VMOVQ V6, (13*16)(res_ptr)
	VMOVQ V7, (14*16)(res_ptr)
	VMOVQ V8, (15*16)(res_ptr)

	VMOVQ (16*16)(a_ptr), V1
	VMOVQ (17*16)(a_ptr), V2
	VMOVQ (18*16)(a_ptr), V3
	VMOVQ (19*16)(a_ptr), V4
	VMOVQ (20*16)(a_ptr), V5
	VMOVQ (21*16)(a_ptr), V6
	VMOVQ (22*16)(a_ptr), V7
	VMOVQ (23*16)(a_ptr), V8

	VANDNV V1, V0, V1
	VANDNV V2, V0, V2
	VANDNV V3, V0, V3
	VANDNV V4, V0, V4
	VANDNV V5, V0, V5
	VANDNV V6, V0, V6
	VANDNV V7, V0, V7
	VANDNV V8, V0, V8

	VMOVQ (16*16)(b_ptr), V9
	VMOVQ (17*16)(b_ptr), V10
	VMOVQ (18*16)(b_ptr), V11
	VMOVQ (19*16)(b_ptr), V12
	VMOVQ (20*16)(b_ptr), V13
	VMOVQ (21*16)(b_ptr), V14
	VMOVQ (22*16)(b_ptr), V15
	VMOVQ (23*16)(b_ptr), V16

	VANDV V9, V0, V9
	VANDV V10, V0, V10
	VANDV V11, V0, V11
	VANDV V12, V0, V12
	VANDV V13, V0, V13
	VANDV V14, V0, V14
	VANDV V15, V0, V15
	VANDV V16, V0, V16

	VORV V1, V9, V1
	VORV V2, V10, V2
	VORV V3, V11, V3
	VORV V4, V12, V4
	VORV V5, V13, V5
	VORV V6, V14, V6
	VORV V7, V15, V7
	VORV V8, V16, V8

	VMOVQ V1, (16*16)(res_ptr)
	VMOVQ V2, (17*16)(res_ptr)
	VMOVQ V3, (18*16)(res_ptr)
	VMOVQ V4, (19*16)(res_ptr)
	VMOVQ V5, (20*16)(res_ptr)
	VMOVQ V6, (21*16)(res_ptr)
	VMOVQ V7, (22*16)(res_ptr)
	VMOVQ V8, (23*16)(res_ptr)
	RET

basic_path:
	MOVV $12, R7
basic_path_loop:	
		MOVV (0*8)(a_ptr), R8
		MOVV (1*8)(a_ptr), R9
		MOVV (2*8)(a_ptr), R10
		MOVV (3*8)(a_ptr), R11
		MOVV (0*8)(b_ptr), R12
		MOVV (1*8)(b_ptr), R13
		MOVV (2*8)(b_ptr), R14
		MOVV (3*8)(b_ptr), R15

		MASKNEZ R31, R12, R12
		MASKNEZ R31, R13, R13
		MASKNEZ R31, R14, R14
		MASKNEZ R31, R15, R15
		MASKEQZ R31, R8, R8
		MASKEQZ R31, R9, R9
		MASKEQZ R31, R10, R10
		MASKEQZ R31, R11, R11
		ORR R12, R8
		ORR R13, R9
		ORR R14, R10
		ORR R15, R11
		MOVV R8, (0*8)(res_ptr)
		MOVV R9, (1*8)(res_ptr)
		MOVV R10, (2*8)(res_ptr)
		MOVV R11, (3*8)(res_ptr)

		ADDV $32, a_ptr
		ADDV $32, b_ptr
		ADDV $32, res_ptr
		SUBV $1, R7
		BNE  R7, basic_path_loop
	RET	

/* ---------------------------------------*/
// func curvePointMovCond(res, a, b *curvePoint, cond int)
// If cond == 0 res=b, else res=a
TEXT ·curvePointMovCond(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV a+8(FP), a_ptr
	MOVV b+16(FP), b_ptr
	MOVV cond+24(FP), R31

	MOVV ·supportLSX+0(SB), R7
	BEQ  R7, ZERO, basic_path

	MOVV ·supportLASX+0(SB), R7
	BEQ  R7, ZERO, lsx_path

	// LASX path
	XVMOVQ R31, X0.V4
	XVXORV X1, X1, X1
	XVSEQV X0, X1, X0

	XVMOVQ (32*0)(a_ptr), X1
	XVMOVQ (32*1)(a_ptr), X2
	XVMOVQ (32*2)(a_ptr), X3
	XVMOVQ (32*3)(a_ptr), X4

	XVANDNV X1, X0, X1
	XVANDNV X2, X0, X2
	XVANDNV X3, X0, X3
	XVANDNV X4, X0, X4

	XVMOVQ (32*0)(b_ptr), X13
	XVMOVQ (32*1)(b_ptr), X14
	XVMOVQ (32*2)(b_ptr), X15
	XVMOVQ (32*3)(b_ptr), X16

	XVANDV X13, X0, X13
	XVANDV X14, X0, X14
	XVANDV X15, X0, X15
	XVANDV X16, X0, X16

	XVORV X1, X13, X1
	XVORV X2, X14, X2
	XVORV X3, X15, X3
	XVORV X4, X16, X4

	XVMOVQ X1, (32*0)(res_ptr)
	XVMOVQ X2, (32*1)(res_ptr)
	XVMOVQ X3, (32*2)(res_ptr)
	XVMOVQ X4, (32*3)(res_ptr)
	RET

lsx_path:
	VMOVQ R31, V0.V2
	VXORV V1, V1, V1
	VSEQV V0, V1, V0

	VMOVQ (16*0)(a_ptr), V1
	VMOVQ (16*1)(a_ptr), V2
	VMOVQ (16*2)(a_ptr), V3
	VMOVQ (16*3)(a_ptr), V4
	VMOVQ (16*4)(a_ptr), V5
	VMOVQ (16*5)(a_ptr), V6
	VMOVQ (16*6)(a_ptr), V7
	VMOVQ (16*7)(a_ptr), V8

	VANDNV V1, V0, V1
	VANDNV V2, V0, V2
	VANDNV V3, V0, V3
	VANDNV V4, V0, V4
	VANDNV V5, V0, V5
	VANDNV V6, V0, V6
	VANDNV V7, V0, V7
	VANDNV V8, V0, V8

	VMOVQ (16*0)(b_ptr), V9
	VMOVQ (16*1)(b_ptr), V10
	VMOVQ (16*2)(b_ptr), V11
	VMOVQ (16*3)(b_ptr), V12
	VMOVQ (16*4)(b_ptr), V13
	VMOVQ (16*5)(b_ptr), V14
	VMOVQ (16*6)(b_ptr), V15
	VMOVQ (16*7)(b_ptr), V16

	VANDV V9, V0, V9
	VANDV V10, V0, V10
	VANDV V11, V0, V11
	VANDV V12, V0, V12
	VANDV V13, V0, V13
	VANDV V14, V0, V14
	VANDV V15, V0, V15
	VANDV V16, V0, V16

	VORV V1, V9, V1
	VORV V2, V10, V2
	VORV V3, V11, V3
	VORV V4, V12, V4
	VORV V5, V13, V5
	VORV V6, V14, V6
	VORV V7, V15, V7
	VORV V8, V16, V8

	VMOVQ V1, (16*0)(res_ptr)
	VMOVQ V2, (16*1)(res_ptr)
	VMOVQ V3, (16*2)(res_ptr)
	VMOVQ V4, (16*3)(res_ptr)
	VMOVQ V5, (16*4)(res_ptr)
	VMOVQ V6, (16*5)(res_ptr)
	VMOVQ V7, (16*6)(res_ptr)
	VMOVQ V8, (16*7)(res_ptr)
	RET

basic_path:
	MOVV $4, R7
basic_path_loop:	
		MOVV (0*8)(a_ptr), R8
		MOVV (1*8)(a_ptr), R9
		MOVV (2*8)(a_ptr), R10
		MOVV (3*8)(a_ptr), R11
		MOVV (0*8)(b_ptr), R12
		MOVV (1*8)(b_ptr), R13
		MOVV (2*8)(b_ptr), R14
		MOVV (3*8)(b_ptr), R15

		MASKNEZ R31, R12, R12
		MASKNEZ R31, R13, R13
		MASKNEZ R31, R14, R14
		MASKNEZ R31, R15, R15
		MASKEQZ R31, R8, R8
		MASKEQZ R31, R9, R9
		MASKEQZ R31, R10, R10
		MASKEQZ R31, R11, R11
		ORR R12, R8
		ORR R13, R9
		ORR R14, R10
		ORR R15, R11
		MOVV R8, (0*8)(res_ptr)
		MOVV R9, (1*8)(res_ptr)
		MOVV R10, (2*8)(res_ptr)
		MOVV R11, (3*8)(res_ptr)

		ADDV $32, a_ptr
		ADDV $32, b_ptr
		ADDV $32, res_ptr
		SUBV $1, R7
		BNE  R7, basic_path_loop
	RET

/* ---------------------------------------*/
// func twistPointMovCond(res, a, b *twistPoint, cond int)
// If cond == 0 res=b, else res=a
TEXT ·twistPointMovCond(SB),NOSPLIT,$0
	MOVV res+0(FP), res_ptr
	MOVV a+8(FP), a_ptr
	MOVV b+16(FP), b_ptr
	MOVV cond+24(FP), R31

	MOVV ·supportLSX+0(SB), R7
	BEQ  R7, ZERO, basic_path

	MOVV ·supportLASX+0(SB), R7
	BEQ  R7, ZERO, lsx_path

	// LASX path
	XVMOVQ R31, X0.V4
	XVXORV X1, X1, X1
	XVSEQV X0, X1, X0

	XVMOVQ (32*0)(a_ptr), X1
	XVMOVQ (32*1)(a_ptr), X2
	XVMOVQ (32*2)(a_ptr), X3
	XVMOVQ (32*3)(a_ptr), X4
	XVMOVQ (32*4)(a_ptr), X5
	XVMOVQ (32*5)(a_ptr), X6
	XVMOVQ (32*6)(a_ptr), X7
	XVMOVQ (32*7)(a_ptr), X8

	XVANDNV X1, X0, X1
	XVANDNV X2, X0, X2
	XVANDNV X3, X0, X3
	XVANDNV X4, X0, X4
	XVANDNV X5, X0, X5
	XVANDNV X6, X0, X6
	XVANDNV X7, X0, X7
	XVANDNV X8, X0, X8

	XVMOVQ (32*0)(b_ptr), X13
	XVMOVQ (32*1)(b_ptr), X14
	XVMOVQ (32*2)(b_ptr), X15
	XVMOVQ (32*3)(b_ptr), X16
	XVMOVQ (32*4)(b_ptr), X17
	XVMOVQ (32*5)(b_ptr), X18
	XVMOVQ (32*6)(b_ptr), X19
	XVMOVQ (32*7)(b_ptr), X20

	XVANDV X13, X0, X13
	XVANDV X14, X0, X14
	XVANDV X15, X0, X15
	XVANDV X16, X0, X16
	XVANDV X17, X0, X17
	XVANDV X18, X0, X18
	XVANDV X19, X0, X19
	XVANDV X20, X0, X20

	XVORV X1, X13, X1
	XVORV X2, X14, X2
	XVORV X3, X15, X3
	XVORV X4, X16, X4
	XVORV X5, X17, X5
	XVORV X6, X18, X6
	XVORV X7, X19, X7
	XVORV X8, X20, X8

	XVMOVQ X1, (32*0)(res_ptr)
	XVMOVQ X2, (32*1)(res_ptr)
	XVMOVQ X3, (32*2)(res_ptr)
	XVMOVQ X4, (32*3)(res_ptr)
	XVMOVQ X5, (32*4)(res_ptr)
	XVMOVQ X6, (32*5)(res_ptr)
	XVMOVQ X7, (32*6)(res_ptr)
	XVMOVQ X8, (32*7)(res_ptr)
	RET

lsx_path:
	VMOVQ R31, V0.V2
	VXORV V1, V1, V1
	VSEQV V0, V1, V0

	VMOVQ (16*0)(a_ptr), V1
	VMOVQ (16*1)(a_ptr), V2
	VMOVQ (16*2)(a_ptr), V3
	VMOVQ (16*3)(a_ptr), V4
	VMOVQ (16*4)(a_ptr), V5
	VMOVQ (16*5)(a_ptr), V6
	VMOVQ (16*6)(a_ptr), V7
	VMOVQ (16*7)(a_ptr), V8

	VANDNV V1, V0, V1
	VANDNV V2, V0, V2
	VANDNV V3, V0, V3
	VANDNV V4, V0, V4
	VANDNV V5, V0, V5
	VANDNV V6, V0, V6
	VANDNV V7, V0, V7
	VANDNV V8, V0, V8

	VMOVQ (16*0)(b_ptr), V9
	VMOVQ (16*1)(b_ptr), V10
	VMOVQ (16*2)(b_ptr), V11
	VMOVQ (16*3)(b_ptr), V12
	VMOVQ (16*4)(b_ptr), V13
	VMOVQ (16*5)(b_ptr), V14
	VMOVQ (16*6)(b_ptr), V15
	VMOVQ (16*7)(b_ptr), V16

	VANDV V9, V0, V9
	VANDV V10, V0, V10
	VANDV V11, V0, V11
	VANDV V12, V0, V12
	VANDV V13, V0, V13
	VANDV V14, V0, V14
	VANDV V15, V0, V15
	VANDV V16, V0, V16

	VORV V1, V9, V1
	VORV V2, V10, V2
	VORV V3, V11, V3
	VORV V4, V12, V4
	VORV V5, V13, V5
	VORV V6, V14, V6
	VORV V7, V15, V7
	VORV V8, V16, V8

	VMOVQ V1, (16*0)(res_ptr)
	VMOVQ V2, (16*1)(res_ptr)
	VMOVQ V3, (16*2)(res_ptr)
	VMOVQ V4, (16*3)(res_ptr)
	VMOVQ V5, (16*4)(res_ptr)
	VMOVQ V6, (16*5)(res_ptr)
	VMOVQ V7, (16*6)(res_ptr)
	VMOVQ V8, (16*7)(res_ptr)

	VMOVQ (8*16)(a_ptr), V1
	VMOVQ (9*16)(a_ptr), V2
	VMOVQ (10*16)(a_ptr), V3
	VMOVQ (11*16)(a_ptr), V4
	VMOVQ (12*16)(a_ptr), V5
	VMOVQ (13*16)(a_ptr), V6
	VMOVQ (14*16)(a_ptr), V7
	VMOVQ (15*16)(a_ptr), V8

	VANDNV V1, V0, V1
	VANDNV V2, V0, V2
	VANDNV V3, V0, V3
	VANDNV V4, V0, V4
	VANDNV V5, V0, V5
	VANDNV V6, V0, V6
	VANDNV V7, V0, V7
	VANDNV V8, V0, V8

	VMOVQ (8*16)(b_ptr), V9
	VMOVQ (9*16)(b_ptr), V10
	VMOVQ (10*16)(b_ptr), V11
	VMOVQ (11*16)(b_ptr), V12
	VMOVQ (12*16)(b_ptr), V13
	VMOVQ (13*16)(b_ptr), V14
	VMOVQ (14*16)(b_ptr), V15
	VMOVQ (15*16)(b_ptr), V16

	VANDV V9, V0, V9
	VANDV V10, V0, V10
	VANDV V11, V0, V11
	VANDV V12, V0, V12
	VANDV V13, V0, V13
	VANDV V14, V0, V14
	VANDV V15, V0, V15
	VANDV V16, V0, V16

	VORV V1, V9, V1
	VORV V2, V10, V2
	VORV V3, V11, V3
	VORV V4, V12, V4
	VORV V5, V13, V5
	VORV V6, V14, V6
	VORV V7, V15, V7
	VORV V8, V16, V8

	VMOVQ V1, (8*16)(res_ptr)
	VMOVQ V2, (9*16)(res_ptr)
	VMOVQ V3, (10*16)(res_ptr)
	VMOVQ V4, (11*16)(res_ptr)
	VMOVQ V5, (12*16)(res_ptr)
	VMOVQ V6, (13*16)(res_ptr)
	VMOVQ V7, (14*16)(res_ptr)
	VMOVQ V8, (15*16)(res_ptr)
	RET

basic_path:
	MOVV $8, R7
basic_path_loop:	
		MOVV (0*8)(a_ptr), R8
		MOVV (1*8)(a_ptr), R9
		MOVV (2*8)(a_ptr), R10
		MOVV (3*8)(a_ptr), R11
		MOVV (0*8)(b_ptr), R12
		MOVV (1*8)(b_ptr), R13
		MOVV (2*8)(b_ptr), R14
		MOVV (3*8)(b_ptr), R15

		MASKNEZ R31, R12, R12
		MASKNEZ R31, R13, R13
		MASKNEZ R31, R14, R14
		MASKNEZ R31, R15, R15
		MASKEQZ R31, R8, R8
		MASKEQZ R31, R9, R9
		MASKEQZ R31, R10, R10
		MASKEQZ R31, R11, R11
		ORR R12, R8
		ORR R13, R9
		ORR R14, R10
		ORR R15, R11
		MOVV R8, (0*8)(res_ptr)
		MOVV R9, (1*8)(res_ptr)
		MOVV R10, (2*8)(res_ptr)
		MOVV R11, (3*8)(res_ptr)

		ADDV $32, a_ptr
		ADDV $32, b_ptr
		ADDV $32, res_ptr
		SUBV $1, R7
		BNE  R7, basic_path_loop
	RET
