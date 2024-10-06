// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"

#define res_ptr R3
#define a_ptr R4
#define b_ptr R5

// func gfpCopy(res, a *gfP)
TEXT ·gfpCopy(SB),NOSPLIT,$0
	MOVD res+0(FP), res_ptr
	MOVD a+8(FP), a_ptr
	MOVD $16, R10

	LXVD2X (a_ptr)(R0), V0
	LXVD2X (a_ptr)(R10), V1

	STXVD2X V0, (res_ptr)(R0)
	STXVD2X V1, (res_ptr)(R10)
	RET

#define copyFirst64 \
	LXVD2X (a_ptr)(R0), V0     \
	LXVD2X (a_ptr)(R6), V1     \
	LXVD2X (a_ptr)(R7), V2     \
	LXVD2X (a_ptr)(R8), V3     \
	STXVD2X V0, (res_ptr)(R0)     \
	STXVD2X V1, (res_ptr)(R6)     \
	STXVD2X V2, (res_ptr)(R7)     \
	STXVD2X V3, (res_ptr)(R8)

#define copyNext64 \
	LXVD2X (a_ptr)(R6), V0     \
	LXVD2X (a_ptr)(R7), V1     \
	LXVD2X (a_ptr)(R8), V2     \
	LXVD2X (a_ptr)(R9), V3     \
	STXVD2X V0, (res_ptr)(R6)     \
	STXVD2X V1, (res_ptr)(R7)     \
	STXVD2X V2, (res_ptr)(R8)     \
	STXVD2X V3, (res_ptr)(R9)     \

// func gfp2Copy(res, a *gfP2)
TEXT ·gfp2Copy(SB),NOSPLIT,$0
	MOVD res+0(FP), res_ptr
	MOVD a+8(FP), a_ptr
	MOVD $16, R6
	MOVD $32, R7
	MOVD $48, R8

	copyFirst64
	RET

/* ---------------------------------------*/
// func gfp4Copy(res, a *gfP4)
TEXT ·gfp4Copy(SB),NOSPLIT,$0
	MOVD res+0(FP), res_ptr
	MOVD a+8(FP), a_ptr
	MOVD $16, R6
	MOVD $32, R7
	MOVD $48, R8

	copyFirst64

	MOVD $0x40, R6
	MOVD $0x50, R7
	MOVD $0x60, R8
	MOVD $0x70, R9

	copyNext64

	RET

// func gfp6Copy(res, a *gfP6)
TEXT ·gfp6Copy(SB),NOSPLIT,$0
	MOVD res+0(FP), res_ptr
	MOVD a+8(FP), a_ptr
	MOVD $16, R6
	MOVD $32, R7
	MOVD $48, R8
	copyFirst64

	MOVD $0x40, R6
	MOVD $0x50, R7
	MOVD $0x60, R8
	MOVD $0x70, R9
	copyNext64

	MOVD $0x80, R6
	MOVD $0x90, R7
	MOVD $0xa0, R8
	MOVD $0xb0, R9
	copyNext64
	RET

// func gfp12Copy(res, a *gfP12)
TEXT ·gfp12Copy(SB),NOSPLIT,$0
	MOVD res+0(FP), res_ptr
	MOVD a+8(FP), a_ptr
	MOVD $16, R6
	MOVD $32, R7
	MOVD $48, R8
	copyFirst64

	MOVD $0x40, R6
	MOVD $0x50, R7
	MOVD $0x60, R8
	MOVD $0x70, R9
	copyNext64

	MOVD $0x80, R6
	MOVD $0x90, R7
	MOVD $0xa0, R8
	MOVD $0xb0, R9
	copyNext64

	MOVD $0xc0, R6
	MOVD $0xd0, R7
	MOVD $0xe0, R8
	MOVD $0xf0, R9
	copyNext64

	MOVD $0x0100, R6
	MOVD $0x0110, R7
	MOVD $0x0120, R8
	MOVD $0x0130, R9
	copyNext64

	MOVD $0x0140, R6
	MOVD $0x0150, R7
	MOVD $0x0160, R8
	MOVD $0x0170, R9
	copyNext64	
	RET

#define ZER V10
#define SEL V11

#define moveFirst64 \
	LXVD2X (a_ptr)(R0), V0     \
	LXVD2X (a_ptr)(R6), V1     \
	LXVD2X (a_ptr)(R7), V2     \
	LXVD2X (a_ptr)(R8), V3     \
	LXVD2X (b_ptr)(R0), V4     \
	LXVD2X (b_ptr)(R6), V5     \
	LXVD2X (b_ptr)(R7), V6     \
	LXVD2X (b_ptr)(R8), V7     \
	VSEL V0, V4, SEL, V0     \
	VSEL V1, V5, SEL, V1     \
	VSEL V2, V6, SEL, V2     \
	VSEL V3, V7, SEL, V3     \
	STXVD2X V0, (res_ptr)(R0)     \
	STXVD2X V1, (res_ptr)(R6)     \
	STXVD2X V2, (res_ptr)(R7)     \
	STXVD2X V3, (res_ptr)(R8)

#define moveNext64 \
	LXVD2X (a_ptr)(R6), V0     \
	LXVD2X (a_ptr)(R7), V1     \
	LXVD2X (a_ptr)(R8), V2     \
	LXVD2X (a_ptr)(R9), V3     \
	LXVD2X (b_ptr)(R6), V4     \
	LXVD2X (b_ptr)(R7), V5     \
	LXVD2X (b_ptr)(R8), V6     \
	LXVD2X (b_ptr)(R9), V7     \
	VSEL V0, V4, SEL, V0     \
	VSEL V1, V5, SEL, V1     \
	VSEL V2, V6, SEL, V2     \
	VSEL V3, V7, SEL, V3     \	
	STXVD2X V0, (res_ptr)(R6)     \
	STXVD2X V1, (res_ptr)(R7)     \
	STXVD2X V2, (res_ptr)(R8)     \
	STXVD2X V3, (res_ptr)(R9)     \

// func gfP12MovCond(res, a, b *gfP12, cond int)
// If cond == 0 res=b, else res=a
TEXT ·gfP12MovCond(SB),NOSPLIT,$0
	MOVD	res+0(FP), res_ptr
	MOVD	a+8(FP), a_ptr
	MOVD	b+16(FP), b_ptr
	MOVD $56, R21
	// cond is R1 + 24 (cond offset) + 32
	LXVDSX (R1)(R21), SEL
	VSPLTISB $0, ZER
	// SEL controls whether to store a or b
	VCMPEQUD SEL, ZER, SEL

	MOVD $16, R6
	MOVD $32, R7
	MOVD $48, R8
	moveFirst64

	MOVD $0x40, R6
	MOVD $0x50, R7
	MOVD $0x60, R8
	MOVD $0x70, R9
	moveNext64

	MOVD $0x80, R6
	MOVD $0x90, R7
	MOVD $0xa0, R8
	MOVD $0xb0, R9
	moveNext64

	MOVD $0xc0, R6
	MOVD $0xd0, R7
	MOVD $0xe0, R8
	MOVD $0xf0, R9
	moveNext64

	MOVD $0x0100, R6
	MOVD $0x0110, R7
	MOVD $0x0120, R8
	MOVD $0x0130, R9
	moveNext64

	MOVD $0x0140, R6
	MOVD $0x0150, R7
	MOVD $0x0160, R8
	MOVD $0x0170, R9
	moveNext64
	RET

// func curvePointMovCond(res, a, b *curvePoint, cond int)
// If cond == 0 res=b, else res=a
TEXT ·curvePointMovCond(SB),NOSPLIT,$0
	MOVD	res+0(FP), res_ptr
	MOVD	a+8(FP), a_ptr
	MOVD	b+16(FP), b_ptr
	MOVD $56, R21
	// cond is R1 + 24 (cond offset) + 32
	LXVDSX (R1)(R21), SEL
	VSPLTISB $0, ZER
	// SEL controls whether to store a or b
	VCMPEQUD SEL, ZER, SEL

	MOVD $16, R6
	MOVD $32, R7
	MOVD $48, R8
	moveFirst64

	MOVD $0x40, R6
	MOVD $0x50, R7
	MOVD $0x60, R8
	MOVD $0x70, R9
	moveNext64	
	RET

// func twistPointMovCond(res, a, b *twistPoint, cond int)
// If cond == 0 res=b, else res=a
TEXT ·twistPointMovCond(SB),NOSPLIT,$0
	MOVD	res+0(FP), res_ptr
	MOVD	a+8(FP), a_ptr
	MOVD	b+16(FP), b_ptr
	MOVD $56, R21
	// cond is R1 + 24 (cond offset) + 32
	LXVDSX (R1)(R21), SEL
	VSPLTISB $0, ZER
	// SEL controls whether to store a or b
	VCMPEQUD SEL, ZER, SEL

	MOVD $16, R6
	MOVD $32, R7
	MOVD $48, R8
	moveFirst64

	MOVD $0x40, R6
	MOVD $0x50, R7
	MOVD $0x60, R8
	MOVD $0x70, R9
	moveNext64

	MOVD $0x80, R6
	MOVD $0x90, R7
	MOVD $0xa0, R8
	MOVD $0xb0, R9
	moveNext64

	MOVD $0xc0, R6
	MOVD $0xd0, R7
	MOVD $0xe0, R8
	MOVD $0xf0, R9
	moveNext64

	RET
