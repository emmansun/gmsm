//go:build !purego

#include "textflag.h"

#define res_ptr R0
#define a_ptr R1
#define b_ptr R2

/* ---------------------------------------*/
// func gfpCopy(res, a *gfP)
TEXT ·gfpCopy(SB),NOSPLIT,$0
	MOVD res+0(FP), res_ptr
	MOVD a+8(FP), a_ptr

	VLD1	(a_ptr), [V0.B16, V1.B16]
	VST1	[V0.B16, V1.B16], (res_ptr)

	RET

/* ---------------------------------------*/
// func gfp2Copy(res, a *gfP2)
TEXT ·gfp2Copy(SB),NOSPLIT,$0
	MOVD res+0(FP), res_ptr
	MOVD a+8(FP), a_ptr

	VLD1	(a_ptr), [V0.B16, V1.B16, V2.B16, V3.B16]
	VST1	[V0.B16, V1.B16, V2.B16, V3.B16], (res_ptr)

	RET

/* ---------------------------------------*/
// func gfp4Copy(res, a *gfP4)
TEXT ·gfp4Copy(SB),NOSPLIT,$0
	MOVD res+0(FP), res_ptr
	MOVD a+8(FP), a_ptr

	VLD1.P	64(a_ptr), [V0.B16, V1.B16, V2.B16, V3.B16]
	VST1.P	[V0.B16, V1.B16, V2.B16, V3.B16], 64(res_ptr)

	VLD1.P	64(a_ptr), [V0.B16, V1.B16, V2.B16, V3.B16]
	VST1.P	[V0.B16, V1.B16, V2.B16, V3.B16], 64(res_ptr)

	RET

/* ---------------------------------------*/
// func gfp6Copy(res, a *gfP6)
TEXT ·gfp6Copy(SB),NOSPLIT,$0
	MOVD res+0(FP), res_ptr
	MOVD a+8(FP), a_ptr

	VLD1.P	64(a_ptr), [V0.B16, V1.B16, V2.B16, V3.B16]
	VST1.P	[V0.B16, V1.B16, V2.B16, V3.B16], 64(res_ptr)

	VLD1.P	64(a_ptr), [V0.B16, V1.B16, V2.B16, V3.B16]
	VST1.P	[V0.B16, V1.B16, V2.B16, V3.B16], 64(res_ptr)

	VLD1.P	64(a_ptr), [V0.B16, V1.B16, V2.B16, V3.B16]
	VST1.P	[V0.B16, V1.B16, V2.B16, V3.B16], 64(res_ptr)

	RET

/* ---------------------------------------*/
// func gfp12Copy(res, a *gfP12)
TEXT ·gfp12Copy(SB),NOSPLIT,$0
	MOVD res+0(FP), res_ptr
	MOVD a+8(FP), a_ptr

	VLD1.P	64(a_ptr), [V0.B16, V1.B16, V2.B16, V3.B16]
	VST1.P	[V0.B16, V1.B16, V2.B16, V3.B16], 64(res_ptr)

	VLD1.P	64(a_ptr), [V0.B16, V1.B16, V2.B16, V3.B16]
	VST1.P	[V0.B16, V1.B16, V2.B16, V3.B16], 64(res_ptr)

	VLD1.P	64(a_ptr), [V0.B16, V1.B16, V2.B16, V3.B16]
	VST1.P	[V0.B16, V1.B16, V2.B16, V3.B16], 64(res_ptr)

	VLD1.P	64(a_ptr), [V0.B16, V1.B16, V2.B16, V3.B16]
	VST1.P	[V0.B16, V1.B16, V2.B16, V3.B16], 64(res_ptr)

	VLD1.P	64(a_ptr), [V0.B16, V1.B16, V2.B16, V3.B16]
	VST1.P	[V0.B16, V1.B16, V2.B16, V3.B16], 64(res_ptr)

	VLD1.P	64(a_ptr), [V0.B16, V1.B16, V2.B16, V3.B16]
	VST1.P	[V0.B16, V1.B16, V2.B16, V3.B16], 64(res_ptr)
		
	RET

/* ---------------------------------------*/
// func gfP12MovCond(res, a, b *gfP12, cond int)
// If cond == 0 res=b, else res=a
TEXT ·gfP12MovCond(SB),NOSPLIT,$0
	MOVD	res+0(FP), res_ptr
	MOVD	a+8(FP), a_ptr
	MOVD	b+16(FP), b_ptr
	MOVD	cond+24(FP), R3

	VEOR V0.B16, V0.B16, V0.B16
	VMOV R3, V1.S4
	VCMEQ V0.S4, V1.S4, V2.S4

	VLD1.P (64)(a_ptr), [V3.B16, V4.B16, V5.B16, V6.B16]
	VLD1.P (64)(b_ptr), [V7.B16, V8.B16, V9.B16, V10.B16]
	VBIT V2.B16, V7.B16, V3.B16
	VBIT V2.B16, V8.B16, V4.B16
	VBIT V2.B16, V9.B16, V5.B16
	VBIT V2.B16, V10.B16, V6.B16
	VST1.P [V3.B16, V4.B16, V5.B16, V6.B16], (64)(res_ptr)

	VLD1.P (64)(a_ptr), [V3.B16, V4.B16, V5.B16, V6.B16]
	VLD1.P (64)(b_ptr), [V7.B16, V8.B16, V9.B16, V10.B16]
	VBIT V2.B16, V7.B16, V3.B16
	VBIT V2.B16, V8.B16, V4.B16
	VBIT V2.B16, V9.B16, V5.B16
	VBIT V2.B16, V10.B16, V6.B16
	VST1.P [V3.B16, V4.B16, V5.B16, V6.B16], (64)(res_ptr)

	VLD1.P (64)(a_ptr), [V3.B16, V4.B16, V5.B16, V6.B16]
	VLD1.P (64)(b_ptr), [V7.B16, V8.B16, V9.B16, V10.B16]
	VBIT V2.B16, V7.B16, V3.B16
	VBIT V2.B16, V8.B16, V4.B16
	VBIT V2.B16, V9.B16, V5.B16
	VBIT V2.B16, V10.B16, V6.B16
	VST1.P [V3.B16, V4.B16, V5.B16, V6.B16], (64)(res_ptr)

	VLD1.P (64)(a_ptr), [V3.B16, V4.B16, V5.B16, V6.B16]
	VLD1.P (64)(b_ptr), [V7.B16, V8.B16, V9.B16, V10.B16]
	VBIT V2.B16, V7.B16, V3.B16
	VBIT V2.B16, V8.B16, V4.B16
	VBIT V2.B16, V9.B16, V5.B16
	VBIT V2.B16, V10.B16, V6.B16
	VST1.P [V3.B16, V4.B16, V5.B16, V6.B16], (64)(res_ptr)

	VLD1.P (64)(a_ptr), [V3.B16, V4.B16, V5.B16, V6.B16]
	VLD1.P (64)(b_ptr), [V7.B16, V8.B16, V9.B16, V10.B16]
	VBIT V2.B16, V7.B16, V3.B16
	VBIT V2.B16, V8.B16, V4.B16
	VBIT V2.B16, V9.B16, V5.B16
	VBIT V2.B16, V10.B16, V6.B16
	VST1.P [V3.B16, V4.B16, V5.B16, V6.B16], (64)(res_ptr)

	VLD1 (a_ptr), [V3.B16, V4.B16, V5.B16, V6.B16]
	VLD1 (b_ptr), [V7.B16, V8.B16, V9.B16, V10.B16]
	VBIT V2.B16, V7.B16, V3.B16
	VBIT V2.B16, V8.B16, V4.B16
	VBIT V2.B16, V9.B16, V5.B16
	VBIT V2.B16, V10.B16, V6.B16
	VST1 [V3.B16, V4.B16, V5.B16, V6.B16], (res_ptr)

	RET

/* ---------------------------------------*/
// func curvePointMovCond(res, a, b *curvePoint, cond int)
// If cond == 0 res=b, else res=a
TEXT ·curvePointMovCond(SB),NOSPLIT,$0
	MOVD	res+0(FP), res_ptr
	MOVD	a+8(FP), a_ptr
	MOVD	b+16(FP), b_ptr
	MOVD	cond+24(FP), R3

	VEOR V0.B16, V0.B16, V0.B16
	VMOV R3, V1.S4
	VCMEQ V0.S4, V1.S4, V2.S4

	VLD1.P (64)(a_ptr), [V3.B16, V4.B16, V5.B16, V6.B16]
	VLD1.P (64)(b_ptr), [V7.B16, V8.B16, V9.B16, V10.B16]
	VBIT V2.B16, V7.B16, V3.B16
	VBIT V2.B16, V8.B16, V4.B16
	VBIT V2.B16, V9.B16, V5.B16
	VBIT V2.B16, V10.B16, V6.B16
	VST1.P [V3.B16, V4.B16, V5.B16, V6.B16], (64)(res_ptr)

	VLD1 (a_ptr), [V3.B16, V4.B16, V5.B16, V6.B16]
	VLD1 (b_ptr), [V7.B16, V8.B16, V9.B16, V10.B16]
	VBIT V2.B16, V7.B16, V3.B16
	VBIT V2.B16, V8.B16, V4.B16
	VBIT V2.B16, V9.B16, V5.B16
	VBIT V2.B16, V10.B16, V6.B16
	VST1 [V3.B16, V4.B16, V5.B16, V6.B16], (res_ptr)

	RET

/* ---------------------------------------*/
// func twistPointMovCond(res, a, b *twistPoint, cond int)
// If cond == 0 res=b, else res=a
TEXT ·twistPointMovCond(SB),NOSPLIT,$0
	MOVD	res+0(FP), res_ptr
	MOVD	a+8(FP), a_ptr
	MOVD	b+16(FP), b_ptr
	MOVD	cond+24(FP), R3

	VEOR V0.B16, V0.B16, V0.B16
	VMOV R3, V1.S4
	VCMEQ V0.S4, V1.S4, V2.S4

	VLD1.P (64)(a_ptr), [V3.B16, V4.B16, V5.B16, V6.B16]
	VLD1.P (64)(b_ptr), [V7.B16, V8.B16, V9.B16, V10.B16]
	VBIT V2.B16, V7.B16, V3.B16
	VBIT V2.B16, V8.B16, V4.B16
	VBIT V2.B16, V9.B16, V5.B16
	VBIT V2.B16, V10.B16, V6.B16
	VST1.P [V3.B16, V4.B16, V5.B16, V6.B16], (64)(res_ptr)

	VLD1.P (64)(a_ptr), [V3.B16, V4.B16, V5.B16, V6.B16]
	VLD1.P (64)(b_ptr), [V7.B16, V8.B16, V9.B16, V10.B16]
	VBIT V2.B16, V7.B16, V3.B16
	VBIT V2.B16, V8.B16, V4.B16
	VBIT V2.B16, V9.B16, V5.B16
	VBIT V2.B16, V10.B16, V6.B16
	VST1.P [V3.B16, V4.B16, V5.B16, V6.B16], (64)(res_ptr)

	VLD1.P (64)(a_ptr), [V3.B16, V4.B16, V5.B16, V6.B16]
	VLD1.P (64)(b_ptr), [V7.B16, V8.B16, V9.B16, V10.B16]
	VBIT V2.B16, V7.B16, V3.B16
	VBIT V2.B16, V8.B16, V4.B16
	VBIT V2.B16, V9.B16, V5.B16
	VBIT V2.B16, V10.B16, V6.B16
	VST1.P [V3.B16, V4.B16, V5.B16, V6.B16], (64)(res_ptr)

	VLD1 (a_ptr), [V3.B16, V4.B16, V5.B16, V6.B16]
	VLD1 (b_ptr), [V7.B16, V8.B16, V9.B16, V10.B16]
	VBIT V2.B16, V7.B16, V3.B16
	VBIT V2.B16, V8.B16, V4.B16
	VBIT V2.B16, V9.B16, V5.B16
	VBIT V2.B16, V10.B16, V6.B16
	VST1 [V3.B16, V4.B16, V5.B16, V6.B16], (res_ptr)

	RET
