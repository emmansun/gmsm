// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.27 && !purego

#include "textflag.h"

#define ZERO X0
#define RSP X2

DATA gcmPoly<>+0x00(SB)/8, $0x0000000000000001
DATA gcmPoly<>+0x08(SB)/8, $0xc200000000000000

GLOBL gcmPoly<>(SB), (NOPTR+RODATA), $16

// VSM4R_VS performs vsm4r.vs Vd, Vs2
// OP-P(0x77) | funct6=101001,vm=1 → 0x53 | vs2[24:20] | vs1=10000 | funct3=010 | vd
#define VSM4R_VS(Vd, Vs2) \
	WORD $((0x53 << 25) | ((Vs2) << 20) | (0x10 << 15) | (2 << 12) | ((Vd) << 7) | 0x77)

// VSM4K_VI performs vsm4k.vi Vd, Vs2, imm5
// OP-P(0x77) | funct6=100001,vm=1 → 0x43 | vs2[24:20] | imm[19:15] | funct3=010 | vd[11:7]
#define VSM4K_VI(Vd, Vs2, Imm) \
	WORD $((0x43 << 25) | ((Vs2) << 20) | ((Imm) << 15) | (2 << 12) | ((Vd) << 7) | 0x77)

#define stackaddress(index) ((index)*8+8)(RSP) // for RISCV64 stack usage, we CAN NOT overwrite the first 8 bytes space!

// func gcmSm4Init(productTable *[256]byte, rk []uint32)
TEXT ·gcmSm4Init(SB),NOSPLIT,$0
#define dst X10
#define RK X11

	MOV productTable+0(FP), dst
	MOV rk+8(FP), RK

	MOV $gcmPoly<>(SB), X12

	// Encrypt block 0, with the sm4 round keys to generate the hash key H
	VSETIVLI	$4, E32, M1, TA, MA, X0
	VXORVV V4, V4, V4

	VLE32V	(RK), V16
	ADD	$16, RK, X14
	VLE32V	(X14), V17
	ADD	$16, X14
	VLE32V	(X14), V18
	ADD	$16, X14
	VLE32V	(X14), V19
	ADD	$16, X14
	VLE32V	(X14), V20
	ADD	$16, X14
	VLE32V	(X14), V21
	ADD	$16, X14
	VLE32V	(X14), V22
	ADD	$16, X14
	VLE32V	(X14), V23

	VSM4R_VS(4, 16) // VSM4RVS	V16, V4
	VSM4R_VS(4, 17) // VSM4RVS	V17, V4
	VSM4R_VS(4, 18) // VSM4RVS	V18, V4
	VSM4R_VS(4, 19) // VSM4RVS	V19, V4
	VSM4R_VS(4, 20) // VSM4RVS	V20, V4
	VSM4R_VS(4, 21) // VSM4RVS	V21, V4
	VSM4R_VS(4, 22) // VSM4RVS	V22, V4
	VSM4R_VS(4, 23) // VSM4RVS	V23, V4

	// H * 2
	VSLLVI $1, V4, V2
	VSRLVI $31, V4, V3
	VSLIDE1UPVX ZERO, V3, V1
	VORVV V2, V1, V2
	VSRAVI $31, V4, V3  // V3[3] = 0xFFFFFFFF or 0x0
	VSLIDEDOWNVI $3, V3, V1 // V1[0] = V3[3]
	VMVXS V1, X15
	VLE32V (X12), V3
	VANDVX X15, V3, V3
	VORVV V2, V3, V1
	
	// Karatsuba pre-computations
	VSLIDEDOWNVI $2, V1, V2
	VSLIDEUPVI $2, V1, V2
	VXORVV V1, V2, V2

	ADD $240, dst, X14
	VSE32V V2, (X14)
	SUB $16, X14, X14
	VSE32V V1, (X14)

	// Now prepare powers of H and pre-computations for them
	VSETIVLI	$2, E64, M1, TA, MA, X0
	MOV $0xC200000000000000, X15

initLoop:
		VCLMULVV V1, V1, V3
		VCLMULHVV V1, V1, V4
		VCLMULVV V2, V2, V5
		VCLMULHVV V2, V2, V6

		VXORVV V3, V4, V1
		VXORVV V1, V5, V5
		VSLIDEDOWNVI $1, V3, V2
		VXORVV V2, V5, V5
		VSLIDEUPVI $1, V5, V3

		VSLIDEDOWNVI $1, V1, V1
		VXORVV V1, V6, V6
		VXORVV V4, V6, V6
		VSLIDEDOWNVI $1, V4, V4
		VSLIDEUPVI $1, V4, V6  // result = [V3, V6]

		// Fast reduction
		// 1st reduction
		VCLMULVX X15, V3, V1
		VCLMULHVX X15, V3, V2
		VSLIDEUPVI $1, V2, V1
		VXORVV V1, V3, V3
		// 2nd reduction
		VCLMULVX X15, V3, V1
		VCLMULHVX X15, V3, V2
		VSLIDEUPVI $1, V2, V1
		VXORVV V1, V3, V3
		VXORVV V3, V6, V1

		VSLIDEDOWNVI $1, V1, V2
		VSLIDEUPVI $1, V1, V2
		VXORVV V1, V2, V2

		SUB $16, X14, X14
		VSE32V V2, (X14)
		SUB $16, X14, X14
		VSE32V V1, (X14)

	BNE ZERO, X14, initLoop
	RET

// func gcmSm4Data(productTable *[256]byte, data []byte, T *[16]byte)
TEXT ·gcmSm4Data(SB),NOSPLIT,$0
	RET

// func gcmSm4Finish(productTable *[256]byte, tagMask, T *[16]byte, pLen, dLen uint64)
TEXT ·gcmSm4Finish(SB),NOSPLIT,$0
	RET
	
// func gcmSm4Enc(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)
TEXT ·gcmSm4Enc(SB),0,$256-96
	RET

// func gcmSm4Dec(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)
TEXT ·gcmSm4Dec(SB),0,$128-96
	RET
