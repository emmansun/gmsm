// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.27 && !purego

#include "textflag.h"

#define ZERO X0
#define RSP X2
#define XK X10
#define DST X11
#define SRC X12
#define IV_LOW_LE X16
#define IV_HIGH_LE X17

// VSM4R_VS performs vsm4r.vs Vd, Vs2
// OP-P(0x77) | funct6=101001,vm=1 → 0x53 | vs2[24:20] | vs1=10000 | funct3=010 | vd
#define VSM4R_VS(Vd, Vs2) \
	WORD $((0x53 << 25) | ((Vs2) << 20) | (0x10 << 15) | (2 << 12) | ((Vd) << 7) | 0x77)

// VSM4K_VI performs vsm4k.vi Vd, Vs2, imm5
// OP-P(0x77) | funct6=100001,vm=1 → 0x43 | vs2[24:20] | imm[19:15] | funct3=010 | vd[11:7]
#define VSM4K_VI(Vd, Vs2, Imm) \
	WORD $((0x43 << 25) | ((Vs2) << 20) | ((Imm) << 15) | (2 << 12) | ((Vd) << 7) | 0x77)

#define stackaddress(index) ((index)*8+8)(RSP) // for RISCV64 stack usage, we CAN NOT overwrite the first 8 bytes space!

// res = a + b
// carryOut = 0 or 1
// a and res CAN'T be the same register
#define ADDS(a, b, res, carryOut) \
	ADD a, b, res                       \
	SLTU a, res, carryOut

// res = a + b + carryIn
#define ADC(carryIn, a, b, res) \
	ADD a, b, res                       \
	ADD carryIn, res, res

// func ctrBlocks1Asm(xk *uint32, dst, src *[BlockSize]byte, ivlo, ivhi uint64)
TEXT ·ctrBlocks1Asm(SB), NOSPLIT, $0
	MOV xk+0(FP), XK
	MOV dst+8(FP), DST
	MOV src+16(FP), SRC
	MOV ivlo+24(FP), IV_LOW_LE
	MOV ivhi+32(FP), IV_HIGH_LE

	VSETIVLI	$2, E64, M1, TA, MA, X0
	VMVSX IV_LOW_LE, V0
	VSLIDEUPVX  IV_HIGH_LE, V0, V4
	VREV8V	V4, V4

	VSETIVLI	$4, E32, M1, TA, MA, X0
	VLE32V	(XK), V16
	ADD	$16, XK, X13
	VLE32V	(X13), V17
	ADD	$16, X13
	VLE32V	(X13), V18
	ADD	$16, X13
	VLE32V	(X13), V19
	ADD	$16, X13
	VLE32V	(X13), V20
	ADD	$16, X13
	VLE32V	(X13), V21
	ADD	$16, X13
	VLE32V	(X13), V22
	ADD	$16, X13
	VLE32V	(X13), V23

	VSM4R_VS(4, 16) // VSM4RVS	V16, V4
	VSM4R_VS(4, 17) // VSM4RVS	V17, V4
	VSM4R_VS(4, 18) // VSM4RVS	V18, V4
	VSM4R_VS(4, 19) // VSM4RVS	V19, V4
	VSM4R_VS(4, 20) // VSM4RVS	V20, V4
	VSM4R_VS(4, 21) // VSM4RVS	V21, V4
	VSM4R_VS(4, 22) // VSM4RVS	V22, V4
	VSM4R_VS(4, 23) // VSM4RVS	V23, V4

	MOV	$·riscv64ZvksedRev(SB), X13
	VLE32V	(X13), V24	// reversal index
	VRGATHERVV	V24, V4, V0
	VREV8V	V0, V0
	VLE32V (SRC), V24
	VXORVV V0, V24, V4
	VSE32V	V4, (DST)
	RET

// func ctrBlocks2Asm(xk *uint32, dst, src *[2 * BlockSize]byte, ivlo, ivhi uint64)
TEXT ·ctrBlocks2Asm(SB), 0, $40-40
	MOV xk+0(FP), XK
	MOV dst+8(FP), DST
	MOV src+16(FP), SRC
	MOV ivlo+24(FP), IV_LOW_LE
	MOV ivhi+32(FP), IV_HIGH_LE

	MOV IV_HIGH_LE, stackaddress(0)
	MOV IV_LOW_LE, stackaddress(1)
	ADD $1, IV_LOW_LE, X13
	SLTU IV_LOW_LE, X13, X14
	ADD X14, IV_HIGH_LE, X15
	MOV X15, stackaddress(2)
	MOV X13, stackaddress(3)

	VSETIVLI	$4, E64, M1, TA, MA, X0
	VLE64V	stackaddress(0), V4
	VREV8V	V4, V4

	// round keys, shared by the 2-block and tail paths
	VSETIVLI	$4, E32, M1, TA, MA, X0
	VLE32V	(XK), V8
	ADD	$16, XK, X14
	VLE32V	(X14), V10
	ADD	$16, X14
	VLE32V	(X14), V12
	ADD	$16, X14
	VLE32V	(X14), V14
	ADD	$16, X14
	VLE32V	(X14), V16
	ADD	$16, X14
	VLE32V	(X14), V18
	ADD	$16, X14
	VLE32V	(X14), V20
	ADD	$16, X14
	VLE32V	(X14), V22

	VSETIVLI	$8, E32, M2, TA, MA, X0
	MOV	$·riscv64ZvksedRev(SB), X13
	VLE32V	(X13), V24	// reversal index (loop-invariant)

	VSM4R_VS(4, 8)  // VSM4RVS	V8, V4
	VSM4R_VS(4, 10) // VSM4RVS	V10, V4
	VSM4R_VS(4, 12) // VSM4RVS	V12, V4
	VSM4R_VS(4, 14) // VSM4RVS	V14, V4
	VSM4R_VS(4, 16) // VSM4RVS	V16, V4
	VSM4R_VS(4, 18) // VSM4RVS	V18, V4
	VSM4R_VS(4, 20) // VSM4RVS	V20, V4
	VSM4R_VS(4, 22) // VSM4RVS	V22, V4

	VRGATHERVV	V24, V4, V4
	VREV8V	V4, V4
	VLE32V (SRC), V24
	VXORVV V4, V24, V4
	VSE32V	V4, (DST)	
	RET

// func ctrBlocks4Asm(xk *uint32, dst, src *[4 * BlockSize]byte, ivlo, ivhi uint64)
TEXT ·ctrBlocks4Asm(SB), NOSPLIT, $0
	RET

// func ctrBlocks8Asm(xk *uint32, dst, src *[8 * BlockSize]byte, ivlo, ivhi uint64)
TEXT ·ctrBlocks8Asm(SB), NOSPLIT, $0
	RET
