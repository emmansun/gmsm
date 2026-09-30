// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && go1.27 && !purego

#include "textflag.h"

// SM4 using the Zvksed extension (vsm4k.vi, vsm4r.vs/vv) plus Zvbb (vrev8)
// for byte order.
//
// Data convention: the round-key arrays hold SM4 words as integers, so they
// are loaded/stored with plain vle32/vse32. The 16-byte block is byte-swapped
// with vrev8 after loading (and before storing), because SM4 words are
// big-endian. After the last vsm4r round the state words are in elements
// 0..3 = X[32..35]; the ciphertext is the reverse word order Y[i] = X[35-i],
// so the store reverses the element order.
//
// vsm4r.vs broadcasts the 4 round keys of vs2 element group 0 to every
// element group of vd, so a single register group processes 2 blocks per
// pass under LMUL=2.

// FK system parameters for the key schedule, as integers.
DATA ·riscv64ZvksedFK+0(SB)/4, $0xa3b1bac6
DATA ·riscv64ZvksedFK+4(SB)/4, $0x56aa3350
DATA ·riscv64ZvksedFK+8(SB)/4, $0x677d9197
DATA ·riscv64ZvksedFK+12(SB)/4, $0xb27022dc
GLOBL ·riscv64ZvksedFK(SB), RODATA, $16

// Element-reversal index for the multi-block store (first 8 entries used
// per pass under vl=8).
DATA ·riscv64ZvksedRev+0(SB)/4, $3
DATA ·riscv64ZvksedRev+4(SB)/4, $2
DATA ·riscv64ZvksedRev+8(SB)/4, $1
DATA ·riscv64ZvksedRev+12(SB)/4, $0
DATA ·riscv64ZvksedRev+16(SB)/4, $7
DATA ·riscv64ZvksedRev+20(SB)/4, $6
DATA ·riscv64ZvksedRev+24(SB)/4, $5
DATA ·riscv64ZvksedRev+28(SB)/4, $4
DATA ·riscv64ZvksedRev+32(SB)/4, $11
DATA ·riscv64ZvksedRev+36(SB)/4, $10
DATA ·riscv64ZvksedRev+40(SB)/4, $9
DATA ·riscv64ZvksedRev+44(SB)/4, $8
DATA ·riscv64ZvksedRev+48(SB)/4, $15
DATA ·riscv64ZvksedRev+52(SB)/4, $14
DATA ·riscv64ZvksedRev+56(SB)/4, $13
DATA ·riscv64ZvksedRev+60(SB)/4, $12
GLOBL ·riscv64ZvksedRev(SB), RODATA, $64

// https://github.com/golang/go/blob/master/src/cmd/internal/obj/riscv/inst.go
// VSM4R_VV performs vsm4r.vv Vd, Vs2
// OP-P(0x77) | funct6=101000,vm=1 → 0x51 | vs2[24:20] | vs1=10000 | funct3=010 | vd
#define VSM4R_VV(Vd, Vs2) \
	WORD $((0x51 << 25) | ((Vs2) << 20) | (0x10 << 15) | (2 << 12) | ((Vd) << 7) | 0x77)

// VSM4R_VS performs vsm4r.vs Vd, Vs2
// OP-P(0x77) | funct6=101001,vm=1 → 0x53 | vs2[24:20] | vs1=10000 | funct3=010 | vd
#define VSM4R_VS(Vd, Vs2) \
	WORD $((0x53 << 25) | ((Vs2) << 20) | (0x10 << 15) | (2 << 12) | ((Vd) << 7) | 0x77)

// VSM4K_VI performs vsm4k.vi Vd, Vs2, imm5
// OP-P(0x77) | funct6=100001,vm=1 → 0x43 | vs2[24:20] | imm[19:15] | funct3=010 | vd[11:7]
#define VSM4K_VI(Vd, Vs2, Imm) \
	WORD $((0x43 << 25) | ((Vs2) << 20) | ((Imm) << 15) | (2 << 12) | ((Vd) << 7) | 0x77)

// func encryptBlockAsm(xk *uint32, dst, src *byte, inst int)
TEXT ·encryptBlockAsm(SB), NOSPLIT, $0
	MOV	xk+0(FP), X10
	MOV	dst+8(FP), X11
	MOV	src+16(FP), X12

	VSETIVLI	$4, E32, M1, TA, MA, X0

	// Load the input data.
	VLE32V	(X12), V4
	VREV8V	V4, V4	

	VLE32V	(X10), V16
	ADD	$16, X10, X13
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

	// Store the output data (in reverse element order).
	VREV8V	V4, V4	
	MOV	$-4, X14
	ADD	$12, X11, X15
	VSSE32V	V4, X14, (X15)	// store words in reverse element order
	RET

// func encryptBlocksAsm(xk *uint32, dst, src []byte, inst int)
TEXT ·encryptBlocksAsm(SB), NOSPLIT, $0
	MOV	xk+0(FP), X10
	MOV	dst_base+8(FP), X11
	MOV	src_base+32(FP), X12
	MOV	src_len+40(FP), X13

	VSETIVLI	$4, E32, M1, TA, MA, X0

	// round keys, shared by the 2-block and tail paths
	VLE32V	(X10), V8
	ADD	$16, X10, X14
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

	// 2-block loop bound: end32 = src + (len & ~31); tail handles len%32.
	AND	$-32, X13, X14
	BEQ	X14, ZERO, tail
	ADD	X12, X14, X14

	VSETIVLI	$8, E32, M2, TA, MA, X0
	MOV	$·riscv64ZvksedRev(SB), X16
	VLE32V	(X16), V24	// reversal index (loop-invariant)

loop4:
	VLE32V	(X12), V4
	ADD	$32, X12
	VREV8V	V4, V4
	VSM4R_VS(4, 8)  // VSM4RVS	V8, V4
	VSM4R_VS(4, 10) // VSM4RVS	V10, V4
	VSM4R_VS(4, 12) // VSM4RVS	V12, V4
	VSM4R_VS(4, 14) // VSM4RVS	V14, V4
	VSM4R_VS(4, 16) // VSM4RVS	V16, V4
	VSM4R_VS(4, 18) // VSM4RVS	V18, V4
	VSM4R_VS(4, 20) // VSM4RVS	V20, V4
	VSM4R_VS(4, 22) // VSM4RVS	V22, V4
	VREV8V	V4, V4
	VRGATHERVV	V24, V4, V26
	VSE32V	V26, (X11)
	ADD	$32, X11
	BNE	X12, X14, loop4

tail:
	AND	$31, X13, X13	// remaining bytes: 0 or 16 (len is a multiple of 16)
	BEQ	X13, ZERO, ret
	// single remaining block; keep LMUL=2, only vl 8 -> 4
	VSETIVLI	$4, E32, M2, TA, MA, X0
	MOV	$-4, X17
	VLE32V	(X12), V4
	ADD	$16, X12
	VREV8V	V4, V4
	VSM4R_VS(4, 8)  // VSM4RVS	V8, V4
	VSM4R_VS(4, 10) // VSM4RVS	V10, V4
	VSM4R_VS(4, 12) // VSM4RVS	V12, V4
	VSM4R_VS(4, 14) // VSM4RVS	V14, V4
	VSM4R_VS(4, 16) // VSM4RVS	V16, V4
	VSM4R_VS(4, 18) // VSM4RVS	V18, V4
	VSM4R_VS(4, 20) // VSM4RVS	V20, V4
	VSM4R_VS(4, 22) // VSM4RVS	V22, V4
	VREV8V	V4, V4
	ADD	$12, X11, X18
	VSSE32V	V4, X17, (X18)
	ADD	$16, X11

ret:
	RET

// func expandKeyAsm(key *byte, ck, enc, dec *uint32, inst int)
// Key schedule using vsm4k.vi; the CK constants are generated in hardware.
// dec[] receives the round keys in reverse order.
TEXT ·expandKeyAsm(SB), NOSPLIT, $0
	MOV	key+0(FP), X10
	MOV	enc+16(FP), X11
	MOV	dec+24(FP), X12

	VSETIVLI	$4, E32, M1, TA, MA, X0

	// Load the user key
	VLE32V	(X10), V4	// MK, little-endian words
	VREV8V	V4, V4		// MK, big-endian

	// XOR the user key with the family key.
	MOV	$·riscv64ZvksedFK(SB), X13
	VLE32V	(X13), V1
	VXORVV	V1, V4, V4	// K[0..3] = MK ^ FK

	VSM4K_VI(1, 4, 0) // VSM4KVI	$0, V4, V1
	VSM4K_VI(2, 1, 1) // VSM4KVI	$1, V1, V2
	VSM4K_VI(3, 2, 2) // VSM4KVI	$2, V2, V3
	VSM4K_VI(4, 3, 3) // VSM4KVI	$3, V3, V4
	VSM4K_VI(5, 4, 4) // VSM4KVI	$4, V4, V5
	VSM4K_VI(6, 5, 5) // VSM4KVI	$5, V5, V6
	VSM4K_VI(7, 6, 6) // VSM4KVI	$6, V6, V7
	VSM4K_VI(8, 7, 7) // VSM4KVI	$7, V7, V8

	VSE32V	V1, (X11)
	ADD	$16, X11, X14
	VSE32V	V2, (X14)
	ADD	$16, X14
	VSE32V	V3, (X14)
	ADD	$16, X14
	VSE32V	V4, (X14)
	ADD	$16, X14
	VSE32V	V5, (X14)
	ADD	$16, X14
	VSE32V	V6, (X14)
	ADD	$16, X14
	VSE32V	V7, (X14)
	ADD	$16, X14
	VSE32V	V8, (X14)

	// dec[i] = rk[31-i]: store each group with reversed element order
	MOV	$-4, X15
	ADD	$12, X12, X16
	VSSE32V	V8, X15, (X16)
	ADD	$16, X16
	VSSE32V	V7, X15, (X16)
	ADD	$16, X16
	VSSE32V	V6, X15, (X16)
	ADD	$16, X16
	VSSE32V	V5, X15, (X16)
	ADD	$16, X16
	VSSE32V	V4, X15, (X16)
	ADD	$16, X16
	VSSE32V	V3, X15, (X16)
	ADD	$16, X16
	VSSE32V	V2, X15, (X16)
	ADD	$16, X16
	VSSE32V	V1, X15, (X16)
	RET
