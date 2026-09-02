// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && go1.26 && !purego

#include "textflag.h"

// VSM3C_VI performs vsm3c.vi Vd, Vs2, imm5
// Opcode base: 0x77, funct3: 0x2 (OPMVV), funct7: 0x57
// Encoding: funct7 | vs2 | imm5 | funct3 | vd | opcode
#define VSM3C_VI(Vd, Vs2, Imm) \
	WORD $((0x57 << 25) | ((Vs2) << 20) | ((Imm) << 15) | (2 << 12) | ((Vd) << 7) | 0x77)

// VSM3ME_VV performs vsm3me.vv Vd, Vs2, Vs1
// Opcode base: 0x77, funct3: 0x2 (OPMVV), funct7: 0x41
// Encoding: funct7 | vs2 | vs1 | funct3 | vd | opcode
#define VSM3ME_VV(Vd, Vs2, Vs1) \
	WORD $((0x41 << 25) | ((Vs2) << 20) | ((Vs1) << 15) | (2 << 12) | ((Vd) << 7) | 0x77)

// func blockZVKSH(dig *digest, p []byte)
TEXT ·blockZVKSH(SB), NOSPLIT, $0-32
	MOV	dig+0(FP), X10
	MOV	p_base+8(FP), X11
	MOV	p_len+16(FP), X12

	BEQ	X12, ZERO, end

	ADD	X11, X12, X13

	VSETIVLI	$8, E32, M2, TA, MA, X0
	VLE32V	(X10), V16
	VREV8V	V16, V16

loop:
	VMVVV	V16, V18
	VLE32V	(X11), V2	// W[0..7]
	ADD	$32, X11
	VLE32V	(X11), V4	// W[8..15]
	ADD	$32, X11

	// rounds 0,1
	VSM3C_VI(16, 2, 0) // VSM3CVI	$0, V2, V16
	VSLIDEDOWNVI	$2, V2, V6
	VSM3C_VI(16, 6, 1) // VSM3CVI	$1, V6, V16
	// rounds 2,3
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V4, V6
	VSM3C_VI(16, 6, 2) // VSM3CVI	$2, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 3) // VSM3CVI	$3, V6, V16
	// rounds 4,5
	VSM3C_VI(16, 4, 4) // VSM3CVI	$4, V4, V16
	VSLIDEDOWNVI	$2, V4, V6
	VSM3C_VI(16, 6, 5) // VSM3CVI	$5, V6, V16
	// expand W[16..23] into V2
	VSM3ME_VV(2, 4, 2) // VSM3MEVV	V2, V4, V2
	// rounds 6,7
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V2, V6
	VSM3C_VI(16, 6, 6) // VSM3CVI	$6, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 7) // VSM3CVI	$7, V6, V16
	// rounds 8,9
	VSM3C_VI(16, 2, 8) // VSM3CVI	$8, V2, V16
	VSLIDEDOWNVI	$2, V2, V6
	VSM3C_VI(16, 6, 9) // VSM3CVI	$9, V6, V16
	// expand W[24..31] into V4
	VSM3ME_VV(4, 2, 4) // VSM3MEVV	V4, V2, V4
	// rounds 10,11
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V4, V6
	VSM3C_VI(16, 6, 10) // VSM3CVI	$10, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 11) // VSM3CVI	$11, V6, V16
	// rounds 12,13
	VSM3C_VI(16, 4, 12) // VSM3CVI	$12, V4, V16
	VSLIDEDOWNVI	$2, V4, V6
	VSM3C_VI(16, 6, 13) // VSM3CVI	$13, V6, V16
	// expand W[32..39] into V2
	VSM3ME_VV(2, 4, 2) // VSM3MEVV	V2, V4, V2
	// rounds 14,15
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V2, V6
	VSM3C_VI(16, 6, 14) // VSM3CVI	$14, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 15) // VSM3CVI	$15, V6, V16
	// rounds 16,17
	VSM3C_VI(16, 2, 16) // VSM3CVI	$16, V2, V16
	VSLIDEDOWNVI	$2, V2, V6
	VSM3C_VI(16, 6, 17) // VSM3CVI	$17, V6, V16
	// expand W[40..47] into V4
	VSM3ME_VV(4, 2, 4) // VSM3MEVV	V4, V2, V4
	// rounds 18,19
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V4, V6
	VSM3C_VI(16, 6, 18) // VSM3CVI	$18, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 19) // VSM3CVI	$19, V6, V16
	// rounds 20,21
	VSM3C_VI(16, 4, 20) // VSM3CVI	$20, V4, V16
	VSLIDEDOWNVI	$2, V4, V6
	VSM3C_VI(16, 6, 21) // VSM3CVI	$21, V6, V16
	// expand W[48..55] into V2
	VSM3ME_VV(2, 4, 2) // VSM3MEVV	V2, V4, V2
	// rounds 22,23
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V2, V6
	VSM3C_VI(16, 6, 22) // VSM3CVI	$22, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 23) // VSM3CVI	$23, V6, V16
	// rounds 24,25
	VSM3C_VI(16, 2, 24) // VSM3CVI	$24, V2, V16
	VSLIDEDOWNVI	$2, V2, V6
	VSM3C_VI(16, 6, 25) // VSM3CVI	$25, V6, V16
	// expand W[56..63] into V4
	VSM3ME_VV(4, 2, 4) // VSM3MEVV	V4, V2, V4
	// rounds 26,27
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V4, V6
	VSM3C_VI(16, 6, 26) // VSM3CVI	$26, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 27) // VSM3CVI	$27, V6, V16
	// rounds 28,29
	VSM3C_VI(16, 4, 28) // VSM3CVI	$28, V4, V16
	VSLIDEDOWNVI	$2, V4, V6
	VSM3C_VI(16, 6, 29) // VSM3CVI	$29, V6, V16
	// expand W[64..71] into V2
	VSM3ME_VV(2, 4, 2) // VSM3MEVV	V2, V4, V2
	// rounds 30,31
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V2, V6
	VSM3C_VI(16, 6, 30) // VSM3CVI	$30, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 31) // VSM3CVI	$31, V6, V16

	VXORVV	V18, V16, V16	// state ^= previous state
	BNE	X11, X13, loop

	VREV8V	V16, V16
	VSE32V	V16, (X10)

end:
	RET
