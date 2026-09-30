// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && go1.27 && !purego

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
	// Save the previous state.
	VMVVV	V16, V18

	// Load the next 64 bytes of input data.
	VLE32V	(X11), V2	// W[0..7]
	ADD	$32, X11
	VLE32V	(X11), V4	// W[8..15]
	ADD	$32, X11

	// Do 4 rounds using W_{0}..W_{7}.
	VSM3C_VI(16, 2, 0) // VSM3CVI	$0, V2, V16
	VSLIDEDOWNVI	$2, V2, V6
	VSM3C_VI(16, 6, 1) // VSM3CVI	$1, V6, V16
	// Prepare W_{4}..W_{11}.
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V4, V6
	// Do 4 rounds using W_{4}..W_{11}.
	VSM3C_VI(16, 6, 2) // VSM3CVI	$2, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 3) // VSM3CVI	$3, V6, V16
	// Compute W_{16}..W_{23}.
	VSM3ME_VV(2, 4, 2) // VSM3MEVV	V2, V4, V2

	// Do 4 rounds using W_{8}..W_{15}.
	VSM3C_VI(16, 4, 4) // VSM3CVI	$4, V4, V16
	VSLIDEDOWNVI	$2, V4, V6
	VSM3C_VI(16, 6, 5) // VSM3CVI	$5, V6, V16
	// Prepare W_{12}..W_{19}.
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V2, V6
	// Do 4 rounds using W_{12}..W_{19}.
	VSM3C_VI(16, 6, 6) // VSM3CVI	$6, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 7) // VSM3CVI	$7, V6, V16
	// Compute W_{24}..W_{31}.
	VSM3ME_VV(4, 2, 4) // VSM3MEVV	V4, V2, V4

	// Do 4 rounds using W_{16}..W_{23}.
	VSM3C_VI(16, 2, 8) // VSM3CVI	$8, V2, V16
	VSLIDEDOWNVI	$2, V2, V6
	VSM3C_VI(16, 6, 9) // VSM3CVI	$9, V6, V16
	// Prepare W_{20}..W_{27}.
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V4, V6
	// Do 4 rounds using W_{20}..W_{27}.
	VSM3C_VI(16, 6, 10) // VSM3CVI	$10, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 11) // VSM3CVI	$11, V6, V16
	// Compute W_{32}..W_{39}.
	VSM3ME_VV(2, 4, 2) // VSM3MEVV	V2, V4, V2

	// Do 4 rounds using W_{24}..W_{31}.
	VSM3C_VI(16, 4, 12) // VSM3CVI	$12, V4, V16
	VSLIDEDOWNVI	$2, V4, V6
	VSM3C_VI(16, 6, 13) // VSM3CVI	$13, V6, V16
	// Prepare W_{28}..W_{35}.
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V2, V6
	// Do 4 rounds using W_{28}..W_{35}.
	VSM3C_VI(16, 6, 14) // VSM3CVI	$14, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 15) // VSM3CVI	$15, V6, V16
	// Compute W_{40}..W_{47}.
	VSM3ME_VV(4, 2, 4) // VSM3MEVV	V4, V2, V4

	// Do 4 rounds using W_{32}..W_{39}.
	VSM3C_VI(16, 2, 16) // VSM3CVI	$16, V2, V16
	VSLIDEDOWNVI	$2, V2, V6
	VSM3C_VI(16, 6, 17) // VSM3CVI	$17, V6, V16
	// Prepare W_{36}..W_{43}.
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V4, V6
	// Do 4 rounds using W_{36}..W_{43}.
	VSM3C_VI(16, 6, 18) // VSM3CVI	$18, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 19) // VSM3CVI	$19, V6, V16
	// Compute W_{48}..W_{55}.
	VSM3ME_VV(2, 4, 2) // VSM3MEVV	V2, V4, V2

	// Do 4 rounds using W_{40}..W_{47}.
	VSM3C_VI(16, 4, 20) // VSM3CVI	$20, V4, V16
	VSLIDEDOWNVI	$2, V4, V6
	VSM3C_VI(16, 6, 21) // VSM3CVI	$21, V6, V16
	// Prepare W_{44}..W_{51}.
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V2, V6
	// Do 4 rounds using W_{44}..W_{51}.
	VSM3C_VI(16, 6, 22) // VSM3CVI	$22, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 23) // VSM3CVI	$23, V6, V16
	// Compute W_{56}..W_{63}.
	VSM3ME_VV(4, 2, 4) // VSM3MEVV	V4, V2, V4

	// Do 4 rounds using W_{48}..W_{55}.
	VSM3C_VI(16, 2, 24) // VSM3CVI	$24, V2, V16
	VSLIDEDOWNVI	$2, V2, V6
	VSM3C_VI(16, 6, 25) // VSM3CVI	$25, V6, V16
	// Prepare W_{52}..W_{59}.
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V4, V6
	// Do 4 rounds using W_{52}..W_{59}.
	VSM3C_VI(16, 6, 26) // VSM3CVI	$26, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 27) // VSM3CVI	$27, V6, V16
	// Compute W_{64}..W_{71}.
	VSM3ME_VV(2, 4, 2) // VSM3MEVV	V2, V4, V2

	// Do 4 rounds using W_{56}..W_{63}.
	VSM3C_VI(16, 4, 28) // VSM3CVI	$28, V4, V16
	VSLIDEDOWNVI	$2, V4, V6
	VSM3C_VI(16, 6, 29) // VSM3CVI	$29, V6, V16
	// Prepare W_{60}..W_{67}.
	VSLIDEDOWNVI	$2, V6, V6
	VSLIDEUPVI	$4, V2, V6
	// Do 4 rounds using W_{60}..W_{67}.
	VSM3C_VI(16, 6, 30) // VSM3CVI	$30, V6, V16
	VSLIDEDOWNVI	$2, V6, V6
	VSM3C_VI(16, 6, 31) // VSM3CVI	$31, V6, V16

	VXORVV	V18, V16, V16	// state ^= previous state
	BNE	X11, X13, loop

	VREV8V	V16, V16
	VSE32V	V16, (X10)

end:
	RET
