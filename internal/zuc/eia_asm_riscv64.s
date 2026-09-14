// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.27 && !purego

#include "textflag.h"

#define ZERO X0
#define RSP X2

DATA eia_const<>+0x00(SB)/8, $0x0f0f0f0f0f0f0f0f
DATA eia_const<>+0x08(SB)/8, $0x0f0f0f0f0f0f0f0f
DATA eia_const<>+0x10(SB)/8, $0x0e060a020c040800 // bit_reverse_table low
DATA eia_const<>+0x18(SB)/8, $0x0f070b030d050901
DATA eia_const<>+0x20(SB)/8, $0xe060a020c0408000 // bit_reverse_table high
DATA eia_const<>+0x28(SB)/8, $0xf070b030d0509010
GLOBL eia_const<>(SB), RODATA, $48

// func eiaRoundTag4(t *uint32, keyStream *uint32, p *byte)
TEXT ·eiaRoundTag4(SB),NOSPLIT,$0
	MOV t+0(FP), X8
	MOV ks+8(FP), X9
	MOV p+16(FP), X10

	// Load constants into vector registers
	VSETIVLI	$16, E8, M1, TA, MA, X0
	MOV	$eia_const<>(SB), X11
	VLE8V (X11), V1
	ADD $16, X11
	VLE8V (X11), V2
	ADD $16, X11
	VLE8V (X11), V3

	// Load data
	VLE8V (X10), V6

	// Reverse data bytes
	VANDVV V1, V6, V7
	VRGATHERVV V7, V3, V8
	VSRLVI $4, V6, V7
	VRGATHERVV V7, V2, V9
	VORVV V8, V9, V6

	VSETIVLI	$2, E64, M1, TA, MA, X0
	// ZUC authentication part, 4x32 data bits
	// Setup KS
	VLE64V	(X9), V7
	VSRLVI $32, V7, V8           // [W1, 0, W3, 0]
	VSLLVI $32, V7, V7           // [0, W0, 0, W2]
	VORVV V7, V8, V7             // [W1, W0, W3, W2]
	ADD $8, X9
	VLE64V	(X9), V8
	VSRLVI $32, V8, V9           // [W3, 0, W5, 0]
	VSLLVI $32, V8, V8           // [0, W2, 0, W4]
	VORVV V8, V9, V8             // [W3, W2, W5, W4]

	// Setup DATA
	VSRLVI $32, V6, V9          // [W1, 0, W3, 0]
	VSLLVI $32, V6, V10         // [0, W0, 0, W2]
	VSRLVI $32, V10, V6         // [W0, 0, W2, 0]
	VSLIDEDOWNVI $1, V6, V10    // [W2, 0, 0, 0]
	VSLIDEUPVI $1, V9, V6       // [W0, 0, W1, 0]
	VSLIDEDOWNVI $1, V9, V9    // [W3, 0, 0, 0]
	VSLIDEUPVI $1, V9, V10      // [W2, 0, W3, 0]

	// clmul
	// xor the results from 4 32-bit words together
	// Calculate lower 32 bits of tag
	VCLMULVV V7, V6, V11        // LOW(KS_L, DATA_L)
	VCLMULVV V8, V10, V13       // LOW(KS_H, DATA_H)
	VXORVV V11, V13, V11        // LOW(KS_L, DATA_L) XOR LOW(KS_H, DATA_H)
	VSLIDEDOWNVI $1, V13, V13
	VXORVV V13, V11, V11

	// Update tag
	VMVXS V11, X11
	SRL $32, X11
	MOVWU (X8), X12
	XOR X11, X12, X11
	MOVW X11, (X8)

	// Copy last 16 bytes of KS to the front
	ADD $8, X9
	VLE64V	(X9), V6
	SUB $16, X9
	VSE64V V6, (X9)

	RET

// func eia256RoundTag8(t *uint32, keyStream *uint32, p *byte)
TEXT ·eia256RoundTag8(SB),NOSPLIT,$0
	MOV t+0(FP), X8
	MOV ks+8(FP), X9
	MOV p+16(FP), X10
	RET

// func eia256RoundTag16(t *uint32, keyStream *uint32, p *byte)
TEXT ·eia256RoundTag16(SB),NOSPLIT,$0
	MOV t+0(FP), X8
	MOV ks+8(FP), X9
	MOV p+16(FP), X10
	RET
