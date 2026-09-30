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

	VSETIVLI	$16, E8, M1, TA, MA, X0
	// Load data
	VLE8V (X10), V6

	// Reverse data bits
	MOVBU ·supportsZvbb+0(SB), X11
	BEQZ X11, noZvbb
	VBREV8V V6, V6
	JMP setupKS

noZvbb:
	MOV	$eia_const<>(SB), X11
	VLE8V (X11), V1
	ADD $16, X11
	VLE8V (X11), V2
	ADD $16, X11
	VLE8V (X11), V3
	VANDVV V1, V6, V7
	VRGATHERVV V7, V3, V8
	VSRLVI $4, V6, V7
	VRGATHERVV V7, V2, V9
	VORVV V8, V9, V6

setupKS:
	MOV $4, X14
	MOV $32, X15
	VSETIVLI	$2, E64, M1, TA, MA, X0
	// ZUC authentication part, 4x32 data bits
	// Setup KS
	VLSE64V	(X9), X14, V7        // [W0, W1, W1, W2]
	VSRLVX X15, V7, V8           // [W1, 0, W2, 0]
	VSLLVX X15, V7, V7           // [0, W0, 0, W1]
	VORVV V7, V8, V7             // [W1, W0, W2, W1]
	ADD $8, X9
	VLSE64V	(X9), X14, V8        // [W2, W3, W3, W4]
	VSRLVX X15, V8, V9           // [W3, 0, W4, 0]
	VSLLVX X15, V8, V8           // [0, W2, 0, W3]
	VORVV V8, V9, V8             // [W3, W2, W4, W3]

	// Setup DATA
	VSRLVX X15, V6, V9          // [W1, 0, W3, 0]
	VSLLVX X15, V6, V10         // [0, W0, 0, W2]
	VSRLVX X15, V10, V6         // [W0, 0, W2, 0]
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
	VSLIDEDOWNVI $1, V11, V13
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

	VSETIVLI	$16, E8, M1, TA, MA, X0
	// Load data
	VLE8V (X10), V6

	// Reverse data bits
	MOVBU ·supportsZvbb+0(SB), X11
	BEQZ X11, noZvbb
	VBREV8V V6, V6
	JMP setupKS

noZvbb:
	MOV	$eia_const<>(SB), X11
	VLE8V (X11), V1
	ADD $16, X11
	VLE8V (X11), V2
	ADD $16, X11
	VLE8V (X11), V3
	VANDVV V1, V6, V7
	VRGATHERVV V7, V3, V8
	VSRLVI $4, V6, V7
	VRGATHERVV V7, V2, V9
	VORVV V8, V9, V6

setupKS:
	MOV $4, X14
	MOV $32, X15
	VSETIVLI	$2, E64, M1, TA, MA, X0
	// ZUC authentication part, 4x32 data bits
	// Setup KS
	VLSE64V	(X9), X14, V7        // [W0, W1, W1, W2]
	VSRLVX X15, V7, V8           // [W1, 0, W2, 0]
	VSLLVX X15, V7, V7           // [0, W0, 0, W1]
	VORVV V7, V8, V7             // [W1, W0, W2, W1]
	ADD $8, X9
	VLSE64V	(X9), X14, V8        // [W2, W3, W3, W4]
	VSRLVX X15, V8, V9           // [W3, 0, W4, 0]
	VSLLVX X15, V8, V8           // [0, W2, 0, W3]
	VORVV V8, V9, V8             // [W3, W2, W4, W3]	
	ADD $8, X9
	VLSE64V	(X9), X14, V9        // [W4, W5, W5, W6]
	VSRLVX X15, V9, V10          // [W5, 0, W6, 0]
	VSLLVX X15, V9, V9           // [0, W4, 0, W5]
	VORVV V10, V9, V9            // [W5, W4, W6, W5]

	// Setup DATA
	VSRLVX X15, V6, V10          // [W1, 0, W3, 0]
	VSLLVX X15, V6, V11          // [0, W0, 0, W2]
	VSRLVX X15, V11, V6          // [W0, 0, W2, 0]
	VSLIDEDOWNVI $1, V6, V11     // [W2, 0, 0, 0]
	VSLIDEUPVI $1, V10, V6       // [W0, 0, W1, 0]
	VSLIDEDOWNVI $1, V10, V10    // [W3, 0, 0, 0]
	VSLIDEUPVI $1, V10, V11      // [W2, 0, W3, 0]

	// clmul
	// xor the results from 4 32-bit words together
	// Calculate lower 32 bits of tag
	VCLMULVV V7, V6, V12        // LOW(KS_L, DATA_L)
	VCLMULVV V8, V11, V13       // LOW(KS_H, DATA_H)
	VXORVV V12, V13, V12        // LOW(KS_L, DATA_L) XOR LOW(KS_H, DATA_H)
	VSLIDEDOWNVI $1, V12, V13
	VXORVV V13, V12, V12
	VMVXS V12, X11
	SRL $32, X11

	// Prepare ks and calculate bits 63-32 of tag
	VSLIDEDOWNVI $1, V7, V7     // [W2, W1, 0, 0]
	VSLIDEUPVI $1, V8, V7       // [W2, W1, W3, W2]
	VSLIDEDOWNVI $1, V8, V8     // [W4, W3, 0, 0]
	VSLIDEUPVI $1, V9, V8       // [W4, W3, W5, W4]
	VCLMULVV V7, V6, V12        // LOW(KS_L, DATA_L)
	VCLMULVV V8, V11, V13       // LOW(KS_H, DATA_H)
	VXORVV V12, V13, V12        // LOW(KS_L, DATA_L) XOR LOW(KS_H, DATA_H)
	VSLIDEDOWNVI $1, V12, V13
	VXORVV V13, V12, V12
	VMVXS V12, X12
	SRL $32, X12
	SLL $32, X12
	OR X11, X12, X11

	MOV (X8), X12
	XOR X11, X12, X11
	MOV X11, (X8)

	// Copy last 16 bytes of KS to the front
	VLE64V	(X9), V6
	SUB $16, X9
	VSE64V V6, (X9)

	RET

// func eia256RoundTag16(t *uint32, keyStream *uint32, p *byte)
TEXT ·eia256RoundTag16(SB),NOSPLIT,$0
	MOV t+0(FP), X8
	MOV ks+8(FP), X9
	MOV p+16(FP), X10

	VSETIVLI	$16, E8, M1, TA, MA, X0
	// Load data
	VLE8V (X10), V6

	// Reverse data bits
	MOVBU ·supportsZvbb+0(SB), X11
	BEQZ X11, noZvbb
	VBREV8V V6, V6
	JMP setupKS

noZvbb:
	MOV	$eia_const<>(SB), X11
	VLE8V (X11), V1
	ADD $16, X11
	VLE8V (X11), V2
	ADD $16, X11
	VLE8V (X11), V3
	VANDVV V1, V6, V7
	VRGATHERVV V7, V3, V8
	VSRLVI $4, V6, V7
	VRGATHERVV V7, V2, V9
	VORVV V8, V9, V6

setupKS:
	MOV $4, X14
	MOV $32, X15
	VSETIVLI	$2, E64, M1, TA, MA, X0
	// ZUC authentication part, 4x32 data bits
	// Setup KS
	VLSE64V	(X9), X14, V7        // [W0, W1, W1, W2]
	VSRLVX X15, V7, V8           // [W1, 0, W2, 0]
	VSLLVX X15, V7, V7           // [0, W0, 0, W1]
	VORVV V7, V8, V7             // [W1, W0, W2, W1]
	ADD $8, X9
	VLSE64V	(X9), X14, V8        // [W2, W3, W3, W4]
	VSRLVX X15, V8, V9           // [W3, 0, W4, 0]
	VSLLVX X15, V8, V8           // [0, W2, 0, W3]
	VORVV V8, V9, V8             // [W3, W2, W4, W3]	
	ADD $8, X9
	VLSE64V	(X9), X14, V9        // [W4, W5, W5, W6]
	VSRLVX X15, V9, V10          // [W5, 0, W6, 0]
	VSLLVX X15, V9, V9           // [0, W4, 0, W5]
	VORVV V10, V9, V9            // [W5, W4, W6, W5]
	ADD $8, X9
	VLSE64V	(X9), X14, V10       // [W6, W7, W7, X]
	VSRLVX X15, V10, V11         // [W7, 0, W8, 0]
	VSLLVX X15, V10, V10         // [0, W6, 0, W7]
	VORVV V11, V10, V10          // [W7, W6, X, W7]

	// Setup DATA
	VSRLVX X15, V6, V11          // [W1, 0, W3, 0]
	VSLLVX X15, V6, V12          // [0, W0, 0, W2]
	VSRLVX X15, V12, V6          // [W0, 0, W2, 0]
	VSLIDEDOWNVI $1, V6, V12     // [W2, 0, 0, 0]
	VSLIDEUPVI $1, V11, V6       // [W0, 0, W1, 0]
	VSLIDEDOWNVI $1, V11, V11    // [W3, 0, 0, 0]
	VSLIDEUPVI $1, V11, V12      // [W2, 0, W3, 0]

	// clmul
	// xor the results from 4 32-bit words together
	// Calculate lower 32 bits of tag
	VCLMULVV V7, V6, V13        // LOW(KS_L, DATA_L)
	VCLMULVV V8, V12, V14       // LOW(KS_H, DATA_H)
	VXORVV V13, V14, V13        // LOW(KS_L, DATA_L) XOR LOW(KS_H, DATA_H)
	VSLIDEDOWNVI $1, V13, V14
	VXORVV V14, V13, V13
	VMVXS V13, X11
	SRL $32, X11

	// Prepare KS windows and calculate bits 63-32 of tag
	VSLIDEDOWNVI $1, V7, V7     // [W2, W1, 0, 0]
	VSLIDEUPVI $1, V8, V7       // [W2, W1, W3, W2]
	VSLIDEDOWNVI $1, V8, V13    // [W4, W3, 0, 0]
	VSLIDEUPVI $1, V9, V13      // [W4, W3, W5, W4]
	VCLMULVV V7, V6, V14        // LOW(KS_L, DATA_L)
	VCLMULVV V13, V12, V15      // LOW(KS_H, DATA_H)
	VXORVV V14, V15, V14        // LOW(KS_L, DATA_L) XOR LOW(KS_H, DATA_H)
	VSLIDEDOWNVI $1, V14, V15
	VXORVV V15, V14, V14
	VMVXS V14, X12
	SRL $32, X12
	SLL $32, X12
	OR X11, X12, X11
	VMVSX X11, V7

	// Calculate bits 95-64 of tag
	VCLMULVV V8, V6, V13        // LOW(KS_L, DATA_L)
	VCLMULVV V9, V12, V14       // LOW(KS_H, DATA_H)
	VXORVV V13, V14, V13        // LOW(KS_L, DATA_L) XOR LOW(KS_H, DATA_H)
	VSLIDEDOWNVI $1, V13, V14
	VXORVV V14, V13, V13
	VMVXS V13, X11
	SRL $32, X11

	// Prepare KS windows and calculate bits 127-96 of tag
	VSLIDEDOWNVI $1, V8, V8     // [W4, W3, 0, 0]
	VSLIDEUPVI $1, V9, V8       // [W4, W3, W5, W4]
	VSLIDEDOWNVI $1, V9, V9     // [W6, W5, 0, 0]
	VSLIDEUPVI $1, V10, V9      // [W6, W5, W7, W6]
	VCLMULVV V8, V6, V13        // LOW(KS_L, DATA_L)
	VCLMULVV V9, V12, V14       // LOW(KS_H, DATA_H)
	VXORVV V13, V14, V13        // LOW(KS_L, DATA_L) XOR LOW(KS_H, DATA_H)
	VSLIDEDOWNVI $1, V13, V14
	VXORVV V14, V13, V13
	VMVXS V13, X12
	SRL $32, X12
	SLL $32, X12
	OR X11, X12, X11
	VMVSX X11, V8
	VSLIDEUPVI $1, V8, V7
	VLE64V	(X8), V8
	VXORVV V7, V8, V7
	VSE64V V7, (X8)

	// Copy last 16 bytes of KS to the front
	SUB $8, X9
	VLE64V	(X9), V6
	SUB $16, X9
	VSE64V V6, (X9)
	RET
