// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"

DATA ·rcon+0x00(SB)/8, $0x0b0a09080f0e0d0c // byte swap per word
DATA ·rcon+0x08(SB)/8, $0x0302010007060504
DATA ·rcon+0x10(SB)/8, $0x0c0d0e0f08090a0b // reverse words
DATA ·rcon+0x18(SB)/8, $0x0405060700010203
DATA ·rcon+0x20(SB)/8, $0x0F0F0F0F0F0F0F0F // nibble mask
DATA ·rcon+0x28(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA ·rcon+0x30(SB)/8, $0x691CA0D5B6C37F0A // affine transform matrix m1 low
DATA ·rcon+0x38(SB)/8, $0x53269AEF8CF94530
DATA ·rcon+0x40(SB)/8, $0x009837AF6CF45BC3 // affine transform matrix m1 high
DATA ·rcon+0x48(SB)/8, $0xAB339C04C75FF068
DATA ·rcon+0x50(SB)/8, $0x616EF1FE050A959A // affine transform matrix m2 low
DATA ·rcon+0x58(SB)/8, $0xF5FA656A919E010E
DATA ·rcon+0x60(SB)/8, $0x00A4E044CD692D89 // affine transform matrix m2 high
DATA ·rcon+0x68(SB)/8, $0xA50145E168CC882C
GLOBL ·rcon(SB), RODATA, $112

#define REVERSE_WORDS V19
#define M1L V20
#define M1H V21
#define M2L V22
#define M2H V23
#define V_FOUR V24
#define NIBBLE_MASK V29
// For instruction emulation
#define ESPERMW  V31 // Endian swapping permute into BE

#define TMP0 V10
#define TMP1 V11
#define TMP2 V12
#define TMP3 V13

#include "aesni_macros_ppc64x.s"

#define SM4_TAO_L2(x, y, z)         \
	SM4_SBOX(x, y, z);                      \
	;                                       \ //####################  4 parallel L2 linear transforms ##################//
	VSPLTISW $13, z;                        \
	VRLW	x, z, y;                        \ // y = x <<< 13
	VXOR x, y, x;                           \
	VSPLTISW $10, z;                        \
	VRLW y, z, y;                           \ // y = x <<< 23
	VXOR x, y, x

#define SM4_EXPANDKEY_ROUND(CK, x, y, z, t0, t1, t2, t3, target) \
	VXOR t1, CK, x;                      \
	VXOR t2, x, x;                       \
	VXOR t3, x, x;                       \
	SM4_TAO_L2(x, y, z);                 \
	VXOR x, t0, t0;                      \
	VSLDOI $4, target, t0, target

// func expandKeyAsm(key *byte, ck, enc, dec *uint32, inst int)
TEXT ·expandKeyAsm(SB),NOSPLIT,$0
	// prepare/load constants
	VSPLTISB $4, V_FOUR;
#ifdef NEEDS_PERMW
	MOVD	$·rcon(SB), R4
	LVX	(R4), ESPERMW
#endif
	MOVD	$·rcon+0x10(SB), R4
	LOAD_CONSTS(R4, R3)

	MOVD key+0(FP), R3
	MOVD ck+8(FP), R4
	MOVD enc+16(FP), R5
	MOVD dec+24(FP), R6

	ADD $112, R6

	// load fk
	MOVD $·fk+0(SB), R7
	LXVW4X (R7), V4

	// load key
	PPC64X_LXVW4X(R3, R0, V0)

	// xor key with fk
	VXOR V0, V4, V0
	VSLDOI $4, V0, V0, V1
	VSLDOI $4, V1, V1, V2
	VSLDOI $4, V2, V2, V3

	// prepare counter
	MOVD $8, R7
	MOVD R7, CTR

ksLoop:
	LXVW4X (R4), V4
	SM4_EXPANDKEY_ROUND(V4, V7, V8, V9, V0, V1, V2, V3, V5)
	VSLDOI $4, V4, V4, V4
	SM4_EXPANDKEY_ROUND(V4, V7, V8, V9, V1, V2, V3, V0, V5)
	VSLDOI $4, V4, V4, V4
	SM4_EXPANDKEY_ROUND(V4, V7, V8, V9, V2, V3, V0, V1, V5)
	VSLDOI $4, V4, V4, V4
	SM4_EXPANDKEY_ROUND(V4, V7, V8, V9, V3, V0, V1, V2, V5)
	STXVW4X V5, (R5)
	VPERM V5, V5, REVERSE_WORDS, V5
	STXVW4X V5, (R6)

	ADD $16, R5
	ADD $16, R4
	ADD $-16, R6
	BDNZ	ksLoop

    RET

// func encryptBlockAsm(xk *uint32, dst, src *byte, inst int)
TEXT ·encryptBlockAsm(SB),NOSPLIT,$0
	// prepare/load constants
	VSPLTISB $4, V_FOUR;
#ifdef NEEDS_PERMW
	MOVD	$·rcon(SB), R4
	LVX	(R4), ESPERMW
#endif
	MOVD	$·rcon+0x10(SB), R4
	LOAD_CONSTS(R4, R3)

	MOVD xk+0(FP), R3
	MOVD dst+8(FP), R4
	MOVD src+16(FP), R5

	// load src
	PPC64X_LXVW4X(R5, R0, V0)
	VSLDOI $4, V0, V0, V1
	VSLDOI $4, V1, V1, V2
	VSLDOI $4, V2, V2, V3

	// prepare counter
	MOVD $8, R7
	MOVD R7, CTR

encryptBlockLoop:
	// load xk
	LXVW4X (R3), V8
	PROCESS_SINGLEBLOCK_4ROUND
	ADD $16, R3
	BDNZ	encryptBlockLoop

	VSLDOI $4, V3, V3, V3
	VSLDOI $4, V3, V2, V2
	VSLDOI $4, V2, V1, V1
	VSLDOI $4, V1, V0, V0

	PPC64X_STXVW4X(V0, R4, R0)

	RET

// func encryptBlocksAsm(xk *uint32, dst, src []byte, inst int)
TEXT ·encryptBlocksAsm(SB),NOSPLIT,$0
	// prepare/load constants
	VSPLTISB $4, V_FOUR;
#ifdef NEEDS_PERMW
	MOVD	$·rcon(SB), R4
	LVX	(R4), ESPERMW
#endif
	MOVD	$·rcon+0x10(SB), R4
	LOAD_CONSTS(R4, R3)

	MOVD xk+0(FP), R3
	MOVD dst+8(FP), R4
	MOVD src+32(FP), R5
	MOVD src_len+40(FP), R6

	CMP	R6, $128
	BEQ enc8blocks

enc4blocks:
	// prepare counter
	MOVD $8, R7
	MOVD R7, CTR

	MOVD $16, R7
	MOVD $32, R8
	MOVD $48, R9
	PPC64X_LXVW4X(R5, R0, V0)
	PPC64X_LXVW4X(R5, R7, V1)
	PPC64X_LXVW4X(R5, R8, V2)
	PPC64X_LXVW4X(R5, R9, V3)
	PRE_TRANSPOSE_MATRIX(V0, V1, V2, V3)

enc4blocksLoop:
		// load xk
		LXVW4X (R3), V8
		PROCESS_4BLOCKS_4ROUND	
		ADD $16, R3
		BDNZ	enc4blocksLoop

	TRANSPOSE_MATRIX(V0, V1, V2, V3)
	PPC64X_STXVW4X(V0, R4, R0)
	PPC64X_STXVW4X(V1, R4, R7)
	PPC64X_STXVW4X(V2, R4, R8)
	PPC64X_STXVW4X(V3, R4, R9)
	RET

enc8blocks:
	// prepare counter
	MOVD $8, R7
	MOVD R7, CTR

	MOVD $16, R7
	MOVD $32, R8
	MOVD $48, R9
	MOVD $64, R10
	MOVD $80, R11
	MOVD $96, R12
	MOVD $112, R14
	PPC64X_LXVW4X(R5, R0, V0)
	PPC64X_LXVW4X(R5, R7, V1)
	PPC64X_LXVW4X(R5, R8, V2)
	PPC64X_LXVW4X(R5, R9, V3)
	PPC64X_LXVW4X(R5, R10, V4)
	PPC64X_LXVW4X(R5, R11, V5)
	PPC64X_LXVW4X(R5, R12, V6)
	PPC64X_LXVW4X(R5, R14, V7)
	PRE_TRANSPOSE_MATRIX(V0, V1, V2, V3)
	PRE_TRANSPOSE_MATRIX(V4, V5, V6, V7)

enc8blocksLoop:
		LXVW4X (R3), V8
		PROCESS_8BLOCKS_4ROUND
		ADD $16, R3
		BDNZ	enc8blocksLoop
	
	TRANSPOSE_MATRIX(V0, V1, V2, V3)
	TRANSPOSE_MATRIX(V4, V5, V6, V7)
	PPC64X_STXVW4X(V0, R4, R0)
	PPC64X_STXVW4X(V1, R4, R7)
	PPC64X_STXVW4X(V2, R4, R8)
	PPC64X_STXVW4X(V3, R4, R9)
	PPC64X_STXVW4X(V4, R4, R10)
	PPC64X_STXVW4X(V5, R4, R11)
	PPC64X_STXVW4X(V6, R4, R12)
	PPC64X_STXVW4X(V7, R4, R14)

	RET
