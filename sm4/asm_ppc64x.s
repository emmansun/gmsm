// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"

#define ZERO V18
#define REVERSE_WORDS V19
#define M1L V20
#define M1H V21
#define M2L V22
#define M2H V23
#define V_FOUR V24
#define M0 V25
#define M1 V26
#define M2 V27
#define M3 V28
#define NIBBLE_MASK V29
#define INVERSE_SHIFT_ROWS V30
// For instruction emulation
#define ESPERMW  V31 // Endian swapping permute into BE

DATA ·rcon+0x00(SB)/8, $0x0b0a09080f0e0d0c // byte swap per word
DATA ·rcon+0x08(SB)/8, $0x0302010007060504
DATA ·rcon+0x10(SB)/8, $0x0001020310111213 // Permute for transpose matrix
DATA ·rcon+0x18(SB)/8, $0x0405060714151617
DATA ·rcon+0x20(SB)/8, $0x08090a0b18191a1b
DATA ·rcon+0x28(SB)/8, $0x0c0d0e0f1c1d1e1f
DATA ·rcon+0x30(SB)/8, $0x0001020304050607
DATA ·rcon+0x38(SB)/8, $0x1011121314151617
DATA ·rcon+0x40(SB)/8, $0x08090a0b0c0d0e0f
DATA ·rcon+0x48(SB)/8, $0x18191a1b1c1d1e1f
DATA ·rcon+0x50(SB)/8, $0x0c0d0e0f08090a0b // reverse words
DATA ·rcon+0x58(SB)/8, $0x0405060700010203
DATA ·rcon+0x60(SB)/8, $0x0F0F0F0F0F0F0F0F // nibble mask
DATA ·rcon+0x68(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA ·rcon+0x70(SB)/8, $0x000D0A0704010E0B // inverse shift rows
DATA ·rcon+0x78(SB)/8, $0x0805020F0C090603
DATA ·rcon+0x80(SB)/8, $0x691CA0D5B6C37F0A // affine transform matrix m1 low
DATA ·rcon+0x88(SB)/8, $0x53269AEF8CF94530
DATA ·rcon+0x90(SB)/8, $0x009837AF6CF45BC3 // affine transform matrix m1 high
DATA ·rcon+0x98(SB)/8, $0xAB339C04C75FF068
DATA ·rcon+0xa0(SB)/8, $0x616EF1FE050A959A // affine transform matrix m2 low
DATA ·rcon+0xa8(SB)/8, $0xF5FA656A919E010E
DATA ·rcon+0xb0(SB)/8, $0x00A4E044CD692D89 // affine transform matrix m2 high
DATA ·rcon+0xb8(SB)/8, $0xA50145E168CC882C

GLOBL ·rcon(SB), RODATA, $192

#ifdef GOARCH_ppc64le
#define NEEDS_PERMW

#define PPC64X_LXVW4X(RA,RB,VT) \
	LXVW4X	(RA+RB), VT \
	VPERM	VT, VT, ESPERMW, VT

#define PPC64X_STXVW4X(VS, RA, RB) \
	VPERM	VS, VS, ESPERMW, VS \
	STXVW4X	VS, (RA+RB)

#else
#define PPC64X_LXVW4X(RA,RB,VT)  LXVW4X	(RA+RB), VT
#define PPC64X_STXVW4X(VS, RA, RB) STXVW4X	VS, (RA+RB)
#endif // defined(GOARCH_ppc64le)

// r = s <<< n
// Due to VSPLTISW's limitation, the n MUST be [0, 15],
// If n > 15, we have to call it multiple times.
// VSPLTISW takes a 5-bit immediate value as an operand.
// I also did NOT find one vector instruction to use immediate value for ROTL.
#define PROLD(s, r, tmp, n) \
	VSPLTISW $n, tmp \
	VRLW	s, tmp, r

#define TRANSPOSE_MATRIX(T0, T1, T2, T3) \
	VPERM T0, T1, M0, TMP0; \
	VPERM T2, T3, M0, TMP1; \
	VPERM T0, T1, M1, TMP2; \
	VPERM T2, T3, M1, TMP3; \
	VPERM TMP0, TMP1, M2, T0; \
	VPERM TMP0, TMP1, M3, T1; \
	VPERM TMP2, TMP3, M2, T2; \
	VPERM TMP2, TMP3, M3, T3

// Affine Transform
// parameters:
// -  L: table low nibbles
// -  H: table high nibbles
// -  x: 128 bits register as sbox input/output data
// -  y: 128 bits temp register
// -  z: 128 bits temp register
#define AFFINE_TRANSFORM(L, H, V_FOUR, x, y, z)  \
	VAND NIBBLE_MASK, x, z;              \
	VPERM L, L, z, y;                    \
	VSRD x, V_FOUR, x;                   \
	VAND NIBBLE_MASK, x, z;              \
	VPERM H, H, z, x;                    \
	VXOR y, x, x

// Affine Transform
// parameters:
// -  L: table low nibbles
// -  H: table high nibbles
// -  x: 128 bits register as sbox input/output data
// -  y: 128 bits temp register
// -  z: 128 bits temp register
#define AFFINE_TRANSFORM_NOTX(L, H, V_FOUR, x, y, z)  \
	VNOR  x, x, z;                       \ // z = NOT(x)
	VAND  NIBBLE_MASK, z, z;             \	
	VPERM L, L, z, y;                    \
	VSRD x, V_FOUR, x;                   \
	VAND NIBBLE_MASK, x, z;              \
	VPERM H, H, z, x;                    \
	VXOR y, x, x

// SM4 sbox function
// parameters:
// -  x: 128 bits register as sbox input/output data
// -  y: 128 bits temp register
// -  z: 128 bits temp register
#define SM4_SBOX(x, y, z) \
	AFFINE_TRANSFORM(M1L, M1H, V_FOUR, x, y, z); \
	VPERM x, x, INVERSE_SHIFT_ROWS, x;           \
	VCIPHERLAST x, NIBBLE_MASK, x;               \
	AFFINE_TRANSFORM_NOTX(M2L, M2H, V_FOUR, x, y, z)

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

// SM4 TAO L1 function
// parameters:
// -  x: 128 bits register as TAO_L1 input/output data
// -  tmp1: 128 bits temp register
// -  tmp2: 128 bits temp register
// -  tmp3: 128 bits temp register
#define SM4_TAO_L1(x, tmp1, tmp2, tmp3)         \
	SM4_SBOX(x, tmp1, tmp2);                      \
	;                                       \ //####################  4 parallel L1 linear transforms ##################//
	VSPLTISW $8, tmp3;                      \
	VRLW	x, tmp3, tmp1;                  \ // tmp1 = x <<< 8
	VRLW tmp1, tmp3, tmp2;                  \ // tmp2 = x <<< 16
	VXOR x, tmp1, tmp1;                     \ // tmp1 = x xor (x <<< 8)
	VXOR tmp1, tmp2, tmp1;                  \ // tmp1 = x xor (x <<< 8) xor (x <<< 16)
	VRLW tmp2, tmp3, tmp2;                  \ // tmp2 = x <<< 24
	VXOR tmp2, x, x;                        \ // x = x xor (x <<< 24)
	VSPLTISW $2, tmp3;                      \
	VRLW tmp1, tmp3, tmp1;                  \ // tmp1 = (x xor (x <<< 8) xor (x <<< 16)) <<< 2
	VXOR tmp1, x, x

// func expandKeyAsm(key *byte, ck, enc, dec *uint32, inst int)
TEXT ·expandKeyAsm(SB),NOSPLIT,$0
	// prepare/load constants
	VSPLTISW $4, V_FOUR;
#ifdef NEEDS_PERMW
	MOVD	$·rcon(SB), R4
	LVX	(R4), ESPERMW
#endif
	MOVD	$·rcon+0x50(SB), R4
	LXVD2X (R4)(R0), REVERSE_WORDS
	MOVD $16, R3
	LXVD2X (R4)(R3), NIBBLE_MASK
	MOVD $32, R3
	LXVD2X (R4)(R3), INVERSE_SHIFT_ROWS
	MOVD $48, R3
	LXVD2X (R4)(R3), M1L
	MOVD $64, R3
	LXVD2X (R4)(R3), M1H
	MOVD $80, R3
	LXVD2X (R4)(R3), M2L
	MOVD $96, R3
	LXVD2X (R4)(R3), M2H

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
	VSPLTISW $4, V_FOUR;
#ifdef NEEDS_PERMW
	MOVD	$·rcon(SB), R4
	LVX	(R4), ESPERMW
#endif
	MOVD	$·rcon+0x50(SB), R4
	LXVD2X (R4)(R0), REVERSE_WORDS
	MOVD $16, R3
	LXVD2X (R4)(R3), NIBBLE_MASK
	MOVD $32, R3
	LXVD2X (R4)(R3), INVERSE_SHIFT_ROWS
	MOVD $48, R3
	LXVD2X (R4)(R3), M1L
	MOVD $64, R3
	LXVD2X (R4)(R3), M1H
	MOVD $80, R3
	LXVD2X (R4)(R3), M2L
	MOVD $96, R3
	LXVD2X (R4)(R3), M2H

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
	LXVW4X (R3), V4
	SM4_ROUND(V4, V5, V6, V7, V8, V0, V1, V2, V3)
	VSLDOI $4, V4, V4, V4
	SM4_ROUND(V4, V5, V6, V7, V8, V1, V2, V3, V0)
	VSLDOI $4, V4, V4, V4
	SM4_ROUND(V4, V5, V6, V7, V8, V2, V3, V0, V1)
	VSLDOI $4, V4, V4, V4
	SM4_ROUND(V4, V5, V6, V7, V8, V3, V0, V1, V2)

	BDNZ	encryptBlockLoop

	VSLDOI $4, V3, V3, V3
	VSLDOI $4, V3, V2, V2
	VSLDOI $4, V2, V1, V1
	VSLDOI $4, V1, V0, V0

	PPC64X_STXVW4X(V0, R4, R0)

	RET

// func encryptBlocksAsm(xk *uint32, dst, src []byte, inst int)
TEXT ·encryptBlocksAsm(SB),NOSPLIT,$0
	RET
