// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"

DATA rcon<>+0x00(SB)/8, $0x0F0F0F0F0F0F0F0F // nibble mask
DATA rcon<>+0x08(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA rcon<>+0x10(SB)/8, $0x691CA0D5B6C37F0A // affine transform matrix m1 low
DATA rcon<>+0x18(SB)/8, $0x53269AEF8CF94530
DATA rcon<>+0x20(SB)/8, $0x009837AF6CF45BC3 // affine transform matrix m1 high
DATA rcon<>+0x28(SB)/8, $0xAB339C04C75FF068
DATA rcon<>+0x30(SB)/8, $0x616EF1FE050A959A // affine transform matrix m2 low
DATA rcon<>+0x38(SB)/8, $0xF5FA656A919E010E
DATA rcon<>+0x40(SB)/8, $0x00A4E044CD692D89 // affine transform matrix m2 high
DATA rcon<>+0x48(SB)/8, $0xA50145E168CC882C
DATA rcon<>+0x50(SB)/8, $0x090F000E0F0F020A // P1
DATA rcon<>+0x58(SB)/8, $0x0004000C07050309 // P1
DATA rcon<>+0x60(SB)/8, $0x080D060507000C04 // P2
DATA rcon<>+0x68(SB)/8, $0x0B010E0A0F030902 // P2
DATA rcon<>+0x70(SB)/8, $0x02060A06000D0A0F // P3
DATA rcon<>+0x78(SB)/8, $0x03030D0500090C0D // P3
DATA rcon<>+0x80(SB)/8, $0xff00ff00ff00ff00 // S0
DATA rcon<>+0x88(SB)/8, $0xff00ff00ff00ff00
DATA rcon<>+0x90(SB)/8, $0x00ff00ff00ff00ff // S1
DATA rcon<>+0x98(SB)/8, $0x00ff00ff00ff00ff
GLOBL rcon<>(SB), RODATA, $160


#define M1L V20
#define M1H V21
#define M2L V22
#define M2H V23
#define V_FOUR V24
#define NIBBLE_MASK V25
#define S1_MASK V26
#define S0_MASK V27
#define P1 V28
#define P2 V29
#define P3 V30

#define LOAD_CONSTS \
	VSPLTISW $4, V_FOUR \
	MOVD $rcon<>+0x00(SB), R4 \
	LXVD2X (R4)(R0), NIBBLE_MASK \
	MOVD $0x10, R5 \
	LXVD2X (R4)(R5), M1L \
	MOVD $0x20, R5 \
	LXVD2X (R4)(R5), M1H \
	MOVD $0x30, R5 \
	LXVD2X (R4)(R5), M2L \
	MOVD $0x40, R5 \
	LXVD2X (R4)(R5), M2H \
	MOVD $0x50, R5 \
	LXVD2X (R4)(R5), P1 \
	MOVD $0x60, R5 \
	LXVD2X (R4)(R5), P2 \
	MOVD $0x70, R5 \
	LXVD2X (R4)(R5), P3 \
	MOVD $0x80, R5 \
	LXVD2X (R4)(R5), S0_MASK \
	MOVD $0x90, R5 \
	LXVD2X (R4)(R5), S1_MASK

#define S0_comput(IN_OUT, V_FOUR, XTMP1, XTMP2)    \
	VSRW IN_OUT, V_FOUR, XTMP1;                    \
	VAND XTMP1, NIBBLE_MASK, XTMP1;                \
	VAND IN_OUT, NIBBLE_MASK, IN_OUT;              \
	VPERM P1, P1, IN_OUT, XTMP2;                   \
	VXOR XTMP1, XTMP2, XTMP2;                      \
	VPERM P2, P2, XTMP2, XTMP1;                    \
	VXOR IN_OUT, XTMP1, XTMP1;                     \
	VPERM P3, P3, XTMP1, IN_OUT;                   \
	VXOR XTMP2, IN_OUT, IN_OUT;                    \
	VSLW IN_OUT, V_FOUR, IN_OUT;                   \
	VXOR IN_OUT, XTMP1, IN_OUT;                    \
	VSPLTISB $5, XTMP1;                            \
	VRLB IN_OUT, XTMP1, IN_OUT

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

#define SHLDL(a, b, n) \  // NO SHLDL in GOLANG now
	SLW n, a, a           \
	SRW n, b, b           \  
	OR  b, a, a

// zuc sbox function
// parameters:
// -  x: 128 bits register as sbox input/output data
// -  y: 128 bits temp register
// -  z: 128 bits temp register
#define S1_comput(x, y, z) \
	AFFINE_TRANSFORM(M1L, M1H, V_FOUR, x, y, z); \
	VSBOX x, x;                                  \
	AFFINE_TRANSFORM(M2L, M2H, V_FOUR, x, y, z)

#define OFFSET_FR1      (16*4)
#define OFFSET_FR2      (17*4)
#define OFFSET_BRC_X0   (18*4)
#define OFFSET_BRC_X1   (19*4)
#define OFFSET_BRC_X2   (20*4)
#define OFFSET_BRC_X3   (21*4)

#define F_R1 R7
#define F_R2 R8
#define BRC_X0 R9
#define BRC_X1 R10
#define BRC_X2 R11
#define BRC_X3 R12

#define BITS_REORG(idx, addr, tmpR1, tmpR2, tmpR3, tmpR4)                      \
	MOVWZ (((15 + idx) % 16)*4)(addr), BRC_X0      \
	MOVWZ (((14 + idx) % 16)*4)(addr), tmpR1       \
	MOVWZ (((11 + idx) % 16)*4)(addr), BRC_X1      \
	MOVWZ (((9 + idx) % 16)*4)(addr), tmpR2        \
	MOVWZ (((7 + idx) % 16)*4)(addr), BRC_X2       \ 
	MOVWZ (((5 + idx) % 16)*4)(addr), tmpR3        \
	MOVWZ (((2 + idx) % 16)*4)(addr), BRC_X3       \
	MOVWZ (((0 + idx) % 16)*4)(addr), tmpR4        \
	SRW $15, BRC_X0, BRC_X0                        \
	SLW $16, tmpR1, tmpR1                          \
	SLW $1, tmpR2, tmpR2                           \
	SLW $1, tmpR3, tmpR3                           \
	SLW $1, tmpR4, tmpR4                           \
	SHLDL(BRC_X0, tmpR1, $16)                      \
	SHLDL(BRC_X1, tmpR2, $16)                      \
	SHLDL(BRC_X2, tmpR3, $16)                      \
	SHLDL(BRC_X3, tmpR4, $16) 

#define LOAD_STATE(addr)                       \
	MOVWZ OFFSET_FR1(addr), F_R1                \
	MOVWZ OFFSET_FR2(addr), F_R2                \
	MOVWZ OFFSET_BRC_X0(addr), BRC_X0           \
	MOVWZ OFFSET_BRC_X1(addr), BRC_X1           \
	MOVWZ OFFSET_BRC_X2(addr), BRC_X2           \
	MOVWZ OFFSET_BRC_X3(addr), BRC_X3

#define SAVE_STATE(addr)                       \
	MOVW F_R1, OFFSET_FR1(addr)                \
	MOVW F_R2, OFFSET_FR2(addr)                \
	MOVW BRC_X0, OFFSET_BRC_X0(addr)           \
	MOVW BRC_X1, OFFSET_BRC_X1(addr)           \
	MOVW BRC_X2, OFFSET_BRC_X2(addr)           \
	MOVW BRC_X3, OFFSET_BRC_X3(addr)

#define NONLIN_FUN(AX, BX, CX, DX)                           \
	XOR F_R1, BRC_X0, AX                     \ // F_R1 xor BRC_X0
	ADD F_R2, AX                             \ // W = (F_R1 xor BRC_X1) + F_R2
	ADD BRC_X1, F_R1                         \ // W1= F_R1 + BRC_X1
	XOR BRC_X2, F_R2                         \ // W2= F_R2 ^ BRC_X2
	\
	SLW $16, F_R1, DX                        \
	SRW $16, F_R2, CX                        \  	
	OR CX, DX                                \ // P = (W1 << 16) | (W2 >> 16)
	SHLDL(F_R2, F_R1, $16)                   \ // Q = (W2 << 16) | (W1 >> 16)
	ROTLW $2, DX, BX                         \ // start L1 
	ROTLW $24, DX, CX                        \
	XOR CX, DX                               \
	XOR BX, DX                               \
	ROTLW $8, BX                             \
	XOR BX, DX                               \
	ROTLW $8, BX                             \
	XOR BX, DX, BX                           \ // U = L1(P) = EDX, hi(RDX)=0
	RLDICL $0, BX, $32, DX                   \ // make sure hi(RDX)=0
	ROTLW $8, F_R2, BX                       \
	ROTLW $14, F_R2, CX                      \	
	XOR BX, F_R2                             \
	XOR CX, F_R2                             \
	ROTLW $8, CX                             \
	XOR CX, F_R2                             \
	ROTLW $8, CX                             \
	XOR CX, F_R2                             \ // V = L2(Q) = R11D, hi(R11)=0
	SLD $32, F_R2                            \ // DX = V || U
	XOR F_R2, DX                             \
	MTVSRD DX, V0                            \ // save V || U to V0
	VOR V0, V0, V1                           \
	S0_comput(V0, V_FOUR, V2, V3)            \
	S1_comput(V1, V2, V3)                    \
	MFVSRD V1, DX                            \
	SRD $32, DX, F_R1                        \
	MOVWZ DX, F_R2

#define LFSR_UPDT(idx, addr, W, tmpR1, tmpR2, tmpR3, tmpR4 )       \
	MOVWZ (((0 + idx) % 16)*4)(addr), tmpR1        \
	MOVWZ (((4 + idx) % 16)*4)(addr), tmpR2        \
	MOVWZ (((10 + idx) % 16)*4)(addr), tmpR3       \
	MOVWZ (((13 + idx) % 16)*4)(addr), tmpR4       \
	\ // Calculate 64-bit LFSR feedback
	ADD tmpR1, W                               \
	SLD $8, tmpR1                              \
	SLD $20, tmpR2                             \
	SLD $21, tmpR3                             \
	SLD $17, tmpR4                             \
	ADD tmpR1, W                               \
	ADD tmpR2, W                               \
	ADD tmpR3, W                               \
	ADD tmpR4, W                               \
	MOVWZ (((15 + idx) % 16)*4)(addr), tmpR4   \
	SLD $15, tmpR4                             \
	ADD tmpR4, W                               \
	\ // Reduce it to 31-bit value
	MOVD $0x7FFFFFFF, tmpR2                    \
	SRD $31, W, tmpR1                          \
	AND tmpR2, W                               \
	ADD tmpR1, W                               \
	\
	SRD $31, W, tmpR1                          \
	AND tmpR2, W                               \
	ADD tmpR1, W                               \
	\ // LFSR_S16 = (LFSR_S15++) = W
	MOVW W, (((0 + idx) % 16)*4)(addr)

#define RESTORE_LFSR_0(addr, tmpR1, tmpR2, tmpR3, tmpR4)        \
	MOVWZ (addr), tmpR1                                 \
	MOVD $4, tmpR4                                      \
	LXVD2X (tmpR4)(addr), V0                            \
	MOVD $20, tmpR4                                     \
	LXVD2X (tmpR4)(addr), V1                            \
	MOVD $36, tmpR4                                     \
	LXVD2X (tmpR4)(addr), V2                            \
	MOVD 52(addr), tmpR2								\
	MOVWZ 60(addr), tmpR3								\
	STXVD2X V0, (addr)                                  \
	MOVD $16, tmpR4                                     \
	STXVD2X V1, (tmpR4)(addr)                           \
	MOVD $32, tmpR4                                     \
	STXVD2X V2, (tmpR4)(addr)                           \
	MOVD tmpR2, 48(addr)                                \
	MOVW tmpR3, 56(addr)                                \
	MOVW tmpR1, 60(addr)

#define RESTORE_LFSR_2(addr, tmpR1, tmpR2, tmpR3)       \
	MOVD (addr), tmpR1                                 \
	MOVD 8(addr), tmpR2                                \
	LXVD2X (tmpR2)(addr), V0                           \
	MOVD 24(addr), tmpR2                               \
	LXVD2X (tmpR2)(addr), V1                           \
	MOVD 40(addr), tmpR2                               \
	LXVD2X (tmpR2)(addr), V2                           \
	MOVD 56(addr), tmpR3                               \
	\
	STXVD2X V0, (addr)                                 \
	MOVD 16(addr), tmpR2                               \
	STXVD2X V1, (tmpR2)(addr)                          \
	MOVD 32(addr), tmpR2                               \
	STXVD2X V2, (tmpR2)(addr)                          \
	MOVW tmpR3, 48(addr)                               \
	MOVW tmpR1, 56(addr)


// func genKeywordAsm(s *zucState32) uint32
TEXT ·genKeywordAsm(SB),NOSPLIT,$0
	LOAD_CONSTS

	MOVD pState+0(FP), R4
	LOAD_STATE(R4)
	BITS_REORG(0, R4, R14, R15, R16, R17)
	NONLIN_FUN(R14, R15, R16, R17)
	// (BRC_X3 xor W) as result
	XOR BRC_X3, R14
	MOVW R14, ret+8(FP)

	// LFSRWithWorkMode
	XOR R14, R14
	LFSR_UPDT(0, R4, R14, R15, R16, R17, R18)
	SAVE_STATE(R4)
	RESTORE_LFSR_0(R4, R15, R16, R17, R18)

	RET

// func genKeyStreamAsm(keyStream []uint32, pState *zucState32)
TEXT ·genKeyStreamAsm(SB),NOSPLIT,$0
	RET

// func genKeyStreamRev32Asm(keyStream []byte, pState *zucState32)
TEXT ·genKeyStreamRev32Asm(SB),NOSPLIT,$0
	RET
