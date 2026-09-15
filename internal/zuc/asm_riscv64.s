// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.27 && !purego

#include "textflag.h"

DATA zucVectorConstants<>+0x00(SB)/8, $0x0F0F0F0F0F0F0F0F // nibble mask
DATA zucVectorConstants<>+0x08(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA zucVectorConstants<>+0x10(SB)/8, $0x1D1C9F9E83820100 // affine transform matrix m1 low
DATA zucVectorConstants<>+0x18(SB)/8, $0x3938BBBAA7A62524
DATA zucVectorConstants<>+0x20(SB)/8, $0xA174A97CDD08D500 // affine transform matrix m1 high
DATA zucVectorConstants<>+0x28(SB)/8, $0x3DE835E04194499C
DATA zucVectorConstants<>+0x30(SB)/8, $0xA8BC0216D9CD7367 // affine transform matrix m2 low
DATA zucVectorConstants<>+0x38(SB)/8, $0x1F0BB5A16E7AC4D0
DATA zucVectorConstants<>+0x40(SB)/8, $0x638CFA1523CCBA55 // affine transform matrix m2 high
DATA zucVectorConstants<>+0x48(SB)/8, $0x3FD0A6497F90E609
DATA zucVectorConstants<>+0x50(SB)/8, $0x0A020F0F0E000F09 // P1
DATA zucVectorConstants<>+0x58(SB)/8, $0x090305070C000400 // P1
DATA zucVectorConstants<>+0x60(SB)/8, $0x040C000705060D08 // P2
DATA zucVectorConstants<>+0x68(SB)/8, $0x0209030F0A0E010B // P2
DATA zucVectorConstants<>+0x70(SB)/8, $0x0F0A0D00060A0602 // P3
DATA zucVectorConstants<>+0x78(SB)/8, $0x0D0C0900050D0303 // P3
DATA zucVectorConstants<>+0x80(SB)/8, $0x0B0E0104070A0D00 // shuffle mask
DATA zucVectorConstants<>+0x88(SB)/8, $0x0306090C0F020508
DATA zucVectorConstants<>+0x90(SB)/8, $0xff00ff00ff00ff00 // S0
DATA zucVectorConstants<>+0x98(SB)/8, $0xff00ff00ff00ff00
DATA zucVectorConstants<>+0xa0(SB)/8, $0x00ff00ff00ff00ff // S1
DATA zucVectorConstants<>+0xa8(SB)/8, $0x00ff00ff00ff00ff
// 16-byte aligned tables.
GLOBL zucVectorConstants<>(SB), RODATA|NOPTR, $176


#define ZERO X0
#define RSP X2

#define ZERO_VECTOR      V0
#define NIBBLE_MASK      V16

#define M1L              V17
#define M1H              V18
#define M2L              V19
#define M2H              V20

#define P1               V21
#define P2               V22
#define P3               V23

#define INV_SHIFT_ROWS   V24

#define S0_MASK          V25
#define S1_MASK          V26

// VAESEF_VV performs vaesef.vv vd, vs2
#define VAESEF_VV(Vd, Vs2) \
    WORD $((0x51 << 25) | ((Vs2) << 20) | (0x03 << 15) | (2 << 12) | ((Vd) << 7) | 0x77)

// VAESEF_VS performs vaesef.vs vd, vs2
#define VAESEF_VS(Vd, Vs2) \
    WORD $((0x53 << 25) | ((Vs2) << 20) | (0x03 << 15) | (2 << 12) | ((Vd) << 7) | 0x77)

#define LOAD_ZUC_VECTOR_CONSTANTS(ptr) \
	MOV $zucVectorConstants<>(SB), ptr; \
	VSETIVLI $16, E8, M1, TA, MA, X0; \
	VLE8V (ptr), NIBBLE_MASK; \
	ADD $16, ptr; \
	VLE8V (ptr), M1L; \
	ADD $16, ptr; \
	VLE8V (ptr), M1H; \
	ADD $16, ptr; \
	VLE8V (ptr), M2L; \
	ADD $16, ptr; \
	VLE8V (ptr), M2H; \
	ADD $16, ptr; \
	VLE8V (ptr), P1; \
	ADD $16, ptr; \
	VLE8V (ptr), P2; \
	ADD $16, ptr; \
	VLE8V (ptr), P3; \
	ADD $16, ptr; \
	VLE8V (ptr), INV_SHIFT_ROWS; \
	ADD $16, ptr; \
	VLE8V (ptr), S0_MASK; \
	ADD $16, ptr; \
	VLE8V (ptr), S1_MASK

#define ROTL5_PER_BYTE(x, tmp) \
	VSLLVI $5, x, tmp; \
	VSRLVI $3, x, x; \
	VORVV tmp, x, x

#define S0_COMPUTE(x, t0, t1) \
	/* t0 = x1, x = x2 */ \
	VSRLVI $4, x, t0; \
	VANDVV NIBBLE_MASK, x, x; \
	/* t1 = P1[x2], then q = x1 XOR P1[x2]. */ \
	VRGATHERVV x, P1, t1; \
	VXORVV t0, t1, t1; \
	/* t0 = P2[q], then r = x2 XOR P2[q]. */ \
	VRGATHERVV t1, P2, t0; \
	VXORVV x, t0, t0; \
	/* x = P3[r], then s = q XOR P3[r]. */ \
	VRGATHERVV t0, P3, x; \
	VXORVV t1, x, x; \
	/* t = (s << 4) XOR r. */ \
	VSLLVI $4, x, x; \
	VXORVV t0, x, x; \
	ROTL5_PER_BYTE(x, t0); \
	VANDVV S0_MASK, x, x

// x = tableLow[x & 0x0f] XOR tableHigh[x >> 4]
//
// Parameters:
//   x    input/output
#define AFFINE_TRANSFORM(low, high, x, t0, t1) \
	VANDVV NIBBLE_MASK, x, t0; \
	VRGATHERVV t0, low, t1; \
	VSRLVI $4, x, t0; \
	VRGATHERVV t0, high, t0; \
	VXORVV t1, t0, x

// Compute 16 ZUC S1 values.
//
// x    input/output
#define S1_COMPUTE(x) \
	/* Convert ZUC S1 input representation to AES S-box basis. */ \
	AFFINE_TRANSFORM(M1L, M1H, x, V1, V2); \
	/* Cancel the ShiftRows performed by VAES final round. */ \
	VRGATHERVV INV_SHIFT_ROWS, x, V3; \
	/* VAES final round requires SEW=32, EGS=4. */ \
	VSETIVLI $4, E32, M1, TA, MA, X0; \
	VAESEF_VV(3, 0); \
	/* Restore byte-oriented configuration. */ \
	VSETIVLI $16, E8, M1, TA, MA, X0; \
	/* Convert AES S-box output representation to ZUC S1. */ \
	AFFINE_TRANSFORM(M2L, M2H, V3, V1, V2); \
	VANDVV S1_MASK, V3, x

// X10=r1, X11=r2, X12=x0, X13=x1, X14=x2, X15=x3
#define LOAD_STATE(r) \
	MOVWU 64+r, X10; \
	MOVWU 68+r, X11; \
	MOVWU 72+r, X12; \
	MOVWU 76+r, X13; \
	MOVWU 80+r, X14; \
	MOVWU 84+r, X15

// X10=r1, X11=r2, X12=x0, X13=x1, X14=x2, X15=x3
#define SAVE_STATE(r) \
	MOVW X10, 64+r; \
	MOVW X11, 68+r; \
	MOVW X12, 72+r; \
	MOVW X13, 76+r; \
	MOVW X14, 80+r; \
	MOVW X15, 84+r


#define MERGE16(a, b) \
	SLLW $16, a;          \
	SRLW $16, b;          \
	OR  b, a

// X12=x0, X13=x1, X14=x2, X15=x3
#define BITS_REORG(idx)                      \
	MOVWU (((15 + idx) % 16)*4)(X8), X12;      \
	MOVWU (((14 + idx) % 16)*4)(X8), X16;      \
	MOVWU (((11 + idx) % 16)*4)(X8), X13;      \
	MOVWU (((9 + idx) % 16)*4)(X8), X17;       \
	MOVWU (((7 + idx) % 16)*4)(X8), X14;       \
	MOVWU (((5 + idx) % 16)*4)(X8), X18;       \
	MOVWU (((2 + idx) % 16)*4)(X8), X15;       \
	MOVWU (((0 + idx) % 16)*4)(X8), X19;       \
	SRLW $15, X12;                            \
	SLLW $16, X16;                            \
	SLLW $1, X17;                             \
	SLLW $1, X18;                             \
	SLLW $1, X19;                             \
	MERGE16(X12, X16);                        \
	MERGE16(X13, X17);                        \
	MERGE16(X14, X18);                        \
	MERGE16(X15, X19)

#define NONLIN_FUN()                         \
	XOR X10, X12, X16;                        \ // r1 ^ x0
	ADDW X11, X16;                            \ // W = r2 + r1 ^ x0
	ADDW X13, X10;                            \ // W1= F_R1 + BRC_X1
	XOR X14, X11;                             \ // W2= F_R2 ^ BRC_X2
	\
	SLLW $16, X10, X19;                       \
	SRLW $16, X11, X18;                       \
	OR X18, X19;                              \ // P = (W1 << 16) | (W2 >> 16)
	MERGE16(X11, X10);                     \ // Q = (W2 << 16) | (W1 >> 16)
	RORW $30, X19, X17;                       \ // ROL(P, 2)
	RORW $22, X19, X18;                       \ // ROL(P, 10)
	RORW $14, X19, X20;                       \ // ROL(P, 18)
	RORW $8, X19, X21;                        \ // ROL(P, 24)
	XOR X17, X19;                             \
	XOR X18, X19;                             \
	XOR X20, X19;                             \
	XOR X21, X19;                             \ // U = L1(P) = EDX, hi(RDX)=0
	RORW $24, X11, X17;                       \
	RORW $18, X11, X18;                       \
	RORW $10, X11, X20;                       \
	RORW $2, X11, X21;                        \
	XOR X17, X11;                             \
	XOR X18, X11;                             \
	XOR X20, X11;                             \
	XOR X21, X11;                             \ // V = L2(Q) = R11D, hi(R11)=0
	SLL $32, X11;                             \
	SLL $32, X19;                             \
	SRL $32, X19;                             \
	OR X11, X19;                              \ // X19 = V || U
	VSETIVLI	$2, E64, M1, TA, MA, X0;      \
	VMVSX X19, V4;                            \
	VMVVV V4, V5;                             \
	VSETIVLI $16, E8, M1, TA, MA, X0;        \
	S0_COMPUTE(V5, V1, V2);                   \
	S1_COMPUTE(V4);                           \
	VXORVV V5, V4, V4;                        \ 
	\
	VSETIVLI	$2, E64, M1, TA, MA, X0;      \
	VMVXS  V4, X10;                           \ // F_R1
	SRL $32, X10, X11

#define LFSR_UPDT(idx)                       \
	MOVWU (((0 + idx) % 16)*4)(X8), X17;       \ // lfsr[0]
	MOVWU (((4 + idx) % 16)*4)(X8), X18;       \ // lfsr[4]
	MOVWU (((10 + idx) % 16)*4)(X8), X19;      \ // lfsr[10]
	MOVWU (((13 + idx) % 16)*4)(X8), X20;      \ // lfsr[13]
	MOVWU (((15 + idx) % 16)*4)(X8), X21;      \ // lfsr[15]
	ADD X17, X16;                              \ // W = W + lfsr[0]
	SLL $8, X17;                               \ // lfsr[0] << 8
	SLL $20, X18;                              \ // lfsr[4] << 20	
	SLL $21, X19;                              \ // lfsr[10] << 21
	SLL $17, X20;                              \ // lfsr[13] << 17
	SLL $15, X21;                              \ // lfsr[15] << 15
	ADD X17, X16;                              \
	ADD X18, X16;                              \
	ADD X19, X16;                              \
	ADD X20, X16;                              \
	ADD X21, X16;                              \
	\
	SRL $31, X16, X17;                         \
	AND X25, X16;                              \
	ADD X17, X16;                              \
	\
	SRL $31, X16, X17;                         \
	AND X25, X16;                              \
	ADD X17, X16;                              \
	\
	MOVW X16, (((0 + idx) % 16)*4)(X8)

#define RESTORE_LFSR_0()                     \
	MOVWU (X8), X17;                           \
	ADD $4, X8, X20;                           \
	VLE64V (X20), V1;                          \
	ADD $16, X20;                              \
	VLE64V (X20), V2;                          \
	ADD $16, X20;                              \
	VLE64V (X20), V3;                          \
	ADD $16, X20;                              \
	MOV (X20), X18;                            \
	MOVWU 8(X20), X19;                         \
	VSE64V V1, (X8);                           \
	ADD $16, X8, X20;                          \
	VSE64V V2, (X20);                          \
	ADD $16, X20;                              \
	VSE64V V3, (X20);                          \
	ADD $16, X20;                              \
	MOV X18, (X20);                            \
	MOVW X19, 8(X20);                          \
	MOVW X17, 12(X20)

#define RESTORE_LFSR_2() \
	MOV (X8), X17; \
	ADD $8, X8, X20; \
	VLE64V (X20), V1; \
	ADD $16, X20; \
	VLE64V (X20), V2; \
	ADD $16, X20; \
	VLE64V (X20), V3; \
	ADD $16, X20; \
	MOV (X20), X18; \
	VSE64V V1, (X8); \
	ADD $16, X8, X20; \
	VSE64V V2, (X20); \
	ADD $16, X20; \
	VSE64V V3, (X20); \
	ADD $16, X20; \
	MOV X18, (X20); \
	MOV X17, 8(X20)

#define RESTORE_LFSR_4()                     \
	VLE64V (X8), V1; \
	ADD $16, X8, X20; \
	VLE64V (X20), V2; \
	ADD $16, X20; \
	VLE64V (X20), V3; \
	ADD $16, X20; \
	VLE64V (X20), V4; \
	VSE64V V2, (X8); \
	ADD $16, X8, X20; \
	VSE64V V3, (X20); \
	ADD $16, X20; \
	VSE64V V4, (X20); \
	ADD $16, X20; \
	VSE64V V1, (X20)

#define RESTORE_LFSR_8()                     \
	VLE64V (X8), V1; \
	ADD $16, X8, X20; \
	VLE64V (X20), V2; \
	ADD $16, X20; \
	VLE64V (X20), V3; \
	ADD $16, X20; \
	VLE64V (X20), V4; \
	VSE64V V3, (X8); \
	ADD $16, X8, X20; \
	VSE64V V4, (X20); \
	ADD $16, X20; \
	VSE64V V1, (X20); \
	ADD $16, X20; \
	VSE64V V2, (X20)

// func genKeywordAsm(s *zucState32) uint32
TEXT ·genKeywordAsm(SB),NOSPLIT,$0
	LOAD_ZUC_VECTOR_CONSTANTS(X8)
	VXORVV ZERO_VECTOR, ZERO_VECTOR, ZERO_VECTOR
	MOV $0x7FFFFFFF, X25

	MOV pState+0(FP), X8
	LOAD_STATE(0(X8))
	BITS_REORG(0)
	NONLIN_FUN()

	XOR X15, X16, X16
	MOVW X16, ret+8(FP)

	XOR X16, X16, X16
	LFSR_UPDT(0)
	SAVE_STATE(0(X8))
	RESTORE_LFSR_0()

	RET

#define ONEROUND(idx)      \
	BITS_REORG(idx);               \
	NONLIN_FUN();                  \
	XOR X15, X16, X16;             \
	MOVW X16, (idx*4)(X9);         \
	XOR X16, X16, X16;             \
	LFSR_UPDT(idx)

// func genKeyStreamAsm(keyStream []uint32, pState *zucState32)
TEXT ·genKeyStreamAsm(SB),NOSPLIT,$0
	LOAD_ZUC_VECTOR_CONSTANTS(X8)
	VXORVV ZERO_VECTOR, ZERO_VECTOR, ZERO_VECTOR
	MOV $0x7FFFFFFF, X25

	MOV ks+0(FP), X9
	MOV ks_len+8(FP), X22
	MOV pState+24(FP), X8

	LOAD_STATE(0(X8))

	MOV $16, X23
zucSixteens:
		BLT X22, X23, zucOctet
		SUB $16, X22, X22
		ONEROUND(0)
		ONEROUND(1)
		ONEROUND(2)
		ONEROUND(3)
		ONEROUND(4)
		ONEROUND(5)
		ONEROUND(6)
		ONEROUND(7)
		ONEROUND(8)
		ONEROUND(9)
		ONEROUND(10)
		ONEROUND(11)
		ONEROUND(12)
		ONEROUND(13)
		ONEROUND(14)
		ONEROUND(15)
		ADD $64, X9, X9
	JMP zucSixteens

zucOctet:
	MOV $8, X23
	BLT X22, X23, zucNibble
	SUB $8, X22, X22
	ONEROUND(0)
	ONEROUND(1)
	ONEROUND(2)
	ONEROUND(3)
	ONEROUND(4)
	ONEROUND(5)
	ONEROUND(6)
	ONEROUND(7)
	ADD $32, X9, X9
	RESTORE_LFSR_8()

zucNibble:
	MOV $4, X23
	BLT X22, X23, zucDouble
	SUB $4, X22, X22
	ONEROUND(0)
	ONEROUND(1)
	ONEROUND(2)
	ONEROUND(3)
	ADD $16, X9, X9
	RESTORE_LFSR_4()	

zucDouble:
	MOV $2, X23
	BLT X22, X23, zucSingle
	SUB $2, X22, X22
	ONEROUND(0)
	ONEROUND(1)
	ADD $8, X9, X9
	RESTORE_LFSR_2()

zucSingle:
	BEQZ X22, zucRet
	ONEROUND(0)
	RESTORE_LFSR_0()

zucRet:
	SAVE_STATE(0(X8))
	RET

#define ROUND_REV32(idx)      \
	BITS_REORG(idx);               \
	NONLIN_FUN();                  \
	XOR X15, X16, X16;             \
	REV8 X16, X16;                 \
	SRL $32, X16, X16;             \
	MOVW X16, (idx*4)(X9);         \
	XOR X16, X16, X16;             \
	LFSR_UPDT(idx)

// func genKeyStreamRev32Asm(keyStream []byte, pState *zucState32)
TEXT ·genKeyStreamRev32Asm(SB),NOSPLIT,$0
	LOAD_ZUC_VECTOR_CONSTANTS(X8)
	VXORVV ZERO_VECTOR, ZERO_VECTOR, ZERO_VECTOR
	MOV $0x7FFFFFFF, X25

	MOV ks+0(FP), X9
	MOV ks_len+8(FP), X22
	MOV pState+24(FP), X8

	LOAD_STATE(0(X8))

	SRL $2, X22, X22

	MOV $16, X23
revZucSixteens:
		BLT X22, X23, revZucOctet
		SUB $16, X22, X22
		ROUND_REV32(0)
		ROUND_REV32(1)
		ROUND_REV32(2)
		ROUND_REV32(3)
		ROUND_REV32(4)
		ROUND_REV32(5)
		ROUND_REV32(6)
		ROUND_REV32(7)
		ROUND_REV32(8)
		ROUND_REV32(9)
		ROUND_REV32(10)
		ROUND_REV32(11)
		ROUND_REV32(12)
		ROUND_REV32(13)
		ROUND_REV32(14)
		ROUND_REV32(15)
		ADD $64, X9, X9
	JMP revZucSixteens

revZucOctet:
	MOV $8, X23
	BLT X22, X23, revZucNibble
	SUB $8, X22, X22
	ROUND_REV32(0)
	ROUND_REV32(1)
	ROUND_REV32(2)
	ROUND_REV32(3)
	ROUND_REV32(4)
	ROUND_REV32(5)
	ROUND_REV32(6)
	ROUND_REV32(7)
	ADD $32, X9, X9
	RESTORE_LFSR_8()

revZucNibble:
	MOV $4, X23
	BLT X22, X23, revZucDouble
	SUB $4, X22, X22
	ROUND_REV32(0)
	ROUND_REV32(1)
	ROUND_REV32(2)
	ROUND_REV32(3)
	ADD $16, X9, X9
	RESTORE_LFSR_4()	

revZucDouble:
	MOV $2, X23
	BLT X22, X23, revZucSingle
	SUB $2, X22, X22
	ROUND_REV32(0)
	ROUND_REV32(1)
	ADD $8, X9, X9
	RESTORE_LFSR_2()

revZucSingle:
	BEQZ X22, revZucRet
	ROUND_REV32(0)
	RESTORE_LFSR_0()

revZucRet:
	SAVE_STATE(0(X8))
	RET
