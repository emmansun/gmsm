// This is a port of the NIST P256 s390x asm implementation to SM2 P256.
//
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"
#include "go_asm.h"

DATA p256ordK0<>+0x00(SB)/4, $0x72350975
DATA p256ord<>+0x00(SB)/8, $0xfffffffeffffffff
DATA p256ord<>+0x08(SB)/8, $0xffffffffffffffff
DATA p256ord<>+0x10(SB)/8, $0x7203df6b21c6052b
DATA p256ord<>+0x18(SB)/8, $0x53bbf40939d54123
DATA p256<>+0x00(SB)/8, $0xfffffffeffffffff // P256
DATA p256<>+0x08(SB)/8, $0xffffffffffffffff // P256
DATA p256<>+0x10(SB)/8, $0xffffffff00000000 // P256
DATA p256<>+0x18(SB)/8, $0xffffffffffffffff // P256
DATA p256<>+0x20(SB)/8, $0x0000000000000000 // SEL 0 0 d1 d0
DATA p256<>+0x28(SB)/8, $0x18191a1b1c1d1e1f // SEL 0 0 d1 d0
DATA p256<>+0x30(SB)/8, $0x0706050403020100 // LE2BE permute mask
DATA p256<>+0x38(SB)/8, $0x0f0e0d0c0b0a0908 // LE2BE permute mask
DATA p256mul<>+0x00(SB)/8, $0xfffffffeffffffff // P256
DATA p256mul<>+0x08(SB)/8, $0xffffffffffffffff // P256
DATA p256mul<>+0x10(SB)/8, $0xffffffff00000000 // P256
DATA p256mul<>+0x18(SB)/8, $0xffffffffffffffff // P256
DATA p256mul<>+0x20(SB)/8, $0x1c1d1e1f00000000 // SEL d0  0  0 d0
DATA p256mul<>+0x28(SB)/8, $0x000000001c1d1e1f // SEL d0  0  0 d0
DATA p256mul<>+0x30(SB)/8, $0x0001020304050607 // SEL d0  0 d1 d0
DATA p256mul<>+0x38(SB)/8, $0x1c1d1e1f0c0d0e0f // SEL d0  0 d1 d0
DATA p256mul<>+0x40(SB)/8, $0x040506071c1d1e1f // SEL  0 d1 d0 d1
DATA p256mul<>+0x48(SB)/8, $0x0c0d0e0f1c1d1e1f // SEL  0 d1 d0 d1
DATA p256mul<>+0x50(SB)/8, $0x0405060704050607 // SEL  0  0 d1 d0
DATA p256mul<>+0x58(SB)/8, $0x1c1d1e1f0c0d0e0f // SEL  0  0 d1 d0
DATA p256mul<>+0x60(SB)/8, $0x0c0d0e0f1c1d1e1f // SEL d1 d0 d1 d0
DATA p256mul<>+0x68(SB)/8, $0x0c0d0e0f1c1d1e1f // SEL d1 d0 d1 d0
DATA p256mul<>+0x70(SB)/8, $0x141516170c0d0e0f // SEL 0  d1 d0  0
DATA p256mul<>+0x78(SB)/8, $0x1c1d1e1f14151617 // SEL 0  d1 d0  0
DATA p256mul<>+0x80(SB)/8, $0x0000000100000000 // (1*2^256)%P256
DATA p256mul<>+0x88(SB)/8, $0x0000000000000000 // (1*2^256)%P256
DATA p256mul<>+0x90(SB)/8, $0x00000000ffffffff // (1*2^256)%P256
DATA p256mul<>+0x98(SB)/8, $0x0000000000000001 // (1*2^256)%P256
GLOBL p256ordK0<>(SB), 8, $4
GLOBL p256ord<>(SB), 8, $32
GLOBL p256<>(SB), 8, $64
GLOBL p256mul<>(SB), 8, $160

// func p256OrdLittleToBig(res *[32]byte, in *p256OrdElement)
TEXT ·p256OrdLittleToBig(SB), NOSPLIT, $0
	JMP ·p256BigToLittle(SB)

// func p256OrdBigToLittle(res *p256OrdElement, in *[32]byte)
TEXT ·p256OrdBigToLittle(SB), NOSPLIT, $0
	JMP ·p256BigToLittle(SB)

// ---------------------------------------
// func p256LittleToBig(res *[32]byte, in *p256Element)
TEXT ·p256LittleToBig(SB), NOSPLIT, $0
	JMP ·p256BigToLittle(SB)

// func p256BigToLittle(res *p256Element, in *[32]byte)
#define res_ptr   R1
#define in_ptr   R2
#define T1L   V2
#define T1H   V3

TEXT ·p256BigToLittle(SB), NOSPLIT, $0
	MOVD res+0(FP), res_ptr
	MOVD in+8(FP), in_ptr

	VL 0(in_ptr), T1H
	VL 16(in_ptr), T1L

	VPDI $0x4, T1L, T1L, T1L
	VPDI $0x4, T1H, T1H, T1H

	VST T1L, 0(res_ptr)
	VST T1H, 16(res_ptr)
	RET

#undef res_ptr
#undef in_ptr
#undef T1L
#undef T1H

// ---------------------------------------
// iff cond == 1  val <- -val
// func p256NegCond(val *p256Element, cond int)
#define P1ptr   R1
#define CPOOL   R4

#define Y1L   V0
#define Y1H   V1
#define T1L   V2
#define T1H   V3

#define PL    V30
#define PH    V31

#define ZER   V4
#define SEL1  V5
#define CAR1  V6
TEXT ·p256NegCond(SB), NOSPLIT, $0
	MOVD val+0(FP), P1ptr

	MOVD $p256mul<>+0x00(SB), CPOOL
	VL   16(CPOOL), PL
	VL   0(CPOOL), PH

	VL   16(P1ptr), Y1H
	VPDI $0x4, Y1H, Y1H, Y1H
	VL   0(P1ptr), Y1L
	VPDI $0x4, Y1L, Y1L, Y1L

	VLREPG cond+8(FP), SEL1
	VZERO  ZER
	VCEQG  SEL1, ZER, SEL1

	VSCBIQ Y1L, PL, CAR1
	VSQ    Y1L, PL, T1L
	VSBIQ  PH, Y1H, CAR1, T1H

	VSEL Y1L, T1L, SEL1, Y1L
	VSEL Y1H, T1H, SEL1, Y1H

	VPDI $0x4, Y1H, Y1H, Y1H
	VST  Y1H, 16(P1ptr)
	VPDI $0x4, Y1L, Y1L, Y1L
	VST  Y1L, 0(P1ptr)
	RET

#undef P1ptr
#undef CPOOL
#undef Y1L
#undef Y1H
#undef T1L
#undef T1H
#undef PL
#undef PH
#undef ZER
#undef SEL1
#undef CAR1

// ---------------------------------------
// if cond == 0 res <- b; else res <- a
// func p256MovCond(res, a, b *P256Point, cond int)
#define P3ptr   R1
#define P1ptr   R2
#define P2ptr   R3

#define X1L    V0
#define X1H    V1
#define Y1L    V2
#define Y1H    V3
#define Z1L    V4
#define Z1H    V5
#define X2L    V6
#define X2H    V7
#define Y2L    V8
#define Y2H    V9
#define Z2L    V10
#define Z2H    V11

#define ZER   V18
#define SEL1  V19
TEXT ·p256MovCond(SB), NOSPLIT, $0
	MOVD   res+0(FP), P3ptr
	MOVD   a+8(FP), P1ptr
	MOVD   b+16(FP), P2ptr
	VLREPG cond+24(FP), SEL1
	VZERO  ZER
	VCEQG  SEL1, ZER, SEL1

	VL 0(P1ptr), X1H
	VL 16(P1ptr), X1L
	VL 32(P1ptr), Y1H
	VL 48(P1ptr), Y1L
	VL 64(P1ptr), Z1H
	VL 80(P1ptr), Z1L

	VL 0(P2ptr), X2H
	VL 16(P2ptr), X2L
	VL 32(P2ptr), Y2H
	VL 48(P2ptr), Y2L
	VL 64(P2ptr), Z2H
	VL 80(P2ptr), Z2L

	VSEL X2L, X1L, SEL1, X1L
	VSEL X2H, X1H, SEL1, X1H
	VSEL Y2L, Y1L, SEL1, Y1L
	VSEL Y2H, Y1H, SEL1, Y1H
	VSEL Z2L, Z1L, SEL1, Z1L
	VSEL Z2H, Z1H, SEL1, Z1H

	VST X1H, 0(P3ptr)
	VST X1L, 16(P3ptr)
	VST Y1H, 32(P3ptr)
	VST Y1L, 48(P3ptr)
	VST Z1H, 64(P3ptr)
	VST Z1L, 80(P3ptr)

	RET

#undef P3ptr
#undef P1ptr
#undef P2ptr
#undef X1L
#undef X1H
#undef Y1L
#undef Y1H
#undef Z1L
#undef Z1H
#undef X2L
#undef X2H
#undef Y2L
#undef Y2H
#undef Z2L
#undef Z2H
#undef ZER
#undef SEL1

// ---------------------------------------
// Constant time table access
// Indexed from 1 to 15, with -1 offset
// (index 0 is implicitly point at infinity)
// func p256Select(res *P256Point, table *p256Table, idx int)
#define P3ptr   R1
#define P1ptr   R2
#define COUNT   R4

#define X1L    V0
#define X1H    V1
#define Y1L    V2
#define Y1H    V3
#define Z1L    V4
#define Z1H    V5
#define X2L    V6
#define X2H    V7
#define Y2L    V8
#define Y2H    V9
#define Z2L    V10
#define Z2H    V11

#define ONE   V18
#define IDX   V19
#define SEL1  V20
#define SEL2  V21
TEXT ·p256Select(SB), NOSPLIT, $0
	MOVD   res+0(FP), P3ptr
	MOVD   table+8(FP), P1ptr
	VLREPB idx+(16+7)(FP), IDX
	VREPIB $1, ONE
	VREPIB $1, SEL2
	MOVD   $1, COUNT

	VZERO X1H
	VZERO X1L
	VZERO Y1H
	VZERO Y1L
	VZERO Z1H
	VZERO Z1L

loop_select:
	VL 0(P1ptr), X2H
	VL 16(P1ptr), X2L
	VL 32(P1ptr), Y2H
	VL 48(P1ptr), Y2L
	VL 64(P1ptr), Z2H
	VL 80(P1ptr), Z2L

	VCEQG SEL2, IDX, SEL1

	VSEL X2L, X1L, SEL1, X1L
	VSEL X2H, X1H, SEL1, X1H
	VSEL Y2L, Y1L, SEL1, Y1L
	VSEL Y2H, Y1H, SEL1, Y1H
	VSEL Z2L, Z1L, SEL1, Z1L
	VSEL Z2H, Z1H, SEL1, Z1H

	VAB  SEL2, ONE, SEL2
	ADDW $1, COUNT
	ADD  $96, P1ptr
	CMPW COUNT, $17
	BLT  loop_select

	VST X1H, 0(P3ptr)
	VST X1L, 16(P3ptr)
	VST Y1H, 32(P3ptr)
	VST Y1L, 48(P3ptr)
	VST Z1H, 64(P3ptr)
	VST Z1L, 80(P3ptr)
	RET

#undef P3ptr
#undef P1ptr
#undef COUNT
#undef X1L
#undef X1H
#undef Y1L
#undef Y1H
#undef Z1L
#undef Z1H
#undef X2L
#undef X2H
#undef Y2L
#undef Y2H
#undef Z2L
#undef Z2H
#undef ONE
#undef IDX
#undef SEL1
#undef SEL2

// ---------------------------------------

//  func p256FromMont(res, in *p256Element)
#define res_ptr R1
#define x_ptr   R2
#define CPOOL   R4

#define T0   V0
#define T1   V1
#define T2   V2
#define TT0  V3
#define TT1  V4

#define ZER   V6
#define SEL1  V7
#define SEL2  V8
#define CAR1  V9
#define CAR2  V10
#define RED1  V11
#define RED2  V12
#define PL    V14
#define PH    V15

TEXT ·p256FromMont(SB), NOSPLIT, $0
	MOVD res+0(FP), res_ptr
	MOVD in+8(FP), x_ptr

	VZERO T2
	VZERO ZER
	MOVD  $p256<>+0x00(SB), CPOOL
	VL    16(CPOOL), PL
	VL    0(CPOOL), PH
	VL    48(CPOOL), SEL2
	VL    64(CPOOL), SEL1

	VL   (0*16)(x_ptr), T0
	VPDI $0x4, T0, T0, T0
	VL   (1*16)(x_ptr), T1
	VPDI $0x4, T1, T1, T1

	// First round
	VPERM ZER, T0, SEL1, RED1   // 0 0 d1 d0
	VSLDB $4, RED1, ZER, TT0    // 0 d1 d0 0
	VSLDB $4, TT0, ZER, RED2    // d1 d0 0 0
	VSCBIQ  TT0, RED1, CAR1
	VSQ	 TT0, RED1, RED1
	VSBIQ  RED2, TT0, CAR1, RED2 // Guaranteed not to underflow

	VSLDB $8, T1, T0, T0
	VSLDB $8, T2, T1, T1

	VACCQ  T0, RED1, CAR1
	VAQ    T0, RED1, T0
	VACCCQ T1, RED2, CAR1, CAR2
	VACQ   T1, RED2, CAR1, T1
	VAQ    T2, CAR2, T2

	// Second round
	VPERM ZER, T0, SEL1, RED1   // 0 0 d1 d0
	VSLDB $4, RED1, ZER, TT0    // 0 d1 d0 0
	VSLDB $4, TT0, ZER, RED2    // d1 d0 0 0
	VSCBIQ  TT0, RED1, CAR1
	VSQ	 TT0, RED1, RED1
	VSBIQ  RED2, TT0, CAR1, RED2 // Guaranteed not to underflow

	VSLDB $8, T1, T0, T0
	VSLDB $8, T2, T1, T1

	VACCQ  T0, RED1, CAR1
	VAQ    T0, RED1, T0
	VACCCQ T1, RED2, CAR1, CAR2
	VACQ   T1, RED2, CAR1, T1
	VAQ    T2, CAR2, T2

	// Third round
	VPERM ZER, T0, SEL1, RED1   // 0 0 d1 d0
	VSLDB $4, RED1, ZER, TT0    // 0 d1 d0 0
	VSLDB $4, TT0, ZER, RED2    // d1 d0 0 0
	VSCBIQ  TT0, RED1, CAR1
	VSQ	 TT0, RED1, RED1
	VSBIQ  RED2, TT0, CAR1, RED2 // Guaranteed not to underflow

	VSLDB $8, T1, T0, T0
	VSLDB $8, T2, T1, T1

	VACCQ  T0, RED1, CAR1
	VAQ    T0, RED1, T0
	VACCCQ T1, RED2, CAR1, CAR2
	VACQ   T1, RED2, CAR1, T1
	VAQ    T2, CAR2, T2

	// Last round
	VPERM ZER, T0, SEL1, RED1   // 0 0 d1 d0
	VSLDB $4, RED1, ZER, TT0    // 0 d1 d0 0
	VSLDB $4, TT0, ZER, RED2    // d1 d0 0 0
	VSCBIQ  TT0, RED1, CAR1
	VSQ	 TT0, RED1, RED1
	VSBIQ  RED2, TT0, CAR1, RED2 // Guaranteed not to underflow

	VSLDB $8, T1, T0, T0
	VSLDB $8, T2, T1, T1

	VACCQ  T0, RED1, CAR1
	VAQ    T0, RED1, T0
	VACCCQ T1, RED2, CAR1, CAR2
	VACQ   T1, RED2, CAR1, T1
	VAQ    T2, CAR2, T2

	// ---------------------------------------------------

	VSCBIQ  PL, T0, CAR1
	VSQ     PL, T0, TT0
	VSBCBIQ T1, PH, CAR1, CAR2
	VSBIQ   T1, PH, CAR1, TT1
	VSBIQ   T2, ZER, CAR2, T2

	// what output to use, TT1||TT0 or T1||T0?
	VSEL T0, TT0, T2, T0
	VSEL T1, TT1, T2, T1

	VPDI $0x4, T0, T0, TT0
	VST  TT0, (0*16)(res_ptr)
	VPDI $0x4, T1, T1, TT1
	VST  TT1, (1*16)(res_ptr)
	RET

#undef res_ptr
#undef x_ptr
#undef CPOOL
#undef T0
#undef T1
#undef T2
#undef TT0
#undef TT1
#undef ZER
#undef SEL1
#undef SEL2
#undef CAR1
#undef CAR2
#undef RED1
#undef RED2
#undef PL
#undef PH

// Constant time table access
// Indexed from 1 to 15, with -1 offset
// (index 0 is implicitly point at infinity)
// func p256SelectBase(point *p256Point, table []p256Point, idx int)
// new : func p256SelectAffine(res *p256AffinePoint, table *p256AffineTable, idx int)

#define P3ptr   R1
#define P1ptr   R2
#define COUNT   R4
#define CPOOL   R5

#define X1L    V0
#define X1H    V1
#define Y1L    V2
#define Y1H    V3
#define Z1L    V4
#define Z1H    V5
#define X2L    V6
#define X2H    V7
#define Y2L    V8
#define Y2H    V9
#define Z2L    V10
#define Z2H    V11
#define LE2BE  V12

#define ONE   V18
#define IDX   V19
#define SEL1  V20
#define SEL2  V21

TEXT ·p256SelectAffine(SB), NOSPLIT, $0
	MOVD   res+0(FP), P3ptr
	MOVD   table+8(FP), P1ptr
	MOVD   $p256<>+0x00(SB), CPOOL
	VLREPB idx+(16+7)(FP), IDX
	VREPIB $1, ONE
	VREPIB $1, SEL2
	MOVD   $1, COUNT
	VL     80(CPOOL), LE2BE

	VZERO X1H
	VZERO X1L
	VZERO Y1H
	VZERO Y1L

loop_select:
	VL 0(P1ptr), X2H
	VL 16(P1ptr), X2L
	VL 32(P1ptr), Y2H
	VL 48(P1ptr), Y2L

	VCEQG SEL2, IDX, SEL1

	VSEL X2L, X1L, SEL1, X1L
	VSEL X2H, X1H, SEL1, X1H
	VSEL Y2L, Y1L, SEL1, Y1L
	VSEL Y2H, Y1H, SEL1, Y1H

	VAB  SEL2, ONE, SEL2
	ADDW $1, COUNT
	ADD  $64, P1ptr
	CMPW COUNT, $65
	BLT  loop_select
	VST  X1H, 0(P3ptr)
	VST  X1L, 16(P3ptr)
	VST  Y1H, 32(P3ptr)
	VST  Y1L, 48(P3ptr)

	RET

#undef P3ptr
#undef P1ptr
#undef COUNT
#undef X1L
#undef X1H
#undef Y1L
#undef Y1H
#undef Z1L
#undef Z1H
#undef X2L
#undef X2H
#undef Y2L
#undef Y2H
#undef Z2L
#undef Z2H
#undef ONE
#undef IDX
#undef SEL1
#undef SEL2
#undef CPOOL

// ---------------------------------------

// func p256OrdMul(res, in1, in2 *p256OrdElement)
#define res_ptr R1
#define x_ptr R2
#define y_ptr R3
#define X0    V0
#define X1    V1
#define Y0    V2
#define Y1    V3
#define M0    V4
#define M1    V5
#define T0    V6
#define T1    V7
#define T2    V8
#define YDIG  V9

#define ADD1  V16
#define ADD1H V17
#define ADD2  V18
#define ADD2H V19
#define RED1  V20
#define RED1H V21
#define RED2  V22
#define RED2H V23
#define CAR1  V24
#define CAR1M V25

#define MK0   V30
#define K0    V31
TEXT ·p256OrdMul<>(SB), NOSPLIT, $0
	MOVD res+0(FP), res_ptr
	MOVD in1+8(FP), x_ptr
	MOVD in2+16(FP), y_ptr

	VZERO T2
	MOVD  $p256ordK0<>+0x00(SB), R4

	// VLEF    $3, 0(R4), K0
	WORD $0xE7F40000
	BYTE $0x38
	BYTE $0x03
	MOVD $p256ord<>+0x00(SB), R4
	VL   16(R4), M0
	VL   0(R4), M1

	VL   (0*16)(x_ptr), X0
	VPDI $0x4, X0, X0, X0
	VL   (1*16)(x_ptr), X1
	VPDI $0x4, X1, X1, X1
	VL   (0*16)(y_ptr), Y0
	VPDI $0x4, Y0, Y0, Y0
	VL   (1*16)(y_ptr), Y1
	VPDI $0x4, Y1, Y1, Y1

	// ---------------------------------------------------------------------------/
	VREPF $3, Y0, YDIG
	VMLF  X0, YDIG, ADD1
	VMLF  ADD1, K0, MK0
	VREPF $3, MK0, MK0

	VMLF  X1, YDIG, ADD2
	VMLHF X0, YDIG, ADD1H
	VMLHF X1, YDIG, ADD2H

	VMALF  M0, MK0, ADD1, RED1
	VMALHF M0, MK0, ADD1, RED1H
	VMALF  M1, MK0, ADD2, RED2
	VMALHF M1, MK0, ADD2, RED2H

	VSLDB $12, RED2, RED1, RED1
	VSLDB $12, T2, RED2, RED2

	VACCQ RED1, ADD1H, CAR1
	VAQ   RED1, ADD1H, T0
	VACCQ RED1H, T0, CAR1M
	VAQ   RED1H, T0, T0

	// << ready for next MK0

	VACQ   RED2, ADD2H, CAR1, T1
	VACCCQ RED2, ADD2H, CAR1, CAR1
	VACCCQ RED2H, T1, CAR1M, T2
	VACQ   RED2H, T1, CAR1M, T1
	VAQ    CAR1, T2, T2

	// ---------------------------------------------------
/* *
 * ---+--------+--------+
 *  T2|   T1   |   T0   |
 * ---+--------+--------+
 *           *(add)*
 *    +--------+--------+
 *    |   X1   |   X0   |
 *    +--------+--------+
 *           *(mul)*
 *    +--------+--------+
 *    |  YDIG  |  YDIG  |
 *    +--------+--------+
 *           *(add)*
 *    +--------+--------+
 *    |   M1   |   M0   |
 *    +--------+--------+
 *           *(mul)*
 *    +--------+--------+
 *    |   MK0  |   MK0  |
 *    +--------+--------+
 *
 *   ---------------------
 *
 *    +--------+--------+
 *    |  ADD2  |  ADD1  |
 *    +--------+--------+
 *  +--------+--------+
 *  | ADD2H  | ADD1H  |
 *  +--------+--------+
 *    +--------+--------+
 *    |  RED2  |  RED1  |
 *    +--------+--------+
 *  +--------+--------+
 *  | RED2H  | RED1H  |
 *  +--------+--------+
 */
	VREPF $2, Y0, YDIG
	VMALF X0, YDIG, T0, ADD1
	VMLF  ADD1, K0, MK0
	VREPF $3, MK0, MK0

	VMALF  X1, YDIG, T1, ADD2
	VMALHF X0, YDIG, T0, ADD1H
	VMALHF X1, YDIG, T1, ADD2H

	VMALF  M0, MK0, ADD1, RED1
	VMALHF M0, MK0, ADD1, RED1H
	VMALF  M1, MK0, ADD2, RED2
	VMALHF M1, MK0, ADD2, RED2H

	VSLDB $12, RED2, RED1, RED1
	VSLDB $12, T2, RED2, RED2

	VACCQ RED1, ADD1H, CAR1
	VAQ   RED1, ADD1H, T0
	VACCQ RED1H, T0, CAR1M
	VAQ   RED1H, T0, T0

	// << ready for next MK0

	VACQ   RED2, ADD2H, CAR1, T1
	VACCCQ RED2, ADD2H, CAR1, CAR1
	VACCCQ RED2H, T1, CAR1M, T2
	VACQ   RED2H, T1, CAR1M, T1
	VAQ    CAR1, T2, T2

	// ---------------------------------------------------
	VREPF $1, Y0, YDIG
	VMALF X0, YDIG, T0, ADD1
	VMLF  ADD1, K0, MK0
	VREPF $3, MK0, MK0

	VMALF  X1, YDIG, T1, ADD2
	VMALHF X0, YDIG, T0, ADD1H
	VMALHF X1, YDIG, T1, ADD2H

	VMALF  M0, MK0, ADD1, RED1
	VMALHF M0, MK0, ADD1, RED1H
	VMALF  M1, MK0, ADD2, RED2
	VMALHF M1, MK0, ADD2, RED2H

	VSLDB $12, RED2, RED1, RED1
	VSLDB $12, T2, RED2, RED2

	VACCQ RED1, ADD1H, CAR1
	VAQ   RED1, ADD1H, T0
	VACCQ RED1H, T0, CAR1M
	VAQ   RED1H, T0, T0

	// << ready for next MK0

	VACQ   RED2, ADD2H, CAR1, T1
	VACCCQ RED2, ADD2H, CAR1, CAR1
	VACCCQ RED2H, T1, CAR1M, T2
	VACQ   RED2H, T1, CAR1M, T1
	VAQ    CAR1, T2, T2

	// ---------------------------------------------------
	VREPF $0, Y0, YDIG
	VMALF X0, YDIG, T0, ADD1
	VMLF  ADD1, K0, MK0
	VREPF $3, MK0, MK0

	VMALF  X1, YDIG, T1, ADD2
	VMALHF X0, YDIG, T0, ADD1H
	VMALHF X1, YDIG, T1, ADD2H

	VMALF  M0, MK0, ADD1, RED1
	VMALHF M0, MK0, ADD1, RED1H
	VMALF  M1, MK0, ADD2, RED2
	VMALHF M1, MK0, ADD2, RED2H

	VSLDB $12, RED2, RED1, RED1
	VSLDB $12, T2, RED2, RED2

	VACCQ RED1, ADD1H, CAR1
	VAQ   RED1, ADD1H, T0
	VACCQ RED1H, T0, CAR1M
	VAQ   RED1H, T0, T0

	// << ready for next MK0

	VACQ   RED2, ADD2H, CAR1, T1
	VACCCQ RED2, ADD2H, CAR1, CAR1
	VACCCQ RED2H, T1, CAR1M, T2
	VACQ   RED2H, T1, CAR1M, T1
	VAQ    CAR1, T2, T2

	// ---------------------------------------------------
	VREPF $3, Y1, YDIG
	VMALF X0, YDIG, T0, ADD1
	VMLF  ADD1, K0, MK0
	VREPF $3, MK0, MK0

	VMALF  X1, YDIG, T1, ADD2
	VMALHF X0, YDIG, T0, ADD1H
	VMALHF X1, YDIG, T1, ADD2H

	VMALF  M0, MK0, ADD1, RED1
	VMALHF M0, MK0, ADD1, RED1H
	VMALF  M1, MK0, ADD2, RED2
	VMALHF M1, MK0, ADD2, RED2H

	VSLDB $12, RED2, RED1, RED1
	VSLDB $12, T2, RED2, RED2

	VACCQ RED1, ADD1H, CAR1
	VAQ   RED1, ADD1H, T0
	VACCQ RED1H, T0, CAR1M
	VAQ   RED1H, T0, T0

	// << ready for next MK0

	VACQ   RED2, ADD2H, CAR1, T1
	VACCCQ RED2, ADD2H, CAR1, CAR1
	VACCCQ RED2H, T1, CAR1M, T2
	VACQ   RED2H, T1, CAR1M, T1
	VAQ    CAR1, T2, T2

	// ---------------------------------------------------
	VREPF $2, Y1, YDIG
	VMALF X0, YDIG, T0, ADD1
	VMLF  ADD1, K0, MK0
	VREPF $3, MK0, MK0

	VMALF  X1, YDIG, T1, ADD2
	VMALHF X0, YDIG, T0, ADD1H
	VMALHF X1, YDIG, T1, ADD2H

	VMALF  M0, MK0, ADD1, RED1
	VMALHF M0, MK0, ADD1, RED1H
	VMALF  M1, MK0, ADD2, RED2
	VMALHF M1, MK0, ADD2, RED2H

	VSLDB $12, RED2, RED1, RED1
	VSLDB $12, T2, RED2, RED2

	VACCQ RED1, ADD1H, CAR1
	VAQ   RED1, ADD1H, T0
	VACCQ RED1H, T0, CAR1M
	VAQ   RED1H, T0, T0

	// << ready for next MK0

	VACQ   RED2, ADD2H, CAR1, T1
	VACCCQ RED2, ADD2H, CAR1, CAR1
	VACCCQ RED2H, T1, CAR1M, T2
	VACQ   RED2H, T1, CAR1M, T1
	VAQ    CAR1, T2, T2

	// ---------------------------------------------------
	VREPF $1, Y1, YDIG
	VMALF X0, YDIG, T0, ADD1
	VMLF  ADD1, K0, MK0
	VREPF $3, MK0, MK0

	VMALF  X1, YDIG, T1, ADD2
	VMALHF X0, YDIG, T0, ADD1H
	VMALHF X1, YDIG, T1, ADD2H

	VMALF  M0, MK0, ADD1, RED1
	VMALHF M0, MK0, ADD1, RED1H
	VMALF  M1, MK0, ADD2, RED2
	VMALHF M1, MK0, ADD2, RED2H

	VSLDB $12, RED2, RED1, RED1
	VSLDB $12, T2, RED2, RED2

	VACCQ RED1, ADD1H, CAR1
	VAQ   RED1, ADD1H, T0
	VACCQ RED1H, T0, CAR1M
	VAQ   RED1H, T0, T0

	// << ready for next MK0

	VACQ   RED2, ADD2H, CAR1, T1
	VACCCQ RED2, ADD2H, CAR1, CAR1
	VACCCQ RED2H, T1, CAR1M, T2
	VACQ   RED2H, T1, CAR1M, T1
	VAQ    CAR1, T2, T2

	// ---------------------------------------------------
	VREPF $0, Y1, YDIG
	VMALF X0, YDIG, T0, ADD1
	VMLF  ADD1, K0, MK0
	VREPF $3, MK0, MK0

	VMALF  X1, YDIG, T1, ADD2
	VMALHF X0, YDIG, T0, ADD1H
	VMALHF X1, YDIG, T1, ADD2H

	VMALF  M0, MK0, ADD1, RED1
	VMALHF M0, MK0, ADD1, RED1H
	VMALF  M1, MK0, ADD2, RED2
	VMALHF M1, MK0, ADD2, RED2H

	VSLDB $12, RED2, RED1, RED1
	VSLDB $12, T2, RED2, RED2

	VACCQ RED1, ADD1H, CAR1
	VAQ   RED1, ADD1H, T0
	VACCQ RED1H, T0, CAR1M
	VAQ   RED1H, T0, T0

	// << ready for next MK0

	VACQ   RED2, ADD2H, CAR1, T1
	VACCCQ RED2, ADD2H, CAR1, CAR1
	VACCCQ RED2H, T1, CAR1M, T2
	VACQ   RED2H, T1, CAR1M, T1
	VAQ    CAR1, T2, T2

	// ---------------------------------------------------

	VZERO   RED1
	VSCBIQ  M0, T0, CAR1
	VSQ     M0, T0, ADD1
	VSBCBIQ T1, M1, CAR1, CAR1M
	VSBIQ   T1, M1, CAR1, ADD2
	VSBIQ   T2, RED1, CAR1M, T2

	// what output to use, ADD2||ADD1 or T1||T0?
	VSEL T0, ADD1, T2, T0
	VSEL T1, ADD2, T2, T1

	VPDI $0x4, T0, T0, T0
	VST  T0, (0*16)(res_ptr)
	VPDI $0x4, T1, T1, T1
	VST  T1, (1*16)(res_ptr)
	RET

#undef res_ptr
#undef x_ptr
#undef y_ptr
#undef X0
#undef X1
#undef Y0
#undef Y1
#undef M0
#undef M1
#undef T0
#undef T1
#undef T2
#undef YDIG

#undef ADD1
#undef ADD1H
#undef ADD2
#undef ADD2H
#undef RED1
#undef RED1H
#undef RED2
#undef RED2H
#undef CAR1
#undef CAR1M

#undef MK0
#undef K0

TEXT ·p256Mul(SB), NOSPLIT, $0
	RET

TEXT ·p256Sqr(SB), NOSPLIT, $0
	RET

TEXT ·p256PointAddAffineAsm(SB), NOSPLIT, $0
	RET

TEXT ·p256PointDoubleAsm(SB), NOSPLIT, $0
	RET

TEXT ·p256PointAddAsm(SB), NOSPLIT, $0
	RET
	
TEXT ·p256PointDouble6TimesAsm(SB), NOSPLIT, $0
	RET

#define res_ptr R1
#define CPOOL   R4

#define T0   V0
#define T1   V1
#define T2   V2
#define TT0  V3
#define TT1  V4

#define ZER   V6
#define CAR1  V7
#define CAR2  V8
#define PL    V9
#define PH    V10

//func p256OrdReduce(s *p256OrdElement)
TEXT ·p256OrdReduce(SB),NOSPLIT,$0
	MOVD res+0(FP), res_ptr

	VZERO T2
	VZERO ZER
	MOVD  $p256ord<>+0x00(SB), CPOOL
	VL    16(CPOOL), PL
	VL    0(CPOOL), PH

	VL   (0*16)(res_ptr), T0
	VPDI $0x4, T0, T0, T0
	VL   (1*16)(res_ptr), T1
	VPDI $0x4, T1, T1, T1

	VSCBIQ  PL, T0, CAR1
	VSQ     PL, T0, TT0
	VSBCBIQ T1, PH, CAR1, CAR2
	VSBIQ   T1, PH, CAR1, TT1
	VSBIQ   T2, ZER, CAR2, T2

	// what output to use, TT1||TT0 or T1||T0?
	VSEL T0, TT0, T2, T0
	VSEL T1, TT1, T2, T1

	VPDI $0x4, T0, T0, TT0
	VST  TT0, (0*16)(res_ptr)
	VPDI $0x4, T1, T1, TT1
	VST  TT1, (1*16)(res_ptr)

	RET
#undef res_ptr
#undef CPOOL
#undef T0
#undef T1
#undef T2
#undef TT0
#undef TT1
#undef ZER
#undef CAR1
#undef CAR2
#undef PL
#undef PH
