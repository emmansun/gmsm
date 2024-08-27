//go:build !purego

#include "textflag.h"

// This is a port of the s390x asm implementation.
// to ppc64le.

// Some changes were needed due to differences in
// the Go opcodes and/or available instructions
// between s390x and ppc64le.

// 1. There were operand order differences in the
// VSUBUQM, VSUBCUQ, and VSEL instructions.

// 2. ppc64 does not have a multiply high and low
// like s390x, so those were implemented using
// macros to compute the equivalent values.

// 3. The LVX, STVX instructions on ppc64 require
// 16 byte alignment of the data.  To avoid that
// requirement, data is loaded using LXVD2X and
// STXVD2X with VPERM to reorder bytes correctly.

// I have identified some areas where I believe
// changes would be needed to make this work for big
// endian; however additional changes beyond what I
// have noted are most likely needed to make it work.
// - The string used with VPERM to swap the byte order
//   for loads and stores.
// - The constants that are loaded from CPOOL.
//

// The following constants are defined in an order
// that is correct for use with LXVD2X/STXVD2X
// on little endian.
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
DATA p256mul<>+0x00(SB)/8, $0xffffffff00000000 // P256 original
DATA p256mul<>+0x08(SB)/8, $0xffffffffffffffff // P256
DATA p256mul<>+0x10(SB)/8, $0xfffffffeffffffff // P256 original
DATA p256mul<>+0x18(SB)/8, $0xffffffffffffffff // P256
DATA p256mul<>+0x20(SB)/8, $0x1c1d1e1f00000000 // SEL d0  0  0 d0
DATA p256mul<>+0x28(SB)/8, $0x000000001c1d1e1f // SEL d0  0  0 d0
DATA p256mul<>+0x30(SB)/8, $0x0405060708090a0b // SEL  0  0 d1 d0
DATA p256mul<>+0x38(SB)/8, $0x1c1d1e1f0c0d0e0f // SEL  0  0 d1 d0
DATA p256mul<>+0x40(SB)/8, $0x00000000ffffffff // (1*2^256)%P256
DATA p256mul<>+0x48(SB)/8, $0x0000000000000001 // (1*2^256)%P256
DATA p256mul<>+0x50(SB)/8, $0x0000000100000000 // (1*2^256)%P256
DATA p256mul<>+0x58(SB)/8, $0x0000000000000000 // (1*2^256)%P256

// External declarations for constants
GLOBL p256ordK0<>(SB), 8, $4
GLOBL p256ord<>(SB), 8, $32
GLOBL p256<>(SB), 8, $48
GLOBL p256mul<>(SB), 8, $96

// The following macros are used to implement the ppc64le
// equivalent function from the corresponding s390x
// instruction for vector multiply high, low, and add,
// since there aren't exact equivalent instructions.
// The corresponding s390x instructions appear in the
// comments.
// Implementation for big endian would have to be
// investigated, I think it would be different.
//
//
// Vector multiply word
//
//	VMLF  x0, x1, out_low
//	VMLHF x0, x1, out_hi
#define VMULT(x1, x2, out_low, out_hi) \
	VMULEUW x1, x2, TMP1; \
	VMULOUW x1, x2, TMP2; \
	VMRGEW TMP1, TMP2, out_hi; \
	VMRGOW TMP1, TMP2, out_low

//
// Vector multiply add word
//
//	VMALF  x0, x1, y, out_low
//	VMALHF x0, x1, y, out_hi
#define VMULT_ADD(x1, x2, y, one, out_low, out_hi) \
	VMULEUW  y, one, TMP2; \
	VMULOUW  y, one, TMP1; \
	VMULEUW  x1, x2, out_low; \
	VMULOUW  x1, x2, out_hi; \
	VADDUDM  TMP2, out_low, TMP2; \
	VADDUDM  TMP1, out_hi, TMP1; \
	VMRGOW   TMP2, TMP1, out_low; \
	VMRGEW   TMP2, TMP1, out_hi

#define res_ptr R3
#define a_ptr R4

#undef res_ptr
#undef a_ptr

#define P1ptr   R3
#define CPOOL   R7

#define Y1L   V0
#define Y1H   V1
#define T1L   V2
#define T1H   V3

#define PL    V30
#define PH    V31

#define CAR1  V6
// func p256NegCond(val *p256Point, cond int)
TEXT ·p256NegCond(SB), NOSPLIT, $0-16
	MOVD val+0(FP), P1ptr
	MOVD $16, R16

	MOVD cond+8(FP), R6
	CMP  $0, R6
	BC   12, 2, LR      // just return if cond == 0

	MOVD $p256mul<>+0x00(SB), CPOOL

	LXVD2X (P1ptr)(R0), Y1L
	LXVD2X (P1ptr)(R16), Y1H

	XXPERMDI Y1H, Y1H, $2, Y1H
	XXPERMDI Y1L, Y1L, $2, Y1L

	LXVD2X (CPOOL)(R0), PL
	LXVD2X (CPOOL)(R16), PH

	VSUBCUQ  PL, Y1L, CAR1      // subtract part2 giving carry
	VSUBUQM  PL, Y1L, T1L       // subtract part2 giving result
	VSUBEUQM PH, Y1H, CAR1, T1H // subtract part1 using carry from part2

	XXPERMDI T1H, T1H, $2, T1H
	XXPERMDI T1L, T1L, $2, T1L

	STXVD2X T1L, (R0+P1ptr)
	STXVD2X T1H, (R16+P1ptr)
	RET

#undef P1ptr
#undef CPOOL
#undef Y1L
#undef Y1H
#undef T1L
#undef T1H
#undef PL
#undef PH
#undef CAR1

#define P3ptr   R3
#define P1ptr   R4
#define P2ptr   R5

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
#define SEL    V12
#define ZER    V13

// This function uses LXVD2X and STXVD2X to avoid the
// data alignment requirement for LVX, STVX. Since
// this code is just moving bytes and not doing arithmetic,
// order of the bytes doesn't matter.
//
// func p256MovCond(res, a, b *p256Point, cond int)
TEXT ·p256MovCond(SB), NOSPLIT, $0-32
	MOVD res+0(FP), P3ptr
	MOVD a+8(FP), P1ptr
	MOVD b+16(FP), P2ptr
	MOVD $16, R16
	MOVD $32, R17
	MOVD $48, R18
	MOVD $56, R21
	MOVD $64, R19
	MOVD $80, R20
	// cond is R1 + 24 (cond offset) + 32
	LXVDSX (R1)(R21), SEL
	VSPLTISB $0, ZER
	// SEL controls whether to store a or b
	VCMPEQUD SEL, ZER, SEL

	LXVD2X (P1ptr+R0), X1H
	LXVD2X (P1ptr+R16), X1L
	LXVD2X (P1ptr+R17), Y1H
	LXVD2X (P1ptr+R18), Y1L
	LXVD2X (P1ptr+R19), Z1H
	LXVD2X (P1ptr+R20), Z1L

	LXVD2X (P2ptr+R0), X2H
	LXVD2X (P2ptr+R16), X2L
	LXVD2X (P2ptr+R17), Y2H
	LXVD2X (P2ptr+R18), Y2L
	LXVD2X (P2ptr+R19), Z2H
	LXVD2X (P2ptr+R20), Z2L

	VSEL X1H, X2H, SEL, X1H
	VSEL X1L, X2L, SEL, X1L
	VSEL Y1H, Y2H, SEL, Y1H
	VSEL Y1L, Y2L, SEL, Y1L
	VSEL Z1H, Z2H, SEL, Z1H
	VSEL Z1L, Z2L, SEL, Z1L

	STXVD2X X1H, (P3ptr+R0)
	STXVD2X X1L, (P3ptr+R16)
	STXVD2X Y1H, (P3ptr+R17)
	STXVD2X Y1L, (P3ptr+R18)
	STXVD2X Z1H, (P3ptr+R19)
	STXVD2X Z1L, (P3ptr+R20)

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
#undef SEL
#undef ZER

#define P3ptr   R3
#define P1ptr   R4
#define COUNT   R5

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
// func p256Select(point *p256Point, table *p256Table, idx int, limit int)
TEXT ·p256Select(SB), NOSPLIT, $0-24
	MOVD res+0(FP), P3ptr
	MOVD table+8(FP), P1ptr
    MOVD limit+24(FP), COUNT
	MOVD $16, R16
	MOVD $32, R17
	MOVD $48, R18
	MOVD $64, R19
	MOVD $80, R20

	LXVDSX   (R1)(R18), SEL1 // VLREPG idx+32(FP), SEL1
	VSPLTB   $7, SEL1, IDX    // splat byte
	VSPLTISB $1, ONE          // VREPIB $1, ONE
	VSPLTISB $1, SEL2         // VREPIB $1, SEL2
	MOVD     COUNT, CTR       // set up ctr

	VSPLTISB $0, X1H // VZERO  X1H
	VSPLTISB $0, X1L // VZERO  X1L
	VSPLTISB $0, Y1H // VZERO  Y1H
	VSPLTISB $0, Y1L // VZERO  Y1L
	VSPLTISB $0, Z1H // VZERO  Z1H
	VSPLTISB $0, Z1L // VZERO  Z1L

loop_select:

	// LVXD2X is used here since data alignment doesn't
	// matter.

	LXVD2X (P1ptr+R0), X2H
	LXVD2X (P1ptr+R16), X2L
	LXVD2X (P1ptr+R17), Y2H
	LXVD2X (P1ptr+R18), Y2L
	LXVD2X (P1ptr+R19), Z2H
	LXVD2X (P1ptr+R20), Z2L

	VCMPEQUD SEL2, IDX, SEL1 // VCEQG SEL2, IDX, SEL1 OK

	// This will result in SEL1 being all 0s or 1s, meaning
	// the result is either X1L or X2L, no individual byte
	// selection.

	VSEL X1L, X2L, SEL1, X1L
	VSEL X1H, X2H, SEL1, X1H
	VSEL Y1L, Y2L, SEL1, Y1L
	VSEL Y1H, Y2H, SEL1, Y1H
	VSEL Z1L, Z2L, SEL1, Z1L
	VSEL Z1H, Z2H, SEL1, Z1H

	// Add 1 to all bytes in SEL2
	VADDUBM SEL2, ONE, SEL2    // VAB  SEL2, ONE, SEL2 OK
	ADD     $96, P1ptr
	BDNZ    loop_select

	// STXVD2X is used here so that alignment doesn't
	// need to be verified. Since values were loaded
	// using LXVD2X this is OK.
	STXVD2X X1H, (P3ptr+R0)
	STXVD2X X1L, (P3ptr+R16)
	STXVD2X Y1H, (P3ptr+R17)
	STXVD2X Y1L, (P3ptr+R18)
	STXVD2X Z1H, (P3ptr+R19)
	STXVD2X Z1L, (P3ptr+R20)
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

// The following functions all reverse the byte order.

//func p256BigToLittle(res *p256Element, in *[32]byte)
TEXT ·p256BigToLittle(SB), NOSPLIT, $0-16
	MOVD	res+0(FP), R3
	MOVD	in+8(FP), R4
	BR	p256InternalEndianSwap<>(SB)

//func p256LittleToBig(res *[32]byte, in *p256Element)
TEXT ·p256LittleToBig(SB), NOSPLIT, $0-16
	MOVD	res+0(FP), R3
	MOVD	in+8(FP), R4
	BR	p256InternalEndianSwap<>(SB)

//func p256OrdBigToLittle(res *p256OrdElement, in *[32]byte)
TEXT ·p256OrdBigToLittle(SB), NOSPLIT, $0-16
	MOVD	res+0(FP), R3
	MOVD	in+8(FP), R4
	BR	p256InternalEndianSwap<>(SB)

//func p256OrdLittleToBig(res *[32]byte, in *p256OrdElement)
TEXT ·p256OrdLittleToBig(SB), NOSPLIT, $0-16
	MOVD	res+0(FP), R3
	MOVD	in+8(FP), R4
	BR	p256InternalEndianSwap<>(SB)

TEXT p256InternalEndianSwap<>(SB), NOSPLIT, $0-0
	// Index registers needed for BR movs
	MOVD	$8, R9
	MOVD	$16, R10
	MOVD	$24, R14

	MOVDBR	(R0)(R4), R5
	MOVDBR	(R9)(R4), R6
	MOVDBR	(R10)(R4), R7
	MOVDBR	(R14)(R4), R8

	MOVD	R8, 0(R3)
	MOVD	R7, 8(R3)
	MOVD	R6, 16(R3)
	MOVD	R5, 24(R3)

	RET

#define P3ptr   R3
#define P1ptr   R4
#define COUNT   R5

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

// func p256SelectAffine(res *p256AffinePoint, table *p256AffineTable, idx int)
TEXT ·p256SelectAffine(SB), NOSPLIT, $0-24
	MOVD res+0(FP), P3ptr
	MOVD table+8(FP), P1ptr
	MOVD $16, R16
	MOVD $32, R17
	MOVD $48, R18

	LXVDSX (R1)(R18), SEL1
	VSPLTB $7, SEL1, IDX    // splat byte

	VSPLTISB $1, ONE    // Vector with byte 1s
	VSPLTISB $1, SEL2   // Vector with byte 1s
	MOVD     $32, COUNT
	MOVD     COUNT, CTR // loop count

	VSPLTISB $0, X1H // VZERO  X1H
	VSPLTISB $0, X1L // VZERO  X1L
	VSPLTISB $0, Y1H // VZERO  Y1H
	VSPLTISB $0, Y1L // VZERO  Y1L

loop_select:
	LXVD2X (P1ptr+R0), X2H
	LXVD2X (P1ptr+R16), X2L
	LXVD2X (P1ptr+R17), Y2H
	LXVD2X (P1ptr+R18), Y2L

	VCMPEQUD SEL2, IDX, SEL1 // Compare against idx

	VSEL X1L, X2L, SEL1, X1L // Select if idx matched
	VSEL X1H, X2H, SEL1, X1H
	VSEL Y1L, Y2L, SEL1, Y1L
	VSEL Y1H, Y2H, SEL1, Y1H

	VADDUBM SEL2, ONE, SEL2    // Increment SEL2 bytes by 1
	ADD     $64, P1ptr         // Next chunk
	BDNZ	loop_select

	STXVD2X X1H, (P3ptr+R0)
	STXVD2X X1L, (P3ptr+R16)
	STXVD2X Y1H, (P3ptr+R17)
	STXVD2X Y1L, (P3ptr+R18)
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

#define res_ptr R3
#define x_ptr   R4
#define CPOOL   R7

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
#define PL    V13
#define PH    V14

// func p256FromMont(res, in *p256Element)
TEXT ·p256FromMont(SB), NOSPLIT, $0-16
	MOVD res+0(FP), res_ptr
	MOVD in+8(FP), x_ptr

	MOVD $16, R16
	MOVD $32, R17
	MOVD $p256<>+0x00(SB), CPOOL

	VSPLTISB $0, T2  // VZERO T2
	VSPLTISB $0, ZER // VZERO ZER

	// Constants are defined so that the LXVD2X is correct
	LXVD2X (CPOOL+R0), PH
	LXVD2X (CPOOL+R16), PL

	// VPERM byte selections
	LXVD2X (CPOOL+R17), SEL1

	LXVD2X (R16)(x_ptr), T1
	LXVD2X (R0)(x_ptr), T0

	// Put in true little endian order
	XXPERMDI T0, T0, $2, T0
	XXPERMDI T1, T1, $2, T1

	// First round
    VPERM ZER, T0, SEL1, RED1      // 0 0 d1 d0
    VSLDOI $4, RED1, ZER, TT0      // 0 d1 d0 0
	VSLDOI $4, TT0, ZER, RED2      // d1 d0 0 0
    VSUBCUQ  RED1, TT0, CAR1       // VSCBIQ  TT0, RED1, CAR1
	VSUBUQM  RED1, TT0, RED1       // VSQ	 TT0, RED1, RED1
	VSUBEUQM RED2, TT0, CAR1, RED2 // VSBIQ  RED2, TT0, CAR1, RED2 // Guaranteed not to underflow

	VSLDOI $8, T1, T0, T0 // VSLDB $8, T1, T0, T0
	VSLDOI $8, T2, T1, T1 // VSLDB $8, T2, T1, T1

	VADDCUQ  T0, RED1, CAR1       // VACCQ  T0, RED1, CAR1
	VADDUQM  T0, RED1, T0         // VAQ    T0, RED1, T0
	VADDECUQ T1, RED2, CAR1, CAR2 // VACCCQ T1, RED2, CAR1, CAR2
	VADDEUQM T1, RED2, CAR1, T1   // VACQ   T1, RED2, CAR1, T1
	VADDUQM  T2, CAR2, T2         // VAQ    T2, CAR2, T2

	// Second round
    VPERM ZER, T0, SEL1, RED1      // 0 0 d1 d0
    VSLDOI $4, RED1, ZER, TT0      // 0 d1 d0 0
	VSLDOI $4, TT0, ZER, RED2      // d1 d0 0 0
    VSUBCUQ  RED1, TT0, CAR1       // VSCBIQ  TT0, RED1, CAR1
	VSUBUQM  RED1, TT0, RED1       // VSQ	 TT0, RED1, RED1
	VSUBEUQM RED2, TT0, CAR1, RED2 // VSBIQ  RED2, TT0, CAR1, RED2 // Guaranteed not to underflow

	VSLDOI $8, T1, T0, T0 // VSLDB $8, T1, T0, T0
	VSLDOI $8, T2, T1, T1 // VSLDB $8, T2, T1, T1

	VADDCUQ  T0, RED1, CAR1       // VACCQ  T0, RED1, CAR1
	VADDUQM  T0, RED1, T0         // VAQ    T0, RED1, T0
	VADDECUQ T1, RED2, CAR1, CAR2 // VACCCQ T1, RED2, CAR1, CAR2
	VADDEUQM T1, RED2, CAR1, T1   // VACQ   T1, RED2, CAR1, T1
	VADDUQM  T2, CAR2, T2         // VAQ    T2, CAR2, T2

	// Third round
    VPERM ZER, T0, SEL1, RED1      // 0 0 d1 d0
    VSLDOI $4, RED1, ZER, TT0      // 0 d1 d0 0
	VSLDOI $4, TT0, ZER, RED2      // d1 d0 0 0
    VSUBCUQ  RED1, TT0, CAR1       // VSCBIQ  TT0, RED1, CAR1
	VSUBUQM  RED1, TT0, RED1       // VSQ	 TT0, RED1, RED1
	VSUBEUQM RED2, TT0, CAR1, RED2 // VSBIQ  RED2, TT0, CAR1, RED2 // Guaranteed not to underflow

	VSLDOI $8, T1, T0, T0 // VSLDB $8, T1, T0, T0
	VSLDOI $8, T2, T1, T1 // VSLDB $8, T2, T1, T1

	VADDCUQ  T0, RED1, CAR1       // VACCQ  T0, RED1, CAR1
	VADDUQM  T0, RED1, T0         // VAQ    T0, RED1, T0
	VADDECUQ T1, RED2, CAR1, CAR2 // VACCCQ T1, RED2, CAR1, CAR2
	VADDEUQM T1, RED2, CAR1, T1   // VACQ   T1, RED2, CAR1, T1
	VADDUQM  T2, CAR2, T2         // VAQ    T2, CAR2, T2

	// Last round
    VPERM ZER, T0, SEL1, RED1      // 0 0 d1 d0
    VSLDOI $4, RED1, ZER, TT0      // 0 d1 d0 0
	VSLDOI $4, TT0, ZER, RED2      // d1 d0 0 0
    VSUBCUQ  RED1, TT0, CAR1       // VSCBIQ  TT0, RED1, CAR1
	VSUBUQM  RED1, TT0, RED1       // VSQ	 TT0, RED1, RED1
	VSUBEUQM RED2, TT0, CAR1, RED2 // VSBIQ  RED2, TT0, CAR1, RED2 // Guaranteed not to underflow

	VSLDOI $8, T1, T0, T0 // VSLDB $8, T1, T0, T0
	VSLDOI $8, T2, T1, T1 // VSLDB $8, T2, T1, T1

	VADDCUQ  T0, RED1, CAR1       // VACCQ  T0, RED1, CAR1
	VADDUQM  T0, RED1, T0         // VAQ    T0, RED1, T0
	VADDECUQ T1, RED2, CAR1, CAR2 // VACCCQ T1, RED2, CAR1, CAR2
	VADDEUQM T1, RED2, CAR1, T1   // VACQ   T1, RED2, CAR1, T1
	VADDUQM  T2, CAR2, T2         // VAQ    T2, CAR2, T2

	// ---------------------------------------------------

	VSUBCUQ  T0, PL, CAR1       // VSCBIQ  PL, T0, CAR1
	VSUBUQM  T0, PL, TT0        // VSQ     PL, T0, TT0
	VSUBECUQ T1, PH, CAR1, CAR2 // VSBCBIQ T1, PH, CAR1, CAR2
	VSUBEUQM T1, PH, CAR1, TT1  // VSBIQ   T1, PH, CAR1, TT1
	VSUBEUQM T2, ZER, CAR2, T2  // VSBIQ   T2, ZER, CAR2, T2

	VSEL TT0, T0, T2, T0
	VSEL TT1, T1, T2, T1

	// Reorder the bytes so STXVD2X can be used.
	// TT0, TT1 used for VPERM result in case
	// the caller expects T0, T1 to be good.
	XXPERMDI T0, T0, $2, TT0
	XXPERMDI T1, T1, $2, TT1

	STXVD2X TT0, (R0)(res_ptr)
	STXVD2X TT1, (R16)(res_ptr)
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

//func p256OrdReduce(s *p256OrdElement)
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

TEXT ·p256OrdReduce(SB),NOSPLIT,$0
	MOVD res+0(FP), res_ptr
	MOVD $16, R16

	VSPLTISB $0, T2  // VZERO T2
	VSPLTISB $0, ZER // VZERO ZER

	MOVD  $p256ord<>+0x00(SB), CPOOL
	LXVD2X (CPOOL+R0), PH
	LXVD2X (CPOOL+R16), PL

	LXVD2X (R16)(res_ptr), T1
	LXVD2X (R0)(res_ptr), T0

	// Put in true little endian order
	XXPERMDI T0, T0, $2, T0
	XXPERMDI T1, T1, $2, T1

	VSUBCUQ  T0, PL, CAR1       // VSCBIQ  PL, T0, CAR1
	VSUBUQM  T0, PL, TT0        // VSQ     PL, T0, TT0
	VSUBECUQ T1, PH, CAR1, CAR2 // VSBCBIQ T1, PH, CAR1, CAR2
	VSUBEUQM T1, PH, CAR1, TT1  // VSBIQ   T1, PH, CAR1, TT1
	VSUBEUQM T2, ZER, CAR2, T2  // VSBIQ   T2, ZER, CAR2, T2

	VSEL TT0, T0, T2, T0
	VSEL TT1, T1, T2, T1

	// Reorder the bytes so STXVD2X can be used.
	// TT0, TT1 used for VPERM result in case
	// the caller expects T0, T1 to be good.
	XXPERMDI T0, T0, $2, TT0
	XXPERMDI T1, T1, $2, TT1

	STXVD2X TT0, (R0)(res_ptr)
	STXVD2X TT1, (R16)(res_ptr)

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
