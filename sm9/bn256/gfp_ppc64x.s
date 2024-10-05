// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"

#define X1L   V0
#define X1H   V1
#define Y1L   V2
#define Y1H   V3
#define T1L   V4
#define T1H   V5
#define T0    V4
#define T1    V5
#define T2    V6
#define SEL1  V7
#define ZERO  V8
#define CAR1  V9
#define CAR2  V10
#define TT0   V11
#define TT1   V12

#define PL    V30
#define PH    V31

TEXT ·gfpNegAsm(SB),0,$0-16
	MOVD c+0(FP), R3
	MOVD a+8(FP), R4

	MOVD $16, R5
	LXVD2X (R4)(R0), Y1L
	LXVD2X (R4)(R5), Y1H

	XXPERMDI Y1H, Y1H, $2, Y1H
	XXPERMDI Y1L, Y1L, $2, Y1L

	MOVD $·p2+0(SB), R6
	LXVD2X (R6)(R0), PL
	LXVD2X (R6)(R5), PH

	XXPERMDI PH, PH, $2, PH
	XXPERMDI PL, PL, $2, PL

	VSUBCUQ  PL, Y1L, CAR1      // subtract part2 giving carry
	VSUBUQM  PL, Y1L, T1L       // subtract part2 giving result
	VSUBEUQM PH, Y1H, CAR1, T1H // subtract part1 using carry from part2

	VSUBCUQ Y1L, PL, CAR1
	VSUBUQM Y1L, PL, TT0
	VSUBECUQ Y1H, PH, CAR1, SEL1
	VSUBEUQM Y1H, PH, CAR1, TT1

	VSEL T1H, TT1, SEL1, Y1H
	VSEL T1L, TT0, SEL1, Y1L

	XXPERMDI Y1H, Y1H, $2, Y1H
	XXPERMDI Y1L, Y1L, $2, Y1L

	STXVD2X Y1L, (R0+R3)
	STXVD2X Y1H, (R5+R3)
	RET


#define gfpSubInternal(T1, T0, X1, X0, Y1, Y0) \
	VSPLTISB $0, ZERO           \ // VZERO
	VSUBCUQ  X0, Y0, CAR1       \
	VSUBUQM  X0, Y0, T0         \
	VSUBECUQ X1, Y1, CAR1, SEL1 \
	VSUBEUQM X1, Y1, CAR1, T1   \
	VSUBUQM  ZERO, SEL1, SEL1   \ // VSQ
	                            \
	VADDCUQ  T0, PL, CAR1       \ // VACCQ
	VADDUQM  T0, PL, TT0        \ // VAQ
	VADDEUQM T1, PH, CAR1, TT1  \ // VACQ
	                            \
	VSEL     TT0, T0, SEL1, T0  \
	VSEL     TT1, T1, SEL1, T1  \

TEXT ·gfpSubAsm(SB),0,$0-24
	MOVD c+0(FP), R3
	MOVD a+8(FP), R4
	MOVD b+16(FP), R5

	MOVD $16, R6
	LXVD2X (R4)(R0), X1L
	LXVD2X (R4)(R6), X1H
	XXPERMDI X1H, X1H, $2, X1H
	XXPERMDI X1L, X1L, $2, X1L

	LXVD2X (R5)(R0), Y1L
	LXVD2X (R5)(R6), Y1H
	XXPERMDI Y1H, Y1H, $2, Y1H
	XXPERMDI Y1L, Y1L, $2, Y1L

	MOVD $·p2+0(SB), R7
	LXVD2X (R7)(R0), PL
	LXVD2X (R7)(R6), PH
	XXPERMDI PH, PH, $2, PH
	XXPERMDI PL, PL, $2, PL

	gfpSubInternal(T1, T0, X1H, X1L, Y1H, Y1L)

	XXPERMDI T1, T1, $2, T1
	XXPERMDI T0, T0, $2, T0

	STXVD2X T0, (R0+R3)
	STXVD2X T1, (R6+R3)
	RET

#define gfpAddInternal(T1, T0, X1, X0, Y1, Y0) \
	VADDCUQ  X0, Y0, CAR1         \
	VADDUQM  X0, Y0, T0           \
	VADDECUQ X1, Y1, CAR1, T2     \ // VACCCQ
	VADDEUQM X1, Y1, CAR1, T1     \
	                              \
	VSUBCUQ  T0, PL, CAR1         \ // VSCBIQ
	VSUBUQM  T0, PL, TT0          \
	VSUBECUQ T1, PH, CAR1, CAR2   \ // VSBCBIQ
	VSUBEUQM T1, PH, CAR1, TT1    \ // VSBIQ
	VSUBEUQM T2, ZERO, CAR2, SEL1 \
	                              \
	VSEL     TT0, T0, SEL1, T0    \
	VSEL     TT1, T1, SEL1, T1

TEXT ·gfpAddAsm(SB),0,$0-24
	MOVD c+0(FP), R3
	MOVD a+8(FP), R4
	MOVD b+16(FP), R5

	MOVD $16, R6
	LXVD2X (R4)(R0), X1L
	LXVD2X (R4)(R6), X1H
	XXPERMDI X1H, X1H, $2, X1H
	XXPERMDI X1L, X1L, $2, X1L

	LXVD2X (R5)(R0), Y1L
	LXVD2X (R5)(R6), Y1H
	XXPERMDI Y1H, Y1H, $2, Y1H
	XXPERMDI Y1L, Y1L, $2, Y1L

	MOVD $·p2+0(SB), R7
	LXVD2X (R7)(R0), PL
	LXVD2X (R7)(R6), PH
	XXPERMDI PH, PH, $2, PH
	XXPERMDI PL, PL, $2, PL

	VSPLTISB $0, ZERO

	gfpAddInternal(T1, T0, X1H, X1L, Y1H, Y1L)

	XXPERMDI T1, T1, $2, T1
	XXPERMDI T0, T0, $2, T0

	STXVD2X T0, (R0+R3)
	STXVD2X T1, (R6+R3)
	RET

TEXT ·gfpDoubleAsm(SB),0,$0-16
	MOVD c+0(FP), R3
	MOVD a+8(FP), R4

	MOVD $16, R6
	LXVD2X (R4)(R0), X1L
	LXVD2X (R4)(R6), X1H
	XXPERMDI X1H, X1H, $2, X1H
	XXPERMDI X1L, X1L, $2, X1L

	MOVD $·p2+0(SB), R7
	LXVD2X (R7)(R0), PL
	LXVD2X (R7)(R6), PH
	XXPERMDI PH, PH, $2, PH
	XXPERMDI PL, PL, $2, PL

	VSPLTISB $0, ZERO

	gfpAddInternal(T1, T0, X1H, X1L, X1H, X1L)

	XXPERMDI T1, T1, $2, T1
	XXPERMDI T0, T0, $2, T0

	STXVD2X T0, (R0+R3)
	STXVD2X T1, (R6+R3)
	RET

TEXT ·gfpTripleAsm(SB),0,$0-16
	MOVD c+0(FP), R3
	MOVD a+8(FP), R4

	MOVD $16, R6
	LXVD2X (R4)(R0), X1L
	LXVD2X (R4)(R6), X1H
	XXPERMDI X1H, X1H, $2, X1H
	XXPERMDI X1L, X1L, $2, X1L

	MOVD $·p2+0(SB), R7
	LXVD2X (R7)(R0), PL
	LXVD2X (R7)(R6), PH
	XXPERMDI PH, PH, $2, PH
	XXPERMDI PL, PL, $2, PL

	VSPLTISB $0, ZERO

	gfpAddInternal(T1, T0, X1H, X1L, X1H, X1L)

	VOR T1, T1, X1H
	VOR T0, T0, X1L
	gfpAddInternal(T1, T0, X1H, X1L, X1H, X1L)

	XXPERMDI T1, T1, $2, T1
	XXPERMDI T0, T0, $2, T0

	STXVD2X T0, (R0+R3)
	STXVD2X T1, (R6+R3)
	RET
