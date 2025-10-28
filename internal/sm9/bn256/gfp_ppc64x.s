// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"

//func gfpUnmarshal(out *gfP, in *[32]byte)
TEXT ·gfpUnmarshal(SB), NOSPLIT, $0-16
	MOVD	res+0(FP), R3
	MOVD	in+8(FP), R4
	BR	gfpInternalEndianSwap<>(SB)

// func gfpMarshal(out *[32]byte, in *gfP)
TEXT ·gfpMarshal(SB), NOSPLIT, $0-16
	MOVD	res+0(FP), R3
	MOVD	in+8(FP), R4
	BR	gfpInternalEndianSwap<>(SB)

TEXT gfpInternalEndianSwap<>(SB), NOSPLIT, $0-0
	// Index registers needed for BR movs
#ifdef GOARCH_ppc64le	
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
#else
	MOVD	$16, R10
	LXVD2X (R4)(R0), V0
	LXVD2X (R4)(R10), V1

	XXPERMDI V0, V0, $2, V0
	XXPERMDI V1, V1, $2, V1

	STXVD2X V1, (R0+R3)
	STXVD2X V0, (R10+R3)	
#endif
	RET

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

TEXT ·gfpNeg(SB), NOSPLIT, $0-16
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

	VSPLTISB $0, X1L
	gfpSubInternal(T1, T0, X1L, X1L, Y1H, Y1L)

	XXPERMDI T1, T1, $2, T1
	XXPERMDI T0, T0, $2, T0

	STXVD2X T0, (R0+R3)
	STXVD2X T1, (R5+R3)
	RET

TEXT ·gfpSub(SB), NOSPLIT, $0-24
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

TEXT ·gfpAdd(SB), NOSPLIT, $0-24
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

TEXT ·gfpDouble(SB), NOSPLIT, $0-16
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

TEXT ·gfpTriple(SB), NOSPLIT, $0-16
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
	gfpAddInternal(T1, T0, T1, T0, X1H, X1L)

	XXPERMDI T1, T1, $2, T1
	XXPERMDI T0, T0, $2, T0

	STXVD2X T0, (R0+R3)
	STXVD2X T1, (R6+R3)
	RET

#undef X1L
#undef X1H
#undef Y1L
#undef Y1H
#undef T1L
#undef T1H
#undef T0
#undef T1
#undef T2
#undef SEL1
#undef ZERO
#undef CAR1
#undef CAR2
#undef TT0
#undef TT1
#undef PL
#undef PH

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
	VMULEUW  y, one, TMP1; \
	VMULOUW  y, one, TMP2; \
	VMULEUW  x1, x2, out_hi; \
	VMULOUW  x1, x2, out_low; \
	VADDUDM  TMP1, out_hi, TMP1; \
	VADDUDM  TMP2, out_low, TMP2; \
	VMRGEW   TMP1, TMP2, out_hi; \
	VMRGOW   TMP1, TMP2, out_low


// ---------------------------------------
// gfpMulInternal
#define X0    V0
#define X1    V1
#define Y0    V2
#define Y1    V3
#define M1    V4
#define M0    V5
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

// TMP1, TMP2 used in
// VMULT macros
#define TMP1  V13
#define TMP2  V27
#define ONE   V29 // 1s splatted by word

TEXT gfpMulInternal<>(SB), NOSPLIT, $0
	// ---------------------------------------------------------------------------/
	//	VREPF $3, Y0, YDIG
	VSPLTW $3, Y0, YDIG
	VSPLTISW $1, ONE

	//	VMLF  X0, YDIG, ADD1
	//	VMLF  X1, YDIG, ADD2
	//	VMLHF X0, YDIG, ADD1H
	//	VMLHF X1, YDIG, ADD2H
	VMULT(X0, YDIG, ADD1, ADD1H)
	VMULT(X1, YDIG, ADD2, ADD2H)

	//	VMLF  ADD1, K0, MK0
	//	VREPF $3, MK0, MK0
	VMULUWM ADD1, K0, MK0
	VSPLTW $3, MK0, MK0

	//	VMALF  M0, MK0, ADD1, RED1
	//	VMALHF M0, MK0, ADD1, RED1H
	//	VMALF  M1, MK0, ADD2, RED2
	//	VMALHF M1, MK0, ADD2, RED2H
	VMULT_ADD(M0, MK0, ADD1, ONE, RED1, RED1H)
	VMULT_ADD(M1, MK0, ADD2, ONE, RED2, RED2H)

	VSPLTISB $0, T2 // VZERO T2

	VSLDOI $12, RED2, RED1, RED1 // VSLDB
	VSLDOI $12, T2, RED2, RED2   // VSLDB

	VADDCUQ RED1, ADD1H, CAR1  // VACCQ
	VADDUQM RED1, ADD1H, T0    // VAQ
	VADDCUQ RED1H, T0, CAR1M   // VACCQ
	VADDUQM RED1H, T0, T0      // VAQ

	// << ready for next MK0

	VADDEUQM RED2, ADD2H, CAR1, T1   // VACQ
	VADDECUQ RED2, ADD2H, CAR1, CAR1 // VACCCQ
	VADDECUQ RED2H, T1, CAR1M, T2    // VACCCQ
	VADDEUQM RED2H, T1, CAR1M, T1    // VACQ
	VADDUQM  CAR1, T2, T2            // VAQ

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
	// VREPF $2, Y0, YDIG
	VSPLTW $2, Y0, YDIG

	//	VMALF X0, YDIG, T0, ADD1
	//	VMALF  X1, YDIG, T1, ADD2
	//	VMALHF X0, YDIG, T0, ADD1H
	//	VMALHF X1, YDIG, T1, ADD2H
	VMULT_ADD(X0, YDIG, T0, ONE, ADD1, ADD1H)
	VMULT_ADD(X1, YDIG, T1, ONE, ADD2, ADD2H)

	//	VMLF  ADD1, K0, MK0
	//	VREPF $3, MK0, MK0
	VMULUWM ADD1, K0, MK0
	VSPLTW $3, MK0, MK0

	//	VMALF  M0, MK0, ADD1, RED1
	//	VMALHF M0, MK0, ADD1, RED1H
	//	VMALF  M1, MK0, ADD2, RED2
	//	VMALHF M1, MK0, ADD2, RED2H
	VMULT_ADD(M0, MK0, ADD1, ONE, RED1, RED1H)
	VMULT_ADD(M1, MK0, ADD2, ONE, RED2, RED2H)

	VSLDOI $12, RED2, RED1, RED1 // VSLDB
	VSLDOI $12, T2, RED2, RED2   // VSLDB

	VADDCUQ RED1, ADD1H, CAR1 // VACCQ
	VADDUQM RED1, ADD1H, T0   // VAQ
	VADDCUQ RED1H, T0, CAR1M  // VACCQ
	VADDUQM RED1H, T0, T0     // VAQ

	// << ready for next MK0

	VADDEUQM RED2, ADD2H, CAR1, T1   // VACQ
	VADDECUQ RED2, ADD2H, CAR1, CAR1 // VACCCQ
	VADDECUQ RED2H, T1, CAR1M, T2    // VACCCQ
	VADDEUQM RED2H, T1, CAR1M, T1    // VACQ
	VADDUQM  CAR1, T2, T2            // VAQ

	// ---------------------------------------------------
	//	VREPF $1, Y0, YDIG
	VSPLTW $1, Y0, YDIG

	//	VMALF X0, YDIG, T0, ADD1
	//	VMALF  X1, YDIG, T1, ADD2
	//	VMALHF X0, YDIG, T0, ADD1H
	//	VMALHF X1, YDIG, T1, ADD2H
	VMULT_ADD(X0, YDIG, T0, ONE, ADD1, ADD1H)
	VMULT_ADD(X1, YDIG, T1, ONE, ADD2, ADD2H)

	//	VMLF  ADD1, K0, MK0
	//	VREPF $3, MK0, MK0
	VMULUWM ADD1, K0, MK0
	VSPLTW $3, MK0, MK0

	//	VMALF  M0, MK0, ADD1, RED1
	//	VMALHF M0, MK0, ADD1, RED1H
	//	VMALF  M1, MK0, ADD2, RED2
	//	VMALHF M1, MK0, ADD2, RED2H
	VMULT_ADD(M0, MK0, ADD1, ONE, RED1, RED1H)
	VMULT_ADD(M1, MK0, ADD2, ONE, RED2, RED2H)
	
	VSLDOI $12, RED2, RED1, RED1 // VSLDB
	VSLDOI $12, T2, RED2, RED2   // VSLDB

	VADDCUQ RED1, ADD1H, CAR1 // VACCQ
	VADDUQM RED1, ADD1H, T0 // VAQ
	VADDCUQ RED1H, T0, CAR1M  // VACCQ
	VADDUQM RED1H, T0, T0   // VAQ

	// << ready for next MK0

	VADDEUQM RED2, ADD2H, CAR1, T1   // VACQ
	VADDECUQ RED2, ADD2H, CAR1, CAR1 // VACCCQ
	VADDECUQ RED2H, T1, CAR1M, T2    // VACCCQ
	VADDEUQM RED2H, T1, CAR1M, T1    // VACQ
	VADDUQM  CAR1, T2, T2            // VAQ

	// ---------------------------------------------------
	//	VREPF $0, Y0, YDIG
	VSPLTW $0, Y0, YDIG

	//	VMALF X0, YDIG, T0, ADD1
	//	VMALF  X1, YDIG, T1, ADD2
	//	VMALHF X0, YDIG, T0, ADD1H
	//	VMALHF X1, YDIG, T1, ADD2H
	VMULT_ADD(X0, YDIG, T0, ONE, ADD1, ADD1H)
	VMULT_ADD(X1, YDIG, T1, ONE, ADD2, ADD2H)

	//	VMLF  ADD1, K0, MK0
	//	VREPF $3, MK0, MK0
	VMULUWM ADD1, K0, MK0
	VSPLTW $3, MK0, MK0

	//	VMALF  M0, MK0, ADD1, RED1
	//	VMALHF M0, MK0, ADD1, RED1H
	//	VMALF  M1, MK0, ADD2, RED2
	//	VMALHF M1, MK0, ADD2, RED2H
	VMULT_ADD(M0, MK0, ADD1, ONE, RED1, RED1H)
	VMULT_ADD(M1, MK0, ADD2, ONE, RED2, RED2H)

	VSLDOI $12, RED2, RED1, RED1
	VSLDOI $12, T2, RED2, RED2

	VADDCUQ RED1, ADD1H, CAR1 // VACCQ
	VADDUQM RED1, ADD1H, T0   // VAQ
	VADDCUQ RED1H, T0, CAR1M  // VACCQ
	VADDUQM RED1H, T0, T0     // VAQ

	// << ready for next MK0

	VADDEUQM RED2, ADD2H, CAR1, T1   // VACQ
	VADDECUQ RED2, ADD2H, CAR1, CAR1 // VACCCQ
	VADDECUQ RED2H, T1, CAR1M, T2    // VACCCQ
	VADDEUQM RED2H, T1, CAR1M, T1    // VACQ
	VADDUQM  CAR1, T2, T2            // VAQ

	// ---------------------------------------------------
	//	VREPF $3, Y1, YDIG
	VSPLTW $3, Y1, YDIG

	//	VMALF X0, YDIG, T0, ADD1
	//	VMALF  X1, YDIG, T1, ADD2
	//	VMALHF X0, YDIG, T0, ADD1H
	//	VMALHF X1, YDIG, T1, ADD2H
	VMULT_ADD(X0, YDIG, T0, ONE, ADD1, ADD1H)
	VMULT_ADD(X1, YDIG, T1, ONE, ADD2, ADD2H)

	//	VMLF  ADD1, K0, MK0
	//	VREPF $3, MK0, MK0
	VMULUWM ADD1, K0, MK0
	VSPLTW $3, MK0, MK0

	//	VMALF  M0, MK0, ADD1, RED1
	//	VMALHF M0, MK0, ADD1, RED1H
	//	VMALF  M1, MK0, ADD2, RED2
	//	VMALHF M1, MK0, ADD2, RED2H
	VMULT_ADD(M0, MK0, ADD1, ONE, RED1, RED1H)
	VMULT_ADD(M1, MK0, ADD2, ONE, RED2, RED2H)

	VSLDOI $12, RED2, RED1, RED1
	VSLDOI $12, T2, RED2, RED2

	VADDCUQ RED1, ADD1H, CAR1 // VACCQ
	VADDUQM RED1, ADD1H, T0   // VAQ
	VADDCUQ RED1H, T0, CAR1M  // VACCQ
	VADDUQM RED1H, T0, T0     // VAQ

	// << ready for next MK0

	VADDEUQM RED2, ADD2H, CAR1, T1   // VACQ
	VADDECUQ RED2, ADD2H, CAR1, CAR1 // VACCCQ
	VADDECUQ RED2H, T1, CAR1M, T2    // VACCCQ
	VADDEUQM RED2H, T1, CAR1M, T1    // VACQ
	VADDUQM  CAR1, T2, T2            // VAQ

	// ---------------------------------------------------
	//	VREPF $2, Y1, YDIG
	VSPLTW $2, Y1, YDIG

	//	VMALF X0, YDIG, T0, ADD1
	//	VMALF  X1, YDIG, T1, ADD2
	//	VMALHF X0, YDIG, T0, ADD1H
	//	VMALHF X1, YDIG, T1, ADD2H
	VMULT_ADD(X0, YDIG, T0, ONE, ADD1, ADD1H)
	VMULT_ADD(X1, YDIG, T1, ONE, ADD2, ADD2H)

	//	VMLF  ADD1, K0, MK0
	//	VREPF $3, MK0, MK0
	VMULUWM ADD1, K0, MK0
	VSPLTW $3, MK0, MK0

	//	VMALF  M0, MK0, ADD1, RED1
	//	VMALHF M0, MK0, ADD1, RED1H
	//	VMALF  M1, MK0, ADD2, RED2
	//	VMALHF M1, MK0, ADD2, RED2H
	VMULT_ADD(M0, MK0, ADD1, ONE, RED1, RED1H)
	VMULT_ADD(M1, MK0, ADD2, ONE, RED2, RED2H)

	VSLDOI $12, RED2, RED1, RED1
	VSLDOI $12, T2, RED2, RED2

	VADDCUQ RED1, ADD1H, CAR1 // VACCQ
	VADDUQM RED1, ADD1H, T0   // VAQ
	VADDCUQ RED1H, T0, CAR1M  // VACCQ
	VADDUQM RED1H, T0, T0     // VAQ

	// << ready for next MK0

	VADDEUQM RED2, ADD2H, CAR1, T1   // VACQ
	VADDECUQ RED2, ADD2H, CAR1, CAR1 // VACCCQ
	VADDECUQ RED2H, T1, CAR1M, T2    // VACCCQ
	VADDEUQM RED2H, T1, CAR1M, T1    // VACQ
	VADDUQM  CAR1, T2, T2            // VAQ

	// ---------------------------------------------------
	//	VREPF $1, Y1, YDIG
	VSPLTW $1, Y1, YDIG

	//	VMALF X0, YDIG, T0, ADD1
	//	VMALF  X1, YDIG, T1, ADD2
	//	VMALHF X0, YDIG, T0, ADD1H
	//	VMALHF X1, YDIG, T1, ADD2H
	VMULT_ADD(X0, YDIG, T0, ONE, ADD1, ADD1H)
	VMULT_ADD(X1, YDIG, T1, ONE, ADD2, ADD2H)

	//	VMLF  ADD1, K0, MK0
	//	VREPF $3, MK0, MK0
	VMULUWM ADD1, K0, MK0
	VSPLTW $3, MK0, MK0

	//	VMALF  M0, MK0, ADD1, RED1
	//	VMALHF M0, MK0, ADD1, RED1H
	//	VMALF  M1, MK0, ADD2, RED2
	//	VMALHF M1, MK0, ADD2, RED2H
	VMULT_ADD(M0, MK0, ADD1, ONE, RED1, RED1H)
	VMULT_ADD(M1, MK0, ADD2, ONE, RED2, RED2H)

	VSLDOI $12, RED2, RED1, RED1
	VSLDOI $12, T2, RED2, RED2

	VADDCUQ RED1, ADD1H, CAR1 // VACCQ
	VADDUQM RED1, ADD1H, T0   // VAQ
	VADDCUQ RED1H, T0, CAR1M  // VACCQ
	VADDUQM RED1H, T0, T0     // VAQ

	// << ready for next MK0

	VADDEUQM RED2, ADD2H, CAR1, T1   // VACQ
	VADDECUQ RED2, ADD2H, CAR1, CAR1 // VACCCQ
	VADDECUQ RED2H, T1, CAR1M, T2    // VACCCQ
	VADDEUQM RED2H, T1, CAR1M, T1    // VACQ
	VADDUQM  CAR1, T2, T2            // VAQ

	// ---------------------------------------------------
	//	VREPF $0, Y1, YDIG
	VSPLTW $0, Y1, YDIG
	
	//	VMALF X0, YDIG, T0, ADD1
	//	VMALF  X1, YDIG, T1, ADD2
	//	VMALHF X0, YDIG, T0, ADD1H
	//	VMALHF X1, YDIG, T1, ADD2H
	VMULT_ADD(X0, YDIG, T0, ONE, ADD1, ADD1H)
	VMULT_ADD(X1, YDIG, T1, ONE, ADD2, ADD2H)

	//	VMLF  ADD1, K0, MK0
	//	VREPF $3, MK0, MK0
	VMULUWM ADD1, K0, MK0
	VSPLTW $3, MK0, MK0

	//	VMALF  M0, MK0, ADD1, RED1
	//	VMALHF M0, MK0, ADD1, RED1H
	//	VMALF  M1, MK0, ADD2, RED2
	//	VMALHF M1, MK0, ADD2, RED2H
	VMULT_ADD(M0, MK0, ADD1, ONE, RED1, RED1H)
	VMULT_ADD(M1, MK0, ADD2, ONE, RED2, RED2H)

	VSLDOI $12, RED2, RED1, RED1
	VSLDOI $12, T2, RED2, RED2

	VADDCUQ RED1, ADD1H, CAR1 // VACCQ
	VADDUQM RED1, ADD1H, T0   // VAQ
	VADDCUQ RED1H, T0, CAR1M  // VACCQ
	VADDUQM RED1H, T0, T0     // VAQ

	// << ready for next MK0

	VADDEUQM RED2, ADD2H, CAR1, T1   // VACQ
	VADDECUQ RED2, ADD2H, CAR1, CAR1 // VACCCQ
	VADDECUQ RED2H, T1, CAR1M, T2    // VACCCQ
	VADDEUQM RED2H, T1, CAR1M, T1    // VACQ
	VADDUQM  CAR1, T2, T2            // VAQ

	// ---------------------------------------------------

	//	VZERO   RED1
	//	VSCBIQ  M0, T0, CAR1
	//	VSQ     M0, T0, ADD1
	//	VSBCBIQ T1, M1, CAR1, CAR1M
	//	VSBIQ   T1, M1, CAR1, ADD2
	//	VSBIQ   T2, RED1, CAR1M, T2
	VSPLTISB $0, RED1 // VZERO RED1
	VSUBCUQ  T0, M0, CAR1         // VSCBIQ
	VSUBUQM  T0, M0, ADD1         // VSQ
	VSUBECUQ T1, M1, CAR1, CAR1M  // VSBCBIQ
	VSUBEUQM T1, M1, CAR1, ADD2   // VSBIQ
	VSUBEUQM T2, RED1, CAR1M, T2  // VSBIQ

	// what output to use, ADD2||ADD1 or T1||T0?
	VSEL ADD1, T0, T2, T0
	VSEL ADD2, T1, T2, T1
	RET

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
#undef TMP1
#undef TMP2
#undef ONE

// func gfpMul(c, a, b *gfP)
#define res_ptr R3
#define x_ptr R4
#define y_ptr R5
#define CPOOL R7
#define N     R8

#define X0    V0
#define X1    V1
#define Y0    V2
#define Y1    V3
#define M0    V5
#define M1    V4
#define T0    V6
#define T1    V7
#define K0    V31

TEXT ·gfpMul(SB),NOSPLIT,$0
	MOVD	c+0(FP), res_ptr
	MOVD	a+8(FP), x_ptr
	MOVD	b+16(FP), y_ptr

	MOVD $16, R16

	LXVD2X (R0)(x_ptr), X0
	LXVD2X (R16)(x_ptr), X1

	XXPERMDI X0, X0, $2, X0
	XXPERMDI X1, X1, $2, X1

	LXVD2X (R0)(y_ptr), Y0
	LXVD2X (R16)(y_ptr), Y1

	XXPERMDI Y0, Y0, $2, Y0
	XXPERMDI Y1, Y1, $2, Y1

	MOVD $·p2+0(SB), CPOOL
	LXVD2X (CPOOL)(R0), M0
	LXVD2X (CPOOL)(R16), M1
	
	XXPERMDI M0, M0, $2, M0
	XXPERMDI M1, M1, $2, M1

	MOVD $·np+0(SB), CPOOL
	LXVD2X (CPOOL)(R0), K0
	VSPLTW $1, K0, K0

	CALL gfpMulInternal<>(SB)

	XXPERMDI T0, T0, $2, T0
	XXPERMDI T1, T1, $2, T1
	STXVD2X T0, (R0)(res_ptr)
	STXVD2X T1, (R16)(res_ptr)

	RET

// func gfpSqr(res, in *gfP, n int)
TEXT ·gfpSqr(SB),NOSPLIT,$0
	MOVD res+0(FP), res_ptr
	MOVD in+8(FP), x_ptr
	MOVD n+16(FP), N
	MOVD $16, R16

	LXVD2X (R0)(x_ptr), X0
	LXVD2X (R16)(x_ptr), X1

	XXPERMDI X0, X0, $2, X0
	XXPERMDI X1, X1, $2, X1

	MOVD $·p2+0(SB), CPOOL
	LXVD2X (CPOOL)(R0), M0
	LXVD2X (CPOOL)(R16), M1
	
	XXPERMDI M0, M0, $2, M0
	XXPERMDI M1, M1, $2, M1

	MOVD $·np+0(SB), CPOOL
	LXVD2X (CPOOL)(R0), K0
	VSPLTW $1, K0, K0

sqrLoop:
	// Sqr uses same value for both

	VOR	X0, X0, Y0
	VOR	X1, X1, Y1
	CALL gfpMulInternal<>(SB)

	ADD	$-1, N
	CMP	$0, N
	BEQ	done

	VOR	T0, T0, X0
	VOR	T1, T1, X1
	BR	sqrLoop

done:
	XXPERMDI T0, T0, $2, T0
	XXPERMDI T1, T1, $2, T1
	STXVD2X T0, (R0)(res_ptr)
	STXVD2X T1, (R16)(res_ptr)
	RET

#undef res_ptr
#undef x_ptr
#undef y_ptr
#undef CPOOL
#undef N
#undef X0
#undef X1
#undef Y0
#undef Y1
#undef M0
#undef M1
#undef T0
#undef T1
#undef K0

/* ---------------------------------------*/
#define res_ptr R3
#define x_ptr R4
#define CPOOL R7

#define M0    V5
#define M1    V4
#define T0    V6
#define T1    V7
#define T2    V8

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

// TMP1, TMP2 used in
// VMULT macros
#define TMP1  V13
#define TMP2  V27
#define ONE   V29 // 1s splatted by word
// func gfpFromMont(res, in *gfP)
TEXT ·gfpFromMont(SB),NOSPLIT,$0
	MOVD res+0(FP), res_ptr
	MOVD in+8(FP), x_ptr

	MOVD $16, R16

	LXVD2X (R0)(x_ptr), T0
	LXVD2X (R16)(x_ptr), T1

	XXPERMDI T0, T0, $2, T0
	XXPERMDI T1, T1, $2, T1

	MOVD $·p2+0(SB), CPOOL
	LXVD2X (CPOOL)(R0), M0
	LXVD2X (CPOOL)(R16), M1
	
	XXPERMDI M0, M0, $2, M0
	XXPERMDI M1, M1, $2, M1

	MOVD $·np+0(SB), CPOOL
	LXVD2X (CPOOL)(R0), K0
	VSPLTW $1, K0, K0

	// ---------------------------------------------------------------------------/
	VSPLTISW $1, ONE
	VSPLTISB $0, T2 // VZERO T2

	MOVD $8, R5
	MOVD R5, CTR

loop:
	VMULUWM T0, K0, MK0
	VSPLTW $3, MK0, MK0

	VMULT_ADD(M0, MK0, T0, ONE, RED1, RED1H)
	VMULT_ADD(M1, MK0, T1, ONE, RED2, RED2H)

	VSLDOI $12, RED2, RED1, RED1 // VSLDB
	VSLDOI $12, T2, RED2, RED2   // VSLDB

	VADDCUQ RED1H, RED1, CAR1M   // VACCQ
	VADDUQM RED1H, RED1, T0      // VAQ

	// << ready for next MK0

	VADDECUQ RED2H, RED2, CAR1M, T2    // VACCCQ
	VADDEUQM RED2H, RED2, CAR1M, T1    // VACQ

	BDNZ loop
	// ---------------------------------------------------
	VSPLTISB $0, RED1 // VZERO RED1
	VSUBCUQ  T0, M0, CAR1         // VSCBIQ
	VSUBUQM  T0, M0, ADD1         // VSQ
	VSUBECUQ T1, M1, CAR1, CAR1M  // VSBCBIQ
	VSUBEUQM T1, M1, CAR1, ADD2   // VSBIQ
	VSUBEUQM T2, RED1, CAR1M, T2  // VSBIQ

	// what output to use, ADD2||ADD1 or T1||T0?
	VSEL ADD1, T0, T2, T0
	VSEL ADD2, T1, T2, T1

	XXPERMDI T0, T0, $2, T0
	XXPERMDI T1, T1, $2, T1
	STXVD2X T0, (R0)(res_ptr)
	STXVD2X T1, (R16)(res_ptr)	
	RET
