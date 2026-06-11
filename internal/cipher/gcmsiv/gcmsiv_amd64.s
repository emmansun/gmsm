// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// POLYVAL authentication for GCM-SIV using PCLMULQDQ (Carry-less Multiply).
//
// The implementation follows the same Karatsuba strategy as gcmSm4Data in
// internal/sm4/gcm_amd64.s; the only structural differences are:
//
//   polyvalTableInitAsm   – H is provided directly (no block-cipher key schedule);
//                        a PSHUFB converts from little-endian POLYVAL form to
//                        the GHASH-internal representation used for multiply.
//
//   polyvalBlocksUpdateAsm – identical Karatsuba single-block loop; PSHUFB on
//                         each input block converts it from POLYVAL LE byte
//                         order to GHASH-internal form.  The accumulator y is
//                         loaded at entry and stored back at exit so the
//                         function can be called repeatedly for AAD, plaintext,
//                         and the length block.
//
//go:build !purego

#include "textflag.h"

// 16-byte BSWAP shuffle mask: reverses bytes 0-15 of an XMM register.
DATA ·bswap_mask+0x00(SB)/8, $0x08090a0b0c0d0e0f
DATA ·bswap_mask+0x08(SB)/8, $0x0001020304050607
GLOBL ·bswap_mask(SB), RODATA, $16

// GCM/POLYVAL reduction polynomial constant:
//   low  qword = 0x0000000000000001
//   high qword = 0xc200000000000000
DATA gcmSIVPoly<>+0x00(SB)/8, $0x0000000000000001
DATA gcmSIVPoly<>+0x08(SB)/8, $0xc200000000000000
GLOBL gcmSIVPoly<>(SB), (NOPTR|RODATA), $16

DATA gcmPoly<>+0x00(SB)/8, $0x0000000000000000
DATA gcmPoly<>+0x08(SB)/8, $0xe100000000000000
GLOBL gcmPoly<>(SB), (NOPTR|RODATA), $16

// Register aliases matching gcm_amd64.s conventions.
#define B0 X0
#define B1 X1
#define B2 X2
#define B3 X3
#define B4 X4
#define B5 X5
#define B6 X6
#define B7 X7

#define ACC0 X8
#define ACC1 X9
#define ACCM X10

#define T0   X11
#define T1   X12
#define T2   X13
#define POLY X14
#define BSWAP X15

// reduceRound performs one step of the two-round Montgomery-like reduction
// used by the standard GCM/POLYVAL fast-reduction algorithm.
//
//   PCLMULQDQ $0x01, a, T0  →  T0 = a_high64 × POLY_low64
//   PSHUFD $78, a, a        →  swap high/low 64-bit halves of a
//   PXOR T0, a              →  a ^= T0
//
// After two applications the 256-bit product in [ACC1, ACC0] is reduced to a
// 128-bit result in ACC0.
#define reduceRound(a) \
	MOVOU POLY, T0        \
	PCLMULQDQ $0x01, a, T0 \
	PSHUFD $78, a, a      \
	PXOR T0, a

// ── polyvalTableInitAsm ──────────────────────────────────────────────────────────
//
// func polyvalTableInitAsm(h *[16]byte, table *polyvalAsmTable)
//
// Builds the 256-byte Karatsuba product table for POLYVAL.
// h is the 16-byte authentication key in POLYVAL little-endian byte order.
//
// The table layout is identical to gcmSm4Data's productTable:
//   table[14*16 .. 15*16+15]: H^1 and Karatsuba precomp H[0]^H[1]
//   table[12*16 .. 13*16+15]: H^2 and Karatsuba precomp
//   ...
//   table[ 0*16 ..  1*16+15]: H^8 and Karatsuba precomp
//
// Requires: PCLMULQDQ, SSE2, SSSE3
TEXT ·polyvalTableInitAsm(SB), NOSPLIT, $0-16
#define hPtr DI
#define dst  SI

	MOVQ h+0(FP), hPtr
	MOVQ table+8(FP), dst

	MOVOU gcmPoly<>(SB), POLY

	MOVOU (hPtr), B0

    // POLYVAL special handling
    MOVOU B0, T0
 	PSHUFD $0, B0, T1
	PSRLQ $1, B0
	PSLLQ $63, T0
	PSRLDQ $8, T0
	POR T0, B0
	PSLLL $31, T1
	PSRAL $31, T1
	PAND POLY, T1
	PXOR T1, B0

    // change to a reversed poly for below calculations
    MOVOU gcmSIVPoly<>(SB), POLY

	// H * 2
	PSHUFD $0xff, B0, T0
	MOVOU B0, T1
	PSRAL $31, T0
	PAND POLY, T0
	PSRLL $31, T1
	PSLLDQ $4, T1
	PSLLL $1, B0
	PXOR T0, B0
	PXOR T1, B0
	// Karatsuba pre-computations
	MOVOU B0, (16*14)(dst)
	PSHUFD $78, B0, B1
	PXOR B0, B1
	MOVOU B1, (16*15)(dst)

	MOVOU B0, B2
	MOVOU B1, B3
	// Now prepare powers of H and pre-computations for them
	MOVQ $7, AX

initLoop:
		// B0 * B2, Karatsuba Approach
		MOVOU B2, T0
		MOVOU B2, T1
		MOVOU B3, T2
		PCLMULQDQ $0x00, B0, T0 // B0[0] * B2[0]
		PCLMULQDQ $0x11, B0, T1 // B0[1] * B2[1]
		PCLMULQDQ $0x00, B1, T2 // (B0[0] + B0[1]) * (B2[0] + B2[1])

		PXOR T0, T2             // (B0[0] + B0[1]) * (B2[0] + B2[1]) - B0[0] * B2[0]
		PXOR T1, T2             // B0[0] * B2[1] + B0[1] * B2[0]
		MOVOU T2, B4
		PSLLDQ $8, B4
		PSRLDQ $8, T2
		PXOR B4, T0
		PXOR T2, T1             // [T1, T0] = B0 * B2

		// Fast reduction
		// 1st reduction
		MOVOU POLY, B2
		PCLMULQDQ $0x01, T0, B2 // B2 = T0[0] * POLY[1]
		PSHUFD $78, T0, T0
		PXOR B2, T0
		// 2nd reduction
		MOVOU POLY, B2
		PCLMULQDQ $0x01, T0, B2
		PSHUFD $78, T0, T0
		PXOR T0, B2
		PXOR T1, B2

		MOVOU B2, (16*12)(dst)
		PSHUFD $78, B2, B3
		PXOR B2, B3
		MOVOU B3, (16*13)(dst)

		DECQ AX
		LEAQ (-16*2)(dst), dst
	JNE initLoop

	RET
#undef hPtr
#undef dst

// ── polyvalBlocksUpdateAsm ───────────────────────────────────────────────────────
//
// func polyvalBlocksUpdateAsm(table *polyvalAsmTable, y *[16]byte, blocks []byte)
//
// Processes each 16-byte block of blocks, updating the accumulator y in-place.
// blocks must have length that is a multiple of 16.
//
// The loop is a direct copy of the dataSinglesLoop in gcmSm4Data, with the
// single change that ACC0 is initialised from y (not zeroed) so the function
// can be called incrementally for AAD, plaintext, and length-block.
//
// Requires: PCLMULQDQ, SSE2, SSSE3
TEXT ·polyvalBlocksUpdateAsm(SB), NOSPLIT, $0-40
#define pTbl   DI
#define yPtr   SI
#define aut    CX
#define autLen DX

#define mulRoundAAD(X ,i) \
	MOVOU (16*(i*2))(pTbl), T1;\
	MOVOU T1, T2;\
	PCLMULQDQ $0x00, X, T1;\
	PXOR T1, ACC0;\
	PCLMULQDQ $0x11, X, T2;\
	PXOR T2, ACC1;\
	PSHUFD $78, X, T1;\
	PXOR T1, X;\
	MOVOU (16*(i*2+1))(pTbl), T1;\
	PCLMULQDQ $0x00, X, T1;\
	PXOR T1, ACCM

	MOVQ table+0(FP), pTbl
	MOVQ y+8(FP), yPtr
	MOVQ blocks_base+16(FP), aut
	MOVQ blocks_len+24(FP), autLen

	MOVOU gcmSIVPoly<>(SB), POLY
	MOVOU (yPtr), ACC0        // load current accumulator (differs from gcmSm4Data)

	TESTQ autLen, autLen
	JEQ   polyvalUpdateDone

dataOctaLoop:
		CMPQ autLen, $128
		JB startSinglesLoop
		SUBQ $128, autLen

		MOVOU (16*0)(aut), X0
		MOVOU (16*1)(aut), X1
		MOVOU (16*2)(aut), X2
		MOVOU (16*3)(aut), X3
		MOVOU (16*4)(aut), X4
		MOVOU (16*5)(aut), X5
		MOVOU (16*6)(aut), X6
		MOVOU (16*7)(aut), X7
		LEAQ (16*8)(aut), aut
		PXOR ACC0, X0

		MOVOU (16*0)(pTbl), ACC0
		MOVOU (16*1)(pTbl), ACCM
		MOVOU ACC0, ACC1
		PSHUFD $78, X0, T1
		PXOR X0, T1
		PCLMULQDQ $0x00, X0, ACC0
		PCLMULQDQ $0x11, X0, ACC1
		PCLMULQDQ $0x00, T1, ACCM

		mulRoundAAD(X1, 1)
		mulRoundAAD(X2, 2)
		mulRoundAAD(X3, 3)
		mulRoundAAD(X4, 4)
		mulRoundAAD(X5, 5)
		mulRoundAAD(X6, 6)
		mulRoundAAD(X7, 7)

		PXOR ACC0, ACCM
		PXOR ACC1, ACCM
		MOVOU ACCM, T0
		PSRLDQ $8, ACCM
		PSLLDQ $8, T0
		PXOR ACCM, ACC1
		PXOR T0, ACC0
		reduceRound(ACC0)
		reduceRound(ACC0)
		PXOR ACC1, ACC0
	JMP dataOctaLoop

startSinglesLoop:    
	// Preload H and its Karatsuba precomp — same as startSinglesLoop.
	MOVOU (16*14)(pTbl), T1
	MOVOU (16*15)(pTbl), T2

polyvalUpdateLoop:
	    CMPQ  autLen, $16
	    JB    polyvalUpdateDone
	    SUBQ  $16, autLen

	    MOVOU (aut), B0
dataMul:    
	    // Block is pre-reversed by the Go caller (byteReverse16), so PSHUFB BSWAP
	    // applies a second reversal, making the XMM representation match exactly what
	    // gcmSm4Data expects: XMM[63:0]=field.high, XMM[127:64]=field.low in LE.
	    // PSHUFB BSWAP, B0
	    PXOR   ACC0, B0           // XOR with running accumulator

	    // Reload H into ACC0/ACC1/ACCM (same as dataSinglesLoop dataMul label).
	    MOVOU T1, ACC0
	    MOVOU T2, ACCM
	    MOVOU T1, ACC1

	    // Karatsuba multiply: B0 × H
	    PSHUFD    $78, B0, T0
	    PXOR      B0, T0
	    PCLMULQDQ $0x00, B0, ACC0
	    PCLMULQDQ $0x11, B0, ACC1
	    PCLMULQDQ $0x00, T0, ACCM

	    // Combine: compute cross product and split into halves.
	    PXOR   ACC0, ACCM
	    PXOR   ACC1, ACCM
	    MOVOU  ACCM, T0
	    PSRLDQ $8, ACCM
	    PSLLDQ $8, T0
	    PXOR   ACCM, ACC1
	    PXOR   T0, ACC0

	    // Two-round reduction.
	    reduceRound(ACC0)
	    reduceRound(ACC0)
	    PXOR ACC1, ACC0           // ACC0 = updated hash state

	    LEAQ 16(aut), aut
	JMP  polyvalUpdateLoop

polyvalUpdateDone:
	MOVOU ACC0, (yPtr)        // store accumulator back to y
	RET

#undef pTbl
#undef yPtr
#undef aut
#undef autLen
