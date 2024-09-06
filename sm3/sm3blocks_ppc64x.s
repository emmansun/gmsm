// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"
#include "sm3_const_asm.s"

#define a V0
#define e V1
#define b V2
#define f V3
#define c V4
#define g V5
#define d V6
#define h V7
#define M0 V8
#define M1 V9
#define M2 V10
#define M3 V11
#define TMP0 V12
#define TMP1 V13
#define TMP2 V14
#define TMP3 V15
#define TMP4 V16
#define TMP5 V17

// For instruction emulation
#define ESPERMW  V31 // Endian swapping permute into BE

DATA ·mask+0x00(SB)/8, $0x0b0a09080f0e0d0c // byte swap per word
DATA ·mask+0x08(SB)/8, $0x0302010007060504
DATA ·mask+0x10(SB)/8, $0x0001020310111213 // Permute for transpose matrix
DATA ·mask+0x18(SB)/8, $0x0405060714151617
DATA ·mask+0x20(SB)/8, $0x08090a0b18191a1b
DATA ·mask+0x28(SB)/8, $0x0c0d0e0f1c1d1e1f
DATA ·mask+0x30(SB)/8, $0x0001020304050607
DATA ·mask+0x38(SB)/8, $0x1011121314151617
DATA ·mask+0x40(SB)/8, $0x08090a0b0c0d0e0f
DATA ·mask+0x48(SB)/8, $0x18191a1b1c1d1e1f

GLOBL ·mask(SB), RODATA, $80

#ifdef GOARCH_ppc64le
#define NEEDS_PERMW

#define PPC64X_STXVD2X(VS,RA,RB) \
	VPERM	VS, VS, ESPERMW, TMP5 \ // byte swap per word
	STXVD2X	TMP5, (RA+RB)

#define PPC64X_LXVW4X(RA,RB,VT) \
	LXVW4X	(RA+RB), VT \
	VPERM	VT, VT, ESPERMW, VT

#else
#define PPC64X_STXVD2X(VS,RA,RB) STXVD2X	VS, (RA+RB)	
#define PPC64X_LXVW4X(RA,RB,VT)  LXVW4X	(RA+RB), VT
#endif // defined(GOARCH_ppc64le)

// r = s <<< n
#define PROLD(s, r, n) \
	VSPLTISW $n, TMP5 \
	VRLW	s, TMP5, r

#define loadWordByIndex(W, i) \
	MOVD $(16*(i)), R19 \
	LXVW4X (R19)(statePtr), W

// one word is 16 bytes
#define prepare4Words \
	PPC64X_LXVW4X(srcPtr1, srcPtrPtr, V16); \
	PPC64X_LXVW4X(srcPtr2, srcPtrPtr, V17); \
	PPC64X_LXVW4X(srcPtr3, srcPtrPtr, V18); \
	PPC64X_LXVW4X(srcPtr4, srcPtrPtr, V19); \
	TRANSPOSE_MATRIX(V16, V17, V18, V19); \
	ADD $16, srcPtrPtr; \
	STXVW4X V16, (wordPtr); \
	ADD $16, wordPtr; \
	STXVW4X V17, (wordPtr); \
	ADD $16, wordPtr; \
	STXVW4X V18, (wordPtr); \
	ADD $16, wordPtr; \
	STXVW4X V19, (wordPtr); \
	ADD $16, wordPtr

#define TRANSPOSE_MATRIX(T0, T1, T2, T3) \
	VPERM T0, T1, M0, TMP0; \
	VPERM T2, T3, M0, TMP1; \
	VPERM T0, T1, M1, TMP2; \
	VPERM T2, T3, M1, TMP3; \
	VPERM TMP0, TMP1, M2, T0; \
	VPERM TMP0, TMP1, M3, T1; \
	VPERM TMP2, TMP3, M2, T2; \
	VPERM TMP2, TMP3, M3, T3

// Load constant T, How to simlify it?
// Solution 1: big constant table
// Solution 2: 2 constant T, rotate shift left one bit every time
// Which solution's performance is better?
#define LOAD_T(index, const, target) \
	MOVD $const, R19                 \
	MTVSRWZ R19, target                \
	VSPLTW $1, target, target

#define ROUND_00_11(index, const, a, b, c, d, e, f, g, h) \
	PROLD(a, TMP0, 12)               \
	VOR TMP0, TMP0, TMP1             \
	LOAD_T(index, const, TMP2)       \
	VADDUWM TMP2, TMP0, TMP0         \
	VADDUWM e, TMP0, TMP0            \
	PROLD(TMP0, TMP2, 7)             \ // TMP2 = SS1
	VXOR TMP2, TMP1, TMP0            \ // TMP0 = SS2
	VXOR a, b, TMP1                  \
	VXOR c, TMP1, TMP1               \
	VADDUWM TMP1, d, TMP1            \ // TMP1 = (a XOR b XOR c) + d
	loadWordByIndex(TMP3, index)     \
	loadWordByIndex(TMP4, index+4)   \
	VXOR TMP3, TMP4, TMP4            \
	VADDUWM TMP4, TMP1, TMP1         \ // TMP1 = (a XOR b XOR c) + d + (Wt XOR Wt+4)
	VADDUWM TMP1, TMP0, TMP1         \ // TMP1 = TT1
	VADDUWM h, TMP3, TMP3            \
	VADDUWM TMP3, TMP2, TMP3         \ // Wt + h + SS1
	VXOR e, f, TMP4                  \
	VXOR g, TMP4, TMP4               \
	VADDUWM TMP4, TMP3, TMP3         \ // TT2 = (e XOR f XOR g) + Wt + h + SS1
	VOR b, b, TMP4                   \
	PROLD(TMP4, b, 9)                \ // b = b <<< 9
	VOR TMP1, TMP1, h                \ // h = TT1
	PROLD(f, TMP4, 10)               \
	PROLD(TMP4, f, 9)                \ // f = f <<< 19
	PROLD(TMP3, TMP4, 9)             \ // TMP4 = TT2 <<< 9
	PROLD(TMP4, TMP0, 8)             \ // TMP0 = TT2 <<< 17
	VXOR TMP3, TMP4, TMP4            \ // TMP4 = TT2 XOR (TT2 <<< 9)
	VXOR TMP4, TMP0, d               \ // d = TT2 XOR (TT2 <<< 9) XOR (TT2 <<< 17)

#define MESSAGE_SCHEDULE(index) \
	loadWordByIndex(TMP0, index+1)    \ // Wj-3
	PROLD(TMP0, TMP1, 15)             \
	loadWordByIndex(TMP0, index-12)   \ // Wj-16
	VXOR TMP0, TMP1, TMP0             \
	loadWordByIndex(TMP1, index-5)    \ // Wj-9
	VXOR TMP0, TMP1, TMP0             \
	PROLD(TMP0, TMP1, 15)             \
	PROLD(TMP1, TMP2, 8)              \
	VXOR TMP1, TMP0, TMP0             \
	VXOR TMP2, TMP0, TMP0             \ // P1
	loadWordByIndex(TMP1, index-9)    \ // Wj-13
	PROLD(TMP1, TMP2, 7)              \
	VXOR TMP2, TMP0, TMP0             \
	loadWordByIndex(TMP1, index-2)    \ // Wj-6
	VXOR TMP1, TMP0, TMP1             \
	STXVW4X TMP1, (wordPtr)           \
	ADD $16, wordPtr                  \

#define ROUND_12_15(index, const, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index)                               \
	ROUND_00_11(index, const, a, b, c, d, e, f, g, h)

#define ROUND_16_63(index, const, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index)          \ // TMP1 is Wt+4 now, Pls do not use it
	PROLD(a, TMP0, 12)               \
	VOR TMP0, TMP0, TMP4             \
	LOAD_T(index, const, TMP2)       \
	VADDUWM TMP2, TMP0, TMP0         \
	VADDUWM e, TMP0, TMP0            \
	PROLD(TMP0, TMP2, 7)             \ // TMP2 = SS1
	VXOR TMP2, TMP4, TMP0            \ // TMP0 = SS2
	VOR a, b, TMP3                   \
	VAND a, b, TMP4                  \
	VAND c, TMP3, TMP3               \
	VOR TMP4, TMP3, TMP4             \ // (a AND b) OR (a AND c) OR (b AND c)
	VADDUWM TMP4, d, TMP4            \ // (a AND b) OR (a AND c) OR (b AND c) + d
	loadWordByIndex(TMP3, index)     \ // Wj
	VXOR TMP3, TMP1, TMP1            \ // Wj XOR Wj+4
	VADDUWM TMP4, TMP1, TMP4         \ // (a AND b) OR (a AND c) OR (b AND c) + d + (Wt XOR Wt+4)
	VADDUWM TMP4, TMP0, TMP4         \ // TT1
	VADDUWM h, TMP3, TMP3            \ // Wt + h
	VADDUWM TMP2, TMP3, TMP3         \ // Wt + h + SS1
	VXOR f, g, TMP1                  \
	VAND TMP1, e, TMP1               \
	VXOR g, TMP1, TMP1               \ // (f XOR g) AND e XOR g
	VADDUWM TMP3, TMP1, TMP3         \ // TT2
	VOR b, b, TMP1                   \
	PROLD(TMP1, b, 9)                \ // b = b <<< 9
	VOR TMP4, TMP4, h                \ // h = TT1
	PROLD(f, TMP1, 10)               \
	PROLD(TMP1, f, 9)                \ // f = f <<< 19
	PROLD(TMP3, TMP1, 9)             \ // TMP1 = TT2 <<< 9
	PROLD(TMP1, TMP0, 8)             \ // TMP0 = TT2 <<< 17
	VXOR TMP3, TMP1, TMP1            \ // TMP1 = TT2 XOR (TT2 <<< 9)
	VXOR TMP1, TMP0, d               \ // d = TT2 XOR (TT2 <<< 9) XOR (TT2 <<< 17)

// Used general purpose registers R1-R11.
// blockMultBy4(dig **[8]uint32, p **byte, buffer *byte, blocks int)
TEXT ·blockMultBy4(SB), NOSPLIT, $0
	MOVD	$8, R15
	MOVD 	$16, R16
	MOVD 	$24, R17
	MOVD 	$32, R18
	MOVD 	$48, R19
#ifdef NEEDS_PERMW
	MOVD	$·mask(SB), R4
	LVX	(R4), ESPERMW
	ADD	$0x10, R4
#else
	MOVD	$·mask+0x10(SB), R4
#endif
	LXVD2X 	(R0)(R4), M0
	LXVD2X 	(R16)(R4), M1
	LXVD2X 	(R18)(R4), M2
	LXVD2X 	(R19)(R4), M3	
#define digPtr R11
#define srcPtrPtr R5
#define statePtr R4
#define blockCount R6
#define srcPtr1 R7
#define srcPtr2 R8
#define srcPtr3 R9
#define srcPtr4 R10
#define wordPtr R12
	MOVD	dig+0(FP), digPtr
	MOVD	p+8(FP), srcPtrPtr
	MOVD	buffer+16(FP), statePtr
	MOVD	blocks+24(FP), blockCount

	// load state
	MOVD (R0)(digPtr), R4
	LXVW4X (R0)(R4), a
	LXVW4X (R16)(R4), e
	MOVD (R15)(digPtr), R4
	LXVW4X (R0)(R4), b
	LXVW4X (R16)(R4), f
	MOVD (R16)(digPtr), R4
	LXVW4X (R0)(R4), c
	LXVW4X (R16)(R4), g
	MOVD (R17)(digPtr), R4
	LXVW4X (R0)(R4), d
	LXVW4X (R16)(R4), h

	TRANSPOSE_MATRIX(a, b, c, d)
	TRANSPOSE_MATRIX(e, f, g, h)

	MOVD (R0)(srcPtrPtr), srcPtr1
	MOVD (R15)(srcPtrPtr), srcPtr2
	MOVD (R16)(srcPtrPtr), srcPtr3
	MOVD (R17)(srcPtrPtr), srcPtr4
	MOVD $0, srcPtrPtr

	MOVD blockCount, CTR

loop:
	// Offload to VSR24-31 (aka FPR24-31)
	XXLOR	V0, V0, VS24
	XXLOR	V1, V1, VS25
	XXLOR	V2, V2, VS26
	XXLOR	V3, V3, VS27
	XXLOR	V4, V4, VS28
	XXLOR	V5, V5, VS29
	XXLOR	V6, V6, VS30
	XXLOR	V7, V7, VS31

	// reset wordPtr
	MOVD statePtr, wordPtr

	// load message block
	prepare4Words
	prepare4Words
	prepare4Words
	prepare4Words

	ROUND_00_11(0, T0, a, b, c, d, e, f, g, h)
	ROUND_00_11(1, T1, h, a, b, c, d, e, f, g)
	ROUND_00_11(2, T2, g, h, a, b, c, d, e, f)
	ROUND_00_11(3, T3, f, g, h, a, b, c, d, e)
	ROUND_00_11(4, T4, e, f, g, h, a, b, c, d)
	ROUND_00_11(5, T5, d, e, f, g, h, a, b, c)
	ROUND_00_11(6, T6, c, d, e, f, g, h, a, b)
	ROUND_00_11(7, T7, b, c, d, e, f, g, h, a)
	ROUND_00_11(8, T8, a, b, c, d, e, f, g, h)
	ROUND_00_11(9, T9, h, a, b, c, d, e, f, g)
	ROUND_00_11(10, T10, g, h, a, b, c, d, e, f)
	ROUND_00_11(11, T11, f, g, h, a, b, c, d, e)

	ROUND_12_15(12, T12, e, f, g, h, a, b, c, d)
	ROUND_12_15(13, T13, d, e, f, g, h, a, b, c)
	ROUND_12_15(14, T14, c, d, e, f, g, h, a, b)
	ROUND_12_15(15, T15, b, c, d, e, f, g, h, a)

	ROUND_16_63(16, T16, a, b, c, d, e, f, g, h)
	ROUND_16_63(17, T17, h, a, b, c, d, e, f, g)
	ROUND_16_63(18, T18, g, h, a, b, c, d, e, f)
	ROUND_16_63(19, T19, f, g, h, a, b, c, d, e)
	ROUND_16_63(20, T20, e, f, g, h, a, b, c, d)
	ROUND_16_63(21, T21, d, e, f, g, h, a, b, c)
	ROUND_16_63(22, T22, c, d, e, f, g, h, a, b)
	ROUND_16_63(23, T23, b, c, d, e, f, g, h, a)
	ROUND_16_63(24, T24, a, b, c, d, e, f, g, h)
	ROUND_16_63(25, T25, h, a, b, c, d, e, f, g)
	ROUND_16_63(26, T26, g, h, a, b, c, d, e, f)
	ROUND_16_63(27, T27, f, g, h, a, b, c, d, e)
	ROUND_16_63(28, T28, e, f, g, h, a, b, c, d)
	ROUND_16_63(29, T29, d, e, f, g, h, a, b, c)
	ROUND_16_63(30, T30, c, d, e, f, g, h, a, b)
	ROUND_16_63(31, T31, b, c, d, e, f, g, h, a)
	ROUND_16_63(32, T32, a, b, c, d, e, f, g, h)
	ROUND_16_63(33, T33, h, a, b, c, d, e, f, g)
	ROUND_16_63(34, T34, g, h, a, b, c, d, e, f)
	ROUND_16_63(35, T35, f, g, h, a, b, c, d, e)
	ROUND_16_63(36, T36, e, f, g, h, a, b, c, d)
	ROUND_16_63(37, T37, d, e, f, g, h, a, b, c)
	ROUND_16_63(38, T38, c, d, e, f, g, h, a, b)
	ROUND_16_63(39, T39, b, c, d, e, f, g, h, a)
	ROUND_16_63(40, T40, a, b, c, d, e, f, g, h)
	ROUND_16_63(41, T41, h, a, b, c, d, e, f, g)
	ROUND_16_63(42, T42, g, h, a, b, c, d, e, f)
	ROUND_16_63(43, T43, f, g, h, a, b, c, d, e)
	ROUND_16_63(44, T44, e, f, g, h, a, b, c, d)
	ROUND_16_63(45, T45, d, e, f, g, h, a, b, c)
	ROUND_16_63(46, T46, c, d, e, f, g, h, a, b)
	ROUND_16_63(47, T47, b, c, d, e, f, g, h, a)
	ROUND_16_63(48, T16, a, b, c, d, e, f, g, h)
	ROUND_16_63(49, T17, h, a, b, c, d, e, f, g)
	ROUND_16_63(50, T18, g, h, a, b, c, d, e, f)
	ROUND_16_63(51, T19, f, g, h, a, b, c, d, e)
	ROUND_16_63(52, T20, e, f, g, h, a, b, c, d)
	ROUND_16_63(53, T21, d, e, f, g, h, a, b, c)
	ROUND_16_63(54, T22, c, d, e, f, g, h, a, b)
	ROUND_16_63(55, T23, b, c, d, e, f, g, h, a)
	ROUND_16_63(56, T24, a, b, c, d, e, f, g, h)
	ROUND_16_63(57, T25, h, a, b, c, d, e, f, g)
	ROUND_16_63(58, T26, g, h, a, b, c, d, e, f)
	ROUND_16_63(59, T27, f, g, h, a, b, c, d, e)
	ROUND_16_63(60, T28, e, f, g, h, a, b, c, d)
	ROUND_16_63(61, T29, d, e, f, g, h, a, b, c)
	ROUND_16_63(62, T30, c, d, e, f, g, h, a, b)
	ROUND_16_63(63, T31, b, c, d, e, f, g, h, a)

	XXLXOR	V0, VS24, V0
	XXLXOR	V1, VS25, V1
	XXLXOR	V2, VS26, V2
	XXLXOR	V3, VS27, V3
	XXLXOR	V4, VS28, V4
	XXLXOR	V5, VS29, V5
	XXLXOR	V6, VS30, V6
	XXLXOR	V7, VS31, V7

	BDNZ	loop

end:
	TRANSPOSE_MATRIX(a, b, c, d)
	TRANSPOSE_MATRIX(e, f, g, h)

	// save state
	MOVD (R0)(digPtr), R4
	STXVW4X a, (R0)(R4)
	STXVW4X e, (R16)(R4)
	MOVD (R15)(digPtr), R4
	STXVW4X b, (R0)(R4)
	STXVW4X f, (R16)(R4)
	MOVD (R16)(digPtr), R4
	STXVW4X c, (R0)(R4)
	STXVW4X g, (R16)(R4)
	MOVD (R17)(digPtr), R4
	STXVW4X d, (R0)(R4)
	STXVW4X h, (R16)(R4)

	RET

// func copyResultsBy4(dig *uint32, dst *byte)
TEXT ·copyResultsBy4(SB),NOSPLIT,$0
	MOVD	dig+0(FP), R6
	MOVD	dst+8(FP), R4

#ifdef NEEDS_PERMW	
	MOVD	$·mask+0x00(SB), R5
	LVX	(R5), ESPERMW
#endif
	MOVD	$16, R5
	MOVD 	$32, R16
	MOVD 	$48, R17
	MOVD 	$64, R18
	MOVD 	$80, R19
	MOVD	$96, R8
	MOVD	$112, R9

	LXVD2X 	(R0)(R6), V0
	PPC64X_STXVD2X(V0, R0, R4)

	LXVD2X 	(R5)(R6), V0
	PPC64X_STXVD2X(V0, R5, R4)
	
	LXVD2X 	(R16)(R6), V0
	PPC64X_STXVD2X(V0, R16, R4)

	LXVD2X 	(R17)(R6), V0
	PPC64X_STXVD2X(V0, R17, R4)

	LXVD2X 	(R18)(R6), V0
	PPC64X_STXVD2X(V0, R18, R4)

	LXVD2X 	(R19)(R6), V0
	PPC64X_STXVD2X(V0, R19, R4)

	LXVD2X 	(R8)(R6), V0
	PPC64X_STXVD2X(V0, R8, R4)

	LXVD2X 	(R9)(R6), V0
	PPC64X_STXVD2X(V0, R9, R4)

	RET
