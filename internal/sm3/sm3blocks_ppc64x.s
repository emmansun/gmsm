// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"

#define a V0
#define e V1
#define b V2
#define f V3
#define c V4
#define g V5
#define d V6
#define h V7

#define T0 V8
#define T1 V9
#define T2 V10
#define ONE V11

#define TMP0 V12
#define TMP1 V13
#define TMP2 V14
#define TMP3 V15
#define TMP4 V16
#define TMP5 V17

#define DATA0 V16
#define DATA1 V17
#define DATA2 V18
#define DATA3 V19

#define V_x07 V20
#define V_x08 V21
#define V_x09 V22
#define V_x0C V23
#define V_x13 V24
#define V_x0F V25

// For instruction emulation
#define ESPERMW  V31 // Endian swapping permute into BE

DATA t_const<>+0x00(SB)/8, $0x79cc451979cc4519
DATA t_const<>+0x08(SB)/8, $0x79cc451979cc4519
DATA t_const<>+0x10(SB)/8, $0x9d8a7a879d8a7a87
DATA t_const<>+0x18(SB)/8, $0x9d8a7a879d8a7a87
GLOBL t_const<>(SB), RODATA, $32

#define R_x08 R15
#define R_x10 R16
#define R_x18 R17
#define R_TMP R19

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
// Due to VSPLTISW's limitation, the n MUST be [0, 31]
#define PROLD(s, r, n) \
	VSPLTISW $n, TMP5 \
	VRLW	s, TMP5, r

#define loadWordByIndex(W, i) \
	MOVD $(16*(i)), R_TMP \
	LXVW4X (R_TMP)(statePtr), W

// one word is 16 bytes
#define prepare4Words \
	PPC64X_LXVW4X(srcPtr1, srcPtrPtr, DATA0);    \
	PPC64X_LXVW4X(srcPtr2, srcPtrPtr, DATA1);    \
	PPC64X_LXVW4X(srcPtr3, srcPtrPtr, DATA2);    \
	PPC64X_LXVW4X(srcPtr4, srcPtrPtr, DATA3);    \
	TRANSPOSE_MATRIX(DATA0, DATA1, DATA2, DATA3);\
	ADD $16, srcPtrPtr;                          \
	STXVW4X DATA0, (wordPtr);                    \
	ADD $16, wordPtr;                            \
	STXVW4X DATA1, (wordPtr);                    \
	ADD $16, wordPtr;                            \
	STXVW4X DATA2, (wordPtr);                    \
	ADD $16, wordPtr;                            \
	STXVW4X DATA3, (wordPtr);                    \
	ADD $16, wordPtr

#define TRANSPOSE_MATRIX(T0, T1, T2, T3) \
	VMRGEW T0, T1, TMP0; \
	VMRGEW T2, T3, TMP1; \
	VMRGOW T0, T1, TMP2; \
	VMRGOW T2, T3, TMP3; \
	XXPERMDI TMP0, TMP1, $0, T0; \
	XXPERMDI TMP0, TMP1, $3, T2; \
	XXPERMDI TMP2, TMP3, $0, T1; \
	XXPERMDI TMP2, TMP3, $3, T3

#define ROUND_00_11(index, T, a, b, c, d, e, f, g, h) \
	VRLW a, V_x0C, TMP0              \
	VOR TMP0, TMP0, TMP1             \
	VADDUWM T, TMP0, TMP0            \
	VRLW T, ONE, T                   \
	VADDUWM e, TMP0, TMP0            \
	VRLW TMP0, V_x07, TMP2           \ // TMP2 = SS1
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
	VRLW TMP4, V_x09, b              \ // b = b <<< 9
	VOR TMP1, TMP1, h                \ // h = TT1
	VRLW f, V_x13, f                 \ // f = f <<< 19
	VRLW TMP3, V_x09, TMP4           \ // TMP4 = TT2 <<< 9
	VRLW TMP4, V_x08, TMP0           \ // TMP0 = TT2 <<< 17
	VXOR TMP3, TMP4, TMP4            \ // TMP4 = TT2 XOR (TT2 <<< 9)
	VXOR TMP4, TMP0, d               \ // d = TT2 XOR (TT2 <<< 9) XOR (TT2 <<< 17)

#define MESSAGE_SCHEDULE(index) \
	loadWordByIndex(TMP0, index+1)    \ // Wj-3
	VRLW TMP0, V_x0F, TMP1            \
	loadWordByIndex(TMP0, index-12)   \ // Wj-16
	VXOR TMP0, TMP1, TMP0             \
	loadWordByIndex(TMP1, index-5)    \ // Wj-9
	VXOR TMP0, TMP1, TMP0             \
	VRLW TMP0, V_x0F, TMP1            \
	VRLW TMP1, V_x08, TMP2            \
	VXOR TMP1, TMP0, TMP0             \
	VXOR TMP2, TMP0, TMP0             \ // P1
	loadWordByIndex(TMP1, index-9)    \ // Wj-13
	VRLW TMP1, V_x07, TMP2            \
	VXOR TMP2, TMP0, TMP0             \
	loadWordByIndex(TMP1, index-2)    \ // Wj-6
	VXOR TMP1, TMP0, TMP1             \
	STXVW4X TMP1, (wordPtr)           \
	ADD $16, wordPtr                  \

#define ROUND_12_15(index, T, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index)                               \
	ROUND_00_11(index, T, a, b, c, d, e, f, g, h)

#define ROUND_16_63(index, T, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index)          \ // TMP1 is Wt+4 now, Pls do not use it
	VRLW a, V_x0C, TMP0              \
	VOR TMP0, TMP0, TMP4             \
	VADDUWM T, TMP0, TMP0            \
	VRLW T, ONE, T                   \
	VADDUWM e, TMP0, TMP0            \
	VRLW TMP0, V_x07, TMP2           \ // TMP2 = SS1
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
	VRLW TMP1, V_x09, b              \ // b = b <<< 9
	VOR TMP4, TMP4, h                \ // h = TT1
	VRLW f, V_x13, f                 \ // f = f <<< 19
	VRLW TMP3, V_x09, TMP1           \ // TMP1 = TT2 <<< 9
	VRLW TMP1, V_x08, TMP0           \ // TMP0 = TT2 <<< 17
	VXOR TMP3, TMP1, TMP1            \ // TMP1 = TT2 XOR (TT2 <<< 9)
	VXOR TMP1, TMP0, d               \ // d = TT2 XOR (TT2 <<< 9) XOR (TT2 <<< 17)

// Used general purpose registers R4-R12, R15-R19.
// blockMultBy4(dig **[8]uint32, p **byte, buffer *byte, blocks int)
TEXT ·blockMultBy4(SB), NOSPLIT, $0
	MOVD	$8, R_x08
	MOVD 	$16, R_x10
	MOVD 	$24, R_x18
#ifdef NEEDS_PERMW
	MOVD	$·flip_mask(SB), R4
	LVX	(R4), ESPERMW
#endif
	VSPLTISW $1, ONE
	VSPLTISW $7, V_x07
	VSPLTISW $8, V_x08
	VSPLTISW $9, V_x09
	VSPLTISW $12, V_x0C
	VSPLTISW $15, V_x0F
	VSPLTISW $19, V_x13
	MOVD $t_const<>(SB), R4
	LXVD2X (R0)(R4), T0
	LXVD2X (R_x10)(R4), T1
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
	MOVD (R0)(digPtr), R_TMP
	LXVW4X (R0)(R_TMP), a
	LXVW4X (R_x10)(R_TMP), e
	MOVD (R_x08)(digPtr), R_TMP
	LXVW4X (R0)(R_TMP), b
	LXVW4X (R_x10)(R_TMP), f
	MOVD (R_x10)(digPtr), R_TMP
	LXVW4X (R0)(R_TMP), c
	LXVW4X (R_x10)(R_TMP), g
	MOVD (R_x18)(digPtr), R_TMP
	LXVW4X (R0)(R_TMP), d
	LXVW4X (R_x10)(R_TMP), h

	TRANSPOSE_MATRIX(a, b, c, d)
	TRANSPOSE_MATRIX(e, f, g, h)

	MOVD (R0)(srcPtrPtr), srcPtr1
	MOVD (R_x08)(srcPtrPtr), srcPtr2
	MOVD (R_x10)(srcPtrPtr), srcPtr3
	MOVD (R_x18)(srcPtrPtr), srcPtr4
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

	XXLOR T0, T0, T2
	ROUND_00_11(0, T2, a, b, c, d, e, f, g, h)
	ROUND_00_11(1, T2, h, a, b, c, d, e, f, g)
	ROUND_00_11(2, T2, g, h, a, b, c, d, e, f)
	ROUND_00_11(3, T2, f, g, h, a, b, c, d, e)
	ROUND_00_11(4, T2, e, f, g, h, a, b, c, d)
	ROUND_00_11(5, T2, d, e, f, g, h, a, b, c)
	ROUND_00_11(6, T2, c, d, e, f, g, h, a, b)
	ROUND_00_11(7, T2, b, c, d, e, f, g, h, a)
	ROUND_00_11(8, T2, a, b, c, d, e, f, g, h)
	ROUND_00_11(9, T2, h, a, b, c, d, e, f, g)
	ROUND_00_11(10, T2, g, h, a, b, c, d, e, f)
	ROUND_00_11(11, T2, f, g, h, a, b, c, d, e)

	ROUND_12_15(12, T2, e, f, g, h, a, b, c, d)
	ROUND_12_15(13, T2, d, e, f, g, h, a, b, c)
	ROUND_12_15(14, T2, c, d, e, f, g, h, a, b)
	ROUND_12_15(15, T2, b, c, d, e, f, g, h, a)

	XXLOR T1, T1, T2
	ROUND_16_63(16, T2, a, b, c, d, e, f, g, h)
	ROUND_16_63(17, T2, h, a, b, c, d, e, f, g)
	ROUND_16_63(18, T2, g, h, a, b, c, d, e, f)
	ROUND_16_63(19, T2, f, g, h, a, b, c, d, e)
	ROUND_16_63(20, T2, e, f, g, h, a, b, c, d)
	ROUND_16_63(21, T2, d, e, f, g, h, a, b, c)
	ROUND_16_63(22, T2, c, d, e, f, g, h, a, b)
	ROUND_16_63(23, T2, b, c, d, e, f, g, h, a)
	ROUND_16_63(24, T2, a, b, c, d, e, f, g, h)
	ROUND_16_63(25, T2, h, a, b, c, d, e, f, g)
	ROUND_16_63(26, T2, g, h, a, b, c, d, e, f)
	ROUND_16_63(27, T2, f, g, h, a, b, c, d, e)
	ROUND_16_63(28, T2, e, f, g, h, a, b, c, d)
	ROUND_16_63(29, T2, d, e, f, g, h, a, b, c)
	ROUND_16_63(30, T2, c, d, e, f, g, h, a, b)
	ROUND_16_63(31, T2, b, c, d, e, f, g, h, a)
	ROUND_16_63(32, T2, a, b, c, d, e, f, g, h)
	ROUND_16_63(33, T2, h, a, b, c, d, e, f, g)
	ROUND_16_63(34, T2, g, h, a, b, c, d, e, f)
	ROUND_16_63(35, T2, f, g, h, a, b, c, d, e)
	ROUND_16_63(36, T2, e, f, g, h, a, b, c, d)
	ROUND_16_63(37, T2, d, e, f, g, h, a, b, c)
	ROUND_16_63(38, T2, c, d, e, f, g, h, a, b)
	ROUND_16_63(39, T2, b, c, d, e, f, g, h, a)
	ROUND_16_63(40, T2, a, b, c, d, e, f, g, h)
	ROUND_16_63(41, T2, h, a, b, c, d, e, f, g)
	ROUND_16_63(42, T2, g, h, a, b, c, d, e, f)
	ROUND_16_63(43, T2, f, g, h, a, b, c, d, e)
	ROUND_16_63(44, T2, e, f, g, h, a, b, c, d)
	ROUND_16_63(45, T2, d, e, f, g, h, a, b, c)
	ROUND_16_63(46, T2, c, d, e, f, g, h, a, b)
	ROUND_16_63(47, T2, b, c, d, e, f, g, h, a)
	ROUND_16_63(48, T2, a, b, c, d, e, f, g, h)
	ROUND_16_63(49, T2, h, a, b, c, d, e, f, g)
	ROUND_16_63(50, T2, g, h, a, b, c, d, e, f)
	ROUND_16_63(51, T2, f, g, h, a, b, c, d, e)
	ROUND_16_63(52, T2, e, f, g, h, a, b, c, d)
	ROUND_16_63(53, T2, d, e, f, g, h, a, b, c)
	ROUND_16_63(54, T2, c, d, e, f, g, h, a, b)
	ROUND_16_63(55, T2, b, c, d, e, f, g, h, a)
	ROUND_16_63(56, T2, a, b, c, d, e, f, g, h)
	ROUND_16_63(57, T2, h, a, b, c, d, e, f, g)
	ROUND_16_63(58, T2, g, h, a, b, c, d, e, f)
	ROUND_16_63(59, T2, f, g, h, a, b, c, d, e)
	ROUND_16_63(60, T2, e, f, g, h, a, b, c, d)
	ROUND_16_63(61, T2, d, e, f, g, h, a, b, c)
	ROUND_16_63(62, T2, c, d, e, f, g, h, a, b)
	ROUND_16_63(63, T2, b, c, d, e, f, g, h, a)

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
	MOVD (R0)(digPtr), R_TMP
	STXVW4X a, (R0)(R_TMP)
	STXVW4X e, (R_x10)(R_TMP)
	MOVD (R_x08)(digPtr), R_TMP
	STXVW4X b, (R0)(R_TMP)
	STXVW4X f, (R_x10)(R_TMP)
	MOVD (R_x10)(digPtr), R_TMP
	STXVW4X c, (R0)(R_TMP)
	STXVW4X g, (R_x10)(R_TMP)
	MOVD (R_x18)(digPtr), R_TMP
	STXVW4X d, (R0)(R_TMP)
	STXVW4X h, (R_x10)(R_TMP)

	RET

// Used general purpose registers R4-R6, R8-R9, R16-R19.
// func copyResultsBy4(dig *uint32, dst *byte)
TEXT ·copyResultsBy4(SB),NOSPLIT,$0
	MOVD	dig+0(FP), R6
	MOVD	dst+8(FP), R4

#ifdef NEEDS_PERMW	
	MOVD	$·flip_mask(SB), R5
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
