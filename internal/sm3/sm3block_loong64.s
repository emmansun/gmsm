// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

#define ZERO R0
#define RSP R3

#define REG_A R7
#define REG_B R8
#define REG_C R9
#define REG_D R10
#define REG_E R11
#define REG_F R12
#define REG_G R13
#define REG_H R14

#define REG_A1 R15
#define REG_B1 R16
#define REG_C1 R17
#define REG_D1 R18
#define REG_E1 R19
#define REG_F1 R20
#define REG_G1 R21
#define REG_H1 R23

#define REG_END_ADDR R24

#define AX R25
#define BX R26
#define CX R27
#define DX R28
#define hlp0 R29
#define REG_KT R31

// Wt+4 = Mt+4; for 0 <= t <= 11
#define MSGSCHEDULE01(index) \
	MOVW	((index+4)*4)(R5), AX; \
	REVB2W	AX, AX; \
	MOVW	AX, ((index+4)*4)(RSP)

// x = Wt-12 XOR Wt-5 XOR ROTL(15, Wt+1)
// p1(x) = x XOR ROTL(15, x) XOR ROTL(23, x)
// Wt+4 = p1(x) XOR ROTL(7, Wt-9) XOR Wt-2
// for 12 <= t <= 63
#define MSGSCHEDULE1(index) \
	MOVW ((index+1)*4)(RSP), AX; \     // Wt+1
	ROTR $(32-15), AX, AX; \           // AX = ROTL(15, Wt+1)
	MOVW ((index-12)*4)(RSP), BX; \    // Wt-12
	XOR BX, AX, AX; \                  // AX = Wt-12 XOR ROTL(15, Wt+1)
	MOVW ((index-5)*4)(RSP), BX; \     // Wt-5 
	XOR BX, AX, AX; \                  // AX = x
	ROTR $(32-15), AX, BX; \           // BX = ROTL(15, x)
	ROTR $(32-23), AX, CX; \           // CX = ROTL(23, x)
	XOR BX, AX, AX; \                  // AX = x XOR ROTL(15, x)
	XOR CX, AX, AX; \                  // AX = p1(x)
	MOVW ((index-9)*4)(RSP), BX; \
	ROTR $(32-7), BX, BX; \            // BX = ROTL(7, Wt-9)
	MOVW ((index-2)*4)(RSP), CX; \
	XOR BX, AX, AX; \                  // AX = p1(x) XOR ROTL(7, Wt-9)
	XOR CX, AX, AX; \
	MOVW AX, ((index+4)*4)(RSP)

// Calculate ss1 in BX
// x = ROTL(12, a) + e + ROTL(index, const)
// ret = ROTL(7, x)
#define SM3SS1(index, a, e) \
	ROTR $(32-12), a, BX; \
	ADD e, BX; \
	MOVW	(index*4)(REG_KT), hlp0; \
	ADD hlp0, BX; \
	ROTR $(32-7), BX, BX

// Calculate tt1 in CX
// ret = (a XOR b XOR c) + d + (ROTL(12, a) XOR ss1) + (Wt XOR Wt+4)
#define SM3TT10(index, a, b, c, d) \  
	XOR a, b, DX; \
	XOR c, DX; \
	ADD d, DX; \                      // DX = (a XOR b XOR c) + d
	MOVW	(index*4)(RSP), hlp0; \   // Wt
	XOR hlp0, AX; \                   // AX = Wt XOR Wt+4
	ADD AX, DX; \
	ROTR $(32-12), a, CX; \
	XOR BX, CX, CX; \           // SS2
	ADD DX, CX

// Calculate tt2 in BX
// ret = (e XOR f XOR g) + h + ss1 + Wt
#define SM3TT20(e, f, g, h) \  
	ADD h, hlp0; \
	ADD BX, hlp0; \
	XOR e, f, BX; \
	XOR g, BX; \
	ADD hlp0, BX

// Calculate tt1 in CX, used DX, hlp0
// ret = ((a AND b) OR (a AND c) OR (b AND c)) + d + (ROTL(12, a) XOR ss1) + (Wt XOR Wt+4)
#define SM3TT11(index, a, b, c, d) \  
	OR a, b, DX; \
	AND a, b, hlp0; \
	AND c, DX; \
	OR hlp0, DX; \                    // DX = (a AND b) OR (a AND c) OR (b AND c)
	ADD d, DX; \
	ROTR $(32-12), a, CX; \
	XOR BX, CX, CX; \
	ADD DX, CX; \
	MOVW	(index*4)(RSP), hlp0; \
	XOR hlp0, AX; \
	ADD AX, CX

// Calculate tt2 in BX
// ret = ((e AND f) OR (NOT(e) AND g)) + h + ss1 + Wt
#define SM3TT21(e, f, g, h) \  
	ADD h, hlp0; \
	ADD BX, hlp0; \
	XOR f, g, BX; \
	AND e, BX; \
	XOR g, BX; \
	ADD hlp0, BX

#define COPYRESULT(b, d, f, h) \
	ROTR $(32-9), b; \
	MOVW CX, h; \
	ROTR $(32-19), f; \
	ROTR $(32-9), BX, CX; \   // CX = ROTL(9, tt2)
	XOR BX, CX; \             // CX = tt2 XOR ROTL(9, tt2)
	ROTR $(32-17), BX; \      // BX = ROTL(17, tt2)
	XOR BX, CX, d             // d = tt2 XOR ROTL(9, tt2) XOR ROTL(17, tt2) 

#define SM3ROUND0(index, a, b, c, d, e, f, g, h) \
	MSGSCHEDULE01(index); \
	SM3SS1(index, a, e); \
	SM3TT10(index, a, b, c, d); \
	SM3TT20(e, f, g, h); \
	COPYRESULT(b, d, f, h)

#define SM3ROUND1(index, a, b, c, d, e, f, g, h) \
	MSGSCHEDULE1(index); \
	SM3SS1(index, a, e); \
	SM3TT10(index, a, b, c, d); \
	SM3TT20(e, f, g, h); \
	COPYRESULT(b, d, f, h)

#define SM3ROUND2(index, a, b, c, d, e, f, g, h) \
	MSGSCHEDULE1(index); \
	SM3SS1(index, a, e); \
	SM3TT11(index, a, b, c, d); \
	SM3TT21(e, f, g, h); \
	COPYRESULT(b, d, f, h)

// A stack frame size of 272 bytes is required here, because
// the frame size used for data expansion is 272 bytes.
// (4 bytes * 68 entries).
//
// func block(dig *digest, p []byte)
TEXT ·block(SB), 0, $272-32
	MOVV	dig+0(FP), R4
	MOVV	p_base+8(FP), R5
	MOVV	p_len+16(FP), R6

	AND	$~63, R6
	BEQ	R6, end

	MOVV	$·_K(SB), REG_KT		// const table

	ADDV R5, R6, REG_END_ADDR

	MOVW	(0*4)(R4), REG_A
	MOVW	(1*4)(R4), REG_B
	MOVW	(2*4)(R4), REG_C
	MOVW	(3*4)(R4), REG_D
	MOVW	(4*4)(R4), REG_E
	MOVW	(5*4)(R4), REG_F
	MOVW	(6*4)(R4), REG_G
	MOVW	(7*4)(R4), REG_H

loop:
	MOVW REG_A, REG_A1
	MOVW REG_B, REG_B1
	MOVW REG_C, REG_C1
	MOVW REG_D, REG_D1
	MOVW REG_E, REG_E1
	MOVW REG_F, REG_F1
	MOVW REG_G, REG_G1
	MOVW REG_H, REG_H1

	MOVW (0*4)(R5), R25
	REVB2W	R25, R25
	MOVW R25, (0*4)(RSP)
	
	MOVW (1*4)(R5), R25
	REVB2W	R25, R25
	MOVW R25, (1*4)(RSP)

	MOVW (2*4)(R5), R25
	REVB2W	R25, R25
	MOVW R25, (2*4)(RSP)

	MOVW (3*4)(R5), R25
	REVB2W	R25, R25
	MOVW R25, (3*4)(RSP)

	SM3ROUND0(0, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H)
	SM3ROUND0(1, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G)
	SM3ROUND0(2, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F)
	SM3ROUND0(3, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E)
	SM3ROUND0(4, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D)
	SM3ROUND0(5, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C)
	SM3ROUND0(6, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B)
	SM3ROUND0(7, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A)
	SM3ROUND0(8, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H)
	SM3ROUND0(9, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G)
	SM3ROUND0(10, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F)
	SM3ROUND0(11, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E)

	SM3ROUND1(12, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D)
	SM3ROUND1(13, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C)
	SM3ROUND1(14, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B)
	SM3ROUND1(15, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A)
	
	SM3ROUND2(16, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H)
	SM3ROUND2(17, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G)
	SM3ROUND2(18, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F)
	SM3ROUND2(19, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E)
	SM3ROUND2(20, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D)
	SM3ROUND2(21, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C)
	SM3ROUND2(22, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B)
	SM3ROUND2(23, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A)
	SM3ROUND2(24, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H)
	SM3ROUND2(25, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G)
	SM3ROUND2(26, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F)
	SM3ROUND2(27, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E)
	SM3ROUND2(28, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D)
	SM3ROUND2(29, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C)
	SM3ROUND2(30, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B)
	SM3ROUND2(31, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A)
	SM3ROUND2(32, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H)
	SM3ROUND2(33, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G)
	SM3ROUND2(34, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F)
	SM3ROUND2(35, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E)
	SM3ROUND2(36, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D)
	SM3ROUND2(37, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C)
	SM3ROUND2(38, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B)
	SM3ROUND2(39, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A)
	SM3ROUND2(40, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H)
	SM3ROUND2(41, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G)
	SM3ROUND2(42, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F)
	SM3ROUND2(43, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E)
	SM3ROUND2(44, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D)
	SM3ROUND2(45, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C)
	SM3ROUND2(46, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B)
	SM3ROUND2(47, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A)
	SM3ROUND2(48, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H)
	SM3ROUND2(49, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G)
	SM3ROUND2(50, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F)
	SM3ROUND2(51, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E)
	SM3ROUND2(52, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D)
	SM3ROUND2(53, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C)
	SM3ROUND2(54, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B)
	SM3ROUND2(55, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A)
	SM3ROUND2(56, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H)
	SM3ROUND2(57, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G)
	SM3ROUND2(58, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F)
	SM3ROUND2(59, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E)
	SM3ROUND2(60, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D)
	SM3ROUND2(61, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C)
	SM3ROUND2(62, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B)
	SM3ROUND2(63, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A)

	XOR REG_A1, REG_A
	XOR REG_B1, REG_B
	XOR REG_C1, REG_C
	XOR REG_D1, REG_D
	XOR REG_E1, REG_E
	XOR REG_F1, REG_F
	XOR REG_G1, REG_G
	XOR REG_H1, REG_H

	ADDV	$64, R5
	BNE	R5, REG_END_ADDR, loop

	MOVW REG_A, (0*4)(R4)
	MOVW REG_B, (1*4)(R4)
	MOVW REG_C, (2*4)(R4)
	MOVW REG_D, (3*4)(R4)
	MOVW REG_E, (4*4)(R4)
	MOVW REG_F, (5*4)(R4)
	MOVW REG_G, (6*4)(R4)
	MOVW REG_H, (7*4)(R4)
end:
	RET
