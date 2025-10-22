// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

#define ZERO X0
#define RSP X2

#define REG_A X8
#define REG_B X9
#define REG_C X10
#define REG_D X11
#define REG_E X12
#define REG_F X13
#define REG_G X14
#define REG_H X15

#define REG_A1 X16
#define REG_B1 X17
#define REG_C1 X18
#define REG_D1 X19
#define REG_E1 X20
#define REG_F1 X21
#define REG_G1 X22
#define REG_H1 X23

#define REG_END_ADDR X24

#define AX X25
#define BX X26
#define CX X28
#define DX X29
#define hlp0 X7
#define REG_KT X30

#define stackaddress(index) ((index)*4 + 8)(RSP)

// Wt = Mt; for 0 <= t <= 3
#define MSGSCHEDULE0(index) \
	MOVW	(index*4)(X6), AX; \
	REV8	AX, AX; \
	SRL 	$32, AX; \
	MOVW	AX, stackaddress(index)

// Wt+4 = Mt+4; for 0 <= t <= 11
#define MSGSCHEDULE01(index) \
	MOVW	((index+4)*4)(X6), AX; \
	REV8	AX, AX; \
	SRL 	$32, AX; \
	MOVW	AX, stackaddress(index+4)

// x = Wt-12 XOR Wt-5 XOR ROTL(15, Wt+1)
// p1(x) = x XOR ROTL(15, x) XOR ROTL(23, x)
// Wt+4 = p1(x) XOR ROTL(7, Wt-9) XOR Wt-2
// for 12 <= t <= 63
#define MSGSCHEDULE1(index) \
	MOVW stackaddress(index+1), AX; \    // Wt+1
	RORW $(32-15), AX; \                    // AX = ROTL(15, Wt+1)
	MOVW stackaddress(index-12), BX; \   // Wt-12
	XOR BX, AX, AX; \                  // AX = Wt-12 XOR ROTL(15, Wt+1)
	MOVW stackaddress(index-5), BX; \    // Wt-5 
	XOR BX, AX, AX; \                  // AX = x
	RORW $(32-15), AX, BX; \                // BX = ROTL(15, x)
	RORW $(32-23), AX, CX; \                // CX = ROTL(23, x)
	XOR BX, AX, AX; \                  // AX = x XOR ROTL(15, x)
	XOR CX, AX, AX; \                  // AX = p1(x)
	MOVW stackaddress(index-9), BX; \
	RORW $(32-7), BX; \                 // BX = ROTL(7, Wt-9)
	MOVW stackaddress(index-2), CX; \
	XOR BX, AX, AX; \                  // AX = p1(x) XOR ROTL(7, Wt-9)
	XOR CX, AX, AX; \
	MOVW AX, stackaddress(index+4)

// Calculate ss1 in BX
// x = ROTL(12, a) + e + ROTL(index, const)
// ret = ROTL(7, x)
#define SM3SS1(index, a, e) \
	RORW $(32-12), a, BX; \
	ADDW e, BX; \
	MOVW	(index*4)(REG_KT), hlp0; \
	ADDW hlp0, BX; \
	RORW $(32-7), BX

// Calculate tt1 in CX
// ret = (a XOR b XOR c) + d + (ROTL(12, a) XOR ss1) + (Wt XOR Wt+4)
#define SM3TT10(index, a, b, c, d) \  
	XOR a, b, DX; \
	XOR c, DX; \
	ADDW d, DX; \                      // DX = (a XOR b XOR c) + d
	MOVW	stackaddress(index), hlp0; \   // Wt
	XOR hlp0, AX; \                   // AX = Wt XOR Wt+4
	ADDW AX, DX; \
	RORW $(32-12), a, CX; \
	XOR BX, CX, CX; \           // SS2
	ADDW DX, CX

// Calculate tt2 in BX
// ret = (e XOR f XOR g) + h + ss1 + Wt
#define SM3TT20(e, f, g, h) \  
	ADDW h, hlp0; \
	ADDW BX, hlp0; \
	XOR e, f, BX; \
	XOR g, BX; \
	ADDW hlp0, BX

// Calculate tt1 in CX, used DX, hlp0
// ret = ((a AND b) OR (a AND c) OR (b AND c)) + d + (ROTL(12, a) XOR ss1) + (Wt XOR Wt+4)
#define SM3TT11(index, a, b, c, d) \  
	OR a, b, DX; \
	ADDW a, b, hlp0; \
	ADDW c, DX; \
	OR hlp0, DX; \                    // DX = (a AND b) OR (a AND c) OR (b AND c)
	ADDW d, DX; \
	RORW $(32-12), a, CX; \
	XOR BX, CX, CX; \
	ADDW DX, CX; \
	MOVW	stackaddress(index), hlp0; \
	XOR hlp0, AX; \
	ADDW AX, CX

// Calculate tt2 in BX
// ret = ((e AND f) OR (NOT(e) AND g)) + h + ss1 + Wt
#define SM3TT21(e, f, g, h) \  
	ADDW h, hlp0; \
	ADDW BX, hlp0; \
	XOR f, g, BX; \
	AND e, BX; \
	XOR g, BX; \
	ADDW hlp0, BX

#define COPYRESULT(b, d, f, h) \
	RORW $(32-9), b; \
	MOVW CX, h; \
	RORW $(32-19), f; \
	RORW $(32-9), BX, CX; \        // CX = ROTL(9, tt2)
	XOR BX, CX; \             // CX = tt2 XOR ROTL(9, tt2)
	RORW $(32-17), BX; \           // BX = ROTL(17, tt2)
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
TEXT ·block(SB), 0, $280-32
	MOV	dig+0(FP), X5
	MOV	p_base+8(FP), X6
	MOV	p_len+16(FP), X7

	SRL $6, X7
	SLL $6, X7
	BEQ X7, ZERO, end

	MOV	$·_K(SB), REG_KT		// const table

	ADD X6, X7, REG_END_ADDR

	MOVW	(0*4)(X5), REG_A
	MOVW	(1*4)(X5), REG_B
	MOVW	(2*4)(X5), REG_C
	MOVW	(3*4)(X5), REG_D
	MOVW	(4*4)(X5), REG_E
	MOVW	(5*4)(X5), REG_F
	MOVW	(6*4)(X5), REG_G
	MOVW	(7*4)(X5), REG_H

loop:
	MOVW REG_A, REG_A1
	MOVW REG_B, REG_B1
	MOVW REG_C, REG_C1
	MOVW REG_D, REG_D1
	MOVW REG_E, REG_E1
	MOVW REG_F, REG_F1
	MOVW REG_G, REG_G1
	MOVW REG_H, REG_H1

	MSGSCHEDULE0(0)
	MSGSCHEDULE0(1)
	MSGSCHEDULE0(2)
	MSGSCHEDULE0(3)

	SM3ROUND0(0, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H)


	ADD	$64, X6
	BNE	X6, REG_END_ADDR, loop

	MOVW REG_A, (0*4)(X5)
	MOVW REG_B, (1*4)(X5)
	MOVW REG_C, (2*4)(X5)
	MOVW REG_D, (3*4)(X5)
	MOVW REG_E, (4*4)(X5)
	MOVW REG_F, (5*4)(X5)
	MOVW REG_G, (6*4)(X5)
	MOVW REG_H, (7*4)(X5)

end:
	RET
