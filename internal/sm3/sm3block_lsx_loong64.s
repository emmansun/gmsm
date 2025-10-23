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

#define XWORD0 V0
#define XWORD1 V1
#define XWORD2 V2
#define XWORD3 V3

#define XTMP0 V4
#define XTMP1 V5
#define XTMP2 V6
#define XTMP3 V7
#define XTMP4 V8
#define XTMP5 V9

#define Wt V10

#define MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3) \
	\ // Message schedule for next 4 words
	VSHUF4IW $0x90, XWORD1, XTMP0    \
	VMOVQ XWORD0.W[3], hlp0          \
	VMOVQ hlp0, XTMP0.W[0]           \ // XTMP0 = W[-13] = {w6,w5,w4,w3}
	VROTRW $(32-7), XTMP0, XTMP1     \ // XTMP1 = W[-13] rol 7
	VSHUF4IW $0xB0, XWORD3, XTMP0    \
	VMOVQ XWORD2.V[0], hlp0          \
	VMOVQ hlp0, XTMP0.V[1]           \ // XTMP0 = W[-6] = {w13,w12,w11,w10}
	VXORV XTMP1, XTMP0, XTMP0        \ // XTMP0 = W[-6] ^ (W[-13] rol 7)
	\ // Prepare P1 parameters
	VSHUF4IW $0x90, XWORD2, XTMP1    \
	VMOVQ XWORD1.W[3], hlp0          \
	VMOVQ hlp0, XTMP1.W[0]           \ // XTMP1 =  W[-9] = {w10,w9,w8,w7}
	VXORV XWORD0, XTMP1, XTMP1       \ // XTMP1 = W[-9] ^ W[-16]
	VSHUF4IW $0x39, XWORD3, XTMP5    \ // XTMP5 = W[-3] {w12,w15,w14,w13}
	VROTRW $(32-15), XTMP5, XTMP2    \ // XTMP2 = W[-3] rol 15 {xxBA}
	VXORV XTMP1, XTMP2, XTMP2        \ // XTMP2 = x = W[-9] ^ W[-16] ^ (W[-3] rol 15)
	\ // P1
	VROTRW $(32-15), XTMP2, XTMP4   \ // XTMP4 = x rol 15 {xxBA}
	VROTRW $(32-8), XTMP4, XTMP3    \ // XTMP3 = x rol 23 {xxBA}
	VXORV XTMP2, XTMP4, XTMP4       \ // XTMP4 = x ^ (x rol 15)
	VXORV XTMP4, XTMP3, XTMP4       \ // XTMP4 = p1(x)
	\ // First 2 words message schedule result
	VXORV XTMP4, XTMP0, XTMP2       \ // XTMP2 = p1(x) ^ (W[-6] ^ (W[-13] rol 7))
	\ // // Prepare P1 parameters
	VMOVQ XTMP2.W[0], hlp0          \
	VMOVQ hlp0, XTMP5.W[3]          \ // XTMP5 = W[-3] {W[0],w15, w14, w13}
	VROTRW $(32-15), XTMP5, XTMP4   \ // XTMP4 = W[-3] rol 15 {DCBA}
	VXORV XTMP1, XTMP4, XTMP4       \ // XTMP4 = x = W[-9] ^ W[-16] ^ (W[-3] rol 15)
	\ // P1
	VROTRW $(32-15), XTMP4, XTMP3   \
	VROTRW $(32-8), XTMP3, XTMP1    \
	VXORV XTMP4, XTMP3, XTMP3       \
	VXORV XTMP3, XTMP1, XTMP1       \
	\ // 4 words message schedule result
	VXORV XTMP1, XTMP0, XWORD0

#define DO_ROUND_N_0(kIdx, wIdx, a, b, c, d, e, f, g, h, W1, Wt) \
	ROTR $(32-12), a, AX;              \ // AX = a <<< 12
	MOVV (kIdx*4)(REG_KT), hlp0;       \
	ADD hlp0, e, BX;                   \
	ADD AX, BX;                        \ // BX = a <<< 12 + e + T
	ROTR $(32-7), BX, CX;              \ // CX = ss1
	XOR CX, AX;                        \ // AX = ss2
	VMOVQ W1.W[wIdx], BX;               \ // BX = W
	ADD BX, CX;                        \ // CX = ss1 + W
	ADD h, CX;					       \ // CX = h + ss1 + W (part of tt2)
	VMOVQ Wt.W[wIdx], BX;              \ // BX = Wt
	ADD BX, AX;				           \ // AX = ss2 + Wt
	ADD d, AX;                         \ // AX = d + ss2 + Wt (part of tt1)
	; \ //FF
	XOR a, b, h;					   \
	XOR c, h;						   \
	ADD AX, h;                         \ // h = tt1
	; \ //GG
	XOR e, f, BX; 					   \
	XOR g, BX;					       \
	ADD BX, CX;					       \ // CX = tt2
	; \
	ROTR $(32-9), b;                   \
	ROTR $(32-19), f;                  \
	; \ // P(tt2)
	ROTR $(32-9), CX, AX; 		       \
	ROTR $(32-17), CX, d;              \
	XOR AX, d;					       \
	XOR CX, d

#define DO_ROUND_N_1(kIdx, wIdx, a, b, c, d, e, f, g, h, W1, Wt) \
	ROTR $(32-12), a, AX;              \ // AX = a <<< 12
	MOVV  (kIdx*4)(REG_KT), hlp0;      \
	ADD hlp0, e, BX;                   \
	ADD AX, BX;                        \ // BX = a <<< 12 + e + T
	ROTR $(32-7), BX, CX;              \ // CX = ss1
	XOR CX, AX;                        \ // AX = ss2
	VMOVQ W1.W[wIdx], BX;               \ // BX = W
	ADD BX, CX;                        \ // CX = ss1 + W
	ADD h, CX;					       \ // CX = h + ss1 + W (part of tt2)
	VMOVQ Wt.W[wIdx], BX;              \ // BX = Wt
	ADD BX, AX;				           \ // AX = ss2 + Wt
	ADD d, AX;                         \ // AX = d + ss2 + Wt (part of tt1)
	; \ //FF
	OR a, b, BX;                       \
	AND a, b, h;					   \
	AND c, BX;                         \
	OR BX, h;                          \ // h = (a AND b) OR (a AND c) OR (b AND c)
	ADD AX, h;                         \ // h = tt1
	; \ //GG
	XOR f, g, BX;                      \
	AND e, BX;				           \
	XOR g, BX;					       \
	ADD BX, CX;					       \ // CX = tt2
	; \
	ROTR $(32-9), b;                   \
	ROTR $(32-19), f;                  \
	; \ // P(tt2)
	ROTR $(32-9), CX, AX; 		       \
	ROTR $(32-17), CX, d;              \
	XOR AX, d;					       \
	XOR CX, d

// func blockLsx(dig *digest, p []byte)
TEXT ·blockLsx(SB), NOSPLIT, $0
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

    VMOVQ (0*16)(R5), XWORD0        // load 16 words
    VMOVQ (1*16)(R5), XWORD1
    VMOVQ (2*16)(R5), XWORD2
    VMOVQ (3*16)(R5), XWORD3
    
    VSHUF4IB $0x1B, XWORD0, XWORD0  // change byte order
    VSHUF4IB $0x1B, XWORD1, XWORD1  // change byte order
    VSHUF4IB $0x1B, XWORD2, XWORD2  // change byte order
    VSHUF4IB $0x1B, XWORD3, XWORD3  // change byte order

schedule_compress: // for w0 - w47
    // Do 4 rounds and scheduling
    VXORV XWORD0, XWORD1, Wt        // Wt = Wt XOR Wt+4
    DO_ROUND_N_0(0, 0, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, XWORD0, Wt)
	DO_ROUND_N_0(1, 1, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, XWORD0, Wt)
	DO_ROUND_N_0(2, 2, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, XWORD0, Wt)
	DO_ROUND_N_0(3, 3, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, XWORD0, Wt)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)
	
	VXORV XWORD2, XWORD1, Wt
	DO_ROUND_N_0(4, 0, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, XWORD1, Wt)
	DO_ROUND_N_0(5, 1, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, XWORD1, Wt)
	DO_ROUND_N_0(6, 2, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, XWORD1, Wt)
	DO_ROUND_N_0(7, 3, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, XWORD1, Wt)
	MESSAGE_SCHEDULE(XWORD1, XWORD2, XWORD3, XWORD0)
/*
	VXORV XWORD3, XWORD2, Wt
	DO_ROUND_N_0(8, 0, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, XWORD2, Wt)
	DO_ROUND_N_0(9, 1, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, XWORD2, Wt)
	DO_ROUND_N_0(10, 2, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, XWORD2, Wt)
	DO_ROUND_N_0(11, 3, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, XWORD2, Wt)
	MESSAGE_SCHEDULE(XWORD2, XWORD3, XWORD0, XWORD1)

	VXORV XWORD0, XWORD3, Wt
	DO_ROUND_N_0(12, 0, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, XWORD3, Wt)
	DO_ROUND_N_0(13, 1, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, XWORD3, Wt)
	DO_ROUND_N_0(14, 2, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, XWORD3, Wt)
	DO_ROUND_N_0(15, 3, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, XWORD3, Wt)
	MESSAGE_SCHEDULE(XWORD3, XWORD0, XWORD1, XWORD2)

	VXORV XWORD1, XWORD0, Wt
	DO_ROUND_N_1(16, 0, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, XWORD0, Wt)
	DO_ROUND_N_1(17, 1, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, XWORD0, Wt)
	DO_ROUND_N_1(18, 2, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, XWORD0, Wt)
	DO_ROUND_N_1(19, 3, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, XWORD0, Wt)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)

	VXORV XWORD2, XWORD1, Wt
	DO_ROUND_N_1(20, 0, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, XWORD1, Wt)
	DO_ROUND_N_1(21, 1, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, XWORD1, Wt)
	DO_ROUND_N_1(22, 2, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, XWORD1, Wt)
	DO_ROUND_N_1(23, 3, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, XWORD1, Wt)
	MESSAGE_SCHEDULE(XWORD1, XWORD2, XWORD3, XWORD0)

	VXORV XWORD3, XWORD2, Wt
	DO_ROUND_N_1(24, 0, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, XWORD2, Wt)
	DO_ROUND_N_1(25, 1, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, XWORD2, Wt)
	DO_ROUND_N_1(26, 2, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, XWORD2, Wt)
	DO_ROUND_N_1(27, 3, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, XWORD2, Wt)
	MESSAGE_SCHEDULE(XWORD2, XWORD3, XWORD0, XWORD1)

	VXORV XWORD0, XWORD3, Wt
	DO_ROUND_N_1(28, 0, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, XWORD3, Wt)
	DO_ROUND_N_1(29, 1, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, XWORD3, Wt)
	DO_ROUND_N_1(30, 2, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, XWORD3, Wt)
	DO_ROUND_N_1(31, 3, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, XWORD3, Wt)
	MESSAGE_SCHEDULE(XWORD3, XWORD0, XWORD1, XWORD2)

	VXORV XWORD1, XWORD0, Wt
	DO_ROUND_N_1(32, 0, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, XWORD0, Wt)
	DO_ROUND_N_1(33, 1, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, XWORD0, Wt)
	DO_ROUND_N_1(34, 2, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, XWORD0, Wt)
	DO_ROUND_N_1(35, 3, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, XWORD0, Wt)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)

	VXORV XWORD2, XWORD1, Wt
	DO_ROUND_N_1(36, 0, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, XWORD1, Wt)
	DO_ROUND_N_1(37, 1, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, XWORD1, Wt)
	DO_ROUND_N_1(38, 2, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, XWORD1, Wt)
	DO_ROUND_N_1(39, 3, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, XWORD1, Wt)
	MESSAGE_SCHEDULE(XWORD1, XWORD2, XWORD3, XWORD0)

	VXORV XWORD3, XWORD2, Wt
	DO_ROUND_N_1(40, 0, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, XWORD2, Wt)
	DO_ROUND_N_1(41, 1, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, XWORD2, Wt)
	DO_ROUND_N_1(42, 2, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, XWORD2, Wt)
	DO_ROUND_N_1(43, 3, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, XWORD2, Wt)
	MESSAGE_SCHEDULE(XWORD2, XWORD3, XWORD0, XWORD1)

	VXORV XWORD0, XWORD3, Wt
	DO_ROUND_N_1(44, 0, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, XWORD3, Wt)
	DO_ROUND_N_1(45, 1, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, XWORD3, Wt)
	DO_ROUND_N_1(46, 2, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, XWORD3, Wt)
	DO_ROUND_N_1(47, 3, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, XWORD3, Wt)
	MESSAGE_SCHEDULE(XWORD3, XWORD0, XWORD1, XWORD2)

	// w48 - w63 processed with only 4 rounds scheduling (last 16 rounds)
	VXORV XWORD1, XWORD0, Wt
	DO_ROUND_N_1(48, 0, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, XWORD0, Wt)
	DO_ROUND_N_1(49, 1, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, XWORD0, Wt)
	DO_ROUND_N_1(50, 2, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, XWORD0, Wt)
	DO_ROUND_N_1(51, 3, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, XWORD0, Wt)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)

	VXORV XWORD2, XWORD1, Wt
	DO_ROUND_N_1(52, 0, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, XWORD1, Wt)
	DO_ROUND_N_1(53, 1, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, XWORD1, Wt)
	DO_ROUND_N_1(54, 2, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, XWORD1, Wt)
	DO_ROUND_N_1(55, 3, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, XWORD1, Wt)
	
	VXORV XWORD3, XWORD2, Wt
	DO_ROUND_N_1(56, 0, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, XWORD2, Wt)
	DO_ROUND_N_1(57, 1, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, XWORD2, Wt)
	DO_ROUND_N_1(58, 2, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, XWORD2, Wt)
	DO_ROUND_N_1(59, 3, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, REG_E, XWORD2, Wt)

	VXORV XWORD0, XWORD3, Wt
	DO_ROUND_N_1(60, 0, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, REG_D, XWORD3, Wt)
	DO_ROUND_N_1(61, 1, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, REG_C, XWORD3, Wt)
	DO_ROUND_N_1(62, 2, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, REG_B, XWORD3, Wt)
	DO_ROUND_N_1(63, 3, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, REG_A, XWORD3, Wt)

	XOR REG_A1, REG_A
	XOR REG_B1, REG_B
	XOR REG_C1, REG_C
	XOR REG_D1, REG_D
	XOR REG_E1, REG_E
	XOR REG_F1, REG_F
	XOR REG_G1, REG_G
	XOR REG_H1, REG_H
*/
	ADDV	$64, R5
	BNE	R5, REG_END_ADDR, loop

	VMOVQ XWORD0, (0*16)(R4)
	VMOVQ XWORD1, (1*16)(R4)

/*
	MOVW REG_A, (0*4)(R4)
	MOVW REG_B, (1*4)(R4)
	MOVW REG_C, (2*4)(R4)
	MOVW REG_D, (3*4)(R4)
	MOVW REG_E, (4*4)(R4)
	MOVW REG_F, (5*4)(R4)
	MOVW REG_G, (6*4)(R4)
	MOVW REG_H, (7*4)(R4)
*/
end:
    RET
