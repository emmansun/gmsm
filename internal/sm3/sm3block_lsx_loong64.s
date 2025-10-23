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

#define Wt V9

// For rounds [0 - 16)
#define ROUND_AND_SCHED_N_0_0(disp, idx, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3, Wt) \
    VSHUF4IW $0x90, XWORD1, XTMP0    \
    VMOVQ XWORD0.W[3], XTMP0.W[0]   \ // XTMP0 = W[-13] = {w6,w5,w4,w3}
    VROTRW $(32-7), XTMP0, XTMP1    \ // XTMP1 = W[-13] rol 7
    VSHUF4IW 0xB0, XWORD3, XTMP0    \
    VMOVQ XWORD2.V[0], XTMP0.V[1]   \ // XTMP0 = W[-6] = {w13,w12,w11,w10}
    VXORV XTMP1, XTMP0, XTMP0       \ // XTMP0 = W[-6] ^ (W[-13] rol 7)
    \ // Prepare P1 parameters
    VSHUF4IW $0x90, XWORD2, XTMP1    \
    VMOVQ XWORD1.W[3], XTMP1.W[0]   \ // XTMP1 =  W[-9] = {w10,w9,w8,w7}
    VXORV XWORD0, XTMP1, XTMP1      \ // XTMP1 = W[-9] ^ W[-16]
    VSHUF4IW $0x39, XWORD3, XTMP3    \ // XTMP3 = W[-3] {w12,w15,w14,w13}
    VROTRW $(32-15), XTMP3, XTMP2   \ // XTMP2 = W[-3] rol 15 {xxBA}
    VXORV XTMP1, XTMP2, XTMP2       \ // XTMP2 = x = W[-9] ^ W[-16] ^ (W[-3] rol 15)
    \ // P1
    VROTRW $(32-15), XTMP2, XTMP4   \ // XTMP4 = x rol 15 {xxBA}
    VROTRW $(32-8), XTMP4, XTMP3    \ // XTMP3 = x rol 23 {xxBA}
    VXORV XTMP2, XTMP4, XTMP4       \ // XTMP4 = x ^ (x rol 15)
    VXORV XTMP4, XTMP3, XTMP4       \ // XTMP4 = p1(x)
    \ // First 2 words message schedule result
    VXORV XTMP4, XTMP0, XTMP2       \ // XTMP2 = p1(x) ^ (W[-6] ^ (W[-13] rol 7))
    \ // // Prepare P1 parameters
    VSHUF4IW $0x39, XWORD3, XTMP3    \
    VMOVQ XTMP2.W[0], XTMP3.W[3]    \ // XTMP3 = W[-3] {W[0],w15, w14, w13}
    VROTRW $(32-15), XTMP3, XTMP4   \ // XTMP4 = W[-3] rol 15 {DCBA}
    VXORV XTMP1, XTMP4, XTMP4       \ // XTMP4 = x = W[-9] ^ W[-16] ^ (W[-3] rol 15)
    \ // P1
    VROTRW $(32-15), XTMP4, XTMP3   \
    VROTRW $(32-8), XTMP3, XTMP1    \
    VXORV XTMP4, XTMP3, XTMP3       \
    VXORV XTMP3, XTMP1, XTMP1       \
    \ // 4 words message schedule result
    VXORV XTMP1, XTMP0, XTMP1


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
    ROUND_AND_SCHED_N_0_0(0*16, 0, REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H, XWORD0, XWORD1, XWORD2, XWORD3, Wt)


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
    VMOVQ XTMP1, (0*16)(R4)        // store 16 words    
end:
    RET
