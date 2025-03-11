// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"
#include "sm3_const_asm.s"

// We can also use MFVSRWZ to extract the first word from vector register
// and then use VSLDOI to shift the vector register, thus we can avoid the usage of memory (buffer).
// But due to we have no real phisical machine to test the performance difference,
// we'll keep current implementation first.

#ifdef GOARCH_ppc64le
#define NEEDS_PERMW

#define PPC64X_LXVW4X(RA,RB,VT) \
	LXVW4X	(RA+RB), VT \
	VPERM	VT, VT, ESPERMW, VT

#else
#define PPC64X_LXVW4X(RA,RB,VT)  LXVW4X	(RA+RB), VT
#endif // defined(GOARCH_ppc64le)

#define a R7
#define b R8
#define c R9
#define d R10
#define e R11
#define f R12
#define g R14
#define h R15

#define CTX	R3
#define INP	R4
#define LEN	R5
#define BUFFER R16

#define R_x000	R0
#define R_x010	R17
#define R_x020	R18
#define R_x030	R19

#define y0 R20
#define y1 R21
#define y2 R22
#define TEMP R6

#define XWORD0 V0
#define XWORD1 V1
#define XWORD2 V2
#define XWORD3 V3

#define XTMP0 V4
#define XTMP1 V5
#define XTMP2 V6
#define XTMP3 V7
#define XTMP4 V8

#define XFER  V9
#define V_x07 V10
#define V_x08 V11
#define V_x0F V12

// For instruction emulation
#define ESPERMW  V31 // Endian swapping permute into BE

// shuffle byte order from LE to BE
DATA ·flip_mask+0x00(SB)/8, $0x0b0a09080f0e0d0c // byte swap per word
DATA ·flip_mask+0x08(SB)/8, $0x0302010007060504

GLOBL ·flip_mask(SB), RODATA, $16

#define SS12(a, e, const, ss1, ss2) \
	ROTLW     $12, a, ss2;                     \ // y0 = a <<< 12
	ADD     $const, e, ss1;                    \
	ADD     ss2, ss1;                          \ // y2 = a <<< 12 + e + T
	ROTLW     $7, ss1;                         \ // y2 = SS1
	XOR     ss1, ss2

#define P0(tt2, tmp, out) \
	ROTLW     $9, tt2, tmp;                        \
	ROTLW     $17, tt2, out;                       \
	XOR     tmp, out;                              \
	XOR     tt2, out

// For rounds [0 - 16)
// addr1 for w, addr2 for w'
#define DO_ROUND_N_0(addr1, addr2, const, a, b, c, d, e, f, g, h) \
	;                                            \
	SS12(a, e, const, y2, y0);                   \
	MOVWZ addr1, y1;                             \
	ADD   y1, y2;                                \ // y2 = SS1 + W
	ADD   h, y2;                                 \ // y2 = h + SS1 + W    
	MOVWZ addr2, y1;                             \
	ADD   y1, y0;                                \ // y0 = SS2 + W'
	ADD   d, y0;                                 \ // y0 = d + SS2 + W'
	;                                            \
	XOR     a, b, h;                             \
	XOR     c, h;                                \
	ADD     y0, h;                               \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	;                                            \
	XOR      e, f, y1;                           \
	XOR      g, y1;                              \
	ADD      y1, y2;                             \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	;                                            \
	ROTLW    $9, b;                              \
	ROTLW    $19, f;                             \
	;                                            \
	P0(y2, y0, d)

// For rounds [16 - 64)
// addr1 for w, addr2 for w'
#define DO_ROUND_N_1(addr1, addr2, const, a, b, c, d, e, f, g, h) \
	;                                            \
	SS12(a, e, const, y2, y0);                   \
	MOVWZ addr1, y1;                             \
	ADD     y1, y2;                              \ // y2 = SS1 + W
	ADD     h, y2;                               \ // y2 = h + SS1 + W    
	MOVWZ addr2, y1;                             \
	ADD     y1, y0;                              \ // y0 = SS2 + W'
	ADD     d, y0;                               \ // y0 = d + SS2 + W'
	;                                            \
	OR      a, b, y1;                            \
	AND     a, b, h;                             \
	AND     c, y1;                               \
	OR      y1, h;                               \ // h =  (a AND b) OR (a AND c) OR (b AND c)  
	ADD     y0, h;                               \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	;                                            \
	XOR     f, g, y1;                            \
	AND     e, y1;                               \
	XOR     g, y1;                               \ // y1 = GG2(e, f, g)	
	ADD     y1, y2;                              \ // y2 = GG2(e, f, g) + h + SS1 + W = tt2  
	;                                            \
	ROTLW     $9, b;                             \
	ROTLW     $19, f;                            \
	;                                            \
	P0(y2, y0, d)

// r = s <<< n
// Due to VSPLTISW's limitation, the n MUST be [0, 31]
#define PROLD(s, r, n) \
	VSPLTISW $n, XFER \
	VRLW	s, XFER, r

#define MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3) \
	VSLDOI $12, XWORD0, XWORD1, XTMP0; \ // XTMP0 = W[-13] = {w3, w4, w5, w6}
	VRLW XTMP0, V_x07, XTMP1;          \ // XTMP1 = W[-13] rol 7
	VSLDOI $8, XWORD2, XWORD3, XTMP0;  \ // XTMP0 = W[-6] = {w10, w11, w12, w13}
	VXOR XTMP0, XTMP1, XTMP0;          \ // XTMP0 = W[-6] xor (W[-13] rol 7)
	; \ // Prepare P1 parameters
	VSLDOI $12, XWORD1, XWORD2, XTMP1; \ // XTMP1 = W[-9] = {w7, w8, w9, w10}
	VXOR XTMP1, XWORD0, XTMP1;         \ // XTMP1 = W[-9] xor W[-16]
	VSLDOI $4, XWORD3, XWORD2, XTMP3;  \ // XTMP3 = W[-3] = {w13, w14, w15, w8}
	VRLW XTMP3, V_x0F, XTMP2;          \ // XTMP2 = W[-3] rol 15
	VXOR XTMP1, XTMP2, XTMP2;          \ // XTMP2 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {ABxx}
	; \ // P1
	VRLW XTMP2, V_x0F, XTMP4;          \ // XTMP4 = XTMP2 rol 15 {ABxx}
	VRLW XTMP4, V_x08, XTMP3;          \ // XTMP3 = XTMP4 rol 8 {ABxx} = XTMP2 rol 23 {ABxx}
	VXOR XTMP2, XTMP4, XTMP4;          \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {ABxx})
	VXOR XTMP4, XTMP3, XTMP4;          \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {ABxx}) XOR (XTMP2 rol 23 {ABxx})
	; \ // First 2 words message schedule result
	VXOR XTMP4, XTMP0, XTMP2;          \ // XTMP2 = {w[0], w[1], ..., ...}
	; \ // Prepare P1 parameters
	VSLDOI $4, XWORD3, XTMP2, XTMP3;   \ // XTMP3 = W[-3] = {w13, w14, w15, w0}
	VRLW XTMP3, V_x0F, XTMP4;          \ // XTMP4 = W[-3] rol 15
	VXOR XTMP1, XTMP4, XTMP4;		   \ // XTMP4 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {ABCD}
	; \ // P1
	VRLW XTMP4, V_x0F, XTMP3;          \ // XTMP3 = XTMP4 rol 15 {ABCD}
	VRLW XTMP3, V_x08, XTMP1;          \ // XTMP1 = XTMP4 rol 8 {ABCD} = XTMP4 rol 23 {ABCD}
	VXOR XTMP4, XTMP3, XTMP3;          \ // XTMP3 = XTMP4 XOR (XTMP4 rol 15 {ABCD})
	VXOR XTMP3, XTMP1, XTMP1;          \ // XTMP1 = XTMP4 XOR (XTMP4 rol 15 {ABCD}) XOR (XTMP4 rol 23 {ABCD})
	; \ // 4 words message schedule result
	VXOR XTMP1, XTMP0, XWORD0;         \ // XWORD0 = {w[0], w[1], w[2], w[3]}


// func blockASM(dig *digest, p []byte, buffer *uint32)
TEXT ·blockASM(SB), NOSPLIT, $0
#ifdef NEEDS_PERMW
	MOVD	$·flip_mask(SB), TEMP
	LVX	(TEMP), ESPERMW
#endif

	MOVD	dig+0(FP), CTX
	MOVD	p_base+8(FP), INP
	MOVD	p_len+16(FP), LEN
	MOVD	buffer+32(FP), BUFFER

	// We assume p_len >= 64
	SRD	$6, LEN
	MOVD LEN, CTR

	MOVD  $16, R_x010
	MOVD  $32, R_x020
	MOVD  $48, R_x030

	// Load initial digest
	MOVWZ 0(CTX), a
	MOVWZ 4(CTX), b
	MOVWZ 8(CTX), c
	MOVWZ 12(CTX), d
	MOVWZ 16(CTX), e
	MOVWZ 20(CTX), f
	MOVWZ 24(CTX), g
	MOVWZ 28(CTX), h

	VSPLTISW $7, V_x07
	VSPLTISW $8, V_x08
	VSPLTISW $15, V_x0F

loop:
	PPC64X_LXVW4X(INP, R_x000, XWORD0)
	PPC64X_LXVW4X(INP, R_x010, XWORD1)
	PPC64X_LXVW4X(INP, R_x020, XWORD2)
	PPC64X_LXVW4X(INP, R_x030, XWORD3)

	ADD 	$64, INP

schedule_compress: // for w0 - w47
	// Do 4 rounds and scheduling
	STXVW4X XWORD0, (BUFFER)(R_x000)
	VXOR XWORD0, XWORD1, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	DO_ROUND_N_0(0(BUFFER), 16(BUFFER), T0, a, b, c, d, e, f, g, h)
	DO_ROUND_N_0(4(BUFFER), 20(BUFFER), T1, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)
	DO_ROUND_N_0(8(BUFFER), 24(BUFFER), T2, g, h, a, b, c, d, e, f)
	DO_ROUND_N_0(12(BUFFER), 28(BUFFER), T3, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	STXVW4X XWORD1, (BUFFER)(R_x000)
	VXOR XWORD1, XWORD2, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	DO_ROUND_N_0(0(BUFFER), 16(BUFFER), T4, e, f, g, h, a, b, c, d)
	DO_ROUND_N_0(4(BUFFER), 20(BUFFER), T5, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD1, XWORD2, XWORD3, XWORD0)
	DO_ROUND_N_0(8(BUFFER), 24(BUFFER), T6, c, d, e, f, g, h, a, b)
	DO_ROUND_N_0(12(BUFFER), 28(BUFFER), T7, b, c, d, e, f, g, h, a)

	// Do 4 rounds and scheduling
	STXVW4X XWORD2, (BUFFER)(R_x000)
	VXOR XWORD2, XWORD3, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	DO_ROUND_N_0(0(BUFFER), 16(BUFFER), T8, a, b, c, d, e, f, g, h)
	DO_ROUND_N_0(4(BUFFER), 20(BUFFER), T9, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD2, XWORD3, XWORD0, XWORD1)
	DO_ROUND_N_0(8(BUFFER), 24(BUFFER), T10, g, h, a, b, c, d, e, f)
	DO_ROUND_N_0(12(BUFFER), 28(BUFFER), T11, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	STXVW4X XWORD3, (BUFFER)(R_x000)
	VXOR XWORD3, XWORD0, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	DO_ROUND_N_0(0(BUFFER), 16(BUFFER), T12, e, f, g, h, a, b, c, d)
	DO_ROUND_N_0(4(BUFFER), 20(BUFFER), T13, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD3, XWORD0, XWORD1, XWORD2)
	DO_ROUND_N_0(8(BUFFER), 24(BUFFER), T14, c, d, e, f, g, h, a, b)
	DO_ROUND_N_0(12(BUFFER), 28(BUFFER), T15, b, c, d, e, f, g, h, a)

	// Do 4 rounds and scheduling
	STXVW4X XWORD0, (BUFFER)(R_x000)
	VXOR XWORD0, XWORD1, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	DO_ROUND_N_1(0(BUFFER), 16(BUFFER), T16, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(4(BUFFER), 20(BUFFER), T17, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)
	DO_ROUND_N_1(8(BUFFER), 24(BUFFER), T18, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(12(BUFFER), 28(BUFFER), T19, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	STXVW4X XWORD1, (BUFFER)(R_x000)
	VXOR XWORD1, XWORD2, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	DO_ROUND_N_1(0(BUFFER), 16(BUFFER), T20, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(4(BUFFER), 20(BUFFER), T21, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD1, XWORD2, XWORD3, XWORD0)
	DO_ROUND_N_1(8(BUFFER), 24(BUFFER), T22, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(12(BUFFER), 28(BUFFER), T23, b, c, d, e, f, g, h, a)
	
	// Do 4 rounds and scheduling
	STXVW4X XWORD2, (BUFFER)(R_x000)
	VXOR XWORD2, XWORD3, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	DO_ROUND_N_1(0(BUFFER), 16(BUFFER), T24, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(4(BUFFER), 20(BUFFER), T25, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD2, XWORD3, XWORD0, XWORD1)
	DO_ROUND_N_1(8(BUFFER), 24(BUFFER), T26, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(12(BUFFER), 28(BUFFER), T27, f, g, h, a, b, c, d, e)
		
	// Do 4 rounds and scheduling
	STXVW4X XWORD3, (BUFFER)(R_x000)
	VXOR XWORD3, XWORD0, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	DO_ROUND_N_1(0(BUFFER), 16(BUFFER), T28, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(4(BUFFER), 20(BUFFER), T29, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD3, XWORD0, XWORD1, XWORD2)
	DO_ROUND_N_1(8(BUFFER), 24(BUFFER), T30, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(12(BUFFER), 28(BUFFER), T31, b, c, d, e, f, g, h, a)

	// Do 4 rounds and scheduling
	STXVW4X XWORD0, (BUFFER)(R_x000)
	VXOR XWORD0, XWORD1, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	DO_ROUND_N_1(0(BUFFER), 16(BUFFER), T32, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(4(BUFFER), 20(BUFFER), T33, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)
	DO_ROUND_N_1(8(BUFFER), 24(BUFFER), T34, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(12(BUFFER), 28(BUFFER), T35, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	STXVW4X XWORD1, (BUFFER)(R_x000)
	VXOR XWORD1, XWORD2, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	DO_ROUND_N_1(0(BUFFER), 16(BUFFER), T36, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(4(BUFFER), 20(BUFFER), T37, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD1, XWORD2, XWORD3, XWORD0)
	DO_ROUND_N_1(8(BUFFER), 24(BUFFER), T38, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(12(BUFFER), 28(BUFFER), T39, b, c, d, e, f, g, h, a)

	// Do 4 rounds and scheduling
	STXVW4X XWORD2, (BUFFER)(R_x000)
	VXOR XWORD2, XWORD3, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	DO_ROUND_N_1(0(BUFFER), 16(BUFFER), T40, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(4(BUFFER), 20(BUFFER), T41, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD2, XWORD3, XWORD0, XWORD1)
	DO_ROUND_N_1(8(BUFFER), 24(BUFFER), T42, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(12(BUFFER), 28(BUFFER), T43, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	STXVW4X XWORD3, (BUFFER)(R_x000)
	VXOR XWORD3, XWORD0, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	DO_ROUND_N_1(0(BUFFER), 16(BUFFER), T44, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(4(BUFFER), 20(BUFFER), T45, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD3, XWORD0, XWORD1, XWORD2)
	DO_ROUND_N_1(8(BUFFER), 24(BUFFER), T46, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(12(BUFFER), 28(BUFFER), T47, b, c, d, e, f, g, h, a)

	// w48 - w63 processed with only 4 rounds scheduling (last 16 rounds)
	// Do 4 rounds
	STXVW4X XWORD0, (BUFFER)(R_x000)
	VXOR XWORD0, XWORD1, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	DO_ROUND_N_1(0(BUFFER), 16(BUFFER), T48, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(4(BUFFER), 20(BUFFER), T49, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(8(BUFFER), 24(BUFFER), T50, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(12(BUFFER), 28(BUFFER), T51, f, g, h, a, b, c, d, e)

	STXVW4X XWORD1, (BUFFER)(R_x000)
	VXOR XWORD1, XWORD2, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	DO_ROUND_N_1(0(BUFFER), 16(BUFFER), T52, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(4(BUFFER), 20(BUFFER), T53, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(8(BUFFER), 24(BUFFER), T54, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(12(BUFFER), 28(BUFFER), T55, b, c, d, e, f, g, h, a)

	STXVW4X XWORD2, (BUFFER)(R_x000)
	VXOR XWORD2, XWORD3, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)
	DO_ROUND_N_1(0(BUFFER), 16(BUFFER), T56, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(4(BUFFER), 20(BUFFER), T57, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(8(BUFFER), 24(BUFFER), T58, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(12(BUFFER), 28(BUFFER), T59, f, g, h, a, b, c, d, e)

	STXVW4X XWORD3, (BUFFER)(R_x000)
	VXOR XWORD3, XWORD0, XFER
	STXVW4X XFER, (BUFFER)(R_x010)
	DO_ROUND_N_1(0(BUFFER), 16(BUFFER), T60, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(4(BUFFER), 20(BUFFER), T61, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(8(BUFFER), 24(BUFFER), T62, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(12(BUFFER), 28(BUFFER), T63, b, c, d, e, f, g, h, a)

	MOVWZ 0(CTX), TEMP
	XOR TEMP, a
	MOVWZ  a, 0(CTX)

	MOVWZ 4(CTX), TEMP
	XOR TEMP, b
	MOVWZ  b, 4(CTX)

	MOVWZ 8(CTX), TEMP
	XOR TEMP, c
	MOVWZ  c, 8(CTX)

	MOVWZ 12(CTX), TEMP
	XOR TEMP, d
	MOVWZ  d, 12(CTX)

	MOVWZ 16(CTX), TEMP
	XOR TEMP, e
	MOVWZ  e, 16(CTX)

	MOVWZ 20(CTX), TEMP
	XOR TEMP, f
	MOVWZ  f, 20(CTX)

	MOVWZ 24(CTX), TEMP
	XOR TEMP, g
	MOVWZ  g, 24(CTX)

	MOVWZ 28(CTX), TEMP
	XOR TEMP, h
	MOVWZ  h, 28(CTX)

	BDNZ	loop

end:
	RET
