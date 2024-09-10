// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"
#include "sm3_const_asm.s"

#define a R1
#define b R2
#define c R3
#define d R4
#define e R5
#define f R6
#define g R7
#define h R8

#define CTX	R9
#define INP	R10
#define LEN	R11
#define END R12

#define y0 R9
#define y1 R11
#define y2 R12

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

#define SS12(a, e, const, ss1, ss2) \
	RLL     $12, a, ss2;                       \ // y0 = a <<< 12
	ADD     $const, e, ss1;                    \
	ADD     ss2, ss1;                          \ // y2 = a <<< 12 + e + T
	RLL     $7, ss1;                           \ // y2 = SS1
	XOR     ss1, ss2

#define P0(tt2, tmp, out) \
	RLL     $9, tt2, tmp;                        \
	RLL     $17, tt2, out;                       \
	XOR     tmp, out;                            \
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
	RLL    $9, b;                                \
	RLL    $19, f;                               \
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
	RLL     $9, b;                               \
	RLL     $19, f;                              \
	;                                            \
	P0(y2, y0, d)

// r = s <<< n
#define PROLD(s, r, n) \
	VERLLF $n, s, r

#define MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3) \
	VSLDB $12, XWORD0, XWORD1, XTMP0;  \ // XTMP0 = W[-13] = {w3, w4, w5, w6}
	PROLD(XTMP0, XTMP1, 7);            \ // XTMP1 = W[-13] rol 7
	VSLDB $8, XWORD2, XWORD3, XTMP0;   \ // XTMP0 = W[-6] = {w10, w11, w12, w13}
	VX XTMP0, XTMP1, XTMP0;            \ // XTMP0 = W[-6] xor (W[-13] rol 7)
	; \ // Prepare P1 parameters
	VSLDB $12, XWORD1, XWORD2, XTMP1;  \ // XTMP1 = W[-9] = {w7, w8, w9, w10}
	VX XTMP1, XWORD0, XTMP1;           \ // XTMP1 = W[-9] xor W[-16]
	VSLDB $4, XWORD3, XWORD2, XTMP3;   \ // XTMP3 = W[-3] = {w13, w14, w15, w8}
	PROLD(XTMP3, XTMP2, 15);           \ // XTMP2 = W[-3] rol 15
	VX XTMP1, XTMP2, XTMP2;            \ // XTMP2 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {ABxx}
	; \ // P1
	PROLD(XTMP2, XTMP4, 15);           \ // XTMP4 =  = XTMP2 rol 15 {ABxx}
	PROLD(XTMP4, XTMP3, 8);            \ // XTMP3 = XTMP2 rol 23 {ABxx}
	VX XTMP2, XTMP4, XTMP4;            \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {ABxx})
	VX XTMP4, XTMP3, XTMP4;            \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {ABxx}) XOR (XTMP2 rol 23 {ABxx})
	; \ // First 2 words message schedule result
	VX XTMP4, XTMP0, XTMP2;            \ // XTMP2 = {w[0], w[1], ..., ...}
	; \ // Prepare P1 parameters
	VSLDB $4, XWORD3, XTMP2, XTMP3;    \ // XTMP3 = W[-3] = {w13, w14, w15, w0}
	PROLD(XTMP3, XTMP4, 15);           \ // XTMP4 = W[-3] rol 15
	VX XTMP1, XTMP4, XTMP4;		       \ // XTMP4 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {ABCD}
	; \ // P1
	PROLD(XTMP4, XTMP3, 15);           \ // XTMP3 =  = XTMP4 rol 15 {ABCD}
	PROLD(XTMP3, XTMP1, 8);            \ // XTMP1 = XTMP4 rol 23 {ABCD}
	VX XTMP4, XTMP3, XTMP3;            \ // XTMP3 = XTMP4 XOR (XTMP4 rol 15 {ABCD})
	VX XTMP3, XTMP1, XTMP1;            \ // XTMP1 = XTMP4 XOR (XTMP4 rol 15 {ABCD}) XOR (XTMP4 rol 23 {ABCD})
	; \ // 4 words message schedule result
	VX XTMP1, XTMP0, XWORD0;           \ // XWORD0 = {w[0], w[1], w[2], w[3]}

// For the usage of tmp-xx(SP), I referred to the code of
// https://github.com/golang/go/blob/master/src/crypto/md5/md5block_s390x.s
//
// func block(dig *digest, p []byte)
TEXT ·block(SB),NOSPLIT,$72-32
	MOVD	dig+0(FP), CTX
	MOVD	p+8(FP), INP
	MOVD	p_len+16(FP), LEN
	AND	$-64, LEN
	LAY	(INP)(LEN*1), END

	CMPBEQ	INP, END, end
	MOVD END, tmp-8(SP) // backup END
	LMY 0(CTX), a, h

loop:
	STMY	a, h, tmp-40(SP) // backup state
	VLM (INP), XWORD0, XWORD3

schedule_compress: // for w0 - w47
	// Do 4 rounds and scheduling
	VST XWORD0, tmp-56(SP)
	VX  XWORD0, XWORD1, XFER
	VST XFER, tmp-72(SP)
	DO_ROUND_N_0(tmp-56(SP), tmp-72(SP), T0, a, b, c, d, e, f, g, h)
	DO_ROUND_N_0(tmp-52(SP), tmp-68(SP), T1, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)
	DO_ROUND_N_0(tmp-48(SP), tmp-64(SP), T2, g, h, a, b, c, d, e, f)
	DO_ROUND_N_0(tmp-44(SP), tmp-60(SP), T3, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	VST XWORD1, tmp-56(SP)
	VX XWORD1, XWORD2, XFER
	VST XFER, tmp-72(SP)
	DO_ROUND_N_0(tmp-56(SP), tmp-72(SP), T4, e, f, g, h, a, b, c, d)
	DO_ROUND_N_0(tmp-52(SP), tmp-68(SP), T5, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD1, XWORD2, XWORD3, XWORD0)
	DO_ROUND_N_0(tmp-48(SP), tmp-64(SP), T6, c, d, e, f, g, h, a, b)
	DO_ROUND_N_0(tmp-44(SP), tmp-60(SP), T7, b, c, d, e, f, g, h, a)

	// Do 4 rounds and scheduling
	VST XWORD2, tmp-56(SP)
	VX XWORD2, XWORD3, XFER
	VST XFER, tmp-72(SP)
	DO_ROUND_N_0(tmp-56(SP), tmp-72(SP), T8, a, b, c, d, e, f, g, h)
	DO_ROUND_N_0(tmp-52(SP), tmp-68(SP), T9, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD2, XWORD3, XWORD0, XWORD1)
	DO_ROUND_N_0(tmp-48(SP), tmp-64(SP), T10, g, h, a, b, c, d, e, f)
	DO_ROUND_N_0(tmp-44(SP), tmp-60(SP), T11, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	VST XWORD3, tmp-56(SP)
	VX XWORD3, XWORD0, XFER
	VST XFER, tmp-72(SP)
	DO_ROUND_N_0(tmp-56(SP), tmp-72(SP), T12, e, f, g, h, a, b, c, d)
	DO_ROUND_N_0(tmp-52(SP), tmp-68(SP), T13, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD3, XWORD0, XWORD1, XWORD2)
	DO_ROUND_N_0(tmp-48(SP), tmp-64(SP), T14, c, d, e, f, g, h, a, b)
	DO_ROUND_N_0(tmp-44(SP), tmp-60(SP), T15, b, c, d, e, f, g, h, a)

	// Do 4 rounds and scheduling
	VST XWORD0, tmp-56(SP)
	VX XWORD0, XWORD1, XFER
	VST XFER, tmp-72(SP)
	DO_ROUND_N_1(tmp-56(SP), tmp-72(SP), T16, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(tmp-52(SP), tmp-68(SP), T17, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)
	DO_ROUND_N_1(tmp-48(SP), tmp-64(SP), T18, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(tmp-44(SP), tmp-60(SP), T19, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	VST XWORD1, tmp-56(SP)
	VX XWORD1, XWORD2, XFER
	VST XFER, tmp-72(SP)
	DO_ROUND_N_1(tmp-56(SP), tmp-72(SP), T20, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(tmp-52(SP), tmp-68(SP), T21, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD1, XWORD2, XWORD3, XWORD0)
	DO_ROUND_N_1(tmp-48(SP), tmp-64(SP), T22, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(tmp-44(SP), tmp-60(SP), T23, b, c, d, e, f, g, h, a)
	
	// Do 4 rounds and scheduling
	VST XWORD2, tmp-56(SP)
	VX XWORD2, XWORD3, XFER
	VST XFER, tmp-72(SP)
	DO_ROUND_N_1(tmp-56(SP), tmp-72(SP), T24, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(tmp-52(SP), tmp-68(SP), T25, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD2, XWORD3, XWORD0, XWORD1)
	DO_ROUND_N_1(tmp-48(SP), tmp-64(SP), T26, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(tmp-44(SP), tmp-60(SP), T27, f, g, h, a, b, c, d, e)
		
	// Do 4 rounds and scheduling
	VST XWORD3, tmp-56(SP)
	VX XWORD3, XWORD0, XFER
	VST XFER, tmp-72(SP)
	DO_ROUND_N_1(tmp-56(SP), tmp-72(SP), T28, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(tmp-52(SP), tmp-68(SP), T29, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD3, XWORD0, XWORD1, XWORD2)
	DO_ROUND_N_1(tmp-48(SP), tmp-64(SP), T30, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(tmp-44(SP), tmp-60(SP), T31, b, c, d, e, f, g, h, a)

	// Do 4 rounds and scheduling
	VST XWORD0, tmp-56(SP)
	VX XWORD0, XWORD1, XFER
	VST XFER, tmp-72(SP)
	DO_ROUND_N_1(tmp-56(SP), tmp-72(SP), T32, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(tmp-52(SP), tmp-68(SP), T33, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)
	DO_ROUND_N_1(tmp-48(SP), tmp-64(SP), T34, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(tmp-44(SP), tmp-60(SP), T35, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	VST XWORD1, tmp-56(SP)
	VX XWORD1, XWORD2, XFER
	VST XFER, tmp-72(SP)
	DO_ROUND_N_1(tmp-56(SP), tmp-72(SP), T36, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(tmp-52(SP), tmp-68(SP), T37, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD1, XWORD2, XWORD3, XWORD0)
	DO_ROUND_N_1(tmp-48(SP), tmp-64(SP), T38, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(tmp-44(SP), tmp-60(SP), T39, b, c, d, e, f, g, h, a)

	// Do 4 rounds and scheduling
	VST XWORD2, tmp-56(SP)
	VX XWORD2, XWORD3, XFER
	VST XFER, tmp-72(SP)
	DO_ROUND_N_1(tmp-56(SP), tmp-72(SP), T40, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(tmp-52(SP), tmp-68(SP), T41, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD2, XWORD3, XWORD0, XWORD1)
	DO_ROUND_N_1(tmp-48(SP), tmp-64(SP), T42, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(tmp-44(SP), tmp-60(SP), T43, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	VST XWORD3, tmp-56(SP)
	VX XWORD3, XWORD0, XFER
	VST XFER, tmp-72(SP)
	DO_ROUND_N_1(tmp-56(SP), tmp-72(SP), T44, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(tmp-52(SP), tmp-68(SP), T45, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD3, XWORD0, XWORD1, XWORD2)
	DO_ROUND_N_1(tmp-48(SP), tmp-64(SP), T46, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(tmp-44(SP), tmp-60(SP), T47, b, c, d, e, f, g, h, a)

	// w48 - w63 processed with only 4 rounds scheduling (last 16 rounds)
	// Do 4 rounds
	VST XWORD0, tmp-56(SP)
	VX XWORD0, XWORD1, XFER
	VST XFER, tmp-72(SP)
	DO_ROUND_N_1(tmp-56(SP), tmp-72(SP), T48, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(tmp-52(SP), tmp-68(SP), T49, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(tmp-48(SP), tmp-64(SP), T50, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(tmp-44(SP), tmp-60(SP), T51, f, g, h, a, b, c, d, e)

	VST XWORD1, tmp-56(SP)
	VX XWORD1, XWORD2, XFER
	VST XFER, tmp-72(SP)
	DO_ROUND_N_1(tmp-56(SP), tmp-72(SP), T52, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(tmp-52(SP), tmp-68(SP), T53, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(tmp-48(SP), tmp-64(SP), T54, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(tmp-44(SP), tmp-60(SP), T55, b, c, d, e, f, g, h, a)

	VST XWORD2, tmp-56(SP)
	VX XWORD2, XWORD3, XFER
	VST XFER, tmp-72(SP)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)
	DO_ROUND_N_1(tmp-56(SP), tmp-72(SP), T56, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(tmp-52(SP), tmp-68(SP), T57, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(tmp-48(SP), tmp-64(SP), T58, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(tmp-44(SP), tmp-60(SP), T59, f, g, h, a, b, c, d, e)

	VST XWORD3, tmp-56(SP)
	VX XWORD3, XWORD0, XFER
	VST XFER, tmp-72(SP)
	DO_ROUND_N_1(tmp-56(SP), tmp-72(SP), T60, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(tmp-52(SP), tmp-68(SP), T61, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(tmp-48(SP), tmp-64(SP), T62, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(tmp-44(SP), tmp-60(SP), T63, b, c, d, e, f, g, h, a)

	MOVWZ tmp-40(SP), END
	XOR END, a
	MOVWZ tmp-36(SP), END
	XOR END, b
	MOVWZ tmp-32(SP), END
	XOR END, c
	MOVWZ tmp-28(SP), END
	XOR END, d
	MOVWZ tmp-24(SP), END
	XOR END, e
	MOVWZ tmp-20(SP), END
	XOR END, f
	MOVWZ tmp-16(SP), END
	XOR END, g
	MOVWZ tmp-12(SP), END
	XOR END, h

	LA	64(INP), INP
	MOVD tmp-8(SP), END
	CMPBLT	INP, END, loop

end:
	MOVD	dig+0(FP), CTX
	STMY	a, h, 0(CTX)
	RET
