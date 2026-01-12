//go:build !purego

#include "textflag.h"

#include "sm3_const_asm.s"
// Definitions for AVX version

// xorm (mem), reg
// Xor reg to mem using reg-mem xor and store
#define xorm(P1, P2) \
	XORL P2, P1; \
	MOVL P1, P2

#define XWORD0 X4
#define XWORD1 X5
#define XWORD2 X6
#define XWORD3 X7

#define XTMP0 X0
#define XTMP1 X1
#define XTMP2 X2
#define XTMP3 X3
#define XTMP4 X8

#define XFER  X9
#define R08_SHUFFLE_MASK X10
#define X_BYTE_FLIP_MASK X13 // mask to convert LE -> BE

#define NUM_BYTES DX
#define INP	DI

#define CTX SI // Beginning of digest in memory (a, b, c, ... , h)

#define a AX
#define b BX
#define c CX
#define d R8
#define e DX
#define f R9
#define g R10
#define h R11

#define y0 R12
#define y1 R13
#define y2 R14

// Offsets
#define XFER_SIZE 2*16
#define INP_END_SIZE 8

#define _XFER 0
#define _INP_END _XFER + XFER_SIZE
#define STACK_SIZE _INP_END + INP_END_SIZE

#define SS12(a, e, const, ss1, ss2) \
	MOVL     a, ss2;                            \
	ROLL     $12, ss2;                          \ // y0 = a <<< 12
	MOVL     e, ss1;                            \
	ADDL     $const, ss1;                       \
	ADDL     ss2, ss1;                          \ // y2 = a <<< 12 + e + T
	ROLL     $7, ss1;                           \ // y2 = SS1
	XORL     ss1, ss2

#define P0(tt2, tmp, out) \
	MOVL     tt2, tmp;                             \
	ROLL     $9, tmp;                              \
	MOVL     tt2, out;                             \
	ROLL     $17, out;                             \ 
	XORL     tmp, out;                             \
	XORL     tt2, out

// For rounds [0 - 16)
#define DO_ROUND_N_0(disp, idx, const, a, b, c, d, e, f, g, h) \
	;                                            \ // #############################  RND N + 0 ############################//
	SS12(a, e, const, y2, y0);                   \
	ADDL     (disp + idx*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                              \ // y2 = h + SS1 + W    
	ADDL     (disp + idx*4 + 16)(SP), y0;        \ // y0 = SS2 + W'
	ADDL     d, y0;                              \ // y0 = d + SS2 + W'
	;                                            \
	MOVL     a, h;                               \
	XORL     b, h;                               \
	XORL     c, h;                               \
	ADDL     y0, h;                              \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	;                                            \
	MOVL     e, y1;                              \
	XORL     f, y1;                              \
	XORL     g, y1;                              \
	ADDL     y1, y2;                             \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	;                                            \
	ROLL     $9, b;                              \
	ROLL     $19, f;                             \
	;                                            \
	P0(y2, y0, d)

// For rounds [16 - 64)
#define DO_ROUND_N_1(disp, idx, const, a, b, c, d, e, f, g, h) \
	;                                            \ // #############################  RND N + 0 ############################//
	SS12(a, e, const, y2, y0);                   \
	ADDL     (disp + idx*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                              \ // y2 = h + SS1 + W    
	ADDL     (disp + idx*4 + 16)(SP), y0;        \ // y0 = SS2 + W'
	ADDL     d, y0;                              \ // y0 = d + SS2 + W'
	;                                            \
	MOVL     a, y1;                              \
	ORL      b, y1;                              \
	MOVL     a, h;                               \
	ANDL     b, h;                               \
	ANDL     c, y1;                              \
	ORL      y1, h;                              \ // h =  (a AND b) OR (a AND c) OR (b AND c)  
	ADDL     y0, h;                              \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	;                                            \
	MOVL     f, y1;                              \
	XORL     g, y1;                              \
	ANDL     e, y1;                              \
	XORL     g, y1;                              \ // y1 = GG2(e, f, g)	
	ADDL     y1, y2;                             \ // y2 = GG2(e, f, g) + h + SS1 + W = tt2  
	;                                            \
	ROLL     $9, b;                              \
	ROLL     $19, f;                             \
	;                                            \
	P0(y2, y0, d)

// Requires: SSE2, SSSE3
#define MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3) \
	MOVOU  XWORD1, XTMP0;                    \ 
	PALIGNR $12, XWORD0, XTMP0;              \ // XTMP0 = W[-13] = {w6,w5,w4,w3}
	MOVOU  XTMP0, XTMP1;                     \
	PSLLL  $7, XTMP1;                        \
	PSRLL  $(32-7), XTMP0;                   \
	POR    XTMP0, XTMP1;                     \ // XTMP1 = W[-13] rol 7
	MOVOU  XWORD3, XTMP0;                    \
	PALIGNR $8, XWORD2, XTMP0;               \ // XTMP0 = W[-6] = {w13,w12,w11,w10}
	PXOR   XTMP1, XTMP0;                     \ // XTMP0 = W[-6] XOR (W[-13] rol 7) 
	; \ // Prepare P1 parameters 
	MOVOU  XWORD2, XTMP1;                    \
	PALIGNR $12, XWORD1, XTMP1;              \ // XTMP1 = W[-9] = {w10,w9,w8,w7}
	PXOR  XWORD0, XTMP1;                     \ // XTMP1 = W[-9] XOR W[-16]
	PSHUFD $0xA5, XWORD3, XTMP2;             \ // XTMP2 = W[-3] {BBAA} {w14,w14,w13,w13}
	PSRLQ  $17, XTMP2;                       \ // XTMP2 = W[-3] rol 15 {xBxA}
	PXOR  XTMP1, XTMP2;                      \ // XTMP2 = W[-9] XOR W[-16] XOR (W[-3] rol 15) {xxxA}
	; \ // P1
	PSHUFD $0x00, XTMP2, XTMP2;              \ // XTMP2 = {AAAA}
	MOVOU XTMP2, XTMP3;                      \
	PSRLQ  $17, XTMP3;                       \ // XTMP3 = XTMP2 rol 15 {xxxA}
	MOVOU XTMP2, XTMP4;                      \
	PSRLQ  $9, XTMP4;                        \ // XTMP4 = XTMP2 rol 23 {xxxA}
	PXOR  XTMP2, XTMP4;                      \
	PXOR  XTMP3, XTMP4;                      \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {xxxA}) XOR (XTMP2 rol 23 {xxxA})
	; \ // First 1 words message schedule result
	MOVOU XTMP0, XTMP2;                      \
	PXOR  XTMP4, XTMP2;                      \ // XTMP2 = {..., ..., ..., W[0]}
	; \ // Prepare P1 parameters
	PALIGNR  $4, XWORD3, XTMP2;              \ // XTMP2 = {W[0], w15, w14, w13}
	MOVOU XTMP2, XTMP4;                      \
	PSLLL  $15, XTMP4;                       \
	PSRLL  $(32-15), XTMP2;                  \
	POR  XTMP2, XTMP4;                       \ // XTMP4 = W[-3] rol 15 {DCBA}
	PXOR XTMP1, XTMP4;                       \ // XTMP4 = W[-9] XOR W[-16] XOR (W[-3] rol 15) {DCBA}
	; \ // P1
	MOVOU XTMP4, XTMP2;                      \
	PSLLL  $15, XTMP2;                       \
	MOVOU XTMP4, XTMP3;                      \
	PSRLL  $(32-15), XTMP3;                  \
	POR  XTMP2, XTMP3;                       \ // XTMP3 = XTMP4 rol 15 {DCBA}
	MOVOU XTMP3, XTMP1;                      \
	PSHUFB  r08_mask<>(SB), XTMP1;           \ // XTMP1 = XTMP4 rol 23 {DCBA}
	PXOR XTMP4, XTMP3;                       \
	PXOR XTMP3, XTMP1;                       \ // XTMP1 = XTMP4 XOR (XTMP4 rol 15 {DCBA}) XOR (XTMP4 rol 23 {DCBA})
	; \ // 4 words message schedule result
	MOVOU XTMP0, XWORD0;                     \
	PXOR XTMP1, XWORD0

TEXT ·blockSIMD(SB), 0, $48-32
	MOVQ dig+0(FP), CTX          // d.h[8]
	MOVQ p_base+8(FP), INP
	MOVQ p_len+16(FP), NUM_BYTES

	LEAQ -64(INP)(NUM_BYTES*1), NUM_BYTES // Pointer to the last block
	MOVQ NUM_BYTES, _INP_END(SP)

	// Load initial digest
	MOVL 0(CTX), a  // a = H0
	MOVL 4(CTX), b  // b = H1
	MOVL 8(CTX), c  // c = H2
	MOVL 12(CTX), d // d = H3
	MOVL 16(CTX), e // e = H4
	MOVL 20(CTX), f // f = H5
	MOVL 24(CTX), g // g = H6
	MOVL 28(CTX), h // h = H7

	MOVOU flip_mask<>(SB), X_BYTE_FLIP_MASK
	MOVOU r08_mask<>(SB), R08_SHUFFLE_MASK

sse_loop: // at each iteration works with one block (512 bit)
	MOVOU 0(INP), XWORD0
	MOVOU 16(INP), XWORD1
	MOVOU 32(INP), XWORD2
	MOVOU 48(INP), XWORD3

	PSHUFB X_BYTE_FLIP_MASK, XWORD0 // w3,  w2,  w1,  w0
	PSHUFB X_BYTE_FLIP_MASK, XWORD1 // w7,  w6,  w5,  w4
	PSHUFB X_BYTE_FLIP_MASK, XWORD2 // w11, w10,  w9,  w8
	PSHUFB X_BYTE_FLIP_MASK, XWORD3 // w15, w14, w13, w12

	ADDQ $64, INP

sse_schedule_compress: // for w0 - w47
	// Do 4 rounds and scheduling
	MOVOU XWORD0, (_XFER + 0*16)(SP)
	MOVOU XWORD1, XFER
	PXOR  XWORD0, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_0(_XFER, 0, T0, a, b, c, d, e, f, g, h)
	DO_ROUND_N_0(_XFER, 1, T1, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)
	DO_ROUND_N_0(_XFER, 2, T2, g, h, a, b, c, d, e, f)
	DO_ROUND_N_0(_XFER, 3, T3, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	MOVOU XWORD1, (_XFER + 0*16)(SP)
	MOVOU XWORD2, XFER
	PXOR  XWORD1, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_0(_XFER, 0, T4, e, f, g, h, a, b, c, d)
	DO_ROUND_N_0(_XFER, 1, T5, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD1, XWORD2, XWORD3, XWORD0)
	DO_ROUND_N_0(_XFER, 2, T6, c, d, e, f, g, h, a, b)
	DO_ROUND_N_0(_XFER, 3, T7, b, c, d, e, f, g, h, a)

	// Do 4 rounds and scheduling
	MOVOU XWORD2, (_XFER + 0*16)(SP)
	MOVOU XWORD3, XFER
	PXOR  XWORD2, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_0(_XFER, 0, T8, a, b, c, d, e, f, g, h)
	DO_ROUND_N_0(_XFER, 1, T9, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD2, XWORD3, XWORD0, XWORD1)
	DO_ROUND_N_0(_XFER, 2, T10, g, h, a, b, c, d, e, f)
	DO_ROUND_N_0(_XFER, 3, T11, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	MOVOU XWORD3, (_XFER + 0*16)(SP)
	MOVOU XWORD0, XFER
	PXOR  XWORD3, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_0(_XFER, 0, T12, e, f, g, h, a, b, c, d)
	DO_ROUND_N_0(_XFER, 1, T13, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD3, XWORD0, XWORD1, XWORD2)
	DO_ROUND_N_0(_XFER, 2, T14, c, d, e, f, g, h, a, b)
	DO_ROUND_N_0(_XFER, 3, T15, b, c, d, e, f, g, h, a)

	// Do 4 rounds and scheduling
	MOVOU XWORD0, (_XFER + 0*16)(SP)
	MOVOU XWORD1, XFER
	PXOR  XWORD0, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_1(_XFER, 0, T16, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER, 1, T17, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)
	DO_ROUND_N_1(_XFER, 2, T18, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER, 3, T19, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	MOVOU XWORD1, (_XFER + 0*16)(SP)
	MOVOU XWORD2, XFER
	PXOR  XWORD1, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_1(_XFER, 0, T20, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER, 1, T21, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD1, XWORD2, XWORD3, XWORD0)
	DO_ROUND_N_1(_XFER, 2, T22, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER, 3, T23, b, c, d, e, f, g, h, a)

	// Do 4 rounds and scheduling
	MOVOU XWORD2, (_XFER + 0*16)(SP)
	MOVOU XWORD3, XFER
	PXOR  XWORD2, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_1(_XFER, 0, T24, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER, 1, T25, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD2, XWORD3, XWORD0, XWORD1)
	DO_ROUND_N_1(_XFER, 2, T26, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER, 3, T27, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	MOVOU XWORD3, (_XFER + 0*16)(SP)
	MOVOU XWORD0, XFER
	PXOR  XWORD3, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_1(_XFER, 0, T28, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER, 1, T29, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD3, XWORD0, XWORD1, XWORD2)
	DO_ROUND_N_1(_XFER, 2, T30, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER, 3, T31, b, c, d, e, f, g, h, a)

	// Do 4 rounds and scheduling
	MOVOU XWORD0, (_XFER + 0*16)(SP)
	MOVOU XWORD1, XFER
	PXOR  XWORD0, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_1(_XFER, 0, T32, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER, 1, T33, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)
	DO_ROUND_N_1(_XFER, 2, T34, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER, 3, T35, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	MOVOU XWORD1, (_XFER + 0*16)(SP)
	MOVOU XWORD2, XFER
	PXOR  XWORD1, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_1(_XFER, 0, T36, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER, 1, T37, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD1, XWORD2, XWORD3, XWORD0)
	DO_ROUND_N_1(_XFER, 2, T38, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER, 3, T39, b, c, d, e, f, g, h, a)

	// Do 4 rounds and scheduling
	MOVOU XWORD2, (_XFER + 0*16)(SP)
	MOVOU XWORD3, XFER
	PXOR  XWORD2, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_1(_XFER, 0, T40, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER, 1, T41, h, a, b, c, d, e, f, g)
	MESSAGE_SCHEDULE(XWORD2, XWORD3, XWORD0, XWORD1)
	DO_ROUND_N_1(_XFER, 2, T42, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER, 3, T43, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
	MOVOU XWORD3, (_XFER + 0*16)(SP)
	MOVOU XWORD0, XFER
	PXOR  XWORD3, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_1(_XFER, 0, T44, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER, 1, T45, d, e, f, g, h, a, b, c)
	MESSAGE_SCHEDULE(XWORD3, XWORD0, XWORD1, XWORD2)
	DO_ROUND_N_1(_XFER, 2, T46, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER, 3, T47, b, c, d, e, f, g, h, a)

	// w48 - w63 processed with only 4 rounds scheduling (last 16 rounds)
	// Do 4 rounds
	MOVOU XWORD0, (_XFER + 0*16)(SP)
	MOVOU XWORD1, XFER
	PXOR  XWORD0, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_1(_XFER, 0, T48, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER, 1, T49, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER, 2, T50, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER, 3, T51, f, g, h, a, b, c, d, e)

	// Do 4 rounds
	MOVOU XWORD1, (_XFER + 0*16)(SP)
	MOVOU XWORD2, XFER
	PXOR  XWORD1, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_1(_XFER, 0, T52, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER, 1, T53, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER, 2, T54, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER, 3, T55, b, c, d, e, f, g, h, a)

	// Do 4 rounds
	MOVOU XWORD2, (_XFER + 0*16)(SP)
	MOVOU XWORD3, XFER
	PXOR  XWORD2, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	MESSAGE_SCHEDULE(XWORD0, XWORD1, XWORD2, XWORD3)
	DO_ROUND_N_1(_XFER, 0, T56, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER, 1, T57, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER, 2, T58, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER, 3, T59, f, g, h, a, b, c, d, e)

	// Do 4 rounds
	MOVOU XWORD3, (_XFER + 0*16)(SP)
	MOVOU XWORD0, XFER
	PXOR  XWORD3, XFER
	MOVOU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_1(_XFER, 0, T60, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER, 1, T61, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER, 2, T62, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER, 3, T63, b, c, d, e, f, g, h, a)

	xorm(  0(CTX), a)
	xorm(  4(CTX), b)
	xorm(  8(CTX), c)
	xorm( 12(CTX), d)
	xorm( 16(CTX), e)
	xorm( 20(CTX), f)
	xorm( 24(CTX), g)
	xorm( 28(CTX), h)

	CMPQ _INP_END(SP), INP
	JAE   sse_loop

sse_done_hash:
	RET

// shuffle byte order from LE to BE
DATA flip_mask<>+0x00(SB)/8, $0x0405060700010203
DATA flip_mask<>+0x08(SB)/8, $0x0c0d0e0f08090a0b
GLOBL flip_mask<>(SB), 8, $16

DATA r08_mask<>+0x00(SB)/8, $0x0605040702010003
DATA r08_mask<>+0x08(SB)/8, $0x0E0D0C0F0A09080B
GLOBL r08_mask<>(SB), 8, $16
