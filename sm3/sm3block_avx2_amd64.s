//go:build amd64 && !purego
// +build amd64,!purego

#include "textflag.h"

// Definitions for AVX2 version

// xorm (mem), reg
// Xor reg to mem using reg-mem xor and store
#define xorm(P1, P2) \
	XORL P2, P1; \
	MOVL P1, P2

#define XDWORD0 Y4
#define XDWORD1 Y5
#define XDWORD2 Y6
#define XDWORD3 Y7

#define XWORD0 X4
#define XWORD1 X5
#define XWORD2 X6
#define XWORD3 X7

#define XTMP0 Y0
#define XTMP1 Y1
#define XTMP2 Y2
#define XTMP3 Y3
#define XTMP4 Y8
#define XTMP5 Y11

#define XFER  Y9

#define BYTE_FLIP_MASK 	Y13 // mask to convert LE -> BE
#define X_BYTE_FLIP_MASK X13

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

#define SRND SI // SRND is same register as CTX

#define y0 R12
#define y1 R13
#define y2 R14
#define y3 DI

// Offsets
#define XFER_SIZE 4*64*4
#define INP_END_SIZE 8
#define INP_SIZE 8

#define _XFER 0
#define _INP_END _XFER + XFER_SIZE
#define _INP _INP_END + INP_END_SIZE
#define STACK_SIZE _INP + INP_SIZE

// For rounds [0 - 16)
#define ROUND_AND_SCHED_N_0_0(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 0 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12, RORXL is BMI2 instr
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	VPALIGNR $12, XDWORD0, XDWORD1, XTMP0;     \ // XTMP0 = W[-13] = {w6,w5,w4,w3}
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                           \ // y2 = SS1
	VPSLLD   $7, XTMP0, XTMP1;                 \ // XTMP1 = W[-13] << 7 = {w6<<7,w5<<7,w4<<7,w3<<7}
	XORL     y2, y0                            \ // y0 = SS2
	ADDL     (disp + 0*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
	VPSRLD   $(32-7), XTMP0, XTMP0;            \ // XTMP0 = W[-13] >> 25 = {w6>>25,w5>>25,w4>>25,w3>>25}
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	ADDL     (disp + 0*4 + 32)(SP)(SRND*1), y0;\ // y0 = SS2 + W'
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	VPOR     XTMP0, XTMP1, XTMP1;              \ // XTMP1 = W[-13] rol 7
	;                                          \
	MOVL     a, h;                             \
	XORL     b, h;                             \
	XORL     c, h;                             \
	VPALIGNR $8, XDWORD2, XDWORD3, XTMP0;      \ // XTMP0 = W[-6] = {w13,w12,w11,w10}
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	;                                          \
	MOVL     e, y1;                            \
	VPXOR   XTMP1, XTMP0, XTMP0;               \ // XTMP0 = W[-6] ^ (W[-13] rol 7)
	XORL     f, y1;                            \
	XORL     g, y1;                            \
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	VPALIGNR $12, XDWORD1, XDWORD2, XTMP1;     \ // XTMP1 = W[-9] = {w10,w9,w8,w7}
	;                                          \
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	;                                          \
	RORXL    $23, y2, y0;                      \
	VPXOR XDWORD0, XTMP1, XTMP1;               \ // XTMP1 = W[-9] ^ W[-16]
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPSHUFD $0xA5, XDWORD3, XTMP2;             \ // XTMP2 = W[-3] {BBAA} {w14,w14,w13,w13}

#define ROUND_AND_SCHED_N_0_1(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 1 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	VPSLLQ  $15, XTMP2, XTMP2;                 \ // XTMP2 = W[-3] rol 15 {BxAx}
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	VPSHUFB shuff_00BA<>(SB), XTMP2, XTMP2;    \ // XTMP2 = W[-3] rol 15 {00BA}
	ADDL     (disp + 1*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W
	ADDL     (disp + 1*4 + 32)(SP)(SRND*1), y0;\ // y0 = SS2 + W'
	VPXOR   XTMP1, XTMP2, XTMP2;               \ // XTMP2 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {xxBA}
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
	MOVL     a, h;                             \
	XORL     b, h;                             \
	VPSLLD   $15, XTMP2, XTMP3;                \
	XORL     c, h;                             \
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	;                                          \
	MOVL     e, y1;                            \
	VPSRLD   $(32-15), XTMP2, XTMP4;           \
	XORL     f, y1;                            \
	XORL     g, y1;                            \
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2
	VPOR     XTMP3, XTMP4, XTMP4;              \ // XTMP4 = XTMP2 rol 15 {xxBA}
	;                                          \
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	;                                          \
	RORXL    $23, y2, y0;                      \
	VPSHUFB  r08_mask<>(SB), XTMP4, XTMP3;     \ // XTMP3 = XTMP2 rol 23 {DCxx}
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPXOR    XTMP2, XTMP4, XTMP4;              \ // XTMP4 = XTMP2 ^ (XTMP2 rol 15 {xxBA})

#define ROUND_AND_SCHED_N_0_2(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 2 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	VPXOR    XTMP4, XTMP3, XTMP4;              \ // XTMP4 = XTMP2 ^ (XTMP2 rol 15 {xxBA}) ^ (XTMP2 rol 23 {xxBA})
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	VPXOR    XTMP4, XTMP0, XTMP2;              \ // XTMP2 = {..., ..., W[1], W[0]}
	ADDL     (disp + 2*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W
	ADDL     (disp + 2*4 + 32)(SP)(SRND*1), y0;\ // y0 = SS2 + W'
	VPALIGNR $12, XDWORD3, XTMP2, XTMP3;       \ // XTMP3 = {..., W[1], W[0], w15}
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
	MOVL     a, h;                             \
	XORL     b, h;                             \
	VPSHUFD $80, XTMP3, XTMP4;                 \ // XTMP4 =  = W[-3] {DDCC}
	XORL     c, h;                             \
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	;                                          \
	MOVL     e, y1;                            \
	VPSLLQ  $15, XTMP4, XTMP4;                 \ // XTMP4 = W[-3] rol 15 {DxCx}
	XORL     f, y1;                            \
	XORL     g, y1;                            \
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	;                                          \
	VPSHUFB shuff_DC00<>(SB), XTMP4, XTMP4;    \ // XTMP4 = W[-3] rol 15 {DC00}
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	;                                          \
	RORXL    $23, y2, y0;                      \
	VPXOR   XTMP1, XTMP4, XTMP4;               \ // XTMP4 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {DCxx}
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPSLLD   $15, XTMP4, XTMP5;

#define ROUND_AND_SCHED_N_0_3(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 3 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	VPSRLD   $(32-15), XTMP4, XTMP3;           \
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	VPOR     XTMP3, XTMP5, XTMP3;              \ // XTMP3 = XTMP4 rol 15 {DCxx}
	ADDL     (disp + 3*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	ADDL     (disp + 3*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
	VPSHUFB  r08_mask<>(SB), XTMP3, XTMP1;     \ // XTMP1 = XTMP4 rol 23 {DCxx}
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
	MOVL     a, h;                             \
	XORL     b, h;                             \
	VPXOR    XTMP3, XTMP4, XTMP3;              \ // XTMP3 = XTMP4 ^ (XTMP4 rol 15 {DCxx})
	XORL     c, h;                             \
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	;                                          \
	MOVL     e, y1;                            \
	VPXOR    XTMP3, XTMP1, XTMP1;              \ // XTMP1 = XTMP4 ^ (XTMP4 rol 15 {DCxx}) ^ (XTMP4 rol 23 {DCxx})
	XORL     f, y1;                            \
	XORL     g, y1;                            \
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	;                                          \
	VPXOR    XTMP1, XTMP0, XTMP1;              \ // XTMP1 = {W[3], W[2], ..., ...}
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	;                                          \
	RORXL    $23, y2, y0;                      \
	VPALIGNR $8, XTMP1, XTMP2, XTMP3;          \ // XTMP3 = {W[1], W[0], W[3], W[2]}
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPSHUFD $0x4E, XTMP3, XDWORD0;             \ // XDWORD0 = {W[3], W[2], W[1], W[0]}

// For rounds [16 - 64)
#define ROUND_AND_SCHED_N_1_0(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 0 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	VPALIGNR $12, XDWORD0, XDWORD1, XTMP0;     \ // XTMP0 = W[-13] = {w6,w5,w4,w3}
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	VPSLLD   $7, XTMP0, XTMP1;                 \ // XTMP1 = W[-13] << 7 = {w6<<7,w5<<7,w4<<7,w3<<7}
	ADDL     (disp + 0*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	ADDL     (disp + 0*4 + 32)(SP)(SRND*1), y0;\ // y0 = SS2 + W'
	VPSRLD   $(32-7), XTMP0, XTMP0;            \ // XTMP0 = W[-13] >> 25 = {w6>>25,w5>>25,w4>>25,w3>>25}
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
	MOVL     a, y1;                            \
	MOVL     b, y3;                            \
	VPOR     XTMP0, XTMP1, XTMP1;              \ // XTMP1 = W[-13] rol 7 = {ROTL(7,w6),ROTL(7,w5),ROTL(7,w4),ROTL(7,w3)}
	ANDL     y1, y3;                           \
	ANDL     c, y1;                            \
	ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c)
	MOVL     b, h;                             \
	VPALIGNR $8, XDWORD2, XDWORD3, XTMP0;      \ // XTMP0 = W[-6] = {w13,w12,w11,w10}
	ANDL     c, h;                             \
	ORL      y1, h;                            \ // h =  (a AND b) OR (a AND c) OR (b AND c)
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	;                                          \
	VPXOR   XTMP1, XTMP0, XTMP0;               \ // XTMP0 = W[-6] ^ (W[-13] rol 7) 
	MOVL     f, y3;                            \
	ANDL     e, y3;                            \ // y3 = e AND f
	ANDNL    g, e, y1;                         \ // y1 = NOT(e) AND g
	VPALIGNR $12, XDWORD1, XDWORD2, XTMP1;     \ // XTMP1 = W[-9] = {w10,w9,w8,w7}
	ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	;                                          \
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPXOR XDWORD0, XTMP1, XTMP1;               \ // XTMP1 = W[-9] ^ W[-16]
	;                                          \
	RORXL    $23, y2, y0;                      \
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPSHUFD $0xA5, XDWORD3, XTMP2;             \ // XTMP2 = W[-3] {BBAA} {w14,w14,w13,w13}

#define ROUND_AND_SCHED_N_1_1(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 1 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	VPSLLQ  $15, XTMP2, XTMP2;                 \ // XTMP2 = W[-3] rol 15 {BxAx}
	ROLL    $7, y2;                            \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	ADDL     (disp + 1*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	VPSHUFB shuff_00BA<>(SB), XTMP2, XTMP2;    \ // XTMP2 = W[-3] rol 15 {00BA}
	ADDL     (disp + 1*4 + 32)(SP)(SRND*1), y0;\ // y0 = SS2 + W'
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
	MOVL     a, y1;                            \
	MOVL     b, y3;                            \
	VPXOR   XTMP1, XTMP2, XTMP2;               \ // XTMP2 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {xxBA}
	ANDL     y1, y3;                           \
	ANDL     c, y1;                            \
	ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c)
	MOVL     b, h;                             \
	VPSLLD   $15, XTMP2, XTMP3;                \
	ANDL     c, h;                             \
	ORL      y1, h;                            \ // h =  (a AND b) OR (a AND c) OR (b AND c)
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	;                                          \
	VPSRLD   $(32-15), XTMP2, XTMP4;           \
	MOVL     f, y3;                            \
	ANDL     e, y3;                            \ // y3 = e AND f
	ANDNL    g, e, y1;                         \ // y1 = NOT(e) AND g
	VPOR     XTMP3, XTMP4, XTMP4;              \ // XTMP4 = XTMP2 rol 15 {xxBA}
	ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	;                                          \
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPSHUFB  r08_mask<>(SB), XTMP4, XTMP3;     \ // XTMP3 = XTMP2 rol 23 {xxBA}
	;                                          \
	RORXL    $23, y2, y0;                      \
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPXOR    XTMP2, XTMP4, XTMP4;              \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {xxBA})

#define ROUND_AND_SCHED_N_1_2(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 2 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	VPXOR    XTMP4, XTMP3, XTMP4;              \ // XTMP4 = XTMP2 ^ (XTMP2 rol 15 {xxBA}) ^ (XTMP2 rol 23 {xxBA})
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	ADDL     (disp + 2*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	VPXOR    XTMP4, XTMP0, XTMP2;              \ // XTMP2 = {..., ..., W[1], W[0]}
	ADDL     (disp + 2*4 + 32)(SP)(SRND*1), y0;\ // y0 = SS2 + W'
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
	MOVL     a, y1;                            \
	MOVL     b, y3;                            \
	VPALIGNR $12, XDWORD3, XTMP2, XTMP3;       \ // XTMP3 = {..., W[1], W[0], w15}
	ANDL     y1, y3;                           \
	ANDL     c, y1;                            \
	ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c)
	MOVL     b, h;                             \
	VPSHUFD $80, XTMP3, XTMP4;                 \ // XTMP4 = W[-3] {DDCC} = {W[0],W[0],w15,w15}
	ANDL     c, h;                             \
	ORL      y1, h;                            \ // h =  (a AND b) OR (a AND c) OR (b AND c)
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	;                                          \
	VPSLLQ  $15, XTMP4, XTMP4;                 \ // XTMP4 = W[-3] rol 15 {DxCx}
	MOVL     f, y3;                            \
	ANDL     e, y3;                            \ // y3 = e AND f
	ANDNL    g, e, y1;                         \ // y1 = NOT(e) AND g
	VPSHUFB shuff_DC00<>(SB), XTMP4, XTMP4;    \ // XTMP4 = W[-3] rol 15 {DC00}
	ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	;                                          \
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPXOR   XTMP1, XTMP4, XTMP4;               \ // XTMP4 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {DCxx}
	;                                          \
	RORXL    $23, y2, y0;                      \
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPSLLD   $15, XTMP4, XTMP5;                \ 

#define ROUND_AND_SCHED_N_1_3(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 3 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	VPSRLD   $(32-15), XTMP4, XTMP3;           \
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	ADDL     (disp + 3*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	VPOR     XTMP3, XTMP5, XTMP3;              \ // XTMP3 = XTMP4 rol 15 {DCxx}
	ADDL     (disp + 3*4 + 32)(SP)(SRND*1), y0;\ // y0 = SS2 + W'
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
	MOVL     a, y1;                            \
	MOVL     b, y3;                            \
	VPSHUFB  r08_mask<>(SB), XTMP3, XTMP1;     \ // XTMP1 = XTMP4 rol 23 {DCxx}
	ANDL     y1, y3;                           \
	ANDL     c, y1;                            \
	ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c)
	MOVL     b, h;                             \
	VPXOR    XTMP3, XTMP4, XTMP3;              \ // XTMP3 = XTMP4 ^ (XTMP4 rol 15 {DCxx})
	ANDL     c, h;                             \
	ORL      y1, h;                            \ // h =  (a AND b) OR (a AND c) OR (b AND c)
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	;                                          \
	VPXOR    XTMP3, XTMP1, XTMP1;              \ // XTMP1 = XTMP4 ^ (XTMP4 rol 15 {DCxx}) ^ (XTMP4 rol 23 {DCxx})
	MOVL     f, y3;                            \
	ANDL     e, y3;                            \ // y3 = e AND f
	ANDNL    g, e, y1;                         \ // y1 = NOT(e) AND g
	VPXOR    XTMP1, XTMP0, XTMP1;              \ // XTMP1 = {W[3], W[2], ..., ...}
	ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	;                                          \
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPALIGNR $8, XTMP1, XTMP2, XTMP3;          \ // XTMP3 = {W[1], W[0], W[3], W[2]}
	;                                          \
	RORXL    $23, y2, y0;                      \
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPSHUFD $0x4E, XTMP3, XDWORD0;             \ // XDWORD0 = {W[3], W[2], W[1], W[0]}

// For rounds [0 - 16)
#define DO_ROUND_N_0(disp, idx, const, a, b, c, d, e, f, g, h) \
	;                                            \ // #############################  RND N + 0 ############################//
	RORXL    $20, a, y0;                         \ // y0 = a <<< 12
	MOVL     e, y2;                              \
	ADDL     $const, y2;                         \
	ADDL     y0, y2;                             \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                             \ // y2 = SS1
	XORL     y2, y0                              \ // y0 = SS2
	ADDL     (disp + idx*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
	ADDL     h, y2;                              \ // y2 = h + SS1 + W    
	ADDL     (disp + idx*4 + 32)(SP)(SRND*1), y0;\ // y0 = SS2 + W'
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
	RORXL    $23, y2, y0;                        \
	RORXL    $15, y2, d;                         \
	XORL     y0, d;                              \
	XORL     y2, d;                              \ // d = P(tt2)

// For rounds [16 - 64)
#define DO_ROUND_N_1(disp, idx, const, a, b, c, d, e, f, g, h) \
	;                                            \ // #############################  RND N + 0 ############################//
	RORXL    $20, a, y0;                         \ // y0 = a <<< 12
	MOVL     e, y2;                              \
	ADDL     $const, y2;                         \
	ADDL     y0, y2;                             \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                             \ // y2 = SS1
	XORL     y2, y0                              \ // y0 = SS2
	ADDL     (disp + idx*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
	ADDL     h, y2;                              \ // y2 = h + SS1 + W    
	ADDL     (disp + idx*4 + 32)(SP)(SRND*1), y0;\ // y0 = SS2 + W'
	ADDL     d, y0;                              \ // y0 = d + SS2 + W'
	;                                            \
	MOVL     a, y1;                              \
	MOVL     b, y3;                              \
	ANDL     y1, y3;                             \
	ANDL     c, y1;                              \
	ORL      y3, y1;                             \ // y1 =  (a AND b) OR (a AND c)
	MOVL     b, h;                               \
	ANDL     c, h;                               \
	ORL      y1, h;                              \ // h =  (a AND b) OR (a AND c) OR (b AND c)
	ADDL     y0, h;                              \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	;                                            \
	MOVL     f, y3;                              \
	ANDL     e, y3;                              \ // y3 = e AND f
	ANDNL    g, e, y1;                           \ // y1 = NOT(e) AND g
	ORL      y3, y1;                             \ // y1 = (e AND f) OR (NOT(e) AND g)
	ADDL     y1, y2;                             \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	;                                            \
	ROLL     $9, b;                              \
	ROLL     $19, f;                             \
	;                                            \
	RORXL    $23, y2, y0;                        \
	RORXL    $15, y2, d;                         \
	XORL     y0, d;                              \
	XORL     y2, d;                              \ // d = P(tt2)

TEXT ·blockAVX2(SB), 0, $1048-32
	MOVQ dig+0(FP), CTX          // d.h[8]
	MOVQ p_base+8(FP), INP
	MOVQ p_len+16(FP), NUM_BYTES

	LEAQ -64(INP)(NUM_BYTES*1), NUM_BYTES // Pointer to the last block
	MOVQ NUM_BYTES, _INP_END(SP)

	CMPQ NUM_BYTES, INP
	JE   avx2_only_one_block

	// Load initial digest
	MOVL 0(CTX), a  // a = H0
	MOVL 4(CTX), b  // b = H1
	MOVL 8(CTX), c  // c = H2
	MOVL 12(CTX), d // d = H3
	MOVL 16(CTX), e // e = H4
	MOVL 20(CTX), f // f = H5
	MOVL 24(CTX), g // g = H6
	MOVL 28(CTX), h // h = H7

avx2_loop: // at each iteration works with one block (512 bit)

	VMOVDQU (0*32)(INP), XTMP0
	VMOVDQU (1*32)(INP), XTMP1
	VMOVDQU (2*32)(INP), XTMP2
	VMOVDQU (3*32)(INP), XTMP3

	VMOVDQU flip_mask<>(SB), BYTE_FLIP_MASK

	// Apply Byte Flip Mask: LE -> BE
	VPSHUFB BYTE_FLIP_MASK, XTMP0, XTMP0
	VPSHUFB BYTE_FLIP_MASK, XTMP1, XTMP1
	VPSHUFB BYTE_FLIP_MASK, XTMP2, XTMP2
	VPSHUFB BYTE_FLIP_MASK, XTMP3, XTMP3

	// Transpose data into high/low parts
	VPERM2I128 $0x20, XTMP2, XTMP0, XDWORD0 // w19, w18, w17, w16;  w3,  w2,  w1,  w0
	VPERM2I128 $0x31, XTMP2, XTMP0, XDWORD1 // w23, w22, w21, w20;  w7,  w6,  w5,  w4
	VPERM2I128 $0x20, XTMP3, XTMP1, XDWORD2 // w27, w26, w25, w24; w11, w10,  w9,  w8
	VPERM2I128 $0x31, XTMP3, XTMP1, XDWORD3 // w31, w30, w29, w28; w15, w14, w13, w12

avx2_last_block_enter:
	ADDQ $64, INP
	MOVQ INP, _INP(SP)
	XORQ SRND, SRND

avx2_schedule_compress: // for w0 - w47
	// Do 4 rounds and scheduling
	VMOVDQU XDWORD0, (_XFER + 0*32)(SP)(SRND*1)
	VPXOR  XDWORD0, XDWORD1, XFER
	VMOVDQU XFER, (_XFER + 1*32)(SP)(SRND*1)
	ROUND_AND_SCHED_N_0_0(_XFER + 0*32, 0x79cc4519, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_0_1(_XFER + 0*32, 0xf3988a32, h, a, b, c, d, e, f, g, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_0_2(_XFER + 0*32, 0xe7311465, g, h, a, b, c, d, e, f, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_0_3(_XFER + 0*32, 0xce6228cb, f, g, h, a, b, c, d, e, XDWORD0, XDWORD1, XDWORD2, XDWORD3)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD1, (_XFER + 2*32)(SP)(SRND*1)
	VPXOR  XDWORD1, XDWORD2, XFER
	VMOVDQU XFER, (_XFER + 3*32)(SP)(SRND*1)
	ROUND_AND_SCHED_N_0_0(_XFER + 2*32, 0x9cc45197, e, f, g, h, a, b, c, d, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_0_1(_XFER + 2*32, 0x3988a32f, d, e, f, g, h, a, b, c, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_0_2(_XFER + 2*32, 0x7311465e, c, d, e, f, g, h, a, b, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_0_3(_XFER + 2*32, 0xe6228cbc, b, c, d, e, f, g, h, a, XDWORD1, XDWORD2, XDWORD3, XDWORD0)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD2, (_XFER + 4*32)(SP)(SRND*1)
	VPXOR  XDWORD2, XDWORD3, XFER
	VMOVDQU XFER, (_XFER + 5*32)(SP)(SRND*1)
	ROUND_AND_SCHED_N_0_0(_XFER + 4*32, 0xcc451979, a, b, c, d, e, f, g, h, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_0_1(_XFER + 4*32, 0x988a32f3, h, a, b, c, d, e, f, g, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_0_2(_XFER + 4*32, 0x311465e7, g, h, a, b, c, d, e, f, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_0_3(_XFER + 4*32, 0x6228cbce, f, g, h, a, b, c, d, e, XDWORD2, XDWORD3, XDWORD0, XDWORD1)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD3, (_XFER + 6*32)(SP)(SRND*1)
	VPXOR  XDWORD3, XDWORD0, XFER
	VMOVDQU XFER, (_XFER + 7*32)(SP)(SRND*1)
	ROUND_AND_SCHED_N_0_0(_XFER + 6*32, 0xc451979c, e, f, g, h, a, b, c, d, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_0_1(_XFER + 6*32, 0x88a32f39, d, e, f, g, h, a, b, c, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_0_2(_XFER + 6*32, 0x11465e73, c, d, e, f, g, h, a, b, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_0_3(_XFER + 6*32, 0x228cbce6, b, c, d, e, f, g, h, a, XDWORD3, XDWORD0, XDWORD1, XDWORD2)

	ADDQ $8*32, SRND

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD0, (_XFER + 0*32)(SP)(SRND*1)
	VPXOR  XDWORD0, XDWORD1, XFER
	VMOVDQU XFER, (_XFER + 1*32)(SP)(SRND*1)
	ROUND_AND_SCHED_N_1_0(_XFER + 0*32, 0x9d8a7a87, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_1(_XFER + 0*32, 0x3b14f50f, h, a, b, c, d, e, f, g, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_2(_XFER + 0*32, 0x7629ea1e, g, h, a, b, c, d, e, f, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_3(_XFER + 0*32, 0xec53d43c, f, g, h, a, b, c, d, e, XDWORD0, XDWORD1, XDWORD2, XDWORD3)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD1, (_XFER + 2*32)(SP)(SRND*1)
	VPXOR  XDWORD1, XDWORD2, XFER
	VMOVDQU XFER, (_XFER + 3*32)(SP)(SRND*1)
	ROUND_AND_SCHED_N_1_0(_XFER + 2*32, 0xd8a7a879, e, f, g, h, a, b, c, d, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_1_1(_XFER + 2*32, 0xb14f50f3, d, e, f, g, h, a, b, c, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_1_2(_XFER + 2*32, 0x629ea1e7, c, d, e, f, g, h, a, b, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_1_3(_XFER + 2*32, 0xc53d43ce, b, c, d, e, f, g, h, a, XDWORD1, XDWORD2, XDWORD3, XDWORD0)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD2, (_XFER + 4*32)(SP)(SRND*1)
	VPXOR  XDWORD2, XDWORD3, XFER
	VMOVDQU XFER, (_XFER + 5*32)(SP)(SRND*1)

	ROUND_AND_SCHED_N_1_0(_XFER + 4*32, 0x8a7a879d, a, b, c, d, e, f, g, h, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_1_1(_XFER + 4*32, 0x14f50f3b, h, a, b, c, d, e, f, g, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_1_2(_XFER + 4*32, 0x29ea1e76, g, h, a, b, c, d, e, f, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_1_3(_XFER + 4*32, 0x53d43cec, f, g, h, a, b, c, d, e, XDWORD2, XDWORD3, XDWORD0, XDWORD1)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD3, (_XFER + 6*32)(SP)(SRND*1)
	VPXOR  XDWORD3, XDWORD0, XFER
	VMOVDQU XFER, (_XFER + 7*32)(SP)(SRND*1)
	ROUND_AND_SCHED_N_1_0(_XFER + 6*32, 0xa7a879d8, e, f, g, h, a, b, c, d, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_1_1(_XFER + 6*32, 0x4f50f3b1, d, e, f, g, h, a, b, c, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_1_2(_XFER + 6*32, 0x9ea1e762, c, d, e, f, g, h, a, b, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_1_3(_XFER + 6*32, 0x3d43cec5, b, c, d, e, f, g, h, a, XDWORD3, XDWORD0, XDWORD1, XDWORD2)

	ADDQ $8*32, SRND

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD0, (_XFER + 0*32)(SP)(SRND*1)
	VPXOR  XDWORD0, XDWORD1, XFER
	VMOVDQU XFER, (_XFER + 1*32)(SP)(SRND*1)
	ROUND_AND_SCHED_N_1_0(_XFER + 0*32, 0x7a879d8a, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_1(_XFER + 0*32, 0xf50f3b14, h, a, b, c, d, e, f, g, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_2(_XFER + 0*32, 0xea1e7629, g, h, a, b, c, d, e, f, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_3(_XFER + 0*32, 0xd43cec53, f, g, h, a, b, c, d, e, XDWORD0, XDWORD1, XDWORD2, XDWORD3)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD1, (_XFER + 2*32)(SP)(SRND*1)
	VPXOR  XDWORD1, XDWORD2, XFER
	VMOVDQU XFER, (_XFER + 3*32)(SP)(SRND*1)
	ROUND_AND_SCHED_N_1_0(_XFER + 2*32, 0xa879d8a7, e, f, g, h, a, b, c, d, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_1_1(_XFER + 2*32, 0x50f3b14f, d, e, f, g, h, a, b, c, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_1_2(_XFER + 2*32, 0xa1e7629e, c, d, e, f, g, h, a, b, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_1_3(_XFER + 2*32, 0x43cec53d, b, c, d, e, f, g, h, a, XDWORD1, XDWORD2, XDWORD3, XDWORD0)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD2, (_XFER + 4*32)(SP)(SRND*1)
	VPXOR  XDWORD2, XDWORD3, XFER
	VMOVDQU XFER, (_XFER + 5*32)(SP)(SRND*1)
	ROUND_AND_SCHED_N_1_0(_XFER + 4*32, 0x879d8a7a, a, b, c, d, e, f, g, h, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_1_1(_XFER + 4*32, 0xf3b14f5, h, a, b, c, d, e, f, g, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_1_2(_XFER + 4*32, 0x1e7629ea, g, h, a, b, c, d, e, f, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_1_3(_XFER + 4*32, 0x3cec53d4, f, g, h, a, b, c, d, e, XDWORD2, XDWORD3, XDWORD0, XDWORD1)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD3, (_XFER + 6*32)(SP)(SRND*1)
	VPXOR  XDWORD3, XDWORD0, XFER
	VMOVDQU XFER, (_XFER + 7*32)(SP)(SRND*1)
	ROUND_AND_SCHED_N_1_0(_XFER + 6*32, 0x79d8a7a8, e, f, g, h, a, b, c, d, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_1_1(_XFER + 6*32, 0xf3b14f50, d, e, f, g, h, a, b, c, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_1_2(_XFER + 6*32, 0xe7629ea1, c, d, e, f, g, h, a, b, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_1_3(_XFER + 6*32, 0xcec53d43, b, c, d, e, f, g, h, a, XDWORD3, XDWORD0, XDWORD1, XDWORD2)

	ADDQ $8*32, SRND

	// w48 - w63 processed with only 4 rounds scheduling (last 16 rounds)
	// Do 4 rounds and scheduling
	VMOVDQU XDWORD0, (_XFER + 0*32)(SP)(SRND*1)
	VPXOR  XDWORD0, XDWORD1, XFER
	VMOVDQU XFER, (_XFER + 1*32)(SP)(SRND*1)
	ROUND_AND_SCHED_N_1_0(_XFER + 0*32, 0x9d8a7a87, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_1(_XFER + 0*32, 0x3b14f50f, h, a, b, c, d, e, f, g, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_2(_XFER + 0*32, 0x7629ea1e, g, h, a, b, c, d, e, f, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_3(_XFER + 0*32, 0xec53d43c, f, g, h, a, b, c, d, e, XDWORD0, XDWORD1, XDWORD2, XDWORD3)  

	// w52 - w63 processed with no scheduling (last 12 rounds)
	// Do 4 rounds
	VMOVDQU XDWORD1, (_XFER + 2*32)(SP)(SRND*1)
	VPXOR  XDWORD1, XDWORD2, XFER
	VMOVDQU XFER, (_XFER + 3*32)(SP)(SRND*1)
	DO_ROUND_N_1(_XFER + 2*32, 0, 0xd8a7a879, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 2*32, 1, 0xb14f50f3, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 2*32, 2, 0x629ea1e7, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 2*32, 3, 0xc53d43ce, b, c, d, e, f, g, h, a)

	// Do 4 rounds
	VMOVDQU XDWORD2, (_XFER + 4*32)(SP)(SRND*1)
	VPXOR  XDWORD2, XDWORD3, XFER
	VMOVDQU XFER, (_XFER + 5*32)(SP)(SRND*1)
	DO_ROUND_N_1(_XFER + 4*32, 0, 0x8a7a879d, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER + 4*32, 1, 0x14f50f3b, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER + 4*32, 2, 0x29ea1e76, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER + 4*32, 3, 0x53d43cec, f, g, h, a, b, c, d, e)

	// Do 4 rounds
	VMOVDQU XDWORD3, (_XFER + 6*32)(SP)(SRND*1)
	VPXOR  XDWORD3, XDWORD0, XFER
	VMOVDQU XFER, (_XFER + 7*32)(SP)(SRND*1)
	DO_ROUND_N_1(_XFER + 6*32, 0, 0xa7a879d8, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 6*32, 1, 0x4f50f3b1, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 6*32, 2, 0x9ea1e762, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 6*32, 3, 0x3d43cec5, b, c, d, e, f, g, h, a)

	MOVQ dig+0(FP), CTX // d.h[8]
	MOVQ _INP(SP), INP

	xorm(  0(CTX), a)
	xorm(  4(CTX), b)
	xorm(  8(CTX), c)
	xorm( 12(CTX), d)
	xorm( 16(CTX), e)
	xorm( 20(CTX), f)
	xorm( 24(CTX), g)
	xorm( 28(CTX), h)

	CMPQ _INP_END(SP), INP
	JB   done_hash

	XORQ SRND, SRND

avx2_compress: // Do second block using previously scheduled results
	DO_ROUND_N_0(_XFER + 0*32 + 16, 0, 0x79cc4519, a, b, c, d, e, f, g, h)
	DO_ROUND_N_0(_XFER + 0*32 + 16, 1, 0xf3988a32, h, a, b, c, d, e, f, g)
	DO_ROUND_N_0(_XFER + 0*32 + 16, 2, 0xe7311465, g, h, a, b, c, d, e, f)
	DO_ROUND_N_0(_XFER + 0*32 + 16, 3, 0xce6228cb, f, g, h, a, b, c, d, e)

	DO_ROUND_N_0(_XFER + 2*32 + 16, 0, 0x9cc45197, e, f, g, h, a, b, c, d)
	DO_ROUND_N_0(_XFER + 2*32 + 16, 1, 0x3988a32f, d, e, f, g, h, a, b, c)
	DO_ROUND_N_0(_XFER + 2*32 + 16, 2, 0x7311465e, c, d, e, f, g, h, a, b)
	DO_ROUND_N_0(_XFER + 2*32 + 16, 3, 0xe6228cbc, b, c, d, e, f, g, h, a)

	DO_ROUND_N_0(_XFER + 4*32 + 16, 0, 0xcc451979, a, b, c, d, e, f, g, h)
	DO_ROUND_N_0(_XFER + 4*32 + 16, 1, 0x988a32f3, h, a, b, c, d, e, f, g)
	DO_ROUND_N_0(_XFER + 4*32 + 16, 2, 0x311465e7, g, h, a, b, c, d, e, f)
	DO_ROUND_N_0(_XFER + 4*32 + 16, 3, 0x6228cbce, f, g, h, a, b, c, d, e)

	DO_ROUND_N_0(_XFER + 6*32 + 16, 0, 0xc451979c, e, f, g, h, a, b, c, d)
	DO_ROUND_N_0(_XFER + 6*32 + 16, 1, 0x88a32f39, d, e, f, g, h, a, b, c)
	DO_ROUND_N_0(_XFER + 6*32 + 16, 2, 0x11465e73, c, d, e, f, g, h, a, b)
	DO_ROUND_N_0(_XFER + 6*32 + 16, 3, 0x228cbce6, b, c, d, e, f, g, h, a)

	ADDQ $8*32, SRND

	DO_ROUND_N_1(_XFER + 0*32 + 16, 0, 0x9d8a7a87, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER + 0*32 + 16, 1, 0x3b14f50f, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER + 0*32 + 16, 2, 0x7629ea1e, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER + 0*32 + 16, 3, 0xec53d43c, f, g, h, a, b, c, d, e)

	DO_ROUND_N_1(_XFER + 2*32 + 16, 0, 0xd8a7a879, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 2*32 + 16, 1, 0xb14f50f3, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 2*32 + 16, 2, 0x629ea1e7, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 2*32 + 16, 3, 0xc53d43ce, b, c, d, e, f, g, h, a)

	DO_ROUND_N_1(_XFER + 4*32 + 16, 0, 0x8a7a879d, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER + 4*32 + 16, 1, 0x14f50f3b, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER + 4*32 + 16, 2, 0x29ea1e76, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER + 4*32 + 16, 3, 0x53d43cec, f, g, h, a, b, c, d, e)

	DO_ROUND_N_1(_XFER + 6*32 + 16, 0, 0xa7a879d8, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 6*32 + 16, 1, 0x4f50f3b1, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 6*32 + 16, 2, 0x9ea1e762, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 6*32 + 16, 3, 0x3d43cec5, b, c, d, e, f, g, h, a)

	ADDQ $8*32, SRND

	DO_ROUND_N_1(_XFER + 0*32 + 16, 0, 0x7a879d8a, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER + 0*32 + 16, 1, 0xf50f3b14, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER + 0*32 + 16, 2, 0xea1e7629, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER + 0*32 + 16, 3, 0xd43cec53, f, g, h, a, b, c, d, e)

	DO_ROUND_N_1(_XFER + 2*32 + 16, 0, 0xa879d8a7, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 2*32 + 16, 1, 0x50f3b14f, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 2*32 + 16, 2, 0xa1e7629e, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 2*32 + 16, 3, 0x43cec53d, b, c, d, e, f, g, h, a)

	DO_ROUND_N_1(_XFER + 4*32 + 16, 0, 0x879d8a7a, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER + 4*32 + 16, 1, 0xf3b14f5, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER + 4*32 + 16, 2, 0x1e7629ea, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER + 4*32 + 16, 3, 0x3cec53d4, f, g, h, a, b, c, d, e)

	DO_ROUND_N_1(_XFER + 6*32 + 16, 0, 0x79d8a7a8, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 6*32 + 16, 1, 0xf3b14f50, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 6*32 + 16, 2, 0xe7629ea1, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 6*32 + 16, 3, 0xcec53d43, b, c, d, e, f, g, h, a)

	ADDQ $8*32, SRND

	DO_ROUND_N_1(_XFER + 0*32 + 16, 0, 0x9d8a7a87, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER + 0*32 + 16, 1, 0x3b14f50f, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER + 0*32 + 16, 2, 0x7629ea1e, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER + 0*32 + 16, 3, 0xec53d43c, f, g, h, a, b, c, d, e)

	DO_ROUND_N_1(_XFER + 2*32 + 16, 0, 0xd8a7a879, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 2*32 + 16, 1, 0xb14f50f3, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 2*32 + 16, 2, 0x629ea1e7, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 2*32 + 16, 3, 0xc53d43ce, b, c, d, e, f, g, h, a)

	DO_ROUND_N_1(_XFER + 4*32 + 16, 0, 0x8a7a879d, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER + 4*32 + 16, 1, 0x14f50f3b, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER + 4*32 + 16, 2, 0x29ea1e76, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER + 4*32 + 16, 3, 0x53d43cec, f, g, h, a, b, c, d, e)

	DO_ROUND_N_1(_XFER + 6*32 + 16, 0, 0xa7a879d8, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 6*32 + 16, 1, 0x4f50f3b1, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 6*32 + 16, 2, 0x9ea1e762, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 6*32 + 16, 3, 0x3d43cec5, b, c, d, e, f, g, h, a)

	MOVQ dig+0(FP), CTX // d.h[8]
	MOVQ _INP(SP), INP
	ADDQ $64, INP

	xorm(  0(CTX), a)
	xorm(  4(CTX), b)
	xorm(  8(CTX), c)
	xorm( 12(CTX), d)
	xorm( 16(CTX), e)
	xorm( 20(CTX), f)
	xorm( 24(CTX), g)
	xorm( 28(CTX), h)

	CMPQ _INP_END(SP), INP
	JA   avx2_loop
	JB   done_hash

avx2_do_last_block:

	VMOVDQU 0(INP), XWORD0
	VMOVDQU 16(INP), XWORD1
	VMOVDQU 32(INP), XWORD2
	VMOVDQU 48(INP), XWORD3

	VMOVDQU flip_mask<>(SB), BYTE_FLIP_MASK

	VPSHUFB X_BYTE_FLIP_MASK, XWORD0, XWORD0
	VPSHUFB X_BYTE_FLIP_MASK, XWORD1, XWORD1
	VPSHUFB X_BYTE_FLIP_MASK, XWORD2, XWORD2
	VPSHUFB X_BYTE_FLIP_MASK, XWORD3, XWORD3

	JMP avx2_last_block_enter

avx2_only_one_block:
	// Load initial digest
	MOVL 0(CTX), a  // a = H0
	MOVL 4(CTX), b  // b = H1
	MOVL 8(CTX), c  // c = H2
	MOVL 12(CTX), d // d = H3
	MOVL 16(CTX), e // e = H4
	MOVL 20(CTX), f // f = H5
	MOVL 24(CTX), g // g = H6
	MOVL 28(CTX), h // h = H7

	JMP avx2_do_last_block

done_hash:
	VZEROUPPER
	RET

// shuffle byte order from LE to BE
DATA flip_mask<>+0x00(SB)/8, $0x0405060700010203
DATA flip_mask<>+0x08(SB)/8, $0x0c0d0e0f08090a0b
DATA flip_mask<>+0x10(SB)/8, $0x0405060700010203
DATA flip_mask<>+0x18(SB)/8, $0x0c0d0e0f08090a0b
GLOBL flip_mask<>(SB), 8, $32

// shuffle BxAx -> 00BA
DATA shuff_00BA<>+0x00(SB)/8, $0x0f0e0d0c07060504
DATA shuff_00BA<>+0x08(SB)/8, $0xFFFFFFFFFFFFFFFF
DATA shuff_00BA<>+0x10(SB)/8, $0x0f0e0d0c07060504
DATA shuff_00BA<>+0x18(SB)/8, $0xFFFFFFFFFFFFFFFF
GLOBL shuff_00BA<>(SB), 8, $32

// shuffle DxCx -> DC00
DATA shuff_DC00<>+0x00(SB)/8, $0xFFFFFFFFFFFFFFFF
DATA shuff_DC00<>+0x08(SB)/8, $0x0f0e0d0c07060504
DATA shuff_DC00<>+0x10(SB)/8, $0xFFFFFFFFFFFFFFFF
DATA shuff_DC00<>+0x18(SB)/8, $0x0f0e0d0c07060504
GLOBL shuff_DC00<>(SB), 8, $32

DATA r08_mask<>+0x00(SB)/8, $0x0605040702010003
DATA r08_mask<>+0x08(SB)/8, $0x0E0D0C0F0A09080B
DATA r08_mask<>+0x10(SB)/8, $0x0605040702010003
DATA r08_mask<>+0x18(SB)/8, $0x0E0D0C0F0A09080B
GLOBL r08_mask<>(SB), 8, $32
