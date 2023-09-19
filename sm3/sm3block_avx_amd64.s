//go:build amd64 && !purego
// +build amd64,!purego

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
#define XTMP5 X11

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
#define y3 DI

// Offsets
#define XFER_SIZE 2*16
#define INP_END_SIZE 8
#define INP_SIZE 8

#define _XFER 0
#define _INP_END _XFER + XFER_SIZE
#define _INP _INP_END + INP_END_SIZE
#define STACK_SIZE _INP + INP_SIZE

// For rounds [0 - 16)
#define ROUND_AND_SCHED_N_0_0(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	;                                          \ // #############################  RND N + 0 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12, RORXL is BMI2 instr
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	VPALIGNR $12, XWORD0, XWORD1, XTMP0;       \ // XTMP0 = W[-13] = {w6,w5,w4,w3}
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	VPSLLD   $7, XTMP0, XTMP1;                 \ // XTMP1 = W[-13] << 7 = {w6<<7,w5<<7,w4<<7,w3<<7}
	ADDL     (disp + 0*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	ADDL     (disp + 0*4 + 16)(SP), y0;        \ // y0 = SS2 + W'
	VPSRLD   $(32-7), XTMP0, XTMP0;            \ // XTMP0 = W[-13] >> 25 = {w6>>25,w5>>25,w4>>25,w3>>25}
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	MOVL     a, h;                             \
	XORL     b, h;                             \
	VPOR     XTMP0, XTMP1, XTMP1;              \ // XTMP1 = W[-13] rol 7
	XORL     c, h;                             \
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     e, y1;                            \
	VPALIGNR $8, XWORD2, XWORD3, XTMP0;        \ // XTMP0 = W[-6] = {w13,w12,w11,w10}
	XORL     f, y1;                            \
	XORL     g, y1;                            \
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	VPXOR   XTMP1, XTMP0, XTMP0;               \ // XTMP0 = W[-6] ^ (W[-13] rol 7)
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	RORXL    $23, y2, y0;                      \
	VPALIGNR $12, XWORD1, XWORD2, XTMP1;       \ // XTMP1 = W[-9] = {w10,w9,w8,w7}
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPXOR XWORD0, XTMP1, XTMP1;                \ // XTMP1 = W[-9] ^ W[-16]

#define ROUND_AND_SCHED_N_0_1(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	;                                          \ // #############################  RND N + 1 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	VPSHUFD $0xA5, XWORD3, XTMP2;              \ // XTMP2 = W[-3] {BBAA} {w14,w14,w13,w13}
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	VPSRLQ  $17, XTMP2, XTMP2;                 \ // XTMP2 = W[-3] rol 15 {xBxA}
	ADDL     (disp + 1*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W
	ADDL     (disp + 1*4 + 16)(SP), y0;        \ // y0 = SS2 + W'
	VPXOR   XTMP1, XTMP2, XTMP2;               \ // XTMP2 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {xxxA}
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	MOVL     a, h;                             \
	XORL     b, h;                             \
	VPSHUFD $0x00, XTMP2, XTMP2;               \ // XTMP2 = {AAAA}
	XORL     c, h;                             \
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     e, y1;                            \ 
	XORL     f, y1;                            \
	VPSRLQ  $17, XTMP2, XTMP3;                 \ // XTMP3 = XTMP2 rol 15 {xxxA}
	XORL     g, y1;                            \
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPSRLQ  $9, XTMP2, XTMP4;                  \ // XTMP4 = XTMP2 rol 23 {xxxA}
	RORXL    $23, y2, y0;                      \
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPXOR    XTMP2, XTMP4, XTMP4;              \ // XTMP4 = XTMP2 ^ (XTMP2 rol 23 {xxxA})

#define ROUND_AND_SCHED_N_0_2(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	;                                          \ // #############################  RND N + 2 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	VPXOR    XTMP4, XTMP3, XTMP4;              \ // XTMP4 = XTMP2 ^ (XTMP2 rol 15 {xxxA}) ^ (XTMP2 rol 23 {xxxA})
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	ADDL     (disp + 2*4)(SP), y2;             \ // y2 = SS1 + W
	VPXOR    XTMP4, XTMP0, XTMP2;              \ // XTMP2 = {..., ..., ..., W[0]}
	ADDL     h, y2;                            \ // y2 = h + SS1 + W
	ADDL     (disp + 2*4 + 16)(SP), y0;        \ // y0 = SS2 + W'
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	VPALIGNR $4, XWORD3, XTMP2, XTMP3;         \ // XTMP3 = {W[0], w15, w14, w13}
	MOVL     a, h;                             \
	XORL     b, h;                             \
	XORL     c, h;                             \
	VPSLLD   $15, XTMP3, XTMP4;                \
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     e, y1;                            \
	XORL     f, y1;                            \
	XORL     g, y1;                            \
	VPSRLD   $(32-15), XTMP3, XTMP3;           \
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPOR     XTMP3, XTMP4, XTMP4;              \ // XTMP4 = (W[-3] rol 15) {DCxx}
	RORXL    $23, y2, y0;                      \
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPXOR   XTMP1, XTMP4, XTMP4;               \ // XTMP4 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {DCxx}

#define ROUND_AND_SCHED_N_0_3(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	;                                          \ // #############################  RND N + 3 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	VPSLLD   $15, XTMP4, XTMP5;                \
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	ADDL     (disp + 3*4)(SP), y2;             \ // y2 = SS1 + W
	VPSRLD   $(32-15), XTMP4, XTMP3;           \
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	ADDL     (disp + 3*4 + 16)(SP), y0;        \ // y2 = SS2 + W'
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	VPOR     XTMP3, XTMP5, XTMP3;              \ // XTMP3 = XTMP4 rol 15 {DCxx}
	MOVL     a, h;                             \
	XORL     b, h;                             \
	XORL     c, h;                             \
	VPSHUFB  R08_SHUFFLE_MASK, XTMP3, XTMP1;   \ // XTMP1 = XTMP4 rol 23 {DCxx}
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     e, y1;                            \
	XORL     f, y1;                            \
	XORL     g, y1;                            \
	VPXOR    XTMP3, XTMP4, XTMP3;              \ // XTMP3 = XTMP4 ^ (XTMP4 rol 15 {DCxx})
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPXOR    XTMP3, XTMP1, XTMP1;              \ // XTMP1 = XTMP4 ^ (XTMP4 rol 15 {DCxx}) ^ (XTMP4 rol 23 {DCxx})
	RORXL    $23, y2, y0;                      \
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPXOR    XTMP1, XTMP0, XWORD0;             \ // XWORD0 = {W[3], W[2], W[1], W[0]}

// For rounds [16 - 64)
#define ROUND_AND_SCHED_N_1_0(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	;                                          \ // #############################  RND N + 0 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	VPALIGNR $12, XWORD0, XWORD1, XTMP0;       \ // XTMP0 = W[-13] = {w6,w5,w4,w3}
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	VPSLLD   $7, XTMP0, XTMP1;                 \ // XTMP1 = W[-13] << 7 = {w6<<7,w5<<7,w4<<7,w3<<7}
	ADDL     (disp + 0*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	ADDL     (disp + 0*4 + 16)(SP), y0;        \ // y0 = SS2 + W'
	VPSRLD   $(32-7), XTMP0, XTMP0;            \ // XTMP0 = W[-13] >> 25 = {w6>>25,w5>>25,w4>>25,w3>>25}
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	MOVL     a, y1;                            \
	ORL      b, y1;                            \
	VPOR     XTMP0, XTMP1, XTMP1;              \ // XTMP1 = W[-13] rol 7 = {ROTL(7,w6),ROTL(7,w5),ROTL(7,w4),ROTL(7,w3)}
	MOVL     a, h;                             \
	ANDL     b, h;                             \
	ANDL     c, y1;                            \
	ORL      y1, h;                            \ // h =  (a AND b) OR (a AND c) OR (b AND c)  
	VPALIGNR $8, XWORD2, XWORD3, XTMP0;        \ // XTMP0 = W[-6] = {w13,w12,w11,w10}
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     f, y3;                            \
	ANDL     e, y3;                            \ // y3 = e AND f
	ANDNL    g, e, y1;                         \ // y1 = NOT(e) AND g
	VPXOR   XTMP1, XTMP0, XTMP0;               \ // XTMP0 = W[-6] ^ (W[-13] rol 7) 
	ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPALIGNR $12, XWORD1, XWORD2, XTMP1;       \ // XTMP1 = W[-9] = {w10,w9,w8,w7}
	RORXL    $23, y2, y0;                      \
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPXOR XWORD0, XTMP1, XTMP1;                \ // XTMP1 = W[-9] ^ W[-16]

#define ROUND_AND_SCHED_N_1_1(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	;                                          \ // #############################  RND N + 1 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	VPSHUFD $0xA5, XWORD3, XTMP2;              \ // XTMP2 = W[-3] {BBAA} {w14,w14,w13,w13}
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	ADDL     (disp + 1*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	VPSRLQ  $17, XTMP2, XTMP2;                 \ // XTMP2 = W[-3] rol 15 {xBxA}
	ADDL     (disp + 1*4 + 16)(SP), y0;        \ // y0 = SS2 + W'
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	MOVL     a, y1;                            \
	ORL      b, y1;                            \
	VPXOR   XTMP1, XTMP2, XTMP2;               \ // XTMP2 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {xxxA}
	MOVL     a, h;                             \
	ANDL     b, h;                             \
	ANDL     c, y1;                            \
	ORL      y1, h;                            \ // h =  (a AND b) OR (a AND c) OR (b AND c)     
	VPSHUFD $0x00, XTMP2, XTMP2;               \ // XTMP2 = {AAAA}
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     f, y3;                            \
	ANDL     e, y3;                            \ // y3 = e AND f
	ANDNL    g, e, y1;                         \ // y1 = NOT(e) AND g
	VPSRLQ  $17, XTMP2, XTMP3;                 \ // XTMP3 = XTMP2 rol 15 {xxxA}
	ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPSRLQ  $9, XTMP2, XTMP4;                  \ // XTMP4 = XTMP2 rol 23 {xxxA}
	RORXL    $23, y2, y0;                      \
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPXOR    XTMP2, XTMP4, XTMP4;              \ // XTMP4 = XTMP2 XOR (XTMP2 rol 23 {xxxA})

#define ROUND_AND_SCHED_N_1_2(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	;                                          \ // #############################  RND N + 2 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	VPXOR    XTMP4, XTMP3, XTMP4;              \ // XTMP4 = XTMP2 ^ (XTMP2 rol 15 {xxxA}) ^ (XTMP2 rol 23 {xxxA})
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	ADDL     (disp + 2*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	VPXOR    XTMP4, XTMP0, XTMP2;              \ // XTMP2 = {..., ..., ..., W[0]}
	ADDL     (disp + 2*4 + 16)(SP), y0;        \ // y0 = SS2 + W'
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	MOVL     a, y1;                            \
	ORL      b, y1;                            \
	VPALIGNR $4, XWORD3, XTMP2, XTMP3;         \ // XTMP3 = {W[0], w15, w14, w13}
	MOVL     a, h;                             \
	ANDL     b, h;                             \
	ANDL     c, y1;                            \
	ORL      y1, h;                            \ // h =  (a AND b) OR (a AND c) OR (b AND c)  
	VPSLLD   $15, XTMP3, XTMP4;                \
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     f, y3;                            \
	ANDL     e, y3;                            \ // y3 = e AND f
	ANDNL    g, e, y1;                         \ // y1 = NOT(e) AND g
	VPSRLD   $(32-15), XTMP3, XTMP3;           \
	ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPOR    XTMP3, XTMP4, XTMP4;               \ // XTMP4 = (W[-3] rol 15) {DCBA}
	RORXL    $23, y2, y0;                      \
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPXOR   XTMP1, XTMP4, XTMP4;               \ // XTMP4 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {DCBA}

#define ROUND_AND_SCHED_N_1_3(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	;                                          \ // #############################  RND N + 3 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	VPSLLD   $15, XTMP4, XTMP5;                \ 
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	ADDL     (disp + 3*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	VPSRLD   $(32-15), XTMP4, XTMP3;           \
	ADDL     (disp + 3*4 + 16)(SP), y0;        \ // y0 = SS2 + W'
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	MOVL     a, y1;                            \
	ORL      b, y1;                            \
	VPOR     XTMP3, XTMP5, XTMP3;              \ // XTMP3 = XTMP4 rol 15 {DCBA}
	MOVL     a, h;                             \
	ANDL     b, h;                             \
	ANDL     c, y1;                            \
	ORL      y1, h;                            \ // h =  (a AND b) OR (a AND c) OR (b AND c)  
	VPSHUFB  R08_SHUFFLE_MASK, XTMP3, XTMP1;   \ // XTMP1 = XTMP4 rol 23 {DCBA}
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     f, y3;                            \
	ANDL     e, y3;                            \ // y3 = e AND f
	ANDNL    g, e, y1;                         \ // y1 = NOT(e) AND g
	VPXOR    XTMP3, XTMP4, XTMP3;              \ // XTMP3 = XTMP4 ^ (XTMP4 rol 15 {DCBA})
	ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPXOR    XTMP3, XTMP1, XTMP1;              \ // XTMP1 = XTMP4 ^ (XTMP4 rol 15 {DCBA}) ^ (XTMP4 rol 23 {DCBA})
	RORXL    $23, y2, y0;                      \
	RORXL    $15, y2, d;                       \
	XORL     y0, d;                            \
	XORL     y2, d;                            \ // d = P(tt2)
	VPXOR    XTMP1, XTMP0, XWORD0;             \ // XWORD0 = {W[3], W[2], W[1], W[0]}

// For rounds [16 - 64)
#define DO_ROUND_N_1(disp, idx, const, a, b, c, d, e, f, g, h) \
	;                                            \ // #############################  RND N + 0 ############################//
	RORXL    $20, a, y0;                         \ // y0 = a <<< 12
	MOVL     e, y2;                              \
	ADDL     $const, y2;                         \
	ADDL     y0, y2;                             \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                             \ // y2 = SS1
	XORL     y2, y0                              \ // y0 = SS2
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

TEXT ·blockAVX(SB), 0, $56-32
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

	VMOVDQU flip_mask<>(SB), X_BYTE_FLIP_MASK
	VMOVDQU r08_mask<>(SB), R08_SHUFFLE_MASK

avx_loop: // at each iteration works with one block (512 bit)

	VMOVDQU 0(INP), XWORD0
	VMOVDQU 16(INP), XWORD1
	VMOVDQU 32(INP), XWORD2
	VMOVDQU 48(INP), XWORD3

	VPSHUFB X_BYTE_FLIP_MASK, XWORD0, XWORD0 // w3,  w2,  w1,  w0
	VPSHUFB X_BYTE_FLIP_MASK, XWORD1, XWORD1 // w7,  w6,  w5,  w4
	VPSHUFB X_BYTE_FLIP_MASK, XWORD2, XWORD2 // w11, w10,  w9,  w8
	VPSHUFB X_BYTE_FLIP_MASK, XWORD3, XWORD3 // w15, w14, w13, w12

	ADDQ $64, INP
	MOVQ INP, _INP(SP)

avx_schedule_compress: // for w0 - w47
	// Do 4 rounds and scheduling
	VMOVDQU XWORD0, (_XFER + 0*16)(SP)
	VPXOR  XWORD0, XWORD1, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)
	ROUND_AND_SCHED_N_0_0(_XFER, T0, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_0_1(_XFER, T1, h, a, b, c, d, e, f, g, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_0_2(_XFER, T2, g, h, a, b, c, d, e, f, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_0_3(_XFER, T3, f, g, h, a, b, c, d, e, XWORD0, XWORD1, XWORD2, XWORD3)

	// Do 4 rounds and scheduling
	VMOVDQU XWORD1, (_XFER + 0*16)(SP)
	VPXOR  XWORD1, XWORD2, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)
	ROUND_AND_SCHED_N_0_0(_XFER, T4, e, f, g, h, a, b, c, d, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_0_1(_XFER, T5, d, e, f, g, h, a, b, c, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_0_2(_XFER, T6, c, d, e, f, g, h, a, b, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_0_3(_XFER, T7, b, c, d, e, f, g, h, a, XWORD1, XWORD2, XWORD3, XWORD0)

	// Do 4 rounds and scheduling
	VMOVDQU XWORD2, (_XFER + 0*16)(SP)
	VPXOR  XWORD2, XWORD3, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)
	ROUND_AND_SCHED_N_0_0(_XFER, T8, a, b, c, d, e, f, g, h, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_0_1(_XFER, T9, h, a, b, c, d, e, f, g, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_0_2(_XFER, T10, g, h, a, b, c, d, e, f, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_0_3(_XFER, T11, f, g, h, a, b, c, d, e, XWORD2, XWORD3, XWORD0, XWORD1)

	// Do 4 rounds and scheduling
	VMOVDQU XWORD3, (_XFER + 0*16)(SP)
	VPXOR  XWORD3, XWORD0, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)
	ROUND_AND_SCHED_N_0_0(_XFER, T12, e, f, g, h, a, b, c, d, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_0_1(_XFER, T13, d, e, f, g, h, a, b, c, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_0_2(_XFER, T14, c, d, e, f, g, h, a, b, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_0_3(_XFER, T15, b, c, d, e, f, g, h, a, XWORD3, XWORD0, XWORD1, XWORD2)

	// Do 4 rounds and scheduling
	VMOVDQU XWORD0, (_XFER + 0*16)(SP)
	VPXOR  XWORD0, XWORD1, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER, T16, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_1(_XFER, T17, h, a, b, c, d, e, f, g, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_2(_XFER, T18, g, h, a, b, c, d, e, f, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_3(_XFER, T19, f, g, h, a, b, c, d, e, XWORD0, XWORD1, XWORD2, XWORD3)

	// Do 4 rounds and scheduling
	VMOVDQU XWORD1, (_XFER + 0*16)(SP)
	VPXOR  XWORD1, XWORD2, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER, T20, e, f, g, h, a, b, c, d, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_1_1(_XFER, T21, d, e, f, g, h, a, b, c, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_1_2(_XFER, T22, c, d, e, f, g, h, a, b, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_1_3(_XFER, T23, b, c, d, e, f, g, h, a, XWORD1, XWORD2, XWORD3, XWORD0)

	// Do 4 rounds and scheduling
	VMOVDQU XWORD2, (_XFER + 0*16)(SP)
	VPXOR  XWORD2, XWORD3, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)

	ROUND_AND_SCHED_N_1_0(_XFER, T24, a, b, c, d, e, f, g, h, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_1_1(_XFER, T25, h, a, b, c, d, e, f, g, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_1_2(_XFER, T26, g, h, a, b, c, d, e, f, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_1_3(_XFER, T27, f, g, h, a, b, c, d, e, XWORD2, XWORD3, XWORD0, XWORD1)

	// Do 4 rounds and scheduling
	VMOVDQU XWORD3, (_XFER + 0*16)(SP)
	VPXOR  XWORD3, XWORD0, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER, T28, e, f, g, h, a, b, c, d, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_1_1(_XFER, T29, d, e, f, g, h, a, b, c, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_1_2(_XFER, T30, c, d, e, f, g, h, a, b, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_1_3(_XFER, T31, b, c, d, e, f, g, h, a, XWORD3, XWORD0, XWORD1, XWORD2)

	// Do 4 rounds and scheduling
	VMOVDQU XWORD0, (_XFER + 0*16)(SP)
	VPXOR  XWORD0, XWORD1, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER, T32, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_1(_XFER, T33, h, a, b, c, d, e, f, g, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_2(_XFER, T34, g, h, a, b, c, d, e, f, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_3(_XFER, T35, f, g, h, a, b, c, d, e, XWORD0, XWORD1, XWORD2, XWORD3)

	// Do 4 rounds and scheduling
	VMOVDQU XWORD1, (_XFER + 0*16)(SP)
	VPXOR  XWORD1, XWORD2, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER, T36, e, f, g, h, a, b, c, d, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_1_1(_XFER, T37, d, e, f, g, h, a, b, c, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_1_2(_XFER, T38, c, d, e, f, g, h, a, b, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_1_3(_XFER, T39, b, c, d, e, f, g, h, a, XWORD1, XWORD2, XWORD3, XWORD0)

	// Do 4 rounds and scheduling
	VMOVDQU XWORD2, (_XFER + 0*16)(SP)
	VPXOR  XWORD2, XWORD3, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER, T40, a, b, c, d, e, f, g, h, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_1_1(_XFER, T41, h, a, b, c, d, e, f, g, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_1_2(_XFER, T42, g, h, a, b, c, d, e, f, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_1_3(_XFER, T43, f, g, h, a, b, c, d, e, XWORD2, XWORD3, XWORD0, XWORD1)

	// Do 4 rounds and scheduling
	VMOVDQU XWORD3, (_XFER + 0*16)(SP)
	VPXOR  XWORD3, XWORD0, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER, T44, e, f, g, h, a, b, c, d, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_1_1(_XFER, T45, d, e, f, g, h, a, b, c, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_1_2(_XFER, T46, c, d, e, f, g, h, a, b, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_1_3(_XFER, T47, b, c, d, e, f, g, h, a, XWORD3, XWORD0, XWORD1, XWORD2)

	// w48 - w63 processed with only 4 rounds scheduling (last 16 rounds)
	// Do 4 rounds and scheduling
	VMOVDQU XWORD0, (_XFER + 0*16)(SP)
	VPXOR  XWORD0, XWORD1, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER, T48, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_1(_XFER, T49, h, a, b, c, d, e, f, g, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_2(_XFER, T50, g, h, a, b, c, d, e, f, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_3(_XFER, T51, f, g, h, a, b, c, d, e, XWORD0, XWORD1, XWORD2, XWORD3)  

	// w52 - w63 processed with no scheduling (last 12 rounds)
	// Do 4 rounds
	VMOVDQU XWORD1, (_XFER + 0*16)(SP)
	VPXOR  XWORD1, XWORD2, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_1(_XFER, 0, T52, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER, 1, T53, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER, 2, T54, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER, 3, T55, b, c, d, e, f, g, h, a)

	// Do 4 rounds
	VMOVDQU XWORD2, (_XFER + 0*16)(SP)
	VPXOR  XWORD2, XWORD3, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_1(_XFER, 0, T56, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER, 1, T57, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER, 2, T58, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER, 3, T59, f, g, h, a, b, c, d, e)

	// Do 4 rounds
	VMOVDQU XWORD3, (_XFER + 0*16)(SP)
	VPXOR  XWORD3, XWORD0, XFER
	VMOVDQU XFER, (_XFER + 1*16)(SP)
	DO_ROUND_N_1(_XFER, 0, T60, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER, 1, T61, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER, 2, T62, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER, 3, T63, b, c, d, e, f, g, h, a)

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
	JMP   avx_loop

done_hash:
	RET

// shuffle byte order from LE to BE
DATA flip_mask<>+0x00(SB)/8, $0x0405060700010203
DATA flip_mask<>+0x08(SB)/8, $0x0c0d0e0f08090a0b
GLOBL flip_mask<>(SB), 8, $16

DATA r08_mask<>+0x00(SB)/8, $0x0605040702010003
DATA r08_mask<>+0x08(SB)/8, $0x0E0D0C0F0A09080B
GLOBL r08_mask<>(SB), 8, $16
