#include "textflag.h"

// Wt = Mt; for 0 <= t <= 3
#define MSGSCHEDULE0(index) \
	MOVL	(index*4)(SI), AX; \
	BSWAPL	AX; \
	MOVL	AX, (index*4)(BP)

// Wt+4 = Mt+4; for 0 <= t <= 11
#define MSGSCHEDULE01(index) \
	MOVL	((index+4)*4)(SI), AX; \
	BSWAPL	AX; \
	MOVL	AX, ((index+4)*4)(BP)

// x = Wt-12 XOR Wt-5 XOR ROTL(15, Wt+1)
// p1(x) = x XOR ROTL(15, x) XOR ROTL(23, x)
// Wt+4 = p1(x) XOR ROTL(7, Wt-9) XOR Wt-2
// for 12 <= t <= 63
#define MSGSCHEDULE1(index) \
  MOVL	((index+1)*4)(BP), AX; \
  ROLL  $15, AX; \
  MOVL	((index-12)*4)(BP), BX; \
  XORL  BX, AX; \
  MOVL	((index-5)*4)(BP), BX; \
  XORL  BX, AX; \
  MOVL  AX, BX; \
  ROLL  $15, BX; \
  MOVL  AX, CX; \
  ROLL  $23, CX; \
  XORL  BX, AX; \
  XORL  CX, AX; \
  MOVL	((index-9)*4)(BP), BX; \
  ROLL  $7, BX; \
  MOVL	((index-2)*4)(BP), CX; \
  XORL  BX, AX; \
  XORL  CX, AX; \
  MOVL  AX, ((index+4)*4)(BP)

// Calculate ss1 in BX
// x = ROTL(12, a) + e + ROTL(index, const)
// ret = ROTL(7, x)
#define SM3SS1(const, a, e) \
  MOVL  a, BX; \
  ROLL  $12, BX; \
  ADDL  e, BX; \
  ADDL  $const, BX; \
  ROLL  $7, BX

// Calculate tt1 in CX
// ret = (a XOR b XOR c) + d + (ROTL(12, a) XOR ss1) + (Wt XOR Wt+4)
#define SM3TT10(index, a, b, c, d) \  
  MOVL a, CX; \
  MOVL b, DX; \
  XORL CX, DX; \
  MOVL c, DI; \
  XORL DI, DX; \  // (a XOR b XOR c)
  ADDL d, DX; \   // (a XOR b XOR c) + d 
  MOVL ((index)*4)(BP), DI; \ //Wt
  XORL DI, AX; \ //Wt XOR Wt+4
  ADDL AX, DX;  \
  ROLL $12, CX; \
  XORL BX, CX; \ // ROTL(12, a) XOR ss1
  ADDL DX, CX  // (a XOR b XOR c) + d + (ROTL(12, a) XOR ss1)

// Calculate tt2 in BX
// ret = (e XOR f XOR g) + h + ss1 + Wt
#define SM3TT20(e, f, g, h) \  
  ADDL h, DI; \   //Wt + h
  ADDL BX, DI; \  //Wt + h + ss1
  MOVL e, BX; \
  MOVL f, DX; \
  XORL DX, BX; \  // e XOR f
  MOVL g, DX; \
  XORL DX, BX; \  // e XOR f XOR g
  ADDL DI, BX     // (e XOR f XOR g) + Wt + h + ss1

// Calculate tt1 in CX, used DX, DI
// ret = ((a AND b) OR (a AND c) OR (b AND c)) + d + (ROTL(12, a) XOR ss1) + (Wt XOR Wt+4)
#define SM3TT11(index, a, b, c, d) \  
  MOVL a, CX; \
  MOVL b, DX; \
  ANDL CX, DX; \  // a AND b
  MOVL c, DI; \
  ANDL DI, CX; \  // a AND c
  ORL  DX, CX; \  // (a AND b) OR (a AND c)
  MOVL b, DX; \
  ANDL DI, DX; \  // b AND c
  ORL  CX, DX; \  // (a AND b) OR (a AND c) OR (b AND c)
  ADDL d, DX; \
  MOVL a, CX; \
  ROLL $12, CX; \
  XORL BX, CX; \
  ADDL DX, CX; \  // ((a AND b) OR (a AND c) OR (b AND c)) + d + (ROTL(12, a) XOR ss1)
  MOVL ((index)*4)(BP), DI; \
  XORL DI, AX; \  // Wt XOR Wt+4
  ADDL AX, CX

// Calculate tt2 in BX
// ret = ((e AND f) OR (NOT(e) AND g)) + h + ss1 + Wt
#define SM3TT21(e, f, g, h) \  
  ADDL h, DI; \   // Wt + h
  ADDL BX, DI; \  // h + ss1 + Wt
  MOVL e, BX; \
  MOVL f, DX; \   
  ANDL BX, DX; \  // e AND f
  NOTL BX; \      // NOT(e)
  MOVL g, AX; \
  ANDL AX, BX; \ // NOT(e) AND g
  ORL  DX, BX; \
  ADDL DI, BX

#define COPYRESULT(b, d, f, h) \
  ROLL $9, b; \
  MOVL CX, h; \   // a = ttl
  ROLL $19, f; \
  MOVL BX, CX; \
  ROLL $9, CX; \
  XORL BX, CX; \  // tt2 XOR ROTL(9, tt2)
  ROLL $17, BX; \
  XORL BX, CX; \  // tt2 XOR ROTL(9, tt2) XOR ROTL(17, tt2)
  MOVL CX, d    // e = tt2 XOR ROTL(9, tt2) XOR ROTL(17, tt2)

#define SM3ROUND0(index, const, a, b, c, d, e, f, g, h) \
  MSGSCHEDULE01(index); \
  SM3SS1(const, a, e); \
  SM3TT10(index, a, b, c, d); \
  SM3TT20(e, f, g, h); \
  COPYRESULT(b, d, f, h)

#define SM3ROUND1(index, const, a, b, c, d, e, f, g, h) \
  MSGSCHEDULE1(index); \
  SM3SS1(const, a, e); \
  SM3TT10(index, a, b, c, d); \
  SM3TT20(e, f, g, h); \
  COPYRESULT(b, d, f, h)

#define SM3ROUND2(index, const, a, b, c, d, e, f, g, h) \
  MSGSCHEDULE1(index); \
  SM3SS1(const, a, e); \
  SM3TT11(index, a, b, c, d); \
  SM3TT21(e, f, g, h); \
  COPYRESULT(b, d, f, h)

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

//#define old_h R11

//#define TBL BP

#define SRND SI // SRND is same register as CTX

#define T1 R12

#define y0 R13
#define y1 R14
#define y2 R15
#define y3 DI

// Offsets
#define XFER_SIZE 4*64*4
#define INP_END_SIZE 8
#define INP_SIZE 8

#define _XFER 0
#define _INP_END _XFER + XFER_SIZE
#define _INP _INP_END + INP_END_SIZE
#define STACK_SIZE _INP + INP_SIZE

#define ROUND_AND_SCHED_N_0_0(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 0 ############################//
	RORXL    $(-12), a, y0;                    \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  ADDL     $const, y1;                       \
  VPALIGNR $12, XDWORD0, XDWORD1, XTMP0;     \ // XTMP0 = W[-13] = {w6,w5,w4,w3}
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  RORXL    $(-7), y1, y2;                    \ // y2 = SS1
  VPSLLD   $7, XTMP0, XTMP1;                 \
  XORL     y2, y0                            \ // y0 = SS2
  ADDL     (disp + 0*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  VPSRLD   $(32-7), XTMP0, XTMP0;            \
  ADDL     h, y2;                            \ // y2 = h + SS1 + W    
  ADDL     (disp + 0*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
  VPOR     XTMP0, XTMP1, XTMP1;              \ // XTMP1 = W[-13] rol 7
	;                                          \
  MOVL     a, y1;                            \
  XORL     b, y1;                            \
  XORL     c, y1;                            \
  VPALIGNR $8, XDWORD2, XDWORD3, XTMP0;      \ // XTMP0 = W[-6] = {w13,w12,w11,w10}
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
  ;                                          \
  MOVL     e, y1;                            \
  VPXOR   XTMP1, XTMP0, XTMP0;               \ // XTMP0 = W[-6] XOR (W[-13] rol 7)
  XORL     f, y1;                            \
  XORL     g, y1;                            \
  ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
  VPALIGNR $12, XDWORD1, XDWORD2, XTMP1;     \ // XTMP1 = W[-9] = {w10,w9,w8,w7}
  ;                                          \
  ROLL     $9, b;                            \
  ROLL     $19, f;                           \
  MOVL     y0, h;                            \ // h = tt1
  ;                                          \
  RORXL    $(-9), y2, y0;                    \
  VPXOR XDWORD0, XTMP1, XTMP1;               \ // XTMP1 = W[-9] XOR W[-16]
  RORXL    $(-17), y2, y1;                   \
  XORL     y0, y2;                           \
  XORL     y1, y2;                           \
  VPSHUFD $0xA5, XDWORD3, XTMP2;             \ // XTMP2 = W[-3] {BBAA} {w14,w14,w13,w13}
  MOVL     y2, d                               // d = P(tt2)

#define ROUND_AND_SCHED_N_0_1(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 1 ############################//
	RORXL    $-12, a, y0;                      \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  VPSLLQ  $15, XTMP2, XTMP2;                 \ // XTMP2 = W[-3] rol 15 {BxAx}
  ADDL     $const, y1;                       \
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  RORXL    $-7, y1, y2;                      \ // y2 = SS1
  VPSHUFB shuff_00BA<>(SB), XTMP2, XTMP2;    \ // XTMP2 = W[-3] rol 15 {00BA}
  XORL     y2, y0                            \ // y0 = SS2
  ADDL     (disp + 1*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  ADDL     h, y2;                            \ // y2 = h + SS1 + W
  VPXOR   XTMP1, XTMP2, XTMP2;               \ // XTMP2 = W[-9] XOR W[-16] XOR (W[-3] rol 15) {xxBA}
  ADDL     (disp + 1*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
  MOVL     a, y1;                            \
  XORL     b, y1;                            \
  VPSLLD   $15, XTMP2, XTMP3;                \
  XORL     c, y1;                            \
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
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
  VPXOR    XTMP2, XTMP4, XTMP4;              \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {xxBA})
  MOVL     y0, h;                            \ // h = tt1
  ;                                          \
  RORXL    $-9, y2, y0;                      \
  RORXL    $-17, y2, y1;                     \
  VPSLLD   $23, XTMP2, XTMP3;                \
  XORL     y0, y2;                           \
  XORL     y1, y2;                           \
  VPSRLD   $(32-23), XTMP2, XTMP5;           \
  MOVL     y2, d                               // d = P(tt2)

#define ROUND_AND_SCHED_N_0_2(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 2 ############################//
	RORXL    $-12, a, y0;                      \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  VPOR     XTMP3, XTMP5, XTMP5;              \ //XTMP5 = XTMP2 rol 23 {xxBA}
  ADDL     $const, y1;                       \
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  RORXL    $-7, y1, y2;                      \ // y2 = SS1
  VPXOR    XTMP4, XTMP5, XTMP4;              \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {xxBA}) XOR (XTMP2 rol 23 {xxBA})
  XORL     y2, y0                            \ // y0 = SS2
  ADDL     (disp + 2*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  ADDL     h, y2;                            \ // y2 = h + SS1 + W
  VPXOR    XTMP4, XTMP0, XTMP2;              \ // XTMP2 = {..., ..., W[1], W[0]}
  ADDL     (disp + 2*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
  MOVL     a, y1;                            \
  VPALIGNR $12, XDWORD3, XTMP2, XTMP3;       \ // XTMP3 = {..., W[1], W[0], w15}
  XORL     b, y1;                            \
  XORL     c, y1;                            \
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
  VPSHUFD $80, XTMP3, XTMP4;                 \ // XTMP4 =  = W[-3] {DDCC}
  ;                                          \
  MOVL     e, y1;                            \
  XORL     f, y1;                            \
  XORL     g, y1;                            \
  VPSLLQ  $15, XTMP4, XTMP4;                 \ // XTMP4 = W[-3] rol 15 {DxCx}
  ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
  ;                                          \
  ROLL     $9, b;                            \
  ROLL     $19, f;                           \
  VPSHUFB shuff_DC00<>(SB), XTMP4, XTMP4;    \ // XTMP4 = W[-3] rol 15 {DC00}
  MOVL     y0, h;                            \ // h = tt1
  ;                                          \
  RORXL    $-9, y2, y0;                      \
  RORXL    $-17, y2, y1;                     \
  VPXOR   XTMP1, XTMP4, XTMP4;               \ // XTMP4 = W[-9] XOR W[-16] XOR (W[-3] rol 15) {DCxx}
  XORL     y0, y2;                           \
  XORL     y1, y2;                           \
  VPSLLD   $15, XTMP4, XTMP5;                \
  MOVL     y2, d                               // d = P(tt2)

#define ROUND_AND_SCHED_N_0_3(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 3 ############################//
	RORXL    $-12, a, y0;                      \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  VPSRLD   $(32-15), XTMP4, XTMP3;           \
  ADDL     $const, y1;                       \
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  VPOR     XTMP3, XTMP5, XTMP3;              \ // XTMP3 = XTMP4 rol 15 {DCxx}
  RORXL    $-7, y1, y2;                      \ // y2 = SS1
  XORL     y2, y0                            \ // y0 = SS2
  VPXOR    XTMP3, XTMP4, XTMP3;              \ // XTMP3 = XTMP4 XOR (XTMP4 rol 15 {DCxx})
  ADDL     (disp + 3*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  ADDL     h, y2;                            \ // y2 = h + SS1 + W    
  ADDL     (disp + 3*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  VPSLLD   $23, XTMP4, XTMP5;                \
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
  MOVL     a, y1;                            \
  XORL     b, y1;                            \
  VPSRLD   $(32-23), XTMP4, XTMP1;           \
  XORL     c, y1;                            \
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
  ;                                          \
  VPOR     XTMP1, XTMP5, XTMP1;              \ // XTMP1 = XTMP4 rol 23 {DCxx}
  MOVL     e, y1;                            \
  XORL     f, y1;                            \
  VPXOR    XTMP3, XTMP1, XTMP1;              \ // XTMP1 = XTMP4 XOR (XTMP4 rol 15 {DCxx}) XOR (XTMP4 rol 23 {DCxx})
  XORL     g, y1;                            \
  ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
  ;                                          \
  ROLL     $9, b;                            \
  VPXOR    XTMP1, XTMP0, XTMP1;              \ // XTMP1 = {W[3], W[2], ..., ...}
  ROLL     $19, f;                           \
  MOVL     y0, h;                            \ // h = tt1
  ;                                          \
  RORXL    $-9, y2, y0;                      \
  VPALIGNR $8, XTMP1, XTMP2, XTMP3;          \ // XTMP3 = {W[1], W[0], W[3], W[2]}
  RORXL    $-17, y2, y1;                     \
  XORL     y0, y2;                           \
  XORL     y1, y2;                           \
  VPSHUFD $0x4E, XTMP3, XDWORD0;             \ // XDWORD0 = {W[3], W[2], W[1], W[0]}
  MOVL     y2, d                               // d = P(tt2)

#define ROUND_AND_SCHED_N_1_0(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 0 ############################//
	RORXL    $-12, a, y0;                      \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  ADDL     $const, y1;                       \
  VPALIGNR $12, XDWORD0, XDWORD1, XTMP0;     \ // XTMP0 = W[-13] = {w6,w5,w4,w3}
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  RORXL    $-7, y1, y2;                      \ // y2 = SS1
  XORL     y2, y0                            \ // y0 = SS2
  VPSLLD   $7, XTMP0, XTMP1;                 \
  ADDL     (disp + 0*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  ADDL     h, y2;                            \ // y2 = h + SS1 + W    
  ADDL     (disp + 0*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
  VPSRLD   $(32-7), XTMP0, XTMP0;            \
	;                                          \
  MOVL     a, y1;                            \
  MOVL     b, y3;                            \
  VPOR     XTMP0, XTMP1, XTMP1;              \ // XTMP1 = W[-13] rol 7
  ANDL     y1, y3;                           \
  MOVL     c, T1;                            \
  ANDL     T1, y1;                           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c)
  VPALIGNR $8, XDWORD2, XDWORD3, XTMP0;      \ // XTMP0 = W[-6] = {w13,w12,w11,w10}
  MOVL     b, y3;                            \
  ANDL     T1, y3;                           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c) OR (b AND c)
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
  ;                                          \
  VPXOR   XTMP1, XTMP0, XTMP0;               \ // XTMP0 = W[-6] XOR (W[-13] rol 7) 
  MOVL     e, y1;                            \
  MOVL     f, y3;                            \
  ANDL     y1, y3;                           \ // y3 = e AND f
  NOTL     y1;                               \
  MOVL     g, T1;                            \
  ANDL     T1, y1;                           \ // y1 = NOT(e) AND g
  ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
  VPALIGNR $12, XDWORD1, XDWORD2, XTMP1;     \ // XTMP1 = W[-9] = {w10,w9,w8,w7}
  ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
  ;                                          \
  ROLL     $9, b;                            \
  ROLL     $19, f;                           \
  VPXOR XDWORD0, XTMP1, XTMP1;               \ // XTMP1 = W[-9] XOR W[-16]
  MOVL     y0, h;                            \ // h = tt1
  ;                                          \
  RORXL    $-9, y2, y0;                      \
  RORXL    $-17, y2, y1;                     \
  XORL     y0, y2;                           \
  XORL     y1, y2;                           \
  VPSHUFD $0xA5, XDWORD3, XTMP2;             \ // XTMP2 = W[-3] {BBAA} {w14,w14,w13,w13}
  MOVL     y2, d                               // d = P(tt2)

#define ROUND_AND_SCHED_N_1_1(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 1 ############################//
	RORXL    $-12, a, y0;                      \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  ADDL     $const, y1;                       \
  VPSLLQ  $15, XTMP2, XTMP2;                 \ // XTMP2 = W[-3] rol 15 {BxAx}
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  RORXL    $-7, y1, y2;                      \ // y2 = SS1
  VPSHUFB shuff_00BA<>(SB), XTMP2, XTMP2;    \ // XTMP2 = W[-3] rol 15 {00BA}
  XORL     y2, y0                            \ // y0 = SS2
  ADDL     (disp + 1*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  ADDL     h, y2;                            \ // y2 = h + SS1 + W    
  VPXOR   XTMP1, XTMP2, XTMP2;               \ // XTMP2 = W[-9] XOR W[-16] XOR (W[-3] rol 15) {xxBA}
  ADDL     (disp + 1*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
  MOVL     a, y1;                            \
  VPSLLD   $15, XTMP2, XTMP3;                \
  MOVL     b, y3;                            \
  ANDL     y1, y3;                           \
  MOVL     c, T1;                            \
  ANDL     T1, y1;                           \
  VPSRLD   $(32-15), XTMP2, XTMP4;           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c)
  MOVL     b, y3;                            \
  ANDL     T1, y3;                           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c) OR (b AND c)
  VPOR     XTMP3, XTMP4, XTMP4;              \ // XTMP4 = XTMP2 rol 15 {xxBA}
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
  ;                                          \
  MOVL     e, y1;                            \
  MOVL     f, y3;                            \
  ANDL     y1, y3;                           \ // y3 = e AND f
  NOTL     y1;                               \
  MOVL     g, T1;                            \
  VPXOR    XTMP2, XTMP4, XTMP4;              \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {xxBA})
  ANDL     T1, y1;                           \ // y1 = NOT(e) AND g
  ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
  ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
  ;                                          \
  ROLL     $9, b;                            \
  ROLL     $19, f;                           \
  VPSLLD   $23, XTMP2, XTMP3;                \
  MOVL     y0, h;                            \ // h = tt1
  ;                                          \
  RORXL    $-9, y2, y0;                      \
  RORXL    $-17, y2, y1;                     \
  XORL     y0, y2;                           \
  VPSRLD   $(32-23), XTMP2, XTMP5;           \
  XORL     y1, y2;                           \
  MOVL     y2, d                               // d = P(tt2)

#define ROUND_AND_SCHED_N_1_2(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 2 ############################//
	RORXL    $-12, a, y0;                      \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  ADDL     $const, y1;                       \
  VPOR     XTMP3, XTMP5, XTMP5;              \ //XTMP5 = XTMP2 rol 23 {xxBA}
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  RORXL    $-7, y1, y2;                      \ // y2 = SS1
  XORL     y2, y0                            \ // y0 = SS2
  VPXOR    XTMP4, XTMP5, XTMP4;              \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {xxBA}) XOR (XTMP2 rol 23 {xxBA})
  ADDL     (disp + 2*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  ADDL     h, y2;                            \ // y2 = h + SS1 + W    
  ADDL     (disp + 2*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  VPXOR    XTMP4, XTMP0, XTMP2;              \ // XTMP2 = {..., ..., W[1], W[0]}
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
  MOVL     a, y1;                            \
  MOVL     b, y3;                            \
  VPALIGNR $12, XDWORD3, XTMP2, XTMP3;       \ // XTMP3 = {..., W[1], W[0], w15}
  ANDL     y1, y3;                           \
  MOVL     c, T1;                            \
  ANDL     T1, y1;                           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c)
  VPSHUFD $80, XTMP3, XTMP4;                 \ // XTMP4 =  = W[-3] {DDCC}
  MOVL     b, y3;                            \
  ANDL     T1, y3;                           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c) OR (b AND c)
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
  VPSLLQ  $15, XTMP4, XTMP4;                 \ // XTMP4 = W[-3] rol 15 {DxCx}
  ;                                          \
  MOVL     e, y1;                            \
  MOVL     f, y3;                            \
  ANDL     y1, y3;                           \ // y3 = e AND f
  NOTL     y1;                               \
  VPSHUFB shuff_DC00<>(SB), XTMP4, XTMP4;    \ // XTMP4 = W[-3] rol 15 {DC00}
  MOVL     g, T1;                            \
  ANDL     T1, y1;                           \ // y1 = NOT(e) AND g
  ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
  ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
  VPXOR   XTMP1, XTMP4, XTMP4;               \ // XTMP4 = W[-9] XOR W[-16] XOR (W[-3] rol 15) {DCxx}
  ;                                          \
  ROLL     $9, b;                            \
  ROLL     $19, f;                           \
  MOVL     y0, h;                            \ // h = tt1
  VPSLLD   $15, XTMP4, XTMP5;                \ 
  ;                                          \
  RORXL    $-9, y2, y0;                      \
  RORXL    $-17, y2, y1;                     \
  XORL     y0, y2;                           \
  XORL     y1, y2;                           \
  VPSRLD   $(32-15), XTMP4, XTMP3;           \
  MOVL     y2, d                               // d = P(tt2)

#define ROUND_AND_SCHED_N_1_3(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 3 ############################//
	RORXL    $-12, a, y0;                      \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  ADDL     $const, y1;                       \
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  VPOR     XTMP3, XTMP5, XTMP3;              \ // XTMP3 = XTMP4 rol 15 {DCxx}
  RORXL    $-7, y1, y2;                      \ // y2 = SS1
  XORL     y2, y0                            \ // y0 = SS2
  ADDL     (disp + 3*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  VPXOR    XTMP3, XTMP4, XTMP3;              \ // XTMP3 = XTMP4 XOR (XTMP4 rol 15 {DCxx})
  ADDL     h, y2;                            \ // y2 = h + SS1 + W    
  ADDL     (disp + 3*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
  MOVL     a, y1;                            \
  VPSLLD   $23, XTMP4, XTMP5;                \
  MOVL     b, y3;                            \
  ANDL     y1, y3;                           \
  MOVL     c, T1;                            \
  ANDL     T1, y1;                           \
  VPSRLD   $(32-23), XTMP4, XTMP1;           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c)
  MOVL     b, y3;                            \
  ANDL     T1, y3;                           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c) OR (b AND c)
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
  VPOR     XTMP1, XTMP5, XTMP1;              \ // XTMP1 = XTMP4 rol 23 {DCxx}
  ;                                          \
  MOVL     e, y1;                            \
  MOVL     f, y3;                            \
  ANDL     y1, y3;                           \ // y3 = e AND f
  NOTL     y1;                               \
  VPXOR    XTMP3, XTMP1, XTMP1;              \ // XTMP1 = XTMP4 XOR (XTMP4 rol 15 {DCxx}) XOR (XTMP4 rol 23 {DCxx})
  MOVL     g, T1;                            \
  ANDL     T1, y1;                           \ // y1 = NOT(e) AND g
  ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
  ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
  VPXOR    XTMP1, XTMP0, XTMP1;              \ // XTMP1 = {W[3], W[2], ..., ...}
  ;                                          \
  ROLL     $9, b;                            \
  ROLL     $19, f;                           \
  MOVL     y0, h;                            \ // h = tt1
  VPALIGNR $8, XTMP1, XTMP2, XTMP3;          \ // XTMP3 = {W[1], W[0], W[3], W[2]}
  ;                                          \
  RORXL    $-9, y2, y0;                      \
  RORXL    $-17, y2, y1;                     \
  XORL     y0, y2;                           \
  XORL     y1, y2;                           \
  VPSHUFD $0x4E, XTMP3, XDWORD0;             \ // XDWORD0 = {W[3], W[2], W[1], W[0]}
  MOVL     y2, d                               // d = P(tt2)

#define ROUND_N_0_0(disp, const, a, b, c, d, e, f, g, h) \
	;                                          \ // #############################  RND N + 0 ############################//
	RORXL    $-12, a, y0;                      \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  ADDL     $const, y1;                       \
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  RORXL    $-7, y1, y2;                      \ // y2 = SS1
  XORL     y2, y0                            \ // y0 = SS2
  ADDL     (disp + 0*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  ADDL     h, y2;                            \ // y2 = h + SS1 + W    
  ADDL     (disp + 0*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
  MOVL     a, y1;                            \
  XORL     b, y1;                            \
  XORL     c, y1;                            \
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
  ;                                          \
  MOVL     e, y1;                            \
  XORL     f, y1;                            \
  XORL     g, y1;                            \
  ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
  ;                                          \
  ROLL     $9, b;                            \
  ROLL     $19, f;                           \
  MOVL     y0, h;                            \ // h = tt1
  ;                                          \
  RORXL    $-9, y2, y0;                      \
  RORXL    $-17, y2, y1;                     \
  XORL     y0, y2;                           \
  XORL     y1, y2;                           \
  MOVL     y2, d                               // d = P(tt2)

#define ROUND_N_0_1(disp, const, a, b, c, d, e, f, g, h) \
	;                                          \ // #############################  RND N + 1 ############################//
	RORXL    $-12, a, y0;                      \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  ADDL     $const, y1;                       \
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  RORXL    $-7, y1, y2;                      \ // y2 = SS1
  XORL     y2, y0                            \ // y0 = SS2
  ADDL     (disp + 1*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  ADDL     h, y2;                            \ // y2 = h + SS1 + W    
  ADDL     (disp + 1*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
  MOVL     a, y1;                            \
  XORL     b, y1;                            \
  XORL     c, y1;                            \
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
  ;                                          \
  MOVL     e, y1;                            \
  XORL     f, y1;                            \
  XORL     g, y1;                            \
  ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
  ;                                          \
  ROLL     $9, b;                            \
  ROLL     $19, f;                           \
  MOVL     y0, h;                            \ // h = tt1
  ;                                          \
  RORXL    $-9, y2, y0;                      \
  RORXL    $-17, y2, y1;                     \
  XORL     y0, y2;                           \
  XORL     y1, y2;                           \
  MOVL     y2, d                               // d = P(tt2)

#define ROUND_N_0_2(disp, const, a, b, c, d, e, f, g, h) \
	;                                          \ // #############################  RND N + 2 ############################//
	RORXL    $-12, a, y0;                      \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  ADDL     $const, y1;                       \
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  RORXL    $-7, y1, y2;                      \ // y2 = SS1
  XORL     y2, y0                            \ // y0 = SS2
  ADDL     (disp + 2*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  ADDL     h, y2;                            \ // y2 = h + SS1 + W    
  ADDL     (disp + 2*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
  MOVL     a, y1;                            \
  XORL     b, y1;                            \
  XORL     c, y1;                            \
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
  ;                                          \
  MOVL     e, y1;                            \
  XORL     f, y1;                            \
  XORL     g, y1;                            \
  ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
  ;                                          \
  ROLL     $9, b;                            \
  ROLL     $19, f;                           \
  MOVL     y0, h;                            \ // h = tt1
  ;                                          \
  RORXL    $-9, y2, y0;                      \
  RORXL    $-17, y2, y1;                     \
  XORL     y0, y2;                           \
  XORL     y1, y2;                           \
  MOVL     y2, d                               // d = P(tt2)

#define ROUND_N_0_3(disp, const, a, b, c, d, e, f, g, h) \
	;                                          \ // #############################  RND N + 3 ############################//
	RORXL    $-12, a, y0;                      \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  ADDL     $const, y1;                       \
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  RORXL    $-7, y1, y2;                      \ // y2 = SS1
  XORL     y2, y0                            \ // y0 = SS2
  ADDL     (disp + 3*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  ADDL     h, y2;                            \ // y2 = h + SS1 + W    
  ADDL     (disp + 3*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
  MOVL     a, y1;                            \
  XORL     b, y1;                            \
  XORL     c, y1;                            \
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
  ;                                          \
  MOVL     e, y1;                            \
  XORL     f, y1;                            \
  XORL     g, y1;                            \
  ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
  ;                                          \
  ROLL     $9, b;                            \
  ROLL     $19, f;                           \
  MOVL     y0, h;                            \ // h = tt1
  ;                                          \
  RORXL    $-9, y2, y0;                      \
  RORXL    $-17, y2, y1;                     \
  XORL     y0, y2;                           \
  XORL     y1, y2;                           \
  MOVL     y2, d                               // d = P(tt2)

#define ROUND_N_1_0(disp, const, a, b, c, d, e, f, g, h) \
	;                                          \ // #############################  RND N + 0 ############################//
	RORXL    $-12, a, y0;                      \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  ADDL     $const, y1;                       \
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  RORXL    $-7, y1, y2;                      \ // y2 = SS1
  XORL     y2, y0                            \ // y0 = SS2
  ADDL     (disp + 0*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  ADDL     h, y2;                            \ // y2 = h + SS1 + W    
  ADDL     (disp + 0*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
  MOVL     a, y1;                            \
  MOVL     b, y3;                            \
  ANDL     y1, y3;                           \
  MOVL     c, T1;                            \
  ANDL     T1, y1;                           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c)
  MOVL     b, y3;                            \
  ANDL     T1, y3;                           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c) OR (b AND c)
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
  ;                                          \
  MOVL     e, y1;                            \
  MOVL     f, y3;                            \
  ANDL     y1, y3;                           \ // y3 = e AND f
  NOTL     y1;                               \
  MOVL     g, T1;                            \
  ANDL     T1, y1;                           \ // y1 = NOT(e) AND g
  ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
  ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
  ;                                          \
  ROLL     $9, b;                            \
  ROLL     $19, f;                           \
  MOVL     y0, h;                            \ // h = tt1
  ;                                          \
  RORXL    $-9, y2, y0;                      \
  RORXL    $-17, y2, y1;                     \
  XORL     y0, y2;                           \
  XORL     y1, y2;                           \
  MOVL     y2, d                               // d = P(tt2)

#define ROUND_N_1_1(disp, const, a, b, c, d, e, f, g, h) \
	;                                          \ // #############################  RND N + 1 ############################//
	RORXL    $-12, a, y0;                      \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  ADDL     $const, y1;                       \
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  RORXL    $-7, y1, y2;                      \ // y2 = SS1
  XORL     y2, y0                            \ // y0 = SS2
  ADDL     (disp + 1*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  ADDL     h, y2;                            \ // y2 = h + SS1 + W    
  ADDL     (disp + 1*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
  MOVL     a, y1;                            \
  MOVL     b, y3;                            \
  ANDL     y1, y3;                           \
  MOVL     c, T1;                            \
  ANDL     T1, y1;                           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c)
  MOVL     b, y3;                            \
  ANDL     T1, y3;                           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c) OR (b AND c)
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
  ;                                          \
  MOVL     e, y1;                            \
  MOVL     f, y3;                            \
  ANDL     y1, y3;                           \ // y3 = e AND f
  NOTL     y1;                               \
  MOVL     g, T1;                            \
  ANDL     T1, y1;                           \ // y1 = NOT(e) AND g
  ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
  ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
  ;                                          \
  ROLL     $9, b;                            \
  ROLL     $19, f;                           \
  MOVL     y0, h;                            \ // h = tt1
  ;                                          \
  RORXL    $-9, y2, y0;                      \
  RORXL    $-17, y2, y1;                     \
  XORL     y0, y2;                           \
  XORL     y1, y2;                           \
  MOVL     y2, d                               // d = P(tt2)

#define ROUND_N_1_2(disp, const, a, b, c, d, e, f, g, h) \
	;                                          \ // #############################  RND N + 2 ############################//
	RORXL    $-12, a, y0;                      \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  ADDL     $const, y1;                       \
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  RORXL    $-7, y1, y2;                      \ // y2 = SS1
  XORL     y2, y0                            \ // y0 = SS2
  ADDL     (disp + 2*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  ADDL     h, y2;                            \ // y2 = h + SS1 + W    
  ADDL     (disp + 2*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
  MOVL     a, y1;                            \
  MOVL     b, y3;                            \
  ANDL     y1, y3;                           \
  MOVL     c, T1;                            \
  ANDL     T1, y1;                           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c)
  MOVL     b, y3;                            \
  ANDL     T1, y3;                           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c) OR (b AND c)
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
  ;                                          \
  MOVL     e, y1;                            \
  MOVL     f, y3;                            \
  ANDL     y1, y3;                           \ // y3 = e AND f
  NOTL     y1;                               \
  MOVL     g, T1;                            \
  ANDL     T1, y1;                           \ // y1 = NOT(e) AND g
  ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
  ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
  ;                                          \
  ROLL     $9, b;                            \
  ROLL     $19, f;                           \
  MOVL     y0, h;                            \ // h = tt1
  ;                                          \
  RORXL    $-9, y2, y0;                      \
  RORXL    $-17, y2, y1;                     \
  XORL     y0, y2;                           \
  XORL     y1, y2;                           \
  MOVL     y2, d                               // d = P(tt2)

#define ROUND_N_1_3(disp, const, a, b, c, d, e, f, g, h) \
	;                                          \ // #############################  RND N + 3 ############################//
	RORXL    $-12, a, y0;                      \ // y0 = a <<< 12
  MOVL     e, y1;                            \
  ADDL     $const, y1;                       \
  ADDL     y0, y1;                           \ // y1 = a <<< 12 + e + T
  RORXL    $-7, y1, y2;                      \ // y2 = SS1
  XORL     y2, y0                            \ // y0 = SS2
  ADDL     (disp + 3*4)(SP)(SRND*1), y2;     \ // y2 = SS1 + W
  ADDL     h, y2;                            \ // y2 = h + SS1 + W    
  ADDL     (disp + 3*4 + 32)(SP)(SRND*1), y0;\ // y2 = SS2 + W'
  ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	;                                          \
  MOVL     a, y1;                            \
  MOVL     b, y3;                            \
  ANDL     y1, y3;                           \
  MOVL     c, T1;                            \
  ANDL     T1, y1;                           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c)
  MOVL     b, y3;                            \
  ANDL     T1, y3;                           \
  ORL      y3, y1;                           \ // y1 =  (a AND b) OR (a AND c) OR (b AND c)
  ADDL     y1, y0;                           \ // y0 = FF(a, b, c) + d + SS2 + W' = tt1
  ;                                          \
  MOVL     e, y1;                            \
  MOVL     f, y3;                            \
  ANDL     y1, y3;                           \ // y3 = e AND f
  NOTL     y1;                               \
  MOVL     g, T1;                            \
  ANDL     T1, y1;                           \ // y1 = NOT(e) AND g
  ORL      y3, y1;                           \ // y1 = (e AND f) OR (NOT(e) AND g)
  ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
  ;                                          \
  ROLL     $9, b;                            \
  ROLL     $19, f;                           \
  MOVL     y0, h;                            \ // h = tt1
  ;                                          \
  RORXL    $-9, y2, y0;                      \
  RORXL    $-17, y2, y1;                     \
  XORL     y0, y2;                           \
  XORL     y1, y2;                           \
  MOVL     y2, d                               // d = P(tt2)

TEXT ·block(SB), 0, $1048-32
	CMPB ·useAVX2(SB), $1
	JE   avx2

	MOVQ p_base+8(FP), SI
	MOVQ p_len+16(FP), DX
	SHRQ $6, DX
	SHLQ $6, DX

	LEAQ (SI)(DX*1), DI
	MOVQ DI, 272(SP)
	CMPQ SI, DI
	JEQ  end

	MOVQ dig+0(FP), BP
	MOVL (0*4)(BP), R8  // a = H0
	MOVL (1*4)(BP), R9  // b = H1
	MOVL (2*4)(BP), R10 // c = H2
	MOVL (3*4)(BP), R11 // d = H3
	MOVL (4*4)(BP), R12 // e = H4
	MOVL (5*4)(BP), R13 // f = H5
	MOVL (6*4)(BP), R14 // g = H6
	MOVL (7*4)(BP), R15 // h = H7

loop:
	MOVQ SP, BP

  MSGSCHEDULE0(0)
  MSGSCHEDULE0(1)
  MSGSCHEDULE0(2)
  MSGSCHEDULE0(3)

  SM3ROUND0(0, 0x79cc4519, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND0(1, 0xf3988a32, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND0(2, 0xe7311465, R14, R15, R8, R9, R10, R11, R12, R13)
  SM3ROUND0(3, 0xce6228cb, R13, R14, R15, R8, R9, R10, R11, R12)
  SM3ROUND0(4, 0x9cc45197, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND0(5, 0x3988a32f, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND0(6, 0x7311465e, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND0(7, 0xe6228cbc, R9, R10, R11, R12, R13, R14, R15, R8)
  SM3ROUND0(8, 0xcc451979, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND0(9, 0x988a32f3, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND0(10, 0x311465e7, R14, R15, R8, R9, R10, R11, R12, R13)
  SM3ROUND0(11, 0x6228cbce, R13, R14, R15, R8, R9, R10, R11, R12)
  
  SM3ROUND1(12, 0xc451979c, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND1(13, 0x88a32f39, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND1(14, 0x11465e73, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND1(15, 0x228cbce6, R9, R10, R11, R12, R13, R14, R15, R8)
  
  SM3ROUND2(16, 0x9d8a7a87, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND2(17, 0x3b14f50f, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND2(18, 0x7629ea1e, R14, R15, R8, R9, R10, R11, R12, R13)
  SM3ROUND2(19, 0xec53d43c, R13, R14, R15, R8, R9, R10, R11, R12)
  SM3ROUND2(20, 0xd8a7a879, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND2(21, 0xb14f50f3, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND2(22, 0x629ea1e7, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND2(23, 0xc53d43ce, R9, R10, R11, R12, R13, R14, R15, R8)
  SM3ROUND2(24, 0x8a7a879d, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND2(25, 0x14f50f3b, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND2(26, 0x29ea1e76, R14, R15, R8, R9, R10, R11, R12, R13)
  SM3ROUND2(27, 0x53d43cec, R13, R14, R15, R8, R9, R10, R11, R12)
  SM3ROUND2(28, 0xa7a879d8, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND2(29, 0x4f50f3b1, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND2(30, 0x9ea1e762, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND2(31, 0x3d43cec5, R9, R10, R11, R12, R13, R14, R15, R8)
  SM3ROUND2(32, 0x7a879d8a, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND2(33, 0xf50f3b14, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND2(34, 0xea1e7629, R14, R15, R8, R9, R10, R11, R12, R13)
  SM3ROUND2(35, 0xd43cec53, R13, R14, R15, R8, R9, R10, R11, R12)
  SM3ROUND2(36, 0xa879d8a7, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND2(37, 0x50f3b14f, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND2(38, 0xa1e7629e, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND2(39, 0x43cec53d, R9, R10, R11, R12, R13, R14, R15, R8)
  SM3ROUND2(40, 0x879d8a7a, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND2(41, 0xf3b14f5, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND2(42, 0x1e7629ea, R14, R15, R8, R9, R10, R11, R12, R13)
  SM3ROUND2(43, 0x3cec53d4, R13, R14, R15, R8, R9, R10, R11, R12)
  SM3ROUND2(44, 0x79d8a7a8, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND2(45, 0xf3b14f50, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND2(46, 0xe7629ea1, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND2(47, 0xcec53d43, R9, R10, R11, R12, R13, R14, R15, R8)
  SM3ROUND2(48, 0x9d8a7a87, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND2(49, 0x3b14f50f, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND2(50, 0x7629ea1e, R14, R15, R8, R9, R10, R11, R12, R13)
  SM3ROUND2(51, 0xec53d43c, R13, R14, R15, R8, R9, R10, R11, R12)
  SM3ROUND2(52, 0xd8a7a879, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND2(53, 0xb14f50f3, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND2(54, 0x629ea1e7, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND2(55, 0xc53d43ce, R9, R10, R11, R12, R13, R14, R15, R8)
  SM3ROUND2(56, 0x8a7a879d, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND2(57, 0x14f50f3b, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND2(58, 0x29ea1e76, R14, R15, R8, R9, R10, R11, R12, R13)
  SM3ROUND2(59, 0x53d43cec, R13, R14, R15, R8, R9, R10, R11, R12)
  SM3ROUND2(60, 0xa7a879d8, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND2(61, 0x4f50f3b1, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND2(62, 0x9ea1e762, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND2(63, 0x3d43cec5, R9, R10, R11, R12, R13, R14, R15, R8)

	MOVQ dig+0(FP), BP

	XORL (0*4)(BP), R8  // H0 = a XOR H0
	MOVL R8, (0*4)(BP)
	XORL (1*4)(BP), R9  // H1 = b XOR H1
	MOVL R9, (1*4)(BP)
	XORL (2*4)(BP), R10 // H2 = c XOR H2
	MOVL R10, (2*4)(BP)
	XORL (3*4)(BP), R11 // H3 = d XOR H3
	MOVL R11, (3*4)(BP)
	XORL (4*4)(BP), R12 // H4 = e XOR H4
	MOVL R12, (4*4)(BP)
	XORL (5*4)(BP), R13 // H5 = f XOR H5
	MOVL R13, (5*4)(BP)
	XORL (6*4)(BP), R14 // H6 = g XOR H6
	MOVL R14, (6*4)(BP)
	XORL (7*4)(BP), R15 // H7 = h XOR H7
	MOVL R15, (7*4)(BP)

	ADDQ $64, SI
	CMPQ SI, 272(SP)
	JB   loop

end:
	RET

avx2:
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

avx2_loop0: // at each iteration works with one block (512 bit)

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

avx2_loop1: // for w0 - w47
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

  // w48 - w63 processed with no scheduling (last 16 rounds)
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
	ROUND_N_1_0(_XFER + 2*32, 0xd8a7a879, e, f, g, h, a, b, c, d)
	ROUND_N_1_1(_XFER + 2*32, 0xb14f50f3, d, e, f, g, h, a, b, c)
	ROUND_N_1_2(_XFER + 2*32, 0x629ea1e7, c, d, e, f, g, h, a, b)
	ROUND_N_1_3(_XFER + 2*32, 0xc53d43ce, b, c, d, e, f, g, h, a)

	// Do 4 rounds and scheduling
  VMOVDQU XDWORD2, (_XFER + 4*32)(SP)(SRND*1)
	VPXOR  XDWORD2, XDWORD3, XFER
	VMOVDQU XFER, (_XFER + 5*32)(SP)(SRND*1)
	ROUND_N_1_0(_XFER + 4*32, 0x8a7a879d, a, b, c, d, e, f, g, h)
	ROUND_N_1_1(_XFER + 4*32, 0x14f50f3b, h, a, b, c, d, e, f, g)
	ROUND_N_1_2(_XFER + 4*32, 0x29ea1e76, g, h, a, b, c, d, e, f)
	ROUND_N_1_3(_XFER + 4*32, 0x53d43cec, f, g, h, a, b, c, d, e)

	// Do 4 rounds and scheduling
  VMOVDQU XDWORD3, (_XFER + 6*32)(SP)(SRND*1)
	VPXOR  XDWORD3, XDWORD0, XFER
	VMOVDQU XFER, (_XFER + 7*32)(SP)(SRND*1)
	ROUND_N_1_0(_XFER + 6*32, 0xa7a879d8, e, f, g, h, a, b, c, d)
	ROUND_N_1_1(_XFER + 6*32, 0x4f50f3b1, d, e, f, g, h, a, b, c)
	ROUND_N_1_2(_XFER + 6*32, 0x9ea1e762, c, d, e, f, g, h, a, b)
	ROUND_N_1_3(_XFER + 6*32, 0x3d43cec5, b, c, d, e, f, g, h, a)

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

avx2_loop3: // Do second block using previously scheduled results
	ROUND_N_0_0(_XFER + 0*32 + 16, 0x79cc4519, a, b, c, d, e, f, g, h)
	ROUND_N_0_1(_XFER + 0*32 + 16, 0xf3988a32, h, a, b, c, d, e, f, g)
	ROUND_N_0_2(_XFER + 0*32 + 16, 0xe7311465, g, h, a, b, c, d, e, f)
	ROUND_N_0_3(_XFER + 0*32 + 16, 0xce6228cb, f, g, h, a, b, c, d, e)

	ROUND_N_0_0(_XFER + 2*32 + 16, 0x9cc45197, e, f, g, h, a, b, c, d)
	ROUND_N_0_1(_XFER + 2*32 + 16, 0x3988a32f, d, e, f, g, h, a, b, c)
	ROUND_N_0_2(_XFER + 2*32 + 16, 0x7311465e, c, d, e, f, g, h, a, b)
	ROUND_N_0_3(_XFER + 2*32 + 16, 0xe6228cbc, b, c, d, e, f, g, h, a)

	ROUND_N_0_0(_XFER + 4*32 + 16, 0xcc451979, a, b, c, d, e, f, g, h)
	ROUND_N_0_1(_XFER + 4*32 + 16, 0x988a32f3, h, a, b, c, d, e, f, g)
	ROUND_N_0_2(_XFER + 4*32 + 16, 0x311465e7, g, h, a, b, c, d, e, f)
	ROUND_N_0_3(_XFER + 4*32 + 16, 0x6228cbce, f, g, h, a, b, c, d, e)

	ROUND_N_0_0(_XFER + 6*32 + 16, 0xc451979c, e, f, g, h, a, b, c, d)
	ROUND_N_0_1(_XFER + 6*32 + 16, 0x88a32f39, d, e, f, g, h, a, b, c)
	ROUND_N_0_2(_XFER + 6*32 + 16, 0x11465e73, c, d, e, f, g, h, a, b)
	ROUND_N_0_3(_XFER + 6*32 + 16, 0x228cbce6, b, c, d, e, f, g, h, a)

  ADDQ $8*32, SRND

  ROUND_N_1_0(_XFER + 0*32 + 16, 0x9d8a7a87, a, b, c, d, e, f, g, h)
	ROUND_N_1_1(_XFER + 0*32 + 16, 0x3b14f50f, h, a, b, c, d, e, f, g)
	ROUND_N_1_2(_XFER + 0*32 + 16, 0x7629ea1e, g, h, a, b, c, d, e, f)
	ROUND_N_1_3(_XFER + 0*32 + 16, 0xec53d43c, f, g, h, a, b, c, d, e)

	ROUND_N_1_0(_XFER + 2*32 + 16, 0xd8a7a879, e, f, g, h, a, b, c, d)
	ROUND_N_1_1(_XFER + 2*32 + 16, 0xb14f50f3, d, e, f, g, h, a, b, c)
	ROUND_N_1_2(_XFER + 2*32 + 16, 0x629ea1e7, c, d, e, f, g, h, a, b)
	ROUND_N_1_3(_XFER + 2*32 + 16, 0xc53d43ce, b, c, d, e, f, g, h, a)

	ROUND_N_1_0(_XFER + 4*32 + 16, 0x8a7a879d, a, b, c, d, e, f, g, h)
	ROUND_N_1_1(_XFER + 4*32 + 16, 0x14f50f3b, h, a, b, c, d, e, f, g)
	ROUND_N_1_2(_XFER + 4*32 + 16, 0x29ea1e76, g, h, a, b, c, d, e, f)
	ROUND_N_1_3(_XFER + 4*32 + 16, 0x53d43cec, f, g, h, a, b, c, d, e)

	ROUND_N_1_0(_XFER + 6*32 + 16, 0xa7a879d8, e, f, g, h, a, b, c, d)
	ROUND_N_1_1(_XFER + 6*32 + 16, 0x4f50f3b1, d, e, f, g, h, a, b, c)
	ROUND_N_1_2(_XFER + 6*32 + 16, 0x9ea1e762, c, d, e, f, g, h, a, b)
	ROUND_N_1_3(_XFER + 6*32 + 16, 0x3d43cec5, b, c, d, e, f, g, h, a)

  ADDQ $8*32, SRND

  ROUND_N_1_0(_XFER + 0*32 + 16, 0x7a879d8a, a, b, c, d, e, f, g, h)
	ROUND_N_1_1(_XFER + 0*32 + 16, 0xf50f3b14, h, a, b, c, d, e, f, g)
	ROUND_N_1_2(_XFER + 0*32 + 16, 0xea1e7629, g, h, a, b, c, d, e, f)
	ROUND_N_1_3(_XFER + 0*32 + 16, 0xd43cec53, f, g, h, a, b, c, d, e)

	ROUND_N_1_0(_XFER + 2*32 + 16, 0xa879d8a7, e, f, g, h, a, b, c, d)
	ROUND_N_1_1(_XFER + 2*32 + 16, 0x50f3b14f, d, e, f, g, h, a, b, c)
	ROUND_N_1_2(_XFER + 2*32 + 16, 0xa1e7629e, c, d, e, f, g, h, a, b)
	ROUND_N_1_3(_XFER + 2*32 + 16, 0x43cec53d, b, c, d, e, f, g, h, a)

	ROUND_N_1_0(_XFER + 4*32 + 16, 0x879d8a7a, a, b, c, d, e, f, g, h)
	ROUND_N_1_1(_XFER + 4*32 + 16, 0xf3b14f5, h, a, b, c, d, e, f, g)
	ROUND_N_1_2(_XFER + 4*32 + 16, 0x1e7629ea, g, h, a, b, c, d, e, f)
	ROUND_N_1_3(_XFER + 4*32 + 16, 0x3cec53d4, f, g, h, a, b, c, d, e)

	ROUND_N_1_0(_XFER + 6*32 + 16, 0x79d8a7a8, e, f, g, h, a, b, c, d)
	ROUND_N_1_1(_XFER + 6*32 + 16, 0xf3b14f50, d, e, f, g, h, a, b, c)
	ROUND_N_1_2(_XFER + 6*32 + 16, 0xe7629ea1, c, d, e, f, g, h, a, b)
	ROUND_N_1_3(_XFER + 6*32 + 16, 0xcec53d43, b, c, d, e, f, g, h, a)

  ADDQ $8*32, SRND

  ROUND_N_1_0(_XFER + 0*32 + 16, 0x9d8a7a87, a, b, c, d, e, f, g, h)
	ROUND_N_1_1(_XFER + 0*32 + 16, 0x3b14f50f, h, a, b, c, d, e, f, g)
	ROUND_N_1_2(_XFER + 0*32 + 16, 0x7629ea1e, g, h, a, b, c, d, e, f)
	ROUND_N_1_3(_XFER + 0*32 + 16, 0xec53d43c, f, g, h, a, b, c, d, e)

	ROUND_N_1_0(_XFER + 2*32 + 16, 0xd8a7a879, e, f, g, h, a, b, c, d)
	ROUND_N_1_1(_XFER + 2*32 + 16, 0xb14f50f3, d, e, f, g, h, a, b, c)
	ROUND_N_1_2(_XFER + 2*32 + 16, 0x629ea1e7, c, d, e, f, g, h, a, b)
	ROUND_N_1_3(_XFER + 2*32 + 16, 0xc53d43ce, b, c, d, e, f, g, h, a)

	ROUND_N_1_0(_XFER + 4*32 + 16, 0x8a7a879d, a, b, c, d, e, f, g, h)
	ROUND_N_1_1(_XFER + 4*32 + 16, 0x14f50f3b, h, a, b, c, d, e, f, g)
	ROUND_N_1_2(_XFER + 4*32 + 16, 0x29ea1e76, g, h, a, b, c, d, e, f)
	ROUND_N_1_3(_XFER + 4*32 + 16, 0x53d43cec, f, g, h, a, b, c, d, e)

	ROUND_N_1_0(_XFER + 6*32 + 16, 0xa7a879d8, e, f, g, h, a, b, c, d)
	ROUND_N_1_1(_XFER + 6*32 + 16, 0x4f50f3b1, d, e, f, g, h, a, b, c)
	ROUND_N_1_2(_XFER + 6*32 + 16, 0x9ea1e762, c, d, e, f, g, h, a, b)
	ROUND_N_1_3(_XFER + 6*32 + 16, 0x3d43cec5, b, c, d, e, f, g, h, a)

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
	JA   avx2_loop0
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
