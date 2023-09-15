//go:build arm64 && !purego
// +build arm64,!purego

#include "textflag.h"

#define XWORD0 V0
#define XWORD1 V1
#define XWORD2 V2
#define XWORD3 V3

#define XTMP0 V4
#define XTMP1 V5
#define XTMP2 V6
#define XTMP3 V7
#define XTMP4 V8

#define a R0
#define b R1
#define c R2
#define d R3
#define e R4
#define f R5
#define g R6
#define h R7

#define y0 R8
#define y1 R9
#define y2 R10
#define y3 R11

#define NUM_BYTES R12
#define INP	R13
#define CTX R14 // Beginning of digest in memory (a, b, c, ... , h)

#define a1 R15
#define b1 R16
#define c1 R19
#define d1 R20
#define e1 R21
#define f1 R22
#define g1 R23
#define h1 R24

// For rounds [0 - 16)
#define ROUND_AND_SCHED_N_0_0(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	VEXT $12, XWORD1.B16, XWORD0.B16, XTMP0.B16;  \ // XTMP0 = W[-13] = {w6,w5,w4,w3}, Vm = XWORD1, Vn = XWORD0
	RORW  $25, y1, y2;                            \ // y2 = SS1
	EORW  y2, y0;                                 \ // y0 = SS2
	MOVW  (disp + 0*4)(RSP), y1;                  \
	VSHL $7, XTMP0.S4, XTMP1.S4;                  \ 
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	MOVW  (disp + 16 + 0*4)(RSP), y1;             \
	VSRI $25, XTMP0.S4, XTMP1.S4;                 \ // XTMP1 = W[-13] rol 7
	ADDW  y1, y0;                                 \ // y0 = SS2 + W'
	ADDW  d, y0;                                  \ // y0 = d + SS2 + W'
	; \
	EORW  a, b, h;                                \
	VEXT $8, XWORD3.B16, XWORD2.B16, XTMP0.B16;   \ // XTMP0 = W[-6] = {w13,w12,w11,w10}
	EORW  c, h;                                   \
	ADDW  y0, h;                                  \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	; \
	EORW  e, f, y1;                               \
	VEOR XTMP1.B16, XTMP0.B16, XTMP0.B16;         \ // XTMP0 = W[-6] ^ (W[-13] rol 7)
	EORW  g, y1;                                  \
	ADDW  y1, y2;                                 \ // y2 = GG(e, f, g) + h + SS1 + W = tt2
	; \
	RORW  $23, b;                                 \
	VEXT $12, XWORD2.B16, XWORD1.B16, XTMP1.B16;  \ // XTMP1 = W[-9] = {w10,w9,w8,w7}, Vm = XWORD2, Vn = XWORD1
	RORW  $13, f;                                 \
	; \
	RORW  $23, y2, y0;                            \
	RORW  $15, y2, d;                             \
	VEOR XWORD0.B16, XTMP1.B16, XTMP1.B16;        \ // XTMP1 = W[-9] ^ W[-16]
	EORW  y0, d;                                  \
	EORW  y2, d;                                  \ // d = P(tt2)
	VEXT $4, XWORD2.B16, XWORD3.B16, XTMP3.B16;   \ // XTMP3 = W[-3] {w11,w15,w14,w13}

#define ROUND_AND_SCHED_N_0_1(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	VSHL $15, XTMP3.S4, XTMP2.S4;                 \
	RORW  $25, y1, y2;                            \ // y2 = SS1
	EORW  y2, y0;                                 \ // y0 = SS2
	MOVW  (disp + 1*4)(RSP), y1;                  \
	VSRI $17, XTMP3.S4, XTMP2.S4;                 \ // XTMP2 = W[-3] rol 15 {xxBA}
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	MOVW  (disp + 16 + 1*4)(RSP), y1;             \
	VEOR XTMP1.B16, XTMP2.B16, XTMP2.B16;         \ // XTMP2 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {xxBA}
	ADDW  y1, y0;                                 \ // y0 = SS2 + W'
	ADDW  d, y0;                                  \ // y0 = d + SS2 + W'
	; \
	EORW  a, b, h;                                \
	VSHL $15, XTMP2.S4, XTMP4.S4;                 \
	EORW  c, h;                                   \
	ADDW  y0, h;                                  \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	; \
	EORW  e, f, y1;                               \
	VSRI $17, XTMP2.S4, XTMP4.S4;                 \ // XTMP4 =  = XTMP2 rol 15 {xxBA}
	EORW  g, y1;                                  \
	ADDW  y1, y2;                                 \ // y2 = GG(e, f, g) + h + SS1 + W = tt2
	; \
	RORW  $23, b;                                 \
	VSHL $8, XTMP4.S4, XTMP3.S4;                  \
	RORW  $13, f;                                 \
	; \
	RORW  $23, y2, y0;                            \
	RORW  $15, y2, d;                             \
	VSRI $24, XTMP4.S4, XTMP3.S4;                 \ // XTMP3 = XTMP2 rol 23 {xxBA}
	EORW  y0, d;                                  \
	EORW  y2, d;                                  \ // d = P(tt2)
	VEOR XTMP2.B16, XTMP4.B16, XTMP4.B16;         \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {xxBA})	

#define ROUND_AND_SCHED_N_0_2(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	VEOR XTMP4.B16, XTMP3.B16, XTMP4.B16;         \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {xxBA}) XOR (XTMP2 rol 23 {xxBA})
	RORW  $25, y1, y2;                            \ // y2 = SS1
	EORW  y2, y0;                                 \ // y0 = SS2
	MOVW  (disp + 2*4)(RSP), y1;                  \
	VEOR XTMP4.B16, XTMP0.B16, XTMP2.B16;         \ // XTMP2 = {..., ..., W[1], W[0]}
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	MOVW  (disp + 16 + 2*4)(RSP), y1;             \
	VEXT $4, XTMP2.B16, XWORD3.B16, XTMP3.B16;    \ // XTMP3 = W[-3] {W[0],w15, w14, w13}, Vm = XTMP2, Vn = XWORD3
	ADDW  y1, y0;                                 \ // y0 = SS2 + W'
	ADDW  d, y0;                                  \ // y0 = d + SS2 + W'
	; \
	EORW  a, b, h;                                \
	VSHL $15, XTMP3.S4, XTMP4.S4;                 \
	EORW  c, h;                                   \
	ADDW  y0, h;                                  \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	; \
	EORW  e, f, y1;                               \
	VSRI $17, XTMP3.S4, XTMP4.S4;                 \ // XTMP4 = W[-3] rol 15 {DCxx}
	EORW  g, y1;                                  \
	ADDW  y1, y2;                                 \ // y2 = GG(e, f, g) + h + SS1 + W = tt2
	; \
	RORW  $23, b;                                 \
	VEOR XTMP1.B16, XTMP4.B16, XTMP4.B16;         \ // XTMP4 = W[-9] XOR W[-16] XOR (W[-3] rol 15) {DCxx}
	RORW  $13, f;                                 \
	; \
	RORW  $23, y2, y0;                            \
	RORW  $15, y2, d;                             \
	VSHL $15, XTMP4.S4, XTMP3.S4;                 \
	EORW  y0, d;                                  \
	EORW  y2, d;                                  \ // d = P(tt2)
	VSRI $17, XTMP4.S4, XTMP3.S4;                 \ // XTMP3 = XTMP4 rol 15 {DCxx}

#define ROUND_AND_SCHED_N_0_3(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	RORW  $25, y1, y2;                            \ // y2 = SS1
	VSHL $8, XTMP3.S4, XTMP1.S4;                  \
	EORW  y2, y0;                                 \ // y0 = SS2
	MOVW  (disp + 3*4)(RSP), y1;                  \
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	VSRI $24, XTMP3.S4, XTMP1.S4;                 \ // XTMP1 = XTMP4 rol 23 {DCxx}
	MOVW  (disp + 16 + 3*4)(RSP), y1;             \
	ADDW  y1, y0;                                 \ // y0 = SS2 + W'
	ADDW  d, y0;                                  \ // y0 = d + SS2 + W'
	; \
	VEOR XTMP3.B16, XTMP4.B16, XTMP3.B16;         \ // XTMP3 = XTMP4 XOR (XTMP4 rol 15 {DCxx})
	EORW  a, b, h;                                \
	EORW  c, h;                                   \
	ADDW  y0, h;                                  \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	VEOR XTMP3.B16, XTMP1.B16, XTMP1.B16;         \ // XTMP1 = XTMP4 XOR (XTMP4 rol 15 {DCxx}) XOR (XTMP4 rol 23 {DCxx})
	; \
	EORW  e, f, y1;                               \
	EORW  g, y1;                                  \
	ADDW  y1, y2;                                 \ // y2 = GG(e, f, g) + h + SS1 + W = tt2
	VEOR XTMP1.B16, XTMP0.B16, XTMP1.B16;         \ // XTMP1 = {W[3], W[2], ..., ...}
	; \
	RORW  $23, b;                                 \
	RORW  $13, f;                                 \
	; \
	RORW  $23, y2, y0;                            \
	VEXT $8, XTMP2.B16, XTMP1.B16, XTMP3.B16;     \ // XTMP3 = {W[1], W[0], W[3], W[2]}, Vm = XTMP2, Vn = XTMP1
	RORW  $15, y2, d;                             \
	EORW  y0, d;                                  \
	EORW  y2, d;                                  \ // d = P(tt2)
	VEXT $8, XTMP3.B16, XTMP3.B16, XWORD0.B16;    \ // XWORD0 = {W[3], W[2], W[1], W[0]}	

// For rounds [16 - 64)
#define ROUND_AND_SCHED_N_1_0(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	VEXT $12, XWORD1.B16, XWORD0.B16, XTMP0.B16;  \ // XTMP0 = W[-13] = {w6,w5,w4,w3}, Vm = XWORD1, Vn = XWORD0
	RORW  $25, y1, y2;                            \ // y2 = SS1
	EORW  y2, y0;                                 \ // y0 = SS2
	MOVW  (disp + 0*4)(RSP), y1;                  \
	VSHL $7, XTMP0.S4, XTMP1.S4;                  \ 
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	MOVW  (disp + 16 + 0*4)(RSP), y1;             \
	VSRI $25, XTMP0.S4, XTMP1.S4;                 \ // XTMP1 = W[-13] rol 7
	ADDW  y1, y0;                                 \ // y0 = SS2 + W'
	ADDW  d, y0;                                  \ // y0 = d + SS2 + W'
	; \
	ANDW  a, b, y1;                               \
	VEXT $8, XWORD3.B16, XWORD2.B16, XTMP0.B16;   \ // XTMP0 = W[-6] = {w13,w12,w11,w10}
	ANDW  a, c, y3;                               \
	ORRW  y3, y1;                                 \ // y1 =  (a AND b) OR (a AND c)
	ANDW  b, c, h;                                \
	VEOR XTMP1.B16, XTMP0.B16, XTMP0.B16;         \ // XTMP0 = W[-6] ^ (W[-13] rol 7)
	ORRW  y1, h;                                  \ // h =  (a AND b) OR (a AND c) OR (b AND c)
	ADDW  y0, h;                                  \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	; \
	ANDW  e, f, y1;                               \
	BICW  e, g, y3;                               \
	VEXT $12, XWORD2.B16, XWORD1.B16, XTMP1.B16;  \ // XTMP1 = W[-9] = {w10,w9,w8,w7}, Vm = XWORD2, Vn = XWORD1
	ORRW  y3, y1;                                 \ // y1 = (e AND f) OR (NOT(e) AND g)
	ADDW  y1, y2;                                 \ // y2 = GG(e, f, g) + h + SS1 + W = tt2 
	; \
	RORW  $23, b;                                 \
	RORW  $13, f;                                 \
	VEOR XWORD0.B16, XTMP1.B16, XTMP1.B16;        \ // XTMP1 = W[-9] ^ W[-16]
	; \
	RORW  $23, y2, y0;                            \
	RORW  $15, y2, d;                             \
	EORW  y0, d;                                  \
	EORW  y2, d;                                  \ // d = P(tt2)	
	VEXT $4, XWORD2.B16, XWORD3.B16, XTMP3.B16;   \ // XTMP3 = W[-3] {w11,w15,w14,w13}

#define ROUND_AND_SCHED_N_1_1(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	VSHL $15, XTMP3.S4, XTMP2.S4;                 \           
	RORW  $25, y1, y2;                            \ // y2 = SS1
	EORW  y2, y0;                                 \ // y0 = SS2
	MOVW  (disp + 1*4)(RSP), y1;                  \
	VSRI $17, XTMP3.S4, XTMP2.S4;                 \ // XTMP2 = W[-3] rol 15 {xxBA}
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	MOVW  (disp + 16 + 1*4)(RSP), y1;             \
	VEOR XTMP1.B16, XTMP2.B16, XTMP2.B16;         \ // XTMP2 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {xxBA}
	ADDW  y1, y0;                                 \ // y0 = SS2 + W'
	ADDW  d, y0;                                  \ // y0 = d + SS2 + W'
	; \
	ANDW  a, b, y1;                               \
	VSHL $15, XTMP2.S4, XTMP4.S4;                 \
	ANDW  a, c, y3;                               \
	ORRW  y3, y1;                                 \ // y1 =  (a AND b) OR (a AND c)
	ANDW  b, c, h;                                \
	ORRW  y1, h;                                  \ // h =  (a AND b) OR (a AND c) OR (b AND c)
	VSRI $17, XTMP2.S4, XTMP4.S4;                 \ // XTMP4 =  = XTMP2 rol 15 {xxBA}
	ADDW  y0, h;                                  \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	; \
	ANDW  e, f, y1;                               \
	BICW  e, g, y3;                               \
	ORRW  y3, y1;                                 \ // y1 = (e AND f) OR (NOT(e) AND g)
	VSHL $8, XTMP4.S4, XTMP3.S4;                  \
	ADDW  y1, y2;                                 \ // y2 = GG(e, f, g) + h + SS1 + W = tt2 
	; \
	RORW  $23, b;                                 \
	RORW  $13, f;                                 \
	; \
	RORW  $23, y2, y0;                            \
	VSRI $24, XTMP4.S4, XTMP3.S4;                 \ // XTMP3 = XTMP2 rol 23 {xxBA}
	RORW  $15, y2, d;                             \
	EORW  y0, d;                                  \
	EORW  y2, d;                                  \ // d = P(tt2)	
	VEOR XTMP2.B16, XTMP4.B16, XTMP4.B16;         \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {xxBA})

#define ROUND_AND_SCHED_N_1_2(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	VEOR XTMP4.B16, XTMP3.B16, XTMP4.B16;         \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {xxBA}) XOR (XTMP2 rol 23 {xxBA})
	RORW  $25, y1, y2;                            \ // y2 = SS1
	EORW  y2, y0;                                 \ // y0 = SS2
	MOVW  (disp + 2*4)(RSP), y1;                  \
	VEOR XTMP4.B16, XTMP0.B16, XTMP2.B16;         \ // XTMP2 = {..., ..., W[1], W[0]}
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	MOVW  (disp + 16 + 2*4)(RSP), y1;             \
	VEXT $4, XTMP2.B16, XWORD3.B16, XTMP3.B16;    \ // XTMP3 = W[-3] {W[0],w15, w14, w13}, Vm = XTMP2, Vn = XWORD3
	ADDW  y1, y0;                                 \ // y0 = SS2 + W'
	ADDW  d, y0;                                  \ // y0 = d + SS2 + W'
	; \
	ANDW  a, b, y1;                               \
	VSHL $15, XTMP3.S4, XTMP4.S4;                 \
	ANDW  a, c, y3;                               \
	ORRW  y3, y1;                                 \ // y1 =  (a AND b) OR (a AND c)
	ANDW  b, c, h;                                \
	ORRW  y1, h;                                  \ // h =  (a AND b) OR (a AND c) OR (b AND c)
	VSRI $17, XTMP3.S4, XTMP4.S4;                 \ // XTMP4 = W[-3] rol 15 {DCxx}
	ADDW  y0, h;                                  \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	; \
	ANDW  e, f, y1;                               \
	BICW  e, g, y3;                               \
	ORRW  y3, y1;                                 \ // y1 = (e AND f) OR (NOT(e) AND g)
	VEOR XTMP1.B16, XTMP4.B16, XTMP4.B16;         \ // XTMP4 = W[-9] XOR W[-16] XOR (W[-3] rol 15) {DCxx}
	ADDW  y1, y2;                                 \ // y2 = GG(e, f, g) + h + SS1 + W = tt2 
	; \
	RORW  $23, b;                                 \
	RORW  $13, f;                                 \
	; \
	RORW  $23, y2, y0;                            \
	VSHL $15, XTMP4.S4, XTMP3.S4;                 \
	RORW  $15, y2, d;                             \
	EORW  y0, d;                                  \
	EORW  y2, d;                                  \ // d = P(tt2)	
	VSRI $17, XTMP4.S4, XTMP3.S4;                 \ // XTMP3 = XTMP4 rol 15 {DCxx}

#define ROUND_AND_SCHED_N_1_3(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	RORW  $25, y1, y2;                            \ // y2 = SS1
	VSHL $8, XTMP3.S4, XTMP1.S4;                  \
	EORW  y2, y0;                                 \ // y0 = SS2
	MOVW  (disp + 3*4)(RSP), y1;                  \
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	VSRI $24, XTMP3.S4, XTMP1.S4;                 \ // XTMP1 = XTMP4 rol 23 {DCxx}
	MOVW  (disp + 16 + 3*4)(RSP), y1;             \
	ADDW  y1, y0;                                 \ // y0 = SS2 + W'
	ADDW  d, y0;                                  \ // y0 = d + SS2 + W'
	; \
	ANDW  a, b, y1;                               \
	VEOR XTMP3.B16, XTMP4.B16, XTMP3.B16;         \ // XTMP3 = XTMP4 XOR (XTMP4 rol 15 {DCxx})
	ANDW  a, c, y3;                               \
	ORRW  y3, y1;                                 \ // y1 =  (a AND b) OR (a AND c)
	ANDW  b, c, h;                                \
	ORRW  y1, h;                                  \ // h =  (a AND b) OR (a AND c) OR (b AND c)
	VEOR XTMP3.B16, XTMP1.B16, XTMP1.B16;         \ // XTMP1 = XTMP4 XOR (XTMP4 rol 15 {DCxx}) XOR (XTMP4 rol 23 {DCxx})
	ADDW  y0, h;                                  \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	; \
	ANDW  e, f, y1;                               \
	BICW  e, g, y3;                               \
	ORRW  y3, y1;                                 \ // y1 = (e AND f) OR (NOT(e) AND g)
	VEOR XTMP1.B16, XTMP0.B16, XTMP1.B16;         \ // XTMP1 = {W[3], W[2], ..., ...}
	ADDW  y1, y2;                                 \ // y2 = GG(e, f, g) + h + SS1 + W = tt2 
	; \
	RORW  $23, b;                                 \
	RORW  $13, f;                                 \
	; \
	RORW  $23, y2, y0;                            \
	VEXT $8, XTMP2.B16, XTMP1.B16, XTMP3.B16;     \ // XTMP3 = {W[1], W[0], W[3], W[2]}, Vm = XTMP2, Vn = XTMP1
	RORW  $15, y2, d;                             \
	EORW  y0, d;                                  \
	EORW  y2, d;                                  \ // d = P(tt2)	
	VEXT $8, XTMP3.B16, XTMP3.B16, XWORD0.B16;    \ // XWORD0 = {W[3], W[2], W[1], W[0]}

// For rounds [16 - 64)
#define DO_ROUND_N_1(disp, idx, const, a, b, c, d, e, f, g, h) \
	RORW  $20, a, y0;                          \ // y0 = a <<< 12
	ADDW  $const, e, y1;                       \
	ADDW  y0, y1;                              \ // y1 = a <<< 12 + e + T
	RORW  $25, y1, y2;                         \ // y2 = SS1
	EORW  y2, y0;                              \ // y0 = SS2
	MOVW  (disp + idx*4)(RSP), y1;             \
	ADDW  y1, y2;                              \ // y2 = SS1 + W
	ADDW  h, y2;                               \ // y2 = h + SS1 + W
	MOVW  (disp + 16 + idx*4)(RSP), y1;        \
	ADDW  y1, y0;                              \ // y0 = SS2 + W'
	ADDW  d, y0;                               \ // y0 = d + SS2 + W'
	; \
	ANDW  a, b, y1;                            \
	ANDW  a, c, y3;                            \
	ORRW  y3, y1;                              \ // y1 =  (a AND b) OR (a AND c)
	ANDW  b, c, h;                             \
	ORRW  y1, h;                               \ // h =  (a AND b) OR (a AND c) OR (b AND c)
	ADDW  y0, h;                               \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	; \
	ANDW  e, f, y1;                            \
	BICW  e, g, y3;                            \
	ORRW  y3, y1;                              \ // y1 = (e AND f) OR (NOT(e) AND g)
	ADDW  y1, y2;                              \ // y2 = GG(e, f, g) + h + SS1 + W = tt2 
	; \
	RORW  $23, b;                              \
	RORW  $13, f;                              \
	; \
	RORW  $23, y2, y0;                         \
	RORW  $15, y2, d;                          \
	EORW  y0, d;                               \
	EORW  y2, d;                               \ // d = P(tt2)	

// func blockARM64(dig *digest, p []byte)
TEXT ·blockARM64(SB), 0, $32-32
	MOVD dig+0(FP), CTX
	MOVD p_base+8(FP), INP
	MOVD p_len+16(FP), NUM_BYTES

	AND	$~63, NUM_BYTES
	CBZ	NUM_BYTES, end  

	LDPW	(0*8)(CTX), (a, b)
	LDPW	(1*8)(CTX), (c, d)
	LDPW	(2*8)(CTX), (e, f)
	LDPW	(3*8)(CTX), (g, h)

loop:
	MOVW  a, a1
	MOVW  b, b1
	MOVW  c, c1
	MOVW  d, d1
	MOVW  e, e1
	MOVW  f, f1
	MOVW  g, g1
	MOVW  h, h1

	VLD1.P	64(INP), [XWORD0.B16, XWORD1.B16, XWORD2.B16, XWORD3.B16]
	VREV32	XWORD0.B16, XWORD0.B16
	VREV32	XWORD1.B16, XWORD1.B16
	VREV32	XWORD2.B16, XWORD2.B16
	VREV32	XWORD3.B16, XWORD3.B16

schedule_compress: // for w0 - w47
	// Do 4 rounds and scheduling
	VMOV XWORD0.B16, XTMP0.B16
	VEOR XWORD0.B16, XWORD1.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	ROUND_AND_SCHED_N_0_0(0*16, 0x79cc4519, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_0_1(0*16, 0xf3988a32, h, a, b, c, d, e, f, g, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_0_2(0*16, 0xe7311465, g, h, a, b, c, d, e, f, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_0_3(0*16, 0xce6228cb, f, g, h, a, b, c, d, e, XWORD0, XWORD1, XWORD2, XWORD3)

	// Do 4 rounds and scheduling
	VMOV XWORD1.B16, XTMP0.B16
	VEOR XWORD1.B16, XWORD2.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	ROUND_AND_SCHED_N_0_0(0*16, 0x9cc45197, e, f, g, h, a, b, c, d, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_0_1(0*16, 0x3988a32f, d, e, f, g, h, a, b, c, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_0_2(0*16, 0x7311465e, c, d, e, f, g, h, a, b, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_0_3(0*16, 0xe6228cbc, b, c, d, e, f, g, h, a, XWORD1, XWORD2, XWORD3, XWORD0)

	// Do 4 rounds and scheduling
	VMOV XWORD2.B16, XTMP0.B16
	VEOR XWORD2.B16, XWORD3.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	ROUND_AND_SCHED_N_0_0(0*16, 0xcc451979, a, b, c, d, e, f, g, h, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_0_1(0*16, 0x988a32f3, h, a, b, c, d, e, f, g, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_0_2(0*16, 0x311465e7, g, h, a, b, c, d, e, f, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_0_3(0*16, 0x6228cbce, f, g, h, a, b, c, d, e, XWORD2, XWORD3, XWORD0, XWORD1)

	// Do 4 rounds and scheduling
	VMOV XWORD3.B16, XTMP0.B16
	VEOR XWORD3.B16, XWORD0.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	ROUND_AND_SCHED_N_0_0(0*16, 0xc451979c, e, f, g, h, a, b, c, d, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_0_1(0*16, 0x88a32f39, d, e, f, g, h, a, b, c, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_0_2(0*16, 0x11465e73, c, d, e, f, g, h, a, b, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_0_3(0*16, 0x228cbce6, b, c, d, e, f, g, h, a, XWORD3, XWORD0, XWORD1, XWORD2)

	// Do 4 rounds and scheduling
	VMOV XWORD0.B16, XTMP0.B16
	VEOR XWORD0.B16, XWORD1.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	ROUND_AND_SCHED_N_1_0(0*16, 0x9d8a7a87, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_1(0*16, 0x3b14f50f, h, a, b, c, d, e, f, g, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_2(0*16, 0x7629ea1e, g, h, a, b, c, d, e, f, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_3(0*16, 0xec53d43c, f, g, h, a, b, c, d, e, XWORD0, XWORD1, XWORD2, XWORD3)

	// Do 4 rounds and scheduling
	VMOV XWORD1.B16, XTMP0.B16
	VEOR XWORD1.B16, XWORD2.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	ROUND_AND_SCHED_N_1_0(0*16, 0xd8a7a879, e, f, g, h, a, b, c, d, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_1_1(0*16, 0xb14f50f3, d, e, f, g, h, a, b, c, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_1_2(0*16, 0x629ea1e7, c, d, e, f, g, h, a, b, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_1_3(0*16, 0xc53d43ce, b, c, d, e, f, g, h, a, XWORD1, XWORD2, XWORD3, XWORD0)

	// Do 4 rounds and scheduling
	VMOV XWORD2.B16, XTMP0.B16
	VEOR XWORD2.B16, XWORD3.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	ROUND_AND_SCHED_N_1_0(0*16, 0x8a7a879d, a, b, c, d, e, f, g, h, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_1_1(0*16, 0x14f50f3b, h, a, b, c, d, e, f, g, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_1_2(0*16, 0x29ea1e76, g, h, a, b, c, d, e, f, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_1_3(0*16, 0x53d43cec, f, g, h, a, b, c, d, e, XWORD2, XWORD3, XWORD0, XWORD1)

	// Do 4 rounds and scheduling
	VMOV XWORD3.B16, XTMP0.B16
	VEOR XWORD3.B16, XWORD0.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	ROUND_AND_SCHED_N_1_0(0*16, 0xa7a879d8, e, f, g, h, a, b, c, d, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_1_1(0*16, 0x4f50f3b1, d, e, f, g, h, a, b, c, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_1_2(0*16, 0x9ea1e762, c, d, e, f, g, h, a, b, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_1_3(0*16, 0x3d43cec5, b, c, d, e, f, g, h, a, XWORD3, XWORD0, XWORD1, XWORD2)

	// Do 4 rounds and scheduling
	VMOV XWORD0.B16, XTMP0.B16
	VEOR XWORD0.B16, XWORD1.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	ROUND_AND_SCHED_N_1_0(0*16, 0x7a879d8a, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_1(0*16, 0xf50f3b14, h, a, b, c, d, e, f, g, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_2(0*16, 0xea1e7629, g, h, a, b, c, d, e, f, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_3(0*16, 0xd43cec53, f, g, h, a, b, c, d, e, XWORD0, XWORD1, XWORD2, XWORD3)

	// Do 4 rounds and scheduling
	VMOV XWORD1.B16, XTMP0.B16
	VEOR XWORD1.B16, XWORD2.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	ROUND_AND_SCHED_N_1_0(0*16, 0xa879d8a7, e, f, g, h, a, b, c, d, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_1_1(0*16, 0x50f3b14f, d, e, f, g, h, a, b, c, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_1_2(0*16, 0xa1e7629e, c, d, e, f, g, h, a, b, XWORD1, XWORD2, XWORD3, XWORD0)
	ROUND_AND_SCHED_N_1_3(0*16, 0x43cec53d, b, c, d, e, f, g, h, a, XWORD1, XWORD2, XWORD3, XWORD0)

	// Do 4 rounds and scheduling
	VMOV XWORD2.B16, XTMP0.B16
	VEOR XWORD2.B16, XWORD3.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	ROUND_AND_SCHED_N_1_0(0*16, 0x879d8a7a, a, b, c, d, e, f, g, h, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_1_1(0*16, 0xf3b14f5, h, a, b, c, d, e, f, g, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_1_2(0*16, 0x1e7629ea, g, h, a, b, c, d, e, f, XWORD2, XWORD3, XWORD0, XWORD1)
	ROUND_AND_SCHED_N_1_3(0*16, 0x3cec53d4, f, g, h, a, b, c, d, e, XWORD2, XWORD3, XWORD0, XWORD1)

	// Do 4 rounds and scheduling
	VMOV XWORD3.B16, XTMP0.B16
	VEOR XWORD3.B16, XWORD0.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	ROUND_AND_SCHED_N_1_0(0*16, 0x79d8a7a8, e, f, g, h, a, b, c, d, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_1_1(0*16, 0xf3b14f50, d, e, f, g, h, a, b, c, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_1_2(0*16, 0xe7629ea1, c, d, e, f, g, h, a, b, XWORD3, XWORD0, XWORD1, XWORD2)
	ROUND_AND_SCHED_N_1_3(0*16, 0xcec53d43, b, c, d, e, f, g, h, a, XWORD3, XWORD0, XWORD1, XWORD2)

	// w48 - w63 processed with only 4 rounds scheduling (last 16 rounds)
	// Do 4 rounds and scheduling
	VMOV XWORD0.B16, XTMP0.B16
	VEOR XWORD0.B16, XWORD1.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	ROUND_AND_SCHED_N_1_0(0*16, 0x9d8a7a87, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_1(0*16, 0x3b14f50f, h, a, b, c, d, e, f, g, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_2(0*16, 0x7629ea1e, g, h, a, b, c, d, e, f, XWORD0, XWORD1, XWORD2, XWORD3)
	ROUND_AND_SCHED_N_1_3(0*16, 0xec53d43c, f, g, h, a, b, c, d, e, XWORD0, XWORD1, XWORD2, XWORD3)  

	// w52 - w63 processed with no scheduling (last 12 rounds)
	// Do 4 rounds
	VMOV XWORD1.B16, XTMP0.B16
	VEOR XWORD1.B16, XWORD2.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	DO_ROUND_N_1(0*16, 0, 0xd8a7a879, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(0*16, 1, 0xb14f50f3, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(0*16, 2, 0x629ea1e7, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(0*16, 3, 0xc53d43ce, b, c, d, e, f, g, h, a)

	// Do 4 rounds
	VMOV XWORD2.B16, XTMP0.B16
	VEOR XWORD2.B16, XWORD3.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	DO_ROUND_N_1(0*16, 0, 0x8a7a879d, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(0*16, 1, 0x14f50f3b, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(0*16, 2, 0x29ea1e76, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(0*16, 3, 0x53d43cec, f, g, h, a, b, c, d, e)

	// Do 4 rounds
	VMOV XWORD3.B16, XTMP0.B16
	VEOR XWORD3.B16, XWORD0.B16, XTMP1.B16
	VST1 [XTMP0.B16, XTMP1.B16], (RSP)
	DO_ROUND_N_1(0*16, 0, 0xa7a879d8, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(0*16, 1, 0x4f50f3b1, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(0*16, 2, 0x9ea1e762, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(0*16, 3, 0x3d43cec5, b, c, d, e, f, g, h, a)

	EORW a1, a  // H0 = a XOR H0
	EORW b1, b  // H1 = b XOR H1
	EORW c1, c  // H0 = a XOR H0
	EORW d1, d  // H1 = b XOR H1
	EORW e1, e  // H0 = a XOR H0
	EORW f1, f  // H1 = b XOR H1
	EORW g1, g  // H0 = a XOR H0
	EORW h1, h  // H1 = b XOR H1
 
	SUB	$64, NUM_BYTES, NUM_BYTES
	CBNZ	NUM_BYTES, loop  	

	STPW	(a, b), (0*8)(CTX)
	STPW	(c, d), (1*8)(CTX)
	STPW	(e, f), (2*8)(CTX)
	STPW	(g, h), (3*8)(CTX)

end:	
	RET
