//go:build !purego

#include "textflag.h"

#include "sm3_const_asm.s"

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

#define NUM_BYTES R11
#define INP	R12
#define CTX R13 // Beginning of digest in memory (a, b, c, ... , h)

#define a1 R15
#define b1 R16
#define c1 R19
#define d1 R20
#define e1 R21
#define f1 R22
#define g1 R23
#define h1 R24

// For rounds [0 - 16)
#define ROUND_AND_SCHED_N_0_0(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3, Wt) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	VEXT $12, XWORD1.B16, XWORD0.B16, XTMP0.B16;  \ // XTMP0 = W[-13] = {w6,w5,w4,w3}, Vm = XWORD1, Vn = XWORD0
	RORW  $25, y1, y2;                            \ // y2 = SS1
	EORW  y2, y0;                                 \ // y0 = SS2
	VMOV  XWORD0.S[0], y1;                        \
	VSHL $7, XTMP0.S4, XTMP1.S4;                  \ 
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	VMOV  Wt.S[0], y1;                            \
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

#define ROUND_AND_SCHED_N_0_1(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3, Wt) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	VSHL $15, XTMP3.S4, XTMP2.S4;                 \
	RORW  $25, y1, y2;                            \ // y2 = SS1
	EORW  y2, y0;                                 \ // y0 = SS2
	VMOV  XWORD0.S[1], y1;                        \
	VSRI $17, XTMP3.S4, XTMP2.S4;                 \ // XTMP2 = W[-3] rol 15 {xxBA}
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	VMOV  Wt.S[1], y1;                            \
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

#define ROUND_AND_SCHED_N_0_2(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3, Wt) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	VEOR XTMP4.B16, XTMP3.B16, XTMP4.B16;         \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {xxBA}) XOR (XTMP2 rol 23 {xxBA})
	RORW  $25, y1, y2;                            \ // y2 = SS1
	EORW  y2, y0;                                 \ // y0 = SS2
	VMOV  XWORD0.S[2], y1;                        \
	VEOR XTMP4.B16, XTMP0.B16, XTMP2.B16;         \ // XTMP2 = {..., ..., W[1], W[0]}
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	VMOV  Wt.S[2], y1;                            \
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
	VSRI $17, XTMP3.S4, XTMP4.S4;                 \ // XTMP4 = W[-3] rol 15 {DCBA}
	EORW  g, y1;                                  \
	ADDW  y1, y2;                                 \ // y2 = GG(e, f, g) + h + SS1 + W = tt2
	RORW  $23, b;                                 \
	RORW  $13, f;                                 \
	VEOR XTMP1.B16, XTMP4.B16, XTMP4.B16;         \ // XTMP4 = W[-9] XOR W[-16] XOR (W[-3] rol 15) {DCBA}
	RORW  $23, y2, y0;                            \
	RORW  $15, y2, d;                             \
	EORW  y0, d;                                  \
	EORW  y2, d;                                  \ // d = P(tt2)
	VSHL $15, XTMP4.S4, XTMP3.S4;                 \

#define ROUND_AND_SCHED_N_0_3(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3, Wt) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	RORW  $25, y1, y2;                            \ // y2 = SS1
	VSRI $17, XTMP4.S4, XTMP3.S4;                 \ // XTMP3 = XTMP4 rol 15 {DCBA}
	EORW  y2, y0;                                 \ // y0 = SS2
	VMOV  XWORD0.S[3], y1;                        \
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	VSHL $8, XTMP3.S4, XTMP1.S4;                  \
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	VMOV  Wt.S[3], y1;                            \
	ADDW  y1, y0;                                 \ // y0 = SS2 + W'
	ADDW  d, y0;                                  \ // y0 = d + SS2 + W'
	VSRI $24, XTMP3.S4, XTMP1.S4;                 \ // XTMP1 = XTMP4 rol 23 {DCBA}
	EORW  a, b, h;                                \
	EORW  c, h;                                   \
	ADDW  y0, h;                                  \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	EORW  e, f, y1;                               \
	VEOR XTMP3.B16, XTMP4.B16, XTMP3.B16;         \ // XTMP3 = XTMP4 XOR (XTMP4 rol 15 {DCBA})
	EORW  g, y1;                                  \
	ADDW  y1, y2;                                 \ // y2 = GG(e, f, g) + h + SS1 + W = tt2
	RORW  $23, b;                                 \
	RORW  $13, f;                                 \
	VEOR XTMP3.B16, XTMP1.B16, XTMP1.B16;         \ // XTMP1 = XTMP4 XOR (XTMP4 rol 15 {DCBA}) XOR (XTMP4 rol 23 {DCBA})
	RORW  $23, y2, y0;                            \
	RORW  $15, y2, d;                             \
	EORW  y0, d;                                  \
	EORW  y2, d;                                  \ // d = P(tt2)
	VEOR XTMP1.B16, XTMP0.B16, XWORD0.B16;        \ // XWORD0 = {W[3], W[2], W[1], W[0]}	

// For rounds [16 - 64)
#define ROUND_AND_SCHED_N_1_0(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3, Wt) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	VEXT $12, XWORD1.B16, XWORD0.B16, XTMP0.B16;  \ // XTMP0 = W[-13] = {w6,w5,w4,w3}, Vm = XWORD1, Vn = XWORD0
	RORW  $25, y1, y2;                            \ // y2 = SS1
	EORW  y2, y0;                                 \ // y0 = SS2
	VMOV  XWORD0.S[0], y1;                        \
	VSHL $7, XTMP0.S4, XTMP1.S4;                  \ 
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	VMOV  Wt.S[0], y1;                            \
	VSRI $25, XTMP0.S4, XTMP1.S4;                 \ // XTMP1 = W[-13] rol 7
	ADDW  y1, y0;                                 \ // y0 = SS2 + W'
	ADDW  d, y0;                                  \ // y0 = d + SS2 + W'
	; \
	ORRW  a, b, y1;                               \
	VEXT $8, XWORD3.B16, XWORD2.B16, XTMP0.B16;   \ // XTMP0 = W[-6] = {w13,w12,w11,w10}
	ANDW  a, b, h;                                \
	ANDW  c, y1;                                  \
	ORRW  y1, h;                                  \ // h =  (a AND b) OR (a AND c) OR (b AND c)	
	VEOR XTMP1.B16, XTMP0.B16, XTMP0.B16;         \ // XTMP0 = W[-6] ^ (W[-13] rol 7)
	ADDW  y0, h;                                  \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	; \
	EORW  f, g, y1;                               \
	ANDW  e, y1;                                  \	
	VEXT $12, XWORD2.B16, XWORD1.B16, XTMP1.B16;  \ // XTMP1 = W[-9] = {w10,w9,w8,w7}, Vm = XWORD2, Vn = XWORD1
	EORW  g, y1;                                  \ // y1 = GG2(e, f, g) = (e AND f) OR (NOT(e) AND g)	
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

#define ROUND_AND_SCHED_N_1_1(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3, Wt) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	VSHL $15, XTMP3.S4, XTMP2.S4;                 \           
	RORW  $25, y1, y2;                            \ // y2 = SS1
	EORW  y2, y0;                                 \ // y0 = SS2
	VMOV  XWORD0.S[1], y1;                        \
	VSRI $17, XTMP3.S4, XTMP2.S4;                 \ // XTMP2 = W[-3] rol 15 {xxBA}
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	VMOV  Wt.S[1], y1;                            \
	VEOR XTMP1.B16, XTMP2.B16, XTMP2.B16;         \ // XTMP2 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {xxBA}
	ADDW  y1, y0;                                 \ // y0 = SS2 + W'
	ADDW  d, y0;                                  \ // y0 = d + SS2 + W'
	; \
	ORRW  a, b, y1;                               \
	VSHL $15, XTMP2.S4, XTMP4.S4;                 \
	ANDW  a, b, h;                                \
	ANDW  c, y1;                                  \
	ORRW  y1, h;                                  \ // h =  (a AND b) OR (a AND c) OR (b AND c)	
	VSRI $17, XTMP2.S4, XTMP4.S4;                 \ // XTMP4 =  = XTMP2 rol 15 {xxBA}
	ADDW  y0, h;                                  \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	; \
	EORW  f, g, y1;                               \
	ANDW  e, y1;                                  \	
	EORW  g, y1;                                  \ // y1 = GG2(e, f, g) = (e AND f) OR (NOT(e) AND g)	
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

#define ROUND_AND_SCHED_N_1_2(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3, Wt) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	VEOR XTMP4.B16, XTMP3.B16, XTMP4.B16;         \ // XTMP4 = XTMP2 XOR (XTMP2 rol 15 {xxBA}) XOR (XTMP2 rol 23 {xxBA})
	RORW  $25, y1, y2;                            \ // y2 = SS1
	EORW  y2, y0;                                 \ // y0 = SS2
	VMOV  XWORD0.S[2], y1;                        \
	VEOR XTMP4.B16, XTMP0.B16, XTMP2.B16;         \ // XTMP2 = {..., ..., W[1], W[0]}
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	VMOV  Wt.S[2], y1;                            \
	ADDW  y1, y0;                                 \ // y0 = SS2 + W'
	VEXT $4, XTMP2.B16, XWORD3.B16, XTMP3.B16;    \ // XTMP3 = W[-3] {W[0],w15, w14, w13}, Vm = XTMP2, Vn = XWORD3
	ADDW  d, y0;                                  \ // y0 = d + SS2 + W'
	ORRW  a, b, y1;                               \
	ANDW  a, b, h;                                \
	ANDW  c, y1;                                  \
	VSHL $15, XTMP3.S4, XTMP4.S4;                 \
	ORRW  y1, h;                                  \ // h =  (a AND b) OR (a AND c) OR (b AND c)	
	ADDW  y0, h;                                  \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	EORW  f, g, y1;                               \
	ANDW  e, y1;                                  \	
	VSRI $17, XTMP3.S4, XTMP4.S4;                 \ // XTMP4 = W[-3] rol 15 {DCBA}
	EORW  g, y1;                                  \ // y1 = GG2(e, f, g) = (e AND f) OR (NOT(e) AND g)	
	ADDW  y1, y2;                                 \ // y2 = GG(e, f, g) + h + SS1 + W = tt2 
	RORW  $23, b;                                 \
	RORW  $13, f;                                 \
	VEOR XTMP1.B16, XTMP4.B16, XTMP4.B16;         \ // XTMP4 = W[-9] XOR W[-16] XOR (W[-3] rol 15) {DCBA}
	RORW  $23, y2, y0;                            \
	RORW  $15, y2, d;                             \
	EORW  y0, d;                                  \
	EORW  y2, d;                                  \ // d = P(tt2)	
	VSHL $15, XTMP4.S4, XTMP3.S4;                 \

#define ROUND_AND_SCHED_N_1_3(disp, const, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3, Wt) \
	RORW  $20, a, y0;                             \ // y0 = a <<< 12
	ADDW  $const, e, y1;                          \
	ADDW  y0, y1;                                 \ // y1 = a <<< 12 + e + T
	RORW  $25, y1, y2;                            \ // y2 = SS1
	VSRI $17, XTMP4.S4, XTMP3.S4;                 \ // XTMP3 = XTMP4 rol 15 {DCBA}
	EORW  y2, y0;                                 \ // y0 = SS2
	VMOV  XWORD0.S[3], y1;                        \
	ADDW  y1, y2;                                 \ // y2 = SS1 + W
	ADDW  h, y2;                                  \ // y2 = h + SS1 + W
	VMOV  Wt.S[3], y1;                            \
	VSHL $8, XTMP3.S4, XTMP1.S4;                  \
	ADDW  y1, y0;                                 \ // y0 = SS2 + W'
	ADDW  d, y0;                                  \ // y0 = d + SS2 + W'
	ORRW  a, b, y1;                               \
	ANDW  a, b, h;                                \
	ANDW  c, y1;                                  \
	VSRI $24, XTMP3.S4, XTMP1.S4;                 \ // XTMP1 = XTMP4 rol 23 {DCBA}
	ORRW  y1, h;                                  \ // h =  (a AND b) OR (a AND c) OR (b AND c)
	ADDW  y0, h;                                  \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	EORW  f, g, y1;                               \
	ANDW  e, y1;                                  \
	VEOR XTMP3.B16, XTMP4.B16, XTMP3.B16;         \ // XTMP3 = XTMP4 XOR (XTMP4 rol 15 {DCBA})
	EORW  g, y1;                                  \ // y1 = GG2(e, f, g) = (e AND f) OR (NOT(e) AND g)
	ADDW  y1, y2;                                 \ // y2 = GG(e, f, g) + h + SS1 + W = tt2 
	RORW  $23, b;                                 \
	RORW  $13, f;                                 \
	VEOR XTMP3.B16, XTMP1.B16, XTMP1.B16;         \ // XTMP1 = XTMP4 XOR (XTMP4 rol 15 {DCBA}) XOR (XTMP4 rol 23 {DCBA})
	RORW  $23, y2, y0;                            \
	RORW  $15, y2, d;                             \
	EORW  y0, d;                                  \
	EORW  y2, d;                                  \ // d = P(tt2)	
	VEOR XTMP1.B16, XTMP0.B16, XWORD0.B16;        \ // XWORD0 = {W[3], W[2], W[1], W[0]}

// For rounds [16 - 64)
#define DO_ROUND_N_1(disp, idx, const, a, b, c, d, e, f, g, h, W, Wt) \
	RORW  $20, a, y0;                          \ // y0 = a <<< 12
	ADDW  $const, e, y1;                       \
	ADDW  y0, y1;                              \ // y1 = a <<< 12 + e + T
	RORW  $25, y1, y2;                         \ // y2 = SS1
	EORW  y2, y0;                              \ // y0 = SS2
	VMOV  W.S[idx], y1;                        \
	ADDW  y1, y2;                              \ // y2 = SS1 + W
	ADDW  h, y2;                               \ // y2 = h + SS1 + W
	VMOV  Wt.S[idx], y1;                       \
	ADDW  y1, y0;                              \ // y0 = SS2 + W'
	ADDW  d, y0;                               \ // y0 = d + SS2 + W'
	; \
	ORRW  a, b, y1;                            \
	ANDW  a, b, h;                             \
	ANDW  c, y1;                               \
	ORRW  y1, h;                               \ // h =  (a AND b) OR (a AND c) OR (b AND c)
	ADDW  y0, h;                               \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	; \
	EORW  f, g, y1;                            \
	ANDW  e, y1;                               \
	EORW  g, y1;                               \ // y1 = GG2(e, f, g) = (e AND f) OR (NOT(e) AND g)
	ADDW  y1, y2;                              \ // y2 = GG2(e, f, g) + h + SS1 + W = tt2 
	; \
	RORW  $23, b;                              \
	RORW  $13, f;                              \
	; \
	RORW  $23, y2, y0;                         \
	RORW  $15, y2, d;                          \
	EORW  y0, d;                               \
	EORW  y2, d;                               \ // d = P(tt2)	

// func blockARM64(dig *digest, p []byte)
TEXT ·blockARM64(SB), NOSPLIT, $0
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
	VEOR XWORD0.B16, XWORD1.B16, Wt.B16
	ROUND_AND_SCHED_N_0_0(0*16, T0, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3, Wt)
	ROUND_AND_SCHED_N_0_1(0*16, T1, h, a, b, c, d, e, f, g, XWORD0, XWORD1, XWORD2, XWORD3, Wt)
	ROUND_AND_SCHED_N_0_2(0*16, T2, g, h, a, b, c, d, e, f, XWORD0, XWORD1, XWORD2, XWORD3, Wt)
	ROUND_AND_SCHED_N_0_3(0*16, T3, f, g, h, a, b, c, d, e, XWORD0, XWORD1, XWORD2, XWORD3, Wt)

	// Do 4 rounds and scheduling
	VEOR XWORD1.B16, XWORD2.B16, Wt.B16
	ROUND_AND_SCHED_N_0_0(0*16, T4, e, f, g, h, a, b, c, d, XWORD1, XWORD2, XWORD3, XWORD0, Wt)
	ROUND_AND_SCHED_N_0_1(0*16, T5, d, e, f, g, h, a, b, c, XWORD1, XWORD2, XWORD3, XWORD0, Wt)
	ROUND_AND_SCHED_N_0_2(0*16, T6, c, d, e, f, g, h, a, b, XWORD1, XWORD2, XWORD3, XWORD0, Wt)
	ROUND_AND_SCHED_N_0_3(0*16, T7, b, c, d, e, f, g, h, a, XWORD1, XWORD2, XWORD3, XWORD0, Wt)

	// Do 4 rounds and scheduling
	VEOR XWORD2.B16, XWORD3.B16, Wt.B16
	ROUND_AND_SCHED_N_0_0(0*16, T8, a, b, c, d, e, f, g, h, XWORD2, XWORD3, XWORD0, XWORD1, Wt)
	ROUND_AND_SCHED_N_0_1(0*16, T9, h, a, b, c, d, e, f, g, XWORD2, XWORD3, XWORD0, XWORD1, Wt)
	ROUND_AND_SCHED_N_0_2(0*16, T10, g, h, a, b, c, d, e, f, XWORD2, XWORD3, XWORD0, XWORD1, Wt)
	ROUND_AND_SCHED_N_0_3(0*16, T11, f, g, h, a, b, c, d, e, XWORD2, XWORD3, XWORD0, XWORD1, Wt)

	// Do 4 rounds and scheduling
	VEOR XWORD3.B16, XWORD0.B16, Wt.B16
	ROUND_AND_SCHED_N_0_0(0*16, T12, e, f, g, h, a, b, c, d, XWORD3, XWORD0, XWORD1, XWORD2, Wt)
	ROUND_AND_SCHED_N_0_1(0*16, T13, d, e, f, g, h, a, b, c, XWORD3, XWORD0, XWORD1, XWORD2, Wt)
	ROUND_AND_SCHED_N_0_2(0*16, T14, c, d, e, f, g, h, a, b, XWORD3, XWORD0, XWORD1, XWORD2, Wt)
	ROUND_AND_SCHED_N_0_3(0*16, T15, b, c, d, e, f, g, h, a, XWORD3, XWORD0, XWORD1, XWORD2, Wt)

	// Do 4 rounds and scheduling
	VEOR XWORD0.B16, XWORD1.B16, Wt.B16
	ROUND_AND_SCHED_N_1_0(0*16, T16, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3, Wt)
	ROUND_AND_SCHED_N_1_1(0*16, T17, h, a, b, c, d, e, f, g, XWORD0, XWORD1, XWORD2, XWORD3, Wt)
	ROUND_AND_SCHED_N_1_2(0*16, T18, g, h, a, b, c, d, e, f, XWORD0, XWORD1, XWORD2, XWORD3, Wt)
	ROUND_AND_SCHED_N_1_3(0*16, T19, f, g, h, a, b, c, d, e, XWORD0, XWORD1, XWORD2, XWORD3, Wt)

	// Do 4 rounds and scheduling
	VEOR XWORD1.B16, XWORD2.B16, Wt.B16
	ROUND_AND_SCHED_N_1_0(0*16, T20, e, f, g, h, a, b, c, d, XWORD1, XWORD2, XWORD3, XWORD0, Wt)
	ROUND_AND_SCHED_N_1_1(0*16, T21, d, e, f, g, h, a, b, c, XWORD1, XWORD2, XWORD3, XWORD0, Wt)
	ROUND_AND_SCHED_N_1_2(0*16, T22, c, d, e, f, g, h, a, b, XWORD1, XWORD2, XWORD3, XWORD0, Wt)
	ROUND_AND_SCHED_N_1_3(0*16, T23, b, c, d, e, f, g, h, a, XWORD1, XWORD2, XWORD3, XWORD0, Wt)

	// Do 4 rounds and scheduling
	VEOR XWORD2.B16, XWORD3.B16, Wt.B16
	ROUND_AND_SCHED_N_1_0(0*16, T24, a, b, c, d, e, f, g, h, XWORD2, XWORD3, XWORD0, XWORD1, Wt)
	ROUND_AND_SCHED_N_1_1(0*16, T25, h, a, b, c, d, e, f, g, XWORD2, XWORD3, XWORD0, XWORD1, Wt)
	ROUND_AND_SCHED_N_1_2(0*16, T26, g, h, a, b, c, d, e, f, XWORD2, XWORD3, XWORD0, XWORD1, Wt)
	ROUND_AND_SCHED_N_1_3(0*16, T27, f, g, h, a, b, c, d, e, XWORD2, XWORD3, XWORD0, XWORD1, Wt)

	// Do 4 rounds and scheduling
	VEOR XWORD3.B16, XWORD0.B16, Wt.B16
	ROUND_AND_SCHED_N_1_0(0*16, T28, e, f, g, h, a, b, c, d, XWORD3, XWORD0, XWORD1, XWORD2, Wt)
	ROUND_AND_SCHED_N_1_1(0*16, T29, d, e, f, g, h, a, b, c, XWORD3, XWORD0, XWORD1, XWORD2, Wt)
	ROUND_AND_SCHED_N_1_2(0*16, T30, c, d, e, f, g, h, a, b, XWORD3, XWORD0, XWORD1, XWORD2, Wt)
	ROUND_AND_SCHED_N_1_3(0*16, T31, b, c, d, e, f, g, h, a, XWORD3, XWORD0, XWORD1, XWORD2, Wt)

	// Do 4 rounds and scheduling
	VEOR XWORD0.B16, XWORD1.B16, Wt.B16
	ROUND_AND_SCHED_N_1_0(0*16, T32, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3, Wt)
	ROUND_AND_SCHED_N_1_1(0*16, T33, h, a, b, c, d, e, f, g, XWORD0, XWORD1, XWORD2, XWORD3, Wt)
	ROUND_AND_SCHED_N_1_2(0*16, T34, g, h, a, b, c, d, e, f, XWORD0, XWORD1, XWORD2, XWORD3, Wt)
	ROUND_AND_SCHED_N_1_3(0*16, T35, f, g, h, a, b, c, d, e, XWORD0, XWORD1, XWORD2, XWORD3, Wt)

	// Do 4 rounds and scheduling
	VEOR XWORD1.B16, XWORD2.B16, Wt.B16
	ROUND_AND_SCHED_N_1_0(0*16, T36, e, f, g, h, a, b, c, d, XWORD1, XWORD2, XWORD3, XWORD0, Wt)
	ROUND_AND_SCHED_N_1_1(0*16, T37, d, e, f, g, h, a, b, c, XWORD1, XWORD2, XWORD3, XWORD0, Wt)
	ROUND_AND_SCHED_N_1_2(0*16, T38, c, d, e, f, g, h, a, b, XWORD1, XWORD2, XWORD3, XWORD0, Wt)
	ROUND_AND_SCHED_N_1_3(0*16, T39, b, c, d, e, f, g, h, a, XWORD1, XWORD2, XWORD3, XWORD0, Wt)

	// Do 4 rounds and scheduling
	VEOR XWORD2.B16, XWORD3.B16, Wt.B16
	ROUND_AND_SCHED_N_1_0(0*16, T40, a, b, c, d, e, f, g, h, XWORD2, XWORD3, XWORD0, XWORD1, Wt)
	ROUND_AND_SCHED_N_1_1(0*16, T41, h, a, b, c, d, e, f, g, XWORD2, XWORD3, XWORD0, XWORD1, Wt)
	ROUND_AND_SCHED_N_1_2(0*16, T42, g, h, a, b, c, d, e, f, XWORD2, XWORD3, XWORD0, XWORD1, Wt)
	ROUND_AND_SCHED_N_1_3(0*16, T43, f, g, h, a, b, c, d, e, XWORD2, XWORD3, XWORD0, XWORD1, Wt)

	// Do 4 rounds and scheduling
	VEOR XWORD3.B16, XWORD0.B16, Wt.B16
	ROUND_AND_SCHED_N_1_0(0*16, T44, e, f, g, h, a, b, c, d, XWORD3, XWORD0, XWORD1, XWORD2, Wt)
	ROUND_AND_SCHED_N_1_1(0*16, T45, d, e, f, g, h, a, b, c, XWORD3, XWORD0, XWORD1, XWORD2, Wt)
	ROUND_AND_SCHED_N_1_2(0*16, T46, c, d, e, f, g, h, a, b, XWORD3, XWORD0, XWORD1, XWORD2, Wt)
	ROUND_AND_SCHED_N_1_3(0*16, T47, b, c, d, e, f, g, h, a, XWORD3, XWORD0, XWORD1, XWORD2, Wt)

	// w48 - w63 processed with only 4 rounds scheduling (last 16 rounds)
	// Do 4 rounds and scheduling
	VEOR XWORD0.B16, XWORD1.B16, Wt.B16
	ROUND_AND_SCHED_N_1_0(0*16, T48, a, b, c, d, e, f, g, h, XWORD0, XWORD1, XWORD2, XWORD3, Wt)
	ROUND_AND_SCHED_N_1_1(0*16, T49, h, a, b, c, d, e, f, g, XWORD0, XWORD1, XWORD2, XWORD3, Wt)
	ROUND_AND_SCHED_N_1_2(0*16, T50, g, h, a, b, c, d, e, f, XWORD0, XWORD1, XWORD2, XWORD3, Wt)
	ROUND_AND_SCHED_N_1_3(0*16, T51, f, g, h, a, b, c, d, e, XWORD0, XWORD1, XWORD2, XWORD3, Wt)  

	// w52 - w63 processed with no scheduling (last 12 rounds)
	// Do 4 rounds
	VEOR XWORD1.B16, XWORD2.B16, Wt.B16
	DO_ROUND_N_1(0*16, 0, T52, e, f, g, h, a, b, c, d, XWORD1, Wt)
	DO_ROUND_N_1(0*16, 1, T53, d, e, f, g, h, a, b, c, XWORD1, Wt)
	DO_ROUND_N_1(0*16, 2, T54, c, d, e, f, g, h, a, b, XWORD1, Wt)
	DO_ROUND_N_1(0*16, 3, T55, b, c, d, e, f, g, h, a, XWORD1, Wt)

	// Do 4 rounds
	VEOR XWORD2.B16, XWORD3.B16, Wt.B16
	DO_ROUND_N_1(0*16, 0, T56, a, b, c, d, e, f, g, h, XWORD2, Wt)
	DO_ROUND_N_1(0*16, 1, T57, h, a, b, c, d, e, f, g, XWORD2, Wt)
	DO_ROUND_N_1(0*16, 2, T58, g, h, a, b, c, d, e, f, XWORD2, Wt)
	DO_ROUND_N_1(0*16, 3, T59, f, g, h, a, b, c, d, e, XWORD2, Wt)

	// Do 4 rounds
	VEOR XWORD3.B16, XWORD0.B16, Wt.B16
	DO_ROUND_N_1(0*16, 0, T60, e, f, g, h, a, b, c, d, XWORD3, Wt)
	DO_ROUND_N_1(0*16, 1, T61, d, e, f, g, h, a, b, c, XWORD3, Wt)
	DO_ROUND_N_1(0*16, 2, T62, c, d, e, f, g, h, a, b, XWORD3, Wt)
	DO_ROUND_N_1(0*16, 3, T63, b, c, d, e, f, g, h, a, XWORD3, Wt)

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
