// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// This file defines assembly macros shared by asm_loong64.s, ecb_loong64.s,
// and cbc_loong64.s.  It must NOT contain any TEXT symbols.

// Register aliases (scalar block encryption helper registers)
#define B0  R10
#define B1  R11
#define B2  R12
#define B3  R13
#define RK  R14
#define TMP R15
#define T0  R16
#define T1  R17
#define T2  R18
#define ST0 R19
#define ST1 R20
#define ST2 R21
#define ST3 R24

// SM4_ROUND: B0 ^= precompute_t(B1 ^ B2 ^ B3 ^ *RK); RK += 4
// Uses: TMP, T0, T1, T2, ST0-ST3.
#define SM4_ROUND(B0, B1, B2, B3) \
	MOVWU (RK), TMP; \
	ADDV $4, RK; \
	XOR B1, B2, T0; \
	XOR B3, T0, T0; \
	XOR TMP, T0, T0; \
	SRLV $24, T0, T2; \
	SLLV $2, T2, T2; \
	ADDV ST0, T2, T2; \
	MOVWU (T2), T1; \
	SRLV $16, T0, T2; \
	AND $0xFF, T2; \
	SLLV $2, T2, T2; \
	ADDV ST1, T2, T2; \
	MOVWU (T2), T2; \
	XOR T2, T1, T1; \
	SRLV $8, T0, T2; \
	AND $0xFF, T2; \
	SLLV $2, T2, T2; \
	ADDV ST2, T2, T2; \
	MOVWU (T2), T2; \
	XOR T2, T1, T1; \
	AND $0xFF, T0, T2; \
	SLLV $2, T2, T2; \
	ADDV ST3, T2, T2; \
	MOVWU (T2), T2; \
	XOR T2, T1, T1; \
	XOR T1, B0, B0

// SM4_4ROUNDS: four consecutive rounds without register rotation.
#define SM4_4ROUNDS() \
	SM4_ROUND(B0, B1, B2, B3); \
	SM4_ROUND(B1, B2, B3, B0); \
	SM4_ROUND(B2, B3, B0, B1); \
	SM4_ROUND(B3, B0, B1, B2)

// ENCRYPT_BLOCK: encrypt one 16-byte block from (R6) into (R5).
// Requires: R4=xk, R5=dst, R6=src, ST0-ST3 pre-loaded.
// Does NOT advance R5 or R6.
#define ENCRYPT_BLOCK() \
	MOVWU 0(R6), B0; REVB2W B0, B0; \
	MOVWU 4(R6), B1; REVB2W B1, B1; \
	MOVWU 8(R6), B2; REVB2W B2, B2; \
	MOVWU 12(R6), B3; REVB2W B3, B3; \
	MOVV R4, RK; \
	SM4_4ROUNDS(); \
	SM4_4ROUNDS(); \
	SM4_4ROUNDS(); \
	SM4_4ROUNDS(); \
	SM4_4ROUNDS(); \
	SM4_4ROUNDS(); \
	SM4_4ROUNDS(); \
	SM4_4ROUNDS(); \
	REVB2W B3, TMP; MOVW TMP, 0(R5); \
	REVB2W B2, TMP; MOVW TMP, 4(R5); \
	REVB2W B1, TMP; MOVW TMP, 8(R5); \
	REVB2W B0, TMP; MOVW TMP, 12(R5)

// ============================================================
// LASX (256-bit SIMD) macros for 8-way parallel SM4 encryption
// ============================================================

// XVSHUF_B(xd, xj, xk, xa): xvshuf.b xd, xj, xk, xa (4-operand byte-shuffle).
// Per 128-bit lane L, byte i:
//   if xa[L][i].bit7==1 : xd[L][i] = 0
//   elif xa[L][i].bit4==1: xd[L][i] = xj[L][xa[L][i] & 0xF]
//   else                  : xd[L][i] = xk[L][xa[L][i] & 0xF]
#define XVSHUF_B(xd, xj, xk, xa) \
	WORD $(0x0D600000 | ((xa) << 15) | ((xk) << 10) | ((xj) << 5) | (xd))

// XVPERMIQ_REPL(xn): XVPERMI.Q $0x00, Xn, Xn, Xn
// Replicates the lower 128-bit lane of Xn into its upper 128-bit lane.
#define XVPERMIQ_REPL(xn) WORD $((0x1DFB << 18) | (0x00 << 10) | ((xn) << 5) | (xn))

// XVPERMIQ(xd, xj, imm8): XVPERMI.Q instruction (xd and xj are register numbers 0-31).
// pool = {Xj.lo=0, Xj.hi=1, Xd_old.lo=2, Xd_old.hi=3}
// Xd.lo = pool[imm[1:0]], Xd.hi = pool[imm[5:4]]
#define XVPERMIQ(xd, xj, imm8) WORD $((0x1DFB << 18) | ((imm8) << 10) | ((xj) << 5) | (xd))

// SM4_SBOX_CHUNK(k, xjk, xkk):
// Performs partial S-box lookup for the k-th 32-byte chunk of the SM4 sbox.
//   xkk = LASX reg index holding sbox[k*32 .. k*32+15] in BOTH 128-bit lanes
//   xjk = LASX reg index holding sbox[k*32+16 .. k*32+31] in BOTH 128-bit lanes
// Non-matching bytes are masked to 0 before OR accumulation using X26 (in_range_mask).
// Register usage (all pre-loaded or scratch):
//   X20 = broadcast(0x01) [all_01]   X21 = broadcast(0x80) [all_80]
//   X23 = b >> 5 (group)             X24 = b & 0x1F (low5)
//   X25,X26,X27,X30,X31 = scratch    X29 = accumulator (OR'd into)
//   R10 = GP temp for k constant
#define SM4_SBOX_CHUNK(k, xjk, xkk) \
	MOVV $k, R10; \
	XVMOVQ R10, X30.B32; \
	XVXORV X23, X30, X25; \
	XVSUBB X20, X25, X25; \
	XVSRAB $7, X25, X26; \
	XVANDNV X21, X26, X27; \
	XVORV X24, X27, X27; \
	XVSHUF_B(31, xjk, xkk, 27); \
	XVANDV X31, X26, X31; \
	XVORV X29, X31, X29

// SM4_SBOX_LASX(): Apply SM4 S-box to X28 (T-function input, 8x32-bit words).
// Output: X29 = S-box output (byte-by-byte lookup, one byte per output byte).
// Pre-conditions:
//   X0-X7  = sbox[0..15], sbox[32..47], ..., sbox[224..239] (each chunk, both lanes)
//   X8-X15 = sbox[16..31], sbox[48..63], ..., sbox[240..255] (each chunk, both lanes)
//   X20 = broadcast(0x01), X21 = broadcast(0x80), X22 = broadcast(0x1F)
// Clobbers: X23-X27, X29-X31, R10
#define SM4_SBOX_LASX() \
	XVSRLB $5, X28, X23; \
	XVANDV X28, X22, X24; \
	XVXORV X29, X29, X29; \
	SM4_SBOX_CHUNK(0, 8, 0); \
	SM4_SBOX_CHUNK(1, 9, 1); \
	SM4_SBOX_CHUNK(2, 10, 2); \
	SM4_SBOX_CHUNK(3, 11, 3); \
	SM4_SBOX_CHUNK(4, 12, 4); \
	SM4_SBOX_CHUNK(5, 13, 5); \
	SM4_SBOX_CHUNK(6, 14, 6); \
	SM4_SBOX_CHUNK(7, 15, 7)

// SM4_L_LASX(): L-transform of X29 → X25.
// After XVSHUF4IB, the 32-bit register integer = the big-endian SM4 word value.
// L(x) = x ^ ROL(x,2) ^ ROL(x,10) ^ ROL(x,18) ^ ROL(x,24)
//       = x ^ ROR(x,30) ^ ROR(x,22) ^ ROR(x,14) ^ ROR(x,8)
// Clobbers: X25 (result), X31 (temp)
#define SM4_L_LASX() \
	XVROTRW $30, X29, X25; \
	XVROTRW $22, X29, X31; \
	XVXORV X31, X25, X25; \
	XVROTRW $14, X29, X31; \
	XVXORV X31, X25, X25; \
	XVROTRW $8, X29, X31; \
	XVXORV X31, X25, X25; \
	XVXORV X29, X25, X25

// LASX_4ROUNDS(): 4 SM4 rounds with state in X16-X19 (B0-B3).
// Each round computes: Bx ^= L(sbox(B(x+1)^B(x+2)^B(x+3)^rk))
// R11 = round key pointer (advanced by 4 per round = 16 total).
// R13 = GP temp for round key value.
// X28 = T-function input, X29 = sbox output, X25 = L output, X31 = rk broadcast/L temp.
#define LASX_4ROUNDS() \
	MOVWU (R11), R13; ADDV $4, R11; XVMOVQ R13, X31.W8; \
	XVXORV X17, X18, X28; XVXORV X19, X28, X28; XVXORV X31, X28, X28; \
	SM4_SBOX_LASX(); SM4_L_LASX(); XVXORV X16, X25, X16; \
	MOVWU (R11), R13; ADDV $4, R11; XVMOVQ R13, X31.W8; \
	XVXORV X18, X19, X28; XVXORV X16, X28, X28; XVXORV X31, X28, X28; \
	SM4_SBOX_LASX(); SM4_L_LASX(); XVXORV X17, X25, X17; \
	MOVWU (R11), R13; ADDV $4, R11; XVMOVQ R13, X31.W8; \
	XVXORV X19, X16, X28; XVXORV X17, X28, X28; XVXORV X31, X28, X28; \
	SM4_SBOX_LASX(); SM4_L_LASX(); XVXORV X18, X25, X18; \
	MOVWU (R11), R13; ADDV $4, R11; XVMOVQ R13, X31.W8; \
	XVXORV X16, X17, X28; XVXORV X18, X28, X28; XVXORV X31, X28, X28; \
	SM4_SBOX_LASX(); SM4_L_LASX(); XVXORV X19, X25, X19
