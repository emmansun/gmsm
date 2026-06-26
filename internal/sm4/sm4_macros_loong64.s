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

// XVBITSEL(xd, xj, xk, xa): xvbitsel.v xd, xj, xk, xa (4-operand bit-select).
// xd[i] = xa[i] ? xk[i] : xj[i]  (bit-level: 1 selects xk, 0 selects xj)
// Opcode 0x0D200000 confirmed from QEMU source.
#define XVBITSEL(xd, xj, xk, xa) \
	WORD $(0x0D200000 | ((xa) << 15) | ((xk) << 10) | ((xj) << 5) | (xd))

// SM4_SBOX_LASX(): Apply SM4 S-box to X24 (T-function input, 8x32-bit words).
// Uses a 3-level binary MUX tree: 8 XVSHUF_B lookups + 7 XVBITSEL.V selects.
// Each byte b is split: group = b>>5 (0-7 selects the 32-byte chunk),
// offset = b&0x1F (lookup index within the chunk, used as XVSHUF_B key).
// Level masks: XVSLLB $k, group, X30; XVSRAB $7, X30, X30 → 0xFF/0x00 per byte.
// Input:  X24 = T-function input.
// Output: X29 = S-box substituted output.
// Pre-conditions:
//   X0-X7  = sbox[k*32..k*32+15] for k=0..7 (chunk low half, both 128-bit lanes equal)
//   X8-X15 = sbox[k*32+16..k*32+31] for k=0..7 (chunk high half, both lanes equal)
//   X22    = broadcast(0x1F) [mask_1F]
// Clobbers: X23-X27, X29-X31  (X28 NOT touched — safe for CBC prev_ct)
#define SM4_SBOX_LASX() \
	XVSRLB $5, X24, X23; \
	XVANDV X24, X22, X24; \
	XVSLLB $7, X23, X30; \
	XVSRAB $7, X30, X30; \
	XVSHUF_B(25, 8, 0, 24); \
	XVSHUF_B(31, 9, 1, 24); \
	XVBITSEL(25, 25, 31, 30); \
	XVSHUF_B(31, 10, 2, 24); \
	XVSHUF_B(26, 11, 3, 24); \
	XVBITSEL(26, 31, 26, 30); \
	XVSHUF_B(27, 12, 4, 24); \
	XVSHUF_B(31, 13, 5, 24); \
	XVBITSEL(27, 27, 31, 30); \
	XVSHUF_B(31, 14, 6, 24); \
	XVSHUF_B(29, 15, 7, 24); \
	XVBITSEL(29, 31, 29, 30); \
	XVSLLB $6, X23, X30; \
	XVSRAB $7, X30, X30; \
	XVBITSEL(25, 25, 26, 30); \
	XVBITSEL(26, 27, 29, 30); \
	XVSLLB $5, X23, X30; \
	XVSRAB $7, X30, X30; \
	XVBITSEL(29, 25, 26, 30)

// SM4_L_LASX(): L-transform of X29 → X25.
// L(x) = x ^ ROL(x,2) ^ ROL(x,10) ^ ROL(x,18) ^ ROL(x,24)
//       = x ^ ROR(x,30) ^ ROR(x,22) ^ ROR(x,14) ^ ROR(x,8)
// Two independent rotation pairs (ROR30^ROR22) and (ROR14^ROR8) are computed in
// parallel, reducing critical-path depth from 5 to 4.
// Clobbers: X25 (result), X26, X27, X31 (temps)
#define SM4_L_LASX() \
	XVROTRW $30, X29, X25; \
	XVROTRW $22, X29, X31; \
	XVROTRW $14, X29, X26; \
	XVROTRW $8, X29, X27; \
	XVXORV X25, X31, X25; \
	XVXORV X26, X27, X26; \
	XVXORV X25, X26, X25; \
	XVXORV X29, X25, X25

// LASX_4ROUNDS(): 4 SM4 rounds with state in X16-X19 (B0-B3).
// Each round computes: Bx ^= L(sbox(B(x+1)^B(x+2)^B(x+3)^rk))
// R11 = round key pointer (advanced by 4 per round = 16 total).
// R13 = GP temp for round key value.
// Clobbers: X23,X24,X25,X26,X27,X29,X30,X31, R12,R13.
// X24 = T-function input (in) → overwritten with offset scratch by SM4_SBOX_LASX.
// X29 = sbox MUX output; X25 = L output; X30 = rk broadcast and MUX/mask scratch.
// X28 is FREE (not used); callers may store persistent data there across calls.
#define LASX_4ROUNDS() \
	MOVWU (R11), R13; ADDV $4, R11; XVMOVQ R13, X31.W8; \
	XVXORV X17, X18, X24; XVXORV X19, X31, X30; XVXORV X24, X30, X24; \
	SM4_SBOX_LASX(); SM4_L_LASX(); XVXORV X16, X25, X16; \
	MOVWU (R11), R13; ADDV $4, R11; XVMOVQ R13, X31.W8; \
	XVXORV X18, X19, X24; XVXORV X16, X31, X30; XVXORV X24, X30, X24; \
	SM4_SBOX_LASX(); SM4_L_LASX(); XVXORV X17, X25, X17; \
	MOVWU (R11), R13; ADDV $4, R11; XVMOVQ R13, X31.W8; \
	XVXORV X19, X16, X24; XVXORV X17, X31, X30; XVXORV X24, X30, X24; \
	SM4_SBOX_LASX(); SM4_L_LASX(); XVXORV X18, X25, X18; \
	MOVWU (R11), R13; ADDV $4, R11; XVMOVQ R13, X31.W8; \
	XVXORV X16, X17, X24; XVXORV X18, X31, X30; XVXORV X24, X30, X24; \
	SM4_SBOX_LASX(); SM4_L_LASX(); XVXORV X19, X25, X19
