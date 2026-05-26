// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

#include "textflag.h"
#include "sm4_macros_loong64.s"

// func decryptBlocksChain(xk *uint32, dst, src []byte, iv *byte)
// CBC decryption: decrypt each block then XOR with previous ciphertext (or IV).
// When src_len >= 128, uses 8-way LASX parallel decryption.
//
// LASX register usage:
//   X0-X15 : sbox data (both lanes replicated)
//   X16-X19: SM4 state B0-B3 (8-block parallel); X16 reused for ct[2,3] reload after rounds
//   X20-X22: constants (all01, all80, mask1F)
//   X23-X26: ciphertext/decrypted blocks (2 per register)
//   X27-X30: interleave intermediates and CBC chain temps
//   X28    : prev_ct [both lanes]; preserved across LASX_4ROUNDS (which no longer uses X28)
//   X31    : clobbered by LASX_4ROUNDS (round-key broadcast) and SM4_L_LASX (temp)
//
// GP registers:
//   R4=xk R5=dst R6=src R7=src_len R8=const_128
//   R9=sbox_addr/temp R10=k_temp R11=rk_ptr R12=ctr R13=rk_val R23=iv_ptr
TEXT ·decryptBlocksChain(SB), NOSPLIT, $0-64
	MOVV xk+0(FP), R4
	MOVV dst_base+8(FP), R5
	MOVV src_base+32(FP), R6
	MOVV src_len+40(FP), R7
	MOVV iv+56(FP), R23

	// ----------------------------------------------------------------
	// LASX path: process 8 blocks (128 bytes) at a time
	// ----------------------------------------------------------------
	MOVV $128, R8
	BLTU R7, R8, cbc_scalar_path

	// Load sbox into X0-X15 (16 bytes each, replicated to both lanes).
	MOVV $·sbox(SB), R9
	VMOVQ 0(R9), V0;    XVPERMIQ_REPL(0)
	VMOVQ 16(R9), V8;   XVPERMIQ_REPL(8)
	VMOVQ 32(R9), V1;   XVPERMIQ_REPL(1)
	VMOVQ 48(R9), V9;   XVPERMIQ_REPL(9)
	VMOVQ 64(R9), V2;   XVPERMIQ_REPL(2)
	VMOVQ 80(R9), V10;  XVPERMIQ_REPL(10)
	VMOVQ 96(R9), V3;   XVPERMIQ_REPL(3)
	VMOVQ 112(R9), V11; XVPERMIQ_REPL(11)
	VMOVQ 128(R9), V4;  XVPERMIQ_REPL(4)
	VMOVQ 144(R9), V12; XVPERMIQ_REPL(12)
	VMOVQ 160(R9), V5;  XVPERMIQ_REPL(5)
	VMOVQ 176(R9), V13; XVPERMIQ_REPL(13)
	VMOVQ 192(R9), V6;  XVPERMIQ_REPL(6)
	VMOVQ 208(R9), V14; XVPERMIQ_REPL(14)
	VMOVQ 224(R9), V7;  XVPERMIQ_REPL(7)
	VMOVQ 240(R9), V15; XVPERMIQ_REPL(15)

	// Load constants.
	MOVV $0x01, R9; XVMOVQ R9, X20.B32
	MOVV $0x80, R9; XVMOVQ R9, X21.B32
	MOVV $0x1F, R9; XVMOVQ R9, X22.B32

	// Load IV into X28 = [IV, IV] as the first batch's "previous ciphertext".
	// X28 is now free in LASX_4ROUNDS (it used to be the T-input temp; that
	// was renamed to X24 in the X28→X24 optimization).  We use word loads for
	// alignment safety, insert into lane 0, then replicate to lane 1.
	MOVWU 0(R23), R9;  XVMOVQ R9, X28.W[0]
	MOVWU 4(R23), R9;  XVMOVQ R9, X28.W[1]
	MOVWU 8(R23), R9;  XVMOVQ R9, X28.W[2]
	MOVWU 12(R23), R9; XVMOVQ R9, X28.W[3]
	XVPERMIQ_REPL(28)             // X28 = [IV, IV]

cbc_lasx_loop:
	// Load 8 ciphertext blocks into X23-X26.
	XVMOVQ 0(R6), X23;  XVMOVQ 32(R6), X24
	XVMOVQ 64(R6), X25; XVMOVQ 96(R6), X26

	// Byte-swap → LE for SM4 decryption.
	XVSHUF4IB $0x1B, X23, X23; XVSHUF4IB $0x1B, X24, X24
	XVSHUF4IB $0x1B, X25, X25; XVSHUF4IB $0x1B, X26, X26

	// Interleave 8 blocks into state X16-X19.
	// Use X31 (will be clobbered by round loop anyway) instead of X28 as scratch,
	// preserving X28 = prev_ct across the interleave and round loop.
	XVILVLW X23, X24, X27; XVILVHW X23, X24, X31
	XVILVLW X25, X26, X29; XVILVHW X25, X26, X30
	XVILVLV X27, X29, X16; XVILVHV X27, X29, X17
	XVILVLV X31, X30, X18; XVILVHV X31, X30, X19

	// Execute 32 decryption rounds (using reversed key schedule in xk).
	// LASX_4ROUNDS clobbers X24, X31 (and others); X28 = prev_ct is preserved.
	MOVV R4, R11; MOVV $8, R12
cbc_round_loop:
	LASX_4ROUNDS()
	ADDV $-1, R12
	BNE R12, R0, cbc_round_loop

	// Deinterleave X16-X19 → X23-X26 with reversed word order [B3,B2,B1,B0].
	// Use X31 (post-round scratch) instead of X28, preserving X28 = prev_ct.
	XVILVLW X19, X18, X27; XVILVHW X19, X18, X31
	XVILVLW X17, X16, X29; XVILVHW X17, X16, X30
	XVILVLV X27, X29, X23; XVILVHV X27, X29, X24
	XVILVLV X31, X30, X25; XVILVHV X31, X30, X26

	// Byte-swap decrypted output back to big-endian format.
	XVSHUF4IB $0x1B, X23, X23; XVSHUF4IB $0x1B, X24, X24
	XVSHUF4IB $0x1B, X25, X25; XVSHUF4IB $0x1B, X26, X26

	// Reload original ciphertext for CBC XOR.
	// X16 is free (data moved to X23 during deinterleave); use it for ct[2,3].
	// X28 = prev_ct is kept intact.
	XVMOVQ 0(R6), X27;  XVMOVQ 32(R6), X16
	XVMOVQ 64(R6), X29; XVMOVQ 96(R6), X30

	// Build CBC XOR chain: for each output block k, XOR with ct[k-1].
	// X27=[ct0,ct1], X16=[ct2,ct3], X29=[ct4,ct5], X30=[ct6,ct7], X28=[prev,prev].
	// Save ct7 to X31 BEFORE XVPERMIQ modifies X30.
	XVPERMIQ(31, 30, 0x11)    // X31 = [ct7, ct7]
	XVPERMIQ(30, 29, 0x21)    // X30 = [ct5, ct6]
	XVPERMIQ(29, 16, 0x21)    // X29 = [ct3, ct4]
	XVPERMIQ(16, 27, 0x21)    // X16 = [ct1, ct2]
	XVPERMIQ(27, 28, 0x21)    // X27 = [prev_ct, ct0]  ← X28 = prev_ct ✓
	XVORV X31, X31, X28       // X28 = [ct7, ct7] for next batch

	// XOR decrypted blocks with CBC chain (byte-level XOR, both in BE format).
	XVXORV X23, X27, X23; XVXORV X24, X16, X24
	XVXORV X25, X29, X25; XVXORV X26, X30, X26

	// Store plaintext to dst.
	XVMOVQ X23, 0(R5);  XVMOVQ X24, 32(R5)
	XVMOVQ X25, 64(R5); XVMOVQ X26, 96(R5)

	ADDV $128, R5; ADDV $128, R6; ADDV $-128, R7
	BGEU R7, R8, cbc_lasx_loop

	// Update IV memory = last ciphertext block processed (ct[7] in X28.lo).
	VMOVQ V28, (R23)

	// ----------------------------------------------------------------
	// Scalar path: handle remaining blocks (0-7) one at a time.
	// ----------------------------------------------------------------
cbc_scalar_path:
	MOVV $·sbox_t0(SB), ST0
	MOVV $·sbox_t1(SB), ST1
	MOVV $·sbox_t2(SB), ST2
	MOVV $·sbox_t3(SB), ST3
	// Load IV words into R8-R9,R25-R26 (the "prev ciphertext" for CBC XOR).
	// This avoids the in-place decryption bug where ENCRYPT_BLOCK overwrites
	// the source block before we can use it as the next IV.
	MOVV iv+56(FP), R23
	MOVWU 0(R23), R8
	MOVWU 4(R23), R9
	MOVWU 8(R23), R25
	MOVWU 12(R23), R26

cbc_loop:
	BEQ R7, R0, cbc_done
	// Save current ciphertext block BEFORE ENCRYPT_BLOCK overwrites dst (in-place case).
	MOVWU 0(R6), R27
	MOVWU 4(R6), R28
	MOVWU 8(R6), R29
	MOVWU 12(R6), R30
	ENCRYPT_BLOCK()
	// XOR decrypted block with previous ciphertext (R8-R9,R25-R26).
	MOVWU 0(R5), T0;  XOR R8,  T0, T0;  MOVW T0, 0(R5)
	MOVWU 4(R5), T0;  XOR R9,  T0, T0;  MOVW T0, 4(R5)
	MOVWU 8(R5), T0;  XOR R25, T0, T0;  MOVW T0, 8(R5)
	MOVWU 12(R5), T0; XOR R26, T0, T0;  MOVW T0, 12(R5)
	// Update prev ciphertext to the block we just processed.
	MOVV R27, R8
	MOVV R28, R9
	MOVV R29, R25
	MOVV R30, R26
	ADDV $16, R5
	ADDV $16, R6
	ADDV $-16, R7
	JMP cbc_loop

cbc_done:
	// Save last ciphertext block to IV memory (R8-R9,R25-R26 hold the last CT).
	MOVV iv+56(FP), R23
	MOVW R8,  0(R23)
	MOVW R9,  4(R23)
	MOVW R25, 8(R23)
	MOVW R26, 12(R23)
	RET
