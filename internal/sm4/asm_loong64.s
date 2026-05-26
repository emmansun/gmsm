// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

#include "textflag.h"
#include "sm4_macros_loong64.s"

// func encryptBlocksAsm(xk *uint32, dst, src []byte, inst int)
// Processes src_len bytes (always a multiple of 16).
// When src_len >= 128, uses 8-way LASX parallel encryption.
// Remaining blocks (< 128 bytes) use the scalar T-table path.
//
// LASX register allocation (X0-X31):
//   X0-X7  : sbox xk regs (chunk k, sbox[k*32..k*32+15] replicated to both 128-bit lanes)
//   X8-X15 : sbox xj regs (chunk k, sbox[k*32+16..k*32+31] replicated to both lanes)
//   X16-X19: state B0-B3 (8 parallel 32-bit words across 8 blocks)
//   X20    : constant broadcast(0x01) to all 32 bytes
//   X21    : constant broadcast(0x80) to all 32 bytes
//   X22    : constant broadcast(0x1F) to all 32 bytes
//   X23-X31: scratch for interleave, S-box, L-transform
//
// GP register allocation:
//   R4=xk  R5=dst  R6=src  R7=src_len  R8=const_128
//   R9=sbox_addr  R10=k_temp  R11=round_key_ptr  R12=round_loop_ctr  R13=rk_val
TEXT ·encryptBlocksAsm(SB), NOSPLIT, $0-64
	MOVV xk+0(FP), R4
	MOVV dst_base+8(FP), R5
	MOVV src_base+32(FP), R6
	MOVV src_len+40(FP), R7

	// ----------------------------------------------------------------
	// LASX path: process 8 blocks (128 bytes) at a time
	// ----------------------------------------------------------------
	MOVV $128, R8
	BLTU R7, R8, scalar_path    // if src_len < 128, skip LASX

	// Load the 256-byte SM4 S-box into X0-X15, 16 bytes per register,
	// replicated into both 128-bit lanes (needed for XVSHUF_B lookup).
	MOVV $·sbox(SB), R9
	VMOVQ 0(R9), V0
	XVPERMIQ_REPL(0)          // X0  = sbox[0..15]   (both lanes)
	VMOVQ 16(R9), V8
	XVPERMIQ_REPL(8)          // X8  = sbox[16..31]  (both lanes)
	VMOVQ 32(R9), V1
	XVPERMIQ_REPL(1)          // X1  = sbox[32..47]  (both lanes)
	VMOVQ 48(R9), V9
	XVPERMIQ_REPL(9)          // X9  = sbox[48..63]  (both lanes)
	VMOVQ 64(R9), V2
	XVPERMIQ_REPL(2)          // X2  = sbox[64..79]  (both lanes)
	VMOVQ 80(R9), V10
	XVPERMIQ_REPL(10)         // X10 = sbox[80..95]  (both lanes)
	VMOVQ 96(R9), V3
	XVPERMIQ_REPL(3)          // X3  = sbox[96..111] (both lanes)
	VMOVQ 112(R9), V11
	XVPERMIQ_REPL(11)         // X11 = sbox[112..127](both lanes)
	VMOVQ 128(R9), V4
	XVPERMIQ_REPL(4)          // X4  = sbox[128..143](both lanes)
	VMOVQ 144(R9), V12
	XVPERMIQ_REPL(12)         // X12 = sbox[144..159](both lanes)
	VMOVQ 160(R9), V5
	XVPERMIQ_REPL(5)          // X5  = sbox[160..175](both lanes)
	VMOVQ 176(R9), V13
	XVPERMIQ_REPL(13)         // X13 = sbox[176..191](both lanes)
	VMOVQ 192(R9), V6
	XVPERMIQ_REPL(6)          // X6  = sbox[192..207](both lanes)
	VMOVQ 208(R9), V14
	XVPERMIQ_REPL(14)         // X14 = sbox[208..223](both lanes)
	VMOVQ 224(R9), V7
	XVPERMIQ_REPL(7)          // X7  = sbox[224..239](both lanes)
	VMOVQ 240(R9), V15
	XVPERMIQ_REPL(15)         // X15 = sbox[240..255](both lanes)

	// Load byte-level constants for S-box range checking.
	MOVV $0x01, R9
	XVMOVQ R9, X20.B32        // X20 = broadcast(0x01) [all_01]
	MOVV $0x80, R9
	XVMOVQ R9, X21.B32        // X21 = broadcast(0x80) [all_80]
	MOVV $0x1F, R9
	XVMOVQ R9, X22.B32        // X22 = broadcast(0x1F) [mask_1F]

lasx_loop:
	// Load 8 consecutive blocks (128 bytes) from src.
	// Each XVMOVQ loads 32 bytes = 2 SM4 blocks.
	XVMOVQ 0(R6), X23         // blocks 0,1
	XVMOVQ 32(R6), X24        // blocks 2,3
	XVMOVQ 64(R6), X25        // blocks 4,5
	XVMOVQ 96(R6), X26        // blocks 6,7

	// Byte-swap each 32-bit word (big-endian mem → little-endian SM4 state).
	XVSHUF4IB $0x1B, X23, X23
	XVSHUF4IB $0x1B, X24, X24
	XVSHUF4IB $0x1B, X25, X25
	XVSHUF4IB $0x1B, X26, X26

	// Interleave 8 blocks into state registers X16-X19.
	// After interleave: X16[S_i] = B0 of block i, X17[S_i]=B1, X18=B2, X19=B3.
	XVILVLW X23, X24, X27     // interleave B0,B1 of blocks 0/1 with 2/3 X27 = { B3.w1 B1.w1 B3.w0 B1.w0 B2.w1 B0.w1 B2.w0 B0.w0 }
	XVILVHW X23, X24, X28     // interleave B2,B3 of blocks 0/1 with 2/3 X28 = { B3.w3 B1.w3 B3.w2 B1.w2 B2.w3 B0.w3 B2.w2 B0.w2 }
	XVILVLW X25, X26, X29     // interleave B0,B1 of blocks 4/5 with 6/7 X29 = { B7.w1 B5.w1 B7.w0 B5.w0 B6.w1 B4.w.w1 B6.w0 B4.w0 }
	XVILVHW X25, X26, X30     // interleave B2,B3 of blocks 4/5 with 6/7 X30 = { B7.w3 B5.w3 B7.w2 B5.w2 B6.w3 B4.w.w3 B6.w2 B4.w2 }
	XVILVLV X27, X29, X16     // X16 = B0 from all 8 blocks X16 = { B7.w0 B5.w0 B3.w0 B1.w0 B6.w0 B4.w0 B2.w0 B0.w0 }
	XVILVHV X27, X29, X17     // X17 = B1 from all 8 blocks X17 = { B7.w1 B5.w1 B3.w1 B1.w1 B6.w1 B4.w1 B2.w1 B0.w1 }
	XVILVLV X28, X30, X18     // X18 = B2 from all 8 blocks X18 = { B7.w2 B5.w2 B3.w2 B1.w2 B6.w2 B4.w2 B2.w2 B0.w2 }
	XVILVHV X28, X30, X19     // X19 = B3 from all 8 blocks X19 = { B7.w3 B5.w3 B3.w3 B1.w3 B6.w3 B4.w3 B2.w3 B0.w3 }

	// Execute 32 SM4 rounds via 8 × LASX_4ROUNDS().
	MOVV R4, R11              // R11 = xk (round key pointer for this batch)
	MOVV $8, R12              // R12 = loop counter

lasx_round_loop:
	LASX_4ROUNDS()
	ADDV $-1, R12
	BNE R12, R0, lasx_round_loop

	// Deinterleave X16-X19 back into 8 blocks.
	// X16-X19 layout (8 words each): [B0,B2,B4,B6 | B1,B3,B5,B7] per state word.
	// Use X19=B3_state, X18=B2_state, X17=B1_state, X16=B0_state (reversed for output).
	// XVILVLW grabs positions 0,1 per lane → blocks 0,2 (low) and 1,3 (high).
	// XVILVHW grabs positions 2,3 per lane → blocks 4,6 (low) and 5,7 (high).
	XVILVLW X18, X19, X27     // low pos: {B0.w3,B0.w2,B2.w3,B2.w2 | B1.w3,B1.w2,B3.w3,B3.w2}
	XVILVLW X16, X17, X29     // low pos: {B0.w1,B0.w0,B2.w1,B2.w0 | B1.w1,B1.w0,B3.w1,B3.w0}
	XVILVHW X18, X19, X28     // high pos: {B4.w3,B4.w2,B6.w3,B6.w2 | B5.w3,B5.w2,B7.w3,B7.w2}
	XVILVHW X16, X17, X30     // high pos: {B4.w1,B4.w0,B6.w1,B6.w0 | B5.w1,B5.w0,B7.w1,B7.w0}
	XVILVLV X27, X29, X23     // X23 = blocks 0,1: [B0.w3..B0.w0 | B1.w3..B1.w0]
	XVILVHV X27, X29, X24     // X24 = blocks 2,3: [B2.w3..B2.w0 | B3.w3..B3.w0]
	XVILVLV X28, X30, X25     // X25 = blocks 4,5: [B4.w3..B4.w0 | B5.w3..B5.w0]
	XVILVHV X28, X30, X26     // X26 = blocks 6,7: [B6.w3..B6.w0 | B7.w3..B7.w0]

	// Byte-swap back (little-endian SM4 state → big-endian ciphertext).
	XVSHUF4IB $0x1B, X23, X23
	XVSHUF4IB $0x1B, X24, X24
	XVSHUF4IB $0x1B, X25, X25
	XVSHUF4IB $0x1B, X26, X26

	// Store 8 encrypted blocks to dst.
	XVMOVQ X23, 0(R5)
	XVMOVQ X24, 32(R5)
	XVMOVQ X25, 64(R5)
	XVMOVQ X26, 96(R5)

	ADDV $128, R5
	ADDV $128, R6
	ADDV $-128, R7
	BGEU R7, R8, lasx_loop    // process next 8-block batch if enough remain

	// ----------------------------------------------------------------
	// Scalar path: handle remaining blocks (0-7) one at a time.
	// ----------------------------------------------------------------
scalar_path:
	MOVV $·sbox_t0(SB), ST0
	MOVV $·sbox_t1(SB), ST1
	MOVV $·sbox_t2(SB), ST2
	MOVV $·sbox_t3(SB), ST3

encrypt_blocks_loop:
	BEQ R7, R0, encrypt_blocks_done
	ENCRYPT_BLOCK()
	ADDV $16, R5
	ADDV $16, R6
	ADDV $-16, R7
	JMP encrypt_blocks_loop

encrypt_blocks_done:
	RET
