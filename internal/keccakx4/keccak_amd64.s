// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

#include "textflag.h"

// Lane offsets in State4 (lane i is at offset i*32 bytes)
#define A00 (0*32)
#define A10 (1*32)
#define A20 (2*32)
#define A30 (3*32)
#define A40 (4*32)
#define A01 (5*32)
#define A11 (6*32)
#define A21 (7*32)
#define A31 (8*32)
#define A41 (9*32)
#define A02 (10*32)
#define A12 (11*32)
#define A22 (12*32)
#define A32 (13*32)
#define A42 (14*32)
#define A03 (15*32)
#define A13 (16*32)
#define A23 (17*32)
#define A33 (18*32)
#define A43 (19*32)
#define A04 (20*32)
#define A14 (21*32)
#define A24 (22*32)
#define A34 (23*32)
#define A44 (24*32)

// ROT64 rotates YMM register by n bits (64-bit lanes).
// Uses Y14 and Y15 as temporaries, result in dst.
#define ROT64(n, src, dst) \
	VPSLLQ $n, src, Y14 \
	VPSRLQ $(64-n), src, Y15 \
	VPOR Y14, Y15, dst

// THETA_RHOPI merges θ XOR and ρπ: load A[x,y], XOR D[x], rotate, store to B[dst].
// Dreg is the D[x] register (Y5-Y9), rot is the ρ offset, dst is the B output offset.
// Uses Y0 as load temp, Y1 as result, Y14/Y15 as rotate temps.
#define THETA_RHOPI(src_off, Dreg, rot, dst_off) \
	VMOVDQU src_off(AX), Y0 \
	VPXOR Dreg, Y0, Y0 \
	ROT64(rot, Y0, Y1) \
	VMOVDQU Y1, dst_off(BX)

// THETA_RHOPI_NOROT: for lane (0,0) where rotation = 0.
#define THETA_RHOPI_NOROT(src_off, Dreg, dst_off) \
	VMOVDQU src_off(AX), Y0 \
	VPXOR Dreg, Y0, Y0 \
	VMOVDQU Y0, dst_off(BX)

// func permute4AVX2(state *State4)
TEXT ·permute4AVX2(SB), $832-8
	// Frame: 800 bytes for B buffer + 32 bytes alignment padding
	MOVQ state+0(FP), AX       // AX = pointer to state
	LEAQ ·roundConstants(SB), CX // CX = pointer to round constants
	MOVQ $24, DX               // DX = round counter
	LEAQ 32(SP), BX            // BX = pointer to B buffer (on stack)

round_loop:
	// === θ step: compute column parities C[0..4] ===
	// C[0] = A[0,0] ^ A[0,1] ^ A[0,2] ^ A[0,3] ^ A[0,4]
	VMOVDQU A00(AX), Y0
	VPXOR A01(AX), Y0, Y0
	VPXOR A02(AX), Y0, Y0
	VPXOR A03(AX), Y0, Y0
	VPXOR A04(AX), Y0, Y0
	// C[1]
	VMOVDQU A10(AX), Y1
	VPXOR A11(AX), Y1, Y1
	VPXOR A12(AX), Y1, Y1
	VPXOR A13(AX), Y1, Y1
	VPXOR A14(AX), Y1, Y1
	// C[2]
	VMOVDQU A20(AX), Y2
	VPXOR A21(AX), Y2, Y2
	VPXOR A22(AX), Y2, Y2
	VPXOR A23(AX), Y2, Y2
	VPXOR A24(AX), Y2, Y2
	// C[3]
	VMOVDQU A30(AX), Y3
	VPXOR A31(AX), Y3, Y3
	VPXOR A32(AX), Y3, Y3
	VPXOR A33(AX), Y3, Y3
	VPXOR A34(AX), Y3, Y3
	// C[4]
	VMOVDQU A40(AX), Y4
	VPXOR A41(AX), Y4, Y4
	VPXOR A42(AX), Y4, Y4
	VPXOR A43(AX), Y4, Y4
	VPXOR A44(AX), Y4, Y4

	// D[x] = C[(x+4)%5] ^ ROT(C[(x+1)%5], 1)
	// D[0] = C[4] ^ ROT(C[1], 1) → Y5
	ROT64(1, Y1, Y5)
	VPXOR Y4, Y5, Y5
	// D[1] = C[0] ^ ROT(C[2], 1) → Y6
	ROT64(1, Y2, Y6)
	VPXOR Y0, Y6, Y6
	// D[2] = C[1] ^ ROT(C[3], 1) → Y7
	ROT64(1, Y3, Y7)
	VPXOR Y1, Y7, Y7
	// D[3] = C[2] ^ ROT(C[4], 1) → Y8
	ROT64(1, Y4, Y8)
	VPXOR Y2, Y8, Y8
	// D[4] = C[3] ^ ROT(C[0], 1) → Y9
	ROT64(1, Y0, Y9)
	VPXOR Y3, Y9, Y9

	// === Merged θ XOR + ρ + π ===
	// For each lane (x,y): load A[x,y], XOR D[x], rotate ρ[x,y], store to B[π(x,y)]
	// D[0]=Y5, D[1]=Y6, D[2]=Y7, D[3]=Y8, D[4]=Y9

	// (0,0) → B[0], rot 0
	THETA_RHOPI_NOROT(A00, Y5, 0*32)
	// (1,0) → B[10], rot 1
	THETA_RHOPI(A10, Y6, 1, 10*32)
	// (2,0) → B[20], rot 62
	THETA_RHOPI(A20, Y7, 62, 20*32)
	// (3,0) → B[5], rot 28
	THETA_RHOPI(A30, Y8, 28, 5*32)
	// (4,0) → B[15], rot 27
	THETA_RHOPI(A40, Y9, 27, 15*32)
	// (0,1) → B[16], rot 36
	THETA_RHOPI(A01, Y5, 36, 16*32)
	// (1,1) → B[1], rot 44
	THETA_RHOPI(A11, Y6, 44, 1*32)
	// (2,1) → B[11], rot 6
	THETA_RHOPI(A21, Y7, 6, 11*32)
	// (3,1) → B[21], rot 55
	THETA_RHOPI(A31, Y8, 55, 21*32)
	// (4,1) → B[6], rot 20
	THETA_RHOPI(A41, Y9, 20, 6*32)
	// (0,2) → B[7], rot 3
	THETA_RHOPI(A02, Y5, 3, 7*32)
	// (1,2) → B[17], rot 10
	THETA_RHOPI(A12, Y6, 10, 17*32)
	// (2,2) → B[2], rot 43
	THETA_RHOPI(A22, Y7, 43, 2*32)
	// (3,2) → B[12], rot 25
	THETA_RHOPI(A32, Y8, 25, 12*32)
	// (4,2) → B[22], rot 39
	THETA_RHOPI(A42, Y9, 39, 22*32)
	// (0,3) → B[23], rot 41
	THETA_RHOPI(A03, Y5, 41, 23*32)
	// (1,3) → B[8], rot 45
	THETA_RHOPI(A13, Y6, 45, 8*32)
	// (2,3) → B[18], rot 15
	THETA_RHOPI(A23, Y7, 15, 18*32)
	// (3,3) → B[3], rot 21
	THETA_RHOPI(A33, Y8, 21, 3*32)
	// (4,3) → B[13], rot 8
	THETA_RHOPI(A43, Y9, 8, 13*32)
	// (0,4) → B[14], rot 18
	THETA_RHOPI(A04, Y5, 18, 14*32)
	// (1,4) → B[24], rot 2
	THETA_RHOPI(A14, Y6, 2, 24*32)
	// (2,4) → B[9], rot 61
	THETA_RHOPI(A24, Y7, 61, 9*32)
	// (3,4) → B[19], rot 56
	THETA_RHOPI(A34, Y8, 56, 19*32)
	// (4,4) → B[4], rot 14
	THETA_RHOPI(A44, Y9, 14, 4*32)

	// === χ step + ι merged ===
	// A'[x,y] = B[x,y] ^ (~B[x+1,y] & B[x+2,y])
	// ι: A'[0,0] ^= RC[round] (merged into row 0)

	// Preload round constant for ι merge
	VPBROADCASTQ (CX), Y13

	// Row 0: B[0], B[1], B[2], B[3], B[4]
	VMOVDQU (0*32)(BX), Y0   // B[0]
	VMOVDQU (1*32)(BX), Y1   // B[1]
	VMOVDQU (2*32)(BX), Y2   // B[2]
	VMOVDQU (3*32)(BX), Y3   // B[3]
	VMOVDQU (4*32)(BX), Y4   // B[4]
	// A'[0,0] = B[0] ^ (~B[1] & B[2]) ^ RC
	VPANDN Y2, Y1, Y5
	VPXOR Y0, Y5, Y5
	VPXOR Y13, Y5, Y5
	VMOVDQU Y5, A00(AX)
	// A'[1,0] = B[1] ^ (~B[2] & B[3])
	VPANDN Y3, Y2, Y5
	VPXOR Y1, Y5, Y5
	VMOVDQU Y5, A10(AX)
	// A'[2,0] = B[2] ^ (~B[3] & B[4])
	VPANDN Y4, Y3, Y5
	VPXOR Y2, Y5, Y5
	VMOVDQU Y5, A20(AX)
	// A'[3,0] = B[3] ^ (~B[4] & B[0])
	VPANDN Y0, Y4, Y5
	VPXOR Y3, Y5, Y5
	VMOVDQU Y5, A30(AX)
	// A'[4,0] = B[4] ^ (~B[0] & B[1])
	VPANDN Y1, Y0, Y5
	VPXOR Y4, Y5, Y5
	VMOVDQU Y5, A40(AX)

	// Row 1: B[5], B[6], B[7], B[8], B[9]
	VMOVDQU (5*32)(BX), Y0
	VMOVDQU (6*32)(BX), Y1
	VMOVDQU (7*32)(BX), Y2
	VMOVDQU (8*32)(BX), Y3
	VMOVDQU (9*32)(BX), Y4
	VPANDN Y2, Y1, Y5
	VPXOR Y0, Y5, Y5
	VMOVDQU Y5, A01(AX)
	VPANDN Y3, Y2, Y5
	VPXOR Y1, Y5, Y5
	VMOVDQU Y5, A11(AX)
	VPANDN Y4, Y3, Y5
	VPXOR Y2, Y5, Y5
	VMOVDQU Y5, A21(AX)
	VPANDN Y0, Y4, Y5
	VPXOR Y3, Y5, Y5
	VMOVDQU Y5, A31(AX)
	VPANDN Y1, Y0, Y5
	VPXOR Y4, Y5, Y5
	VMOVDQU Y5, A41(AX)

	// Row 2: B[10], B[11], B[12], B[13], B[14]
	VMOVDQU (10*32)(BX), Y0
	VMOVDQU (11*32)(BX), Y1
	VMOVDQU (12*32)(BX), Y2
	VMOVDQU (13*32)(BX), Y3
	VMOVDQU (14*32)(BX), Y4
	VPANDN Y2, Y1, Y5
	VPXOR Y0, Y5, Y5
	VMOVDQU Y5, A02(AX)
	VPANDN Y3, Y2, Y5
	VPXOR Y1, Y5, Y5
	VMOVDQU Y5, A12(AX)
	VPANDN Y4, Y3, Y5
	VPXOR Y2, Y5, Y5
	VMOVDQU Y5, A22(AX)
	VPANDN Y0, Y4, Y5
	VPXOR Y3, Y5, Y5
	VMOVDQU Y5, A32(AX)
	VPANDN Y1, Y0, Y5
	VPXOR Y4, Y5, Y5
	VMOVDQU Y5, A42(AX)

	// Row 3: B[15], B[16], B[17], B[18], B[19]
	VMOVDQU (15*32)(BX), Y0
	VMOVDQU (16*32)(BX), Y1
	VMOVDQU (17*32)(BX), Y2
	VMOVDQU (18*32)(BX), Y3
	VMOVDQU (19*32)(BX), Y4
	VPANDN Y2, Y1, Y5
	VPXOR Y0, Y5, Y5
	VMOVDQU Y5, A03(AX)
	VPANDN Y3, Y2, Y5
	VPXOR Y1, Y5, Y5
	VMOVDQU Y5, A13(AX)
	VPANDN Y4, Y3, Y5
	VPXOR Y2, Y5, Y5
	VMOVDQU Y5, A23(AX)
	VPANDN Y0, Y4, Y5
	VPXOR Y3, Y5, Y5
	VMOVDQU Y5, A33(AX)
	VPANDN Y1, Y0, Y5
	VPXOR Y4, Y5, Y5
	VMOVDQU Y5, A43(AX)

	// Row 4: B[20], B[21], B[22], B[23], B[24]
	VMOVDQU (20*32)(BX), Y0
	VMOVDQU (21*32)(BX), Y1
	VMOVDQU (22*32)(BX), Y2
	VMOVDQU (23*32)(BX), Y3
	VMOVDQU (24*32)(BX), Y4
	VPANDN Y2, Y1, Y5
	VPXOR Y0, Y5, Y5
	VMOVDQU Y5, A04(AX)
	VPANDN Y3, Y2, Y5
	VPXOR Y1, Y5, Y5
	VMOVDQU Y5, A14(AX)
	VPANDN Y4, Y3, Y5
	VPXOR Y2, Y5, Y5
	VMOVDQU Y5, A24(AX)
	VPANDN Y0, Y4, Y5
	VPXOR Y3, Y5, Y5
	VMOVDQU Y5, A34(AX)
	VPANDN Y1, Y0, Y5
	VPXOR Y4, Y5, Y5
	VMOVDQU Y5, A44(AX)

	// Advance round constant pointer and decrement counter
	ADDQ $8, CX
	DECQ DX
	JNZ round_loop

	VZEROUPPER
	RET

// TRANSPOSE4x4 transposes a 4×4 matrix of uint64 values in Y0-Y3.
// Input:  Y0={a0,a1,a2,a3}, Y1={b0,b1,b2,b3}, Y2={c0,c1,c2,c3}, Y3={d0,d1,d2,d3}
// Output: Y0={a0,b0,c0,d0}, Y1={a1,b1,c1,d1}, Y2={a2,b2,c2,d2}, Y3={a3,b3,c3,d3}
// Uses Y4, Y5, Y6, Y7 as temporaries.
#define TRANSPOSE4x4() \
	VPUNPCKLQDQ Y1, Y0, Y4 \  // {a0, b0, a2, b2}
	VPUNPCKHQDQ Y1, Y0, Y5 \  // {a1, b1, a3, b3}
	VPUNPCKLQDQ Y3, Y2, Y6 \  // {c0, d0, c2, d2}
	VPUNPCKHQDQ Y3, Y2, Y7 \  // {c1, d1, c3, d3}
	VPERM2I128 $0x20, Y6, Y4, Y0 \ // {a0, b0, c0, d0}
	VPERM2I128 $0x20, Y7, Y5, Y1 \ // {a1, b1, c1, d1}
	VPERM2I128 $0x31, Y6, Y4, Y2 \ // {a2, b2, c2, d2}
	VPERM2I128 $0x31, Y7, Y5, Y3    // {a3, b3, c3, d3}

// func copyOut4AVX2(state *State4, out0, out1, out2, out3 *byte, lanes int)
TEXT ·copyOut4AVX2(SB), NOSPLIT, $0-48
	MOVQ state+0(FP), AX
	MOVQ out0+8(FP), R8
	MOVQ out1+16(FP), R9
	MOVQ out2+24(FP), R10
	MOVQ out3+32(FP), R11
	MOVQ lanes+40(FP), CX

	XORQ DX, DX  // DX = offset counter (0, 4, 8, ...)

copyout_loop4:
	// Check if we have at least 4 lanes remaining
	MOVQ CX, BX
	SUBQ DX, BX
	CMPQ BX, $4
	JL copyout_tail

	// Load 4 interleaved lanes from state
	MOVQ DX, BX
	SHLQ $5, BX     // BX = DX * 32 (byte offset into state)
	VMOVDQU (AX)(BX*1), Y0       // lane DX+0: {s0, s1, s2, s3}
	VMOVDQU 32(AX)(BX*1), Y1     // lane DX+1
	VMOVDQU 64(AX)(BX*1), Y2     // lane DX+2
	VMOVDQU 96(AX)(BX*1), Y3     // lane DX+3

	// Transpose: rows=lanes, cols=states → rows=states, cols=lanes
	TRANSPOSE4x4()

	// Store 32 bytes (4 sequential uint64) to each output buffer
	MOVQ DX, BX
	SHLQ $3, BX     // BX = DX * 8 (byte offset into output)
	VMOVDQU Y0, (R8)(BX*1)
	VMOVDQU Y1, (R9)(BX*1)
	VMOVDQU Y2, (R10)(BX*1)
	VMOVDQU Y3, (R11)(BX*1)

	ADDQ $4, DX
	JMP copyout_loop4

copyout_tail:
	// Process remaining lanes one at a time
	CMPQ DX, CX
	JGE copyout_done

	MOVQ DX, BX
	SHLQ $5, BX     // byte offset into state
	MOVQ (AX)(BX*1), R12       // state[lane*4+0]
	MOVQ 8(AX)(BX*1), R13     // state[lane*4+1]
	MOVQ 16(AX)(BX*1), R14    // state[lane*4+2]
	MOVQ 24(AX)(BX*1), R15    // state[lane*4+3]

	MOVQ DX, BX
	SHLQ $3, BX     // byte offset into output
	MOVQ R12, (R8)(BX*1)
	MOVQ R13, (R9)(BX*1)
	MOVQ R14, (R10)(BX*1)
	MOVQ R15, (R11)(BX*1)

	INCQ DX
	JMP copyout_tail

copyout_done:
	VZEROUPPER
	RET

// func xorIn4AVX2(state *State4, in0, in1, in2, in3 *byte, lanes int)
TEXT ·xorIn4AVX2(SB), NOSPLIT, $0-48
	MOVQ state+0(FP), AX
	MOVQ in0+8(FP), R8
	MOVQ in1+16(FP), R9
	MOVQ in2+24(FP), R10
	MOVQ in3+32(FP), R11
	MOVQ lanes+40(FP), CX

	XORQ DX, DX  // DX = lane offset counter

xorin_loop4:
	MOVQ CX, BX
	SUBQ DX, BX
	CMPQ BX, $4
	JL xorin_tail

	// Load 32 bytes from each input buffer (4 consecutive uint64 = 4 lanes per state)
	MOVQ DX, BX
	SHLQ $3, BX     // BX = DX * 8 (byte offset into inputs)
	VMOVDQU (R8)(BX*1), Y0    // {in0_lane_j, in0_lane_j+1, in0_lane_j+2, in0_lane_j+3}
	VMOVDQU (R9)(BX*1), Y1
	VMOVDQU (R10)(BX*1), Y2
	VMOVDQU (R11)(BX*1), Y3

	// Transpose: rows=states, cols=lanes → rows=lanes, cols=states
	TRANSPOSE4x4()

	// XOR into state at interleaved positions
	MOVQ DX, BX
	SHLQ $5, BX     // BX = DX * 32 (byte offset into state)
	VPXOR (AX)(BX*1), Y0, Y0
	VMOVDQU Y0, (AX)(BX*1)
	VPXOR 32(AX)(BX*1), Y1, Y1
	VMOVDQU Y1, 32(AX)(BX*1)
	VPXOR 64(AX)(BX*1), Y2, Y2
	VMOVDQU Y2, 64(AX)(BX*1)
	VPXOR 96(AX)(BX*1), Y3, Y3
	VMOVDQU Y3, 96(AX)(BX*1)

	ADDQ $4, DX
	JMP xorin_loop4

xorin_tail:
	CMPQ DX, CX
	JGE xorin_done

	// Load 8 bytes from each input, interleave, XOR into state
	MOVQ DX, BX
	SHLQ $3, BX     // byte offset into inputs
	MOVQ (R8)(BX*1), R12
	MOVQ (R9)(BX*1), R13
	MOVQ (R10)(BX*1), R14
	MOVQ (R11)(BX*1), R15

	MOVQ DX, BX
	SHLQ $5, BX     // byte offset into state
	XORQ (AX)(BX*1), R12
	MOVQ R12, (AX)(BX*1)
	XORQ 8(AX)(BX*1), R13
	MOVQ R13, 8(AX)(BX*1)
	XORQ 16(AX)(BX*1), R14
	MOVQ R14, 16(AX)(BX*1)
	XORQ 24(AX)(BX*1), R15
	MOVQ R15, 24(AX)(BX*1)

	INCQ DX
	JMP xorin_tail

xorin_done:
	VZEROUPPER
	RET
