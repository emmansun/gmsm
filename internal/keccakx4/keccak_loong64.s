// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

#include "textflag.h"

// Register allocation:
// X0-X24:  25 Keccak state lanes (permanently in registers, zero memory traffic!)
// X25-X29: θ column parity C[0..4]
// X30:     temp (ρ+π merged save / χ save B[0] per row)
// X31:     temp (χ save B[1] per row)
//
// XVROTRV $k, Xsrc, Xdst — rotate Xsrc right by k bits (64-bit lanes), write to Xdst.
// Rotate left by n bits = rotate right by (64-n) bits.

// XVPERMIQ(Xd, Xj, imm8) — xvpermi.q Xd, Xj, imm8.
// Semantics: pool={Xj.lo=0, Xj.hi=1, Xd_old.lo=2, Xd_old.hi=3}
//   Xd.lo = pool[imm[1:0]],  Xd.hi = pool[imm[5:4]]
// Opcode 0x1DFB: xvpermi.q X8, X9, 0x02 → WORD $0x77ec0928
#define XVPERMIQ(Xd, Xj, imm8) WORD $((0x1DFB << 18) | ((imm8) << 10) | ((Xj) << 5) | (Xd))

// func permute4LASX(state *State4)
TEXT ·permute4LASX(SB), NOSPLIT, $0-8
	MOVV state+0(FP), R4

	// Load all 25 lanes into X0-X24
	XVMOVQ (0*32)(R4), X0
	XVMOVQ (1*32)(R4), X1
	XVMOVQ (2*32)(R4), X2
	XVMOVQ (3*32)(R4), X3
	XVMOVQ (4*32)(R4), X4
	XVMOVQ (5*32)(R4), X5
	XVMOVQ (6*32)(R4), X6
	XVMOVQ (7*32)(R4), X7
	XVMOVQ (8*32)(R4), X8
	XVMOVQ (9*32)(R4), X9
	XVMOVQ (10*32)(R4), X10
	XVMOVQ (11*32)(R4), X11
	XVMOVQ (12*32)(R4), X12
	XVMOVQ (13*32)(R4), X13
	XVMOVQ (14*32)(R4), X14
	XVMOVQ (15*32)(R4), X15
	XVMOVQ (16*32)(R4), X16
	XVMOVQ (17*32)(R4), X17
	XVMOVQ (18*32)(R4), X18
	XVMOVQ (19*32)(R4), X19
	XVMOVQ (20*32)(R4), X20
	XVMOVQ (21*32)(R4), X21
	XVMOVQ (22*32)(R4), X22
	XVMOVQ (23*32)(R4), X23
	XVMOVQ (24*32)(R4), X24

	MOVV $·roundConstants(SB), R5  // round constant pointer
	MOVV $24, R6                    // round counter

round_loop:
	// ===== θ step =====
	// C[x] = A[x,0] ^ A[x,1] ^ A[x,2] ^ A[x,3] ^ A[x,4]
	// Lane (x,y) lives in register X[x + 5*y].
	XVXORV X0, X5, X25
	XVXORV X25, X10, X25
	XVXORV X25, X15, X25
	XVXORV X25, X20, X25       // X25 = C[0]

	XVXORV X1, X6, X26
	XVXORV X26, X11, X26
	XVXORV X26, X16, X26
	XVXORV X26, X21, X26       // X26 = C[1]

	XVXORV X2, X7, X27
	XVXORV X27, X12, X27
	XVXORV X27, X17, X27
	XVXORV X27, X22, X27       // X27 = C[2]

	XVXORV X3, X8, X28
	XVXORV X28, X13, X28
	XVXORV X28, X18, X28
	XVXORV X28, X23, X28       // X28 = C[3]

	XVXORV X4, X9, X29
	XVXORV X29, X14, X29
	XVXORV X29, X19, X29
	XVXORV X29, X24, X29       // X29 = C[4]

	// D[x] = C[(x+4)%5] ^ ROL(C[(x+1)%5], 1)
	// Compute each D value and XOR directly into the 5 affected lanes.

	// D[0] = C[4] ^ ROL(C[1], 1)
	XVROTRV $63, X26, X30      // X30 = ROL(C[1], 1) = rotate-right-63
	XVXORV X29, X30, X30       // X30 = D[0]
	XVXORV X0, X30, X0
	XVXORV X5, X30, X5
	XVXORV X10, X30, X10
	XVXORV X15, X30, X15
	XVXORV X20, X30, X20

	// D[1] = C[0] ^ ROL(C[2], 1)
	XVROTRV $63, X27, X30      // X30 = ROL(C[2], 1)
	XVXORV X25, X30, X30       // X30 = D[1]
	XVXORV X1, X30, X1
	XVXORV X6, X30, X6
	XVXORV X11, X30, X11
	XVXORV X16, X30, X16
	XVXORV X21, X30, X21

	// D[2] = C[1] ^ ROL(C[3], 1)
	XVROTRV $63, X28, X30      // X30 = ROL(C[3], 1)
	XVXORV X26, X30, X30       // X30 = D[2]
	XVXORV X2, X30, X2
	XVXORV X7, X30, X7
	XVXORV X12, X30, X12
	XVXORV X17, X30, X17
	XVXORV X22, X30, X22

	// D[3] = C[2] ^ ROL(C[4], 1)
	XVROTRV $63, X29, X30      // X30 = ROL(C[4], 1)
	XVXORV X27, X30, X30       // X30 = D[3]
	XVXORV X3, X30, X3
	XVXORV X8, X30, X8
	XVXORV X13, X30, X13
	XVXORV X18, X30, X18
	XVXORV X23, X30, X23

	// D[4] = C[3] ^ ROL(C[0], 1)
	XVROTRV $63, X25, X30      // X30 = ROL(C[0], 1)
	XVXORV X28, X30, X30       // X30 = D[4]
	XVXORV X4, X30, X4
	XVXORV X9, X30, X9
	XVXORV X14, X30, X14
	XVXORV X19, X30, X19
	XVXORV X24, X30, X24

	// ===== ρ+π step: merged rotate-and-permute =====
	// Replaces separate ρ (24 in-place ROT64) + π (25 XVORV moves) = 49 instructions
	// with 1 XVORV save + 24 XVROTRV src→dst = 25 instructions (saves 24 per round).
	//
	// Cycle: 1→10→7→11→17→18→3→5→16→8→21→24→4→15→23→19→13→12→2→20→14→22→9→6→1
	// Process backward: each source is unmodified when read. Save X1 first (overwritten
	// on step 1 but consumed last). X0 is fixed (ρ[0]=0, π: (0,0)→(0,0)).
	XVORV X1, X1, X30           // save X1 → X30  (used last: X10 ← ROT64(1, X1))
	XVROTRV $(64-44), X6,  X1   // X1  ← ROT64(44, X6)   [6→1,   ρ=44]
	XVROTRV $(64-20), X9,  X6   // X6  ← ROT64(20, X9)   [9→6,   ρ=20]
	XVROTRV $(64-61), X22, X9   // X9  ← ROT64(61, X22)  [22→9,  ρ=61]
	XVROTRV $(64-39), X14, X22  // X22 ← ROT64(39, X14)  [14→22, ρ=39]
	XVROTRV $(64-18), X20, X14  // X14 ← ROT64(18, X20)  [20→14, ρ=18]
	XVROTRV $(64-62), X2,  X20  // X20 ← ROT64(62, X2)   [2→20,  ρ=62]
	XVROTRV $(64-43), X12, X2   // X2  ← ROT64(43, X12)  [12→2,  ρ=43]
	XVROTRV $(64-25), X13, X12  // X12 ← ROT64(25, X13)  [13→12, ρ=25]
	XVROTRV $(64-8),  X19, X13  // X13 ← ROT64(8,  X19)  [19→13, ρ=8]
	XVROTRV $(64-56), X23, X19  // X19 ← ROT64(56, X23)  [23→19, ρ=56]
	XVROTRV $(64-41), X15, X23  // X23 ← ROT64(41, X15)  [15→23, ρ=41]
	XVROTRV $(64-27), X4,  X15  // X15 ← ROT64(27, X4)   [4→15,  ρ=27]
	XVROTRV $(64-14), X24, X4   // X4  ← ROT64(14, X24)  [24→4,  ρ=14]
	XVROTRV $(64-2),  X21, X24  // X24 ← ROT64(2,  X21)  [21→24, ρ=2]
	XVROTRV $(64-55), X8,  X21  // X21 ← ROT64(55, X8)   [8→21,  ρ=55]
	XVROTRV $(64-45), X16, X8   // X8  ← ROT64(45, X16)  [16→8,  ρ=45]
	XVROTRV $(64-36), X5,  X16  // X16 ← ROT64(36, X5)   [5→16,  ρ=36]
	XVROTRV $(64-28), X3,  X5   // X5  ← ROT64(28, X3)   [3→5,   ρ=28]
	XVROTRV $(64-21), X18, X3   // X3  ← ROT64(21, X18)  [18→3,  ρ=21]
	XVROTRV $(64-15), X17, X18  // X18 ← ROT64(15, X17)  [17→18, ρ=15]
	XVROTRV $(64-10), X11, X17  // X17 ← ROT64(10, X11)  [11→17, ρ=10]
	XVROTRV $(64-6),  X7,  X11  // X11 ← ROT64(6,  X7)   [7→11,  ρ=6]
	XVROTRV $(64-3),  X10, X7   // X7  ← ROT64(3,  X10)  [10→7,  ρ=3]
	XVROTRV $(64-1),  X30, X10  // X10 ← ROT64(1,  X1)   [1→10,  ρ=1]

	// ===== χ + ι steps =====
	// A'[x,y] = B[x,y] ^ (~B[(x+1)%5,y] & B[(x+2)%5,y])
	// XVANDNV Xa, Xb, Xd  ≡  ~Xb & Xa  (second arg is negated, per LoongArch Go asm convention)
	// So to compute ~B[x+1] & B[x+2], write: XVANDNV B[x+2], B[x+1], tmp

	// Row 0 (X0..X4) — combined with ι
	XVORV X0, X0, X30      // X30 = B[0,0] saved
	XVORV X1, X1, X31      // X31 = B[1,0] saved
	XVANDNV X2, X1, X25
	XVXORV X25, X0, X0     // X0 = B[0] ^ (~B[1] & B[2])
	XVANDNV X3, X2, X25
	XVXORV X25, X31, X1    // X1 = B[1] ^ (~B[2] & B[3])
	XVANDNV X4, X3, X25
	XVXORV X25, X2, X2     // X2 = B[2] ^ (~B[3] & B[4])
	XVANDNV X30, X4, X25
	XVXORV X25, X3, X3     // X3 = B[3] ^ (~B[4] & B[0])
	XVANDNV X31, X30, X25
	XVXORV X25, X4, X4     // X4 = B[4] ^ (~B[0] & B[1])
	// ι: A'[0,0] ^= roundConstants[round]
	MOVV (R5), R7
	XVMOVQ R7, X25.V4      // broadcast 64-bit RC to all 4 lanes
	XVXORV X25, X0, X0

	// Row 1 (X5..X9)
	XVORV X5, X5, X30
	XVORV X6, X6, X31
	XVANDNV X7, X6, X25
	XVXORV X25, X5, X5
	XVANDNV X8, X7, X25
	XVXORV X25, X31, X6
	XVANDNV X9, X8, X25
	XVXORV X25, X7, X7
	XVANDNV X30, X9, X25
	XVXORV X25, X8, X8
	XVANDNV X31, X30, X25
	XVXORV X25, X9, X9

	// Row 2 (X10..X14)
	XVORV X10, X10, X30
	XVORV X11, X11, X31
	XVANDNV X12, X11, X25
	XVXORV X25, X10, X10
	XVANDNV X13, X12, X25
	XVXORV X25, X31, X11
	XVANDNV X14, X13, X25
	XVXORV X25, X12, X12
	XVANDNV X30, X14, X25
	XVXORV X25, X13, X13
	XVANDNV X31, X30, X25
	XVXORV X25, X14, X14

	// Row 3 (X15..X19)
	XVORV X15, X15, X30
	XVORV X16, X16, X31
	XVANDNV X17, X16, X25
	XVXORV X25, X15, X15
	XVANDNV X18, X17, X25
	XVXORV X25, X31, X16
	XVANDNV X19, X18, X25
	XVXORV X25, X17, X17
	XVANDNV X30, X19, X25
	XVXORV X25, X18, X18
	XVANDNV X31, X30, X25
	XVXORV X25, X19, X19

	// Row 4 (X20..X24)
	XVORV X20, X20, X30
	XVORV X21, X21, X31
	XVANDNV X22, X21, X25
	XVXORV X25, X20, X20
	XVANDNV X23, X22, X25
	XVXORV X25, X31, X21
	XVANDNV X24, X23, X25
	XVXORV X25, X22, X22
	XVANDNV X30, X24, X25
	XVXORV X25, X23, X23
	XVANDNV X31, X30, X25
	XVXORV X25, X24, X24

	ADDV $8, R5
	ADDV $-1, R6
	BNE R6, R0, round_loop

	// Store all 25 lanes back to state
	XVMOVQ X0, (0*32)(R4)
	XVMOVQ X1, (1*32)(R4)
	XVMOVQ X2, (2*32)(R4)
	XVMOVQ X3, (3*32)(R4)
	XVMOVQ X4, (4*32)(R4)
	XVMOVQ X5, (5*32)(R4)
	XVMOVQ X6, (6*32)(R4)
	XVMOVQ X7, (7*32)(R4)
	XVMOVQ X8, (8*32)(R4)
	XVMOVQ X9, (9*32)(R4)
	XVMOVQ X10, (10*32)(R4)
	XVMOVQ X11, (11*32)(R4)
	XVMOVQ X12, (12*32)(R4)
	XVMOVQ X13, (13*32)(R4)
	XVMOVQ X14, (14*32)(R4)
	XVMOVQ X15, (15*32)(R4)
	XVMOVQ X16, (16*32)(R4)
	XVMOVQ X17, (17*32)(R4)
	XVMOVQ X18, (18*32)(R4)
	XVMOVQ X19, (19*32)(R4)
	XVMOVQ X20, (20*32)(R4)
	XVMOVQ X21, (21*32)(R4)
	XVMOVQ X22, (22*32)(R4)
	XVMOVQ X23, (23*32)(R4)
	XVMOVQ X24, (24*32)(R4)
	RET

// func xorIn4LASX(state *State4, in0, in1, in2, in3 *byte, lanes int)
//
// 4×4 transpose (non-interleaved → interleaved) for batches of 4 lanes:
//   Load 4×uint64 from each input → XVILVLV/H interleave pairs → XVPERMIQ combine halves → XOR with state.
//   XVILVLV Xa, Xb, Xd : Xd = [Xa.D[0], Xb.D[0], Xa.D[2], Xb.D[2]]  (even from FIRST arg)
//   XVPERMIQ WORD encoding: 0x77EC0000 | (imm8<<10) | (vj<<5) | vd
//     imm8=0x08 → Xd.lo stays, Xd.hi = Xj.lo
//     imm8=0x0d → Xd.lo = Xd.hi (orig), Xd.hi = Xj.hi
TEXT ·xorIn4LASX(SB), NOSPLIT, $0-48
	MOVV state+0(FP), R4
	MOVV in0+8(FP), R5
	MOVV in1+16(FP), R6
	MOVV in2+24(FP), R7
	MOVV in3+32(FP), R8
	MOVV lanes+40(FP), R9
	MOVV $4, R11

xorin_vec4:
	// Process 4 lanes at a time using vector transpose
	BLTU R9, R11, xorin_scalar

	// Load 4 consecutive uint64 from each input (32 bytes each)
	XVMOVQ (R5), X0    // A = in0[i..i+3]
	XVMOVQ (R6), X1    // B = in1[i..i+3]
	XVMOVQ (R7), X2    // C = in2[i..i+3]
	XVMOVQ (R8), X3    // D = in3[i..i+3]

	// Step 1: XVILVLV/H — pair-interleave A+B and C+D
	// XVILVLV Xa, Xb, Xd: 64-bit interleave lower — even positions from Xa (FIRST arg), odd from Xb
	XVILVLV X0, X1, X4    // vk=X0=A, vj=X1=B → X4 = [A0, B0, A2, B2]
	XVILVHV X0, X1, X5    // X5 = [A1, B1, A3, B3]
	XVILVLV X2, X3, X6    // vk=X2=C, vj=X3=D → X6 = [C0, D0, C2, D2]
	XVILVHV X2, X3, X7    // X7 = [C1, D1, C3, D3]

	// Step 2: XVPERMIQ — merge low+high halves into final row vectors
	// Semantics: pool={Xj.lo=0, Xj.hi=1, Xd_old.lo=2, Xd_old.hi=3}
	//   dst.lo = pool[imm[1:0]], dst.hi = pool[imm[5:4]]
	//   imm=0x02: lower_sel=2(=Xd.lo), upper_sel=0(=Xj.lo) → keep lo, replace hi←Xj.lo
	//   imm=0x13: lower_sel=3(=Xd.hi), upper_sel=1(=Xj.hi) → swap Xd.hi←lo, Xj.hi←hi
	// X0 = [A0, B0, C0, D0] : keep X4.lo, replace X4.hi ← X6.lo (imm=0x02, vj=X6, vd=X4)
	XVORV X4, X4, X0
	XVPERMIQ(0, 6, 0x02)    // xvpermi.q X0, X6, 0x02 → X0=[A0,B0,C0,D0]
	// X4 = [A2, B2, C2, D2] : X4.lo←X4.hi(orig), X4.hi←X6.hi (imm=0x13)
	XVPERMIQ(4, 6, 0x13)    // xvpermi.q X4, X6, 0x13 → X4=[A2,B2,C2,D2]
	// X1 = [A1, B1, C1, D1]
	XVORV X5, X5, X1
	XVPERMIQ(1, 7, 0x02)    // xvpermi.q X1, X7, 0x02 → X1=[A1,B1,C1,D1]
	// X5 = [A3, B3, C3, D3]
	XVPERMIQ(5, 7, 0x13)    // xvpermi.q X5, X7, 0x13 → X5=[A3,B3,C3,D3]

	// XOR with state rows and store (state is interleaved: each 32-byte slot = 4 instances)
	XVMOVQ (0*32)(R4), X2
	XVXORV X2, X0, X0
	XVMOVQ X0, (0*32)(R4)
	XVMOVQ (1*32)(R4), X2
	XVXORV X2, X1, X1
	XVMOVQ X1, (1*32)(R4)
	XVMOVQ (2*32)(R4), X2
	XVXORV X2, X4, X4
	XVMOVQ X4, (2*32)(R4)
	XVMOVQ (3*32)(R4), X2
	XVXORV X2, X5, X5
	XVMOVQ X5, (3*32)(R4)

	ADDV $128, R4      // 4 lanes × 32 bytes
	ADDV $32, R5       // 4 lanes × 8 bytes
	ADDV $32, R6
	ADDV $32, R7
	ADDV $32, R8
	ADDV $-4, R9
	JMP xorin_vec4

xorin_scalar:
	// Scalar tail: 0..3 remaining lanes
	BEQ R9, R0, xorin_done
	MOVV (R5), R11
	MOVV (R6), R12
	MOVV (R7), R13
	MOVV (R8), R14
	MOVV (R4), R15
	XOR R11, R15, R15
	MOVV R15, (R4)
	MOVV 8(R4), R15
	XOR R12, R15, R15
	MOVV R15, 8(R4)
	MOVV 16(R4), R15
	XOR R13, R15, R15
	MOVV R15, 16(R4)
	MOVV 24(R4), R15
	XOR R14, R15, R15
	MOVV R15, 24(R4)
	ADDV $32, R4
	ADDV $8, R5
	ADDV $8, R6
	ADDV $8, R7
	ADDV $8, R8
	ADDV $-1, R9
	JMP xorin_scalar

xorin_done:
	RET

// func copyOut4LASX(state *State4, out0, out1, out2, out3 *byte, lanes int)
//
// Reverse 4×4 transpose (interleaved → non-interleaved) using the same
// XVILVLV/H + XVPERMIQ pattern. Exact same WORD encodings as xorIn4.
TEXT ·copyOut4LASX(SB), NOSPLIT, $0-48
	MOVV state+0(FP), R4
	MOVV out0+8(FP), R5
	MOVV out1+16(FP), R6
	MOVV out2+24(FP), R7
	MOVV out3+32(FP), R8
	MOVV lanes+40(FP), R9
	MOVV $4, R11

copyout_vec4:
	BLTU R9, R11, copyout_scalar

	// Load 4 consecutive state rows (each 32 bytes = [inst0, inst1, inst2, inst3])
	XVMOVQ (0*32)(R4), X0   // R0 = [a0, b0, c0, d0]
	XVMOVQ (1*32)(R4), X1   // R1 = [a1, b1, c1, d1]
	XVMOVQ (2*32)(R4), X2   // R2 = [a2, b2, c2, d2]
	XVMOVQ (3*32)(R4), X3   // R3 = [a3, b3, c3, d3]

	// Step 1: XVILVLV/H — produce column pairs
	// XVILVLV Xa, Xb, Xd: even (D[0],D[2]) from Xa, odd (D[1],D[3]) from Xb
	XVILVLV X0, X1, X4    // vk=X0=R0, vj=X1=R1 → X4 = [a0, a1, c0, c1]
	XVILVHV X0, X1, X5    // X5 = [b0, b1, d0, d1]
	XVILVLV X2, X3, X6    // vk=X2=R2, vj=X3=R3 → X6 = [a2, a3, c2, c3]
	XVILVHV X2, X3, X7    // X7 = [b2, b3, d2, d3]

	// Step 2: XVPERMIQ — combine into full columns (same WORD encodings as xorIn4)
	// out0 = A = [a0,a1,a2,a3] = X4.lo | X6.lo
	XVORV X4, X4, X0
	XVPERMIQ(0, 6, 0x02)    // xvpermi.q X0, X6, 0x02 → X0=[a0,a1,a2,a3]=A
	// out2 = C = [c0,c1,c2,c3] = X4.hi | X6.hi
	XVPERMIQ(4, 6, 0x13)    // xvpermi.q X4, X6, 0x13 → X4=[c0,c1,c2,c3]=C
	// out1 = B = [b0,b1,b2,b3] = X5.lo | X7.lo
	XVORV X5, X5, X1
	XVPERMIQ(1, 7, 0x02)    // xvpermi.q X1, X7, 0x02 → X1=[b0,b1,b2,b3]=B
	// out3 = D = [d0,d1,d2,d3] = X5.hi | X7.hi
	XVPERMIQ(5, 7, 0x13)    // xvpermi.q X5, X7, 0x13 → X5=[d0,d1,d2,d3]=D

	// Store columns to output buffers
	XVMOVQ X0, (R5)    // out0[i..i+3] = A
	XVMOVQ X1, (R6)    // out1[i..i+3] = B
	XVMOVQ X4, (R7)    // out2[i..i+3] = C
	XVMOVQ X5, (R8)    // out3[i..i+3] = D

	ADDV $128, R4
	ADDV $32, R5
	ADDV $32, R6
	ADDV $32, R7
	ADDV $32, R8
	ADDV $-4, R9
	JMP copyout_vec4

copyout_scalar:
	// Scalar tail: 0..3 remaining lanes
	BEQ R9, R0, copyout_done
	MOVV (R4), R11
	MOVV 8(R4), R12
	MOVV 16(R4), R13
	MOVV 24(R4), R14
	MOVV R11, (R5)
	MOVV R12, (R6)
	MOVV R13, (R7)
	MOVV R14, (R8)
	ADDV $32, R4
	ADDV $8, R5
	ADDV $8, R6
	ADDV $8, R7
	ADDV $8, R8
	ADDV $-1, R9
	JMP copyout_scalar

copyout_done:
	RET
