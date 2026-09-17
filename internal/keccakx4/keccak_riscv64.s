// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && go1.27 && !purego

#include "textflag.h"

// Stack layout:
//
//       0(X2) ..   7(X2): reserved, must not be overwritten
//       8(X2) .. 807(X2): temporary State4
//
// X10 = original state
// X11 = scratch state, X2 + 8
// X12 = round constant address
// X13 = one
// X14 = rotation amount
// X15 = round constant
// X16 = temporary lane address

#define RSP X2

#define C0 V0
#define C1 V2
#define C2 V4
#define C3 V6
#define C4 V8

#define B0 V0
#define B1 V2
#define B2 V4
#define B3 V6
#define B4 V8

#define D0 V10
#define D1 V12
#define D2 V14
#define D3 V16
#define D4 V18

#define TMP V20

#define LOAD_LANE(BASE, LANE, DST) \
	ADD $((LANE)*32), BASE, X16; \
	VLE64V (X16), DST

#define STORE_LANE(BASE, LANE, SRC) \
	ADD $((LANE)*32), BASE, X16; \
	VSE64V SRC, (X16)

// C[x] = A[x,0] XOR A[x,1] XOR A[x,2] XOR A[x,3] XOR A[x,4]
#define COMPUTE_C(SRC, CX, X) \
	LOAD_LANE(SRC, ((X)+0), CX); \
	LOAD_LANE(SRC, ((X)+5), TMP); \
	VXORVV TMP, CX, CX; \
	LOAD_LANE(SRC, ((X)+10), TMP); \
	VXORVV TMP, CX, CX; \
	LOAD_LANE(SRC, ((X)+15), TMP); \
	VXORVV TMP, CX, CX; \
	LOAD_LANE(SRC, ((X)+20), TMP); \
	VXORVV TMP, CX, CX

// D[x] = C[x-1] XOR ROL64(C[x+1], 1)
//
// X13 must contain 1.
#define COMPUTE_D(DST, CPREV, CNEXT) \
	VROLVX X13, CNEXT, DST; \
	VXORVV CPREV, DST, DST

// Fused theta + rho + pi for rotation zero.
//
// DST = state[LANE] XOR D[column]
#define LOAD_B_ZERO(SRC, DSTREG, LANE, DX) \
	LOAD_LANE(SRC, LANE, DSTREG); \
	VXORVV DX, DSTREG, DSTREG

// Fused theta + rho + pi.
//
// DST = ROL64(state[LANE] XOR D[column], ROT)
//
// Pi is implemented by selecting which B register receives the
// source lane. No vector gather is required.
#define LOAD_B_ROT(SRC, DSTREG, LANE, DX, ROT) \
	LOAD_LANE(SRC, LANE, DSTREG); \
	VXORVV DX, DSTREG, DSTREG; \
	MOV $ROT, X14; \
	VROLVX X14, DSTREG, DSTREG

// Keccak chi:
//
//     result = A XOR ((NOT B) AND C)
//
// RISC-V VANDN.VV semantics:
//
//     vd = vs2 & ~vs1
//
// Therefore:
//
//     VANDNVV B, C, TMP
//
// calculates:
//
//     TMP = C & ~B
//
// The original B0..B4 registers are not modified.
#define CHI_STORE(DST, A, B, C, LANE) \
	VANDNVV B, C, TMP; \
	VXORVV A, TMP, TMP; \
	STORE_LANE(DST, LANE, TMP)

// Chi followed by iota.
//
// X15 contains the round constant.
#define CHI_IOTA_STORE(DST, A, B, C, LANE) \
	VANDNVV B, C, TMP; \
	VXORVV A, TMP, TMP; \
	VXORVX X15, TMP, TMP; \
	STORE_LANE(DST, LANE, TMP)

// One complete Keccak-f[1600] round.
//
// SRC and DST must point to distinct State4 buffers.
#define KECCAK_ROUND(SRC, DST, idx) \
	/* Load RC before vector computation. */ \
	MOV ((idx)*8)(X12), X15; \
	/* theta: calculate the five column parities. */ \
	COMPUTE_C(SRC, C0, 0); \
	COMPUTE_C(SRC, C1, 1); \
	COMPUTE_C(SRC, C2, 2); \
	COMPUTE_C(SRC, C3, 3); \
	COMPUTE_C(SRC, C4, 4); \
	/* theta: calculate D0..D4 in vector registers. */ \
	COMPUTE_D(D0, C4, C1); \
	COMPUTE_D(D1, C0, C2); \
	COMPUTE_D(D2, C1, C3); \
	COMPUTE_D(D3, C2, C4); \
	COMPUTE_D(D4, C3, C0); \
	/* Output row 0. */ \
	/* B[0,0] = ROL(A[0,0] XOR D0,  0) */ \
	/* B[1,0] = ROL(A[1,1] XOR D1, 44) */ \
	/* B[2,0] = ROL(A[2,2] XOR D2, 43) */ \
	/* B[3,0] = ROL(A[3,3] XOR D3, 21) */ \
	/* B[4,0] = ROL(A[4,4] XOR D4, 14) */ \
	LOAD_B_ZERO(SRC, B0,  0, D0); \
	LOAD_B_ROT(SRC, B1,  6, D1, 44); \
	LOAD_B_ROT(SRC, B2, 12, D2, 43); \
	LOAD_B_ROT(SRC, B3, 18, D3, 21); \
	LOAD_B_ROT(SRC, B4, 24, D4, 14); \
	CHI_IOTA_STORE(DST, B0, B1, B2, 0); \
	CHI_STORE(DST, B1, B2, B3, 1); \
	CHI_STORE(DST, B2, B3, B4, 2); \
	CHI_STORE(DST, B3, B4, B0, 3); \
	CHI_STORE(DST, B4, B0, B1, 4); \
	/* Output row 1. */ \
	/* B[0,1] = ROL(A[3,0] XOR D3, 28) */ \
	/* B[1,1] = ROL(A[4,1] XOR D4, 20) */ \
	/* B[2,1] = ROL(A[0,2] XOR D0,  3) */ \
	/* B[3,1] = ROL(A[1,3] XOR D1, 45) */ \
	/* B[4,1] = ROL(A[2,4] XOR D2, 61) */ \
	LOAD_B_ROT(SRC, B0,  3, D3, 28); \
	LOAD_B_ROT(SRC, B1,  9, D4, 20); \
	LOAD_B_ROT(SRC, B2, 10, D0,  3); \
	LOAD_B_ROT(SRC, B3, 16, D1, 45); \
	LOAD_B_ROT(SRC, B4, 22, D2, 61); \
	CHI_STORE(DST, B0, B1, B2, 5); \
	CHI_STORE(DST, B1, B2, B3, 6); \
	CHI_STORE(DST, B2, B3, B4, 7); \
	CHI_STORE(DST, B3, B4, B0, 8); \
	CHI_STORE(DST, B4, B0, B1, 9); \
	/* Output row 2. */ \
	/* B[0,2] = ROL(A[1,0] XOR D1,  1) */ \
	/* B[1,2] = ROL(A[2,1] XOR D2,  6) */ \
	/* B[2,2] = ROL(A[3,2] XOR D3, 25) */ \
	/* B[3,2] = ROL(A[4,3] XOR D4,  8) */ \
	/* B[4,2] = ROL(A[0,4] XOR D0, 18) */ \
	LOAD_B_ROT(SRC, B0,  1, D1,  1); \
	LOAD_B_ROT(SRC, B1,  7, D2,  6); \
	LOAD_B_ROT(SRC, B2, 13, D3, 25); \
	LOAD_B_ROT(SRC, B3, 19, D4,  8); \
	LOAD_B_ROT(SRC, B4, 20, D0, 18); \
	CHI_STORE(DST, B0, B1, B2, 10); \
	CHI_STORE(DST, B1, B2, B3, 11); \
	CHI_STORE(DST, B2, B3, B4, 12); \
	CHI_STORE(DST, B3, B4, B0, 13); \
	CHI_STORE(DST, B4, B0, B1, 14); \
	/* Output row 3. */ \
	/* B[0,3] = ROL(A[4,0] XOR D4, 27) */ \
	/* B[1,3] = ROL(A[0,1] XOR D0, 36) */ \
	/* B[2,3] = ROL(A[1,2] XOR D1, 10) */ \
	/* B[3,3] = ROL(A[2,3] XOR D2, 15) */ \
	/* B[4,3] = ROL(A[3,4] XOR D3, 56) */ \
	LOAD_B_ROT(SRC, B0,  4, D4, 27); \
	LOAD_B_ROT(SRC, B1,  5, D0, 36); \
	LOAD_B_ROT(SRC, B2, 11, D1, 10); \
	LOAD_B_ROT(SRC, B3, 17, D2, 15); \
	LOAD_B_ROT(SRC, B4, 23, D3, 56); \
	CHI_STORE(DST, B0, B1, B2, 15); \
	CHI_STORE(DST, B1, B2, B3, 16); \
	CHI_STORE(DST, B2, B3, B4, 17); \
	CHI_STORE(DST, B3, B4, B0, 18); \
	CHI_STORE(DST, B4, B0, B1, 19); \
	/* Output row 4. */ \
	/* B[0,4] = ROL(A[2,0] XOR D2, 62) */ \
	/* B[1,4] = ROL(A[3,1] XOR D3, 55) */ \
	/* B[2,4] = ROL(A[4,2] XOR D4, 39) */ \
	/* B[3,4] = ROL(A[0,3] XOR D0, 41) */ \
	/* B[4,4] = ROL(A[1,4] XOR D1,  2) */ \
	LOAD_B_ROT(SRC, B0,  2, D2, 62); \
	LOAD_B_ROT(SRC, B1,  8, D3, 55); \
	LOAD_B_ROT(SRC, B2, 14, D4, 39); \
	LOAD_B_ROT(SRC, B3, 15, D0, 41); \
	LOAD_B_ROT(SRC, B4, 21, D1,  2); \
	CHI_STORE(DST, B0, B1, B2, 20); \
	CHI_STORE(DST, B1, B2, B3, 21); \
	CHI_STORE(DST, B2, B3, B4, 22); \
	CHI_STORE(DST, B3, B4, B0, 23); \
	CHI_STORE(DST, B4, B0, B1, 24)

// Two-round ping-pong.
//
// After the pair, the result is always back in STATE.
#define KECCAK_2ROUNDS(STATE, SCRATCH, idx) \
	KECCAK_ROUND(STATE, SCRATCH, idx); \
	KECCAK_ROUND(SCRATCH, STATE, (idx+1))

// func permute4RVV128(state *State4)
TEXT ·permute4RVV128(SB), 0, $808-8
	MOV state+0(FP), X10

	MOV ·roundConstants(SB), X12
	MOV $1, X13
	// The first 8 bytes of the RISCV64 local stack frame must not
	// be used as scratch storage.
	//
	// Usable 800-byte State4 scratch:
	//
	//     8(RSP) .. 807(RSP)
	ADD $8, RSP, X11

	VSETIVLI $4, E64, M2, TA, MA, X0

	KECCAK_2ROUNDS(X10, X11, 0)
	KECCAK_2ROUNDS(X10, X11, 2)
	KECCAK_2ROUNDS(X10, X11, 4)
	KECCAK_2ROUNDS(X10, X11, 6)

	KECCAK_2ROUNDS(X10, X11, 8)
	KECCAK_2ROUNDS(X10, X11, 10)
	KECCAK_2ROUNDS(X10, X11, 12)
	KECCAK_2ROUNDS(X10, X11, 14)

	KECCAK_2ROUNDS(X10, X11, 16)
	KECCAK_2ROUNDS(X10, X11, 18)
	KECCAK_2ROUNDS(X10, X11, 20)
	KECCAK_2ROUNDS(X10, X11, 22)

	RET

// Scalar register allocation:
//
// X10 = state pointer
// X11 = stream 0 pointer
// X12 = stream 1 pointer
// X13 = stream 2 pointer
// X14 = stream 3 pointer
// X15 = remaining lanes
// X16 = current VL
// X17 = state instance pointer
// X18 = state stride, 32 bytes
// X19 = byte advance for streams, VL*8
// X20 = state byte advance, VL*32
//
// Vector registers:
//
// V0:V1 = input/output data
// V2:V3 = current state data

// func xorIn4RVV(state *State4, in0, in1, in2, in3 *byte, lanes int)
TEXT ·xorIn4RVV(SB), NOSPLIT, $0-48
	MOV state+0(FP), X10
	MOV in0+8(FP), X11
	MOV in1+16(FP), X12
	MOV in2+24(FP), X13
	MOV in3+32(FP), X14
	MOV lanes+40(FP), X15

	MOV $32, X18

xorin_loop:
	BEQ X15, X0, xorin_done

	// VL = min(remaining, VLMAX).
	//
	// With VLEN=128, SEW=64 and LMUL=2:
	//
	//     VLMAX = 4
	VSETVLI X15, E64, M2, TA, MA, X16

	// Advance amounts for this iteration.
	SLL $3, X16, X19        // streamAdvance = VL * 8
	SLL $5, X16, X20        // stateAdvance  = VL * 32

	// ------------------------------------------------------------
	// Instance 0
	//
	// Input is unit-stride:
	//
	//     in0[currentLane : currentLane+VL]
	//
	// State is strided:
	//
	//     state[currentLane*4+0]
	//     state[(currentLane+1)*4+0]
	//     ...
	// ------------------------------------------------------------

	VLE64V  (X11), V0

	MOV X10, X17
	VLSE64V (X17), X18, V2

	VXORVV V2, V0, V0
	VSSE64V V0, X18, (X17)

	// Instance 1 starts 8 bytes after instance 0.

	ADD $8, X10, X17

	VLE64V  (X12), V0
	VLSE64V (X17), X18, V2

	VXORVV V2, V0, V0
	VSSE64V V0, X18, (X17)

	// Instance 2.

	ADD $16, X10, X17

	VLE64V  (X13), V0
	VLSE64V (X17), X18, V2

	VXORVV V2, V0, V0
	VSSE64V V0, X18, (X17)

	// Instance 3.

	ADD $24, X10, X17

	VLE64V  (X14), V0
	VLSE64V (X17), X18, V2

	VXORVV V2, V0, V0
	VSSE64V V0, X18, (X17)

	// Advance the four unit-stride input streams by VL*8.

	ADD X19, X11, X11
	ADD X19, X12, X12
	ADD X19, X13, X13
	ADD X19, X14, X14

	// Advance state by VL lanes, each lane being 32 bytes.

	ADD X20, X10, X10

	SUB X16, X15, X15
	JMP xorin_loop

xorin_done:
	RET

// func copyOut4RVV(state *State4, out0, out1, out2, out3 *byte, lanes int)
TEXT ·copyOut4RVV(SB), NOSPLIT, $0-48
	MOV state+0(FP), X10
	MOV out0+8(FP), X11
	MOV out1+16(FP), X12
	MOV out2+24(FP), X13
	MOV out3+32(FP), X14
	MOV lanes+40(FP), X15

	MOV $32, X18

copyout_loop:
	BEQ X15, X0, copyout_done

	// VL = min(remaining, VLMAX).
	VSETVLI X15, E64, M2, TA, MA, X16

	SLL $3, X16, X19        // outputAdvance = VL * 8
	SLL $5, X16, X20        // stateAdvance  = VL * 32

	// Instance 0:
	//
	// Strided load from the interleaved State4, followed by a
	// unit-stride store into the corresponding output stream.

	MOV X10, X17
	VLSE64V (X17), X18, V0
	VSE64V  V0, (X11)

	// Instance 1.

	ADD $8, X10, X17
	VLSE64V (X17), X18, V0
	VSE64V  V0, (X12)

	// Instance 2.

	ADD $16, X10, X17
	VLSE64V (X17), X18, V0
	VSE64V  V0, (X13)

	// Instance 3.

	ADD $24, X10, X17
	VLSE64V (X17), X18, V0
	VSE64V  V0, (X14)

	ADD X19, X11, X11
	ADD X19, X12, X12
	ADD X19, X13, X13
	ADD X19, X14, X14

	ADD X20, X10, X10

	SUB X16, X15, X15
	JMP copyout_loop

copyout_done:
	RET
