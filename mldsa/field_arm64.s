// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// nttMulNEON computes out[i] = fieldMul(lhs[i], rhs[i]) for i in [0, 255].
TEXT ·nttMulNEON(SB), NOSPLIT, $0-24
	MOVD lhs+0(FP), R0
	MOVD rhs+8(FP), R1
	MOVD out+16(FP), R2

	// pinned
	MOVD $8380417, R8
	VDUP R8, V31.S4
	MOVD $4236238847, R8
	VDUP R8, V30.S4
	MOVD $32, R4

loop:
	VLD1.P (32)(R0), [V0.S4, V1.S4]   // lhs
	VLD1.P (32)(R1), [V2.S4, V3.S4]   // rhs

	// step 1: V0 * V2
	WORD $0x4ea29c14                  // MUL   V20.4S, V0.4S, V2.4S
	WORD $0x4ebe9e96                  // MUL   V22.4S, V20.4S, V30.4S
	WORD $0x6ea2b415                  // SQRDMULH V21.4S, V0.4S, V2.4S (hi' = Round(2*hi))
	WORD $0x6ebfb6d7                  // SQRDMULH V23.4S, V22.4S, V31.4S (corr' = Round(2*corr))
	VADD V21.S4, V23.S4, V20.S4       // raw = 2*Result
	WORD $0x4f3f0694                  // VSSHR V20.S4, V20.S4, #1
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VAND V31.B16, V24.B16, V24.B16    // q if underflow, else 0
	VADD V20.S4, V24.S4, V4.S4        // result in V4

	// step 1: V1 * V3
	WORD $0x4ea39c34                  // MUL   V20.4S, V1.4S, V3.4S
	WORD $0x4ebe9e96                  // MUL   V22.4S, V20.4S, V30.4S
	WORD $0x6ea3b435                  // SQRDMULH V21.4S, V1.4S, V3.4S (hi' = Round(2*hi))
	WORD $0x6ebfb6d7                  // SQRDMULH V23.4S, V22.4S, V31.4S (corr' = Round(2*corr))
	VADD V21.S4, V23.S4, V20.S4       // raw = 2*Result
	WORD $0x4f3f0694                  // VSSHR V20.S4, V20.S4, #1
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VAND V31.B16, V24.B16, V24.B16    // q if underflow, else 0
	VADD V20.S4, V24.S4, V5.S4        // result in V5

	VST1.P [V4.S4, V5.S4], (32)(R2)
	SUBS $1, R4, R4
	BNE loop

done:
	RET

// nttMulAccNEON computes out[i] = fieldAdd(out[i], fieldMul(lhs[i], rhs[i])) for i in [0, 255].
TEXT ·nttMulAccNEON(SB), NOSPLIT, $0-24
	MOVD lhs+0(FP), R0
	MOVD rhs+8(FP), R1
	MOVD out+16(FP), R2
	MOVD $32, R3

	// pinned
	MOVD $8380417, R8
	VDUP R8, V31.S4
	MOVD $4236238847, R8
	VDUP R8, V30.S4
	MOVD $32, R4

loop:
	VLD1.P (32)(R0), [V0.S4, V1.S4]   // lhs
	VLD1.P (32)(R1), [V2.S4, V3.S4]   // rhs
	VLD1 (R2), [V4.S4, V5.S4]         // out (acc)

	// step 1: V0 * V2
	WORD $0x4ea29c14                  // MUL   V20.4S, V0.4S, V2.4S
	WORD $0x4ebe9e96                  // MUL   V22.4S, V20.4S, V30.4S
	WORD $0x6ea2b415                  // SQRDMULH V21.4S, V0.4S, V2.4S (hi' = Round(2*hi))
	WORD $0x6ebfb6d7                  // SQRDMULH V23.4S, V22.4S, V31.4S (corr' = Round(2*corr))
	VADD V21.S4, V23.S4, V20.S4       // raw = 2*Result
	WORD $0x4f3f0694                  // VSSHR V20.S4, V20.S4, #1
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VAND V31.B16, V24.B16, V24.B16    // q if underflow, else 0
	VADD V20.S4, V24.S4, V6.S4        // result in V6

	// step 1: V1 * V3
	WORD $0x4ea39c34                  // MUL   V20.4S, V1.4S, V3.4S
	WORD $0x4ebe9e96                  // MUL   V22.4S, V20.4S, V30.4S
	WORD $0x6ea3b435                  // SQRDMULH V21.4S, V1.4S, V3.4S (hi' = Round(2*hi))
	WORD $0x6ebfb6d7                  // SQRDMULH V23.4S, V22.4S, V31.4S (corr' = Round(2*corr))
	VADD V21.S4, V23.S4, V20.S4       // raw = 2*Result
	WORD $0x4f3f0694                  // VSSHR V20.S4, V20.S4, #1
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VAND V31.B16, V24.B16, V24.B16    // q if underflow, else 0
	VADD V20.S4, V24.S4, V7.S4        // result in V7

	// add acc
	VADD V6.S4, V4.S4, V4.S4          // acc + result in V4
	VADD V7.S4, V5.S4, V5.S4          // acc + result in V5

	// final reduction
	VSUB V31.S4, V4.S4, V20.S4
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VAND V31.B16, V24.B16, V24.B16    // q if underflow, else 0
	VADD V20.S4, V24.S4, V4.S4        // result in V4
	
	VSUB V31.S4, V5.S4, V20.S4
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VAND V31.B16, V24.B16, V24.B16    // q if underflow, else 0
	VADD V20.S4, V24.S4, V5.S4        // result in V5

	VST1.P [V4.S4, V5.S4], (32)(R2)
	SUBS $1, R4, R4
	BNE loop

done:
	RET

// Corrected fieldReduceOnce (input in [0,2q), output in [0,q)):
//   try = Vx - q; if try < 0: Vx stays; else Vx = try
// Inlined version of the sequence. V20,V24 is clobbered.
#define REDUCE_ONCE(VX) \
	VSUB V31.S4, VX.S4, V20.S4        \
	WORD $0x4f210698                  \
	VAND V31.B16, V24.B16, V24.B16    \
	VADD V20.S4, V24.S4, VX.S4        // result in VX

#define DBL_MONT_MUL_FIXED(VOUT) \
	WORD $0x4ea19c14                        \ // MUL   V20.4S, V0.4S, V1.4S
	WORD $0x4ebe9e96                        \ // MUL   V22.4S, V20.4S, V30.4S
	WORD $0x6ea1b415                        \ // SQRDMULH V21.4S, V0.4S, V1.4S (hi' = Round(2*hi))
	WORD $0x6ebfb6d7                        \ // SQRDMULH V23.4S, V22.4S, V31.4S (corr' = Round(2*corr))
	VADD V21.S4, V23.S4, V20.S4             \ // raw = 2*Result
	WORD $0x4f3f0694                        \ // VSSHR V20.S4, V20.S4, #1
	WORD $0x4f210698                        \ // VSSHR V24.S4, V20.S4, #31
	VAND V31.B16, V24.B16, V24.B16          \ // q if underflow, else 0
	VADD V20.S4, V24.S4, VOUT.S4              // result in VOUT

#define MONT_MUL(VA, VZ, VOUT) \
	VMOV   VA.B16, V0.B16                    \
	VMOV   VZ.B16, V1.B16                    \
	DBL_MONT_MUL_FIXED(VOUT)

// Fast-path when inputs are already in fixed MONT_MUL registers.
#define MONT_MUL_V0_V1(VOUT) \
	DBL_MONT_MUL_FIXED(VOUT)

// Fast-path when multiplicand is already in V0; only load the zeta/input into V1.
#define MONT_MUL_V0_VZ(VZ, VOUT) \
	VMOV   VZ.B16, V1.B16                    \
	DBL_MONT_MUL_FIXED(VOUT)

// Cooley-Tukey butterfly:
//   t  = MontMul(zeta, odd)
//   odd  = fieldSub(even_old, t)
//   even = fieldAdd(even_old, t)
// Clobbers V0,V1,V20,V24,V25,V26.
#define BUTTERFLY(VA, VB, VZ) \
	VMOV   VA.B16, V25.B16            \
	MONT_MUL(VB, VZ, V26)             \
	VADD   V25.S4, V26.S4, VA.S4      \
	REDUCE_ONCE(VA)                   \
	VSUB   V26.S4, V25.S4, V20.S4     \
	WORD   $0x4f210698                \
	VAND   V31.B16, V24.B16, V24.B16  \
	VADD   V20.S4, V24.S4, VB.S4

#define BUTTERFLY01(VZ) \
	VMOV   V0.B16, V25.B16            \
	VMOV   VZ.B16, V0.B16             \
	MONT_MUL_V0_V1(V26)               \
	VADD   V25.S4, V26.S4, V0.S4      \
	REDUCE_ONCE(V0)                   \
	VSUB   V26.S4, V25.S4, V20.S4     \
	WORD   $0x4f210698                \
	VAND   V31.B16, V24.B16, V24.B16  \
	VADD   V20.S4, V24.S4, V1.S4

// internalNTTNEON implements the same algorithm as internalNTTGeneric.
// L0-L5 are vectorized (4 lanes of uint32); L6-L7 are scalar for correctness-first bring-up.
TEXT ·internalNTTNEON(SB), NOSPLIT, $0-8
	MOVD f+0(FP), R0

	MOVD $·zetasMontgomery(SB), R1
	ADD $4, R1, R1 // point to zetasMontgomery[1]

	// pinned constants
	MOVD $8380417, R8
	VDUP R8, V31.S4
	MOVD $4236238847, R8
	VDUP R8, V30.S4


	// L0: len=128, one zeta, 32 vector butterflies.
	MOVWU.P 4(R1), R10
	VDUP R10, V7.S4
	MOVD R0, R11
	ADD $512, R11, R12
	MOVD $32, R4
ntt_l0_loop:
	VLD1 (R11), [V0.S4]
	VLD1 (R12), [V1.S4]
	BUTTERFLY01(V7)
	VST1.P [V0.S4], (16)(R11)
	VST1.P [V1.S4], (16)(R12)
	SUBS $1, R4, R4
	BNE ntt_l0_loop

	// L1: len=64, two groups, each 16 vector butterflies.
	MOVD $2, R5
	MOVD R0, R6
ntt_l1_group:
	MOVWU.P 4(R1), R10
	VDUP R10, V7.S4
	MOVD R6, R11
	ADD $256, R11, R12
	MOVD $16, R4
ntt_l1_loop:
	VLD1 (R11), [V0.S4]
	VLD1 (R12), [V1.S4]
	BUTTERFLY01(V7)
	VST1.P [V0.S4], (16)(R11)
	VST1.P [V1.S4], (16)(R12)
	SUBS $1, R4, R4
	BNE ntt_l1_loop
	ADD $512, R6, R6
	SUBS $1, R5, R5
	BNE ntt_l1_group

	// L2: len=32, four groups, each 8 vector butterflies.
	MOVD $4, R5
	MOVD R0, R6
ntt_l2_group:
	MOVWU.P 4(R1), R10
	VDUP R10, V7.S4
	MOVD R6, R11
	ADD $128, R11, R12
	MOVD $8, R4
ntt_l2_loop:
	VLD1 (R11), [V0.S4]
	VLD1 (R12), [V1.S4]
	BUTTERFLY01(V7)
	VST1.P [V0.S4], (16)(R11)
	VST1.P [V1.S4], (16)(R12)
	SUBS $1, R4, R4
	BNE ntt_l2_loop
	ADD $256, R6, R6
	SUBS $1, R5, R5
	BNE ntt_l2_group

	// L3: len=16, eight groups, each 4 vector butterflies.
	MOVD $8, R5
	MOVD R0, R6
ntt_l3_group:
	MOVWU.P 4(R1), R10
	VDUP R10, V7.S4
	MOVD R6, R11
	ADD $64, R11, R12
	MOVD $4, R4
ntt_l3_loop:
	VLD1 (R11), [V0.S4]
	VLD1 (R12), [V1.S4]
	BUTTERFLY01(V7)
	VST1.P [V0.S4], (16)(R11)
	VST1.P [V1.S4], (16)(R12)
	SUBS $1, R4, R4
	BNE ntt_l3_loop
	ADD $128, R6, R6
	SUBS $1, R5, R5
	BNE ntt_l3_group

	// L4: len=8, 16 groups, each 2 vector butterflies.
	MOVD $16, R5
	MOVD R0, R6
ntt_l4_group:
	MOVWU.P 4(R1), R10
	VDUP R10, V7.S4
	MOVD R6, R11
	ADD $32, R11, R12
	MOVD $2, R4
ntt_l4_loop:
	VLD1 (R11), [V0.S4]
	VLD1 (R12), [V1.S4]
	BUTTERFLY01(V7)
	VST1.P [V0.S4], (16)(R11)
	VST1.P [V1.S4], (16)(R12)
	SUBS $1, R4, R4
	BNE ntt_l4_loop
	ADD $64, R6, R6
	SUBS $1, R5, R5
	BNE ntt_l4_group

	// L5: len=4, 32 groups, each 1 vector butterfly.
	MOVD $32, R5
	MOVD R0, R6
ntt_l5_group:
	MOVWU.P 4(R1), R10
	VDUP R10, V7.S4
	MOVD R6, R11
	ADD $16, R11, R12
	VLD1 (R11), [V0.S4]
	VLD1 (R12), [V1.S4]
	BUTTERFLY01(V7)
	VST1 [V0.S4], (R11)
	VST1 [V1.S4], (R12)
	ADD $32, R6, R6
	SUBS $1, R5, R5
	BNE ntt_l5_group

	// L6: len=2. Two groups packed per vector butterfly.
	MOVD $32, R5
	MOVD R0, R6
ntt_l6_group:
	MOVD.P 8(R1), R10
	VDUP R10, V7.D2
	VZIP1 V7.S4, V7.S4, V7.S4 // [z0 z0 z1 z1]

	VLD1 (R6), [V20.S4, V21.S4]
	VZIP1 V21.D2, V20.D2, V0.D2 // even: [e0 e1 e2 e3]
	VZIP2 V21.D2, V20.D2, V1.D2 // odd:  [o0 o1 o2 o3]
	BUTTERFLY01(V7)
	VZIP1 V1.D2, V0.D2, V20.D2
	VZIP2 V1.D2, V0.D2, V21.D2
	VST1.P [V20.S4, V21.S4], 32(R6)

	SUBS $1, R5, R5
	BNE ntt_l6_group

	// L7: len=1. Four groups packed per vector butterfly.
	MOVD $32, R5
	MOVD R0, R6
ntt_l7_group:
	VLD1.P (16)(R1), [V7.S4]         // [z0 z1 z2 z3]
	VLD1 (R6), [V20.S4, V21.S4]      // [e0 o0 e1 o1 | e2 o2 e3 o3]
	VUZP1 V21.S4, V20.S4, V0.S4      // even: [e0 e1 e2 e3]
	VUZP2 V21.S4, V20.S4, V1.S4      // odd:  [o0 o1 o2 o3]
	BUTTERFLY01(V7)
	VZIP1 V1.S4, V0.S4, V20.S4
	VZIP2 V1.S4, V0.S4, V21.S4
	VST1.P [V20.S4, V21.S4], 32(R6)

	SUBS $1, R5, R5
	BNE ntt_l7_group

	RET

	