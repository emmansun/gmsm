// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

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

// polyAddAssignNEON updates dst[i] = fieldAdd(dst[i], src[i]) for i in [0, 255].
TEXT ·polyAddAssignNEON(SB), NOSPLIT, $0-16
	MOVD dst+0(FP), R0
	MOVD src+8(FP), R1

	MOVD $8380417, R8
	VDUP R8, V31.S4
	MOVD $64, R4

poly_add_assign_loop:
	VLD1 (R0), [V0.S4]
	VLD1.P (16)(R1), [V1.S4]
	VADD V1.S4, V0.S4, V0.S4
	REDUCE_ONCE(V0)
	VST1.P [V0.S4], (16)(R0)
	SUBS $1, R4, R4
	BNE poly_add_assign_loop
	RET

// polySubAssignNEON updates dst[i] = fieldSub(dst[i], src[i]) for i in [0, 255].
TEXT ·polySubAssignNEON(SB), NOSPLIT, $0-16
	MOVD dst+0(FP), R0
	MOVD src+8(FP), R1

	MOVD $8380417, R8
	VDUP R8, V31.S4
	MOVD $64, R4

poly_sub_assign_loop:
	VLD1 (R0), [V0.S4]
	VLD1.P (16)(R1), [V1.S4]
	VSUB V1.S4, V0.S4, V0.S4
	VADD V31.S4, V0.S4, V0.S4
	REDUCE_ONCE(V0)
	VST1.P [V0.S4], (16)(R0)
	SUBS $1, R4, R4
	BNE poly_sub_assign_loop
	RET

// polyInfinityNormNEON returns max(infinityNorm(a[i])) for i in [0, 255].
TEXT ·polyInfinityNormNEON(SB), NOSPLIT, $0-16
	MOVD a+0(FP), R0
	MOVD $0, R9

	MOVD $8380417, R8
	VDUP R8, V31.S4
	MOVD $4190208, R8 // (q-1)/2
	VDUP R8, V29.S4
	MOVD $64, R4
	VEOR V27.B16, V27.B16, V27.B16 // running max

poly_inf_norm_loop:
	VLD1.P (16)(R0), [V0.S4]
	VSUB V0.S4, V31.S4, V1.S4
	VUMIN V1.S4, V0.S4, V0.S4
	VUMAX V0.S4, V27.S4, V27.S4

	SUBS $1, R4, R4
	BNE poly_inf_norm_loop

	// Extract each lane and compare with running max
	VMOV V27.S[0], R10
	CMPW R9, R10
	CSEL CS, R10, R9, R9
	VMOV V27.S[1], R10
	CMPW R9, R10
	CSEL CS, R10, R9, R9
	VMOV V27.S[2], R10
	CMPW R9, R10
	CSEL CS, R10, R9, R9
	VMOV V27.S[3], R10
	CMPW R9, R10
	CSEL CS, R10, R9, R9

	MOVW R9, ret+8(FP)
	RET

// polyInfinityNormSignedNEON returns max(abs(a[i])) for i in [0, 255].
TEXT ·polyInfinityNormSignedNEON(SB), NOSPLIT, $0-16
	MOVD a+0(FP), R0
	MOVD $0, R9
	MOVD $64, R4
	VEOR V27.B16, V27.B16, V27.B16 // running max

poly_inf_norm_signed_loop:
	VLD1.P (16)(R0), [V20.S4]
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VEOR V24.B16, V20.B16, V21.B16
	VSUB V24.S4, V21.S4, V0.S4
	VUMAX V0.S4, V27.S4, V27.S4

	SUBS $1, R4, R4
	BNE poly_inf_norm_signed_loop

	// Extract each lane and compare with running max
	VMOV V27.S[0], R10
	CMPW R9, R10
	CSEL CS, R10, R9, R9
	VMOV V27.S[1], R10
	CMPW R9, R10
	CSEL CS, R10, R9, R9
	VMOV V27.S[2], R10
	CMPW R9, R10
	CSEL CS, R10, R9, R9
	VMOV V27.S[3], R10
	CMPW R9, R10
	CSEL CS, R10, R9, R9

	MOVW R9, ret+8(FP)
	RET

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

// Butterfly with zeta in V7, even in V0, odd in V1. Output in V0 (even) and V1 (odd).
// Clobbers V20,V21,V22,V23,V24.
#define BUTTERFLY01_Z7                      \
	WORD $0x4ea19cf4                        \ // MUL   V20.4S, V7.4S, V1.4S
	WORD $0x4ebe9e96                        \ // MUL   V22.4S, V20.4S, V30.4S
	WORD $0x6ea1b4f5                        \ // SQRDMULH V21.4S, V7.4S, V1.4S (hi' = Round(2*hi))
	WORD $0x6ebfb6d7                        \ // SQRDMULH V23.4S, V22.4S, V31.4S (corr' = Round(2*corr))
	VADD V21.S4, V23.S4, V20.S4             \ // raw = 2*Result
	WORD $0x4f3f0694                        \ // VSSHR V20.S4, V20.S4, #1
	WORD $0x4f210698                        \ // VSSHR V24.S4, V20.S4, #31
	VAND V31.B16, V24.B16, V24.B16          \ // q if underflow, else 0
	VADD V20.S4, V24.S4, V21.S4             \ // t in V21
	\ // odd = even - t
	VSUB V21.S4, V0.S4, V20.S4              \ // odd in V20
	WORD $0x4f210698                        \ // VSSHR V24.S4, V20.S4, #31
	VAND V31.B16, V24.B16, V24.B16          \
	VADD V20.S4, V24.S4, V1.S4	            \
	\ // even = even + t
	VADD V21.S4, V0.S4, V0.S4               \
	REDUCE_ONCE(V0)

// Gentleman-Sande butterfly with zeta in V7, even in V0, odd in V1.
// Output in V0 (even') and V1 (odd').
//   even' = fieldReduceOnce(even + odd)
//   odd'  = MontMul(zeta, even - odd + q)
// Clobbers V20,V21,V22,V23,V24,V25,V26.
#define INVERSE_BUTTERFLY01_Z7              \
	VMOV V0.B16, V25.B16                    \
	VADD V1.S4, V0.S4, V0.S4                \
	REDUCE_ONCE(V0)                         \
	VSUB V1.S4, V25.S4, V1.S4               \
	VADD V31.S4, V1.S4, V1.S4               \
	WORD $0x4ea19cf4                        \ // MUL   V20.4S, V7.4S, V1.4S
	WORD $0x4ebe9e96                        \ // MUL   V22.4S, V20.4S, V30.4S
	WORD $0x6ea1b4f5                        \ // SQRDMULH V21.4S, V7.4S, V1.4S (hi' = Round(2*hi))
	WORD $0x6ebfb6d7                        \ // SQRDMULH V23.4S, V22.4S, V31.4S (corr' = Round(2*corr))
	VADD V21.S4, V23.S4, V20.S4             \ // raw = 2*Result
	WORD $0x4f3f0694                        \ // VSSHR V20.S4, V20.S4, #1
	WORD $0x4f210698                        \ // VSSHR V24.S4, V20.S4, #31
	VAND V31.B16, V24.B16, V24.B16          \ // q if underflow, else 0
	VADD V20.S4, V24.S4, V1.S4

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
	BUTTERFLY01_Z7
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
	BUTTERFLY01_Z7
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
	BUTTERFLY01_Z7
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
	BUTTERFLY01_Z7
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
	BUTTERFLY01_Z7
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
	VLD1 (R6), [V0.S4, V1.S4]
	BUTTERFLY01_Z7
	VST1.P [V0.S4, V1.S4], 32(R6)
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
	BUTTERFLY01_Z7
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
	BUTTERFLY01_Z7
	VZIP1 V1.S4, V0.S4, V20.S4
	VZIP2 V1.S4, V0.S4, V21.S4
	VST1.P [V20.S4, V21.S4], 32(R6)

	SUBS $1, R5, R5
	BNE ntt_l7_group

	RET

// internalInverseNTTNEON implements the same algorithm as internalInverseNTTGeneric.
// L0-L7 are vectorized.
TEXT ·internalInverseNTTNEON(SB), NOSPLIT, $0-8
	MOVD f+0(FP), R0

	// qMinusZetas pointer for L1-L7 starts at one-past qMinusZetasMontgomeryARM64[127].
	MOVD $·qMinusZetasMontgomeryARM64(SB), R1
	ADD $512, R1, R1

	// L0 uses pre-reordered qMinusZetas blocks: [q-z255 ... q-z128].
	MOVD $·qMinusZetasMontgomeryL0ReorderedARM64(SB), R13

	// pinned constants
	MOVD $8380417, R8
	VDUP R8, V31.S4
	MOVD $4236238847, R9
	VDUP R9, V30.S4

	// L0: len=1, 128 groups, four groups packed per vector butterfly.
	MOVD R0, R11
	MOVD $32, R4
intt_l0_group:
	VLD1.P (16)(R13), [V7.S4]

	VLD1 (R11), [V20.S4, V21.S4]      // [e0 o0 e1 o1 | e2 o2 e3 o3]
	VUZP1 V21.S4, V20.S4, V0.S4       // even: [e0 e1 e2 e3]
	VUZP2 V21.S4, V20.S4, V1.S4       // odd:  [o0 o1 o2 o3]
	INVERSE_BUTTERFLY01_Z7
	VZIP1 V1.S4, V0.S4, V20.S4
	VZIP2 V1.S4, V0.S4, V21.S4
	VST1.P [V20.S4, V21.S4], 32(R11)

	SUBS $1, R4, R4
	BNE intt_l0_group

	// L1: len=2, 64 groups, two groups packed per vector butterfly.
	MOVD R0, R6
	MOVD $32, R5
intt_l1_group:
	MOVWU.W -4(R1), R10
	MOVWU.W -4(R1), R12
	VDUP R10, V7.S4
	VDUP R12, V6.S4
	VUZP1 V6.S4, V7.S4, V7.S4         // [z0 z0 z1 z1]

	VLD1 (R6), [V20.S4, V21.S4]       // [a0 a1 b0 b1 | c0 c1 d0 d1]
	VZIP1 V21.D2, V20.D2, V0.D2       // even: [a0 a1 c0 c1]
	VZIP2 V21.D2, V20.D2, V1.D2       // odd:  [b0 b1 d0 d1]
	INVERSE_BUTTERFLY01_Z7
	VZIP1 V1.D2, V0.D2, V20.D2
	VZIP2 V1.D2, V0.D2, V21.D2
	VST1.P [V20.S4, V21.S4], 32(R6)

	SUBS $1, R5, R5
	BNE intt_l1_group

	// L2: len=4, 32 groups, one vector butterfly each.
	MOVD $32, R5
	MOVD R0, R6
intt_l2_group:
	MOVWU.W -4(R1), R10
	VDUP R10, V7.S4

	VLD1 (R6), [V0.S4, V1.S4]
	INVERSE_BUTTERFLY01_Z7
	VST1.P [V0.S4, V1.S4], 32(R6)

	SUBS $1, R5, R5
	BNE intt_l2_group

	// L3: len=8, 16 groups, two vector butterflies each.
	MOVD $16, R5
	MOVD R0, R6
intt_l3_group:
	MOVWU.W -4(R1), R10
	VDUP R10, V7.S4

	MOVD R6, R11
	ADD $32, R11, R12
	MOVD $2, R4
intt_l3_loop:
	VLD1 (R11), [V0.S4]
	VLD1 (R12), [V1.S4]
	INVERSE_BUTTERFLY01_Z7
	VST1.P [V0.S4], (16)(R11)
	VST1.P [V1.S4], (16)(R12)
	SUBS $1, R4, R4
	BNE intt_l3_loop

	ADD $64, R6, R6
	SUBS $1, R5, R5
	BNE intt_l3_group

	// L4: len=16, 8 groups, four vector butterflies each.
	MOVD $8, R5
	MOVD R0, R6
intt_l4_group:
	MOVWU.W -4(R1), R10
	VDUP R10, V7.S4

	MOVD R6, R11
	ADD $64, R11, R12
	MOVD $4, R4
intt_l4_loop:
	VLD1 (R11), [V0.S4]
	VLD1 (R12), [V1.S4]
	INVERSE_BUTTERFLY01_Z7
	VST1.P [V0.S4], (16)(R11)
	VST1.P [V1.S4], (16)(R12)
	SUBS $1, R4, R4
	BNE intt_l4_loop

	ADD $128, R6, R6
	SUBS $1, R5, R5
	BNE intt_l4_group

	// L5: len=32, 4 groups, eight vector butterflies each.
	MOVD $4, R5
	MOVD R0, R6
intt_l5_group:
	MOVWU.W -4(R1), R10
	VDUP R10, V7.S4

	MOVD R6, R11
	ADD $128, R11, R12
	MOVD $8, R4
intt_l5_loop:
	VLD1 (R11), [V0.S4]
	VLD1 (R12), [V1.S4]
	INVERSE_BUTTERFLY01_Z7
	VST1.P [V0.S4], (16)(R11)
	VST1.P [V1.S4], (16)(R12)
	SUBS $1, R4, R4
	BNE intt_l5_loop

	ADD $256, R6, R6
	SUBS $1, R5, R5
	BNE intt_l5_group

	// L6: len=64, 2 groups, sixteen vector butterflies each.
	MOVD $2, R5
	MOVD R0, R6
intt_l6_group:
	MOVWU.W -4(R1), R10
	VDUP R10, V7.S4

	MOVD R6, R11
	ADD $256, R11, R12
	MOVD $16, R4
intt_l6_loop:
	VLD1 (R11), [V0.S4]
	VLD1 (R12), [V1.S4]
	INVERSE_BUTTERFLY01_Z7
	VST1.P [V0.S4], (16)(R11)
	VST1.P [V1.S4], (16)(R12)
	SUBS $1, R4, R4
	BNE intt_l6_loop

	ADD $512, R6, R6
	SUBS $1, R5, R5
	BNE intt_l6_group

	// L7: len=128, 1 group, thirty-two vector butterflies.
	MOVWU.W -4(R1), R10
	VDUP R10, V7.S4

	MOVD R0, R11
	ADD $512, R11, R12
	MOVD $32, R4
intt_l7_loop:
	VLD1 (R11), [V0.S4]
	VLD1 (R12), [V1.S4]
	INVERSE_BUTTERFLY01_Z7
	VST1.P [V0.S4], (16)(R11)
	VST1.P [V1.S4], (16)(R12)
	SUBS $1, R4, R4
	BNE intt_l7_loop

	// Final scale by invDegreeMontgomery = 41978.
	MOVD $41978, R10
	VDUP R10, V7.S4
	MOVD R0, R11
	MOVD $32, R4
intt_scale_loop:
	VLD1 (R11), [V2.S4, V3.S4]
	MONT_MUL(V2, V7, V4)
	MONT_MUL(V3, V7, V5)
	VST1.P [V4.S4, V5.S4], 32(R11)
	SUBS $1, R4, R4
	BNE intt_scale_loop

	RET

// decomposeSubToR0Gamma32ARM64 computes decompose(fieldSub(w, cs2), gamma2QMinus1Div32).r0.
TEXT ·decomposeSubToR0Gamma32ARM64(SB), NOSPLIT, $0-24
	MOVD w+0(FP), R0
	MOVD cs2+8(FP), R1
	MOVD out+16(FP), R2
	MOVD $64, R3

	MOVD $8380417, R8
	VDUP R8, V31.S4
	MOVD $127, R8
	VDUP R8, V30.S4
	MOVD $1025, R8
	VDUP R8, V29.S4
	MOVD $2097152, R8
	VDUP R8, V28.S4
	MOVD $523776, R8
	VDUP R8, V27.S4
	MOVD $4190208, R8
	VDUP R8, V26.S4
	MOVD $15, R8
	VDUP R8, V25.S4

decompose_sub_to_r0_gamma32_loop:
	VLD1.P (16)(R0), [V0.S4]
	VLD1.P (16)(R1), [V1.S4]

	VADD V31.S4, V0.S4, V2.S4
	VSUB V1.S4, V2.S4, V2.S4
	REDUCE_ONCE(V2)

	VADD V30.S4, V2.S4, V3.S4
	VUSHR $7, V3.S4, V3.S4
	WORD $0x4ebd9c64                  // MUL   V4.4S, V3.4S, V29.4S
	VADD V28.S4, V4.S4, V4.S4
	VUSHR $22, V4.S4, V4.S4
	VAND V25.B16, V4.B16, V4.B16

	WORD $0x4ebb9c85                  // MUL   V5.4S, V4.4S, V27.4S
	VSUB V5.S4, V2.S4, V5.S4
	VSUB V5.S4, V26.S4, V20.S4
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VAND V31.B16, V24.B16, V24.B16
	VSUB V24.S4, V5.S4, V5.S4

	VST1.P [V5.S4], (16)(R2)
	SUBS $1, R3, R3
	BNE decompose_sub_to_r0_gamma32_loop
	RET

// decomposeSubToR0Gamma88ARM64 computes decompose(fieldSub(w, cs2), gamma2QMinus1Div88).r0.
TEXT ·decomposeSubToR0Gamma88ARM64(SB), NOSPLIT, $0-24
	MOVD w+0(FP), R0
	MOVD cs2+8(FP), R1
	MOVD out+16(FP), R2
	MOVD $64, R3

	MOVD $8380417, R8
	VDUP R8, V31.S4
	MOVD $127, R8
	VDUP R8, V30.S4
	MOVD $11275, R8
	VDUP R8, V29.S4
	MOVD $8388608, R8
	VDUP R8, V28.S4
	MOVD $190464, R8
	VDUP R8, V27.S4
	MOVD $4190208, R8
	VDUP R8, V26.S4
	MOVD $43, R8
	VDUP R8, V25.S4

decompose_sub_to_r0_gamma88_loop:
	VLD1.P (16)(R0), [V0.S4]
	VLD1.P (16)(R1), [V1.S4]

	VADD V31.S4, V0.S4, V2.S4
	VSUB V1.S4, V2.S4, V2.S4
	REDUCE_ONCE(V2)

	VADD V30.S4, V2.S4, V3.S4
	VUSHR $7, V3.S4, V3.S4
	WORD $0x4ebd9c64                  // MUL   V4.4S, V3.4S, V29.4S
	VADD V28.S4, V4.S4, V4.S4
	VUSHR $24, V4.S4, V4.S4

	VSUB V4.S4, V25.S4, V20.S4
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VAND V4.B16, V24.B16, V24.B16
	VEOR V24.B16, V4.B16, V4.B16

	WORD $0x4ebb9c85                  // MUL   V5.4S, V4.4S, V27.4S
	VSUB V5.S4, V2.S4, V5.S4
	VSUB V5.S4, V26.S4, V20.S4
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VAND V31.B16, V24.B16, V24.B16
	VSUB V24.S4, V5.S4, V5.S4

	VST1.P [V5.S4], (16)(R2)
	SUBS $1, R3, R3
	BNE decompose_sub_to_r0_gamma88_loop
	RET

// useHintPolyGamma32ARM64 applies useHint coefficient-wise with gamma2QMinus1Div32.
//
// Security note:
// This routine is used in verification where h is public input from the signature.
// The logic is data-dependent on h and r0 sign to implement UseHint semantics.
// Do not copy this style into secret-dependent signing code paths.
TEXT ·useHintPolyGamma32ARM64(SB), NOSPLIT, $0-24
	MOVD h+0(FP), R0
	MOVD r+8(FP), R1
	MOVD out+16(FP), R2
	MOVD $64, R3

	MOVD $8380417, R8
	VDUP R8, V31.S4
	MOVD $127, R8
	VDUP R8, V30.S4
	MOVD $1025, R8
	VDUP R8, V29.S4
	MOVD $2097152, R8
	VDUP R8, V28.S4
	MOVD $523776, R8
	VDUP R8, V27.S4
	MOVD $4190208, R8
	VDUP R8, V26.S4
	MOVD $15, R8
	VDUP R8, V25.S4
	MOVD $1, R8
	VDUP R8, V22.S4
	VEOR V23.B16, V23.B16, V23.B16

use_hint_poly_gamma32_loop:
	VLD1.P (16)(R0), [V0.S4]
	VLD1.P (16)(R1), [V1.S4]

	VADD V30.S4, V1.S4, V3.S4
	VUSHR $7, V3.S4, V3.S4
	WORD $0x4ebd9c64                  // MUL   V4.4S, V3.4S, V29.4S
	VADD V28.S4, V4.S4, V4.S4
	VUSHR $22, V4.S4, V4.S4
	VAND V25.B16, V4.B16, V4.B16

	// Fast path: if this 4-lane h block is all zero, output r1 directly.
	// This branch is safe here because h is public in verification.
	VMOV V0.S[0], R12
	VMOV V0.S[1], R13
	ORRW R13, R12, R12
	VMOV V0.S[2], R13
	ORRW R13, R12, R12
	VMOV V0.S[3], R13
	ORRW R13, R12, R12
	CBNZ R12, use_hint_poly_gamma32_nonzero
	VST1.P [V4.S4], (16)(R2)
	SUBS $1, R3, R3
	BNE use_hint_poly_gamma32_loop
	RET

use_hint_poly_gamma32_nonzero:

	WORD $0x4ebb9c85                  // MUL   V5.4S, V4.4S, V27.4S
	VSUB V5.S4, V1.S4, V5.S4
	VSUB V5.S4, V26.S4, V20.S4
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VAND V31.B16, V24.B16, V24.B16
	VSUB V24.S4, V5.S4, V5.S4

	VCMEQ V23.S4, V5.S4, V6.S4
	VMOV V5.B16, V20.B16
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VORR V24.B16, V6.B16, V6.B16

	VADD V22.S4, V4.S4, V7.S4
	VAND V25.B16, V7.B16, V7.B16
	VSUB V22.S4, V4.S4, V8.S4
	VAND V25.B16, V8.B16, V8.B16
	VBIT V6.B16, V8.B16, V7.B16

	VSUB V0.S4, V23.S4, V9.S4
	VBIT V9.B16, V7.B16, V4.B16

	VST1.P [V4.S4], (16)(R2)
	SUBS $1, R3, R3
	BNE use_hint_poly_gamma32_loop
	RET

// useHintPolyGamma88ARM64 applies useHint coefficient-wise with gamma2QMinus1Div88.
//
// Security note:
// This routine is used in verification where h is public input from the signature.
// The sparse-h fast path below is intentionally data-dependent on h to improve
// throughput for sparse hints. Do not reuse this pattern on secret-dependent paths.
TEXT ·useHintPolyGamma88ARM64(SB), NOSPLIT, $0-24
	MOVD h+0(FP), R0
	MOVD r+8(FP), R1
	MOVD out+16(FP), R2
	MOVD $16, R3

	MOVD $8380417, R8
	VDUP R8, V31.S4
	MOVD $127, R8
	VDUP R8, V30.S4
	MOVD $11275, R8
	VDUP R8, V29.S4
	MOVD $8388608, R8
	VDUP R8, V28.S4
	MOVD $190464, R8
	VDUP R8, V27.S4
	MOVD $4190208, R8
	VDUP R8, V26.S4
	MOVD $43, R8
	VDUP R8, V25.S4
	MOVD $44, R8
	VDUP R8, V19.S4
	MOVD $1, R8
	VDUP R8, V22.S4
	VEOR V23.B16, V23.B16, V23.B16

use_hint_poly_gamma88_loop:
	VLD1.P (16)(R0), [V0.S4]
	VLD1.P (16)(R1), [V1.S4]

	VADD V30.S4, V1.S4, V3.S4
	VUSHR $7, V3.S4, V3.S4
	WORD $0x4ebd9c64                  // MUL   V4.4S, V3.4S, V29.4S
	VADD V28.S4, V4.S4, V4.S4
	VUSHR $24, V4.S4, V4.S4

	VCMEQ V19.S4, V4.S4, V8.S4
	VBIT V8.B16, V23.B16, V4.B16

	// Fast path: if this 4-lane h block is all zero, output r1 directly.
	// This branch is safe here because h is public in verification.
	VMOV V0.S[0], R12
	VMOV V0.S[1], R13
	ORRW R13, R12, R12
	VMOV V0.S[2], R13
	ORRW R13, R12, R12
	VMOV V0.S[3], R13
	ORRW R13, R12, R12
	CBNZ R12, use_hint_poly_gamma88_blk0_nonzero
	VST1.P [V4.S4], (16)(R2)
	JMP use_hint_poly_gamma88_blk0_done

use_hint_poly_gamma88_blk0_nonzero:
	// Slow path for non-zero h lanes: apply full UseHint adjustment rules.

	WORD $0x4ebb9c85                  // MUL   V5.4S, V4.4S, V27.4S
	VSUB V5.S4, V1.S4, V20.S4
	VCMEQ V23.S4, V20.S4, V6.S4
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VORR V24.B16, V6.B16, V6.B16
	VSUB V20.S4, V26.S4, V20.S4
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VORR V24.B16, V6.B16, V6.B16

	VADD V22.S4, V4.S4, V7.S4
	VCMEQ V25.S4, V4.S4, V8.S4
	VBIT V8.B16, V23.B16, V7.B16

	VSUB V22.S4, V4.S4, V9.S4
	VCMEQ V23.S4, V4.S4, V10.S4
	VBIT V10.B16, V25.B16, V9.B16

	VBIT V6.B16, V9.B16, V7.B16

	VSUB V0.S4, V23.S4, V11.S4
	VBIT V11.B16, V7.B16, V4.B16

	VST1.P [V4.S4], (16)(R2)

use_hint_poly_gamma88_blk0_done:

	VLD1.P (16)(R0), [V0.S4]
	VLD1.P (16)(R1), [V1.S4]

	VADD V30.S4, V1.S4, V3.S4
	VUSHR $7, V3.S4, V3.S4
	WORD $0x4ebd9c64                  // MUL   V4.4S, V3.4S, V29.4S
	VADD V28.S4, V4.S4, V4.S4
	VUSHR $24, V4.S4, V4.S4

	VCMEQ V19.S4, V4.S4, V8.S4
	VBIT V8.B16, V23.B16, V4.B16

	// Fast path: if this 4-lane h block is all zero, output r1 directly.
	VMOV V0.S[0], R12
	VMOV V0.S[1], R13
	ORRW R13, R12, R12
	VMOV V0.S[2], R13
	ORRW R13, R12, R12
	VMOV V0.S[3], R13
	ORRW R13, R12, R12
	CBNZ R12, use_hint_poly_gamma88_blk1_nonzero
	VST1.P [V4.S4], (16)(R2)
	JMP use_hint_poly_gamma88_blk1_done

use_hint_poly_gamma88_blk1_nonzero:
	// Slow path for non-zero h lanes: apply full UseHint adjustment rules.

	WORD $0x4ebb9c85                  // MUL   V5.4S, V4.4S, V27.4S
	VSUB V5.S4, V1.S4, V20.S4
	VCMEQ V23.S4, V20.S4, V6.S4
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VORR V24.B16, V6.B16, V6.B16
	VSUB V20.S4, V26.S4, V20.S4
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VORR V24.B16, V6.B16, V6.B16

	VADD V22.S4, V4.S4, V7.S4
	VCMEQ V25.S4, V4.S4, V8.S4
	VBIT V8.B16, V23.B16, V7.B16

	VSUB V22.S4, V4.S4, V9.S4
	VCMEQ V23.S4, V4.S4, V10.S4
	VBIT V10.B16, V25.B16, V9.B16

	VBIT V6.B16, V9.B16, V7.B16

	VSUB V0.S4, V23.S4, V11.S4
	VBIT V11.B16, V7.B16, V4.B16

	VST1.P [V4.S4], (16)(R2)

use_hint_poly_gamma88_blk1_done:

	VLD1.P (16)(R0), [V0.S4]
	VLD1.P (16)(R1), [V1.S4]

	VADD V30.S4, V1.S4, V3.S4
	VUSHR $7, V3.S4, V3.S4
	WORD $0x4ebd9c64                  // MUL   V4.4S, V3.4S, V29.4S
	VADD V28.S4, V4.S4, V4.S4
	VUSHR $24, V4.S4, V4.S4

	VCMEQ V19.S4, V4.S4, V8.S4
	VBIT V8.B16, V23.B16, V4.B16

	// Fast path: if this 4-lane h block is all zero, output r1 directly.
	VMOV V0.S[0], R12
	VMOV V0.S[1], R13
	ORRW R13, R12, R12
	VMOV V0.S[2], R13
	ORRW R13, R12, R12
	VMOV V0.S[3], R13
	ORRW R13, R12, R12
	CBNZ R12, use_hint_poly_gamma88_blk2_nonzero
	VST1.P [V4.S4], (16)(R2)
	JMP use_hint_poly_gamma88_blk2_done

use_hint_poly_gamma88_blk2_nonzero:
	// Slow path for non-zero h lanes: apply full UseHint adjustment rules.

	WORD $0x4ebb9c85                  // MUL   V5.4S, V4.4S, V27.4S
	VSUB V5.S4, V1.S4, V20.S4
	VCMEQ V23.S4, V20.S4, V6.S4
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VORR V24.B16, V6.B16, V6.B16
	VSUB V20.S4, V26.S4, V20.S4
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VORR V24.B16, V6.B16, V6.B16

	VADD V22.S4, V4.S4, V7.S4
	VCMEQ V25.S4, V4.S4, V8.S4
	VBIT V8.B16, V23.B16, V7.B16

	VSUB V22.S4, V4.S4, V9.S4
	VCMEQ V23.S4, V4.S4, V10.S4
	VBIT V10.B16, V25.B16, V9.B16

	VBIT V6.B16, V9.B16, V7.B16

	VSUB V0.S4, V23.S4, V11.S4
	VBIT V11.B16, V7.B16, V4.B16

	VST1.P [V4.S4], (16)(R2)

use_hint_poly_gamma88_blk2_done:

	VLD1.P (16)(R0), [V0.S4]
	VLD1.P (16)(R1), [V1.S4]

	VADD V30.S4, V1.S4, V3.S4
	VUSHR $7, V3.S4, V3.S4
	WORD $0x4ebd9c64                  // MUL   V4.4S, V3.4S, V29.4S
	VADD V28.S4, V4.S4, V4.S4
	VUSHR $24, V4.S4, V4.S4

	VCMEQ V19.S4, V4.S4, V8.S4
	VBIT V8.B16, V23.B16, V4.B16

	// Fast path: if this 4-lane h block is all zero, output r1 directly.
	VMOV V0.S[0], R12
	VMOV V0.S[1], R13
	ORRW R13, R12, R12
	VMOV V0.S[2], R13
	ORRW R13, R12, R12
	VMOV V0.S[3], R13
	ORRW R13, R12, R12
	CBNZ R12, use_hint_poly_gamma88_blk3_nonzero
	VST1.P [V4.S4], (16)(R2)
	JMP use_hint_poly_gamma88_blk3_done

use_hint_poly_gamma88_blk3_nonzero:
	// Slow path for non-zero h lanes: apply full UseHint adjustment rules.

	WORD $0x4ebb9c85                  // MUL   V5.4S, V4.4S, V27.4S
	VSUB V5.S4, V1.S4, V20.S4
	VCMEQ V23.S4, V20.S4, V6.S4
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VORR V24.B16, V6.B16, V6.B16
	VSUB V20.S4, V26.S4, V20.S4
	WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VORR V24.B16, V6.B16, V6.B16

	VADD V22.S4, V4.S4, V7.S4
	VCMEQ V25.S4, V4.S4, V8.S4
	VBIT V8.B16, V23.B16, V7.B16

	VSUB V22.S4, V4.S4, V9.S4
	VCMEQ V23.S4, V4.S4, V10.S4
	VBIT V10.B16, V25.B16, V9.B16

	VBIT V6.B16, V9.B16, V7.B16

	VSUB V0.S4, V23.S4, V11.S4
	VBIT V11.B16, V7.B16, V4.B16

	VST1.P [V4.S4], (16)(R2)

use_hint_poly_gamma88_blk3_done:
	SUBS $1, R3, R3
	BNE use_hint_poly_gamma88_loop
	RET
