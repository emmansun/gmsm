// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// ---- Static constants ----
//
// kBarrettConsts layout:
//   [0x00..0x0F] = {5039,5039,5039,5039}  -> VkBMul  (uint32x4)
//   [0x10..0x1F] = {24,0,24,0}            -> VkBShift (uint64x2)
//   [0x20..0x2F] = {3329,3329,3329,3329}  -> VkPrime32 (uint32x4)
//   [0x30..0x3F] = {3329 x8}              -> VkPrime16 (uint16x8)
DATA kBarrettConsts<>+0x00(SB)/4, $5039
DATA kBarrettConsts<>+0x04(SB)/4, $5039
DATA kBarrettConsts<>+0x08(SB)/4, $5039
DATA kBarrettConsts<>+0x0C(SB)/4, $5039
DATA kBarrettConsts<>+0x10(SB)/4, $24
DATA kBarrettConsts<>+0x14(SB)/4, $0
DATA kBarrettConsts<>+0x18(SB)/4, $24
DATA kBarrettConsts<>+0x1C(SB)/4, $0
DATA kBarrettConsts<>+0x20(SB)/4, $3329
DATA kBarrettConsts<>+0x24(SB)/4, $3329
DATA kBarrettConsts<>+0x28(SB)/4, $3329
DATA kBarrettConsts<>+0x2C(SB)/4, $3329
DATA kBarrettConsts<>+0x30(SB)/2, $3329
DATA kBarrettConsts<>+0x32(SB)/2, $3329
DATA kBarrettConsts<>+0x34(SB)/2, $3329
DATA kBarrettConsts<>+0x36(SB)/2, $3329
DATA kBarrettConsts<>+0x38(SB)/2, $3329
DATA kBarrettConsts<>+0x3A(SB)/2, $3329
DATA kBarrettConsts<>+0x3C(SB)/2, $3329
DATA kBarrettConsts<>+0x3E(SB)/2, $3329
GLOBL kBarrettConsts<>(SB), RODATA|NOPTR, $64

// lxvNaturalOrderMask: VPERM mask to convert LXVD2X output to natural uint16 order.
// After LXVD2X, bytes within each 8-byte group are reversed.
// This mask reorders the BE register so each uint16 slot holds its correct LE value
// in natural (memory) order: slot[i] = a[i].
// Desired BE register view: {6,7,4,5,2,3,0,1, 14,15,12,13,10,11,8,9}
// Stored reversed for LVX loading (Memory[j] = RegisterBE[15-j]).
DATA lxvNaturalOrderMask<>+0x00(SB)/8, $0x0E0F0C0D0A0B0809
DATA lxvNaturalOrderMask<>+0x08(SB)/8, $0x0607040502030001
GLOBL lxvNaturalOrderMask<>(SB), RODATA|NOPTR, $16

// lxvPairSwapMask: VPERM mask to convert LXVD2X output to pair-swapped uint16 order.
// Equivalent to natural order then swapping adjacent pairs: (a0,a1)->(a1,a0).
// Desired BE register view: {4,5,6,7,0,1,2,3, 12,13,14,15,8,9,10,11}
DATA lxvPairSwapMask<>+0x00(SB)/8, $0x0C0D0E0F08090A0B
DATA lxvPairSwapMask<>+0x08(SB)/8, $0x0405060700010203
GLOBL lxvPairSwapMask<>(SB), RODATA|NOPTR, $16

// lxvPackU32ToU16Mask: VPERM mask to pack two 4-uint32 vectors to 8 uint16.
// Extracts the low 2 bytes of each uint32 (the actual value when value < 2^16).
// Input: VA=[e0,o0,e1,o1] as uint32, VB=[e2,o2,e3,o3] as uint32
// Output: [e0,o0,e1,o1, e2,o2,e3,o3] as 8 uint16
// VPERM selects: bytes 2,3 from each uint32 of VA (indices 0-15) and VB (16-31).
// Desired BE register view: {2,3,6,7,10,11,14,15, 18,19,22,23,26,27,30,31}
// Stored as LE 64-bit integers so LVX reverses into correct BE positions.
// Memory bytes 0-7: {31,30,27,26,23,22,19,18} → DATA LE64 = 0x121316171A1B1E1F
// Memory bytes 8-15: {15,14,11,10,7,6,3,2}   → DATA LE64 = 0x020306070A0B0E0F
DATA lxvPackU32ToU16Mask<>+0x00(SB)/8, $0x121316171A1B1E1F
DATA lxvPackU32ToU16Mask<>+0x08(SB)/8, $0x020306070A0B0E0F
GLOBL lxvPackU32ToU16Mask<>(SB), RODATA|NOPTR, $16

// polyAddAssignPPC64LE(dst, src *ringElement)
// dst[i] = barrettReduce(dst[i] + src[i]) for all 256 int16 coefficients.
// LXVD2X on ppc64le reverses bytes within each 8-byte group. Since STXVD2X
// applies the same reversal on store, both cancel out and element-wise uint16
// arithmetic with VADDUHM/VSUBUHM is correct without any VPERM.
TEXT ·polyAddAssignPPC64LE(SB), NOSPLIT, $0-16
	MOVD dst+0(FP), R4
	MOVD src+8(FP), R5
	MOVD $0, R0

	// Load q=3329 into all 8 uint16 slots of V21.
	// kBarrettConsts+0x30 stores {3329 x8} as uint16 LE.
	// LVX reverses all 16 bytes; since data is symmetric (all slots equal),
	// each 16-bit slot in the register = 0x0D01 = 3329. ✓
	MOVD $kBarrettConsts<>(SB), R6
	MOVD $48, R7
	LVX  (R7)(R6), V21

	MOVD $16, R8
	MOVD $16, R6   // loop counter: 16 iters × 32 bytes = 512 bytes

poly_add_loop:
	LXVD2X (R0)(R4), VS32   // V0 = dst[i..i+7]
	LXVD2X (R8)(R4), VS33   // V1 = dst[i+8..i+15]
	LXVD2X (R0)(R5), VS34   // V2 = src[i..i+7]
	LXVD2X (R8)(R5), VS35   // V3 = src[i+8..i+15]

	VADDUHM V0, V2, V0
	VADDUHM V1, V3, V1

	// Conditional reduce: if V0[i] >= q, subtract q.
	VSUBUHM V0, V21, V4     // V4 = V0 - q (wraps if V0 < q)
	VSUBUHM V1, V21, V5
	// V6[i] = 0xFFFF if q > V4[i] (i.e. V0[i] >= q, reduction applied correctly)
	VCMPGTUH V21, V4, V6
	VCMPGTUH V21, V5, V7
	// Select V4 (reduced) when V6=all-ones, V0 (original) when V6=0.
	VSEL V0, V4, V6, V0
	VSEL V1, V5, V7, V1

	STXVD2X VS32, (R0)(R4)
	STXVD2X VS33, (R8)(R4)

	ADD  $32, R4
	ADD  $32, R5
	SUB  $1, R6
	CMP  R6, $0
	BNE  poly_add_loop

	RET

// polySubAssignPPC64LE(dst, src *ringElement)
// dst[i] = barrettReduce(dst[i] + q - src[i]) for all 256 int16 coefficients.
TEXT ·polySubAssignPPC64LE(SB), NOSPLIT, $0-16
	MOVD dst+0(FP), R4
	MOVD src+8(FP), R5
	MOVD $0, R0

	MOVD $kBarrettConsts<>(SB), R6
	MOVD $48, R7
	LVX  (R7)(R6), V21

	MOVD $16, R8
	MOVD $16, R6

poly_sub_loop:
	LXVD2X (R0)(R4), VS32
	LXVD2X (R8)(R4), VS33
	LXVD2X (R0)(R5), VS34
	LXVD2X (R8)(R5), VS35

	// V0 = V0 + q - V2; V1 = V1 + q - V3
	VADDUHM V0, V21, V0
	VSUBUHM V0, V2, V0
	VADDUHM V1, V21, V1
	VSUBUHM V1, V3, V1

	// Conditional reduce
	VSUBUHM V0, V21, V4
	VSUBUHM V1, V21, V5
	VCMPGTUH V21, V4, V6
	VCMPGTUH V21, V5, V7
	VSEL V0, V4, V6, V0
	VSEL V1, V5, V7, V1

	STXVD2X VS32, (R0)(R4)
	STXVD2X VS33, (R8)(R4)

	ADD  $32, R4
	ADD  $32, R5
	SUB  $1, R6
	CMP  R6, $0
	BNE  poly_sub_loop

	RET

// ---- Stubs for future asm implementation ----

TEXT ·internalNTTPPC64LE(SB), NOSPLIT, $0-8
	MOVD f+0(FP), R4
	RET

TEXT ·internalInverseNTTPPC64LE(SB), NOSPLIT, $0-8
	MOVD f+0(FP), R4
	RET

TEXT ·internalNTTMulPPC64LE(SB), NOSPLIT, $0-24
	MOVD out+0(FP), R4
	MOVD lhs+8(FP), R5
	MOVD rhs+16(FP), R6
	RET

// internalNTTMulAccPPC64LE(acc, lhs, rhs *nttElement)
//
// For each pair (2i, 2i+1), i=0..127 (Barrett standard-domain arithmetic):
//   acc[2i]   += fieldMul(a0,b0) + fieldMul(fieldMul(a1,b1), gamma[i])
//   acc[2i+1] += fieldMul(a0,b1) + fieldMul(a1,b0)
//
// Processes 4 pairs (8 uint16) per VMX iteration, 32 total iterations.
//
// Pinned registers (V14-V19, volatile but loaded once before the loop):
//   V14 = kBMul    = {5039 x4}  uint32 (Barrett multiplier)
//   V15 = kShift   = {24,24}   uint64 (shift amount for VSRD)
//   V16 = kPrime32 = {3329 x4}  uint32 (Barrett modulus)
//   V17 = kPrime16 = {3329 x8}  uint16 (for acc reduce)
//   V18 = lxvNaturalOrderMask (LXVD2X → natural uint16 order; self-inverse)
//   V19 = lxvPairSwapMask     (LXVD2X → pair-swapped uint16 order)
//
// Per-iteration (V0-V13):
//   V0-V7: input data and intermediate products
//   V8-V10: Barrett temporaries (reused)
//   V11-V13: gamma products and delta
//
// Barrett reduce macro (inline, 7 instructions):
//   VMULOUW Vtmp1, Vin, V14   // odd × kBMul → 64-bit
//   VMULEUW Vtmp2, Vin, V14   // even × kBMul → 64-bit
//   VSRD Vtmp1, V15, Vtmp1    // >> 24 → odd quotients
//   VSRD Vtmp2, V15, Vtmp2    // >> 24 → even quotients
//   VMRGOW Vtmp2, Vtmp1, Vtmp3 // [q0,q1,q2,q3]
//   VMULUWM Vtmp3, V16, Vtmp2  // quotient × q
//   VSUBUWM Vin, Vtmp2, Vin    // remainder ∈ [0, 2q)
TEXT ·internalNTTMulAccPPC64LE(SB), NOSPLIT, $0-24
	MOVD acc+0(FP), R4
	MOVD lhs+8(FP), R5
	MOVD rhs+16(FP), R6
	MOVD $·nttGammaU32PPC64LE(SB), R7
	MOVD $0, R0

	// Load pinned constants
	MOVD $kBarrettConsts<>(SB), R10
	MOVD $0, R11
	LVX  (R11)(R10), V14         // V14 = kBMul  = {5039 x4} uint32
	MOVD $16, R11
	LVX  (R11)(R10), V15         // V15 = kShift = {24,0,24,0}
	MOVD $32, R11
	LVX  (R11)(R10), V16         // V16 = kPrime32 = {3329 x4}
	MOVD $48, R11
	LVX  (R11)(R10), V17         // V17 = kPrime16 = {3329 x8}

	MOVD $lxvNaturalOrderMask<>(SB), R10
	LVX  (R0)(R10), V18           // V18 = natural-order VPERM mask (self-inverse)
	MOVD $lxvPairSwapMask<>(SB), R10
	LVX  (R0)(R10), V19           // V19 = pair-swap VPERM mask

	MOVD $lxvPackU32ToU16Mask<>(SB), R10
	LVX  (R0)(R10), V12           // V12 = pack uint32→uint16 VPERM mask (pinned)

	MOVD $32, R9                  // loop counter (32 iterations × 16 bytes = 512 bytes)

nttmlacc_loop:
	// Load lhs → natural uint16 order in V0
	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0        // V0 = lhs natural order

	// Load rhs: pair-swapped → V2, natural → V1
	LXVD2X (R0)(R6), VS33        // V1 = rhs raw
	VPERM  V1, V1, V19, V2        // V2 = rhs pair-swapped (from raw V1)
	VPERM  V1, V1, V18, V1        // V1 = rhs natural order

	// Load gamma: 4 uint32 values [g_{4j},g_{4j+1},g_{4j+2},g_{4j+3}].
	// nttGammaU32PPC64LE stores [g1,g0,g3,g2] as LE uint32 per group.
	// LXVD2X byte-reversal within each 8-byte group gives [g0,g1,g2,g3]. ✓
	LXVD2X (R0)(R7), VS35         // V3 = [g0,g1,g2,g3] as 4 uint32

	// Compute 4 pair products (each yields 4 uint32)
	VMULEUH V0, V1, V4            // V4 = [a0b0, a2b2, a4b4, a6b6] (even×even)
	VMULOUH V0, V1, V5            // V5 = [a1b1, a3b3, a5b5, a7b7] (odd×odd)
	VMULEUH V0, V2, V6            // V6 = [a0b1, a2b3, a4b5, a6b7] (even×swap_even)
	VMULOUH V0, V2, V7            // V7 = [a1b0, a3b2, a5b4, a7b6] (odd×swap_odd)

	// Barrett reduce V4 → V_r00 ∈ [0, 2q)
	VMULEUW V4, V14, V8    // V8 = even words of V4 × kBMul (64-bit products)
	VMULOUW V4, V14, V9    // V9 = odd words of V4 × kBMul (64-bit products)
	VSRD    V8, V15, V8    // V8 = [0,q0,0,q2] after >>24
	VSRD    V9, V15, V9    // V9 = [0,q1,0,q3] after >>24
	VMRGOW  V8, V9, V10   // V10 = [q0,q1,q2,q3] (even-source first)
	VMULUWM V10, V16, V9   // V9 = quotient * prime
	VSUBUWM V4, V9, V4

	// Barrett reduce V5 → V_r11 ∈ [0, 2q)
	VMULEUW V5, V14, V8
	VMULOUW V5, V14, V9
	VSRD    V8, V15, V8
	VSRD    V9, V15, V9
	VMRGOW  V8, V9, V10
	VMULUWM V10, V16, V9
	VSUBUWM V5, V9, V5

	// Barrett reduce V6 → V_r01 ∈ [0, 2q)
	VMULEUW V6, V14, V8
	VMULOUW V6, V14, V9
	VSRD    V8, V15, V8
	VSRD    V9, V15, V9
	VMRGOW  V8, V9, V10
	VMULUWM V10, V16, V9
	VSUBUWM V6, V9, V6

	// Barrett reduce V7 → V_r10 ∈ [0, 2q)
	VMULEUW V7, V14, V8
	VMULOUW V7, V14, V9
	VSRD    V8, V15, V8
	VSRD    V9, V15, V9
	VMRGOW  V8, V9, V10
	VMULUWM V10, V16, V9
	VSUBUWM V7, V9, V7

	// Gamma multiplication: VMULUWM(r11_reduced, gamma_u32) → 4 uint32 products.
	// V5 = [a1b1_r, a3b3_r, a5b5_r, a7b7_r] as 4 uint32 ∈ [0,q)
	// V3 = [g0,g1,g2,g3] as 4 uint32 ∈ [0,q)
	// Product < q² < 2^24 → fits in uint32. No packing needed.
	VMULUWM V5, V3, V0            // V0 = [a1b1_r*g0, a3b3_r*g1, a5b5_r*g2, a7b7_r*g3]

	// Barrett reduce V0 (gamma products) → V_rg ∈ [0, 2q)
	VMULEUW V0, V14, V8
	VMULOUW V0, V14, V9
	VSRD    V8, V15, V8
	VSRD    V9, V15, V9
	VMRGOW  V8, V9, V10
	VMULUWM V10, V16, V9
	VSUBUWM V0, V9, V0

	// Even pair sums = V_r00 + V_rg (stored in V1, reusing V1=rhs)
	VADDUWM V4, V0, V1            // V1 = [a0b0_r+g0*a1b1_r, ...] ∈ [0, 2q)
	// Odd pair sums = V_r01 + V_r10 (stored in V2, reusing V2=rhs_swap)
	VADDUWM V6, V7, V2            // V2 = [a0b1_r+a1b0_r, ...] ∈ [0, 2q)

	// fieldReduceOnce even sums (uint32: [0,2q) → [0,q))
	VSUBUWM V1, V16, V8           // V8 = V1 - q (wraps if V1 < q)
	VCMPGTUW V16, V1, V9          // V9 = 0xFFFFFFFF where q > V1 (no reduce needed)
	VSEL    V8, V1, V9, V1        // V1 = V9? V1 (keep) : V8 (reduced)

	// fieldReduceOnce odd sums
	VSUBUWM V2, V16, V8
	VCMPGTUW V16, V2, V9
	VSEL    V8, V2, V9, V2

	// Interleave even/odd sums and pack to uint16 delta (NO VPKUWUS):
	// XXMRGHW: V0=[e0,o0,e1,o1] as 4 uint32 (pairs 0,1)
	// XXMRGLW: V11=[e2,o2,e3,o3] as 4 uint32 (pairs 2,3)
	// VPERM extracts bytes 2,3 of each uint32 (the actual value) from both sources:
	// V13=[e0,o0,e1,o1, e2,o2,e3,o3] as 8 uint16 (delta)
	XXMRGHW VS33, VS34, VS32      // VS33=V1, VS34=V2, VS32=V0
	XXMRGLW VS33, VS34, VS43      // VS43=V11
	VPERM   V0, V11, V12, V13    // V13 = delta uint16 (V12=pack mask, pinned)

	// Load acc → natural order in V0
	LXVD2X (R0)(R4), VS32
	VPERM  V0, V0, V18, V0        // V0 = acc natural order

	// acc += delta (values in [0, 2q) as uint16)
	VADDUHM V0, V13, V0

	// fieldReduceOnce acc (uint16: [0,2q) → [0,q))
	VSUBUHM V0, V17, V8           // V8 = acc - q (wraps if acc < q)
	VCMPGTUH V17, V0, V9          // V9 = 0xFFFF where q > acc (no reduce)
	VSEL    V8, V0, V9, V0        // V0 = V9? V0 : V8

	// Store back: apply inverse VPERM (V18 is self-inverse) then STXVD2X
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R4)

	// Advance pointers
	ADD  $16, R4                  // acc: next 8 coefficients
	ADD  $16, R5                  // lhs: next 8 coefficients
	ADD  $16, R6                  // rhs: next 8 coefficients
	ADD  $16, R7                  // gamma: 4 uint32 = 16 bytes per iteration

	SUB  $1, R9
	CMP  R9, $0
	BNE  nttmlacc_loop

	RET

// internalNTTMulAccKeyGenPPC64LE uses the same Barrett arithmetic as internalNTTMulAccPPC64LE.
TEXT ·internalNTTMulAccKeyGenPPC64LE(SB), NOSPLIT, $0-24
	JMP ·internalNTTMulAccPPC64LE(SB)

TEXT ·ringCompressAndEncode1PPC64LE(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R4
	MOVD f+24(FP), R5
	RET

TEXT ·ringCompressAndEncode4PPC64LE(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R4
	MOVD f+24(FP), R5
	RET

TEXT ·ringDecodeAndDecompress4PPC64LE(SB), NOSPLIT, $0-16
	MOVD b+0(FP), R4
	MOVD f+8(FP), R5
	RET

TEXT ·ringCompressAndEncode5PPC64LE(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R4
	MOVD f+24(FP), R5
	RET

TEXT ·ringDecodeAndDecompress5PPC64LE(SB), NOSPLIT, $0-16
	MOVD b+0(FP), R4
	MOVD f+8(FP), R5
	RET

TEXT ·ringCompressAndEncode10PPC64LE(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R4
	MOVD f+24(FP), R5
	RET

TEXT ·ringCompressAndEncode11PPC64LE(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R4
	MOVD f+24(FP), R5
	RET

TEXT ·decodeAndDecompressU10PPC64LE(SB), NOSPLIT, $0-48
	MOVD dst_base+0(FP), R4
	MOVD c_base+24(FP), R5
	RET

TEXT ·decodeAndDecompressU11PPC64LE(SB), NOSPLIT, $0-48
	MOVD dst_base+0(FP), R4
	MOVD c_base+24(FP), R5
	RET

TEXT ·samplePolyCBD2PPC64LE(SB), NOSPLIT, $0-16
	MOVD f+0(FP), R4
	MOVD buf+8(FP), R5
	RET

TEXT ·samplePolyCBD3PPC64LE(SB), NOSPLIT, $0-16
	MOVD f+0(FP), R4
	MOVD buf+8(FP), R5
	RET

TEXT ·rejUniformPPC64LE(SB), NOSPLIT, $0-48
	MOVD buf_base+0(FP), R4
	MOVD buf_len+8(FP), R5
	MOVD a+24(FP), R6
	MOVD j+32(FP), R7
	MOVD $0, R3
	MOVD R3, ret+40(FP)
	RET
