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

// lxvPackU32ToU16Mask: VPERM mask to directly interleave and pack V1=[e0,e1,e2,e3] and
// V2=[o0,o1,o2,o3] (both uint32 in [0,2q)) to V13=[e0,o0,e1,o1,e2,o2,e3,o3] as 8 uint16.
// Desired BE register view: {2,3,18,19, 6,7,22,23, 10,11,26,27, 14,15,30,31}
// (selects low 2 bytes of each uint32 from VA=V1 and VB=V2 alternately)
// LVX on ppc64le reverses all 16 bytes. Memory = reverse of desired:
// {31,30,15,14, 27,26,11,10, 23,22,7,6, 19,18,3,2}
DATA lxvPackU32ToU16Mask<>+0x00(SB)/8, $0x0A0B1A1B0E0F1E1F
DATA lxvPackU32ToU16Mask<>+0x08(SB)/8, $0x0203121306071617
GLOBL lxvPackU32ToU16Mask<>(SB), RODATA|NOPTR, $16

// ---- NTT twiddle masks ----
//
// nttL6L7DeinterleaveMaskLo: VPERM mask to extract first pair (A) from each 4-element group.
// After L6, V0=[lo0,lo1,lo2,lo3, hi0,hi1,hi2,hi3], V1 similarly.
// L7 groups: group k uses A=[e_{4k},e_{4k+1}] and B=[e_{4k+2},e_{4k+3}] with zeta z_k.
// A (first pair of each 4-group): bytes {0,1,2,3, 8,9,10,11} from V0 and V1.
// Desired BE byte indices: {0,1,2,3, 8,9,10,11, 16,17,18,19, 24,25,26,27}
// memory[i] = desired_BE[15-i]:
//   memory[0..15]: 1B,1A,19,18, 13,12,11,10, 0B,0A,09,08, 03,02,01,00
// As two LE uint64: 0x10111213_18191A1B / 0x00010203_08090A0B
DATA nttL6L7DeinterleaveMaskLo<>+0x00(SB)/8, $0x10111213_18191A1B
DATA nttL6L7DeinterleaveMaskLo<>+0x08(SB)/8, $0x00010203_08090A0B
GLOBL nttL6L7DeinterleaveMaskLo<>(SB), RODATA|NOPTR, $16

// nttL6L7DeinterleaveMaskHi: VPERM mask to extract second pair (B) from each 4-element group.
// B (second pair): bytes {4,5,6,7, 12,13,14,15} from V0 and V1.
// Desired BE byte indices: {4,5,6,7, 12,13,14,15, 20,21,22,23, 28,29,30,31}
// memory[i] = desired_BE[15-i]:
//   memory[0..15]: 1F,1E,1D,1C, 17,16,15,14, 0F,0E,0D,0C, 07,06,05,04
// As two LE uint64: 0x14151617_1C1D1E1F / 0x04050607_0C0D0E0F
DATA nttL6L7DeinterleaveMaskHi<>+0x00(SB)/8, $0x14151617_1C1D1E1F
DATA nttL6L7DeinterleaveMaskHi<>+0x08(SB)/8, $0x04050607_0C0D0E0F
GLOBL nttL6L7DeinterleaveMaskHi<>(SB), RODATA|NOPTR, $16

// nttL7ReinterleaveMask0: reinterleave A'+B' for first 8 output elements.
// VA=V8=A'=[A'[0..7]], VB=V9=B'=[B'[0..7]].
// Output: [A'[0],A'[1], B'[0],B'[1], A'[2],A'[3], B'[2],B'[3]].
// Desired BE byte indices: {0,1,2,3, 16,17,18,19, 4,5,6,7, 20,21,22,23}
// memory[i] = desired_BE[15-i]:
//   memory[0..15]: 17,16,15,14, 07,06,05,04, 13,12,11,10, 03,02,01,00
// As two LE uint64: 0x04050607_14151617 / 0x00010203_10111213
DATA nttL7ReinterleaveMask0<>+0x00(SB)/8, $0x04050607_14151617
DATA nttL7ReinterleaveMask0<>+0x08(SB)/8, $0x00010203_10111213
GLOBL nttL7ReinterleaveMask0<>(SB), RODATA|NOPTR, $16

// nttL7ReinterleaveMask1: reinterleave A'+B' for second 8 output elements.
// Output: [A'[4],A'[5], B'[4],B'[5], A'[6],A'[7], B'[6],B'[7]].
// Desired BE byte indices: {8,9,10,11, 24,25,26,27, 12,13,14,15, 28,29,30,31}
// memory[i] = desired_BE[15-i]:
//   memory[0..15]: 1F,1E,1D,1C, 0F,0E,0D,0C, 1B,1A,19,18, 0B,0A,09,08
// As two LE uint64: 0x0C0D0E0F_1C1D1E1F / 0x08090A0B_18191A1B
DATA nttL7ReinterleaveMask1<>+0x00(SB)/8, $0x0C0D0E0F_1C1D1E1F
DATA nttL7ReinterleaveMask1<>+0x08(SB)/8, $0x08090A0B_18191A1B
GLOBL nttL7ReinterleaveMask1<>(SB), RODATA|NOPTR, $16

// BARRETT_REDUCE_U32(Vin, V14, V15, V16, Vtmp1, Vtmp2, Vtmp3) - Barrett reduce Vin to [0,2q)
// V14=kBMul={5039x4}, V15=kShift={24,24}uint64, V16=kPrime32={3329x4}
// Vtmp1, Vtmp2, Vtmp3 are scratch registers
#define BARRETT_REDUCE_U32(Vin, Vtmp1, Vtmp2, Vtmp3) \
	VMULEUW Vin, V14, Vtmp1; \
	VMULOUW Vin, V14, Vtmp2; \
	VSRD    Vtmp1, V15, Vtmp1; \
	VSRD    Vtmp2, V15, Vtmp2; \
	VMRGOW  Vtmp1, Vtmp2, Vtmp3; \
	VMULUWM Vtmp3, V16, Vtmp2; \
	VSUBUWM Vin, Vtmp2, Vin

// FIELD_REDUCE_ONCE_U16: reduce Vval from [0,2q) to [0,q).
// Uses: signed shift-right by 15 to detect underflow.
// Clobbers Vtmp1 (shift mask) and Vtmp2 (shifted value / borrow).
// V17 must be pinned to {3329 x8} as uint16.
//
// Algorithm:
//   tmp = val - q           (uint16 wraps; negative becomes large positive)
//   borrow = tmp >> 15      (arithmetic, all-ones if underflow, 0 otherwise)
//   fix = borrow & q        (q if underflow, 0 otherwise)
//   val = tmp + fix
//
// Note: VSPLTISH is used each time since V_shift15 register is not pinned.
#define FIELD_REDUCE_ONCE_U16(Vval, Vtmp1, Vtmp2) \
	VSPLTISH $15, Vtmp1;           \
	VSUBUHM  Vval, V17, Vtmp2;    \
	VSRAH    Vtmp2, Vtmp1, Vtmp1;  \
	VAND     Vtmp1, V17, Vtmp1;    \
	VADDUHM  Vtmp1, Vtmp2, Vval


// MUL_ZETA_U16: compute t = fieldMul(VZ, VB) for uint16 inputs -> uint16 output in [0,2q).
// VB, VZ: 8 x uint16 in [0,q). Product P = VB*VZ < q^2 < 2^24.
// Since P < 11082241, P'=(P>>4) <= 692640, and P'*5039 <= 3490212960 < 2^32 (fits in uint32).
// Barrett quotient: floor(P*5039/2^24) = floor(P'*5039/2^20). No 64-bit needed.
// V14={5039x4}, V16={3329x4}, V12=packMask. Clobbers: Vtmp1,Vtmp2,Vtmp3,Vshift.
#define MUL_ZETA_U16(VB, VZ, Vt, Vtmp1, Vtmp2, Vtmp3, Vshift) \
	VMULEUH  VB, VZ, Vtmp1;        \
	VMULOUH  VB, VZ, Vtmp2;        \
	VSPLTISW $4, Vshift;            \
	VSRW     Vtmp1, Vshift, Vtmp3; \
	VMULUWM  Vtmp3, V14, Vtmp3;    \
	VSPLTISW $20, Vshift;           \
	VSRW     Vtmp3, Vshift, Vtmp3; \
	VMULUWM  Vtmp3, V16, Vtmp3;    \
	VSUBUWM  Vtmp1, Vtmp3, Vtmp1;  \
	VSPLTISW $4, Vshift;            \
	VSRW     Vtmp2, Vshift, Vtmp3; \
	VMULUWM  Vtmp3, V14, Vtmp3;    \
	VSPLTISW $20, Vshift;           \
	VSRW     Vtmp3, Vshift, Vtmp3; \
	VMULUWM  Vtmp3, V16, Vtmp3;    \
	VSUBUWM  Vtmp2, Vtmp3, Vtmp2;  \
	VPERM    Vtmp1, Vtmp2, V12, Vt

// BUTTERFLY_U16: Cooley-Tukey butterfly.
// VA updated to VA+t (in [0,q)), VB updated to VA-t+q (in [0,q)), t = fieldMul(VZ,VB).
// V17=prime16 (pinned), V12=packMask (pinned).
// Clobbers: Vt, Vtmp1, Vtmp2, Vtmp3, Vshift, Vsave.
#define BUTTERFLY_U16(VA, VB, VZ, Vt, Vtmp1, Vtmp2, Vtmp3, Vshift, Vsave) \
	MUL_ZETA_U16(VB, VZ, Vt, Vtmp1, Vtmp2, Vtmp3, Vshift);  \
	FIELD_REDUCE_ONCE_U16(Vt, Vtmp1, Vtmp2);                  \
	VADDUHM  VA, Vt, Vsave;       \
	FIELD_REDUCE_ONCE_U16(Vsave, Vtmp1, Vtmp2);               \
	VSUBUHM  VA, Vt, VB;          \
	VADDUHM  VB, V17, VB;         \
	FIELD_REDUCE_ONCE_U16(VB, Vtmp1, Vtmp2);                  \
	VOR      Vsave, Vsave, VA



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
	// each 16-bit slot in the register = 0x0D01 = 3329. (ok)
	MOVD $kBarrettConsts<>(SB), R6
	MOVD $48, R7
	LVX  (R7)(R6), V21

	MOVD $16, R8
	MOVD $16, R6   // loop counter: 16 iters x 32 bytes = 512 bytes
	MOVD R6, CTR

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
	BDNZ poly_add_loop

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
	MOVD R6, CTR

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
	BDNZ poly_sub_loop

	RET

// ---- Forward NTT ----
//
// internalNTTPPC64LE(f *ringElement)
//
// Computes the forward NTT in place. 7 layers (len=128..2).
// All coefficients must be in [0, q) on entry; exit in [0, q).
//
// Pinned registers:
//   R0  = 0 (always zero)
//   R4  = f pointer (advances through layers)
//   V12 = lxvPackU32ToU16Mask (for MUL_ZETA_U16 interleave)
//   V14 = kBMul32 = {5039 x4}
//   V16 = kPrime32 = {3329 x4}
//   V17 = kPrime16 = {3329 x8}
//   V18 = naturalOrderMask (LXVD2X <-> natural uint16 order)
//   V19 = nttL6L7DeinterleaveMaskLo
//
// Working registers (per-butterfly): V0..V11, V13, V15.
//
TEXT ·internalNTTPPC64LE(SB), NOSPLIT, $0-8
	MOVD f+0(FP), R4
	MOVD $0, R0

	// Load pinned constants
	MOVD $kBarrettConsts<>(SB), R10
	MOVD $0, R11
	LVX  (R11)(R10), V14         // V14 = {5039 x4}
	MOVD $32, R11
	LVX  (R11)(R10), V16         // V16 = {3329 x4}
	MOVD $48, R11
	LVX  (R11)(R10), V17         // V17 = {3329 x8}

	MOVD $lxvNaturalOrderMask<>(SB), R10
	LVX  (R0)(R10), V18

	MOVD $lxvPackU32ToU16Mask<>(SB), R10
	LVX  (R0)(R10), V12

	MOVD $nttL6L7DeinterleaveMaskLo<>(SB), R10
	LVX  (R0)(R10), V19

	// ================================================================
	// Layer L1: len=128, 1 zeta = zetas[1], 16 iterations
	// lo = f[0..7], f[16..23], ..., f[112..119]
	// hi = f[128..135], ..., f[240..247]
	// ================================================================
	MOVD $·nttTwiddleL1PrecompPPC64LE(SB), R10
	LXVD2X (R0)(R10), VS40   // V8=broadcast zeta[1]
	VPERM  V8, V8, V18, V2   // V2 = zeta broadcast in natural order

	MOVD $8, R9
	MOVD R9, CTR
	MOVD R4, R6               // R6 = hi pointer = f + 256 bytes
	ADD  $256, R6
ntt_l1_loop:
	// ---- Group A: lo at R4+0, hi at R6+0 ----
	LXVD2X (R0)(R4), VS32    // V0 = lo_A
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6), VS33    // V1 = hi_A
	VPERM  V1, V1, V18, V1
	// ---- Group B: lo at R4+16, hi at R6+16 (pre-load, overlaps A butterfly) ----
	MOVD   $16, R5
	LXVD2X (R5)(R4), VS41    // V9 = lo_B
	VPERM  V9, V9, V18, V9
	LXVD2X (R5)(R6), VS42    // V10 = hi_B
	VPERM  V10, V10, V18, V10

	BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7, V8)

	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R4)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)

	BUTTERFLY_U16(V9, V10, V2, V3, V4, V5, V6, V7, V13)

	VPERM  V9, V9, V18, V9
	STXVD2X VS41, (R5)(R4)
	VPERM  V10, V10, V18, V10
	STXVD2X VS42, (R5)(R6)

	ADD  $32, R4
	ADD  $32, R6
	BDNZ ntt_l1_loop

	// Reset R4 to base
	MOVD f+0(FP), R4

	// ================================================================
	// Layer L2: len=64, 2 zetas, 2 outer, 8 inner iterations
	// Group 0: lo=f[0..63], hi=f[64..127]
	// Group 1: lo=f[128..191], hi=f[192..255]
	// ================================================================
	MOVD $·nttTwiddleL2bPrecompPPC64LE(SB), R10

	// Group 0: zeta = zetas[2]
	LXVD2X (R0)(R10), VS40
	VPERM  V8, V8, V18, V2    // V2 = zeta broadcast

	MOVD R4, R5               // lo = f[0]
	MOVD R4, R6
	ADD  $128, R6             // hi = f[128] (64 elements x 2 bytes)
	MOVD $4, R9
	MOVD R9, CTR
ntt_l2_g0_loop:
	MOVD   $16, R13
	LXVD2X (R0)(R5),   VS32  // V0  = lo_A
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6),   VS33  // V1  = hi_A
	VPERM  V1, V1, V18, V1
	LXVD2X (R13)(R5),  VS41  // V9  = lo_B
	VPERM  V9, V9, V18, V9
	LXVD2X (R13)(R6),  VS42  // V10 = hi_B
	VPERM  V10, V10, V18, V10
	BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7, V8)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)
	BUTTERFLY_U16(V9, V10, V2, V3, V4, V5, V6, V7, V13)
	VPERM  V9, V9, V18, V9
	STXVD2X VS41, (R13)(R5)
	VPERM  V10, V10, V18, V10
	STXVD2X VS42, (R13)(R6)
	ADD  $32, R5
	ADD  $32, R6
	BDNZ ntt_l2_g0_loop

	// Group 1: zeta = zetas[3]
	MOVD $16, R11
	LXVD2X (R11)(R10), VS40
	VPERM  V8, V8, V18, V2

	MOVD R4, R5
	ADD  $256, R5             // lo = f[128]
	MOVD R5, R6
	ADD  $128, R6             // hi = f[192]
	MOVD $4, R9
	MOVD R9, CTR
ntt_l2_g1_loop:
	MOVD   $16, R13
	LXVD2X (R0)(R5),   VS32
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6),   VS33
	VPERM  V1, V1, V18, V1
	LXVD2X (R13)(R5),  VS41
	VPERM  V9, V9, V18, V9
	LXVD2X (R13)(R6),  VS42
	VPERM  V10, V10, V18, V10
	BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7, V8)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)
	BUTTERFLY_U16(V9, V10, V2, V3, V4, V5, V6, V7, V13)
	VPERM  V9, V9, V18, V9
	STXVD2X VS41, (R13)(R5)
	VPERM  V10, V10, V18, V10
	STXVD2X VS42, (R13)(R6)
	ADD  $32, R5
	ADD  $32, R6
	BDNZ ntt_l2_g1_loop

	// ================================================================
	// Layer L3: len=32, 4 zetas, 4 groups, 4 inner iters (unrolled outer)
	// Group g: lo=f[g*128..g*128+63], hi=lo+64 bytes
	// ================================================================
	MOVD $·nttTwiddleL3PrecompPPC64LE(SB), R10
	MOVD $0, R11

	// Group 0
	LXVD2X (R11)(R10), VS40
	VPERM  V8, V8, V18, V2
	MOVD R4, R5
	MOVD R4, R6
	ADD  $64, R6
	MOVD $4, R9
	MOVD R9, CTR
ntt_l3g0:
	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6), VS33
	VPERM  V1, V1, V18, V1
	BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7, V8)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)
	ADD  $16, R5
	ADD  $16, R6
	BDNZ ntt_l3g0

	// Group 1
	ADD  $16, R11
	LXVD2X (R11)(R10), VS40
	VPERM  V8, V8, V18, V2
	MOVD R4, R5
	ADD  $128, R5
	MOVD R5, R6
	ADD  $64, R6
	MOVD $4, R9
	MOVD R9, CTR
ntt_l3g1:
	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6), VS33
	VPERM  V1, V1, V18, V1
	BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7, V8)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)
	ADD  $16, R5
	ADD  $16, R6
	BDNZ ntt_l3g1

	// Group 2
	ADD  $16, R11
	LXVD2X (R11)(R10), VS40
	VPERM  V8, V8, V18, V2
	MOVD R4, R5
	ADD  $256, R5
	MOVD R5, R6
	ADD  $64, R6
	MOVD $4, R9
	MOVD R9, CTR
ntt_l3g2:
	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6), VS33
	VPERM  V1, V1, V18, V1
	BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7, V8)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)
	ADD  $16, R5
	ADD  $16, R6
	BDNZ ntt_l3g2

	// Group 3
	ADD  $16, R11
	LXVD2X (R11)(R10), VS40
	VPERM  V8, V8, V18, V2
	MOVD R4, R5
	ADD  $384, R5
	MOVD R5, R6
	ADD  $64, R6
	MOVD $4, R9
	MOVD R9, CTR
ntt_l3g3:
	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6), VS33
	VPERM  V1, V1, V18, V1
	BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7, V8)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)
	ADD  $16, R5
	ADD  $16, R6
	BDNZ ntt_l3g3

	// ================================================================
	// Layer L4: len=16, 8 zetas, 8 outer, 2 inner iterations
	// Group g: lo=f[g*32..g*32+15], hi=f[g*32+16..g*32+31]
	// ================================================================
	MOVD $·nttTwiddleL4bPrecompPPC64LE(SB), R10
	MOVD $0, R11
	MOVD R4, R5               // lo pointer

	MOVD $8, R13
	MOVD R13, CTR
ntt_l4_outer:
	LXVD2X (R11)(R10), VS40
	VPERM  V8, V8, V18, V2

	MOVD R5, R6
	ADD  $32, R6              // hi = lo + 32 bytes

	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6), VS33
	VPERM  V1, V1, V18, V1
	BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7, V8)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)

	ADD  $16, R5
	ADD  $16, R6

	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6), VS33
	VPERM  V1, V1, V18, V1
	BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7, V8)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)

	ADD  $48, R5              // advance to next group (R5 was lo+16; lo+16+48=lo+64)
	ADD  $16, R11
	BDNZ ntt_l4_outer

	// ================================================================
	// Layer L5: len=8, 16 zetas, 16 iterations -> 2x unrolled to 8 iters.
	// Each iter processes 2 consecutive groups (A and B) with different zetas.
	// Group g: lo=f[g*16..g*16+7], hi=f[g*16+8..g*16+15].
	// Registers: Group A -> V0/V1, zeta_A -> V2, temps V3-V8.
	//            Group B -> V9/V10, zeta_B -> V11, temps V3-V7, V13(Vsave).
	// ================================================================
	MOVD $·nttTwiddleL5PrecompPPC64LE(SB), R10
	MOVD $0, R11
	MOVD R4, R5

	MOVD $8, R9
	MOVD R9, CTR
ntt_l5_loop:
	// Load zeta_A at R10+R11
	LXVD2X (R11)(R10), VS40
	VPERM  V8, V8, V18, V2    // V2 = zeta_A
	// Load zeta_B at R10+(R11+16): use R9 as temp = R11+16
	ADD    $16, R11, R9        // R9 = R11+16
	LXVD2X (R9)(R10), VS43    // V11 = twiddle_B raw
	VPERM  V11, V11, V18, V11 // V11 = zeta_B

	// Group A: lo at R5+0, hi at R5+16
	MOVD   R5, R6
	ADD    $16, R6             // R6 = R5+16 (hi_A)
	LXVD2X (R0)(R5), VS32     // V0 = lo_A
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6), VS33     // V1 = hi_A
	VPERM  V1, V1, V18, V1

	// Group B: lo at R5+32, hi at R5+48 (pre-load; overlaps Group A butterfly)
	MOVD   $32, R9             // R9 = 32
	MOVD   $48, R8             // R8 = 48
	LXVD2X (R9)(R5), VS41     // V9  = lo_B
	VPERM  V9, V9, V18, V9
	LXVD2X (R8)(R5), VS42     // V10 = hi_B
	VPERM  V10, V10, V18, V10

	BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7, V8)

	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)    // R6 = R5+16

	BUTTERFLY_U16(V9, V10, V11, V3, V4, V5, V6, V7, V13)

	VPERM  V9, V9, V18, V9
	STXVD2X VS41, (R9)(R5)    // R9 = 32 (from above, unchanged)
	VPERM  V10, V10, V18, V10
	STXVD2X VS42, (R8)(R5)    // R8 = 48 (from above, unchanged)

	ADD    $64, R5             // advance by 2 groups x 32 bytes each
	ADD    $32, R11            // advance twiddle by 2 entries
	BDNZ   ntt_l5_loop

	// ================================================================
	// Layer L6: len=4, 32 zetas, 16 iterations, 2 groups per iter.
	// Per iter: load 2 VMX vecs (16 elements), XXPERMDI split into lo/hi,
	// butterfly with [za x4, zb x4] twiddle, repack, store.
	// ================================================================
	MOVD $·nttTwiddleL4PrecompPPC64LE(SB), R10
	MOVD $0, R11
	MOVD R4, R5

	MOVD $16, R9
	MOVD R9, CTR
ntt_l6_loop:
	// Load twiddle [za x4, zb x4] into V2
	LXVD2X (R11)(R10), VS34
	VPERM  V2, V2, V18, V2

	// Load 16 consecutive elements into V0, V1
	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	MOVD $16, R6
	LXVD2X (R6)(R5), VS33
	VPERM  V1, V1, V18, V1

	// XXPERMDI split: V0=[a0..a7], V1=[b0..b7]
	// V_lo=[a0..a3, b0..b3], V_hi=[a4..a7, b4..b7]
	XXPERMDI VS32, VS33, $0, VS41   // V9 = V_lo
	XXPERMDI VS32, VS33, $3, VS40   // V8 = V_hi

	// Butterfly: VA=V9(lo), VB=V8(hi), VZ=V2
	BUTTERFLY_U16(V9, V8, V2, V3, V4, V5, V6, V7, V10)

	// Repack: V0=[lo[0..3], hi[0..3]], V1=[lo[4..7], hi[4..7]]
	XXPERMDI VS41, VS40, $0, VS32   // V0 = [lo[0..3], hi[0..3]] = [a0..a7]
	XXPERMDI VS41, VS40, $3, VS33   // V1 = [lo[4..7], hi[4..7]] = [b0..b7]

	// Store (convert back to LXVD2X byte order)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R6)(R5)

	ADD  $32, R5
	ADD  $16, R11
	BDNZ ntt_l6_loop

	// ================================================================
	// Layer L7: len=2, 64 zetas, 16 iters, 4 groups per iter.
	// Each iter processes 2 VMX vecs (32 elements = 4 groups, 8 elements).
	// Twiddle: 4 distinct zetas per iter, each x2 = [z0,z0,z1,z1,z2,z2,z3,z3].
	// VPERM deinterleave separates lo pairs from hi pairs, butterfly, reinterleave.
	// ================================================================
	MOVD $·nttTwiddleL2PrecompPPC64LE(SB), R10
	MOVD $0, R11
	MOVD R4, R5

	// Load masks for deinterleave/reinterleave
	MOVD $nttL6L7DeinterleaveMaskHi<>(SB), R7
	LVX  (R0)(R7), V11        // V11 = hi deinterleave mask (reloaded each iter)
	MOVD $nttL7ReinterleaveMask0<>(SB), R12
	LVX  (R0)(R12), V13       // V13 = reinterleave mask 0 (first 8 elems)
	MOVD $nttL7ReinterleaveMask1<>(SB), R12
	LVX  (R0)(R12), V15       // V15 = reinterleave mask 1 (second 8 elems)

	MOVD $16, R9
	MOVD R9, CTR
ntt_l7_loop:
	// Reload V11 hi-deinterleave mask (V11 is used as Vsave inside BUTTERFLY_U16)
	LVX  (R0)(R7), V11

	// Load twiddle [z0..z7] into V2
	LXVD2X (R11)(R10), VS34
	VPERM  V2, V2, V18, V2

	// Load 16 consecutive elements
	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	MOVD $16, R6
	LXVD2X (R6)(R5), VS33
	VPERM  V1, V1, V18, V1

	// Deinterleave: V_lo=[e0..e7], V_hi=[o0..o7]
	VPERM  V0, V1, V19, V8    // V8 = V_lo (even elements)
	VPERM  V0, V1, V11, V9    // V9 = V_hi (odd elements)

	// Butterfly: VA=V8(lo=a), VB=V9(hi=b), VZ=V2
	BUTTERFLY_U16(V8, V9, V2, V3, V4, V5, V6, V7, V11)

	// Reinterleave: V0=[e'0,o'0,...,e'3,o'3], V1=[e'4,o'4,...,e'7,o'7]
	VPERM  V8, V9, V13, V0   // V0 = reinterleave(lo[0..3], hi[0..3])
	VPERM  V8, V9, V15, V1   // V1 = reinterleave(lo[4..7], hi[4..7])

	// Store
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R6)(R5)

	ADD  $32, R5
	ADD  $16, R11
	BDNZ ntt_l7_loop

	RET

// GS_BUTTERFLY_U16: Gentleman-Sande butterfly.
// VA (lo) updated to sum = lo+hi (mod q); VB (hi) updated to zeta*(hi-lo) (mod q).
// diff = hi - lo + q (reduce to [0,q)); then hi_new = MUL_ZETA(zeta, diff).
// V17=prime16 (pinned), V12=packMask (pinned), V14=kBMul32, V16=kPrime32.
// Clobbers: Vt, Vtmp1, Vtmp2, Vtmp3, Vshift.
#define GS_BUTTERFLY_U16(VA, VB, VZ, Vt, Vtmp1, Vtmp2, Vtmp3, Vshift) \
	VADDUHM  VA, VB, Vt;             \
	FIELD_REDUCE_ONCE_U16(Vt, Vtmp1, Vtmp2); \
	VSUBUHM  VB, VA, VB;             \
	VADDUHM  VB, V17, VB;            \
	FIELD_REDUCE_ONCE_U16(VB, Vtmp1, Vtmp2); \
	MUL_ZETA_U16(VB, VZ, VB, Vtmp1, Vtmp2, Vtmp3, Vshift); \
	FIELD_REDUCE_ONCE_U16(VB, Vtmp1, Vtmp2); \
	VOR      Vt, Vt, VA

// internalInverseNTTPPC64LE(f *nttElement)
//
// Computes the inverse NTT in place (Gentleman-Sande, len=2..128).
// All coefficients must be in [0, q) on entry; exit in [0, q).
// Applies final scale by kInverseDegree=3303 (= 128^-1 mod q).
//
// Pinned registers (same as forward NTT):
//   R0  = 0 (always zero)
//   R4  = f pointer (base address, not advanced across layers)
//   V12 = lxvPackU32ToU16Mask
//   V14 = kBMul32 = {5039 x4}
//   V16 = kPrime32 = {3329 x4}
//   V17 = kPrime16 = {3329 x8}
//   V18 = naturalOrderMask
//   V19 = nttL6L7DeinterleaveMaskLo (reused for INTT interleave)
TEXT ·internalInverseNTTPPC64LE(SB), NOSPLIT, $0-8
	MOVD f+0(FP), R4
	MOVD $0, R0

	MOVD $kBarrettConsts<>(SB), R10
	MOVD $0, R11
	LVX  (R11)(R10), V14
	MOVD $32, R11
	LVX  (R11)(R10), V16
	MOVD $48, R11
	LVX  (R11)(R10), V17

	MOVD $lxvNaturalOrderMask<>(SB), R10
	LVX  (R0)(R10), V18

	MOVD $lxvPackU32ToU16Mask<>(SB), R10
	LVX  (R0)(R10), V12

	MOVD $nttL6L7DeinterleaveMaskLo<>(SB), R10
	LVX  (R0)(R10), V19

	// ================================================================
	// INTT Layer 6' (GS len=2): 16 iters, 4 groups per iter.
	// Reverses forward L7. Data layout same as forward L7 input.
	// Twiddle: inttTwiddleL2PrecompPPC64LE, 16 vectors of [z0,z0,z1,z1,z2,z2,z3,z3].
	// ================================================================
	MOVD $·inttTwiddleL2PrecompPPC64LE(SB), R10
	MOVD $0, R11
	MOVD R4, R5

	// Preload reinterleave masks (same masks as forward L7)
	MOVD $nttL7ReinterleaveMask0<>(SB), R12
	LVX  (R0)(R12), V13       // V13 = reinterleave mask 0
	MOVD $nttL7ReinterleaveMask1<>(SB), R12
	LVX  (R0)(R12), V15       // V15 = reinterleave mask 1
	MOVD $nttL6L7DeinterleaveMaskHi<>(SB), R7

	MOVD $16, R9
	MOVD R9, CTR
intt_l6_loop:
	// Reload hi deinterleave mask (V11 is clobbered by forward NTT; INTT doesn't use it as such,
	// but we need it for deinterleave same as forward L7)
	LVX  (R0)(R7), V11

	// Load twiddle [z0,z0,z1,z1,z2,z2,z3,z3]
	LXVD2X (R11)(R10), VS34
	VPERM  V2, V2, V18, V2

	// Load 16 elements
	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	MOVD $16, R6
	LXVD2X (R6)(R5), VS33
	VPERM  V1, V1, V18, V1

	// Deinterleave: V8=lo (even pairs), V9=hi (odd pairs)
	VPERM  V0, V1, V19, V8    // V8 = lo pairs
	VPERM  V0, V1, V11, V9    // V9 = hi pairs

	// GS butterfly: lo=sum, hi=zeta*(lo-hi)
	GS_BUTTERFLY_U16(V8, V9, V2, V3, V4, V5, V6, V7)

	// Reinterleave
	VPERM  V8, V9, V13, V0
	VPERM  V8, V9, V15, V1

	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R6)(R5)

	ADD  $32, R5
	ADD  $16, R11
	BDNZ intt_l6_loop

	// Reset R4-based pointer
	MOVD R4, R5

	// ================================================================
	// INTT Layer 5' (GS len=4): 16 iters, 2 groups per iter.
	// Reverses forward L6 (XXPERMDI-based split/repack).
	// Twiddle: inttTwiddleL4PrecompPPC64LE, [za x4, zb x4].
	// ================================================================
	MOVD $·inttTwiddleL4PrecompPPC64LE(SB), R10
	MOVD $0, R11
	MOVD R4, R5

	MOVD $16, R9
	MOVD R9, CTR
intt_l5_loop:
	LXVD2X (R11)(R10), VS34
	VPERM  V2, V2, V18, V2    // V2 = [za x4, zb x4]

	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	MOVD $16, R6
	LXVD2X (R6)(R5), VS33
	VPERM  V1, V1, V18, V1

	// Split: V_lo=[a0..a3, b0..b3], V_hi=[a4..a7, b4..b7]
	XXPERMDI VS32, VS33, $0, VS41   // V9 = V_lo
	XXPERMDI VS32, VS33, $3, VS40   // V8 = V_hi

	// GS butterfly: VA=V9(lo), VB=V8(hi), VZ=V2
	GS_BUTTERFLY_U16(V9, V8, V2, V3, V4, V5, V6, V7)

	// Repack
	XXPERMDI VS41, VS40, $0, VS32   // V0 = first 8 elems
	XXPERMDI VS41, VS40, $3, VS33   // V1 = second 8 elems

	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R6)(R5)

	ADD  $32, R5
	ADD  $16, R11
	BDNZ intt_l5_loop

	// ================================================================
	// INTT Layer 4' (GS len=8): 16 iters, 1 group per iter.
	// Reverses forward L5 (direct lo/hi load, 16-byte stride).
	// Twiddle: inttTwiddleL5PrecompPPC64LE (broadcast, 1 zeta per iter).
	// ================================================================
	MOVD $·inttTwiddleL5PrecompPPC64LE(SB), R10
	MOVD $0, R11
	MOVD R4, R5

	MOVD $16, R9
	MOVD R9, CTR
intt_l4_loop:
	LXVD2X (R11)(R10), VS40
	VPERM  V8, V8, V18, V2    // V2 = broadcast zeta

	MOVD R5, R6
	ADD  $16, R6              // hi = lo + 16

	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0    // V0 = lo
	LXVD2X (R0)(R6), VS33
	VPERM  V1, V1, V18, V1    // V1 = hi

	GS_BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7)

	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)

	ADD  $32, R5
	ADD  $16, R11
	BDNZ intt_l4_loop

	// ================================================================
	// INTT Layer 3' (GS len=16): 8 groups, 2 iters each.
	// Reverses forward L4 (8 outer x 2 inner).
	// Twiddle: inttTwiddleL4bPrecompPPC64LE (broadcast per group).
	// ================================================================
	MOVD $·inttTwiddleL4bPrecompPPC64LE(SB), R10
	MOVD $0, R11

	MOVD $8, R9
	MOVD R9, CTR
	MOVD R4, R5
intt_l3_outer:
	LXVD2X (R11)(R10), VS40
	VPERM  V8, V8, V18, V2

	MOVD R5, R6
	ADD  $32, R6              // hi = lo + 32

	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6), VS33
	VPERM  V1, V1, V18, V1
	GS_BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)

	ADD  $16, R5
	ADD  $16, R6

	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6), VS33
	VPERM  V1, V1, V18, V1
	GS_BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)

	ADD  $48, R5              // advance to next group (lo+16+48=lo+64)
	ADD  $16, R11
	BDNZ intt_l3_outer

	// ================================================================
	// INTT Layer 2' (GS len=32): 4 groups, 4 iters each.
	// Reverses forward L3 (4 groups x 4 inner iters).
	// Twiddle: inttTwiddleL3PrecompPPC64LE (broadcast per group).
	// ================================================================
	MOVD $·inttTwiddleL3PrecompPPC64LE(SB), R10
	MOVD $0, R11

	// Group 0: lo=f[0..31], hi=f[32..63]
	LXVD2X (R11)(R10), VS40
	VPERM  V8, V8, V18, V2
	MOVD R4, R5
	MOVD R4, R6
	ADD  $64, R6
	MOVD $4, R9
	MOVD R9, CTR
intt_l2g0:
	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6), VS33
	VPERM  V1, V1, V18, V1
	GS_BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)
	ADD  $16, R5
	ADD  $16, R6
	BDNZ intt_l2g0

	// Group 1: lo=f[64..95], hi=f[96..127]
	ADD  $16, R11
	LXVD2X (R11)(R10), VS40
	VPERM  V8, V8, V18, V2
	MOVD R4, R5
	ADD  $128, R5
	MOVD R5, R6
	ADD  $64, R6
	MOVD $4, R9
	MOVD R9, CTR
intt_l2g1:
	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6), VS33
	VPERM  V1, V1, V18, V1
	GS_BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)
	ADD  $16, R5
	ADD  $16, R6
	BDNZ intt_l2g1

	// Group 2: lo=f[128..159], hi=f[160..191]
	ADD  $16, R11
	LXVD2X (R11)(R10), VS40
	VPERM  V8, V8, V18, V2
	MOVD R4, R5
	ADD  $256, R5
	MOVD R5, R6
	ADD  $64, R6
	MOVD $4, R9
	MOVD R9, CTR
intt_l2g2:
	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6), VS33
	VPERM  V1, V1, V18, V1
	GS_BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)
	ADD  $16, R5
	ADD  $16, R6
	BDNZ intt_l2g2

	// Group 3: lo=f[192..223], hi=f[224..255]
	ADD  $16, R11
	LXVD2X (R11)(R10), VS40
	VPERM  V8, V8, V18, V2
	MOVD R4, R5
	ADD  $384, R5
	MOVD R5, R6
	ADD  $64, R6
	MOVD $4, R9
	MOVD R9, CTR
intt_l2g3:
	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6), VS33
	VPERM  V1, V1, V18, V1
	GS_BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)
	ADD  $16, R5
	ADD  $16, R6
	BDNZ intt_l2g3

	// ================================================================
	// INTT Layer 1' (GS len=64): 2 groups, 4 iters each.
	// Reverses forward L2 (2 outer x 8 inner, 2x-unrolled here).
	// Twiddle: inttTwiddleL2bPrecompPPC64LE.
	// ================================================================
	MOVD $·inttTwiddleL2bPrecompPPC64LE(SB), R10

	// Group 0: zeta=zetas[3] (INTT reversal), lo=f[0..63], hi=f[64..127]
	LXVD2X (R0)(R10), VS40
	VPERM  V8, V8, V18, V2
	MOVD R4, R5
	MOVD R4, R6
	ADD  $128, R6             // hi = f[64] (64 elements x 2 bytes)
	MOVD $4, R9
	MOVD R9, CTR
intt_l1g0:
	MOVD   $16, R13
	LXVD2X (R0)(R5),   VS32
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6),   VS33
	VPERM  V1, V1, V18, V1
	LXVD2X (R13)(R5),  VS41
	VPERM  V9, V9, V18, V9
	LXVD2X (R13)(R6),  VS42
	VPERM  V10, V10, V18, V10
	GS_BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)
	GS_BUTTERFLY_U16(V9, V10, V2, V3, V4, V5, V6, V7)
	VPERM  V9, V9, V18, V9
	STXVD2X VS41, (R13)(R5)
	VPERM  V10, V10, V18, V10
	STXVD2X VS42, (R13)(R6)
	ADD  $32, R5
	ADD  $32, R6
	BDNZ intt_l1g0

	// Group 1: zeta=zetas[2] (INTT reversal), lo=f[128..191], hi=f[192..255]
	MOVD $16, R11
	LXVD2X (R11)(R10), VS40
	VPERM  V8, V8, V18, V2
	MOVD R4, R5
	ADD  $256, R5             // lo = f[128]
	MOVD R5, R6
	ADD  $128, R6             // hi = f[192]
	MOVD $4, R9
	MOVD R9, CTR
intt_l1g1:
	MOVD   $16, R13
	LXVD2X (R0)(R5),   VS32
	VPERM  V0, V0, V18, V0
	LXVD2X (R0)(R6),   VS33
	VPERM  V1, V1, V18, V1
	LXVD2X (R13)(R5),  VS41
	VPERM  V9, V9, V18, V9
	LXVD2X (R13)(R6),  VS42
	VPERM  V10, V10, V18, V10
	GS_BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7)
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)
	GS_BUTTERFLY_U16(V9, V10, V2, V3, V4, V5, V6, V7)
	VPERM  V9, V9, V18, V9
	STXVD2X VS41, (R13)(R5)
	VPERM  V10, V10, V18, V10
	STXVD2X VS42, (R13)(R6)
	ADD  $32, R5
	ADD  $32, R6
	BDNZ intt_l1g1

	// ================================================================
	// INTT Layer 0' (GS len=128): 1 group, 8 iters.
	// Reverses forward L1. lo=f[0..127], hi=f[128..255].
	// Also applies final scale by kInverseDegree=3303.
	// ================================================================
	MOVD $·inttTwiddleL1PrecompPPC64LE(SB), R10
	LXVD2X (R0)(R10), VS40
	VPERM  V8, V8, V18, V2    // V2 = broadcast zeta[1]

	// Load kInverseDegree=3303 for final scale
	MOVD $·inverseDegreeVecPPC64LE(SB), R10
	LXVD2X (R0)(R10), VS40
	VPERM  V8, V8, V18, V20   // V20 = {3303 x8}

	MOVD $·inttTwiddleL1PrecompPPC64LE(SB), R10
	LXVD2X (R0)(R10), VS40
	VPERM  V8, V8, V18, V2

	MOVD $16, R9
	MOVD R9, CTR
	MOVD R4, R5               // lo pointer
	MOVD R4, R6
	ADD  $256, R6              // hi pointer = f + 256 bytes
intt_l0_loop:
	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0    // V0 = lo
	LXVD2X (R0)(R6), VS33
	VPERM  V1, V1, V18, V1    // V1 = hi

	GS_BUTTERFLY_U16(V0, V1, V2, V3, V4, V5, V6, V7)

	// Scale lo (V0) and hi (V1) by kInverseDegree=3303
	MUL_ZETA_U16(V0, V20, V3, V4, V5, V6, V7)
	FIELD_REDUCE_ONCE_U16(V3, V4, V5)
	VOR      V3, V3, V0
	MUL_ZETA_U16(V1, V20, V3, V4, V5, V6, V7)
	FIELD_REDUCE_ONCE_U16(V3, V4, V5)
	VOR      V3, V3, V1

	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R5)
	VPERM  V1, V1, V18, V1
	STXVD2X VS33, (R0)(R6)

	ADD  $16, R5
	ADD  $16, R6
	BDNZ intt_l0_loop

	RET

// internalNTTMulPPC64LE(out, lhs, rhs *nttElement)
//
// Computes out[i] = lhs[i] * rhs[i] in NTT domain (standard Barrett).
// Identical to nttMulAcc but without accumulation: out is zero-initialized.
// Same register layout as internalNTTMulAccPPC64LE, minus acc load/add.
TEXT ·internalNTTMulPPC64LE(SB), NOSPLIT, $0-24
	MOVD out+0(FP), R4
	MOVD lhs+8(FP), R5
	MOVD rhs+16(FP), R6
	MOVD $·nttGammaU32PPC64LE(SB), R7
	MOVD $0, R0

	MOVD $kBarrettConsts<>(SB), R10
	MOVD $0, R11
	LVX  (R11)(R10), V14
	MOVD $16, R11
	LVX  (R11)(R10), V15
	MOVD $32, R11
	LVX  (R11)(R10), V16
	MOVD $48, R11
	LVX  (R11)(R10), V17

	MOVD $lxvNaturalOrderMask<>(SB), R10
	LVX  (R0)(R10), V18
	MOVD $lxvPairSwapMask<>(SB), R10
	LVX  (R0)(R10), V19

	MOVD $lxvPackU32ToU16Mask<>(SB), R10
	LVX  (R0)(R10), V12

	MOVD $32, R9
	MOVD R9, CTR

nttmul_loop:
	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0

	LXVD2X (R0)(R6), VS33
	VPERM  V1, V1, V19, V2
	VPERM  V1, V1, V18, V1

	LXVD2X (R0)(R7), VS35

	VMULEUH V0, V1, V4
	VMULOUH V0, V1, V5
	VMULEUH V0, V2, V6
	VMULOUH V0, V2, V7

	BARRETT_REDUCE_U32(V4, V8, V9, V10)
	BARRETT_REDUCE_U32(V5, V8, V9, V10)
	BARRETT_REDUCE_U32(V6, V8, V9, V10)
	BARRETT_REDUCE_U32(V7, V8, V9, V10)

	VMULUWM V5, V3, V0
	BARRETT_REDUCE_U32(V0, V8, V9, V10)

	VADDUWM V4, V0, V1
	VADDUWM V6, V7, V2

	// 32-bit fast Barrett for sums
	VSPLTISW $24, V10
	VMULUWM V1, V14, V8
	VSRW    V8, V10, V8
	VMULUWM V8, V16, V9
	VSUBUWM V1, V9, V1

	VMULUWM V2, V14, V8
	VSRW    V8, V10, V8
	VMULUWM V8, V16, V9
	VSUBUWM V2, V9, V2

	// Single VPERM interleave and pack to delta uint16 in [0, 2q)
	VPERM   V1, V2, V12, V13

	// Reduce delta from [0, 2q) to [0, q) before storing
	VSUBUHM V13, V17, V8
	VCMPGTUH V17, V13, V9
	VSEL    V8, V13, V9, V13

	// Store to out (apply inverse VPERM for STXVD2X compat)
	VPERM  V13, V13, V18, V13
	STXVD2X VS45, (R0)(R4)

	ADD  $16, R4
	ADD  $16, R5
	ADD  $16, R6
	ADD  $16, R7

	BDNZ nttmul_loop

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
//   V18 = lxvNaturalOrderMask (LXVD2X -> natural uint16 order; self-inverse)
//   V19 = lxvPairSwapMask     (LXVD2X -> pair-swapped uint16 order)
//
// Per-iteration (V0-V13):
//   V0-V7: input data and intermediate products
//   V8-V10: Barrett temporaries (reused)
//   V11-V13: gamma products and delta
//
// Barrett reduce macro (inline, 7 instructions):
//   VMULOUW Vtmp1, Vin, V14   // odd x kBMul -> 64-bit
//   VMULEUW Vtmp2, Vin, V14   // even x kBMul -> 64-bit
//   VSRD Vtmp1, V15, Vtmp1    // >> 24 -> odd quotients
//   VSRD Vtmp2, V15, Vtmp2    // >> 24 -> even quotients
//   VMRGOW Vtmp2, Vtmp1, Vtmp3 // [q0,q1,q2,q3]
//   VMULUWM Vtmp3, V16, Vtmp2  // quotient x q
//   VSUBUWM Vin, Vtmp2, Vin    // remainder in [0, 2q)
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
	LVX  (R0)(R10), V12           // V12 = pack uint32->uint16 VPERM mask (pinned)

	MOVD $32, R9                  // loop counter (32 iterations x 16 bytes = 512 bytes)
	MOVD R9, CTR

nttmlacc_loop:
	// Load lhs -> natural uint16 order in V0
	LXVD2X (R0)(R5), VS32
	VPERM  V0, V0, V18, V0        // V0 = lhs natural order

	// Load rhs: pair-swapped -> V2, natural -> V1
	LXVD2X (R0)(R6), VS33        // V1 = rhs raw
	VPERM  V1, V1, V19, V2        // V2 = rhs pair-swapped (from raw V1)
	VPERM  V1, V1, V18, V1        // V1 = rhs natural order

	// Load gamma: 4 uint32 values [g_{4j},g_{4j+1},g_{4j+2},g_{4j+3}].
	// nttGammaU32PPC64LE stores [g1,g0,g3,g2] as LE uint32 per group.
	// LXVD2X byte-reversal within each 8-byte group gives [g0,g1,g2,g3]. (ok)
	LXVD2X (R0)(R7), VS35         // V3 = [g0,g1,g2,g3] as 4 uint32

	// Compute 4 pair products (each yields 4 uint32)
	VMULEUH V0, V1, V4            // V4 = [a0b0, a2b2, a4b4, a6b6] (even*even)
	VMULOUH V0, V1, V5            // V5 = [a1b1, a3b3, a5b5, a7b7] (odd*odd)
	VMULEUH V0, V2, V6            // V6 = [a0b1, a2b3, a4b5, a6b7] (even*swap_even)
	VMULOUH V0, V2, V7            // V7 = [a1b0, a3b2, a5b4, a7b6] (odd*swap_odd)

	// Barrett reduce V4 -> V_r00 in [0, 2q)
	BARRETT_REDUCE_U32(V4, V8, V9, V10)

	// Barrett reduce V5 -> V_r11 in [0, 2q)
	BARRETT_REDUCE_U32(V5, V8, V9, V10)

	// Barrett reduce V6 -> V_r01 in [0, 2q)
	BARRETT_REDUCE_U32(V6, V8, V9, V10)

	// Barrett reduce V7 -> V_r10 in [0, 2q)
	BARRETT_REDUCE_U32(V7, V8, V9, V10)

	// Gamma multiplication: VMULUWM(r11_reduced, gamma_u32) -> 4 uint32 products.
	// V5 = [a1b1_r, a3b3_r, a5b5_r, a7b7_r] as 4 uint32 in [0,q)
	// V3 = [g0,g1,g2,g3] as 4 uint32 in [0,q)
	// Product < q^2 < 2^24 -> fits in uint32. No packing needed.
	VMULUWM V5, V3, V0            // V0 = [a1b1_r*g0, a3b3_r*g1, a5b5_r*g2, a7b7_r*g3]

	// Barrett reduce V0 (gamma products) -> V_rg in [0, 2q)
	BARRETT_REDUCE_U32(V0, V8, V9, V10)

	// Even pair sums = V_r00 + V_rg (stored in V1, reusing V1=rhs)
	VADDUWM V4, V0, V1            // V1 in [0, 4q)
	// Odd pair sums = V_r01 + V_r10 (stored in V2, reusing V2=rhs_swap)
	VADDUWM V6, V7, V2            // V2 in [0, 4q)

	// 32-bit fast Barrett for sums (max product 13314 x 5039 < 2^27, fits in uint32):
	// VSPLTISW $24 creates {24,24,24,24} for VSRW (V10 is scratch, reused).
	VSPLTISW $24, V10
	VMULUWM V1, V14, V8    // V8 = V1 * kBMul (low 32 bits, no overflow)
	VSRW    V8, V10, V8    // V8 >>= 24: quotients
	VMULUWM V8, V16, V9    // V9 = quotient * prime
	VSUBUWM V1, V9, V1     // V1 in [0, 2q)

	VMULUWM V2, V14, V8
	VSRW    V8, V10, V8
	VMULUWM V8, V16, V9
	VSUBUWM V2, V9, V2     // V2 in [0, 2q)

	// Single VPERM to interleave and pack V1,V2 -> delta uint16.
	// V12 mask: selects low 2 bytes of each uint32 from V1 and V2 alternately.
	// V13=[e0,o0,e1,o1, e2,o2,e3,o3] as 8 uint16 in [0, 2q)
	VPERM   V1, V2, V12, V13

	// Load acc -> natural order in V0
	LXVD2X (R0)(R4), VS32
	VPERM  V0, V0, V18, V0        // V0 = acc natural order

	// acc += delta (delta in [0, 2q) as uint16, acc in [0, q))
	VADDUHM V0, V13, V0           // V0 in [0, 3q)

	// fieldReduceOnce acc: two passes [0,3q) -> [0,2q) -> [0,q)
	VSUBUHM V0, V17, V8
	VCMPGTUH V17, V0, V9
	VSEL    V8, V0, V9, V0        // -> [0, 2q)
	VSUBUHM V0, V17, V8
	VCMPGTUH V17, V0, V9
	VSEL    V8, V0, V9, V0        // -> [0, q)

	// Store back: apply inverse VPERM (V18 is self-inverse) then STXVD2X
	VPERM  V0, V0, V18, V0
	STXVD2X VS32, (R0)(R4)

	// Advance pointers
	ADD  $16, R4                  // acc: next 8 coefficients
	ADD  $16, R5                  // lhs: next 8 coefficients
	ADD  $16, R6                  // rhs: next 8 coefficients
	ADD  $16, R7                  // gamma: 4 uint32 = 16 bytes per iteration

	BDNZ nttmlacc_loop

	RET

// ringCompressAndEncode1PPC64LE computes ByteEncode_1(Compress_1(f)).
// compress(x, 1) = 1 if 833 <= x <= 2496, else 0.
// Each output byte packs 8 coefficients as bits (bit 0 = coeff 0, bit 1 = coeff 1, ...).
// func ringCompressAndEncode1PPC64LE(out []byte, f *ringElement)
TEXT ·ringCompressAndEncode1PPC64LE(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R4  // out pointer
	MOVD f+24(FP), R5        // f pointer
	MOVD $833, R8            // lower threshold (inclusive)
	MOVD $2497, R9           // upper threshold (exclusive)
	MOVD $32, R10            // 32 bytes output (256 coefficients / 8)

compress1_outer:
	MOVD $0, R3              // accumulated byte
	// 8 coefficients -> 1 byte
	MOVHZ (R5), R6; ADD $2, R5
	CMP R6, R8; BLT compress1_b0; CMP R6, R9; BGE compress1_b0; OR $1, R3
compress1_b0:
	MOVHZ (R5), R6; ADD $2, R5
	CMP R6, R8; BLT compress1_b1; CMP R6, R9; BGE compress1_b1; OR $2, R3
compress1_b1:
	MOVHZ (R5), R6; ADD $2, R5
	CMP R6, R8; BLT compress1_b2; CMP R6, R9; BGE compress1_b2; OR $4, R3
compress1_b2:
	MOVHZ (R5), R6; ADD $2, R5
	CMP R6, R8; BLT compress1_b3; CMP R6, R9; BGE compress1_b3; OR $8, R3
compress1_b3:
	MOVHZ (R5), R6; ADD $2, R5
	CMP R6, R8; BLT compress1_b4; CMP R6, R9; BGE compress1_b4; OR $16, R3
compress1_b4:
	MOVHZ (R5), R6; ADD $2, R5
	CMP R6, R8; BLT compress1_b5; CMP R6, R9; BGE compress1_b5; OR $32, R3
compress1_b5:
	MOVHZ (R5), R6; ADD $2, R5
	CMP R6, R8; BLT compress1_b6; CMP R6, R9; BGE compress1_b6; OR $64, R3
compress1_b6:
	MOVHZ (R5), R6; ADD $2, R5
	CMP R6, R8; BLT compress1_b7; CMP R6, R9; BGE compress1_b7; OR $128, R3
compress1_b7:
	MOVB R3, (R4)            // store byte
	ADD $1, R4
	ADD $-1, R10
	BNE compress1_outer
	RET

// ringCompressAndEncode4PPC64LE computes ByteEncode_4(Compress_4(f)).
// compress(x, 4) = round(x * 16 / q) mod 16  [q=3329]
// Output: 128 bytes, each packing 2 nibbles (coeff[2i] | coeff[2i+1]<<4).
// Uses scalar formula: c = ((x << 4) + 1664) * 1290168 >> 32 & 0xF
// func ringCompressAndEncode4PPC64LE(out []byte, f *ringElement)
TEXT ·ringCompressAndEncode4PPC64LE(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R4  // out pointer
	MOVD f+24(FP), R5        // f pointer
	MOVD $1290168, R9        // magic multiplier for /q via mulhigh32
	MOVD $1664, R11          // bias = q/2 = 3329/2 rounded down = 1664
	MOVD $15, R12            // mask for 4-bit result
	MOVD $128, R10           // 128 bytes output

compress4_loop:
	// Load two uint16 coefficients
	MOVHZ (R5), R6; ADD $2, R5   // a
	MOVHZ (R5), R7; ADD $2, R5   // b
	// compress(a, 4): ca = ((a << 4) + 1664) * 1290168 >> 32 & 0xF
	SLD $4, R6                    // a << 4
	ADD R11, R6, R6              // + 1664
	MULLD R9, R6, R6             // * 1290168
	SRD $32, R6                  // >> 32
	AND R12, R6                  // & 0xF
	// compress(b, 4): cb = ((b << 4) + 1664) * 1290168 >> 32 & 0xF
	SLD $4, R7
	ADD R11, R7, R7
	MULLD R9, R7, R7
	SRD $32, R7
	AND R12, R7
	SLD $4, R7                   // cb << 4
	OR R6, R7                    // ca | (cb << 4)
	MOVB R7, (R4)               // store byte
	ADD $1, R4
	ADD $-1, R10
	BNE compress4_loop
	RET

// ringDecodeAndDecompress4PPC64LE computes Decompress_4(ByteDecode_4(b)).
// Each input byte has two 4-bit nibbles: c_lo = byte & 0xF, c_hi = byte >> 4.
// decompress(y, 4) = round(y * q / 16) = ((y * q) >> 4) + ((y * q >> 3) & 1)
// func ringDecodeAndDecompress4PPC64LE(b *[encodingSize4]byte, f *ringElement)
TEXT ·ringDecodeAndDecompress4PPC64LE(SB), NOSPLIT, $0-16
	MOVD b+0(FP), R4         // input byte pointer
	MOVD f+8(FP), R5         // output ringElement pointer
	MOVD $3329, R9           // q
	MOVD $15, R11            // nibble mask
	MOVD $128, R10           // 128 input bytes

decompress4_loop:
	MOVBZ (R4), R6           // load byte
	ADD $1, R4
	// low nibble: c_lo = byte & 0xF
	AND R11, R6, R7          // c_lo
	// decompress(c_lo, 4): ((c_lo * q) >> 4) + round bit
	MULLD R9, R7, R7         // c_lo * q
	SRD $3, R7, R8           // >> 3
	ANDCC $1, R8, R8         // & 1 (round bit)
	SRD $4, R7               // c_lo * q >> 4
	ADD R8, R7               // + round bit
	MOVH R7, (R5)            // store uint16 result
	ADD $2, R5
	// high nibble: c_hi = byte >> 4
	SRD $4, R6               // c_hi
	MULLD R9, R6, R6         // c_hi * q
	SRD $3, R6, R8           // >> 3
	ANDCC $1, R8, R8         // round bit
	SRD $4, R6               // c_hi * q >> 4
	ADD R8, R6               // + round bit
	MOVH R6, (R5)
	ADD $2, R5
	ADD $-1, R10
	BNE decompress4_loop
	RET

// ringCompressAndEncode5PPC64LE computes ByteEncode_5(Compress_5(f)).
// compress(x, 5) = round(x * 32 / q) mod 32
// Output: 160 bytes, each 5-bit value packed (8 values per 5 bytes).
// Uses scalar formula: c = ((x << 5) + 1664) * 1290168 >> 32 & 0x1F
// Uses a 40-bit accumulator split across two registers to avoid callee-saved regs.
// func ringCompressAndEncode5PPC64LE(out []byte, f *ringElement)
TEXT ·ringCompressAndEncode5PPC64LE(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R4  // out pointer
	MOVD f+24(FP), R5        // f pointer
	MOVD $1290168, R9        // magic multiplier
	MOVD $1664, R11          // bias = 1664
	MOVD $31, R12            // mask for 5-bit result (0x1F)
	MOVD $32, R10            // 32 iterations: 8 coefficients × 5 bits = 5 bytes per iter

// Compress a single coefficient c and return it in R6, using R7 as scratch.
// Inputs: coeff in R3 (loaded before macro), R9=multiplier, R11=bias, R12=mask
// Output: compressed 5-bit value in R6
// Usage: load R3 from memory, then:
//   SLD $5, R3; ADD R11, R3; MULLD R9, R3; SRD $32, R3; AND R12, R3
//   → compressed value in R3

compress5_loop:
	// Process 8 coefficients → 40-bit packed value → 5 bytes
	// Build 40-bit value in two 64-bit regs: R6=bits[39:0] (we only use 40 bits)
	// Since 40 < 64, a single register suffices.

	// c0
	MOVHZ (R5), R3; ADD $2, R5
	SLD $5, R3; ADD R11, R3; MULLD R9, R3; SRD $32, R3; AND R12, R3
	// c1
	MOVHZ (R5), R6; ADD $2, R5
	SLD $5, R6; ADD R11, R6; MULLD R9, R6; SRD $32, R6; AND R12, R6
	// Accumulate bits[9:0] = c0 | c1<<5
	SLD $5, R6, R7; OR R3, R7          // bits[9:0]

	// c2
	MOVHZ (R5), R3; ADD $2, R5
	SLD $5, R3; ADD R11, R3; MULLD R9, R3; SRD $32, R3; AND R12, R3
	// c3
	MOVHZ (R5), R6; ADD $2, R5
	SLD $5, R6; ADD R11, R6; MULLD R9, R6; SRD $32, R6; AND R12, R6
	// bits[24:10] = c2<<10 | c3<<15
	SLD $10, R3, R8; OR R7, R8         // |= c2<<10
	SLD $15, R6, R3; OR R8, R3         // |= c3<<15  → R3=bits[24:0]

	// c4
	MOVHZ (R5), R6; ADD $2, R5
	SLD $5, R6; ADD R11, R6; MULLD R9, R6; SRD $32, R6; AND R12, R6
	// c5
	MOVHZ (R5), R7; ADD $2, R5
	SLD $5, R7; ADD R11, R7; MULLD R9, R7; SRD $32, R7; AND R12, R7
	// bits[34:20] = c4<<20 | c5<<25
	SLD $20, R6, R8; OR R3, R8         // |= c4<<20  → R8=bits[24:0]|c4<<20
	SLD $25, R7, R3; OR R8, R3         // |= c5<<25  → R3=bits[29:0]

	// c6
	MOVHZ (R5), R6; ADD $2, R5
	SLD $5, R6; ADD R11, R6; MULLD R9, R6; SRD $32, R6; AND R12, R6
	// c7
	MOVHZ (R5), R7; ADD $2, R5
	SLD $5, R7; ADD R11, R7; MULLD R9, R7; SRD $32, R7; AND R12, R7
	// bits[39:30] = c6<<30 | c7<<35
	SLD $30, R6, R8; OR R3, R8         // |= c6<<30
	SLD $35, R7, R3; OR R8, R3         // |= c7<<35  → R3=bits[39:0] (40 bits)

	// Store 5 bytes from R3
	MOVB R3, 0(R4)
	SRD $8, R3, R6; MOVB R6, 1(R4)
	SRD $16, R3, R6; MOVB R6, 2(R4)
	SRD $24, R3, R6; MOVB R6, 3(R4)
	SRD $32, R3, R6; MOVB R6, 4(R4)
	ADD $5, R4
	ADD $-1, R10
	BNE compress5_loop
	RET

// ringDecodeAndDecompress5PPC64LE computes Decompress_5(ByteDecode_5(b)).
// Each 5-byte block contains 8 packed 5-bit values.
// decompress(y, 5) = ((y * q) >> 5) + ((y * q >> 4) & 1)
// Processes 1 coefficient at a time to minimize register pressure.
// func ringDecodeAndDecompress5PPC64LE(b *[encodingSize5]byte, f *ringElement)
TEXT ·ringDecodeAndDecompress5PPC64LE(SB), NOSPLIT, $0-16
	MOVD b+0(FP), R4         // input pointer
	MOVD f+8(FP), R5         // output pointer
	MOVD $3329, R9           // q
	MOVD $31, R12            // 5-bit mask (0x1F)
	MOVD $32, R10            // 32 iterations (8 coefficients per iter = 5 bytes)

decompress5_loop:
	// Load 5 bytes and build 40-bit value in R3
	MOVBZ 0(R4), R3
	MOVBZ 1(R4), R6; SLD $8, R6; OR R3, R6
	MOVBZ 2(R4), R3; SLD $16, R3; OR R6, R3
	MOVBZ 3(R4), R6; SLD $24, R6; OR R3, R6
	MOVBZ 4(R4), R3; SLD $32, R3; OR R6, R3   // R3 = 40-bit value
	ADD $5, R4

	// Extract and decompress 8 x 5-bit values from R3
	// Macro: extract bits [pos+4:pos] from R3, decompress, store
#define DECOMP5(shift) \
	SRD $shift, R3, R6; \
	AND R12, R6;         \
	MULLD R9, R6;        \
	SRD $4, R6, R7; ANDCC $1, R7, R7; \
	SRD $5, R6;          \
	ADD R7, R6;           \
	MOVH R6, (R5);        \
	ADD $2, R5

	DECOMP5(0)
	DECOMP5(5)
	DECOMP5(10)
	DECOMP5(15)
	DECOMP5(20)
	DECOMP5(25)
	DECOMP5(30)
	DECOMP5(35)
#undef DECOMP5
	ADD $-1, R10
	BNE decompress5_loop
	RET

// ringCompressAndEncode10PPC64LE computes ByteEncode_10(Compress_10(f)).
// compress(x, 10) = round(x * 1024 / q) mod 1024
// 4 coefficients pack into 5 bytes: 40 bits total.
// Uses scalar formula: c = ((x << 10) + 1664) * 1290168 >> 32 & 0x3FF
// All registers used are R3-R12 only (volatile).
// func ringCompressAndEncode10PPC64LE(out []byte, f *ringElement)
TEXT ·ringCompressAndEncode10PPC64LE(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R4  // out pointer
	MOVD f+24(FP), R5        // f pointer
	MOVD $1290168, R9        // magic multiplier
	MOVD $1664, R11          // bias
	MOVD $1023, R12          // 10-bit mask (0x3FF)
	MOVD $64, R10            // 64 iterations: 4 coefficients → 5 bytes each

compress10_loop:
	MOVHZ (R5), R3; ADD $2, R5    // load c0
	MOVHZ (R5), R6; ADD $2, R5    // load c1
	MOVHZ (R5), R7; ADD $2, R5    // load c2
	MOVHZ (R5), R8; ADD $2, R5    // load c3

	// compress(ci, 10): ((ci << 10) + 1664) * 1290168 >> 32 & 0x3FF
	SLD $10, R3; ADD R11, R3; MULLD R9, R3; SRD $32, R3; AND R12, R3  // c0 → R3
	SLD $10, R6; ADD R11, R6; MULLD R9, R6; SRD $32, R6; AND R12, R6  // c1 → R6
	SLD $10, R7; ADD R11, R7; MULLD R9, R7; SRD $32, R7; AND R12, R7  // c2 → R7
	SLD $10, R8; ADD R11, R8; MULLD R9, R8; SRD $32, R8; AND R12, R8  // c3 → R8

	// After compress: c0=R3, c1=R6, c2=R7, c3=R8 (all 10-bit values)
	// Pack into 40-bit value x = c0 | c1<<10 | c2<<20 | c3<<30
	SLD $10, R6; OR R3, R6    // R6 = c0 | c1<<10
	SLD $20, R7, R3; OR R6, R3 // R3 = c0|c1<<10|c2<<20 (but SLD has already shifted R7!)
	// Wait: SLD $20, R7 shifts R7's value by 20. But we already have R7=c2.
	// Then OR R6, R3 with R3=0 would fail. Let me use R3 as dest properly.
	// Actually: SLD $20, R7, R3 means R3 = R7 << 20. Then OR R6, R3 means R3 |= R6.
	// But R6 = c0|c1<<10 and R3 = c2<<20, so OR R6, R3 → R3 = c0|c1<<10|c2<<20. Correct.
	SLD $30, R8, R8; OR R3, R8  // R8 = c0|c1<<10|c2<<20|c3<<30 (40-bit)

	// Store 5 bytes
	MOVB R8, 0(R4)
	SRD $8, R8, R3; MOVB R3, 1(R4)
	SRD $16, R8, R3; MOVB R3, 2(R4)
	SRD $24, R8, R3; MOVB R3, 3(R4)
	SRD $32, R8, R3; MOVB R3, 4(R4)
	ADD $5, R4
	ADD $-1, R10
	BNE compress10_loop
	RET

// ringCompressAndEncode11PPC64LE computes ByteEncode_11(Compress_11(f)).
// compress(x, 11) = round(x * 2048 / q) mod 2048
// 8 coefficients pack into 11 bytes (88 bits).
// Uses scalar formula: c = ((x << 11) + 1664) * 1290168 >> 32 & 0x7FF
// Strategy: build two 44-bit halves (c0-c3 and c4-c7) in R3 and R6, then pack.
// func ringCompressAndEncode11PPC64LE(out []byte, f *ringElement)
TEXT ·ringCompressAndEncode11PPC64LE(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R4  // out pointer
	MOVD f+24(FP), R5        // f pointer
	MOVD $1290168, R9        // magic multiplier
	MOVD $1664, R11          // bias
	MOVD $2047, R12          // 11-bit mask (0x7FF)
	MOVD $32, R10            // 32 iterations: 8 coefficients → 11 bytes each

compress11_loop:
	// Process first 4 coefficients → R3 (44-bit value: c0|c1<<11|c2<<22|c3<<33)
	MOVHZ (R5), R3;  ADD $2, R5
	SLD $11, R3; ADD R11, R3; MULLD R9, R3; SRD $32, R3; AND R12, R3   // c0
	MOVHZ (R5), R6;  ADD $2, R5
	SLD $11, R6; ADD R11, R6; MULLD R9, R6; SRD $32, R6; AND R12, R6   // c1
	SLD $11, R6, R7; OR R3, R7             // R7 = c0 | c1<<11
	MOVHZ (R5), R3;  ADD $2, R5
	SLD $11, R3; ADD R11, R3; MULLD R9, R3; SRD $32, R3; AND R12, R3   // c2
	SLD $22, R3, R8; OR R7, R8             // R8 = c0|c1<<11|c2<<22
	MOVHZ (R5), R3;  ADD $2, R5
	SLD $11, R3; ADD R11, R3; MULLD R9, R3; SRD $32, R3; AND R12, R3   // c3
	SLD $33, R3, R6; OR R8, R6             // R6 = lo = c0|c1<<11|c2<<22|c3<<33 (44-bit)

	// Process second 4 coefficients → R3 (44-bit value: c4|c5<<11|c6<<22|c7<<33)
	MOVHZ (R5), R3;  ADD $2, R5
	SLD $11, R3; ADD R11, R3; MULLD R9, R3; SRD $32, R3; AND R12, R3   // c4
	MOVHZ (R5), R7;  ADD $2, R5
	SLD $11, R7; ADD R11, R7; MULLD R9, R7; SRD $32, R7; AND R12, R7   // c5
	SLD $11, R7, R8; OR R3, R8             // R8 = c4 | c5<<11
	MOVHZ (R5), R3;  ADD $2, R5
	SLD $11, R3; ADD R11, R3; MULLD R9, R3; SRD $32, R3; AND R12, R3   // c6
	SLD $22, R3, R7; OR R8, R7             // R7 = c4|c5<<11|c6<<22
	MOVHZ (R5), R3;  ADD $2, R5
	SLD $11, R3; ADD R11, R3; MULLD R9, R3; SRD $32, R3; AND R12, R3   // c7
	SLD $33, R3, R8; OR R7, R8             // R8 = hi = c4|c5<<11|c6<<22|c7<<33 (44-bit)

	// Now R6=lo (bits 0-43), R8=hi (bits 44-87 of the 88-bit stream)
	// Store 11 bytes:
	// byte0-4: bits[39:0] of lo → 5 bytes
	// byte5: lo[43:40] | hi[3:0]<<4  (crossover)
	// byte6-10: hi[43:4] → 5 bytes (right-shifted by 4)
	MOVB R6, 0(R4)
	SRD $8, R6, R3; MOVB R3, 1(R4)
	SRD $16, R6, R3; MOVB R3, 2(R4)
	SRD $24, R6, R3; MOVB R3, 3(R4)
	SRD $32, R6, R3; MOVB R3, 4(R4)
	// byte5 = lo[43:40] | hi[3:0]<<4
	SRD $40, R6, R3                        // lo>>40 (4 bits: c3[10:7])
	SLD $4, R8, R7; OR R3, R7             // | hi<<4
	MOVB R7, 5(R4)
	// byte6-10 = hi>>4 (40 bits = hi[43:4])
	SRD $4, R8, R3; MOVB R3, 6(R4)
	SRD $12, R8, R3; MOVB R3, 7(R4)
	SRD $20, R8, R3; MOVB R3, 8(R4)
	SRD $28, R8, R3; MOVB R3, 9(R4)
	SRD $36, R8, R3; MOVB R3, 10(R4)
	ADD $11, R4
	ADD $-1, R10
	BNE compress11_loop
	RET

// decodeAndDecompressU10PPC64LE decodes multiple ring elements from ByteEncode_10 format.
// Each ring element is 320 bytes (256 coefficients × 10 bits / 8 = 320 bytes).
// decompress(y, 10) = ((y * q) >> 10) + ((y * q >> 9) & 1)
// Uses only R3-R12 (volatile registers).
// func decodeAndDecompressU10PPC64LE(dst []ringElement, c []byte)
TEXT ·decodeAndDecompressU10PPC64LE(SB), NOSPLIT, $0-48
	MOVD dst_base+0(FP), R4  // dst ringElement slice base
	MOVD dst_len+8(FP), R10  // number of ring elements
	MOVD c_base+24(FP), R5   // input bytes pointer
	MOVD $3329, R9            // q
	MOVD $1023, R12           // 10-bit mask

	// For each ring element, decode 320 bytes into 256 uint16 coefficients
	// Each 5-byte block → 4 coefficients (10 bits each)
decode_u10_elem:
	MOVD $64, R11            // 64 groups of 4 coefficients

decode_u10_group:
	// Build 40-bit x from 5 bytes in R3
	MOVBZ 0(R5), R3
	MOVBZ 1(R5), R6; SLD $8, R6; OR R3, R6
	MOVBZ 2(R5), R3; SLD $16, R3; OR R6, R3
	MOVBZ 3(R5), R6; SLD $24, R6; OR R3, R6
	MOVBZ 4(R5), R3; SLD $32, R3; OR R6, R3  // R3 = 40-bit x
	ADD $5, R5

	// Extract 4 x 10-bit values and decompress each using a macro
	// Macro: extract x>>(shift) & 0x3FF into R6, decompress, store to (R4)
#define DECOMP10(shift) \
	SRD $shift, R3, R6; AND R12, R6; \
	MULLD R9, R6;        \
	SRD $9, R6, R7; ANDCC $1, R7, R7; \
	SRD $10, R6;         \
	ADD R7, R6;           \
	MOVH R6, (R4);        \
	ADD $2, R4

	DECOMP10(0)
	DECOMP10(10)
	DECOMP10(20)
	DECOMP10(30)
#undef DECOMP10

	ADD $-1, R11
	BNE decode_u10_group
	ADD $-1, R10
	BNE decode_u10_elem
	RET

// decodeAndDecompressU11PPC64LE decodes multiple ring elements from ByteEncode_11 format.
// Each ring element is 352 bytes (256 coefficients × 11 bits / 8 = 352 bytes).
// decompress(y, 11) = ((y * q) >> 11) + ((y * q >> 10) & 1)
// Uses only R3-R12 (volatile registers).
// 11 bytes → 2 registers: R6 = bytes[0..7] (64-bit LE), R7 = bytes[8..10] (24-bit).
// func decodeAndDecompressU11PPC64LE(dst []ringElement, c []byte)
TEXT ·decodeAndDecompressU11PPC64LE(SB), NOSPLIT, $0-48
	MOVD dst_base+0(FP), R4  // dst ringElement slice base
	MOVD dst_len+8(FP), R10  // number of ring elements
	MOVD c_base+24(FP), R5   // input bytes pointer
	MOVD $3329, R9            // q
	MOVD $2047, R12           // 11-bit mask

decode_u11_elem:
	MOVD $32, R11            // 32 groups of 8 coefficients

decode_u11_group:
	// Build 64-bit x_lo from bytes[0..7] into R6
	MOVBZ 0(R5), R6
	MOVBZ 1(R5), R3; SLD $8, R3; OR R6, R3
	MOVBZ 2(R5), R6; SLD $16, R6; OR R3, R6
	MOVBZ 3(R5), R3; SLD $24, R3; OR R6, R3
	MOVBZ 4(R5), R6; SLD $32, R6; OR R3, R6
	MOVBZ 5(R5), R3; SLD $40, R3; OR R6, R3
	MOVBZ 6(R5), R6; SLD $48, R6; OR R3, R6
	MOVBZ 7(R5), R3; SLD $56, R3; OR R6, R3   // R3 = x_lo = bytes[0..7]

	// Build 24-bit x_hi from bytes[8..10] into R6
	MOVBZ 8(R5), R6
	MOVBZ 9(R5), R7; SLD $8, R7; OR R6, R7
	MOVBZ 10(R5), R6; SLD $16, R6; OR R7, R6  // R6 = x_hi = bytes[8..10]
	ADD $11, R5

	// Now R3=x_lo (64-bit), R6=x_hi (24-bit)
	// Extract 8 x 11-bit values:
	// c0..c4 = x_lo >> (0,11,22,33,44) & 0x7FF
	// c5 = (x_lo>>55) | (x_hi<<9) & 0x7FF  [x_lo has 1 bit of c5, x_hi has 10 bits]
	// c6 = x_hi>>2 & 0x7FF
	// c7 = x_hi>>13 & 0x7FF
	// Decompress each immediately to minimize register pressure.
#define DECOMP11_LO(shift) \
	SRD $shift, R3, R8; AND R12, R8; \
	MULLD R9, R8;         \
	SRD $10, R8, R7; ANDCC $1, R7, R7; \
	SRD $11, R8;          \
	ADD R7, R8;            \
	MOVH R8, (R4);         \
	ADD $2, R4

	DECOMP11_LO(0)
	DECOMP11_LO(11)
	DECOMP11_LO(22)
	DECOMP11_LO(33)
	DECOMP11_LO(44)

	// c5: (x_lo>>55) | (x_hi<<9) & 0x7FF
	SRD $55, R3, R8; SLD $9, R6, R7; OR R8, R7; AND R12, R7
	MULLD R9, R7
	SRD $10, R7, R8; ANDCC $1, R8, R8
	SRD $11, R7
	ADD R8, R7
	MOVH R7, (R4); ADD $2, R4

#define DECOMP11_HI(shift) \
	SRD $shift, R6, R8; AND R12, R8; \
	MULLD R9, R8;         \
	SRD $10, R8, R7; ANDCC $1, R7, R7; \
	SRD $11, R8;          \
	ADD R7, R8;            \
	MOVH R8, (R4);         \
	ADD $2, R4

	DECOMP11_HI(2)
	DECOMP11_HI(13)
#undef DECOMP11_LO
#undef DECOMP11_HI

	ADD $-1, R11
	BNE decode_u11_group
	ADD $-1, R10
	BNE decode_u11_elem
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
