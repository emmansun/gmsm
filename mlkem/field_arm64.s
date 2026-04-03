// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// ── Constants ────────────────────────────────────────────────────────────────
//
// q        = 3329
// qNegInv  = 3327   (-q⁻¹ mod 2¹⁶)
// one      = 1
// rr       = 1353   (r² mod q; MontMul(x, rr) converts Montgomery→standard)
// scale1441= 1441   (128⁻¹·r² mod q; INTT final scale)
//
// Pinned NEON registers throughout every function:
//   V31.H8 = broadcast(3329)   q
//   V30.H8 = broadcast(3327)   qNegInv
//   V29.H8 = broadcast(1)      one
//   V28.H8 = zero               (cleared via VEOR)
//
// ── NEON Montgomery multiply (8 × int16) ─────────────────────────────────────
//
// MONT_MUL uses WORD-encoded instructions for opcodes that Go arm64 asm does
// not expose (MUL/UMULL/UMULL2/SHRN/SHRN2 for integer vectors).
//
// Fixed-register core:
//   input  : V0.8H (a), V1.8H (z)
//   output : V2.8H
//   clobber: V20..V24
//
// Step 1:  lo = (a * z) mod 2¹⁶    WORD(MUL)
// Step 2:  hi = (a * z) >> 16      WORD(UMULL/UMULL2/SHRN/SHRN2)
// Step 3:  t  = lo * qNegInv mod 2¹⁶ WORD(MUL)
// Step 4:  correction = (t * q) >> 16 WORD(UMULL/UMULL2/SHRN/SHRN2)
// Step 5:  raw = hi + correction       VADD
// Step 6:  lo==0 edge: raw += (lo!=0) VCMEQ / VADD / VADD
// Step 7:  reduce once                VSUB / VUSHR / VSUB / VAND / VADD
//
// Note on Go arm64 asm operand order for 3-register ops:
//   INSTRUCTION Vn.type, Vm.type, Vd.type  -> Vd = Vm op Vn
// Tmp regs: V20=lo, V21=hi, V22=t, V23=corr, V24=mask
//
// Fixed-register montgomery core: V0,V1 -> VOUT (parameter).
// WORD opcodes (validated from ARM64 encoding):
//   0x4E619C14: MUL   V20.8H, V0.8H, V1.8H
//   0x2E61C015: UMULL V21.4S, V0.4H, V1.4H
//   0x6E61C016: UMULL2 V22.4S, V0.8H, V1.8H
//   0x0F1086B5: SHRN  V21.4H, V21.4S, #16
//   0x4F1086D5: SHRN2 V21.8H, V22.4S, #16
//   0x4E7E9E96: MUL   V22.8H, V20.8H, V30.8H
//   0x2E7FC2D7: UMULL V23.4S, V22.4H, V31.4H
//   0x6E7FC2D8: UMULL2 V24.4S, V22.8H, V31.8H
//   0x0F1086F7: SHRN  V23.4H, V23.4S, #16
//   0x4F108717: SHRN2 V23.8H, V24.4S, #16
#define MONT_MUL_FIXED(VOUT) \
	WORD $0x4E619C14                        \ // OPCODE: MUL   V20.8H, V0.8H, V1.8H
	WORD $0x2E61C015                        \ // OPCODE: UMULL V21.4S, V0.4H, V1.4H
	WORD $0x6E61C016                        \ // OPCODE: UMULL2 V22.4S, V0.8H, V1.8H
	WORD $0x0F1086B5                        \ // OPCODE: SHRN  V21.4H, V21.4S, #16
	WORD $0x4F1086D5                        \ // OPCODE: SHRN2 V21.8H, V22.4S, #16
	WORD $0x4E7E9E96                        \ // OPCODE: MUL   V22.8H, V20.8H, V30.8H
	WORD $0x2E7FC2D7                        \ // OPCODE: UMULL V23.4S, V22.4H, V31.4H
	WORD $0x6E7FC2D8                        \ // OPCODE: UMULL2 V24.4S, V22.8H, V31.8H
	WORD $0x0F1086F7                        \ // OPCODE: SHRN  V23.4H, V23.4S, #16
	WORD $0x4F108717                        \ // OPCODE: SHRN2 V23.8H, V24.4S, #16
	VADD   V21.H8, V23.H8, VOUT.H8          \ // raw = hi + correction
	VCMEQ  V20.H8, V28.H8, V24.H8           \ // 0xFFFF where lo==0
	VADD   V29.H8, V24.H8, V24.H8           \ // 0 where lo==0, else 1
	VADD   VOUT.H8, V24.H8, VOUT.H8         \ // raw += (lo!=0)
	VSUB   V31.H8, VOUT.H8, V20.H8          \ // try = raw - q
	VUSHR  $15, V20.H8, V24.H8              \ // 1 if underflow, else 0
	VSUB   V24.H8, V28.H8, V24.H8           \ // 0xFFFF if underflow, else 0
	VAND   V31.B16, V24.B16, V24.B16        \ // q if underflow, else 0
	VADD   V20.H8, V24.H8, VOUT.H8           // result in VOUT

#define MONT_MUL(VA, VZ, VOUT) \
	VMOV   VA.B16, V0.B16                    \
	VMOV   VZ.B16, V1.B16                    \
	MONT_MUL_FIXED(VOUT)

// Fast-path when inputs are already in fixed MONT_MUL registers.
#define MONT_MUL_V0_V1(VOUT) \
	MONT_MUL_FIXED(VOUT)

// Fast-path when multiplicand is already in V0; only load the zeta/input into V1.
#define MONT_MUL_V0_VZ(VZ, VOUT) \
	VMOV   VZ.B16, V1.B16                    \
	MONT_MUL_FIXED(VOUT)

// Corrected fieldReduceOnce (input in [0,2q), output in [0,q)):
//   try = Vx - q; if try < 0: Vx stays; else Vx = try
// Inlined version of the sequence. V24 is clobbered.
#define REDUCE_ONCE(VX) \
	VSUB   V31.H8, VX.H8, V20.H8      \ // try = VX - q
	VUSHR  $15, V20.H8, V24.H8        \ // 1 if underflow, else 0
	VSUB   V24.H8, V28.H8, V24.H8     \ // 0xFFFF if underflow, else 0
	VAND   V31.B16, V24.B16, V24.B16  \ // q if underflow, else 0
	VADD   V20.H8, V24.H8, VX.H8       // VX = try + q_if_underflow

// Cooley-Tukey butterfly:
//   VA' = fieldReduceOnce(VA + t)  where t = MontMul(VZ, VB)
//   VB' = fieldSub(VA_old, t)
// V25 holds VA_old, V26 holds t.
// Clobbers: V20..V26.
#define BUTTERFLY(VA, VB, VZ) \
	VMOV   VA.B16, V25.B16            \ // save VA
	MONT_MUL(VB, VZ, V26)             \ // t = MontMul(VZ, VB) → V26
	VADD   V25.H8, V26.H8, VA.H8      \ // VA = VA_old + t
	VSUB   V31.H8, VA.H8, V20.H8      \ // try = VA - q → V20
	VUSHR  $15, V20.H8, V24.H8        \ // 1 if underflow, else 0
	VSUB   V24.H8, V28.H8, V24.H8     \ // 0xFFFF if underflow
	VAND   V31.B16, V24.B16, V24.B16  \ // q if underflow
	VADD   V20.H8, V24.H8, VA.H8      \ // VA = try + correction
	VSUB   V26.H8, V25.H8, VB.H8      \ // VB = VA_old - t  (V25-V26)
	VUSHR  $15, VB.H8, V24.H8         \ // 1 if negative, else 0
	VSUB   V24.H8, V28.H8, V24.H8     \ // 0xFFFF if negative
	VAND   V31.B16, V24.B16, V24.B16  \ // q if negative
	VADD   VB.H8, V24.H8, VB.H8        // VB += q if negative

// Gentleman-Sande butterfly:
//   VA' = fieldReduceOnce(VA + VB)
//   VB' = MontMul(VZ, fieldSub(VB, VA_old))
// V25 holds VA_old. Clobbers: V20..V26.
#define INTT_BUTTERFLY(VA, VB, VZ) \
	VMOV   VA.B16, V25.B16            \ // save VA_old
	VADD   VA.H8, VB.H8, VA.H8        \ // VA = VA_old + VB
	VSUB   V31.H8, VA.H8, V20.H8      \ // try = VA - q → V20
	VUSHR  $15, V20.H8, V24.H8        \ // 1 if underflow, else 0
	VSUB   V24.H8, V28.H8, V24.H8     \ // 0xFFFF if underflow
	VAND   V31.B16, V24.B16, V24.B16  \ // q if underflow
	VADD   V20.H8, V24.H8, VA.H8      \ // VA = try + correction
	VSUB   V25.H8, VB.H8, VB.H8       \ // diff = VB - VA_old  (VB=VB-V25)
	VUSHR  $15, VB.H8, V24.H8         \ // 1 if negative, else 0
	VSUB   V24.H8, V28.H8, V24.H8     \ // 0xFFFF if negative
	VAND   V31.B16, V24.B16, V24.B16  \ // q if negative
	VADD   VB.H8, V24.H8, VB.H8       \ // fieldSub: add q if negative
	VMOV   VA.B16, V25.B16            \ // save VA' before MONT_MUL clobbers V0
	MONT_MUL(VB, VZ, VB)              \ // VB = MontMul(VZ, diff) — clobbers VA's reg (V0)
	VMOV   V25.B16, VA.B16             // restore VA'

// ── Level-load macros (16 bytes = 8 × int16 per NEON vector) ──────────────────
//
// Each AVX2 macro handles 32 bytes (16 × int16).
// Each NEON version handles 16 bytes (8 × int16).
// Two NEON invocations → one AVX2 worth.
//
// nttL0: Layer len=128, 1 group, zeta stored in VZ.
//   Left half:  f[0..127]   bytes [0..255]
//   Right half: f[128..255] bytes [256..511]
//   offset selects 16-byte chunk within each half (0..15).
#define nttL0(dataAddr, VZ, offset) \
	ADD  $((offset)*16), dataAddr, R11          \
	VLD1 (R11), [V0.H8]                          \
	ADD  $((offset)*16+256), dataAddr, R12      \
	VLD1 (R12), [V1.H8]                          \
	BUTTERFLY(V0, V1, VZ)                        \
	VST1 [V0.H8], (R11)                          \
	VST1 [V1.H8], (R12)

// nttL1: Layer len=64, 2 groups.
//   group g occupies bytes [g*256 .. g*256+256).
//   Left: [g*256 + offset*16], Right: [g*256+128 + offset*16]
//   offset ∈ {0..7}
#define nttL1(dataAddr, VZ, groupIdx, offset) \
	ADD  $((groupIdx)*256+(offset)*16), dataAddr, R11        \
	VLD1 (R11), [V0.H8]                                       \
	ADD  $((groupIdx)*256+(offset)*16+128), dataAddr, R12    \
	VLD1 (R12), [V1.H8]                                       \
	BUTTERFLY(V0, V1, VZ)                                     \
	VST1 [V0.H8], (R11)                                       \
	VST1 [V1.H8], (R12)

// nttL2: Layer len=32, 4 groups.
//   group g occupies bytes [g*128 .. g*128+128).
//   Left: [g*128 + offset*16], Right: [g*128+64 + offset*16]
//   offset ∈ {0..3}
#define nttL2(dataAddr, VZ, groupIdx, offset) \
	ADD  $((groupIdx)*128+(offset)*16), dataAddr, R11       \
	VLD1 (R11), [V0.H8]                                      \
	ADD  $((groupIdx)*128+(offset)*16+64), dataAddr, R12    \
	VLD1 (R12), [V1.H8]                                      \
	BUTTERFLY(V0, V1, VZ)                                    \
	VST1 [V0.H8], (R11)                                      \
	VST1 [V1.H8], (R12)

// nttL3: Layer len=16, 8 groups.
//   group g: bytes [g*64 .. g*64+64). Left=[g*64], Right=[g*64+32]
//   Two NEON loads cover 16 bytes each → covers 32 bytes per side.
//   offset ∈ {0,1}
#define nttL3(dataAddr, VZ, groupIdx, offset) \
	ADD  $((groupIdx)*64+(offset)*16), dataAddr, R11       \
	VLD1 (R11), [V0.H8]                                     \
	ADD  $((groupIdx)*64+(offset)*16+32), dataAddr, R12    \
	VLD1 (R12), [V1.H8]                                     \
	BUTTERFLY(V0, V1, VZ)                                   \
	VST1 [V0.H8], (R11)                                     \
	VST1 [V1.H8], (R12)

// inttL0: INTT final layer len=128, with scale multiply on both outputs.
// Note: MONT_MUL_FIXED always outputs to V2, so Vscale must NOT be V2.
//       MONT_MUL(V0,Vscale,V0) expands VMOV Vscale→V1, clobbering VB'; save it first.
#define inttL0(dataAddr, VZ, Vscale, offset) \
	ADD  $((offset)*16), dataAddr, R11           \
	VLD1 (R11), [V0.H8]                           \
	ADD  $((offset)*16+256), dataAddr, R12       \
	VLD1 (R12), [V1.H8]                           \
	INTT_BUTTERFLY(V0, V1, VZ)                   \
	VMOV V1.B16, V26.B16                         \ // save VB'; MONT_MUL will clobber V1
	MONT_MUL(V0, Vscale, V0)                     \
	VST1 [V0.H8], (R11)                           \
	MONT_MUL(V26, Vscale, V1)                   \
	VST1 [V1.H8], (R12)

#define inttL1(dataAddr, VZ, groupIdx, offset) \
	ADD  $((groupIdx)*256+(offset)*16), dataAddr, R11        \
	VLD1 (R11), [V0.H8]                                       \
	ADD  $((groupIdx)*256+(offset)*16+128), dataAddr, R12    \
	VLD1 (R12), [V1.H8]                                       \
	INTT_BUTTERFLY(V0, V1, VZ)                                \
	VST1 [V0.H8], (R11)                                       \
	VST1 [V1.H8], (R12)

#define inttL2(dataAddr, VZ, groupIdx, offset) \
	ADD  $((groupIdx)*128+(offset)*16), dataAddr, R11       \
	VLD1 (R11), [V0.H8]                                      \
	ADD  $((groupIdx)*128+(offset)*16+64), dataAddr, R12    \
	VLD1 (R12), [V1.H8]                                      \
	INTT_BUTTERFLY(V0, V1, VZ)                               \
	VST1 [V0.H8], (R11)                                      \
	VST1 [V1.H8], (R12)

#define inttL3(dataAddr, VZ, groupIdx, offset) \
	ADD  $((groupIdx)*64+(offset)*16), dataAddr, R11       \
	VLD1 (R11), [V0.H8]                                     \
	ADD  $((groupIdx)*64+(offset)*16+32), dataAddr, R12    \
	VLD1 (R12), [V1.H8]                                     \
	INTT_BUTTERFLY(V0, V1, VZ)                              \
	VST1 [V0.H8], (R11)                                     \
	VST1 [V1.H8], (R12)

#define LOAD_ZETA_NTT(VZ) \	
	MOVHU.P 2(R1), R10 \
	VDUP R10, VZ.H8

#define LOAD_ZETA_INTT(VZ) \	
	MOVHU.W -2(R1), R10 \
	VDUP R10, VZ.H8

// ── internalNTTNEON ───────────────────────────────────────────────────────────
// func internalNTTNEON(f *ringElement)
// All 7 NTT layers (len=128 down to len=2).
// Uses only 16-byte (8 × int16) NEON vectors throughout.
TEXT ·internalNTTNEON(SB), NOSPLIT, $0-8
	MOVD f+0(FP), R0

	MOVD $·zetasMontgomery(SB), R1
	ADD $2, R1, R1 // point to zetasMontgomery[1] for first layer

	// Setup pinned registers
	MOVD $3329, R8
	VDUP R8, V31.H8       // V31 = q
	MOVD $3327, R8
	VDUP R8, V30.H8       // V30 = qNegInv
	MOVD $1, R8
	VDUP R8, V29.H8       // V29 = 1
	VEOR V28.B16, V28.B16, V28.B16 // V28 = 0

	// ── Layer L0: len=128. zeta = zetasMontgomery[1] (byte offset 2) ──────
	LOAD_ZETA_NTT(V7)
	nttL0(R0, V7, 0)
	nttL0(R0, V7, 1)
	nttL0(R0, V7, 2)
	nttL0(R0, V7, 3)
	nttL0(R0, V7, 4)
	nttL0(R0, V7, 5)
	nttL0(R0, V7, 6)
	nttL0(R0, V7, 7)
	nttL0(R0, V7, 8)
	nttL0(R0, V7, 9)
	nttL0(R0, V7, 10)
	nttL0(R0, V7, 11)
	nttL0(R0, V7, 12)
	nttL0(R0, V7, 13)
	nttL0(R0, V7, 14)
	nttL0(R0, V7, 15)

	// ── Layer L1: len=64. 2 groups ─────────────────────────────────────────
	// Group 0: zeta = zetasMontgomery[2] (byte offset 4)
	// Group 1: zeta = zetasMontgomery[3] (byte offset 6)
	LOAD_ZETA_NTT(V7)
	LOAD_ZETA_NTT(V6)
	nttL1(R0, V7, 0, 0)
	nttL1(R0, V7, 0, 1)
	nttL1(R0, V7, 0, 2)
	nttL1(R0, V7, 0, 3)
	nttL1(R0, V7, 0, 4)
	nttL1(R0, V7, 0, 5)
	nttL1(R0, V7, 0, 6)
	nttL1(R0, V7, 0, 7)
	nttL1(R0, V6, 1, 0)
	nttL1(R0, V6, 1, 1)
	nttL1(R0, V6, 1, 2)
	nttL1(R0, V6, 1, 3)
	nttL1(R0, V6, 1, 4)
	nttL1(R0, V6, 1, 5)
	nttL1(R0, V6, 1, 6)
	nttL1(R0, V6, 1, 7)

	// ── Layer L2: len=32. 4 groups ─────────────────────────────────────────
	// Group 0: zeta = zetasMontgomery[4] (byte 8)
	// Group 1: zeta = zetasMontgomery[5] (byte 10)
	LOAD_ZETA_NTT(V7)
	LOAD_ZETA_NTT(V6)
	nttL2(R0, V7, 0, 0)
	nttL2(R0, V7, 0, 1)
	nttL2(R0, V7, 0, 2)
	nttL2(R0, V7, 0, 3)
	nttL2(R0, V6, 1, 0)
	nttL2(R0, V6, 1, 1)
	nttL2(R0, V6, 1, 2)
	nttL2(R0, V6, 1, 3)

	// Group 2: zeta = zetasMontgomery[6] (byte 12)
	// Group 3: zeta = zetasMontgomery[7] (byte 14)
	LOAD_ZETA_NTT(V7)
	LOAD_ZETA_NTT(V6)
	nttL2(R0, V7, 2, 0)
	nttL2(R0, V7, 2, 1)
	nttL2(R0, V7, 2, 2)
	nttL2(R0, V7, 2, 3)
	nttL2(R0, V6, 3, 0)
	nttL2(R0, V6, 3, 1)
	nttL2(R0, V6, 3, 2)
	nttL2(R0, V6, 3, 3)

	// ── Layer L3: len=16. 8 groups ─────────────────────────────────────────
	// Group g: zeta = zetasMontgomery[8+g] (byte 16+g*2)
	LOAD_ZETA_NTT(V7)
	LOAD_ZETA_NTT(V6)
	nttL3(R0, V7, 0, 0)
	nttL3(R0, V7, 0, 1)
	nttL3(R0, V6, 1, 0)
	nttL3(R0, V6, 1, 1)

	LOAD_ZETA_NTT(V7)
	LOAD_ZETA_NTT(V6)
	nttL3(R0, V7, 2, 0)
	nttL3(R0, V7, 2, 1)
	nttL3(R0, V6, 3, 0)
	nttL3(R0, V6, 3, 1)

	LOAD_ZETA_NTT(V7)
	LOAD_ZETA_NTT(V6)
	nttL3(R0, V7, 4, 0)
	nttL3(R0, V7, 4, 1)
	nttL3(R0, V6, 5, 0)
	nttL3(R0, V6, 5, 1)

	LOAD_ZETA_NTT(V7)
	LOAD_ZETA_NTT(V6)
	nttL3(R0, V7, 6, 0)
	nttL3(R0, V7, 6, 1)
	nttL3(R0, V6, 7, 0)
	nttL3(R0, V6, 7, 1)

	// ── Layer L4: len=8. 16 groups. zeta = zetasMontgomery[16+g] ──────────
	// group g: left at g*32, right at g*32+16; byte offset = g*32
	// zeta byte offset in table = (16+g)*2 = 32+g*2
	MOVD R0, R3         // R3 = base address of current layer
	MOVD $0, R4         // R4 = group counter
ntt_len8_loop:
	CMP $16, R4
	BGE ntt_len4_start
	LOAD_ZETA_NTT(V7)
	VLD1 (R3), [V0.H8, V1.H8]   // load both left and right halves together (16 bytes each)
	BUTTERFLY(V0, V1, V7)
	VST1.P [V0.H8, V1.H8], 32(R3)
	ADD $1, R4, R4
	B ntt_len8_loop

	// ── Layer L5: len=4. 32 groups. zeta = zetasMontgomery[32+g] ──────────
	// group g: left at g*16, right at g*16+8
ntt_len4_start:
	MOVD R0, R3
	MOVD $0, R4
ntt_len4_loop:
	CMP $16, R4
	BGE ntt_len2_start
	LOAD_ZETA_NTT(V7)
	LOAD_ZETA_NTT(V8)
	VZIP1 V8.D2, V7.D2, V7.D2
	VLD1 (R3), [V20.H8, V21.H8]
	VZIP1 V21.D2, V20.D2, V0.D2
	VZIP2 V21.D2, V20.D2, V1.D2
	BUTTERFLY(V0, V1, V7)
	VZIP1 V1.D2, V0.D2, V20.D2
	VZIP2 V1.D2, V0.D2, V21.D2
	VST1.P [V20.H8, V21.H8], 32(R3)
	ADD $1, R4, R4
	B ntt_len4_loop

	// ── Layer L6: len=2. 64 groups. zeta = zetasMontgomery[64+g] ──────────
	// group g: left at g*8, right at g*8+4
ntt_len2_start:
	MOVD R0, R3
	MOVD $0, R4
ntt_len2_loop:
	CMP $16, R4
	BGE ntt_len2_done
	MOVD.P 8(R1), R10
	VDUP R10, V20.D2
	VZIP1 V20.H8, V20.H8, V7.H8
	VLD1 (R3), [V20.H8, V21.H8]
	VZIP1 V21.D2, V20.D2, V22.D2
	VZIP2 V21.D2, V20.D2, V23.D2
	VZIP1 V23.S4, V22.S4, V20.S4
	VZIP2 V23.S4, V22.S4, V21.S4
	VZIP1 V21.D2, V20.D2, V0.D2
	VZIP2 V21.D2, V20.D2, V1.D2
	BUTTERFLY(V0, V1, V7)
	VZIP1 V1.S4, V0.S4, V20.S4
	VZIP2 V1.S4, V0.S4, V21.S4
	VST1.P [V20.H8, V21.H8], 32(R3)
	ADD $1, R4, R4
	B ntt_len2_loop

ntt_len2_done:
	RET

// ── internalInverseNTTNEON ─────────────────────────────────────────────────────
// func internalInverseNTTNEON(f *nttElement)
// All 7 inverse NTT layers (Gentleman-Sande, len=2..128) + scale by 1441.
TEXT ·internalInverseNTTNEON(SB), NOSPLIT, $0-8
	MOVD f+0(FP), R0

	MOVD $·zetasMontgomery(SB), R1
	ADD $256, R1, R1         // point R1 to zetasMontgomery[128]

	// Setup pinned registers
	MOVD $3329, R8
	VDUP R8, V31.H8
	MOVD $3327, R8
	VDUP R8, V30.H8
	MOVD $1, R8
	VDUP R8, V29.H8
	VEOR V28.B16, V28.B16, V28.B16

	// ── L6: len=2. 64 groups. zeta = zetasMontgomery[127..64] ────────────
	// k descends: group g uses zetasMontgomery[127-g], byte offset = (127-g)*2 = 254-g*2
	// SI = zeta offset (starts at 254, decreases by 2 each group)
	MOVD R0, R3
	MOVD $0, R4
intt_len2_loop:
	CMP $16, R4
	BGE intt_len4_start
	MOVD.W -8(R1), R10
	VDUP R10, V20.D2
	VREV64 V20.H8, V20.H8
	VZIP1 V20.H8, V20.H8, V7.H8
	VLD1 (R3), [V20.H8, V21.H8]
	VZIP1 V21.D2, V20.D2, V22.D2
	VZIP2 V21.D2, V20.D2, V23.D2
	VZIP1 V23.S4, V22.S4, V20.S4
	VZIP2 V23.S4, V22.S4, V21.S4
	VZIP1 V21.D2, V20.D2, V0.D2
	VZIP2 V21.D2, V20.D2, V1.D2
	INTT_BUTTERFLY(V0, V1, V7)
	VZIP1 V1.S4, V0.S4, V20.S4
	VZIP2 V1.S4, V0.S4, V21.S4
	VST1.P [V20.H8, V21.H8], 32(R3)	
	ADD $1, R4, R4
	B intt_len2_loop

	// ── L5: len=4. 32 groups. zeta = zetasMontgomery[63..32] ─────────────
intt_len4_start:
	MOVD R0, R3
	MOVD $0, R4
intt_len4_loop:
	CMP $16, R4
	BGE intt_len8_start
	LOAD_ZETA_INTT(V7)
	LOAD_ZETA_INTT(V8)
	VZIP1 V8.D2, V7.D2, V7.D2
	VLD1 (R3), [V20.H8, V21.H8]
	VZIP1 V21.D2, V20.D2, V0.D2
	VZIP2 V21.D2, V20.D2, V1.D2
	INTT_BUTTERFLY(V0, V1, V7)
	VZIP1 V1.D2, V0.D2, V20.D2
	VZIP2 V1.D2, V0.D2, V21.D2
	VST1.P [V20.H8, V21.H8], 32(R3)
	ADD $1, R4, R4
	B intt_len4_loop

	// ── L4: len=8. 16 groups. zeta = zetasMontgomery[31..16] ─────────────
intt_len8_start:
	MOVD R0, R3
	MOVD $0, R4
intt_len8_loop:
	CMP $16, R4
	BGE intt_len16_start
	LOAD_ZETA_INTT(V7)
	VLD1 (R3), [V0.H8, V1.H8]   // load both left and right halves together (16 bytes each)
	INTT_BUTTERFLY(V0, V1, V7)
	VST1.P [V0.H8, V1.H8], 32(R3)
	ADD $1, R4, R4
	B intt_len8_loop

	// ── L3: len=16. 8 groups. zeta = zetasMontgomery[15..8] ──────────────
intt_len16_start:
	LOAD_ZETA_INTT(V7)
	LOAD_ZETA_INTT(V6)
	inttL3(R0, V7, 0, 0)
	inttL3(R0, V7, 0, 1)
	inttL3(R0, V6, 1, 0)
	inttL3(R0, V6, 1, 1)

	LOAD_ZETA_INTT(V7)
	LOAD_ZETA_INTT(V6)
	inttL3(R0, V7, 2, 0)
	inttL3(R0, V7, 2, 1)
	inttL3(R0, V6, 3, 0)
	inttL3(R0, V6, 3, 1)

	LOAD_ZETA_INTT(V7)
	LOAD_ZETA_INTT(V6)
	inttL3(R0, V7, 4, 0)
	inttL3(R0, V7, 4, 1)
	inttL3(R0, V6, 5, 0)
	inttL3(R0, V6, 5, 1)

	LOAD_ZETA_INTT(V7)
	LOAD_ZETA_INTT(V6)
	inttL3(R0, V7, 6, 0)
	inttL3(R0, V7, 6, 1)
	inttL3(R0, V6, 7, 0)
	inttL3(R0, V6, 7, 1)

	// ── L2: len=32. 4 groups. zeta = zetasMontgomery[7..4] ───────────────
	LOAD_ZETA_INTT(V7)
	LOAD_ZETA_INTT(V6)
	inttL2(R0, V7, 0, 0)
	inttL2(R0, V7, 0, 1)
	inttL2(R0, V7, 0, 2)
	inttL2(R0, V7, 0, 3)
	inttL2(R0, V6, 1, 0)
	inttL2(R0, V6, 1, 1)
	inttL2(R0, V6, 1, 2)
	inttL2(R0, V6, 1, 3)

	LOAD_ZETA_INTT(V7)
	LOAD_ZETA_INTT(V6)
	inttL2(R0, V7, 2, 0)
	inttL2(R0, V7, 2, 1)
	inttL2(R0, V7, 2, 2)
	inttL2(R0, V7, 2, 3)
	inttL2(R0, V6, 3, 0)
	inttL2(R0, V6, 3, 1)
	inttL2(R0, V6, 3, 2)
	inttL2(R0, V6, 3, 3)

	// ── L1: len=64. 2 groups. zeta = zetasMontgomery[3..2] ───────────────
	LOAD_ZETA_INTT(V7)
	LOAD_ZETA_INTT(V6)
	inttL1(R0, V7, 0, 0)
	inttL1(R0, V7, 0, 1)
	inttL1(R0, V7, 0, 2)
	inttL1(R0, V7, 0, 3)
	inttL1(R0, V7, 0, 4)
	inttL1(R0, V7, 0, 5)
	inttL1(R0, V7, 0, 6)
	inttL1(R0, V7, 0, 7)
	inttL1(R0, V6, 1, 0)
	inttL1(R0, V6, 1, 1)
	inttL1(R0, V6, 1, 2)
	inttL1(R0, V6, 1, 3)
	inttL1(R0, V6, 1, 4)
	inttL1(R0, V6, 1, 5)
	inttL1(R0, V6, 1, 6)
	inttL1(R0, V6, 1, 7)

	// ── L0: len=128. 1 group. zeta = zetasMontgomery[1]. Scale by 1441 ───
	// Use V3 for scale (NOT V2: MONT_MUL_FIXED always clobbers V2).
	LOAD_ZETA_INTT(V7)
	MOVD $1441, R8
	VDUP R8, V3.H8    // V3 = scale = 1441
	inttL0(R0, V7, V3, 0)
	inttL0(R0, V7, V3, 1)
	inttL0(R0, V7, V3, 2)
	inttL0(R0, V7, V3, 3)
	inttL0(R0, V7, V3, 4)
	inttL0(R0, V7, V3, 5)
	inttL0(R0, V7, V3, 6)
	inttL0(R0, V7, V3, 7)
	inttL0(R0, V7, V3, 8)
	inttL0(R0, V7, V3, 9)
	inttL0(R0, V7, V3, 10)
	inttL0(R0, V7, V3, 11)
	inttL0(R0, V7, V3, 12)
	inttL0(R0, V7, V3, 13)
	inttL0(R0, V7, V3, 14)
	inttL0(R0, V7, V3, 15)

	RET

// ── internalNTTMulAccNEON ──────────────────────────────────────────────────────
// func internalNTTMulAccNEON(acc, lhs, rhs *nttElement)
//
// For each pair (i, i+1):
//   acc[i]   += MontMul(a0,b0) + MontMul(MontMul(a1,b1), gamma[i/2])
//   acc[i+1] += MontMul(a0,b1) + MontMul(a1,b0)
//
// We process 4 pairs (8 coefficients = 16 bytes) per loop iteration.
// gammaMulTable<> layout: [r, γ[0], r, γ[1], ...] (r=2285, all in int16)
// For 4-pair iteration: load 8 × int16 = 16 bytes from gamma table.
//
// Register allocation:
//   V0 = lhs[i..i+7], V1 = rhs[i..i+7], V2 = acc[i..i+7]
//   V3 = gamma[j..j+7] ([r,γ[k], r,γ[k+1], r,γ[k+2], r,γ[k+3]])
//   V4 = rhs with adjacent pairs swapped (VREV32)
//   V5 = t_ab = MontMul(lhs, rhs)
//   V6 = t_cross = MontMul(lhs, rhs_swapped)
//   V7 = MontMul(t_ab, gamma)
// After MontMul:
//   V7 = [a0b0*r, γ*a1b1, a2b2*r, γ*a3b3, ...] (element-wise)
//   V6 = [a0b1, a1b0, a2b3, a3b2, ...]
// Pairwise add (VADDP Vd.8H, Vn.8H, Vm.8H: Vd[0..3]=pairs(Vn), Vd[4..7]=pairs(Vm)):
//   VADDP V7.8H, V7.8H, V7.8H → all 8 lanes = pairwise sums of V7 (4 even-acc deltas, replicated)
//   VADDP V6.8H, V6.8H, V6.8H → same for V6 (4 odd-acc deltas)
// Re-interleave: VZIP1 Vd.8H, Vn.8H, Vm.8H: Vm=[Vd[0],Vn[0],Vd[1],Vn[1],Vd[2],Vn[2],Vd[3],Vn[3]]
//   VZIP1 V7.8H, V6.8H, V5.8H → V5 = interleaved deltas
//
// R0=acc, R1=lhs, R2=rhs, R3=gamma, R4=byte offset
TEXT ·internalNTTMulAccNEON(SB), NOSPLIT, $0-24
	MOVD acc+0(FP), R0
	MOVD lhs+8(FP), R1
	MOVD rhs+16(FP), R2

	// pinned
	MOVD $3329, R8
	VDUP R8, V31.H8
	MOVD $3327, R8
	VDUP R8, V30.H8
	MOVD $1, R8
	VDUP R8, V29.H8
	VEOR V28.B16, V28.B16, V28.B16

	MOVD $·gammaMulTableNEON(SB), R3
	MOVD $0, R4         // byte offset

nttmlacc_neon_loop:
	CMP $512, R4
	BGE nttmlacc_neon_done

	VLD1.P (16)(R1), [V0.H8]   // lhs
	VLD1.P (16)(R2), [V1.H8]   // rhs
	VLD1.P (16)(R3), [V3.H8]   // gamma table

	// V4 = rhs with adjacent int16 pairs swapped: VREV32 on H type swaps adjacent H lanes
	VREV32 V1.H8, V4.H8

	// t_ab = MontMul(V0, V1) → V5  (element-wise: a0b0, a1b1, ...)
	MONT_MUL_V0_V1(V5)

	// t_cross = MontMul(V0, V4) → V6  (element-wise: a0b1, a1b0, ...)
	MONT_MUL_V0_VZ(V4, V6)

	// t_scaled = MontMul(V5, V3) → V7  (even: a0b0*r=a0b0, odd: γ*a1b1)
	MONT_MUL(V5, V3, V7)

	// Pairwise add to combine even+odd sums
	// VADDP Vd.8H, Vn.8H, Vm.8H: Vd[0..3]=pairwise(Vn), Vd[4..7]=pairwise(Vm)
	// Using same src twice: both halves = pairwise sums of V7
	VADDP V7.H8, V7.H8, V7.H8
	VADDP V6.H8, V6.H8, V6.H8

	// fieldReduceOnce on both
	REDUCE_ONCE(V7)
	REDUCE_ONCE(V6)

	// Re-interleave: VZIP1 Va.8H, Vb.8H, Vd.8H in Go Plan9 → ARM64 ZIP1 Vd,Vb,Va → Vd=[Vb[0],Va[0],...]
	// We want [even_sum0, odd_sum0, even_sum1, odd_sum1, ...]
	// V7 has even sums, V6 has odd sums → VZIP1 V6,V7,V5 → V5=[V7[0],V6[0],...]
	VZIP1 V6.H8, V7.H8, V5.H8

	// Add delta to acc (load acc late to avoid preserving V2 across MONT_MUL calls)
	VLD1 (R0), [V2.H8]
	VADD V5.H8, V2.H8, V2.H8
	REDUCE_ONCE(V2)

	VST1.P [V2.H8], (16)(R0)

	ADD $16, R4, R4
	B nttmlacc_neon_loop

nttmlacc_neon_done:
	RET

// ── internalNTTMulAccKeyGenNEON ────────────────────────────────────────────────
// func internalNTTMulAccKeyGenNEON(acc, lhs, rhs *nttElement)
//
// Same as internalNTTMulAccNEON but converts delta from Montgomery to standard
// domain before accumulating: MontMul(delta, rr) where rr=1353=r^2 mod q.
TEXT ·internalNTTMulAccKeyGenNEON(SB), NOSPLIT, $0-24
	MOVD acc+0(FP), R0
	MOVD lhs+8(FP), R1
	MOVD rhs+16(FP), R2

	// pinned
	MOVD $3329, R8
	VDUP R8, V31.H8
	MOVD $3327, R8
	VDUP R8, V30.H8
	MOVD $1, R8
	VDUP R8, V29.H8
	VEOR V28.B16, V28.B16, V28.B16

	MOVD $1353, R8
	VDUP R8, V27.H8     // V27 = rr = 1353 (fromMont scale)

	MOVD $·gammaMulTableNEON(SB), R3
	MOVD $0, R4

nttmlacc_kg_neon_loop:
	CMP $512, R4
	BGE nttmlacc_kg_neon_done

	VLD1.P (16)(R1), [V0.H8]
	VLD1.P (16)(R2), [V1.H8]
	VLD1.P (16)(R3), [V3.H8]

	VREV32 V1.H8, V4.H8

	MONT_MUL_V0_V1(V5)
	MONT_MUL_V0_VZ(V4, V6)
	MONT_MUL(V5, V3, V7)

	VADDP V7.H8, V7.H8, V7.H8
	VADDP V6.H8, V6.H8, V6.H8

	REDUCE_ONCE(V7)
	REDUCE_ONCE(V6)

	VZIP1 V6.H8, V7.H8, V5.H8

	// Convert delta from Montgomery to standard domain
	MONT_MUL(V5, V27, V5)

	VLD1 (R0), [V2.H8]
	VADD V5.H8, V2.H8, V2.H8
	REDUCE_ONCE(V2)

	VST1.P [V2.H8], (16)(R0)

	ADD $16, R4, R4
	B nttmlacc_kg_neon_loop

nttmlacc_kg_neon_done:
	RET

// samplePolyCBD2NEON computes D_eta=2 coefficients from 128 PRF bytes.
// It vectorizes bit extraction and coefficient packing in 16-byte chunks.
// func samplePolyCBD2NEON(dst *ringElement, buf *[128]byte)
TEXT ·samplePolyCBD2NEON(SB), NOSPLIT, $0-16
	MOVD dst+0(FP), R0
	MOVD buf+8(FP), R1
	MOVD $8, R2 // 128 / 16 chunks

	MOVD $0x55, R3
	VDUP R3, V23.B16 // pair-bit mask
	MOVD $0x03, R3
	VDUP R3, V22.B16 // 2-bit mask
	MOVD $2, R3
	VDUP R3, V21.B16 // +2 bias

	MOVD $·cbd2DiffMapLow(SB), R9
	VLD1 (R9), [V16.B16]
	MOVD $·cbd2DiffMapHigh(SB), R10
	VLD1 (R10), [V17.B16]

samplecbd2_loop:
	CBZ R2, samplecbd2_done

	VLD1.P 16(R1), [V0.B16]

	// d = (b & 0x55) + ((b >> 1) & 0x55)
	VAND V23.B16, V0.B16, V1.B16
	VUSHR $1, V0.B16, V2.B16
	VAND V23.B16, V2.B16, V2.B16
	VADD V2.B16, V1.B16, V1.B16

	// t0 = ((d & 0x03) + 2) - ((d >> 2) & 0x03) in [0..4]
	VAND V22.B16, V1.B16, V3.B16
	VUSHR $2, V1.B16, V4.B16
	VAND V22.B16, V4.B16, V4.B16
	VADD V21.B16, V3.B16, V3.B16
	VSUB V4.B16, V3.B16, V3.B16

	// t1 = (((d >> 4) & 0x03) + 2) - ((d >> 6) & 0x03) in [0..4]
	VUSHR $4, V1.B16, V5.B16
	VAND V22.B16, V5.B16, V5.B16
	VUSHR $6, V1.B16, V6.B16
	VAND V22.B16, V6.B16, V6.B16
	VADD V21.B16, V5.B16, V5.B16
	VSUB V6.B16, V5.B16, V5.B16

	// Map [0..4] -> field element bytes via lookup tables.
	VTBL V3.B16, [V16.B16], V7.B16  // c0 low byte
	VTBL V3.B16, [V17.B16], V8.B16  // c0 high byte
	VTBL V5.B16, [V16.B16], V9.B16  // c1 low byte
	VTBL V5.B16, [V17.B16], V10.B16 // c1 high byte

	// Pack little-endian uint16s for c0/c1 and interleave as c0,c1,c0,c1...
	VZIP1 V8.B16, V7.B16, V11.B16
	VZIP2 V8.B16, V7.B16, V12.B16
	VZIP1 V10.B16, V9.B16, V13.B16
	VZIP2 V10.B16, V9.B16, V14.B16

	VZIP1 V13.H8, V11.H8, V15.H8
	VZIP2 V13.H8, V11.H8, V4.H8
	VST1.P [V15.B16], 16(R0)
	VST1.P [V4.B16], 16(R0)

	VZIP1 V14.H8, V12.H8, V15.H8
	VZIP2 V14.H8, V12.H8, V4.H8
	VST1.P [V15.B16], 16(R0)
	VST1.P [V4.B16], 16(R0)

	SUB $1, R2, R2
	B samplecbd2_loop

samplecbd2_done:
	RET

// ── CBD2 Lookup Tables ──────────────────────────────────────────────────────
// cbd2DiffMapLow/High map a centered eta=2 coefficient in [-2,2]
// encoded as index (value+2) to its field element bytes modulo q.
// index: 0->q-2, 1->q-1, 2->0, 3->1, 4->2
GLOBL ·cbd2DiffMapLow(SB), RODATA, $16
DATA ·cbd2DiffMapLow+0(SB)/4, $0x000000FF
DATA ·cbd2DiffMapLow+4(SB)/4, $0x01000000
DATA ·cbd2DiffMapLow+8(SB)/4, $0x02000000
DATA ·cbd2DiffMapLow+12(SB)/4, $0x00000000

GLOBL ·cbd2DiffMapHigh(SB), RODATA, $16
DATA ·cbd2DiffMapHigh+0(SB)/4, $0x00000D0C
DATA ·cbd2DiffMapHigh+4(SB)/4, $0x00000000
DATA ·cbd2DiffMapHigh+8(SB)/4, $0x00000000
DATA ·cbd2DiffMapHigh+12(SB)/4, $0x00000000
