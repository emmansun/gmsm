// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// reference algorithm 13 in https://eprint.iacr.org/2021/986.pdf
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
// Clobbers: V20,V21,V22,V23,V24
#define DBL_MONT_MUL_FIXED(VOUT) \
	WORD $0x4E619C14                        \ // MUL   V20.H8, V0.H8, V1.H8
	WORD $0x4E7E9E96                        \ // MUL   V22.H8, V20.H8, V30.H8
	WORD $0x6e61b415                        \ // SQRDMULH V21.H8, V0.H8, V1.H8 (hi' = Round(2*hi))
	WORD $0x6e5f86d5                        \ // SQRDMALH V21.H8, V22.H8, V31.H8 (raw = Round(2*corr) + hi')
	WORD $0x4f1f06b5                        \ // VSSHR V21.H8, V21.H8, #1
	WORD $0x4f1106b8                        \ // VSSHR V24.H8, V21.H8, #15
	VAND V31.B16, V24.B16, V24.B16          \ // q if underflow, else 0
	VADD V21.H8, V24.H8, VOUT.H8              // result in VOUT

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
//   VA' = fieldReduceOnce(VA + t)  where t = MontMul(VZ, VB)
//   VB' = fieldSub(VA_old, t)
// V25 holds VA_old, V26 holds t.
// Clobbers: V20..V26.
#define BUTTERFLY(VA, VB, VZ) \
	VMOV   VA.B16, V25.B16            \ // save VA
	MONT_MUL(VB, VZ, V26)             \ // t = MontMul(VZ, VB) → V26
	VADD   V25.H8, V26.H8, VA.H8      \ // VA = VA_old + t
	VSUB   V31.H8, VA.H8, V20.H8      \ // try = VA - q → V20
	WORD   $0x4f110698                \ // VSSHR V24.H8, V20.H8, #15
	VAND   V31.B16, V24.B16, V24.B16  \ // q if underflow
	VADD   V20.H8, V24.H8, VA.H8      \ // VA = try + correction
	VSUB   V26.H8, V25.H8, V20.H8     \ // V20 = VA_old - t  (V25-V26)
	WORD   $0x4f110698                \ // VSSHR V24.H8, V20.H8, #15
	VAND   V31.B16, V24.B16, V24.B16  \ // q if negative
	VADD   V20.H8, V24.H8, VB.H8        // VB += q if negative

// Specialized forward butterfly for VA=V0, VB=V1.
// Saves one VMOV compared with BUTTERFLY(V0, V1, VZ) by using
// commutativity in Montgomery multiply: MontMul(V1, VZ) == MontMul(VZ, V1).
#define BUTTERFLY01(VZ) \
	VMOV   V0.B16, V25.B16            \ // save VA_old
	VMOV   VZ.B16, V0.B16             \ // V0 = zeta, V1 keeps VB
	DBL_MONT_MUL_FIXED(V26)           \ // t = MontMul(V0, V1)
	VADD   V25.H8, V26.H8, V0.H8      \ // VA = VA_old + t
	WORD   $0x6e7f3c14				  \ // CMGT.U V20.H8, V0.H8, V31.H8 (V0 >= q ? 0xFFFF : 0)
	VAND   V31.B16, V20.B16, V20.B16  \ // q if underflow
	VSUB   V20.H8, V0.H8, V0.H8       \ // VA = VA - q if underflow
	VSUB   V26.H8, V25.H8, V20.H8     \ // V20 = VA_old - t
	WORD   $0x4f110698                \ // VSSHR V24.H8, V20.H8, #15
	VAND   V31.B16, V24.B16, V24.B16  \ // q if negative
	VADD   V20.H8, V24.H8, V1.H8        // VB += q if negative

// Gentleman-Sande butterfly:
//   VA' = fieldReduceOnce(VA + VB)
//   VB' = MontMul(VZ, fieldSub(VB, VA_old))
// V25 holds VA_old. Clobbers: V20..V26.
#define INTT_BUTTERFLY(VA, VB, VZ) \
	VSUB   VA.H8, VB.H8, V22.H8       \ // diff = VB - VA_old  (V22=VB-VA_old)
	VADD   VA.H8, VB.H8, V20.H8       \ // V20 = VA_old + VB
	\ // VA reduction
	WORD   $0x6e7f3e95				  \ // CMGT.U V21.H8, V20.H8, V31.H8 (V20 >= q ? 0xFFFF : 0)
	VAND   V31.B16, V21.B16, V21.B16  \ // q if negative
	VSUB   V21.H8, V20.H8, V25.H8      \
	\ // VB reduction
	WORD   $0x4f1106d8                \ // VSSHR V24.H8, V22.H8, #15
	VAND   V31.B16, V24.B16, V24.B16  \ // q if negative
	VADD   V22.H8, V24.H8, VB.H8      \ // fieldSub: add q if negative
	MONT_MUL(VB, VZ, VB)              \ // VB = MontMul(VZ, diff) — clobbers VA's reg (V0)
	VMOV   V25.B16, VA.B16             // restore VA'

// Specialized inverse butterfly for VA=V0, VB=V1.
// Saves one VMOV vs INTT_BUTTERFLY(V0, V1, VZ).
#define INTT_BUTTERFLY01(VZ) \
	VSUB   V0.H8, V1.H8, V22.H8       \ // diff = VB - VA_old
	VADD   V0.H8, V1.H8, V20.H8       \ // V20 = VA_old + VB
	\ // VA reduction
	WORD   $0x6e7f3e95				  \ // CMGT.U V21.H8, V20.H8, V31.H8 (V20 >= q ? 0xFFFF : 0)
	VAND   V31.B16, V21.B16, V21.B16  \ // q if negative
	VSUB   V21.H8, V20.H8, V25.H8      \
	\ // VB reduction
	WORD   $0x4f1106d8                \ // VSSHR V24.H8, V22.H8, #15
	VAND   V31.B16, V24.B16, V24.B16  \ // q if negative
	VADD   V22.H8, V24.H8, V1.H8      \ // fieldSub: add q if negative
	VMOV   VZ.B16, V0.B16             \ // V0 = zeta, V1 keeps diff
	MONT_MUL_V0_V1(V1)                \ // VB = MontMul(V0, V1)
	VMOV   V25.B16, V0.B16             // restore VA'

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
#define nttL0to3(evenDataAddr, oddDataAddr, VZ)  \
	VLD1 (evenDataAddr), [V0.H8]                 \
	VLD1 (oddDataAddr), [V1.H8]                  \
	BUTTERFLY01(VZ)                              \
	VST1.P [V0.H8], 16(evenDataAddr)             \
	VST1.P [V1.H8], 16(oddDataAddr)

// inttL0: INTT final layer len=128, with scale multiply on both outputs.
#define inttL0(evenDataAddr, oddDataAddr, VZ, Vscale) \
	VLD1 (evenDataAddr), [V0.H8]                      \
	VLD1 (oddDataAddr), [V1.H8]                       \
	INTT_BUTTERFLY01(VZ)                              \
	VMOV V1.B16, V26.B16                              \ // save VB'; MONT_MUL will clobber V1
	MONT_MUL_V0_VZ(Vscale, V0)                        \
	VST1.P [V0.H8], 16(evenDataAddr)                  \
	MONT_MUL(V26, Vscale, V1)                         \
	VST1.P [V1.H8], 16(oddDataAddr)

#define inttL1to3(evenDataAddr, oddDataAddr, VZ) \
	VLD1 (evenDataAddr), [V0.H8]                      \
	VLD1 (oddDataAddr), [V1.H8]                       \
	INTT_BUTTERFLY01(VZ)                              \
	VST1.P [V0.H8], 16(evenDataAddr)                  \
	VST1.P [V1.H8], 16(oddDataAddr)

#define LOAD_ZETA_NTT(VZ) \	
	MOVHU.P 2(R1), R10 \
	VDUP R10, VZ.H8

#define LOAD_ZETA_INTT(VZ) \	
	MOVHU.W -2(R1), R10 \
	VDUP R10, VZ.H8

TEXT ·internalNTTNEON(SB), NOSPLIT, $0-8
	MOVD f+0(FP), R0

	MOVD $·zetasMontgomery(SB), R1
	ADD $2, R1, R1 // point to zetasMontgomery[1]

	// Setup pinned registers
	MOVD $3329, R8
	VDUP R8, V31.H8
	MOVD $3327, R8
	VDUP R8, V30.H8
	MOVD $1, R8
	VDUP R8, V29.H8
	VEOR V28.B16, V28.B16, V28.B16

	// Layer L0: len=128
	LOAD_ZETA_NTT(V7)
	MOVD R0, R11
	ADD $256, R11, R12
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)

	// Layer L1: len=64
	LOAD_ZETA_NTT(V7)
	LOAD_ZETA_NTT(V6)
	MOVD R0, R11
	ADD $128, R11, R12	
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	ADD $256, R0, R11
	ADD $128, R11, R12	
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)

	// Layer L2: len=32
	LOAD_ZETA_NTT(V7)
	LOAD_ZETA_NTT(V6)
	MOVD R0, R11
	ADD $64, R11, R12		
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	ADD $128, R0, R11
	ADD $64, R11, R12
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)
	LOAD_ZETA_NTT(V7)
	LOAD_ZETA_NTT(V6)
	ADD $256, R0, R11
	ADD $64, R11, R12
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	ADD $384, R0, R11
	ADD $64, R11, R12
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)

	// Layer L3: len=16
	LOAD_ZETA_NTT(V7)
	LOAD_ZETA_NTT(V6)
	MOVD R0, R11
	ADD $32, R11, R12		
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	ADD $64, R0, R11
	ADD $32, R11, R12
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)

	LOAD_ZETA_NTT(V7)
	LOAD_ZETA_NTT(V6)
	ADD $128, R0, R11
	ADD $32, R11, R12
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	ADD $192, R0, R11
	ADD $32, R11, R12
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)
	
	LOAD_ZETA_NTT(V7)
	LOAD_ZETA_NTT(V6)
	ADD $256, R0, R11
	ADD $32, R11, R12
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	ADD $320, R0, R11
	ADD $32, R11, R12
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)

	LOAD_ZETA_NTT(V7)
	LOAD_ZETA_NTT(V6)
	ADD $384, R0, R11
	ADD $32, R11, R12
	nttL0to3(R11, R12, V7)
	nttL0to3(R11, R12, V7)
	ADD $448, R0, R11
	ADD $32, R11, R12	
	nttL0to3(R11, R12, V6)
	nttL0to3(R11, R12, V6)

	// Layer L4: len=8. butterfly (plain adjacent pairs).
	MOVD R0, R3
	MOVD $0, R4
ntt_len8_loop:
	CMP $16, R4
	BGE ntt_len4_start
	LOAD_ZETA_NTT(V7)
	VLD1 (R3), [V0.H8, V1.H8]
	BUTTERFLY01(V7)
	VST1.P [V0.H8, V1.H8], 32(R3)
	ADD $1, R4, R4
	B ntt_len8_loop

	// Layer L5: len=4. butterfly with prepacked zetas.
ntt_len4_start:
	MOVD R0, R3
	MOVD $0, R4
	MOVD $·nttZetasL5L6Packed(SB), R13
ntt_len4_loop:
	CMP $8, R4
	BGE ntt_len2_start

	VLD1.P (16)(R13), [V7.H8]
	VLD1 (R3), [V20.H8, V21.H8]
	VZIP1 V21.D2, V20.D2, V0.D2
	VZIP2 V21.D2, V20.D2, V1.D2
	BUTTERFLY01(V7)
	VZIP1 V1.D2, V0.D2, V20.D2
	VZIP2 V1.D2, V0.D2, V21.D2
	VST1.P [V20.H8, V21.H8], 32(R3)

	VLD1.P (16)(R13), [V7.H8]
	VLD1 (R3), [V20.H8, V21.H8]
	VZIP1 V21.D2, V20.D2, V0.D2
	VZIP2 V21.D2, V20.D2, V1.D2
	BUTTERFLY01(V7)
	VZIP1 V1.D2, V0.D2, V20.D2
	VZIP2 V1.D2, V0.D2, V21.D2
	VST1.P [V20.H8, V21.H8], 32(R3)

	ADD $1, R4, R4
	B ntt_len4_loop

	// Layer L6: len=2. butterfly with prepacked zetas.
ntt_len2_start:
	MOVD R0, R3
	MOVD $0, R4
ntt_len2_loop:
	CMP $8, R4
	BGE ntt_len2_done

	// Block 1
	VLD1.P (16)(R13), [V7.H8]
	VLD1 (R3), [V20.H8, V21.H8]
	VZIP1 V21.D2, V20.D2, V22.D2
	VZIP2 V21.D2, V20.D2, V23.D2
	VZIP1 V23.S4, V22.S4, V20.S4
	VZIP2 V23.S4, V22.S4, V21.S4
	VZIP1 V21.D2, V20.D2, V0.D2
	VZIP2 V21.D2, V20.D2, V1.D2
	BUTTERFLY01(V7)
	VZIP1 V1.S4, V0.S4, V20.S4
	VZIP2 V1.S4, V0.S4, V21.S4
	VST1.P [V20.H8, V21.H8], 32(R3)

	// Block 2
	VLD1.P (16)(R13), [V7.H8]
	VLD1 (R3), [V20.H8, V21.H8]
	VZIP1 V21.D2, V20.D2, V22.D2
	VZIP2 V21.D2, V20.D2, V23.D2
	VZIP1 V23.S4, V22.S4, V20.S4
	VZIP2 V23.S4, V22.S4, V21.S4
	VZIP1 V21.D2, V20.D2, V0.D2
	VZIP2 V21.D2, V20.D2, V1.D2
	BUTTERFLY01(V7)
	VZIP1 V1.S4, V0.S4, V20.S4
	VZIP2 V1.S4, V0.S4, V21.S4
	VST1.P [V20.H8, V21.H8], 32(R3)

	ADD $1, R4, R4
	B ntt_len2_loop

ntt_len2_done:
	RET

// func internalInverseNTTNEON(f *nttElement)
// All 7 inverse NTT layers (Gentleman-Sande, len=2..128) + scale by 1441.
TEXT ·internalInverseNTTNEON(SB), NOSPLIT, $0-8
	MOVD f+0(FP), R0

	// Setup pinned registers
	MOVD $3329, R8
	VDUP R8, V31.H8
	MOVD $3327, R8
	VDUP R8, V30.H8
	MOVD $1, R8
	VDUP R8, V29.H8
	VEOR V28.B16, V28.B16, V28.B16
	MOVD $6658, R8
	VDUP R8, V27.H8

	// ── L6: len=2. 64 groups. zeta = zetasMontgomery[127..64] ────────────
	MOVD $·inttZetasL6L5Packed(SB), R13
	MOVD R0, R3
	MOVD $0, R4
intt_len2_loop:
	CMP $8, R4
	BGE intt_len4_start

	// Block 1
	VLD1.P (16)(R13), [V7.H8]
	VLD1 (R3), [V20.H8, V21.H8]
	VZIP1 V21.D2, V20.D2, V22.D2
	VZIP2 V21.D2, V20.D2, V23.D2
	VZIP1 V23.S4, V22.S4, V20.S4
	VZIP2 V23.S4, V22.S4, V21.S4
	VZIP1 V21.D2, V20.D2, V0.D2
	VZIP2 V21.D2, V20.D2, V1.D2
	INTT_BUTTERFLY01(V7)
	VZIP1 V1.S4, V0.S4, V20.S4
	VZIP2 V1.S4, V0.S4, V21.S4
	VST1.P [V20.H8, V21.H8], 32(R3)

	// Block 2
	VLD1.P (16)(R13), [V7.H8]
	VLD1 (R3), [V20.H8, V21.H8]
	VZIP1 V21.D2, V20.D2, V22.D2
	VZIP2 V21.D2, V20.D2, V23.D2
	VZIP1 V23.S4, V22.S4, V20.S4
	VZIP2 V23.S4, V22.S4, V21.S4
	VZIP1 V21.D2, V20.D2, V0.D2
	VZIP2 V21.D2, V20.D2, V1.D2
	INTT_BUTTERFLY01(V7)
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
	CMP $8, R4
	BGE intt_len8_start

	// Block 1
	VLD1.P (16)(R13), [V7.H8]
	VLD1 (R3), [V20.H8, V21.H8]
	VZIP1 V21.D2, V20.D2, V0.D2
	VZIP2 V21.D2, V20.D2, V1.D2
	INTT_BUTTERFLY01(V7)
	VZIP1 V1.D2, V0.D2, V20.D2
	VZIP2 V1.D2, V0.D2, V21.D2
	VST1.P [V20.H8, V21.H8], 32(R3)

	// Block 2
	VLD1.P (16)(R13), [V7.H8]
	VLD1 (R3), [V20.H8, V21.H8]
	VZIP1 V21.D2, V20.D2, V0.D2
	VZIP2 V21.D2, V20.D2, V1.D2
	INTT_BUTTERFLY01(V7)
	VZIP1 V1.D2, V0.D2, V20.D2
	VZIP2 V1.D2, V0.D2, V21.D2
	VST1.P [V20.H8, V21.H8], 32(R3)

	ADD $1, R4, R4
	B intt_len4_loop

	// ── L4: len=8. 16 groups. zeta = zetasMontgomery[31..16] ─────────────
intt_len8_start:
	MOVD $·zetasMontgomery(SB), R1
	ADD $64, R1, R1 // point R1 to zetasMontgomery[32]
	MOVD R0, R3
	MOVD $0, R4
intt_len8_loop:
	CMP $16, R4
	BGE intt_len16_start
	LOAD_ZETA_INTT(V7)
	VLD1 (R3), [V0.H8, V1.H8]   // load both left and right halves together (16 bytes each)
	INTT_BUTTERFLY01(V7)
	VST1.P [V0.H8, V1.H8], 32(R3)
	ADD $1, R4, R4
	B intt_len8_loop

	// ── L3: len=16. 8 groups. zeta = zetasMontgomery[15..8] ──────────────
intt_len16_start:
	LOAD_ZETA_INTT(V7)
	LOAD_ZETA_INTT(V6)
	MOVD R0, R11
	ADD $32, R11, R12
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	ADD $64, R0, R11
	ADD $32, R11, R12
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)

	LOAD_ZETA_INTT(V7)
	LOAD_ZETA_INTT(V6)
	ADD $128, R0, R11
	ADD $32, R11, R12
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	ADD $192, R0, R11
	ADD $32, R11, R12
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)

	LOAD_ZETA_INTT(V7)
	LOAD_ZETA_INTT(V6)
	ADD $256, R0, R11
	ADD $32, R11, R12
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	ADD $320, R0, R11
	ADD $32, R11, R12
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)

	LOAD_ZETA_INTT(V7)
	LOAD_ZETA_INTT(V6)
	ADD $384, R0, R11
	ADD $32, R11, R12
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	ADD $448, R0, R11
	ADD $32, R11, R12
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)

	// ── L2: len=32. 4 groups. zeta = zetasMontgomery[7..4] ───────────────
	LOAD_ZETA_INTT(V7)
	LOAD_ZETA_INTT(V6)
	MOVD R0, R11
	ADD $64, R11, R12
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	ADD $128, R0, R11
	ADD $64, R11, R12
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)

	LOAD_ZETA_INTT(V7)
	LOAD_ZETA_INTT(V6)
	ADD $256, R0, R11
	ADD $64, R11, R12
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	ADD $384, R0, R11
	ADD $64, R11, R12
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)

	// ── L1: len=64. 2 groups. zeta = zetasMontgomery[3..2] ───────────────
	LOAD_ZETA_INTT(V7)
	LOAD_ZETA_INTT(V6)
	MOVD R0, R11
	ADD $128, R11, R12
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	inttL1to3(R11, R12, V7)
	ADD $256, R0, R11
	ADD $128, R11, R12
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)
	inttL1to3(R11, R12, V6)

	// ── L0: len=128. 1 group. zeta = zetasMontgomery[1]. Scale by 1441 ───
	// Use V3 for scale (NOT V2: MONT_MUL_FIXED always clobbers V2).
	LOAD_ZETA_INTT(V7)
	MOVD $1441, R8
	VDUP R8, V3.H8    // V3 = scale = 1441
	MOVD R0, R11
	ADD $256, R11, R12
	inttL0(R11, R12, V7, V3)
	inttL0(R11, R12, V7, V3)
	inttL0(R11, R12, V7, V3)
	inttL0(R11, R12, V7, V3)
	inttL0(R11, R12, V7, V3)
	inttL0(R11, R12, V7, V3)
	inttL0(R11, R12, V7, V3)
	inttL0(R11, R12, V7, V3)
	inttL0(R11, R12, V7, V3)
	inttL0(R11, R12, V7, V3)
	inttL0(R11, R12, V7, V3)
	inttL0(R11, R12, V7, V3)
	inttL0(R11, R12, V7, V3)
	inttL0(R11, R12, V7, V3)
	inttL0(R11, R12, V7, V3)
	inttL0(R11, R12, V7, V3)

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
// Pairwise add (VADDP Vd.H8, Vn.H8, Vm.H8: Vd[0..3]=pairs(Vn), Vd[4..7]=pairs(Vm)):
//   VADDP V7.H8, V7.H8, V7.H8 → all 8 lanes = pairwise sums of V7 (4 even-acc deltas, replicated)
//   VADDP V6.H8, V6.H8, V6.H8 → same for V6 (4 odd-acc deltas)
// Re-interleave: VZIP1 Vd.H8, Vn.H8, Vm.H8: Vm=[Vd[0],Vn[0],Vd[1],Vn[1],Vd[2],Vn[2],Vd[3],Vn[3]]
//   VZIP1 V7.H8, V6.H8, V5.H8 → V5 = interleaved deltas
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
	// VADDP Vd.H8, Vn.H8, Vm.H8: Vd[0..3]=pairwise(Vn), Vd[4..7]=pairwise(Vm)
	// Using same src twice: both halves = pairwise sums of V7
	VADDP V7.H8, V7.H8, V7.H8
	VADDP V6.H8, V6.H8, V6.H8

	// fieldReduceOnce on both
	WORD $0x6e7f3cf4  // CMGT.U V20.H8, V7.H8, V31.H8  (V20=0xFFFF where V7>3329, else 0)
	VAND V20.B16, V31.B16, V20.B16
	VSUB V20.H8, V7.H8, V7.H8

	WORD $0x6e7f3cd5  // CMGT.U V21.H8, V6.H8, V31.H8  (V20=0xFFFF where V6>3329, else 0)
	VAND V21.B16, V31.B16, V21.B16
	VSUB V21.H8, V6.H8, V6.H8

	// Re-interleave: VZIP1 Va.H8, Vb.H8, Vd.H8 in Go Plan9 → ARM64 ZIP1 Vd,Vb,Va → Vd=[Vb[0],Va[0],...]
	// We want [even_sum0, odd_sum0, even_sum1, odd_sum1, ...]
	// V7 has even sums, V6 has odd sums → VZIP1 V6,V7,V5 → V5=[V7[0],V6[0],...]
	VZIP1 V6.H8, V7.H8, V5.H8

	// Add delta to acc (load acc late to avoid preserving V2 across MONT_MUL calls)
	VLD1 (R0), [V2.H8]
	VADD V5.H8, V2.H8, V2.H8
	WORD $0x6e7f3c54  // CMGT.U V20.H8, V2.H8, V31.H8  (V20=0xFFFF where V2>3329, else 0)
	VAND V20.B16, V31.B16, V20.B16
	VSUB V20.H8, V2.H8, V2.H8

	VST1.P [V2.H8], (16)(R0)

	ADD $16, R4, R4
	B nttmlacc_neon_loop

nttmlacc_neon_done:
	RET

TEXT ·internalNTTMulNEON(SB), NOSPLIT, $0-24
	MOVD out+0(FP), R0
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

nttml_neon_loop:
	CMP $512, R4
	BGE nttml_neon_done

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
	// VADDP Vd.H8, Vn.H8, Vm.H8: Vd[0..3]=pairwise(Vn), Vd[4..7]=pairwise(Vm)
	// Using same src twice: both halves = pairwise sums of V7
	VADDP V7.H8, V7.H8, V7.H8
	VADDP V6.H8, V6.H8, V6.H8

	// fieldReduceOnce on both
	WORD $0x6e7f3cf4  // CMGT.U V20.H8, V7.H8, V31.H8  (V20=0xFFFF where V7>3329, else 0)
	VAND V20.B16, V31.B16, V20.B16
	VSUB V20.H8, V7.H8, V7.H8

	WORD $0x6e7f3cd5  // CMGT.U V21.H8, V6.H8, V31.H8  (V20=0xFFFF where V6>3329, else 0)
	VAND V21.B16, V31.B16, V21.B16
	VSUB V21.H8, V6.H8, V6.H8

	// Re-interleave: VZIP1 Va.H8, Vb.H8, Vd.H8 in Go Plan9 → ARM64 ZIP1 Vd,Vb,Va → Vd=[Vb[0],Va[0],...]
	// We want [even_sum0, odd_sum0, even_sum1, odd_sum1, ...]
	// V7 has even sums, V6 has odd sums → VZIP1 V6,V7,V5 → V5=[V7[0],V6[0],...]
	VZIP1 V6.H8, V7.H8, V5.H8

	VST1.P [V5.H8], (16)(R0)

	ADD $16, R4, R4
	B nttml_neon_loop

nttml_neon_done:
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

	WORD $0x6e7f3cf4  // CMGT.U V20.H8, V7.H8, V31.H8  (V20=0xFFFF where V7>3329, else 0)
	VAND V20.B16, V31.B16, V20.B16
	VSUB V20.H8, V7.H8, V7.H8

	WORD $0x6e7f3cd5  // CMGT.U V21.H8, V6.H8, V31.H8  (V20=0xFFFF where V6>3329, else 0)
	VAND V21.B16, V31.B16, V21.B16
	VSUB V21.H8, V6.H8, V6.H8

	VZIP1 V6.H8, V7.H8, V5.H8

	// Convert delta from Montgomery to standard domain
	MONT_MUL(V5, V27, V5)

	VLD1 (R0), [V2.H8]
	VADD V5.H8, V2.H8, V2.H8
	WORD $0x6e7f3c54  // CMGT.U V20.H8, V2.H8, V31.H8  (V20=0xFFFF where V2>3329, else 0)
	VAND V20.B16, V31.B16, V20.B16
	VSUB V20.H8, V2.H8, V2.H8

	VST1.P [V2.H8], (16)(R0)

	ADD $16, R4, R4
	B nttmlacc_kg_neon_loop

nttmlacc_kg_neon_done:
	RET

// samplePolyCBD2NEON computes D_eta=2 coefficients from 128 PRF bytes.
// This version vectorizes bit extraction and coefficient packing in 16-byte chunks.
DATA ·cbd2DiffMapLow+0(SB)/8, $0x00000002010000FF
DATA ·cbd2DiffMapLow+8(SB)/8, $0x0000000000000000
GLOBL ·cbd2DiffMapLow(SB), RODATA, $16

DATA ·cbd2DiffMapHigh+0(SB)/8, $0x0000000000000D0C
DATA ·cbd2DiffMapHigh+8(SB)/8, $0x0000000000000000
GLOBL ·cbd2DiffMapHigh(SB), RODATA, $16

// func samplePolyCBD2NEON(dst *ringElement, buf *[128]byte)
TEXT ·samplePolyCBD2NEON(SB), NOSPLIT, $0-16
	MOVD dst+0(FP), R0
	MOVD buf+8(FP), R1
	MOVD $8, R2            // 128 / 16 chunks

	MOVD $0x55, R3
	VDUP R3, V23.B16       // pair-bit mask
	MOVD $0x03, R3
	VDUP R3, V22.B16       // 2-bit mask
	MOVD $2, R3
	VDUP R3, V21.B16       // +2 bias for [0..4] encoding

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
	VTBL V3.B16, [V16.B16], V7.B16   // t0 low byte
	VTBL V3.B16, [V17.B16], V8.B16   // t0 high byte
	VTBL V5.B16, [V16.B16], V9.B16   // t1 low byte
	VTBL V5.B16, [V17.B16], V10.B16  // t1 high byte

	// Pack little-endian uint16 lanes for t0 and t1.
	VZIP1 V8.B16, V7.B16, V11.B16
	VZIP2 V8.B16, V7.B16, V12.B16
	VZIP1 V10.B16, V9.B16, V13.B16
	VZIP2 V10.B16, V9.B16, V14.B16

	// Interleave t0/t1 halfwords to coefficient order c0,c1,c2,c3,...
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

// samplePolyCBD3NEON computes D_eta=3 coefficients from 192 PRF bytes.
// Each iteration consumes 24 bytes and emits 32 uint16 coefficients.
DATA ·cbd3ShufA+0(SB)/8, $0xFF050403FF020100
DATA ·cbd3ShufA+8(SB)/8, $0xFF0B0A09FF080706
GLOBL ·cbd3ShufA(SB), RODATA, $16

DATA ·cbd3ShufB+0(SB)/8, $0xFF050403FF020100
DATA ·cbd3ShufB+8(SB)/8, $0xFF0B0A09FF080706
GLOBL ·cbd3ShufB(SB), RODATA, $16

// func samplePolyCBD3NEON(dst *ringElement, buf *[192]byte)
TEXT ·samplePolyCBD3NEON(SB), NOSPLIT, $0-16
	MOVD dst+0(FP), R0
	MOVD buf+8(FP), R1
	MOVD $8, R2

	MOVD $·cbd3ShufA(SB), R3
	VLD1 (R3), [V30.B16]
	MOVD $·cbd3ShufB(SB), R3
	VLD1 (R3), [V29.B16]
	MOVD $0x00249249, R3
	VDUP R3, V28.S4
	MOVD $0x006DB6DB, R3
	VDUP R3, V27.S4
	MOVD $0x7, R3
	VDUP R3, V26.S4
	VSHL $16, V26.S4, V25.S4

	MOVD $3, R3
	VDUP R3, V24.H8
	MOVD $3329, R3
	VDUP R3, V23.H8
	VEOR V22.B16, V22.B16, V22.B16

samplecbd3_loop:
	CBZ R2, samplecbd3_done

	VLD1 (R1), [V0.B16]
	ADD $12, R1, R12
	VLD1 (R12), [V1.B16]
	// Two overlapping 12-byte windows per iteration:
	// block A uses bytes [0..11] from V0, block B uses bytes [12..23] from V1.
	// This emits 32 coefficients (64 bytes) per loop.

	// ---- block A: bytes [0..11] ----
	VTBL V30.B16, [V0.B16], V2.B16
	// After VTBL, each 32-bit lane packs one 3-byte group for bit-sliced popcount.

	VUSHR $1, V2.S4, V3.S4
	VUSHR $2, V2.S4, V4.S4
	VAND V28.B16, V2.B16, V2.B16
	VAND V28.B16, V3.B16, V3.B16
	VAND V28.B16, V4.B16, V4.B16
	VADD V3.S4, V2.S4, V2.S4
	VADD V4.S4, V2.S4, V2.S4

	VUSHR $3, V2.S4, V3.S4
	VADD V27.S4, V2.S4, V2.S4
	VSUB V3.S4, V2.S4, V2.S4
	// Lane values now hold (a-b+3) in [0..6] for two coeffs per 6-bit chunk.

	VSHL $10, V2.S4, V4.S4
	VUSHR $12, V2.S4, V5.S4
	VUSHR $2, V2.S4, V6.S4
	VAND V26.B16, V2.B16, V7.B16
	VAND V25.B16, V4.B16, V4.B16
	VAND V26.B16, V5.B16, V5.B16
	VAND V25.B16, V6.B16, V6.B16
	VADD V4.H8, V7.H8, V7.H8
	VADD V6.H8, V5.H8, V5.H8

	VZIP1 V5.S4, V7.S4, V8.S4
	VZIP2 V5.S4, V7.S4, V9.S4
	// V8/V9 are int16 coefficients in [-3,3] before field mapping.

	VSUB V24.H8, V8.H8, V8.H8
	VSUB V24.H8, V9.H8, V9.H8
	VUSHR $15, V8.H8, V10.H8
	VUSHR $15, V9.H8, V11.H8
	VSUB V10.H8, V22.H8, V10.H8
	VSUB V11.H8, V22.H8, V11.H8
	VAND V23.B16, V10.B16, V10.B16
	VAND V23.B16, V11.B16, V11.B16
	VADD V10.H8, V8.H8, V8.H8
	VADD V11.H8, V9.H8, V9.H8
	// Same signed-to-field mapping as CBD2: add q to negative lanes.

	VST1.P [V8.B16], 16(R0)
	VST1.P [V9.B16], 16(R0)

	// ---- block B: bytes [12..23], represented by V1[4..15] ----
	VTBL V29.B16, [V1.B16], V2.B16

	VUSHR $1, V2.S4, V3.S4
	VUSHR $2, V2.S4, V4.S4
	VAND V28.B16, V2.B16, V2.B16
	VAND V28.B16, V3.B16, V3.B16
	VAND V28.B16, V4.B16, V4.B16
	VADD V3.S4, V2.S4, V2.S4
	VADD V4.S4, V2.S4, V2.S4

	VUSHR $3, V2.S4, V3.S4
	VADD V27.S4, V2.S4, V2.S4
	VSUB V3.S4, V2.S4, V2.S4

	VSHL $10, V2.S4, V4.S4
	VUSHR $12, V2.S4, V5.S4
	VUSHR $2, V2.S4, V6.S4
	VAND V26.B16, V2.B16, V7.B16
	VAND V25.B16, V4.B16, V4.B16
	VAND V26.B16, V5.B16, V5.B16
	VAND V25.B16, V6.B16, V6.B16
	VADD V4.H8, V7.H8, V7.H8
	VADD V6.H8, V5.H8, V5.H8

	VZIP1 V5.S4, V7.S4, V8.S4
	VZIP2 V5.S4, V7.S4, V9.S4

	VSUB V24.H8, V8.H8, V8.H8
	VSUB V24.H8, V9.H8, V9.H8
	VUSHR $15, V8.H8, V10.H8
	VUSHR $15, V9.H8, V11.H8
	VSUB V10.H8, V22.H8, V10.H8
	VSUB V11.H8, V22.H8, V11.H8
	VAND V23.B16, V10.B16, V10.B16
	VAND V23.B16, V11.B16, V11.B16
	VADD V10.H8, V8.H8, V8.H8
	VADD V11.H8, V9.H8, V9.H8

	VST1.P [V8.B16], 16(R0)
	VST1.P [V9.B16], 16(R0)

	ADD $24, R1, R1
	SUB $1, R2, R2
	B samplecbd3_loop

samplecbd3_done:
	RET

// decodeAndDecompressU10NEON decodes d=10 ciphertext chunks into ring elements.
//
// Layout facts for one 10-byte block:
//   - 80 payload bits contain 8 coefficients, each 10 bits.
//   - We unpack those 8 values with scalar shifts/masks into two 64-bit words,
//     then move them into one NEON vector as 8xuint16.
//   - The shared Decompress_10 arithmetic is vectorized for all 8 lanes.
//
// Decompress_10 per lane y:
//   dividend = y * q
//   out      = (dividend >> 10) + ((dividend >> 9) & 1)
//
// func decodeAndDecompressU10NEON(dst []ringElement, c []byte)
TEXT ·decodeAndDecompressU10NEON(SB), NOSPLIT, $0-48
	MOVD dst_base+0(FP), R0
	MOVD dst_len+8(FP), R1
	MOVD c_base+24(FP), R2

	CBZ R1, decode_u10_neon_done

	MOVD $3329, R3
	VDUP R3, V1.H8
	MOVD $1, R3
	VDUP R3, V24.S4

decode_u10_neon_ring_loop:
	// One ring has 256 coefficients -> 32 blocks of 8 coefficients.
	MOVD $32, R5

decode_u10_neon_block_loop:
	// Load packed 80 bits: low 64 bits in R6 and high 16 bits in R7.
	MOVD (R2), R6
	MOVHU 8(R2), R7

	// Extract c0..c5 from R6.
	AND $0x3FF, R6, R10

	UBFX $10, R6, $10, R11
	UBFX $20, R6, $10, R12
	UBFX $30, R6, $10, R13
	UBFX $40, R6, $10, R14
	UBFX $50, R6, $10, R15

	// c6 crosses the 64-bit boundary:
	//   low 4 bits from R6[63:60], high 6 bits from R7[5:0].
	EXTR $60, R6, R7, R16
	AND $0x3FF, R16, R16

	// c7 comes from R7[15:6].
	UBFX $6, R7, $10, R17

	// Pack c0..c3 and c4..c7 into two 64-bit words.
	ORR R11<<16, R10, R10
	ORR R12<<32, R10, R10
	ORR R13<<48, R10, R10
	VMOV R10, V0.D[0]

	ORR R15<<16, R14, R14
	ORR R16<<32, R14, R14
	ORR R17<<48, R14, R14
	VMOV R14, V0.D[1]

	// Vectorized Decompress_10 on 8 lanes:
	//   dividend = y*q (32-bit lanes via UMULL/UMULL2)
	//   roundbit = (dividend >> 9) & 1
	//   out      = (dividend >> 10) + roundbit
	WORD $0x2E61C015 // UMULL  V21.S4, V0.H4, V1.H4
	WORD $0x6E61C016 // UMULL2 V22.S4, V0.H8, V1.H8

	VUSHR $9, V21.S4, V23.S4
	VUSHR $9, V22.S4, V25.S4
	VAND V24.B16, V23.B16, V23.B16
	VAND V24.B16, V25.B16, V25.B16
	VUSHR $10, V21.S4, V21.S4
	VUSHR $10, V22.S4, V22.S4
	VADD V23.S4, V21.S4, V21.S4
	VADD V25.S4, V22.S4, V22.S4
	VSHL $16, V21.S4, V21.S4
	VSHL $16, V22.S4, V22.S4
	WORD $0x0F1086B5 // SHRN  V21.H4, V21.S4, #16
	WORD $0x4F1086D5 // SHRN2 V21.H8, V22.S4, #16

	VST1.P [V21.H8], 16(R0)
	ADD $10, R2, R2
	SUB $1, R5, R5
	CBNZ R5, decode_u10_neon_block_loop

	SUB $1, R1, R1
	CBNZ R1, decode_u10_neon_ring_loop

decode_u10_neon_done:
	RET

// decodeAndDecompressU11NEON decodes d=11 ciphertext chunks into ring elements.
// Each 11-byte block contains 8 packed coefficients. We unpack those 8 values
// with one 64-bit load plus a 24-bit tail load, then use NEON for the shared
// 8-lane Decompress_11 arithmetic.
// func decodeAndDecompressU11NEON(dst []ringElement, c []byte)
TEXT ·decodeAndDecompressU11NEON(SB), NOSPLIT, $0-48
	MOVD dst_base+0(FP), R0
	MOVD dst_len+8(FP), R1
	MOVD c_base+24(FP), R2

	CBZ R1, decode_u11_neon_done

	MOVD $3329, R3
	VDUP R3, V1.H8
	MOVD $1, R3
	VDUP R3, V24.S4

decode_u11_neon_ring_loop:
	// One ring has 256 coefficients -> 32 blocks of 8 coefficients.
	MOVD $32, R5

decode_u11_neon_block_loop:
	// Load packed 88 bits: low 64 bits in R6 and high 24 bits split as R7|R8.
	MOVD (R2), R6
	MOVHU 8(R2), R7
	MOVBU 10(R2), R8

	// Merge byte10 with bytes8..9 to form a contiguous 24-bit tail in R7.
	MOVD R8, R9
	LSL $16, R9, R9
	ORR R9, R7, R7

	// Extract c0..c4 from R6 (each coefficient is 11 bits).
	AND $0x7FF, R6, R10

	UBFX $11, R6, $11, R11
	UBFX $22, R6, $11, R12
	UBFX $33, R6, $11, R13
	UBFX $44, R6, $11, R14

	// c5 crosses the 64-bit boundary:
	//   low 9 bits from R6[63:55], high 2 bits from R7[1:0].
	EXTR $55, R6, R7, R15
	AND $0x7FF, R15, R15

	// c6 and c7 are fully in tail bits R7.
	UBFX $2, R7, $11, R16

	UBFX $13, R7, $11, R17

	// Pack c0..c3 and c4..c7 into two 64-bit words, then move to V0 lanes.
	ORR R11<<16, R10, R10
	ORR R12<<32, R10, R10
	ORR R13<<48, R10, R10
	VMOV R10, V0.D[0]

	ORR R15<<16, R14, R14
	ORR R16<<32, R14, R14
	ORR R17<<48, R14, R14
	VMOV R14, V0.D[1]

	// Vectorized Decompress_11 on 8 lanes:
	//   dividend = y*q
	//   out = (dividend >> 11) + ((dividend >> 10) & 1)
	WORD $0x2E61C015 // UMULL  V21.S4, V0.H4, V1.H4
	WORD $0x6E61C016 // UMULL2 V22.S4, V0.H8, V1.H8

	VUSHR $10, V21.S4, V23.S4
	VUSHR $10, V22.S4, V25.S4
	VAND V24.B16, V23.B16, V23.B16
	VAND V24.B16, V25.B16, V25.B16
	VUSHR $11, V21.S4, V21.S4
	VUSHR $11, V22.S4, V22.S4
	VADD V23.S4, V21.S4, V21.S4
	VADD V25.S4, V22.S4, V22.S4
	VSHL $16, V21.S4, V21.S4
	VSHL $16, V22.S4, V22.S4
	WORD $0x0F1086B5 // SHRN  V21.H4, V21.S4, #16
	WORD $0x4F1086D5 // SHRN2 V21.H8, V22.S4, #16

	// Store 8 decompressed coefficients (8 * uint16 = 16 bytes).
	VST1.P [V21.H8], 16(R0)
	ADD $11, R2, R2
	SUB $1, R5, R5
	CBNZ R5, decode_u11_neon_block_loop

	SUB $1, R1, R1
	CBNZ R1, decode_u11_neon_ring_loop

decode_u11_neon_done:
	RET

// polyAddAssignNEON computes dst[i] = fieldAdd(dst[i], src[i]) for all i in [0, 256).
// Uses NEON to process 8 int16 values (16 bytes) per iteration.
TEXT ·polyAddAssignNEON(SB), NOSPLIT, $0-16
	MOVD dst+0(FP), R0
	MOVD src+8(FP), R1

	MOVD $3329, R2
	VDUP R2, V31.H8

	MOVD $8, R2

poly_add_neon_loop:
	VLD1 (R0), [V0.H8, V1.H8, V2.H8, V3.H8]  // load 64 bytes = 16 coefficients
	VLD1.P 64(R1), [V4.H8, V5.H8, V6.H8, V7.H8]

	VADD V4.H8, V0.H8, V0.H8
	VADD V5.H8, V1.H8, V1.H8
	VADD V6.H8, V2.H8, V2.H8
	VADD V7.H8, V3.H8, V3.H8

	// reduction
	WORD   $0x6e7f3c14				  // CMGT.U V20.H8, V0.H8, V31.H8 (V0 >= q ? 0xFFFF : 0)
	VAND   V31.B16, V20.B16, V20.B16  // q if underflow
	VSUB   V20.H8, V0.H8, V0.H8       // VA = VA - q if underflow

	WORD   $0x6e7f3c35				  // CMGT.U V21.H8, V1.H8, V31.H8 (V1 >= q ? 0xFFFF : 0)
	VAND   V31.B16, V21.B16, V21.B16  // q if underflow
	VSUB   V21.H8, V1.H8, V1.H8       // VA = VA - q if underflow

	WORD   $0x6e7f3c56				  // CMGT.U V22.H8, V2.H8, V31.H8 (V2 >= q ? 0xFFFF : 0)
	VAND   V31.B16, V22.B16, V22.B16  // q if underflow
	VSUB   V22.H8, V2.H8, V2.H8       // VA = VA - q if underflow

	WORD   $0x6e7f3c77				  // CMGT.U V23.H8, V3.H8, V31.H8 (V3 >= q ? 0xFFFF : 0)
	VAND   V31.B16, V23.B16, V23.B16  // q if underflow
	VSUB   V23.H8, V3.H8, V3.H8       // VA = VA - q if underflow

	VST1.P [V0.H8, V1.H8, V2.H8, V3.H8], 64(R0)

	SUB $1, R2, R2
	CBNZ R2, poly_add_neon_loop

poly_add_neon_done:
	RET

// polySubAssignNEON computes dst[i] = fieldSub(dst[i], src[i]) for all i in [0, 256).
// fieldSub: x = uint16(a - b + q); return fieldReduceOnce(x)
TEXT ·polySubAssignNEON(SB), NOSPLIT, $0-16
	MOVD dst+0(FP), R0
	MOVD src+8(FP), R1

	MOVD $3329, R2
	VDUP R2, V31.H8

	MOVD $8, R2

poly_sub_neon_loop:
	VLD1 (R0), [V0.H8, V1.H8, V2.H8, V3.H8]  // load 64 bytes = 16 coefficients
	VLD1.P 64(R1), [V4.H8, V5.H8, V6.H8, V7.H8]

	VSUB V4.H8, V0.H8, V0.H8
	VADD V31.H8, V0.H8, V0.H8

	VSUB V5.H8, V1.H8, V1.H8
	VADD V31.H8, V1.H8, V1.H8

	VSUB V6.H8, V2.H8, V2.H8
	VADD V31.H8, V2.H8, V2.H8

	VSUB V7.H8, V3.H8, V3.H8
	VADD V31.H8, V3.H8, V3.H8

	// reduction
	WORD   $0x6e7f3c14				  // CMGT.U V20.H8, V0.H8, V31.H8 (V0 >= q ? 0xFFFF : 0)
	VAND   V31.B16, V20.B16, V20.B16  // q if underflow
	VSUB   V20.H8, V0.H8, V0.H8       // VA = VA - q if underflow

	WORD   $0x6e7f3c35				  // CMGT.U V21.H8, V1.H8, V31.H8 (V1 >= q ? 0xFFFF : 0)
	VAND   V31.B16, V21.B16, V21.B16  // q if underflow
	VSUB   V21.H8, V1.H8, V1.H8       // VA = VA - q if underflow

	WORD   $0x6e7f3c56				  // CMGT.U V22.H8, V2.H8, V31.H8 (V2 >= q ? 0xFFFF : 0)
	VAND   V31.B16, V22.B16, V22.B16  // q if underflow
	VSUB   V22.H8, V2.H8, V2.H8       // VA = VA - q if underflow

	WORD   $0x6e7f3c77				  // CMGT.U V23.H8, V3.H8, V31.H8 (V3 >= q ? 0xFFFF : 0)
	VAND   V31.B16, V23.B16, V23.B16  // q if underflow
	VSUB   V23.H8, V3.H8, V3.H8       // VA = VA - q if underflow

	VST1.P [V0.H8, V1.H8, V2.H8, V3.H8], 64(R0)

	SUB $1, R2, R2
	CBNZ R2, poly_sub_neon_loop

poly_sub_neon_done:
	RET

// ringCompressAndEncode4NEON computes ByteEncode_4(Compress_4(f)).
//
// 8-lane vectorized compress, then efficient scalar packing without stack:
//   - Load 8 coefficients, UMULL by 20159, extract high16, +32, >>6, &0x0f
//   - Use UMOV to extract each 16-bit lane to scalar regs
//   - Pack 8 compressed 4-bit values into 4 output bytes using bitfield OR
//   - Inspired by decodeAndDecompressU10NEON's packing strategy
//
// 16 iterations × 8 coefficients = 128 pairs = 256 total coefficients
// No stack spills - direct register-to-register packing.
// Expected 2-3x speedup vs scalar loop.
//
// func ringCompressAndEncode4NEON(out []byte, f *ringElement)
TEXT ·ringCompressAndEncode4NEON(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R0
	MOVD f+24(FP), R1

	// Setup constants
	MOVD $20159, R2
	VDUP R2, V1.H8           // V1 = [20159 x 8]
	MOVD $32, R2
	VDUP R2, V23.S4          // V23 = [32, 32, 32, 32]
	MOVD $0x0f, R2
	VDUP R2, V24.S4          // V24 = [15, 15, 15, 15]

	MOVD $16, R2             // 16 iterations

compress_encode4_neon_loop:
	// Load 8 coefficients
	VLD1.P 16(R1), [V0.H8]

	// UMULL and reduce to 4-bit compressed values
	WORD $0x2E61C015 // UMULL V21.S4, V0.H4, V1.H4   (low 4)
	WORD $0x6E61C016 // UMULL2 V22.S4, V0.H8, V1.H8  (high 4)

	VUSHR $16, V21.S4, V21.S4
	VUSHR $16, V22.S4, V22.S4
	VADD V23.S4, V21.S4, V21.S4
	VADD V23.S4, V22.S4, V22.S4
	VUSHR $6, V21.S4, V21.S4
	VUSHR $6, V22.S4, V22.S4
	VAND V24.B16, V21.B16, V21.B16
	VAND V24.B16, V22.B16, V22.B16

	// Narrow to 16-bit
	VSHL $16, V21.S4, V21.S4
	VSHL $16, V22.S4, V22.S4
	WORD $0x0F1086B5 // SHRN  V21.H4, V21.S4, #16
	WORD $0x4F1086D5 // SHRN2 V21.H8, V22.S4, #16
	// Now V21.H8 = [c0, c1, c2, c3, c4, c5, c6, c7]
	
	// Efficient packing: pair consecutive lanes and combine
	// Use ZIP1/ZIP2 to extract even/odd lanes into separate registers
	VZIP1 V21.H8, V21.H8, V25.H8   // V25 = [c0, c2, c4, c6, c0, c2, c4, c6]
	VZIP2 V21.H8, V21.H8, V26.H8   // V26 = [c1, c3, c5, c7, c1, c3, c5, c7]
	
	// Shift odd lanes left and add: byte = even | (odd << 4)
	VSHL $4, V26.H8, V26.H8
	VADD V26.H8, V25.H8, V25.H8    // V25 = [c0|(c1<<4), c2|(c3<<4), c4|(c5<<4), c6|(c7<<4), ...]
	

	// Narrow to bytes
	VSHL $8, V25.H8, V25.H8
	WORD $0x0F211B39                // SHRN V25.B8, V25.H8, #8
	
	// Write 4 bytes
	VST1 [V25.B8], (R0)
	ADD $4, R0

	SUB $1, R2
	CBNZ R2, compress_encode4_neon_loop

	RET
