// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

#include "textflag.h"

// NEON keccakx4: 4-way Keccak-f[1600] using 2 passes of 2-wide NEON.
//
// State4 layout: [100]uint64, slot j = [inst0, inst1, inst2, inst3] (32 bytes).
// Pass 1: load bytes [0..15] of each slot → V0-V24 hold instances {0,1}.
// Pass 2: load bytes [16..31] of each slot → V0-V24 hold instances {2,3}.
//
// Register allocation (per pass):
//   V0-V24:  25 Keccak lanes (each V.D2 holds 2 parallel 64-bit instances)
//   V25-V29: θ column parity C[0..4]
//   V30:     temp (ρ+π save V1 / χ save B[0] per row)
//   V31:     temp (χ save B[1] per row)
//
// ROT64(n, Vsrc, Vdst): rotate Vsrc left by n bits into Vdst (2 instructions).
//   VSHL $n, Vsrc.D2, Vdst.D2       // Vdst = Vsrc << n; upper (64-n) bits = Vsrc[63-n:0]
//   VSRI $(64-n), Vsrc.D2, Vdst.D2  // SRI preserves upper (64-n) bits; fills lower n bits with Vsrc[63:64-n]
// Result: ROL(Vsrc, n). V31 is NOT used; it is free for χ.
//
// χ uses BIC (vector AND-NOT, VBIC mnemonic not recognized in Go asm).
// BIC Vd.16B, Vn.16B, Vm.16B = Vd = Vn AND NOT Vm
// WORD encoding: 0x4E601C00 | (Vm<<16) | (Vn<<5) | Vd
// For χ: ~B[x+1] & B[x+2] → BIC V25, B[x+2], B[x+1]  (V25 = B[x+2] AND NOT B[x+1])

#define ROT64(n, Vsrc, Vdst)              \
	VSHL $(n), Vsrc.D2, Vdst.D2         \
	VSRI $(64-(n)), Vsrc.D2, Vdst.D2

// KECCAK_ROUND: one full Keccak-f round (θ + ρ+π + χ + ι).
// R5 points to current round constant (8 bytes); after macro R5 is unchanged
// (caller must ADD $8, R5, R5 between rounds).
//
// θ: C[x] = column XOR; D[x] = C[x-1] ^ ROL(C[x+1],1); XOR D into each lane.
// ρ+π: merged — rotate each source directly into its π-destination.
//       Cycle: 1→10→7→11→17→18→3→5→16→8→21→24→4→15→23→19→13→12→2→20→14→22→9→6→1
//       Process backward; save V1 first (used last).
// χ: A'[x] = B[x] ^ (~B[x+1] & B[x+2]) per row.
// ι: A'[0,0] ^= roundConstant.

#define KECCAK_ROUND \
	/* ===== θ: column parities ===== */                            \
	VEOR V0.B16, V5.B16, V25.B16                                   \
	VEOR V25.B16, V10.B16, V25.B16                                 \
	VEOR V25.B16, V15.B16, V25.B16                                 \
	VEOR V25.B16, V20.B16, V25.B16                                 \
	VEOR V1.B16, V6.B16, V26.B16                                   \
	VEOR V26.B16, V11.B16, V26.B16                                 \
	VEOR V26.B16, V16.B16, V26.B16                                 \
	VEOR V26.B16, V21.B16, V26.B16                                 \
	VEOR V2.B16, V7.B16, V27.B16                                   \
	VEOR V27.B16, V12.B16, V27.B16                                 \
	VEOR V27.B16, V17.B16, V27.B16                                 \
	VEOR V27.B16, V22.B16, V27.B16                                 \
	VEOR V3.B16, V8.B16, V28.B16                                   \
	VEOR V28.B16, V13.B16, V28.B16                                 \
	VEOR V28.B16, V18.B16, V28.B16                                 \
	VEOR V28.B16, V23.B16, V28.B16                                 \
	VEOR V4.B16, V9.B16, V29.B16                                   \
	VEOR V29.B16, V14.B16, V29.B16                                 \
	VEOR V29.B16, V19.B16, V29.B16                                 \
	VEOR V29.B16, V24.B16, V29.B16                                 \
	/* D[0] = C[4] ^ ROL(C[1],1); XOR into column 0 */             \
	ROT64(1, V26, V30)                                              \
	VEOR V29.B16, V30.B16, V30.B16                                 \
	VEOR V0.B16, V30.B16, V0.B16                                   \
	VEOR V5.B16, V30.B16, V5.B16                                   \
	VEOR V10.B16, V30.B16, V10.B16                                 \
	VEOR V15.B16, V30.B16, V15.B16                                 \
	VEOR V20.B16, V30.B16, V20.B16                                 \
	/* D[1] = C[0] ^ ROL(C[2],1); XOR into column 1 */             \
	ROT64(1, V27, V30)                                              \
	VEOR V25.B16, V30.B16, V30.B16                                 \
	VEOR V1.B16, V30.B16, V1.B16                                   \
	VEOR V6.B16, V30.B16, V6.B16                                   \
	VEOR V11.B16, V30.B16, V11.B16                                 \
	VEOR V16.B16, V30.B16, V16.B16                                 \
	VEOR V21.B16, V30.B16, V21.B16                                 \
	/* D[2] = C[1] ^ ROL(C[3],1); XOR into column 2 */             \
	ROT64(1, V28, V30)                                              \
	VEOR V26.B16, V30.B16, V30.B16                                 \
	VEOR V2.B16, V30.B16, V2.B16                                   \
	VEOR V7.B16, V30.B16, V7.B16                                   \
	VEOR V12.B16, V30.B16, V12.B16                                 \
	VEOR V17.B16, V30.B16, V17.B16                                 \
	VEOR V22.B16, V30.B16, V22.B16                                 \
	/* D[3] = C[2] ^ ROL(C[4],1); XOR into column 3 */             \
	ROT64(1, V29, V30)                                              \
	VEOR V27.B16, V30.B16, V30.B16                                 \
	VEOR V3.B16, V30.B16, V3.B16                                   \
	VEOR V8.B16, V30.B16, V8.B16                                   \
	VEOR V13.B16, V30.B16, V13.B16                                 \
	VEOR V18.B16, V30.B16, V18.B16                                 \
	VEOR V23.B16, V30.B16, V23.B16                                 \
	/* D[4] = C[3] ^ ROL(C[0],1); XOR into column 4 */             \
	ROT64(1, V25, V30)                                              \
	VEOR V28.B16, V30.B16, V30.B16                                 \
	VEOR V4.B16, V30.B16, V4.B16                                   \
	VEOR V9.B16, V30.B16, V9.B16                                   \
	VEOR V14.B16, V30.B16, V14.B16                                 \
	VEOR V19.B16, V30.B16, V19.B16                                 \
	VEOR V24.B16, V30.B16, V24.B16                                 \
	/* ===== ρ+π: merged rotate-and-permute ===== */                \
	/* Save V1 (used last: V10 ← ROT1(V1)) */                      \
	VMOV V1.B16, V30.B16                                            \
	ROT64(44, V6,  V1)                                              \
	ROT64(20, V9,  V6)                                              \
	ROT64(61, V22, V9)                                              \
	ROT64(39, V14, V22)                                             \
	ROT64(18, V20, V14)                                             \
	ROT64(62, V2,  V20)                                             \
	ROT64(43, V12, V2)                                              \
	ROT64(25, V13, V12)                                             \
	ROT64(8,  V19, V13)                                             \
	ROT64(56, V23, V19)                                             \
	ROT64(41, V15, V23)                                             \
	ROT64(27, V4,  V15)                                             \
	ROT64(14, V24, V4)                                              \
	ROT64(2,  V21, V24)                                             \
	ROT64(55, V8,  V21)                                             \
	ROT64(45, V16, V8)                                              \
	ROT64(36, V5,  V16)                                             \
	ROT64(28, V3,  V5)                                              \
	ROT64(21, V18, V3)                                              \
	ROT64(15, V17, V18)                                             \
	ROT64(10, V11, V17)                                             \
	ROT64(6,  V7,  V11)                                             \
	ROT64(3,  V10, V7)                                              \
	ROT64(1,  V30, V10)                                             \
	/* ===== χ + ι ===== */                                         \
	/* Row 0 (V0..V4) with ι */                                     \
	VMOV V0.B16, V30.B16                                            \
	VMOV V1.B16, V31.B16                                            \
	WORD $0x4E611C59 /* BIC V25.16B,V2.16B,V1.16B  ~V1&V2→V25 */ \
	VEOR V25.B16, V0.B16, V0.B16                                   \
	WORD $0x4E621C79 /* BIC V25.16B,V3.16B,V2.16B  ~V2&V3→V25 */ \
	VEOR V25.B16, V31.B16, V1.B16                                  \
	WORD $0x4E631C99 /* BIC V25.16B,V4.16B,V3.16B  ~V3&V4→V25 */ \
	VEOR V25.B16, V2.B16, V2.B16                                   \
	WORD $0x4E641FD9 /* BIC V25.16B,V30.16B,V4.16B ~V4&V30→V25*/ \
	VEOR V25.B16, V3.B16, V3.B16                                   \
	WORD $0x4E7E1FF9 /* BIC V25.16B,V31.16B,V30.16B~V30&V31→V25*/\
	VEOR V25.B16, V4.B16, V4.B16                                   \
	VLD1R (R5), [V25.D2]                                            \
	VEOR V25.B16, V0.B16, V0.B16                                   \
	/* Row 1 (V5..V9) */                                            \
	VMOV V5.B16, V30.B16                                            \
	VMOV V6.B16, V31.B16                                            \
	WORD $0x4E661CF9 /* BIC V25.16B,V7.16B,V6.16B  ~V6&V7→V25 */ \
	VEOR V25.B16, V5.B16, V5.B16                                   \
	WORD $0x4E671D19 /* BIC V25.16B,V8.16B,V7.16B  ~V7&V8→V25 */ \
	VEOR V25.B16, V31.B16, V6.B16                                  \
	WORD $0x4E681D39 /* BIC V25.16B,V9.16B,V8.16B  ~V8&V9→V25 */ \
	VEOR V25.B16, V7.B16, V7.B16                                   \
	WORD $0x4E691FD9 /* BIC V25.16B,V30.16B,V9.16B ~V9&V30→V25*/ \
	VEOR V25.B16, V8.B16, V8.B16                                   \
	WORD $0x4E7E1FF9 /* BIC V25.16B,V31.16B,V30.16B~V30&V31→V25*/\
	VEOR V25.B16, V9.B16, V9.B16                                   \
	/* Row 2 (V10..V14) */                                          \
	VMOV V10.B16, V30.B16                                           \
	VMOV V11.B16, V31.B16                                           \
	WORD $0x4E6B1D99 /* BIC V25.16B,V12.16B,V11.16B~V11&V12→V25*/\
	VEOR V25.B16, V10.B16, V10.B16                                 \
	WORD $0x4E6C1DB9 /* BIC V25.16B,V13.16B,V12.16B~V12&V13→V25*/\
	VEOR V25.B16, V31.B16, V11.B16                                 \
	WORD $0x4E6D1DD9 /* BIC V25.16B,V14.16B,V13.16B~V13&V14→V25*/\
	VEOR V25.B16, V12.B16, V12.B16                                 \
	WORD $0x4E6E1FD9 /* BIC V25.16B,V30.16B,V14.16B~V14&V30→V25*/\
	VEOR V25.B16, V13.B16, V13.B16                                 \
	WORD $0x4E7E1FF9 /* BIC V25.16B,V31.16B,V30.16B~V30&V31→V25*/\
	VEOR V25.B16, V14.B16, V14.B16                                 \
	/* Row 3 (V15..V19) */                                          \
	VMOV V15.B16, V30.B16                                           \
	VMOV V16.B16, V31.B16                                           \
	WORD $0x4E701E39 /* BIC V25.16B,V17.16B,V16.16B~V16&V17→V25*/\
	VEOR V25.B16, V15.B16, V15.B16                                 \
	WORD $0x4E711E59 /* BIC V25.16B,V18.16B,V17.16B~V17&V18→V25*/\
	VEOR V25.B16, V31.B16, V16.B16                                 \
	WORD $0x4E721E79 /* BIC V25.16B,V19.16B,V18.16B~V18&V19→V25*/\
	VEOR V25.B16, V17.B16, V17.B16                                 \
	WORD $0x4E731FD9 /* BIC V25.16B,V30.16B,V19.16B~V19&V30→V25*/\
	VEOR V25.B16, V18.B16, V18.B16                                 \
	WORD $0x4E7E1FF9 /* BIC V25.16B,V31.16B,V30.16B~V30&V31→V25*/\
	VEOR V25.B16, V19.B16, V19.B16                                 \
	/* Row 4 (V20..V24) */                                          \
	VMOV V20.B16, V30.B16                                           \
	VMOV V21.B16, V31.B16                                           \
	WORD $0x4E751ED9 /* BIC V25.16B,V22.16B,V21.16B~V21&V22→V25*/\
	VEOR V25.B16, V20.B16, V20.B16                                 \
	WORD $0x4E761EF9 /* BIC V25.16B,V23.16B,V22.16B~V22&V23→V25*/\
	VEOR V25.B16, V31.B16, V21.B16                                 \
	WORD $0x4E771F19 /* BIC V25.16B,V24.16B,V23.16B~V23&V24→V25*/\
	VEOR V25.B16, V22.B16, V22.B16                                 \
	WORD $0x4E781FD9 /* BIC V25.16B,V30.16B,V24.16B~V24&V30→V25*/\
	VEOR V25.B16, V23.B16, V23.B16                                 \
	WORD $0x4E7E1FF9 /* BIC V25.16B,V31.16B,V30.16B~V30&V31→V25*/\
	VEOR V25.B16, V24.B16, V24.B16

// func permute4NEON(state *State4)
// Applies Keccak-f[1600] × 24 rounds to all 4 interleaved instances.
// Two passes: pass 1 = instances {0,1}, pass 2 = instances {2,3}.
TEXT ·permute4NEON(SB), NOSPLIT, $0-8
	MOVD state+0(FP), R4

	// ===== Pass 1: instances {0, 1} (lower 16 bytes of each 32-byte slot) =====
	// Load 25 lanes: VLD1.P 16 bytes, skip 16 bytes per slot.
	MOVD R4, R10
	VLD1.P 16(R10), [V0.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V1.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V2.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V3.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V4.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V5.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V6.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V7.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V8.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V9.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V10.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V11.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V12.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V13.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V14.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V15.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V16.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V17.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V18.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V19.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V20.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V21.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V22.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V23.D2]
	ADD $16, R10, R10
	VLD1 (R10), [V24.D2]

	MOVD $·roundConstants(SB), R5
	MOVD $24, R6

neon_pass1_loop:
	KECCAK_ROUND
	ADD $8, R5, R5
	SUBS $1, R6, R6
	BNE neon_pass1_loop

	// Store instances {0, 1} back (lower 16 bytes of each slot).
	MOVD R4, R10
	VST1.P [V0.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V1.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V2.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V3.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V4.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V5.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V6.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V7.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V8.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V9.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V10.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V11.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V12.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V13.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V14.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V15.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V16.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V17.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V18.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V19.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V20.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V21.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V22.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V23.D2], 16(R10)
	ADD $16, R10, R10
	VST1 [V24.D2], (R10)

	// ===== Pass 2: instances {2, 3} (upper 16 bytes of each 32-byte slot) =====
	// Load from offset +16 within each slot.
	MOVD R4, R10
	ADD $16, R10, R10          // skip slot 0 lower half
	VLD1.P 16(R10), [V0.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V1.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V2.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V3.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V4.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V5.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V6.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V7.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V8.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V9.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V10.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V11.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V12.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V13.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V14.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V15.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V16.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V17.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V18.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V19.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V20.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V21.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V22.D2]
	ADD $16, R10, R10
	VLD1.P 16(R10), [V23.D2]
	ADD $16, R10, R10
	VLD1 (R10), [V24.D2]

	MOVD $·roundConstants(SB), R5
	MOVD $24, R6

neon_pass2_loop:
	KECCAK_ROUND
	ADD $8, R5, R5
	SUBS $1, R6, R6
	BNE neon_pass2_loop

	// Store instances {2, 3} back (upper 16 bytes of each slot).
	MOVD R4, R10
	ADD $16, R10, R10          // skip slot 0 lower half
	VST1.P [V0.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V1.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V2.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V3.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V4.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V5.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V6.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V7.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V8.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V9.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V10.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V11.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V12.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V13.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V14.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V15.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V16.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V17.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V18.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V19.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V20.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V21.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V22.D2], 16(R10)
	ADD $16, R10, R10
	VST1.P [V23.D2], 16(R10)
	ADD $16, R10, R10
	VST1 [V24.D2], (R10)

	RET
