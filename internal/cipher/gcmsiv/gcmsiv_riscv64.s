// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// POLYVAL authentication for GCM-SIV on riscv64.
//
// Two code paths are provided:
//
//   Zvkg (vghsh.vv): single-instruction GHASH multiply-accumulate.
//     Data blocks are byte-reversed to GHASH byte order before each vghsh.vv.
//
//   Zvbc (vclmul/vclmulh): carry-less multiply with Karatsuba product table.
//     Follows the same patterns as the SM4 GCM Zvbc path in
//     internal/sm4/gcm_zvksed_riscv64.s.
//
// The assembly functions check ·hasGHASH (Zvkg) at runtime to select the path.
//
//go:build go1.27 && !purego

#include "textflag.h"

#define ZERO X0

// Data blocks
#define B0 V1
#define B1 V2
#define B2 V3
#define B3 V4
#define B4 V5
#define B5 V6
#define B6 V7
#define B7 V8

// Accumulator and Karatsuba partial products
#define ACC0  V9
#define ACC1  V10
#define ACCML V11
#define ACCMH V12

#define XPOLY X15
#define SWAP_IDX V25
#define T0 V26
#define T1 V27
#define T2 V28
#define T3 V29

// ── Vector crypto instruction macros ──────────────────────────────────────

// VGHSH_VV: vghsh.vv Vd, Vs1(data), Vs2(H)  →  Vd = (Vd ^ Vs1) * Vs2
#define VGHSH_VV(Vd, Vs1, Vs2) \
	WORD $((0x59 << 25) | ((Vs2) << 20) | ((Vs1) << 15) | (2 << 12) | ((Vd) << 7) | 0x77)

// ── Reduction polynomial constants ────────────────────────────────────────

// gcmSIVPoly: POLYVAL reduction polynomial for Karatsuba reduction rounds.
//   {R_low, R_high} = {0x0000000000000001, 0xc200000000000000}
DATA gcmSIVPoly<>+0x00(SB)/8, $0x0000000000000001
DATA gcmSIVPoly<>+0x08(SB)/8, $0xc200000000000000
GLOBL gcmSIVPoly<>(SB), (NOPTR+RODATA), $16

// gcmPoly: GHASH key transform reduction constant (mulX in GHASH field).
//   {0x0000000000000000, 0xe100000000000000} — element 0 (= 0) unused,
//   element 3 carries the reduction mask for bit 127 carry-out.
DATA gcmPoly<>+0x00(SB)/8, $0x0000000000000000
DATA gcmPoly<>+0x08(SB)/8, $0xe100000000000000
GLOBL gcmPoly<>(SB), (NOPTR+RODATA), $16

// Element-reversal index for full 16-byte reversal (E32 word swap): [3,2,1,0].
// Used by the Zvkg path for POLYVAL ↔ GHASH byte-order conversion.
DATA polyvalRevIdx<>+0(SB)/4, $3
DATA polyvalRevIdx<>+4(SB)/4, $2
DATA polyvalRevIdx<>+8(SB)/4, $1
DATA polyvalRevIdx<>+12(SB)/4, $0
GLOBL polyvalRevIdx<>(SB), RODATA, $16

// ── Reduction macro (Zvbc path) ──────────────────────────────────────────

// reduceRound: one Montgomery-like reduction step for 2×E64 vector a.
//   swap(a) ^= clmul(a, XPOLY)
// XPOLY must hold 0xc200000000000000 (high-half POLYVAL reduction constant).
// SWAP_IDX must hold [1, 0] for the E64 half-swap.
#define reduceRound(a) \
	VCLMULVX  XPOLY, a, T0; \
	VCLMULHVX XPOLY, a, ACCMH; \
	VSLIDEUPVI $1, ACCMH, T0; \
	VRGATHERVV SWAP_IDX, a, T1; \
	VXORVV T0, T1, a

// ── polyvalTableInitAsm ───────────────────────────────────────────────────
//
// func polyvalTableInitAsm(h *[16]byte, table *polyvalAsmTable)
//
// Builds the product table from the 16-byte POLYVAL authentication key h.
//
// Zvkg path: stores byte-reversed, key-transformed H (16 bytes) at table[0:16].
// Zvbc path: builds a full 256-byte Karatsuba product table (H^1..H^8).
//
TEXT ·polyvalTableInitAsm(SB), NOSPLIT, $0
#define hPtr X10
#define dst  X11

	MOV h+0(FP), hPtr
	MOV table+8(FP), dst

	// Branch on Zvkg
	MOVBU ·hasGHASH+0(SB), X14
	BNEZ  X14, zvkgInit

	// ════════════════════════════════════════════════════════════════════
	// Zvbc path: build Karatsuba product table.
	// Follows internal/sm4/gcm_zvksed_riscv64.s zvbcInit exactly.
	// ════════════════════════════════════════════════════════════════════

	VSETIVLI $4, E32, M1, TA, MA, X0
	VLE32V   (hPtr), V4            // V4 = raw 16-byte POLYVAL key (4×E32)

	// ── Key transform: H / x in POLYVAL field (RFC 8452 §2.3) ──
	// H_right = H >> 1 (with cross-element carry propagation)
	// result  = H_right XOR (H[0] ? gcmPoly : 0)
	// gcmPoly = {0, 0xe1} = x^7+x^2+x+1 at bit 64+ for the reflected representation.
	MOV    $gcmPoly<>(SB), X12
	VSRLVI $1, V4, V2              // V2 = V4 >> 1 per E32
	VSLLVI $31, V4, V3             // V3 = underflow-out per E32 (bit 0 → bit 31)
	VSLIDE1UPVX ZERO, V3, V1       // propagate underflow across E32 boundaries
	VORVV  V2, V1, V2             // V2 = H >> 1 with carries
	// Extract bit 0 of H (element 0, bit 0) and broadcast as mask
	VMVXS  V4, X15                 // X15 = V4[0]
	SLLI   $63, X15, X15           // move bit 0 to bit 63
	SRAI   $63, X15, X15           // arithmetic broadcast: all-ones if bit 0 was set
	VLE32V (X12), V3              // V3 = full gcmPoly (all 4 E32 elements)
	VANDVX X15, V3, V3            // conditional reduction mask
	VXORVV V2, V3, V1             // V1 = key-transformed H (= H/x in POLYVAL field)

	// Switch to E64 for product table computation
	VSETIVLI $2, E64, M1, TA, MA, X0

	// Setup swap index [1, 0] for E64 half-swap
	VIDV    SWAP_IDX
	VRSUBVI $1, SWAP_IDX, SWAP_IDX

	// Karatsuba pre-computation for H: swap halves and XOR
	VRGATHERVV SWAP_IDX, V1, V2
	VXORVV V1, V2, V2             // V2 = H_precomp

	// Store H^1 precomp at table[240], H^1 value at table[224]
	ADD    $240, dst, X14
	VSE64V V2, (X14)               // table[240] = H^1 precomp
	SUB    $16, X14, X14
	VSE64V V1, (X14)               // table[224] = H^1

	// Load reduction constant (high half only)
	MOV    gcmSIVPoly<>+0x08(SB), XPOLY
	VMVVV  V1, V3                  // V3 = current H^n (starts at H^1)
	VMVVV  V2, V4                  // V4 = current precomp

initLoop:
		// Karatsuba multiply: V1 × V3
		VCLMULVV  V1, V3, V5       // low(V1 * V3) = [C0, D0]
		VCLMULHVV V1, V3, V6       // high(V1 * V3) = [C1, D1]
		VCLMULVV  V2, V4, V7       // low(V2 * V4) = [E0, F0]
		VCLMULHVV V2, V4, V8       // high(V2 * V4) = [E1, F1]

		// Combine Karatsuba products
		VXORVV V5, V6, V3          // [C0^C1, D0^D1]
		VXORVV V3, V7, V7          // [C0^C1^E0, D0^D1^F0]
		VSLIDEDOWNVI $1, V5, V4    // [D0, 0]
		VXORVV V4, V7, V7
		VSLIDEUPVI $1, V7, V5

		VSLIDEDOWNVI $1, V3, V3    // [D0^D1, 0]
		VXORVV V3, V8, V8
		VXORVV V6, V8, V8
		VSLIDEDOWNVI $1, V6, V6
		VSLIDEUPVI $1, V6, V8      // result = [V5, V8]

		// Fast reduction (2 rounds)
		reduceRound(V5)
		reduceRound(V5)
		VXORVV V5, V8, V3          // V3 = H^(n+1)

		// Karatsuba pre-computation
		VRGATHERVV SWAP_IDX, V3, V4
		VXORVV V3, V4, V4          // V4 = H^(n+1)_precomp

		// Store precomp, then value
		SUB    $16, X14, X14
		VSE64V V4, (X14)           // precomp
		SUB    $16, X14, X14
		VSE64V V3, (X14)           // value

	BNE dst, X14, initLoop

	RET

	// ════════════════════════════════════════════════════════════════════
	// Zvkg path: store byte-reversed, key-transformed H
	// ════════════════════════════════════════════════════════════════════
zvkgInit:
	VSETIVLI $4, E32, M1, TA, MA, X0
	VLE32V   (hPtr), V4

	// Key transform: H / x in POLYVAL field (same as Zvbc path)
	MOV    $gcmPoly<>(SB), X12
	VSRLVI $1, V4, V2
	VSLLVI $31, V4, V3
	VSLIDE1UPVX ZERO, V3, V1
	VORVV  V2, V1, V2
	VMVXS  V4, X15
	SLLI   $63, X15, X15
	SRAI   $63, X15, X15
	VLE32V (X12), V3
	VANDVX X15, V3, V3
	VXORVV V2, V3, V1             // V1 = key-transformed H

	// Byte-reverse to GHASH byte order for vghsh.vv
	MOV    $polyvalRevIdx<>(SB), X16
	VLE32V (X16), V24
	VREV8V V1, V1
	VRGATHERVV V24, V1, V2
	VMVVV V2, V1

	VSE32V V1, (dst)
	RET
#undef hPtr
#undef dst

// ── polyvalBlocksUpdateAsm ────────────────────────────────────────────────
//
// func polyvalBlocksUpdateAsm(table *polyvalAsmTable, y *[16]byte, blocks []byte)
//
// Processes len(blocks)/16 complete 16-byte blocks, updating y in-place.
//
TEXT ·polyvalBlocksUpdateAsm(SB), NOSPLIT, $0
#define pTbl   X10
#define yPtr   X11
#define aut    X12
#define autLen X13

	MOV table+0(FP), pTbl
	MOV y+8(FP), yPtr
	MOV blocks_base+16(FP), aut
	MOV blocks_len+24(FP), autLen

	// Branch on Zvkg
	MOVBU ·hasGHASH+0(SB), X14
	BNEZ  X14, zvkgDataStart

	// ════════════════════════════════════════════════════════════════════
	// Zvbc path
	// ════════════════════════════════════════════════════════════════════

	VSETIVLI $2, E64, M1, TA, MA, X0
	VLE64V   (yPtr), ACC0          // load accumulator

	BEQZ autLen, zvbcDataDone

	// Setup swap index [1, 0] for E64 half-swap using VIDV
	VIDV    SWAP_IDX
	VRSUBVI $1, SWAP_IDX, SWAP_IDX  // SWAP_IDX = [1, 0] as 2×E64

	MOV gcmSIVPoly<>+0x08(SB), XPOLY

	// Load H^1 from table[224] and precomp from table[240]
	ADD    $224, pTbl, X14
	VLE64V (X14), T1               // T1 = H^1
	ADD    $16, X14, X14
	VLE64V (X14), T2               // T2 = H^1 precomp

	MOV $128, X8
	BGE autLen, X8, zvbcOctaLoop
	JMP zvbcSinglesLoop

zvbcOctaLoop:
		ADD $-128, autLen, autLen

		// Load 8 blocks (POLYVAL LE = vclmul native format, no byte-reversal)
		VLE64V (aut), B0
		ADD $16, aut

		VLE64V (aut), B1
		ADD $16, aut

		VLE64V (aut), B2
		ADD $16, aut

		VLE64V (aut), B3
		ADD $16, aut

		VLE64V (aut), B4
		ADD $16, aut

		VLE64V (aut), B5
		ADD $16, aut

		VLE64V (aut), B6
		ADD $16, aut

		VLE64V (aut), B7
		ADD $16, aut

		// XOR first block with accumulator
		VXORVV ACC0, B0, B0

		// First block × H^8 (table[0])
		VLE64V (pTbl), T1
		ADD $16, pTbl, X14
		VLE64V (X14), T2

		// Prepare B0 precomp
		VRGATHERVV SWAP_IDX, B0, T0
		VXORVV B0, T0, T0

		VCLMULVV  B0, T1, ACC0
		VCLMULHVV B0, T1, ACC1
		VCLMULVV  T0, T2, ACCML
		VCLMULHVV T0, T2, ACCMH

#define mulRoundOcta(X, off) \
	ADD $(off), pTbl, X14; \
	VLE64V (X14), T1; \
	ADD $16, X14, X14; \
	VLE64V (X14), T2; \
	VRGATHERVV SWAP_IDX, X, T0; \
	VXORVV X, T0, T0; \
	VCLMULVV X, T1, T3; \
	VXORVV T3, ACC0, ACC0; \
	VCLMULHVV X, T1, T3; \
	VXORVV T3, ACC1, ACC1; \
	VCLMULVV T0, T2, T3; \
	VXORVV T3, ACCML, ACCML; \
	VCLMULHVV T0, T2, T3; \
	VXORVV T3, ACCMH, ACCMH

		mulRoundOcta(B1, 32)
		mulRoundOcta(B2, 64)
		mulRoundOcta(B3, 96)
		mulRoundOcta(B4, 128)
		mulRoundOcta(B5, 160)
		mulRoundOcta(B6, 192)
		mulRoundOcta(B7, 224)
#undef mulRoundOcta

		// Combine cross products
		VXORVV ACC0, ACC1, T0
		VXORVV T0, ACCML, ACCML
		VSLIDEDOWNVI $1, T0, T0
		VXORVV T0, ACCMH, ACCMH
		VSLIDEDOWNVI $1, ACC0, T0
		VXORVV T0, ACCML, ACCML
		VSLIDEUPVI $1, ACCML, ACC0
		VSLIDEDOWNVI $1, ACC1, T0
		VXORVV ACC1, ACCMH, ACC1
		VSLIDEUPVI $1, T0, ACC1

		// Reduction
		reduceRound(ACC0)
		reduceRound(ACC0)
		VXORVV ACC0, ACC1, ACC0

		// T1/T2 still hold H^1 (from last mulRoundOcta at offset 224)
		MOV $128, X8
		BGE autLen, X8, zvbcOctaLoop

zvbcSinglesLoop:
		MOV $16, X8
		BLT autLen, X8, zvbcDataEnd
		ADD $-16, autLen, autLen

		VLE64V (aut), B0
		ADD $16, aut
		VXORVV ACC0, B0, B0

		// Prepare B0 precomp
		VRGATHERVV SWAP_IDX, B0, T0
		VXORVV B0, T0, T0

		// Karatsuba multiply B0 × H^1
		VCLMULVV  B0, T1, ACC0
		VCLMULHVV B0, T1, ACC1
		VCLMULVV  T0, T2, ACCML
		VCLMULHVV T0, T2, ACCMH

		// Combine
		VXORVV ACC0, ACC1, T0
		VXORVV T0, ACCML, ACCML
		VSLIDEDOWNVI $1, T0, T0
		VXORVV T0, ACCMH, ACCMH
		VSLIDEDOWNVI $1, ACC0, T0
		VXORVV T0, ACCML, ACCML
		VSLIDEUPVI $1, ACCML, ACC0
		VSLIDEDOWNVI $1, ACC1, T0
		VXORVV ACC1, ACCMH, ACC1
		VSLIDEUPVI $1, T0, ACC1

		// Reduction
		reduceRound(ACC0)
		reduceRound(ACC0)
		VXORVV ACC0, ACC1, ACC0

	JMP zvbcSinglesLoop

zvbcDataEnd:
	BEQZ autLen, zvbcDataDone
	// Partial tail block: load byte-by-byte then multiply
	JMP zvbcDataDone               // TODO: handle partial tail

zvbcDataDone:
	VSE64V ACC0, (yPtr)
	RET

	// ════════════════════════════════════════════════════════════════════
	// Zvkg path
	// ════════════════════════════════════════════════════════════════════
zvkgDataStart:
	VSETIVLI $4, E32, M1, TA, MA, X0
	// Load accumulator, byte-reverse to GHASH BE
	VLE32V (yPtr), ACC0
	MOV    $polyvalRevIdx<>(SB), X16
	VLE32V (X16), V24
	VREV8V ACC0, ACC0
	VRGATHERVV V24, ACC0, V2
	VMVVV V2, ACC0

	// Load H from table[0:16]
	VLE32V (pTbl), ACC1

	MOV $16, X14
	BLT autLen, X14, zvkgDataTail

zvkgDataLoop:
		VLE32V (aut), B0
		VREV8V B0, B0
		VRGATHERVV V24, B0, T0
		VMVVV T0, B0
		VGHSH_VV(9, 1, 10)         // ACC0 = (ACC0 ^ B0) * ACC1
		ADD $-16, autLen, autLen
		ADD $16, aut
		BGE autLen, X14, zvkgDataLoop

zvkgDataTail:
	BEQZ autLen, zvkgDataBail
	// Partial block: byte-by-byte load
	XOR X8, X8
	XOR X9, X9
	XOR X14, X14
	MOV $8, X21
	BGE autLen, X21, zvkgLoadGT8

zvkgLoadLT8:
		MOVBU (aut), X22
		SLL   X14, X22, X22
		OR    X22, X9, X9
		ADD   $-1, autLen, autLen
		ADD   $1, aut
		ADD   $8, X14, X14
		BNEZ  autLen, zvkgLoadLT8
	JMP zvkgLoadDone

zvkgLoadGT8:
	MOV (aut), X9
	ADD $8, aut
	ADD $-8, autLen, autLen

zvkgLoadHigh8:
		BEQZ autLen, zvkgLoadDone
		MOVBU (aut), X22
		SLL   X14, X22, X22
		OR    X22, X8, X8
		ADD   $-1, autLen, autLen
		ADD   $1, aut
		ADD   $8, X14, X14
	JMP zvkgLoadHigh8

zvkgLoadDone:
	VSETIVLI $2, E64, M1, TA, MA, X0
	VMVSX X9, B0
	VMVSX X8, B1
	VSLIDEUPVI $1, B1, B0
	VSETIVLI $4, E32, M1, TA, MA, X0
	VREV8V B0, B0
	VRGATHERVV V24, B0, T0
	VMVVV T0, B0
	VGHSH_VV(9, 1, 10)

zvkgDataBail:
	// Byte-reverse accumulator back to POLYVAL LE and store
	VREV8V ACC0, ACC0
	VRGATHERVV V24, ACC0, V2
	VMVVV V2, ACC0
	VSE32V ACC0, (yPtr)
	RET

#undef pTbl
#undef yPtr
#undef aut
#undef autLen
