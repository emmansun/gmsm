// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// ---- Static constants ----
// compress1Weights: [1,2,4,8,16,32,64,128] × 2 as uint16, for XVMULH bit-pack
DATA compress1Weights<>+0(SB)/8,  $0x0008000400020001
DATA compress1Weights<>+8(SB)/8,  $0x0080004000200010
DATA compress1Weights<>+16(SB)/8, $0x0008000400020001
DATA compress1Weights<>+24(SB)/8, $0x0080004000200010
GLOBL compress1Weights<>(SB), RODATA, $32

// ---- Constants ----
// q = 3329 = 0x0D01
// qInv = 62209 (q^{-1} mod 2^16, bit pattern as int16 = -3327)
// As 64-bit with 16-bit lanes: 0x0D010D010D010D01
// qInv as 64-bit: 62209 = 0xF301, so 0xF301F301F301F301

// ---- Register conventions ----
// X15 = broadcast(q=3329)
// X14 = broadcast(qInv=62209)
// R4  = primary data pointer
// R5  = secondary pointer (src or zetas)
// R6  = loop counter or offset
// R7, R8, R9 = temporaries for zeta broadcast

// ---- Macros ----

// BROADCAST_ZETA loads a 16-bit value from offset(Rbase) and broadcasts to all 16 lanes of Xdst.
// XVMOVQ offset(Rbase), Xdst.H16 requires go1.26+
// Clobbers: R8.
#define BROADCAST_ZETA(offset, Rbase, Xdst) \
	MOVHU offset(Rbase), R8     \
	XVMOVQ R8, Xdst.H16

// MONT_MUL_LASX computes Montgomery multiplication: XOUT = MontMul(XA, XZ).
// Uses signed approach: result = (a*z)_hi - ((a*z)_lo * qInv)_hi * q
// Result in (-q, q).
// Constants: X14=qInv, X15=q.
// Clobbers: XT1, XT2.
#define MONT_MUL_LASX(XA, XZ, XOUT, XT1, XT2) \
	XVMULH  XA, XZ, XT1        \ // XT1 = (a * z) low 16 bits
	XVMUHH  XA, XZ, XOUT       \ // XOUT = (a * z) high 16 bits (signed)
	XVMULH  X14, XT1, XT2      \ // XT2 = prod_lo * qInv (low 16 bits)
	XVMUHH  X15, XT2, XT2      \ // XT2 = (prod_lo * qInv) * q (high 16 bits, signed)
	XVSUBH  XT2, XOUT, XOUT      // XOUT = prod_hi - tq_hi

// REDUCE_MONT reduces value from (-q, q) to [0, q).
// If val < 0: add q.
// Clobbers: Xtmp.
#define REDUCE_MONT(Xval, Xq, Xtmp) \
	XVSRAH $15, Xval, Xtmp     \ // mask = all-ones if negative
	XVANDV Xtmp, Xq, Xtmp      \ // fix = q if negative
	XVADDH Xtmp, Xval, Xval      // val += q if negative

// FIELD_REDUCE_ONCE reduces value from [0, 2q) to [0, q).
// tmp = val - q; if tmp < 0 then val else tmp.
// Clobbers: Xtmp, Xmask.
#define FIELD_REDUCE_ONCE(Xval, Xq, Xtmp, Xmask) \
	XVSUBH Xq, Xval, Xtmp      \ // tmp = val - q
	XVSRAH $15, Xtmp, Xmask    \ // mask = all-ones if tmp < 0
	XVANDV Xmask, Xq, Xmask    \ // fix = q if tmp < 0
	XVADDH Xmask, Xtmp, Xval     // val = tmp + fix

// BUTTERFLY_LASX performs a Cooley-Tukey butterfly.
// VA' = fieldReduceOnce(VA + t), VB' = fieldSub(VA_old, t), where t = MontMul(VB, VZ).
// Inputs: XA, XB, XZ (zeta). Constants: X14=qInv, X15=q.
// XA is overwritten with VA'. XB is overwritten with VB'.
// Clobbers: X4, X5, X6, X7, X8.
#define BUTTERFLY_LASX(XA, XB, XZ) \
	MONT_MUL_LASX(XB, XZ, X4, X5, X6)  \ // X4 = t = MontMul(VB, VZ) in (-q,q)
	REDUCE_MONT(X4, X15, X5)            \ // X4 = t in [0, q)
	XVORV XA, XA, X7                    \ // X7 = save VA_old
	XVADDH X4, XA, XA                   \ // XA = VA + t, in [0, 2q)
	FIELD_REDUCE_ONCE(XA, X15, X5, X6)  \ // XA = VA' in [0, q)
	XVSUBH X4, X7, XB                   \ // XB = VA_old - t, in [-(q-1), q-1]
	REDUCE_MONT(XB, X15, X8)              // XB = VB' in [0, q)

// INTT_BUTTERFLY_LASX performs a Gentleman-Sande butterfly.
// VA' = fieldReduceOnce(VA + VB), VB' = MontMul(VZ, fieldSub(VB, VA_old)).
// Clobbers: X4, X5, X6, X7, X8.
#define INTT_BUTTERFLY_LASX(XA, XB, XZ) \
	XVSUBH XA, XB, X4                   \ // X4 = VB - VA (diff), in [-(q-1), q-1]
	XVADDH XA, XB, XA                   \ // XA = VA + VB, in [0, 2q)
	FIELD_REDUCE_ONCE(XA, X15, X5, X6)  \ // XA = VA' in [0, q)
	REDUCE_MONT(X4, X15, X5)            \ // X4 = diff in [0, q)
	MONT_MUL_LASX(X4, XZ, XB, X5, X6)  \ // XB = MontMul(diff, zeta) in (-q, q)
	REDUCE_MONT(XB, X15, X7)              // XB = VB' in [0, q)

// XVPERMIQ performs xvpermi.q Xd, Xj, imm8.
// Real semantics: pool={Xj.lo, Xj.hi, Xd_old.lo, Xd_old.hi} = {0,1,2,3}
//   dst.qword[0] = pool[imm[1:0]], dst.qword[1] = pool[imm[5:4]]
// Opcode 0x1DFB verified: xvpermi.q X8, X9, 0x02 → WORD $0x77ec0928
#define XVPERMIQ(Xd, Xj, imm8) \
	WORD $((0x1DFB << 18) | ((imm8) << 10) | ((Xj) << 5) | (Xd))

// XVPICKEV_H performs xvpickev.h Xvd, Xvj, Xvk.
// Picks even-indexed halfwords from Xvk (into result[0..3]) and Xvj (into result[4..7]) per 128-bit lane.
// opcode: 0111 01010001 11101 .vk. .vj. .vd. → base = 0x751E8000
// In Go asm, first arg = vk (hardware), second = vj, third = vd.
#define XVPICKEV_H(Xvd, Xvj, Xvk) \
	WORD $((0x751E8000) | ((Xvk) << 10) | ((Xvj) << 5) | (Xvd))

// XVPICKEV_B performs xvpickev.b Xvd, Xvj, Xvk.
// Picks even-indexed bytes from Xvk (lower half of each 128-bit lane) and Xvj (upper half).
// opcode base: 0x751E0000 (same as H but element-width field = 0 for byte)
#define XVPICKEV_B(Xvd, Xvj, Xvk) \
	WORD $((0x751E0000) | ((Xvk) << 10) | ((Xvj) << 5) | (Xvd))

// XVPICKOD_B performs xvpickod.b Xvd, Xvj, Xvk.
// Picks odd-indexed bytes from Xvk (lower half of each 128-bit lane) and Xvj (upper half).
// opcode base: 0x752E0000
#define XVPICKOD_B(Xvd, Xvj, Xvk) \
	WORD $((0x752E0000) | ((Xvk) << 10) | ((Xvj) << 5) | (Xvd))

// XVPICKOD_H performs xvpickod.h Xvd, Xvj, Xvk.
// Picks odd-indexed halfwords from Xvk (lower half) and Xvj (upper half) per 128-bit lane.
// opcode base: 0x752E8000 (pickod.h = pickev.h with od bit set)
#define XVPICKOD_H(Xvd, Xvj, Xvk) \
	WORD $((0x752E8000) | ((Xvk) << 10) | ((Xvj) << 5) | (Xvd))

// COMPRESS4(Xin, Xcout16, Xtmp, Xmul): compress 16 coefficients to 4-bit each.
// Xcout16: each int16 lane has a 4-bit compressed value [0,15].
// Xmul must be preloaded with broadcast(20159).
// Clobbers: Xtmp.
// Formula: c = ((mulhigh16(x, 20159) + 32) >> 6) & 0xF
#define COMPRESS4(Xin, Xcout16, Xmul20159, Xtmp, Xrnd32, Xmask0F) \
	XVMUHH Xin, Xmul20159, Xcout16     \ // t = mulhigh16(x, 20159)
	XVADDH Xrnd32, Xcout16, Xcout16    \ // t += 32 (for rounding)
	XVSRAH $6, Xcout16, Xcout16        \ // t >>= 6
	XVANDV Xmask0F, Xcout16, Xcout16    // t &= 0xF

// SETUP_CONSTS initializes X15=q and X14=qInv broadcasts.
#define SETUP_CONSTS \
	MOVV $0x0D010D010D010D01, R7  \
	XVMOVQ R7, X15.V4            \
	MOVV $0xF301F301F301F301, R7  \
	XVMOVQ R7, X14.V4

// polyAddAssignLASX computes dst[i] = fieldAdd(dst[i], src[i]) for all i in [0, 256).
// Uses LASX to process 16 int16 values (32 bytes) per vector, 2 vectors per iteration.
// func polyAddAssignLASX(dst, src *ringElement)
TEXT ·polyAddAssignLASX(SB), NOSPLIT, $0-16
	MOVV dst+0(FP), R4
	MOVV src+8(FP), R5

	// Broadcast q=3329 (0x0D01) to all 16 int16 lanes
	// 0x0D010D010D010D01 = 3329 repeated in each 16-bit position of a 64-bit word
	MOVV $0x0D010D010D010D01, R7
	XVMOVQ R7, X15.V4

	MOVV $8, R6  // loop counter: 8 iterations * 64 bytes = 512 bytes

poly_add_loop:
	// Load 2x 256-bit vectors = 32 coefficients
	XVMOVQ (R4), X0
	XVMOVQ 32(R4), X1
	XVMOVQ (R5), X2
	XVMOVQ 32(R5), X3

	// dst = dst + src
	XVADDH X2, X0, X0
	XVADDH X3, X1, X1

	// Conditional reduction: if dst >= q, subtract q
	// tmp = dst - q
	XVSUBH X15, X0, X4
	XVSUBH X15, X1, X5

	// mask = arithmetic right shift 15 (0xFFFF if tmp < 0, else 0)
	XVSRAH $15, X4, X6
	XVSRAH $15, X5, X7

	// fix = mask & q (q if tmp < 0, i.e., original was < q, so keep original)
	XVANDV X6, X15, X6
	XVANDV X7, X15, X7

	// result = tmp + fix (if tmp < 0: tmp + q = original; if tmp >= 0: tmp + 0 = dst - q)
	XVADDH X6, X4, X0
	XVADDH X7, X5, X1

	// Store results
	XVMOVQ X0, (R4)
	XVMOVQ X1, 32(R4)

	ADDV $64, R4
	ADDV $64, R5
	ADDV $-1, R6
	BNE R6, R0, poly_add_loop

	RET

// polySubAssignLASX computes dst[i] = fieldSub(dst[i], src[i]) for all i in [0, 256).
// fieldSub: x = uint16(a - b + q); return fieldReduceOnce(x)
// func polySubAssignLASX(dst, src *ringElement)
TEXT ·polySubAssignLASX(SB), NOSPLIT, $0-16
	MOVV dst+0(FP), R4
	MOVV src+8(FP), R5

	// Broadcast q=3329 (0x0D01) to all 16 int16 lanes
	MOVV $0x0D010D010D010D01, R7
	XVMOVQ R7, X15.V4

	MOVV $8, R6  // loop counter: 8 iterations * 64 bytes = 512 bytes

poly_sub_loop:
	// Load 2x 256-bit vectors = 32 coefficients
	XVMOVQ (R4), X0
	XVMOVQ 32(R4), X1
	XVMOVQ (R5), X2
	XVMOVQ 32(R5), X3

	// Compute dst + q - src
	XVADDH X15, X0, X0    // dst = dst + q
	XVSUBH X2, X0, X0     // dst = (dst + q) - src, result in [0, 2q)

	XVADDH X15, X1, X1    // dst = dst + q
	XVSUBH X3, X1, X1     // dst = (dst + q) - src

	// Conditional reduction: if dst >= q, subtract q
	// tmp = dst - q
	XVSUBH X15, X0, X4
	XVSUBH X15, X1, X5

	// mask = arithmetic right shift 15
	XVSRAH $15, X4, X6
	XVSRAH $15, X5, X7

	// fix = mask & q
	XVANDV X6, X15, X6
	XVANDV X7, X15, X7

	// result = tmp + fix
	XVADDH X6, X4, X0
	XVADDH X7, X5, X1

	// Store results
	XVMOVQ X0, (R4)
	XVMOVQ X1, 32(R4)

	ADDV $64, R4
	ADDV $64, R5
	ADDV $-1, R6
	BNE R6, R0, poly_sub_loop

	RET

// internalNTTLASX computes the full forward NTT (layers len=128..2).
// Uses signed Montgomery multiplication (5 instructions per MontMul).
// func internalNTTLASX(f *ringElement)
TEXT ·internalNTTLASX(SB), NOSPLIT, $0-8
	MOVV f+0(FP), R4
	MOVV $·zetasMontgomery(SB), R5

	SETUP_CONSTS

	// ---- Layer 0: len=128, 1 zeta (zetasMontgomery[1]) ----
	// Butterfly between f[i] and f[i+128] for i in [0, 128)
	// 128 coefficients = 8 vectors, stride = 256 bytes
	BROADCAST_ZETA(2, R5, X3)
	MOVV R4, R10                // R10 = even ptr (f[0..127])
	ADDV $256, R4, R11          // R11 = odd ptr (f[128..255])
	MOVV $8, R6

ntt_l0_loop:
	XVMOVQ (R10), X0
	XVMOVQ (R11), X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, (R10)
	XVMOVQ X1, (R11)
	ADDV $32, R10
	ADDV $32, R11
	ADDV $-1, R6
	BNE R6, R0, ntt_l0_loop

	// ---- Layer 1: len=64, 2 groups ----
	// Group 0: zeta=zetasMontgomery[2], pairs f[i] and f[i+64], i in [0,64)
	// Group 1: zeta=zetasMontgomery[3], pairs f[128+i] and f[128+i+64], i in [0,64)
	BROADCAST_ZETA(4, R5, X3)
	MOVV R4, R10
	ADDV $128, R4, R11
	MOVV $4, R6

ntt_l1_g0_loop:
	XVMOVQ (R10), X0
	XVMOVQ (R11), X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, (R10)
	XVMOVQ X1, (R11)
	ADDV $32, R10
	ADDV $32, R11
	ADDV $-1, R6
	BNE R6, R0, ntt_l1_g0_loop

	BROADCAST_ZETA(6, R5, X3)
	ADDV $256, R4, R10
	ADDV $384, R4, R11
	MOVV $4, R6

ntt_l1_g1_loop:
	XVMOVQ (R10), X0
	XVMOVQ (R11), X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, (R10)
	XVMOVQ X1, (R11)
	ADDV $32, R10
	ADDV $32, R11
	ADDV $-1, R6
	BNE R6, R0, ntt_l1_g1_loop

	// ---- Layer 2: len=32, 4 groups ----
	// Group g: zeta=zetasMontgomery[4+g], stride=64 bytes within 128-byte block
	BROADCAST_ZETA(8, R5, X3)
	MOVV R4, R10
	ADDV $64, R4, R11
	MOVV $2, R6

ntt_l2_g0_loop:
	XVMOVQ (R10), X0
	XVMOVQ (R11), X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, (R10)
	XVMOVQ X1, (R11)
	ADDV $32, R10
	ADDV $32, R11
	ADDV $-1, R6
	BNE R6, R0, ntt_l2_g0_loop

	BROADCAST_ZETA(10, R5, X3)
	ADDV $128, R4, R10
	ADDV $192, R4, R11
	MOVV $2, R6

ntt_l2_g1_loop:
	XVMOVQ (R10), X0
	XVMOVQ (R11), X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, (R10)
	XVMOVQ X1, (R11)
	ADDV $32, R10
	ADDV $32, R11
	ADDV $-1, R6
	BNE R6, R0, ntt_l2_g1_loop

	BROADCAST_ZETA(12, R5, X3)
	ADDV $256, R4, R10
	ADDV $320, R4, R11
	MOVV $2, R6

ntt_l2_g2_loop:
	XVMOVQ (R10), X0
	XVMOVQ (R11), X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, (R10)
	XVMOVQ X1, (R11)
	ADDV $32, R10
	ADDV $32, R11
	ADDV $-1, R6
	BNE R6, R0, ntt_l2_g2_loop

	BROADCAST_ZETA(14, R5, X3)
	ADDV $384, R4, R10
	ADDV $448, R4, R11
	MOVV $2, R6

ntt_l2_g3_loop:
	XVMOVQ (R10), X0
	XVMOVQ (R11), X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, (R10)
	XVMOVQ X1, (R11)
	ADDV $32, R10
	ADDV $32, R11
	ADDV $-1, R6
	BNE R6, R0, ntt_l2_g3_loop

	// ---- Layer 3: len=16, 8 groups ----
	// Group g: zeta=zetasMontgomery[8+g], stride=32 bytes, 1 vector pair each
	BROADCAST_ZETA(16, R5, X3)
	XVMOVQ (R4), X0
	XVMOVQ 32(R4), X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, (R4)
	XVMOVQ X1, 32(R4)

	BROADCAST_ZETA(18, R5, X3)
	XVMOVQ 64(R4), X0
	XVMOVQ 96(R4), X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, 64(R4)
	XVMOVQ X1, 96(R4)

	BROADCAST_ZETA(20, R5, X3)
	XVMOVQ 128(R4), X0
	XVMOVQ 160(R4), X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, 128(R4)
	XVMOVQ X1, 160(R4)

	BROADCAST_ZETA(22, R5, X3)
	XVMOVQ 192(R4), X0
	XVMOVQ 224(R4), X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, 192(R4)
	XVMOVQ X1, 224(R4)

	BROADCAST_ZETA(24, R5, X3)
	XVMOVQ 256(R4), X0
	XVMOVQ 288(R4), X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, 256(R4)
	XVMOVQ X1, 288(R4)

	BROADCAST_ZETA(26, R5, X3)
	XVMOVQ 320(R4), X0
	XVMOVQ 352(R4), X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, 320(R4)
	XVMOVQ X1, 352(R4)

	BROADCAST_ZETA(28, R5, X3)
	XVMOVQ 384(R4), X0
	XVMOVQ 416(R4), X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, 384(R4)
	XVMOVQ X1, 416(R4)

	BROADCAST_ZETA(30, R5, X3)
	XVMOVQ 448(R4), X0
	XVMOVQ 480(R4), X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, 448(R4)
	XVMOVQ X1, 480(R4)

	// ---- Layer 4: len=8, 16 groups ----
	// Each 256-bit vector = 16 coefficients = one group of 16.
	// Butterfly between low 8 (lane 0) and high 8 (lane 1).
	// Use xvpermi.q to separate/recombine 128-bit lanes.
	MOVV $·nttTwiddleL8PrecompLASX(SB), R10
	MOVV R4, R11
	MOVV $8, R6

ntt_l4_loop:
	// Load precomputed twiddle (low half has one zeta, high half has another)
	XVMOVQ (R10), X3

	// Load 2 vectors = 2 groups of 16 coefficients
	XVMOVQ (R11), X9
	XVMOVQ 32(R11), X10

	// Pack lows: X0 = [X9.lo | X10.lo]
	XVORV X9, X9, X0
	XVPERMIQ(0, 10, 0x02)

	// Pack highs: X1 = [X9.hi | X10.hi]
	XVORV X9, X9, X1
	XVPERMIQ(1, 10, 0x13)

	// Butterfly on the packed halves
	BUTTERFLY_LASX(X0, X1, X3)

	// Repack: X9 = [X0.lo | X1.lo], X10 = [X0.hi | X1.hi]
	XVORV X0, X0, X9
	XVPERMIQ(9, 1, 0x02)
	XVORV X0, X0, X10
	XVPERMIQ(10, 1, 0x13)

	// Store
	XVMOVQ X9, (R11)
	XVMOVQ X10, 32(R11)

	ADDV $32, R10
	ADDV $64, R11
	ADDV $-1, R6
	BNE R6, R0, ntt_l4_loop

	// ---- Layer 5: len=4, 32 groups ----
	MOVV $·nttTwiddleL4PrecompLASX(SB), R10
	MOVV R4, R11
	MOVV $8, R6
ntt_l5_main_loop:
	XVMOVQ (R10), X3
	XVMOVQ (R11), X9
	XVMOVQ 32(R11), X10
	XVILVLV X10, X9, X0
	XVILVHV X10, X9, X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVILVHV X0, X1, X9
	XVILVLV X0, X1, X10
	XVMOVQ X9, (R11)
	XVMOVQ X10, 32(R11)
	ADDV $32, R10
	ADDV $64, R11
	ADDV $-1, R6
	BNE R6, R0, ntt_l5_main_loop

	// ---- Layer 6: len=2, 64 groups ----
	MOVV $·nttTwiddleL2PrecompLASX(SB), R10
	MOVV R4, R11
	MOVV $8, R6
ntt_l6_main_loop:
	XVMOVQ (R10), X3
	XVMOVQ (R11), X9
	XVMOVQ 32(R11), X10
	XVSHUF4IW $0xD8, X9, X11
	XVSHUF4IW $0xD8, X10, X12
	XVILVLV X12, X11, X0
	XVILVHV X12, X11, X1
	BUTTERFLY_LASX(X0, X1, X3)
	XVILVHV X0, X1, X11
	XVILVLV X0, X1, X12
	XVSHUF4IW $0xD8, X11, X9
	XVSHUF4IW $0xD8, X12, X10
	XVMOVQ X9, (R11)
	XVMOVQ X10, 32(R11)
	ADDV $32, R10
	ADDV $64, R11
	ADDV $-1, R6
	BNE R6, R0, ntt_l6_main_loop

	RET

// internalInverseNTTLASX computes the full inverse NTT (layers len=2..128)
// in Gentleman-Sande order, then applies final scale.
// func internalInverseNTTLASX(f *nttElement)
TEXT ·internalInverseNTTLASX(SB), NOSPLIT, $0-8
	MOVV f+0(FP), R4
	MOVV $·zetasMontgomery(SB), R5

	SETUP_CONSTS

	// ---- Layer 6 (inverse): len=2, 64 groups ----
	MOVV $·inttTwiddleL2PrecompLASX(SB), R10
	MOVV R4, R11
	MOVV $8, R6

intt_l6_loop:
	XVMOVQ (R10), X3

	XVMOVQ (R11), X9
	XVMOVQ 32(R11), X10

	// Same split as forward NTT layer 6
	XVSHUF4IW $0xD8, X9, X11
	XVSHUF4IW $0xD8, X10, X12

	XVILVLV X12, X11, X0    // X0 = pure a's
	XVILVHV X12, X11, X1    // X1 = pure b's

	INTT_BUTTERFLY_LASX(X0, X1, X3)

	// Repack: same correction as forward NTT layer 6
	XVILVHV X0, X1, X11
	XVILVLV X0, X1, X12

	XVSHUF4IW $0xD8, X11, X9
	XVSHUF4IW $0xD8, X12, X10

	XVMOVQ X9, (R11)
	XVMOVQ X10, 32(R11)

	ADDV $32, R10
	ADDV $64, R11
	ADDV $-1, R6
	BNE R6, R0, intt_l6_loop

	// ---- Layer 5 (inverse): len=4, 32 groups ----
	MOVV $·inttTwiddleL4PrecompLASX(SB), R10
	MOVV R4, R11
	MOVV $8, R6

intt_l5_loop:
	XVMOVQ (R10), X3

	XVMOVQ (R11), X9
	XVMOVQ 32(R11), X10

	XVILVLV X10, X9, X0
	XVILVHV X10, X9, X1

	INTT_BUTTERFLY_LASX(X0, X1, X3)

	// Repack back: same correction as NTT Layer 5 repack.
	XVILVHV X0, X1, X9
	XVILVLV X0, X1, X10

	XVMOVQ X9, (R11)
	XVMOVQ X10, 32(R11)

	ADDV $32, R10
	ADDV $64, R11
	ADDV $-1, R6
	BNE R6, R0, intt_l5_loop

	// ---- Layer 4 (inverse): len=8, 16 groups ----
	MOVV $·inttTwiddleL8PrecompLASX(SB), R10
	MOVV R4, R11
	MOVV $8, R6

intt_l4_loop:
	XVMOVQ (R10), X3

	XVMOVQ (R11), X9
	XVMOVQ 32(R11), X10

	XVORV X9, X9, X0
	XVPERMIQ(0, 10, 0x02)
	XVORV X9, X9, X1
	XVPERMIQ(1, 10, 0x13)

	INTT_BUTTERFLY_LASX(X0, X1, X3)

	XVORV X0, X0, X9
	XVPERMIQ(9, 1, 0x02)
	XVORV X0, X0, X10
	XVPERMIQ(10, 1, 0x13)

	XVMOVQ X9, (R11)
	XVMOVQ X10, 32(R11)

	ADDV $32, R10
	ADDV $64, R11
	ADDV $-1, R6
	BNE R6, R0, intt_l4_loop

	// ---- Layer 3 (inverse): len=16, 8 groups ----
	// Groups processed high-to-low (start=224..0). Zetas[8..15] in ascending start order.
	// start=224→zeta[8], start=192→zeta[9], ..., start=0→zeta[15].

	BROADCAST_ZETA(16, R5, X3)  // start=224, zeta[8]
	XVMOVQ 448(R4), X0
	XVMOVQ 480(R4), X1
	INTT_BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, 448(R4)
	XVMOVQ X1, 480(R4)

	BROADCAST_ZETA(18, R5, X3)  // start=192, zeta[9]
	XVMOVQ 384(R4), X0
	XVMOVQ 416(R4), X1
	INTT_BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, 384(R4)
	XVMOVQ X1, 416(R4)

	BROADCAST_ZETA(20, R5, X3)  // start=160, zeta[10]
	XVMOVQ 320(R4), X0
	XVMOVQ 352(R4), X1
	INTT_BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, 320(R4)
	XVMOVQ X1, 352(R4)

	BROADCAST_ZETA(22, R5, X3)  // start=128, zeta[11]
	XVMOVQ 256(R4), X0
	XVMOVQ 288(R4), X1
	INTT_BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, 256(R4)
	XVMOVQ X1, 288(R4)

	BROADCAST_ZETA(24, R5, X3)  // start=96, zeta[12]
	XVMOVQ 192(R4), X0
	XVMOVQ 224(R4), X1
	INTT_BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, 192(R4)
	XVMOVQ X1, 224(R4)

	BROADCAST_ZETA(26, R5, X3)  // start=64, zeta[13]
	XVMOVQ 128(R4), X0
	XVMOVQ 160(R4), X1
	INTT_BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, 128(R4)
	XVMOVQ X1, 160(R4)

	BROADCAST_ZETA(28, R5, X3)  // start=32, zeta[14]
	XVMOVQ 64(R4), X0
	XVMOVQ 96(R4), X1
	INTT_BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, 64(R4)
	XVMOVQ X1, 96(R4)

	BROADCAST_ZETA(30, R5, X3)  // start=0, zeta[15]
	XVMOVQ (R4), X0
	XVMOVQ 32(R4), X1
	INTT_BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, (R4)
	XVMOVQ X1, 32(R4)

	// ---- Layer 2 (inverse): len=32, 4 groups ----
	// Groups processed high-to-low (start=192..0). Zetas[4..7] in ascending start order.
	// start=192→zeta[4], start=128→zeta[5], start=64→zeta[6], start=0→zeta[7].
	BROADCAST_ZETA(8, R5, X3)   // start=192, zeta[4]
	ADDV $384, R4, R10
	ADDV $448, R4, R11
	MOVV $2, R6

intt_l2_g3_loop:
	XVMOVQ (R10), X0
	XVMOVQ (R11), X1
	INTT_BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, (R10)
	XVMOVQ X1, (R11)
	ADDV $32, R10
	ADDV $32, R11
	ADDV $-1, R6
	BNE R6, R0, intt_l2_g3_loop

	BROADCAST_ZETA(10, R5, X3)  // start=128, zeta[5]
	ADDV $256, R4, R10
	ADDV $320, R4, R11
	MOVV $2, R6

intt_l2_g2_loop:
	XVMOVQ (R10), X0
	XVMOVQ (R11), X1
	INTT_BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, (R10)
	XVMOVQ X1, (R11)
	ADDV $32, R10
	ADDV $32, R11
	ADDV $-1, R6
	BNE R6, R0, intt_l2_g2_loop

	BROADCAST_ZETA(12, R5, X3)  // start=64, zeta[6]
	ADDV $128, R4, R10
	ADDV $192, R4, R11
	MOVV $2, R6

intt_l2_g1_loop:
	XVMOVQ (R10), X0
	XVMOVQ (R11), X1
	INTT_BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, (R10)
	XVMOVQ X1, (R11)
	ADDV $32, R10
	ADDV $32, R11
	ADDV $-1, R6
	BNE R6, R0, intt_l2_g1_loop

	BROADCAST_ZETA(14, R5, X3)  // start=0, zeta[7]
	MOVV R4, R10
	ADDV $64, R4, R11
	MOVV $2, R6

intt_l2_g0_loop:
	XVMOVQ (R10), X0
	XVMOVQ (R11), X1
	INTT_BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, (R10)
	XVMOVQ X1, (R11)
	ADDV $32, R10
	ADDV $32, R11
	ADDV $-1, R6
	BNE R6, R0, intt_l2_g0_loop

	// ---- Layer 1 (inverse): len=64, 2 groups ----
	// Groups processed high-to-low (start=128,0). start=128→zeta[2], start=0→zeta[3].
	BROADCAST_ZETA(4, R5, X3)   // start=128, zeta[2]
	ADDV $256, R4, R10
	ADDV $384, R4, R11
	MOVV $4, R6

intt_l1_g1_loop:
	XVMOVQ (R10), X0
	XVMOVQ (R11), X1
	INTT_BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, (R10)
	XVMOVQ X1, (R11)
	ADDV $32, R10
	ADDV $32, R11
	ADDV $-1, R6
	BNE R6, R0, intt_l1_g1_loop

	BROADCAST_ZETA(6, R5, X3)   // start=0, zeta[3]
	MOVV R4, R10
	ADDV $128, R4, R11
	MOVV $4, R6

intt_l1_g0_loop:
	XVMOVQ (R10), X0
	XVMOVQ (R11), X1
	INTT_BUTTERFLY_LASX(X0, X1, X3)
	XVMOVQ X0, (R10)
	XVMOVQ X1, (R11)
	ADDV $32, R10
	ADDV $32, R11
	ADDV $-1, R6
	BNE R6, R0, intt_l1_g0_loop

	// ---- Layer 0 (inverse): len=128, with final scale ----
	// INTT butterfly + scale by 1441 (= 128^{-1} * r^2 mod q).
	// 1441 = 0x05A1
	BROADCAST_ZETA(2, R5, X3)

	// Broadcast scale = 1441
	MOVV $0x05A105A105A105A1, R7
	XVMOVQ R7, X13.V4

	MOVV R4, R10
	ADDV $256, R4, R11
	MOVV $8, R6

intt_l0_loop:
	XVMOVQ (R10), X0
	XVMOVQ (R11), X1
	INTT_BUTTERFLY_LASX(X0, X1, X3)

	// Scale both outputs by 1441 via Montgomery multiply
	MONT_MUL_LASX(X0, X13, X0, X9, X10)
	REDUCE_MONT(X0, X15, X9)
	MONT_MUL_LASX(X1, X13, X1, X9, X10)
	REDUCE_MONT(X1, X15, X9)

	XVMOVQ X0, (R10)
	XVMOVQ X1, (R11)
	ADDV $32, R10
	ADDV $32, R11
	ADDV $-1, R6
	BNE R6, R0, intt_l0_loop

	RET

// ── internalNTTMulAccLASX ─────────────────────────────────────────────────────
// func internalNTTMulAccLASX(acc, lhs, rhs *nttElement)
//
// For each pair (2i, 2i+1):
//   acc[2i]   += a0*b0 + gamma[i]*a1*b1   (Montgomery domain)
//   acc[2i+1] += a0*b1 + a1*b0
//
// Processes 8 pairs (16 × int16 = 32 bytes) per iteration.
// gammaMulTableLASX layout: [r=2285, γ[0], r, γ[1], ...] for 128 pairs.
//
// Register allocation:
//   R4=acc, R5=lhs, R6=rhs, R7=gammaMulTableLASX ptr, R8=loop counter(=16)
//   X14=broadcast(qInv=62209), X15=broadcast(q=3329)
//   X0=lhs chunk, X1=rhs chunk, X2=acc chunk, X3=gamma table chunk
//   X4=rhs_swapped, X5=t_ab, X6=t_cross, X7=t_scaled
//   X8,X9=temporaries for MONT_MUL, X10,X11=pairwise sums
//
// Algorithm:
//   X4 = swap adjacent int16 within 32-bit groups of X1
//   X5 = MontMul(X0, X1)        // [a0b0, a1b1, ...]
//   X6 = MontMul(X0, X4)        // [a0b1, a1b0, ...]
//   X7 = MontMul(X5, X3)        // [r*a0b0=a0b0, γ*a1b1, ...]
//   even_dup = pairwise_add(X7) // [a0b0+γa1b1 x2, ...]
//   odd_dup  = pairwise_add(X6) // [a0b1+a1b0 x2, ...]
//   Reduce even_dup, odd_dup
//   XVPICKEV_H to dedup, XVILVLH to interleave → delta
//   acc += delta; reduce acc
TEXT ·internalNTTMulAccLASX(SB), NOSPLIT, $0-24
	MOVV acc+0(FP), R4
	MOVV lhs+8(FP), R5
	MOVV rhs+16(FP), R6

	SETUP_CONSTS

	MOVV $·gammaMulTableLASX(SB), R7
	MOVV $16, R8    // 16 iterations × 32 bytes = 512 bytes

nttmlacc_lasx_loop:
	XVMOVQ (R5), X0         // lhs
	XVMOVQ (R6), X1         // rhs
	XVMOVQ (R4), X2         // acc
	XVMOVQ (R7), X3         // gamma table [r,γ[k], ...]

	// Swap adjacent int16 within each 32-bit group: [b0,b1,b2,b3] → [b1,b0,b3,b2]
	XVSHUF4IH $0xB1, X1, X4

	// t_ab = MontMul(lhs, rhs)
	MONT_MUL_LASX(X0, X1, X5, X8, X9)

	// t_cross = MontMul(lhs, rhs_swapped)
	MONT_MUL_LASX(X0, X4, X6, X8, X9)

	// t_scaled = MontMul(t_ab, gamma): even pos: MontMul(a0b0, r)=a0b0; odd: γ*a1b1
	MONT_MUL_LASX(X5, X3, X7, X8, X9)

	// MONT_MUL_LASX outputs (-q, q); reduce to [0, q) before pairwise add.
	REDUCE_MONT(X7, X15, X8)
	REDUCE_MONT(X6, X15, X8)

	// Pairwise horizontal add via swap-and-add (within each 32-bit group):
	// X7 = [a0b0, γa1b1, a2b2, γa3b3, ...] → after swap+add:
	// X7 = [(a0b0+γa1b1)×2, (a2b2+γa3b3)×2, ...] (duplicated even sums, in [0,2q))
	XVSHUF4IH $0xB1, X7, X8
	XVADDH X7, X8, X7

	// X6 = [a0b1, a1b0, ...] → after swap+add:
	// X6 = [(a0b1+a1b0)×2, ...] (duplicated odd sums, in [0,2q))
	XVSHUF4IH $0xB1, X6, X8
	XVADDH X6, X8, X6

	// Field reduce once (values in [0, 2q) → [0, q))
	FIELD_REDUCE_ONCE(X7, X15, X8, X9)
	FIELD_REDUCE_ONCE(X6, X15, X8, X9)

	// De-duplicate: pick even halfwords → [e0,e1,e2,e3, e0,e1,e2,e3 | e4,...]
	XVPICKEV_H(10, 7, 7)    // xvpickev.h X10, X7, X7 → X10 = deduped even sums
	XVPICKEV_H(11, 6, 6)    // xvpickev.h X11, X6, X6 → X11 = deduped odd sums

	// Interleave: XVILVLH(vk=X10_even, vj=X11_odd, vd=X5)
	// Hardware xvilvl.h vd=X5, vj=X11, vk=X10 → [X10[0],X11[0],X10[1],X11[1],...]
	// = [e0, o0, e1, o1, e2, o2, e3, o3 | e4, o4, ...] = delta
	XVILVLH X10, X11, X5

	// acc += delta; field reduce once
	XVADDH X5, X2, X2
	FIELD_REDUCE_ONCE(X2, X15, X8, X9)
	XVMOVQ X2, (R4)

	ADDV $32, R4
	ADDV $32, R5
	ADDV $32, R6
	ADDV $32, R7
	ADDV $-1, R8
	BNE R8, R0, nttmlacc_lasx_loop

	RET

// ── internalNTTMulLASX ────────────────────────────────────────────────────────
// func internalNTTMulLASX(out, lhs, rhs *nttElement)
//
// Same as internalNTTMulAccLASX but writes delta directly to out (no accumulate).
TEXT ·internalNTTMulLASX(SB), NOSPLIT, $0-24
	MOVV out+0(FP), R4
	MOVV lhs+8(FP), R5
	MOVV rhs+16(FP), R6

	SETUP_CONSTS

	MOVV $·gammaMulTableLASX(SB), R7
	MOVV $16, R8

nttmlasx_loop:
	XVMOVQ (R5), X0
	XVMOVQ (R6), X1
	XVMOVQ (R7), X3

	XVSHUF4IH $0xB1, X1, X4

	MONT_MUL_LASX(X0, X1, X5, X8, X9)
	MONT_MUL_LASX(X0, X4, X6, X8, X9)
	MONT_MUL_LASX(X5, X3, X7, X8, X9)

	REDUCE_MONT(X7, X15, X8)
	REDUCE_MONT(X6, X15, X8)

	XVSHUF4IH $0xB1, X7, X8
	XVADDH X7, X8, X7

	XVSHUF4IH $0xB1, X6, X8
	XVADDH X6, X8, X6

	FIELD_REDUCE_ONCE(X7, X15, X8, X9)
	FIELD_REDUCE_ONCE(X6, X15, X8, X9)

	XVPICKEV_H(10, 7, 7)
	XVPICKEV_H(11, 6, 6)

	XVILVLH X10, X11, X5

	XVMOVQ X5, (R4)

	ADDV $32, R4
	ADDV $32, R5
	ADDV $32, R6
	ADDV $32, R7
	ADDV $-1, R8
	BNE R8, R0, nttmlasx_loop

	RET

// ── internalNTTMulAccKeyGenLASX ───────────────────────────────────────────────
// func internalNTTMulAccKeyGenLASX(acc, lhs, rhs *nttElement)
//
// Same as internalNTTMulAccLASX but converts delta from Montgomery to standard
// domain via MontMul(delta, rr) where rr=1353=r^2 mod q.
TEXT ·internalNTTMulAccKeyGenLASX(SB), NOSPLIT, $0-24
	MOVV acc+0(FP), R4
	MOVV lhs+8(FP), R5
	MOVV rhs+16(FP), R6

	SETUP_CONSTS

	// Broadcast rr=1353 into X12
	// 1353 = 0x0549; replicated 64-bit: 0x054905490549_0549
	MOVV $0x0549054905490549, R9
	XVMOVQ R9, X12.V4

	MOVV $·gammaMulTableLASX(SB), R7
	MOVV $16, R8

nttmlacc_kg_lasx_loop:
	XVMOVQ (R5), X0
	XVMOVQ (R6), X1
	XVMOVQ (R4), X2
	XVMOVQ (R7), X3

	XVSHUF4IH $0xB1, X1, X4

	MONT_MUL_LASX(X0, X1, X5, X9, X10)
	MONT_MUL_LASX(X0, X4, X6, X9, X10)
	MONT_MUL_LASX(X5, X3, X7, X9, X10)

	REDUCE_MONT(X7, X15, X9)
	REDUCE_MONT(X6, X15, X9)

	XVSHUF4IH $0xB1, X7, X9
	XVADDH X7, X9, X7

	XVSHUF4IH $0xB1, X6, X9
	XVADDH X6, X9, X6

	FIELD_REDUCE_ONCE(X7, X15, X9, X10)
	FIELD_REDUCE_ONCE(X6, X15, X9, X10)

	XVPICKEV_H(11, 7, 7)
	XVPICKEV_H(13, 6, 6)

	XVILVLH X11, X13, X5

	// Convert delta from Montgomery to standard domain: MontMul(delta, rr)
	MONT_MUL_LASX(X5, X12, X5, X9, X10)
	REDUCE_MONT(X5, X15, X9)

	XVADDH X5, X2, X2
	FIELD_REDUCE_ONCE(X2, X15, X9, X10)
	XVMOVQ X2, (R4)

	ADDV $32, R4
	ADDV $32, R5
	ADDV $32, R6
	ADDV $32, R7
	ADDV $-1, R8
	BNE R8, R0, nttmlacc_kg_lasx_loop

	RET

// ── ringCompressAndEncode4LASX ────────────────────────────────────────────────
// func ringCompressAndEncode4LASX(out []byte, f *ringElement)
//
// Compress_4 + ByteEncode_4: maps 256 int16 coefficients in [0,q) to 128 bytes.
// Packing: out[i] = compress(f[2i]) | compress(f[2i+1]) << 4
//
// Uses LASX for compress (XVMUHH), then XVPICKEV_B + XVMOVQ element extraction
// for nibble-packing — no stack access required.
//
// Algorithm per 16 coefficients (1 LASX register):
//   1. COMPRESS4 → X2 = [c0..c15] as int16 ∈[0,15]
//   2. XVSHUF4IH $0xB1: swap adjacent H within each W → X5 = [c1,c0,c3,c2,...] 
//   3. XVSLLH $4, X5 → X5 = [c1<<4, c0<<4, c3<<4, ...]
//   4. XVORV X2, X5 → X6: even halfwords = c[2i]|(c[2i+1]<<4) = packed byte b[i]
//   5. XVPICKEV_H(X4, X6, X6): compact to 4 halfwords per lane = [b0,b1,b2,b3 | b4..b7]
//   6. XVPICKEV_B(X6, X4, X4): compact packed bytes (each b in low byte of int16)
//      X6.V[0] = b0|b1<<8|b2<<16|b3<<24|...  X6.V[2] = b4|b5<<8|b6<<16|b7<<24|...
//   7. XVMOVQ X6.V[0], R11; MOVW R11, 0(R4) — extract b0..b3
//      XVMOVQ X6.V[2], R11; MOVW R11, 4(R4) — extract b4..b7
//
// Register allocation:
//   R4=out, R5=f, R6=loop counter, R11=GPR temp
//   X0=input (16 coefficients), X2=compress result
//   X8=broadcast(20159), X9=broadcast(32), X10=broadcast(0xF)
//   X4,X5,X6=nibble packing temporaries
TEXT ·ringCompressAndEncode4LASX(SB), NOSPLIT, $0-32
	MOVV out_base+0(FP), R4
	MOVV f+24(FP), R5

	// Setup constants (broadcast to all 16 halfwords using .H16)
	MOVV $20159, R7
	XVMOVQ R7, X8.H16   // broadcast 20159 to all halfwords
	MOVV $32, R7
	XVMOVQ R7, X9.H16   // broadcast 32 to all halfwords
	MOVV $15, R7
	XVMOVQ R7, X10.H16  // broadcast 0xF to all halfwords

	MOVV $16, R6   // 16 iterations × 16 coefficients = 256 coefficients

compress4_loop:
	XVMOVQ (R5), X0   // load 16 int16 coefficients

	// Compress: c = ((mulhigh16(x, 20159) + 32) >> 6) & 0xF
	COMPRESS4(X0, X2, X8, X4, X9, X10)

	// Pack nibble pairs: out[k] = c[2k] | (c[2k+1] << 4)
	// Swap adjacent halfwords within each 32-bit word to bring odd nibbles to even positions
	XVSHUF4IH $0xB1, X2, X5        // X5 = [c1,c0, c3,c2, c5,c4, c7,c6, ...] per 32-bit group
	XVSLLH $4, X5, X5              // X5 = [c1<<4, 0, c3<<4, 0, ...] (odd nibbles shifted to high-nibble of byte)
	XVORV X2, X5, X6               // X6: even halfwords = c[2k] | (c[2k+1]<<4) = packed byte b[k]

	// Compact: keep only even halfwords (packed bytes) per lane
	// XVPICKEV_H(4, 6, 6): even halfw of lane0 → X4.lane0.half[0..3] = [b0,b1,b2,b3]
	//                       even halfw of lane1 → X4.lane1.half[0..3] = [b4,b5,b6,b7]
	XVPICKEV_H(4, 6, 6)

	// Compact bytes: X4 has [b0,0, b1,0, b2,0, b3,0 | b4,0,...] as bytes per lane
	// XVPICKEV_B(6, 4, 4): even bytes of lane0 → X6.lane0.byte[0..7] = [b0,b1,b2,b3,b0,b1,b2,b3]
	//                       even bytes of lane1 → X6.lane1.byte[0..7] = [b4,b5,b6,b7,b4,b5,b6,b7]
	XVPICKEV_B(6, 4, 4)

	// Extract packed bytes via LASX element extraction (no stack needed)
	// V[0] = lane0 qword 0 = b0|b1<<8|b2<<16|b3<<24|b0<<32|... (repeated in 64-bit)
	// V[2] = lane1 qword 0 = b4|...|b7<<24|...
	XVMOVQ X6.V[0], R11
	MOVW   R11, 0(R4)
	XVMOVQ X6.V[2], R11
	MOVW   R11, 4(R4)

	ADDV   $32, R5   // advance input by 16 int16 = 32 bytes
	ADDV   $8, R4    // advance output by 8 bytes
	ADDV   $-1, R6
	BNE    R6, R0, compress4_loop

	RET

// ── ringDecodeAndDecompress4LASX ──────────────────────────────────────────────
// func ringDecodeAndDecompress4LASX(b *[128]byte, f *ringElement)
//
// ByteDecode₄ + Decompress₄: maps 128 packed bytes to 256 int16 coefficients.
// Each byte b[i] encodes two 4-bit values: c[2i] = b[i] & 0xF, c[2i+1] = b[i] >> 4.
// Output: f[j] = decompress(c[j], 4) = round(c[j] * 3329 / 16).
// Formula: f = (c * q + 8) >> 4,  q = 3329, rounding = 8.
//
// Algorithm (per 8 input bytes → 16 output coefficients):
//   1. Broadcast 8 bytes into all LASX quadwords (X0.V4)
//   2. Extract even nibbles: XVANDV with 0x0F byte mask → X1
//   3. Extract odd nibbles:  XVSRLB $4 → X2
//   4. XVILVLB(X1, X2, X3): interleave → X3.lane0 = [c0,c1,...,c15]
//   5. XVMULWEVHBU(X3,X11,X4): even bytes → uint16 [c0,c2,...,c14]
//      XVMULWODHBU(X3,X11,X5): odd bytes → uint16 [c1,c3,...,c15]
//   6. XVILVLH(X4,X5,X6): [c0,c1,...,c7]; XVILVHH(X4,X5,X7): [c8..c15]
//   7. Decompress via XVMULWEVWHU(×q) + XVMULWODWHU(×q) + XVADDW($8) + XVSRLW($4)
//   8. Reorder via XVILVLW + XVILVHW + XVPICKEV_H → [f0..f7] and [f8..f15]
//   9. Store 16 halfwords via 2×VMOVQ
//
// Register allocation:
//   R4=b (input), R5=f (output), R6=loop counter, R10=GPR temp
//   X8=broadcast(q=3329, H16), X9=broadcast(8, W8)
//   X10=broadcast(0x0F, B32), X11=broadcast(0x01, B32)
//   X0-X7,X12 = temporaries
TEXT ·ringDecodeAndDecompress4LASX(SB), NOSPLIT, $0-16
	MOVV b+0(FP), R4
	MOVV f+8(FP), R5

	// Setup constants
	MOVV $3329, R7
	XVMOVQ R7, X8.H16              // X8 = q=3329 broadcast to 16 uint16 halfwords
	MOVV $8, R7
	XVMOVQ R7, X9.W8               // X9 = 8 broadcast to 8 uint32 words
	MOVV $0x0F, R7
	XVMOVQ R7, X10.B32             // X10 = 0x0F per byte (nibble mask)
	MOVV $1, R7
	XVMOVQ R7, X11.B32             // X11 = 0x01 per byte (ones for zero-extension)

	MOVV $16, R6                    // 16 iterations × 8 bytes = 128 bytes total

decompress4_loop:
	MOVV (R4), R10                  // load 8 input bytes

	// Broadcast 8 bytes to all quadwords of X0
	XVMOVQ R10, X0.V4

	// Extract even nibbles (low 4 bits of each byte)
	XVANDV X0, X10, X1             // X1.byte[i] = b[i%8] & 0x0F = c[2*(i%8)]

	// Extract odd nibbles (high 4 bits of each byte)
	XVSRLB $4, X0, X2              // X2.byte[i] = b[i%8] >> 4 = c[2*(i%8)+1]

	// Interleave nibble bytes: X3.lane0.byte[0..15] = [c0,c1,c2,...,c15]
	// XVILVLB Xvk=X1, Xvj=X2, Xvd=X3: byte[2i]=X1.byte[i]=c[2i], byte[2i+1]=X2.byte[i]=c[2i+1]
	XVILVLB X1, X2, X3

	// Zero-extend nibble bytes to uint16 halfwords
	// XVMULWEVHBU: even bytes × ones → even bytes zero-extended to halfword
	XVMULWEVHBU X3, X11, X4        // X4.half[i] = X3.byte[2i] = c[2i]; [c0,c2,...,c14] per lane0
	XVMULWODHBU X3, X11, X5        // X5.half[i] = X3.byte[2i+1] = c[2i+1]; [c1,c3,...,c15]

	// Interleave halfwords to get sequential nibble values
	// XVILVLH Xvk=X4, Xvj=X5: even positions from X4, odd from X5
	XVILVLH X4, X5, X6             // X6.half[0..7] = [c0,c1,c2,c3,c4,c5,c6,c7] per lane0
	XVILVHH X4, X5, X7             // X7.half[0..7] = [c8,c9,...,c15] per lane0

	// ── Decompress X6 → [f0..f7] ──────────────────────────────────────────
	// f = (c * q + 8) >> 4,  using 32-bit intermediate arithmetic
	XVMULWEVWHU X6, X8, X12        // X12.word[0..3] = c[0,2,4,6] × q  (lane0)
	XVMULWODWHU X6, X8, X0         // X0.word[0..3]  = c[1,3,5,7] × q
	XVADDW X9, X12, X12            // add rounding 8
	XVADDW X9, X0, X0
	XVSRLW $4, X12, X12            // >> 4: f[0,2,4,6] in low 16 bits of each word
	XVSRLW $4, X0, X0              // f[1,3,5,7]
	// Merge words into sequential halfwords:
	// XVILVLW Xvk=X12, Xvj=X0: word[2i]=X12.word[i], word[2i+1]=X0.word[i]
	XVILVLW X12, X0, X3            // X3.word = [f0,f1,f2,f3] per lane (in low 16b each)
	XVILVHW X12, X0, X4            // X4.word = [f4,f5,f6,f7]
	// XVPICKEV_H(Xvd=6, Xvj=4, Xvk=3): even halfwords (= low 16b of each word)
	XVPICKEV_H(6, 4, 3)            // X6.half = [f0,f1,f2,f3, f4,f5,f6,f7] per lane0

	// ── Decompress X7 → [f8..f15] ─────────────────────────────────────────
	XVMULWEVWHU X7, X8, X12
	XVMULWODWHU X7, X8, X0
	XVADDW X9, X12, X12
	XVADDW X9, X0, X0
	XVSRLW $4, X12, X12
	XVSRLW $4, X0, X0
	XVILVLW X12, X0, X3
	XVILVHW X12, X0, X4
	XVPICKEV_H(7, 4, 3)            // X7.half = [f8,f9,...,f15] per lane0

	// Store 16 coefficients (32 bytes total)
	VMOVQ V6, 0(R5)                // f[0..7] (16 bytes)
	VMOVQ V7, 16(R5)               // f[8..15] (16 bytes)

	ADDV $8, R4                    // advance input by 8 bytes
	ADDV $32, R5                   // advance output by 16 int16 = 32 bytes
	ADDV $-1, R6
	BNE R6, R0, decompress4_loop

	RET

// ── ringCompressAndEncode1LASX ────────────────────────────────────────────────
// func ringCompressAndEncode1LASX(out []byte, f *ringElement)
//
// Compress_1 + ByteEncode_1: maps 256 int16 coefficients to 32 bytes (1 bit each).
// compress(x, 1) = 1 if 833 ≤ x ≤ 2496, else 0.
//
// LASX algorithm: 8 iterations × 32 coefs → 4 output bytes per iteration.
// Per 32-coef group (X0 and X1 processed identically):
//   1. Load 16 coefs into X0.
//   2. Compute in-range mask via sign-bit trick:
//        lo = XVSUBH(X8, X0) → x-833; XVSRLH $15 → 1 if x < 833
//        hi = XVSUBH(X0, X9) → 2496-x; XVSRLH $15 → 1 if x > 2496
//        out_of_range = lo | hi; in_range = 1 - out_of_range (0 or 1 per halfword)
//   3. XVMULH in_range, weights → positional values [b0*1, b1*2, b2*4, ..., b7*128]
//   4. Horizontal reduction (2 rounds of shuffle+add):
//        Round 1: XVSHUF4IH $0xB1 (swap adjacent halfwords in 32-bit groups) + XVADDH
//                 → pairs summed: [s01, s01, s23, s23, s45, s45, s67, s67]
//        Round 2: XVSHUF4IH $0x4E (swap 32-bit halves within 64-bit groups) + XVADDH
//                 → [s0123, s0123, s0123, s0123, s4567, s4567, s4567, s4567]
//   5. Extract 2 output bytes per LASX register:
//        Lane 0: word0=s0123|s0123<<16 → SRLV+OR → s0123 in low byte
//                word2=s4567|s4567<<16 → ADD → s0123+s4567 = packed byte
//        Lane 1: words 4 and 6 similarly → second byte
//
// Register allocation:
//   R4=out, R5=f, R6=loop counter, R7=scratch
//   X8=broadcast(833, H16), X9=broadcast(2496, H16), X10=broadcast(1, H16)
//   X12=compress1Weights (bit-position weights [1,2,4,8,16,32,64,128,...])
//   X0,X1=coefs; X2,X3=in-range masks/weighted bits; X4=shuffle temp
TEXT ·ringCompressAndEncode1LASX(SB), NOSPLIT, $0-32
	MOVV out_base+0(FP), R4
	MOVV f+24(FP), R5

	// Setup constants
	MOVV $833, R7
	XVMOVQ R7, X8.H16           // X8 = broadcast(833)
	MOVV $2496, R7
	XVMOVQ R7, X9.H16           // X9 = broadcast(2496)
	MOVV $1, R7
	XVMOVQ R7, X10.H16          // X10 = broadcast(1) for sign-bit inversion

	// Load bit-position weights [1,2,4,8,16,32,64,128, 1,2,4,8,16,32,64,128]
	MOVV $compress1Weights<>(SB), R7
	XVMOVQ (R7), X12

	MOVV $8, R6                 // 8 iterations × 32 coefs = 256

compress1_loop:
	// Load 32 coefficients
	XVMOVQ (R5),    X0          // X0 = coefs[0..15]
	XVMOVQ 32(R5),  X1          // X1 = coefs[16..31]

	// ── X0: in-range detection and bit-packing ────────────────────────────
	XVSUBH X8, X0, X2            // X2 = x - 833 per halfword
	XVSRLH $15, X2, X2           // X2 = 1 where x < 833 (lo mask)
	XVSUBH X0, X9, X3            // X3 = 2496 - x per halfword
	XVSRLH $15, X3, X3           // X3 = 1 where x > 2496 (hi mask)
	XVORV  X2, X3, X2            // X2 = 1 where out-of-range
	XVSUBH X2, X10, X2           // X2 = 1 - out = in-range (0 or 1)
	XVMULH X2, X12, X2           // X2 = positional values: [b0*1, b1*2, ..., b7*128, ...]
	// Round 1: swap adjacent halfwords within each 32-bit word → pair-sum
	XVSHUF4IH $0xB1, X2, X4
	XVADDH    X2, X4, X2         // [s01, s01, s23, s23, s45, s45, s67, s67, ...]
	// Round 2: swap 32-bit halves within each 64-bit group → quad-sum
	XVSHUF4IH $0x4E, X2, X4
	XVADDH    X2, X4, X2         // [s0123, ×4, s4567, ×4 | s0123', ×4, s4567', ×4]

	// ── X1: same pipeline ─────────────────────────────────────────────────
	XVSUBH X8, X1, X3; XVSRLH $15, X3, X3     // lo: 1 where x < 833
	XVSUBH X1, X9, X4; XVSRLH $15, X4, X4     // hi: 1 where x > 2496
	XVORV  X3, X4, X3                           // out-of-range
	XVSUBH X3, X10, X3                          // in-range
	XVMULH X3, X12, X3
	XVSHUF4IH $0xB1, X3, X4; XVADDH X3, X4, X3
	XVSHUF4IH $0x4E, X3, X4; XVADDH X3, X4, X3

// ── Extract 4 output bytes ────────────────────────────────────────────
	// After round 2: X2 = [s0123,s0123,s0123,s0123, s4567,s4567,s4567,s4567 | lane1...]
	// V[0]=s0123 (low 64-bit group of lane0), V[1]=s4567 (high group of lane0)
	// V[2]=s0123' (lane1 low), V[3]=s4567' (lane1 high)
	// Low 8 bits of each V[n] hold the partial byte sum.
	// Byte 0 (X2 coefs 0..7 = lane0): s0123 + s4567
	XVMOVQ X2.V[0], R10
	XVMOVQ X2.V[1], R11
	ADD  R10, R11, R10
	MOVBU R10, 0(R4)
	// Byte 1 (coefs 8..15): lane1 of X2
	XVMOVQ X2.V[2], R10
	XVMOVQ X2.V[3], R11
	ADD  R10, R11, R10
	MOVBU R10, 1(R4)
	// X3: same structure for coefs 16..31
	// Byte 2 (coefs 16..23):
	XVMOVQ X3.V[0], R10
	XVMOVQ X3.V[1], R11
	ADD  R10, R11, R10
	MOVBU R10, 2(R4)
	// Byte 3 (coefs 24..31):
	XVMOVQ X3.V[2], R10
	XVMOVQ X3.V[3], R11
	ADD  R10, R11, R10
	MOVBU R10, 3(R4)

	ADDV $64, R5                // 32 int16 = 64 bytes
	ADDV $4, R4                 // 4 output bytes
	ADDV $-1, R6
	BNE R6, R0, compress1_loop

	RET

// ── ringCompressAndEncode5LASX ────────────────────────────────────────────────
// func ringCompressAndEncode5LASX(out []byte, f *ringElement)
//
// Compress_5 + ByteEncode_5: maps 256 int16 coefficients to 160 bytes.
// Compress formula: c = ((mulhigh16(x, 20159) + 16) >> 5) & 0x1F
// ByteEncode_5: 8 × 5-bit → 5 bytes. x = c0|c1<<5|c2<<10|c3<<15|c4<<20|c5<<25|c6<<30|c7<<35
//
// Algorithm: 32 iterations × 8 coefs → 5 bytes each.
// Per iteration: load 8 coefs via VMOVQ (lower 128-bit lane), compress via LASX,
// extract V[0]/V[1] to GPR, pack 5-bit values, store 5 bytes.
TEXT ·ringCompressAndEncode5LASX(SB), NOSPLIT, $0-32
	MOVV out_base+0(FP), R4
	MOVV f+24(FP), R5

	MOVV $20159, R7
	XVMOVQ R7, X8.H16        // X8 = broadcast(20159)
	MOVV $16, R7
	XVMOVQ R7, X9.H16        // X9 = broadcast(16)
	MOVV $0x1F, R7
	XVMOVQ R7, X10.H16       // X10 = broadcast(0x1F)
	MOVV $0x1F, R7            // scalar 5-bit mask

	MOVV $32, R6

compress5_loop:
	VMOVQ (R5), V0            // load 8 coefs into V0 (lower 128-bit of X0)

	// Compress: ((mulhigh16(x, 20159) + 16) >> 5) & 0x1F
	XVMUHH X0, X8, X1
	XVADDH X9, X1, X1
	XVSRAH $5, X1, X1
	XVANDV X10, X1, X1        // X1.half[0..7] = c0..c7

	// Extract c0..c7 from LASX register (lower 128-bit lane)
	XVMOVQ X1.V[0], R10      // R10 = c0|(c1<<16)|(c2<<32)|(c3<<48)
	XVMOVQ X1.V[1], R11      // R11 = c4|(c5<<16)|(c6<<32)|(c7<<48)

	// Pack into 40-bit accumulator R20
	// XVMOVQ X1.V[n] gives [c0,c1,c2,c3] as uint16 halfwords in 64-bit GPR
	// c0 at [15:0], c1 at [31:16], c2 at [47:32], c3 at [63:48]
	MOVV   R10, R20
	AND    R7, R20             // c0 in R20

	SRLV   $16, R10, R12
	AND    R7, R12             // c1 raw
	SLLV   $5, R12, R12
	OR     R12, R20            // c1 at [9:5]

	SRLV   $32, R10, R12
	AND    R7, R12             // c2 raw
	SLLV   $10, R12, R12
	OR     R12, R20            // c2 at [14:10]

	SRLV   $48, R10, R12
	AND    R7, R12             // c3 raw
	SLLV   $15, R12, R12
	OR     R12, R20            // c3 at [19:15]

	MOVV   R11, R12
	AND    R7, R12             // c4 raw
	SLLV   $20, R12, R12
	OR     R12, R20            // c4 at [24:20]

	SRLV   $16, R11, R12
	AND    R7, R12             // c5 raw
	SLLV   $25, R12, R12
	OR     R12, R20            // c5 at [29:25]

	SRLV   $32, R11, R12
	AND    R7, R12             // c6 raw
	SLLV   $30, R12, R12
	OR     R12, R20            // c6 at [34:30]

	SRLV   $48, R11, R12
	AND    R7, R12             // c7 raw
	SLLV   $35, R12, R12
	OR     R12, R20            // c7 at [39:35]

	// Store 5 bytes
	MOVBU  R20, 0(R4); SRLV $8, R20, R20
	MOVBU  R20, 1(R4); SRLV $8, R20, R20
	MOVBU  R20, 2(R4); SRLV $8, R20, R20
	MOVBU  R20, 3(R4); SRLV $8, R20, R20
	MOVBU  R20, 4(R4)

	ADDV $16, R5              // 8 int16 = 16 bytes
	ADDV $5, R4               // 5 output bytes
	ADDV $-1, R6
	BNE R6, R0, compress5_loop

	RET

// ── ringDecodeAndDecompress5LASX ──────────────────────────────────────────────
// func ringDecodeAndDecompress5LASX(b *[160]byte, f *ringElement)
//
// ByteDecode_5 + Decompress_5: maps 160 bytes to 256 int16 coefficients.
// Formula: f = (c * q + 16) >> 5, where q=3329, c ∈ [0,31].
// Max c*q = 31*3329 = 103199 → needs 32-bit arithmetic (uint17).
//
// Algorithm: 32 iterations × 5 bytes → 8 coefficients (16 bytes).
// Each iteration:
//   1. Scalar: load 5 bytes, extract 8 × 5-bit values, pack 4 per GPR (as uint16 in positions [15:0],[31:16],[47:32],[63:48])
//   2. Load 2 GPRs into lower 128-bit lane of LASX register X0 (8 halfwords)
//   3. LASX decompress: XVMULWEVWHU×q + XVMULWODWHU×q + XVADDW(16) + XVSRLW(5) + reorder
//   4. XVPICKEV_H to get 8 halfwords → VMOVQ to store 16 bytes
//
// Register allocation:
//   R4=b, R5=f, R6=loop counter, R7=5-bit mask (0x1F), R8=q (3329)
//   R10=packed input bits (40-bit), R11-R18=extracted c0..c7
//   X8=broadcast(q=3329, H16), X9=broadcast(16, W8)
//   X0,X12=temporaries for decompress
TEXT ·ringDecodeAndDecompress5LASX(SB), NOSPLIT, $0-16
	MOVV b+0(FP), R4
	MOVV f+8(FP), R5

	// Setup LASX constants
	MOVV $3329, R7
	XVMOVQ R7, X8.H16           // X8 = broadcast(3329) to 16 halfwords
	MOVV $16, R7
	XVMOVQ R7, X9.W8            // X9 = broadcast(16) to 8 words
	MOVV $0x1F, R7              // scalar 5-bit mask

	MOVV $32, R6

decompress5_loop:
	// Load 5 bytes (40 bits = 8 × 5-bit values)
	MOVWU (R4), R10             // bytes 0..3 (zero-extended to 64-bit)
	MOVBU 4(R4), R11
	SLLV  $32, R11, R11
	OR    R11, R10              // R10[39:0] = all 5 bytes

	// Extract 8 × 5-bit values into c0..c7
	MOVV  R10, R11; AND R7, R11       // c0
	SRLV  $5,  R10, R12; AND R7, R12  // c1
	SRLV  $10, R10, R13; AND R7, R13  // c2
	SRLV  $15, R10, R14; AND R7, R14  // c3
	SRLV  $20, R10, R15; AND R7, R15  // c4
	SRLV  $25, R10, R16; AND R7, R16  // c5
	SRLV  $30, R10, R17; AND R7, R17  // c6
	SRLV  $35, R10, R18; AND R7, R18  // c7

	// Pack c0..c3 into one 64-bit GPR as 4 uint16 halfwords
	// R11 = c0 | (c1<<16) | (c2<<32) | (c3<<48)
	SLLV $16, R12, R12; OR R12, R11
	SLLV $32, R13, R13; OR R13, R11
	SLLV $48, R14, R14; OR R14, R11

	// Pack c4..c7 into second 64-bit GPR
	// R15 = c4 | (c5<<16) | (c6<<32) | (c7<<48)
	SLLV $16, R16, R16; OR R16, R15
	SLLV $32, R17, R17; OR R17, R15
	SLLV $48, R18, R18; OR R18, R15

	// Write packed GPRs to output buffer, load as LASX, then overwrite with results.
	// (Safe: output buffer is 16 bytes aligned and writable; we overwrite it immediately after.)
	MOVV R11, 0(R5)
	MOVV R15, 8(R5)
	XVMOVQ (R5), X0             // X0[127:0] = [c0,c1,...,c7] as uint16 halfwords

	// LASX decompress: f = (c * q + 16) >> 5 (32-bit arithmetic)
	XVMULWEVWHU X0, X8, X12     // X12.word[i] = X0.half[2i] × q  (for c0,c2,c4,c6)
	XVMULWODWHU X0, X8, X0     // X0.word[i]  = X0_orig.half[2i+1] × q  (c1,c3,c5,c7)
	XVADDW X9, X12, X12         // add 16 (rounding)
	XVADDW X9, X0,  X0
	XVSRLW $5, X12, X12         // >> 5: f[0,2,4,6] in low 16 bits of each word
	XVSRLW $5, X0,  X0          // f[1,3,5,7]

	// Reorder: interleave even/odd results into sequential halfwords
	XVILVLW X12, X0, X1         // X1.words = [f0,f1,f2,f3, ...] (low 16b each)
	XVILVHW X12, X0, X2         // X2.words = [f4,f5,f6,f7, ...]
	XVPICKEV_H(0, 2, 1)         // X0.half = [f0,f1,f2,f3,f4,f5,f6,f7] in lower lane

	// Store 8 int16 values from lower 128-bit lane (V0)
	VMOVQ V0, 0(R5)

	ADDV $5, R4
	ADDV $16, R5                // 8 int16 = 16 bytes
	ADDV $-1, R6
	BNE R6, R0, decompress5_loop

	RET

// ── ringCompressAndEncode10LASX ───────────────────────────────────────────────
// func ringCompressAndEncode10LASX(out []byte, f *ringElement)
//
// Compress_10 + ByteEncode_10: maps 256 int16 coefficients to 320 bytes.
// Formula: n=(x<<10)+1664; c=(n*1290168)>>32; c&=0x3FF
// ByteEncode_10: 4 × 10-bit → 5 bytes. x=c0|c1<<10|c2<<20|c3<<30 (40 bits).
//
// LASX algorithm: 16 iterations × 16 coefs → 20 bytes (4 × 5-byte groups).
// Per iteration:
//   1. Load 16 coefficients (X0) as uint16 halfwords
//   2. Widen to 32-bit (XVMULWEVWHU×1 and XVMULWODWHU×1)
//   3. XVSLLW $10 + XVADDW(1664) → n values (22-bit in 32-bit words)
//   4. XVMULWEVVWU × 1290168 + XVMULWODVWU × 1290168 → 64-bit products
//   5. XVSRLV $32 → upper 32 bits (compressed values)
//   6. XVANDV × 0x3FF → 10-bit values
//   7. Extract via XVMOVQ V[] to GPR, scalar pack 4×10-bit → 5 bytes
//
// Register allocation:
//   R4=out, R5=f, R6=loop counter, R7=scratch
//   X8=broadcast(1=ones, H16), X9=broadcast(1664, W8)
//   X10=broadcast(1290168, W8), X11=broadcast(0x3FF, W8)
//   X0,X1,X2,X3,X12,X13 = temporaries
TEXT ·ringCompressAndEncode10LASX(SB), NOSPLIT, $0-32
	MOVV out_base+0(FP), R4
	MOVV f+24(FP), R5

	MOVV $1, R7
	XVMOVQ R7, X8.H16          // broadcast 1 to all halfwords (for widening)
	MOVV $1664, R7
	XVMOVQ R7, X9.W8           // broadcast 1664 to all words
	MOVV $1290168, R7
	XVMOVQ R7, X10.W8          // broadcast 1290168 to all words
	MOVV $0x3FF, R7
	XVMOVQ R7, X11.W8          // broadcast 0x3FF to all words

	MOVV $16, R6   // 16 iterations × 16 coefficients = 256

compress10_loop:
	// Load 16 coefficients (32 bytes)
	XVMOVQ (R5), X0

	// Widen even/odd halfwords to 32-bit words
	XVMULWEVWHU X0, X8, X1     // X1.word[i] = X0.half[2i] (even coefs, zero-extended)
	XVMULWODWHU X0, X8, X2     // X2.word[i] = X0.half[2i+1] (odd coefs, zero-extended)

	// Compute n = (x << 10) + 1664 for even coefs
	XVSLLW $10, X1, X1         // x << 10
	XVADDW X9, X1, X1          // n = (x<<10) + 1664

	// Compute n = (x << 10) + 1664 for odd coefs
	XVSLLW $10, X2, X2
	XVADDW X9, X2, X2

	// Multiply even words by 1290168 → 64-bit products (word × word → dword)
	XVMULWEVVWU X1, X10, X12   // X12.dword[i] = X1.word[2i] * 1290168
	XVMULWODVWU X1, X10, X13   // X13.dword[i] = X1.word[2i+1] * 1290168
	// Shift right 32 to get upper 32 bits
	XVSRLV $32, X12, X12       // c_ev[0,2,4,6] in low 32 bits of each dword
	XVSRLV $32, X13, X13       // c_ev[1,3,5,7]

	// Multiply odd (halfword-index) words by 1290168
	XVMULWEVVWU X2, X10, X1
	XVMULWODVWU X2, X10, X2
	XVSRLV $32, X1, X1         // c_od[0,2,4,6]
	XVSRLV $32, X2, X2         // c_od[1,3,5,7]

	// Mask all results to 10 bits
	XVANDV X11, X12, X12
	XVANDV X11, X13, X13
	XVANDV X11, X1, X1
	XVANDV X11, X2, X2

	// X12 = {c0_comp, c4_comp, c8_comp, c12_comp} as 64-bit dwords (value in low 32 bits each)
	// X13 = {c2_comp, c6_comp, c10_comp, c14_comp}
	// X1  = {c1_comp, c5_comp, c9_comp, c13_comp}
	// X2  = {c3_comp, c7_comp, c11_comp, c15_comp}
	//
	// V[n] extracts quadword n (64-bit). Each quadword holds one compressed value (in low 32 bits).
	// 4 groups × 4 extractions = 16 XVMOVQ, but scalar packing is straightforward.

	// Group 0: c0,c1,c2,c3 → 5 bytes
	XVMOVQ X12.V[0], R10
	XVMOVQ X13.V[0], R11
	XVMOVQ X1.V[0],  R12
	XVMOVQ X2.V[0],  R13
	MOVV  R10, R20; SLLV $10, R12, R14; OR R14, R20; SLLV $20, R11, R14; OR R14, R20; SLLV $30, R13, R14; OR R14, R20
	MOVBU R20, 0(R4); SRLV $8, R20, R20; MOVBU R20, 1(R4); SRLV $8, R20, R20; MOVBU R20, 2(R4); SRLV $8, R20, R20; MOVBU R20, 3(R4); SRLV $8, R20, R20; MOVBU R20, 4(R4)

	// Group 1: c4,c5,c6,c7 → 5 bytes
	XVMOVQ X12.V[1], R10
	XVMOVQ X13.V[1], R11
	XVMOVQ X1.V[1],  R12
	XVMOVQ X2.V[1],  R13
	MOVV  R10, R20; SLLV $10, R12, R14; OR R14, R20; SLLV $20, R11, R14; OR R14, R20; SLLV $30, R13, R14; OR R14, R20
	MOVBU R20, 5(R4); SRLV $8, R20, R20; MOVBU R20, 6(R4); SRLV $8, R20, R20; MOVBU R20, 7(R4); SRLV $8, R20, R20; MOVBU R20, 8(R4); SRLV $8, R20, R20; MOVBU R20, 9(R4)

	// Group 2: c8,c9,c10,c11 → 5 bytes
	XVMOVQ X12.V[2], R10
	XVMOVQ X13.V[2], R11
	XVMOVQ X1.V[2],  R12
	XVMOVQ X2.V[2],  R13
	MOVV  R10, R20; SLLV $10, R12, R14; OR R14, R20; SLLV $20, R11, R14; OR R14, R20; SLLV $30, R13, R14; OR R14, R20
	MOVBU R20, 10(R4); SRLV $8, R20, R20; MOVBU R20, 11(R4); SRLV $8, R20, R20; MOVBU R20, 12(R4); SRLV $8, R20, R20; MOVBU R20, 13(R4); SRLV $8, R20, R20; MOVBU R20, 14(R4)

	// Group 3: c12,c13,c14,c15 → 5 bytes
	XVMOVQ X12.V[3], R10
	XVMOVQ X13.V[3], R11
	XVMOVQ X1.V[3],  R12
	XVMOVQ X2.V[3],  R13
	MOVV  R10, R20; SLLV $10, R12, R14; OR R14, R20; SLLV $20, R11, R14; OR R14, R20; SLLV $30, R13, R14; OR R14, R20
	MOVBU R20, 15(R4); SRLV $8, R20, R20; MOVBU R20, 16(R4); SRLV $8, R20, R20; MOVBU R20, 17(R4); SRLV $8, R20, R20; MOVBU R20, 18(R4); SRLV $8, R20, R20; MOVBU R20, 19(R4)

	ADDV $32, R5              // 16 int16 = 32 bytes
	ADDV $20, R4              // 16 × 10-bit = 20 bytes
	ADDV $-1, R6
	BNE R6, R0, compress10_loop

	RET

// ── ringCompressAndEncode11LASX ───────────────────────────────────────────────
// func ringCompressAndEncode11LASX(out []byte, f *ringElement)
//
// Compress_11 + ByteEncode_11: maps 256 int16 coefficients to 352 bytes.
// Compress_11 (32-bit): n=(x<<11)+1664; c=(n*1290168)>>32; c&=0x7FF
// ByteEncode_11: 8 × 11-bit → 11 bytes (88 bits packed across two GPRs).
//
// LASX vectorization: 16 coefs per iteration → 22 bytes output, 16 iterations.
// Pipeline (same structure as compress10 but XVSLLW $11 and mask $0x7FF):
//   X0  = 16 int16 coefs
//   X1  = even-indexed coefs widened to 32-bit (XVMULWEVWHU X0, X8, X1, where X8=1)
//   X2  = odd-indexed coefs widened to 32-bit
//   XVSLLW $11 on X1,X2; XVADDW X9 (1664); XVMULWEVVWU/XVMULWODVWU × X10 (1290168)
//   XVSRLV $32; XVANDV X11 (0x7FF)
//   X12={c0,c4,c8,c12}; X13={c2,c6,c10,c14}; X1={c1,c5,c9,c13}; X2={c3,c7,c11,c15}
//   Extract via XVMOVQ V[0..3] → pack half1 (c0..c7→11 bytes) and half2 (c8..c15→11 bytes).
TEXT ·ringCompressAndEncode11LASX(SB), NOSPLIT, $0-32
	MOVV out_base+0(FP), R4
	MOVV f+24(FP), R5

	MOVV $1, R7
	XVMOVQ R7, X8.H16           // X8 = broadcast 1 to all 16 halfwords
	MOVV $1664, R7
	XVMOVQ R7, X9.W8            // X9 = broadcast 1664
	MOVV $1290168, R7
	XVMOVQ R7, X10.W8           // X10 = broadcast 1290168
	MOVV $0x7FF, R7
	XVMOVQ R7, X11.W8           // X11 = broadcast 0x7FF

	MOVV $16, R6

compress11_loop:
	XVMOVQ (R5), X0             // load 16 int16 coefs

	// Widen to 32-bit: multiply each halfword by 1
	XVMULWEVWHU X0, X8, X1      // X1[word i] = coef[2i]   (even halfwords)
	XVMULWODWHU X0, X8, X2      // X2[word i] = coef[2i+1] (odd halfwords)

	// n_ev = coef_ev << 11 + 1664; n_od = coef_od << 11 + 1664
	XVSLLW $11, X1, X1
	XVADDW X9, X1, X1
	XVSLLW $11, X2, X2
	XVADDW X9, X2, X2

	// c_ev = (n_ev * 1290168) >> 32; split into even/odd dwords for 64-bit multiply
	XVMULWEVVWU X1, X10, X12    // 64-bit products from even words of X1 → {c0,c4,c8,c12}
	XVMULWODVWU X1, X10, X13    // 64-bit products from odd  words of X1 → {c2,c6,c10,c14}
	XVSRLV $32, X12, X12
	XVSRLV $32, X13, X13

	// c_od = (n_od * 1290168) >> 32
	XVMULWEVVWU X2, X10, X1     // {c1,c5,c9,c13}
	XVMULWODVWU X2, X10, X2     // {c3,c7,c11,c15}
	XVSRLV $32, X1, X1
	XVSRLV $32, X2, X2

	// Apply 11-bit mask
	XVANDV X11, X12, X12
	XVANDV X11, X13, X13
	XVANDV X11, X1,  X1
	XVANDV X11, X2,  X2

	// X12={c0,c4,c8,c12}; X13={c2,c6,c10,c14}; X1={c1,c5,c9,c13}; X2={c3,c7,c11,c15}
	// Each value is a 32-bit compressed coef in the low 32 bits of each 64-bit dword.
	// V[n] extracts the n-th 64-bit quadword.

	// Half 1: c0..c7 → 11 bytes
	// c0,c1,c2,c3 from V[0]
	XVMOVQ X12.V[0], R10        // c0
	XVMOVQ X13.V[0], R11        // c2
	XVMOVQ X1.V[0],  R12        // c1
	XVMOVQ X2.V[0],  R13        // c3
	// c4,c5,c6,c7 from V[1]
	XVMOVQ X12.V[1], R14        // c4
	XVMOVQ X13.V[1], R15        // c6
	XVMOVQ X1.V[1],  R16        // c5
	XVMOVQ X2.V[1],  R17        // c7

	// Pack c0..c7 into 11 bytes
	// R24 = c0|c1<<11|c2<<22|c3<<33|c4<<44|c5[8:0]<<55
	MOVV  R10, R24
	SLLV  $11, R12, R18; OR R18, R24    // c1<<11
	SLLV  $22, R11, R18; OR R18, R24    // c2<<22
	SLLV  $33, R13, R18; OR R18, R24    // c3<<33
	SLLV  $44, R14, R18; OR R18, R24    // c4<<44
	SLLV  $55, R16, R18; OR R18, R24    // c5[8:0]<<55

	// R25 = c5>>9 | c6<<2 | c7<<13
	SRLV  $9, R16, R25
	SLLV  $2, R15, R18; OR R18, R25     // c6<<2
	SLLV  $13, R17, R18; OR R18, R25    // c7<<13

	// Store 11 bytes
	MOVBU R24, 0(R4); SRLV $8, R24, R24
	MOVBU R24, 1(R4); SRLV $8, R24, R24
	MOVBU R24, 2(R4); SRLV $8, R24, R24
	MOVBU R24, 3(R4); SRLV $8, R24, R24
	MOVBU R24, 4(R4); SRLV $8, R24, R24
	MOVBU R24, 5(R4); SRLV $8, R24, R24
	MOVBU R24, 6(R4); SRLV $8, R24, R24
	MOVBU R24, 7(R4)
	MOVBU R25, 8(R4); SRLV $8, R25, R25
	MOVBU R25, 9(R4); SRLV $8, R25, R25
	MOVBU R25, 10(R4)

	// Half 2: c8..c15 → 11 bytes
	// c8,c9,c10,c11 from V[2]
	XVMOVQ X12.V[2], R10        // c8
	XVMOVQ X13.V[2], R11        // c10
	XVMOVQ X1.V[2],  R12        // c9
	XVMOVQ X2.V[2],  R13        // c11
	// c12,c13,c14,c15 from V[3]
	XVMOVQ X12.V[3], R14        // c12
	XVMOVQ X13.V[3], R15        // c14
	XVMOVQ X1.V[3],  R16        // c13
	XVMOVQ X2.V[3],  R17        // c15

	// Pack c8..c15 into 11 bytes
	MOVV  R10, R24
	SLLV  $11, R12, R18; OR R18, R24
	SLLV  $22, R11, R18; OR R18, R24
	SLLV  $33, R13, R18; OR R18, R24
	SLLV  $44, R14, R18; OR R18, R24
	SLLV  $55, R16, R18; OR R18, R24

	SRLV  $9, R16, R25
	SLLV  $2, R15, R18; OR R18, R25
	SLLV  $13, R17, R18; OR R18, R25

	MOVBU R24, 11(R4); SRLV $8, R24, R24
	MOVBU R24, 12(R4); SRLV $8, R24, R24
	MOVBU R24, 13(R4); SRLV $8, R24, R24
	MOVBU R24, 14(R4); SRLV $8, R24, R24
	MOVBU R24, 15(R4); SRLV $8, R24, R24
	MOVBU R24, 16(R4); SRLV $8, R24, R24
	MOVBU R24, 17(R4); SRLV $8, R24, R24
	MOVBU R24, 18(R4)
	MOVBU R25, 19(R4); SRLV $8, R25, R25
	MOVBU R25, 20(R4); SRLV $8, R25, R25
	MOVBU R25, 21(R4)

	ADDV $32, R5              // 16 int16 = 32 bytes
	ADDV $22, R4
	ADDV $-1, R6
	BNE R6, R0, compress11_loop

	RET

// ── decodeAndDecompressU10LASX ────────────────────────────────────────────────
// func decodeAndDecompressU10LASX(dst []ringElement, c []byte)
//
// Decodes 10-bit packed values and decompresses to ring elements.
// Each ring element: 256 coefs, encoded as 320 bytes (256×10/8).
// Inner loop: 8 coefs per 10 bytes → 16 bytes output.
// Decompress_10: f = (y*q >> 10) + ((y*q >> 9) & 1)
//
// Register usage:
//   R4 = src pointer (c)
//   R5 = dst pointer
//   R6 = outer loop counter (len(dst))
//   R7 = inner loop counter (32 per ring element)
//   R8 = 64-bit word from input
//   R9 = 16-bit word from input (bytes 8..9)
//   R10..R19 = scratch for coef extraction and packing
//   R12 = 10-bit mask (0x3FF)
//   X8 = broadcast(3329) as uint16
//   X9 = broadcast(1) as uint32 (rounding mask)
//   X10,X12 = even/odd products and temps
TEXT ·decodeAndDecompressU10LASX(SB), NOSPLIT, $0-48
	MOVV dst_base+0(FP), R5     // dst pointer
	MOVV dst_len+8(FP), R6      // number of ring elements
	MOVV c_base+24(FP), R4      // src pointer

	// Setup LASX constants
	MOVV $3329, R7
	XVMOVQ R7, X8.H16           // X8 = broadcast(3329) as uint16
	MOVV $1, R7
	XVMOVQ R7, X9.W8            // X9 = broadcast(1) as uint32
	MOVV $0x3FF, R12             // 10-bit mask

u10_outer:
	MOVV $32, R7                 // 32 inner iterations per ring element (8 coefs each)

u10_inner:
	// Load 10 bytes from src
	MOVV  (R4), R8               // bytes 0..7
	MOVHU 8(R4), R9              // bytes 8..9 (zero-extended to 64-bit)

	// Extract c0..c5 (all within R8)
	MOVV  R8, R10
	AND   R12, R10               // c0 = R8[9:0]

	SRLV  $10, R8, R11
	AND   R12, R11               // c1 = R8[19:10]

	SRLV  $20, R8, R13
	AND   R12, R13               // c2 = R8[29:20]

	SRLV  $30, R8, R14
	AND   R12, R14               // c3 = R8[39:30]

	SRLV  $40, R8, R15
	AND   R12, R15               // c4 = R8[49:40]

	SRLV  $50, R8, R16
	AND   R12, R16               // c5 = R8[59:50]

	// c6: 4 bits from R8[63:60] + 6 bits from R9[5:0]
	SRLV  $60, R8, R17           // R17 = R8[63:60] (4 bits, in [3:0])
	MOVV  R9, R18
	MOVV  $0x3F, R19
	AND   R19, R18               // R18 = R9[5:0]
	SLLV  $4, R18, R18           // R18 = R9[5:0] shifted to [9:4]
	OR    R17, R18               // R18 = c6 (10 bits)

	// c7 = R9[15:6]
	SRLV  $6, R9, R19
	AND   R12, R19               // c7

	// Pack c0..c3 into R10: c0 | c1<<16 | c2<<32 | c3<<48
	SLLV  $16, R11, R11; OR R11, R10
	SLLV  $32, R13, R13; OR R13, R10
	SLLV  $48, R14, R14; OR R14, R10

	// Pack c4..c7 into R15: c4 | c5<<16 | c6<<32 | c7<<48
	SLLV  $16, R16, R16; OR R16, R15
	SLLV  $32, R18, R18; OR R18, R15
	SLLV  $48, R19, R19; OR R19, R15

	// Write raw coefs to dst (will be overwritten by decompress results)
	MOVV  R10, 0(R5)
	MOVV  R15, 8(R5)
	XVMOVQ (R5), X0              // X0[127:0] = [c0,c1,...,c7] as uint16 halfwords

	// Decompress_10: f = (y*q >> 10) + ((y*q >> 9) & 1)
	XVMULWEVWHU X0, X8, X12     // X12.word[i] = c[2i] * q (even coefs)
	XVMULWODWHU X0, X8, X0     // X0.word[i]  = c[2i+1] * q (odd coefs)

	// Rounding and shift for even coefs
	XVSRLW $9,  X12, X10
	XVANDV X9,  X10, X10        // rounding bit
	XVSRLW $10, X12, X12
	XVADDW X10, X12, X12        // f_even

	// Rounding and shift for odd coefs
	XVSRLW $9,  X0,  X10
	XVANDV X9,  X10, X10        // rounding bit
	XVSRLW $10, X0,  X0
	XVADDW X10, X0,  X0         // f_odd

	// Interleave even and odd results
	XVILVLW X12, X0, X1         // X1.words = [f0,f1,f2,f3] (low 16b each)
	XVILVHW X12, X0, X2         // X2.words = [f4,f5,f6,f7]
	XVPICKEV_H(0, 2, 1)         // X0.half  = [f0,f1,f2,f3,f4,f5,f6,f7]

	// Store 8 int16 = 16 bytes
	VMOVQ V0, 0(R5)

	ADDV  $10, R4
	ADDV  $16, R5
	ADDV  $-1, R7
	BNE   R7, R0, u10_inner

	ADDV  $-1, R6
	BNE   R6, R0, u10_outer

	RET

// ── decodeAndDecompressU11LASX ────────────────────────────────────────────────
// func decodeAndDecompressU11LASX(dst []ringElement, c []byte)
//
// Decodes 11-bit packed values and decompresses to ring elements.
// Each ring element: 256 coefs, encoded as 352 bytes (256×11/8).
// Inner loop: 8 coefs per 11 bytes → 16 bytes output.
// Decompress_11: f = (y*q >> 11) + ((y*q >> 10) & 1)
//
// Register usage:
//   R4 = src pointer (c)
//   R5 = dst pointer
//   R6 = outer loop counter (len(dst))
//   R7 = inner loop counter (32 per ring element)
//   R8 = 64-bit word from input (bytes 0..7)
//   R9 = 24-bit word from input (bytes 8..10)
//   R10..R19 = scratch for coef extraction and packing
//   R12 = 11-bit mask (0x7FF)
//   X8 = broadcast(3329) as uint16
//   X9 = broadcast(1) as uint32 (rounding mask)
//   X10,X12 = even/odd products and temps
TEXT ·decodeAndDecompressU11LASX(SB), NOSPLIT, $0-48
	MOVV dst_base+0(FP), R5     // dst pointer
	MOVV dst_len+8(FP), R6      // number of ring elements
	MOVV c_base+24(FP), R4      // src pointer

	// Setup LASX constants
	MOVV $3329, R7
	XVMOVQ R7, X8.H16           // X8 = broadcast(3329) as uint16
	MOVV $1, R7
	XVMOVQ R7, X9.W8            // X9 = broadcast(1) as uint32
	MOVV $0x7FF, R12             // 11-bit mask

u11_outer:
	MOVV $32, R7                 // 32 inner iterations per ring element (8 coefs each)

u11_inner:
	// Load 11 bytes from src
	MOVV  (R4), R8               // bytes 0..7 (64 bits)
	MOVHU 8(R4), R9              // bytes 8..9 (16 bits, zero-extended)
	MOVBU 10(R4), R10            // byte 10 (8 bits, zero-extended)
	SLLV  $16, R10, R10
	OR    R10, R9                // R9 = bytes[8..10] in [23:0]

	// Extract c0..c4 (all within R8)
	MOVV  R8, R10
	AND   R12, R10               // c0 = R8[10:0]

	SRLV  $11, R8, R11
	AND   R12, R11               // c1 = R8[21:11]

	SRLV  $22, R8, R13
	AND   R12, R13               // c2 = R8[32:22]

	SRLV  $33, R8, R14
	AND   R12, R14               // c3 = R8[43:33]

	SRLV  $44, R8, R15
	AND   R12, R15               // c4 = R8[54:44]

	// c5: 9 bits from R8[63:55] + 2 bits from R9[1:0]
	SRLV  $55, R8, R16           // R16 = R8[63:55] (9 bits, in [8:0])
	MOVV  R9, R17
	MOVV  $3, R19
	AND   R19, R17               // R17 = R9[1:0] (low 2 bits)
	SLLV  $9, R17, R17           // R17 = R9[1:0] shifted to [10:9]
	OR    R16, R17               // R17 = c5 (11 bits)

	// c6 = R9[12:2]
	SRLV  $2, R9, R18
	AND   R12, R18               // c6

	// c7 = R9[23:13]
	SRLV  $13, R9, R19
	AND   R12, R19               // c7

	// Pack c0..c3 into R10: c0 | c1<<16 | c2<<32 | c3<<48
	SLLV  $16, R11, R11; OR R11, R10
	SLLV  $32, R13, R13; OR R13, R10
	SLLV  $48, R14, R14; OR R14, R10

	// Pack c4..c7 into R15: c4 | c5<<16 | c6<<32 | c7<<48
	SLLV  $16, R17, R17; OR R17, R15
	SLLV  $32, R18, R18; OR R18, R15
	SLLV  $48, R19, R19; OR R19, R15

	// Write raw coefs to dst (will be overwritten by decompress results)
	MOVV  R10, 0(R5)
	MOVV  R15, 8(R5)
	XVMOVQ (R5), X0              // X0[127:0] = [c0,c1,...,c7] as uint16 halfwords

	// Decompress_11: f = (y*q >> 11) + ((y*q >> 10) & 1)
	XVMULWEVWHU X0, X8, X12     // X12.word[i] = c[2i] * q (even coefs)
	XVMULWODWHU X0, X8, X0     // X0.word[i]  = c[2i+1] * q (odd coefs)

	// Rounding and shift for even coefs
	XVSRLW $10, X12, X10
	XVANDV X9,  X10, X10        // rounding bit
	XVSRLW $11, X12, X12
	XVADDW X10, X12, X12        // f_even

	// Rounding and shift for odd coefs
	XVSRLW $10, X0,  X10
	XVANDV X9,  X10, X10        // rounding bit
	XVSRLW $11, X0,  X0
	XVADDW X10, X0,  X0         // f_odd

	// Interleave even and odd results
	XVILVLW X12, X0, X1         // X1.words = [f0,f1,f2,f3] (low 16b each)
	XVILVHW X12, X0, X2         // X2.words = [f4,f5,f6,f7]
	XVPICKEV_H(0, 2, 1)         // X0.half  = [f0,f1,f2,f3,f4,f5,f6,f7]

	// Store 8 int16 = 16 bytes
	VMOVQ V0, 0(R5)

	ADDV  $11, R4
	ADDV  $16, R5
	ADDV  $-1, R7
	BNE   R7, R0, u11_inner

	ADDV  $-1, R6
	BNE   R6, R0, u11_outer

	RET
