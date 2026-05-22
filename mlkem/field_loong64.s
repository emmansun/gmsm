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

// cbd3Shuf: per-lane shuffle table for samplePolyCBD3LASX.
// Rearranges 12 bytes into 4 uint32 words, each holding one 3-byte group (+ 0x00 pad).
// Layout: [0,1,2,0x80, 3,4,5,0x80, 6,7,8,0x80, 9,10,11,0x80] repeated for both lanes.
DATA ·cbd3Shuf+0x00(SB)/8, $0x8005040380020100
DATA ·cbd3Shuf+0x08(SB)/8, $0x800B0A0980080706
DATA ·cbd3Shuf+0x10(SB)/8, $0x8005040380020100
DATA ·cbd3Shuf+0x18(SB)/8, $0x800B0A0980080706
GLOBL ·cbd3Shuf(SB), RODATA, $32

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

// XVSHUF_B performs xvshuf.b Xvd, Xvj, Xvk, Xva (4-register byte shuffle).
// Per lane n: Xd[n][i] = (Xa[n][i] bit7==1) ? 0 : (bit4==1) ? Xj[n][Xa[n][i]&0xF] : Xk[n][Xa[n][i]&0xF]
// Opcode: 0x0D6<<20 | Xva<<15 | Xvk<<10 | Xvj<<5 | Xvd
#define XVSHUF_B(Xvd, Xvj, Xvk, Xva) \
	WORD $(((0xD6) << 20) | ((Xva) << 15) | ((Xvk) << 10) | ((Xvj) << 5) | (Xvd))

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
// Algorithm: 16 iterations × 16 coefs → 10 bytes each.
// Per iteration: XVMOVQ loads 16 coefs (256 bits), compress via LASX (full width),
// extract 4 quadwords (V[0..3]) to GPRs, pack each 8-coef group into 5 bytes using
// BSTRPICKV/BSTRINSV, store 5 bytes via MOVW + MOVBU.
TEXT ·ringCompressAndEncode5LASX(SB), NOSPLIT, $0-32
	MOVV out_base+0(FP), R4
	MOVV f+24(FP), R5

	MOVV $20159, R7
	XVMOVQ R7, X8.H16        // X8 = broadcast(20159)
	MOVV $16, R7
	XVMOVQ R7, X9.H16        // X9 = broadcast(16)
	MOVV $0x1F, R7
	XVMOVQ R7, X10.H16       // X10 = broadcast(0x1F)

	MOVV $16, R6             // 16 iterations × 16 coefs = 256

compress5_loop:
	XVMOVQ (R5), X0           // load 16 coefs (32 bytes) into X0

	// Compress all 16: ((mulhigh16(x, 20159) + 16) >> 5) & 0x1F
	XVMUHH X0, X8, X1
	XVADDH X9, X1, X1
	XVSRAH $5, X1, X1
	XVANDV X10, X1, X1        // X1.half[0..15] = c0..c15

	// Extract all 4 quadwords (each holds 4 × uint16 coefs)
	XVMOVQ X1.V[0], R10      // R10 = c0|(c1<<16)|(c2<<32)|(c3<<48)
	XVMOVQ X1.V[1], R11      // R11 = c4|(c5<<16)|(c6<<32)|(c7<<48)
	XVMOVQ X1.V[2], R12      // R12 = c8|(c9<<16)|(c10<<32)|(c11<<48)
	XVMOVQ X1.V[3], R13      // R13 = c12|(c13<<16)|(c14<<32)|(c15<<48)

	// Pack c0..c7 (from R10, R11) → 5 bytes at 0(R4)
	// Target R20: c0[4:0]|c1[9:5]|c2[14:10]|c3[19:15]|c4[24:20]|c5[29:25]|c6[34:30]|c7[39:35]
	BSTRPICKV $4,  R10, $0,  R20  // c0
	BSTRPICKV $20, R10, $16, R14; BSTRINSV $9,  R14, $5,  R20  // c1
	BSTRPICKV $36, R10, $32, R14; BSTRINSV $14, R14, $10, R20  // c2
	BSTRPICKV $52, R10, $48, R14; BSTRINSV $19, R14, $15, R20  // c3
	BSTRPICKV $4,  R11, $0,  R14; BSTRINSV $24, R14, $20, R20  // c4
	BSTRPICKV $20, R11, $16, R14; BSTRINSV $29, R14, $25, R20  // c5
	BSTRPICKV $36, R11, $32, R14; BSTRINSV $34, R14, $30, R20  // c6
	BSTRPICKV $52, R11, $48, R14; BSTRINSV $39, R14, $35, R20  // c7
	MOVW  R20, 0(R4)
	SRLV  $32, R20, R14; MOVBU R14, 4(R4)

	// Pack c8..c15 (from R12, R13) → 5 bytes at 5(R4)
	BSTRPICKV $4,  R12, $0,  R20  // c8
	BSTRPICKV $20, R12, $16, R14; BSTRINSV $9,  R14, $5,  R20  // c9
	BSTRPICKV $36, R12, $32, R14; BSTRINSV $14, R14, $10, R20  // c10
	BSTRPICKV $52, R12, $48, R14; BSTRINSV $19, R14, $15, R20  // c11
	BSTRPICKV $4,  R13, $0,  R14; BSTRINSV $24, R14, $20, R20  // c12
	BSTRPICKV $20, R13, $16, R14; BSTRINSV $29, R14, $25, R20  // c13
	BSTRPICKV $36, R13, $32, R14; BSTRINSV $34, R14, $30, R20  // c14
	BSTRPICKV $52, R13, $48, R14; BSTRINSV $39, R14, $35, R20  // c15
	MOVW  R20, 5(R4)
	SRLV  $32, R20, R14; MOVBU R14, 9(R4)

	ADDV $32, R5              // 16 int16 = 32 bytes
	ADDV $10, R4              // 16 × 5-bit = 10 bytes
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
// Algorithm: 16 iterations × 10 bytes → 16 coefficients (32 bytes).
// Each iteration:
//   1. Scalar: load 10 bytes (80 bits), extract 16 × 5-bit values via BSTRPICKV, pack 8 per GPR
//   2. Write 2 GPRs to output buffer, reload as LASX 256-bit (16 halfwords)
//   3. LASX decompress all 16 at once (full 256-bit): XVMULWEVWHU×q + XVMULWODWHU×q + XVADDW(16) + XVSRLW(5) + reorder
//   4. XVPICKEV_H + XVMOVQ to store 32 bytes
//
// Register allocation:
//   R4=b, R5=f, R6=loop counter
//   R10=bytes 0..7, R11=bytes 8..9 (for c8..c15)
//   R20=packed c0..c7, R21=packed c8..c15, R14=temp for BSTRPICKV/BSTRINSV
//   X8=broadcast(q=3329, H16), X9=broadcast(16, W8)
//   X0,X1,X2,X12 = temporaries for decompress
TEXT ·ringDecodeAndDecompress5LASX(SB), NOSPLIT, $0-16
	MOVV b+0(FP), R4
	MOVV f+8(FP), R5

	// Setup LASX constants
	MOVV $3329, R7
	XVMOVQ R7, X8.H16           // X8 = broadcast(3329) to 16 halfwords
	MOVV $16, R7
	XVMOVQ R7, X9.W8            // X9 = broadcast(16) to 8 words

	MOVV $16, R6                // 16 iterations × 16 coefs = 256

decompress5_loop:
	// Load 10 bytes (80 bits = 16 × 5-bit values)
	MOVV  (R4), R10             // bytes 0..7
	MOVHU 8(R4), R11            // bytes 8..9

	// Extract c0..c7 from R10 using BSTRPICKV
	BSTRPICKV $4,  R10, $0,  R20  // c0
	BSTRPICKV $9,  R10, $5,  R14; BSTRINSV $20, R14, $16, R20  // c1
	BSTRPICKV $14, R10, $10, R14; BSTRINSV $36, R14, $32, R20  // c2
	BSTRPICKV $19, R10, $15, R14; BSTRINSV $52, R14, $48, R20  // c3

	// c4..c7 also from R10 (bits 20..39)
	BSTRPICKV $24, R10, $20, R21  // c4
	BSTRPICKV $29, R10, $25, R14; BSTRINSV $20, R14, $16, R21  // c5
	BSTRPICKV $34, R10, $30, R14; BSTRINSV $36, R14, $32, R21  // c6
	BSTRPICKV $39, R10, $35, R14; BSTRINSV $52, R14, $48, R21  // c7

	// c8..c11 from R10 (bits 40..63)
	BSTRPICKV $44, R10, $40, R23  // c8
	BSTRPICKV $49, R10, $45, R14; BSTRINSV $20, R14, $16, R23  // c9
	BSTRPICKV $54, R10, $50, R14; BSTRINSV $36, R14, $32, R23  // c10
	BSTRPICKV $59, R10, $55, R14; BSTRINSV $52, R14, $48, R23  // c11

	// c12..c15: c12 crosses byte 7/8 boundary (R10[63:60] + R11[0])
	BSTRPICKV $63, R10, $60, R25; BSTRPICKV $0, R11, $0, R14; SLLV $4, R14, R14; OR R14, R25  // c12
	BSTRPICKV $5, R11, $1, R14; BSTRINSV $20, R14, $16, R25   // c13
	BSTRPICKV $10, R11, $6, R14; BSTRINSV $36, R14, $32, R25  // c14
	BSTRPICKV $15, R11, $11, R14; BSTRINSV $52, R14, $48, R25 // c15

	// Write all 4 GPRs to output buffer (32 bytes), reload as LASX
	MOVV R20, 0(R5)
	MOVV R21, 8(R5)
	MOVV R23, 16(R5)
	MOVV R25, 24(R5)
	XVMOVQ (R5), X0             // X0 = [c0..c15] as uint16 halfwords (256-bit)

	// LASX decompress: f = (c * q + 16) >> 5 (32-bit arithmetic)
	XVMULWEVWHU X0, X8, X12     // X12.word[i] = X0.half[2i] × q  (even coefs)
	XVMULWODWHU X0, X8, X0     // X0.word[i]  = X0_orig.half[2i+1] × q  (odd coefs)
	XVADDW X9, X12, X12
	XVADDW X9, X0,  X0
	XVSRLW $5, X12, X12
	XVSRLW $5, X0,  X0

	// Reorder: interleave even/odd results into sequential halfwords
	XVILVLW X12, X0, X1
	XVILVHW X12, X0, X2
	XVPICKEV_H(0, 2, 1)         // X0 = [f0..f15] in 16 halfwords

	// Store 16 int16 values (32 bytes)
	XVMOVQ X0, (R5)

	ADDV $10, R4                // 10 input bytes
	ADDV $32, R5                // 16 int16 = 32 bytes
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
	MOVV  R10, R20; BSTRINSV $19, R12, $10, R20; BSTRINSV $29, R11, $20, R20; BSTRINSV $39, R13, $30, R20
	MOVBU R20, 0(R4); SRLV $8, R20, R20; MOVBU R20, 1(R4); SRLV $8, R20, R20; MOVBU R20, 2(R4); SRLV $8, R20, R20; MOVBU R20, 3(R4); SRLV $8, R20, R20; MOVBU R20, 4(R4)

	// Group 1: c4,c5,c6,c7 → 5 bytes
	XVMOVQ X12.V[1], R10
	XVMOVQ X13.V[1], R11
	XVMOVQ X1.V[1],  R12
	XVMOVQ X2.V[1],  R13
	MOVV  R10, R20; BSTRINSV $19, R12, $10, R20; BSTRINSV $29, R11, $20, R20; BSTRINSV $39, R13, $30, R20
	MOVBU R20, 5(R4); SRLV $8, R20, R20; MOVBU R20, 6(R4); SRLV $8, R20, R20; MOVBU R20, 7(R4); SRLV $8, R20, R20; MOVBU R20, 8(R4); SRLV $8, R20, R20; MOVBU R20, 9(R4)

	// Group 2: c8,c9,c10,c11 → 5 bytes
	XVMOVQ X12.V[2], R10
	XVMOVQ X13.V[2], R11
	XVMOVQ X1.V[2],  R12
	XVMOVQ X2.V[2],  R13
	MOVV  R10, R20; BSTRINSV $19, R12, $10, R20; BSTRINSV $29, R11, $20, R20; BSTRINSV $39, R13, $30, R20
	MOVBU R20, 10(R4); SRLV $8, R20, R20; MOVBU R20, 11(R4); SRLV $8, R20, R20; MOVBU R20, 12(R4); SRLV $8, R20, R20; MOVBU R20, 13(R4); SRLV $8, R20, R20; MOVBU R20, 14(R4)

	// Group 3: c12,c13,c14,c15 → 5 bytes
	XVMOVQ X12.V[3], R10
	XVMOVQ X13.V[3], R11
	XVMOVQ X1.V[3],  R12
	XVMOVQ X2.V[3],  R13
	MOVV  R10, R20; BSTRINSV $19, R12, $10, R20; BSTRINSV $29, R11, $20, R20; BSTRINSV $39, R13, $30, R20
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

	// Pack c0..c7 into 11 bytes using BSTRINSV
	// R24 = c0|c1<<11|c2<<22|c3<<33|c4<<44|c5[8:0]<<55
	MOVV     R10, R24
	BSTRINSV $21, R12, $11, R24         // c1 at [21:11]
	BSTRINSV $32, R11, $22, R24         // c2 at [32:22]
	BSTRINSV $43, R13, $33, R24         // c3 at [43:33]
	BSTRINSV $54, R14, $44, R24         // c4 at [54:44]
	BSTRINSV $63, R16, $55, R24         // c5[8:0] at [63:55]

	// R25 = c5>>9 | c6<<2 | c7<<13
	SRLV     $9, R16, R25
	BSTRINSV $12, R15, $2, R25          // c6 at [12:2]
	BSTRINSV $23, R17, $13, R25         // c7 at [23:13]

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

	// Pack c8..c15 into 11 bytes using BSTRINSV
	MOVV     R10, R24
	BSTRINSV $21, R12, $11, R24
	BSTRINSV $32, R11, $22, R24
	BSTRINSV $43, R13, $33, R24
	BSTRINSV $54, R14, $44, R24
	BSTRINSV $63, R16, $55, R24

	SRLV     $9, R16, R25
	BSTRINSV $12, R15, $2, R25
	BSTRINSV $23, R17, $13, R25

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
// Inner loop: 16 coefs per 20 bytes → 32 bytes output (full 256-bit LASX).
// Decompress_10: f = (y*q >> 10) + ((y*q >> 9) & 1)
//
// Register usage:
//   R4 = src pointer (c), R5 = dst pointer
//   R6 = outer loop counter, R7 = inner loop counter (16 per ring element)
//   R8 = bytes 0..7, R9 = bytes 8..15, R11 = bytes 16..19
//   R20=packed c0..c3, R21=packed c4..c7, R23=packed c8..c11, R25=packed c12..c15
//   R14 = temp for BSTRPICKV/BSTRINSV
//   X8 = broadcast(3329) as uint16, X9 = broadcast(1) as uint32 (rounding mask)
TEXT ·decodeAndDecompressU10LASX(SB), NOSPLIT, $0-48
	MOVV dst_base+0(FP), R5     // dst pointer
	MOVV dst_len+8(FP), R6      // number of ring elements
	MOVV c_base+24(FP), R4      // src pointer

	// Setup LASX constants
	MOVV $3329, R7
	XVMOVQ R7, X8.H16           // X8 = broadcast(3329) as uint16
	MOVV $1, R7
	XVMOVQ R7, X9.W8            // X9 = broadcast(1) as uint32

u10_outer:
	MOVV $16, R7                 // 16 inner iterations per ring element (16 coefs each)

u10_inner:
	// Load 20 bytes (160 bits = 16 × 10-bit values)
	MOVV  (R4), R8               // bytes 0..7  (stream bits [63:0])
	MOVV  8(R4), R9              // bytes 8..15 (stream bits [127:64])
	MOVWU 16(R4), R11            // bytes 16..19 (stream bits [159:128], zero-extended)

	// c0..c3 from R8
	BSTRPICKV $9,  R8, $0,  R20   // c0
	BSTRPICKV $19, R8, $10, R14; BSTRINSV $25, R14, $16, R20  // c1
	BSTRPICKV $29, R8, $20, R14; BSTRINSV $41, R14, $32, R20  // c2
	BSTRPICKV $39, R8, $30, R14; BSTRINSV $57, R14, $48, R20  // c3

	// c4..c5 from R8
	BSTRPICKV $49, R8, $40, R21   // c4
	BSTRPICKV $59, R8, $50, R14; BSTRINSV $25, R14, $16, R21  // c5

	// c6: crosses R8/R9 boundary at stream bit 63/64
	BSTRPICKV $63, R8, $60, R14   // low 4 bits of c6
	BSTRPICKV $5,  R9, $0,  R13   // high 6 bits of c6
	SLLV $4, R13, R13; OR R13, R14  // c6 in R14
	BSTRINSV $41, R14, $32, R21   // c6 at R21[41:32]

	// c7 from R9
	BSTRPICKV $15, R9, $6, R14; BSTRINSV $57, R14, $48, R21   // c7

	// c8..c11 from R9
	BSTRPICKV $25, R9, $16, R23   // c8
	BSTRPICKV $35, R9, $26, R14; BSTRINSV $25, R14, $16, R23  // c9
	BSTRPICKV $45, R9, $36, R14; BSTRINSV $41, R14, $32, R23  // c10
	BSTRPICKV $55, R9, $46, R14; BSTRINSV $57, R14, $48, R23  // c11

	// c12: crosses R9/R11 boundary at stream bit 127/128
	BSTRPICKV $63, R9, $56, R14   // low 8 bits of c12
	BSTRPICKV $1,  R11, $0, R13   // high 2 bits of c12
	SLLV $8, R13, R13; OR R13, R14  // c12 in R14
	MOVV R14, R25                  // c12 at R25[9:0]

	// c13..c15 from R11
	BSTRPICKV $11, R11, $2,  R14; BSTRINSV $25, R14, $16, R25  // c13
	BSTRPICKV $21, R11, $12, R14; BSTRINSV $41, R14, $32, R25  // c14
	BSTRPICKV $31, R11, $22, R14; BSTRINSV $57, R14, $48, R25  // c15

	// Write all 4 GPRs (32 bytes) to dst, reload as LASX 256-bit
	MOVV  R20, 0(R5)
	MOVV  R21, 8(R5)
	MOVV  R23, 16(R5)
	MOVV  R25, 24(R5)
	XVMOVQ (R5), X0              // X0 = [c0..c15] as uint16 halfwords (256-bit)

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
	XVILVLW X12, X0, X1
	XVILVHW X12, X0, X2
	XVPICKEV_H(0, 2, 1)         // X0 = [f0..f15] in 16 halfwords

	// Store 16 int16 = 32 bytes
	XVMOVQ X0, (R5)

	ADDV  $20, R4               // 20 input bytes
	ADDV  $32, R5               // 16 int16 = 32 bytes
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
// Inner loop: 16 coefs per 22 bytes → 32 bytes output (full 256-bit LASX).
// Decompress_11: f = (y*q >> 11) + ((y*q >> 10) & 1)
//
// Register usage:
//   R4 = src pointer (c), R5 = dst pointer
//   R6 = outer loop counter, R7 = inner loop counter (16 per ring element)
//   R8 = bytes 0..7, R9 = bytes 8..15, R12 = bytes 16..21 (6 bytes, 48 bits)
//   R20=packed c0..c3, R21=packed c4..c7, R23=packed c8..c11, R25=packed c12..c15
//   R13, R14 = temp for BSTRPICKV/BSTRINSV
//   X8 = broadcast(3329) as uint16, X9 = broadcast(1) as uint32 (rounding mask)
TEXT ·decodeAndDecompressU11LASX(SB), NOSPLIT, $0-48
	MOVV dst_base+0(FP), R5     // dst pointer
	MOVV dst_len+8(FP), R6      // number of ring elements
	MOVV c_base+24(FP), R4      // src pointer

	// Setup LASX constants
	MOVV $3329, R7
	XVMOVQ R7, X8.H16           // X8 = broadcast(3329) as uint16
	MOVV $1, R7
	XVMOVQ R7, X9.W8            // X9 = broadcast(1) as uint32

u11_outer:
	MOVV $16, R7                 // 16 inner iterations per ring element (16 coefs each)

u11_inner:
	// Load 22 bytes (176 bits = 16 × 11-bit values)
	MOVV  (R4), R8               // bytes 0..7  (stream bits [63:0])
	MOVV  8(R4), R9              // bytes 8..15 (stream bits [127:64])
	MOVWU 16(R4), R12            // bytes 16..19 (stream bits [159:128], zero-extended)
	MOVHU 20(R4), R10; SLLV $32, R10, R10; OR R10, R12  // bytes 20..21 → R12[47:32]

	// c0..c4 from R8
	BSTRPICKV $10, R8, $0,  R20   // c0
	BSTRPICKV $21, R8, $11, R14; BSTRINSV $26, R14, $16, R20  // c1
	BSTRPICKV $32, R8, $22, R14; BSTRINSV $42, R14, $32, R20  // c2
	BSTRPICKV $43, R8, $33, R14; BSTRINSV $58, R14, $48, R20  // c3

	BSTRPICKV $54, R8, $44, R21   // c4

	// c5: 9 bits from R8[63:55] + 2 bits from R9[1:0]
	BSTRPICKV $63, R8, $55, R14   // c5 low 9 bits
	BSTRPICKV $1,  R9, $0,  R13; SLLV $9, R13, R13; OR R13, R14  // c5 high 2 bits
	BSTRINSV $26, R14, $16, R21   // c5

	// c6, c7 from R9
	BSTRPICKV $12, R9, $2,  R14; BSTRINSV $42, R14, $32, R21  // c6
	BSTRPICKV $23, R9, $13, R14; BSTRINSV $58, R14, $48, R21  // c7

	// c8..c10 from R9
	BSTRPICKV $34, R9, $24, R23   // c8
	BSTRPICKV $45, R9, $35, R14; BSTRINSV $26, R14, $16, R23  // c9
	BSTRPICKV $56, R9, $46, R14; BSTRINSV $42, R14, $32, R23  // c10

	// c11: 7 bits from R9[63:57] + 4 bits from R12[3:0]
	BSTRPICKV $63, R9, $57, R14   // c11 low 7 bits
	BSTRPICKV $3,  R12, $0, R13; SLLV $7, R13, R13; OR R13, R14  // c11 high 4 bits
	BSTRINSV $58, R14, $48, R23   // c11

	// c12..c15 from R12
	BSTRPICKV $14, R12, $4,  R25   // c12
	BSTRPICKV $25, R12, $15, R14; BSTRINSV $26, R14, $16, R25  // c13
	BSTRPICKV $36, R12, $26, R14; BSTRINSV $42, R14, $32, R25  // c14
	BSTRPICKV $47, R12, $37, R14; BSTRINSV $58, R14, $48, R25  // c15

	// Write all 4 GPRs (32 bytes) to dst, reload as LASX 256-bit
	MOVV  R20, 0(R5)
	MOVV  R21, 8(R5)
	MOVV  R23, 16(R5)
	MOVV  R25, 24(R5)
	XVMOVQ (R5), X0              // X0 = [c0..c15] as uint16 halfwords (256-bit)

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
	XVILVLW X12, X0, X1
	XVILVHW X12, X0, X2
	XVPICKEV_H(0, 2, 1)         // X0 = [f0..f15] in 16 halfwords

	// Store 16 int16 = 32 bytes
	XVMOVQ X0, (R5)

	ADDV  $22, R4               // 22 input bytes
	ADDV  $32, R5               // 16 int16 = 32 bytes
	ADDV  $-1, R7
	BNE   R7, R0, u11_inner

	ADDV  $-1, R6
	BNE   R6, R0, u11_outer

	RET


// samplePolyCBD2LASX samples a polynomial from CBD with eta=2.
// 4 iterations x 32 input bytes -> 64 int16 coefs per iter.
// Algorithm mirrors samplePolyCBD2AVX2:
//   d = (b&0x55) + ((b>>1)&0x55)         -> 2-bit pair sums [0..2]
//   d = (d&0x33) + 0x33 - ((d>>2)&0x33)  -> nibble sums biased [1..3]
//   t0 = (d & 0x0F) - 0x03               -> even coefs in int8 [-2..2]
//   t1 = (d >> 4) - 0x03                 -> odd coefs in int8 [-2..2]
//   interleave t0/t1 bytes, sign-extend int8 to int16, add q to negatives
// func samplePolyCBD2LASX(dst *ringElement, buf *[128]byte)
TEXT ·samplePolyCBD2LASX(SB), NOSPLIT, $0-16
	MOVV dst+0(FP), R5
	MOVV buf+8(FP), R4

	MOVV $0x5555555555555555, R7
	XVMOVQ R7, X8.V4
	MOVV $0x3333333333333333, R7
	XVMOVQ R7, X9.V4
	MOVV $0x0F0F0F0F0F0F0F0F, R7
	XVMOVQ R7, X10.V4
	MOVV $0x0303030303030303, R7
	XVMOVQ R7, X11.V4
	MOVV $0x0D010D010D010D01, R7
	XVMOVQ R7, X12.V4

	MOVV $4, R6

cbd2_outer:
	XVMOVQ (R4), X0
	ADDV   $32, R4

	// d = (b & 0x55) + ((b>>1) & 0x55)
	XVSRLB $1, X0, X1
	XVANDV X8, X0, X0
	XVANDV X8, X1, X1
	XVADDB X1, X0, X0

	// d = (d & 0x33) + 0x33 - ((d>>2) & 0x33)
	XVSRLB $2, X0, X1
	XVANDV X9, X0, X0
	XVANDV X9, X1, X1
	XVADDB X9, X0, X0
	XVSUBB X1, X0, X0

	// t0 = (d & 0x0F) - 0x03, t1 = (d>>4) - 0x03
	XVSRLB $4, X0, X1
	XVANDV X10, X0, X0
	XVANDV X10, X1, X1
	XVSUBB X11, X0, X0
	XVSUBB X11, X1, X1

	// Interleave t0 (even) and t1 (odd) bytes
	// XVILVLB Xvk=X0(t0->even bytes), Xvj=X1(t1->odd bytes), Xvd=X2
	XVILVLB X0, X1, X2
	XVILVHB X0, X1, X3

	// Sign-extend int8 to int16 and conditional add Q.
	// XVILVLB/XVILVHB operate independently per 128-bit lane:
	//   XVILVLB(X2,X4): lane0→coefs[0..7] at offsets 0..15, lane1→coefs[32..39] at offsets 16..31
	//   XVILVHB(X2,X4): lane0→coefs[8..15], lane1→coefs[40..47]
	// Use VMOVQ to extract each lane separately for correct layout.

	XVSRAB $7, X2, X4
	// lane0 low half → coefs[0..7]
	XVILVLB X2, X4, X5
	XVSRAH  $15, X5, X6
	XVANDV  X6, X12, X6
	XVADDH  X6, X5, X5
	VMOVQ   V5, 0(R5)
	// lane1 of X5 → coefs[32..39]
	XVPERMIQ(5, 5, 0x11)
	VMOVQ   V5, 64(R5)

	// lane0 high half → coefs[8..15]
	XVILVHB X2, X4, X6
	XVSRAH  $15, X6, X7
	XVANDV  X7, X12, X7
	XVADDH  X7, X6, X6
	VMOVQ   V6, 16(R5)
	// lane1 of X6 → coefs[40..47]
	XVPERMIQ(6, 6, 0x11)
	VMOVQ   V6, 80(R5)

	XVSRAB $7, X3, X4
	// lane0 low half → coefs[16..23]
	XVILVLB X3, X4, X5
	XVSRAH  $15, X5, X6
	XVANDV  X6, X12, X6
	XVADDH  X6, X5, X5
	VMOVQ   V5, 32(R5)
	// lane1 of X5 → coefs[48..55]
	XVPERMIQ(5, 5, 0x11)
	VMOVQ   V5, 96(R5)

	// lane0 high half → coefs[24..31]
	XVILVHB X3, X4, X6
	XVSRAH  $15, X6, X7
	XVANDV  X7, X12, X7
	XVADDH  X7, X6, X6
	VMOVQ   V6, 48(R5)
	// lane1 of X6 → coefs[56..63]
	XVPERMIQ(6, 6, 0x11)
	VMOVQ   V6, 112(R5)

	ADDV $128, R5
	ADDV  $-1, R6
	BNE   R6, R0, cbd2_outer

	RET

// samplePolyCBD3LASX samples a polynomial from CBD with eta=3.
// 8 iterations x 24 input bytes -> 32 int16 coefs per iter.
// func samplePolyCBD3LASX(dst *ringElement, buf *[192]byte)
TEXT ·samplePolyCBD3LASX(SB), NOSPLIT, $0-16
	MOVV dst+0(FP), R5
	MOVV buf+8(FP), R4

	MOVV $·cbd3Shuf(SB), R7
	XVMOVQ (R7), X20

	MOVV $0x249249, R7
	MOVV R7, R8
	SLLV $32, R8
	OR   R8, R7
	XVMOVQ R7, X21.V4

	MOVV $0x6DB6DB, R7
	MOVV R7, R8
	SLLV $32, R8
	OR   R8, R7
	XVMOVQ R7, X22.V4

	MOVV $7, R7
	MOVV R7, R8
	SLLV $32, R8
	OR   R8, R7
	XVMOVQ R7, X23.V4

	MOVV $0x70000, R7
	MOVV R7, R8
	SLLV $32, R8
	OR   R8, R7
	XVMOVQ R7, X24.V4

	MOVV $0x0003000300030003, R7
	XVMOVQ R7, X25.V4

	MOVV $0x0D010D010D010D01, R7
	XVMOVQ R7, X26.V4

	MOVV $8, R6

cbd3_outer:
	VMOVQ (R4), V0
	VMOVQ 12(R4), V1
	ADDV  $24, R4

	XVORV X0, X0, X2
	XVPERMIQ(2, 1, 0x02)

	XVSHUF_B(3, 2, 2, 20)

	// Bit-sliced popcount: count 'a' bits (at positions 0,1,2 of each 6-bit group)
	// mask 0x249249 selects bits {0,3,6,9,12,15,18,21} = one 'a' bit per group per shift
	XVSRLW $1, X3, X5
	XVSRLW $2, X3, X6
	XVANDV X21, X3, X4             // X4 = a_bit0 per group
	XVANDV X21, X5, X5             // X5 = a_bit1 per group (shifted right by 1)
	XVANDV X21, X6, X6             // X6 = a_bit2 per group (shifted right by 2)
	XVADDW X5, X4, X4
	XVADDW X6, X4, X4              // X4 = sum_a per group at positions {0,6,12,18}

	// b = sum_a >> 3 (b bits are 3 positions right of a bits in each 6-bit group)
	XVSRLW $3, X4, X5              // X5 = sum_b

	// (a + 3 - b) at 3-bit positions 0,6,12,18 within each uint32
	XVADDW X22, X4, X4             // X4 = sum_a + 0x6DB6DB (bias 3 per group)
	XVSUBW X5, X4, X4              // X4 = (a+3-b) per group

	// Extract deltas from 3-bit groups at bit positions 0,6,12,18
	XVANDV X23, X4, X5
	XVSRLW $6, X4, X6
	XVANDV X23, X6, X6
	XVSRLW $12, X4, X7
	XVANDV X23, X7, X7
	XVSRLW $18, X4, X8
	XVANDV X23, X8, X8

	// Pack pairs: word = {delta1, delta0} and {delta3, delta2}
	XVSLLW $16, X6, X6
	XVADDW X6, X5, X5
	XVSLLW $16, X8, X8
	XVADDW X8, X7, X7

	// Subtract bias 3
	XVSUBH X25, X5, X5
	XVSUBH X25, X7, X7

	// Map negatives: add q if negative
	XVSRAH $15, X5, X9
	XVANDV X9, X26, X9
	XVADDH X9, X5, X5

	XVSRAH $15, X7, X9
	XVANDV X9, X26, X9
	XVADDH X9, X7, X7

	// Interleave words: XVILVLW Xvk=X5({d0,d1}->even), Xvj=X7({d2,d3}->odd)
	XVILVLW X5, X7, X10
	XVILVHW X5, X7, X11

	// Permute to get sequential 256-bit output
	XVORV X10, X10, X14
	XVPERMIQ(14, 11, 0x02)

	XVORV X11, X11, X15
	XVPERMIQ(15, 10, 0x31)

	XVMOVQ X14, (R5)
	XVMOVQ X15, 32(R5)
	ADDV   $64, R5

	ADDV  $-1, R6
	BNE   R6, R0, cbd3_outer

	RET

// rejUniformLoong64 is the scalar rejection sampler for sampleNTT.
// Processes buf in 3-byte groups, extracting two 12-bit candidates per group.
// Accepts values < 3329 into a[j..], returns number accepted.
// Fast path for len(buf)==24 and j <= 240: unrolled, 8 groups = 16 candidates.
//
// func rejUniformLoong64(buf []byte, a *nttElement, j int) int
TEXT ·rejUniformLoong64(SB), NOSPLIT, $0-48
	MOVV buf_base+0(FP), R4    // buf pointer
	MOVV buf_len+8(FP), R5     // buf length
	MOVV a+24(FP), R6          // a pointer
	MOVV j+32(FP), R7          // j (start index)
	MOVV R7, R8                // save start j

	// R9 = &a[j] = R6 + j*2
	SLLV $1, R7, R9
	ADDV R6, R9, R9            // R9 = write pointer

	MOVV $256, R10
	BGE  R7, R10, rejuniform_done

	MOVV $24, R11
	BNE  R5, R11, rejuniform_loop_setup
	MOVV $240, R11
	BLT  R11, R7, rejuniform_loop_setup

	// Fast path: len==24, j <= 240. Unroll 8 groups × 2 candidates = 16.
	MOVV $3329, R25

	// Group 0: offset 0
	MOVWU 0(R4), R20
	MOVV  R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fast0_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fast0_s1:
	SRLV  $12, R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fast1_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fast1_s1:

	// Group 1: offset 3
	MOVWU 3(R4), R20
	MOVV  R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fast2_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fast2_s1:
	SRLV  $12, R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fast3_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fast3_s1:

	// Group 2: offset 6
	MOVWU 6(R4), R20
	MOVV  R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fast4_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fast4_s1:
	SRLV  $12, R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fast5_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fast5_s1:

	// Group 3: offset 9
	MOVWU 9(R4), R20
	MOVV  R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fast6_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fast6_s1:
	SRLV  $12, R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fast7_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fast7_s1:

	// Group 4: offset 12
	MOVWU 12(R4), R20
	MOVV  R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fast8_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fast8_s1:
	SRLV  $12, R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fast9_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fast9_s1:

	// Group 5: offset 15
	MOVWU 15(R4), R20
	MOVV  R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fastA_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fastA_s1:
	SRLV  $12, R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fastB_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fastB_s1:

	// Group 6: offset 18
	MOVWU 18(R4), R20
	MOVV  R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fastC_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fastC_s1:
	SRLV  $12, R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fastD_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fastD_s1:

	// Group 7: offset 21
	MOVWU 21(R4), R20
	MOVV  R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fastE_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fastE_s1:
	SRLV  $12, R20, R21
	AND   $0x0FFF, R21
	BGE   R21, R25, rej_fastF_s1
	MOVH  R21, (R9)
	ADDV  $2, R9
	ADDV  $1, R7
rej_fastF_s1:

	JMP rejuniform_done

rejuniform_loop_setup:
	MOVV $0, R11              // offset in buf
	MOVV $3329, R25

rejuniform_loop:
	BGE  R11, R5, rejuniform_done

	// Load 3 bytes at buf[off..off+2]
	ADDV  R11, R4, R23
	MOVBU 0(R23), R20
	MOVBU 1(R23), R19
	MOVBU 2(R23), R17

	// d1 = (R19<<8 | R20) & 0x0FFF
	SLLV $8, R19, R24
	OR   R20, R24, R24
	AND  $0x0FFF, R24

	BGE  R24, R25, rejuniform_skip_d1
	MOVH R24, (R9)
	ADDV $2, R9
	ADDV $1, R7
	BGE  R7, R10, rejuniform_done

rejuniform_skip_d1:
	// d2 = (buf[1]>>4) | (buf[2]<<4)  [= (LEUint16(buf[1:]) >> 4) & 0x0FFF]
	SRLV $4, R19, R24
	SLLV $4, R17, R20
	OR   R24, R20, R24
	AND  $0x0FFF, R24

	BGE  R24, R25, rejuniform_next
	MOVH R24, (R9)
	ADDV $2, R9
	ADDV $1, R7
	BGE  R7, R10, rejuniform_done

rejuniform_next:
	ADDV $3, R11
	JMP  rejuniform_loop

rejuniform_done:
	SUBV R8, R7, R7
	MOVV R7, ret+40(FP)
	RET

