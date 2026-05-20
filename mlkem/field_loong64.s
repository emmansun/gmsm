// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

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

	// Pairwise horizontal add via swap-and-add (within each 32-bit group):
	// X7 = [a0b0, γa1b1, a2b2, γa3b3, ...] → after swap+add:
	// X7 = [(a0b0+γa1b1)×2, (a2b2+γa3b3)×2, ...] (duplicated even sums)
	XVSHUF4IH $0xB1, X7, X8
	XVADDH X7, X8, X7

	// X6 = [a0b1, a1b0, ...] → after swap+add:
	// X6 = [(a0b1+a1b0)×2, ...] (duplicated odd sums)
	XVSHUF4IH $0xB1, X6, X8
	XVADDH X6, X8, X6

	// Field reduce once (values in [0, 2q))
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
