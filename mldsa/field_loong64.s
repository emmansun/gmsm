// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// ---- ML-DSA LASX field_loong64.s ----
// ML-DSA: q=8380417, int32, 256 coefficients per polynomial.
// LASX: 256-bit vectors, 8 × int32 per vector, 32 vectors per polynomial.
//
// Register conventions:
//   R22 = goroutine pointer — NEVER use as scratch
//   X0-X31: LASX 256-bit vector registers
//   V0-V31: LSX  128-bit vector registers (low half of X0-X31)
//
// Montgomery multiply (signed 5-instruction scheme):
//   qInv  = 58728449  (q^{-1} mod 2^32, signed)
//   Steps: XVMULW a, qInv → lo; XVMUHW lo, q → corr; XVMUHW a, b → hi; hi - corr → result
//   (result ∈ (-q, q), no conditional reduction needed for intermediate values)
//
// Macro: MONTMUL_LASX Xa, Xb, Xout, Xtmp1
//   Computes out = MontMul(a, b) using X regs. Clobbers Xtmp1.
//   Uses X28 for q vector, X29 for qInv vector (set up by caller).

// DATA for q and qInv broadcast constants
// q = 8380417 = 0x007F00E1
// qInv = 58728449 = 0x03800001
DATA mldsaQ<>+0(SB)/8, $0x007F00E1007F00E1
DATA mldsaQ<>+8(SB)/8, $0x007F00E1007F00E1
DATA mldsaQ<>+16(SB)/8, $0x007F00E1007F00E1
DATA mldsaQ<>+24(SB)/8, $0x007F00E1007F00E1
GLOBL mldsaQ<>(SB), RODATA, $32

DATA mldsaQInv<>+0(SB)/8, $0x0380000103800001
DATA mldsaQInv<>+8(SB)/8, $0x0380000103800001
DATA mldsaQInv<>+16(SB)/8, $0x0380000103800001
DATA mldsaQInv<>+24(SB)/8, $0x0380000103800001
GLOBL mldsaQInv<>(SB), RODATA, $32

// ============================================================
// polyAddAssignLASX: dst[i] = fieldAdd(dst[i], src[i]), i=0..255
// func polyAddAssignLASX(dst, src *fieldElement)
// R4 = dst, R5 = src
// fieldAdd(a,b): t = a+b-q; result = t + (q if t<0)
// Since a,b ∈ [0,q), a+b ∈ [0,2q), so one conditional subtract suffices.
// ============================================================
TEXT ·polyAddAssignLASX(SB), NOSPLIT, $0-16
	MOVV dst+0(FP), R4
	MOVV src+8(FP), R5
	MOVV $8380417, R8
	XVMOVQ R8, X31.W8          // X31 = {q,q,q,q,q,q,q,q}
	MOVV $32, R6               // 256/8 = 32 LASX vectors
polyadd_loop:
	XVMOVQ (R4), X0
	XVMOVQ (R5), X1
	XVADDW X0, X1, X0          // x = a + b
	XVSUBW X31, X0, X2         // t = x - q  (XVSUBW A,B,C = C=B-A, so A=X31,B=X0,C=X2 = X0-X31)
	XVSRAW $31, X2, X3         // mask: all-1 if t<0 (i.e. a+b < q)
	XVANDV X31, X3, X3         // q if a+b < q, else 0
	XVADDW X2, X3, X0          // result = (x-q) + (q if x<q) = x if x<q, else x-q
	XVMOVQ X0, (R4)
	ADDV $32, R4
	ADDV $32, R5
	ADDV $-1, R6
	BNE R6, R0, polyadd_loop
	RET

// ============================================================
// polySubAssignLASX: dst[i] = fieldSub(dst[i], src[i]), i=0..255
// func polySubAssignLASX(dst, src *fieldElement)
// R4 = dst, R5 = src
// fieldSub(a,b): x = a-b; result = x + (q if x<0)
// Since a,b ∈ [0,q), a-b ∈ (-(q-1),q), one conditional add suffices.
// ============================================================
TEXT ·polySubAssignLASX(SB), NOSPLIT, $0-16
	MOVV dst+0(FP), R4
	MOVV src+8(FP), R5
	MOVV $8380417, R8
	XVMOVQ R8, X31.W8          // X31 = {q,q,q,q,q,q,q,q}
	MOVV $32, R6               // 256/8
polysub_loop:
	XVMOVQ (R4), X0
	XVMOVQ (R5), X1
	XVSUBW X1, X0, X0          // x = a - b (may be negative)
	XVSRAW $31, X0, X2         // mask: all-1 if x<0
	XVANDV X31, X2, X2         // q if x<0, else 0
	XVADDW X0, X2, X0          // result = x + (q if x<0) ∈ [0, q)
	XVMOVQ X0, (R4)
	ADDV $32, R4
	ADDV $32, R5
	ADDV $-1, R6
	BNE R6, R0, polysub_loop
	RET

// ============================================================
// Stubs — to be implemented in subsequent phases
// ============================================================

// ============================================================
// Signed Montgomery multiply macro (5-instruction scheme)
// MontMul(Xa, Xb) → Xout, clobbers Xtmp
// Xq   = broadcast(q=8380417),  must be set up by caller
// XqInv = broadcast(qInv=58728449), must be set up by caller
//
// Steps:
//   1. prod_lo = Xa * Xb  (low 32)    XVMULW
//   2. t       = prod_lo * qInv (low32) XVMULW
//   3. prod_hi = Xa * Xb  (hi32,signed) XVMUHW
//   4. tq_hi   = t * q    (hi32,signed) XVMUHW
// XVPERMIQ performs xvpermi.q Xd, Xj, imm8.
// Real semantics: pool={Xj.lo, Xj.hi, Xd_old.lo, Xd_old.hi} = {0,1,2,3}
//   dst.qword[0] = pool[imm[1:0]], dst.qword[1] = pool[imm[5:4]]
// Opcode 0x1DFB verified: xvpermi.q X8, X9, 0x02 → WORD $0x77ec0928
#define XVPERMIQ(Xd, Xj, imm8) \
	WORD $((0x1DFB << 18) | ((imm8) << 10) | ((Xj) << 5) | (Xd))

// ============================================================
//   5. Xout    = prod_hi - tq_hi        XVSUBW
//
// Result ∈ (-q, q). Caller decides whether to do conditional reduction.
// ============================================================
#define MONTMUL(Xa, Xb, Xout, Xtmp, XqInv, Xq) \
	XVMULW  Xa, Xb, Xout        \ // Xout = a*b low32
	XVMULW  Xout, XqInv, Xtmp   \ // Xtmp = prod_lo * qInv low32
	XVMUHW  Xa, Xb, Xout        \ // Xout = a*b high32 (signed)
	XVMUHW  Xtmp, Xq, Xtmp      \ // Xtmp = t*q high32 (signed)
	XVSUBW  Xtmp, Xout, Xout      // Xout = prod_hi - tq_hi ∈ (-q,q)  (XVSUBW A,B,C = C=B-A)

// ============================================================
// nttMulLASX: out[i] = MontMul(lhs[i], rhs[i]), no final reduction
// func nttMulLASX(lhs, rhs, out *nttElement)
// R4 = lhs, R5 = rhs, R6 = out
// ============================================================
TEXT ·nttMulLASX(SB), NOSPLIT, $0-24
	MOVV lhs+0(FP), R4
	MOVV rhs+8(FP), R5
	MOVV out+16(FP), R6
	MOVV $8380417, R8
	XVMOVQ R8, X31.W8         // X31 = {q, q, q, q, q, q, q, q}
	MOVV $58728449, R9
	XVMOVQ R9, X30.W8         // X30 = {qInv, ...}
	MOVV $32, R7               // 32 vectors of 8 int32 = 256 elements
nttmul_loop:
	XVMOVQ (R4), X0
	XVMOVQ (R5), X1
	MONTMUL(X0, X1, X2, X3, X30, X31)
	// Conditional final reduction: result ∈ (-q,q), bring to [0,q)
	// add q if negative:
	XVSRAW $31, X2, X3         // mask: all-1 if x<0
	XVANDV X31, X3, X3         // q if x<0
	XVADDW X2, X3, X2          // now x ∈ [0, 2q-1]
	// subtract q if >= q:
	XVSUBW X31, X2, X3         // t = x - q  (X3 = X2 - X31)
	XVSRAW $31, X3, X4         // mask: all-1 if t<0 (x < q)
	XVANDV X31, X4, X4         // q if x < q
	XVADDW X3, X4, X2          // (x-q) + (q if x<q) = x if x<q, else x-q
	XVMOVQ X2, (R6)
	ADDV $32, R4
	ADDV $32, R5
	ADDV $32, R6
	ADDV $-1, R7
	BNE R7, R0, nttmul_loop
	RET

// ============================================================
// nttMulAccLASX: out[i] += MontMul(lhs[i], rhs[i])
// func nttMulAccLASX(lhs, rhs, out *nttElement)
// R4 = lhs, R5 = rhs, R6 = out (accumulator)
// ============================================================
TEXT ·nttMulAccLASX(SB), NOSPLIT, $0-24
	MOVV lhs+0(FP), R4
	MOVV rhs+8(FP), R5
	MOVV out+16(FP), R6
	MOVV $8380417, R8
	XVMOVQ R8, X31.W8
	MOVV $58728449, R9
	XVMOVQ R9, X30.W8
	MOVV $32, R7
nttmulacc_loop:
	XVMOVQ (R4), X0
	XVMOVQ (R5), X1
	MONTMUL(X0, X1, X2, X3, X30, X31)
	// Reduce product to [0, q) before accumulation
	XVSRAW $31, X2, X3
	XVANDV X31, X3, X3
	XVADDW X2, X3, X2          // now in [0, 2q-1]
	XVSUBW X31, X2, X3         // t = x - q  (X3 = X2 - X31)
	XVSRAW $31, X3, X4
	XVANDV X31, X4, X4
	XVADDW X3, X4, X2          // now in [0, q)
	// Accumulate: acc += product; reduce acc mod q
	XVMOVQ (R6), X5
	XVADDW X5, X2, X5          // acc + product ∈ [0, 2q-1]
	XVSUBW X31, X5, X3         // t = acc - q  (X3 = X5 - X31)
	XVSRAW $31, X3, X4
	XVANDV X31, X4, X4
	XVADDW X3, X4, X5          // final ∈ [0, q)
	XVMOVQ X5, (R6)
	ADDV $32, R4
	ADDV $32, R5
	ADDV $32, R6
	ADDV $-1, R7
	BNE R7, R0, nttmulacc_loop
	RET

// ============================================================
// nttMatRowVecMulLASX: dst = sum_{i=0}^{length-1} MontMul(vec[i], matRow[i])
// func nttMatRowVecMulLASX(dst, vec, matRow *nttElement, length int)
// R4 = dst, R5 = vec, R6 = matRow, R7 = length
//
// Strategy: outer loop over 32 chunks (32 bytes = 8 int32 each),
// inner loop over length polynomials, accumulate in register.
// ============================================================
TEXT ·nttMatRowVecMulLASX(SB), NOSPLIT, $0-32
	MOVV dst+0(FP), R4
	MOVV vec+8(FP), R5
	MOVV matRow+16(FP), R6
	MOVV length+24(FP), R7
	MOVV $8380417, R8
	XVMOVQ R8, X31.W8          // X31 = q
	MOVV $58728449, R9
	XVMOVQ R9, X30.W8          // X30 = qInv
	MOVV $32, R10               // 32 chunks of 8 int32
	MOVV $0, R11                // chunk_offset = 0
nttmvm_chunk_loop:
	// Load first element product into accumulator X5
	MOVV R5, R12; ADDV R11, R12 // vec_chunk_ptr
	MOVV R6, R13; ADDV R11, R13 // mat_chunk_ptr
	XVMOVQ (R12), X0
	XVMOVQ (R13), X1
	MONTMUL(X0, X1, X5, X3, X30, X31)
	// Reduce accumulator to [0, q)
	XVSRAW $31, X5, X3
	XVANDV X31, X3, X3
	XVADDW X5, X3, X5
	XVSUBW X31, X5, X3         // t = X5 - X31 = x - q
	XVSRAW $31, X3, X4
	XVANDV X31, X4, X4
	XVADDW X3, X4, X5          // X5 = reduced product ∈ [0, q)
	MOVV R7, R14; ADDV $-1, R14 // remaining = length - 1
	BEQ R14, R0, nttmvm_write   // if length==1, skip accumulate
nttmvm_acc_loop:
	// Advance to next polynomial (1024 bytes per poly = 256*4)
	ADDV $1024, R12
	ADDV $1024, R13
	XVMOVQ (R12), X0
	XVMOVQ (R13), X1
	MONTMUL(X0, X1, X2, X3, X30, X31)
	// Reduce product
	XVSRAW $31, X2, X3
	XVANDV X31, X3, X3
	XVADDW X2, X3, X2
	XVSUBW X31, X2, X3         // t = x - q  (X3 = X2 - X31)
	XVSRAW $31, X3, X4
	XVANDV X31, X4, X4
	XVADDW X3, X4, X2          // X2 ∈ [0, q)
	// Accumulate and reduce
	XVADDW X5, X2, X5
	XVSUBW X31, X5, X3         // t = acc - q  (X3 = X5 - X31)
	XVSRAW $31, X3, X4
	XVANDV X31, X4, X4
	XVADDW X3, X4, X5          // X5 ∈ [0, q)
	ADDV $-1, R14
	BNE R14, R0, nttmvm_acc_loop
nttmvm_write:
	// Write accumulated chunk to dst
	MOVV R4, R12; ADDV R11, R12
	XVMOVQ X5, (R12)
	ADDV $32, R11               // next chunk (8 int32 * 4 bytes)
	ADDV $-1, R10
	BNE R10, R0, nttmvm_chunk_loop
	RET

// ============================================================
// NTT / INTT helper macros
// ============================================================

// NTT_BUTTERFLY: Cooley-Tukey butterfly using LASX (8 x int32).
// Input:  XA = even half, XB = odd half, XZ = broadcast zeta
// Output: XA = fieldAdd(XA, t), XB = fieldSub(XA_orig, t)  where t = MontMul(XZ, XB)
// Clobbers: X2, X3, X4
// Prerequisites: X30 = qInv (broadcast), X31 = q (broadcast)
#define NTT_BUTTERFLY(XA, XB, XZ) \
	MONTMUL(XZ, XB, X2, X3, X30, X31)                                           \ // X2 = t in (-q,q)
	XVSRAW $31, X2, X3; XVANDV X31, X3, X3; XVADDW X2, X3, X2                  \ // t -> [0, 2q-1]
	XVSUBW X31, X2, X3; XVSRAW $31, X3, X4; XVANDV X31, X4, X4; XVADDW X3, X4, X2 \ // t -> [0, q)
	XVSUBW X2, XA, XB; XVSRAW $31, XB, X3; XVANDV X31, X3, X3; XVADDW XB, X3, XB  \ // XB = XA - t (mod q)
	XVADDW XA, X2, XA; XVSUBW X31, XA, X3; XVSRAW $31, X3, X4; XVANDV X31, X4, X4; XVADDW X3, X4, XA  // XA = XA + t (mod q)

// INTT_BUTTERFLY: Gentleman-Sande butterfly using LASX (8 x int32).
// Input:  XA = even half, XB = odd half, XZ = broadcast (q - zeta)
// Output: XA = fieldAdd(XA, XB), XB = MontMul(q-zeta, XA_orig - XB)
//   (note: XA_orig - XB + q is passed to MontMul to stay non-negative)
// Clobbers: X2, X3, X4
// Prerequisites: X30 = qInv (broadcast), X31 = q (broadcast)
#define INTT_BUTTERFLY(XA, XB, XZ) \
	XVSUBW XB, XA, X2; XVSRAW $31, X2, X3; XVANDV X31, X3, X3; XVADDW X2, X3, X2 \ // diff = XA - XB (mod q) -> [0, q)
	XVADDW XA, XB, XA; XVSUBW X31, XA, X3; XVSRAW $31, X3, X4; XVANDV X31, X4, X4; XVADDW X3, X4, XA \ // XA = XA + XB (mod q)
	MONTMUL(XZ, X2, XB, X3, X30, X31)                                               \ // XB = MontMul(qmz, diff) in (-q,q)
	XVSRAW $31, XB, X3; XVANDV X31, X3, X3; XVADDW XB, X3, XB                      \ // XB -> [0, 2q-1]
	XVSUBW X31, XB, X3; XVSRAW $31, X3, X4; XVANDV X31, X4, X4; XVADDW X3, X4, XB  // XB -> [0, q)

TEXT ·internalNTTLASX(SB), NOSPLIT, $0-8
	MOVV f+0(FP), R4
	MOVV $·zetasMontgomery(SB), R5
	ADDV $4, R5             // point to zetasMontgomery[1]
	MOVV $8380417, R8
	XVMOVQ R8, X31.W8      // X31 = q broadcast
	MOVV $58728449, R9
	XVMOVQ R9, X30.W8      // X30 = qInv broadcast

	// L0: len=128, 1 group, 16 LASX butterfly pairs (inner unrolled ×2).
	MOVWU (R5), R10; ADDV $4, R5
	XVMOVQ R10, X29.W8
	MOVV R4, R11; MOVV R4, R12; ADDV $512, R12   // f+0, f+128*4
	MOVV $8, R6
ntt_l0_loop:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	XVMOVQ 32(R11), X6; XVMOVQ 32(R12), X7
	NTT_BUTTERFLY(X0, X1, X29)
	NTT_BUTTERFLY(X6, X7, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	XVMOVQ X6, 32(R11); XVMOVQ X7, 32(R12)
	ADDV $64, R11; ADDV $64, R12
	ADDV $-1, R6; BNE R6, R0, ntt_l0_loop

	// L1: len=64, 2 groups, 8 LASX butterfly pairs each (inner unrolled ×2).
	MOVV $2, R6; MOVV R4, R7
ntt_l1_outer:
	MOVWU (R5), R10; ADDV $4, R5; XVMOVQ R10, X29.W8
	MOVV R7, R11; MOVV R7, R12; ADDV $256, R12   // 64*4
	MOVV $4, R13
ntt_l1_inner:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	XVMOVQ 32(R11), X6; XVMOVQ 32(R12), X7
	NTT_BUTTERFLY(X0, X1, X29)
	NTT_BUTTERFLY(X6, X7, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	XVMOVQ X6, 32(R11); XVMOVQ X7, 32(R12)
	ADDV $64, R11; ADDV $64, R12
	ADDV $-1, R13; BNE R13, R0, ntt_l1_inner
	ADDV $512, R7; ADDV $-1, R6; BNE R6, R0, ntt_l1_outer

	// L2: len=32, 4 groups, 4 LASX butterfly pairs each (inner unrolled ×2).
	MOVV $4, R6; MOVV R4, R7
ntt_l2_outer:
	MOVWU (R5), R10; ADDV $4, R5; XVMOVQ R10, X29.W8
	MOVV R7, R11; MOVV R7, R12; ADDV $128, R12   // 32*4
	MOVV $2, R13
ntt_l2_inner:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	XVMOVQ 32(R11), X6; XVMOVQ 32(R12), X7
	NTT_BUTTERFLY(X0, X1, X29)
	NTT_BUTTERFLY(X6, X7, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	XVMOVQ X6, 32(R11); XVMOVQ X7, 32(R12)
	ADDV $64, R11; ADDV $64, R12
	ADDV $-1, R13; BNE R13, R0, ntt_l2_inner
	ADDV $256, R7; ADDV $-1, R6; BNE R6, R0, ntt_l2_outer

	// L3: len=16, 8 groups, 2 LASX butterfly pairs each (16 elements = 64 bytes = 2 vectors).
	MOVV $8, R6; MOVV R4, R7
ntt_l3_outer:
	MOVWU (R5), R10; ADDV $4, R5; XVMOVQ R10, X29.W8
	MOVV R7, R11; MOVV R7, R12; ADDV $64, R12    // 16*4
	MOVV $2, R13
ntt_l3_inner:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	NTT_BUTTERFLY(X0, X1, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	ADDV $32, R11; ADDV $32, R12
	ADDV $-1, R13; BNE R13, R0, ntt_l3_inner
	ADDV $128, R7; ADDV $-1, R6; BNE R6, R0, ntt_l3_outer

	// L4: len=8, 16 groups, 1 LASX butterfly pair each (8 elements = 32 bytes = 1 vector).
	MOVV $16, R6; MOVV R4, R7
ntt_l4_outer:
	MOVWU (R5), R10; ADDV $4, R5; XVMOVQ R10, X29.W8
	MOVV R7, R11; MOVV R7, R12; ADDV $32, R12    // 8*4
	MOVV $1, R13
ntt_l4_inner:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	NTT_BUTTERFLY(X0, X1, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	ADDV $32, R11; ADDV $32, R12
	ADDV $-1, R13; BNE R13, R0, ntt_l4_inner
	ADDV $64, R7; ADDV $-1, R6; BNE R6, R0, ntt_l4_outer

	// L5: len=4, 32 groups (LASX, 1 group per vector via XVPERMIQ lane split).
	// Each group = 8 int32: even=[0..3] in low 128-bit lane, odd=[4..7] in high 128-bit lane.
	MOVV $32, R6; MOVV R4, R7
ntt_l5_outer:
	MOVWU (R5), R10; ADDV $4, R5
	XVMOVQ R10, X29.W8
	XVMOVQ (R7), X9
	XVORV X9, X9, X0
	XVPERMIQ(0, 9, 0x00)      // X0 = {X9.lo, X9.lo} = even duplicated
	XVORV X9, X9, X1
	XVPERMIQ(1, 9, 0x11)      // X1 = {X9.hi, X9.hi} = odd duplicated
	NTT_BUTTERFLY(X0, X1, X29)
	XVORV X0, X0, X9
	XVPERMIQ(9, 1, 0x02)      // X9 = {X0.lo, X1.lo} = [even' | odd']
	XVMOVQ X9, (R7)
	ADDV $32, R7; ADDV $-1, R6; BNE R6, R0, ntt_l5_outer

	// L6: len=2, 64 groups (LASX, 4 groups per 2 vectors via XVILVLV/XVILVHV).
	// Memory layout: [e0,e1,o0,o1 | e2,e3,o2,o3] per LASX vector (2 groups).
	// Process 4 groups (2 vectors) per iteration using precomputed twiddle.
	MOVV $·nttZetasL2PrecompLASX(SB), R10
	MOVV R4, R11; MOVV $16, R6
ntt_l6_loop:
	XVMOVQ (R10), X5            // load twiddle: [z2,z2,z0,z0 | z3,z3,z1,z1]
	XVMOVQ (R11), X9            // load groups 0,1
	XVMOVQ 32(R11), X12         // load groups 2,3
	XVILVLV X12, X9, X0         // even: [e4,e5,e0,e1 | e6,e7,e2,e3]
	XVILVHV X12, X9, X1         // odd:  [o4,o5,o0,o1 | o6,o7,o2,o3]
	NTT_BUTTERFLY(X0, X1, X5)
	XVILVHV X0, X1, X9          // recombine groups 0,1
	XVILVLV X0, X1, X12         // recombine groups 2,3
	XVMOVQ X9, (R11)
	XVMOVQ X12, 32(R11)
	ADDV $32, R10
	ADDV $64, R11
	ADDV $-1, R6; BNE R6, R0, ntt_l6_loop

	// L7: len=1, 128 groups (LASX, 8 groups per 2 vectors via XVSHUF4IW+XVILVLV/XVILVHV).
	// Memory layout: [e0,o0,e1,o1 | e2,o2,e3,o3] per LASX vector (4 groups).
	// Process 8 groups (2 vectors) per iteration using precomputed twiddle.
	MOVV $·nttZetasL1PrecompLASX(SB), R10
	MOVV R4, R11; MOVV $16, R6
ntt_l7_loop:
	XVMOVQ (R10), X5            // load twiddle: [z4,z5,z0,z1 | z6,z7,z2,z3]
	XVMOVQ (R11), X9            // load groups 0..3: [e0,o0,e1,o1 | e2,o2,e3,o3]
	XVMOVQ 32(R11), X12         // load groups 4..7: [e4,o4,e5,o5 | e6,o6,e7,o7]
	XVSHUF4IW $0xD8, X9, X11   // X11 = [e0,e1,o0,o1 | e2,e3,o2,o3]
	XVSHUF4IW $0xD8, X12, X10  // X10 = [e4,e5,o4,o5 | e6,e7,o6,o7]
	XVILVLV X10, X11, X0        // even: [e4,e5,e0,e1 | e6,e7,e2,e3]
	XVILVHV X10, X11, X1        // odd:  [o4,o5,o0,o1 | o6,o7,o2,o3]
	NTT_BUTTERFLY(X0, X1, X5)
	XVILVHV X0, X1, X11         // X11 = [e0',e1',o0',o1' | e2',e3',o2',o3']
	XVILVLV X0, X1, X10         // X10 = [e4',e5',o4',o5' | e6',e7',o6',o7']
	XVSHUF4IW $0xD8, X11, X9   // X9 = [e0',o0',e1',o1' | e2',o2',e3',o3']
	XVSHUF4IW $0xD8, X10, X12  // X12 = [e4',o4',e5',o5' | e6',o6',e7',o7']
	XVMOVQ X9, (R11)
	XVMOVQ X12, 32(R11)
	ADDV $32, R10
	ADDV $64, R11
	ADDV $-1, R6; BNE R6, R0, ntt_l7_loop
	RET

TEXT ·internalInverseNTTLASX(SB), NOSPLIT, $0-8
	MOVV f+0(FP), R4
	MOVV $8380417, R8
	XVMOVQ R8, X31.W8      // X31 = q broadcast
	MOVV $58728449, R9
	XVMOVQ R9, X30.W8      // X30 = qInv broadcast

	// INTT ordering (same as generic code, len ascending):
	// L0: len=1, 128 groups; L1: len=2, 64 groups; L2: len=4, 32 groups (LASX via precomp+XVPERMIQ)
	// L3: len=8, 16 groups; ... L7: len=128, 1 group (LASX via R5 zeta pointer)
	// Reset pointer to zetasMontgomery[255]:
	MOVV $·zetasMontgomery(SB), R5
	ADDV $1020, R5          // zetasMontgomery[255]

	// L0: len=1, 128 groups (LASX, 8 groups per 2 vectors via XVSHUF4IW+XVILVLV/XVILVHV).
	// Memory layout: [e0,o0,e1,o1 | e2,o2,e3,o3] per LASX vector (4 groups).
	// Process 8 groups (2 vectors) per iteration using precomputed qmz twiddle.
	MOVV $·inttQMinusZetasL1PrecompLASX(SB), R10
	MOVV R4, R11; MOVV $16, R6
intt_l0_loop:
	XVMOVQ (R10), X5            // load twiddle: [qmz4,qmz5,qmz0,qmz1 | qmz6,qmz7,qmz2,qmz3]
	XVMOVQ (R11), X9            // groups 0..3
	XVMOVQ 32(R11), X12         // groups 4..7
	XVSHUF4IW $0xD8, X9, X11   // X11 = [e0,e1,o0,o1 | e2,e3,o2,o3]
	XVSHUF4IW $0xD8, X12, X10  // X10 = [e4,e5,o4,o5 | e6,e7,o6,o7]
	XVILVLV X10, X11, X0        // even: [e4,e5,e0,e1 | e6,e7,e2,e3]
	XVILVHV X10, X11, X1        // odd:  [o4,o5,o0,o1 | o6,o7,o2,o3]
	INTT_BUTTERFLY(X0, X1, X5)
	XVILVHV X0, X1, X11         // X11 = [e0',e1',o0',o1' | e2',e3',o2',o3']
	XVILVLV X0, X1, X10         // X10 = [e4',e5',o4',o5' | e6',e7',o6',o7']
	XVSHUF4IW $0xD8, X11, X9   // X9 = [e0',o0',e1',o1' | e2',o2',e3',o3']
	XVSHUF4IW $0xD8, X10, X12  // X12 = [e4',o4',e5',o5' | e6',o6',e7',o7']
	XVMOVQ X9, (R11)
	XVMOVQ X12, 32(R11)
	ADDV $32, R10
	ADDV $64, R11
	ADDV $-1, R6; BNE R6, R0, intt_l0_loop

	// L1: len=2, 64 groups (LASX, 4 groups per 2 vectors via XVILVLV/XVILVHV).
	// Memory layout: [e0,e1,o0,o1 | e2,e3,o2,o3] per LASX vector (2 groups).
	// Process 4 groups (2 vectors) per iteration using precomputed qmz twiddle.
	MOVV $·inttQMinusZetasL2PrecompLASX(SB), R10
	MOVV R4, R11; MOVV $16, R6
intt_l1_loop:
	XVMOVQ (R10), X5            // load twiddle: [qmz2,qmz2,qmz0,qmz0 | qmz3,qmz3,qmz1,qmz1]
	XVMOVQ (R11), X9            // groups 0,1
	XVMOVQ 32(R11), X12         // groups 2,3
	XVILVLV X12, X9, X0         // even: [e4,e5,e0,e1 | e6,e7,e2,e3]
	XVILVHV X12, X9, X1         // odd:  [o4,o5,o0,o1 | o6,o7,o2,o3]
	INTT_BUTTERFLY(X0, X1, X5)
	XVILVHV X0, X1, X9          // recombine groups 0,1
	XVILVLV X0, X1, X12         // recombine groups 2,3
	XVMOVQ X9, (R11)
	XVMOVQ X12, 32(R11)
	ADDV $32, R10
	ADDV $64, R11
	ADDV $-1, R6; BNE R6, R0, intt_l1_loop

	// L2: len=4, 32 groups (LASX, 1 group per vector via XVPERMIQ lane split).
	// Each group = 8 int32: even=[0..3] in low 128-bit lane, odd=[4..7] in high 128-bit lane.
	// Zetas k=63..32; set R5 to zetasMontgomery[63].
	MOVV $·zetasMontgomery(SB), R5
	ADDV $252, R5           // zetasMontgomery[63]
	MOVV $32, R6; MOVV R4, R7
intt_l2_outer:
	MOVWU (R5), R10; ADDV $-4, R5
	SUBV R10, R8, R10              // qmz = q - zeta (R8 = q)
	XVMOVQ R10, X29.W8
	XVMOVQ (R7), X9
	XVORV X9, X9, X0
	XVPERMIQ(0, 9, 0x00)           // X0 = {X9.lo, X9.lo} = even duplicated
	XVORV X9, X9, X1
	XVPERMIQ(1, 9, 0x11)           // X1 = {X9.hi, X9.hi} = odd duplicated
	INTT_BUTTERFLY(X0, X1, X29)
	XVORV X0, X0, X9
	XVPERMIQ(9, 1, 0x02)           // X9 = {X0.lo, X1.lo} = [even' | odd']
	XVMOVQ X9, (R7)
	ADDV $32, R7; ADDV $-1, R6; BNE R6, R0, intt_l2_outer

	// L3-L7: LASX vector loops. k=31..1.
	// L3: len=8, 16 groups, 1 LASX butterfly pair each (8 elements = 32 bytes = 1 vector). k=31..16.
	MOVV $16, R6; MOVV R4, R7
intt_l3_outer:
	MOVWU (R5), R10; ADDV $-4, R5
	SUBV R10, R8, R10              // qmz = q - zeta (R8 = q = 8380417)
	XVMOVQ R10, X29.W8
	MOVV R7, R11; MOVV R7, R12; ADDV $32, R12    // 8*4
	MOVV $1, R13
intt_l3_inner:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	INTT_BUTTERFLY(X0, X1, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	ADDV $32, R11; ADDV $32, R12
	ADDV $-1, R13; BNE R13, R0, intt_l3_inner
	ADDV $64, R7; ADDV $-1, R6; BNE R6, R0, intt_l3_outer

	// L4: len=16, 8 groups, 2 LASX butterfly pairs each (16 elements = 64 bytes = 2 vectors). k=15..8.
	MOVV $8, R6; MOVV R4, R7
intt_l4_outer:
	MOVWU (R5), R10; ADDV $-4, R5
	SUBV R10, R8, R10
	XVMOVQ R10, X29.W8
	MOVV R7, R11; MOVV R7, R12; ADDV $64, R12    // 16*4
	MOVV $2, R13
intt_l4_inner:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	INTT_BUTTERFLY(X0, X1, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	ADDV $32, R11; ADDV $32, R12
	ADDV $-1, R13; BNE R13, R0, intt_l4_inner
	ADDV $128, R7; ADDV $-1, R6; BNE R6, R0, intt_l4_outer

	// L5: len=32, 4 groups, 4 LASX butterfly pairs each (inner unrolled ×2). k=7..4.
	MOVV $4, R6; MOVV R4, R7
intt_l5_outer:
	MOVWU (R5), R10; ADDV $-4, R5
	SUBV R10, R8, R10
	XVMOVQ R10, X29.W8
	MOVV R7, R11; MOVV R7, R12; ADDV $128, R12   // 32*4
	MOVV $2, R13
intt_l5_inner:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	XVMOVQ 32(R11), X6; XVMOVQ 32(R12), X7
	INTT_BUTTERFLY(X0, X1, X29)
	INTT_BUTTERFLY(X6, X7, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	XVMOVQ X6, 32(R11); XVMOVQ X7, 32(R12)
	ADDV $64, R11; ADDV $64, R12
	ADDV $-1, R13; BNE R13, R0, intt_l5_inner
	ADDV $256, R7; ADDV $-1, R6; BNE R6, R0, intt_l5_outer

	// L6: len=64, 2 groups, 8 LASX butterfly pairs each (inner unrolled ×2). k=3..2.
	MOVV $2, R6; MOVV R4, R7
intt_l6_outer:
	MOVWU (R5), R10; ADDV $-4, R5
	SUBV R10, R8, R10
	XVMOVQ R10, X29.W8
	MOVV R7, R11; MOVV R7, R12; ADDV $256, R12   // 64*4
	MOVV $4, R13
intt_l6_inner:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	XVMOVQ 32(R11), X6; XVMOVQ 32(R12), X7
	INTT_BUTTERFLY(X0, X1, X29)
	INTT_BUTTERFLY(X6, X7, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	XVMOVQ X6, 32(R11); XVMOVQ X7, 32(R12)
	ADDV $64, R11; ADDV $64, R12
	ADDV $-1, R13; BNE R13, R0, intt_l6_inner
	ADDV $512, R7; ADDV $-1, R6; BNE R6, R0, intt_l6_outer

	// L7: len=128, 1 group, 16 LASX butterfly pairs (inner unrolled ×2). k=1.
	MOVWU (R5), R10; ADDV $-4, R5
	SUBV R10, R8, R10
	XVMOVQ R10, X29.W8
	MOVV R4, R11; MOVV R4, R12; ADDV $512, R12   // 128*4
	MOVV $8, R6
intt_l7_loop:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	XVMOVQ 32(R11), X6; XVMOVQ 32(R12), X7
	INTT_BUTTERFLY(X0, X1, X29)
	INTT_BUTTERFLY(X6, X7, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	XVMOVQ X6, 32(R11); XVMOVQ X7, 32(R12)
	ADDV $64, R11; ADDV $64, R12
	ADDV $-1, R6; BNE R6, R0, intt_l7_loop

	// Multiply all 256 elements by invDegreeMont = 41978 (unrolled ×2)
	// 41978 = ((256⁻¹ mod q) * (2³² * 2³² mod q)) mod q
	MOVV $41978, R10
	XVMOVQ R10, X29.W8
	MOVV R4, R11; MOVV $16, R6
intt_scale_loop:
	XVMOVQ (R11), X0
	XVMOVQ 32(R11), X6
	MONTMUL(X29, X0, X1, X2, X30, X31)
	MONTMUL(X29, X6, X8, X2, X30, X31)
	XVSRAW $31, X1, X2; XVANDV X31, X2, X2; XVADDW X1, X2, X1
	XVSUBW X31, X1, X2; XVSRAW $31, X2, X3; XVANDV X31, X3, X3; XVADDW X2, X3, X1
	XVSRAW $31, X8, X2; XVANDV X31, X2, X2; XVADDW X8, X2, X8
	XVSUBW X31, X8, X2; XVSRAW $31, X2, X3; XVANDV X31, X3, X3; XVADDW X2, X3, X8
	XVMOVQ X1, (R11)
	XVMOVQ X8, 32(R11)
	ADDV $64, R11
	ADDV $-1, R6; BNE R6, R0, intt_scale_loop
	RET

TEXT ·polyInfinityNormLASX(SB), NOSPLIT, $0-12
	MOVV a+0(FP), R4
	MOVV $8380417, R5
	XVMOVQ R5, X31.W8      // X31 = q broadcast
	MOVV $4190208, R5       // (q-1)/2 = 4190208
	XVMOVQ R5, X30.W8      // X30 = qMinus1Div2 broadcast

	// Accumulate max in X27, X28 (2-way for ILP).
	XVORV X27, X27, X27   // X27 = 0
	XVORV X28, X28, X28   // X28 = 0
	MOVV $16, R6
poly_inf_norm_loop:
	XVMOVQ (R4), X0
	XVMOVQ 32(R4), X1

	// infinity norm of X0: min(a, q-a) = a if a <= qM1D2, else q-a.
	XVSUBW X0, X31, X9    // X9 = q - X0
	XVSUBW X0, X30, X2    // X2 = qMinus1Div2 - X0 (C=B-A)
	XVSRAW $31, X2, X2    // mask: -1 if X0 > qMinus1Div2
	XVXORV X0, X9, X3    // X3 = X0 ^ (q - X0)
	XVANDV X2, X3, X3    // select XOR bits where a > qM1D2
	XVXORV X3, X0, X3    // X3 = (a > qM1D2) ? q-a : a = norm

	XVSUBW X3, X27, X4   // X27 - X3
	XVSRAW $31, X4, X4   // mask: -1 if X27 < X3
	XVANDV X4, X3, X5
	XVANDNV X4, X27, X6
	XVORV X5, X6, X27    // X27 = max(X27, X3)

	// infinity norm of X1:
	XVSUBW X1, X31, X9
	XVSUBW X1, X30, X2
	XVSRAW $31, X2, X2
	XVXORV X1, X9, X3
	XVANDV X2, X3, X3
	XVXORV X3, X1, X3    // norm of X1

	XVSUBW X3, X28, X4
	XVSRAW $31, X4, X4
	XVANDV X4, X3, X5
	XVANDNV X4, X28, X6
	XVORV X5, X6, X28

	ADDV $64, R4
	ADDV $-1, R6; BNE R6, R0, poly_inf_norm_loop

	// Merge X27, X28:
	XVSUBW X28, X27, X0
	XVSRAW $31, X0, X0
	XVANDV X0, X28, X1
	XVANDNV X0, X27, X2
	XVORV X1, X2, X27    // X27 = max(X27, X28)

	// Horizontal max: fold high 128-bit lane into low.
	XVORV X27, X27, X28
	XVPERMIQ(28, 27, 0x11)  // X28 = {X27.hi, X27.hi}
	XVSUBW X28, X27, X0
	XVSRAW $31, X0, X0
	XVANDV X0, X28, X1
	XVANDNV X0, X27, X2
	XVORV X1, X2, X27    // X27.lo = max(X27.lo, X27.hi)

	// Fold 4 → 2 using XVSHUF4IW.
	XVORV X27, X27, X28
	XVSHUF4IW $0x4E, X27, X28  // [w2,w3,w0,w1 | ...]
	XVSUBW X28, X27, X0
	XVSRAW $31, X0, X0
	XVANDV X0, X28, X1
	XVANDNV X0, X27, X2
	XVORV X1, X2, X27

	// Fold 2 → 1 using XVSHUF4IW.
	XVORV X27, X27, X28
	XVSHUF4IW $0xB1, X27, X28  // [w1,w0,w3,w2 | ...]
	XVSUBW X28, X27, X0
	XVSRAW $31, X0, X0
	XVANDV X0, X28, X1
	XVANDNV X0, X27, X2
	XVORV X1, X2, X27    // X27[0] = scalar max

	// Extract X27[0] to GP register via float register alias.
	// F0 shares storage with X0.W[0]. movfr2gr.s r9, f0 = 0x114B409
	XVORV X27, X27, X0   // copy X27 to X0
	WORD $0x114B409       // movfr2gr.s r9, f0 → R9 = X0.W[0] = max
	MOVW R9, ret+8(FP)
	RET

TEXT ·polyInfinityNormSignedLASX(SB), NOSPLIT, $0-12
	MOVV a+0(FP), R4

	// Accumulate max in X27, X28 (2-way for ILP).
	XVORV X27, X27, X27   // X27 = 0
	XVORV X28, X28, X28   // X28 = 0
	MOVV $16, R6
poly_inf_norm_signed_loop:
	XVMOVQ (R4), X0
	XVMOVQ 32(R4), X1
	// abs(X0) = (X0 ^ sign) - sign where sign = X0 >> 31
	XVSRAW $31, X0, X2
	XVXORV X2, X0, X3
	XVSUBW X2, X3, X3    // X3 = abs(X0)

	XVSUBW X3, X27, X4
	XVSRAW $31, X4, X4
	XVANDV X4, X3, X5
	XVANDNV X4, X27, X6
	XVORV X5, X6, X27

	XVSRAW $31, X1, X2
	XVXORV X2, X1, X3
	XVSUBW X2, X3, X3    // X3 = abs(X1)

	XVSUBW X3, X28, X4
	XVSRAW $31, X4, X4
	XVANDV X4, X3, X5
	XVANDNV X4, X28, X6
	XVORV X5, X6, X28

	ADDV $64, R4
	ADDV $-1, R6; BNE R6, R0, poly_inf_norm_signed_loop

	// Merge, horizontal reduce (same as above).
	XVSUBW X28, X27, X0
	XVSRAW $31, X0, X0
	XVANDV X0, X28, X1
	XVANDNV X0, X27, X2
	XVORV X1, X2, X27

	XVORV X27, X27, X28
	XVPERMIQ(28, 27, 0x11)
	XVSUBW X28, X27, X0
	XVSRAW $31, X0, X0
	XVANDV X0, X28, X1
	XVANDNV X0, X27, X2
	XVORV X1, X2, X27

	XVORV X27, X27, X28
	XVSHUF4IW $0x4E, X27, X28
	XVSUBW X28, X27, X0
	XVSRAW $31, X0, X0
	XVANDV X0, X28, X1
	XVANDNV X0, X27, X2
	XVORV X1, X2, X27

	XVORV X27, X27, X28
	XVSHUF4IW $0xB1, X27, X28
	XVSUBW X28, X27, X0
	XVSRAW $31, X0, X0
	XVANDV X0, X28, X1
	XVANDNV X0, X27, X2
	XVORV X1, X2, X27

	// Extract X27[0] to GP register via float register alias.
	// F0 shares storage with X0.W[0]. movfr2gr.s r9, f0 = 0x114B409
	XVORV X27, X27, X0   // copy X27 to X0
	WORD $0x114B409       // movfr2gr.s r9, f0 → R9 = X0.W[0] = max
	MOVW R9, ret+8(FP)
	RET

TEXT ·decomposeSubToR0Gamma32LASX(SB), NOSPLIT, $0-24
	MOVV w+0(FP), R4
	MOVV cs2+8(FP), R5
	MOVV out+16(FP), R6
	// TODO: implement
	RET

TEXT ·decomposeSubToR0Gamma88LASX(SB), NOSPLIT, $0-24
	MOVV w+0(FP), R4
	MOVV cs2+8(FP), R5
	MOVV out+16(FP), R6
	// TODO: implement
	RET

TEXT ·useHintPolyGamma32LASX(SB), NOSPLIT, $0-24
	MOVV h+0(FP), R4
	MOVV r+8(FP), R5
	MOVV out+16(FP), R6
	// TODO: implement
	RET

TEXT ·useHintPolyGamma88LASX(SB), NOSPLIT, $0-24
	MOVV h+0(FP), R4
	MOVV r+8(FP), R5
	MOVV out+16(FP), R6
	// TODO: implement
	RET

TEXT ·makeHintPolyGamma32LASX(SB), NOSPLIT, $0-32
	MOVV ct0+0(FP), R4
	MOVV cs2+8(FP), R5
	MOVV w+16(FP), R6
	MOVV hint+24(FP), R7
	// TODO: implement
	RET

TEXT ·makeHintPolyGamma88LASX(SB), NOSPLIT, $0-32
	MOVV ct0+0(FP), R4
	MOVV cs2+8(FP), R5
	MOVV w+16(FP), R6
	MOVV hint+24(FP), R7
	// TODO: implement
	RET
