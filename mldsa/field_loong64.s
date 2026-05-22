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
	XVSUBW X0, X31, X2         // t = x - q
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
//   5. Xout    = prod_hi - tq_hi        XVSUBW
//
// Result ∈ (-q, q). Caller decides whether to do conditional reduction.
// ============================================================
#define MONTMUL(Xa, Xb, Xout, Xtmp, XqInv, Xq) \
	XVMULW  Xa, Xb, Xout        \ // Xout = a*b low32
	XVMULW  Xout, XqInv, Xtmp   \ // Xtmp = prod_lo * qInv low32
	XVMUHW  Xa, Xb, Xout        \ // Xout = a*b high32 (signed)
	XVMUHW  Xtmp, Xq, Xtmp      \ // Xtmp = t*q high32 (signed)
	XVSUBW  Xtmp, Xout, Xout      // Xout = prod_hi - tq_hi ∈ (-q,q)

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
	// For (q>0): if x<0, x+=q; then if x>=q, x-=q (but since input ∈ [0,q), result ∈ (-q,q))
	// Use: x += (x>>31 & q); then x -= ((q-x-1)>>31 & q)... simpler: just do one pass
	// add q if negative:
	XVSRAW $31, X2, X3         // mask: all-1 if x<0
	XVANDV X31, X3, X3         // q if x<0
	XVADDW X2, X3, X2          // now x ∈ [0, 2q-1]
	// subtract q if >= q:
	XVSUBW X2, X31, X3         // t = x - q
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
	XVSUBW X2, X31, X3
	XVSRAW $31, X3, X4
	XVANDV X31, X4, X4
	XVADDW X3, X4, X2          // now in [0, q)
	// Accumulate: acc += product; reduce acc mod q
	XVMOVQ (R6), X5
	XVADDW X5, X2, X5          // acc + product ∈ [0, 2q-1]
	XVSUBW X5, X31, X3         // t = acc - q
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
	XVSUBW X5, X31, X3
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
	XVSUBW X2, X31, X3
	XVSRAW $31, X3, X4
	XVANDV X31, X4, X4
	XVADDW X3, X4, X2          // X2 ∈ [0, q)
	// Accumulate and reduce
	XVADDW X5, X2, X5
	XVSUBW X5, X31, X3
	XVSRAW $31, X3, X4
	XVANDV X31, X4, X4
	XVADDW X3, X4, X5
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

TEXT ·internalNTTLASX(SB), NOSPLIT, $0-8
	MOVV f+0(FP), R4
	// TODO: implement
	RET

TEXT ·internalInverseNTTLASX(SB), NOSPLIT, $0-8
	MOVV f+0(FP), R4
	// TODO: implement
	RET

TEXT ·polyInfinityNormLASX(SB), NOSPLIT, $0-16
	MOVV a+0(FP), R4
	// TODO: implement
	MOVV $0, R4
	MOVV R4, ret+8(FP)
	RET

TEXT ·polyInfinityNormSignedLASX(SB), NOSPLIT, $0-16
	MOVV a+0(FP), R4
	// TODO: implement
	MOVV $0, R4
	MOVV R4, ret+8(FP)
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
