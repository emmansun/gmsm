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

// Scalar Montgomery multiply: Rd = MontMul(Ra, Rb).
// Ra, Rb = 32-bit inputs (sign-extended in 64-bit registers).
// Uses: R_qNegInv (must be loaded as qNegInv=4236238847), R_q (must be 8380417).
// Clobbers: Rtmp0, Rtmp1, Rd
// Note: result is in [0, q).
#define SCALAR_MONTMUL(Ra, Rb, Rd, Rtmp0, Rtmp1, R_qNegInv, R_q) \
	MULVU Ra, Rb, Rtmp0          \ // Rtmp0 = lo64(Ra*Rb)
	AND $0xFFFFFFFF, Rtmp0, Rtmp1 \ // Rtmp1 = lo32
	MULVU Rtmp1, R_qNegInv, Rtmp1 \ // Rtmp1 = lo64(lo32 * qNegInv)
	AND $0xFFFFFFFF, Rtmp1, Rtmp1 \ // Rtmp1 = lo32 of above
	MULVU Rtmp1, R_q, Rtmp1       \ // Rtmp1 = Rtmp1 * q
	ADDVU Rtmp0, Rtmp1, Rd        \ // Rd = Ra*Rb + t*q
	SRLV $32, Rd                  \ // Rd = (Ra*Rb + t*q) >> 32
	BGEU Rd, R_q, 2(PC)           \
	JMP 2(PC)                     \
	SUBV R_q, Rd

// Scalar CT butterfly: (Ra, Rb, zeta_in_R10) → (Ra', Rb')
// Ra' = Ra + t, Rb' = Ra - t, t = MontMul(zeta, Rb)
// Clobbers: R15, R16, R17, R18
#define SCALAR_CT_BUTTERFLY(Ra, Rb, Rzeta, R15, R16, R17, R18, R_qNegInv, R_q) \
	SCALAR_MONTMUL(Rzeta, Rb, R15, R16, R17, R_qNegInv, R_q) \ // R15 = t
	SUBV R15, Ra, R16         \ // R16 = Ra - t
	BLT R16, R0, 2(PC)        \
	JMP 2(PC)                 \
	ADDV R_q, R16             \ // ensure >= 0
	ADDV R15, Ra, R18         \ // R18 = Ra + t
	BGEU R18, R_q, 2(PC)      \
	JMP 2(PC)                 \
	SUBV R_q, R18             \ // ensure < q
	MOVV R18, Ra              \
	MOVV R16, Rb

// Scalar GS butterfly: (Ra, Rb, qmzeta_in_Rzeta) → (Ra', Rb')
// Ra' = Ra + Rb, Rb' = MontMul(q-zeta, Ra - Rb)
// Clobbers: R15, R16, R17, R18
#define SCALAR_GS_BUTTERFLY(Ra, Rb, Rzeta, R15, R16, R17, R18, R_qNegInv, R_q) \
	SUBV Rb, Ra, R15           \ // R15 = Ra - Rb
	BLT R15, R0, 2(PC)         \
	JMP 2(PC)                  \
	ADDV R_q, R15              \ // R15 -> >= 0
	ADDV Ra, Rb, Ra            \ // Ra = Ra + Rb
	BGEU Ra, R_q, 2(PC)        \
	JMP 2(PC)                  \
	SUBV R_q, Ra               \ // Ra < q
	SCALAR_MONTMUL(Rzeta, R15, Rb, R16, R17, R_qNegInv, R_q)

TEXT ·internalNTTLASX(SB), NOSPLIT, $0-8
	MOVV f+0(FP), R4
	MOVV $·zetasMontgomery(SB), R5
	ADDV $4, R5             // point to zetasMontgomery[1]
	MOVV $8380417, R8
	XVMOVQ R8, X31.W8      // X31 = q broadcast
	MOVV $58728449, R9
	XVMOVQ R9, X30.W8      // X30 = qInv broadcast

	// L0: len=128, 1 group, 16 LASX butterfly pairs (each 8 int32 = 32 bytes per side).
	MOVWU (R5), R10; ADDV $4, R5
	XVMOVQ R10, X29.W8
	MOVV R4, R11; MOVV R4, R12; ADDV $512, R12   // f+0, f+128*4
	MOVV $16, R6
ntt_l0_loop:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	NTT_BUTTERFLY(X0, X1, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	ADDV $32, R11; ADDV $32, R12
	ADDV $-1, R6; BNE R6, R0, ntt_l0_loop

	// L1: len=64, 2 groups, 8 LASX butterfly pairs each (64 elements = 256 bytes = 8 vectors).
	MOVV $2, R6; MOVV R4, R7
ntt_l1_outer:
	MOVWU (R5), R10; ADDV $4, R5; XVMOVQ R10, X29.W8
	MOVV R7, R11; MOVV R7, R12; ADDV $256, R12   // 64*4
	MOVV $8, R13
ntt_l1_inner:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	NTT_BUTTERFLY(X0, X1, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	ADDV $32, R11; ADDV $32, R12
	ADDV $-1, R13; BNE R13, R0, ntt_l1_inner
	ADDV $512, R7; ADDV $-1, R6; BNE R6, R0, ntt_l1_outer

	// L2: len=32, 4 groups, 4 LASX butterfly pairs each (32 elements = 128 bytes = 4 vectors).
	MOVV $4, R6; MOVV R4, R7
ntt_l2_outer:
	MOVWU (R5), R10; ADDV $4, R5; XVMOVQ R10, X29.W8
	MOVV R7, R11; MOVV R7, R12; ADDV $128, R12   // 32*4
	MOVV $4, R13
ntt_l2_inner:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	NTT_BUTTERFLY(X0, X1, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	ADDV $32, R11; ADDV $32, R12
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

	// L5-L7: scalar loops (correctness-first; 4, 2, 1 elems per group).
	// R19 = qNegInv, R21 = q
	MOVV $4236238847, R19
	MOVV $8380417, R21

	// L5: len=4, 32 groups.
	// Group start at stride 8*4=32 bytes. even=f[start..start+3], odd=f[start+4..start+7].
	MOVV $32, R6; MOVV R4, R7
ntt_l5_outer:
	MOVWU (R5), R10; ADDV $4, R5    // zeta
	MOVV $4, R13; MOVV R7, R11; MOVV R7, R12; ADDV $16, R12
ntt_l5_inner:
	MOVWU (R11), R15; MOVWU (R12), R16
	MULVU R10, R16, R24           // R24 = lo64(zeta * odd)
	AND $0xFFFFFFFF, R24, R25     // lo32
	MULVU R25, R19, R25           // lo64(lo32 * qNegInv)
	AND $0xFFFFFFFF, R25, R25     // lo32 of above
	MULVU R25, R21, R25           // R25 * q
	ADDVU R24, R25, R25           // zeta*odd + t*q
	SRLV $32, R25                 // t = (zeta*odd + t*q) >> 32
	BGEU R25, R21, 2(PC); JMP 2(PC); SUBV R21, R25  // t -> [0, q)
	// now: R25 = t, R15 = even (f[j]), need: even' = even+t, odd' = even-t
	ADDV R25, R15, R24; BGEU R24, R21, 2(PC); JMP 2(PC); SUBV R21, R24
	SUBV R25, R15, R23; BLT R23, R0, 2(PC); JMP 2(PC); ADDV R21, R23
	MOVW R24, (R11); MOVW R23, (R12)
	ADDV $4, R11; ADDV $4, R12
	ADDV $-1, R13; BNE R13, R0, ntt_l5_inner
	ADDV $32, R7; ADDV $-1, R6; BNE R6, R0, ntt_l5_outer

	// L6: len=2, 64 groups.
	// Group start at stride 4*4=16 bytes. even=f[start..start+1], odd=f[start+2..start+3].
	MOVV $64, R6; MOVV R4, R7
ntt_l6_outer:
	MOVWU (R5), R10; ADDV $4, R5
	MOVV $2, R13; MOVV R7, R11; MOVV R7, R12; ADDV $8, R12
ntt_l6_inner:
	MOVWU (R11), R15; MOVWU (R12), R16
	MULVU R10, R16, R24; AND $0xFFFFFFFF, R24, R25; MULVU R25, R19, R25; AND $0xFFFFFFFF, R25, R25
	MULVU R25, R21, R25; ADDVU R24, R25, R25; SRLV $32, R25
	BGEU R25, R21, 2(PC); JMP 2(PC); SUBV R21, R25
	ADDV R25, R15, R24; BGEU R24, R21, 2(PC); JMP 2(PC); SUBV R21, R24
	SUBV R25, R15, R23; BLT R23, R0, 2(PC); JMP 2(PC); ADDV R21, R23
	MOVW R24, (R11); MOVW R23, (R12)
	ADDV $4, R11; ADDV $4, R12
	ADDV $-1, R13; BNE R13, R0, ntt_l6_inner
	ADDV $16, R7; ADDV $-1, R6; BNE R6, R0, ntt_l6_outer

	// L7: len=1, 128 groups.
	// Group start at stride 2*4=8 bytes. even=f[start], odd=f[start+1].
	MOVV $128, R6; MOVV R4, R7
ntt_l7_outer:
	MOVWU (R5), R10; ADDV $4, R5
	MOVWU (R7), R15; MOVWU 4(R7), R16
	MULVU R10, R16, R24; AND $0xFFFFFFFF, R24, R25; MULVU R25, R19, R25; AND $0xFFFFFFFF, R25, R25
	MULVU R25, R21, R25; ADDVU R24, R25, R25; SRLV $32, R25
	BGEU R25, R21, 2(PC); JMP 2(PC); SUBV R21, R25
	ADDV R25, R15, R24; BGEU R24, R21, 2(PC); JMP 2(PC); SUBV R21, R24
	SUBV R25, R15, R23; BLT R23, R0, 2(PC); JMP 2(PC); ADDV R21, R23
	MOVW R24, (R7); MOVW R23, 4(R7)
	ADDV $8, R7; ADDV $-1, R6; BNE R6, R0, ntt_l7_outer
	RET

TEXT ·internalInverseNTTLASX(SB), NOSPLIT, $0-8
	MOVV f+0(FP), R4
	MOVV $·zetasMontgomery(SB), R5
	ADDV $1024, R5          // point to zetasMontgomery[256] (end+1)
	MOVV $8380417, R8
	XVMOVQ R8, X31.W8      // X31 = q broadcast
	MOVV $58728449, R9
	XVMOVQ R9, X30.W8      // X30 = qInv broadcast

	// INTT Layer 7: len=128, 1 group, 32 LASX vectors.
	// k=1 (zetasMontgomery[1]), qmz = q - zeta
	ADDV $-4, R5            // point to zetasMontgomery[255]
	ADDV $-4, R5            // point to zetasMontgomery[254]... wait, k goes 255..1
	// Actually k=255 for the first layer, decrementing. Let's reset:
	MOVV $·zetasMontgomery(SB), R5
	ADDV $1020, R5          // point to zetasMontgomery[255] (255*4 bytes from base)
	// k starts at 255, we advance backwards (ADDV $-4, R5 each time)

	// Layer 7 (len=128, 1 group): k=255→...wait, in generic code:
	// k starts at 255, for len=1 (first INTT layer = L0 in INTT ordering).
	// But in my LASX ordering, I'm doing L7 first (len=128) for max vectorization.
	// Wait — the INTT outer loop in generic code:
	//   k=255, len=1: 128 groups of len=1 (GS step, scalar)
	//   k=127, len=2: 64 groups of len=2
	//   ...
	//   k=1, len=128: 1 group of len=128
	// So for LASX efficiency, do in the same order (smallest len first):
	// L0: len=1, 128 groups → scalar
	// L1: len=2, 64 groups → scalar
	// L2: len=4, 32 groups → scalar
	// L3: len=8, 16 groups → LASX possible (2 vecs per group)
	// L4: len=16, 8 groups → LASX
	// L5: len=32, 4 groups → LASX
	// L6: len=64, 2 groups → LASX
	// L7: len=128, 1 group → LASX
	// Reset pointer to zetasMontgomery[255]:
	MOVV $·zetasMontgomery(SB), R5
	ADDV $1020, R5          // zetasMontgomery[255]
	MOVV $4236238847, R19   // qNegInv for scalar
	MOVV $8380417, R21      // q for scalar

	// L0: len=1, 128 groups (scalar). k=255..128.
	MOVV $128, R6; MOVV R4, R7
intt_l0_outer:
	MOVWU (R5), R10; ADDV $-4, R5   // zeta = zetasMontgomery[k--]
	SUBV R10, R21, R10               // qmz = q - zeta
	MOVWU (R7), R15; MOVWU 4(R7), R16
	// GS butterfly: t=R15, even'=t+R16, odd'=MontMul(qmz, t-R16)
	ADDV R15, R16, R24; BGEU R24, R21, 2(PC); JMP 2(PC); SUBV R21, R24  // even' = (t+R16) mod q
	SUBV R16, R15, R23; BLT R23, R0, 2(PC); JMP 2(PC); ADDV R21, R23   // diff = (t-R16+q) mod q
	// MontMul(qmz, diff): R25 = result
	MULVU R10, R23, R25; AND $0xFFFFFFFF, R25, R23; MULVU R23, R19, R23; AND $0xFFFFFFFF, R23, R23
	MULVU R23, R21, R23; ADDVU R25, R23, R25; SRLV $32, R25
	BGEU R25, R21, 2(PC); JMP 2(PC); SUBV R21, R25
	MOVW R24, (R7); MOVW R25, 4(R7)
	ADDV $8, R7; ADDV $-1, R6; BNE R6, R0, intt_l0_outer

	// L1: len=2, 64 groups (scalar). k=127..64.
	MOVV $64, R6; MOVV R4, R7
intt_l1_outer:
	MOVWU (R5), R10; ADDV $-4, R5
	SUBV R10, R21, R10     // qmz = q - zeta
	MOVV R7, R11; MOVV R7, R12; ADDV $8, R12
	MOVV $2, R13
intt_l1_inner:
	MOVWU (R11), R15; MOVWU (R12), R16
	ADDV R15, R16, R24; BGEU R24, R21, 2(PC); JMP 2(PC); SUBV R21, R24
	SUBV R16, R15, R23; BLT R23, R0, 2(PC); JMP 2(PC); ADDV R21, R23
	MULVU R10, R23, R25; AND $0xFFFFFFFF, R25, R23; MULVU R23, R19, R23; AND $0xFFFFFFFF, R23, R23
	MULVU R23, R21, R23; ADDVU R25, R23, R25; SRLV $32, R25
	BGEU R25, R21, 2(PC); JMP 2(PC); SUBV R21, R25
	MOVW R24, (R11); MOVW R25, (R12)
	ADDV $4, R11; ADDV $4, R12
	ADDV $-1, R13; BNE R13, R0, intt_l1_inner
	ADDV $16, R7; ADDV $-1, R6; BNE R6, R0, intt_l1_outer

	// L2: len=4, 32 groups (scalar). k=63..32.
	MOVV $32, R6; MOVV R4, R7
intt_l2_outer:
	MOVWU (R5), R10; ADDV $-4, R5
	SUBV R10, R21, R10
	MOVV R7, R11; MOVV R7, R12; ADDV $16, R12
	MOVV $4, R13
intt_l2_inner:
	MOVWU (R11), R15; MOVWU (R12), R16
	ADDV R15, R16, R24; BGEU R24, R21, 2(PC); JMP 2(PC); SUBV R21, R24
	SUBV R16, R15, R23; BLT R23, R0, 2(PC); JMP 2(PC); ADDV R21, R23
	MULVU R10, R23, R25; AND $0xFFFFFFFF, R25, R23; MULVU R23, R19, R23; AND $0xFFFFFFFF, R23, R23
	MULVU R23, R21, R23; ADDVU R25, R23, R25; SRLV $32, R25
	BGEU R25, R21, 2(PC); JMP 2(PC); SUBV R21, R25
	MOVW R24, (R11); MOVW R25, (R12)
	ADDV $4, R11; ADDV $4, R12
	ADDV $-1, R13; BNE R13, R0, intt_l2_inner
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

	// L5: len=32, 4 groups, 4 LASX butterfly pairs each (32 elements = 128 bytes = 4 vectors). k=7..4.
	MOVV $4, R6; MOVV R4, R7
intt_l5_outer:
	MOVWU (R5), R10; ADDV $-4, R5
	SUBV R10, R8, R10
	XVMOVQ R10, X29.W8
	MOVV R7, R11; MOVV R7, R12; ADDV $128, R12   // 32*4
	MOVV $4, R13
intt_l5_inner:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	INTT_BUTTERFLY(X0, X1, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	ADDV $32, R11; ADDV $32, R12
	ADDV $-1, R13; BNE R13, R0, intt_l5_inner
	ADDV $256, R7; ADDV $-1, R6; BNE R6, R0, intt_l5_outer

	// L6: len=64, 2 groups, 8 LASX butterfly pairs each (64 elements = 256 bytes = 8 vectors). k=3..2.
	MOVV $2, R6; MOVV R4, R7
intt_l6_outer:
	MOVWU (R5), R10; ADDV $-4, R5
	SUBV R10, R8, R10
	XVMOVQ R10, X29.W8
	MOVV R7, R11; MOVV R7, R12; ADDV $256, R12   // 64*4
	MOVV $8, R13
intt_l6_inner:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	INTT_BUTTERFLY(X0, X1, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	ADDV $32, R11; ADDV $32, R12
	ADDV $-1, R13; BNE R13, R0, intt_l6_inner
	ADDV $512, R7; ADDV $-1, R6; BNE R6, R0, intt_l6_outer

	// L7: len=128, 1 group, 16 LASX butterfly pairs (128 elements = 512 bytes = 16 vectors). k=1.
	MOVWU (R5), R10; ADDV $-4, R5
	SUBV R10, R8, R10
	XVMOVQ R10, X29.W8
	MOVV R4, R11; MOVV R4, R12; ADDV $512, R12   // 128*4
	MOVV $16, R6
intt_l7_loop:
	XVMOVQ (R11), X0; XVMOVQ (R12), X1
	INTT_BUTTERFLY(X0, X1, X29)
	XVMOVQ X0, (R11); XVMOVQ X1, (R12)
	ADDV $32, R11; ADDV $32, R12
	ADDV $-1, R6; BNE R6, R0, intt_l7_loop

	// Multiply all 256 elements by invDegreeMont = 41978
	// 41978 = ((256⁻¹ mod q) * (2³² * 2³² mod q)) mod q
	MOVV $41978, R10
	XVMOVQ R10, X29.W8
	MOVV R4, R11; MOVV $32, R6
intt_scale_loop:
	XVMOVQ (R11), X0
	MONTMUL(X29, X0, X1, X2, X30, X31)
	XVSRAW $31, X1, X2; XVANDV X31, X2, X2; XVADDW X1, X2, X1      // [0, 2q-1]
	XVSUBW X31, X1, X2; XVSRAW $31, X2, X3; XVANDV X31, X3, X3; XVADDW X2, X3, X1  // [0, q)
	XVMOVQ X1, (R11)
	ADDV $32, R11
	ADDV $-1, R6; BNE R6, R0, intt_scale_loop
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
