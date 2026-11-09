// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

#include "textflag.h"
#include "sm4_macros_loong64.s"

DATA ·ghashShiftIndex<>(SB)/8, $0x060504030201000f
DATA ·ghashShiftIndex<>+8(SB)/8, $0x0e0d0c0b0a090807
GLOBL ·ghashShiftIndex<>(SB), (NOPTR+RODATA), $16

DATA ·ghashLastIndex<>(SB)/8, $0x0f0f0f0f0f0f0f0f
DATA ·ghashLastIndex<>+8(SB)/8, $0x0f0f0f0f0f0f0f0f
GLOBL ·ghashLastIndex<>(SB), (NOPTR+RODATA), $16

DATA ·ghashShiftMask<>(SB)/8, $0xffffffffffffff00
DATA ·ghashShiftMask<>+8(SB)/8, $0xffffffffffffffff
GLOBL ·ghashShiftMask<>(SB), (NOPTR+RODATA), $16

DATA ·ghashOne<>(SB)/8, $0x0101010101010101
DATA ·ghashOne<>+8(SB)/8, $0x0101010101010101
GLOBL ·ghashOne<>(SB), (NOPTR+RODATA), $16

DATA ·ghashPoly<>(SB)/8, $0x00000000000000e1
DATA ·ghashPoly<>+8(SB)/8, $0x0000000000000000
GLOBL ·ghashPoly<>(SB), (NOPTR+RODATA), $16

// func ghashMulLoongAsm(out *[16]byte, x0, x1 uint64, h *[16]byte)
// Constant-time bit-serial GHASH multiply. LASX performs the field-state
// shifts, conditional XOR, and reduction in both 128-bit lanes in parallel.
TEXT ·ghashMulLoongAsm(SB), NOSPLIT, $0-32
	MOVV out+0(FP), R4
	MOVV x0+8(FP), R5
	MOVV x1+16(FP), R6
	MOVV h+24(FP), R7

	VMOVQ 0(R7), V0
	XVPERMIQ $0x00, X0, X0
	XVXORV X1, X1, X1
	XVXORV X2, X2, X2

	MOVV $·ghashShiftIndex<>(SB), R8
	VMOVQ 0(R8), V10
	XVPERMIQ $0x00, X10, X10
	MOVV $·ghashLastIndex<>(SB), R8
	VMOVQ 0(R8), V11
	XVPERMIQ $0x00, X11, X11
	MOVV $·ghashShiftMask<>(SB), R8
	VMOVQ 0(R8), V12
	XVPERMIQ $0x00, X12, X12
	MOVV $·ghashOne<>(SB), R8
	VMOVQ 0(R8), V13
	XVPERMIQ $0x00, X13, X13
	MOVV $·ghashPoly<>(SB), R8
	VMOVQ 0(R8), V9
	XVPERMIQ $0x00, X9, X9

	MOVV $128, R9
ghashMulLoop:
	SRLV $63, R5, R10
	XVMOVQ R10, X3.B32
	XVSLLB $7, X3, X3
	XVSRAB $7, X3, X3
	XVANDV X3, X0, X4
	XVXORV X1, X4, X1

	XVANDV X13, X0, X5
	XVSHUFB X10, X5, X5, X6
	XVSLLB $7, X6, X6
	XVANDV X12, X6, X6
	XVSRLB $1, X0, X7
	XVORV X6, X7, X7
	XVSHUFB X11, X5, X5, X14
	XVSLLB $7, X14, X14
	XVSRAB $7, X14, X14
	XVANDV X9, X14, X14
	XVXORV X14, X7, X0

	SRLV $63, R6, R10
	ALSLV $1, R5, R10, R5
	SLLV $1, R6, R6
	SUBV $1, R9, R9
	BNE R9, R0, ghashMulLoop

	VMOVQ V1, 0(R4)
	RET
