// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// ---- Static constants ----
//
// kBarrettConsts layout:
//   [0x00..0x0F] = {5039,5039,5039,5039}  -> VkBMul  (uint32x4)
//   [0x10..0x1F] = {24,0,24,0}            -> VkBShift (uint64x2)
//   [0x20..0x2F] = {3329,3329,3329,3329}  -> VkPrime32 (uint32x4)
//   [0x30..0x3F] = {3329 x8}              -> VkPrime16 (uint16x8)
DATA kBarrettConsts<>+0x00(SB)/4, $5039
DATA kBarrettConsts<>+0x04(SB)/4, $5039
DATA kBarrettConsts<>+0x08(SB)/4, $5039
DATA kBarrettConsts<>+0x0C(SB)/4, $5039
DATA kBarrettConsts<>+0x10(SB)/4, $24
DATA kBarrettConsts<>+0x14(SB)/4, $0
DATA kBarrettConsts<>+0x18(SB)/4, $24
DATA kBarrettConsts<>+0x1C(SB)/4, $0
DATA kBarrettConsts<>+0x20(SB)/4, $3329
DATA kBarrettConsts<>+0x24(SB)/4, $3329
DATA kBarrettConsts<>+0x28(SB)/4, $3329
DATA kBarrettConsts<>+0x2C(SB)/4, $3329
DATA kBarrettConsts<>+0x30(SB)/2, $3329
DATA kBarrettConsts<>+0x32(SB)/2, $3329
DATA kBarrettConsts<>+0x34(SB)/2, $3329
DATA kBarrettConsts<>+0x36(SB)/2, $3329
DATA kBarrettConsts<>+0x38(SB)/2, $3329
DATA kBarrettConsts<>+0x3A(SB)/2, $3329
DATA kBarrettConsts<>+0x3C(SB)/2, $3329
DATA kBarrettConsts<>+0x3E(SB)/2, $3329
GLOBL kBarrettConsts<>(SB), RODATA|NOPTR, $64

// lxvPermMask: byte-swap correction for LXVD2X on ppc64le.
// LXVD2X loads a 16-byte vector treating it as two 64-bit big-endian words,
// reversing byte order within each 8-byte group on little-endian systems.
// For int16 elements [a0,a1,a2,a3,...,a7] (each 2 bytes LE) in a 16-byte block:
//   memory: a0lo,a0hi, a1lo,a1hi, a2lo,a2hi, a3lo,a3hi, a4lo,a4hi,...
//   register (BE view): a3hi,a3lo,a2hi,a2lo,a1hi,a1lo,a0hi,a0lo, ...
// To restore natural order, VPERM with mask that selects:
//   out[0]=src[7]=a0lo, out[1]=src[6]=a0hi, out[2]=src[5]=a1lo, ...
// Mask BE register bytes: {7,6,5,4,3,2,1,0, 15,14,13,12,11,10,9,8}
// These are stored as LE 64-bit integers so LVX reverses them into the right BE register positions.
DATA lxvPermMask<>+0x00(SB)/8, $0x0706050403020100
DATA lxvPermMask<>+0x08(SB)/8, $0x0F0E0D0C0B0A0908
GLOBL lxvPermMask<>(SB), RODATA|NOPTR, $16

// polyAddAssignPPC64LE(dst, src *ringElement)
// dst[i] = barrettReduce(dst[i] + src[i]) for all 256 int16 coefficients.
TEXT ·polyAddAssignPPC64LE(SB), NOSPLIT, $0-16
	MOVD dst+0(FP), R4
	MOVD src+8(FP), R5
	MOVD $0, R0

	MOVD $lxvPermMask<>(SB), R6
	LVX  (R0)(R6), V20

	MOVD $kBarrettConsts<>(SB), R6
	MOVD $48, R7
	LVX  (R7)(R6), V21

	MOVD $16, R8
	MOVD $16, R6

poly_add_loop:
	LXVD2X (R0)(R4), V0
	VPERM  V0, V0, V20, V0
	LXVD2X (R8)(R4), V1
	VPERM  V1, V1, V20, V1
	LXVD2X (R0)(R5), V2
	VPERM  V2, V2, V20, V2
	LXVD2X (R8)(R5), V3
	VPERM  V3, V3, V20, V3

	// V0 = V0 + V2; V1 = V1 + V3
	VADDUHM V0, V2, V0
	VADDUHM V1, V3, V1

	// V4 = V0 - q; V5 = V1 - q
	VSUBUHM V0, V21, V4
	VSUBUHM V1, V21, V5
	// V6[i] = 0xFFFF if q > V4[i], meaning V0[i] < q (underflow), keep V0
	VCMPGTUH V21, V4, V6
	VCMPGTUH V21, V5, V7
	// V0 = V6[i] ? V0[i] : V4[i]
	VSEL V4, V0, V6, V0
	VSEL V5, V1, V7, V1

	VPERM  V0, V0, V20, V4
	STXVD2X V4, (R0)(R4)
	VPERM  V1, V1, V20, V4
	STXVD2X V4, (R8)(R4)

	ADD  $32, R4
	ADD  $32, R5
	SUB  $1, R6
	CMP  R6, $0
	BNE  poly_add_loop

	RET

// polySubAssignPPC64LE(dst, src *ringElement)
// dst[i] = barrettReduce(dst[i] + q - src[i]) for all 256 int16 coefficients.
TEXT ·polySubAssignPPC64LE(SB), NOSPLIT, $0-16
	MOVD dst+0(FP), R4
	MOVD src+8(FP), R5
	MOVD $0, R0

	MOVD $lxvPermMask<>(SB), R6
	LVX  (R0)(R6), V20

	MOVD $kBarrettConsts<>(SB), R6
	MOVD $48, R7
	LVX  (R7)(R6), V21

	MOVD $16, R8
	MOVD $16, R6

poly_sub_loop:
	LXVD2X (R0)(R4), V0
	VPERM  V0, V0, V20, V0
	LXVD2X (R8)(R4), V1
	VPERM  V1, V1, V20, V1
	LXVD2X (R0)(R5), V2
	VPERM  V2, V2, V20, V2
	LXVD2X (R8)(R5), V3
	VPERM  V3, V3, V20, V3

	// V0 = V0 + q - V2; V1 = V1 + q - V3
	VADDUHM V0, V21, V0
	VSUBUHM V0, V2, V0
	VADDUHM V1, V21, V1
	VSUBUHM V1, V3, V1

	// Conditional reduce
	VSUBUHM V0, V21, V4
	VSUBUHM V1, V21, V5
	VCMPGTUH V21, V4, V6
	VCMPGTUH V21, V5, V7
	VSEL V4, V0, V6, V0
	VSEL V5, V1, V7, V1

	VPERM  V0, V0, V20, V4
	STXVD2X V4, (R0)(R4)
	VPERM  V1, V1, V20, V4
	STXVD2X V4, (R8)(R4)

	VPERM  V0, V0, V20, V4
	STXVD2X V4, (R0)(R4)
	VPERM  V1, V1, V20, V4
	STXVD2X V4, (R8)(R4)

	ADD  $32, R4
	ADD  $32, R5
	SUB  $1, R6
	CMP  R6, $0
	BNE  poly_sub_loop

	RET

// ---- Stubs for future asm implementation ----

TEXT ·internalNTTPPC64LE(SB), NOSPLIT, $0-8
	MOVD f+0(FP), R4
	RET

TEXT ·internalInverseNTTPPC64LE(SB), NOSPLIT, $0-8
	MOVD f+0(FP), R4
	RET

TEXT ·internalNTTMulPPC64LE(SB), NOSPLIT, $0-24
	MOVD out+0(FP), R4
	MOVD lhs+8(FP), R5
	MOVD rhs+16(FP), R6
	RET

TEXT ·internalNTTMulAccPPC64LE(SB), NOSPLIT, $0-24
	MOVD acc+0(FP), R4
	MOVD lhs+8(FP), R5
	MOVD rhs+16(FP), R6
	RET

TEXT ·internalNTTMulAccKeyGenPPC64LE(SB), NOSPLIT, $0-24
	MOVD acc+0(FP), R4
	MOVD lhs+8(FP), R5
	MOVD rhs+16(FP), R6
	RET

TEXT ·ringCompressAndEncode1PPC64LE(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R4
	MOVD f+24(FP), R5
	RET

TEXT ·ringCompressAndEncode4PPC64LE(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R4
	MOVD f+24(FP), R5
	RET

TEXT ·ringDecodeAndDecompress4PPC64LE(SB), NOSPLIT, $0-16
	MOVD b+0(FP), R4
	MOVD f+8(FP), R5
	RET

TEXT ·ringCompressAndEncode5PPC64LE(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R4
	MOVD f+24(FP), R5
	RET

TEXT ·ringDecodeAndDecompress5PPC64LE(SB), NOSPLIT, $0-16
	MOVD b+0(FP), R4
	MOVD f+8(FP), R5
	RET

TEXT ·ringCompressAndEncode10PPC64LE(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R4
	MOVD f+24(FP), R5
	RET

TEXT ·ringCompressAndEncode11PPC64LE(SB), NOSPLIT, $0-32
	MOVD out_base+0(FP), R4
	MOVD f+24(FP), R5
	RET

TEXT ·decodeAndDecompressU10PPC64LE(SB), NOSPLIT, $0-48
	MOVD dst_base+0(FP), R4
	MOVD c_base+24(FP), R5
	RET

TEXT ·decodeAndDecompressU11PPC64LE(SB), NOSPLIT, $0-48
	MOVD dst_base+0(FP), R4
	MOVD c_base+24(FP), R5
	RET

TEXT ·samplePolyCBD2PPC64LE(SB), NOSPLIT, $0-16
	MOVD f+0(FP), R4
	MOVD buf+8(FP), R5
	RET

TEXT ·samplePolyCBD3PPC64LE(SB), NOSPLIT, $0-16
	MOVD f+0(FP), R4
	MOVD buf+8(FP), R5
	RET

TEXT ·rejUniformPPC64LE(SB), NOSPLIT, $0-48
	MOVD buf_base+0(FP), R4
	MOVD buf_len+8(FP), R5
	MOVD a+24(FP), R6
	MOVD j+32(FP), R7
	MOVD $0, R3
	MOVD R3, ret+40(FP)
	RET
