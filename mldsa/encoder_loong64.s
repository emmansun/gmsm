// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// ============================================================
// ML-DSA encoder -- LoongArch LASX implementation
//
// Calling convention: args in FP pseudo-register.
//   R4 = first pointer arg, R5 = second pointer arg.
//   R6-R14 used as scalar scratch.
//
// All functions use $0 frame (no stack spill) by using
// XVMOVQ element indexing for vector-scalar transfer:
//   XVMOVQ X.W[idx], R  -- xvpickve2gr.w (extract)
//   XVMOVQ R, X.W[idx]  -- xvinsgr2vr.w  (insert)
//
// LASX field constants:
//   q              = 8380417
//   bitPackConst17 = 2^17 + q = 8511489
//   bitPackConst19 = 2^19 + q = 8904705
// ============================================================

// ============================================================
// simpleBitPack4BitsLASX -- pack 256 coefficients in [0,15] into
// 128 bytes, two 4-bit nibbles per byte (FIPS 204 SimpleBitPack b=4).
//
// Strategy: scalar -- read two int32, pack nibbles, store byte.
//
// R4 = dst, R5 = f
// ============================================================
TEXT ·simpleBitPack4BitsLASX(SB), NOSPLIT, $0-16
	MOVV dst+0(FP), R4
	MOVV f+8(FP), R5
	MOVV $32, R6
simpleBitPack4Scalar:
	XVMOVQ (R5), X0
	XVMOVQ X0.W[0], R7; XVMOVQ X0.W[1], R8; SLLV $4, R8, R8; OR R7, R8, R8; MOVBU R8, 0(R4)
	XVMOVQ X0.W[2], R7; XVMOVQ X0.W[3], R8; SLLV $4, R8, R8; OR R7, R8, R8; MOVBU R8, 1(R4)
	XVMOVQ X0.W[4], R7; XVMOVQ X0.W[5], R8; SLLV $4, R8, R8; OR R7, R8, R8; MOVBU R8, 2(R4)
	XVMOVQ X0.W[6], R7; XVMOVQ X0.W[7], R8; SLLV $4, R8, R8; OR R7, R8, R8; MOVBU R8, 3(R4)
	ADDV $32, R5; ADDV $4, R4
	ADDV $-1, R6; BNE R6, R0, simpleBitPack4Scalar
	RET

// ============================================================
// simpleBitPack4BitsHighBitsGamma32LASX -- HighBits(f,(q-1)/32) packed as nibbles.
//
// r1 = (((r+127)>>7)*1025 + 2^21) >> 22, r1 &= 15
//
// LASX vectorizes HighBits (8 coefs/vector), spills, scalar-packs nibbles.
//
// R4 = dst, R5 = f
// ============================================================
TEXT ·simpleBitPack4BitsHighBitsGamma32LASX(SB), NOSPLIT, $0-16
	MOVV dst+0(FP), R4
	MOVV f+8(FP), R5
	MOVV $127,  R7;  XVMOVQ R7, X20.W8
	MOVV $1025, R7;  XVMOVQ R7, X21.W8
	MOVV $1,    R7;  SLLV $21, R7, R7; XVMOVQ R7, X22.W8
	MOVV $15,   R7;  XVMOVQ R7, X23.W8
	MOVV $16,   R6
pack4hbLoop:
	XVMOVQ  (R5), X0
	XVMOVQ 32(R5), X1
	XVADDW X20, X0, X2; XVSRLW $7, X2, X2; XVMULW X21, X2, X2; XVADDW X22, X2, X2; XVSRAW $22, X2, X2; XVANDV X23, X2, X2
	XVADDW X20, X1, X3; XVSRLW $7, X3, X3; XVMULW X21, X3, X3; XVADDW X22, X3, X3; XVSRAW $22, X3, X3; XVANDV X23, X3, X3
	// Extract X2 elements and pack nibble pairs
	XVMOVQ X2.W[0], R7; XVMOVQ X2.W[1], R8; SLLV $4, R8, R8; OR R7, R8, R8; MOVBU R8, 0(R4)
	XVMOVQ X2.W[2], R7; XVMOVQ X2.W[3], R8; SLLV $4, R8, R8; OR R7, R8, R8; MOVBU R8, 1(R4)
	XVMOVQ X2.W[4], R7; XVMOVQ X2.W[5], R8; SLLV $4, R8, R8; OR R7, R8, R8; MOVBU R8, 2(R4)
	XVMOVQ X2.W[6], R7; XVMOVQ X2.W[7], R8; SLLV $4, R8, R8; OR R7, R8, R8; MOVBU R8, 3(R4)
	// Extract X3 elements and pack nibble pairs
	XVMOVQ X3.W[0], R7; XVMOVQ X3.W[1], R8; SLLV $4, R8, R8; OR R7, R8, R8; MOVBU R8, 4(R4)
	XVMOVQ X3.W[2], R7; XVMOVQ X3.W[3], R8; SLLV $4, R8, R8; OR R7, R8, R8; MOVBU R8, 5(R4)
	XVMOVQ X3.W[4], R7; XVMOVQ X3.W[5], R8; SLLV $4, R8, R8; OR R7, R8, R8; MOVBU R8, 6(R4)
	XVMOVQ X3.W[6], R7; XVMOVQ X3.W[7], R8; SLLV $4, R8, R8; OR R7, R8, R8; MOVBU R8, 7(R4)
	ADDV $64, R5; ADDV $8, R4
	ADDV $-1, R6; BNE R6, R0, pack4hbLoop
	RET

// ============================================================
// simpleBitPack6BitsLASX -- pack 256 coefficients in [0,43] into
// 192 bytes, 4 per 3-byte group.
//
// Strategy: scalar loop.
//
// R4 = dst, R5 = f
// ============================================================
TEXT ·simpleBitPack6BitsLASX(SB), NOSPLIT, $0-16
	MOVV dst+0(FP), R4
	MOVV f+8(FP), R5
	MOVV $32, R6
simpleBitPack6Scalar:
	XVMOVQ (R5), X0
	// Group 1: elements 0-3 → 3 bytes
	XVMOVQ X0.W[0], R7
	XVMOVQ X0.W[1], R8; SLLV  $6, R8, R8; OR R7, R8, R7
	XVMOVQ X0.W[2], R8; SLLV $12, R8, R8; OR R7, R8, R7
	XVMOVQ X0.W[3], R8; SLLV $18, R8, R8; OR R7, R8, R7
	MOVBU R7, 0(R4); SRLV $8, R7, R7
	MOVBU R7, 1(R4); SRLV $8, R7, R7
	MOVBU R7, 2(R4)
	// Group 2: elements 4-7 → 3 bytes
	XVMOVQ X0.W[4], R7
	XVMOVQ X0.W[5], R8; SLLV  $6, R8, R8; OR R7, R8, R7
	XVMOVQ X0.W[6], R8; SLLV $12, R8, R8; OR R7, R8, R7
	XVMOVQ X0.W[7], R8; SLLV $18, R8, R8; OR R7, R8, R7
	MOVBU R7, 3(R4); SRLV $8, R7, R7
	MOVBU R7, 4(R4); SRLV $8, R7, R7
	MOVBU R7, 5(R4)
	ADDV $32, R5; ADDV $6, R4
	ADDV $-1, R6; BNE R6, R0, simpleBitPack6Scalar
	RET

// ============================================================
// simpleBitPack6BitsHighBitsGamma88LASX -- HighBits(f,(q-1)/88) packed as 6-bit.
//
// r1 = (((r+127)>>7)*11275 + 2^23) >> 24, then r1==44 -> r1=0
//
// LASX vectorizes HighBits (8 coefs/vector), spills, scalar-packs.
//
// R4 = dst, R5 = f
// ============================================================
TEXT ·simpleBitPack6BitsHighBitsGamma88LASX(SB), NOSPLIT, $0-16
	MOVV dst+0(FP), R4
	MOVV f+8(FP), R5
	MOVV $127,   R7;  XVMOVQ R7, X20.W8
	MOVV $11275, R7;  XVMOVQ R7, X21.W8
	MOVV $1,     R7;  SLLV $23, R7, R7; XVMOVQ R7, X22.W8
	MOVV $43,    R7;  XVMOVQ R7, X23.W8
	MOVV $32,    R6
pack6hbLoop:
	XVMOVQ (R5), X0
	XVADDW X20, X0, X1; XVSRLW $7, X1, X1; XVMULW X21, X1, X1; XVADDW X22, X1, X1; XVSRAW $24, X1, X1
	// r1==44 correction: r1 ^= ((43-r1)>>31) & r1
	XVSUBW X1, X23, X2; XVSRAW $31, X2, X2; XVANDV X2, X1, X2; XVXORV X2, X1, X1
	// Group 0: elements [0,1,2,3] -> 3 bytes
	XVMOVQ X1.W[0], R7; XVMOVQ X1.W[1], R8; SLLV  $6, R8, R8; OR R7, R8, R7
	XVMOVQ X1.W[2], R8; SLLV $12, R8, R8; OR R7, R8, R7
	XVMOVQ X1.W[3], R8; SLLV $18, R8, R8; OR R7, R8, R7
	MOVBU R7, 0(R4); SRLV $8, R7, R7; MOVBU R7, 1(R4); SRLV $8, R7, R7; MOVBU R7, 2(R4)
	// Group 1: elements [4,5,6,7] -> 3 bytes
	XVMOVQ X1.W[4], R7; XVMOVQ X1.W[5], R8; SLLV  $6, R8, R8; OR R7, R8, R7
	XVMOVQ X1.W[6], R8; SLLV $12, R8, R8; OR R7, R8, R7
	XVMOVQ X1.W[7], R8; SLLV $18, R8, R8; OR R7, R8, R7
	MOVBU R7, 3(R4); SRLV $8, R7, R7; MOVBU R7, 4(R4); SRLV $8, R7, R7; MOVBU R7, 5(R4)
	ADDV $32, R5; ADDV $6, R4
	ADDV $-1, R6; BNE R6, R0, pack6hbLoop
	RET

// ============================================================
// bitPackSignedTwoPower17LASX -- encode 256 int32 coefficients as
// 18-bit unsigned values, 9 bytes per 4-coef group.
//
// v = (8511489 - f) mod q  in [0, 2^18-1]
// x = v0 | (v1<<18) | (v2<<36) | (v3<<54)
// out[0..7]=x LE, out[8]=v3>>10
//
// LASX vectorizes fieldSub (8 coefs/iter), spills, scalar-packs.
//
// R4 = dst, R5 = f
// ============================================================
TEXT ·bitPackSignedTwoPower17LASX(SB), NOSPLIT, $0-16
	MOVV dst+0(FP), R4
	MOVV f+8(FP), R5
	MOVV $8511489, R7;  XVMOVQ R7, X30.W8
	MOVV $8380417, R8;  XVMOVQ R8, X31.W8
	MOVV $32, R6
bitPack17Loop:
	XVMOVQ (R5), X0
	XVSUBW X0, X30, X1; XVSUBW X31, X1, X2; XVSRAW $31, X2, X3; XVANDV X3, X31, X3; XVADDW X3, X2, X1
	// Group 0: elements [0..3] -> 9 bytes
	XVMOVQ X1.W[0], R7; XVMOVQ X1.W[1], R8; XVMOVQ X1.W[2], R9; XVMOVQ X1.W[3], R10
	MOVV R7, R11; SLLV $18, R8, R8; OR R8, R11, R11; SLLV $36, R9, R9; OR R9, R11, R11
	MOVV R10, R12; SLLV $54, R12, R12; OR R12, R11, R11
	MOVV R11, 0(R4); SRLV $10, R10, R10; MOVBU R10, 8(R4)
	// Group 1: elements [4..7] -> 9 bytes
	XVMOVQ X1.W[4], R7; XVMOVQ X1.W[5], R8; XVMOVQ X1.W[6], R9; XVMOVQ X1.W[7], R10
	MOVV R7, R11; SLLV $18, R8, R8; OR R8, R11, R11; SLLV $36, R9, R9; OR R9, R11, R11
	MOVV R10, R12; SLLV $54, R12, R12; OR R12, R11, R11
	MOVV R11, 9(R4); SRLV $10, R10, R10; MOVBU R10, 17(R4)
	ADDV $32, R5; ADDV $18, R4
	ADDV $-1, R6; BNE R6, R0, bitPack17Loop
	RET

// ============================================================
// bitPackSignedTwoPower19LASX -- encode 256 int32 coefficients as
// 20-bit unsigned values, 10 bytes per 4-coef group.
//
// v = (8904705 - f) mod q  in [0, 2^20-1]
// x = v0 | (v1<<20) | (v2<<40) | (v3<<60)
// out[0..7]=x LE, out[8..9]=(v3>>4) LE (16-bit)
//
// R4 = dst, R5 = f
// ============================================================
TEXT ·bitPackSignedTwoPower19LASX(SB), NOSPLIT, $0-16
	MOVV dst+0(FP), R4
	MOVV f+8(FP), R5
	MOVV $8904705, R7;  XVMOVQ R7, X30.W8
	MOVV $8380417, R8;  XVMOVQ R8, X31.W8
	MOVV $32, R6
bitPack19Loop:
	XVMOVQ (R5), X0
	XVSUBW X0, X30, X1; XVSUBW X31, X1, X2; XVSRAW $31, X2, X3; XVANDV X3, X31, X3; XVADDW X3, X2, X1
	// Group 0: elements [0..3] -> 10 bytes
	XVMOVQ X1.W[0], R7; XVMOVQ X1.W[1], R8; XVMOVQ X1.W[2], R9; XVMOVQ X1.W[3], R10
	MOVV R7, R11; SLLV $20, R8, R8; OR R8, R11, R11; SLLV $40, R9, R9; OR R9, R11, R11
	MOVV R10, R12; SLLV $60, R12, R12; OR R12, R11, R11
	MOVV R11, 0(R4); SRLV $4, R10, R10; MOVH R10, 8(R4)
	// Group 1: elements [4..7] -> 10 bytes
	XVMOVQ X1.W[4], R7; XVMOVQ X1.W[5], R8; XVMOVQ X1.W[6], R9; XVMOVQ X1.W[7], R10
	MOVV R7, R11; SLLV $20, R8, R8; OR R8, R11, R11; SLLV $40, R9, R9; OR R9, R11, R11
	MOVV R10, R12; SLLV $60, R12, R12; OR R12, R11, R11
	MOVV R11, 10(R4); SRLV $4, R10, R10; MOVH R10, 18(R4)
	ADDV $32, R5; ADDV $20, R4
	ADDV $-1, R6; BNE R6, R0, bitPack19Loop
	RET

// ============================================================
// bitUnpackSignedTwoPower17LASX -- decode 18-bit packed bytes into
// 256 int32 coefficients.
//
// 9 bytes -> 4 coefs:
//   v0 = x[17:0], v1 = x[35:18], v2 = x[53:36], v3 = x[63:54]|(b8<<10)
//   f[i] = (8511489 - v) mod q
//
// Scalar bit-unpack -> stack; LASX vectorizes fieldSub.
//
// R4 = b (input), R5 = f (output)
// ============================================================
TEXT ·bitUnpackSignedTwoPower17LASX(SB), NOSPLIT, $0-16
	MOVV b+0(FP), R4
	MOVV f+8(FP), R5
	MOVV $8511489, R7;  XVMOVQ R7, X30.W8
	MOVV $8380417, R8;  XVMOVQ R8, X31.W8
	MOVV $0x3FFFF, R14
	MOVV $32, R6
bitUnpack17Loop:
	// Group 0: bytes [0..8] -> elements [0..3]
	MOVV  0(R4), R7; MOVBU 8(R4), R8
	MOVV R7, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[0]
	SRLV $18, R7, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[1]
	SRLV $36, R7, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[2]
	SRLV $54, R7, R9; SLLV $10, R8, R8; OR R8, R9, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[3]
	// Group 1: bytes [9..17] -> elements [4..7]
	MOVV  9(R4), R7; MOVBU 17(R4), R8
	MOVV R7, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[4]
	SRLV $18, R7, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[5]
	SRLV $36, R7, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[6]
	SRLV $54, R7, R9; SLLV $10, R8, R8; OR R8, R9, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[7]
	// fieldSub(2^17, v) vectorized
	XVSUBW X0, X30, X1; XVSUBW X31, X1, X2; XVSRAW $31, X2, X3; XVANDV X3, X31, X3; XVADDW X3, X2, X1
	XVMOVQ X1, (R5)
	ADDV $18, R4; ADDV $32, R5
	ADDV $-1, R6; BNE R6, R0, bitUnpack17Loop
	RET

// ============================================================
// bitUnpackSignedTwoPower19LASX -- decode 20-bit packed bytes into
// 256 int32 coefficients.
//
// 10 bytes -> 4 coefs:
//   v0 = x[19:0], v1 = x[39:20], v2 = x[59:40], v3 = x[63:60]|(b16<<4)
//   f[i] = (8904705 - v) mod q
//
// R4 = b (input), R5 = f (output)
// ============================================================
TEXT ·bitUnpackSignedTwoPower19LASX(SB), NOSPLIT, $0-16
	MOVV b+0(FP), R4
	MOVV f+8(FP), R5
	MOVV $8904705, R7;  XVMOVQ R7, X30.W8
	MOVV $8380417, R8;  XVMOVQ R8, X31.W8
	MOVV $0xFFFFF, R14
	MOVV $32, R6
bitUnpack19Loop:
	// Group 0: bytes [0..9] -> elements [0..3]
	MOVV  0(R4), R7; MOVHU 8(R4), R8
	MOVV R7, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[0]
	SRLV $20, R7, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[1]
	SRLV $40, R7, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[2]
	SRLV $60, R7, R9; SLLV $4, R8, R8; OR R8, R9, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[3]
	// Group 1: bytes [10..19] -> elements [4..7]
	MOVV  10(R4), R7; MOVHU 18(R4), R8
	MOVV R7, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[4]
	SRLV $20, R7, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[5]
	SRLV $40, R7, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[6]
	SRLV $60, R7, R9; SLLV $4, R8, R8; OR R8, R9, R9; AND R14, R9, R9; XVMOVQ R9, X0.W[7]
	// fieldSub(2^19, v) vectorized
	XVSUBW X0, X30, X1; XVSUBW X31, X1, X2; XVSRAW $31, X2, X3; XVANDV X3, X31, X3; XVADDW X3, X2, X1
	XVMOVQ X1, (R5)
	ADDV $20, R4; ADDV $32, R5
	ADDV $-1, R6; BNE R6, R0, bitUnpack19Loop
	RET
