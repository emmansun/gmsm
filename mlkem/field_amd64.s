// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// Attribution: The AVX2 vectorization approach used by
// samplePolyCBD2AVX2/samplePolyCBD3AVX2/decodeAndDecompressU11AVX2/decodeAndDecompressU10AVX2
// in this file is inspired by the CRYSTALS-Kyber project: https://github.com/pq-crystals/kyber

DATA nttConsts<>+0x00(SB)/2, $3329 // q
DATA nttConsts<>+0x02(SB)/2, $3327 // qNegInv
DATA nttConsts<>+0x04(SB)/2, $1    // one
DATA nttConsts<>+0x06(SB)/2, $1353 // rr = r^2 mod q (fromMont: MontMul(x, rr) = x*r)
DATA nttConsts<>+0x08(SB)/2, $1441 // inverse NTT final scale for Montgomery acc path: 128⁻¹*r² mod q
GLOBL nttConsts<>(SB), RODATA, $10

#define qConst nttConsts<>+0x00(SB)
#define qNegInvConst nttConsts<>+0x02(SB)
#define oneConst nttConsts<>+0x04(SB)
#define rrConst nttConsts<>+0x06(SB)
#define scale1441Const nttConsts<>+0x08(SB)

// Large AVX2 precomputed tables are declared and initialized in field_amd64.go:
//   ·gammaMulTable
//   ·nttTwiddleL8Precomp
//   ·nttTwiddleL4Precomp
//   ·nttTwiddleL2Precomp

// ── CBD sampling constants ────────────────────────────────────────────────────
DATA decodeU11ShufIdx<>+0x00(SB)/8, $0x0504030202010100
DATA decodeU11ShufIdx<>+0x08(SB)/8, $0x0A09090807060605
DATA decodeU11ShufIdx<>+0x10(SB)/8, $0x0807060505040403
DATA decodeU11ShufIdx<>+0x18(SB)/8, $0x0D0C0C0B0A090908
GLOBL decodeU11ShufIdx<>(SB), RODATA, $32

DATA decodeU11SrlvD<>+0x00(SB)/8, $0x0000000100000000
DATA decodeU11SrlvD<>+0x08(SB)/8, $0x0000000000000000
DATA decodeU11SrlvD<>+0x10(SB)/8, $0x0000000100000000
DATA decodeU11SrlvD<>+0x18(SB)/8, $0x0000000000000000
GLOBL decodeU11SrlvD<>(SB), RODATA, $32

DATA decodeU11SrlvQ<>+0x00(SB)/8, $0x0000000000000000
DATA decodeU11SrlvQ<>+0x08(SB)/8, $0x0000000000000002
DATA decodeU11SrlvQ<>+0x10(SB)/8, $0x0000000000000000
DATA decodeU11SrlvQ<>+0x18(SB)/8, $0x0000000000000002
GLOBL decodeU11SrlvQ<>(SB), RODATA, $32

DATA decodeU11Shift<>+0x00(SB)/8, $0x0020000100040020
DATA decodeU11Shift<>+0x08(SB)/8, $0x0004002000010008
DATA decodeU11Shift<>+0x10(SB)/8, $0x0020000100040020
DATA decodeU11Shift<>+0x18(SB)/8, $0x0004002000010008
GLOBL decodeU11Shift<>(SB), RODATA, $32

DATA decodeU11Mask<>+0x00(SB)/2, $32752 // mask for extracting 11-bit values: 0b0111111111110000
GLOBL decodeU11Mask<>(SB), RODATA, $2

DATA decodeU10ShufIdx<>+0x00(SB)/8, $0x0403030202010100
DATA decodeU10ShufIdx<>+0x08(SB)/8, $0x0908080707060605
DATA decodeU10ShufIdx<>+0x10(SB)/8, $0x0605050404030302
DATA decodeU10ShufIdx<>+0x18(SB)/8, $0x0B0A0A0909080807
GLOBL decodeU10ShufIdx<>(SB), RODATA, $32

DATA decodeU10SllvD<>+0x00(SB)/8, $0x0000000000000004
GLOBL decodeU10SllvD<>(SB), RODATA, $8

DATA decodeU10Q1Const<>+0x00(SB)/4, $0x0D013404 // 4*q + q*2^16 
GLOBL decodeU10Q1Const<>(SB), RODATA, $4

DATA decodeU10MaskConst<>+0x00(SB)/4, $0x7FE01FF8 // mask for extracting 10-bit values: 0b01111111111000000001111111111000
GLOBL decodeU10MaskConst<>(SB), RODATA, $4

// ── CBD sampling constants ────────────────────────────────────────────────────

// cbd2 broadcast masks (32-bit)
DATA cbd2Mask55<>+0x00(SB)/4, $0x55555555
GLOBL cbd2Mask55<>(SB), RODATA, $4

DATA cbd2Mask33<>+0x00(SB)/4, $0x33333333
GLOBL cbd2Mask33<>(SB), RODATA, $4

DATA cbd2Mask0F<>+0x00(SB)/4, $0x0F0F0F0F
GLOBL cbd2Mask0F<>(SB), RODATA, $4

// cbd3 broadcast masks (32-bit unless noted)
// mask249 = 0x00249249  (selects bits 0,3,6,9,12,15,18,21 of each 32-bit word — one bit per 3-bit group)
DATA cbd3Mask249<>+0x00(SB)/4, $0x00249249
GLOBL cbd3Mask249<>(SB), RODATA, $4

// mask6DB = 0x006DB6DB  (sum of 0x00249249<<1 and 0x00249249; used as "add 3 per group" offset)
DATA cbd3Mask6DB<>+0x00(SB)/4, $0x006DB6DB
GLOBL cbd3Mask6DB<>(SB), RODATA, $4

// mask07 = 0x00000007  (isolate low 3-bit group = a value)
DATA cbd3Mask07<>+0x00(SB)/4, $0x00000007
GLOBL cbd3Mask07<>(SB), RODATA, $4

// mask3  = 0x0003 (int16 constant 3; subtract to get a-b from (a, 7-b+3-3) representation)
DATA cbd3Mask3<>+0x00(SB)/2, $3
GLOBL cbd3Mask3<>(SB), RODATA, $2

// cbd3ShufIdx: VPSHUFB table that extracts 3-byte groups from 24-byte input.
// Equivalent to C: _mm256_set_epi8(-1,15,14,13,-1,12,11,10,-1, 9, 8, 7,-1, 6, 5, 4,
//                                  -1,11,10, 9,-1, 8, 7, 6,-1, 5, 4, 3,-1, 2, 1, 0)
// Low  lane (bytes  0..15): groups from buf bytes  0..11
// High lane (bytes 16..31): groups from buf bytes  4..15
DATA cbd3ShufIdx<>+0x00(SB)/8, $0xFF050403FF020100
DATA cbd3ShufIdx<>+0x08(SB)/8, $0xFF0B0A09FF080706
DATA cbd3ShufIdx<>+0x10(SB)/8, $0xFF090807FF060504
DATA cbd3ShufIdx<>+0x18(SB)/8, $0xFF0F0E0DFF0C0B0A
GLOBL cbd3ShufIdx<>(SB), RODATA, $32

DATA compressEncodeMulV<>+0x00(SB)/2, $20159
GLOBL compressEncodeMulV<>(SB), RODATA, $2

DATA compressEncode4Mask<>+0x00(SB)/2, $0x000F
GLOBL compressEncode4Mask<>(SB), RODATA, $2

DATA compressEncode4PermdIdx<>+0x00(SB)/8, $0x0000000400000000
DATA compressEncode4PermdIdx<>+0x08(SB)/8, $0x0000000500000001
DATA compressEncode4PermdIdx<>+0x10(SB)/8, $0x0000000600000002
DATA compressEncode4PermdIdx<>+0x18(SB)/8, $0x0000000700000003
GLOBL compressEncode4PermdIdx<>(SB), RODATA, $32

DATA decompressDecode4Mask<>+0x00(SB)/4, $0x00F0000F
GLOBL decompressDecode4Mask<>(SB), RODATA, $4

DATA decompressDecode4Shift<>+0x00(SB)/4, $0x800800
GLOBL decompressDecode4Shift<>(SB), RODATA, $4

DATA decompressDecode4ShufbIdx<>+0x00(SB)/8, $0x0101010100000000
DATA decompressDecode4ShufbIdx<>+0x08(SB)/8, $0x0303030302020202
DATA decompressDecode4ShufbIdx<>+0x10(SB)/8, $0x0505050504040404
DATA decompressDecode4ShufbIdx<>+0x18(SB)/8, $0x0707070706060606
GLOBL decompressDecode4ShufbIdx<>(SB), RODATA, $32

DATA compressEncode5Mask<>+0x00(SB)/2, $0x001F
GLOBL compressEncode5Mask<>(SB), RODATA, $2

DATA compressEncode5Shift3<>+0x00(SB)/4, $67108865    // 0x04000001
GLOBL compressEncode5Shift3<>(SB), RODATA, $4

DATA compressEncode5SllvdIdx<>+0x00(SB)/8, $0x000000000000000c
GLOBL compressEncode5SllvdIdx<>(SB), RODATA, $8

DATA compressEncode5ShuffleIdx<>+0x00(SB)/8, $0xffffff0403020100
DATA compressEncode5ShuffleIdx<>+0x08(SB)/8, $0xff0c0b0a0908ffff
DATA compressEncode5ShuffleIdx<>+0x10(SB)/8, $0x020100ff0c0b0a09
DATA compressEncode5ShuffleIdx<>+0x18(SB)/8, $0x08ffffffffff0403
GLOBL compressEncode5ShuffleIdx<>(SB), RODATA, $32

DATA decompressDecode5Mask<>+0x00(SB)/8, $0x0f80007c03e0001f
DATA decompressDecode5Mask<>+0x08(SB)/8, $0x00f807c0003e01f0
DATA decompressDecode5Mask<>+0x10(SB)/8, $0x0f80007c03e0001f
DATA decompressDecode5Mask<>+0x18(SB)/8, $0x00f807c0003e01f0
GLOBL decompressDecode5Mask<>(SB), RODATA, $32

DATA decompressDecode5Shift<>+0x00(SB)/8, $0x0008010000200400
DATA decompressDecode5Shift<>+0x08(SB)/8, $0x0080001002000040
DATA decompressDecode5Shift<>+0x10(SB)/8, $0x0008010000200400
DATA decompressDecode5Shift<>+0x18(SB)/8, $0x0080001002000040
GLOBL decompressDecode5Shift<>(SB), RODATA, $32

DATA decompressDecode5ShufbIdx<>+0x00(SB)/8, $0x0201010101000000
DATA decompressDecode5ShufbIdx<>+0x08(SB)/8, $0x0404040303030302
DATA decompressDecode5ShufbIdx<>+0x10(SB)/8, $0x0706060606050505
DATA decompressDecode5ShufbIdx<>+0x18(SB)/8, $0x0909090808080807
GLOBL decompressDecode5ShufbIdx<>(SB), RODATA, $32

DATA compressEncode10ShuffleIdx<>+0x00(SB)/8, $0x0a09080403020100
DATA compressEncode10ShuffleIdx<>+0x08(SB)/8, $0xffffffffffff0c0b
DATA compressEncode10ShuffleIdx<>+0x10(SB)/8, $0xffffffff0c0b0a09
DATA compressEncode10ShuffleIdx<>+0x18(SB)/8, $0x080403020100ffff
GLOBL compressEncode10ShuffleIdx<>(SB), RODATA, $32

DATA compressEncode11Off<>+0x00(SB)/2, $0x0024
GLOBL compressEncode11Off<>(SB), RODATA, $2

DATA compressEncode11SllvdIdx<>+0x00(SB)/8, $0x000000000000000a
GLOBL compressEncode11SllvdIdx<>(SB), RODATA, $8

DATA compressEncode11SrlvdIdx<>+0x00(SB)/8, $0x000000000000000a
DATA compressEncode11SrlvdIdx<>+0x08(SB)/8, $0x000000000000001e
GLOBL compressEncode11SrlvdIdx<>(SB), RODATA, $16

DATA compressEncode11Shift2<>+0x00(SB)/4, $0x08000001
GLOBL compressEncode11Shift2<>(SB), RODATA, $4

DATA compressEncode11ShuffleIdx<>+0x00(SB)/8, $0x0706050403020100
DATA compressEncode11ShuffleIdx<>+0x08(SB)/8, $0xffffffffff0a0908
DATA compressEncode11ShuffleIdx<>+0x10(SB)/8, $0xffff0a0908070605
DATA compressEncode11ShuffleIdx<>+0x18(SB)/8, $0x040302010000ffff
GLOBL compressEncode11ShuffleIdx<>(SB), RODATA, $32

// compress1 thresholds: compress(x,1)=1 iff 833 <= x <= 2496.
DATA compressEncode1Lo<>+0x00(SB)/2, $832
GLOBL compressEncode1Lo<>(SB), RODATA, $2

DATA compressEncode1Hi<>+0x00(SB)/2, $2496
GLOBL compressEncode1Hi<>(SB), RODATA, $2

// MONT_MUL_VEC computes lane-wise Montgomery multiplication YOUT = MontMul(YA, YZ).
// Inputs: YA=value, YZ=multiplier-broadcast.
// Constants: Y15=q, Y14=qNegInv, Y10=one, Y8=zero.
// Clobbers: Y11, Y12, Y13.
#define MONT_MUL_VEC(YA, YZ, YOUT) \
	\ // mul YA by YZ, producing 32-bit products in Y11 (low) and Y12 (high)
	VPMULLW YZ, YA, Y11 \    // lo = (YA * YZ) mod 2^16
	VPMULHUW YZ, YA, Y12 \   // hi = (YA * YZ) >> 16  [unsigned]
	\ // montgomery reduction: m = (t_ab[even] * qNegInv) mod r, t = (t_ab + m*q) / r
	VPMULLW Y14, Y11, Y13 \  // t  = lo * qNegInv mod 2^16
	VPMULHUW Y15, Y13, Y13 \ // correction = (t * q) >> 16
	VPADDW Y13, Y12, Y12 \   // result = hi + correction
	\ // lo==0 edge-case correction (adds 1 when lo != 0):
	VPCMPEQW Y8, Y11, Y13 \  // Y13 = 0xFFFF if lo==0 else 0
	VPADDW Y10, Y13, Y13 \   // Y13 = 0 if lo==0 else 1  (1+0xFFFF=0, 1+0=1)
	VPADDW Y13, Y12, Y12 \   // result += Y13  (adds 1 when lo != 0)
	\ // final conditional subtraction to reduce mod q: if t >= q, subtract q; else keep t
	VPCMPGTW Y12, Y15, Y13 \ // Y13 = 0xFFFF if result < q else 0
	VPANDN Y15, Y13, Y13 \   // Y13 = q if result >= q else 0
	VPSUBW Y13, Y12, YOUT

// BUTTERFLY performs one Cooley-Tukey butterfly on 16 lanes.
// Inputs: YA=a, YB=b, YZ=zeta-broadcast.
// Constants: Y15=q, Y14=qNegInv, Y10=one, Y8=zero.
// Clobbers: Y11, Y12, Y13.
#define BUTTERFLY(YA, YB, YZ) \
	\ // compute t = YZ * YB = Y12
	MONT_MUL_VEC(YB, YZ, Y12) \
	\ // new YB = YA - t
	VPSUBW Y12, YA, YB \
	VPSRAW $15, YB, Y11 \
	VPAND Y15, Y11, Y11 \
	VPADDW Y11, YB, YB \
	\ // new YA = YA + t
	VPADDW Y12, YA, Y12 \
	VPCMPGTW Y12, Y15, Y13 \
	VPANDN Y15, Y13, Y13 \
	VPSUBW Y13, Y12, YA

// INTT_BUTTERFLY performs one Gentleman-Sande (decimation-in-frequency) butterfly on 16 int16 lanes.
// Operation: a' = a + b  (with fieldReduceOnce)
//            b' = zeta * (b - a)  (Montgomery multiply of the difference)
// Inputs:  YA=a, YB=b, YZ=zeta-broadcast (consumed; caller must re-broadcast if reused).
// Constants: Y15=q, Y14=qNegInv, Y10=one, Y8=zero.
// Clobbers: Y9, Y11, Y12, Y13.
// INTT_BUTTERFLY: Gentleman-Sande butterfly.
//   YA' = fieldReduceOnce(YA + YB)
//   YB' = MontMul(YZ, fieldSub(YB, YA_old))
// Constants: Y15=q, Y14=qNegInv, Y10=1, Y8=0.
// Clobbers: Y9, Y11, Y12, Y13.
#define INTT_BUTTERFLY(YA, YB, YZ) \
	VMOVDQA YA, Y9 \
	\ // new YA = YA + YB (mod q, with at most one reduction needed)
	VPADDW YB, YA, YA \
	VPSUBW Y15, YA, Y11 \
	VPSRAW $15, Y11, Y13 \
	VPAND Y15, Y13, Y13 \
	VPADDW Y13, Y11, YA \
	\ // new YB = YZ * (YB - Y9)
	\ // step 1: YB - Y9
	VPSUBW Y9, YB, YB \
	VPSRAW $15, YB, Y12 \
	VPAND Y15, Y12, Y12 \
	VPADDW Y12, YB, YB \
	\ // step 2: MontMul(YZ, YB)
	MONT_MUL_VEC(YB, YZ, YB)

#define nttLevel0(dataAddr, zeta, offset) \
	VMOVDQU (offset*32)(dataAddr), Y0 \
	VMOVDQU (offset*32+256)(dataAddr), Y1 \
	BUTTERFLY(Y0, Y1, zeta) \
	VMOVDQU Y0, (offset*32)(dataAddr) \
	VMOVDQU Y1, (offset*32+256)(dataAddr)

#define nttLevel1(dataAddr, zeta, groupIdx, offset) \
	VMOVDQU (groupIdx*256+32*offset)(dataAddr), Y0 \
	VMOVDQU (groupIdx*256+32*offset+128)(dataAddr), Y1 \
	BUTTERFLY(Y0, Y1, zeta) \
	VMOVDQU Y0, (groupIdx*256+32*offset)(dataAddr) \
	VMOVDQU Y1, (groupIdx*256+32*offset+128)(dataAddr)

#define nttLevel2(dataAddr, zeta, groupIdx, offset) \
	VMOVDQU (groupIdx*128+32*offset)(dataAddr), Y0 \
	VMOVDQU (groupIdx*128+32*offset+64)(dataAddr), Y1 \
	BUTTERFLY(Y0, Y1, zeta) \
	VMOVDQU Y0, (groupIdx*128+32*offset)(dataAddr) \
	VMOVDQU Y1, (groupIdx*128+32*offset+64)(dataAddr)

#define nttLevel3(dataAddr, zeta, groupIdx) \
	VMOVDQU (groupIdx*64)(dataAddr), Y0 \
	VMOVDQU (groupIdx*64+32)(dataAddr), Y1 \
	BUTTERFLY(Y0, Y1, zeta) \
	VMOVDQU Y0, (groupIdx*64)(dataAddr) \
	VMOVDQU Y1, (groupIdx*64+32)(dataAddr)

// internalNTTAVX2 computes full forward NTT layers len=128..2.
TEXT ·internalNTTAVX2(SB), NOSPLIT, $0-8
	MOVQ f+0(FP), AX
	MOVQ $·zetasMontgomery(SB), BX

	VPBROADCASTW qConst, Y15
	VPBROADCASTW qNegInvConst, Y14
	VPBROADCASTW oneConst, Y10
	VPXOR Y8, Y8, Y8

	// Layer len=128, zeta = zetasMontgomery[1], chunk pairs (0,8)..(7,15)
	VPBROADCASTW 2(BX), Y7
	nttLevel0(AX, Y7, 0)
	nttLevel0(AX, Y7, 1)
	nttLevel0(AX, Y7, 2)
	nttLevel0(AX, Y7, 3)
	nttLevel0(AX, Y7, 4)
	nttLevel0(AX, Y7, 5)
	nttLevel0(AX, Y7, 6)
	nttLevel0(AX, Y7, 7)

	// Layer len=64 - batch load 2 zetas for ILP
	// Group 0,1: zeta=zetasMontgomery[2,3]
	VPBROADCASTW 4(BX), Y7
	VPBROADCASTW 6(BX), Y6
	nttLevel1(AX, Y7, 0, 0)
	nttLevel1(AX, Y7, 0, 1)
	nttLevel1(AX, Y7, 0, 2)
	nttLevel1(AX, Y7, 0, 3)
	nttLevel1(AX, Y6, 1, 0)
	nttLevel1(AX, Y6, 1, 1)
	nttLevel1(AX, Y6, 1, 2)
	nttLevel1(AX, Y6, 1, 3)

	// Layer len=32 - batch load 2 zetas for ILP
	// Group 0,1: zeta=zetasMontgomery[4,5]
	VPBROADCASTW 8(BX), Y7
	VPBROADCASTW 10(BX), Y6
	nttLevel2(AX, Y7, 0, 0)
	nttLevel2(AX, Y7, 0, 1)
	nttLevel2(AX, Y6, 1, 0)
	nttLevel2(AX, Y6, 1, 1)

	// Group 2,3: zeta=zetasMontgomery[6,7]
	VPBROADCASTW 12(BX), Y7
	VPBROADCASTW 14(BX), Y6
	nttLevel2(AX, Y7, 2, 0)
	nttLevel2(AX, Y7, 2, 1)
	nttLevel2(AX, Y6, 3, 0)
	nttLevel2(AX, Y6, 3, 1)

	// Layer len=16 - batch load 2 zetas for ILP
	// Group g uses zetasMontgomery[8+g], chunk pairs (2g, 2g+1)
	VPBROADCASTW 16(BX), Y7
	VPBROADCASTW 18(BX), Y6
	nttLevel3(AX, Y7, 0)
	nttLevel3(AX, Y6, 1)

	VPBROADCASTW 20(BX), Y7
	VPBROADCASTW 22(BX), Y6
	nttLevel3(AX, Y7, 2)
	nttLevel3(AX, Y6, 3)

	VPBROADCASTW 24(BX), Y7
	VPBROADCASTW 26(BX), Y6
	nttLevel3(AX, Y7, 4)
	nttLevel3(AX, Y6, 5)

	VPBROADCASTW 28(BX), Y7
	VPBROADCASTW 30(BX), Y6
	nttLevel3(AX, Y7, 6)
	nttLevel3(AX, Y6, 7)

	// Continue with layers len=8, len=4, len=2
len8_start:
	// Layer len=8, groups g=0..15, zeta index = 16+g
	LEAQ ·nttTwiddleL8Precomp(SB), SI
	XORQ CX, CX
	XORQ DI, DI
len8_loop:
	CMPQ CX, $8
	JGE len4_start
	VMOVDQU (SI), Y7

	VMOVDQU (AX)(DI*1), Y6
	VMOVDQU 32(AX)(DI*1), Y1
	VPERM2I128 $0x20, Y1, Y6, Y0
	VPERM2I128 $0x31, Y1, Y6, Y1
	BUTTERFLY(Y0, Y1, Y7)
	VPERM2I128 $0x20, Y1, Y0, Y6
	VPERM2I128 $0x31, Y1, Y0, Y1
	VMOVDQU Y6, (AX)(DI*1)
	VMOVDQU Y1, 32(AX)(DI*1)

	INCQ CX
	ADDQ $32, SI
	ADDQ $64, DI
	JMP len8_loop

	// Layer len=4, groups g=0..31, zeta index = 32+g
len4_start:
	LEAQ ·nttTwiddleL4Precomp(SB), SI
	XORQ CX, CX
	XORQ DI, DI
len4_loop:
	CMPQ CX, $8
	JGE len2_start

	// Load precomputed twiddle vector: [z0*4, z1*4, z2*4, z3*4].
	VMOVDQU (SI), Y7

	// Load 4 contiguous groups (32 coefficients): [g0|g1] and [g2|g3].
	VMOVDQU (AX)(DI*1), Y6
	VMOVDQU 32(AX)(DI*1), Y1

	// Split each group into low/high halves, then pack lows into Y0 and highs into Y2.
	VPERM2I128 $0x01, Y6, Y6, Y3
	VPERM2I128 $0x01, Y1, Y1, Y4
	VPUNPCKLQDQ Y3, Y6, Y0
	VPUNPCKHQDQ Y3, Y6, Y2
	VPUNPCKLQDQ Y4, Y1, Y5
	VPUNPCKHQDQ Y4, Y1, Y3
	VPERM2I128 $0x20, Y5, Y0, Y0
	VPERM2I128 $0x20, Y3, Y2, Y1

	// Butterfly on 4 groups in parallel.
	BUTTERFLY(Y0, Y1, Y7)

	// Repack back to contiguous [g0|g1] and [g2|g3].
	VPUNPCKLQDQ Y1, Y0, Y6
	VPUNPCKHQDQ Y1, Y0, Y1
	VPERM2I128 $0x20, Y1, Y6, Y0
	VPERM2I128 $0x31, Y1, Y6, Y1
	VMOVDQU Y0, (AX)(DI*1)
	VMOVDQU Y1, 32(AX)(DI*1)

	INCQ CX
	ADDQ $32, SI
	ADDQ $64, DI
	JMP len4_loop

	// Layer len=2, groups g=0..63, zeta index = 64+g
len2_start:
	LEAQ ·nttTwiddleL2Precomp(SB), SI
	XORQ CX, CX
	XORQ DI, DI
len2_loop:
	CMPQ CX, $8
	JGE len2_done

	// Load precomputed twiddle vector for 8 groups.
	VMOVDQU (SI), Y7

	// Load 8 contiguous groups (32 coefficients).
	VMOVDQU (AX)(DI*1), Y6
	VMOVDQU 32(AX)(DI*1), Y1

	// Pack low/high halves for each group in twiddle-aligned order.
	VPSHUFD $0xD8, Y6, Y6
	VPSHUFD $0xD8, Y1, Y1
	VPUNPCKLQDQ Y1, Y6, Y0
	VPUNPCKHQDQ Y1, Y6, Y2

	BUTTERFLY(Y0, Y2, Y7)

	// Repack back to contiguous layout.
	VPUNPCKLQDQ Y2, Y0, Y6
	VPUNPCKHQDQ Y2, Y0, Y1
	VPSHUFD $0xD8, Y6, Y6
	VPSHUFD $0xD8, Y1, Y1
	VMOVDQU Y6, (AX)(DI*1)
	VMOVDQU Y1, 32(AX)(DI*1)

	INCQ CX
	ADDQ $32, SI
	ADDQ $64, DI
	JMP len2_loop

len2_done:
	VZEROUPPER
	RET

#define inttLevel0(dataAddr, zeta, scale, offset) \
	VMOVDQU (offset*32)(dataAddr), Y0 \
	VMOVDQU (offset*32+256)(dataAddr), Y1 \
	INTT_BUTTERFLY(Y0, Y1, zeta) \
	MONT_MUL_VEC(Y0, scale, Y0) \
	VMOVDQU Y0, (offset*32)(dataAddr) \
	MONT_MUL_VEC(Y1, scale, Y1) \
	VMOVDQU Y1, (offset*32+256)(dataAddr)

#define inttLevel1(dataAddr, zeta, groupIdx, offset) \
	VMOVDQU (groupIdx*256+32*offset)(dataAddr), Y0 \
	VMOVDQU (groupIdx*256+32*offset+128)(dataAddr), Y1 \
	INTT_BUTTERFLY(Y0, Y1, zeta) \
	VMOVDQU Y0, (groupIdx*256+32*offset)(dataAddr) \
	VMOVDQU Y1, (groupIdx*256+32*offset+128)(dataAddr)

#define inttLevel2(dataAddr, zeta, groupIdx, offset) \
	VMOVDQU (groupIdx*128+32*offset)(dataAddr), Y0 \
	VMOVDQU (groupIdx*128+32*offset+64)(dataAddr), Y1 \
	INTT_BUTTERFLY(Y0, Y1, zeta) \
	VMOVDQU Y0, (groupIdx*128+32*offset)(dataAddr) \
	VMOVDQU Y1, (groupIdx*128+32*offset+64)(dataAddr)

#define inttLevel3(dataAddr, zeta, groupIdx) \
	VMOVDQU (groupIdx*64)(dataAddr), Y0 \
	VMOVDQU (groupIdx*64+32)(dataAddr), Y1 \
	INTT_BUTTERFLY(Y0, Y1, zeta) \
	VMOVDQU Y0, (groupIdx*64)(dataAddr) \
	VMOVDQU Y1, (groupIdx*64+32)(dataAddr)

// internalInverseNTTAVX2 computes the full inverse NTT (all 7 layers) 
// in Gentleman-Sande (decimation-in-frequency) order: len=2→4→8→16→32→64→128 and
// then applies the final scale-by-1441 for the Montgomery accumulator path.
// 1441 = 128⁻¹ * r² mod q.
// AX = f pointer, BX = zetasMontgomery pointer
TEXT ·internalInverseNTTAVX2(SB), NOSPLIT, $0-8
	MOVQ f+0(FP), AX
	MOVQ $·zetasMontgomery(SB), BX

	// Setup YMM constants.
	VPBROADCASTW qConst, Y15
	VPBROADCASTW qNegInvConst, Y14
	VPBROADCASTW oneConst, Y10
	VPXOR Y8, Y8, Y8

	// L6: len=2, 64 groups, zeta = zetasMontgomery[127..64]
	LEAQ ·inttTwiddleL2Precomp(SB), SI
	XORQ CX, CX
	XORQ DI, DI
intt_len2_loop:
	CMPQ CX, $8
	JGE intt_len4_start

	// Load precomputed twiddle vector for 8 groups.
	VMOVDQU (SI), Y7

	// Load 8 contiguous groups (32 coefficients).
	VMOVDQU (AX)(DI*1), Y6
	VMOVDQU 32(AX)(DI*1), Y1

	// Pack low/high halves for each group in twiddle-aligned order.
	VPSHUFD $0xD8, Y6, Y6
	VPSHUFD $0xD8, Y1, Y1
	VPUNPCKLQDQ Y1, Y6, Y0
	VPUNPCKHQDQ Y1, Y6, Y2

	INTT_BUTTERFLY(Y0, Y2, Y7)

	// Repack back to contiguous layout.
	VPUNPCKLQDQ Y2, Y0, Y6
	VPUNPCKHQDQ Y2, Y0, Y1
	VPSHUFD $0xD8, Y6, Y6
	VPSHUFD $0xD8, Y1, Y1
	VMOVDQU Y6, (AX)(DI*1)
	VMOVDQU Y1, 32(AX)(DI*1)

	INCQ CX
	ADDQ $32, SI
	ADDQ $64, DI // next 8 group offset
	JMP intt_len2_loop

	// L5: len=4, 32 groups, zeta = zetasMontgomery[63..32]
intt_len4_start:
	LEAQ ·inttTwiddleL4Precomp(SB), SI
	XORQ CX, CX
	XORQ DI, DI
intt_len4_loop:
	CMPQ CX, $8
	JGE intt_len8_start

	// Load precomputed twiddle vector: [z0*4, z1*4, z2*4, z3*4].
	VMOVDQU (SI), Y7

	// Load 4 contiguous groups (32 coefficients): [g0|g1] and [g2|g3].
	VMOVDQU (AX)(DI*1), Y6
	VMOVDQU 32(AX)(DI*1), Y1

	// Split each group into low/high halves, then pack lows into Y0 and highs into Y2.
	VPERM2I128 $0x01, Y6, Y6, Y3
	VPERM2I128 $0x01, Y1, Y1, Y4
	VPUNPCKLQDQ Y3, Y6, Y0
	VPUNPCKHQDQ Y3, Y6, Y2
	VPUNPCKLQDQ Y4, Y1, Y5
	VPUNPCKHQDQ Y4, Y1, Y3
	VPERM2I128 $0x20, Y5, Y0, Y0
	VPERM2I128 $0x20, Y3, Y2, Y1

	// Inverse butterfly on 4 groups in parallel.
	INTT_BUTTERFLY(Y0, Y1, Y7)

	// Repack back to contiguous [g0|g1] and [g2|g3].
	VPUNPCKLQDQ Y1, Y0, Y6
	VPUNPCKHQDQ Y1, Y0, Y1
	VPERM2I128 $0x20, Y1, Y6, Y0
	VPERM2I128 $0x31, Y1, Y6, Y1
	VMOVDQU Y0, (AX)(DI*1)
	VMOVDQU Y1, 32(AX)(DI*1)

	INCQ CX
	ADDQ $32, SI
	ADDQ $64, DI // next 4 group offset
	JMP intt_len4_loop

	// L4: len=8, 16 groups, zeta = zetasMontgomery[31..16]
intt_len8_start:
	LEAQ ·inttTwiddleL8Precomp(SB), SI
	XORQ CX, CX
	XORQ DI, DI
intt_len8_loop:
	CMPQ CX, $8
	JGE intt_len16_start

	VMOVDQU (SI), Y7

	VMOVDQU (AX)(DI*1), Y6
	VMOVDQU 32(AX)(DI*1), Y1
	VPERM2I128 $0x20, Y1, Y6, Y0
	VPERM2I128 $0x31, Y1, Y6, Y1
	INTT_BUTTERFLY(Y0, Y1, Y7)
	VPERM2I128 $0x20, Y1, Y0, Y6
	VPERM2I128 $0x31, Y1, Y0, Y1
	VMOVDQU Y6, (AX)(DI*1)
	VMOVDQU Y1, 32(AX)(DI*1)

	INCQ CX
	ADDQ $32, SI
	ADDQ $64, DI // next group offset
	JMP intt_len8_loop

intt_len16_start:
	// ── L3: len=16, 8 groups, zeta = zetasMontgomery[15..8] ─────────────
	// group g: fl at g*64 bytes, fr at g*64+32 bytes
	// twiddle index = 15-g → byte offset = (15-g)*2 = 30-g*2
	VPBROADCASTW 30(BX), Y7
	VPBROADCASTW 28(BX), Y6
	inttLevel3(AX, Y7, 0)
	inttLevel3(AX, Y6, 1)

	VPBROADCASTW 26(BX), Y7
	VPBROADCASTW 24(BX), Y6
	inttLevel3(AX, Y7, 2)
	inttLevel3(AX, Y6, 3)

	VPBROADCASTW 22(BX), Y7
	VPBROADCASTW 20(BX), Y6
	inttLevel3(AX, Y7, 4)
	inttLevel3(AX, Y6, 5)

	VPBROADCASTW 18(BX), Y7
	VPBROADCASTW 16(BX), Y6
	inttLevel3(AX, Y7, 6)
	inttLevel3(AX, Y6, 7)

	// ── L2: len=32, 4 groups, zeta = zetasMontgomery[7..4] - batch load 2 zetas for ILP
	// group g: fl at g*128 bytes, fr at g*128+64 bytes
	// twiddle index = 7-g → byte offset = (7-g)*2 = 14-g*2
	VPBROADCASTW 14(BX), Y7
	VPBROADCASTW 12(BX), Y6
	inttLevel2(AX, Y7, 0, 0)
	inttLevel2(AX, Y7, 0, 1)
	inttLevel2(AX, Y6, 1, 0)
	inttLevel2(AX, Y6, 1, 1)

	VPBROADCASTW 10(BX), Y7
	VPBROADCASTW 8(BX), Y6
	inttLevel2(AX, Y7, 2, 0)
	inttLevel2(AX, Y7, 2, 1)
	inttLevel2(AX, Y6, 3, 0)
	inttLevel2(AX, Y6, 3, 1)

	// ── L1: len=64, 2 groups, zeta = zetasMontgomery[3..2] - batch load 2 zetas for ILP
	// group 0: fl at 0, fr at 128 bytes; group 1: fl at 256, fr at 384
	VPBROADCASTW 6(BX), Y7
	VPBROADCASTW 4(BX), Y6
	inttLevel1(AX, Y7, 0, 0)
	inttLevel1(AX, Y7, 0, 1)
	inttLevel1(AX, Y7, 0, 2)
	inttLevel1(AX, Y7, 0, 3)
	inttLevel1(AX, Y6, 1, 0)
	inttLevel1(AX, Y6, 1, 1)
	inttLevel1(AX, Y6, 1, 2)
	inttLevel1(AX, Y6, 1, 3)

	// ── L0: len=128, 1 group, zeta = zetasMontgomery[1] ─────────────────
	// fl at 0..255 bytes (128 × int16), fr at 256..511 bytes
	VPBROADCASTW 2(BX), Y7
	VPBROADCASTW scale1441Const, Y2
	inttLevel0(AX, Y7, Y2, 0)
	inttLevel0(AX, Y7, Y2, 1)
	inttLevel0(AX, Y7, Y2, 2)
	inttLevel0(AX, Y7, Y2, 3)
	inttLevel0(AX, Y7, Y2, 4)
	inttLevel0(AX, Y7, Y2, 5)
	inttLevel0(AX, Y7, Y2, 6)
	inttLevel0(AX, Y7, Y2, 7)

	VZEROUPPER
	RET

// internalNTTMulAccAVX2 computes acc[i] += NTT_MulAcc(lhs, rhs)[i] for all 256 coefficients,
// using Montgomery multiplication. Implements nttMontMulAcc in AVX2.
//
// For each pair (i, i+1):
//   acc[i]   += MontMul(a0,b0) + MontMul(MontMul(a1,b1), gamma[i/2])
//   acc[i+1] += MontMul(a0,b1) + MontMul(a1,b0)
//
// Strategy: process 8 pairs (16 elements) per YMM iteration using VPHADDW
// to combine pair results and VPUNPCKLWD to re-interleave even/odd updates.
//
// gammaMulTable contains [r, γ[0], r, γ[1], ...] (r=2285=Montgomery 1).
// MontMul(x, r) = x, so even entries act as identity for MontMul.
//
// func internalNTTMulAccAVX2(acc, lhs, rhs *nttElement)
TEXT ·internalNTTMulAccAVX2(SB), NOSPLIT, $0-24
	MOVQ acc+0(FP), AX
	MOVQ lhs+8(FP), BX
	MOVQ rhs+16(FP), DX

	VPBROADCASTW qConst, Y15
	VPBROADCASTW qNegInvConst, Y14
	VPBROADCASTW oneConst, Y10
	VPXOR Y8, Y8, Y8

	LEAQ ·gammaMulTable(SB), SI
	XORQ DI, DI           // DI = block byte offset (0..480 step 32)

nttmlacc_loop:
	CMPQ DI, $512
	JGE nttmlacc_done

	// Load 8 pairs (16 × int16) from lhs, rhs, acc, and gammaMulTable.
	VMOVDQU (BX)(DI*1), Y0    // Y0 = lhs[DI/2 .. DI/2+15]
	VMOVDQU (DX)(DI*1), Y1    // Y1 = rhs
	VMOVDQU (AX)(DI*1), Y2    // Y2 = acc
	VMOVDQU (SI)(DI*1), Y3    // Y3 = [r,γ[k], r,γ[k+1], ...] 8 entries

	// Y4 = rhs with adjacent pairs swapped: [b1,b0, b3,b2, ...]
	VPSHUFLW $0xB1, Y1, Y4
	VPSHUFHW $0xB1, Y4, Y4

	// Y5 = t_ab = MontMul(lhs, rhs) = [a0*b0, a1*b1, a2*b2, ...]
	MONT_MUL_VEC(Y0, Y1, Y5)

	// Y6 = t_cross = MontMul(lhs, rhs_swapped) = [a0*b1, a1*b0, a2*b3, ...]
	MONT_MUL_VEC(Y0, Y4, Y6)

	// Y7 = t_scaled = MontMul(t_ab, gamma):
	//   even positions: MontMul(a0*b0, r) = a0*b0
	//   odd positions:  MontMul(a1*b1, γ[k]) = γ[k]*a1*b1
	MONT_MUL_VEC(Y5, Y3, Y7)

	// Horizontal add pairs to combine even/odd contributions:
	//   Y7 → [a0*b0 + γ[k]*a1*b1, ...] (4 values per 128-bit lane, doubled)
	//   Y6 → [a0*b1 + a1*b0, ...]       (4 values per 128-bit lane, doubled)
	VPHADDW Y7, Y7, Y7
	VPHADDW Y6, Y6, Y6

	// fieldReduceOnce on both hadd results (values in [0, 2q))
	VPCMPGTW Y7, Y15, Y11
	VPANDN Y15, Y11, Y11
	VPSUBW Y11, Y7, Y7

	VPCMPGTW Y6, Y15, Y11
	VPANDN Y15, Y11, Y11
	VPSUBW Y11, Y6, Y6

	// Re-interleave even (Y7) and odd (Y6) sums:
	//   VPUNPCKLWD takes low 4 words per lane from each src
	//   Result: [Y7[0],Y6[0], Y7[1],Y6[1], Y7[2],Y6[2], Y7[3],Y6[3] | ...]
	//         = [acc[0]_delta, acc[1]_delta, acc[2]_delta, ...]
	VPUNPCKLWD Y6, Y7, Y5

	// Add update to acc, then fieldReduceOnce (sum in [0, 2q))
	VPADDW Y5, Y2, Y2
	VPCMPGTW Y2, Y15, Y11
	VPANDN Y15, Y11, Y11
	VPSUBW Y11, Y2, Y2

	VMOVDQU Y2, (AX)(DI*1)

	ADDQ $32, DI
	JMP nttmlacc_loop

nttmlacc_done:
	VZEROUPPER
	RET

TEXT ·internalNTTMulAVX2(SB), NOSPLIT, $0-24
	MOVQ acc+0(FP), AX
	MOVQ lhs+8(FP), BX
	MOVQ rhs+16(FP), DX

	VPBROADCASTW qConst, Y15
	VPBROADCASTW qNegInvConst, Y14
	VPBROADCASTW oneConst, Y10
	VPXOR Y8, Y8, Y8

	LEAQ ·gammaMulTable(SB), SI
	XORQ DI, DI           // DI = block byte offset (0..480 step 32)

nttml_loop:
	CMPQ DI, $512
	JGE nttml_done

	// Load 8 pairs (16 × int16) from lhs, rhs, acc, and gammaMulTable.
	VMOVDQU (BX)(DI*1), Y0    // Y0 = lhs[DI/2 .. DI/2+15]
	VMOVDQU (DX)(DI*1), Y1    // Y1 = rhs
	VMOVDQU (AX)(DI*1), Y2    // Y2 = acc
	VMOVDQU (SI)(DI*1), Y3    // Y3 = [r,γ[k], r,γ[k+1], ...] 8 entries

	// Y4 = rhs with adjacent pairs swapped: [b1,b0, b3,b2, ...]
	VPSHUFLW $0xB1, Y1, Y4
	VPSHUFHW $0xB1, Y4, Y4

	// Y5 = t_ab = MontMul(lhs, rhs) = [a0*b0, a1*b1, a2*b2, ...]
	MONT_MUL_VEC(Y0, Y1, Y5)

	// Y6 = t_cross = MontMul(lhs, rhs_swapped) = [a0*b1, a1*b0, a2*b3, ...]
	MONT_MUL_VEC(Y0, Y4, Y6)

	// Y7 = t_scaled = MontMul(t_ab, gamma):
	//   even positions: MontMul(a0*b0, r) = a0*b0
	//   odd positions:  MontMul(a1*b1, γ[k]) = γ[k]*a1*b1
	MONT_MUL_VEC(Y5, Y3, Y7)

	// Horizontal add pairs to combine even/odd contributions:
	//   Y7 → [a0*b0 + γ[k]*a1*b1, ...] (4 values per 128-bit lane, doubled)
	//   Y6 → [a0*b1 + a1*b0, ...]       (4 values per 128-bit lane, doubled)
	VPHADDW Y7, Y7, Y7
	VPHADDW Y6, Y6, Y6

	// fieldReduceOnce on both hadd results (values in [0, 2q))
	VPCMPGTW Y7, Y15, Y11
	VPANDN Y15, Y11, Y11
	VPSUBW Y11, Y7, Y7

	VPCMPGTW Y6, Y15, Y11
	VPANDN Y15, Y11, Y11
	VPSUBW Y11, Y6, Y6

	// Re-interleave even (Y7) and odd (Y6) sums:
	//   VPUNPCKLWD takes low 4 words per lane from each src
	//   Result: [Y7[0],Y6[0], Y7[1],Y6[1], Y7[2],Y6[2], Y7[3],Y6[3] | ...]
	//         = [acc[0]_delta, acc[1]_delta, acc[2]_delta, ...]
	VPUNPCKLWD Y6, Y7, Y5

	VMOVDQU Y5, (AX)(DI*1)

	ADDQ $32, DI
	JMP nttml_loop

nttml_done:
	VZEROUPPER
	RET

// internalNTTMulAccKeyGenAVX2 computes acc[i] += MulAcc(lhs, rhs)[i] for all 256 coefficients
// using standard (Barrett) domain arithmetic — matching nttMulAccGeneric.
//
// Identical to internalNTTMulAccAVX2 except the Montgomery-domain delta is converted back
// to the standard domain via MontMul(delta, rr) = delta * r, before accumulating into acc.
// rr = r^2 mod q = 1353; MontMul(x, rr) = x * r^2 * r^{-1} = x * r = toStandard(x).
//
// func internalNTTMulAccKeyGenAVX2(acc, lhs, rhs *nttElement)
TEXT ·internalNTTMulAccKeyGenAVX2(SB), NOSPLIT, $0-24
	MOVQ acc+0(FP), AX
	MOVQ lhs+8(FP), BX
	MOVQ rhs+16(FP), DX

	VPBROADCASTW qConst, Y15
	VPBROADCASTW qNegInvConst, Y14
	VPBROADCASTW oneConst, Y10
	VPXOR Y8, Y8, Y8
	VPBROADCASTW rrConst, Y9       // Y9 = rr = 1353; MontMul(x, Y9) converts Mont -> standard

	LEAQ ·gammaMulTable(SB), SI
	XORQ DI, DI           // DI = block byte offset (0..480 step 32)

nttmlacc_kg_loop:
	CMPQ DI, $512
	JGE nttmlacc_kg_done

	// Load 8 pairs (16 × int16) from lhs, rhs, acc, and gammaMulTable.
	VMOVDQU (BX)(DI*1), Y0    // Y0 = lhs[DI/2 .. DI/2+15]
	VMOVDQU (DX)(DI*1), Y1    // Y1 = rhs
	VMOVDQU (AX)(DI*1), Y2    // Y2 = acc
	VMOVDQU (SI)(DI*1), Y3    // Y3 = [r,γ[k], r,γ[k+1], ...] 8 entries

	// Y4 = rhs with adjacent pairs swapped: [b1,b0, b3,b2, ...]
	VPSHUFLW $0xB1, Y1, Y4
	VPSHUFHW $0xB1, Y4, Y4

	// Y5 = t_ab = MontMul(lhs, rhs) = [a0*b0, a1*b1, ...]
	MONT_MUL_VEC(Y0, Y1, Y5)

	// Y6 = t_cross = MontMul(lhs, rhs_swapped) = [a0*b1, a1*b0, ...]
	MONT_MUL_VEC(Y0, Y4, Y6)

	// Y7 = MontMul(t_ab, gamma): even=a0*b0, odd=γ[k]*a1*b1 (all Montgomery domain)
	MONT_MUL_VEC(Y5, Y3, Y7)

	// Horizontal add pairs to combine even/odd contributions
	VPHADDW Y7, Y7, Y7
	VPHADDW Y6, Y6, Y6

	// fieldReduceOnce on both hadd results (values in [0, 2q))
	VPCMPGTW Y7, Y15, Y11
	VPANDN Y15, Y11, Y11
	VPSUBW Y11, Y7, Y7

	VPCMPGTW Y6, Y15, Y11
	VPANDN Y15, Y11, Y11
	VPSUBW Y11, Y6, Y6

	// Re-interleave even (Y7) and odd (Y6) sums -> Y5 (Montgomery-domain delta)
	VPUNPCKLWD Y6, Y7, Y5

	// Convert delta from Montgomery domain to standard domain:
	//   MontMul(Y5, rr) = Y5 * rr * r^{-1} = Y5 * r^2 * r^{-1} = Y5 * r
	MONT_MUL_VEC(Y5, Y9, Y5)

	// Add standard-domain delta to acc, then fieldReduceOnce
	VPADDW Y5, Y2, Y2
	VPCMPGTW Y2, Y15, Y11
	VPANDN Y15, Y11, Y11
	VPSUBW Y11, Y2, Y2

	VMOVDQU Y2, (AX)(DI*1)

	ADDQ $32, DI
	JMP nttmlacc_kg_loop

nttmlacc_kg_done:
	VZEROUPPER
	RET

// decodeAndDecompressU10AVX2 decodes and decompresses d=10 ciphertext chunks
// into ring elements. It processes 16 coefficients per AVX2 iteration.
// func decodeAndDecompressU10AVX2(dst []ringElement, c []byte)
TEXT ·decodeAndDecompressU10AVX2(SB), NOSPLIT, $32-48
	MOVQ dst_base+0(FP), AX
	MOVQ dst_len+8(FP), BX
	MOVQ c_base+24(FP), CX

	TESTQ BX, BX
	JLE decode_u10_done

	VMOVDQU decodeU10ShufIdx<>(SB), Y9
	VPBROADCASTQ decodeU10SllvD<>(SB), Y10
	VPBROADCASTD decodeU10MaskConst<>(SB), Y11
	VPBROADCASTD decodeU10Q1Const<>(SB), Y12

decode_u10_ring_loop:
	MOVQ CX, SI // input pointer for this ring
	MOVQ AX, DI // output pointer for this ring
	MOVQ $15, DX

decode_u10_block_loop:
	VMOVDQU (SI), Y0
	VPERMQ $0x94, Y0, Y0
	VPSHUFB Y9, Y0, Y0
	VPSLLVD Y10, Y0, Y0
	VPSRLW $1, Y0, Y0
	VPAND Y11, Y0, Y0
	VPMULHRSW Y12, Y0, Y0
	VMOVDQU Y0, (DI)

	ADDQ $20, SI
	ADDQ $32, DI
	DECQ DX
	JNZ decode_u10_block_loop

	// Tail: copy the final 20 bytes to a zero-padded 32-byte local buffer.
	VPXOR Y1, Y1, Y1
	VMOVDQU Y1, 0(SP)
	MOVOU 300(CX), X2
	MOVOU X2, 0(SP)
	MOVL 316(CX), R8
	MOVL R8, 16(SP)

	VMOVDQU 0(SP), Y0
	VPERMQ $0x94, Y0, Y0
	VPSHUFB Y9, Y0, Y0
	VPSLLVD Y10, Y0, Y0
	VPSRLW $1, Y0, Y0
	VPAND Y11, Y0, Y0
	VPMULHRSW Y12, Y0, Y0
	VMOVDQU Y0, 480(AX)

	ADDQ $512, AX
	ADDQ $320, CX
	DECQ BX
	JNZ decode_u10_ring_loop

decode_u10_done:
	VZEROUPPER
	RET

// decodeAndDecompressU11AVX2 decodes and decompresses d=11 ciphertext chunks
// into ring elements. It processes 16 coefficients per AVX2 iteration.
// func decodeAndDecompressU11AVX2(dst []ringElement, c []byte)
TEXT ·decodeAndDecompressU11AVX2(SB), NOSPLIT, $32-48
	MOVQ dst_base+0(FP), AX
	MOVQ dst_len+8(FP), BX
	MOVQ c_base+24(FP), CX

	TESTQ BX, BX
	JLE decode_u11_done

	VMOVDQU decodeU11ShufIdx<>(SB), Y9
	VMOVDQU decodeU11SrlvD<>(SB), Y10
	VMOVDQU decodeU11SrlvQ<>(SB), Y11
	VMOVDQU decodeU11Shift<>(SB), Y12
	VPBROADCASTW decodeU11Mask<>(SB), Y13
	VPBROADCASTW qConst, Y14

decode_u11_ring_loop:
	MOVQ CX, SI // input pointer for this ring
	MOVQ AX, DI // output pointer for this ring
	MOVQ $15, DX

decode_u11_block_loop:
	VMOVDQU (SI), Y0
	VPERMQ $0x94, Y0, Y0
	VPSHUFB Y9, Y0, Y0
	VPSRLVD Y10, Y0, Y0
	VPSRLVQ Y11, Y0, Y0
	VPMULLW Y12, Y0, Y0
	VPSRLW $1, Y0, Y0
	VPAND Y13, Y0, Y0
	VPMULHRSW Y14, Y0, Y0
	VMOVDQU Y0, (DI)

	ADDQ $22, SI
	ADDQ $32, DI
	DECQ DX
	JNZ decode_u11_block_loop

	// Tail: copy the final 22 bytes to a zero-padded 32-byte local buffer.
	VPXOR Y1, Y1, Y1
	VMOVDQU Y1, 0(SP)
	MOVOU 330(CX), X2
	MOVOU X2, 0(SP)
	MOVL 346(CX), R8
	MOVL R8, 16(SP)
	MOVWLZX 350(CX), R8
	MOVW R8, 20(SP)

	VMOVDQU 0(SP), Y0
	VPERMQ $0x94, Y0, Y0
	VPSHUFB Y9, Y0, Y0
	VPSRLVD Y10, Y0, Y0
	VPSRLVQ Y11, Y0, Y0
	VPMULLW Y12, Y0, Y0
	VPSRLW $1, Y0, Y0
	VPAND Y13, Y0, Y0
	VPMULHRSW Y14, Y0, Y0
	VMOVDQU Y0, 480(AX)

	ADDQ $512, AX
	ADDQ $352, CX
	DECQ BX
	JNZ decode_u11_ring_loop

decode_u11_done:
	VZEROUPPER
	RET

// samplePolyCBD2AVX2 computes 256 coefficients of the Dη=2 distribution from
// 128 pre-computed PRF bytes. It processes N/64=4 iterations, each consuming
// one 32-byte AVX2 register and producing 64 int16 coefficients.
//
// Per 32-byte chunk → 64 int16 coefficients:
//   f1 = f0>>1; f0 &= mask55; f1 &= mask55; f0 = f0+f1
//   f1 = f0>>2; f0 &= mask33; f1 &= mask33; f0 = f0+mask33-f1
//   f1 = f0>>4; f0 &= mask0F; f1 &= mask0F; f0 = f0-mask03; f1 = f1-mask03
//   // each byte now holds a signed coeff in [-2,2]
//   f2 = unpacklo_epi8(f0,f1); f3 = unpackhi_epi8(f0,f1)
//   // sign-extend int8→int16 for all 4 output quadrants
//   store VPMOVSXBW(lo128 of f2), VPMOVSXBW(lo128 of f3)
//   store VPMOVSXBW(hi128 of f2), VPMOVSXBW(hi128 of f3)
//   // coefficients are in [q-2 .. 2] after fieldSub semantics; VPMOVSXBW gives
//   // negative values as 2's-complement int16, which fieldReduceOnce corrects.
//   // However: Go fieldElement is uint16 and uses fieldSub(a,b)=a-b+q; the
//   // values here are stored directly as uint16 in [q-2, q-1, 0, 1, 2].
//   // To match: after sign-extend, add q to negative values.
//
// func samplePolyCBD2AVX2(f *ringElement, buf *[128]byte)
TEXT ·samplePolyCBD2AVX2(SB), NOSPLIT, $0-16
	MOVQ f+0(FP), AX
	MOVQ buf+8(FP), BX

	VPBROADCASTD cbd2Mask55<>(SB), Y8    // Y8  = 0x55555555
	VPBROADCASTD cbd2Mask33<>(SB), Y9    // Y9  = 0x33333333
	VPBROADCASTD cbd2Mask0F<>(SB), Y11   // Y11 = 0x0F0F0F0F
	VPBROADCASTW qConst, Y12             // Y12 = q
	VPAND Y9, Y11, Y10	                 // Y10 = 0x03030303

	MOVQ $4, CX
	XORQ DI, DI

cbd2_loop:
	VMOVDQU (BX), Y0

	// Step 1: bit-pair popcounts
	VPSRLW  $1, Y0, Y1
	VPAND   Y8, Y0, Y0
	VPAND   Y8, Y1, Y1
	VPADDUSB Y1, Y0, Y0

	// Step 2: sum adjacent pairs, biased by mask33
	VPSRLW  $2, Y0, Y1
	VPAND   Y9, Y0, Y0
	VPAND   Y9, Y1, Y1
	VPADDUSB Y9, Y0, Y0
	VPSUBB  Y1, Y0, Y0

	// Step 3: isolate nibble pairs as signed bytes
	VPSRLW  $4, Y0, Y1
	VPAND   Y11, Y0, Y0
	VPAND   Y11, Y1, Y1
	VPSUBB  Y10, Y0, Y0
	VPSUBB  Y10, Y1, Y1

	// Interleave even/odd coefficient bytes
	VPUNPCKLBW Y1, Y0, Y2
	VPUNPCKHBW Y1, Y0, Y3

	// Sign-extend int8â†’int16 and map negative to [0,q): add q where val<0
	VPMOVSXBW X2, Y4
	VPSRAW    $15, Y4, Y5
	VPAND     Y12, Y5, Y5
	VPADDW    Y5, Y4, Y4
	VMOVDQU   Y4, 0(AX)(DI*1)

	VPMOVSXBW X3, Y4
	VPSRAW    $15, Y4, Y5
	VPAND     Y12, Y5, Y5
	VPADDW    Y5, Y4, Y4
	VMOVDQU   Y4, 32(AX)(DI*1)

	VEXTRACTI128 $1, Y2, X2
	VPMOVSXBW X2, Y4
	VPSRAW    $15, Y4, Y5
	VPAND     Y12, Y5, Y5
	VPADDW    Y5, Y4, Y4
	VMOVDQU   Y4, 64(AX)(DI*1)

	VEXTRACTI128 $1, Y3, X3
	VPMOVSXBW X3, Y4
	VPSRAW    $15, Y4, Y5
	VPAND     Y12, Y5, Y5
	VPADDW    Y5, Y4, Y4
	VMOVDQU   Y4, 96(AX)(DI*1)

	ADDQ $32, BX
	ADDQ $128, DI
	DECQ CX
	JNZ  cbd2_loop

	VZEROUPPER
	RET

// samplePolyCBD3AVX2 computes 256 coefficients of the DÎ·=3 distribution from
// 192 pre-computed PRF bytes. It processes 8 iterations, each consuming 24 bytes
// and producing 32 int16 coefficients.
//
// func samplePolyCBD3AVX2(f *ringElement, buf *[192]byte)
TEXT ·samplePolyCBD3AVX2(SB), NOSPLIT, $0-16
	MOVQ f+0(FP), AX
	MOVQ buf+8(FP), BX

	VMOVDQU  cbd3ShufIdx<>(SB), Y15      // Y15 = shufbidx (invariant across iterations)
	VPBROADCASTD cbd3Mask249<>(SB), Y8   // Y8  = 0x00249249
	VPBROADCASTD cbd3Mask6DB<>(SB), Y9   // Y9  = 0x006DB6DB
	VPBROADCASTD cbd3Mask07<>(SB),  Y10  // Y10 = 0x00000007
	VPBROADCASTW cbd3Mask3<>(SB),   Y12  // Y12 = 3 (int16)
	VPBROADCASTW qConst, Y13             // Y13 = q = 3329
	VPSLLD $16, Y10, Y11                 // Y11 = 0x00070000

	XORQ SI, SI   // input  byte offset (0, 24, 48, ..., 168)
	XORQ DI, DI   // output byte offset (0, 64, ..., 448)

cbd3_loop:
	CMPQ DI, $512
	JGE  cbd3_done

	// Load 32 bytes overlapping the 24-byte chunk
	VMOVDQU (BX)(SI*1), Y0

	// Align 3-byte groups across lanes:
	//   dst[0]=src[0], dst[1]=src[1], dst[2]=src[1], dst[3]=src[2]
	VPERMQ  $0x94, Y0, Y0
	VPSHUFB Y15, Y0, Y0          // 4 x zero-padded 3-byte dwords per 128-bit lane

	// 3-bit group sums: f0[bit 3k] = popcount(input bits 3k..3k+2) in [0,3]
	VPSRLD  $1, Y0, Y1
	VPSRLD  $2, Y0, Y2
	VPAND   Y8, Y0, Y0
	VPAND   Y8, Y1, Y1
	VPAND   Y8, Y2, Y2
	VPADDD  Y1, Y0, Y0
	VPADDD  Y2, Y0, Y0

	// After (f0+mask6DB)-(f0>>3): each 3-bit group k holds (coeff_k+3) in [0,6]
	VPSRLD  $3, Y0, Y1
	VPADDD  Y9, Y0, Y0
	VPSUBD  Y1, Y0, Y0

	// Extract two int16 coefficients per dword via mask07/mask70
	VPSLLD  $10, Y0, Y1
	VPSRLD  $12, Y0, Y2
	VPSRLD  $2,  Y0, Y3
	VPAND   Y10, Y0, Y4
	VPAND   Y11, Y1, Y1
	VPAND   Y10, Y2, Y2
	VPAND   Y11, Y3, Y3
	VPADDW  Y1, Y4, Y4
	VPADDW  Y3, Y2, Y2
	VPSUBW  Y12, Y4, Y4
	VPSUBW  Y12, Y2, Y2

	// Interleave dwords then concat 128-bit halves -> 32 contiguous int16s
	VPUNPCKLDQ Y2, Y4, Y5
	VPUNPCKHDQ Y2, Y4, Y6
	VPERM2I128 $0x20, Y6, Y5, Y0
	VPERM2I128 $0x31, Y6, Y5, Y1

	// Map to fieldElement range [0,q): add q to negative values
	VPSRAW  $15, Y0, Y6
	VPAND   Y13, Y6, Y6
	VPADDW  Y6, Y0, Y0

	VPSRAW  $15, Y1, Y6
	VPAND   Y13, Y6, Y6
	VPADDW  Y6, Y1, Y1

	VMOVDQU Y0, 0(AX)(DI*1)
	VMOVDQU Y1, 32(AX)(DI*1)

	ADDQ $24, SI
	ADDQ $64, DI
	JMP  cbd3_loop

cbd3_done:
	VZEROUPPER
	RET

// polyAddAssignAVX2 computes dst[i] = fieldAdd(dst[i], src[i]) for all i in [0, 256).
// Uses AVX2 to process 32 int16 values (64 bytes) per iteration.
TEXT ·polyAddAssignAVX2(SB), NOSPLIT, $0-16
	MOVQ dst+0(FP), AX
	MOVQ src+8(FP), CX

	VPBROADCASTW qConst, Y15

	XORQ DI, DI

poly_add_loop:
	CMPQ DI, $512
	JGE poly_add_done

	VMOVDQU (AX)(DI*1), Y0
	VMOVDQU 32(AX)(DI*1), Y1
	VMOVDQU (CX)(DI*1), Y2
	VMOVDQU 32(CX)(DI*1), Y3

	VPADDW Y2, Y0, Y0
	VPADDW Y3, Y1, Y1

	VPCMPGTW Y0, Y15, Y4  // Y4 = 0xFFFF if result < q else 0
	VPANDN Y15, Y4, Y4    // Y4 = q if result >= q else 0
	VPSUBW Y4, Y0, Y0

	VPCMPGTW Y1, Y15, Y5  // Y5 = 0xFFFF if result < q else 0
	VPANDN Y15, Y5, Y5    // Y5 = q if result >= q else 0
	VPSUBW Y5, Y1, Y1

	VMOVDQU Y0, (AX)(DI*1)
	VMOVDQU Y1, 32(AX)(DI*1)

	ADDQ $64, DI
	JMP poly_add_loop

poly_add_done:
	VZEROUPPER
	RET

// polySubAssignAVX2 computes dst[i] = fieldSub(dst[i], src[i]) for all i in [0, 256).
// fieldSub: x = uint16(a - b + q); return fieldReduceOnce(x)
TEXT ·polySubAssignAVX2(SB), NOSPLIT, $0-16
	MOVQ dst+0(FP), AX
	MOVQ src+8(FP), CX

	VPBROADCASTW qConst, Y15

	XORQ DI, DI

poly_sub_loop:
	CMPQ DI, $512
	JGE poly_sub_done

	VMOVDQU (AX)(DI*1), Y0
	VMOVDQU 32(AX)(DI*1), Y1
	VMOVDQU (CX)(DI*1), Y2
	VMOVDQU 32(CX)(DI*1), Y3

	// Compute dst - src + q
	VPADDW Y15, Y0, Y0      // Y0 = dst + q
	VPSUBW Y2, Y0, Y0       // Y0 = dst + q - src

	VPADDW Y15, Y1, Y1      // Y1 = dst + q
	VPSUBW Y3, Y1, Y1       // Y1 = dst + q - src

	// Reduce once: if >= q, subtract q
	VPCMPGTW Y0, Y15, Y4    // Y4 = 0xFFFF if result >= q else 0
	VPANDN Y15, Y4, Y4      // Y4 = q if result >= q else 0
	VPSUBW Y4, Y0, Y0

	VPCMPGTW Y1, Y15, Y5    // Y5 = 0xFFFF if result >= q else 0
	VPANDN Y15, Y5, Y5      // Y5 = q if result >= q else 0
	VPSUBW Y5, Y1, Y1

	VMOVDQU Y0, (AX)(DI*1)
	VMOVDQU Y1, 32(AX)(DI*1)

	ADDQ $64, DI
	JMP poly_sub_loop

poly_sub_done:
	VZEROUPPER
	RET

// ringCompressAndEncode4AVX2 computes ByteEncode_4(Compress_4(f)).
//
// For each coefficient x in [0, q):
//   c = compress(x, 4) = round((16*x)/q) mod 16.
//
// Vector math used here:
//   t1 = high16(x * 20159)
//   c  = round((t1 * 512) / 2^15)
//
// Since 20159/2^22 is a close fixed-point approximation of 16/q,
// this computes the same 4-bit compressed value as compress(x, 4)
// for ML-KEM input range x in [0, 3328].
//
// Packing layout matches generic implementation:
//   out[i/2] = c[2*i] | (c[2*i+1] << 4)
// for i = 0..127.
//
// func ringCompressAndEncode4AVX2(out []byte, f *ringElement)
TEXT ·ringCompressAndEncode4AVX2(SB), NOSPLIT, $0
	MOVQ out_base+0(FP), AX
	MOVQ f_base+24(FP), BX

	VPBROADCASTW oneConst, Y0
	VPSLLW $9, Y0, Y11  // Y11 = 512
	VPSLLW $12, Y0, Y12 // Y12 = 4096
	VPADDW Y0, Y12, Y12 // Y12 = 4097
	VMOVDQU  compressEncode4PermdIdx<>(SB), Y13
	VPBROADCASTW compressEncodeMulV<>(SB), Y14
	VPBROADCASTW compressEncode4Mask<>(SB), Y15
	
	XORQ DI, DI
	XORQ CX, CX

compress_encode_loop:
	CMPQ DI, $512
	JGE compress_encode_done

	// Load 64 coefficients (4 x YMM, each 16 x int16).
	VMOVDQU (BX)(DI*1), Y0
	VMOVDQU 32(BX)(DI*1), Y1
	VMOVDQU 64(BX)(DI*1), Y2
	VMOVDQU 96(BX)(DI*1), Y3

	// Per-lane compress to 4 bits:
	// 1) VPMULHW with 20159 approximates x * (16/q) in fixed-point.
	// 2) VPMULHRSW with 512 applies round-to-nearest.
	// 3) mask low nibble.
	VPMULHW Y14, Y0, Y0
	VPMULHW Y14, Y1, Y1
	VPMULHW Y14, Y2, Y2
	VPMULHW Y14, Y3, Y3
	VPMULHRSW Y11, Y0, Y0
	VPMULHRSW Y11, Y1, Y1
	VPMULHRSW Y11, Y2, Y2
	VPMULHRSW Y11, Y3, Y3
	VPAND Y15, Y0, Y0
	VPAND Y15, Y1, Y1
	VPAND Y15, Y2, Y2
	VPAND Y15, Y3, Y3

	// Pack 16-bit nibbles to bytes, then combine byte pairs as lo | (hi<<4).
	// VPMADDUBSW with 4097 does: b0*1 + b1*16 for each adjacent byte pair.
	VPACKUSWB Y1, Y0, Y0
	VPACKUSWB Y3, Y2, Y2
	VPMADDUBSW Y12, Y0, Y0
	VPMADDUBSW Y12, Y2, Y2

	// Final byte pack and lane reorder to contiguous 32-byte output block.
	VPACKUSWB Y2, Y0, Y0
	VPERMD Y0, Y13, Y0

	VMOVDQU Y0, (AX)(CX*1)

	ADDQ $128, DI
	ADDQ $32, CX
	JMP compress_encode_loop

compress_encode_done:
	VZEROUPPER
	RET

// ringDecodeAndDecompress4AVX2 computes Decompress_4(ByteDecode_4(b)).
//
// Each input byte packs two 4-bit values:
//   c0 = byte & 0x0f
//   c1 = byte >> 4
// and each nibble is expanded with:
//   decompress(c, 4) = round((c * q) / 16).
//
// Vector strategy (32 input bytes -> 64 output coefficients per loop):
// 1) Load 32 packed bytes and split them into low/high 128-bit lanes.
// 2) VPSHUFB duplicates byte positions so each nibble lands in its own 16-bit lane.
// 3) VPAND keeps only the selected low or high nibble bits.
// 4) VPMULLW applies the fixed-point alignment needed for the decompress scaling.
// 5) VPMULHRSW with q performs the final rounded map back into [0, q).
//
// Four such 16-coefficient vectors are stored per iteration, covering 64
// coefficients = 32 encoded bytes.
// func ringDecodeAndDecompress4AVX2(b *[encodingSize4]byte, f *ringElement)
TEXT ·ringDecodeAndDecompress4AVX2(SB), NOSPLIT, $0
	MOVQ b_base+0(FP), AX
	MOVQ f_base+8(FP), BX

	VPBROADCASTW qConst, Y15
	VPBROADCASTD decompressDecode4Shift<>(SB), Y14
	VPBROADCASTD decompressDecode4Mask<>(SB), Y13
	VMOVDQU decompressDecode4ShufbIdx<>(SB), Y12
	
	XORQ DI, DI  // coefficient index
	XORQ CX, CX  // input byte index

decompress_dencode_loop:
	CMPQ DI, $512
	JGE decompress_dencode_done

	VMOVDQU (AX)(CX*1), Y3
	VPERM2I128 $0x00, Y3, Y3, Y0
	VPERM2I128 $0x11, Y3, Y3, Y3

	VPSHUFB Y12, Y0, Y1
	VPAND Y13, Y1, Y1
	VPMULLW Y14, Y1, Y1
	VPMULHRSW Y15, Y1, Y1
	VMOVDQU Y1, (BX)(DI*1)

	VPSRLDQ $8, Y0, Y0
	VPSHUFB Y12, Y0, Y0
	VPAND Y13, Y0, Y0
	VPMULLW Y14, Y0, Y0
	VPMULHRSW Y15, Y0, Y0
	VMOVDQU Y0, 32(BX)(DI*1)

	VPSHUFB Y12, Y3, Y4
	VPAND Y13, Y4, Y4
	VPMULLW Y14, Y4, Y4
	VPMULHRSW Y15, Y4, Y4
	VMOVDQU Y4, 64(BX)(DI*1)

	VPSRLDQ $8, Y3, Y3
	VPSHUFB Y12, Y3, Y3
	VPAND Y13, Y3, Y3
	VPMULLW Y14, Y3, Y3
	VPMULHRSW Y15, Y3, Y3
	VMOVDQU Y3, 96(BX)(DI*1)	

	ADDQ $32, CX
	ADDQ $128, DI

	JMP decompress_dencode_loop

decompress_dencode_done:
	RET

// ringCompressAndEncode5AVX2 computes ByteEncode_5(Compress_5(f)).
//
// For each coefficient x in [0, q):
//   c = compress(x, 5) = round((32*x)/q) mod 32.
//
// Vector math used here:
//   t1 = high16(x * 20159)
//   c  = round((t1 * 1024) / 2^15)
//
// Since 20159/2^21 is a close fixed-point approximation of 32/q,
// this computes the same 5-bit compressed value as compress(x, 5)
// for ML-KEM input range x in [0, 3328].
//
// Packing strategy (32 coefficients -> 20 bytes per loop):
// 1) VPACKUSWB: pack 16-bit c values to bytes.
// 2) VPMADDUBSW with 8193: combine adjacent pairs as c0 + (c1 << 5).
// 3) VPMADDWD with 0x04000001: merge 10-bit pairs into 20-bit groups.
// 4) VPSLLVD/VPSRLVQ + VPSHUFB: align and compact bit fields.
// 5) VPBLENDVB + stores: emit contiguous 20-byte block.
//
// Output layout matches generic ByteEncode_5:
//   every 8 compressed coefficients are serialized into 5 bytes,
//   little-endian bit order within each byte.
TEXT ·ringCompressAndEncode5AVX2(SB), NOSPLIT, $0
	MOVQ out_base+0(FP), AX
	MOVQ f_base+24(FP), BX

	VPBROADCASTW oneConst, Y0
	VPBROADCASTW compressEncodeMulV<>(SB), Y9    // Y9 = 20159 (fixed-point approx of 16/q)
	VPSLLW $10, Y0, Y10  // Y10 = 1024 (shift for rounding)
	VPSLLW $13, Y0, Y11  // Y11 = 8192
	VPADDW Y0, Y11, Y11  // Y11 = 8193 = (32<<8)+1 for MADDUBSW
	VPBROADCASTD compressEncode5Shift3<>(SB), Y12 // Y12 = 0x04000001 for MADDWD
	VPBROADCASTW compressEncode5Mask<>(SB), Y13  // Y13 = 0x001F (5-bit mask)
	VPBROADCASTQ compressEncode5SllvdIdx<>(SB), Y14 // Y14 = 12
	VMOVDQU compressEncode5ShuffleIdx<>(SB), Y15   // Y15 = shuffle indices

	XORQ DI, DI  // coefficient index
	XORQ CX, CX  // output byte index

ring_compress_encode_loop:
	CMPQ DI, $512
	JGE ring_compress_encode_done

	// Load 32 coefficients (2 YMM registers, 16 int16 each)
	VMOVDQU (BX)(DI*1), Y0
	VMOVDQU 32(BX)(DI*1), Y1

	// Compress to 5 bits: c = round((32*x)/q) & 0x1F
	// Step 1: VPMULHW approximates (16*x)/q
	VPMULHW Y9, Y0, Y0
	VPMULHW Y9, Y1, Y1
	
	// Step 2: VPMULHRSW applies rounding: round((t1*1024)/2^15)
	VPMULHRSW Y10, Y0, Y0
	VPMULHRSW Y10, Y1, Y1
	
	// Step 3: Mask to 5 bits
	VPAND Y13, Y0, Y0
	VPAND Y13, Y1, Y1
	
	// Pack 16-bit compressed values to bytes: 16 x int16 -> 16 x uint8
	VPACKUSWB Y1, Y0, Y0
	
	// Packing step: combine byte pairs as (b0 + b1*32) in int16
	// VPMADDUBSW Y11, Y0, Y0 where Y11 = (32<<8)+1
	// produces: word = byte[0]*1 + byte[1]*32
	VPMADDUBSW Y11, Y0, Y0
	
	// Now Y0 contains 8 x int16 values with 5-bit nibbles interleaved
	// Need to multiply with shift3 and do bit manipulations
	// Key step: VPMADDWD multiplies adjacent 16-bit pairs
	// According to Intel doc: VPMADDWD reg1, reg2 -> result[i] = reg2[2i]*reg1[2i] + reg2[2i+1]*reg1[2i+1]
	VPMADDWD Y12, Y0, Y0
	
	// Y0 now contains 4 x int32 values
	// Apply variable shifts: SLL by 12, then SRL by 12 (on 64-bit chunks)
	VPSLLVD Y14, Y0, Y0
	VPSRLVQ Y14, Y0, Y0
	
	// Now Y0 should contain the bit-packed result
	// Extract and shuffle: VPSHUFB with lookup table
	VPSHUFB Y15, Y0, Y0
	
	// Split into lower and upper 128-bit halves
	VEXTRACTI128 $1, Y0, X1
	
	// Blend the two 128-bit halves using shufbidx as mask
	// VPBLENDVB selects bytes from X1 (if mask bit=1) or X0 (if mask bit=0)
	VPBLENDVB X15, X1, X0, X0
	
	// Store 20 bytes: 16 from X0 + 4 from X1
	VMOVDQU X0, (AX)(CX*1)
	MOVL X1, 16(AX)(CX*1)
	
	ADDQ $64, DI
	ADDQ $20, CX
	JMP ring_compress_encode_loop

ring_compress_encode_done:
	VZEROUPPER
	RET

// ringDecodeAndDecompress5AVX2 computes Decompress_5(ByteDecode_5(b)).
//
// For d=5, every 10 input bytes encode 16 coefficients (5 bits each).
// The vector path decodes one such 10-byte chunk per iteration:
// 1) Load 10 bytes into low 128 bits and mirror them to both 128-bit lanes.
// 2) VPSHUFB expands packed bit fields so each candidate 5-bit value is placed
//    in a dedicated 16-bit lane position.
// 3) VPAND applies the per-lane mask to keep only the desired 5-bit payload.
// 4) VPMULLW applies a fixed shift factor used by the generic decompress map.
// 5) VPMULHRSW with q performs rounded scaling back to [0, q).
//
// Main loop handles 15 chunks (240 coefficients). The final 16 coefficients are
// decoded by a tail path that builds the last 10-byte chunk from 8+2 bytes.
//
// func ringDecodeAndDecompress5AVX2(b *[encodingSize5]byte, f *ringElement)
TEXT ·ringDecodeAndDecompress5AVX2(SB), NOSPLIT, $0
	MOVQ b_base+0(FP), AX
	MOVQ f_base+8(FP), BX

	VPBROADCASTW qConst, Y15
	VMOVDQU decompressDecode5Mask<>(SB), Y14
	VMOVDQU decompressDecode5Shift<>(SB), Y13
	VMOVDQU decompressDecode5ShufbIdx<>(SB), Y12
	
	XORQ DI, DI  // coefficient index
	XORQ CX, CX  // input byte index

decompress_dencode_loop:
	CMPQ DI, $480
	JGE decompress_dencode_tail

	// Load 10-byte chunk into low lane, duplicate to 256b for uniform shuffle.
	VMOVDQU (AX)(CX*1), X0
	VINSERTI128 $1, X0, Y0, Y0
	// Decode 16 packed 5-bit values then apply Decompress_5 rounding to q-domain.
	VPSHUFB Y12, Y0, Y0
	VPAND Y14, Y0, Y0
	VPMULLW Y13, Y0, Y0
	VPMULHRSW Y15, Y0, Y0
	VMOVDQU Y0, (BX)(DI*1)

	ADDQ $10, CX
	ADDQ $32, DI
	JMP decompress_dencode_loop

decompress_dencode_tail:
	// Tail: assemble final 10-byte chunk from 8-byte load + 2-byte load.
	MOVQ (AX)(CX*1), X0
	MOVW 8(AX)(CX*1), R8
	PINSRW $4, R8, X0
	VINSERTI128 $1, X0, Y0, Y0
	VPSHUFB Y12, Y0, Y0
	VPAND Y14, Y0, Y0
	VPMULLW Y13, Y0, Y0
	VPMULHRSW Y15, Y0, Y0
	VMOVDQU Y0, (BX)(DI*1)
	VZEROUPPER
	RET

// ringCompressAndEncode10AVX2 computes ByteEncode_10(Compress_10(f)).
//
// For each coefficient x in [0, q):
//   c = compress(x, 10) = round((1024*x)/q) mod 1024.
//
// Vector math used here:
//   t1 = high16(x * 20159)                          [approximates (16*x)/q]
//   t2 = x * 161272 = x * (20159 << 3)              [approximates (128*x)/q]
//   c  = round((t1 * 4096) / 2^15) with correction  [computes compress(x, 10)]
//
// Since 20159/2^22 ≈ 16/q in fixed-point, we can compute 1024/q via:
//   t1 ≈ (16*x)/q  =>  t1 * 64 ≈ (1024*x)/q
//
// Correction logic handles rounding and adjustment:
//   t2 - t1 checks if low bits of x * 128/q exceed threshold
//   VPANDN extracts sign bit for conditional adjustment
//
// Packing layout (4 coefficients → 5 bytes, little-endian bits):
//   byte[0] = c[0][7:0]
//   byte[1] = c[1][9:2]
//   byte[2] = c[2][9:0] (merged as c[1][1:0] | c[2][7:0])
//   byte[3] = c[3][9:4]
//   byte[4] = c[3][3:0] (upper nibble)
//
// func ringCompressAndEncode10AVX2(out []byte, f *ringElement)
TEXT ·ringCompressAndEncode10AVX2(SB), NOSPLIT, $0
	MOVQ out_base+0(FP), AX
	MOVQ f_base+24(FP), BX

	VPBROADCASTW oneConst, Y0
	VPBROADCASTW compressEncodeMulV<>(SB), Y8        // Y8 = 20159 (fixed-point approx of 16/q)
	VPSLLW $3, Y8, Y9                                // Y9 = 20159 << 3 = 161272 (fixed-point approx of 128/q)
	VPSLLW $12, Y0, Y10                              // Y10 = 4096 (shift for rounding)
	VPSLLW $10, Y0, Y11                              // Y11 = 1024
	VPSUBW Y0, Y11, Y11                              // Y11 = 1023 (10-bit mask)
	VPBROADCASTW compressEncode4Mask<>(SB), Y12      // Y12 = 0x000F (4-bit mask, used for threshold)
	VPBROADCASTQ compressEncode5SllvdIdx<>(SB), Y13	 // Y13 = 12 (bit shift distance)
	VPBROADCASTD compressEncode5Shift3<>(SB), Y14    // Y14 = 0x04000001 for MADDWD
	VMOVDQU compressEncode10ShuffleIdx<>(SB), Y15    // Y15 = shuffle indices for byte packing

	XORQ DI, DI
	XORQ CX, CX

ring_compress_encode_loop:
	CMPQ DI, $512
	JGE ring_compress_encode_done

	// Load 16 coefficients (32 bytes = 2 x int16 lanes)
	VMOVDQU (BX)(DI*1), Y0

	// Compute t2 = high16(x * 161272) ≈ (128*x)/q
	VPMULLW Y9, Y0, Y1

	// Load threshold for rounding correction
	VPADDW Y12, Y0, Y2

	// Compute t1 = high16(x * 20159) ≈ (16*x)/q; also prepare shifted x
	VPSLLW $3, Y0, Y0
	VPMULHW Y8, Y0, Y0

	// Rounding correction: detect if t2 - threshold suggests upward rounding
	VPSUBW Y2, Y1, Y2
	VPANDN Y2, Y1, Y1    // Extract sign bit
	VPSRLW $15, Y1, Y1   // Broadcast sign to all bits

	// Apply correction: subtract sign bit if needed
	VPSUBW Y1, Y0, Y0

	// Round and mask to 10 bits:
	// c = round((t1 * 4096) / 2^15) = VPMULHRSW(t1, 4096)
	VPMULHRSW Y10, Y0, Y0

	// Mask to 10 bits: c &= 0x3FF (1023)
	VPAND Y11, Y0, Y0

	// Pack bits: VPMADDWD multiplies adjacent int16 pairs and sums
	VPMADDWD Y14, Y0, Y0

	// Shift and repack for byte alignment
	VPSLLVD Y13, Y0, Y0
	VPSRLQ $12, Y0, Y0

	// Shuffle to compact 5-byte output
	VPSHUFB Y15, Y0, Y0

	// Extract high 128-bit lane and blend
	VEXTRACTI128 $1, Y0, X1
	VPBLENDW $0xE0, X1, X0, X0

	// Store 20 bytes: 16 from X0 + 4 from X1
	VMOVDQU X0, (AX)(CX*1)
	MOVL X1, 16(AX)(CX*1)

	ADDQ $32, DI
	ADDQ $20, CX
	JMP ring_compress_encode_loop

ring_compress_encode_done:
	VZEROUPPER
	RET

// ringCompressAndEncode11AVX2 computes ByteEncode_11(Compress_11(f)).
//
// For each coefficient x in [0, q):
//   c = compress(x, 11) = round((2048*x)/q) mod 2048.
//
// Vector math used here follows the same fixed-point scheme as encode10,
// but with one extra output bit:
//   t1 = high16((x << 3) * 20159)                  [approximates (128*x)/q]
//   c  = round((t1 * 8192) / 2^15) with correction [computes compress(x, 11)]
//
// Since 20159/2^22 approximates 16/q, shifting x by 3 first gives an
// approximation to 128/q; the final VPMULHRSW by 8192 scales that to 2048/q.
// The VPADDW/VPANDN/VPSRLW sequence applies the same correction used by the
// generic implementation so rounding matches exactly on x in [0, 3328].
//
// Packing layout matches generic ByteEncode_11:
//   every 2 coefficients (22 bits total) are serialized into 11 bytes,
//   little-endian bit order within each byte.
//
// Logically, the main loop handles 16 coefficients -> 22 output bytes per
// iteration. The store sequence is wider: VMOVDQU writes 16 bytes and MOVQ
// writes 8 more, so each main-loop iteration physically stores 24 bytes and
// over-writes the first 2 bytes of the next iteration's output region. That is
// safe because CX advances by 22 and the next iteration (or the tail) rewrites
// those 2 bytes with the correct values.
//
// The tail handles the final 16 coefficients -> 22 bytes. It uses the same
// pipeline, but commits exactly 22 bytes via 16 + 4 + 2 stores, which avoids a
// final 24-byte over-store past the end of the 352-byte output buffer.
//
// func ringCompressAndEncode11AVX2(out []byte, f *ringElement)
TEXT ·ringCompressAndEncode11AVX2(SB), NOSPLIT, $0
	MOVQ out_base+0(FP), AX
	MOVQ f_base+24(FP), BX

	VPBROADCASTW oneConst, Y0
	VPBROADCASTW compressEncodeMulV<>(SB), Y7           // Y7 = 20159 (fixed-point approx of 16/q)
	VPSLLW $3, Y7, Y8                                    // Y8 = 20159 << 3 = 161272 (fixed-point approx of 128/q)
	VPSLLW $13, Y0, Y9                                   // Y9 = 8192 (shift for rounding)
	VPSLLW $11, Y0, Y10                                  // Y10 = 2048
	VPSUBW Y0, Y10, Y10                                  // Y10 = 2047 (11-bit mask)
	VPBROADCASTW compressEncode11Off<>(SB), Y11          // 0x24 
	VPBROADCASTQ compressEncode11SllvdIdx<>(SB), Y12     // 10
	VBROADCASTI128 compressEncode11SrlvdIdx<>(SB), Y13
	VPBROADCASTD compressEncode11Shift2<>(SB), Y14       // 0x08000000 for MADDWD
	VMOVDQU compressEncode11ShuffleIdx<>(SB), Y15

	XORQ DI, DI
	XORQ CX, CX

ring_compress_encode_loop:
	CMPQ DI, $480
	JGE ring_compress_encode_tail

	// Load 16 coefficients (32 bytes = 16 x int16 lanes).
	VMOVDQU (BX)(DI*1), Y0

	// Compute t2 = high16(x * 161272) ~= (128*x)/q.
	VPMULLW Y8, Y0, Y1

	// Load correction threshold (x + 0x24).
	VPADDW Y11, Y0, Y2

	// Compute t1 = high16((x << 3) * 20159) ~= (128*x)/q.
	VPSLLW $3, Y0, Y0
	VPMULHW Y7, Y0, Y0

	// Rounding correction: detect whether t2 crosses threshold.
	VPSUBW Y2, Y1, Y2
	VPANDN Y2, Y1, Y1
	VPSRLW $15, Y1, Y1

	// Apply correction, then round to nearest using 8192 scale.
	VPSUBW Y1, Y0, Y0
	VPMULHRSW Y9, Y0, Y0

	// Keep low 11 bits: c &= 0x7FF.
	VPAND Y10, Y0, Y0

	// Bit-pack stage:
	// 1) VPMADDWD combines adjacent 11-bit values into 32-bit lanes.
	// 2) VPSLLVD/VPSRLVQ aligns bit fields.
	// 3) VPSRLDQ+VPSLLQ carries cross-lane high bits.
	// 4) VPSHUFB compacts bytes to ByteEncode_11 layout.
	VPMADDWD Y14, Y0, Y0
	VPSLLVD Y12, Y0, Y0
	VPSRLDQ $8, Y0, Y1
	VPSRLVQ Y13, Y0, Y0
	VPSLLQ $34, Y1, Y1
	VPADDQ Y1, Y0, Y0
	VPSHUFB Y15, Y0, Y0

	// Blend low/high 128-bit halves for contiguous output bytes.
	VEXTRACTI128 $1, Y0, X1
	VPBLENDVB X15, X1, X0, X0

	// Physical stores: 16 + 8 bytes (next iteration rewrites overlap).
	VMOVDQU X0, (AX)(CX*1)
	MOVQ X1, 16(AX)(CX*1)

	ADDQ $32, DI
	ADDQ $22, CX
	JMP ring_compress_encode_loop

ring_compress_encode_tail:
	// Final 16 coefficients -> 22 bytes. Reuse the same packing pipeline, but
	// finish with exact-width stores (16 + 4 + 2) to avoid over-store at end.
	VMOVDQU (BX)(DI*1), Y0
	VPMULLW Y8, Y0, Y1
	VPADDW Y11, Y0, Y2
	VPSLLW $3, Y0, Y0
	VPMULHW Y7, Y0, Y0
	VPSUBW Y2, Y1, Y2
	VPANDN Y2, Y1, Y1
	VPSRLW $15, Y1, Y1
	VPSUBW Y1, Y0, Y0
	VPMULHRSW Y9, Y0, Y0
	VPAND Y10, Y0, Y0
	VPMADDWD Y14, Y0, Y0
	VPSLLVD Y12, Y0, Y0
	VPSRLDQ $8, Y0, Y1
	VPSRLVQ Y13, Y0, Y0
	VPSLLQ $34, Y1, Y1
	VPADDQ Y1, Y0, Y0
	VPSHUFB Y15, Y0, Y0
	VEXTRACTI128 $1, Y0, X1
	VPBLENDVB X15, X1, X0, X0
	VMOVDQU X0, (AX)(CX*1)
	MOVL X1, 16(AX)(CX*1)
	PEXTRW $2, X1, R8
	MOVW R8, 20(AX)(CX*1)

	VZEROUPPER	
	RET

// ringCompressAndEncode1AVX2 computes ByteEncode_1(Compress_1(f)).
//
// For each coefficient x in [0, q):
//   compress(x, 1) = 1 if 833 <= x <= 2496, else 0.
//
// Vector strategy (32 coefficients -> 4 bytes per iteration):
// 1) Load 32 x int16 coefficients into Y0, Y1.
// 2) VPCMPGTW with 832 and 2496 thresholds identifies the compress=1 range.
// 3) VPANDN combines conditions: 0xFFFF where compress=1.
// 4) VPACKSSWB packs 16-bit results to sign-carrying bytes.
// 5) VPERMQ $0xD8 fixes cross-lane byte ordering from VPACKSSWB.
// 6) VPMOVMSKB extracts MSB of each byte -> 32-bit mask = 4 bytes of output.
//
// The caller pre-zeros the output buffer (required for the generic fallback).
// This implementation writes every output byte directly, so no pre-zero needed.
//
// func ringCompressAndEncode1AVX2(out []byte, f *ringElement)
TEXT ·ringCompressAndEncode1AVX2(SB), NOSPLIT, $0
	MOVQ out_base+0(FP), AX
	MOVQ f_base+24(FP), BX

	VPBROADCASTW compressEncode1Lo<>(SB), Y14  // Y14 = 832  (lower threshold)
	VPBROADCASTW compressEncode1Hi<>(SB), Y15  // Y15 = 2496 (upper threshold)

	XORQ DI, DI  // byte offset into f
	XORQ CX, CX  // output byte offset

ring_compress_encode1_loop:
	CMPQ DI, $512
	JGE ring_compress_encode1_done

	// Load 32 coefficients (64 bytes = 2 x YMM)
	VMOVDQU (BX)(DI*1), Y0
	VMOVDQU 32(BX)(DI*1), Y1

	// Y2 = 0xFFFF where f[i] > 832 (i.e., f[i] >= 833)
	VPCMPGTW Y14, Y0, Y2
	VPCMPGTW Y14, Y1, Y3

	// Y4/Y5 = 0xFFFF where f[i] > 2496 (i.e., f[i] >= 2497)
	VPCMPGTW Y15, Y0, Y4
	VPCMPGTW Y15, Y1, Y5

	// Y2/Y3 = 0xFFFF where 833 <= f[i] <= 2496 (compress=1)
	// VPANDN arg1, arg2, dst => dst = arg1 & ~arg2
	VPANDN Y2, Y4, Y2
	VPANDN Y3, Y5, Y3

	// Pack 32 x int16 {0xFFFF, 0x0000} to 32 x int8 {0x80, 0x00}.
	// VPACKSSWB within 128-bit lanes: low lane = {Y2[0..7], Y3[0..7]},
	// high lane = {Y2[8..15], Y3[8..15]}.
	VPACKSSWB Y3, Y2, Y4

	// Fix cross-lane order: swap 64-bit chunks 1 and 2 so bytes monotonically
	// track coefficients 0..7, 8..15, 16..23, 24..31.
	VPERMQ $0xD8, Y4, Y4

	// Extract the MSB of each byte as a 32-bit bitmask.
	VPMOVMSKB Y4, R8

	// Store 4 output bytes.
	MOVL R8, (AX)(CX*1)

	ADDQ $64, DI   // advance by 32 coefficients x 2 bytes
	ADDQ $4, CX    // 4 output bytes per 32 coefficients
	JMP ring_compress_encode1_loop

ring_compress_encode1_done:
	VZEROUPPER
	RET

// rejUniformAMD64 implements the scalar rejection sampler used by sampleNTT.
// It consumes 3-byte groups, extracts two 12-bit values, and appends values < q.
//
// func rejUniformAMD64(buf []byte, a *nttElement, j int) int
TEXT ·rejUniformAMD64(SB), NOSPLIT, $0-48
	MOVQ buf_base+0(FP), BX
	MOVQ buf_len+8(FP), CX
	MOVQ a+24(FP), DI
	MOVQ j+32(FP), SI
	MOVQ SI, R10
	XORQ DX, DX

	CMPQ SI, $256
	JGE  rejuniform_done
	CMPQ CX, $24
	JE   rejuniform_len24

rejuniform_loop:
	CMPQ DX, CX
	JGE  rejuniform_done

	MOVBLZX 0(BX)(DX*1), AX
	MOVBLZX 1(BX)(DX*1), R8
	SHLQ    $8, R8
	ORQ     R8, AX
	ANDQ    $0x0FFF, AX
	CMPQ    AX, $3329
	JAE     rejuniform_skip_d1
	MOVW    AX, 0(DI)(SI*2)
	INCQ    SI
	CMPQ    SI, $256
	JGE     rejuniform_done

rejuniform_skip_d1:
	MOVBLZX 1(BX)(DX*1), AX
	MOVBLZX 2(BX)(DX*1), R8
	SHLQ    $8, R8
	ORQ     R8, AX
	SHRQ    $4, AX
	CMPQ    AX, $3329
	JAE     rejuniform_next
	MOVW    AX, 0(DI)(SI*2)
	INCQ    SI
	CMPQ    SI, $256
	JGE     rejuniform_done

rejuniform_next:
	ADDQ $3, DX
	JMP  rejuniform_loop

rejuniform_len24:
	CMPQ SI, $240
	JG   rejuniform_len24_checked

	MOVL 0(BX), AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_fast_g0_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
rejuniform_fast_g0_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_fast_g1
	MOVW AX, 0(DI)(SI*2)
	INCQ SI

rejuniform_fast_g1:
	MOVL 3(BX), AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_fast_g1_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
rejuniform_fast_g1_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_fast_g2
	MOVW AX, 0(DI)(SI*2)
	INCQ SI

rejuniform_fast_g2:
	MOVL 6(BX), AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_fast_g2_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
rejuniform_fast_g2_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_fast_g3
	MOVW AX, 0(DI)(SI*2)
	INCQ SI

rejuniform_fast_g3:
	MOVL 9(BX), AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_fast_g3_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
rejuniform_fast_g3_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_fast_g4
	MOVW AX, 0(DI)(SI*2)
	INCQ SI

rejuniform_fast_g4:
	MOVL 12(BX), AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_fast_g4_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
rejuniform_fast_g4_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_fast_g5
	MOVW AX, 0(DI)(SI*2)
	INCQ SI

rejuniform_fast_g5:
	MOVL 15(BX), AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_fast_g5_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
rejuniform_fast_g5_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_fast_g6
	MOVW AX, 0(DI)(SI*2)
	INCQ SI

rejuniform_fast_g6:
	MOVL 18(BX), AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_fast_g6_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
rejuniform_fast_g6_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_fast_g7
	MOVW AX, 0(DI)(SI*2)
	INCQ SI

rejuniform_fast_g7:
	MOVL 20(BX), AX
	SHRQ $8, AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_fast_g7_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
rejuniform_fast_g7_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_done
	MOVW AX, 0(DI)(SI*2)
	INCQ SI
	JMP  rejuniform_done

rejuniform_len24_checked:
	MOVQ $256, R11
	SUBQ SI, R11

	MOVL 0(BX), AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_g0_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
	DECQ R11
	JE   rejuniform_done
rejuniform_g0_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_g1
	MOVW AX, 0(DI)(SI*2)
	INCQ SI
	DECQ R11
	JE   rejuniform_done

rejuniform_g1:
	MOVL 3(BX), AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_g1_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
	DECQ R11
	JE   rejuniform_done
rejuniform_g1_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_g2
	MOVW AX, 0(DI)(SI*2)
	INCQ SI
	DECQ R11
	JE   rejuniform_done

rejuniform_g2:
	MOVL 6(BX), AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_g2_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
	DECQ R11
	JE   rejuniform_done
rejuniform_g2_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_g3
	MOVW AX, 0(DI)(SI*2)
	INCQ SI
	DECQ R11
	JE   rejuniform_done

rejuniform_g3:
	MOVL 9(BX), AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_g3_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
	DECQ R11
	JE   rejuniform_done
rejuniform_g3_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_g4
	MOVW AX, 0(DI)(SI*2)
	INCQ SI
	DECQ R11
	JE   rejuniform_done

rejuniform_g4:
	MOVL 12(BX), AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_g4_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
	DECQ R11
	JE   rejuniform_done
rejuniform_g4_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_g5
	MOVW AX, 0(DI)(SI*2)
	INCQ SI
	DECQ R11
	JE   rejuniform_done

rejuniform_g5:
	MOVL 15(BX), AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_g5_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
	DECQ R11
	JE   rejuniform_done
rejuniform_g5_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_g6
	MOVW AX, 0(DI)(SI*2)
	INCQ SI
	DECQ R11
	JE   rejuniform_done

rejuniform_g6:
	MOVL 18(BX), AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_g6_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
	DECQ R11
	JE   rejuniform_done
rejuniform_g6_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_g7
	MOVW AX, 0(DI)(SI*2)
	INCQ SI
	DECQ R11
	JE   rejuniform_done

rejuniform_g7:
	MOVL 20(BX), AX
	SHRQ $8, AX
	MOVQ AX, R8
	ANDQ $0x0FFF, R8
	CMPQ R8, $3329
	JAE  rejuniform_g7_d2
	MOVW R8, 0(DI)(SI*2)
	INCQ SI
	DECQ R11
	JE   rejuniform_done
rejuniform_g7_d2:
	SHRQ $12, AX
	ANDQ $0x0FFF, AX
	CMPQ AX, $3329
	JAE  rejuniform_done
	MOVW AX, 0(DI)(SI*2)
	INCQ SI

rejuniform_done:
	SUBQ R10, SI
	MOVQ SI, ret+40(FP)
	RET
