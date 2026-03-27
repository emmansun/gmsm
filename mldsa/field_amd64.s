// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

DATA nttConsts<>+0x00(SB)/2, $3329 // q
DATA nttConsts<>+0x02(SB)/2, $3327 // qNegInv
DATA nttConsts<>+0x04(SB)/2, $1    // one
DATA nttConsts<>+0x06(SB)/2, $1353 // rr = r^2 mod q (fromMont: MontMul(x, rr) = x*r)
DATA nttConsts<>+0x08(SB)/2, $1441 // inverse NTT final scale for Montgomery acc path: 128⁻¹*r² mod q
GLOBL nttConsts<>(SB), RODATA, $16

#define qConst nttConsts<>+0x00(SB)
#define qNegInvConst nttConsts<>+0x02(SB)
#define oneConst nttConsts<>+0x04(SB)
#define rrConst nttConsts<>+0x06(SB)
#define scale1441Const nttConsts<>+0x08(SB)

// gammaMulTable<>: 256 × int16 interleaved as [r, γ[0], r, γ[1], ..., r, γ[127]]
// where r=2285 (Montgomery form of 1) and γ[i]=gammasMontgomery[i].
// Used by internalNTTMulAccAVX2: MontMul(t_ab[even], r) = t_ab[even],
// MontMul(t_ab[odd], γ[i]) = γ[i]·a1·b1 for the even-index accumulation.
DATA gammaMulTable<>+0x000(SB)/4, $0x08B208ED
DATA gammaMulTable<>+0x004(SB)/4, $0x044F08ED
DATA gammaMulTable<>+0x008(SB)/4, $0x01AE08ED
DATA gammaMulTable<>+0x00C(SB)/4, $0x0B5308ED
DATA gammaMulTable<>+0x010(SB)/4, $0x022B08ED
DATA gammaMulTable<>+0x014(SB)/4, $0x0AD608ED
DATA gammaMulTable<>+0x018(SB)/4, $0x034B08ED
DATA gammaMulTable<>+0x01C(SB)/4, $0x09B608ED
DATA gammaMulTable<>+0x020(SB)/4, $0x081E08ED
DATA gammaMulTable<>+0x024(SB)/4, $0x04E308ED
DATA gammaMulTable<>+0x028(SB)/4, $0x036708ED
DATA gammaMulTable<>+0x02C(SB)/4, $0x099A08ED
DATA gammaMulTable<>+0x030(SB)/4, $0x060E08ED
DATA gammaMulTable<>+0x034(SB)/4, $0x06F308ED
DATA gammaMulTable<>+0x038(SB)/4, $0x006908ED
DATA gammaMulTable<>+0x03C(SB)/4, $0x0C9808ED
DATA gammaMulTable<>+0x040(SB)/4, $0x01A608ED
DATA gammaMulTable<>+0x044(SB)/4, $0x0B5B08ED
DATA gammaMulTable<>+0x048(SB)/4, $0x024B08ED
DATA gammaMulTable<>+0x04C(SB)/4, $0x0AB608ED
DATA gammaMulTable<>+0x050(SB)/4, $0x00B108ED
DATA gammaMulTable<>+0x054(SB)/4, $0x0C5008ED
DATA gammaMulTable<>+0x058(SB)/4, $0x0C1608ED
DATA gammaMulTable<>+0x05C(SB)/4, $0x00EB08ED
DATA gammaMulTable<>+0x060(SB)/4, $0x0BDE08ED
DATA gammaMulTable<>+0x064(SB)/4, $0x012308ED
DATA gammaMulTable<>+0x068(SB)/4, $0x0B3508ED
DATA gammaMulTable<>+0x06C(SB)/4, $0x01CC08ED
DATA gammaMulTable<>+0x070(SB)/4, $0x062608ED
DATA gammaMulTable<>+0x074(SB)/4, $0x06DB08ED
DATA gammaMulTable<>+0x078(SB)/4, $0x067508ED
DATA gammaMulTable<>+0x07C(SB)/4, $0x068C08ED
DATA gammaMulTable<>+0x080(SB)/4, $0x0C0B08ED
DATA gammaMulTable<>+0x084(SB)/4, $0x00F608ED
DATA gammaMulTable<>+0x088(SB)/4, $0x030A08ED
DATA gammaMulTable<>+0x08C(SB)/4, $0x09F708ED
DATA gammaMulTable<>+0x090(SB)/4, $0x048708ED
DATA gammaMulTable<>+0x094(SB)/4, $0x087A08ED
DATA gammaMulTable<>+0x098(SB)/4, $0x0C6E08ED
DATA gammaMulTable<>+0x09C(SB)/4, $0x009308ED
DATA gammaMulTable<>+0x0A0(SB)/4, $0x09F808ED
DATA gammaMulTable<>+0x0A4(SB)/4, $0x030908ED
DATA gammaMulTable<>+0x0A8(SB)/4, $0x05CB08ED
DATA gammaMulTable<>+0x0AC(SB)/4, $0x073608ED
DATA gammaMulTable<>+0x0B0(SB)/4, $0x0AA708ED
DATA gammaMulTable<>+0x0B4(SB)/4, $0x025A08ED
DATA gammaMulTable<>+0x0B8(SB)/4, $0x045F08ED
DATA gammaMulTable<>+0x0BC(SB)/4, $0x08A208ED
DATA gammaMulTable<>+0x0C0(SB)/4, $0x06CB08ED
DATA gammaMulTable<>+0x0C4(SB)/4, $0x063608ED
DATA gammaMulTable<>+0x0C8(SB)/4, $0x028408ED
DATA gammaMulTable<>+0x0CC(SB)/4, $0x0A7D08ED
DATA gammaMulTable<>+0x0D0(SB)/4, $0x099908ED
DATA gammaMulTable<>+0x0D4(SB)/4, $0x036808ED
DATA gammaMulTable<>+0x0D8(SB)/4, $0x015D08ED
DATA gammaMulTable<>+0x0DC(SB)/4, $0x0BA408ED
DATA gammaMulTable<>+0x0E0(SB)/4, $0x01A208ED
DATA gammaMulTable<>+0x0E4(SB)/4, $0x0B5F08ED
DATA gammaMulTable<>+0x0E8(SB)/4, $0x014908ED
DATA gammaMulTable<>+0x0EC(SB)/4, $0x0BB808ED
DATA gammaMulTable<>+0x0F0(SB)/4, $0x0C6508ED
DATA gammaMulTable<>+0x0F4(SB)/4, $0x009C08ED
DATA gammaMulTable<>+0x0F8(SB)/4, $0x0CB608ED
DATA gammaMulTable<>+0x0FC(SB)/4, $0x004B08ED
DATA gammaMulTable<>+0x100(SB)/4, $0x033108ED
DATA gammaMulTable<>+0x104(SB)/4, $0x09D008ED
DATA gammaMulTable<>+0x108(SB)/4, $0x044908ED
DATA gammaMulTable<>+0x10C(SB)/4, $0x08B808ED
DATA gammaMulTable<>+0x110(SB)/4, $0x025B08ED
DATA gammaMulTable<>+0x114(SB)/4, $0x0AA608ED
DATA gammaMulTable<>+0x118(SB)/4, $0x026208ED
DATA gammaMulTable<>+0x11C(SB)/4, $0x0A9F08ED
DATA gammaMulTable<>+0x120(SB)/4, $0x052A08ED
DATA gammaMulTable<>+0x124(SB)/4, $0x07D708ED
DATA gammaMulTable<>+0x128(SB)/4, $0x07FC08ED
DATA gammaMulTable<>+0x12C(SB)/4, $0x050508ED
DATA gammaMulTable<>+0x130(SB)/4, $0x074808ED
DATA gammaMulTable<>+0x134(SB)/4, $0x05B908ED
DATA gammaMulTable<>+0x138(SB)/4, $0x018008ED
DATA gammaMulTable<>+0x13C(SB)/4, $0x0B8108ED
DATA gammaMulTable<>+0x140(SB)/4, $0x084208ED
DATA gammaMulTable<>+0x144(SB)/4, $0x04BF08ED
DATA gammaMulTable<>+0x148(SB)/4, $0x0C7908ED
DATA gammaMulTable<>+0x14C(SB)/4, $0x008808ED
DATA gammaMulTable<>+0x150(SB)/4, $0x04C208ED
DATA gammaMulTable<>+0x154(SB)/4, $0x083F08ED
DATA gammaMulTable<>+0x158(SB)/4, $0x07CA08ED
DATA gammaMulTable<>+0x15C(SB)/4, $0x053708ED
DATA gammaMulTable<>+0x160(SB)/4, $0x099708ED
DATA gammaMulTable<>+0x164(SB)/4, $0x036A08ED
DATA gammaMulTable<>+0x168(SB)/4, $0x00DC08ED
DATA gammaMulTable<>+0x16C(SB)/4, $0x0C2508ED
DATA gammaMulTable<>+0x170(SB)/4, $0x085E08ED
DATA gammaMulTable<>+0x174(SB)/4, $0x04A308ED
DATA gammaMulTable<>+0x178(SB)/4, $0x068608ED
DATA gammaMulTable<>+0x17C(SB)/4, $0x067B08ED
DATA gammaMulTable<>+0x180(SB)/4, $0x086008ED
DATA gammaMulTable<>+0x184(SB)/4, $0x04A108ED
DATA gammaMulTable<>+0x188(SB)/4, $0x070708ED
DATA gammaMulTable<>+0x18C(SB)/4, $0x05FA08ED
DATA gammaMulTable<>+0x190(SB)/4, $0x080308ED
DATA gammaMulTable<>+0x194(SB)/4, $0x04FE08ED
DATA gammaMulTable<>+0x198(SB)/4, $0x031A08ED
DATA gammaMulTable<>+0x19C(SB)/4, $0x09E708ED
DATA gammaMulTable<>+0x1A0(SB)/4, $0x071B08ED
DATA gammaMulTable<>+0x1A4(SB)/4, $0x05E608ED
DATA gammaMulTable<>+0x1A8(SB)/4, $0x09AB08ED
DATA gammaMulTable<>+0x1AC(SB)/4, $0x035608ED
DATA gammaMulTable<>+0x1B0(SB)/4, $0x099B08ED
DATA gammaMulTable<>+0x1B4(SB)/4, $0x036608ED
DATA gammaMulTable<>+0x1B8(SB)/4, $0x01DE08ED
DATA gammaMulTable<>+0x1BC(SB)/4, $0x0B2308ED
DATA gammaMulTable<>+0x1C0(SB)/4, $0x0C9508ED
DATA gammaMulTable<>+0x1C4(SB)/4, $0x006C08ED
DATA gammaMulTable<>+0x1C8(SB)/4, $0x0BCD08ED
DATA gammaMulTable<>+0x1CC(SB)/4, $0x013408ED
DATA gammaMulTable<>+0x1D0(SB)/4, $0x03E408ED
DATA gammaMulTable<>+0x1D4(SB)/4, $0x091D08ED
DATA gammaMulTable<>+0x1D8(SB)/4, $0x03DF08ED
DATA gammaMulTable<>+0x1DC(SB)/4, $0x092208ED
DATA gammaMulTable<>+0x1E0(SB)/4, $0x03BE08ED
DATA gammaMulTable<>+0x1E4(SB)/4, $0x094308ED
DATA gammaMulTable<>+0x1E8(SB)/4, $0x074D08ED
DATA gammaMulTable<>+0x1EC(SB)/4, $0x05B408ED
DATA gammaMulTable<>+0x1F0(SB)/4, $0x05F208ED
DATA gammaMulTable<>+0x1F4(SB)/4, $0x070F08ED
DATA gammaMulTable<>+0x1F8(SB)/4, $0x065C08ED
DATA gammaMulTable<>+0x1FC(SB)/4, $0x06A508ED
GLOBL gammaMulTable<>(SB), RODATA, $512

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

// MONT_MUL_VECX computes lane-wise Montgomery multiplication YOUT = MontMul(XA, XZ).
// Inputs: XA=value, XZ=multiplier-broadcast.
// Constants: X15=q, X14=qNegInv, X10=one, X8=zero.
// Clobbers: X11, X12, X13.
#define MONT_MUL_VECX(XA, XZ, XOUT) \
	\ // mul XA by XZ, producing 32-bit products in X11 (low) and X12 (high)
	VPMULLW XZ, XA, X11 \    // lo = (XA * XZ) mod 2^16
	VPMULHUW XZ, XA, X12 \   // hi = (XA * XZ) >> 16  [unsigned]
	\ // montgomery reduction: m = (t_ab[even] * qNegInv) mod r, t = (t_ab + m*q) / r
	VPMULLW X14, X11, X13 \  // t  = lo * qNegInv mod 2^16
	VPMULHUW X15, X13, X13 \ // correction = (t * q) >> 16
	VPADDW X13, X12, X12 \   // result = hi + correction
	\ // lo==0 edge-case correction (adds 1 when lo != 0):
	VPCMPEQW X8, X11, X13 \  // X13 = 0xFFFF if lo==0 else 0
	VPADDW X10, X13, X13 \   // X13 = 0 if lo==0 else 1  (1+0xFFFF=0, 1+0=1)
	VPADDW X13, X12, X12 \   // result += X13  (adds 1 when lo != 0)
	\ // final conditional subtraction to reduce mod q: if t >= q, subtract q; else keep t
	VPCMPGTW X12, X15, X13 \ // X13 = 0xFFFF if result < q else 0
	VPANDN X15, X13, X13 \   // X13 = q if result >= q else 0
	VPSUBW X13, X12, XOUT

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

// BUTTERFLYX performs the same butterfly as BUTTERFLY on XMM vectors.
// Inputs: XA, XB, XZ. Constants: X15=q, X14=qNegInv, X10=one, X8=zero.
// Clobbers: X11, X12, X13.
#define BUTTERFLYX(XA, XB, XZ) \
	\ // compute t = MontMul(XZ, XB) → X12
	MONT_MUL_VECX(XB, XZ, X12) \
	\ // new XB = XA - t
	VPSUBW X12, XA, XB \
	VPSRAW $15, XB, X11 \
	VPAND X15, X11, X11 \
	VPADDW X11, XB, XB \
	\ // new XA = XA + t
	VPADDW X12, XA, X12 \
	VPCMPGTW X12, X15, X13 \
	VPANDN X15, X13, X13 \
	VPSUBW X13, X12, XA

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

// INTT_BUTTERFLYX is the same as INTT_BUTTERFLY but operates on XMM vectors.
// Inputs:  XA=a, XB=b, XZ=zeta. Constants: X15=q, X14=qNegInv, X10=one, X8=zero.
// Clobbers: X9, X11, X12, X13.
// INTT_BUTTERFLYX: same as INTT_BUTTERFLY but uses XMM registers.
// Clobbers: X9, X11, X12, X13.
#define INTT_BUTTERFLYX(XA, XB, XZ) \
	VMOVDQA XA, X9 \
	\ // new XA = XA + XB (mod q, with at most one reduction needed)
	VPADDW XB, XA, XA \
	VPSUBW X15, XA, X11 \
	VPSRAW $15, X11, X13 \
	VPAND X15, X13, X13 \
	VPADDW X13, X11, XA \
	\ // new XB = XZ * (XB - X9)
	\ // step 1: XB - X9
	VPSUBW X9, XB, XB \
	VPSRAW $15, XB, X12 \
	VPAND X15, X12, X12 \
	VPADDW X12, XB, XB \
	\ // step 2: MontMul(XZ, XB)
	MONT_MUL_VECX(XB, XZ, XB)

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

	// Layer len=64
	// Group 0: zeta=zetasMontgomery[2], chunk pairs (0,4)..(3,7)
	VPBROADCASTW 4(BX), Y7
	nttLevel1(AX, Y7, 0, 0)
	nttLevel1(AX, Y7, 0, 1)
	nttLevel1(AX, Y7, 0, 2)
	nttLevel1(AX, Y7, 0, 3)

	// Group 1: zeta=zetasMontgomery[3], chunk pairs (8,12)..(11,15)
	VPBROADCASTW 6(BX), Y7
	nttLevel1(AX, Y7, 1, 0)
	nttLevel1(AX, Y7, 1, 1)
	nttLevel1(AX, Y7, 1, 2)
	nttLevel1(AX, Y7, 1, 3)

	// Layer len=32
	// Group 0: zeta=zetasMontgomery[4], pairs (chunk0,2) and (chunk1,3)
	VPBROADCASTW 8(BX), Y7
	nttLevel2(AX, Y7, 0, 0)
	nttLevel2(AX, Y7, 0, 1)

	// Group 1: zeta=zetasMontgomery[5], pairs (chunk4,6) and (chunk5,7)
	VPBROADCASTW 10(BX), Y7
	nttLevel2(AX, Y7, 1, 0)
	nttLevel2(AX, Y7, 1, 1)

	// Group 2: zeta=zetasMontgomery[6], pairs (chunk8,10) and (chunk9,11)
	VPBROADCASTW 12(BX), Y7
	nttLevel2(AX, Y7, 2, 0)
	nttLevel2(AX, Y7, 2, 1)

	// Group 3: zeta=zetasMontgomery[7], pairs (chunk12,14) and (chunk13,15)
	VPBROADCASTW 14(BX), Y7
	nttLevel2(AX, Y7, 3, 0)
	nttLevel2(AX, Y7, 3, 1)

	// Layer len=16
	// Group g uses zetasMontgomery[8+g], chunk pairs (2g, 2g+1)
	VPBROADCASTW 16(BX), Y7
	nttLevel3(AX, Y7, 0)

	VPBROADCASTW 18(BX), Y7
	nttLevel3(AX, Y7, 1)

	VPBROADCASTW 20(BX), Y7
	nttLevel3(AX, Y7, 2)

	VPBROADCASTW 22(BX), Y7
	nttLevel3(AX, Y7, 3)

	VPBROADCASTW 24(BX), Y7
	nttLevel3(AX, Y7, 4)

	VPBROADCASTW 26(BX), Y7
	nttLevel3(AX, Y7, 5)

	VPBROADCASTW 28(BX), Y7
	nttLevel3(AX, Y7, 6)

	VPBROADCASTW 30(BX), Y7
	nttLevel3(AX, Y7, 7)

	// Continue with layers len=8, len=4, len=2
	VPBROADCASTW qConst, X15
	VPBROADCASTW qNegInvConst, X14
	VPBROADCASTW oneConst, X10
	VPXOR X8, X8, X8

	// Layer len=8, groups g=0..15, zeta index = 16+g
	XORQ CX, CX
len8_loop:
	CMPQ CX, $16
	JGE len4_start
	MOVQ CX, SI
	ADDQ $16, SI
	SHLQ $1, SI
	VPBROADCASTW (BX)(SI*1), X7

	MOVQ CX, DI
	SHLQ $5, DI
	VMOVDQU (AX)(DI*1), X0
	VMOVDQU 16(AX)(DI*1), X1
	BUTTERFLYX(X0, X1, X7)
	VMOVDQU X0, (AX)(DI*1)
	VMOVDQU X1, 16(AX)(DI*1)

	INCQ CX
	JMP len8_loop

	// Layer len=4, groups g=0..31, zeta index = 32+g
len4_start:
	XORQ CX, CX
len4_loop:
	CMPQ CX, $32
	JGE len2_start
	MOVQ CX, SI
	ADDQ $32, SI
	SHLQ $1, SI
	VPBROADCASTW (BX)(SI*1), X7

	MOVQ CX, DI
	SHLQ $4, DI
	VMOVQ (AX)(DI*1), X0
	VMOVQ 8(AX)(DI*1), X1
	BUTTERFLYX(X0, X1, X7)
	VMOVQ X0, (AX)(DI*1)
	VMOVQ X1, 8(AX)(DI*1)

	INCQ CX
	JMP len4_loop

	// Layer len=2, groups g=0..63, zeta index = 64+g
len2_start:
	XORQ CX, CX
len2_loop:
	CMPQ CX, $64
	JGE len2_done
	MOVQ CX, SI
	ADDQ $64, SI
	SHLQ $1, SI
	VPBROADCASTW (BX)(SI*1), X7

	MOVQ CX, DI
	SHLQ $3, DI
	VMOVD (AX)(DI*1), X0
	VMOVD 4(AX)(DI*1), X1
	BUTTERFLYX(X0, X1, X7)
	VMOVD X0, (AX)(DI*1)
	VMOVD X1, 4(AX)(DI*1)

	INCQ CX
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

	// ── Setup XMM constants for small layers (len=2,4,8) ──────────────────
	VPBROADCASTW qConst, X15
	VPBROADCASTW qNegInvConst, X14
	VPBROADCASTW oneConst, X10
	VPXOR X8, X8, X8

	// ── L6: len=2, 64 groups, zeta = zetasMontgomery[127..64] ───────────
	// group g: start=g*4 bytes, fl=[start..start+4), fr=[start+4..start+8)
	// twiddle at BX + (127-g)*2  (k counts down from 127)
	XORQ CX, CX
intt_len2_loop:
	CMPQ CX, $64
	JGE intt_len4_start

	// twiddle index = 127 - CX  → byte offset = (127-CX)*2 = 254-CX*2
	MOVQ $254, SI
	MOVQ CX, DI
	SHLQ $1, DI
	SUBQ DI, SI
	VPBROADCASTW (BX)(SI*1), X7

	// byte offset of this group in f: CX * 8  (group g: start = g*2*len*sizeof(uint16) = g*2*2*2 = g*8)
	MOVQ CX, DI
	SHLQ $3, DI
	VMOVD (AX)(DI*1), X0     // fl = f[start..start+2]  (2 × int16 = 4 bytes)
	VMOVD 4(AX)(DI*1), X1    // fr = f[start+2..start+4]
	INTT_BUTTERFLYX(X0, X1, X7)
	VMOVD X0, (AX)(DI*1)
	VMOVD X1, 4(AX)(DI*1)

	INCQ CX
	JMP intt_len2_loop

	// ── L5: len=4, 32 groups, zeta = zetasMontgomery[63..32] ────────────
	// group g: start=g*8 bytes, fl=[start..start+8), fr=[start+8..start+16)
intt_len4_start:
	XORQ CX, CX
intt_len4_loop:
	CMPQ CX, $32
	JGE intt_len8_start

	// twiddle index = 63 - CX  → byte offset = (63-CX)*2 = 126-CX*2
	MOVQ $126, SI
	MOVQ CX, DI
	SHLQ $1, DI
	SUBQ DI, SI
	VPBROADCASTW (BX)(SI*1), X7

	// byte offset: CX * 16  (group g: start = g*2*len*sizeof(uint16) = g*2*4*2 = g*16)
	MOVQ CX, DI
	SHLQ $4, DI
	VMOVQ (AX)(DI*1), X0     // fl = 4 × int16 = 8 bytes
	VMOVQ 8(AX)(DI*1), X1    // fr
	INTT_BUTTERFLYX(X0, X1, X7)
	VMOVQ X0, (AX)(DI*1)
	VMOVQ X1, 8(AX)(DI*1)

	INCQ CX
	JMP intt_len4_loop

	// ── L4: len=8, 16 groups, zeta = zetasMontgomery[31..16] ────────────
	// group g: start=g*16 bytes (= g*32 once you include both halves),
	//          fl=[start..start+16), fr=[start+16..start+32)
intt_len8_start:
	XORQ CX, CX
intt_len8_loop:
	CMPQ CX, $16
	JGE intt_len16_start

	// twiddle index = 31 - CX → byte offset = (31-CX)*2 = 62-CX*2
	MOVQ $62, SI
	MOVQ CX, DI
	SHLQ $1, DI
	SUBQ DI, SI
	VPBROADCASTW (BX)(SI*1), X7

	// byte offset: CX * 32
	MOVQ CX, DI
	SHLQ $5, DI
	VMOVDQU (AX)(DI*1), X0    // fl = 8 × int16 = 16 bytes
	VMOVDQU 16(AX)(DI*1), X1  // fr
	INTT_BUTTERFLYX(X0, X1, X7)
	VMOVDQU X0, (AX)(DI*1)
	VMOVDQU X1, 16(AX)(DI*1)

	INCQ CX
	JMP intt_len8_loop

	// ── Switch to YMM for len≥16 ──────────────────────────────────────────
intt_len16_start:
	VPBROADCASTW qConst, Y15
	VPBROADCASTW qNegInvConst, Y14
	VPBROADCASTW oneConst, Y10
	VPXOR Y8, Y8, Y8

	// ── L3: len=16, 8 groups, zeta = zetasMontgomery[15..8] ─────────────
	// group g: fl at g*64 bytes, fr at g*64+32 bytes
	// twiddle index = 15-g → byte offset = (15-g)*2 = 30-g*2
	VPBROADCASTW 30(BX), Y7
	inttLevel3(AX, Y7, 0)

	VPBROADCASTW 28(BX), Y7
	inttLevel3(AX, Y7, 1)

	VPBROADCASTW 26(BX), Y7
	inttLevel3(AX, Y7, 2)

	VPBROADCASTW 24(BX), Y7
	inttLevel3(AX, Y7, 3)

	VPBROADCASTW 22(BX), Y7
	inttLevel3(AX, Y7, 4)

	VPBROADCASTW 20(BX), Y7
	inttLevel3(AX, Y7, 5)

	VPBROADCASTW 18(BX), Y7
	inttLevel3(AX, Y7, 6)

	VPBROADCASTW 16(BX), Y7
	inttLevel3(AX, Y7, 7)

	// ── L2: len=32, 4 groups, zeta = zetasMontgomery[7..4] ──────────────
	// group g: fl at g*128 bytes, fr at g*128+64 bytes
	// twiddle index = 7-g → byte offset = (7-g)*2 = 14-g*2
	VPBROADCASTW 14(BX), Y7
	inttLevel2(AX, Y7, 0, 0)
	inttLevel2(AX, Y7, 0, 1)

	VPBROADCASTW 12(BX), Y7
	inttLevel2(AX, Y7, 1, 0)
	inttLevel2(AX, Y7, 1, 1)

	VPBROADCASTW 10(BX), Y7
	inttLevel2(AX, Y7, 2, 0)
	inttLevel2(AX, Y7, 2, 1)

	VPBROADCASTW 8(BX), Y7
	inttLevel2(AX, Y7, 3, 0)
	inttLevel2(AX, Y7, 3, 1)

	// ── L1: len=64, 2 groups, zeta = zetasMontgomery[3..2] ──────────────
	// group 0: fl at 0, fr at 128 bytes; group 1: fl at 256, fr at 384
	VPBROADCASTW 6(BX), Y7
	inttLevel1(AX, Y7, 0, 0)
	inttLevel1(AX, Y7, 0, 1)
	inttLevel1(AX, Y7, 0, 2)
	inttLevel1(AX, Y7, 0, 3)

	VPBROADCASTW 4(BX), Y7
	inttLevel1(AX, Y7, 1, 0)
	inttLevel1(AX, Y7, 1, 1)
	inttLevel1(AX, Y7, 1, 2)
	inttLevel1(AX, Y7, 1, 3)

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
// gammaMulTable<> contains [r, γ[0], r, γ[1], ...] (r=2285=Montgomery 1).
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

	LEAQ gammaMulTable<>(SB), SI
	XORQ DI, DI           // DI = block byte offset (0..480 step 32)

nttmlacc_loop:
	CMPQ DI, $512
	JGE nttmlacc_done

	// Load 8 pairs (16 × int16) from lhs, rhs, acc, and gammaMulTable
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

	LEAQ gammaMulTable<>(SB), SI
	XORQ DI, DI           // DI = block byte offset (0..480 step 32)

nttmlacc_kg_loop:
	CMPQ DI, $512
	JGE nttmlacc_kg_done

	// Load 8 pairs (16 × int16) from lhs, rhs, acc, and gammaMulTable
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
