// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

DATA qNegInvYMM<>+0x00(SB)/4, $4236238847
DATA qNegInvYMM<>+0x04(SB)/4, $4236238847
DATA qNegInvYMM<>+0x08(SB)/4, $4236238847
DATA qNegInvYMM<>+0x0c(SB)/4, $4236238847
DATA qNegInvYMM<>+0x10(SB)/4, $4236238847
DATA qNegInvYMM<>+0x14(SB)/4, $4236238847
DATA qNegInvYMM<>+0x18(SB)/4, $4236238847
DATA qNegInvYMM<>+0x1c(SB)/4, $4236238847
GLOBL qNegInvYMM<>(SB), RODATA, $32

DATA qYMM<>+0x00(SB)/4, $8380417
DATA qYMM<>+0x04(SB)/4, $8380417
DATA qYMM<>+0x08(SB)/4, $8380417
DATA qYMM<>+0x0c(SB)/4, $8380417
DATA qYMM<>+0x10(SB)/4, $8380417
DATA qYMM<>+0x14(SB)/4, $8380417
DATA qYMM<>+0x18(SB)/4, $8380417
DATA qYMM<>+0x1c(SB)/4, $8380417
GLOBL qYMM<>(SB), RODATA, $32

DATA invDegreeMontgomery<>+0x00(SB)/4, $41978
DATA invDegreeMontgomery<>+0x04(SB)/4, $41978
DATA invDegreeMontgomery<>+0x08(SB)/4, $41978
DATA invDegreeMontgomery<>+0x0c(SB)/4, $41978
DATA invDegreeMontgomery<>+0x10(SB)/4, $41978
DATA invDegreeMontgomery<>+0x14(SB)/4, $41978
DATA invDegreeMontgomery<>+0x18(SB)/4, $41978
DATA invDegreeMontgomery<>+0x1c(SB)/4, $41978
GLOBL invDegreeMontgomery<>(SB), RODATA, $32

#define Q Y15
#define QNegInv Y14
#define ZETAL Y13
#define ZETAH Y12
#define TMP0 Y11
#define TMP1 Y10
#define TMP2 Y9

TEXT ·nttMulAVX2(SB), NOSPLIT, $0-24
	MOVQ lhs+0(FP), AX
	MOVQ rhs+8(FP), BX
	MOVQ out+16(FP), CX
	MOVL $32, DX

	VMOVDQU qNegInvYMM<>(SB), QNegInv
	VMOVDQU qYMM<>(SB), Q

loop:
	VMOVDQU (AX), Y0
	VMOVDQU (BX), Y1

	VPMULUDQ Y1, Y0, Y2 // multiply even indexes of a and b
	VPSRLQ $32, Y0, Y3
	VPSRLQ $32, Y1, Y4
	VPMULUDQ Y4, Y3, Y3 // multiply odd indexes of a and b

	// Montgomery reduction: t1 = a * b * qNegInv mod r
	VPMULUDQ QNegInv, Y2, Y5
	VPMULUDQ QNegInv, Y3, Y6

	VPMULUDQ Q, Y5, Y5
	VPMULUDQ Q, Y6, Y6

	VPADDQ Y2, Y5, Y5
	VPADDQ Y3, Y6, Y6

	VPSRLQ $32, Y5, Y5
	VPBLENDD $0xAA, Y6, Y5, Y7

	// Final reduction: if out >= q, subtract q
	VPCMPGTD Y7, Q, Y2
	VPANDN Q, Y2, Y2
	VPSUBD Y2, Y7, Y7

	VMOVDQU Y7, (CX)

	ADDQ $32, AX
	ADDQ $32, BX
	ADDQ $32, CX
	DECQ DX
	JNZ loop

	VZEROUPPER
	RET

TEXT ·nttMulAccAVX2(SB), NOSPLIT, $0-24
	MOVQ lhs+0(FP), AX
	MOVQ rhs+8(FP), BX
	MOVQ acc+16(FP), CX
	MOVL $32, DX

	VMOVDQU qNegInvYMM<>(SB), QNegInv
	VMOVDQU qYMM<>(SB), Q

loopAcc:
	VMOVDQU (AX), Y0
	VMOVDQU (BX), Y1

	VPMULUDQ Y1, Y0, Y2 // multiply even indexes of a and b
	VPSRLQ $32, Y0, Y3
	VPSRLQ $32, Y1, Y4
	VPMULUDQ Y4, Y3, Y3 // multiply odd indexes of a and b

	// Montgomery reduction: t1 = a * b * qNegInv mod r
	VPMULUDQ QNegInv, Y2, Y5
	VPMULUDQ QNegInv, Y3, Y6

	VPMULUDQ Q, Y5, Y5
	VPMULUDQ Q, Y6, Y6

	VPADDQ Y2, Y5, Y5
	VPADDQ Y3, Y6, Y6

	VPSRLQ $32, Y5, Y5
	VPBLENDD $0xAA, Y6, Y5, Y7

	// acc += reduced(lhs*rhs)
	VMOVDQU (CX), Y8
	VPADDD Y7, Y8, Y7

	// Final reduction: if out >= q, subtract q
	VPCMPGTD Y7, Q, Y2
	VPANDN Q, Y2, Y2
	VPSUBD Y2, Y7, Y7

	VMOVDQU Y7, (CX)

	ADDQ $32, AX
	ADDQ $32, BX
	ADDQ $32, CX
	DECQ DX
	JNZ loopAcc

	VZEROUPPER
	RET

TEXT ·polyAddAssignAVX2(SB), NOSPLIT, $0-16
	MOVQ dst+0(FP), AX
	MOVQ src+8(FP), BX
	MOVL $32, CX

	VMOVDQU qYMM<>(SB), Q

polyAddAssignLoop:
	VMOVDQU (AX), Y0
	VMOVDQU (BX), Y1
	VPADDD Y1, Y0, Y2

	VPCMPGTD Y2, Q, Y3
	VPANDN Q, Y3, Y3
	VPSUBD Y3, Y2, Y2

	VMOVDQU Y2, (AX)

	ADDQ $32, AX
	ADDQ $32, BX
	DECQ CX
	JNZ polyAddAssignLoop

	VZEROUPPER
	RET

TEXT ·polySubAssignAVX2(SB), NOSPLIT, $0-16
	MOVQ dst+0(FP), AX
	MOVQ src+8(FP), BX
	MOVL $32, CX

	VMOVDQU qYMM<>(SB), Q

polySubAssignLoop:
	VMOVDQU (AX), Y0
	VMOVDQU (BX), Y1
	VPADDD Q, Y0, Y2
	VPSUBD Y1, Y2, Y2

	VPCMPGTD Y2, Q, Y3
	VPANDN Q, Y3, Y3
	VPSUBD Y3, Y2, Y2

	VMOVDQU Y2, (AX)

	ADDQ $32, AX
	ADDQ $32, BX
	DECQ CX
	JNZ polySubAssignLoop

	VZEROUPPER
	RET

// out0 can't be the same register as in0 or in1
// in0 = [a0, a1, a2, a3 | a4, a5, a6, a7]
// in1 = [b0, b1, b2, b3 | b4, b5, b6, b7]
// out0 = [a0, a1, a2, a3 | b0, b1, b2, b3]
// out1 = [a4, a5, a6, a7 | b4, b5, b6, b7]
#define SHUFFLE8(in0, in1, out0, out1) \
	VPERM2I128 $0x20, in1, in0, out0; \
	VPERM2I128 $0x31, in1, in0, out1

// out0 can't be the same register as in0 or in1
// in0 = [a0, a1, a2, a3 | a4, a5, a6, a7]
// in1 = [b0, b1, b2, b3 | b4, b5, b6, b7]
// out0 = [a0, a1, b0, b1 | a4, a5, b4, b5]
// out1 = [a2, a3, b2, b3 | a6, a7, b6, b7]
#define SHUFFLE4(in0, in1, out0, out1) \
	VPUNPCKLQDQ in1, in0, out0; \
	VPUNPCKHQDQ in1, in0, out1

// out0 can't be the same register as in0 or in1
// in0 = [a0, a1, a2, a3 | a4, a5, a6, a7]
// in1 = [b0, b1, b2, b3 | b4, b5, b6, b7]
// out0 = [a0, b0, a2, b2 | a4, b4, a6, b6]
// out1 = [a1, b1, a3, b3 | a5, b5, a7, b7]
#define SHUFFLE2(in0, in1, out0, out1) \
	VPSLLQ $32, in1, out0; \
	VPBLENDD $0xAA, out0, in0, out0; \
	VPSRLQ $32, in0, in0; \
	VPBLENDD $0xAA, in1, in0, out1

#define fieldsMulEvenOdd(in, even, odd, out) \
	\ // // Multiply in and [even | odd]
	VPMULUDQ even, in, TMP0; \
	VPSRLQ $32, in, TMP1; \
	VPMULUDQ TMP1, odd, TMP1; \
	\ // Montgomery reduction: t1 = in * [even | odd] * QNegInv mod r
	VPMULUDQ QNegInv, TMP0, out; \
	VPMULUDQ QNegInv, TMP1, TMP2; \
	VPMULUDQ Q, out, out; \
	VPMULUDQ Q, TMP2, TMP2; \
	VPADDQ TMP0, out, out; \
	VPADDQ TMP1, TMP2, TMP1; \
	VPSRLQ $32, out, out; \
	VPBLENDD $0xAA, TMP1, out, out; \
	\ // Final reduction: if out >= q, subtract q
	VPCMPGTD out, Q, TMP0; \
	VPANDN Q, TMP0, TMP0; \
	VPSUBD TMP0, out, out

#define nttButterfly(even, odd, tmp, zetasL, zetasH, outEven, outOdd) \
	fieldsMulEvenOdd(odd, zetasL, zetasH, tmp); \
	VPADDD even, Q, TMP1; \
	VPSUBD tmp, TMP1, outOdd; \
	\
	VPADDD tmp, even, outEven; \
	\ // Final reduction: if outOdd >= q, subtract q
	VPCMPGTD outOdd, Q, TMP0; \
	VPANDN Q, TMP0, TMP0; \
	VPSUBD TMP0, outOdd, outOdd; \
	\ // Final reduction: if outEven >= q, subtract q
	VPCMPGTD outEven, Q, TMP0; \
	VPANDN Q, TMP0, TMP0; \
	VPSUBD TMP0, outEven, outEven

#define nttLevel0to1(dataAddr, zetasAddr, offset) \
	VMOVDQU ((offset)*32)+dataAddr, Y0; \
	VMOVDQU ((offset)*32+1*128)+dataAddr, Y1; \
	VMOVDQU ((offset)*32+2*128)+dataAddr, Y2; \
	VMOVDQU ((offset)*32+3*128)+dataAddr, Y3; \
	VMOVDQU ((offset)*32+4*128)+dataAddr, Y4; \
	VMOVDQU ((offset)*32+5*128)+dataAddr, Y5; \
	VMOVDQU ((offset)*32+6*128)+dataAddr, Y6; \
	VMOVDQU ((offset)*32+7*128)+dataAddr, Y7; \
	\ // level 0
	VPBROADCASTD 4+zetasAddr, ZETAL; \
	nttButterfly(Y0, Y4, Y8, ZETAL, ZETAL, Y0, Y4); \
	nttButterfly(Y1, Y5, Y8, ZETAL, ZETAL, Y1, Y5); \
	nttButterfly(Y2, Y6, Y8, ZETAL, ZETAL, Y2, Y6); \
	nttButterfly(Y3, Y7, Y8, ZETAL, ZETAL, Y3, Y7); \
	\ // level 1: offset = 64, step = 2
	VPBROADCASTD (4*2)+zetasAddr, ZETAL; \
	nttButterfly(Y0, Y2, Y8, ZETAL, ZETAL, Y0, Y2); \
	nttButterfly(Y1, Y3, Y8, ZETAL, ZETAL, Y1, Y3); \
	\
	VPBROADCASTD (4*3)+zetasAddr, ZETAL; \
	nttButterfly(Y4, Y6, Y8, ZETAL, ZETAL, Y4, Y6); \
	nttButterfly(Y5, Y7, Y8, ZETAL, ZETAL, Y5, Y7); \
	\
	VMOVDQU Y0, ((offset)*32)+dataAddr; \
	VMOVDQU Y1, ((offset)*32+1*128)+dataAddr; \
	VMOVDQU Y2, ((offset)*32+2*128)+dataAddr; \
	VMOVDQU Y3, ((offset)*32+3*128)+dataAddr; \
	VMOVDQU Y4, ((offset)*32+4*128)+dataAddr; \
	VMOVDQU Y5, ((offset)*32+5*128)+dataAddr; \
	VMOVDQU Y6, ((offset)*32+6*128)+dataAddr; \
	VMOVDQU Y7, ((offset)*32+7*128)+dataAddr

#define nttLevel2to7(dataAddr, zetasAddr, offset) \
	VMOVDQU ((offset)*256)+dataAddr, Y0; \
	VMOVDQU ((offset)*256+1*32)+dataAddr, Y1; \
	VMOVDQU ((offset)*256+2*32)+dataAddr, Y2; \
	VMOVDQU ((offset)*256+3*32)+dataAddr, Y3; \
	VMOVDQU ((offset)*256+4*32)+dataAddr, Y4; \
	VMOVDQU ((offset)*256+5*32)+dataAddr, Y5; \
	VMOVDQU ((offset)*256+6*32)+dataAddr, Y6; \
	VMOVDQU ((offset)*256+7*32)+dataAddr, Y7; \
	\ // level 2: offset = 32, step = 4
	VPBROADCASTD (16+(offset)*4)+zetasAddr, ZETAL; \
	nttButterfly(Y0, Y4, Y8, ZETAL, ZETAL, Y0, Y4); \
	nttButterfly(Y1, Y5, Y8, ZETAL, ZETAL, Y1, Y5); \
	nttButterfly(Y2, Y6, Y8, ZETAL, ZETAL, Y2, Y6); \
	nttButterfly(Y3, Y7, Y8, ZETAL, ZETAL, Y3, Y7); \
	\ // level 3: offset = 16, step = 8
	\ // input:
	\ // Y0 = [ 0  1  2  3 |  4  5  6  7]
	\ // Y1 = [ 8  9 10 11 | 12 13 14 15]
	\ // Y2 = [16 17 18 19 | 20 21 22 23]
	\ // Y3 = [24 25 26 27 | 28 29 30 31]
	\ // Y4 = [32 33 34 35 | 36 37 38 39]
	\ // Y5 = [40 41 42 43 | 44 45 46 47]
	\ // Y6 = [48 49 50 51 | 52 53 54 55]
	\ // Y7 = [56 57 58 59 | 60 61 62 63]
	\ // after SHUFFLE8:
	\ // Y8 = [ 0  1  2  3 | 32 33 34 35]
	\ // Y4 = [ 4  5  6  7 | 36 37 38 39]
	\ // Y0 = [ 8  9 10 11 | 40 41 42 43]
	\ // Y5 = [12 13 14 15 | 44 45 46 47]
	\ // Y1 = [16 17 18 19 | 48 49 50 51]
	\ // Y6 = [20 21 22 23 | 52 53 54 55]
	\ // Y2 = [24 25 26 27 | 56 57 58 59]
	\ // Y7 = [28 29 30 31 | 60 61 62 63]	
	SHUFFLE8(Y0, Y4, Y8, Y4); \
	SHUFFLE8(Y1, Y5, Y0, Y5); \
	SHUFFLE8(Y2, Y6, Y1, Y6); \
	SHUFFLE8(Y3, Y7, Y2, Y7); \
	VMOVDQU (32+(offset)*32)+zetasAddr, ZETAL; \
	nttButterfly(Y8, Y1, Y3, ZETAL, ZETAL, Y8, Y1); \
	nttButterfly(Y4, Y6, Y3, ZETAL, ZETAL, Y4, Y6); \
	nttButterfly(Y0, Y2, Y3, ZETAL, ZETAL, Y0, Y2); \
	nttButterfly(Y5, Y7, Y3, ZETAL, ZETAL, Y5, Y7); \	
	\ // level 4: offset = 8, step = 16
	\ // input:
	\ // Y8 = [ 0  1  2  3 | 32 33 34 35]
	\ // Y4 = [ 4  5  6  7 | 36 37 38 39]
	\ // Y0 = [ 8  9 10 11 | 40 41 42 43]
	\ // Y5 = [12 13 14 15 | 44 45 46 47]
	\ // Y1 = [16 17 18 19 | 48 49 50 51]
	\ // Y6 = [20 21 22 23 | 52 53 54 55]
	\ // Y2 = [24 25 26 27 | 56 57 58 59]
	\ // Y7 = [28 29 30 31 | 60 61 62 63]	
	\ // after SHUFFLE8:
	\ // Y3 = [0 1 16 17 | 32 33 48 49]
	\ // Y1 = [2 3 18 19 | 34 35 50 51]
	\ // Y8 = [4 5 20 21 | 36 37 52 53]
	\ // Y6 = [6 7 22 23 | 38 39 54 55]
	\ // Y4 = [8 9 24 25 | 40 41 56 57]
	\ // Y2 = [10 11 26 27 | 42 43 58 59]
	\ // Y0 = [12 13 28 29 | 44 45 60 61]
	\ // Y7 = [14 15 30 31 | 46 47 62 63]	
	SHUFFLE4(Y8, Y1, Y3, Y1); \
	SHUFFLE4(Y4, Y6, Y8, Y6); \
	SHUFFLE4(Y0, Y2, Y4, Y2); \
	SHUFFLE4(Y5, Y7, Y0, Y7); \
	VMOVDQU (160+(offset)*32)+zetasAddr, ZETAL; \
	nttButterfly(Y3, Y4, Y5, ZETAL, ZETAL, Y3, Y4); \
	nttButterfly(Y1, Y2, Y5, ZETAL, ZETAL, Y1, Y2); \
	nttButterfly(Y8, Y0, Y5, ZETAL, ZETAL, Y8, Y0); \
	nttButterfly(Y6, Y7, Y5, ZETAL, ZETAL, Y6, Y7); \
	\ // level 5: offset = 4, step = 32
	\ // input:
	\ // Y3 = [0 1 16 17 | 32 33 48 49]
	\ // Y1 = [2 3 18 19 | 34 35 50 51]
	\ // Y8 = [4 5 20 21 | 36 37 52 53]
	\ // Y6 = [6 7 22 23 | 38 39 54 55]
	\ // Y4 = [8 9 24 25 | 40 41 56 57]
	\ // Y2 = [10 11 26 27 | 42 43 58 59]
	\ // Y0 = [12 13 28 29 | 44 45 60 61]
	\ // Y7 = [14 15 30 31 | 46 47 62 63]
	\ // after SHUFFLE8:
	\ // Y5 = [0 8 16 24 | 32 40 48 56]
	\ // Y4 = [1 9 17 25 | 33 41 49 57]
	\ // Y3 = [2 10 18 26 | 34 42 50 58]
	\ // Y2 = [3 11 19 27 | 35 43 51 59]
	\ // Y1 = [4 12 20 28 | 36 44 52 60]
	\ // Y0 = [5 13 21 29 | 37 45 53 61]
	\ // Y8 = [6 14 22 30 | 38 46 54 62]
	\ // Y7 = [7 15 23 31 | 39 47 55 63]	
	SHUFFLE2(Y3, Y4, Y5, Y4); \
	SHUFFLE2(Y1, Y2, Y3, Y2); \
	SHUFFLE2(Y8, Y0, Y1, Y0); \
	SHUFFLE2(Y6, Y7, Y8, Y7); \
	VMOVDQU (288+(offset)*32)+zetasAddr, ZETAL; \
	VPSRLQ $32, ZETAL, ZETAH; \
	nttButterfly(Y5, Y1, Y6, ZETAL, ZETAH, Y5, Y1); \
	nttButterfly(Y4, Y0, Y6, ZETAL, ZETAH, Y4, Y0); \
	nttButterfly(Y3, Y8, Y6, ZETAL, ZETAH, Y3, Y8); \
	nttButterfly(Y2, Y7, Y6, ZETAL, ZETAH, Y2, Y7); \
	\ // level 6: offset = 2, step = 64
	VMOVDQU (416+(offset)*32)+zetasAddr, ZETAL; \
	VPSRLQ $32, ZETAL, ZETAH; \
	nttButterfly(Y5, Y3, Y6, ZETAL, ZETAH, Y5, Y3); \
	nttButterfly(Y4, Y2, Y6, ZETAL, ZETAH, Y4, Y2); \
	VMOVDQU (544+(offset)*32)+zetasAddr, ZETAL; \
	VPSRLQ $32, ZETAL, ZETAH; \
	nttButterfly(Y1, Y8, Y6, ZETAL, ZETAH, Y1, Y8); \
	nttButterfly(Y0, Y7, Y6, ZETAL, ZETAH, Y0, Y7); \
	\ // level 7: offset = 1, step = 128
	VMOVDQU (672+(offset)*32)+zetasAddr, ZETAL; \
	VPSRLQ $32, ZETAL, ZETAH; \
	nttButterfly(Y5, Y4, Y6, ZETAL, ZETAH, Y5, Y4); \
	VMOVDQU (800+(offset)*32)+zetasAddr, ZETAL; \
	VPSRLQ $32, ZETAL, ZETAH; \
	nttButterfly(Y3, Y2, Y6, ZETAL, ZETAH, Y3, Y2); \
	VMOVDQU (928+(offset)*32)+zetasAddr, ZETAL; \
	VPSRLQ $32, ZETAL, ZETAH; \
	nttButterfly(Y1, Y0, Y6, ZETAL, ZETAH, Y1, Y0); \
	VMOVDQU (1056+(offset)*32)+zetasAddr, ZETAL; \
	VPSRLQ $32, ZETAL, ZETAH; \
	nttButterfly(Y8, Y7, Y6, ZETAL, ZETAH, Y8, Y7); \
	\ // matrix transpose
	SHUFFLE8(Y5, Y1, Y6, Y1); \
	SHUFFLE8(Y4, Y0, Y5, Y0); \
	SHUFFLE8(Y3, Y8, Y4, Y8); \
	SHUFFLE8(Y2, Y7, Y3, Y7); \
	\
	SHUFFLE4(Y6, Y4, Y2, Y4); \
	SHUFFLE4(Y1, Y8, Y6, Y8); \
	SHUFFLE4(Y5, Y3, Y1, Y3); \
	SHUFFLE4(Y0, Y7, Y5, Y7); \
	\
	SHUFFLE2(Y2, Y1, Y0, Y1); \
	SHUFFLE2(Y4, Y3, Y2, Y3); \
	SHUFFLE2(Y6, Y5, Y4, Y5); \
	SHUFFLE2(Y8, Y7, Y6, Y7); \	
	\ // store back
	VMOVDQU Y0, ((offset)*256)+dataAddr; \
	VMOVDQU Y1, ((offset)*256+1*32)+dataAddr; \
	VMOVDQU Y2, ((offset)*256+2*32)+dataAddr; \
	VMOVDQU Y3, ((offset)*256+3*32)+dataAddr; \
	VMOVDQU Y4, ((offset)*256+4*32)+dataAddr; \
	VMOVDQU Y5, ((offset)*256+5*32)+dataAddr; \
	VMOVDQU Y6, ((offset)*256+6*32)+dataAddr; \
	VMOVDQU Y7, ((offset)*256+7*32)+dataAddr; \

#define inttButterfly(even, odd, tmp, zetasL, zetasH, outEven, outOdd) \
	\ // outOdd = (Q + even - odd) * zeta
	\ // Compute this first because outEven can alias even in callers.
	VPSUBD odd, Q, tmp; \
	VPADDD even, tmp, tmp; \
	\ // outEven = even + odd
	VPADDD even, odd, outEven; \
	\ // Final reduction: if outEven >= q, subtract q
	VPCMPGTD outEven, Q, TMP1; \
	VPANDN Q, TMP1, TMP1; \
	VPSUBD TMP1, outEven, outEven; \
	\ // outOdd = (Q + even - odd) * zeta
	fieldsMulEvenOdd(tmp, zetasL, zetasH, outOdd)

#define inttLevel0to5(dataAddr, zetasAddr, offset) \
	VMOVDQU ((offset)*256)+dataAddr, Y0; \
	VMOVDQU ((offset)*256+1*32)+dataAddr, Y1; \
	VMOVDQU ((offset)*256+2*32)+dataAddr, Y2; \
	VMOVDQU ((offset)*256+3*32)+dataAddr, Y3; \
	VMOVDQU ((offset)*256+4*32)+dataAddr, Y4; \
	VMOVDQU ((offset)*256+5*32)+dataAddr, Y5; \
	VMOVDQU ((offset)*256+6*32)+dataAddr, Y6; \
	VMOVDQU ((offset)*256+7*32)+dataAddr, Y7; \
	\ // matrix transpose first, to rearrange the input data for better locality in the butterfly operations.
	\ // Input dword layout:
	\ //   ymm0 = [0 1 2 3 | 4 5 6 7]
	\ //   ymm1 = [8 9 10 11 | 12 13 14 15]
	\ //   ymm2 = [16 17 18 19 | 20 21 22 23]
	\ //   ymm3 = [24 25 26 27 | 28 29 30 31]
	\ //   ymm4 = [32 33 34 35 | 36 37 38 39]
	\ //   ymm5 = [40 41 42 43 | 44 45 46 47]
	\ //   ymm6 = [48 49 50 51 | 52 53 54 55]
	\ //   ymm7 = [56 57 58 59 | 60 61 62 63]
	\ // Required dword layout:
	\ //   ymm5 = [0 8 16 24 | 32 40 48 56]
	\ //   ymm4 = [1 9 17 25 | 33 41 49 57]
	\ //   ymm3 = [2 10 18 26 | 34 42 50 58]
	\ //   ymm2 = [3 11 19 27 | 35 43 51 59]
	\ //   ymm1 = [4 12 20 28 | 36 44 52 60]
	\ //   ymm0 = [5 13 21 29 | 37 45 53 61]
	\ //   ymm8 = [6 14 22 30 | 38 46 54 62]
	\ //   ymm7 = [7 15 23 31 | 39 47 55 63]
	SHUFFLE8(Y0, Y4, Y8, Y4); \
	SHUFFLE8(Y1, Y5, Y0, Y5); \
	SHUFFLE8(Y2, Y6, Y1, Y6); \
	SHUFFLE8(Y3, Y7, Y2, Y7); \
	\
	SHUFFLE4(Y8, Y1, Y3, Y1); \
	SHUFFLE4(Y4, Y6, Y8, Y6); \
	SHUFFLE4(Y0, Y2, Y4, Y2); \
	SHUFFLE4(Y5, Y7, Y0, Y7); \
	\
	SHUFFLE2(Y3, Y4, Y5, Y4); \
	SHUFFLE2(Y1, Y2, Y3, Y2); \
	SHUFFLE2(Y8, Y0, Y1, Y0); \
	SHUFFLE2(Y6, Y7, Y8, Y7); \
	\ // level 0: offset = 1, step = 128
	VMOVDQU (296-8-8*offset)*4+zetasAddr, ZETAH; \
	VPERMQ $0x1B, ZETAH, ZETAH; \
	VPSRLQ $32, ZETAH, ZETAL; \
	inttButterfly(Y5, Y4, Y6, ZETAL, ZETAH, Y5, Y4); \
	\
	VMOVDQU (296-40-8*offset)*4+zetasAddr, ZETAH; \
	VPERMQ $0x1B, ZETAH, ZETAH; \
	VPSRLQ $32, ZETAH, ZETAL; \
	inttButterfly(Y3, Y2, Y6, ZETAL, ZETAH, Y3, Y2); \
	\
	VMOVDQU (296-72-8*offset)*4+zetasAddr, ZETAH; \
	VPERMQ $0x1B, ZETAH, ZETAH; \
	VPSRLQ $32, ZETAH, ZETAL; \
	inttButterfly(Y1, Y0, Y6, ZETAL, ZETAH, Y1, Y0); \
	\ 
	VMOVDQU (296-104-8*offset)*4+zetasAddr, ZETAH; \
	VPERMQ $0x1B, ZETAH, ZETAH; \
	VPSRLQ $32, ZETAH, ZETAL; \
	inttButterfly(Y8, Y7, Y6, ZETAL, ZETAH, Y8, Y7); \
	\ // level 1: offset = 2, step = 64
	VMOVDQU (168-8-8*offset)*4+zetasAddr, ZETAH; \
	VPERMQ $0x1B, ZETAH, ZETAH; \
	VPSRLQ $32, ZETAH, ZETAL; \
	inttButterfly(Y5, Y3, Y6, ZETAL, ZETAH, Y5, Y3); \
	inttButterfly(Y4, Y2, Y6, ZETAL, ZETAH, Y4, Y2); \
	\
	VMOVDQU (168-40-8*offset)*4+zetasAddr, ZETAH; \
	VPERMQ $0x1B, ZETAH, ZETAH; \
	VPSRLQ $32, ZETAH, ZETAL; \
	inttButterfly(Y1, Y8, Y6, ZETAL, ZETAH, Y1, Y8); \
	inttButterfly(Y0, Y7, Y6, ZETAL, ZETAH, Y0, Y7); \
	\ // level 2: offset = 4, step = 32
	VMOVDQU (104-8-8*offset)*4+zetasAddr, ZETAH; \
	VPERMQ $0x1B, ZETAH, ZETAH; \
	VPSRLQ $32, ZETAH, ZETAL; \
	inttButterfly(Y5, Y1, Y6, ZETAL, ZETAH, Y5, Y1); \
	inttButterfly(Y4, Y0, Y6, ZETAL, ZETAH, Y4, Y0); \
	inttButterfly(Y3, Y8, Y6, ZETAL, ZETAH, Y3, Y8); \
	inttButterfly(Y2, Y7, Y6, ZETAL, ZETAH, Y2, Y7); \
	\ // level 3: offset = 8, step = 16
	\ // Input dword layout:
	\ //   ymm5 = [0 8 16 24 | 32 40 48 56]
	\ //   ymm4 = [1 9 17 25 | 33 41 49 57]
	\ //   ymm3 = [2 10 18 26 | 34 42 50 58]
	\ //   ymm2 = [3 11 19 27 | 35 43 51 59]
	\ //   ymm1 = [4 12 20 28 | 36 44 52 60]
	\ //   ymm0 = [5 13 21 29 | 37 45 53 61]
	\ //   ymm8 = [6 14 22 30 | 38 46 54 62]
	\ //   ymm7 = [7 15 23 31 | 39 47 55 63]
	\ // Required dword layout:
	\ //   ymm6 = [0 1 16 17 | 32 33 48 49]
	\ //   ymm4 = [8 9 24 25 | 40 41 56 57]
	\ //   ymm5 = [2 3 18 19 | 34 35 50 51]
	\ //   ymm2 = [10 11 26 27 | 42 43 58 59]
	\ //   ymm3 = [4 5 20 21 | 36 37 52 53]
	\ //   ymm0 = [12 13 28 29 | 44 45 60 61]
	\ //   ymm1 = [6 7 22 23 | 38 39 54 55]
	\ //   ymm7 = [14 15 30 31 | 46 47 62 63]
	SHUFFLE2(Y5, Y4, Y6, Y4); \
	SHUFFLE2(Y3, Y2, Y5, Y2); \
	SHUFFLE2(Y1, Y0, Y3, Y0); \
	SHUFFLE2(Y8, Y7, Y1, Y7); \
	VMOVDQU (72-8-8*offset)*4+zetasAddr, ZETAH; \
	VPERMQ $0x1B, ZETAH, ZETAH; \
	VPSRLQ $32, ZETAH, ZETAL; \
	inttButterfly(Y6, Y4, Y8, ZETAL, ZETAH, Y6, Y4); \
	inttButterfly(Y5, Y2, Y8, ZETAL, ZETAH, Y5, Y2); \
	inttButterfly(Y3, Y0, Y8, ZETAL, ZETAH, Y3, Y0); \
	inttButterfly(Y1, Y7, Y8, ZETAL, ZETAH, Y1, Y7); \
	\ // level 4: offset = 16, step = 8
	\ // Input dword layout:
	\ //   ymm6 = [0 1 16 17 | 32 33 48 49]
	\ //   ymm4 = [8 9 24 25 | 40 41 56 57]
	\ //   ymm5 = [2 3 18 19 | 34 35 50 51]
	\ //   ymm2 = [10 11 26 27 | 42 43 58 59]
	\ //   ymm3 = [4 5 20 21 | 36 37 52 53]
	\ //   ymm0 = [12 13 28 29 | 44 45 60 61]
	\ //   ymm1 = [6 7 22 23 | 38 39 54 55]
	\ //   ymm7 = [14 15 30 31 | 46 47 62 63]
	\ // Required dword layout:
	\ //   ymm8 = [0 1 2 3 | 32 33 34 35]
	\ //   ymm5 = [16 17 18 19 | 48 49 50 51]
	\ //   ymm6 = [4 5 6 7 | 36 37 38 39]
	\ //   ymm1 = [20 21 22 23 | 52 53 54 55]
	\ //   ymm3 = [8 9 10 11 | 40 41 42 43]
	\ //   ymm2 = [24 25 26 27 | 56 57 58 59]
	\ //   ymm4 = [12 13 14 15 | 44 45 46 47]
	\ //   ymm7 = [28 29 30 31 | 60 61 62 63]
	SHUFFLE4(Y6, Y5, Y8, Y5); \
	SHUFFLE4(Y3, Y1, Y6, Y1); \
	SHUFFLE4(Y4, Y2, Y3, Y2); \
	SHUFFLE4(Y0, Y7, Y4, Y7); \
	VMOVDQU (40-8-8*offset)*4+zetasAddr, ZETAL; \
	VPERMQ $0x1B, ZETAL, ZETAL; \
	inttButterfly(Y8, Y5, Y0, ZETAL, ZETAL, Y8, Y5); \
	inttButterfly(Y6, Y1, Y0, ZETAL, ZETAL, Y6, Y1); \
	inttButterfly(Y3, Y2, Y0, ZETAL, ZETAL, Y3, Y2); \
	inttButterfly(Y4, Y7, Y0, ZETAL, ZETAL, Y4, Y7); \
	\ // level 5: offset = 32, step = 4
	\ // Input dword layout:
	\ //   ymm8 = [0 1 2 3 | 32 33 34 35]
	\ //   ymm5 = [16 17 18 19 | 48 49 50 51]
	\ //   ymm6 = [4 5 6 7 | 36 37 38 39]
	\ //   ymm1 = [20 21 22 23 | 52 53 54 55]
	\ //   ymm3 = [8 9 10 11 | 40 41 42 43]
	\ //   ymm2 = [24 25 26 27 | 56 57 58 59]
	\ //   ymm4 = [12 13 14 15 | 44 45 46 47]
	\ //   ymm7 = [28 29 30 31 | 60 61 62 63]
	\ // Required dword layout:
	\ //   ymm0 = [0 1 2 3 | 4 5 6 7]
	\ //   ymm6 = [32 33 34 35 | 36 37 38 39]
	\ //   ymm8 = [8 9 10 11 | 12 13 14 15]
	\ //   ymm4 = [40 41 42 43 | 44 45 46 47]
	\ //   ymm3 = [16 17 18 19 | 20 21 22 23]
	\ //   ymm1 = [48 49 50 51 | 52 53 54 55]
	\ //   ymm5 = [24 25 26 27 | 28 29 30 31]
	\ //   ymm7 = [56 57 58 59 | 60 61 62 63]
	SHUFFLE8(Y8, Y6, Y0, Y6); \
	SHUFFLE8(Y3, Y4, Y8, Y4); \
	SHUFFLE8(Y5, Y1, Y3, Y1); \
	SHUFFLE8(Y2, Y7, Y5, Y7); \
	VPBROADCASTD (7-offset)*4+zetasAddr, ZETAL; \
	inttButterfly(Y0, Y6, Y2, ZETAL, ZETAL, Y0, Y6); \
	inttButterfly(Y8, Y4, Y2, ZETAL, ZETAL, Y8, Y4); \
	inttButterfly(Y3, Y1, Y2, ZETAL, ZETAL, Y3, Y1); \
	inttButterfly(Y5, Y7, Y2, ZETAL, ZETAL, Y5, Y7); \
	\ // store back
	VMOVDQU Y0, ((offset)*256)+dataAddr; \
	VMOVDQU Y8, ((offset)*256+1*32)+dataAddr; \
	VMOVDQU Y3, ((offset)*256+2*32)+dataAddr; \
	VMOVDQU Y5, ((offset)*256+3*32)+dataAddr; \
	VMOVDQU Y6, ((offset)*256+4*32)+dataAddr; \
	VMOVDQU Y4, ((offset)*256+5*32)+dataAddr; \
	VMOVDQU Y1, ((offset)*256+6*32)+dataAddr; \
	VMOVDQU Y7, ((offset)*256+7*32)+dataAddr

#define inttLevel6to7(dataAddr, zetasAddr, offset) \
	VMOVDQU ((offset)*32)+dataAddr, Y0; \
	VMOVDQU ((offset)*32+1*128)+dataAddr, Y1; \
	VMOVDQU ((offset)*32+2*128)+dataAddr, Y2; \
	VMOVDQU ((offset)*32+3*128)+dataAddr, Y3; \
	VMOVDQU ((offset)*32+4*128)+dataAddr, Y4; \
	VMOVDQU ((offset)*32+5*128)+dataAddr, Y5; \
	VMOVDQU ((offset)*32+6*128)+dataAddr, Y6; \
	VMOVDQU ((offset)*32+7*128)+dataAddr, Y7; \
	\ // level 6: offset = 64, step = 2
	VPBROADCASTD (3*4)+zetasAddr, ZETAL; \
	inttButterfly(Y0, Y2, Y8, ZETAL, ZETAL, Y0, Y2); \
	inttButterfly(Y1, Y3, Y8, ZETAL, ZETAL, Y1, Y3); \
	\
	VPBROADCASTD (2*4)+zetasAddr, ZETAL; \
	inttButterfly(Y4, Y6, Y8, ZETAL, ZETAL, Y4, Y6); \
	inttButterfly(Y5, Y7, Y8, ZETAL, ZETAL, Y5, Y7); \
	\ // level 7: offset = 128, step = 1
	VPBROADCASTD (1*4)+zetasAddr, ZETAL; \
	inttButterfly(Y0, Y4, Y8, ZETAL, ZETAL, Y0, Y4); \
	inttButterfly(Y1, Y5, Y8, ZETAL, ZETAL, Y1, Y5); \
	inttButterfly(Y2, Y6, Y8, ZETAL, ZETAL, Y2, Y6); \
	inttButterfly(Y3, Y7, Y8, ZETAL, ZETAL, Y3, Y7); \
	\ // multiply by 41978, 41978 = ((256⁻¹ mod q) * (2³² * 2³² mod q)) mod q
	fieldsMulEvenOdd(Y0, ZETAH, ZETAH, Y8); \
	fieldsMulEvenOdd(Y1, ZETAH, ZETAH, Y0); \
	fieldsMulEvenOdd(Y2, ZETAH, ZETAH, Y1); \
	fieldsMulEvenOdd(Y3, ZETAH, ZETAH, Y2); \
	fieldsMulEvenOdd(Y4, ZETAH, ZETAH, Y3); \
	fieldsMulEvenOdd(Y5, ZETAH, ZETAH, Y4); \
	fieldsMulEvenOdd(Y6, ZETAH, ZETAH, Y5); \
	fieldsMulEvenOdd(Y7, ZETAH, ZETAH, Y6); \
	\ // store back
	VMOVDQU Y8, ((offset)*32)+dataAddr; \
	VMOVDQU Y0, ((offset)*32+1*128)+dataAddr; \
	VMOVDQU Y1, ((offset)*32+2*128)+dataAddr; \
	VMOVDQU Y2, ((offset)*32+3*128)+dataAddr; \
	VMOVDQU Y3, ((offset)*32+4*128)+dataAddr; \
	VMOVDQU Y4, ((offset)*32+5*128)+dataAddr; \
	VMOVDQU Y5, ((offset)*32+6*128)+dataAddr; \
	VMOVDQU Y6, ((offset)*32+7*128)+dataAddr

TEXT ·internalNTTAVX2(SB), NOSPLIT, $0-8
	MOVQ f+0(FP), AX
	MOVQ $·zetasMontgomeryAVX2(SB), BX

	VMOVDQU qNegInvYMM<>(SB), QNegInv
	VMOVDQU qYMM<>(SB), Q

	nttLevel0to1(0(AX), 0(BX), 0)
	nttLevel0to1(0(AX), 0(BX), 1)
	nttLevel0to1(0(AX), 0(BX), 2)
	nttLevel0to1(0(AX), 0(BX), 3)

	nttLevel2to7(0(AX), 0(BX), 0)
	nttLevel2to7(0(AX), 0(BX), 1)
	nttLevel2to7(0(AX), 0(BX), 2)
	nttLevel2to7(0(AX), 0(BX), 3)

	VZEROUPPER
	RET

TEXT ·internalInverseNTTAVX2(SB), NOSPLIT, $0-8
	MOVQ f+0(FP), AX
	MOVQ $·qMinusZetasMontgomeryAVX2(SB), BX

	VMOVDQU qNegInvYMM<>(SB), QNegInv
	VMOVDQU qYMM<>(SB), Q

	inttLevel0to5(0(AX), 0(BX), 0)
	inttLevel0to5(0(AX), 0(BX), 1)
	inttLevel0to5(0(AX), 0(BX), 2)
	inttLevel0to5(0(AX), 0(BX), 3)

	VMOVDQU invDegreeMontgomery<>(SB), ZETAH
	inttLevel6to7(0(AX), 0(BX), 0)
	inttLevel6to7(0(AX), 0(BX), 1)
	inttLevel6to7(0(AX), 0(BX), 2)
	inttLevel6to7(0(AX), 0(BX), 3)

	VZEROUPPER
	RET
