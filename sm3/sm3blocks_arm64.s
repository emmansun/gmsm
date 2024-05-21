//go:build !purego

#include "textflag.h"
#include "sm3_const_asm.s"

#define a V0
#define b V1
#define c V2
#define d V3
#define e V4
#define f V5
#define g V6
#define h V7

#define tmp1 V8
#define tmp2 V9
#define tmp3 V10
#define tmp4 V11

// input: from high to low
// t0 = t0.S3, t0.S2, t0.S1, t0.S0
// t1 = t1.S3, t1.S2, t1.S1, t1.S0
// t2 = t2.S3, t2.S2, t2.S1, t2.S0
// t3 = t3.S3, t3.S2, t3.S1, t3.S0
// output: from high to low
// t0 = t3.S0, t2.S0, t1.S0, t0.S0
// t1 = t3.S1, t2.S1, t1.S1, t0.S1
// t2 = t3.S2, t2.S2, t1.S2, t0.S2
// t3 = t3.S3, t2.S3, t1.S3, t0.S3
#define TRANSPOSE_MATRIX(t0, t1, t2, t3, RTMP0, RTMP1, RTMP2, RTMP3) \
	VZIP1 t1.S4, t0.S4, RTMP0.S4               \
	VZIP1 t3.S4, t2.S4, RTMP1.S4               \
	VZIP2 t1.S4, t0.S4, RTMP2.S4               \
	VZIP2 t3.S4, t2.S4, RTMP3.S4               \
	VZIP1 RTMP1.D2, RTMP0.D2, t0.D2            \
	VZIP2 RTMP1.D2, RTMP0.D2, t1.D2            \
	VZIP1 RTMP3.D2, RTMP2.D2, t2.D2            \
	VZIP2 RTMP3.D2, RTMP2.D2, t3.D2            \

// d = s <<< n
#define PROLD(s, d, n) \
	VSHL $(n), s.S4, d.S4     \
	VSRI $(32-n), s.S4, d.S4  \

#define loadWordByIndex(W, i) \
	ADD $(16*(i)), wordStart, R20 \
	VLD1 (R20), [W.S4]          \ 

#define prepare4Words \
	VLD1.P 16(srcPtr1), [V12.B16] \
	VLD1.P 16(srcPtr2), [V13.B16] \
	VLD1.P 16(srcPtr3), [V14.B16] \
	VLD1.P 16(srcPtr4), [V15.B16] \	
	TRANSPOSE_MATRIX(V12, V13, V14, V15, tmp1, tmp2, tmp3, tmp4); \
	VREV32 V12.B16, V12.B16; \
	VREV32 V13.B16, V13.B16; \
	VREV32 V14.B16, V14.B16; \
	VREV32 V15.B16, V15.B16; \
	VST1.P [V12.B16, V13.B16, V14.B16, V15.B16], 64(wordPtr)

#define LOAD_T(const, T) \
	MOVD $const, R20     \
	VDUP R20, T.S4       \

#define ROUND_00_11(index, const, a, b, c, d, e, f, g, h) \
	PROLD(a, V12, 12)                \
	VMOV V12.B16, V13.B16            \
	LOAD_T(const, tmp1)              \
	VADD tmp1.S4, V12.S4, V12.S4     \
	VADD e.S4, V12.S4, V12.S4        \
	PROLD(V12, V14, 7)               \ // V14 = SS1
	VEOR V14.B16, V13.B16, V12.B16   \ // V12 = SS2
	VEOR a.B16, b.B16, V13.B16       \
	VEOR c.B16, V13.B16, V13.B16     \
	VADD V13.S4, d.S4, V13.S4        \ // V13 = (a XOR b XOR c) + d 
	loadWordByIndex(V10, index)      \
	loadWordByIndex(V11, index+4)    \
	VEOR V10.B16, V11.B16, V11.B16   \
	VADD V11.S4, V13.S4, V13.S4      \ // V13 = (a XOR b XOR c) + d + (Wt XOR Wt+4)
	VADD V13.S4, V12.S4, V13.S4      \ // TT1
	VADD h.S4, V10.S4, V10.S4        \
	VADD V14.S4, V10.S4, V10.S4      \ // Wt + h + SS1
	VEOR e.B16, f.B16, V11.B16       \
	VEOR g.B16, V11.B16, V11.B16     \
	VADD V11.S4, V10.S4, V10.S4      \ // TT2 = (e XOR f XOR g) + Wt + h + SS1
	VMOV b.B16, V11.B16              \
	PROLD(V11, b, 9)                 \ // b = b <<< 9
	VMOV V13.B16, h.B16              \ // h = TT1
	VMOV f.B16, V11.B16              \
	PROLD(V11, f, 19)                \ // f = f <<< 19
	PROLD(V10, V11, 9)               \ // V11 = TT2 <<< 9
	PROLD(V11, V12, 8)               \ // V12 = TT2 <<< 17
	VEOR V10.B16, V11.B16, V11.B16   \ // V11 = TT2 XOR (TT2 <<< 9)
	VEOR V11.B16, V12.B16, d.B16     \ // d = TT2 XOR (TT2 <<< 9) XOR (TT2 <<< 17)

#define MESSAGE_SCHEDULE(index) \
	loadWordByIndex(V10, index+1)    \ // Wj-3
	PROLD(V10, V11, 15)              \
	loadWordByIndex(V10, index-12)   \ // Wj-16
	VEOR V10.B16, V11.B16, V10.B16   \
	loadWordByIndex(V11, index-5)    \ // Wj-9
	VEOR V10.B16, V11.B16, V10.B16   \
	PROLD(V10, V11, 15)              \
	PROLD(V11, V12, 8)               \
	VEOR V11.B16, V10.B16, V10.B16   \
	VEOR V12.B16, V10.B16, V10.B16   \ // P1
	loadWordByIndex(V11, index-9)    \ // Wj-13
	PROLD(V11, V12, 7)               \
	VEOR V12.B16, V10.B16, V10.B16   \
	loadWordByIndex(V11, index-2)    \ // Wj-6
	VEOR V11.B16, V10.B16, V11.B16   \
	VST1.P [V11.S4], 16(wordPtr)     \

#define ROUND_12_15(index, const, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index)                        \
	ROUND_00_11(index, const, a, b, c, d, e, f, g, h)     \

#define ROUND_16_63(index, const, a, b, c, d, e, f, g, h) \
	MESSAGE_SCHEDULE(index); \ // V11 is Wt+4 now, Pls do not use it
	PROLD(a, V12, 12)                \
	VMOV V12.B16, V13.B16            \
	LOAD_T(const, tmp1)              \
	VADD tmp1.S4, V12.S4, V12.S4     \
	VADD e.S4, V12.S4, V12.S4        \
	PROLD(V12, V14, 7)               \ // V14 = SS1
	VEOR V14.B16, V13.B16, V12.B16   \ // V12 = SS2
	VORR a.B16, b.B16, V10.B16       \
	VAND a.B16, b.B16, V13.B16       \
	VAND c.B16, V10.B16, V10.B16     \
	VORR V13.B16, V10.B16, V13.B16   \ // (a AND b) OR (a AND c) OR (b AND c)
	VADD V13.S4, d.S4, V13.S4        \ // (a AND b) OR (a AND c) OR (b AND c) + d
	loadWordByIndex(V10, index)      \ // Wj
	VEOR V10.B16, V11.B16, V11.B16   \ // Wj XOR Wj+4
	VADD V13.S4, V11.S4, V13.S4      \ // (a AND b) OR (a AND c) OR (b AND c) + d + (Wt XOR Wt+4)
	VADD V13.S4, V12.S4, V13.S4      \ // TT1
	VADD h.S4, V10.S4, V10.S4        \ // Wt + h
	VADD V12.S4, V10.S4, V10.S4      \ // Wt + h + SS1
	VEOR f.B16, g.B16, V11.B16       \
	VAND V11.B16, e.B16, V11.B16     \
	VEOR g.B16, v11.B16, V11.B16     \ // (f XOR g) AND e XOR g
	VADD V14.S4, V11.S4, V10.S4      \ // TT2
	VMOV b.B16, V11.B16              \
	PROLD(V11, b, 9)                 \ // b = b <<< 9
	VMOV V13.B16, h.B16              \ // h = TT1
	VMOV f.B16, V11.B16              \
	PROLD(V11, f, 19)                \ // f = f <<< 19
	PROLD(V10, V11, 9)               \ // V11 = TT2 <<< 9
	PROLD(V11, V12, 8)               \ // V12 = TT2 <<< 17
	VEOR V10.B16, V11.B16, V11.B16   \ // V11 = TT2 XOR (TT2 <<< 9)
	VEOR V11.B16, V12.B16, d.B16     \ // d = TT2 XOR (TT2 <<< 9) XOR (TT2 <<< 17)

// func blockMultBy4(dig *digest, p []byte)
TEXT ·blockMultBy4(SB), NOSPLIT, $0
#define digPtr R0
#define srcPtrPtr R1
#define statePtr R2
#define blockCount R3
#define digSave R4
#define wordStart R5
#define srcPtr1 R6
#define srcPtr2 R7
#define srcPtr3 R8
#define srcPtr4 R9
#define wordPtr R10
	MOVD	dig+0(FP), digPtr
	MOVD	p+8(FP), srcPtrPtr
	MOVD	buffer+16(FP), statePtr
	MOVD	blocks+24(FP), blockCount

	// load state
	MOVD digPtr, digSave
	MOVD.P 8(digPtr), R20
	VLD1.P 16(R20), [a.S4]
	VLD1 (R20), [e.S4]
	MOVD.P 8(digPtr), R20
	VLD1.P 16(R20), [b.S4]
	VLD1 (R20), [f.S4]
	MOVD.P 8(digPtr), R20
	VLD1.P 16(R20), [c.S4]
	VLD1 (R20), [g.S4]
	MOVD (digPtr), R20
	VLD1.P 16(R20), [d.S4]
	VLD1 (R20), [h.S4]

	// transpose state
	TRANSPOSE_MATRIX(a, b, c, d, tmp1, tmp2, tmp3, tmp4)
	TRANSPOSE_MATRIX(e, f, g, h, tmp1, tmp2, tmp3, tmp4)

	// store state to temporary buffer
	MOVD statePtr, wordStart
	VST1.P [a.S4, b.S4, c.S4, d.S4], 64(wordStart)
	VST1.P [e.S4, f.S4, g.S4, h.S4], 64(wordStart)
	MOVD wordStart, wordPtr

	MOVD.P 8(srcPtrPtr), srcPtr1
	MOVD.P 8(srcPtrPtr), srcPtr2
	MOVD.P 8(srcPtrPtr), srcPtr3
	MOVD (srcPtrPtr), srcPtr4

loop:
	// load message block
	prepare4Words
	prepare4Words
	prepare4Words
	prepare4Words

	ROUND_00_11(0, T0, a, b, c, d, e, f, g, h)
	ROUND_00_11(1, T1, h, a, b, c, d, e, f, g)
	ROUND_00_11(2, T2, g, h, a, b, c, d, e, f)
	ROUND_00_11(3, T3, f, g, h, a, b, c, d, e)
	ROUND_00_11(4, T4, e, f, g, h, a, b, c, d)
	ROUND_00_11(5, T5, d, e, f, g, h, a, b, c)
	ROUND_00_11(6, T6, c, d, e, f, g, h, a, b)
	ROUND_00_11(7, T7, b, c, d, e, f, g, h, a)
	ROUND_00_11(8, T8, a, b, c, d, e, f, g, h)
	ROUND_00_11(9, T9, h, a, b, c, d, e, f, g)
	ROUND_00_11(10, T10, g, h, a, b, c, d, e, f)
	ROUND_00_11(11, T11, f, g, h, a, b, c, d, e)

	ROUND_12_15(12, T12, e, f, g, h, a, b, c, d)
	ROUND_12_15(13, T13, d, e, f, g, h, a, b, c)
	ROUND_12_15(14, T14, c, d, e, f, g, h, a, b)
	ROUND_12_15(15, T15, b, c, d, e, f, g, h, a)

	ROUND_16_63(16, T16, a, b, c, d, e, f, g, h)
	ROUND_16_63(17, T17, h, a, b, c, d, e, f, g)
	ROUND_16_63(18, T18, g, h, a, b, c, d, e, f)
	ROUND_16_63(19, T19, f, g, h, a, b, c, d, e)
	ROUND_16_63(20, T20, e, f, g, h, a, b, c, d)
	ROUND_16_63(21, T21, d, e, f, g, h, a, b, c)
	ROUND_16_63(22, T22, c, d, e, f, g, h, a, b)
	ROUND_16_63(23, T23, b, c, d, e, f, g, h, a)
	ROUND_16_63(24, T24, a, b, c, d, e, f, g, h)
	ROUND_16_63(25, T25, h, a, b, c, d, e, f, g)
	ROUND_16_63(26, T26, g, h, a, b, c, d, e, f)
	ROUND_16_63(27, T27, f, g, h, a, b, c, d, e)
	ROUND_16_63(28, T28, e, f, g, h, a, b, c, d)
	ROUND_16_63(29, T29, d, e, f, g, h, a, b, c)
	ROUND_16_63(30, T30, c, d, e, f, g, h, a, b)
	ROUND_16_63(31, T31, b, c, d, e, f, g, h, a)
	ROUND_16_63(32, T32, a, b, c, d, e, f, g, h)
	ROUND_16_63(33, T33, h, a, b, c, d, e, f, g)
	ROUND_16_63(34, T34, g, h, a, b, c, d, e, f)
	ROUND_16_63(35, T35, f, g, h, a, b, c, d, e)
	ROUND_16_63(36, T36, e, f, g, h, a, b, c, d)
	ROUND_16_63(37, T37, d, e, f, g, h, a, b, c)
	ROUND_16_63(38, T38, c, d, e, f, g, h, a, b)
	ROUND_16_63(39, T39, b, c, d, e, f, g, h, a)
	ROUND_16_63(40, T40, a, b, c, d, e, f, g, h)
	ROUND_16_63(41, T41, h, a, b, c, d, e, f, g)
	ROUND_16_63(42, T42, g, h, a, b, c, d, e, f)
	ROUND_16_63(43, T43, f, g, h, a, b, c, d, e)
	ROUND_16_63(44, T44, e, f, g, h, a, b, c, d)
	ROUND_16_63(45, T45, d, e, f, g, h, a, b, c)
	ROUND_16_63(46, T46, c, d, e, f, g, h, a, b)
	ROUND_16_63(47, T47, b, c, d, e, f, g, h, a)
	ROUND_16_63(48, T16, a, b, c, d, e, f, g, h)
	ROUND_16_63(49, T17, h, a, b, c, d, e, f, g)
	ROUND_16_63(50, T18, g, h, a, b, c, d, e, f)
	ROUND_16_63(51, T19, f, g, h, a, b, c, d, e)
	ROUND_16_63(52, T20, e, f, g, h, a, b, c, d)
	ROUND_16_63(53, T21, d, e, f, g, h, a, b, c)
	ROUND_16_63(54, T22, c, d, e, f, g, h, a, b)
	ROUND_16_63(55, T23, b, c, d, e, f, g, h, a)
	ROUND_16_63(56, T24, a, b, c, d, e, f, g, h)
	ROUND_16_63(57, T25, h, a, b, c, d, e, f, g)
	ROUND_16_63(58, T26, g, h, a, b, c, d, e, f)
	ROUND_16_63(59, T27, f, g, h, a, b, c, d, e)
	ROUND_16_63(60, T28, e, f, g, h, a, b, c, d)
	ROUND_16_63(61, T29, d, e, f, g, h, a, b, c)
	ROUND_16_63(62, T30, c, d, e, f, g, h, a, b)
	ROUND_16_63(63, T31, b, c, d, e, f, g, h, a)

	MOVD statePtr, R20
	VLD1.P 64(R20), [V8.S4, V9.S4, V10.S4, V11.S4]
	VLD1 (R20), [V12.S4, V13.S4, V14.S4, V15.S4]
	VEOR a.B16, V8.B16, a.B16
	VEOR b.B16, V9.B16, b.B16
	VEOR c.B16, V10.B16, c.B16
	VEOR d.B16, V11.B16, d.B16
	VEOR e.B16, V12.B16, e.B16
	VEOR f.B16, V13.B16, f.B16
	VEOR g.B16, V14.B16, g.B16
	VEOR h.B16, V15.B16, h.B16
	MOVD statePtr, R20
	VST1.P [a.S4, b.S4, c.S4, d.S4], 64(R20)
	VST1 [e.S4, f.S4, g.S4, h.S4], (R20)

	SUB $1, blockCount
	CBNZ blockCount, loop

	// transpose state
	TRANSPOSE_MATRIX(a, b, c, d, tmp1, tmp2, tmp3, tmp4)
	TRANSPOSE_MATRIX(e, f, g, h, tmp1, tmp2, tmp3, tmp4)

	MOVD.P 8(digSave), R20
	VST1.P [a.S4], 16(R20)
	VST1 [e.S4], (R20)
	MOVD.P 8(digSave), R20
	VST1.P [b.S4], 16(R20)
	VST1 [f.S4], (R20)
	MOVD.P 8(digSave), R20
	VST1.P [c.S4], 16(R20)
	VST1 [g.S4], (R20)
	MOVD (digSave), R20
	VST1.P [d.S4], 16(R20)
	VST1 [h.S4], (R20)

	RET
