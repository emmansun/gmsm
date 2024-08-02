// This file contains constant-time, 64-bit assembly implementation of
// P256. The optimizations performed here are described in detail in:
// S.Gueron and V.Krasnov, "Fast prime field elliptic-curve cryptography with
//                          256-bit primes"
// https://link.springer.com/article/10.1007%2Fs13389-014-0090-x
// https://eprint.iacr.org/2013/816.pdf
// https://github.com/emmansun/gmsm/wiki/SM2-WWMM-(2)
//go:build !(purego || plugin)

#include "textflag.h"
#include "p256_macros_amd64.s"
#define t1 R15

/* ---------------------------------------*/
// func p256Sqr(res, in *p256Element, n int)
TEXT ·p256Sqr(SB),NOSPLIT,$0
	MOVQ res+0(FP), res_ptr
	MOVQ in+8(FP), x_ptr
	MOVQ n+16(FP), BX
	CMPB ·supportBMI2+0(SB), $0x01
	JEQ  sqrBMI2

sqrLoop:
	p256SqrRound(t1)
	DECQ BX                              
	JNE  sqrLoop
	RET
	
sqrBMI2:
	p256SqrRoundAdx(t1)
	DECQ BX
	JNE  sqrBMI2
	RET

/* ---------------------------------------*/
// func p256OrdSqr(res, in *p256OrdElement, n int)
TEXT ·p256OrdSqr(SB),NOSPLIT,$0
	MOVQ res+0(FP), res_ptr
	MOVQ in+8(FP), x_ptr
	MOVQ n+16(FP), BX

	CMPB ·supportBMI2+0(SB), $0x01
	JEQ  ordSqrLoopBMI2

ordSqrLoop:
	p256OrdSqrRound(t1)
	DECQ BX
	JNE ordSqrLoop

	RET

ordSqrLoopBMI2:
	p256OrdSqrRoundAdx(t1)
	DECQ BX
	JNE ordSqrLoopBMI2

	RET
	
/* ---------------------------------------*/
#undef res_ptr
#undef x_ptr
#undef y_ptr

#undef acc0
#undef acc1
#undef acc2
#undef acc3
#undef acc4
#undef acc5
#undef t0
#undef t1
/* ---------------------------------------*/
#define mul0 AX
#define mul1 DX
#define acc0 BX
#define acc1 CX
#define acc2 R8
#define acc3 R9
#define acc4 R10
#define acc5 R11
#define acc6 R12
#define acc7 R13
#define t0 R14
#define t1 R15
#define t2 DI
#define t3 SI
#define hlp BP

/* ---------------------------------------*/
// [acc7, acc6, acc5, acc4] = [acc7, acc6, acc5, acc4] * [t3, t2, t1, t0]
TEXT sm2P256MulInternal(SB),NOSPLIT,$8
	CMPB ·supportBMI2+0(SB), $0x01
	JEQ  internalMulBMI2

	MOVQ acc4, mul0
	MULQ t0
	MOVQ mul0, acc0
	MOVQ mul1, acc1

	MOVQ acc4, mul0
	MULQ t1
	ADDQ mul0, acc1
	ADCQ $0, mul1
	MOVQ mul1, acc2

	MOVQ acc4, mul0
	MULQ t2
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, acc3

	MOVQ acc4, mul0
	MULQ t3
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, acc4

	MOVQ acc5, mul0
	MULQ t0
	ADDQ mul0, acc1
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc5, mul0
	MULQ t1
	ADDQ hlp, acc2
	ADCQ $0, mul1
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc5, mul0
	MULQ t2
	ADDQ hlp, acc3
	ADCQ $0, mul1
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc5, mul0
	MULQ t3
	ADDQ hlp, acc4
	ADCQ $0, mul1
	ADDQ mul0, acc4
	ADCQ $0, mul1
	MOVQ mul1, acc5

	MOVQ acc6, mul0
	MULQ t0
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc6, mul0
	MULQ t1
	ADDQ hlp, acc3
	ADCQ $0, mul1
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc6, mul0
	MULQ t2
	ADDQ hlp, acc4
	ADCQ $0, mul1
	ADDQ mul0, acc4
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc6, mul0
	MULQ t3
	ADDQ hlp, acc5
	ADCQ $0, mul1
	ADDQ mul0, acc5
	ADCQ $0, mul1
	MOVQ mul1, acc6

	MOVQ acc7, mul0
	MULQ t0
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc7, mul0
	MULQ t1
	ADDQ hlp, acc4
	ADCQ $0, mul1
	ADDQ mul0, acc4
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc7, mul0
	MULQ t2
	ADDQ hlp, acc5
	ADCQ $0, mul1
	ADDQ mul0, acc5
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc7, mul0
	MULQ t3
	ADDQ hlp, acc6
	ADCQ $0, mul1
	ADDQ mul0, acc6
	ADCQ $0, mul1
	MOVQ mul1, acc7
	sm2P256MulReductionInline
	
	MOVQ $0, BP
	// Add bits [511:256] of the result
	ADCQ acc0, acc4
	ADCQ acc1, acc5
	ADCQ acc2, acc6
	ADCQ acc3, acc7
	ADCQ $0, hlp
	// Copy result
	MOVQ acc4, acc0
	MOVQ acc5, acc1
	MOVQ acc6, acc2
	MOVQ acc7, acc3
	// Subtract p256
	SUBQ $-1, acc4
	SBBQ p256p<>+0x08(SB), acc5
	SBBQ $-1, acc6
	SBBQ p256p<>+0x018(SB), acc7
	SBBQ $0, hlp
	// If the result of the subtraction is negative, restore the previous result
	CMOVQCS acc0, acc4 // CMOVQCS: Move if below (CF == 1)
	CMOVQCS acc1, acc5
	CMOVQCS acc2, acc6
	CMOVQCS acc3, acc7

	RET
internalMulBMI2:
	MOVQ acc4, mul1
	MULXQ t0, acc0, acc1

	MULXQ t1, mul0, acc2
	ADDQ mul0, acc1

	MULXQ t2, mul0, acc3
	ADCQ mul0, acc2

	MULXQ t3, mul0, acc4
	ADCQ mul0, acc3
	ADCQ $0, acc4

	MOVQ acc5, mul1
	MULXQ t0, mul0, hlp
	ADDQ mul0, acc1
	ADCQ hlp, acc2

	MULXQ t1, mul0, hlp
	ADCQ $0, hlp
	ADDQ mul0, acc2
	ADCQ hlp, acc3

	MULXQ t2, mul0, hlp
	ADCQ $0, hlp
	ADDQ mul0, acc3
	ADCQ hlp, acc4

	MULXQ t3, mul0, acc5
	ADCQ $0, acc5
	ADDQ mul0, acc4
	ADCQ $0, acc5

	MOVQ acc6, mul1
	MULXQ t0, mul0, hlp
	ADDQ mul0, acc2
	ADCQ hlp, acc3

	MULXQ t1, mul0, hlp
	ADCQ $0, hlp
	ADDQ mul0, acc3
	ADCQ hlp, acc4

	MULXQ t2, mul0, hlp
	ADCQ $0, hlp
	ADDQ mul0, acc4
	ADCQ hlp, acc5

	MULXQ t3, mul0, acc6
	ADCQ $0, acc6
	ADDQ mul0, acc5
	ADCQ $0, acc6

	MOVQ acc7, mul1
	MULXQ t0, mul0, hlp
	ADDQ mul0, acc3
	ADCQ hlp, acc4

	MULXQ t1, mul0, hlp
	ADCQ $0, hlp
	ADDQ mul0, acc4
	ADCQ hlp, acc5

	MULXQ t2, mul0, hlp
	ADCQ $0, hlp
	ADDQ mul0, acc5
	ADCQ hlp, acc6

	MULXQ t3, mul0, acc7
	ADCQ $0, acc7
	ADDQ mul0, acc6
	ADCQ $0, acc7

	sm2P256MulReductionInline
	MOVQ $0, BP
	// Add bits [511:256] of the result
	ADCQ acc0, acc4
	ADCQ acc1, acc5
	ADCQ acc2, acc6
	ADCQ acc3, acc7
	ADCQ $0, hlp
	// Copy result
	MOVQ acc4, acc0
	MOVQ acc5, acc1
	MOVQ acc6, acc2
	MOVQ acc7, acc3
	// Subtract p256
	SUBQ $-1, acc4
	SBBQ p256p<>+0x08(SB), acc5
	SBBQ $-1, acc6
	SBBQ p256p<>+0x018(SB), acc7
	SBBQ $0, hlp
	// If the result of the subtraction is negative, restore the previous result
	CMOVQCS acc0, acc4 // CMOVQCS: Move if below (CF == 1)
	CMOVQCS acc1, acc5
	CMOVQCS acc2, acc6
	CMOVQCS acc3, acc7

	RET

/* ---------------------------------------*/
// [acc7, acc6, acc5, acc4] = [acc7, acc6, acc5, acc4]^2
TEXT sm2P256SqrInternal(SB),NOSPLIT,$8
	CMPB ·supportBMI2+0(SB), $0x01
	JEQ  internalSqrBMI2

	p256SqrInternalInline
	RET

internalSqrBMI2:
	p256SqrInternalInlineAdx
	RET

/* ---------------------------------------*/
#define LDacc(src) MOVQ src(8*0), acc4; MOVQ src(8*1), acc5; MOVQ src(8*2), acc6; MOVQ src(8*3), acc7
#define LDt(src)   MOVQ src(8*0), t0; MOVQ src(8*1), t1; MOVQ src(8*2), t2; MOVQ src(8*3), t3
#define ST(dst)    MOVQ acc4, dst(8*0); MOVQ acc5, dst(8*1); MOVQ acc6, dst(8*2); MOVQ acc7, dst(8*3)
#define STt(dst)   MOVQ t0, dst(8*0); MOVQ t1, dst(8*1); MOVQ t2, dst(8*2); MOVQ t3, dst(8*3)
#define acc2t      MOVQ acc4, t0; MOVQ acc5, t1; MOVQ acc6, t2; MOVQ acc7, t3
#define t2acc      MOVQ t0, acc4; MOVQ t1, acc5; MOVQ t2, acc6; MOVQ t3, acc7
/* ---------------------------------------*/
#define x1in(off) (32*0 + off)(SP)
#define y1in(off) (32*1 + off)(SP)
#define z1in(off) (32*2 + off)(SP)
#define x2in(off) (32*3 + off)(SP)
#define y2in(off) (32*4 + off)(SP)
#define xout(off) (32*5 + off)(SP)
#define yout(off) (32*6 + off)(SP)
#define zout(off) (32*7 + off)(SP)
#define s2(off)   (32*8 + off)(SP)
#define z1sqr(off) (32*9 + off)(SP)
#define h(off)	  (32*10 + off)(SP)
#define r(off)	  (32*11 + off)(SP)
#define hsqr(off) (32*12 + off)(SP)
#define rsqr(off) (32*13 + off)(SP)
#define hcub(off) (32*14 + off)(SP)
#define rptr	  (32*15)(SP)
#define sel_save  (32*15 + 8)(SP)
#define zero_save (32*15 + 8 + 4)(SP)

#define p256PointAddAffineInline() \
	\// Store pointer to result
	MOVQ mul0, rptr                   \
	MOVL t1, sel_save                 \
	MOVL t2, zero_save                \
	\// Negate y2in based on sign
	MOVQ (16*2 + 8*0)(CX), acc4       \
	MOVQ (16*2 + 8*1)(CX), acc5       \
	MOVQ (16*2 + 8*2)(CX), acc6       \
	MOVQ (16*2 + 8*3)(CX), acc7       \
	MOVQ $-1, acc0                    \
	MOVQ p256p<>+0x08(SB), acc1       \
	MOVQ $-1, acc2                    \
	MOVQ p256p<>+0x018(SB), acc3      \
	XORQ mul0, mul0                   \
	\// Speculatively subtract
	SUBQ acc4, acc0                   \
	SBBQ acc5, acc1                   \
	SBBQ acc6, acc2                   \
	SBBQ acc7, acc3                   \
	SBBQ $0, mul0                     \
	MOVQ acc0, t0                     \
	MOVQ acc1, t1                     \
	MOVQ acc2, t2                     \
	MOVQ acc3, t3                     \
	\// Add in case the operand was > p256
	ADDQ $-1, acc0                    \
	ADCQ p256p<>+0x08(SB), acc1       \
	ADCQ $-1, acc2                    \
	ADCQ p256p<>+0x018(SB), acc3      \
	ADCQ $0, mul0                     \ // ZF := 1 if mul0 == 0 after ADC
	CMOVQNE t0, acc0                  \ // CMOVQNE: Move if not equal (ZF == 0)
	CMOVQNE t1, acc1                  \
	CMOVQNE t2, acc2                  \
	CMOVQNE t3, acc3                  \
	\// If condition is 0, keep original value
	TESTQ DX, DX                      \ // ZF := 1 if (DX AND DX == 0)
	CMOVQEQ acc4, acc0                \ // CMOVQEQ: Move if equal (ZF == 1)
	CMOVQEQ acc5, acc1                \
	CMOVQEQ acc6, acc2                \
	CMOVQEQ acc7, acc3                \
	\// Store result
	MOVQ acc0, y2in(8*0)              \
	MOVQ acc1, y2in(8*1)              \
	MOVQ acc2, y2in(8*2)              \
	MOVQ acc3, y2in(8*3)              \
	\// Begin point add
	LDacc (z1in)                      \
	CALL sm2P256SqrInternal(SB)	      \// z1ˆ2
	ST (z1sqr)                        \
	\
	LDt (x2in)                        \
	CALL sm2P256MulInternal(SB)	      \// u2 = x2 * z1ˆ2
	\
	LDt (x1in)                        \
	p256SubInline2          	      \// h = u2 - x1
	ST (h)                            \
	\
	LDt (z1in)                        \
	CALL sm2P256MulInternal(SB)	      \// z3 = h * z1
	ST (zout)                         \
	\
	LDacc (z1sqr)                     \
	CALL sm2P256MulInternal(SB)	      \// z1ˆ3
	\
	LDt (y2in)                        \
	CALL sm2P256MulInternal(SB)	      \// s2 = y2 * z1ˆ3
	ST (s2)                           \
	\
	LDt (y1in)                        \
	p256SubInline2                    \// r = s2 - y1
	ST (r)                            \
	\
	CALL sm2P256SqrInternal(SB)	      \// rsqr = rˆ2
	ST (rsqr)                         \
	\
	LDacc (h)                         \
	CALL sm2P256SqrInternal(SB)	      \// hsqr = hˆ2
	ST (hsqr)                         \
	\
	LDt (h)                           \
	CALL sm2P256MulInternal(SB)	      \// hcub = hˆ3
	ST (hcub)                         \
	\
	LDt (y1in)                        \
	CALL sm2P256MulInternal(SB)	      \// s2 = y1 * hˆ3
	ST (s2)                           \
	\
	LDacc (x1in)                      \
	LDt (hsqr)                        \
	CALL sm2P256MulInternal(SB)	      \// x1 * hˆ2
	ST (h)                            \
	\
	p256MulBy2Inline			      \// x1 * hˆ2 * 2, inline
	LDacc (rsqr)                      \
	p256SubInline2          	      \// rˆ2 - x1 * hˆ2 * 2
	\
	LDt (hcub)                        \
	p256SubInline                     \
	STt (xout)                         \// xout = rˆ2 - 2 * x1 * hˆ2 - h^3
	LDacc (h)                         \
	p256SubInline2                    \
	\
	LDt (r)                           \
	CALL sm2P256MulInternal(SB)       \
	\
	LDt (s2)                          \
	p256SubInline2                    \
	ST (yout)                         \
	\// Load stored values from stack
	MOVQ rptr, AX                     \

// func p256PointAddAffineAsm(res, in1 *SM2P256Point, in2 *p256AffinePoint, sign, sel, zero int)
TEXT ·p256PointAddAffineAsm(SB),0,$512-48
	// Move input to stack in order to free registers
	MOVQ res+0(FP), AX
	MOVQ in1+8(FP), BX
	MOVQ in2+16(FP), CX
	MOVQ sign+24(FP), DX
	MOVQ sel+32(FP), t1
	MOVQ zero+40(FP), t2

	CMPB ·supportAVX2+0(SB), $0x01
	JEQ  pointaddaffine_avx2

	MOVOU (16*0)(BX), X0
	MOVOU (16*1)(BX), X1
	MOVOU (16*2)(BX), X2
	MOVOU (16*3)(BX), X3
	MOVOU (16*4)(BX), X4
	MOVOU (16*5)(BX), X5

	MOVOU X0, x1in(16*0)
	MOVOU X1, x1in(16*1)
	MOVOU X2, y1in(16*0)
	MOVOU X3, y1in(16*1)
	MOVOU X4, z1in(16*0)
	MOVOU X5, z1in(16*1)

	MOVOU (16*0)(CX), X0
	MOVOU (16*1)(CX), X1

	MOVOU X0, x2in(16*0)
	MOVOU X1, x2in(16*1)
	
	p256PointAddAffineInline()
	// The result is not valid if (sel == 0), conditional choose
	MOVOU xout(16*0), X0
	MOVOU xout(16*1), X1
	MOVOU yout(16*0), X2
	MOVOU yout(16*1), X3
	MOVOU zout(16*0), X4
	MOVOU zout(16*1), X5

	MOVL sel_save, X6 // sel 
	MOVL zero_save, X7 // zero

	PXOR X8, X8 // X8's bits are all 0
	PCMPEQL X9, X9 // X9's bits are all 1

	PSHUFD $0, X6, X6
	PSHUFD $0, X7, X7

	PCMPEQL X8, X6  // X6's bits are all 1 if sel = 0, else are 0
	PCMPEQL X8, X7  // X7's bits are all 1 if zero = 0, else are 0

	MOVOU X6, X15
	PANDN X9, X15 // X15 = NOT(X6)

	MOVOU x1in(16*0), X9
	MOVOU x1in(16*1), X10
	MOVOU y1in(16*0), X11
	MOVOU y1in(16*1), X12
	MOVOU z1in(16*0), X13
	MOVOU z1in(16*1), X14

	PAND X15, X0
	PAND X15, X1
	PAND X15, X2
	PAND X15, X3
	PAND X15, X4
	PAND X15, X5

	PAND X6, X9
	PAND X6, X10
	PAND X6, X11
	PAND X6, X12
	PAND X6, X13
	PAND X6, X14

	PXOR X9, X0
	PXOR X10, X1
	PXOR X11, X2
	PXOR X12, X3
	PXOR X13, X4
	PXOR X14, X5
	// Similarly if zero == 0
	PCMPEQL X9, X9
	MOVOU X7, X15
	PANDN X9, X15 // X15 = NOT(X7)

	MOVOU x2in(16*0), X9
	MOVOU x2in(16*1), X10
	MOVOU y2in(16*0), X11
	MOVOU y2in(16*1), X12
	MOVOU p256one<>+0x00(SB), X13
	MOVOU p256one<>+0x10(SB), X14

	PAND X15, X0
	PAND X15, X1
	PAND X15, X2
	PAND X15, X3
	PAND X15, X4
	PAND X15, X5

	PAND X7, X9
	PAND X7, X10
	PAND X7, X11
	PAND X7, X12
	PAND X7, X13
	PAND X7, X14

	PXOR X9, X0
	PXOR X10, X1
	PXOR X11, X2
	PXOR X12, X3
	PXOR X13, X4
	PXOR X14, X5
	// Finally output the result
	MOVOU X0, (16*0)(AX)
	MOVOU X1, (16*1)(AX)
	MOVOU X2, (16*2)(AX)
	MOVOU X3, (16*3)(AX)
	MOVOU X4, (16*4)(AX)
	MOVOU X5, (16*5)(AX)
	MOVQ $0, rptr

	RET
pointaddaffine_avx2:
	VMOVDQU (32*0)(BX), Y0
	VMOVDQU (32*1)(BX), Y1
	VMOVDQU (32*2)(BX), Y2

	VMOVDQU Y0, x1in(32*0)
	VMOVDQU Y1, y1in(32*0)
	VMOVDQU Y2, z1in(32*0)

	VMOVDQU (32*0)(CX), Y0
	VMOVDQU Y0, x2in(32*0)

	p256PointAddAffineInline()
	// The result is not valid if (sel == 0), conditional choose
	VPXOR Y8, Y8, Y8 // Y8's bits are all 0
	VPBROADCASTD sel_save, Y6 // sel
	VPBROADCASTD zero_save, Y7 // zero

	VPCMPEQD Y8, Y6, Y6 // Y6's bits are all 1 if sel = 0, else are 0
	VPCMPEQD Y8, Y7, Y7 // Y7's bits are all 1 if zero = 0, else are 0

	VPANDN xout(32*0), Y6, Y0
	VPANDN yout(32*0), Y6, Y1
	VPANDN zout(32*0), Y6, Y2

	VPAND x1in(32*0), Y6, Y9
	VPAND y1in(32*0), Y6, Y10
	VPAND z1in(32*0), Y6, Y11

	VPXOR Y9, Y0, Y0
	VPXOR Y10, Y1, Y1
	VPXOR Y11, Y2, Y2

	// Similarly if zero == 0
	VPANDN Y0, Y7, Y0
	VPANDN Y1, Y7, Y1
	VPANDN Y2, Y7, Y2

	VPAND x2in(32*0), Y7, Y9
	VPAND y2in(32*0), Y7, Y10
	VPAND p256one<>+0x00(SB), Y7, Y11

	VPXOR Y9, Y0, Y0
	VPXOR Y10, Y1, Y1
	VPXOR Y11, Y2, Y2

	// Finally output the result
	VMOVDQU Y0, (32*0)(AX)
	VMOVDQU Y1, (32*1)(AX)
	VMOVDQU Y2, (32*2)(AX)
	MOVQ $0, rptr

	VZEROUPPER
	RET	
#undef x1in
#undef y1in
#undef z1in
#undef x2in
#undef y2in
#undef xout
#undef yout
#undef zout
#undef s2
#undef z1sqr
#undef h
#undef r
#undef hsqr
#undef rsqr
#undef hcub
#undef rptr
#undef sel_save
#undef zero_save

/* ---------------------------------------*/
#define x1in(off) (32*0 + off)(SP)
#define y1in(off) (32*1 + off)(SP)
#define z1in(off) (32*2 + off)(SP)
#define x2in(off) (32*3 + off)(SP)
#define y2in(off) (32*4 + off)(SP)
#define z2in(off) (32*5 + off)(SP)

#define xout(off) (32*6 + off)(SP)
#define yout(off) (32*7 + off)(SP)
#define zout(off) (32*8 + off)(SP)

#define u1(off)    (32*9 + off)(SP)
#define u2(off)    (32*10 + off)(SP)
#define s1(off)    (32*11 + off)(SP)
#define s2(off)    (32*12 + off)(SP)
#define z1sqr(off) (32*13 + off)(SP)
#define z2sqr(off) (32*14 + off)(SP)
#define h(off)     (32*15 + off)(SP)
#define r(off)     (32*16 + off)(SP)
#define hsqr(off)  (32*17 + off)(SP)
#define rsqr(off)  (32*18 + off)(SP)
#define hcub(off)  (32*19 + off)(SP)
#define rptr       (32*20)(SP)
#define points_eq  (32*20+8)(SP)

#define p256PointAddInline() \
	\// Begin point add
	LDacc (z2in)                 \
	CALL sm2P256SqrInternal(SB)	 \// z2ˆ2
	ST (z2sqr)                   \
	LDt (z2in)                   \
	CALL sm2P256MulInternal(SB)	 \// z2ˆ3
	LDt (y1in)                   \
	CALL sm2P256MulInternal(SB)	 \// s1 = z2ˆ3*y1
	ST (s1)                      \
	\
	LDacc (z1in)                 \ 
	CALL sm2P256SqrInternal(SB)	 \// z1ˆ2
	ST (z1sqr)                   \
	LDt (z1in)                   \
	CALL sm2P256MulInternal(SB)	 \// z1ˆ3
	LDt (y2in)                   \
	CALL sm2P256MulInternal(SB)	 \// s2 = z1ˆ3*y2
	ST (s2)                      \ 
	\
	LDt (s1)                     \
	p256SubInline2          	 \// r = s2 - s1
	ST (r)                       \
	p256IsZeroInline             \
	MOVQ AX, points_eq           \
	\
	LDacc (z2sqr)                \
	LDt (x1in)                   \
	CALL sm2P256MulInternal(SB)	 \// u1 = x1 * z2ˆ2
	ST (u1)                      \
	LDacc (z1sqr)                \
	LDt (x2in)                   \ 
	CALL sm2P256MulInternal(SB)	 \// u2 = x2 * z1ˆ2
	ST (u2)                      \
	\
	LDt (u1)                     \ 
	p256SubInline2          	 \// h = u2 - u1
	ST (h)                       \
	p256IsZeroInline             \
	ANDQ points_eq, AX           \
	MOVQ AX, points_eq           \
	\
	LDacc (r)                    \
	CALL sm2P256SqrInternal(SB)	 \// rsqr = rˆ2
	ST (rsqr)                    \
	\
	LDacc (h)                    \
	CALL sm2P256SqrInternal(SB)	 \// hsqr = hˆ2
	ST (hsqr)                    \
	\
	LDt (h)                      \
	CALL sm2P256MulInternal(SB)	 \// hcub = hˆ3
	ST (hcub)                    \
	\
	LDt (s1)                     \
	CALL sm2P256MulInternal(SB)  \
	ST (s2)                      \
	\
	LDacc (z1in)                 \
	LDt (z2in)                   \
	CALL sm2P256MulInternal(SB)	 \// z1 * z2
	LDt (h)                      \
	CALL sm2P256MulInternal(SB)	 \// z1 * z2 * h
	ST (zout)                    \
	\
	LDacc (hsqr)                 \
	LDt (u1)                     \
	CALL sm2P256MulInternal(SB)	 \// hˆ2 * u1
	ST (u2)                      \
	\
	p256MulBy2Inline	         \// u1 * hˆ2 * 2, inline
	LDacc (rsqr)                 \
	p256SubInline2          	 \// rˆ2 - u1 * hˆ2 * 2
	\
	LDt (hcub)                   \
	p256SubInline                \
	STt (xout)                   \
	LDacc (u2)                   \
	p256SubInline2               \
	\
	LDt (r)                      \
	CALL sm2P256MulInternal(SB)  \
	\
	LDt (s2)                     \
	p256SubInline2               \
	ST (yout)                    \

//func p256PointAddAsm(res, in1, in2 *SM2P256Point) int
TEXT ·p256PointAddAsm(SB),0,$680-32
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
	// Move input to stack in order to free registers
	MOVQ res+0(FP), AX
	MOVQ in1+8(FP), BX
	MOVQ in2+16(FP), CX

	CMPB ·supportAVX2+0(SB), $0x01
	JEQ  pointadd_avx2

	MOVOU (16*0)(BX), X0
	MOVOU (16*1)(BX), X1
	MOVOU (16*2)(BX), X2
	MOVOU (16*3)(BX), X3
	MOVOU (16*4)(BX), X4
	MOVOU (16*5)(BX), X5

	MOVOU X0, x1in(16*0)
	MOVOU X1, x1in(16*1)
	MOVOU X2, y1in(16*0)
	MOVOU X3, y1in(16*1)
	MOVOU X4, z1in(16*0)
	MOVOU X5, z1in(16*1)

	MOVOU (16*0)(CX), X0
	MOVOU (16*1)(CX), X1
	MOVOU (16*2)(CX), X2
	MOVOU (16*3)(CX), X3
	MOVOU (16*4)(CX), X4
	MOVOU (16*5)(CX), X5

	MOVOU X0, x2in(16*0)
	MOVOU X1, x2in(16*1)
	MOVOU X2, y2in(16*0)
	MOVOU X3, y2in(16*1)
	MOVOU X4, z2in(16*0)
	MOVOU X5, z2in(16*1)
	// Store pointer to result
	MOVQ AX, rptr
	p256PointAddInline()

	MOVOU xout(16*0), X0
	MOVOU xout(16*1), X1
	MOVOU yout(16*0), X2
	MOVOU yout(16*1), X3
	MOVOU zout(16*0), X4
	MOVOU zout(16*1), X5
	// Finally output the result
	MOVQ rptr, AX
	MOVQ $0, rptr
	MOVOU X0, (16*0)(AX)
	MOVOU X1, (16*1)(AX)
	MOVOU X2, (16*2)(AX)
	MOVOU X3, (16*3)(AX)
	MOVOU X4, (16*4)(AX)
	MOVOU X5, (16*5)(AX)

	MOVQ points_eq, AX
	MOVQ AX, ret+24(FP)

	RET
pointadd_avx2:
	VMOVDQU (32*0)(BX), Y0
	VMOVDQU (32*1)(BX), Y1
	VMOVDQU (32*2)(BX), Y2

	VMOVDQU Y0, x1in(32*0)
	VMOVDQU Y1, y1in(32*0)
	VMOVDQU Y2, z1in(32*0)

	VMOVDQU (32*0)(CX), Y0
	VMOVDQU (32*1)(CX), Y1
	VMOVDQU (32*2)(CX), Y2

	VMOVDQU Y0, x2in(32*0)
	VMOVDQU Y1, y2in(32*0)
	VMOVDQU Y2, z2in(32*0)

	// Store pointer to result
	MOVQ AX, rptr
	p256PointAddInline()

	VMOVDQU xout(32*0), Y0
	VMOVDQU yout(32*0), Y1
	VMOVDQU zout(32*0), Y2
	// Finally output the result
	MOVQ rptr, AX
	MOVQ $0, rptr
	VMOVDQU Y0, (32*0)(AX)
	VMOVDQU Y1, (32*1)(AX)
	VMOVDQU Y2, (32*2)(AX)

	MOVQ points_eq, AX
	MOVQ AX, ret+24(FP)

	VZEROUPPER
	RET

#undef x1in
#undef y1in
#undef z1in
#undef x2in
#undef y2in
#undef z2in
#undef xout
#undef yout
#undef zout
#undef s1
#undef s2
#undef u1
#undef u2
#undef z1sqr
#undef z2sqr
#undef h
#undef r
#undef hsqr
#undef rsqr
#undef hcub
#undef rptr
/* ---------------------------------------*/
#define x(off) (32*0 + off)(SP)
#define y(off) (32*1 + off)(SP)
#define z(off) (32*2 + off)(SP)

#define s(off)	(32*3 + off)(SP)
#define m(off)	(32*4 + off)(SP)
#define zsqr(off) (32*5 + off)(SP)
#define tmp(off)  (32*6 + off)(SP)
#define rptr	  (32*7)(SP)

#define calZ() \
	LDacc (z)                               \
	CALL sm2P256SqrInternal(SB)             \
	ST (zsqr)                               \  // ZZ = Z1^2
	\
	LDt (x)                                 \
	p256AddInline                           \
	STt (m)                                 \  // M = ZZ + X1
	\
	LDacc (z)                               \
	LDt (y)                                 \
	CALL sm2P256MulInternal(SB)             \ // Z1 * Y1
	p256MulBy2Inline                        \ // Z3 = 2(Z1 * Y1) = (Y1 + Z1)^2 - Y1^2 - Z1^2

#define calX() \
	LDacc (x)                               \
	LDt (zsqr)                              \
	p256SubInline2                          \ // X1 - ZZ
	LDt (m)                                 \
	CALL sm2P256MulInternal(SB)             \ // M = (X1 - ZZ) * (X1 + ZZ) = X1^2 - ZZ^2
	ST (m)                                  \
	\// Multiply by 3
	p256TripleInline                        \
	STt (m)                                 \  // M = 3 * (X1^2 - ZZ^2)
	\////////////////////////
	LDacc (y)                               \
	p256MulBy2Inline2                       \
	CALL sm2P256SqrInternal(SB)             \ // 4 * YY = (2*Y1)^2
	ST (s)                                  \ // S = 4 * YY
	CALL sm2P256SqrInternal(SB)             \ // (4 * YY)^2 = 16 * YYYY
	\// Divide by 2
	XORQ mul0, mul0                         \
	MOVQ acc4, t0                           \
	MOVQ acc5, t1                           \  
	MOVQ acc6, t2                           \
	MOVQ acc7, t3                           \
	\ // [mul0, acc7, acc6, acc5, acc4] := [acc7, acc6, acc5, acc4] + P
	ADDQ $-1, acc4                          \
	ADCQ p256p<>+0x08(SB), acc5             \
	ADCQ $-1, acc6                          \
	ADCQ p256p<>+0x018(SB), acc7            \
	ADCQ $0, mul0                           \
	TESTQ $1, t0                            \ // ZF := 1 if (t0 AND 1 == 0)
	\ // CMOVQEQ: Move if equal (ZF == 1)
	CMOVQEQ t0, acc4                        \ // acc4 := t0 if (ZF == 1)
	CMOVQEQ t1, acc5                        \ // acc5 := t1 if (ZF == 1)
	CMOVQEQ t2, acc6                        \ // acc6 := t2 if (ZF == 1)
	CMOVQEQ t3, acc7                        \ // acc7 := t3 if (ZF == 1)
	ANDQ t0, mul0                           \ // mul0 := t0 AND mul0 (mul0 := 0 if (ZF == 1) else keeping the original value 0 or 1) 
	\ // Divide even by 2 
	SHRQ $1, acc5, acc4                     \ // acc4 := acc4 >> 1 | acc5 << 63
	SHRQ $1, acc6, acc5                     \ // acc5 := acc5 >> 1 | acc6 << 63
	SHRQ $1, acc7, acc6                     \ // acc6 := acc6 >> 1 | acc7 << 63
	SHRQ $1, mul0, acc7                     \ // acc7 := acc7 >> 1 | mul0 << 63
	ST (y)                                  \ // Y3 = 8 * YYYY
	\/////////////////////////
	LDacc (x)                               \
	LDt (s)                                 \
	CALL sm2P256MulInternal(SB)             \ // X1 * 4 * YY
	ST (s)                                  \ // S = 4 * X1 * YY = 2 * ((X1+YY)^2 - XX - YYYY)
	p256MulBy2Inline                        \
	STt (tmp)                               \ // tmp = 2*S = 8 * X1 * YY
	\
	LDacc (m)                               \
	CALL sm2P256SqrInternal(SB)             \ // M^2 = (3 * (X1^2 - ZZ^2))^2
	LDt (tmp)                               \
	p256SubInline2                          \ // X3 = M^2 - 2*S

#define calY() \
	acc2t                                   \
	LDacc (s)                               \ // S = 4 * X1 * YY = 2 * ((X1+YY)^2 - XX - YYYY)
	p256SubInline2                          \ // S - X3 
	\
	LDt (m)                                 \
	CALL sm2P256MulInternal(SB)             \ // M * (S - X3)
	\
	LDt (y)                                 \
	p256SubInline2                          \ // Y3 = M * (S - X3) - 8 * YYYYY

#define lastP256PointDouble() \
	\ // See https://hyperelliptic.org/EFD/g1p/data/shortw/jacobian-3/doubling/dbl-2007-bl
	calZ()                            \
	MOVQ rptr, AX                     \
	\// Store z
	MOVQ t0, (16*4 + 8*0)(AX)         \
	MOVQ t1, (16*4 + 8*1)(AX)         \
	MOVQ t2, (16*4 + 8*2)(AX)         \
	MOVQ t3, (16*4 + 8*3)(AX)         \
	\
	calX()                            \
	MOVQ rptr, AX                     \
	\// Store x
	MOVQ acc4, (16*0 + 8*0)(AX)       \
	MOVQ acc5, (16*0 + 8*1)(AX)       \
	MOVQ acc6, (16*0 + 8*2)(AX)       \
	MOVQ acc7, (16*0 + 8*3)(AX)       \
	\
	calY()                            \
	MOVQ rptr, AX                     \ 
	\// Store y
	MOVQ acc4, (16*2 + 8*0)(AX)       \  
	MOVQ acc5, (16*2 + 8*1)(AX)       \ 
	MOVQ acc6, (16*2 + 8*2)(AX)       \
	MOVQ acc7, (16*2 + 8*3)(AX)       \
	\///////////////////////
	MOVQ $0, rptr                     \

//func p256PointDoubleAsm(res, in *SM2P256Point)
TEXT ·p256PointDoubleAsm(SB),NOSPLIT,$256-16
	// Move input to stack in order to free registers
	MOVQ res+0(FP), AX
	MOVQ in+8(FP), BX

	p256PointDoubleInit()
	// Store pointer to result
	MOVQ AX, rptr
	// Begin point double
	lastP256PointDouble()

	RET

#define storeTmpX() \
	MOVQ acc4, x(8*0) \
	MOVQ acc5, x(8*1) \
	MOVQ acc6, x(8*2) \
	MOVQ acc7, x(8*3) \

#define storeTmpY() \
	MOVQ acc4, y(8*0) \
	MOVQ acc5, y(8*1) \
	MOVQ acc6, y(8*2) \
	MOVQ acc7, y(8*3) \

#define storeTmpZ() \
	MOVQ t0, z(8*0) \
	MOVQ t1, z(8*1) \
	MOVQ t2, z(8*2) \
	MOVQ t3, z(8*3) \

#define p256PointDoubleRound() \
	calZ()                  \
	storeTmpZ()             \ 
	calX()                  \
	storeTmpX()             \
	calY()                  \
	storeTmpY()             \

//func p256PointDouble6TimesAsm(res, in *SM2P256Point)
TEXT ·p256PointDouble6TimesAsm(SB),NOSPLIT,$256-16
	// Move input to stack in order to free registers
	MOVQ res+0(FP), AX
	MOVQ in+8(FP), BX

	p256PointDoubleInit()
	// Store pointer to result
	MOVQ AX, rptr

	// point double 1-5 rounds
	p256PointDoubleRound()
	p256PointDoubleRound()
	p256PointDoubleRound()
	p256PointDoubleRound()
	p256PointDoubleRound()

	// last point double round
	lastP256PointDouble()

	RET
/* ---------------------------------------*/
