// This file contains constant-time, 64-bit assembly implementation of
// P256. The optimizations performed here are described in detail in:
// S.Gueron and V.Krasnov, "Fast prime field elliptic-curve cryptography with
//                          256-bit primes"
// https://link.springer.com/article/10.1007%2Fs13389-014-0090-x
// https://eprint.iacr.org/2013/816.pdf
//go:build amd64 && !purego && !plugin

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

	// y[1:] * y[0]
	MOVQ (8*0)(x_ptr), t0

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	MOVQ AX, acc1
	MOVQ DX, acc2

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, acc3

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, acc4
	// y[2:] * y[1]
	MOVQ (8*1)(x_ptr), t0

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, acc5
	// y[3] * y[2]
	MOVQ (8*2)(x_ptr), t0

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc5
	ADCQ $0, DX
	MOVQ DX, y_ptr
	XORQ t1, t1
	// *2
	ADDQ acc1, acc1
	ADCQ acc2, acc2
	ADCQ acc3, acc3
	ADCQ acc4, acc4
	ADCQ acc5, acc5
	ADCQ y_ptr, y_ptr
	ADCQ $0, t1
	// Missing products
	MOVQ (8*0)(x_ptr), AX
	MULQ AX
	MOVQ AX, acc0
	MOVQ DX, t0

	MOVQ (8*1)(x_ptr), AX
	MULQ AX
	ADDQ t0, acc1
	ADCQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t0

	MOVQ (8*2)(x_ptr), AX
	MULQ AX
	ADDQ t0, acc3
	ADCQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t0

	MOVQ (8*3)(x_ptr), AX
	MULQ AX
	ADDQ t0, acc5
	ADCQ AX, y_ptr
	ADCQ DX, t1
	MOVQ t1, x_ptr

	// T = [x_ptr, y_ptr, acc5, acc4, acc3, acc2, acc1, acc0]
	p256SqrMontReduce()
	p256PrimReduce(acc0, acc1, acc2, acc3, t0, acc4, acc5, y_ptr, t1, res_ptr)
	MOVQ res_ptr, x_ptr            
	DECQ BX                              
	JNE  sqrLoop
	RET
	
sqrBMI2:
	// y[1:] * y[0]
	MOVQ (8*0)(x_ptr), DX

	MULXQ (8*1)(x_ptr), acc1, acc2
	
	MULXQ (8*2)(x_ptr), AX, acc3
	ADDQ AX, acc2

	MULXQ (8*3)(x_ptr), AX, acc4
	ADCQ AX, acc3
	ADCQ $0, acc4

	// y[2:] * y[1]
	MOVQ (8*1)(x_ptr), DX
	
	MULXQ (8*2)(x_ptr), AX, t1
	ADDQ AX, acc3
	ADCQ t1, acc4

	MULXQ (8*3)(x_ptr), AX, acc5
	ADCQ $0, acc5
	ADDQ AX, acc4

	// y[3] * y[2]
	MOVQ (8*2)(x_ptr), DX

	MULXQ (8*3)(x_ptr), AX, y_ptr
	ADCQ AX, acc5 
	ADCQ $0, y_ptr
	XORQ t1, t1

	// *2
	ADDQ acc1, acc1
	ADCQ acc2, acc2
	ADCQ acc3, acc3
	ADCQ acc4, acc4
	ADCQ acc5, acc5
	ADCQ y_ptr, y_ptr
	ADCQ $0, t1

	// Missing products
	MOVQ (8*0)(x_ptr), DX
	MULXQ DX, acc0, t0
	ADDQ t0, acc1

	MOVQ (8*1)(x_ptr), DX
	MULXQ DX, AX, t0
	ADCQ AX, acc2
	ADCQ t0, acc3

	MOVQ (8*2)(x_ptr), DX
	MULXQ DX, AX, t0
	ADCQ AX, acc4
	ADCQ t0, acc5

	MOVQ (8*3)(x_ptr), DX
	MULXQ DX, AX, x_ptr
	ADCQ AX, y_ptr
	ADCQ t1, x_ptr

	// T = [x_ptr, y_ptr, acc5, acc4, acc3, acc2, acc1, acc0]
	p256SqrMontReduce()
	p256PrimReduce(acc0, acc1, acc2, acc3, t0, acc4, acc5, y_ptr, t1, res_ptr)
	MOVQ res_ptr, x_ptr            
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

	// y[1:] * y[0]
	MOVQ (8*0)(x_ptr), t0

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	MOVQ AX, acc1
	MOVQ DX, acc2

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, acc3

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, acc4
	// y[2:] * y[1]
	MOVQ (8*1)(x_ptr), t0

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, acc5
	// y[3] * y[2]
	MOVQ (8*2)(x_ptr), t0

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc5
	ADCQ $0, DX
	MOVQ DX, y_ptr
	XORQ t1, t1
	// *2
	ADDQ acc1, acc1
	ADCQ acc2, acc2
	ADCQ acc3, acc3
	ADCQ acc4, acc4
	ADCQ acc5, acc5
	ADCQ y_ptr, y_ptr
	ADCQ $0, t1
	// Missing products
	MOVQ (8*0)(x_ptr), AX
	MULQ AX
	MOVQ AX, acc0
	MOVQ DX, t0

	MOVQ (8*1)(x_ptr), AX
	MULQ AX
	ADDQ t0, acc1
	ADCQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t0

	MOVQ (8*2)(x_ptr), AX
	MULQ AX
	ADDQ t0, acc3
	ADCQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t0

	MOVQ (8*3)(x_ptr), AX
	MULQ AX
	ADDQ t0, acc5
	ADCQ AX, y_ptr
	ADCQ DX, t1
	MOVQ t1, x_ptr

	// T = [x_ptr, y_ptr, acc5, acc4, acc3, acc2, acc1, acc0]
	// First reduction step, [ord3, ord2, ord1, ord0] = [1, -0x100000000, -1, ord1, ord0]
	MOVQ acc0, AX
	MULQ p256ordK0<>(SB)
	MOVQ AX, t0                 // Y = t0 = (k0 * acc0) mod 2^64
	// calculate the positive part first: [1, 0, 0, ord1, ord0] * t0 + [0, acc3, acc2, acc1, acc0]
	// the result is [acc0, acc3, acc2, acc1], last lowest limb is dropped.
	MOVQ p256ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc0               // (carry1, acc0) = acc0 + L(t0 * ord0)
	ADCQ $0, DX                 // DX = carry1 + H(t0 * ord0)
	MOVQ DX, t1                 // t1 = carry1 + H(t0 * ord0)
	MOVQ t0, acc0               // acc0 =  t0

	MOVQ p256ord<>+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc1               // (carry2, acc1) = acc1 + t1
	ADCQ $0, DX                 // DX = carry2 + H(t0*ord1)

	ADDQ AX, acc1               // (carry3, acc1) = acc1 + t1 + L(t0*ord1)
	ADCQ DX, acc2
	ADCQ $0, acc3
	ADCQ $0, acc0
	// calculate the negative part: [acc0, acc3, acc2, acc1] - [0, 0x100000000, 1, 0] * t0
	MOVQ t0, AX
	MOVQ t0, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ t0, acc2
	SBBQ AX, acc3
	SBBQ DX, acc0
	// Second reduction step
	MOVQ acc1, AX
	MULQ p256ordK0<>(SB)
	MOVQ AX, t0

	MOVQ p256ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, t1
	MOVQ t0, acc1

	MOVQ p256ord<>+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc2
	ADCQ $0, DX

	ADDQ AX, acc2
	ADCQ DX, acc3
	ADCQ $0, acc0
	ADCQ $0, acc1

	MOVQ t0, AX
	MOVQ t0, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ t0, acc3
	SBBQ AX, acc0
	SBBQ DX, acc1
	// Third reduction step
	MOVQ acc2, AX
	MULQ p256ordK0<>(SB)
	MOVQ AX, t0

	MOVQ p256ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1
	MOVQ t0, acc2

	MOVQ p256ord<>+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX

	ADDQ AX, acc3
	ADCQ DX, acc0
	ADCQ $0, acc1
	ADCQ $0, acc2

	MOVQ t0, AX
	MOVQ t0, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ t0, acc0
	SBBQ AX, acc1
	SBBQ DX, acc2
	// Last reduction step
	MOVQ acc3, AX
	MULQ p256ordK0<>(SB)
	MOVQ AX, t0

	MOVQ p256ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1
	MOVQ t0, acc3

	MOVQ p256ord<>+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc0
	ADCQ $0, DX

	ADDQ AX, acc0
	ADCQ DX, acc1
	ADCQ $0, acc2
	ADCQ $0, acc3

	MOVQ t0, AX
	MOVQ t0, DX
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ t0, acc1
	SBBQ AX, acc2
	SBBQ DX, acc3

	XORQ t0, t0
	// Add bits [511:256] of the sqr result
	ADCQ acc4, acc0
	ADCQ acc5, acc1
	ADCQ y_ptr, acc2
	ADCQ x_ptr, acc3
	ADCQ $0, t0

	p256OrdReduceInline(acc0, acc1, acc2, acc3, t0, acc4, acc5, y_ptr, t1, res_ptr)
	MOVQ res_ptr, x_ptr
	DECQ BX
	JNE ordSqrLoop

	RET

ordSqrLoopBMI2:
	// y[1:] * y[0]
	MOVQ (8*0)(x_ptr), DX
	MULXQ (8*1)(x_ptr), acc1, acc2 

	MULXQ (8*2)(x_ptr), AX, acc3
	ADDQ AX, acc2
	ADCQ $0, acc3

	MULXQ (8*3)(x_ptr), AX, acc4
	ADDQ AX, acc3
	ADCQ $0, acc4

	// y[2:] * y[1]
	MOVQ (8*1)(x_ptr), DX
	MULXQ (8*2)(x_ptr), AX, t1
	ADDQ AX, acc3
	ADCQ t1, acc4

	MULXQ (8*3)(x_ptr), AX, acc5
	ADCQ $0, acc5
	ADDQ AX, acc4
	ADCQ $0, acc5

	// y[3] * y[2]
	MOVQ (8*2)(x_ptr), DX
	MULXQ (8*3)(x_ptr), AX, y_ptr 
	ADDQ AX, acc5
	ADCQ $0, y_ptr

	XORQ t1, t1
	// *2
	ADDQ acc1, acc1
	ADCQ acc2, acc2
	ADCQ acc3, acc3
	ADCQ acc4, acc4
	ADCQ acc5, acc5
	ADCQ y_ptr, y_ptr
	ADCQ $0, t1
	
	// Missing products
	MOVQ (8*0)(x_ptr), DX
	MULXQ DX, acc0, t0
	ADDQ t0, acc1

	MOVQ (8*1)(x_ptr), DX
	MULXQ DX, AX, t0
	ADCQ AX, acc2
	ADCQ t0, acc3

	MOVQ (8*2)(x_ptr), DX
	MULXQ DX, AX, t0 
	ADCQ AX, acc4
	ADCQ t0, acc5

	MOVQ (8*3)(x_ptr), DX
	MULXQ DX, AX, x_ptr
	ADCQ AX, y_ptr
	ADCQ t1, x_ptr

	// T = [x_ptr, y_ptr, acc5, acc4, acc3, acc2, acc1, acc0]
	// First reduction step, [ord3, ord2, ord1, ord0] = [1, -0x100000000, -1, ord1, ord0]
	MOVQ acc0, DX
	MULXQ p256ordK0<>(SB), t0, AX
	// calculate the positive part first: [1, 0, 0, ord1, ord0] * t0 + [0, acc3, acc2, acc1, acc0]
	// the result is [acc0, acc3, acc2, acc1], last lowest limb is dropped.
	MOVQ t0, DX                 // Y = t0 = (k0 * acc0) mod 2^64
	MULXQ p256ord<>+0x00(SB), AX, t1
	ADDQ AX, acc0               // (carry1, acc0) = acc0 + L(t0 * ord0)
	ADCQ t1, acc1               // (carry2, acc1) = acc1 + H(t0 * ord0) + carry1
	MOVQ t0, acc0               // acc0 = t0 

	MULXQ p256ord<>+0x08(SB), AX, t1
	ADCQ $0, t1                 // t1 = carry2 + H(t0*ord1)
	ADDQ AX, acc1               // (carry3, acc1) = acc1 + L(t0*ord1)
	ADCQ t1, acc2               // (carry4, acc2) = acc2 + t1 + carry3
	ADCQ $0, acc3               // (carry5, acc3) = acc3 + carry4
	ADCQ $0, acc0               //           acc0 = t0 + carry5 
	// calculate the negative part: [acc0, acc3, acc2, acc1] - [0, 0x100000000, 1, 0] * t0
	MOVQ t0, AX
	//MOVQ t0, DX              // This is not required due to t0=DX already
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ t0, acc2
	SBBQ AX, acc3
	SBBQ DX, acc0

	// Second reduction step
	MOVQ acc1, DX
	MULXQ p256ordK0<>(SB), t0, AX

	MOVQ t0, DX
	MULXQ p256ord<>+0x00(SB), AX, t1
	ADDQ AX, acc1
	ADCQ t1, acc2
	MOVQ t0, acc1

	MULXQ p256ord<>+0x08(SB), AX, t1
	ADCQ $0, t1
	ADDQ AX, acc2
	ADCQ t1, acc3
	ADCQ $0, acc0
	ADCQ $0, acc1

	MOVQ t0, AX
	//MOVQ t0, DX              // This is not required due to t0=DX already
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ t0, acc3
	SBBQ AX, acc0
	SBBQ DX, acc1
	// Third reduction step
	MOVQ acc2, DX
	MULXQ p256ordK0<>(SB), t0, AX

	MOVQ t0, DX
	MULXQ p256ord<>+0x00(SB), AX, t1
	ADDQ AX, acc2
	ADCQ t1, acc3
	MOVQ t0, acc2

	MULXQ p256ord<>+0x08(SB), AX, t1
	ADCQ $0, t1
	ADDQ AX, acc3
	ADCQ t1, acc0
	ADCQ $0, acc1
	ADCQ $0, acc2

	MOVQ t0, AX
	//MOVQ t0, DX              // This is not required due to t0=DX already
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ t0, acc0
	SBBQ AX, acc1
	SBBQ DX, acc2
	// Last reduction step
	MOVQ acc3, DX
	MULXQ p256ordK0<>(SB), t0, AX

	MOVQ t0, DX
	MULXQ p256ord<>+0x00(SB), AX, t1
	ADDQ AX, acc3
	ADCQ t1, acc0
	MOVQ t0, acc3

	MULXQ p256ord<>+0x08(SB), AX, t1
	ADCQ $0, t1
	ADDQ AX, acc0
	ADCQ t1, acc1
	ADCQ $0, acc2
	ADCQ $0, acc3

	MOVQ t0, AX
	//MOVQ t0, DX              // This is not required due to t0=DX already
	SHLQ $32, AX
	SHRQ $32, DX

	SUBQ t0, acc1
	SBBQ AX, acc2
	SBBQ DX, acc3

	XORQ t0, t0
	// Add bits [511:256] of the sqr result
	ADCQ acc4, acc0
	ADCQ acc5, acc1
	ADCQ y_ptr, acc2
	ADCQ x_ptr, acc3
	ADCQ $0, t0

	p256OrdReduceInline(acc0, acc1, acc2, acc3, t0, acc4, acc5, y_ptr, t1, res_ptr)
	MOVQ res_ptr, x_ptr
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
// [acc7, acc6, acc5, acc4] = [acc7, acc6, acc5, acc4] - [t3, t2, t1, t0]
TEXT sm2P256SubInternal(SB),NOSPLIT,$0
	XORQ mul0, mul0
	SUBQ t0, acc4
	SBBQ t1, acc5
	SBBQ t2, acc6
	SBBQ t3, acc7
	SBBQ $0, mul0

	MOVQ acc4, acc0
	MOVQ acc5, acc1
	MOVQ acc6, acc2
	MOVQ acc7, acc3

	ADDQ $-1, acc4
	ADCQ p256p<>+0x08(SB), acc5
	ADCQ $-1, acc6
	ADCQ p256p<>+0x018(SB), acc7
	ANDQ $1, mul0

	CMOVQEQ acc0, acc4
	CMOVQEQ acc1, acc5
	CMOVQEQ acc2, acc6
	CMOVQEQ acc3, acc7

	RET
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
	sm2P256MulReductionInternal()
	
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
	CMOVQCS acc0, acc4
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

	sm2P256MulReductionInternal()
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
	CMOVQCS acc0, acc4
	CMOVQCS acc1, acc5
	CMOVQCS acc2, acc6
	CMOVQCS acc3, acc7

	RET

/* ---------------------------------------*/
// [acc7, acc6, acc5, acc4] = [acc7, acc6, acc5, acc4]^2
TEXT sm2P256SqrInternal(SB),NOSPLIT,$8
	CMPB ·supportBMI2+0(SB), $0x01
	JEQ  internalSqrBMI2

	MOVQ acc4, mul0
	MULQ acc5
	MOVQ mul0, acc1
	MOVQ mul1, acc2

	MOVQ acc4, mul0
	MULQ acc6
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, acc3

	MOVQ acc4, mul0
	MULQ acc7
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, t0

	MOVQ acc5, mul0
	MULQ acc6
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc5, mul0
	MULQ acc7
	ADDQ hlp, t0
	ADCQ $0, mul1
	ADDQ mul0, t0
	ADCQ $0, mul1
	MOVQ mul1, t1

	MOVQ acc6, mul0
	MULQ acc7
	ADDQ mul0, t1
	ADCQ $0, mul1
	MOVQ mul1, t2
	XORQ t3, t3
	// *2
	ADDQ acc1, acc1
	ADCQ acc2, acc2
	ADCQ acc3, acc3
	ADCQ t0, t0
	ADCQ t1, t1
	ADCQ t2, t2
	ADCQ $0, t3
	// Missing products
	MOVQ acc4, mul0
	MULQ mul0
	MOVQ mul0, acc0
	MOVQ DX, acc4

	MOVQ acc5, mul0
	MULQ mul0
	ADDQ acc4, acc1
	ADCQ mul0, acc2
	ADCQ $0, DX
	MOVQ DX, acc4

	MOVQ acc6, mul0
	MULQ mul0
	ADDQ acc4, acc3
	ADCQ mul0, t0
	ADCQ $0, DX
	MOVQ DX, acc4

	MOVQ acc7, mul0
	MULQ mul0
	ADDQ acc4, t1
	ADCQ mul0, t2
	ADCQ DX, t3
	// T = [t3, t2,, t1, t0, acc3, acc2, acc1, acc0]
	sm2P256SqrReductionInternal()
	RET

internalSqrBMI2:
	MOVQ acc4, mul1
	MULXQ acc5, acc1, acc2

	MULXQ acc6, mul0, acc3
	ADDQ mul0, acc2

	MULXQ acc7, mul0, t0
	ADCQ mul0, acc3
	ADCQ $0, t0

	MOVQ acc5, mul1
	MULXQ acc6, mul0, hlp
	ADDQ mul0, acc3
	ADCQ hlp, t0

	MULXQ acc7, mul0, t1
	ADCQ $0, t1
	ADDQ mul0, t0

	MOVQ acc6, mul1
	MULXQ acc7, mul0, t2
	ADCQ mul0, t1
	ADCQ $0, t2
	XORQ t3, t3

	// *2
	ADDQ acc1, acc1
	ADCQ acc2, acc2
	ADCQ acc3, acc3
	ADCQ t0, t0
	ADCQ t1, t1
	ADCQ t2, t2
	ADCQ $0, t3

	// Missing products
	MOVQ acc4, mul1
	MULXQ mul1, acc0, acc4 
	ADDQ acc4, acc1

	MOVQ acc5, mul1
	MULXQ mul1, mul0, acc4
	ADCQ mul0, acc2
	ADCQ  acc4, acc3

	MOVQ acc6, mul1
	MULXQ mul1, mul0, acc4
	ADCQ mul0, t0
	ADCQ acc4, t1

	MOVQ acc7, mul1
	MULXQ mul1, mul0, acc4
	ADCQ mul0, t2
	ADCQ acc4, t3
	// T = [t3, t2,, t1, t0, acc3, acc2, acc1, acc0]
	sm2P256SqrReductionInternal()

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
	ADDQ $-1, acc0                  \
	ADCQ p256p<>+0x08(SB), acc1     \
	ADCQ $-1, acc2                  \
	ADCQ p256p<>+0x018(SB), acc3    \
	ADCQ $0, mul0                   \
	CMOVQNE t0, acc0                \
	CMOVQNE t1, acc1                \
	CMOVQNE t2, acc2                \
	CMOVQNE t3, acc3                \
	\// If condition is 0, keep original value
	TESTQ DX, DX                      \
	CMOVQEQ acc4, acc0                \
	CMOVQEQ acc5, acc1                \
	CMOVQEQ acc6, acc2                \
	CMOVQEQ acc7, acc3                \
	\// Store result
	MOVQ acc0, y2in(8*0)                \
	MOVQ acc1, y2in(8*1)                \
	MOVQ acc2, y2in(8*2)                \
	MOVQ acc3, y2in(8*3)                \
	\// Begin point add
	LDacc (z1in)                        \
	CALL sm2P256SqrInternal(SB)	        \// z1ˆ2
	ST (z1sqr)                          \
	\
	LDt (x2in)                          \
	CALL sm2P256MulInternal(SB)	        \// x2 * z1ˆ2
	\
	LDt (x1in)                          \
	CALL sm2P256SubInternal(SB)	        \// h = u2 - u1
	ST (h)                              \
	\
	LDt (z1in)                          \
	CALL sm2P256MulInternal(SB)	        \// z3 = h * z1
	ST (zout)                           \
	\
	LDacc (z1sqr)                       \
	CALL sm2P256MulInternal(SB)	        \// z1ˆ3
	\
	LDt (y2in)                          \
	CALL sm2P256MulInternal(SB)	        \// s2 = y2 * z1ˆ3
	ST (s2)                             \
	\
	LDt (y1in)                          \
	CALL sm2P256SubInternal(SB)	        \// r = s2 - s1
	ST (r)                              \
	\
	CALL sm2P256SqrInternal(SB)	        \// rsqr = rˆ2
	ST (rsqr)                           \
	\
	LDacc (h)                           \
	CALL sm2P256SqrInternal(SB)	        \// hsqr = hˆ2
	ST (hsqr)                           \
	\
	LDt (h)                             \
	CALL sm2P256MulInternal(SB)	        \// hcub = hˆ3
	ST (hcub)                           \
	\
	LDt (y1in)                          \
	CALL sm2P256MulInternal(SB)	        \// y1 * hˆ3
	ST (s2)                             \
	\
	LDacc (x1in)                        \
	LDt (hsqr)                          \
	CALL sm2P256MulInternal(SB)	        \// u1 * hˆ2
	ST (h)                              \
	\
	p256MulBy2Inline			        \// u1 * hˆ2 * 2, inline
	LDacc (rsqr)                        \
	CALL sm2P256SubInternal(SB)	        \// rˆ2 - u1 * hˆ2 * 2
	\
	LDt (hcub)                          \
	CALL sm2P256SubInternal(SB)         \
	ST (xout)                           \
	\
	MOVQ acc4, t0                       \
	MOVQ acc5, t1                       \
	MOVQ acc6, t2                       \
	MOVQ acc7, t3                       \
	LDacc (h)                           \
	CALL sm2P256SubInternal(SB)         \
	\
	LDt (r)                             \
	CALL sm2P256MulInternal(SB)         \
	\
	LDt (s2)                            \
	CALL sm2P256SubInternal(SB)         \
	ST (yout)                           \
	\// Load stored values from stack
	MOVQ rptr, AX                       \
	MOVL sel_save, BX                   \
	MOVL zero_save, CX                  \

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

	MOVL BX, X6
	MOVL CX, X7

	PXOR X8, X8
	PCMPEQL X9, X9

	PSHUFD $0, X6, X6
	PSHUFD $0, X7, X7

	PCMPEQL X8, X6
	PCMPEQL X8, X7

	MOVOU X6, X15
	PANDN X9, X15

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
	PANDN X9, X15

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
	MOVL BX, X6
	MOVL CX, X7

	VPXOR Y8, Y8, Y8
	VPCMPEQD Y9, Y9, Y9

	VPBROADCASTD X6, Y6
	VPBROADCASTD X7, Y7

	VPCMPEQD Y8, Y6, Y6
	VPCMPEQD Y8, Y7, Y7

	VMOVDQU Y6, Y15
	VPANDN Y9, Y15, Y15

	VPAND xout(32*0), Y15, Y0
	VPAND yout(32*0), Y15, Y1
	VPAND zout(32*0), Y15, Y2

	VPAND x1in(32*0), Y6, Y9
	VPAND y1in(32*0), Y6, Y10
	VPAND z1in(32*0), Y6, Y11

	VPXOR Y9, Y0, Y0
	VPXOR Y10, Y1, Y1
	VPXOR Y11, Y2, Y2

	// Similarly if zero == 0
	VPCMPEQD Y9, Y9, Y9
	VPANDN Y9, Y7, Y15

	VPAND Y15, Y0, Y0
	VPAND Y15, Y1, Y1
	VPAND Y15, Y2, Y2

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

// sm2P256IsZero returns 1 in AX if [acc4..acc7] represents zero and zero
// otherwise. It writes to [acc4..acc7], t0 and t1.
TEXT sm2P256IsZero(SB),NOSPLIT,$0
	// AX contains a flag that is set if the input is zero.
	XORQ AX, AX
	MOVQ $1, t1

	// Check whether [acc4..acc7] are all zero.
	MOVQ acc4, t0
	ORQ acc5, t0
	ORQ acc6, t0
	ORQ acc7, t0

	// Set the zero flag if so. (CMOV of a constant to a register doesn't
	// appear to be supported in Go. Thus t1 = 1.)
	CMOVQEQ t1, AX

	// XOR [acc4..acc7] with P and compare with zero again.
	XORQ $-1, acc4
	XORQ p256p<>+0x08(SB), acc5
	XORQ $-1, acc6
	XORQ p256p<>+0x018(SB), acc7
	ORQ acc5, acc4
	ORQ acc6, acc4
	ORQ acc7, acc4

	// Set the zero flag if so.
	CMOVQEQ t1, AX
	RET

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
	CALL sm2P256SubInternal(SB)	 \// r = s2 - s1
	ST (r)                       \
	CALL sm2P256IsZero(SB)       \
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
	CALL sm2P256SubInternal(SB)	 \// h = u2 - u1
	ST (h)                       \
	CALL sm2P256IsZero(SB)       \
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
	CALL sm2P256SubInternal(SB)	 \// rˆ2 - u1 * hˆ2 * 2
	\
	LDt (hcub)                   \
	CALL sm2P256SubInternal(SB)  \
	ST (xout)                    \
	\
	MOVQ acc4, t0                \
	MOVQ acc5, t1                \
	MOVQ acc6, t2                \
	MOVQ acc7, t3                \
	LDacc (u2)                   \
	CALL sm2P256SubInternal(SB)  \
	\
	LDt (r)                      \
	CALL sm2P256MulInternal(SB)  \
	\
	LDt (s2)                     \
	CALL sm2P256SubInternal(SB)  \
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
	LDacc (z)                              \
	CALL sm2P256SqrInternal(SB)            \
	ST (zsqr)                              \
	\
	LDt (x)                                \
	p256AddInline                          \
	STt (m)                                \
	\
	LDacc (z)                              \
	LDt (y)                                \
	CALL sm2P256MulInternal(SB)            \
	p256MulBy2Inline                       \  

#define calX() \
	LDacc (x)                               \
	LDt (zsqr)                              \
	CALL sm2P256SubInternal(SB)             \
	LDt (m)                                 \
	CALL sm2P256MulInternal(SB)             \
	ST (m)                                  \
	\// Multiply by 3
	p256MulBy2Inline                        \ 
	LDacc (m)                               \ 
	p256AddInline                           \
	STt (m)                                 \  
	\////////////////////////
	LDacc (y)                               \
	p256MulBy2Inline                        \
	t2acc                                   \
	CALL sm2P256SqrInternal(SB)             \
	ST (s)                                  \
	CALL sm2P256SqrInternal(SB)             \
	\// Divide by 2
	XORQ mul0, mul0                         \
	MOVQ acc4, t0                           \
	MOVQ acc5, t1                           \  
	MOVQ acc6, t2                           \
	MOVQ acc7, t3                           \
	\
	ADDQ $-1, acc4                          \
	ADCQ p256p<>+0x08(SB), acc5             \
	ADCQ $-1, acc6                          \
	ADCQ p256p<>+0x018(SB), acc7            \
	ADCQ $0, mul0                           \
	TESTQ $1, t0                            \
	\
	CMOVQEQ t0, acc4                        \
	CMOVQEQ t1, acc5                        \
	CMOVQEQ t2, acc6                        \
	CMOVQEQ t3, acc7                        \
	ANDQ t0, mul0                           \
	\
	SHRQ $1, acc5, acc4                     \
	SHRQ $1, acc6, acc5                     \ 
	SHRQ $1, acc7, acc6                     \
	SHRQ $1, mul0, acc7                     \ 
	ST (y)                                  \
	\/////////////////////////
	LDacc (x)                               \
	LDt (s)                                 \
	CALL sm2P256MulInternal(SB)             \
	ST (s)                                  \
	p256MulBy2Inline                        \
	STt (tmp)                               \
	\
	LDacc (m)                               \
	CALL sm2P256SqrInternal(SB)             \
	LDt (tmp)                               \
	CALL sm2P256SubInternal(SB)             \

#define calY() \
	acc2t                                   \
	LDacc (s)                               \
	CALL sm2P256SubInternal(SB)             \
	\
	LDt (m)                                 \
	CALL sm2P256MulInternal(SB)             \
	\
	LDt (y)                                 \
	CALL sm2P256SubInternal(SB)             \ 

#define lastP256PointDouble() \
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
