//go:build amd64 && !purego
// +build amd64,!purego

#include "textflag.h"

#include "sm3_const_asm.s"

// xorm (mem), reg
// Xor reg to mem using reg-mem xor and store
#define xorm(P1, P2) \
	XORL P2, P1; \
	MOVL P1, P2

#define a R8
#define b R9
#define c R10
#define d R11
#define e R12
#define f R13
#define g R14
#define h DI

// Wt = Mt; for 0 <= t <= 3
#define MSGSCHEDULE0(index) \
	MOVL	(index*4)(SI), AX; \
	BSWAPL	AX; \
	MOVL	AX, (index*4)(BP)

// Wt+4 = Mt+4; for 0 <= t <= 11
#define MSGSCHEDULE01(index) \
	MOVL	((index+4)*4)(SI), AX; \
	BSWAPL	AX; \
	MOVL	AX, ((index+4)*4)(BP)

// x = Wt-12 XOR Wt-5 XOR ROTL(15, Wt+1)
// p1(x) = x XOR ROTL(15, x) XOR ROTL(23, x)
// Wt+4 = p1(x) XOR ROTL(7, Wt-9) XOR Wt-2
// for 12 <= t <= 63
#define MSGSCHEDULE1(index) \
	MOVL	((index+1)*4)(BP), AX; \
	ROLL  $15, AX; \
	MOVL	((index-12)*4)(BP), BX; \
	XORL  BX, AX; \
	MOVL	((index-5)*4)(BP), BX; \
	XORL  BX, AX; \
	MOVL  AX, BX; \
	ROLL  $15, BX; \
	XORL  BX, AX; \
	ROLL  $8, BX; \
	XORL  BX, AX; \
	MOVL	((index-9)*4)(BP), BX; \
	ROLL  $7, BX; \
	XORL  BX, AX; \
	MOVL	((index-2)*4)(BP), BX; \
	XORL  BX, AX; \
	MOVL  AX, ((index+4)*4)(BP)

// Calculate ss1 in BX
// x = ROTL(12, a) + e + ROTL(index, const)
// ret = ROTL(7, x)
#define SM3SS1(const, a, e) \
	MOVL  a, BX; \
	ROLL  $12, BX; \
	ADDL  e, BX; \
	ADDL  $const, BX; \
	ROLL  $7, BX

// Calculate tt1 in CX
// ret = (a XOR b XOR c) + d + (ROTL(12, a) XOR ss1) + (Wt XOR Wt+4)
#define SM3TT10(index, a, b, c, d) \  
	MOVL b, DX; \
	XORL a, DX; \
	XORL c, DX; \  // (a XOR b XOR c)
	ADDL d, DX; \   // (a XOR b XOR c) + d 
	MOVL ((index)*4)(BP), CX; \ //Wt
	XORL CX, AX; \ //Wt XOR Wt+4
	ADDL AX, DX;  \
	MOVL a, CX; \
	ROLL $12, CX; \
	XORL BX, CX; \ // ROTL(12, a) XOR ss1
	ADDL DX, CX  // (a XOR b XOR c) + d + (ROTL(12, a) XOR ss1)

// Calculate tt2 in BX
// ret = (e XOR f XOR g) + h + ss1 + Wt
#define SM3TT20(index, e, f, g, h) \
	MOVL ((index)*4)(BP), DX; \ //Wt
	ADDL h, DX; \   //Wt + h
	ADDL BX, DX; \  //Wt + h + ss1
	MOVL e, BX; \
	XORL f, BX; \  // e XOR f
	XORL g, BX; \  // e XOR f XOR g
	ADDL DX, BX     // (e XOR f XOR g) + Wt + h + ss1

// Calculate tt1 in CX, used DX
// ret = ((a AND b) OR (a AND c) OR (b AND c)) + d + (ROTL(12, a) XOR ss1) + (Wt XOR Wt+4)
#define SM3TT11(index, a, b, c, d) \  
	MOVL a, DX; \
	ORL  b, DX; \  // a AND b
	MOVL a, CX; \
	ANDL b, CX; \  // a AND b
	ANDL c, DX; \
	ORL  CX, DX; \  // (a AND b) OR (a AND c) OR (b AND c)
	ADDL d, DX; \
	MOVL a, CX; \
	ROLL $12, CX; \
	XORL BX, CX; \
	ADDL DX, CX; \  // ((a AND b) OR (a AND c) OR (b AND c)) + d + (ROTL(12, a) XOR ss1)
	MOVL ((index)*4)(BP), DX; \
	XORL DX, AX; \  // Wt XOR Wt+4
	ADDL AX, CX

// Calculate tt2 in BX
// ret = ((e AND f) OR (NOT(e) AND g)) + h + ss1 + Wt
#define SM3TT21(index, e, f, g, h) \
	MOVL ((index)*4)(BP), DX; \
	ADDL h, DX; \   // Wt + h
	ADDL BX, DX; \  // h + ss1 + Wt
	MOVL f, BX; \   
	XORL g, BX; \
	ANDL e, BX; \
	XORL g, BX; \ // GG2(e, f, g)
	ADDL DX, BX

#define COPYRESULT(b, d, f, h) \
	ROLL $9, b; \
	MOVL CX, h; \   // a = ttl
	ROLL $19, f; \
	MOVL BX, CX; \
	ROLL $9, CX; \
	XORL BX, CX; \  // tt2 XOR ROTL(9, tt2)
	ROLL $17, BX; \
	XORL BX, CX; \  // tt2 XOR ROTL(9, tt2) XOR ROTL(17, tt2)
	MOVL CX, d    // e = tt2 XOR ROTL(9, tt2) XOR ROTL(17, tt2)

#define SM3ROUND0(index, const, a, b, c, d, e, f, g, h) \
	MSGSCHEDULE01(index); \
	SM3SS1(const, a, e); \
	SM3TT10(index, a, b, c, d); \
	SM3TT20(index, e, f, g, h); \
	COPYRESULT(b, d, f, h)

#define SM3ROUND1(index, const, a, b, c, d, e, f, g, h) \
	MSGSCHEDULE1(index); \
	SM3SS1(const, a, e); \
	SM3TT10(index, a, b, c, d); \
	SM3TT20(index, e, f, g, h); \
	COPYRESULT(b, d, f, h)

#define SM3ROUND2(index, const, a, b, c, d, e, f, g, h) \
	MSGSCHEDULE1(index); \
	SM3SS1(const, a, e); \
	SM3TT11(index, a, b, c, d); \
	SM3TT21(index, e, f, g, h); \
	COPYRESULT(b, d, f, h)

TEXT ·blockAMD64(SB), 0, $288-32
	MOVQ p_base+8(FP), SI
	MOVQ p_len+16(FP), DX
	SHRQ $6, DX
	SHLQ $6, DX

	LEAQ (SI)(DX*1), DI
	MOVQ DI, 272(SP)
	CMPQ SI, DI
	JEQ  end

	MOVQ dig+0(FP), BP
	MOVL (0*4)(BP), a // a = H0
	MOVL (1*4)(BP), b // b = H1
	MOVL (2*4)(BP), c // c = H2
	MOVL (3*4)(BP), d // d = H3
	MOVL (4*4)(BP), e // e = H4
	MOVL (5*4)(BP), f // f = H5
	MOVL (6*4)(BP), g // g = H6
	MOVL (7*4)(BP), h // h = H7

loop:
	MOVQ SP, BP

	MSGSCHEDULE0(0)
	MSGSCHEDULE0(1)
	MSGSCHEDULE0(2)
	MSGSCHEDULE0(3)

	SM3ROUND0(0, T0, a, b, c, d, e, f, g, h)
	SM3ROUND0(1, T1, h, a, b, c, d, e, f, g)
	SM3ROUND0(2, T2, g, h, a, b, c, d, e, f)
	SM3ROUND0(3, T3, f, g, h, a, b, c, d, e)
	SM3ROUND0(4, T4, e, f, g, h, a, b, c, d)
	SM3ROUND0(5, T5, d, e, f, g, h, a, b, c)
	SM3ROUND0(6, T6, c, d, e, f, g, h, a, b)
	SM3ROUND0(7, T7, b, c, d, e, f, g, h, a)
	SM3ROUND0(8, T8, a, b, c, d, e, f, g, h)
	SM3ROUND0(9, T9, h, a, b, c, d, e, f, g)
	SM3ROUND0(10, T10, g, h, a, b, c, d, e, f)
	SM3ROUND0(11, T11, f, g, h, a, b, c, d, e)
  
	SM3ROUND1(12, T12, e, f, g, h, a, b, c, d)
	SM3ROUND1(13, T13, d, e, f, g, h, a, b, c)
	SM3ROUND1(14, T14, c, d, e, f, g, h, a, b)
	SM3ROUND1(15, T15, b, c, d, e, f, g, h, a)
  
	SM3ROUND2(16, T16, a, b, c, d, e, f, g, h)
	SM3ROUND2(17, T17, h, a, b, c, d, e, f, g)
	SM3ROUND2(18, T18, g, h, a, b, c, d, e, f)
	SM3ROUND2(19, T19, f, g, h, a, b, c, d, e)
	SM3ROUND2(20, T20, e, f, g, h, a, b, c, d)
	SM3ROUND2(21, T21, d, e, f, g, h, a, b, c)
	SM3ROUND2(22, T22, c, d, e, f, g, h, a, b)
	SM3ROUND2(23, T23, b, c, d, e, f, g, h, a)
	SM3ROUND2(24, T24, a, b, c, d, e, f, g, h)
	SM3ROUND2(25, T25, h, a, b, c, d, e, f, g)
	SM3ROUND2(26, T26, g, h, a, b, c, d, e, f)
	SM3ROUND2(27, T27, f, g, h, a, b, c, d, e)
	SM3ROUND2(28, T28, e, f, g, h, a, b, c, d)
	SM3ROUND2(29, T29, d, e, f, g, h, a, b, c)
	SM3ROUND2(30, T30, c, d, e, f, g, h, a, b)
	SM3ROUND2(31, T31, b, c, d, e, f, g, h, a)
	SM3ROUND2(32, T32, a, b, c, d, e, f, g, h)
	SM3ROUND2(33, T33, h, a, b, c, d, e, f, g)
	SM3ROUND2(34, T34, g, h, a, b, c, d, e, f)
	SM3ROUND2(35, T35, f, g, h, a, b, c, d, e)
	SM3ROUND2(36, T36, e, f, g, h, a, b, c, d)
	SM3ROUND2(37, T37, d, e, f, g, h, a, b, c)
	SM3ROUND2(38, T38, c, d, e, f, g, h, a, b)
	SM3ROUND2(39, T39, b, c, d, e, f, g, h, a)
	SM3ROUND2(40, T40, a, b, c, d, e, f, g, h)
	SM3ROUND2(41, T41, h, a, b, c, d, e, f, g)
	SM3ROUND2(42, T42, g, h, a, b, c, d, e, f)
	SM3ROUND2(43, T43, f, g, h, a, b, c, d, e)
	SM3ROUND2(44, T44, e, f, g, h, a, b, c, d)
	SM3ROUND2(45, T45, d, e, f, g, h, a, b, c)
	SM3ROUND2(46, T46, c, d, e, f, g, h, a, b)
	SM3ROUND2(47, T47, b, c, d, e, f, g, h, a)
	SM3ROUND2(48, T48, a, b, c, d, e, f, g, h)
	SM3ROUND2(49, T49, h, a, b, c, d, e, f, g)
	SM3ROUND2(50, T50, g, h, a, b, c, d, e, f)
	SM3ROUND2(51, T51, f, g, h, a, b, c, d, e)
	SM3ROUND2(52, T52, e, f, g, h, a, b, c, d)
	SM3ROUND2(53, T53, d, e, f, g, h, a, b, c)
	SM3ROUND2(54, T54, c, d, e, f, g, h, a, b)
	SM3ROUND2(55, T55, b, c, d, e, f, g, h, a)
	SM3ROUND2(56, T56, a, b, c, d, e, f, g, h)
	SM3ROUND2(57, T57, h, a, b, c, d, e, f, g)
	SM3ROUND2(58, T58, g, h, a, b, c, d, e, f)
	SM3ROUND2(59, T59, f, g, h, a, b, c, d, e)
	SM3ROUND2(60, T60, e, f, g, h, a, b, c, d)
	SM3ROUND2(61, T61, d, e, f, g, h, a, b, c)
	SM3ROUND2(62, T62, c, d, e, f, g, h, a, b)
	SM3ROUND2(63, T63, b, c, d, e, f, g, h, a)

	MOVQ hg+0(FP), BP

	xorm(  0(BP), a)
	xorm(  4(BP), b)
	xorm(  8(BP), c)
	xorm( 12(BP), d)
	xorm( 16(BP), e)
	xorm( 20(BP), f)
	xorm( 24(BP), g)
	xorm( 28(BP), h)

	ADDQ $64, SI
	CMPQ SI, 272(SP)
	JB   loop

end:
	RET
