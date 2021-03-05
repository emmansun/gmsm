#include "textflag.h"

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
  MOVL  AX, CX; \
  ROLL  $23, CX; \
  XORL  BX, AX; \
  XORL  CX, AX; \
  MOVL	((index-9)*4)(BP), BX; \
  ROLL  $7, BX; \
  MOVL	((index-2)*4)(BP), CX; \
  XORL  BX, AX; \
  XORL  CX, AX; \
  MOVL  AX, ((index+4)*4)(BP)

// Calculate ss1 in BX
// x = ROTL(12, a) + e + ROTL(index, const)
// ret = ROTL(7, x)
#define SM3SS1(index, const, a, e) \
  MOVL  a, BX; \
  ROLL  $12, BX; \
  ADDL  e, BX; \
  MOVL  $const, CX; \
  ROLL  $index, CX; \
  ADDL  CX, BX; \
  ROLL  $7, BX

// Calculate tt1 in CX
// ret = (a XOR b XOR c) + d + (ROTL(12, a) XOR ss1) + (Wt XOR Wt+4)
#define SM3TT10(index, a, b, c, d) \  
  MOVL a, CX; \
  MOVL b, DX; \
  XORL CX, DX; \
  MOVL c, DI; \
  XORL DI, DX; \  // (a XOR b XOR c)
  ADDL d, DX; \   // (a XOR b XOR c) + d 
  MOVL ((index)*4)(BP), DI; \ //Wt
  XORL DI, AX; \ //Wt XOR Wt+4
  ADDL AX, DX;  \
  ROLL $12, CX; \
  XORL BX, CX; \ // ROTL(12, a) XOR ss1
  ADDL DX, CX  // (a XOR b XOR c) + d + (ROTL(12, a) XOR ss1)

// Calculate tt2 in BX
// ret = (e XOR f XOR g) + h + ss1 + Wt
#define SM3TT20(e, f, g, h) \  
  ADDL h, DI; \   //Wt + h
  ADDL BX, DI; \  //Wt + h + ss1
  MOVL e, BX; \
  MOVL f, DX; \
  XORL DX, BX; \  // e XOR f
  MOVL g, DX; \
  XORL DX, BX; \  // e XOR f XOR g
  ADDL DI, BX     // (e XOR f XOR g) + Wt + h + ss1

// Calculate tt1 in CX, used DX, DI
// ret = ((a AND b) OR (a AND c) OR (b AND c)) + d + (ROTL(12, a) XOR ss1) + (Wt XOR Wt+4)
#define SM3TT11(index, a, b, c, d) \  
  MOVL a, CX; \
  MOVL b, DX; \
  ANDL CX, DX; \  // a AND b
  MOVL c, DI; \
  ANDL DI, CX; \  // a AND c
  ORL  DX, CX; \  // (a AND b) OR (a AND c)
  MOVL b, DX; \
  ANDL DI, DX; \  // b AND c
  ORL  CX, DX; \  // (a AND b) OR (a AND c) OR (b AND c)
  ADDL d, DX; \
  MOVL a, CX; \
  ROLL $12, CX; \
  XORL BX, CX; \
  ADDL DX, CX; \  // ((a AND b) OR (a AND c) OR (b AND c)) + d + (ROTL(12, a) XOR ss1)
  MOVL ((index)*4)(BP), DI; \
  XORL DI, AX; \  // Wt XOR Wt+4
  ADDL AX, CX

// Calculate tt2 in BX
// ret = ((e AND f) OR (NOT(e) AND g)) + h + ss1 + Wt
#define SM3TT21(e, f, g, h) \  
  ADDL h, DI; \   // Wt + h
  ADDL BX, DI; \  // h + ss1 + Wt
  MOVL e, BX; \
  MOVL f, DX; \   
  ANDL BX, DX; \  // e AND f
  NOTL BX; \      // NOT(e)
  MOVL g, AX; \
  ANDL AX, BX; \ // NOT(e) AND g
  ORL  DX, BX; \
  ADDL DI, BX

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
  SM3SS1(index, const, a, e); \
  SM3TT10(index, a, b, c, d); \
  SM3TT20(e, f, g, h); \
  COPYRESULT(b, d, f, h)

#define SM3ROUND1(index, const, a, b, c, d, e, f, g, h) \
  MSGSCHEDULE1(index); \
  SM3SS1(index, const, a, e); \
  SM3TT10(index, a, b, c, d); \
  SM3TT20(e, f, g, h); \
  COPYRESULT(b, d, f, h)

#define SM3ROUND2(index, const, a, b, c, d, e, f, g, h) \
  MSGSCHEDULE1(index); \
  SM3SS1(index, const, a, e); \
  SM3TT11(index, a, b, c, d); \
  SM3TT21(e, f, g, h); \
  COPYRESULT(b, d, f, h)

TEXT ·block(SB), 0, $544-32
	MOVQ p_base+8(FP), SI
	MOVQ p_len+16(FP), DX
	SHRQ $6, DX
	SHLQ $6, DX

	LEAQ (SI)(DX*1), DI
	MOVQ DI, 272(SP)
	CMPQ SI, DI
	JEQ  end

	MOVQ dig+0(FP), BP
	MOVL (0*4)(BP), R8  // a = H0
	MOVL (1*4)(BP), R9  // b = H1
	MOVL (2*4)(BP), R10 // c = H2
	MOVL (3*4)(BP), R11 // d = H3
	MOVL (4*4)(BP), R12 // e = H4
	MOVL (5*4)(BP), R13 // f = H5
	MOVL (6*4)(BP), R14 // g = H6
	MOVL (7*4)(BP), R15 // h = H7

loop:
	MOVQ SP, BP

  MSGSCHEDULE0(0)
  MSGSCHEDULE0(1)
  MSGSCHEDULE0(2)
  MSGSCHEDULE0(3)

  SM3ROUND0(0, 0x79cc4519, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND0(1, 0x79cc4519, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND0(2, 0x79cc4519, R14, R15, R8, R9, R10, R11, R12, R13)
  SM3ROUND0(3, 0x79cc4519, R13, R14, R15, R8, R9, R10, R11, R12)
  SM3ROUND0(4, 0x79cc4519, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND0(5, 0x79cc4519, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND0(6, 0x79cc4519, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND0(7, 0x79cc4519, R9, R10, R11, R12, R13, R14, R15, R8)
  
  SM3ROUND0(8, 0x79cc4519, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND0(9, 0x79cc4519, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND0(10, 0x79cc4519, R14, R15, R8, R9, R10, R11, R12, R13)
  
  SM3ROUND0(11, 0x79cc4519, R13, R14, R15, R8, R9, R10, R11, R12)
  
  SM3ROUND1(12, 0x79cc4519, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND1(13, 0x79cc4519, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND1(14, 0x79cc4519, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND1(15, 0x79cc4519, R9, R10, R11, R12, R13, R14, R15, R8)
  
  SM3ROUND2(16, 0x7a879d8a, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND2(17, 0x7a879d8a, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND2(18, 0x7a879d8a, R14, R15, R8, R9, R10, R11, R12, R13)
  SM3ROUND2(19, 0x7a879d8a, R13, R14, R15, R8, R9, R10, R11, R12)
  SM3ROUND2(20, 0x7a879d8a, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND2(21, 0x7a879d8a, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND2(22, 0x7a879d8a, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND2(23, 0x7a879d8a, R9, R10, R11, R12, R13, R14, R15, R8)
  SM3ROUND2(24, 0x7a879d8a, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND2(25, 0x7a879d8a, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND2(26, 0x7a879d8a, R14, R15, R8, R9, R10, R11, R12, R13)
  SM3ROUND2(27, 0x7a879d8a, R13, R14, R15, R8, R9, R10, R11, R12)
  SM3ROUND2(28, 0x7a879d8a, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND2(29, 0x7a879d8a, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND2(30, 0x7a879d8a, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND2(31, 0x7a879d8a, R9, R10, R11, R12, R13, R14, R15, R8)
  SM3ROUND2(32, 0x7a879d8a, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND2(33, 0x7a879d8a, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND2(34, 0x7a879d8a, R14, R15, R8, R9, R10, R11, R12, R13)
  SM3ROUND2(35, 0x7a879d8a, R13, R14, R15, R8, R9, R10, R11, R12)
  SM3ROUND2(36, 0x7a879d8a, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND2(37, 0x7a879d8a, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND2(38, 0x7a879d8a, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND2(39, 0x7a879d8a, R9, R10, R11, R12, R13, R14, R15, R8)
  SM3ROUND2(40, 0x7a879d8a, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND2(41, 0x7a879d8a, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND2(42, 0x7a879d8a, R14, R15, R8, R9, R10, R11, R12, R13)
  SM3ROUND2(43, 0x7a879d8a, R13, R14, R15, R8, R9, R10, R11, R12)
  SM3ROUND2(44, 0x7a879d8a, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND2(45, 0x7a879d8a, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND2(46, 0x7a879d8a, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND2(47, 0x7a879d8a, R9, R10, R11, R12, R13, R14, R15, R8)
  SM3ROUND2(48, 0x7a879d8a, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND2(49, 0x7a879d8a, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND2(50, 0x7a879d8a, R14, R15, R8, R9, R10, R11, R12, R13)
  SM3ROUND2(51, 0x7a879d8a, R13, R14, R15, R8, R9, R10, R11, R12)
  SM3ROUND2(52, 0x7a879d8a, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND2(53, 0x7a879d8a, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND2(54, 0x7a879d8a, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND2(55, 0x7a879d8a, R9, R10, R11, R12, R13, R14, R15, R8)
  SM3ROUND2(56, 0x7a879d8a, R8, R9, R10, R11, R12, R13, R14, R15)
  SM3ROUND2(57, 0x7a879d8a, R15, R8, R9, R10, R11, R12, R13, R14)
  SM3ROUND2(58, 0x7a879d8a, R14, R15, R8, R9, R10, R11, R12, R13)
  SM3ROUND2(59, 0x7a879d8a, R13, R14, R15, R8, R9, R10, R11, R12)
  SM3ROUND2(60, 0x7a879d8a, R12, R13, R14, R15, R8, R9, R10, R11)
  SM3ROUND2(61, 0x7a879d8a, R11, R12, R13, R14, R15, R8, R9, R10)
  SM3ROUND2(62, 0x7a879d8a, R10, R11, R12, R13, R14, R15, R8, R9)
  SM3ROUND2(63, 0x7a879d8a, R9, R10, R11, R12, R13, R14, R15, R8)

	MOVQ dig+0(FP), BP

	XORL (0*4)(BP), R8  // H0 = a XOR H0
	MOVL R8, (0*4)(BP)
	XORL (1*4)(BP), R9  // H1 = b XOR H1
	MOVL R9, (1*4)(BP)
	XORL (2*4)(BP), R10 // H2 = c XOR H2
	MOVL R10, (2*4)(BP)
	XORL (3*4)(BP), R11 // H3 = d XOR H3
	MOVL R11, (3*4)(BP)
	XORL (4*4)(BP), R12 // H4 = e XOR H4
	MOVL R12, (4*4)(BP)
	XORL (5*4)(BP), R13 // H5 = f XOR H5
	MOVL R13, (5*4)(BP)
	XORL (6*4)(BP), R14 // H6 = g XOR H6
	MOVL R14, (6*4)(BP)
	XORL (7*4)(BP), R15 // H7 = h XOR H7
	MOVL R15, (7*4)(BP)

	ADDQ $64, SI
	CMPQ SI, 272(SP)
	JB   loop

end:
	RET
