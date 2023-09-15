//go:build amd64 && !purego
// +build amd64,!purego

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
	MOVL f, AX; \   
	ANDL e, AX; \  // e AND f
	ANDNL g, e, BX; \ // NOT(e) AND g
	ORL  AX, BX; \
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
	MOVL (0*4)(BP), R8  // a = H0
	MOVL (1*4)(BP), R9  // b = H1
	MOVL (2*4)(BP), R10 // c = H2
	MOVL (3*4)(BP), R11 // d = H3
	MOVL (4*4)(BP), R12 // e = H4
	MOVL (5*4)(BP), R13 // f = H5
	MOVL (6*4)(BP), R14 // g = H6
	MOVL (7*4)(BP), DI // h = H7

loop:
	MOVQ SP, BP

	MSGSCHEDULE0(0)
	MSGSCHEDULE0(1)
	MSGSCHEDULE0(2)
	MSGSCHEDULE0(3)

	SM3ROUND0(0, 0x79cc4519, R8, R9, R10, R11, R12, R13, R14, DI)
	SM3ROUND0(1, 0xf3988a32, DI, R8, R9, R10, R11, R12, R13, R14)
	SM3ROUND0(2, 0xe7311465, R14, DI, R8, R9, R10, R11, R12, R13)
	SM3ROUND0(3, 0xce6228cb, R13, R14, DI, R8, R9, R10, R11, R12)
	SM3ROUND0(4, 0x9cc45197, R12, R13, R14, DI, R8, R9, R10, R11)
	SM3ROUND0(5, 0x3988a32f, R11, R12, R13, R14, DI, R8, R9, R10)
	SM3ROUND0(6, 0x7311465e, R10, R11, R12, R13, R14, DI, R8, R9)
	SM3ROUND0(7, 0xe6228cbc, R9, R10, R11, R12, R13, R14, DI, R8)
	SM3ROUND0(8, 0xcc451979, R8, R9, R10, R11, R12, R13, R14, DI)
	SM3ROUND0(9, 0x988a32f3, DI, R8, R9, R10, R11, R12, R13, R14)
	SM3ROUND0(10, 0x311465e7, R14, DI, R8, R9, R10, R11, R12, R13)
	SM3ROUND0(11, 0x6228cbce, R13, R14, DI, R8, R9, R10, R11, R12)
  
	SM3ROUND1(12, 0xc451979c, R12, R13, R14, DI, R8, R9, R10, R11)
	SM3ROUND1(13, 0x88a32f39, R11, R12, R13, R14, DI, R8, R9, R10)
	SM3ROUND1(14, 0x11465e73, R10, R11, R12, R13, R14, DI, R8, R9)
	SM3ROUND1(15, 0x228cbce6, R9, R10, R11, R12, R13, R14, DI, R8)
  
	SM3ROUND2(16, 0x9d8a7a87, R8, R9, R10, R11, R12, R13, R14, DI)
	SM3ROUND2(17, 0x3b14f50f, DI, R8, R9, R10, R11, R12, R13, R14)
	SM3ROUND2(18, 0x7629ea1e, R14, DI, R8, R9, R10, R11, R12, R13)
	SM3ROUND2(19, 0xec53d43c, R13, R14, DI, R8, R9, R10, R11, R12)
	SM3ROUND2(20, 0xd8a7a879, R12, R13, R14, DI, R8, R9, R10, R11)
	SM3ROUND2(21, 0xb14f50f3, R11, R12, R13, R14, DI, R8, R9, R10)
	SM3ROUND2(22, 0x629ea1e7, R10, R11, R12, R13, R14, DI, R8, R9)
	SM3ROUND2(23, 0xc53d43ce, R9, R10, R11, R12, R13, R14, DI, R8)
	SM3ROUND2(24, 0x8a7a879d, R8, R9, R10, R11, R12, R13, R14, DI)
	SM3ROUND2(25, 0x14f50f3b, DI, R8, R9, R10, R11, R12, R13, R14)
	SM3ROUND2(26, 0x29ea1e76, R14, DI, R8, R9, R10, R11, R12, R13)
	SM3ROUND2(27, 0x53d43cec, R13, R14, DI, R8, R9, R10, R11, R12)
	SM3ROUND2(28, 0xa7a879d8, R12, R13, R14, DI, R8, R9, R10, R11)
	SM3ROUND2(29, 0x4f50f3b1, R11, R12, R13, R14, DI, R8, R9, R10)
	SM3ROUND2(30, 0x9ea1e762, R10, R11, R12, R13, R14, DI, R8, R9)
	SM3ROUND2(31, 0x3d43cec5, R9, R10, R11, R12, R13, R14, DI, R8)
	SM3ROUND2(32, 0x7a879d8a, R8, R9, R10, R11, R12, R13, R14, DI)
	SM3ROUND2(33, 0xf50f3b14, DI, R8, R9, R10, R11, R12, R13, R14)
	SM3ROUND2(34, 0xea1e7629, R14, DI, R8, R9, R10, R11, R12, R13)
	SM3ROUND2(35, 0xd43cec53, R13, R14, DI, R8, R9, R10, R11, R12)
	SM3ROUND2(36, 0xa879d8a7, R12, R13, R14, DI, R8, R9, R10, R11)
	SM3ROUND2(37, 0x50f3b14f, R11, R12, R13, R14, DI, R8, R9, R10)
	SM3ROUND2(38, 0xa1e7629e, R10, R11, R12, R13, R14, DI, R8, R9)
	SM3ROUND2(39, 0x43cec53d, R9, R10, R11, R12, R13, R14, DI, R8)
	SM3ROUND2(40, 0x879d8a7a, R8, R9, R10, R11, R12, R13, R14, DI)
	SM3ROUND2(41, 0xf3b14f5, DI, R8, R9, R10, R11, R12, R13, R14)
	SM3ROUND2(42, 0x1e7629ea, R14, DI, R8, R9, R10, R11, R12, R13)
	SM3ROUND2(43, 0x3cec53d4, R13, R14, DI, R8, R9, R10, R11, R12)
	SM3ROUND2(44, 0x79d8a7a8, R12, R13, R14, DI, R8, R9, R10, R11)
	SM3ROUND2(45, 0xf3b14f50, R11, R12, R13, R14, DI, R8, R9, R10)
	SM3ROUND2(46, 0xe7629ea1, R10, R11, R12, R13, R14, DI, R8, R9)
	SM3ROUND2(47, 0xcec53d43, R9, R10, R11, R12, R13, R14, DI, R8)
	SM3ROUND2(48, 0x9d8a7a87, R8, R9, R10, R11, R12, R13, R14, DI)
	SM3ROUND2(49, 0x3b14f50f, DI, R8, R9, R10, R11, R12, R13, R14)
	SM3ROUND2(50, 0x7629ea1e, R14, DI, R8, R9, R10, R11, R12, R13)
	SM3ROUND2(51, 0xec53d43c, R13, R14, DI, R8, R9, R10, R11, R12)
	SM3ROUND2(52, 0xd8a7a879, R12, R13, R14, DI, R8, R9, R10, R11)
	SM3ROUND2(53, 0xb14f50f3, R11, R12, R13, R14, DI, R8, R9, R10)
	SM3ROUND2(54, 0x629ea1e7, R10, R11, R12, R13, R14, DI, R8, R9)
	SM3ROUND2(55, 0xc53d43ce, R9, R10, R11, R12, R13, R14, DI, R8)
	SM3ROUND2(56, 0x8a7a879d, R8, R9, R10, R11, R12, R13, R14, DI)
	SM3ROUND2(57, 0x14f50f3b, DI, R8, R9, R10, R11, R12, R13, R14)
	SM3ROUND2(58, 0x29ea1e76, R14, DI, R8, R9, R10, R11, R12, R13)
	SM3ROUND2(59, 0x53d43cec, R13, R14, DI, R8, R9, R10, R11, R12)
	SM3ROUND2(60, 0xa7a879d8, R12, R13, R14, DI, R8, R9, R10, R11)
	SM3ROUND2(61, 0x4f50f3b1, R11, R12, R13, R14, DI, R8, R9, R10)
	SM3ROUND2(62, 0x9ea1e762, R10, R11, R12, R13, R14, DI, R8, R9)
	SM3ROUND2(63, 0x3d43cec5, R9, R10, R11, R12, R13, R14, DI, R8)

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
	XORL (7*4)(BP), DI // H7 = h XOR H7
	MOVL DI, (7*4)(BP)

	ADDQ $64, SI
	CMPQ SI, 272(SP)
	JB   loop

end:
	RET
