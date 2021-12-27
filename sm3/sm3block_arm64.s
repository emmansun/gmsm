#include "textflag.h"

#define SI R0
#define DI R1
#define BP R2
#define AX R3
#define BX R4
#define CX R5
#define DX R6

// Wt = Mt; for 0 <= t <= 3
#define MSGSCHEDULE0(index) \
	MOVWU	(index*4)(SI), AX; \
	REVW	AX; \
	MOVWU	AX, (index*4)(BP)

// Wt+4 = Mt+4; for 0 <= t <= 11
#define MSGSCHEDULE01(index) \
	MOVWU	((index+4)*4)(SI), AX; \
	REVW	AX; \
	MOVWU	AX, ((index+4)*4)(BP)

// x = Wt-12 XOR Wt-5 XOR ROTL(15, Wt+1)
// p1(x) = x XOR ROTL(15, x) XOR ROTL(23, x)
// Wt+4 = p1(x) XOR ROTL(7, Wt-9) XOR Wt-2
// for 12 <= t <= 63
#define MSGSCHEDULE1(index) \
  MOVWU	((index+1)*4)(BP), AX; \
  RORW  $17, AX; \
  MOVWU	((index-12)*4)(BP), BX; \
  EORW  BX, AX; \
  MOVWU	((index-5)*4)(BP), BX; \
  EORW  BX, AX; \
  MOVWU  AX, BX; \
  RORW  $17, BX; \
  MOVWU  AX, CX; \
  RORW  $9, CX; \
  EORW  BX, AX; \
  EORW  CX, AX; \
  MOVWU	((index-9)*4)(BP), BX; \
  RORW  $25, BX; \
  MOVWU	((index-2)*4)(BP), CX; \
  EORW  BX, AX; \
  EORW  CX, AX; \
  MOVWU  AX, ((index+4)*4)(BP)

// Calculate ss1 in BX
// x = ROTL(12, a) + e + ROTL(index, const)
// ret = ROTL(7, x)
#define SM3SS1(const, a, e) \
  MOVWU  a, BX; \
  RORW  $20, BX; \
  ADDW  e, BX; \
  ADDW  $const, BX; \
  RORW  $25, BX

// Calculate tt1 in CX
// ret = (a XOR b XOR c) + d + (ROTL(12, a) XOR ss1) + (Wt XOR Wt+4)
#define SM3TT10(index, a, b, c, d) \  
  MOVWU a, CX; \
  MOVWU b, DX; \
  EORW CX, DX; \
  MOVWU c, DI; \
  EORW DI, DX; \  // (a XOR b XOR c)
  ADDW d, DX; \   // (a XOR b XOR c) + d 
  MOVWU ((index)*4)(BP), DI; \ //Wt
  EORW DI, AX; \ //Wt XOR Wt+4
  ADDW AX, DX;  \
  RORW $20, CX; \
  EORW BX, CX; \ // ROTL(12, a) XOR ss1
  ADDW DX, CX  // (a XOR b XOR c) + d + (ROTL(12, a) XOR ss1)

// Calculate tt2 in BX
// ret = (e XOR f XOR g) + h + ss1 + Wt
#define SM3TT20(e, f, g, h) \  
  ADDW h, DI; \   //Wt + h
  ADDW BX, DI; \  //Wt + h + ss1
  MOVWU e, BX; \
  MOVWU f, DX; \
  EORW DX, BX; \  // e XOR f
  MOVWU g, DX; \
  EORW DX, BX; \  // e XOR f XOR g
  ADDW DI, BX     // (e XOR f XOR g) + Wt + h + ss1

// Calculate tt1 in CX, used DX, DI
// ret = ((a AND b) OR (a AND c) OR (b AND c)) + d + (ROTL(12, a) XOR ss1) + (Wt XOR Wt+4)
#define SM3TT11(index, a, b, c, d) \  
  MOVWU a, CX; \
  MOVWU b, DX; \
  ANDW CX, DX; \  // a AND b
  MOVWU c, DI; \
  ANDW DI, CX; \  // a AND c
  ORRW  DX, CX; \  // (a AND b) OR (a AND c)
  MOVWU b, DX; \
  ANDW DI, DX; \  // b AND c
  ORRW  CX, DX; \  // (a AND b) OR (a AND c) OR (b AND c)
  ADDW d, DX; \
  MOVWU a, CX; \
  RORW $20, CX; \
  EORW BX, CX; \
  ADDW DX, CX; \  // ((a AND b) OR (a AND c) OR (b AND c)) + d + (ROTL(12, a) XOR ss1)
  MOVWU ((index)*4)(BP), DI; \
  EORW DI, AX; \  // Wt XOR Wt+4
  ADDW AX, CX

// Calculate tt2 in BX
// ret = ((e AND f) OR (NOT(e) AND g)) + h + ss1 + Wt
#define SM3TT21(e, f, g, h) \  
  ADDW h, DI; \   // Wt + h
  ADDW BX, DI; \  // h + ss1 + Wt
  MOVWU e, BX; \
  MOVWU f, DX; \   
  ANDW BX, DX; \  // e AND f
  NOTL BX; \      // NOT(e)
  MOVWU g, AX; \
  ANDW AX, BX; \ // NOT(e) AND g
  ORRW  DX, BX; \
  ADDW DI, BX

#define COPYRESULT(b, d, f, h) \
  RORW $23, b; \
  MOVWU CX, h; \   // a = ttl
  RORW $13, f; \
  MOVWU BX, CX; \
  RORW $23, CX; \
  EORW BX, CX; \  // tt2 XOR ROTL(9, tt2)
  RORW $15, BX; \
  EORW BX, CX; \  // tt2 XOR ROTL(9, tt2) XOR ROTL(17, tt2)
  MOVWU CX, d    // e = tt2 XOR ROTL(9, tt2) XOR ROTL(17, tt2)

#define SM3ROUND0(index, const, a, b, c, d, e, f, g, h) \
  MSGSCHEDULE01(index); \
  SM3SS1(const, a, e); \
  SM3TT10(index, a, b, c, d); \
  SM3TT20(e, f, g, h); \
  COPYRESULT(b, d, f, h)

#define SM3ROUND1(index, const, a, b, c, d, e, f, g, h) \
  MSGSCHEDULE1(index); \
  SM3SS1(const, a, e); \
  SM3TT10(index, a, b, c, d); \
  SM3TT20(e, f, g, h); \
  COPYRESULT(b, d, f, h)

#define SM3ROUND2(index, const, a, b, c, d, e, f, g, h) \
  MSGSCHEDULE1(index); \
  SM3SS1(const, a, e); \
  SM3TT11(index, a, b, c, d); \
  SM3TT21(e, f, g, h); \
  COPYRESULT(b, d, f, h)

// func block(dig *digest, p []byte)
TEXT ·block(SB), 0, $1048-32
  MOVD p_base+8(FP), SI
  MOVD p_len+16(FP), DX
  LSR	$6, DX
  LSL $6, DX
  
  ADD DX, SI, DI
  MOVD DI, 272(RSP)
  CMP SI, DI
  BEQ end

  MOVD dig+0(FP), BP
  MOVWU (0*4)(BP), R19 // a = H0
  MOVWU (1*4)(BP), R20 // b = H1
  MOVWU (2*4)(BP), R21 // c = H2
  MOVWU (3*4)(BP), R22 // d = H3
  MOVWU (4*4)(BP), R23 // e = H4
  MOVWU (5*4)(BP), R24 // f = H5
  MOVWU (6*4)(BP), R25 // g = H6
  MOVWU (7*4)(BP), R26 // h = H7

loop:
  MOVD RSP, BP

  MSGSCHEDULE0(0)
  MSGSCHEDULE0(1)
  MSGSCHEDULE0(2)
  MSGSCHEDULE0(3)

  SM3ROUND0(0, 0x79cc4519, R19, R20, R21, R22, R23, R24, R25, R26)
  SM3ROUND0(1, 0xf3988a32, R26, R19, R20, R21, R22, R23, R24, R25)
  SM3ROUND0(2, 0xe7311465, R25, R26, R19, R20, R21, R22, R23, R24)
  SM3ROUND0(3, 0xce6228cb, R24, R25, R26, R19, R20, R21, R22, R23)
  SM3ROUND0(4, 0x9cc45197, R23, R24, R25, R26, R19, R20, R21, R22)
  SM3ROUND0(5, 0x3988a32f, R22, R23, R24, R25, R26, R19, R20, R21)
  SM3ROUND0(6, 0x7311465e, R21, R22, R23, R24, R25, R26, R19, R20)
  SM3ROUND0(7, 0xe6228cbc, R20, R21, R22, R23, R24, R25, R26, R19)
  SM3ROUND0(8, 0xcc451979, R19, R20, R21, R22, R23, R24, R25, R26)
  SM3ROUND0(9, 0x988a32f3, R26, R19, R20, R21, R22, R23, R24, R25)
  SM3ROUND0(10, 0x311465e7, R25, R26, R19, R20, R21, R22, R23, R24)
  SM3ROUND0(11, 0x6228cbce, R24, R25, R26, R19, R20, R21, R22, R23)
  
  SM3ROUND1(12, 0xc451979c, R23, R24, R25, R26, R19, R20, R21, R22)
  SM3ROUND1(13, 0x88a32f39, R22, R23, R24, R25, R26, R19, R20, R21)
  SM3ROUND1(14, 0x11465e73, R21, R22, R23, R24, R25, R26, R19, R20)
  SM3ROUND1(15, 0x228cbce6, R20, R21, R22, R23, R24, R25, R26, R19)
  
  SM3ROUND2(16, 0x9d8a7a87, R19, R20, R21, R22, R23, R24, R25, R26)
  SM3ROUND2(17, 0x3b14f50f, R26, R19, R20, R21, R22, R23, R24, R25)
  SM3ROUND2(18, 0x7629ea1e, R25, R26, R19, R20, R21, R22, R23, R24)
  SM3ROUND2(19, 0xec53d43c, R24, R25, R26, R19, R20, R21, R22, R23)
  SM3ROUND2(20, 0xd8a7a879, R23, R24, R25, R26, R19, R20, R21, R22)
  SM3ROUND2(21, 0xb14f50f3, R22, R23, R24, R25, R26, R19, R20, R21)
  SM3ROUND2(22, 0x629ea1e7, R21, R22, R23, R24, R25, R26, R19, R20)
  SM3ROUND2(23, 0xc53d43ce, R20, R21, R22, R23, R24, R25, R26, R19)
  SM3ROUND2(24, 0x8a7a879d, R19, R20, R21, R22, R23, R24, R25, R26)
  SM3ROUND2(25, 0x14f50f3b, R26, R19, R20, R21, R22, R23, R24, R25)
  SM3ROUND2(26, 0x29ea1e76, R25, R26, R19, R20, R21, R22, R23, R24)
  SM3ROUND2(27, 0x53d43cec, R24, R25, R26, R19, R20, R21, R22, R23)
  SM3ROUND2(28, 0xa7a879d8, R23, R24, R25, R26, R19, R20, R21, R22)
  SM3ROUND2(29, 0x4f50f3b1, R22, R23, R24, R25, R26, R19, R20, R21)
  SM3ROUND2(30, 0x9ea1e762, R21, R22, R23, R24, R25, R26, R19, R20)
  SM3ROUND2(31, 0x3d43cec5, R20, R21, R22, R23, R24, R25, R26, R19)
  SM3ROUND2(32, 0x7a879d8a, R19, R20, R21, R22, R23, R24, R25, R26)
  SM3ROUND2(33, 0xf50f3b14, R26, R19, R20, R21, R22, R23, R24, R25)
  SM3ROUND2(34, 0xea1e7629, R25, R26, R19, R20, R21, R22, R23, R24)
  SM3ROUND2(35, 0xd43cec53, R24, R25, R26, R19, R20, R21, R22, R23)
  SM3ROUND2(36, 0xa879d8a7, R23, R24, R25, R26, R19, R20, R21, R22)
  SM3ROUND2(37, 0x50f3b14f, R22, R23, R24, R25, R26, R19, R20, R21)
  SM3ROUND2(38, 0xa1e7629e, R21, R22, R23, R24, R25, R26, R19, R20)
  SM3ROUND2(39, 0x43cec53d, R20, R21, R22, R23, R24, R25, R26, R19)
  SM3ROUND2(40, 0x879d8a7a, R19, R20, R21, R22, R23, R24, R25, R26)
  SM3ROUND2(41, 0xf3b14f5, R26, R19, R20, R21, R22, R23, R24, R25)
  SM3ROUND2(42, 0x1e7629ea, R25, R26, R19, R20, R21, R22, R23, R24)
  SM3ROUND2(43, 0x3cec53d4, R24, R25, R26, R19, R20, R21, R22, R23)
  SM3ROUND2(44, 0x79d8a7a8, R23, R24, R25, R26, R19, R20, R21, R22)
  SM3ROUND2(45, 0xf3b14f50, R22, R23, R24, R25, R26, R19, R20, R21)
  SM3ROUND2(46, 0xe7629ea1, R21, R22, R23, R24, R25, R26, R19, R20)
  SM3ROUND2(47, 0xcec53d43, R20, R21, R22, R23, R24, R25, R26, R19)
  SM3ROUND2(48, 0x9d8a7a87, R19, R20, R21, R22, R23, R24, R25, R26)
  SM3ROUND2(49, 0x3b14f50f, R26, R19, R20, R21, R22, R23, R24, R25)
  SM3ROUND2(50, 0x7629ea1e, R25, R26, R19, R20, R21, R22, R23, R24)
  SM3ROUND2(51, 0xec53d43c, R24, R25, R26, R19, R20, R21, R22, R23)
  SM3ROUND2(52, 0xd8a7a879, R23, R24, R25, R26, R19, R20, R21, R22)
  SM3ROUND2(53, 0xb14f50f3, R22, R23, R24, R25, R26, R19, R20, R21)
  SM3ROUND2(54, 0x629ea1e7, R21, R22, R23, R24, R25, R26, R19, R20)
  SM3ROUND2(55, 0xc53d43ce, R20, R21, R22, R23, R24, R25, R26, R19)
  SM3ROUND2(56, 0x8a7a879d, R19, R20, R21, R22, R23, R24, R25, R26)
  SM3ROUND2(57, 0x14f50f3b, R26, R19, R20, R21, R22, R23, R24, R25)
  SM3ROUND2(58, 0x29ea1e76, R25, R26, R19, R20, R21, R22, R23, R24)
  SM3ROUND2(59, 0x53d43cec, R24, R25, R26, R19, R20, R21, R22, R23)
  SM3ROUND2(60, 0xa7a879d8, R23, R24, R25, R26, R19, R20, R21, R22)
  SM3ROUND2(61, 0x4f50f3b1, R22, R23, R24, R25, R26, R19, R20, R21)
  SM3ROUND2(62, 0x9ea1e762, R21, R22, R23, R24, R25, R26, R19, R20)
  SM3ROUND2(63, 0x3d43cec5, R20, R21, R22, R23, R24, R25, R26, R19)

  MOVD dig+0(FP), BP

  EORW (0*4)(BP), R19  // H0 = a XOR H0
  MOVWU R19, (0*4)(BP)
  EORW (1*4)(BP), R20  // H1 = b XOR H1
  MOVWU R20, (1*4)(BP)
  EORW (2*4)(BP), R21 // H2 = c XOR H2
  MOVWU R21, (2*4)(BP)
  EORW (3*4)(BP), R22 // H3 = d XOR H3
  MOVWU R22, (3*4)(BP)
  EORW (4*4)(BP), R23 // H4 = e XOR H4
  MOVWU R23, (4*4)(BP)
  EORW (5*4)(BP), R24 // H5 = f XOR H5
  MOVWU R24, (5*4)(BP)
  EORW (6*4)(BP), R25 // H6 = g XOR H6
  MOVWU R25, (6*4)(BP)
  EORW (7*4)(BP), R26 // H7 = h XOR H7
  MOVWU R26, (7*4)(BP)

  ADD $64, SI
  CMP SI, 272(SP)
  BCC  loop

end:	
  RET
