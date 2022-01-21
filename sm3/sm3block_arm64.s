#include "textflag.h"

#define SI R0
#define DI R1
#define BP R2
#define AX R3
#define BX R4
#define CX R5
#define DX R6
#define hlp0 R7
#define hlp1 R9

// Wt+4 = Mt+4; for 0 <= t <= 11
#define MSGSCHEDULE01(index) \
	MOVW	((index+4)*4)(SI), AX; \
	REVW	AX, AX; \
	MOVW	AX, ((index+4)*4)(BP)

// x = Wt-12 XOR Wt-5 XOR ROTL(15, Wt+1)
// p1(x) = x XOR ROTL(15, x) XOR ROTL(23, x)
// Wt+4 = p1(x) XOR ROTL(7, Wt-9) XOR Wt-2
// for 12 <= t <= 63
#define MSGSCHEDULE1(index) \
  MOVW	((index+1)*4)(BP), AX; \
  RORW  $17, AX; \
  MOVW	((index-12)*4)(BP), BX; \
  EORW  BX, AX; \
  MOVW	((index-5)*4)(BP), BX; \
  EORW  BX, AX; \                      // AX = x
  RORW  $17, AX, BX; \                 // BX =  ROTL(15, x)
  RORW  $9, AX, CX; \                  // CX = ROTL(23, x)   
  EORW  BX, AX; \                      // AX = x xor ROTL(15, x)  
  EORW  CX, AX; \                      // AX = x xor ROTL(15, x) xor ROTL(23, x)  
  MOVW	((index-9)*4)(BP), BX; \
  RORW  $25, BX; \
  MOVW	((index-2)*4)(BP), CX; \
  EORW  BX, AX; \
  EORW  CX, AX; \
  MOVW  AX, ((index+4)*4)(BP)

// Calculate ss1 in BX
// x = ROTL(12, a) + e + ROTL(index, const)
// ret = ROTL(7, x)
#define SM3SS1(const, a, e) \
  RORW  $20, a, BX; \
  ADDW  e, BX; \
  ADDW  $const, BX; \
  RORW  $25, BX

// Calculate tt1 in CX
// ret = (a XOR b XOR c) + d + (ROTL(12, a) XOR ss1) + (Wt XOR Wt+4)
#define SM3TT10(index, a, b, c, d) \  
  EORW a, b, DX; \
  EORW c, DX; \                      // (a XOR b XOR c)
  ADDW d, DX; \                      // (a XOR b XOR c) + d 
  MOVW ((index)*4)(BP), hlp0; \      // Wt
  EORW hlp0, AX; \                   // Wt XOR Wt+4
  ADDW AX, DX;  \
  RORW $20, a, CX; \
  EORW BX, CX; \                     // ROTL(12, a) XOR ss1
  ADDW DX, CX                        // (a XOR b XOR c) + d + (ROTL(12, a) XOR ss1)

// Calculate tt2 in BX
// ret = (e XOR f XOR g) + h + ss1 + Wt
#define SM3TT20(e, f, g, h) \  
  ADDW h, hlp0; \                    // Wt + h
  ADDW BX, hlp0; \                   // Wt + h + ss1
  EORW e, f, BX; \                   // e XOR f
  EORW g, BX; \                      // e XOR f XOR g
  ADDW hlp0, BX                      // (e XOR f XOR g) + Wt + h + ss1

// Calculate tt1 in CX, used DX, hlp0
// ret = ((a AND b) OR (a AND c) OR (b AND c)) + d + (ROTL(12, a) XOR ss1) + (Wt XOR Wt+4)
#define SM3TT11(index, a, b, c, d) \  
  ANDW a, b, DX; \                   // a AND b
  ANDW a, c, CX; \                   // a AND c
  ORRW  DX, CX; \                    // (a AND b) OR (a AND c)
  ANDW b, c, DX; \                   // b AND c
  ORRW  CX, DX; \                    // (a AND b) OR (a AND c) OR (b AND c)
  ADDW d, DX; \
  RORW $20, a, CX; \
  EORW BX, CX; \
  ADDW DX, CX; \                     // ((a AND b) OR (a AND c) OR (b AND c)) + d + (ROTL(12, a) XOR ss1)
  MOVW ((index)*4)(BP), hlp0; \
  EORW hlp0, AX; \                   // Wt XOR Wt+4
  ADDW AX, CX

// Calculate tt2 in BX
// ret = ((e AND f) OR (NOT(e) AND g)) + h + ss1 + Wt
#define SM3TT21(e, f, g, h) \  
  ADDW h, hlp0; \                    // Wt + h
  ADDW BX, hlp0; \                   // h + ss1 + Wt
  ANDW e, f, DX; \                   // e AND f
  MVNW e, BX; \                      // NOT(e)
  ANDW g, BX; \                      // NOT(e) AND g
  ORRW  DX, BX; \
  ADDW hlp0, BX

#define COPYRESULT(b, d, f, h) \
  RORW $23, b; \
  MOVW CX, h; \                      // a = ttl
  RORW $13, f; \
  RORW $23, BX, CX; \
  EORW BX, CX; \                     // tt2 XOR ROTL(9, tt2)
  RORW $15, BX; \
  EORW BX, CX; \                     // tt2 XOR ROTL(9, tt2) XOR ROTL(17, tt2)
  MOVW CX, d                         // e = tt2 XOR ROTL(9, tt2) XOR ROTL(17, tt2)

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
TEXT ·block(SB), 0, $272-32
  MOVD dig+0(FP), hlp1
  MOVD p_base+8(FP), SI
  MOVD p_len+16(FP), DX
  MOVD RSP, BP

  AND	$~63, DX
  CBZ	DX, end  

  ADD SI, DX, DI

  LDPW	(0*8)(hlp1), (R19, R20)
  LDPW	(1*8)(hlp1), (R21, R22)
  LDPW	(2*8)(hlp1), (R23, R24)
  LDPW	(3*8)(hlp1), (R25, R26)

loop:
  MOVW  R19, R10
  MOVW  R20, R11
  MOVW  R21, R12
  MOVW  R22, R13
  MOVW  R23, R14
  MOVW  R24, R15
  MOVW  R25, R16
  MOVW  R26, R17

  // Wt = Mt; for 0 <= t <= 3
  LDPW	(0*8)(SI), (AX, BX)
  REVW	AX, AX
  REVW	BX, BX
  STPW	(AX, BX), (0*8)(BP)

  LDPW	(1*8)(SI), (CX, DX)
  REVW	CX, CX
  REVW	DX, DX
  STPW	(CX, DX), (1*8)(BP)

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

  EORW R10, R19  // H0 = a XOR H0
  EORW R11, R20  // H1 = b XOR H1
  EORW R12, R21  // H0 = a XOR H0
  EORW R13, R22  // H1 = b XOR H1
  EORW R14, R23  // H0 = a XOR H0
  EORW R15, R24  // H1 = b XOR H1
  EORW R16, R25  // H0 = a XOR H0
  EORW R17, R26  // H1 = b XOR H1
 
  ADD $64, SI
  CMP SI, DI
  BNE	loop

  STPW	(R19, R20), (0*8)(hlp1)
  STPW	(R21, R22), (1*8)(hlp1)
  STPW	(R23, R24), (2*8)(hlp1)
  STPW	(R25, R26), (3*8)(hlp1)

end:	
  RET
