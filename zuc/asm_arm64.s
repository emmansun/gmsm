//go:build !purego

#include "textflag.h"

DATA Top3_Bottom5_bits_of_the_byte<>+0x00(SB)/8, $0xe0e0e0e0e0e0e0e0
DATA Top3_Bottom5_bits_of_the_byte<>+0x08(SB)/8, $0xe0e0e0e0e0e0e0e0
DATA Top3_Bottom5_bits_of_the_byte<>+0x10(SB)/8, $0x1f1f1f1f1f1f1f1f
DATA Top3_Bottom5_bits_of_the_byte<>+0x18(SB)/8, $0x1f1f1f1f1f1f1f1f
GLOBL Top3_Bottom5_bits_of_the_byte<>(SB), RODATA, $32

DATA P123_data<>+0x00(SB)/8, $0x0A020F0F0E000F09
DATA P123_data<>+0x08(SB)/8, $0x090305070C000400
DATA P123_data<>+0x10(SB)/8, $0x040C000705060D08
DATA P123_data<>+0x18(SB)/8, $0x0209030F0A0E010B
DATA P123_data<>+0x20(SB)/8, $0x0F0A0D00060A0602
DATA P123_data<>+0x28(SB)/8, $0x0D0C0900050D0303
GLOBL P123_data<>(SB), RODATA, $48

// Affine transform 1 & 2 (low and high nibbles)
DATA m1_2<>+0x00(SB)/8, $0x1D1C9F9E83820100
DATA m1_2<>+0x08(SB)/8, $0x3938BBBAA7A62524
DATA m1_2<>+0x10(SB)/8, $0xA174A97CDD08D500
DATA m1_2<>+0x18(SB)/8, $0x3DE835E04194499C
DATA m1_2<>+0x20(SB)/8, $0xA8BC0216D9CD7367
DATA m1_2<>+0x28(SB)/8, $0x1F0BB5A16E7AC4D0
DATA m1_2<>+0x30(SB)/8, $0x638CFA1523CCBA55
DATA m1_2<>+0x38(SB)/8, $0x3FD0A6497F90E609
GLOBL m1_2<>(SB), RODATA, $64

DATA Shuf_mask<>+0x00(SB)/8, $0x0B0E0104070A0D00
DATA Shuf_mask<>+0x08(SB)/8, $0x0306090C0F020508
GLOBL Shuf_mask<>(SB), RODATA, $16

DATA mask_S01<>+0x00(SB)/8, $0xff00ff00ff00ff00
DATA mask_S01<>+0x08(SB)/8, $0xff00ff00ff00ff00
DATA mask_S01<>+0x10(SB)/8, $0x00ff00ff00ff00ff
DATA mask_S01<>+0x18(SB)/8, $0x00ff00ff00ff00ff
GLOBL mask_S01<>(SB), RODATA, $32

#define SI R0
#define DI R1
#define BP R2
#define AX R3
#define BX R4
#define CX R5
#define DX R6

#define ZERO V16
#define TOP3_BITS V19
#define BOTTOM5_BITS V20
#define NIBBLE_MASK V21
#define INVERSE_SHIFT_ROWS V22
#define M1L V23
#define M1H V24 
#define M2L V25 
#define M2H V26
#define P1 V27
#define P2 V28
#define P3 V29
#define S0_MASK V30
#define S1_MASK V31

#define OFFSET_FR1      (16*4)
#define OFFSET_FR2      (17*4)
#define OFFSET_BRC_X0   (18*4)
#define OFFSET_BRC_X1   (19*4)
#define OFFSET_BRC_X2   (20*4)
#define OFFSET_BRC_X3   (21*4)

#define LOAD_GLOBAL_DATA() \
	MOVW $0x0F0F0F0F, R0                              \
	VDUP R0, NIBBLE_MASK.S4                           \
	MOVD $Top3_Bottom5_bits_of_the_byte<>(SB), R0     \
	VLD1 (R0), [TOP3_BITS.B16, BOTTOM5_BITS.B16]      \
	MOVD $m1_2<>(SB), R0                              \
	VLD1 (R0), [M1L.B16, M1H.B16, M2L.B16, M2H.B16]   \
	MOVD $P123_data<>(SB), R0                         \
	VLD1 (R0), [P1.B16, P2.B16, P3.B16]               \
	MOVD $mask_S01<>(SB), R0                          \
	VLD1 (R0), [S0_MASK.B16, S1_MASK.B16]             \
	MOVD $Shuf_mask<>(SB), R0                         \
	VLD1 (R0), [INVERSE_SHIFT_ROWS.B16]               \

#define SHLDL(a, b, n) \  // NO SHLDL in GOLANG now
	LSLW n, a          \
	LSRW n, b          \  
	ORRW  b, a

#define Rotl_5(XDATA, XTMP0)                           \
	VSHL $5, XDATA.S4, XTMP0.S4                        \
	VUSHR $3, XDATA.S4, XDATA.S4                       \
	VAND TOP3_BITS.B16, XTMP0.B16, XTMP0.B16           \
	VAND BOTTOM5_BITS.B16, XDATA.B16, XDATA.B16        \
	VORR XTMP0.B16, XDATA.B16, XDATA.B16

#define S0_comput(IN_OUT, XTMP1, XTMP2)    \
	VUSHR $4, IN_OUT.S4, XTMP1.S4                \
	VAND NIBBLE_MASK.B16, XTMP1.B16, XTMP1.B16   \
	\
	VAND NIBBLE_MASK.B16, IN_OUT.B16, IN_OUT.B16 \
	\
	VTBL IN_OUT.B16, [P1.B16], XTMP2.B16         \
	VEOR XTMP1.B16, XTMP2.B16, XTMP2.B16         \
	\
	VTBL XTMP2.B16, [P2.B16], XTMP1.B16          \
	VEOR IN_OUT.B16, XTMP1.B16, XTMP1.B16        \
	\
	VTBL XTMP1.B16, [P3.B16], IN_OUT.B16         \
	VEOR XTMP2.B16, IN_OUT.B16, IN_OUT.B16       \
	\
	VSHL $4, IN_OUT.S4, IN_OUT.S4                \
	VEOR XTMP1.B16, IN_OUT.B16, IN_OUT.B16       \
	Rotl_5(IN_OUT, XTMP1)    

// Affine Transform
// parameters:
// -  L: table low nibbles
// -  H: table high nibbles
// -  x: 128 bits register as sbox input/output data
// -  y: 128 bits temp register
// -  z: 128 bits temp register
#define AFFINE_TRANSFORM(L, H, x, y, z)            \
	VAND x.B16, NIBBLE_MASK.B16, z.B16;            \
	VTBL z.B16, [L.B16], y.B16;                    \
	VUSHR $4, x.D2, x.D2;                          \
	VAND x.B16, NIBBLE_MASK.B16, z.B16;            \
	VTBL z.B16, [H.B16], z.B16;                    \
	VEOR y.B16, z.B16, x.B16

#define S1_comput(x, XTMP1, XTMP2)          \    
	AFFINE_TRANSFORM(M1L, M1H, x, XTMP1, XTMP2);   \
	VTBL INVERSE_SHIFT_ROWS.B16, [x.B16], x.B16;   \
	AESE ZERO.B16, x.B16;                          \
	AFFINE_TRANSFORM(M2L, M2H, x, XTMP1, XTMP2)

#define BITS_REORG(idx)                      \
	MOVW (((15 + idx) % 16)*4)(SI), R12      \
	MOVW (((14 + idx) % 16)*4)(SI), AX       \
	MOVW (((11 + idx) % 16)*4)(SI), R13      \
	MOVW (((9 + idx) % 16)*4)(SI), BX        \
	MOVW (((7 + idx) % 16)*4)(SI), R14       \ 
	MOVW (((5 + idx) % 16)*4)(SI), CX        \
	MOVW (((2 + idx) % 16)*4)(SI), R15       \
	MOVW (((0 + idx) % 16)*4)(SI), DX        \
	LSRW $15, R12                            \
	LSLW $16, AX                             \
	LSLW $1, BX                              \
	LSLW $1, CX                              \
	LSLW $1, DX                              \
	SHLDL(R12, AX, $16)                      \
	SHLDL(R13, BX, $16)                      \
	SHLDL(R14, CX, $16)                      \
	SHLDL(R15, DX, $16)           

#define LFSR_UPDT(idx)                       \
	MOVW (((0 + idx) % 16)*4)(SI), BX        \
	MOVW (((4 + idx) % 16)*4)(SI), CX        \
	MOVW (((10 + idx) % 16)*4)(SI), DX       \
	MOVW (((13 + idx) % 16)*4)(SI), R8       \
	MOVW (((15 + idx) % 16)*4)(SI), R9       \
	ADD BX, AX                              \
	LSL $8, BX                              \
	LSL $20, CX                             \
	LSL $21, DX                             \
	LSL $17, R8                             \
	LSL $15, R9                             \
	ADD BX, AX                              \
	ADD CX, AX                              \
	ADD DX, AX                              \
	ADD R8, AX                              \
	ADD R9, AX                              \
	\
	LSR $31, AX, BX                         \
	AND $0x7FFFFFFF, AX                     \
	ADD BX, AX                              \
	\
	LSR $31, AX, BX                         \
	AND $0x7FFFFFFF, AX                     \
	ADD BX, AX                              \
	\
	MOVW AX, (((0 + idx) % 16)*4)(SI)

#define NONLIN_FUN()                         \
	EORW R10, R12, AX                        \
	ADDW R11, AX                             \
	ADDW R13, R10                            \ // W1= F_R1 + BRC_X1
	EORW R14, R11                            \ // W2= F_R2 ^ BRC_X2
	\
	LSLW $16, R10, DX                        \
	LSRW $16, R11, CX                        \  
	ORRW CX, DX                              \ // P = (W1 << 16) | (W2 >> 16)
	SHLDL(R11, R10, $16)                     \ // Q = (W2 << 16) | (W1 >> 16)
	RORW $30, DX, BX                         \
	RORW $22, DX, CX                         \
	RORW $14, DX, R8                         \
	RORW $8, DX, R9                          \
	EORW BX, DX                              \
	EORW CX, DX                              \
	EORW R8, DX                              \
	EORW R9, DX                              \ // U = L1(P) = EDX, hi(RDX)=0
	RORW $24, R11, BX                        \
	RORW $18, R11, CX                        \
	RORW $10, R11, R8                        \
	RORW $2, R11, R9                         \
	EORW BX, R11                             \
	EORW CX, R11                             \
	EORW R8, R11                             \
	EORW R9, R11                             \ // V = L2(Q) = R11D, hi(R11)=0
	LSL $32, R11                             \
	EOR R11, DX                              \
	VDUP DX, V0.D2                           \
	VMOV V0.B16, V1.B16                      \ 
	S0_comput(V1, V2, V3)                    \
	S1_comput(V0, V2, V3)                    \
	\
	VAND S1_MASK.B16, V0.B16, V0.B16         \
	VAND S0_MASK.B16, V1.B16, V1.B16         \ 
	VEOR V1.B16, V0.B16, V0.B16              \ 
	\
	VMOV V0.S[0], R10                        \ // F_R1
	VMOV V0.S[1], R11       

#define RESTORE_LFSR_0()                     \
	MOVW.P 4(SI), AX                         \
	VLD1 (SI), [V0.B16, V1.B16, V2.B16]      \
	SUB $4, SI                               \
	MOVD (52)(SI), BX                        \
	MOVW (60)(SI), CX                        \
	\
	VST1 [V0.B16, V1.B16, V2.B16], (SI)      \
	MOVD BX, (48)(SI)                        \
	MOVW CX, (56)(SI)                        \
	MOVW AX, (60)(SI)     

#define RESTORE_LFSR_2()                     \
	MOVD.P 8(SI), AX                         \
	VLD1 (SI), [V0.B16, V1.B16, V2.B16]      \ 
	SUB $8, SI                               \
	MOVD (56)(SI), BX                        \
	\
	VST1 [V0.B16, V1.B16, V2.B16], (SI)      \
	MOVD BX, (48)(SI)                        \
	MOVD AX, (56)(SI)    

#define RESTORE_LFSR_4()                     \
	VLD1 (SI), [V0.B16, V1.B16, V2.B16, V3.B16]   \ 
	\
	VST1.P [V1.B16, V2.B16, V3.B16], 48(SI)       \
	VST1 [V0.B16], (SI)                           \
	SUB $48, SI

#define RESTORE_LFSR_8()                     \
	VLD1 (SI), [V0.B16, V1.B16, V2.B16, V3.B16]   \ 
	\
	VST1.P [V2.B16, V3.B16], 32(SI)               \
	VST1 [V0.B16, V1.B16], (SI)                   \
	SUB $32, SI

#define LOAD_STATE(r)                         \
	MOVW 64+r, R10                            \
	MOVW 68+r, R11                            \
	MOVW 72+r, R12                            \
	MOVW 76+r, R13                            \
	MOVW 80+r, R14                            \
	MOVW 84+r, R15

#define SAVE_STATE(r)                         \
	MOVW R10, 64+r                            \
	MOVW R11, 68+r                            \
	MOVW R12, 72+r                            \
	MOVW R13, 76+r                            \
	MOVW R14, 80+r                            \
	MOVW R15, 84+r

// func genKeywordAsm(s *zucState32) uint32
TEXT ·genKeywordAsm(SB),NOSPLIT,$0
	LOAD_GLOBAL_DATA()
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	MOVD pState+0(FP), SI
	LOAD_STATE(0(SI))

	BITS_REORG(0)
	NONLIN_FUN()

	EORW R15, AX
	MOVW AX, ret+8(FP)
	EOR AX, AX
	LFSR_UPDT(0)
	SAVE_STATE(0(SI))
	RESTORE_LFSR_0()

	RET

#define ONEROUND(idx)      \
	BITS_REORG(idx)               \
	NONLIN_FUN()                  \
	EORW R15, AX                  \
	MOVW AX, (idx*4)(DI)          \
	EOR AX, AX                    \
	LFSR_UPDT(idx)

#define ROUND_REV32(idx)      \
	BITS_REORG(idx)               \
	NONLIN_FUN()                  \
	EORW R15, AX                  \
	REVW AX, AX                   \
	MOVW AX, (idx*4)(DI)          \
	EOR AX, AX                    \
	LFSR_UPDT(idx)    

// func genKeyStreamAsm(keyStream []uint32, pState *zucState32)
TEXT ·genKeyStreamAsm(SB),NOSPLIT,$0
	LOAD_GLOBAL_DATA()
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	MOVD ks+0(FP), DI
	MOVD ks_len+8(FP), BP
	MOVD pState+24(FP), SI

	LOAD_STATE(0(SI))

zucSixteens:
	CMP $16, BP
	BLT zucOctet
	SUB $16, BP
	ONEROUND(0)
	ONEROUND(1)
	ONEROUND(2)
	ONEROUND(3)
	ONEROUND(4)
	ONEROUND(5)
	ONEROUND(6)
	ONEROUND(7)
	ONEROUND(8)
	ONEROUND(9)
	ONEROUND(10)
	ONEROUND(11)
	ONEROUND(12)
	ONEROUND(13)
	ONEROUND(14)
	ONEROUND(15)
	ADD	$4*16, DI
	B zucSixteens

zucOctet:
	CMP $8, BP
	BLT zucNibble
	SUB $8, BP
	ONEROUND(0)
	ONEROUND(1)
	ONEROUND(2)
	ONEROUND(3)
	ONEROUND(4)
	ONEROUND(5)
	ONEROUND(6)
	ONEROUND(7)
	ADD	$2*16, DI
	RESTORE_LFSR_8()
zucNibble:
	CMP $4, BP
	BLT zucDouble
	SUB $4, BP
	ONEROUND(0)
	ONEROUND(1)
	ONEROUND(2)
	ONEROUND(3)
	ADD	$1*16, DI
	RESTORE_LFSR_4()
zucDouble:
	CMP $2, BP
	BLT zucSingle
	SUB $2, BP
	ONEROUND(0)
	ONEROUND(1)
	ADD	$8, DI
	RESTORE_LFSR_2()
zucSingle:
	TBZ	$0, BP, zucRet
	ONEROUND(0)
	RESTORE_LFSR_0()
zucRet:
	SAVE_STATE(0(SI))
	RET 

// func genKeyStreamRev32Asm(keyStream []byte, pState *zucState32)
TEXT ·genKeyStreamRev32Asm(SB),NOSPLIT,$0
	LOAD_GLOBAL_DATA()
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	MOVD ks+0(FP), DI
	MOVD ks_len+8(FP), BP
	MOVD pState+24(FP), SI

	LSR $2, BP
	LOAD_STATE(0(SI))

zucSixteens:
	CMP $16, BP
	BLT zucOctet
	SUB $16, BP
	ROUND_REV32(0)
	ROUND_REV32(1)
	ROUND_REV32(2)
	ROUND_REV32(3)
	ROUND_REV32(4)
	ROUND_REV32(5)
	ROUND_REV32(6)
	ROUND_REV32(7)
	ROUND_REV32(8)
	ROUND_REV32(9)
	ROUND_REV32(10)
	ROUND_REV32(11)
	ROUND_REV32(12)
	ROUND_REV32(13)
	ROUND_REV32(14)
	ROUND_REV32(15)
	ADD	$4*16, DI
	B zucSixteens

zucOctet:
	CMP $8, BP
	BLT zucNibble
	SUB $8, BP
	ROUND_REV32(0)
	ROUND_REV32(1)
	ROUND_REV32(2)
	ROUND_REV32(3)
	ROUND_REV32(4)
	ROUND_REV32(5)
	ROUND_REV32(6)
	ROUND_REV32(7)
	ADD	$2*16, DI
	RESTORE_LFSR_8()
zucNibble:
	CMP $4, BP
	BLT zucDouble
	SUB $4, BP
	ROUND_REV32(0)
	ROUND_REV32(1)
	ROUND_REV32(2)
	ROUND_REV32(3)
	ADD	$16, DI
	RESTORE_LFSR_4()
zucDouble:
	CMP $2, BP
	BLT zucSingle
	SUB $2, BP
	ROUND_REV32(0)
	ROUND_REV32(1)
	ADD	$8, DI
	RESTORE_LFSR_2()
zucSingle:
	TBZ	$0, BP, zucRet
	ROUND_REV32(0)
	RESTORE_LFSR_0()
zucRet:
	SAVE_STATE(0(SI))
	RET
