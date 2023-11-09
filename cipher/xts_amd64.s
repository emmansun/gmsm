//go:build amd64 && !purego

#include "textflag.h"

DATA bswapMask<>+0x00(SB)/8, $0x08090a0b0c0d0e0f
DATA bswapMask<>+0x08(SB)/8, $0x0001020304050607

DATA gcmPoly<>+0x00(SB)/8, $0x0000000000000087
DATA gcmPoly<>+0x08(SB)/8, $0x0000000000000000

DATA gbGcmPoly<>+0x00(SB)/8, $0x0000000000000000
DATA gbGcmPoly<>+0x08(SB)/8, $0xe100000000000000

GLOBL bswapMask<>(SB), (NOPTR+RODATA), $16
GLOBL gcmPoly<>(SB), (NOPTR+RODATA), $16
GLOBL gbGcmPoly<>(SB), (NOPTR+RODATA), $16


#define POLY X0
#define BSWAP X1
#define B0 X2
#define T0 X3
#define T1 X4

// func mul2(tweak *[blockSize]byte, isGB bool)
TEXT ·mul2(SB),NOSPLIT,$0
	MOVQ tweak+0(FP), DI
	MOVB isGB+8(FP), AX

	MOVOU (0*16)(DI), B0

	CMPB AX, $1
	JE gb_alg

	MOVOU gcmPoly<>(SB), POLY

	// B0 * 2
	PSHUFD $0xff, B0, T0
	MOVOU B0, T1
	PSRAL $31, T0 // T0 for reduction
	PAND POLY, T0
	PSRLL $31, T1
	PSLLDQ $4, T1
	PSLLL $1, B0
	PXOR T0, B0
	PXOR T1, B0

	MOVOU B0, (0*16)(DI)

	RET

gb_alg:
	MOVOU bswapMask<>(SB), BSWAP
	MOVOU gbGcmPoly<>(SB), POLY

	PSHUFB BSWAP, B0

	// B0 * 2
	MOVOU B0, T0
 	PSHUFD $0, B0, T1
	PSRLQ $1, B0
	PSLLQ $63, T0
	PSRLDQ $8, T0
	POR T0, B0

	// reduction
	PSLLL $31, T1
	PSRAL $31, T1
	PAND POLY, T1
	PXOR T1, B0

	PSHUFB BSWAP, B0
	MOVOU B0, (0*16)(DI)
	RET

// func doubleTweaks(tweak *[blockSize]byte, tweaks []byte, isGB bool)
TEXT ·doubleTweaks(SB),NOSPLIT,$0
	MOVQ tweak+0(FP), DI
	MOVQ tweaks+8(FP), AX
	MOVQ tweaks_len+16(FP), BX
	MOVB isGB+32(FP), CX

	MOVOU (0*16)(DI), B0

	SHRQ $4, BX
	XORQ DX, DX

	CMPB CX, $1
	JE dt_gb_alg

	MOVOU gcmPoly<>(SB), POLY

loop:
	MOVOU B0, (0*16)(AX)
	LEAQ 16(AX), AX

	// B0 * 2
	PSHUFD $0xff, B0, T0
	MOVOU B0, T1
	PSRAL $31, T0 // T0 for reduction
	PAND POLY, T0
	PSRLL $31, T1
	PSLLDQ $4, T1
	PSLLL $1, B0
	PXOR T0, B0
	PXOR T1, B0

	ADDQ $1, DX
	CMPQ DX, BX
	JB loop

	MOVOU B0, (0*16)(DI)
	RET

dt_gb_alg:
	MOVOU bswapMask<>(SB), BSWAP
	MOVOU gbGcmPoly<>(SB), POLY

gb_loop:
	MOVOU B0, (0*16)(AX)
	LEAQ 16(AX), AX

	PSHUFB BSWAP, B0

	// B0 * 2
	MOVOU B0, T0
 	PSHUFD $0, B0, T1
	PSRLQ $1, B0
	PSLLQ $63, T0
	PSRLDQ $8, T0
	POR T0, B0

	// reduction
	PSLLL $31, T1
	PSRAL $31, T1
	PAND POLY, T1
	PXOR T1, B0

	PSHUFB BSWAP, B0
	ADDQ $1, DX
	CMPQ DX, BX
	JB gb_loop

	MOVOU B0, (0*16)(DI)
	RET
