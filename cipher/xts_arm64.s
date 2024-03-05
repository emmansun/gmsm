//go:build !purego

#include "textflag.h"

#define B0 V0
#define T1 V1
#define T2 V2

#define POLY V3
#define ZERO V4

#define TW R0
#define GB R1
#define I R2

// func mul2(tweak *[blockSize]byte, isGB bool)
TEXT ·mul2(SB),NOSPLIT,$0
	MOVD tweak+0(FP), TW
	MOVB isGB+8(FP), GB

	VLD1 (TW), [B0.B16]

	VEOR	POLY.B16, POLY.B16, POLY.B16
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	CMP $1, GB
	BEQ gb_alg

	MOVD	$0x87, I
	VMOV	I, POLY.D[0]

	VMOV	B0.D[1], I
	ASR	$63, I
	VMOV	I, T1.D2
	VAND	POLY.B16, T1.B16, T1.B16

	VUSHR	$63, B0.D2, T2.D2
	VEXT	$8, T2.B16, ZERO.B16, T2.B16
	VSHL	$1, B0.D2, B0.D2
	VEOR	T1.B16, B0.B16, B0.B16
	VEOR	T2.B16, B0.B16, B0.B16

	VST1 [B0.B16], (TW)
	RET

gb_alg:
	MOVD	$0xE1, I
	LSL	$56, I
	VMOV	I, POLY.D[1]

	VREV64 B0.B16, B0.B16
	VEXT	$8, B0.B16, B0.B16, B0.B16

	VMOV	B0.D[0], I
	LSL $63, I
	ASR $63, I
	VMOV	I, T1.D2
	VAND	POLY.B16, T1.B16, T1.B16

	VSHL $63, B0.D2, T2.D2
	VEXT	$8, ZERO.B16, T2.B16, T2.B16
	VUSHR	$1, B0.D2, B0.D2
	VEOR	T1.B16, B0.B16, B0.B16
	VEOR	T2.B16, B0.B16, B0.B16

	VEXT	$8, B0.B16, B0.B16, B0.B16
	VREV64 B0.B16, B0.B16

	VST1 [B0.B16], (TW)
	RET

// func doubleTweaks(tweak *[blockSize]byte, tweaks []byte, isGB bool)
TEXT ·doubleTweaks(SB),NOSPLIT,$0
	MOVD tweak+0(FP), TW
	MOVD tweaks+8(FP), R3
	MOVD tweaks_len+16(FP), R4
	MOVB isGB+32(FP), GB

	LSR $4, R4
	EOR R5, R5

	VEOR	POLY.B16, POLY.B16, POLY.B16
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	VLD1 (TW), [B0.B16]

	CMP $1, GB
	BEQ dt_gb_alg

	MOVD	$0x87, I
	VMOV	I, POLY.D[0]

loop:
	VST1.P [B0.B16], 16(R3)

	VMOV	B0.D[1], I
	ASR	$63, I
	VMOV	I, T1.D2
	VAND	POLY.B16, T1.B16, T1.B16

	VUSHR	$63, B0.D2, T2.D2
	VEXT	$8, T2.B16, ZERO.B16, T2.B16
	VSHL	$1, B0.D2, B0.D2
	VEOR	T1.B16, B0.B16, B0.B16
	VEOR	T2.B16, B0.B16, B0.B16

	ADD $1, R5
	CMP R4, R5
	BNE loop

	VST1 [B0.B16], (TW)
	RET

dt_gb_alg:
	MOVD	$0xE1, I
	LSL	$56, I
	VMOV	I, POLY.D[1]

gb_loop:
	VST1.P [B0.B16], 16(R3)

	VREV64 B0.B16, B0.B16
	VEXT	$8, B0.B16, B0.B16, B0.B16

	VMOV	B0.D[0], I
	LSL $63, I
	ASR $63, I
	VMOV	I, T1.D2
	VAND	POLY.B16, T1.B16, T1.B16

	VSHL $63, B0.D2, T2.D2
	VEXT	$8, ZERO.B16, T2.B16, T2.B16
	VUSHR	$1, B0.D2, B0.D2
	VEOR	T1.B16, B0.B16, B0.B16
	VEOR	T2.B16, B0.B16, B0.B16

	VEXT	$8, B0.B16, B0.B16, B0.B16
	VREV64 B0.B16, B0.B16

	ADD $1, R5
	CMP R4, R5
	BNE gb_loop

	VST1 [B0.B16], (TW)	
	RET
