// The original code (non-vector) is ported from Golang 
// https://github.com/golang/go/blob/master/src/crypto/aes/ctr_s390x.go

//go:build !purego

#include "textflag.h"

// func xorBytes(dst, a, b *byte, n int)
TEXT ·xorBytes(SB),NOSPLIT,$0-32
	MOVD	dst+0(FP), R1
	MOVD	a+8(FP), R2
	MOVD	b+16(FP), R3
	MOVD	n+24(FP), R4

	MOVD	$0, R5
	CMPBLT	R4, $16, tail

loop16b:
	VL 0(R2)(R5*1), V0
	VL 0(R3)(R5*1), V1
	VX V0, V1, V2
	VST V2, 0(R1)(R5*1)
	LAY	16(R5), R5
	SUB	$16, R4
	CMPBGE	R4, $16, loop16b

tail:
	CMPBLT	R4, $8, less_than8
	MOVD	0(R2)(R5*1), R7
	MOVD	0(R3)(R5*1), R8
	XOR	R7, R8
	MOVD	R8, 0(R1)(R5*1)
	LAY	8(R5), R5
	SUB	$8, R4

less_than8:
	CMPBLT	R4, $4, less_than4
	MOVWZ	0(R2)(R5*1), R7
	MOVWZ	0(R3)(R5*1), R8
	XOR	R7, R8
	MOVW	R8, 0(R1)(R5*1)
	LAY	4(R5), R5
	SUB	$4, R4

less_than4:
	CMPBLT	R4, $2, less_than2
	MOVHZ	0(R2)(R5*1), R7
	MOVHZ	0(R3)(R5*1), R8
	XOR	R7, R8
	MOVH	R8, 0(R1)(R5*1)
	LAY	2(R5), R5
	SUB	$2, R4

less_than2:
	CMPBEQ	R4, $0, done
	MOVB	0(R2)(R5*1), R7
	MOVB	0(R3)(R5*1), R8
	XOR	R7, R8
	MOVB	R8, 0(R1)(R5*1)

done:
	RET
