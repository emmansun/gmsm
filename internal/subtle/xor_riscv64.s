// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// func xorBytes(dst, a, b *byte, n int)
TEXT ·xorBytes(SB), NOSPLIT|NOFRAME, $0
	MOV	dst+0(FP), X5
	MOV	a+8(FP), X6
	MOV	b+16(FP), X7
	MOV	n+24(FP), X8

	MOV 	$8, X9
	BLTU	X8, X9, tail

loop:
	MOV (X6), X10
	MOV (X7), X11
	XOR X10, X11, X10
	MOV X10, (X5)
	ADD $8, X5
	ADD $8, X6
	ADD $8, X7
	SUB $8, X8
	BGEU X8, X9, loop

tail:
	BEQZ	X8, done
	MOV $4, X9
	BLTU X8, X9, less_than4
	MOVWU (X6), X10
	MOVWU (X7), X11
	XOR X10, X11, X10
	MOVW X10, (X5)
	ADD $4, X5
	ADD $4, X6
	ADD $4, X7
	SUB $4, X8

less_than4:
	MOV $2, X9
	BLTU X8, X9, less_than2
	MOVHU (X6), X10
	MOVHU (X7), X11
	XOR X10, X11, X10
	MOVH X10, (X5)
	ADD $2, X5
	ADD $2, X6
	ADD $2, X7
	SUB $2, X8

less_than2:
	BEQZ	X8, done
	MOVBU (X6), X10
	MOVBU (X7), X11
	XOR X10, X11, X10
	MOVB X10, (X5)

done:
	RET
